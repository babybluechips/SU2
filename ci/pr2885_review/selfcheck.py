#!/usr/bin/env python3
"""Offline preparation checks. No build, solver, process cleanup or network calls."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "review", Path(__file__).with_name("run_review.py")
)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = json.loads(Path(__file__).with_name("target.json").read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def target_file(self, value):
        path = self.root / "target.json"
        path.write_text(json.dumps(value))
        return path

    def bound(self):
        target = copy.deepcopy(self.target)
        target.update(
            source_sha="1" * 40, source_tree="2" * 40, source_diff_sha256="3" * 64
        )
        return target

    def test_unbound_refused(self):
        self.target["source_sha"] = "__FINAL_PR2885_SHA__"
        with self.assertRaisesRegex(RuntimeError, "unbound"):
            review.manifest(self.target_file(self.target))

    def test_bound_manifest(self):
        self.assertEqual(
            review.manifest(self.target_file(self.bound()))["selections"],
            review.SELECTIONS,
        )

    def test_case_and_budget_mutations_refused(self):
        for key, value in (
            ("base_sha", "a" * 40),
            ("repository", "su2code/SU2"),
            ("testcases_sha", "4" * 40),
            ("image", "other"),
            ("build_jobs", 8),
            ("require_identical_ion_printed_rows", False),
            ("job_workload_timeout_seconds", 10000),
            ("selections", {"mpi": ["ion_gy"]}),
        ):
            data = self.bound()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                review.manifest(self.target_file(data))

    def synthetic_source(self, extra="", tol=0.01):
        source = self.root / "source"
        (source / "TestCases").mkdir(parents=True, exist_ok=True)
        text = "def main():\n"
        for case in ("visc_cone", "super_cat", "ion_gy"):
            text += "    %s.cfg_dir = %r\n" % (case, review.CASE_DIRS[case])
            text += "    %s.cfg_file = %r\n" % (case, review.CASE_CONFIGS[case])
            text += "    %s.test_iter = %d\n" % (case, 99 if case == "ion_gy" else 10)
            text += "    %s.test_vals = [1.0, 2.0]\n" % case
        text += "    ion_gy.tol = %r\n" % tol
        text += "    if test.tol == 0.0:\n        test.tol = 0.00001\n"
        text += "    if test.timeout == 0:\n        test.timeout = 1600\n" + extra
        (source / "TestCases/parallel_regression.py").write_text(text)
        return source

    def test_definitions_keep_declared_values_and_tolerance(self):
        _, cases = review.definitions(self.synthetic_source(), "mpi")
        self.assertEqual(cases["ion_gy"]["test_iter"], 99)
        self.assertEqual(cases["ion_gy"]["tol"], 0.01)
        self.assertEqual(cases["visc_cone"]["test_vals"], [1.0, 2.0])
        self.assertNotIn("tol", cases["visc_cone"])

    def test_tolerance_widening_refused(self):
        with self.assertRaises(RuntimeError):
            review.definitions(self.synthetic_source(tol=0.1), "mpi")

    def test_duplicate_assignment_refused(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            review.definitions(
                self.synthetic_source("    ion_gy.test_iter = 10\n"), "mpi"
            )

    def test_nonfinite_target_refused(self):
        log = self.root / "solver.log"
        log.write_text("Begin Solver\n| 10 | nan | 2 |\n")
        with self.assertRaisesRegex(RuntimeError, "nonfinite"):
            review.target_row(log, 10, 2)

    def test_target_and_missing_row(self):
        log = self.root / "solver.log"
        log.write_text("Begin Solver\n| 10 | -5.298550 | 24939 |\n")
        self.assertEqual(review.target_row(log, 10, 2), [-5.29855, 24939.0])
        with self.assertRaisesRegex(RuntimeError, "absent"):
            review.target_row(log, 99, 2)

    def test_duplicate_config_refused(self):
        path = self.root / "case.cfg"
        path.write_text("ITER= 10\nITER= 99\n")
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            review.config_values(path)

    def test_evidence_symlink_refused(self):
        (self.root / "source.txt").write_text("test")
        (self.root / "link.txt").symlink_to(self.root / "source.txt")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            review.tree_files(self.root)

    def test_build_git_trust_is_exact_and_subprocess_only(self):
        source = self.root / "source"
        (source / "externals/nested").mkdir(parents=True)
        original = {
            "KEEP": "value",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "*",
        }
        with patch.dict(review.os.environ, original, clear=True):
            environment, paths = review.build_environment(
                source, [" " + "1" * 40 + " externals/nested (heads/main)"]
            )
            self.assertEqual(dict(review.os.environ), original)
        self.assertEqual(
            paths, [str(source.resolve()), str((source / "externals/nested").resolve())]
        )
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], paths[0])
        self.assertEqual(environment["GIT_CONFIG_VALUE_1"], paths[1])
        self.assertEqual(environment["KEEP"], "value")
        for bad in ("../elsewhere", "/tmp/elsewhere", "."):
            with self.subTest(path=bad), self.assertRaises(RuntimeError):
                review.build_environment(source, [" " + "1" * 40 + " " + bad])
        (source / "alias").symlink_to(source / "externals/nested")
        with self.assertRaises(RuntimeError):
            review.build_environment(source, [" " + "1" * 40 + " alias"])

    def test_failure_details_and_success_rows_visible_with_bounded_logs(self):
        (self.root / "build").mkdir()
        (self.root / "build/configure.log").write_text(
            "HEADER" + "x" * 70000 + "MESON_FAILURE"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            review.emit_failure_diagnostics(
                self.root,
                {"mode": "nompi", "pass": False, "error": "configuration failed"},
            )
        self.assertIn("configuration failed", output.getvalue())
        self.assertIn("MESON_FAILURE", output.getvalue())
        self.assertNotIn("HEADER", output.getvalue())
        self.assertLess(len(output.getvalue()), 67000)
        (self.root / "tests").mkdir()
        (self.root / "tests/full-normal-unit.catch.log").write_text(
            "All tests passed (7 assertions in 2 test cases)"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            review.emit_result_summary(
                self.root,
                {
                    "mode": "nompi",
                    "pass": True,
                    "cases": [
                        {
                            "case": "visc_cone",
                            "pass": True,
                            "computed_target_row": [1.0, 2.0],
                            "inputs_before": {"excluded": "large inventory"},
                        }
                    ],
                },
            )
        self.assertIn('"computed_target_row": [1.0, 2.0]', output.getvalue())
        self.assertIn("7 assertions in 2 test cases", output.getvalue())
        self.assertNotIn("inputs_before", output.getvalue())

    def test_quiescence_includes_other_groups_in_owned_session(self):
        class Entry:
            def __init__(self, pid, group, session, state="S"):
                self.name = str(pid)
                self.text = "%d (worker) %s 1 %d %d 0 0" % (pid, state, group, session)

            def __truediv__(self, name):
                return self

            def read_text(self):
                return self.text

        class Proc:
            def iterdir(self):
                return [
                    Entry(101, 100, 100),
                    Entry(102, 102, 100),
                    Entry(103, 100, 103),
                    Entry(104, 100, 100, "Z"),
                ]

        with patch.object(review, "Path", return_value=Proc()):
            self.assertEqual(review.session_members(100), [101, 102])


if __name__ == "__main__":
    unittest.main()
