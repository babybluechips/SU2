#!/usr/bin/env python3
"""Focused checks using the pinned source's real TestCase.run_test method.

No GitHub API, credential reads, baseline edits, or solver runs in validate/seal.
Each case runs in a dedicated session; only timeout cleanup is specialized.
"""
import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

BASE = "07aa46b1868655ec01f534bf3ac84ba5fbb6b822"
DATA = "01b80cf2edfc69b7a545368747bd511c6d732aec"
IMAGE = "ghcr.io/su2code/su2/build-su2:260405-0054"
SELECTIONS = {
    "nompi": ["visc_cone"],
    "mpi": ["visc_cone", "super_cat", "ion_gy", "ion_gy"],
}
CASE_DIRS = {
    "visc_cone": "nonequilibrium/visc_wedge",
    "super_cat": "nonequilibrium/visc_wedge",
    "ion_gy": "nonequilibrium/visc_cylinder",
}
CASE_CONFIGS = {
    "visc_cone": "axi_visccone.cfg",
    "super_cat": "super_cat.cfg",
    "ion_gy": "cyl_ion_gy.cfg",
}
DEADLINE = None


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def tree_files(root):
    result = {}
    for p in sorted(root.rglob("*")):
        require(not p.is_symlink(), "symlink in evidence/input tree: " + str(p))
        if p.is_file():
            result[str(p.relative_to(root))] = {
                "sha256": sha(p),
                "bytes": p.stat().st_size,
            }
    return result


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-c", "safe.directory=" + str(repo), "-C", str(repo), *args],
        text=True,
        timeout=60,
    ).strip()


def manifest(path):
    value = json.loads(Path(path).read_text())
    require(value["schema"] == "pr2885-focused-ci.v1", "wrong manifest schema")
    require(value["repository"] == "babybluechips/SU2", "unexpected source repository")
    require(
        value["base_sha"] == BASE and value["testcases_sha"] == DATA,
        "unexpected base/data",
    )
    for key, width in (
        ("source_sha", 40),
        ("source_tree", 40),
        ("source_diff_sha256", 64),
    ):
        require(
            re.fullmatch("[0-9a-f]{%d}" % width, value[key]) is not None,
            "unbound/invalid " + key,
        )
    require(value["source_sha"] != BASE, "source cannot be the base")
    require(
        value["image"] == IMAGE and value["selections"] == SELECTIONS,
        "unregistered image/cases",
    )
    require(
        value["require_identical_ion_printed_rows"] is True,
        "repeatability requirement changed",
    )
    for name, expected in (
        ("build_jobs", 2),
        ("build_timeout_seconds", 3600),
        ("unit_timeout_seconds", 600),
        ("case_timeout_seconds", 1600),
        ("job_workload_timeout_seconds", 5400),
    ):
        require(value[name] == expected, "changed resource bound: " + name)
    return value


def source_authority(source, data, target):
    require(
        git(source, "rev-parse", "HEAD") == target["source_sha"], "wrong source SHA"
    )
    require(
        git(source, "rev-parse", "HEAD^{tree}") == target["source_tree"],
        "wrong source tree",
    )
    require(
        not git(source, "status", "--porcelain=v1", "--untracked-files=no"),
        "dirty tracked source",
    )
    require(git(source, "merge-base", BASE, "HEAD") == BASE, "base is not an ancestor")
    patch = subprocess.check_output(
        [
            "git",
            "-c",
            "safe.directory=" + str(source),
            "-C",
            str(source),
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--binary",
            "--full-index",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            BASE + "..HEAD",
        ],
        timeout=60,
    )
    require(
        hashlib.sha256(patch).hexdigest() == target["source_diff_sha256"],
        "wrong source diff",
    )
    modules = git(source, "submodule", "status", "--recursive")
    require(
        modules
        and all(
            re.fullmatch(r" ?[0-9a-f]{40} .+", line) for line in modules.splitlines()
        ),
        "uninitialized/mismatched submodule",
    )
    subprocess.check_call(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(source),
            "submodule",
            "foreach",
            "--quiet",
            "--recursive",
            "git diff --exit-code HEAD --",
        ],
        stdout=subprocess.DEVNULL,
        timeout=60,
    )
    require(git(data, "rev-parse", "HEAD") == DATA, "wrong TestCases SHA")
    require(
        not git(data, "status", "--porcelain=v1", "--untracked-files=no"),
        "dirty TestCases data",
    )
    return {
        "source_sha": target["source_sha"],
        "source_tree": target["source_tree"],
        "diff_sha256": target["source_diff_sha256"],
        "testcases_sha": DATA,
        "submodules": modules.splitlines(),
    }, patch


def definitions(source, mode):
    script = (
        source
        / "TestCases"
        / ("serial_regression.py" if mode == "nompi" else "parallel_regression.py")
    )
    text = script.read_text()
    require(
        re.search(r"if test\.tol == 0\.0:\s*test\.tol = 0\.00001", text),
        "changed runner default tolerance",
    )
    require(
        re.search(r"if test\.timeout == 0:\s*test\.timeout = 1600", text),
        "changed runner default timeout",
    )
    allowed = {
        "cfg_dir",
        "cfg_file",
        "test_iter",
        "test_vals",
        "test_vals_aarch64",
        "tol",
        "tol_aarch64",
        "timeout",
        "new_output",
        "unsteady",
        "multizone",
        "no_restart",
        "enabled_on_cpu_arch",
    }
    found = {case: {} for case in set(SELECTIONS[mode])}
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            lhs = node.targets[0]
            if (
                isinstance(lhs, ast.Attribute)
                and isinstance(lhs.value, ast.Name)
                and lhs.value.id in found
            ):
                require(
                    lhs.attr in allowed,
                    "unexpected selected-case assignment: " + lhs.attr,
                )
                require(
                    lhs.attr not in found[lhs.value.id],
                    "duplicate selected-case assignment",
                )
                found[lhs.value.id][lhs.attr] = ast.literal_eval(node.value)
    for case, item in found.items():
        require(
            {"cfg_dir", "cfg_file", "test_iter", "test_vals"}.issubset(item),
            "missing case definition",
        )
        require(
            item["cfg_dir"] == CASE_DIRS[case]
            and item["cfg_file"] == CASE_CONFIGS[case],
            "unexpected case input",
        )
        require(
            item["test_iter"] == (99 if case == "ion_gy" else 10),
            "unexpected target iteration",
        )
        require(item.get("tol", 0.0) in (0.0, 1e-5, 0.01), "unexpected tolerance")
        require(
            item.get("tol", 0.0) == (0.01 if case == "ion_gy" else 0.0),
            "selected-case tolerance changed",
        )
    return script, found


def session_members(session):
    result = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text()
            fields = raw[raw.rfind(")") + 2 :].split()
            if int(fields[3]) == session and fields[0] != "Z":
                result.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def stop_group(session, sig):
    try:
        os.killpg(session, sig)
    except ProcessLookupError:
        pass


def bounded(command, cwd, log, seconds):
    if DEADLINE is not None:
        seconds = min(seconds, int(DEADLINE - time.monotonic() - 45))
    require(seconds > 0, "workload deadline reached")
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log.open("w") as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        timed_out = False
        try:
            code = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_group(process.pid, signal.SIGTERM)
            try:
                code = process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                stop_group(process.pid, signal.SIGKILL)
                code = process.wait(timeout=15)
        survivors = session_members(process.pid)
        if survivors:
            stop_group(process.pid, signal.SIGKILL)
            until = time.monotonic() + 5
            while session_members(process.pid) and time.monotonic() < until:
                time.sleep(0.1)
        require(
            not session_members(process.pid), "owned command session did not quiesce"
        )
    return {
        "command": command,
        "returncode": code,
        "timed_out": timed_out,
        "unexpected_surviving_children": survivors,
        "owned_session_quiescent": True,
        "clean_exit": code == 0 and not timed_out and not survivors,
        "wall_seconds": round(time.monotonic() - started, 3),
        "log_sha256": sha(log),
    }


def config_values(path):
    values = {}
    for line in path.read_text().splitlines():
        line = line.split("%", 1)[0]
        if "=" in line:
            key, value = line.split("=", 1)
            require(key.strip() not in values, "duplicate effective option")
            values[key.strip()] = value.strip()
    return values


def case_child(args):
    spec = json.loads(Path(args.spec).read_text())
    source, folder = Path(spec["source"]), Path(spec["folder"])
    module_spec = importlib.util.spec_from_file_location(
        "pinned_testcase", source / "TestCases" / "TestCase.py"
    )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    testcase = module.TestCase(spec["case"])
    for key, value in spec["definition"].items():
        setattr(testcase, key, value)
    testcase.cfg_dir = str(folder)
    testcase.tol = testcase.tol or 1e-5
    testcase.timeout = testcase.timeout or 1600
    require(testcase.is_enabled(False, False, False), "selected test would be skipped")
    # Preserve real run_test; constrain its timeout-only cleanup to this owned session.
    class OwnedCommand(module.TestCase.Command):
        def killall(self):
            os.killpg(os.getpgrp(), signal.SIGKILL)

    testcase.command = OwnedCommand(
        "mpirun -n 2" if spec["mode"] == "mpi" else "", shlex.quote(spec["binary"])
    )
    passed = bool(testcase.run_test())
    save(
        folder / "testcase-result.json",
        {
            "testcase_run_test_pass": passed,
            "effective_test_values": testcase.test_vals,
            "effective_tolerance": testcase.tol,
            "target_iteration": testcase.test_iter,
            "cpu_arch": testcase.cpu_arch,
            "executed_config": testcase.cfg_file,
        },
    )
    return 0 if passed else 1


def target_row(log, iteration, width):
    active = False
    for line in log.read_text(errors="replace").splitlines():
        active = active or "Begin Solver" in line
        if not active or not line.strip().startswith("|"):
            continue
        values = [v.strip() for v in line.strip()[1:-1].split("|")]
        try:
            if int(values[0]) != iteration:
                continue
            row = [float(x) for x in values[-width:]]
        except (ValueError, IndexError):
            continue
        require(
            len(row) == width and all(math.isfinite(x) for x in row),
            "nonfinite/malformed target row",
        )
        return row
    raise RuntimeError("target row absent")


def run_case(source, data, binary, evidence, mode, case, repeat, definition):
    folder = evidence / "cases" / (case + "-r" + str(repeat))
    folder.mkdir(parents=True, exist_ok=False)
    shutil.copytree(data / CASE_DIRS[case], folder, dirs_exist_ok=True)
    config = source / "TestCases" / CASE_DIRS[case] / CASE_CONFIGS[case]
    shutil.copy2(config, folder / config.name)
    options = config_values(config)
    require(
        options["MESH_FILENAME"]
        == ("visc_cyl.su2" if case == "ion_gy" else "viscwedge.su2"),
        "unexpected mesh",
    )
    require(
        options["RESTART_SOL"] == ("YES" if case == "ion_gy" else "NO"),
        "wrong initialization",
    )
    inputs = tree_files(folder)
    seed = folder / "restart_flow_gy.dat" if case == "ion_gy" else None
    if seed:
        require(seed.is_file(), "missing pristine ion seed")
        require(options["SOLUTION_FILENAME"] == "restart_flow_gy", "wrong seed prefix")
        require(
            options["RESTART_FILENAME"] != "restart_flow_gy",
            "solver would overwrite seed",
        )
        seed.chmod(0o444)
    spec = {
        "case": case,
        "mode": mode,
        "definition": definition,
        "source": str(source),
        "folder": str(folder),
        "binary": str(binary),
    }
    spec_path = evidence / "specs" / (case + "-r" + str(repeat) + ".json")
    save(spec_path, spec)
    execution = bounded(
        [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "case-child",
            "--spec",
            str(spec_path),
        ],
        evidence,
        folder / "testcase-driver.log",
        1620,
    )
    unchanged = all(
        (folder / name).is_file() and sha(folder / name) == value["sha256"]
        for name, value in inputs.items()
    )
    result_path = folder / "testcase-result.json"
    reported = json.loads(result_path.read_text()) if result_path.exists() else {}
    raw_log = folder / (config.name + ".log")
    row, error = None, None
    try:
        row = target_row(raw_log, definition["test_iter"], len(definition["test_vals"]))
    except Exception as exc:
        error = str(exc)
    result = {
        "case": case,
        "repeat": repeat,
        "mode": mode,
        "execution": execution,
        "inputs_before": inputs,
        "inputs_unchanged": unchanged,
        "source_config_sha256": sha(config),
        "testcase": reported,
        "computed_target_row": row,
        "supplemental_finite_row_error": error,
        "seed_before_sha256": inputs.get("restart_flow_gy.dat", {}).get("sha256"),
        "seed_after_sha256": sha(seed) if seed and seed.exists() else None,
        "pass": execution["clean_exit"]
        and unchanged
        and reported.get("testcase_run_test_pass") is True
        and error is None,
    }
    save(folder / "case-receipt.json", result)
    return result


def run(args):
    global DEADLINE
    target = manifest(args.manifest)
    DEADLINE = time.monotonic() + target["job_workload_timeout_seconds"]
    source, data, evidence = (
        Path(x).resolve() for x in (args.source, args.test_data, args.evidence)
    )
    evidence.mkdir(parents=True, exist_ok=True)
    outcome = {
        "schema": "pr2885-focused-ci-result.v1",
        "mode": args.mode,
        "pass": False,
        "cases": [],
    }
    inputs_before, binary_hashes = None, None
    try:
        require(
            platform.system() == "Linux" and platform.machine() == "x86_64",
            "requires Linux x86_64",
        )
        authority, patch = source_authority(source, data, target)
        save(evidence / "source-authority.json", authority)
        (evidence / "source.diff").write_bytes(patch)
        script, cases = definitions(source, args.mode)
        (evidence / "source").mkdir(exist_ok=True)
        for p in (script, source / "TestCases/TestCase.py"):
            shutil.copy2(p, evidence / "source" / p.name)
        inputs_before = {
            name: tree_files(data / name) for name in sorted(set(CASE_DIRS.values()))
        }
        save(evidence / "canonical-inputs-before.json", inputs_before)
        build = source / ("build-pr2885-" + args.mode)
        require(not build.exists(), "build directory already exists")
        flags = [
            "--buildtype=release",
            "-Dcpu-arch=skylake",
            "-Denable-tests=true",
            "-Denable-pywrapper=true",
            "-Denable-mlpcpp=true",
            "-Dwith-omp=false",
        ]
        if args.mode == "nompi":
            flags += ["-Dwith-mpi=disabled", "-Denable-openblas=true", "--warnlevel=3"]
        else:
            flags += [
                "-Dwith-mpi=enabled",
                "-Denable-coolprop=true",
                "-Denable-mpp=true",
                "-Dinstall-mpp=true",
                "--warnlevel=2",
            ]
        save(
            evidence / "build-request.json",
            {
                "flags": flags,
                "jobs": 2,
                "image_tag": IMAGE,
                "scope": "normal solver and full normal unit target, no AD or full regression suite",
            },
        )
        environment = {}
        for command in (
            ["cc", "--version"],
            ["c++", "--version"],
            ["mpirun", "--version"],
            [sys.executable, "--version"],
            ["pkg-config", "--modversion", "openblas"],
        ):
            r = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
            )
            environment[" ".join(command)] = {
                "returncode": r.returncode,
                "output": r.stdout,
            }
        save(evidence / "toolchain.json", environment)
        setup = bounded(
            [sys.executable, "meson.py", "setup", str(build), *flags],
            source,
            evidence / "build/configure.log",
            900,
        )
        outcome["configure"] = setup
        require(setup["clean_exit"], "configuration failed")
        compilation = bounded(
            [
                str(source / "ninja"),
                "-C",
                str(build),
                "-j",
                "2",
                "SU2_CFD/src/SU2_CFD",
                "UnitTests/test_driver",
            ],
            source,
            evidence / "build/compile.log",
            3600,
        )
        outcome["build"] = compilation
        for name in (
            "intro-buildoptions.json",
            "intro-compilers.json",
            "intro-machines.json",
            "intro-dependencies.json",
        ):
            shutil.copy2(build / "meson-info" / name, evidence / "build" / name)
        shutil.copy2(
            build / "compile_commands.json", evidence / "build/compile_commands.json"
        )
        require(compilation["clean_exit"], "build failed")
        options = {
            x["name"]: x["value"]
            for x in json.loads(
                (build / "meson-info/intro-buildoptions.json").read_text()
            )
        }
        require(
            options["with-mpi"] == ("disabled" if args.mode == "nompi" else "enabled"),
            "incorrect MPI build",
        )
        require(
            options["enable-tests"]
            and not options["with-omp"]
            and not options["enable-autodiff"]
            and not options["enable-directdiff"],
            "wrong normal build options",
        )
        require(
            args.mode != "nompi" or options["enable-openblas"],
            "NoMPI build lacks requested OpenBLAS",
        )
        binary, driver = build / "SU2_CFD/src/SU2_CFD", build / "UnitTests/test_driver"
        binary_hashes = {str(p.relative_to(source)): sha(p) for p in (binary, driver)}
        save(evidence / "binary-hashes.json", binary_hashes)
        unit_layout = evidence.parent / ("unit-layout-" + args.mode)
        (unit_layout / "src").mkdir(parents=True, exist_ok=False)
        (unit_layout / "src/SU2").symlink_to(source, target_is_directory=True)
        unit_report = evidence / "tests/full-normal-unit.catch.log"
        unit = bounded(
            [str(driver), "--out", str(unit_report)],
            unit_layout,
            evidence / "tests/full-normal-unit.stdout.log",
            600,
        )
        unit["catch_report_sha256"] = sha(unit_report) if unit_report.exists() else None
        outcome["unit"] = unit
        counts = {}
        for case in SELECTIONS[args.mode]:
            counts[case] = counts.get(case, 0) + 1
            result = run_case(
                source,
                data,
                binary,
                evidence,
                args.mode,
                case,
                counts[case],
                cases[case],
            )
            outcome["cases"].append(result)
            save(evidence / "result.json", outcome)
        ion = [x for x in outcome["cases"] if x["case"] == "ion_gy"]
        repeat_ok = not ion or (
            len(ion) == 2
            and ion[0]["seed_before_sha256"] is not None
            and ion[0]["seed_before_sha256"] == ion[1]["seed_before_sha256"]
        )
        outcome["fresh_ion_repeat_seed_equal"] = repeat_ok
        rows_equal = not ion or (
            len(ion) == 2
            and ion[0]["computed_target_row"] is not None
            and ion[0]["computed_target_row"] == ion[1]["computed_target_row"]
        )
        outcome["fresh_ion_repeat_rows_equal"] = None if not ion else rows_equal
        outcome["repeatability_pass"] = repeat_ok and rows_equal
        outcome["pass"] = (
            unit["clean_exit"]
            and unit_report.exists()
            and repeat_ok
            and rows_equal
            and all(x["pass"] for x in outcome["cases"])
        )
    except Exception as exc:
        outcome["error"] = str(exc)
    finally:
        try:
            final, _ = source_authority(source, data, target)
            final_inputs = {
                name: tree_files(data / name)
                for name in sorted(set(CASE_DIRS.values()))
            }
            unchanged = inputs_before is not None and final_inputs == inputs_before
            unchanged = unchanged and (
                binary_hashes is None
                or all(sha(source / n) == v for n, v in binary_hashes.items())
            )
            save(evidence / "source-authority-after.json", final)
            save(evidence / "canonical-inputs-after.json", final_inputs)
            outcome["protected_inputs_and_binaries_unchanged"] = unchanged
            outcome["pass"] = outcome["pass"] and unchanged
        except Exception as exc:
            outcome["final_integrity_error"] = str(exc)
            outcome["pass"] = False
        outcome[
            "claim_boundary"
        ] = "Targeted checked-in TestCase regression comparisons and full normal units; not convergence validation or upstream protected CI."
        save(evidence / "result.json", outcome)
    return 0 if outcome["pass"] else 1


def seal(evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    # Workflow calls this only after docker exits, so redirected logs are closed.
    require(
        not (evidence / "SHA256SUMS").exists(), "refusing to replace evidence index"
    )
    files = tree_files(evidence)
    (evidence / "SHA256SUMS").write_text(
        "".join(v["sha256"] + "  " + k + "\n" for k, v in files.items())
    )
    for name, value in files.items():
        require(sha(evidence / name) == value["sha256"], "file changed while indexing")
    print("Indexed", len(files), "captured files. This does not imply test success.")


def main():
    p = argparse.ArgumentParser()
    subs = p.add_subparsers(dest="action", required=True)
    v = subs.add_parser("validate")
    v.add_argument("--manifest", required=True)
    v.add_argument("--github-output")
    r = subs.add_parser("run")
    for name in ("manifest", "source", "test-data", "evidence"):
        r.add_argument("--" + name, required=True)
    r.add_argument("--mode", choices=tuple(SELECTIONS), required=True)
    c = subs.add_parser("case-child")
    c.add_argument("--spec", required=True)
    s = subs.add_parser("seal")
    s.add_argument("--evidence", required=True)
    args = p.parse_args()
    if args.action == "validate":
        m = manifest(args.manifest)
        if args.github_output:
            with open(args.github_output, "a") as f:
                f.write("source_sha=" + m["source_sha"] + "\n")
        print("Bound source target validated:", m["source_sha"])
        return 0
    if args.action == "run":
        return run(args)
    if args.action == "case-child":
        return case_child(args)
    seal(Path(args.evidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
