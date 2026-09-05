#!/usr/bin/env python3
"""Run the NEMO mass-fraction acceptance/rejection matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CASES = (
    {
        "name": "air5_roundoff",
        "composition": "0.999, 0.00025, 0.00025, 0.00025, 0.00025",
        "expect_accept": True,
    },
    {
        "name": "air5_invalid",
        "composition": "0.75, 0.24, 0.0, 0.0, 0.0",
        "expect_accept": False,
    },
    {
        "name": "air5_exact",
        "composition": "0.77, 0.23, 0.0, 0.0, 0.0",
        "expect_accept": True,
    },
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replace_option(text: str, name: str, value: str) -> str:
    replaced, count = re.subn(
        rf"^(\s*{re.escape(name)}\s*=\s*).*$",
        rf"\g<1>{value}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError(f"missing required option {name}")
    return replaced


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--test-data", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve()
    test_data = args.test_data.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    relative_case = Path("nonequilibrium/thermalbath/finitechemistry")
    source_case = source / "TestCases" / relative_case
    data_case = test_data / relative_case
    base_config = source_case / "thermalbath.cfg"
    base_mesh = data_case / "5x5Mesh.su2"
    if not base_config.is_file() or not base_mesh.is_file():
        raise RuntimeError("missing pinned thermal-bath configuration or mesh")

    results: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="su2-arm64-massfrac-") as temporary:
        runs_root = Path(temporary)
        for case in CASES:
            name = str(case["name"])
            run_dir = runs_root / name
            shutil.copytree(data_case, run_dir)
            shutil.copytree(source_case, run_dir, dirs_exist_ok=True)

            config = run_dir / f"{name}.cfg"
            config_text = base_config.read_text(encoding="utf-8")
            config_text = replace_option(config_text, "GAS_MODEL", "AIR-5")
            config_text = replace_option(config_text, "GAS_COMPOSITION", f"({case['composition']})")
            config_text = replace_option(config_text, "TIME_ITER", "1")
            config_text = replace_option(config_text, "OUTPUT_WRT_FREQ", "100000")
            config.write_text(config_text, encoding="utf-8")

            mesh = run_dir / base_mesh.name
            mesh_sha_before = sha256(mesh)
            log_path = output.parent / f"massfrac-{name}.log"
            started = time.monotonic()
            timed_out = False
            try:
                completed = subprocess.run(
                    [str(binary), config.name],
                    cwd=run_dir,
                    env={**os.environ, "OMP_NUM_THREADS": "1"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                    check=False,
                )
                return_code = completed.returncode
                log_text = completed.stdout
            except subprocess.TimeoutExpired as error:
                timed_out = True
                return_code = 124
                stdout = error.stdout or ""
                log_text = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout
            duration = time.monotonic() - started
            log_path.write_text(log_text, encoding="utf-8")

            rejection_present = "mass fractions do not sum to 1" in log_text
            precise_rejection = (
                "Initial gas mass fractions do not sum to 1 (sum = 0.99)" in log_text
            )
            expected_accept = bool(case["expect_accept"])
            accepted = return_code == 0 and "Exit Success" in log_text
            case_passed = (
                not timed_out
                and mesh_sha_before == sha256(mesh)
                and (
                    accepted and not rejection_present
                    if expected_accept
                    else return_code != 0 and rejection_present and precise_rejection
                )
            )
            results[name] = {
                "composition": case["composition"],
                "expect_accept": expected_accept,
                "accepted": accepted,
                "return_code": return_code,
                "timed_out": timed_out,
                "rejection_present": rejection_present,
                "precise_rejection": precise_rejection,
                "mesh_sha256": mesh_sha_before,
                "mesh_unchanged": mesh_sha_before == sha256(mesh),
                "config_sha256": sha256(config),
                "log_sha256": sha256(log_path),
                "duration_seconds": round(duration, 3),
                "passed": case_passed,
            }
            print(
                f"massfrac {name}: expect={'ACCEPT' if expected_accept else 'REJECT'} "
                f"rc={return_code} {'PASS' if case_passed else 'FAIL'}",
                flush=True,
            )

    roundoff_sum = 0.0
    for value in (0.999, 0.00025, 0.00025, 0.00025, 0.00025):
        roundoff_sum += value
    authority = {
        "schema_version": 1,
        "machine": os.uname().machine,
        "source_commit": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip(),
        "source_tree": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True
        ).strip(),
        "testcases_commit": subprocess.check_output(
            ["git", "-C", str(test_data), "rev-parse", "HEAD"], text=True
        ).strip(),
        "binary_sha256": sha256(binary),
        "roundoff_composition_sum": roundoff_sum,
        "roundoff_sum_is_not_bit_exact_unity": roundoff_sum != 1.0,
        "cases": results,
        "passed": roundoff_sum != 1.0
        and all(bool(result["passed"]) for result in results.values()),
    }
    output.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": authority["passed"]}, sort_keys=True))
    return 0 if authority["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
