#!/usr/bin/env python3
"""Run a hash-bound subset of SU2's NEMO regression cases.

This runner deliberately separates vector harvesting from vector verification.
In ``harvest`` mode, a stale or missing aarch64 vector is reported but does not
hide a successful bounded solver run.  In ``verify`` mode, the computed row
must also match the effective aarch64 expectation from the checked-out SU2
regression script.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CASE_SPECS: dict[str, dict[str, Any]] = {
    "invwedge_ausm": {
        "directory": "nonequilibrium/invwedge",
        "config": "invwedge_ausm.cfg",
        "iteration": 10,
        "values": 9,
        "serial_variable": "invwedge",
        "mpi_variable": "invwedge_a",
    },
    "invwedge_msw": {
        "directory": "nonequilibrium/invwedge",
        "config": "invwedge_msw.cfg",
        "iteration": 10,
        "values": 9,
        "serial_variable": "invwedge_msw",
        "mpi_variable": "invwedge_msw",
    },
    "invwedge_roe": {
        "directory": "nonequilibrium/invwedge",
        "config": "invwedge_roe.cfg",
        "iteration": 10,
        "values": 9,
        "serial_variable": "invwedge_roe",
        "mpi_variable": "invwedge_roe",
    },
    "invwedge_lax": {
        "directory": "nonequilibrium/invwedge",
        "config": "invwedge_lax.cfg",
        "iteration": 10,
        "values": 9,
        "serial_variable": "invwedge_lax",
        "mpi_variable": "invwedge_lax",
    },
    "invwedge_ss_inlet": {
        "directory": "nonequilibrium/invwedge",
        "config": "invwedge_ss_inlet.cfg",
        "iteration": 10,
        "values": 9,
        "serial_variable": "invwedge_ss_inlet",
        "mpi_variable": "invwedge_ss_inlet",
    },
    "visc_cone": {
        "directory": "nonequilibrium/visc_wedge",
        "config": "axi_visccone.cfg",
        "iteration": 10,
        "values": 10,
        "serial_variable": "visc_cone",
        "mpi_variable": "visc_cone",
    },
    "super_cat": {
        "directory": "nonequilibrium/visc_wedge",
        "config": "super_cat.cfg",
        "iteration": 10,
        "values": 10,
        "serial_variable": "super_cat",
        "mpi_variable": "super_cat",
    },
    "ion_gy": {
        "directory": "nonequilibrium/visc_cylinder",
        "config": "cyl_ion_gy.cfg",
        "iteration": 10,
        "values": 12,
        "serial_variable": "ion_gy",
        "mpi_variable": "ion_gy",
    },
    "ion_gy_march": {
        "directory": "nonequilibrium/visc_cylinder",
        "config": "cyl_ion_gy_march.cfg",
        "iteration": 99,
        "values": 12,
        "serial_variable": "ion_gy_march",
        "mpi_variable": "ion_gy_march",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def parse_literal_assignment(text: str, variable: str, attribute: str) -> Any | None:
    pattern = re.compile(
        rf"^\s*{re.escape(variable)}\.{re.escape(attribute)}\s*=\s*(.+?)\s*(?:#.*)?$",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        return None
    try:
        return ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as error:
        raise RuntimeError(f"cannot parse {variable}.{attribute}: {match.group(1)!r}") from error


def expected_values(source: Path, mode: str, case: str) -> dict[str, Any]:
    spec = CASE_SPECS[case]
    script_name = "serial_regression.py" if mode == "serial" else "parallel_regression.py"
    script = source / "TestCases" / script_name
    text = script.read_text(encoding="utf-8")
    variable = spec[f"{mode}_variable"]
    default = parse_literal_assignment(text, variable, "test_vals")
    arm = parse_literal_assignment(text, variable, "test_vals_aarch64")
    arm_tolerance = parse_literal_assignment(text, variable, "tol_aarch64")
    default_tolerance = parse_literal_assignment(text, variable, "tol")
    effective = arm if arm else default
    tolerance = arm_tolerance if arm_tolerance not in (None, 0, 0.0) else default_tolerance
    # The public serial and parallel regression drivers use 0.0 as an unset
    # sentinel and replace it with 1e-5 before calling TestCase.run_test().
    if tolerance in (None, 0, 0.0):
        tolerance = 1e-5
    return {
        "script": str(script.relative_to(source)),
        "variable": variable,
        "default": default,
        "aarch64": arm,
        "effective": effective,
        "effective_source": "test_vals_aarch64" if arm else "test_vals",
        "tolerance": tolerance,
    }


def protect_restart_input(config: Path) -> dict[str, Any]:
    """Prevent a regression case from overwriting the restart it reads."""

    text = config.read_text(encoding="utf-8")

    def option(name: str) -> str | None:
        match = re.search(rf"^\s*{name}\s*=\s*([^%\s]+)", text, flags=re.MULTILINE)
        return match.group(1) if match else None

    solution = option("SOLUTION_FILENAME")
    restart = option("RESTART_FILENAME")
    record = {
        "changed": False,
        "solution_filename": solution,
        "restart_filename_before": restart,
        "restart_filename_after": restart,
    }
    if solution is None or restart is None or solution != restart:
        return record

    safe_restart = f"{restart}_arm64_preflight_out"
    replaced, count = re.subn(
        r"^(\s*RESTART_FILENAME\s*=\s*)[^%\s]+",
        rf"\g<1>{safe_restart}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError(f"failed to protect restart input in {config}")
    config.write_text(replaced, encoding="utf-8")
    record.update(
        changed=True,
        restart_filename_after=safe_restart,
        reason="SOLUTION_FILENAME and RESTART_FILENAME were identical",
    )
    return record


def parse_iteration_row(log_text: str, iteration: int, value_count: int) -> list[float] | None:
    in_solver = False
    for line in log_text.splitlines():
        if "Begin Solver" in line:
            in_solver = True
            continue
        if not in_solver or not line.lstrip().startswith("|"):
            continue
        fields = [field.strip() for field in line.strip().strip("|").split("|")]
        if not fields:
            continue
        try:
            row_iteration = int(fields[0])
        except ValueError:
            continue
        if row_iteration != iteration or len(fields) < value_count + 1:
            continue
        try:
            return [float(value) for value in fields[-value_count:]]
        except ValueError:
            continue
    return None


def compare_values(
    computed: list[float] | None, expected: list[float] | None, tolerance: Any
) -> dict[str, Any]:
    if computed is None or expected is None or len(computed) != len(expected):
        return {
            "comparable": False,
            "passed": False,
            "deltas": None,
            "max_abs_delta": None,
        }
    deltas = [abs(actual - reference) for actual, reference in zip(computed, expected)]
    if isinstance(tolerance, list):
        if len(tolerance) != len(deltas):
            passed = False
        else:
            passed = all(delta <= limit for delta, limit in zip(deltas, tolerance))
    else:
        passed = all(delta <= float(tolerance) for delta in deltas)
    return {
        "comparable": True,
        "passed": passed,
        "deltas": deltas,
        "max_abs_delta": max(deltas, default=0.0),
    }


def proposed_assignment(variable: str, computed: list[float] | None) -> str | None:
    if computed is None:
        return None
    values = ", ".join(f"{value:.6f}" for value in computed)
    return f"{variable}.test_vals_aarch64 = [{values}]"


def run_case(
    *,
    source: Path,
    test_data: Path,
    binary: Path,
    mode: str,
    case: str,
    runs_root: Path,
    policy: str,
) -> dict[str, Any]:
    spec = CASE_SPECS[case]
    run_dir = runs_root / f"{mode}-{case}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    data_dir = test_data / spec["directory"]
    source_dir = source / "TestCases" / spec["directory"]
    if not data_dir.is_dir():
        raise RuntimeError(f"missing pinned TestCases directory: {data_dir}")
    if not source_dir.is_dir():
        raise RuntimeError(f"missing SU2 test definition directory: {source_dir}")
    shutil.copytree(data_dir, run_dir)
    shutil.copytree(source_dir, run_dir, dirs_exist_ok=True)

    config = run_dir / spec["config"]
    if not config.is_file():
        raise RuntimeError(f"missing case configuration: {config}")
    config_sha_before = sha256(config)
    restart_protection = protect_restart_input(config)
    config_sha_executed = sha256(config)
    protected_inputs = file_hashes(run_dir)

    command = [str(binary), config.name]
    if mode == "mpi":
        command = ["mpirun"]
        if os.geteuid() == 0:
            command.append("--allow-run-as-root")
        command.extend(["-n", "2", str(binary), config.name])

    environment = os.environ.copy()
    environment.update(OMPI_MCA_osc="pt2pt", OMP_NUM_THREADS="1")
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=run_dir,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1600,
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
    log_path = runs_root / f"{mode}-{case}.log"
    log_path.write_text(log_text, encoding="utf-8")

    computed = parse_iteration_row(log_text, int(spec["iteration"]), int(spec["values"]))
    expected = expected_values(source, mode, case)
    comparison = compare_values(computed, expected["effective"], expected["tolerance"])
    input_hashes_after = file_hashes(run_dir)
    changed_inputs = [
        relative
        for relative, digest in protected_inputs.items()
        if input_hashes_after.get(relative) != digest
    ]
    finite = computed is not None and all(math.isfinite(value) for value in computed)
    runtime_ok = (
        not timed_out
        and return_code == 0
        and computed is not None
        and finite
        and "Begin Solver" in log_text
        and "Exit Success" in log_text
        and "Error Exit" not in log_text
        and "Residual > 10^20" not in log_text
        and not changed_inputs
    )
    policy_ok = runtime_ok and (policy == "harvest" or comparison["passed"])
    return {
        "case": case,
        "mode": mode,
        "command": command,
        "iteration": spec["iteration"],
        "value_count": spec["values"],
        "return_code": return_code,
        "timed_out": timed_out,
        "duration_seconds": round(duration, 3),
        "runtime_ok": runtime_ok,
        "policy": policy,
        "policy_ok": policy_ok,
        "computed": computed,
        "finite": finite,
        "expected": expected,
        "comparison": comparison,
        "proposed_assignment": proposed_assignment(expected["variable"], computed),
        "config_sha256_before_restart_protection": config_sha_before,
        "config_sha256_executed": config_sha_executed,
        "restart_protection": restart_protection,
        "protected_input_hashes": protected_inputs,
        "changed_input_files": changed_inputs,
        "log_sha256": sha256(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--test-data", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("serial", "mpi"), required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--policy", choices=("harvest", "verify"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve()
    test_data = args.test_data.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    runs_root = output.with_suffix("")
    runs_root.mkdir(parents=True, exist_ok=True)
    selected = [case for case in args.cases.split(",") if case]
    unknown = sorted(set(selected) - set(CASE_SPECS))
    if unknown:
        parser.error(f"unknown cases: {', '.join(unknown)}")

    results: dict[str, dict[str, Any]] = {}
    for case in selected:
        result = run_case(
            source=source,
            test_data=test_data,
            binary=binary,
            mode=args.mode,
            case=case,
            runs_root=runs_root,
            policy=args.policy,
        )
        results[case] = result
        print(
            f"{args.label} {args.mode} {case}: "
            f"runtime={'PASS' if result['runtime_ok'] else 'FAIL'} "
            f"vector={'PASS' if result['comparison']['passed'] else 'MISMATCH'} "
            f"policy={args.policy} wall={result['duration_seconds']}s",
            flush=True,
        )

    authority = {
        "schema_version": 1,
        "label": args.label,
        "mode": args.mode,
        "policy": args.policy,
        "machine": os.uname().machine,
        "source_commit": git_value(source, "rev-parse", "HEAD"),
        "source_tree": git_value(source, "rev-parse", "HEAD^{tree}"),
        "testcases_commit": git_value(test_data, "rev-parse", "HEAD"),
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "all_policy_ok": all(result["policy_ok"] for result in results.values()),
        "cases": results,
    }
    output.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "label": authority["label"],
                "mode": authority["mode"],
                "source_commit": authority["source_commit"],
                "testcases_commit": authority["testcases_commit"],
                "all_policy_ok": authority["all_policy_ok"],
            },
            sort_keys=True,
        )
    )
    return 0 if authority["all_policy_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
