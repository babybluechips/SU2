#!/usr/bin/env python3
"""Verify that a SIGTERM exit is not reported as physical convergence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXPECTED = "Interrupt signal received, exiting before the convergence criteria were satisfied."
FORBIDDEN = "All convergence criteria satisfied."


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
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path = output.with_suffix(".log")

    with tempfile.TemporaryDirectory(prefix="su2-arm64-interrupt-") as temporary:
        run_dir = Path(temporary) / "QuickStart"
        shutil.copytree(source / "QuickStart", run_dir)
        config = run_dir / "inv_NACA0012.cfg"
        mesh = run_dir / "mesh_NACA0012_inv.su2"
        original_config_sha = sha256(config)
        config_text = config.read_text(encoding="utf-8")
        config_text = replace_option(config_text, "ITER", "100000")
        config_text = replace_option(config_text, "CONV_RESIDUAL_MINVAL", "-100")
        if re.search(r"^\s*OUTPUT_WRT_FREQ\s*=", config_text, re.MULTILINE):
            config_text = replace_option(config_text, "OUTPUT_WRT_FREQ", "100000")
        config.write_text(config_text, encoding="utf-8")
        executed_config_sha = sha256(config)
        mesh_sha_before = sha256(mesh)

        environment = os.environ.copy()
        environment.update(OMP_NUM_THREADS="1")
        started = time.monotonic()
        marker_seen = False
        sent_signal = False
        forced_kill = False
        with log_path.open("w", encoding="utf-8") as log_stream:
            process = subprocess.Popen(
                [str(binary), config.name],
                cwd=run_dir,
                env=environment,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                text=True,
            )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                log_stream.flush()
                current = log_path.read_text(encoding="utf-8", errors="replace")
                if "Begin Solver" in current:
                    marker_seen = True
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.25)

            if marker_seen and process.poll() is None:
                time.sleep(0.5)
                process.send_signal(signal.SIGTERM)
                sent_signal = True

            try:
                return_code = process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait(timeout=30)
                forced_kill = True
        mesh_sha_after = sha256(mesh)

    duration = time.monotonic() - started
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    checks = {
        "solver_started": marker_seen,
        "sigterm_sent": sent_signal,
        "no_forced_kill": not forced_kill,
        "zero_exit": return_code == 0,
        "exit_success": "Exit Success" in log_text,
        "interrupt_message_present": EXPECTED in log_text,
        "false_convergence_message_absent": FORBIDDEN not in log_text,
        "mesh_input_unchanged": mesh_sha_before == mesh_sha_after,
    }
    authority = {
        "schema_version": 1,
        "source_commit": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip(),
        "machine": os.uname().machine,
        "binary_sha256": sha256(binary),
        "original_config_sha256": original_config_sha,
        "executed_config_sha256": executed_config_sha,
        "mesh_sha256": mesh_sha_before,
        "return_code": return_code,
        "duration_seconds": round(duration, 3),
        "expected_message": EXPECTED,
        "forbidden_message": FORBIDDEN,
        "checks": checks,
        "passed": all(checks.values()),
        "log_sha256": sha256(log_path),
    }
    output.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n")
    print(json.dumps(authority, indent=2, sort_keys=True))
    return 0 if authority["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
