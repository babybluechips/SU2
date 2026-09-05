#!/usr/bin/env python3
"""Validate the fixed ARM64 preflight target manifest."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"^__FINAL_[A-Z0-9_]+__$")
CASES = {
    "invwedge_ausm",
    "invwedge_msw",
    "invwedge_roe",
    "invwedge_lax",
    "invwedge_ss_inlet",
    "visc_cone",
    "super_cat",
    "ion_gy",
    "ion_gy_march",
}
TARGET_FIELDS = {
    "id",
    "kind",
    "pr",
    "sha",
    "tree",
    "diff_sha256",
    "source_heads",
    "run_unit",
    "unit_filter",
    "run_interrupt",
    "run_massfrac",
    "harvest",
    "vector_policy",
    "serial_cases",
    "mpi_cases",
}


def check_identity(value: str, pattern: re.Pattern[str], allow_placeholders: bool) -> bool:
    return bool(pattern.fullmatch(value)) or (
        allow_placeholders and bool(PLACEHOLDER.fullmatch(value))
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--allow-placeholders", action="store_true")
    args = parser.parse_args()
    document = json.loads(args.manifest.read_text(encoding="utf-8"))
    errors: list[str] = []

    if document.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if document.get("trigger_branch") != "ci/arm64-pr2880-2885-20260905":
        errors.append("unexpected trigger_branch")
    for field in ("base_sha", "testcases_sha"):
        if not check_identity(str(document.get(field, "")), SHA40, False):
            errors.append(f"{field} must be a full lowercase commit SHA")

    targets = document.get("targets")
    if not isinstance(targets, list) or len(targets) != 8:
        errors.append("targets must contain exactly six PRs plus S2 and S3")
        targets = targets if isinstance(targets, list) else []
    ids = [target.get("id") for target in targets if isinstance(target, dict)]
    expected_ids = {
        "pr2880",
        "pr2881",
        "pr2882",
        "pr2883",
        "pr2884",
        "pr2885",
        "s2",
        "s3",
    }
    if set(ids) != expected_ids or len(ids) != len(set(ids)):
        errors.append("target IDs must be unique and exactly pr2880..pr2885,s2,s3")

    for target in targets:
        if not isinstance(target, dict):
            errors.append("each target must be an object")
            continue
        target_id = str(target.get("id", "<missing>"))
        missing = sorted(TARGET_FIELDS - set(target))
        if missing:
            errors.append(f"{target_id}: missing fields {','.join(missing)}")
        if target.get("kind") not in {"pr", "stage"}:
            errors.append(f"{target_id}: kind must be pr or stage")
        if target.get("vector_policy") not in {"harvest", "verify"}:
            errors.append(f"{target_id}: vector_policy must be harvest or verify")
        for field in ("run_unit", "run_interrupt", "run_massfrac", "harvest"):
            if not isinstance(target.get(field), bool):
                errors.append(f"{target_id}: {field} must be boolean")
        for field in ("sha", "tree"):
            if not check_identity(str(target.get(field, "")), SHA40, args.allow_placeholders):
                errors.append(f"{target_id}: {field} must be a full SHA")
        if not check_identity(
            str(target.get("diff_sha256", "")),
            SHA256,
            args.allow_placeholders,
        ):
            errors.append(f"{target_id}: diff_sha256 must be a SHA-256")
        bindings: dict[str, str] = {}
        for binding in str(target.get("source_heads", "")).split(","):
            try:
                number, commit = binding.split("=", maxsplit=1)
            except ValueError:
                errors.append(f"{target_id}: malformed source_heads binding {binding!r}")
                continue
            if not re.fullmatch(r"288[0-5]", number):
                errors.append(f"{target_id}: unexpected source PR {number!r}")
            if not check_identity(commit, SHA40, args.allow_placeholders):
                errors.append(f"{target_id}: source head for {number} is not a full SHA")
            if number in bindings:
                errors.append(f"{target_id}: duplicate source head for {number}")
            bindings[number] = commit
        if target.get("kind") == "pr":
            expected_number = str(target.get("pr", ""))
            if bindings != {expected_number: str(target.get("sha", ""))}:
                errors.append(f"{target_id}: PR source_heads must bind its exact target SHA")
        elif target_id == "s2" and set(bindings) != {"2883", "2884"}:
            errors.append("s2: source_heads must bind PRs 2883 and 2884")
        elif target_id == "s3" and set(bindings) != {"2883", "2884", "2885"}:
            errors.append("s3: source_heads must bind PRs 2883, 2884, and 2885")
        for mode in ("serial", "mpi"):
            selected = {value for value in str(target.get(f"{mode}_cases", "")).split(",") if value}
            unknown = selected - CASES
            if unknown:
                errors.append(f"{target_id}: unknown {mode} cases {','.join(sorted(unknown))}")
        if target.get("harvest") and not (target.get("serial_cases") or target.get("mpi_cases")):
            errors.append(f"{target_id}: harvest target has no cases")
        if not target.get("harvest") and (target.get("serial_cases") or target.get("mpi_cases")):
            errors.append(f"{target_id}: non-harvest target lists cases")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "target_count": len(targets),
                "placeholders_allowed": args.allow_placeholders,
                "status": "valid",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
