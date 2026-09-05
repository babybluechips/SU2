# Targeted Linux ARM64 preflight

This temporary workflow provides pre-merge, native Linux ARM64 evidence for
SU2 PRs 2880 through 2885. It does not replace or satisfy the upstream
repository's protected checks.

## Safety and trigger boundary

- The workflow runs only on a push to
  `ci/arm64-pr2880-2885-20260905`.
- It has only `contents: read` permission and persists no checkout credential.
- It accepts no event payload, pull-request code, secret, or free-form input.
- The manifest must contain eight fully resolved, hash-bound targets. Any
  `__FINAL_*__` placeholder stops the `prepare` job before an ARM runner starts.
- The source under test is checked out by full commit SHA, separately from the
  CI-control commit containing these scripts.

## Final identity seal

Before the temporary branch is committed or pushed, rederive the identity
triple for every PR head that changed during review and for both cumulative
stages in `.github/arm64-preflight/targets.json`. Update each corresponding
`source_heads` binding at the same time.

For each target, derive the values from the SU2 repository without abbreviating
them:

```bash
target=<full-commit-sha>
base=07aa46b1868655ec01f534bf3ac84ba5fbb6b822
git rev-parse "$target"
git rev-parse "$target^{tree}"
git diff --no-ext-diff --no-textconv --no-renames \
  --binary --full-index --src-prefix=a/ --dst-prefix=b/ \
  "$base..$target" | sha256sum
```

Then validate locally. The first command checks the current placeholder form;
the second must pass before any push:

```bash
python3 ci/arm64_preflight/validate_targets.py \
  --allow-placeholders .github/arm64-preflight/targets.json
python3 ci/arm64_preflight/validate_targets.py \
  .github/arm64-preflight/targets.json
```

The branch must contain S2 and S3 in its reachable history when pushed so an
exact-SHA checkout can fetch them from the fork. Use GitHub Desktop for the
commit and push.

## Execution model

The generated matrix contains six exact PR jobs and cumulative S2/S3 jobs.
Every exact PR builds natively on `ubuntu-24.04-arm`; all six run the complete
normal unit driver, and PRs with focused tests run that selection again for a
small, direct log. PR 2880 runs the retained three-case solver-launch
acceptance/rejection matrix for freestream mass fractions. PR 2881 additionally
receives a real SIGTERM and must print the interrupt-specific exit message
without the false convergence message.

PRs 2883 through 2885 and S2/S3 run only their affected NEMO cases against
TestCases commit `01b80cf2edfc69b7a545368747bd511c6d732aec`.
Each case receives an isolated copy of the data. If an older configuration
would write its output restart over its input restart, the harness redirects
only that output filename and records both configuration hashes.

`vector_policy: harvest` requires a bounded successful run and records the
computed row plus a proposed `test_vals_aarch64` assignment; stale or missing
ARM expectations are reported but do not hide the solver result. After those
assignments are committed to the relevant PR branches, update their head/tree/
diff identities, change the exact PR targets to `vector_policy: verify`, and
rerun. Verify mode also requires the checked-in effective ARM vector to match
within the case's declared ARM/default tolerance.

Artifacts include source, tree, diff, workflow, submodule, TestCases, toolchain,
input, binary, configuration, solver-log, and whole-evidence SHA-256 receipts.
