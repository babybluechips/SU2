# Focused PR2885 review CI draft

These files belong on the separate `ci/pr2885-review-20260907` branch of
`babybluechips/SU2`, not on the PR branch. Copy `.github/workflows/pr2885-review.yml`
and `ci/pr2885_review/` to the same paths on that branch. No workflow has been
launched by preparing this draft.

Before publishing, fill the three `__FINAL_...__` fields in `target.json` from the
new committed PR revision. Unbound values fail the prepare job before either build
starts. Derive the exact values using the PR worktree:

```sh
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git diff --no-ext-diff --no-textconv --no-renames --binary --full-index \
  --src-prefix=a/ --dst-prefix=b/ \
  07aa46b1868655ec01f534bf3ac84ba5fbb6b822..HEAD | shasum -a 256
```

Run `python3 -B ci/pr2885_review/run_review.py validate --manifest
ci/pr2885_review/target.json` after binding. The source revision, tree, complete
PR diff, submodules and tracked source cleanliness are checked before and after
the workload. The CI control revision does not replace the solver revision.

## Builds

Two independent Linux x86 jobs use the official image tag from this revision's
upstream workflow, `ghcr.io/su2code/su2/build-su2:260405-0054`. The workflow records
the resolved image ID/digests and actual compiler versions. Its entrypoint is
overridden: the image's usual `-b` entrypoint clones `su2code/SU2` and cannot
reliably build a new commit that exists only in the fork. Here it builds the
separately checked-out, fully pinned source directly.

The NoMPI build enables OpenBLAS and uses `cpu-arch=skylake`, matching the relevant
upstream serial settings. The MPI build uses the upstream normal MPI options,
with MPI explicitly required. Both retain the normal solver, tests, Python
wrapper and MLPCpp options; MPI also retains CoolProp and Mutation++. Both use
release optimization and disable OpenMP. No solver source or tolerance is changed.
Only the normal solver and unit target are built; this is not the entire official
installation or upstream protected CI. The image tag is recorded, not claimed
immutable before its runtime digest is known. Missing image dependencies fail the
job rather than silently switching compiler or build recipe.

Each job uses two build jobs/two CPU cores and 7 GiB memory. The workload deadline
is 90 minutes, with individual configure/build/unit/case bounds and shutdown time
reserved; the GitHub job limit is 110 minutes. A hung child is terminated within
its own session. `TestCase.Command.killall` is specialized only for that timeout
cleanup because the upstream implementation searches all processes by name.
The actual pinned `TestCase.run_test`, parsing and comparison implementation are
used unchanged.

## Checks and evidence

Both builds run the full normal unit driver, without a test filter. Catch writes
its own report file as well as retaining wrapper stdout, so a test that redirects
`std::cout` cannot hide the final unit result. The serial
build runs actual `TestCase.run_test` for `visc_cone`. The MPI build runs that
method with two ranks for `visc_cone`, `super_cat`, and two independent executions
of `ion_gy`. Definitions and default tolerance/timeout semantics are read from the
pinned regression files. The ion target is iteration 99, matching the proposed
consolidated checked-in case. Each attempt has a new copy of the data from
TestCases commit `01b80cf2edfc69b7a545368747bd511c6d732aec`; both ion runs start from
the same pristine `restart_flow_gy.dat`. Neither run starts from the other's output.
The original config is preserved alongside the `.autotest` config produced by
`TestCase.adjust_iter`. Input seeds, original configs, meshes, source and binaries
are checked again after execution.

No expected vectors are harvested or overwritten. The effective checked-in
default is compared at its unchanged tolerance, including the ion case's existing
0.01 tolerance. Both ion repetitions must pass independently and retain their
identical original seed. The printed target rows must also repeat identically,
as a separate, explicitly registered repeatability check. This does not alter the
checked-in TestCase tolerances or label a failed vector comparison passing. A
supplemental finite-row check prevents NaN comparisons from appearing to pass.

Artifacts include every actual test log and case working directory, successful
and failed results, inputs and seed hashes, original/effective configs, compiler
and image metadata, Meson options, compilation commands, binary hashes, source
identity/diff and selected regression/TestCase source. The workflow closes the
container log before indexing all captured files and always attempts artifact
upload. Infrastructure failure or GitHub cancellation can leave partial evidence;
the final index is custody evidence and never a claim that tests passed. No
credentials, environment dump, controllers from earlier campaigns, or executable
binaries are included in the artifact.

An archived direct launch of an MPI-enabled binary previously missed the serial
`visc_cone` default by up to 1.7e-5. That build had OpenBLAS disabled. This draft
tests the relevant NoMPI/OpenBLAS combination before recommending any baseline
change. Regression agreement is distinct from iterative convergence, robustness,
physical validation, and maintainer approval of upstream CI.
