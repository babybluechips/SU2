#!/usr/bin/env python3
"""Prepared PR2884 integration controls using the established Linux review harness.

validate/bind/check-public-state/seal perform no builds or solver launches.
run preserves the selected source's TestCase.run_test logic and tolerances.
"""
import argparse
import ast
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
import traceback

BASE = "8118ee0f507b5fb0fd70b819e6f1351c1b3c6d28"
PUBLIC_PR_HEAD = "91a43fc61048dd853138545ca69ec5060cef6cd1"
DATA = "01b80cf2edfc69b7a545368747bd511c6d732aec"
IMAGE = "ghcr.io/su2code/su2/build-su2:260405-0054"
SELECTIONS = {
    "nompi": ["invwedge", "visc_cone"],
    "mpi": ["invwedge_a", "invwedge_ap2", "invwedge_msw", "invwedge_roe",
            "invwedge_lax", "invwedge_ausm_m", "invwedge_ss_inlet",
            "visc_cone", "super_cat", "partial_cat", "ion_gy"],
}
CASE_CONFIGS = {
    "invwedge": "invwedge_ausm.cfg", "invwedge_a": "invwedge_ausm.cfg",
    "invwedge_ap2": "invwedge_ausmplusup2.cfg", "invwedge_msw": "invwedge_msw.cfg",
    "invwedge_roe": "invwedge_roe.cfg", "invwedge_lax": "invwedge_lax.cfg",
    "invwedge_ausm_m": "invwedge_am.cfg", "invwedge_ss_inlet": "invwedge_ss_inlet.cfg",
    "visc_cone": "axi_visccone.cfg", "super_cat": "super_cat.cfg",
    "partial_cat": "partial_cat.cfg", "ion_gy": "cyl_ion_gy.cfg",
}
CASE_DIRS = {name: ("nonequilibrium/invwedge" if name.startswith("invwedge") else
                   "nonequilibrium/visc_cylinder" if name == "ion_gy" else
                   "nonequilibrium/visc_wedge") for name in CASE_CONFIGS}
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


def final_binary_hashes(source, before):
    after, errors = {}, {}
    for name in before or {}:
        try:
            after[name] = sha(source / name)
        except Exception as exc:
            errors[name] = str(exc)
    return after, errors


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


def verify_source_parents(parents, target):
    expected = [target["public_pr_head_sha"], BASE]
    require(parents == expected, "source must be the two-parent merge of the registered PR head and develop, in that order")
    return expected


def verify_public_state(pr, develop, target):
    require(str(pr["number"]) == "2884" and pr["state"] == "open"
            and pr["head_repository"] == "babybluechips/SU2"
            and pr["head_sha"] == target["public_pr_head_sha"],
            "public PR2884 head changed or closed")
    require(develop["ref"] == "refs/heads/develop" and develop["type"] == "commit"
            and develop["sha"] == BASE, "public develop ref changed")
    # GitHub may retain an older base.sha on the PR object. The separately read
    # git/ref/heads/develop is the authority for the current develop revision.
    return {"public_pr_head_sha": pr["head_sha"], "develop_ref_sha": develop["sha"],
            "pr_base_sha_recorded_not_used": pr.get("base_sha"),
            "prepared_source_sha": target["source_sha"]}


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
    parents = git(source, "show", "-s", "--format=%P", "HEAD").split()
    verify_source_parents(parents, target)
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
        "source_parents": parents,
        "base_sha": BASE,
        "registered_public_pr_head_sha": target["public_pr_head_sha"],
        "diff_sha256": target["source_diff_sha256"],
        "testcases_sha": DATA,
        "submodules": modules.splitlines(),
    }, patch


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


def build_environment(source, submodules):
    # Meson's own Git subprocesses must trust only these verified mounted paths.
    source = source.resolve()
    paths = [source]
    for line in submodules:
        match = re.fullmatch(r" ?[0-9a-f]{40} (\S+)(?: \([^\n]*\))?", line)
        require(match is not None, "invalid submodule path record")
        relative = Path(match[1])
        require(
            not relative.is_absolute() and ".." not in relative.parts,
            "submodule path escapes source",
        )
        path = source / relative
        require(
            path.is_dir() and path.resolve() == path and path != source,
            "submodule path is missing, aliased or outside source",
        )
        paths.append(path)
    environment = os.environ.copy()
    for key in list(environment):
        if key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS") or re.fullmatch(
            r"GIT_CONFIG_(KEY|VALUE)_\d+", key
        ):
            del environment[key]
    environment["GIT_CONFIG_COUNT"] = str(len(paths))
    for index, path in enumerate(paths):
        environment["GIT_CONFIG_KEY_" + str(index)] = "safe.directory"
        environment["GIT_CONFIG_VALUE_" + str(index)] = str(path)
    return environment, [str(path) for path in paths]


def bounded(command, cwd, log, seconds, env=None):
    if DEADLINE is not None:
        seconds = min(seconds, int(DEADLINE - time.monotonic() - 45))
    require(seconds > 0, "workload deadline reached")
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    print("Starting captured command: " + shlex.join(command), flush=True)
    with log.open("w") as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
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
    result = {
        "command": command,
        "returncode": code,
        "timed_out": timed_out,
        "unexpected_surviving_children": survivors,
        "owned_session_quiescent": True,
        "clean_exit": code == 0 and not timed_out and not survivors,
        "wall_seconds": round(time.monotonic() - started, 3),
        "log_sha256": sha(log),
    }
    print(
        "Captured command completed: returncode=%d timed_out=%s log=%s"
        % (code, timed_out, log),
        flush=True,
    )
    return result


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
    processes = []

    class RecordedPopen(module.subprocess.Popen):
        def __init__(self, *argv, **kwargs):
            super().__init__(*argv, **kwargs)
            processes.append(self)

    module.subprocess.Popen = RecordedPopen
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
            "solver_returncode": processes[0].returncode if processes else None,
        },
    )
    return 0 if passed else 1


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


def manifest(path, selected):
    value = json.loads(Path(path).read_text())
    require(value["schema"] == "su2-pr2884-prepared-integration-ci.v1", "wrong manifest schema")
    require(value["repository"] == "babybluechips/SU2", "unexpected repository")
    require(value["base_sha"] == BASE and value["testcases_sha"] == DATA, "wrong base/data")
    require(value["image"] == IMAGE, "wrong official image")
    for name, expected in (("build_jobs", 2), ("configure_timeout_seconds", 600),
                           ("build_timeout_seconds", 1800), ("unit_timeout_seconds", 300),
                           ("case_timeout_seconds", 1600), ("job_workload_timeout_seconds", 4800),
                           ("repeats", 2)):
        require(value[name] == expected, "unregistered resource or repeat bound: " + name)
    require(set(value["targets"]) == {"2884"}, "only PR2884 is authorized")
    require(value["targets"]["2884"]["public_pr_head_sha"] == PUBLIC_PR_HEAD,
            "changed registered public PR head")
    for pr in selected:
        require(pr in value["targets"], "unregistered PR")
        for key, width in (("source_sha", 40), ("source_tree", 40), ("source_diff_sha256", 64)):
            entry = value["targets"][pr][key]
            require(isinstance(entry, str) and re.fullmatch("[0-9a-f]{%d}" % width, entry),
                    "unbound/invalid PR " + pr + " " + key)
        require(value["targets"][pr]["source_sha"] != BASE, "target cannot equal the base")
    return value


def bind(args):
    """Bind local clean committed source into the control manifest, without changing Git."""
    source = Path(args.source).resolve()
    require(re.fullmatch("[0-9a-f]{40}", args.source_sha), "exact source SHA required")
    require(git(source, "rev-parse", "HEAD") == args.source_sha, "HEAD differs from requested SHA")
    require(not git(source, "status", "--porcelain=v1", "--untracked-files=no"), "source is dirty")
    require(git(source, "merge-base", BASE, "HEAD") == BASE, "registered base is not ancestor")
    patch = subprocess.check_output([
        "git", "-C", str(source), "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
        "--binary", "--full-index", "--src-prefix=a/", "--dst-prefix=b/", BASE + "..HEAD"])
    value = manifest(args.manifest, [])
    verify_source_parents(git(source, "show", "-s", "--format=%P", "HEAD").split(),
                          value["targets"][args.pr])
    value["targets"][args.pr].update({"source_sha": args.source_sha,
                                    "source_tree": git(source, "rev-parse", "HEAD^{tree}"),
                                    "source_diff_sha256": hashlib.sha256(patch).hexdigest()})
    save(args.manifest, value)
    print("Bound control manifest only:", args.pr, args.source_sha)


def definitions(source, mode):
    script = source / "TestCases" / ("serial_regression.py" if mode == "nompi" else "parallel_regression.py")
    text = script.read_text()
    require(re.search(r"if test\.tol == 0\.0:\s*test\.tol = 0\.00001", text), "changed default tolerance")
    require(re.search(r"if test\.timeout == 0:\s*test\.timeout = 1600", text), "changed default timeout")
    allowed = {"cfg_dir", "cfg_file", "test_iter", "test_vals", "test_vals_aarch64", "tol",
               "tol_aarch64", "timeout", "new_output", "unsteady", "multizone", "no_restart",
               "enabled_on_cpu_arch"}
    found = {case: {} for case in SELECTIONS[mode]}
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        lhs = node.targets[0]
        if isinstance(lhs, ast.Attribute) and isinstance(lhs.value, ast.Name) and lhs.value.id in found:
            require(lhs.attr in allowed, "unsupported selected-case option: " + lhs.attr)
            require(lhs.attr not in found[lhs.value.id], "duplicate selected-case assignment")
            found[lhs.value.id][lhs.attr] = ast.literal_eval(node.value)
    for case, item in found.items():
        require({"cfg_dir", "cfg_file", "test_iter", "test_vals"}.issubset(item), "missing definition: " + case)
        require(item["cfg_dir"] == CASE_DIRS[case] and item["cfg_file"] == CASE_CONFIGS[case], "changed case input")
        require(item["test_iter"] == (99 if case == "ion_gy" else 10), "changed target iteration")
        require(item.get("tol", 0.0) == (0.01 if case == "ion_gy" else 0.0), "changed case tolerance")
        require(item.get("tol_aarch64", 0.0) == 0.0, "unregistered ARM tolerance override")
        require(not item.get("no_restart", False), "restart contract changed")
    return script, found


def target_row(log, iteration, width):
    active, found = False, []
    for line in log.read_text(errors="replace").splitlines():
        active = active or "Begin Solver" in line
        if not active or not line.strip().startswith("|"):
            continue
        fields = [part.strip() for part in line.strip()[1:-1].split("|")]
        try:
            if int(fields[0]) != iteration:
                continue
            row = [float(part) for part in fields[-width:]]
        except (ValueError, IndexError):
            continue
        require(len(row) == width and all(math.isfinite(part) for part in row), "nonfinite/malformed target row")
        found.append(row)
    require(len(found) == 1, "target row absent or duplicated")
    return found[0]


def run_case(source, data, binary, evidence, mode, case, repeat, definition, environment):
    folder = evidence / "cases" / (case + "-r" + str(repeat))
    folder.mkdir(parents=True, exist_ok=False)
    shutil.copytree(data / CASE_DIRS[case], folder, dirs_exist_ok=True)
    config = source / "TestCases" / CASE_DIRS[case] / CASE_CONFIGS[case]
    shutil.copy2(config, folder / config.name)
    options = config_values(config)
    expected_mesh = "invwedge.su2" if case.startswith("invwedge") else "visc_cyl.su2" if case == "ion_gy" else "viscwedge.su2"
    require(options["MESH_FILENAME"] == expected_mesh, "unexpected mesh")
    require(options["RESTART_SOL"] == ("YES" if case == "ion_gy" else "NO"), "wrong initialization")
    inputs = tree_files(folder)
    seed = folder / "restart_flow_gy.dat" if case == "ion_gy" else None
    if seed:
        require(seed.is_file() and options["SOLUTION_FILENAME"] == "restart_flow_gy", "missing/wrong ion seed")
        require(options["RESTART_FILENAME"] != "restart_flow_gy", "solver would overwrite the seed")
        seed.chmod(0o444)
    spec_path = evidence / "specs" / (case + "-r" + str(repeat) + ".json")
    save(spec_path, {"case": case, "mode": mode, "definition": definition,
                     "source": str(source), "folder": str(folder), "binary": str(binary)})
    execution = bounded([sys.executable, "-B", str(Path(__file__).resolve()), "case-child", "--spec", str(spec_path)],
                        evidence, folder / "testcase-driver.log", 1620, env=environment)
    unchanged = all((folder / name).is_file() and sha(folder / name) == entry["sha256"]
                    for name, entry in inputs.items())
    receipt = folder / "testcase-result.json"
    reported = json.loads(receipt.read_text()) if receipt.exists() else {}
    row, error = None, None
    try:
        row = target_row(folder / (config.name + ".log"), definition["test_iter"], len(definition["test_vals"]))
        actual_config = folder / reported["executed_config"]
        expected_options = dict(options, ITER=str(definition["test_iter"] + 1))
        require(config_values(actual_config) == expected_options, "autotest changed options beyond ITER")
    except Exception as exc:
        error = str(exc)
    expected = reported.get("effective_test_values")
    differences = [abs(a - b) for a, b in zip(row, expected)] if row is not None and expected is not None else None
    result = {"case": case, "repeat": repeat, "mode": mode, "execution": execution,
              "inputs_before": inputs, "inputs_unchanged": unchanged,
              "source_config_sha256": sha(config), "testcase": reported,
              "solver_execution_clean": (reported.get("solver_returncode") == 0
                  and not execution["timed_out"] and not execution["unexpected_surviving_children"]),
              "computed_target_row": row, "absolute_differences": differences,
              "supplemental_row_or_config_error": error,
              "seed_before_sha256": inputs.get("restart_flow_gy.dat", {}).get("sha256"),
              "seed_after_sha256": sha(seed) if seed and seed.exists() else None,
              "pass": execution["clean_exit"] and unchanged and reported.get("testcase_run_test_pass") is True and error is None}
    save(folder / "case-receipt.json", result)
    print("Captured row:", json.dumps({key: result[key] for key in
          ("case", "repeat", "mode", "computed_target_row", "absolute_differences", "pass")}), flush=True)
    return result


def toolchain(evidence):
    result = {}
    result["cpu_identity"] = {"machine": platform.machine(), "logical_cpus": os.cpu_count(),
                              "kernel": platform.uname()._asdict(),
                              "proc_cpuinfo": Path("/proc/cpuinfo").read_text()}
    for command in (["cc", "--version"], ["c++", "--version"], ["mpirun", "--version"],
                    [sys.executable, "--version"], ["pkg-config", "--modversion", "openblas"]):
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        result[shlex.join(command)] = {"returncode": process.returncode, "output": process.stdout}
    save(evidence / "toolchain.json", result)


def run_mode(source, data, evidence, target, mode, arch, build_env):
    evidence.mkdir(parents=True, exist_ok=False)
    outcome = {"mode": mode, "architecture": arch, "pass": False, "cases": []}
    binary_hashes = None
    try:
        script, cases = definitions(source, mode)
        for path in (script, source / "TestCases/TestCase.py"):
            shutil.copy2(path, evidence / path.name)
        save(evidence / "case-definitions.json", cases)
        build = source / ("build-pr-refresh-" + mode)
        require(not build.exists(), "build directory exists")
        flags = ["--buildtype=release", "--prefix=" + str(source / ("install-pr-refresh-" + mode)),
                 "-Dcpu-arch=" + ("skylake" if arch == "x86_64" else "armv9-a+simd"),
                 "-Denable-tests=true", "-Denable-pywrapper=true", "-Denable-mlpcpp=true", "-Dwith-omp=false"]
        if mode == "nompi":
            flags += ["-Dwith-mpi=disabled", "-Denable-openblas=true", "--warnlevel=3"]
        else:
            flags += ["-Dwith-mpi=enabled", "-Denable-coolprop=true", "-Denable-mpp=true", "-Dinstall-mpp=true", "--warnlevel=2"]
        save(evidence / "build-request.json", {"flags": flags, "jobs": 2, "image": IMAGE,
             "scope": "normal CFD and full normal units; no AD/DD, no optional dependency fallback"})
        setup = bounded([sys.executable, "meson.py", "setup", str(build), *flags], source,
                        evidence / "build/configure.log", target["configure_timeout_seconds"], env=build_env)
        outcome["configure"] = setup
        meson_log = build / "meson-logs/meson-log.txt"
        if meson_log.is_file():
            shutil.copy2(meson_log, evidence / "build/meson-log.txt")
        require(setup["clean_exit"], "configuration failed; dependencies are not silently disabled")
        compile_result = bounded([str(source / "ninja"), "-C", str(build), "-j", "2",
                                  "SU2_CFD/src/SU2_CFD", "UnitTests/test_driver"], source,
                                 evidence / "build/compile.log", target["build_timeout_seconds"], env=build_env)
        outcome["build"] = compile_result
        for name in ("intro-buildoptions.json", "intro-compilers.json", "intro-machines.json", "intro-dependencies.json"):
            path = build / "meson-info" / name
            if path.is_file():
                shutil.copy2(path, evidence / "build" / name)
        if (build / "compile_commands.json").is_file():
            shutil.copy2(build / "compile_commands.json", evidence / "build/compile_commands.json")
        require(compile_result["clean_exit"], "build failed")
        options = {item["name"]: item["value"] for item in json.loads((build / "meson-info/intro-buildoptions.json").read_text())}
        require(options["with-mpi"] == ("disabled" if mode == "nompi" else "enabled"), "wrong MPI mode")
        require(options["enable-tests"] and options["enable-mlpcpp"] and not options["with-omp"]
                and not options["enable-autodiff"] and not options["enable-directdiff"], "wrong normal unit configuration")
        require(options["enable-openblas"] if mode == "nompi" else options["enable-mpp"] and options["enable-coolprop"],
                "required dependency is disabled")
        binary, driver = build / "SU2_CFD/src/SU2_CFD", build / "UnitTests/test_driver"
        binary_hashes = {str(path.relative_to(source)): sha(path) for path in (binary, driver)}
        save(evidence / "binary-hashes.json", binary_hashes)
        environment = build_env.copy()
        loader = {}
        if mode == "mpi":
            libraries = sorted({path.parent.resolve() for path in build.rglob("libmutation*.so*") if path.is_file()})
            require(libraries, "Mutation++ was enabled but its shared library was not found")
            environment["LD_LIBRARY_PATH"] = ":".join(str(path) for path in libraries)
            if build_env.get("LD_LIBRARY_PATH"):
                environment["LD_LIBRARY_PATH"] += ":" + build_env["LD_LIBRARY_PATH"]
            environment["MPP_DATA_DIRECTORY"] = str(source / "subprojects/Mutationpp/data")
            loader["scoped_Mutationpp_library_directories"] = [str(path) for path in libraries]
            loader["MPP_DATA_DIRECTORY"] = environment["MPP_DATA_DIRECTORY"]
        for label, path in (("solver", binary), ("unit_driver", driver)):
            for env_label, selected_env in (("build_environment", build_env), ("explicit_runtime_environment", environment)):
                check = subprocess.run(["ldd", str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, timeout=30, env=selected_env)
                loader[label + "_" + env_label] = {"returncode": check.returncode, "output": check.stdout}
                if env_label == "explicit_runtime_environment":
                    require(check.returncode == 0 and "not found" not in check.stdout, "unresolved runtime dependency")
        save(evidence / "runtime-loader.json", loader)
        # Same full normal suite as upstream, with no Catch filters or exclusions.
        layout = evidence.parent.parent.parent / ("unit-layout-" + mode)
        (layout / "src").mkdir(parents=True, exist_ok=False)
        (layout / "src/SU2").symlink_to(source, target_is_directory=True)
        report = evidence / "tests/full-normal-unit.catch.log"
        unit = bounded([str(driver), "--out", str(report)], layout,
                       evidence / "tests/full-normal-unit.stdout.log", target["unit_timeout_seconds"], env=environment)
        unit["catch_report_sha256"] = sha(report) if report.is_file() else None
        outcome["unit"] = unit
        for case in SELECTIONS[mode]:
            for repeat in range(1, target["repeats"] + 1):
                try:
                    result = run_case(source, data, binary, evidence, mode, case, repeat, cases[case], environment)
                except Exception as exc:
                    result = {"case": case, "repeat": repeat, "mode": mode, "pass": False, "error": str(exc)}
                    save(evidence / "case-errors" / (case + "-r" + str(repeat) + ".json"), result)
                outcome["cases"].append(result)
                save(evidence / "result.json", outcome)
        repeatability = {}
        for case in SELECTIONS[mode]:
            pair = [item for item in outcome["cases"] if item["case"] == case]
            equal_rows = (len(pair) == 2 and pair[0].get("computed_target_row") is not None
                          and pair[0].get("computed_target_row") == pair[1].get("computed_target_row"))
            equal_seeds = (case != "ion_gy" or len(pair) == 2
                           and pair[0].get("seed_before_sha256") is not None
                           and pair[0].get("seed_before_sha256") == pair[1].get("seed_before_sha256"))
            repeatability[case] = {"printed_rows_identical": equal_rows, "pristine_seeds_equal": equal_seeds}
        outcome["repeatability"] = repeatability
        outcome["execution_and_integrity_pass"] = (unit["clean_exit"] and report.exists()
            and all(item.get("solver_execution_clean") and item.get("inputs_unchanged")
                    and item.get("computed_target_row") is not None
                    and item.get("supplemental_row_or_config_error") is None for item in outcome["cases"]))
        outcome["reference_comparison_pass"] = all(item["pass"] for item in outcome["cases"])
        outcome["repeatability_pass"] = all(item["printed_rows_identical"] and item["pristine_seeds_equal"]
                                             for item in repeatability.values())
        outcome["pass"] = (outcome["execution_and_integrity_pass"] and outcome["reference_comparison_pass"]
                           and outcome["repeatability_pass"])
    except Exception as exc:
        outcome["error"] = str(exc)
        (evidence / "failure-traceback.txt").write_text(traceback.format_exc())
    finally:
        after, hash_errors = final_binary_hashes(source, binary_hashes)
        save(evidence / "binary-hashes-after.json", after)
        if hash_errors:
            save(evidence / "binary-hashes-after-errors.json", hash_errors)
            outcome["binary_hashes_after_errors"] = hash_errors
        outcome["binary_hashes_unchanged"] = bool(binary_hashes) and not hash_errors and after == binary_hashes
        outcome["execution_and_integrity_pass"] = outcome.get("execution_and_integrity_pass", False) and outcome["binary_hashes_unchanged"]
        outcome["pass"] = outcome["pass"] and outcome["binary_hashes_unchanged"]
        save(evidence / "result.json", outcome)
        print("Mode result:", json.dumps({key: value for key, value in outcome.items() if key != "cases"}), flush=True)
    return outcome


def run(args):
    global DEADLINE
    value = manifest(args.manifest, [args.pr])
    target = dict(value, **value["targets"][args.pr])
    DEADLINE = time.monotonic() + target["job_workload_timeout_seconds"]
    source, data, evidence = (Path(path).resolve() for path in (args.source, args.test_data, args.evidence))
    evidence.mkdir(parents=True, exist_ok=True)
    outcome = {"schema": "su2-pr2884-prepared-integration-result.v1", "pr": args.pr, "source_sha": target["source_sha"],
               "architecture": args.arch, "pass": False, "modes": []}
    inputs_before = None
    try:
        require(platform.system() == "Linux", "requires Linux")
        require(platform.machine() in ({"x86_64"} if args.arch == "x86_64" else {"aarch64", "arm64"}), "wrong native architecture")
        authority, patch = source_authority(source, data, target)
        save(evidence / "source-authority.json", authority)
        (evidence / "source.diff").write_bytes(patch)
        inputs_before = {name: tree_files(data / name) for name in sorted(set(CASE_DIRS.values()))}
        save(evidence / "canonical-inputs-before.json", inputs_before)
        build_env, paths = build_environment(source, authority["submodules"])
        save(evidence / "build-git-safe-directories.json", paths)
        toolchain(evidence)
        for mode in ("nompi", "mpi"):
            outcome["modes"].append(run_mode(source, data, evidence / "modes" / mode, target, mode, args.arch, build_env))
            save(evidence / "result.json", outcome)
        outcome["pass"] = all(item["pass"] for item in outcome["modes"])
    except Exception as exc:
        outcome["error"] = str(exc)
        (evidence / "failure-traceback.txt").write_text(traceback.format_exc())
    finally:
        try:
            authority, _ = source_authority(source, data, target)
            save(evidence / "source-authority-after.json", authority)
            after = {name: tree_files(data / name) for name in sorted(set(CASE_DIRS.values()))}
            save(evidence / "canonical-inputs-after.json", after)
            outcome["source_and_canonical_data_unchanged"] = inputs_before is not None and after == inputs_before
            for mode in outcome["modes"]:
                mode["candidate_reference_eligible"] = (mode.get("execution_and_integrity_pass", False)
                    and mode.get("repeatability_pass", False) and outcome["source_and_canonical_data_unchanged"])
            outcome["pass"] = outcome["pass"] and outcome["source_and_canonical_data_unchanged"]
        except Exception as exc:
            outcome["final_integrity_error"] = str(exc)
            outcome["pass"] = False
        outcome["claim_boundary"] = "Prepared PR2884 integration source; public PR remains at its registered earlier head. Supplemental Linux normal units and registered regression comparisons only; no AD/DD, convergence or physical validation, and not upstream protected CI."
        save(evidence / "result.json", outcome)
    return 0 if outcome["pass"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    validate = subs.add_parser("validate")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--prs", choices=["2884"], default="2884")
    validate.add_argument("--architectures", choices=["both"], default="both")
    validate.add_argument("--github-output")
    binding = subs.add_parser("bind")
    for name in ("manifest", "source", "source-sha"):
        binding.add_argument("--" + name, required=True)
    binding.add_argument("--pr", choices=["2884"], required=True)
    head = subs.add_parser("check-public-state")
    for name in ("manifest", "receipt", "develop-receipt"):
        head.add_argument("--" + name, required=True)
    head.add_argument("--pr", choices=["2884"], required=True)
    execution = subs.add_parser("run")
    for name in ("manifest", "source", "test-data", "evidence"):
        execution.add_argument("--" + name, required=True)
    execution.add_argument("--pr", choices=["2884"], required=True)
    execution.add_argument("--arch", choices=["arm64", "x86_64"], required=True)
    child = subs.add_parser("case-child")
    child.add_argument("--spec", required=True)
    sealing = subs.add_parser("seal")
    sealing.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if args.action == "validate":
        prs = ["2884"]
        value = manifest(args.manifest, prs)
        arches = ["arm64", "x86_64"] if args.architectures == "both" else [args.architectures]
        matrix = {"include": [{"pr": pr, "arch": arch, "runner": "ubuntu-24.04-arm" if arch == "arm64" else "ubuntu-24.04",
                               "source_sha": value["targets"][pr]["source_sha"]} for pr in prs for arch in arches]}
        encoded = json.dumps(matrix, separators=(",", ":"))
        if args.github_output:
            with open(args.github_output, "a") as output:
                output.write("matrix=" + encoded + "\n")
        print(encoded)
        return 0
    if args.action == "bind":
        bind(args)
        return 0
    if args.action == "check-public-state":
        target = manifest(args.manifest, [args.pr])["targets"][args.pr]
        pr = json.loads(Path(args.receipt).read_text())
        develop = json.loads(Path(args.develop_receipt).read_text())
        print(json.dumps(verify_public_state(pr, develop, target), sort_keys=True))
        return 0
    if args.action == "run":
        return run(args)
    if args.action == "case-child":
        return case_child(args)
    seal(Path(args.evidence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
