#!/usr/bin/env python3
"""Read-only fetch and bounded execution of prebuilt, digest-bound ramp controls."""
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.parse
import urllib.request
import zipfile

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

def git(repo, *args):
    return subprocess.check_output(
        ["git", "-c", "safe.directory=" + str(repo), "-C", str(repo), *args],
        text=True,
        timeout=60,
    ).strip()

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


def inventory(root, allow_links=False):
    result = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            require(allow_links, "unexpected symlink in inputs/evidence")
            result[relative] = {"link": os.readlink(path)}
        elif path.is_file():
            result[relative] = {"sha256": sha(path), "bytes": path.stat().st_size}
    return result


def manifest(path):
    value = json.loads(Path(path).read_text())
    require(value["schema"] == "su2-ramp-binary-repeat.v1", "wrong schema")
    require(value["repository"] == "su2code/SU2" and set(value["arms"]) == {"develop", "pr2884"}, "wrong source scope")
    require(value["image"] == "ghcr.io/su2code/su2/test-su2:260405-0054", "wrong runtime image")
    require(value["testcases_sha"] == "01b80cf2edfc69b7a545368747bd511c6d732aec", "wrong data")
    require(value["source_config"] == "TestCases/euler/ramp/inv_ramp_msw.cfg", "wrong config")
    for key, expected in (("test_iteration", 100), ("repeats_per_arm", 2),
                           ("workload_timeout_seconds", 480), ("case_timeout_seconds", 120)):
        require(value[key] == expected, "changed numerical/resource scope: " + key)
    for arm in value["arms"].values():
        for key, width in (("source_sha", 40), ("source_tree", 40), ("build_checkout_sha", 40), ("zip_sha256", 64)):
            require(re.fullmatch("[0-9a-f]{%d}" % width, arm[key]), "invalid source/artifact identity")
        require(arm["artifact_id"] > 0 and arm["run_id"] > 0 and 0 < arm["size_in_bytes"] < 200_000_000, "invalid artifact bound")
    return value


class PublicArtifactRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        require(urllib.parse.urlparse(newurl).scheme == "https", "non-HTTPS artifact redirect")
        if urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(request.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


def request(url):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "su2-ramp-repeat-control",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(PublicArtifactRedirect())
    return opener.open(urllib.request.Request(url, headers=headers), timeout=30)


def fetch(args):
    target = manifest(args.manifest)
    workspace, evidence = Path(args.workspace).resolve(), Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    archive_dir = workspace / "archives"
    archive_dir.mkdir(exist_ok=False)
    deadline = time.monotonic() + 300
    receipt = {"complete": False, "arms": {}}
    try:
        for name, arm in target["arms"].items():
            url = "https://api.github.com/repos/su2code/SU2/actions/artifacts/" + str(arm["artifact_id"])
            with request(url) as response:
                metadata = json.loads(response.read(1_000_000))
            save(evidence / (name + "-artifact-metadata.json"), metadata)
            require(metadata["id"] == arm["artifact_id"] and metadata["name"] == "BaseMPI" and not metadata["expired"], "artifact unavailable or wrong")
            require(metadata["digest"] == "sha256:" + arm["zip_sha256"] and metadata["size_in_bytes"] == arm["size_in_bytes"], "artifact digest/size changed")
            require(metadata["workflow_run"]["id"] == arm["run_id"] and metadata["workflow_run"]["head_sha"] == arm["source_sha"], "artifact not bound to requested source run")
            with request("https://api.github.com/repos/su2code/SU2/git/commits/" + arm["build_checkout_sha"]) as response:
                commit = json.loads(response.read(1_000_000))
            save(evidence / (name + "-build-commit.json"), commit)
            require(commit["sha"] == arm["build_checkout_sha"] and commit["tree"]["sha"] == arm["source_tree"], "build checkout tree differs from source head")
            require(arm["build_checkout_sha"] == arm["source_sha"] or arm["source_sha"] in [p["sha"] for p in commit["parents"]], "build checkout not bound to requested source")
            path = archive_dir / (name + ".zip")
            partial = path.with_suffix(".partial")
            total = 0
            with request(url + "/zip") as response, partial.open("xb") as output:
                while True:
                    require(time.monotonic() < deadline, "artifact download deadline reached")
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    require(total <= arm["size_in_bytes"], "archive exceeds registered size")
                    output.write(block)
            require(total == arm["size_in_bytes"] and sha(partial) == arm["zip_sha256"], "downloaded ZIP digest/size mismatch")
            partial.rename(path)
            path.chmod(0o444)
            receipt["arms"][name] = {"zip_sha256": sha(path), "bytes": total, "artifact_id": arm["artifact_id"]}
            save(evidence / "download-receipt.json", receipt)
        receipt["complete"] = True
    except Exception as exc:
        receipt["error"] = str(exc)
        (evidence / "download-failure.txt").write_text(traceback.format_exc())
    finally:
        save(evidence / "download-receipt.json", receipt)
    return 0 if receipt["complete"] else 1


def safe_destination(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and ".." not in path.parts and path.parts, "unsafe archive path")
    result = root.joinpath(*path.parts)
    require(result.resolve().is_relative_to(root.resolve()), "archive path leaves destination")
    return result


def extract_package(archive, destination):
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as package:
        items = [item for item in package.infolist() if not item.is_dir()]
        require(len(items) == 1 and items[0].filename == "install_bin.tgz", "unexpected upstream artifact layout")
        require(items[0].file_size < 500_000_000, "inner archive too large")
        compressed = destination / "install_bin.tgz"
        with package.open(items[0]) as source, compressed.open("xb") as output:
            shutil.copyfileobj(source, output)
    with tarfile.open(compressed, "r:gz") as package:
        members = package.getmembers()
        require(sum(member.size for member in members) < 2_000_000_000, "unpacked package too large")
        seen = set()
        for member in members:
            path = safe_destination(destination, member.name)
            relative = path.relative_to(destination)
            require(relative.parts[0] == "install", "unexpected install archive root")
            require(str(relative) not in seen, "duplicate archive entry")
            seen.add(str(relative))
            require(member.isdir() or member.isfile() or member.issym() or member.islnk(), "unsafe archive entry type")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, path.open("xb") as output:
                    shutil.copyfileobj(source, output)
                path.chmod(member.mode & 0o777)
        for member in members:
            if not (member.issym() or member.islnk()):
                continue
            path = safe_destination(destination, member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                target = path.parent / member.linkname
                require(not Path(member.linkname).is_absolute() and target.resolve().is_relative_to(destination.resolve()), "unsafe library symlink")
                path.symlink_to(member.linkname)
            else:
                target = safe_destination(destination, member.linkname)
                require(target.is_file() and not target.is_symlink(), "unsafe package hardlink")
                os.link(target, path)
    binary = destination / "install/bin/SU2_CFD"
    require(binary.is_file(), "upstream package lacks SU2_CFD")
    return binary


def source_authority(workspace, target):
    result, definitions = {}, {}
    for name, arm in target["arms"].items():
        source = workspace / ("source-" + name)
        require(git(source, "rev-parse", "HEAD") == arm["source_sha"], "source HEAD mismatch")
        require(git(source, "rev-parse", "HEAD^{tree}") == arm["source_tree"], "source tree mismatch")
        require(not git(source, "status", "--porcelain=v1", "--untracked-files=no"), "tracked source changed")
        script = source / "TestCases/parallel_regression.py"
        definition = {}
        for node in ast.walk(ast.parse(script.read_text())):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            left = node.targets[0]
            if isinstance(left, ast.Attribute) and isinstance(left.value, ast.Name) and left.value.id == "ramp_msw":
                require(left.attr not in definition, "duplicate ramp definition")
                definition[left.attr] = ast.literal_eval(node.value)
        require(definition == {"cfg_dir": "euler/ramp", "cfg_file": "inv_ramp_msw.cfg", "test_iter": 100,
                               "test_vals": [-7.219257, -1.444776, -0.077507, 0.054419], "tol": [0.2, 0.2, 1e-5, 1e-5]}, "ramp reference/tolerance contract changed")
        config = source / target["source_config"]
        result[name] = {"source_sha": arm["source_sha"], "source_tree": arm["source_tree"],
                        "config_sha256": sha(config), "definition": definition}
        definitions[name] = definition
    require(result["develop"]["config_sha256"] == result["pr2884"]["config_sha256"], "A/B configs differ")
    data = workspace / "test-data"
    require(git(data, "rev-parse", "HEAD") == target["testcases_sha"], "TestCases head mismatch")
    require(not git(data, "status", "--porcelain=v1", "--untracked-files=no"), "TestCases changed")
    result["testcases_sha"] = target["testcases_sha"]
    result["canonical_inputs"] = inventory(data / "euler/ramp")
    return result, definitions


def run(args):
    global DEADLINE
    target = manifest(args.manifest)
    workspace, evidence = Path(args.workspace).resolve(), Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    DEADLINE = time.monotonic() + target["workload_timeout_seconds"]
    outcome = {"schema": "su2-ramp-binary-repeat-result.v1", "pass": False, "runs": []}
    before, binaries = None, {}
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "requires native Linux x86_64")
        before, definitions = source_authority(workspace, target)
        save(evidence / "source-authority-before.json", before)
        shutil.copytree(workspace / "test-data/euler/ramp", evidence / "protected-case-data")
        for command in (["uname", "-a"], ["lscpu"], ["mpirun", "--version"]):
            receipt = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
            save(evidence / (command[0] + ".json"), {"command": command, "returncode": receipt.returncode, "output": receipt.stdout})
        for name, arm in target["arms"].items():
            archive = workspace / "archives" / (name + ".zip")
            require(sha(archive) == arm["zip_sha256"], "archive changed before execution")
            package = workspace / "packages" / name
            binary = extract_package(archive, package)
            binaries[name] = inventory(package, allow_links=True)
            save(evidence / (name + "-package-inventory.json"), binaries[name])
            environment = os.environ.copy()
            environment["LD_LIBRARY_PATH"] = str(package / "install/lib")
            environment["MPP_DATA_DIRECTORY"] = str(package / "install/mpp-data")
            loader = subprocess.run(["ldd", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=environment, timeout=15)
            save(evidence / (name + "-runtime-loader.json"), {"output": loader.stdout, "returncode": loader.returncode,
                 "library_directory": environment["LD_LIBRARY_PATH"], "binary_sha256": sha(binary)})
            require(loader.returncode == 0 and "not found" not in loader.stdout, "runtime dependency missing")
            source_config = workspace / ("source-" + name) / target["source_config"]
            original = source_config.read_text()
            options = config_values(source_config)
            require(options["SOLVER"] == "EULER" and options["RESTART_SOL"] == "NO", "changed solver/initialization")
            for repeat in range(1, 3):
                folder = evidence / "runs" / (name + "-r" + str(repeat))
                shutil.copytree(workspace / "test-data/euler/ramp", folder)
                shutil.copy2(source_config, folder / source_config.name)
                inputs = inventory(folder)
                staged, count = re.subn(r"(?m)^\s*ITER\s*=.*$", "ITER=101", original)
                require(count == 1, "expected one iteration option")
                config = folder / (source_config.name + ".autotest")
                config.write_text(staged)
                require(config_values(config) == dict(options, ITER="101"), "autotest altered other options")
                staged_hash = sha(config)
                execution = bounded(["mpirun", "--allow-run-as-root", "-n", "2", str(binary), config.name],
                                    folder, folder / "solver.log", target["case_timeout_seconds"], env=environment)
                row, error = None, None
                try:
                    row = target_row(folder / "solver.log", 100, 4)
                except Exception as exc:
                    error = str(exc)
                # RESTART_SOL=NO makes the pre-existing restart an unused fixture.
                # The solver may overwrite it as output; the original is preserved separately.
                unchanged = all((folder / path).is_file() and sha(folder / path) == value["sha256"]
                                for path, value in inputs.items() if path != "restart_flow.dat")
                unchanged = unchanged and sha(config) == staged_hash
                expected, tolerance = definitions[name]["test_vals"], definitions[name]["tol"]
                delta = [abs(a - b) for a, b in zip(row, expected)] if row is not None else None
                comparison = delta is not None and all(a <= b for a, b in zip(delta, tolerance))
                result = {"arm": name, "repeat": repeat, "execution": execution, "row100": row,
                          "stored": expected, "tolerance": tolerance, "absolute_deltas": delta,
                          "reference_pass": comparison, "row_error": error, "inputs_before": inputs,
                          "inputs_unchanged": unchanged, "config_original_sha256": sha(source_config),
                          "unused_restart_before": inputs.get("restart_flow.dat"),
                          "unused_restart_after_sha256": sha(folder / "restart_flow.dat") if (folder / "restart_flow.dat").is_file() else None,
                          "config_autotest_sha256": staged_hash, "binary_sha256": sha(binary)}
                save(folder / "receipt.json", result)
                outcome["runs"].append(result)
                save(evidence / "result.json", outcome)
                print("Ramp result:", json.dumps({key: result[key] for key in
                      ("arm", "repeat", "row100", "absolute_deltas", "reference_pass", "inputs_unchanged")}), flush=True)
        outcome["repeat_rows_identical"] = {name: (len([item for item in outcome["runs"] if item["arm"] == name]) == 2
            and [item["row100"] for item in outcome["runs"] if item["arm"] == name][0] is not None
            and [item["row100"] for item in outcome["runs"] if item["arm"] == name][0]
            == [item["row100"] for item in outcome["runs"] if item["arm"] == name][1]) for name in target["arms"]}
        outcome["all_reference_comparisons_pass"] = all(item["reference_pass"] for item in outcome["runs"])
        outcome["execution_integrity_pass"] = (len(outcome["runs"]) == 4 and all(item["execution"]["clean_exit"]
            and item["row_error"] is None and item["inputs_unchanged"] for item in outcome["runs"]))
    except Exception as exc:
        outcome["error"] = str(exc)
        (evidence / "failure-traceback.txt").write_text(traceback.format_exc())
    finally:
        try:
            after, _ = source_authority(workspace, target)
            save(evidence / "source-authority-after.json", after)
            outcome["protected_inputs_unchanged"] = before is not None and before == after
            outcome["preserved_seed_unchanged"] = inventory(evidence / "protected-case-data") == before["canonical_inputs"]
            outcome["packages_unchanged"] = len(binaries) == 2 and all(
                inventory(workspace / "packages" / name, allow_links=True) == values for name, values in binaries.items())
            outcome["archive_digests_unchanged"] = all(sha(workspace / "archives" / (name + ".zip")) == arm["zip_sha256"]
                                                        for name, arm in target["arms"].items())
        except Exception as exc:
            outcome["final_integrity_error"] = str(exc)
        outcome["diagnostic_valid"] = (outcome.get("execution_integrity_pass", False)
            and outcome.get("protected_inputs_unchanged", False) and outcome.get("packages_unchanged", False)
            and outcome.get("preserved_seed_unchanged", False)
            and outcome.get("archive_digests_unchanged", False))
        outcome["pass"] = (outcome["diagnostic_valid"] and outcome.get("all_reference_comparisons_pass", False)
                           and all(outcome.get("repeat_rows_identical", {}).values()))
        outcome["claim_boundary"] = "Four bounded iteration-100 regression observations from existing upstream binaries; no reference/tolerance edits, convergence or physical validation claim."
        save(evidence / "result.json", outcome)
    return 0 if outcome["pass"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["validate", "fetch", "run", "seal"])
    parser.add_argument("--manifest")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if args.action == "validate":
        manifest(args.manifest)
        print("Ramp target manifest valid; no downloads or execution.")
        return 0
    if args.action == "fetch":
        return fetch(args)
    if args.action == "run":
        return run(args)
    evidence = Path(args.evidence)
    require(not (evidence / "SHA256SUMS").exists(), "refusing to overwrite an evidence seal")
    files = inventory(evidence)
    (evidence / "SHA256SUMS").write_text("".join(value["sha256"] + "  " + name + "\n" for name, value in files.items()))
    require(all(sha(evidence / name) == value["sha256"] for name, value in files.items()), "evidence changed while sealing")
    print("Sealed", len(files), "files; sealing does not imply test success.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
