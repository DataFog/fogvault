#!/usr/bin/env python3
"""Shared local/CI checks over FogVault's existing verifiers and package tests."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evidence import artifact_identity, snapshot, tool_versions, write_report
from delivery_inputs import archive_files, hashes, npm_command

PROFILES = ("policy", "contract", "native", "browser", "extensions", "packaging", "full")
DOC_FILES = {"README.md", "PUBLIC-CHECKOUT-NOTES.md", "public-checkout-manifest.json",
             "AGENTS.md", "CONTRIBUTING.md", "CHANGELOG.md", ".github/pull_request_template.md"}


def pins():
    value = json.loads((ROOT / "conformance/toolchains.json").read_text())
    if value.get("schema") != "fogvault-quality-toolchains/v1":
        raise ValueError("unsupported toolchain policy")
    for field in ("rust", "rust_minimum", "python_minimum", "python_ci", "node", "wasm_bindgen", "playwright_cli"):
        if not isinstance(value.get(field), str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value[field]):
            raise ValueError("missing or malformed toolchain pin: " + field)
    return value


def version(value):
    found = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    return tuple(map(int, found.groups())) if found else None


def diagnose(profile, requirements=None, probe=None):
    """Read pins and report repairs; never installs or changes the environment."""
    required = requirements or pins()
    checks = []

    def run(command):
        if probe:
            return probe(command)
        if not shutil.which(command[0]):
            return None
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=20)
        return result.stdout.strip() if result.returncode == 0 else None

    def admit(name, found, expected, passed, repair):
        checks.append({"id": name, "found": found, "expected": expected,
                       "pass": bool(passed), "repair": repair if not passed else None})

    python = sys.version.split()[0]
    admit("python", python, ">=" + required["python_minimum"],
          version(python) >= version(required["python_minimum"]), "Install supported Python, then rerun this command.")
    git = run(["git", "--version"])
    admit("git", git, "available", git is not None, "Install Git and put it on PATH.")
    rust_profiles = {"native", "browser", "extensions", "packaging", "full"}
    if profile in rust_profiles:
        for tool in ("rustc", "cargo"):
            found = run([tool, "--version"])
            admit(tool, found, required["rust"], found is not None and version(found) == version(required["rust"]),
                  "Install Rust " + required["rust"] + " with rustfmt/clippy, and select that toolchain for this checkout.")
        for tool in (["rustfmt", "--version"], ["cargo", "clippy", "--version"]):
            found = run(tool)
            admit(tool[0] + ("-clippy" if "clippy" in tool else ""), found, "available", found is not None,
                  "rustup component add rustfmt clippy --toolchain " + required["rust"])
    if profile in {"policy", "contract", "browser", "extensions", "packaging", "full"}:
        tool_pins = [("node", required["node"])]
        if profile in {"browser", "extensions", "packaging", "full"}:
            tool_pins.append(("wasm-bindgen", required["wasm_bindgen"]))
        for tool, expected in tool_pins:
            found = run([tool, "--version"])
            repair = ("Install Node " + expected if tool == "node" else
                      "cargo install wasm-bindgen-cli --version " + expected + " --locked")
            admit(tool, found, expected, found is not None and version(found) == version(expected), repair)
    if profile in {"browser", "extensions", "packaging", "full"}:
        # npm.cmd is a Windows batch shim. Its version is reported through Node.
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        admit("npm", str(npm) if npm else None, "available with pinned Node", bool(npm), "Install the pinned Node distribution with npm.")
        targets = run(["rustup", "target", "list", "--installed"])
        admit("wasm-target", targets, "wasm32-unknown-unknown", targets is not None and "wasm32-unknown-unknown" in targets.splitlines(),
              "rustup target add wasm32-unknown-unknown --toolchain " + required["rust"])
        lock = json.loads((ROOT / "packages/browser/package-lock.json").read_text())
        package = json.loads((ROOT / "packages/browser/package.json").read_text())
        admit("npm-lock", lock.get("packages", {}).get("", {}).get("devDependencies"), package["devDependencies"],
              lock.get("packages", {}).get("", {}).get("devDependencies") == package["devDependencies"],
              "Update package.json and its reviewed package-lock.json together; then npm ci --ignore-scripts --prefix packages/browser.")
        admit("npm-installed", (ROOT / "packages/browser/node_modules/.package-lock.json").is_file(), True,
              (ROOT / "packages/browser/node_modules/.package-lock.json").is_file(),
              "npm ci --ignore-scripts --prefix packages/browser")
        cli = ROOT / "packages/browser/node_modules/@playwright/cli/package.json"
        try:
            installed = json.loads(cli.read_text())["version"]
        except (OSError, ValueError, KeyError, TypeError):
            installed = None
        admit("playwright-cli", installed, required["playwright_cli"], installed == required["playwright_cli"],
              "npm ci --ignore-scripts --prefix packages/browser")
    if profile == "full":
        admit("full-host", platform.system() + "/" + platform.machine(), "Darwin/arm64", platform.system() == "Darwin" and platform.machine() == "arm64",
              "Run the full profile on the documented Apple arm64/Xcode qualification host; use named CI profiles elsewhere.")
        for tool in ("xcrun", "clang", "cc"):
            admit(tool, shutil.which(tool), "available", shutil.which(tool) is not None, "Install/select the documented Xcode command-line tools.")
        try:
            import cryptography
            import ctypes.util
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            available = bool(Argon2id) and bool(ctypes.util.find_library("sodium"))
            found = {"cryptography": cryptography.__version__, "sodium": ctypes.util.find_library("sodium")}
        except ImportError:
            available, found = False, None
        admit("independent-decoder", found, "Argon2id cryptography + discoverable libsodium", available,
              "Install the independently captured decoder environment in PUBLIC-CHECKOUT-NOTES.md; the full verifier checks its exact provenance.")
        spec = importlib.util.spec_from_file_location("fogvault_reference_policy", ROOT / "scripts/verify-dependency-audit.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        reference = ROOT / checker.DATABASE_OBJECTS
        admit("reference-db", str(reference), "bootstrapped pinned RustSec Git reference",
              reference.is_dir(), "python3 scripts/bootstrap-reference-db.py")
    return {"schema": "fogvault-quality-doctor/v1", "profile": profile,
            "pass": all(row["pass"] for row in checks), "pins": required, "checks": checks}


def verifier():
    spec = importlib.util.spec_from_file_location("fogvault_quality_contract", ROOT / "scripts/verify-vault.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def check(profile, output_root, engines):
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=output_root))
    v = verifier()
    contract = v.load_contract()
    runner = v.Verifier(run_dir, contract, False)
    before = snapshot(ROOT)
    expected = ["environment"]
    artifacts = []

    def command(name, arguments, validate=None):
        expected.append(name)
        return runner.command(name, npm_command(list(map(str, arguments))), validate)

    def builtin(name, action):
        expected.append(name)
        return runner.builtin(name, action)

    diagnostic = diagnose(profile)
    runner.builtin("environment", lambda: diagnostic if diagnostic["pass"] else (_ for _ in ()).throw(ValueError(json.dumps(diagnostic))))
    if diagnostic["pass"]:
        if profile in {"policy", "contract"}:
            command("quality-self-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"])
        if profile == "contract":
            command("verifier-self-tests", [sys.executable, "tests/verifier_checks.py"])
            manifest = ROOT / contract["manifest"]
            builtin("consumer-pin", lambda: v.check_consumer_pin(contract, manifest))
            builtin("core-boundary", lambda: v.check_core_boundary(ROOT / contract["core_manifest"]))
            builtin("format-vectors", lambda: v.validate_format_vectors(ROOT / contract["format_vectors"]))
            builtin("epoch-vectors", lambda: v.validate_epoch_vectors(ROOT / contract["epoch_vectors"]))
            settings = contract["access_format_vectors"]
            builtin("access-vectors", lambda: v.validate_access_vectors(ROOT / settings["fixture"], ROOT / settings["rust_projection"], settings))
            password = contract["password_vectors"]
            builtin("password-vectors", lambda: v.validate_password_vectors(ROOT / password["fixture"], ROOT / password["rust_projection"], password))
            output = run_dir / "access-paths.json"
            command("access-paths", [sys.executable, "scripts/verify-access-paths.py", "--output", output], lambda _: v.validate_access_file(output, contract))
        elif profile == "native":
            for crate in ("fogvault", "fogvault-native", "fogvault-backup"):
                manifest = ROOT / "crates" / crate / "Cargo.toml"
                command(crate + "-format", ["cargo", "fmt", "--manifest-path", manifest, "--check"])
                command(crate + "-clippy", ["cargo", "clippy", "--locked", "--manifest-path", manifest, "--all-targets", "--all-features", "--", "-D", "warnings"])
            command("core-tests", ["cargo", "test", "--locked", "--manifest-path", "crates/fogvault/Cargo.toml", "--all-features"], lambda out: v.require_cases(out, contract["required_core_cases"]))
            command("native-tests", [sys.executable, "scripts/run-native-tests.py"], lambda out: v.require_cases(out, contract["required_native_cases"] + contract["required_fixture_cases"]))
            command("backup-tests", ["cargo", "test", "--locked", "--manifest-path", "crates/fogvault-backup/Cargo.toml", "--all-features"], lambda out: v.require_cases(out, contract["required_backup_cases"]))
            command("default-api", [sys.executable, "scripts/verify-maintained-api.py"])
            output = run_dir / "native-candidate.json"
            command("installed-native-candidate", [sys.executable, "scripts/verify-candidate.py", "--profile", "native", "--output", output], lambda _: validate_native_candidate(output))
            if output.exists():
                artifacts.append(artifact_identity(output))
        elif profile == "browser":
            manifest = "crates/fogvault-wasm/Cargo.toml"
            command("wasm-format", ["cargo", "fmt", "--manifest-path", manifest, "--check"])
            command("wasm-clippy", ["cargo", "clippy", "--locked", "--manifest-path", manifest, "--all-targets", "--all-features", "--target", "wasm32-unknown-unknown", "--", "-D", "warnings"])
            output = run_dir / "browser-sdk.json"
            command("installed-browser-candidate", [sys.executable, "scripts/verify-browser-sdk.py", "--output", output, "--engines", *engines], lambda _: v.validate_sdk_file(output, engines=engines))
            if output.exists():
                artifacts.append(artifact_identity(output))
        elif profile == "extensions":
            command("extension-build", ["npm", "run", "build", "--prefix", "packages/browser"])
            output = run_dir / "extensions.json"
            command("packaged-extensions", [sys.executable, "scripts/verify-extensions.py", "--output", output], lambda _: v.validate_extension_file(output))
            if output.exists():
                artifacts.append(artifact_identity(output))
        elif profile == "packaging":
            output = run_dir / "packaging.json"
            command("registry-packaging", [sys.executable, "scripts/verify-packaging.py", "--output", output], lambda _: validate_packaging(output))
            if output.exists():
                artifacts.append(artifact_identity(output))
        elif profile == "full":
            command("full-verifier", [sys.executable, "scripts/verify-vault.py", "--with-feasibility", "--output-dir", run_dir / "full"], lambda _: validate_full_report(run_dir / "full", v))
    after = snapshot(ROOT)
    builtin("source-stability", lambda: v.require_stable_sources(before["input_identity"], after["input_identity"]))
    report = {"schema": "fogvault-quality-report/v1", "profile": profile,
              "pass": v.complete_results(runner.checks, expected), "executed": True,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "git": before,
              "environment": diagnostic, "tools": tool_versions({"python": [sys.executable, "--version"], "git": ["git", "--version"], "rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"], "node": ["node", "--version"]}),
              "checks": runner.checks, "required_checks": expected, "artifacts": artifacts}
    write_report(run_dir / "report.json", report)
    print(json.dumps({"pass": report["pass"], "profile": profile, "report": str(run_dir / "report.json")}))
    return 0 if report["pass"] else 1


def validate_native_candidate(path):
    report = json.loads(Path(path).read_text())
    if (not isinstance(report, dict) or report.get("schema") != "fogvault-native-candidate-proof/v1"
            or report.get("pass") is not True or report.get("executed") is not True or report.get("error") is not None):
        raise ValueError("required candidate check did not execute successfully")
    settings = json.loads((ROOT / "conformance/maintained-contract.json").read_text())["native"]
    cases = report.get("cases")
    if (not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases)
            or any(case.get("status") != "pass" or case.get("executed") is not True for case in cases)
            or sorted(case.get("id", "") for case in cases) != sorted(settings["required_candidate_cases"])):
        raise ValueError("native candidate omitted or skipped a required consumer proof")
    candidate = report.get("candidate")
    if not isinstance(candidate, dict) or candidate.get("checkout_path_dependencies") is not False:
        raise ValueError("native consumer must use the extracted archive")
    package = candidate.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("path"), str):
        raise ValueError("native candidate omitted archive identity")
    archive = Path(package["path"])
    if not archive.is_absolute():
        archive = ROOT / archive
    actual = artifact_identity(archive)
    if package.get("sha256") != actual["sha256"] or package.get("bytes") != actual["bytes"]:
        raise ValueError("native candidate archive changed")
    if hashes(archive_files(archive, "fogvault-native-sdk")) != candidate.get("archive_inputs"):
        raise ValueError("native candidate archive inputs changed")
    source = report.get("source")
    if not isinstance(source, dict) or source.get("input_tree_sha256") != snapshot(ROOT)["input_tree_sha256"]:
        raise ValueError("native consumer proof does not identify current source inputs")
    return {"report": artifact_identity(path), "archive": actual, "cases": settings["required_candidate_cases"]}


def validate_packaging(path):
    report = json.loads(Path(path).read_text())
    cases = {"eight-verified-archives", "registry-only-default-backup-consumer",
             "beta3-create-unlock-save-lock-reopen-read", "browser-worker-wasm-package"}
    if (report.get("schema") != "fogvault-registry-packaging/v1" or report.get("pass") is not True
            or report.get("published") is not False or report.get("error") is not None
            or set(report.get("cases", [])) != cases
            or report.get("source", {}).get("input_tree_sha256") != snapshot(ROOT)["input_tree_sha256"]):
        raise ValueError("packaging proof is failed, incomplete or stale")
    artifacts = report.get("artifacts")
    commands = report.get("commands")
    if (not isinstance(artifacts, list) or len(artifacts) != 9 or not isinstance(commands, list)
            or {row.get("id") for row in commands} != {"upstream-provenance", "advisory-origin-capture", "advisory-projection-tests", "workspace-lock-metadata", "batch-package", "registry-consumer", "registry-metadata", "browser-package"}
            or len(commands) != 8):
        raise ValueError("packaging proof omitted a candidate or execution")
    expected_names = {"fogvault-0.1.0.crate", "fogvault-native-0.1.0.crate", "fogvault-backup-0.1.0.crate",
                      "fogvault-age-0.11.5.crate", "fogvault-i18n-config-0.4.8.crate",
                      "fogvault-i18n-embed-impl-0.8.4.crate", "fogvault-i18n-embed-0.16.0.crate",
                      "fogvault-i18n-embed-fl-0.10.1.crate", "datafog-fogvault-browser-0.1.0.tgz"}
    if {Path(row["path"]).name for row in artifacts} != expected_names:
        raise ValueError("packaging proof duplicated or substituted a candidate")
    if report.get("all_archive_registry_identities_in_approved_union") is not True:
        raise ValueError("packaging proof lacks approved archive dependency identities")
    if report.get("preserved_native_backend_registry_dependencies") != {"fogvault-native": 167, "fogvault-backup": 134}:
        raise ValueError("packaging proof did not preserve the audited native/backend registry graph")
    origins = report.get("registry_origin_projection", {})
    if (report.get("advisory_capture") != {"audits_reexecuted": False, "captured_audits_validated": 14}
            or {row["actual_name"] for row in origins.get("mappings", [])} != {"fogvault-age", "fogvault-i18n-config", "fogvault-i18n-embed", "fogvault-i18n-embed-impl", "fogvault-i18n-embed-fl"}):
        raise ValueError("packaging proof lacks upstream advisory origin evidence")
    for row in artifacts + [row["log"] for row in commands] + [origins["lock"]]:
        if artifact_identity(Path(row["path"])) != row:
            raise ValueError("packaging artifact or execution log changed")
    if any(row.get("exit_code") != 0 or not row.get("command") for row in commands):
        raise ValueError("packaging command did not pass")
    return {"report": artifact_identity(Path(path)), "artifacts": artifacts, "cases": sorted(cases)}


def validate_full_report(directory, v=None):
    v = v or verifier()
    reports = list(Path(directory).glob("*/report.json"))
    if len(reports) != 1:
        raise ValueError("full verifier must retain exactly one fresh report")
    report = json.loads(reports[0].read_text())
    if (not isinstance(report, dict) or report.get("schema") != "fogvault-verifier/v1"
            or report.get("pass") is not True or report.get("executed") is not True
            or not v.complete_results(report.get("checks", []), v.required_checks(True))):
        raise ValueError("full verifier report is incomplete or failed")
    contract = v.load_contract()
    current = v.verification_source_identity(ROOT / contract["manifest"], True)
    if report.get("source_identity") != current:
        raise ValueError("full verifier report does not match current source inputs")
    by_id = {check["id"]: check for check in report["checks"]}
    groups = {"core-tests": contract["required_core_cases"],
              "native-tests": contract["required_native_cases"] + contract["required_fixture_cases"],
              "maintained-backup-tests": contract["required_backup_cases"]}
    for name, required in groups.items():
        observed = by_id[name].get("evidence")
        cases = observed.get("executed_cases") if isinstance(observed, dict) else None
        if (not isinstance(cases, list) or any(not isinstance(case, str) for case in cases)
                or not set(required).issubset(cases)):
            raise ValueError("full verifier omitted required executed behavior: " + name)
    if report.get("behavior_evidence") != v.behavior_evidence(report["checks"], contract):
        raise ValueError("full verifier behavior inventory is inconsistent")
    logs = []
    # This parent invokes the normal full profile (not --benchmark-report).
    # All remaining stages are commands and must retain their execution logs.
    builtins = {"consumer-pin", "core-boundary", "format-fixtures", "epoch-format-fixtures",
                "access-format-fixtures", "password-vectors", "source-stability"}
    for row in report["checks"]:
        if row["id"] not in builtins:
            command = row.get("command")
            if (not isinstance(command, list) or not command
                    or any(not isinstance(part, str) or not part for part in command)
                    or row.get("exit_code") != 0 or not isinstance(row.get("log"), str)):
                raise ValueError("full verifier omitted successful command evidence")
            logs.append(artifact_identity(Path(row["log"])))
    return {"report": artifact_identity(reports[0]), "logs": logs,
            "behavior_evidence": report["behavior_evidence"]}


def plan(base, head="HEAD"):
    """Classify the complete committed diff; unknown paths require product checks."""
    def git(*arguments):
        result = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, check=False)
        if result.returncode:
            raise ValueError("quality plan requires available base/head commits: " + " ".join(arguments))
        return result.stdout
    base_sha = git("rev-parse", "--verify", base + "^{commit}").decode().strip()
    head_sha = git("rev-parse", "--verify", head + "^{commit}").decode().strip()
    merge_base = git("merge-base", base_sha, head_sha).decode().strip()
    paths = [os.fsdecode(p) for p in git("diff", "--name-only", "-z", merge_base, head_sha, "--").split(b"\0") if p]
    code = any(name not in DOC_FILES and not name.startswith("docs/") for name in paths)
    return {"schema": "fogvault-quality-plan/v1", "base": base_sha, "head": head_sha,
            "merge_base": merge_base, "paths": paths, "code": code,
            "reason": "product or verification inputs changed" if code else "documentation-only or empty diff; contract and changelog checks still required"}


def gate(results):
    """A stable required result; no missing, cancelled or failed suite is green."""
    if not isinstance(results, dict) or set(results) != {"plan", "contract", "native", "browser", "extensions", "packaging"}:
        raise ValueError("required profile results are missing or malformed")
    if any(not isinstance(value, dict) for value in results.values()):
        raise ValueError("quality profile results must be objects")
    if results["plan"].get("result") != "success" or results["contract"].get("result") != "success":
        raise ValueError("quality scope and contract checks must pass")
    outputs = results["plan"].get("outputs")
    code = outputs.get("code") if isinstance(outputs, dict) else None
    if code not in ("true", "false"):
        raise ValueError("quality scope did not report a deliberate result")
    for name in ("native", "browser", "extensions", "packaging"):
        expected = "success" if code == "true" else "skipped"
        if results[name].get("result") != expected:
            raise ValueError(name + " did not complete its required scope")
    return {"schema": "fogvault-quality-gate/v1", "pass": True, "code": code == "true",
            "result": "all required profiles passed" if code == "true" else "documentation-only: contract passed, product suites deliberately not required"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "check", "plan", "gate"))
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "local-only/quality-runs")
    parser.add_argument("--engines", nargs="+", choices=("chrome", "firefox", "msedge"), default=["chrome", "firefox"])
    args = parser.parse_args()
    try:
        if args.action == "gate":
            report = gate(json.loads(os.environ.get("FOGVAULT_QUALITY_RESULTS", "null")))
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_report(args.output, report)
            print(json.dumps(report))
            return 0
        if args.action == "plan":
            if not args.base:
                parser.error("plan requires --base (the actual PR target)")
            report = plan(args.base, args.head)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_report(args.output, report)
            print(json.dumps(report, indent=2))
            return 0
        if not args.profile:
            parser.error("doctor/check requires --profile")
        if args.action == "doctor":
            report = diagnose(args.profile)
            print(json.dumps(report, indent=2))
            return 0 if report["pass"] else 1
        return check(args.profile, args.output_dir.resolve(), args.engines)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if args.output and not args.output.exists():
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_report(args.output, {"schema": "fogvault-quality-error/v1", "pass": False, "error": str(error)})
            except OSError as capture_error:
                print("Evidence capture failed: " + str(capture_error), file=sys.stderr)
        print("Quality check failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
