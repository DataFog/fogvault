#!/usr/bin/env python3
"""Check first-review packet completeness after a stable full verifier run.

This is not a cryptographic review, production qualification or freeze decision.
It never edits source, expected fixtures, the supplied report or gate statuses.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance/support-manifest.json"
BASELINE = ROOT / "experiments/vault-prototype/evidence/verifier-runs/20261029T232239Z-74rejhfb/report.json"
VERSION = "0.5.0-beta.3"
CHECKSUM = "509259f36e4229fac2c5e254da49539dd44d4aa3ce0f3b0898ba8949752c7bed"
OPEN_ITEMS = {"FVW-048", "FVW-061", "G-CRYPTO", "G-FORMAT", "G-INDEX", "G-BUDGET", "G-ADAPTER", "G-BINDING"}
PACKAGES = {"access_recovery", "rotation_compromise", "format_profile", "record_membership", "snapshot_restore_staging", "lifecycle_adapters", "support_enterprise"}
BEHAVIOR_PACKAGES = {"access_recovery", "rotation_compromise", "record_membership", "snapshot_restore_staging", "lifecycle_adapters"}
BASE_STAGES = {"verifier-tests", "consumer-pin", "core-boundary", "format-fixtures", "password-vectors", "access-path-model", "core-format", "format", "core-clippy", "clippy", "core-tests", "core-public-api", "native-tests", "wasm-target", "core-wasm-compile", "wasm-compile", "index-growth", "resource-budgets", "browser-feasibility", "mobile-feasibility", "source-stability"}
BASE_DOCS = {"spec/review-entry.md", "spec/adapter-contract.md", "spec/support-manifest.md", "spec/requirements.md", "spec/technical-specification.md", "spec/threat-model.md", "spec/decisions.md", "spec/verification-plan.md", "spec/candidate-crypto.md", "spec/candidate-format.md", "spec/candidate-index.md", "spec/access-paths.md", "spec/credential-changes.md", "spec/password-bytes.md"}
BASE_FIXTURES = {"conformance/vault-contract.json", "conformance/host-feasibility-contract.json", "conformance/format-vectors.json", "conformance/access-paths.json", "conformance/password-vectors.json", "conformance/password-vectors.tsv"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repo_file(relative: str) -> Path:
    require(isinstance(relative, str) and bool(relative), "packet path must be a nonempty string")
    path = (ROOT / relative).resolve()
    require(not Path(relative).is_absolute() and path.is_relative_to(ROOT), "packet path escapes the workspace")
    require(path.relative_to(ROOT).as_posix() == relative and path.is_file(), "missing or noncanonical packet input: " + relative)
    return path


def paths(values: list, label: str) -> set[str]:
    require(isinstance(values, list) and bool(values), label + " must name concrete inputs")
    require(all(isinstance(value, str) for value in values) and len(values) == len(set(values)), label + " contains invalid/duplicate inputs")
    for value in values:
        repo_file(value)
    return set(values)


def validate_manifest(data: dict) -> tuple[dict, set[str]]:
    require(data.get("schema") == "fogvault-support-manifest/v1" and data.get("scope") == "first-review-entry-not-freeze-or-release", "unsupported support-manifest scope/schema")
    classes = {"native", "browser", "extension", "mobile", "server"}
    require(set(data.get("architectural_host_classes", [])) == classes, "an accepted architectural host class is missing")
    artifacts = data.get("artifacts", [])
    require(isinstance(artifacts, list) and bool(artifacts), "support artifact matrix is missing")
    ids = [artifact["id"] for artifact in artifacts]
    require(len(ids) == len(set(ids)) and all(isinstance(identity, str) and identity for identity in ids), "support artifacts have invalid/duplicate identities")
    require(classes <= {artifact["host_class"] for artifact in artifacts}, "support matrix dropped a host class")
    for artifact in artifacts:
        states = artifact.get("states", {})
        require(set(states) == {"designed", "implemented", "executed", "qualified"} and all(type(value) is bool for value in states.values()), "artifact states must be explicit Boolean values")
        require(not states["implemented"] or states["designed"], "implementation lacks a declared design")
        require(not states["executed"] or states["implemented"], "runtime execution cannot be inferred for absent implementation")
        require(states["qualified"] is False, "first-review packet must not claim production qualification")
        if artifact["id"] in {"ios-device-static-library", "android-rust-check"}:
            require(states["executed"] is False, "build-only mobile artifact cannot claim device runtime execution")
        require(type(artifact.get("build_checked")) is bool and bool(artifact.get("evidence_scope")) and bool(artifact.get("limitations")), "artifact build/evidence/limitation scope is missing")
        if states["executed"] or artifact["build_checked"]:
            paths(artifact.get("evidence_reports"), "artifact evidence")
    require(data.get("physical_measurements", {}).get("qualified_physical_floors") is False, "physical minimum-host qualification must remain open")
    baseline = data.get("baseline_evidence", {})
    require(baseline.get("report") == BASELINE.relative_to(ROOT).as_posix() and baseline.get("beta3_version") == VERSION and baseline.get("beta3_checksum") == CHECKSUM, "the historical baseline/consumer pin changed")
    entry = data.get("review_entry", {})
    require(entry.get("scope") == "first-review-entry-not-freeze" and entry.get("external_specialist_review_complete") is False and entry.get("design_frozen") is False and entry.get("repository_or_commits_authorized") is False, "review entry must not imply specialist approval, freeze or Git authorization")
    require(set(entry.get("must_remain_open", [])) == OPEN_ITEMS, "external/physical evidence and freeze gates must remain explicitly open")
    packet = paths(entry.get("required_documents"), "required documents")
    require(BASE_DOCS <= packet, "review packet dropped a required contract document")
    fixtures = paths(entry.get("required_fixtures"), "required fixtures")
    require(BASE_FIXTURES <= fixtures, "review packet dropped a baseline fixture/contract")
    packet |= fixtures
    packages = entry.get("work_packages", [])
    package_ids = [package["id"] for package in packages]
    require(set(package_ids) == PACKAGES and len(package_ids) == len(PACKAGES), "review work-package inventory differs")
    for package in packages:
        require(package.get("entry_status") == "ready", "review work package is not ready: " + package["id"])
        require(isinstance(package.get("fvwork_ids"), list) and bool(package["fvwork_ids"]), "work package has no requirement mapping")
        packet |= paths(package.get("documents"), package["id"] + " documents")
        if package.get("fixtures"):
            packet |= paths(package["fixtures"], package["id"] + " fixtures")
        checks = package.get("required_checks")
        require(isinstance(checks, list) and bool(checks) and all(isinstance(name, str) and name for name in checks) and len(checks) == len(set(checks)), "package requires named passing checks: " + package["id"])
        cases = package.get("required_cases")
        require(isinstance(cases, list), "package case requirements must be explicit")
        require(package["id"] not in BEHAVIOR_PACKAGES or bool(cases), "behavioral package requires actual named proof: " + package["id"])
        pairs = [(case.get("stage"), case.get("case")) for case in cases]
        require(all(isinstance(stage, str) and stage and isinstance(case, str) and case for stage, case in pairs) and len(pairs) == len(set(pairs)), "package case requirements are invalid/duplicate")
    packet |= {path.relative_to(ROOT).as_posix() for path in (ROOT / "spec").rglob("*.md")}
    packet |= {MANIFEST.relative_to(ROOT).as_posix(), Path(__file__).relative_to(ROOT).as_posix()}
    return entry, packet


def observed_cases(checks: dict, report_dir: Path) -> dict[str, set[str]]:
    result = {}
    for identity, check in checks.items():
        evidence = check.get("evidence") or {}
        result[identity] = set(evidence.get("executed_cases", evidence.get("executed_case_ids", [])))
    for identity, filename in (("browser-feasibility", "browser-feasibility.json"), ("mobile-feasibility", "mobile-feasibility.json")):
        path = report_dir / filename
        evidence = checks[identity].get("evidence") or {}
        require(path.is_file() and evidence.get("sha256") == digest(path), "host report is missing/changed: " + identity)
        host = json.loads(path.read_text())
        require(host.get("pass") is True, "host report did not pass: " + identity)
        groups = {}
        if identity == "browser-feasibility":
            for engine in host.get("engines", []):
                groups[engine["name"]] = engine["result"]["cases"]
        else:
            for target in host.get("targets", []):
                if target["id"] in {"native-abi-runtime", "ios-simulator-abi-runtime"}:
                    groups[target["id"]] = target["cases"]
        require(bool(groups), "runtime case groups missing: " + identity)
        sets = []
        for group, cases in groups.items():
            names = [case["id"] for case in cases]
            require(len(names) == len(set(names)) and all(case.get("status") == "pass" and case.get("executed") is not False for case in cases), "host cases are failed, duplicate or unexecuted")
            result[identity + "/" + group] = set(names)
            sets.append(set(names))
        result[identity] = set.intersection(*sets)
    return result


def validate_report(report_path: Path, entry: dict) -> tuple[dict, dict[str, str]]:
    report = json.loads(report_path.read_text())
    require(report.get("schema") == "fogvault-verifier/v1" and report.get("profile") == "disposable-vault-host-feasibility" and report.get("pass") is True and report.get("executed") is True, "a complete passing full verifier report is required")
    rows = report.get("checks", [])
    ids = [row["id"] for row in rows]
    require(len(ids) == len(set(ids)) and BASE_STAGES <= set(ids) and all(row.get("required") is True and row.get("executed") is True and row.get("status") == "pass" for row in rows), "full report omitted/failed/unexecuted a required stage")
    checks = {row["id"]: row for row in rows}
    consumer = checks["consumer-pin"].get("evidence", {})
    require(consumer.get("package") == "datafog-core" and consumer.get("version") == VERSION and consumer.get("checksum") == CHECKSUM, "exact published beta.3 evidence changed")
    identity = report.get("source_identity", {})
    require(isinstance(identity, dict) and bool(identity), "full report omitted current source identities")
    required = {MANIFEST.relative_to(ROOT).as_posix(), Path(__file__).relative_to(ROOT).as_posix()}
    require(required <= identity.keys(), "run the full verifier after adding the review checker/manifest")
    for relative, value in identity.items():
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None and digest(repo_file(relative)) == value, "full report source no longer matches: " + relative)
    stable = checks["source-stability"].get("evidence", {})
    require(stable.get("unchanged_during_run") is True and stable.get("source_files") == len(identity), "full verifier did not establish stable inputs")
    cases = observed_cases(checks, report_path.parent)
    contract = json.loads((ROOT / "conformance/vault-contract.json").read_text())
    baseline = json.loads(BASELINE.read_text())
    for stage, field in (("core-tests", "required_core_cases"), ("native-tests", "required_native_cases")):
        current = set(contract[field])
        if stage == "native-tests":
            current |= set(contract["required_fixture_cases"])
        old = set(baseline["behavior_evidence"]["groups"][stage]["required_cases"])
        require(old <= current <= cases[stage], "a baseline/current required Rust case was dropped or did not execute: " + stage)
    for package in entry["work_packages"]:
        require(set(package["required_checks"]) <= checks.keys(), "package passing check was not executed: " + package["id"])
        for requirement in package["required_cases"]:
            require(requirement["case"] in cases.get(requirement["stage"], set()), "package named proof did not execute: " + package["id"] + "/" + requirement["case"])
    return {"stages": len(rows), "required_rust_cases": report["behavior_evidence"]["required_case_count"], "current_source_files": len(identity), "consumer": consumer}, identity


def run(report_path: Path) -> dict:
    data = json.loads(MANIFEST.read_text())
    entry, packet = validate_manifest(data)
    hashes = {relative: digest(repo_file(relative)) for relative in sorted(packet)}
    report_sha = digest(report_path)
    evidence, source_identity = validate_report(report_path, entry)
    require(hashes == {relative: digest(repo_file(relative)) for relative in sorted(packet)} and report_sha == digest(report_path), "review inputs changed while the packet was checked")
    require(source_identity == {relative: digest(repo_file(relative)) for relative in source_identity}, "verified runtime inputs changed during packet checking")
    return {"schema": "fogvault-review-entry/v1", "scope": "first-review-entry-not-freeze-or-release", "pass": True, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "full_report": {"path": str(report_path), "sha256": report_sha, **evidence}, "packet_identity": hashes, "work_packages": [{"id": package["id"], "fvwork_ids": package["fvwork_ids"], "required_checks": package["required_checks"], "required_cases": package["required_cases"]} for package in entry["work_packages"]], "must_remain_open": sorted(OPEN_ITEMS), "external_specialist_review_complete": False, "physical_floors_qualified": False, "design_frozen": False, "limitations": ["Completeness and current-input check; not specialist security approval or proof of every prose claim.", "Synthetic providers and simulator/build evidence do not establish real hardware qualification.", "First review does not authorize commits, GitHub setup or release."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    output = options.output.expanduser().resolve()
    if output.exists():
        parser.error("output must be a fresh path")
    try:
        result = run(options.report.expanduser().resolve())
    except (OSError, ValueError, TypeError, KeyError) as error:
        result = {"schema": "fogvault-review-entry/v1", "scope": "first-review-entry-not-freeze-or-release", "pass": False, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "error": str(error), "must_remain_open": sorted(OPEN_ITEMS), "external_specialist_review_complete": False, "physical_floors_qualified": False, "design_frozen": False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as destination:
        json.dump(result, destination, indent=2)
        destination.write("\n")
    print(("PASS" if result["pass"] else "FAIL") + " first-review entry: " + str(output))
    if not result["pass"]:
        print(result["error"])
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
