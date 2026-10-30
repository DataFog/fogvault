#!/usr/bin/env python3
"""Execute exact, current-lock RustSec audits against the pinned local reference DB.

Point-in-time dependency matching only; no construction, license, C/platform or
unknown-vulnerability clearance. No fetch, dependency update or suppression.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = "artifacts/publication/dependency-audit-maintained-20261030"
INVENTORY = f"{EVIDENCE}/inventory.json"
INVENTORY_SHA = "9c510df09e569bd115af1ddc928a2f99aa309251eab315dd70c226e7db5eba98"
DB_CONTENT_MANIFEST = "artifacts/review-readiness/dependency-audit/advisory-db-files.json"
TOOL = "research/review-dependencies/cargo-audit-v0.22.2/bin/cargo-audit"
TOOL_SHA = "b4f48ca2b4b57bde3846f876dbcb6f72c056b27cc86d701413ecdc156f96dfcb"
DATABASE = "research/review-dependencies/advisory-db"
DATABASE_OBJECTS = "local-only/verifier-tools/advisory-db.git"
DB_REVISION = "ee1a49a2769a24a596afc1c20cb33748d2769586"
DB_TREE = "af3eaf8699bc8040565a708da432e04f1f19407a"
DB_CONTENT_SHA = "0b10a7454c6dd40a226a4dbcbfa0e9a3e70a2662ec175afdfd2fabf1d4e6a09c"
LOCKS = (
    ("core", "crates/fogvault"),
    ("native", "experiments/vault-prototype"),
    ("browser", "experiments/browser-prototype"),
    ("mobile", "experiments/mobile-prototype"),
    ("native-package", "crates/fogvault-native"),
    ("wasm-package", "crates/fogvault-wasm"),
    ("backup-package", "crates/fogvault-backup"),
)
REQUIRED_CASE_IDS = (
    "dependency-tool-identity",
    "dependency-reference-database-identity",
    "dependency-baseline-artifact-hashes",
    "dependency-current-locks-and-manifests",
    "dependency-core-fresh-audit",
    "dependency-native-fresh-audit",
    "dependency-browser-fresh-audit",
    "dependency-mobile-fresh-audit",
    "dependency-native-package-fresh-audit",
    "dependency-wasm-package-fresh-audit",
    "dependency-backup-package-fresh-audit",
    "dependency-input-stability",
)


class AuditFailure(ValueError):
    def __init__(self, message: str, command: dict, audit: dict):
        super().__init__(message)
        self.details = {"command_result": command, "audit": audit}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def repo_file(relative: str) -> Path:
    require(isinstance(relative, str), "nontext source path")
    path = ROOT / relative
    require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
            f"unsafe source path: {relative}")
    require(path.is_file() and not path.is_symlink(), f"missing/nonregular source: {relative}")
    require(path.resolve().is_relative_to(ROOT), f"source escapes workspace: {relative}")
    return path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(relative: str):
    return json.loads(repo_file(relative).read_text())


def run(command: list[str]) -> dict:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    return {"command": command, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def database_state() -> dict:
    # These read-only Git commands address only the downloaded REFERENCE DB.
    # They never inspect or configure the FogVault repository.
    database = ROOT / DATABASE
    if (database / ".git").exists():
        git = ["git", "-C", str(database)]
    else:
        objects = ROOT / DATABASE_OBJECTS
        require(objects.is_dir() and not objects.is_symlink() and objects.resolve().is_relative_to(ROOT),
                "reference Git objects unavailable; run python3 scripts/bootstrap-reference-db.py first")
        git = ["git", "--git-dir", str(objects)]
    result = {}
    for key, ref in (("revision", "HEAD"), ("tree", "HEAD^{tree}")):
        command = [*git, "rev-parse", "--verify", ref]
        row = run(command)
        require(row["exit_code"] == 0, "reference database identity unavailable")
        result[key] = row["stdout"].strip()
    require(result == {"revision": DB_REVISION, "tree": DB_TREE}, "reference database revision/tree changed")
    manifest_relative = DB_CONTENT_MANIFEST
    require(sha(repo_file(manifest_relative)) == DB_CONTENT_SHA, "reference content manifest changed")
    files = read_json(manifest_relative)
    require(isinstance(files, list) and bool(files), "empty database content manifest")
    expected = set()
    for item in files:
        relative = item["path"]
        require(relative not in expected and ".git" not in Path(relative).parts,
                "duplicate/unsafe database content path")
        expected.add(relative)
        path = repo_file(f"{DATABASE}/{relative}")
        require(path.stat().st_size == item["bytes"] and sha(path) == item["sha256"],
                f"reference content differs: {relative}")
    actual = set()
    for path in (ROOT / DATABASE).rglob("*"):
        relative = path.relative_to(ROOT / DATABASE)
        if ".git" in relative.parts:
            continue
        require(not path.is_symlink(), "database contains a symlink")
        if path.is_file():
            actual.add(str(relative))
    require(actual == expected, "database has missing or additional files")
    return {**result, "tracked_content_manifest_sha256": DB_CONTENT_SHA,
            "files": len(expected)}


def validate_audit(audit: dict, exit_code: int, package_count: int) -> None:
    require(exit_code == 0, "cargo-audit did not exit successfully with warnings denied")
    require(audit.get("database", {}).get("advisory-count") == 1386, "advisory count changed")
    require(audit.get("lockfile", {}).get("dependency-count") == package_count,
            "audit did not scan complete current lock membership")
    settings = audit.get("settings", {})
    require(settings.get("ignore") == [] and settings.get("target_arch") == []
            and settings.get("target_os") == [] and settings.get("severity") is None,
            "audit suppression or target/severity filter present")
    require(audit.get("vulnerabilities") == {"found": False, "count": 0, "list": []},
            "dependency vulnerability reported")
    require(audit.get("warnings") == {}, "dependency warning reported")


def execute() -> dict:
    cases, commands, source_paths = [], [], {"scripts/verify-dependency-audit.py", "scripts/bootstrap-reference-db.py", "scripts/capture-remediation-dependencies.py", INVENTORY, TOOL}

    def passed(case_id: str, **details) -> None:
        cases.append({"id": case_id, "pass": True, "status": "pass", "executed": True, **details})

    require(sha(repo_file(INVENTORY)) == INVENTORY_SHA, "pinned audit inventory changed")
    inventory = read_json(INVENTORY)
    require(inventory.get("schema") == "fogvault-dependency-audit-snapshot/v1", "inventory schema changed")
    require(sha(repo_file(TOOL)) == TOOL_SHA, "cargo-audit executable differs")
    version = run([str(ROOT / TOOL), "--version"])
    commands.append(version)
    require(version["exit_code"] == 0 and version["stdout"].strip() == "cargo-audit 0.22.2",
            "cargo-audit version differs")
    passed("dependency-tool-identity", sha256=TOOL_SHA)

    database = database_state()
    passed("dependency-reference-database-identity", **database)
    source_paths.add(DB_CONTENT_MANIFEST)
    for row in read_json(DB_CONTENT_MANIFEST):
        source_paths.add(f"{DATABASE}/{row['path']}")

    for item in inventory["artifacts"]:
        path = repo_file(item["path"])
        require(path.stat().st_size == item["bytes"] and sha(path) == item["sha256"],
                f"baseline audit artifact changed: {item['path']}")
        source_paths.add(item["path"])
    baseline_commands = read_json(f"{EVIDENCE}/commands.json")
    require([r["name"] for r in baseline_commands] == [name for name, _ in LOCKS],
            "baseline audit commands differ")
    passed("dependency-baseline-artifact-hashes", inventory_sha256=INVENTORY_SHA,
           artifacts=len(inventory["artifacts"]))

    lock_rows = {row["name"]: row for row in inventory["locks"]}
    metadata_rows = {row["name"]: row for row in read_json(f"{EVIDENCE}/metadata-commands.json")}
    require(set(lock_rows) == set(metadata_rows) == {name for name, _ in LOCKS},
            "lock/metadata membership differs")
    for (name, directory), original in zip(LOCKS, baseline_commands):
        lock = f"{directory}/Cargo.lock"
        manifest = f"{directory}/Cargo.toml"
        require(lock_rows[name]["lockfile"] == lock and original["lockfile"] == lock,
                "lock path differs")
        current = sha(repo_file(lock))
        require(current == lock_rows[name]["lock_sha256"] == metadata_rows[name]["lock_sha256"]
                == original["lock_sha256_before"] == original["lock_sha256_after"],
                f"stale audit lock: {name}")
        require(sha(repo_file(manifest)) == metadata_rows[name]["manifest_sha256"],
                f"stale metadata manifest: {name}")
        validate_audit(read_json(f"{EVIDENCE}/{name}.json"), original["exit_code"],
                       lock_rows[name]["lock_package_count"])
        source_paths.update((lock, manifest))
    before = {path: sha(repo_file(path)) for path in sorted(source_paths)}
    passed("dependency-current-locks-and-manifests", locks=len(LOCKS), unchanged=True)

    audits = {}
    for name, directory in LOCKS:
        command = [str(ROOT / TOOL), "audit", "--json", "--deny", "warnings", "--no-fetch",
                   "--db", str(ROOT / DATABASE), "--file", str(ROOT / directory / "Cargo.lock")]
        result = run(command)
        commands.append(result)
        try:
            audit = json.loads(result["stdout"])
        except json.JSONDecodeError as error:
            raise ValueError(f"cargo-audit returned no valid JSON for {name}: {result}") from error
        audits[name] = audit
        try:
            validate_audit(audit, result["exit_code"], lock_rows[name]["lock_package_count"])
        except ValueError as error:
            # Preserve all findings and raw command output in the failed proof.
            raise AuditFailure(f"{name}: {error}", result, audit) from error
        passed(f"dependency-{name}-fresh-audit", lock_sha256=lock_rows[name]["lock_sha256"],
               scanned_packages=lock_rows[name]["lock_package_count"], vulnerabilities=0, warnings=0)

    require(database_state() == database, "reference database changed during fresh audits")
    require(before == {path: sha(repo_file(path)) for path in sorted(source_paths)},
            "dependency audit inputs changed during execution")
    passed("dependency-input-stability", source_files=len(before), locks_unchanged=True)
    require(tuple(row["id"] for row in cases) == REQUIRED_CASE_IDS, "incomplete audit proof")
    return {"schema": "fogvault-dependency-audit-proof/v1", "scope": "pinned-local-database-current-lock-advisory-match",
            "pass": True, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "executed_case_ids": [row["id"] for row in cases], "cases": cases,
            "source_identity": before, "database": database, "audits": audits, "commands": commands,
            "network_database_refresh": False, "warnings_denied": True,
            "limitations": ["No matching advisory/warning is not proof of absence of vulnerabilities or malicious dependencies.",
                            "No construction, side-channel, license, C/JS/platform, provider, hardware or release qualification.",
                            "Rejected diagnostic Rust age graphs have separate unsuppressed failed reports; no qualified production backend is selected."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Fresh JSON proof path")
    args = parser.parse_args()
    require(not args.output.exists(), "output path already exists; use a fresh path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        report = execute()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report = {"schema": "fogvault-dependency-audit-proof/v1", "scope": "pinned-local-database-current-lock-advisory-match",
                  "pass": False, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                  "error": str(error), "limitations": ["Failed proof; no advisory or security clearance."]}
        if isinstance(error, AuditFailure):
            report["audit_failure"] = error.details
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "output": str(args.output),
                      "cases": len(report.get("cases", [])), "error": report.get("error")}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
