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
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PREVIOUS_EVIDENCE = "artifacts/publication/dependency-audit-maintained-20261030"
PREVIOUS_INVENTORY_SHA = "9c510df09e569bd115af1ddc928a2f99aa309251eab315dd70c226e7db5eba98"
PREVIOUS_PACKAGING_EVIDENCE = "artifacts/publication/dependency-audit-core-v1-packaging-20261030"
PREVIOUS_PACKAGING_INVENTORY_SHA = "a877d179ab758323152eef59a262f6e5f28b8ab95e63904b97de4e58fa3c5244"
EVIDENCE = "artifacts/publication/dependency-audit-core-v1-narrow-forks-20261030"
INVENTORY = f"{EVIDENCE}/inventory.json"
INVENTORY_SHA = "b0469a782d34d9cf0f45c6c888c6bf12ffcf008931794bfc49a8684ae5abd555"
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
FORKS = {
    "fogvault-age": ("age", "0.11.5"),
    "fogvault-i18n-config": ("i18n-config", "0.4.8"),
    "fogvault-i18n-embed": ("i18n-embed", "0.16.0"),
    "fogvault-i18n-embed-impl": ("i18n-embed-impl", "0.8.4"),
    "fogvault-i18n-embed-fl": ("i18n-embed-fl", "0.10.1"),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
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


def upstream_projection(text: str, forks: dict | None = None) -> tuple[str, list[dict]]:
    """Advisory identities only; never a build lock or assertion of source parity.

    RustSec excludes path packages. Project known vendored forks to their original
    registry names AND versions AND registry source, retaining every other member.
    The actual unmodified lock is always audited separately.
    """
    forks = FORKS if forks is None else forks
    data = tomllib.loads(text)
    require(set(data) <= {"version", "package"}, "unsupported lock top-level fields")
    rows, mappings = [], []
    for original in data["package"]:
        require(set(original) <= {"name", "version", "source", "checksum", "dependencies", "replace"},
                "unsupported lock package fields")
        row = dict(original)
        if row["name"] in forks:
            name, version = forks[row["name"]]
            require(row["version"] == version and row.get("source") in (None, REGISTRY),
                    f"fork version/source drift: {row['name']}")
            mappings.append({"actual_name": row["name"], "actual_version": row["version"],
                             "upstream_name": name, "upstream_version": version,
                             "projected_source": REGISTRY})
            row.update(name=name, version=version, source=REGISTRY)
            row.pop("checksum", None)
        dependencies = []
        for dependency in row.get("dependencies", []):
            first, separator, tail = dependency.partition(" ")
            dependencies.append((forks[first][0] if first in forks else first) + separator + tail)
        if "dependencies" in row:
            row["dependencies"] = dependencies
        rows.append(row)
    identities = [(row["name"], row["version"], row.get("source")) for row in rows]
    require(len(set(identities)) == len(identities), "upstream projection collides with another package")
    lines = [f'version = {data["version"]}', ""]
    for row in rows:
        lines.append("[[package]]")
        for key, value in row.items():
            lines.append(f"{key} = {json.dumps(value)}")
        lines.append("")
    projected = "\n".join(lines)
    require(len(tomllib.loads(projected)["package"]) == len(data["package"]), "projection lost packages")
    return projected, mappings


def audit_lock(lock: Path) -> tuple[dict, dict]:
    command = [str(ROOT / TOOL), "audit", "--json", "--deny", "warnings", "--no-fetch",
               "--db", str(ROOT / DATABASE), "--file", str(lock)]
    result = run(command)
    try:
        audit = json.loads(result["stdout"])
    except json.JSONDecodeError as error:
        raise ValueError(f"cargo-audit returned no valid JSON: {result}") from error
    return result, audit


def fork_manifest_identities() -> dict:
    identities = {}
    for renamed, (upstream, version) in FORKS.items():
        relative = f"crates/fogvault-backup/vendor/{upstream}-{version}/Cargo.toml"
        package = tomllib.loads(repo_file(relative).read_text())["package"]
        require((package["name"], package["version"]) == (renamed, version), "vendored fork identity differs")
        provenance = package.get("metadata", {}).get("fogvault-upstream", {})
        require((provenance.get("name"), provenance.get("version")) == (upstream, version),
                "vendored fork upstream identity differs")
        identities[relative] = sha(repo_file(relative))
    return identities


def validate_capture() -> dict:
    """Portable validation of immutable executed evidence, not a fresh audit."""
    paths = {"scripts/verify-dependency-audit.py", "scripts/test-dependency-audit.py", INVENTORY, TOOL, DB_CONTENT_MANIFEST}
    require(sha(repo_file(INVENTORY)) == INVENTORY_SHA, "pinned audit inventory changed")
    require(sha(repo_file(TOOL)) == TOOL_SHA, "captured audit tool identity differs")
    require(sha(repo_file(DB_CONTENT_MANIFEST)) == DB_CONTENT_SHA, "pinned database content identity differs")
    inventory = read_json(INVENTORY)
    require(inventory.get("schema") == "fogvault-dependency-audit-snapshot/v1" and inventory.get("pass") is True,
            "invalid or failed audit capture")
    require(inventory["advisory_database"] == {"revision": DB_REVISION, "tree": DB_TREE,
            "tracked_content_manifest_sha256": DB_CONTENT_SHA, "files": 1405}, "captured database differs")
    for directory, expected_sha in ((PREVIOUS_EVIDENCE, PREVIOUS_INVENTORY_SHA),
                                    (PREVIOUS_PACKAGING_EVIDENCE, PREVIOUS_PACKAGING_INVENTORY_SHA),
                                    (EVIDENCE, INVENTORY_SHA)):
        relative = f"{directory}/inventory.json"
        require(sha(repo_file(relative)) == expected_sha, "immutable audit inventory changed")
        paths.add(relative)
        for item in read_json(relative)["artifacts"]:
            artifact = repo_file(item["path"])
            require(artifact.stat().st_size == item["bytes"] and sha(artifact) == item["sha256"],
                    f"immutable audit artifact changed: {item['path']}")
            paths.add(item["path"])
    for relative, digest in inventory["source_identity"].items():
        require(sha(repo_file(relative)) == digest, f"stale audit source manifest: {relative}")
        paths.add(relative)
    require(all(inventory["source_identity"].get(relative) == digest for relative, digest in fork_manifest_identities().items()),
            "fork upstream metadata not covered by receipt")
    rows = {row["name"]: row for row in inventory["locks"]}
    metadata = {row["name"]: row for row in read_json(f"{EVIDENCE}/metadata-commands.json")}
    commands = read_json(f"{EVIDENCE}/commands.json")
    names = [name + suffix for name, _ in LOCKS for suffix in ("", "-upstream")]
    require([row["name"] for row in commands] == names, "incomplete captured audit commands")
    require(set(rows) == set(metadata) == {name for name, _ in LOCKS}, "capture graph membership differs")
    captured = {row["name"]: row for row in commands}
    for name, directory in LOCKS:
        lock, manifest = f"{directory}/Cargo.lock", f"{directory}/Cargo.toml"
        require(rows[name]["lockfile"] == lock and metadata[name]["exit_code"] == 0, "capture metadata failed or wrong lock")
        require(sha(repo_file(lock)) == rows[name]["lock_sha256"] == metadata[name]["lock_sha256"], "captured lock is stale")
        require(sha(repo_file(manifest)) == metadata[name]["manifest_sha256"], "captured manifest is stale")
        require(len(tomllib.loads(repo_file(lock).read_text())["package"]) == rows[name]["lock_package_count"], "captured package count differs")
        projected, mappings = upstream_projection(repo_file(lock).read_text())
        projection = rows[name]["upstream_projection"]
        require(projection["mappings"] == mappings and repo_file(projection["path"]).read_text() == projected
                and sha(repo_file(projection["path"])) == projection["sha256"], "upstream advisory projection differs")
        paths.update((lock, manifest, projection["path"]))
        for suffix, relative in (("", lock), ("-upstream", projection["path"])):
            command = captured[name + suffix]
            require(command["lockfile"] == relative and command["lock_sha256_before"] == command["lock_sha256_after"] == sha(repo_file(relative)),
                    "captured audit used a different lock")
            argv = command["command"]
            require(len(argv) == 10 and argv[1:7] == ["audit", "--json", "--deny", "warnings", "--no-fetch", "--db"]
                    and argv[8] == "--file" and argv[0].endswith("/" + TOOL)
                    and argv[7].endswith("/" + DATABASE) and argv[9].endswith("/" + relative),
                    "captured command changed or contains filters")
            report = read_json(f"{EVIDENCE}/{name}{suffix}.json")
            require(json.loads(command["stdout"]) == report, "captured raw stdout differs")
            validate_audit(report, command["exit_code"], rows[name]["lock_package_count"])
    identity = {relative: sha(repo_file(relative)) for relative in sorted(paths)}
    return {"schema": "fogvault-dependency-audit-capture-validation/v1", "pass": True,
            "executed": True, "audits_reexecuted": False, "captured_audits_validated": len(commands),
            "capture": INVENTORY, "captured_utc": inventory["captured_utc"], "source_identity": identity,
            "limitations": ["Validates immutable previously executed audit evidence against current locks; does not execute cargo-audit or refresh RustSec.",
                            "Projected upstream identities do not prove fork source equivalence or absence of vulnerabilities."]}


def capture_current(output: Path) -> None:
    """Create immutable current-lock evidence; never edit historical snapshots."""
    output = output.resolve()
    require(output.is_relative_to(ROOT) and not output.exists(), "capture needs a fresh workspace path")
    require(sha(repo_file(TOOL)) == TOOL_SHA, "cargo-audit executable differs")
    database = database_state()
    output.mkdir(parents=True)
    commands, metadata_commands, locks, source_identity = [], [], [], fork_manifest_identities()
    all_ok = True
    for name, directory in LOCKS:
        manifest, lock = repo_file(f"{directory}/Cargo.toml"), repo_file(f"{directory}/Cargo.lock")
        before, manifest_sha = sha(lock), sha(manifest)
        metadata = run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                        "--manifest-path", str(manifest)])
        (output / f"{name}-cargo-metadata.json").write_text(metadata["stdout"])
        (output / f"{name}-cargo-metadata.stderr.txt").write_text(metadata["stderr"])
        require(metadata["exit_code"] == 0, f"metadata unavailable for {name}; retained failure")
        resolved = json.loads(metadata["stdout"])
        package_count = len(tomllib.loads(lock.read_text())["package"])
        metadata_commands.append({"name": name, "command": metadata["command"], "exit_code": 0,
                                  "lock_sha256": before, "manifest_sha256": manifest_sha})
        projected, mappings = upstream_projection(lock.read_text())
        projected_path = output / f"{name}-upstream-projection.lock"
        projected_path.write_text(projected)
        for suffix, candidate in (("", lock), ("-upstream", projected_path)):
            started = datetime.now(timezone.utc).isoformat()
            result, audit = audit_lock(candidate)
            (output / f"{name}{suffix}.json").write_text(result["stdout"])
            (output / f"{name}{suffix}.stderr.txt").write_text(result["stderr"])
            try:
                validate_audit(audit, result["exit_code"], package_count)
            except ValueError:
                all_ok = False
            commands.append({"name": name + suffix, **result, "started_utc": started,
                             "completed_utc": datetime.now(timezone.utc).isoformat(),
                             "lockfile": str(candidate.relative_to(ROOT)),
                             "lock_sha256_before": sha(candidate), "lock_sha256_after": sha(candidate)})
        require(sha(lock) == before and sha(manifest) == manifest_sha, f"inputs changed: {name}")
        for package in resolved["packages"]:
            source = Path(package["manifest_path"])
            if source.is_relative_to(ROOT):
                source_identity[str(source.relative_to(ROOT))] = sha(source)
        source_identity[str(lock.relative_to(ROOT))] = before
        locks.append({"name": name, "lockfile": str(lock.relative_to(ROOT)), "lock_sha256": before,
                      "lock_package_count": package_count, "metadata_package_count": len(resolved["packages"]),
                      "upstream_projection": {"path": str(projected_path.relative_to(ROOT)),
                                              "sha256": sha(projected_path), "mappings": mappings}})
    require(database_state() == database, "reference database changed during capture")
    require(all(sha(repo_file(name)) == digest for name, digest in source_identity.items()), "source manifests changed during capture")
    for name, value in (("commands.json", commands), ("metadata-commands.json", metadata_commands)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")
    inventory = {"schema": "fogvault-dependency-audit-snapshot/v1", "captured_utc": datetime.now(timezone.utc).isoformat(),
                 "scope": "exact actual locks plus upstream registry identity projection for renamed path forks",
                 "pass": all_ok, "tool": {"path": TOOL, "sha256": TOOL_SHA}, "advisory_database": database,
                 "locks": locks, "source_identity": source_identity,
                 "previous_snapshot": EVIDENCE,
                 "artifacts": [{"path": str(file.relative_to(ROOT)), "bytes": file.stat().st_size, "sha256": sha(file)}
                               for file in sorted(output.iterdir()) if file.is_file()],
                 "limitations": ["Projected registry identity preserves upstream advisory matching; it does not prove fork source equivalence or security.",
                                 "Pinned database only; no network refresh, suppressions, target filters, or unexecuted profile clearance."]}
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps({"pass": all_ok, "inventory": str(output / "inventory.json"), "sha256": sha(output / "inventory.json")}))
    require(all_ok, "capture retained dependency findings; no clearance")


def execute() -> dict:
    cases, commands, source_paths = [], [], {"scripts/verify-dependency-audit.py", "scripts/bootstrap-reference-db.py", "scripts/capture-remediation-dependencies.py", INVENTORY, TOOL}

    def passed(case_id: str, **details) -> None:
        cases.append({"id": case_id, "pass": True, "status": "pass", "executed": True, **details})

    portable = validate_capture()
    source_paths.update(portable["source_identity"])

    require(sha(repo_file(INVENTORY)) == INVENTORY_SHA, "pinned audit inventory changed")
    historical_inventory = f"{PREVIOUS_EVIDENCE}/inventory.json"
    require(sha(repo_file(historical_inventory)) == PREVIOUS_INVENTORY_SHA, "historical audit inventory changed")
    source_paths.add(historical_inventory)
    for item in read_json(historical_inventory)["artifacts"]:
        old = repo_file(item["path"])
        require(old.stat().st_size == item["bytes"] and sha(old) == item["sha256"], "historical audit artifact changed")
        source_paths.add(item["path"])
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
    baseline_commands = [row for row in read_json(f"{EVIDENCE}/commands.json") if not row["name"].endswith("-upstream")]
    require([r["name"] for r in baseline_commands] == [name for name, _ in LOCKS],
            "baseline audit commands differ")
    passed("dependency-baseline-artifact-hashes", inventory_sha256=INVENTORY_SHA,
           artifacts=len(inventory["artifacts"]))

    lock_rows = {row["name"]: row for row in inventory["locks"]}
    require(all(inventory.get("source_identity", {}).get(relative) == digest
                for relative, digest in fork_manifest_identities().items()), "stale fork manifest provenance")
    require(inventory.get("pass") is True, "baseline audit snapshot contains findings")
    for relative, expected in inventory.get("source_identity", {}).items():
        require(sha(repo_file(relative)) == expected, f"stale dependency source manifest: {relative}")
        source_paths.add(relative)
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
        projected, mappings = upstream_projection(repo_file(lock).read_text())
        projection = lock_rows[name].get("upstream_projection")
        require(projection is not None and projection["mappings"] == mappings,
                f"missing/stale upstream advisory coverage: {name}")
        require(repo_file(projection["path"]).read_text() == projected
                and sha(repo_file(projection["path"])) == projection["sha256"],
                f"stale upstream advisory projection: {name}")
        source_paths.add(projection["path"])
        source_paths.update((lock, manifest))
    before = {path: sha(repo_file(path)) for path in sorted(source_paths)}
    passed("dependency-current-locks-and-manifests", locks=len(LOCKS), unchanged=True)

    audits = {}
    for name, directory in LOCKS:
        for suffix, candidate in (("", ROOT / directory / "Cargo.lock"),
                                  ("-upstream", repo_file(lock_rows[name]["upstream_projection"]["path"]))):
            result, audit = audit_lock(candidate)
            commands.append(result)
            audits[name + suffix] = audit
            try:
                validate_audit(audit, result["exit_code"], lock_rows[name]["lock_package_count"])
            except ValueError as error:
                # Preserve all findings and raw command output in the failed proof.
                raise AuditFailure(f"{name}{suffix}: {error}", result, audit) from error
        passed(f"dependency-{name}-fresh-audit", lock_sha256=lock_rows[name]["lock_sha256"],
               scanned_packages=lock_rows[name]["lock_package_count"], vulnerabilities=0, warnings=0,
               upstream_projection=lock_rows[name]["upstream_projection"])

    require(database_state() == database, "reference database changed during fresh audits")
    require(before == {path: sha(repo_file(path)) for path in sorted(source_paths)},
            "dependency audit inputs changed during execution")
    passed("dependency-input-stability", source_files=len(before), locks_unchanged=True)
    require(tuple(row["id"] for row in cases) == REQUIRED_CASE_IDS, "incomplete audit proof")
    return {"schema": "fogvault-dependency-audit-proof/v1", "scope": "pinned-local-database-current-lock-and-upstream-fork-projection-advisory-match",
            "pass": True, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "executed_case_ids": [row["id"] for row in cases], "cases": cases,
            "source_identity": before, "database": database, "audits": audits, "commands": commands,
            "network_database_refresh": False, "warnings_denied": True,
            "limitations": ["No matching advisory/warning is not proof of absence of vulnerabilities or malicious dependencies.",
                            "Upstream registry identity projection compensates for path-package exclusion; it does not assert fork source equivalence or security.",
                            "No construction, side-channel, license, C/JS/platform, provider, hardware or release qualification.",
                            "Rejected diagnostic Rust age graphs have separate unsuppressed failed reports; no qualified production backend is selected."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="Fresh JSON proof path")
    mode.add_argument("--capture-dir", type=Path, help="Explicitly capture NEW immutable current locks and upstream projections")
    mode.add_argument("--verify-capture", action="store_true", help="Validate historical execution against current locks; never execute audit binary")
    args = parser.parse_args()
    if args.verify_capture:
        print(json.dumps(validate_capture(), indent=2))
        return 0
    if args.capture_dir is not None:
        capture_current(args.capture_dir)
        return 0
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
