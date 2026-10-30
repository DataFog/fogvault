#!/usr/bin/env python3
"""Capture a NEW immutable audit/metadata snapshot; never overwrite old evidence.

Exact pinned local RustSec database match only. Not dependency/code approval.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "research/review-dependencies/cargo-audit-v0.22.2/bin/cargo-audit"
DATABASE = ROOT / "research/review-dependencies/advisory-db"
BASELINE = ROOT / "artifacts/publication/dependency-audit-20261030-mit/inventory.json"
PACKAGES = [("core", "crates/fogvault"), ("native", "experiments/vault-prototype"),
            ("browser", "experiments/browser-prototype"), ("mobile", "experiments/mobile-prototype"),
            ("native-package", "crates/fogvault-native"), ("wasm-package", "crates/fogvault-wasm"),
            ("backup-package", "crates/fogvault-backup")]

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--include-export-diagnostic", action="store_true",
                        help="also scan the rejected experimental export graph; retain findings and fail")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.relative_to(ROOT)
    if output.exists():
        parser.error("snapshot destination already exists; use a fresh path")
    output.mkdir(parents=True)
    baseline = json.loads(BASELINE.read_text())
    if sha(TOOL) != baseline["tool"]["sha256"]:
        raise ValueError("audit executable differs from pinned reference")
    metadata_commands, commands, locks = [], [], []
    all_ok = True
    packages_to_scan = PACKAGES + ([("rust-export", "experiments/export-prototype")]
                                   if args.include_export_diagnostic else [])
    for name, directory in packages_to_scan:
        manifest = ROOT / directory / "Cargo.toml"
        lock = manifest.parent / "Cargo.lock"
        before = sha(lock)
        command = ["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                   "--manifest-path", str(manifest)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        (output / f"{name}-cargo-metadata.json").write_text(result.stdout)
        (output / f"{name}-cargo-metadata.stderr.txt").write_text(result.stderr)
        if result.returncode:
            raise ValueError(f"metadata failed for {name}; retained command output")
        data = json.loads(result.stdout)
        features = {node["id"]: node["features"] for node in data["resolve"]["nodes"]}
        packages = [{key: row.get(key) for key in
                    ("id", "name", "version", "source", "license", "license_file", "manifest_path")}
                    | {"resolved_features": features.get(row["id"], [])} for row in data["packages"]]
        (output / f"{name}-packages.json").write_text(json.dumps(packages, indent=2) + "\n")
        metadata_commands.append({"name": name, "command": command, "exit_code": result.returncode,
            "package_count": len(packages), "manifest_sha256": sha(manifest),
            "lock_sha256": before, "metadata_sha256": sha(output / f"{name}-cargo-metadata.json")})
        command = [str(TOOL), "audit", "--json", "--deny", "warnings", "--no-fetch",
                   "--db", str(DATABASE), "--file", str(lock)]
        started = datetime.now(timezone.utc).isoformat()
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        (output / f"{name}.json").write_text(result.stdout)
        (output / f"{name}.stderr.txt").write_text(result.stderr)
        audit = json.loads(result.stdout)
        all_ok &= result.returncode == 0
        commands.append({"name": name, "lockfile": lock.relative_to(ROOT).as_posix(),
            "lock_sha256_before": before, "lock_sha256_after": sha(lock), "command": command,
            "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
            "exit_code": result.returncode})
        if sha(lock) != before:
            raise ValueError(f"lock changed during snapshot: {name}")
        resolved = {(row["name"], row["version"]): row for row in packages}
        locked = tomllib.loads(lock.read_text())["package"]
        rows = []
        for row in locked:
            available = resolved.get((row["name"], row["version"]))
            rows.append({key: row.get(key) for key in ("name", "version", "source", "checksum")}
                | {"license": available.get("license") if available else None,
                   "metadata_resolved": available is not None,
                   "resolved_features": available["resolved_features"] if available else None})
        locks.append({"name": name, "lockfile": lock.relative_to(ROOT).as_posix(), "lock_sha256": before,
            "lock_package_count": len(locked), "metadata_package_count": len(packages),
            "all_locked_packages": rows, "vulnerabilities": audit.get("vulnerabilities"),
            "warnings": audit.get("warnings")})
    for name, value in [("commands.json", commands), ("metadata-commands.json", metadata_commands)]:
        (output / name).write_text(json.dumps(value, indent=2) + "\n")
    artifacts = [{"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": sha(path)}
                 for path in sorted(output.iterdir()) if path.is_file()]
    inventory = {"schema": "fogvault-dependency-audit-snapshot/v1",
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "current exact locks/features/licenses and dated pinned-database advisory match",
        "tool": baseline["tool"], "advisory_database": baseline["advisory_database"],
        "host": {"platform": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "locks": locks, "artifacts": artifacts, "pass": all_ok,
        "previous_snapshot": BASELINE.relative_to(ROOT).as_posix(),
        "limitations": ["No audit suppressions or target filters; warnings denied; findings are retained.",
            "Metadata can resolve fewer packages than the lock. Missing licenses are not clearance.",
            "No unknown-vulnerability, source/side-channel, C/JS/OS, cryptographic or production approval.",
            "Rejected experimental Rust age graphs have separate unsuppressed failed reports; they are not production-selected."]}
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps({"pass": all_ok, "inventory": str(output / "inventory.json"),
                      "sha256": sha(output / "inventory.json"), "locks": len(locks)}))
    if not all_ok:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
