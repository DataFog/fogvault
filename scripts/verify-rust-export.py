#!/usr/bin/env python3
"""Run the isolated Rust age/export staging proof and pinned Go interoperability.

Synthetic data only; no plaintext data temporary files, no Git or DB fetch.
This proves selected construction behavior, not maintained native restoration,
receipt persistence, physical durability or production backend qualification.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "experiments/export-prototype"
MANIFEST = PROJECT / "Cargo.toml"
GO = ROOT / "research/review-dependencies/age-v1.3.2/bin/age"
AUDIT = ROOT / "research/review-dependencies/cargo-audit-v0.22.2/bin/cargo-audit"
DB = ROOT / "research/review-dependencies/advisory-db"
GO_SHA = "4012dfc2725883beafb710894af4f599b7a94f8c8e0f51f02cc96ab8df33915e"
AUDIT_SHA = "b4f48ca2b4b57bde3846f876dbcb6f72c056b27cc86d701413ecdc156f96dfcb"
DB_MANIFEST_SHA = "0b10a7454c6dd40a226a4dbcbfa0e9a3e70a2662ec175afdfd2fabf1d4e6a09c"
REQUIRED_RUST_CASES = (
    "rust_age_complete_stream_activates_only_encrypted_finished_stage",
    "rust_age_complete_inner_in_nonfinal_chunk_never_activates",
    "rust_age_every_truncation_tamper_trailing_wrong_identity_never_activates",
    "rust_age_admission_precedes_identity_work_and_body_allocation",
    "rust_age_origin_receipt_source_and_owner_authority_are_separate",
    "rust_age_all_fixed_payload_vectors_and_truncated_inner_frames_reject",
    "rust_age_sixteen_mib_payload_streams_to_encrypted_stage_with_bounded_application_buffer",
    "rust_age_sink_failure_never_issues_finished_export_receipt",
)
CASE_IDS = (*REQUIRED_RUST_CASES, "rust_age_go_x25519_interop_both_directions", "rust_age_wasm_target_compiles", "rust_age_dependency_advisory_and_license_inventory", "rust_age_source_stability")


def sha(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def identities() -> dict:
    files = [Path(__file__), MANIFEST, PROJECT / "Cargo.lock", GO, AUDIT]
    for directory in (PROJECT / "src", PROJECT / "tests", PROJECT / "provenance"):
        files.extend(p for p in directory.rglob("*") if p.is_file())
    files.extend((ROOT / "conformance").glob("export-vectors*"))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(files))}


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; select a fresh evidence path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs = args.output.parent / (args.output.stem + ".logs")
    logs.mkdir(exist_ok=False)
    before = identities()
    commands, cases = [], []
    report = {"schema": "fogvault-rust-export-proof/v1", "pass": False, "functional_pass": False, "audit_pass": False, "backend_dependency_qualified": False, "backend_selected_for_production":False, "backend": {"crate":"age", "version":"0.11.5", "default_features":False}, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "source_identity": before, "cases": cases, "commands": commands, "environment": {"platform": platform.platform(), "python": sys.version}}

    def run(name, command, *, input_bytes=None, pass_fds=(), secret_output=False, allow_failure=False):
        result = subprocess.run([str(v) for v in command], cwd=ROOT, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds, env={**os.environ, "CARGO_TERM_COLOR": "never"})
        path = logs / (name + ".log")
        if secret_output:
            path.write_text("Ephemeral test identity output retained in memory only; not logged.\n")
        else:
            # Binary ciphertext/plaintext output is compared in memory; store
            # only its identity, never plaintext record data or private keys.
            if name in {"go-decrypt-rust", "go-encrypt-records"}:
                path.write_text(json.dumps({"stdout_bytes": len(result.stdout), "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr": result.stderr.decode(errors="replace")}, indent=2) + "\n")
            else:
                path.write_bytes(result.stdout + b"\nSTDERR\n" + result.stderr)
        commands.append({"id": name, "command": [str(v) for v in command], "exit_code": result.returncode, "log": str(path), "log_sha256": sha(path)})
        if result.returncode and not allow_failure:
            raise ValueError(f"{name} failed; inspect retained log")
        return result

    try:
        require(sha(GO) == GO_SHA and sha(AUDIT) == AUDIT_SHA, "pinned executable identity mismatch")
        report["environment"]["rustc"] = run("rust-version", ["rustc", "--version"]).stdout.decode().strip()
        report["environment"]["go_age"] = run("go-age-version", [GO, "--version"]).stdout.decode().strip()
        run("format", ["cargo", "fmt", "--manifest-path", MANIFEST, "--check"])
        run("clippy", ["cargo", "clippy", "--locked", "--manifest-path", MANIFEST, "--all-targets", "--", "-D", "warnings"])
        result = run("rust-contracts", ["cargo", "test", "--locked", "--manifest-path", MANIFEST, "--", "--test-threads=1", "--nocapture"])
        executed = set(re.findall(r"^test (\S+) \.\.\. (?:[^\n]*\n)?ok$", result.stdout.decode(), re.MULTILINE))
        for case in REQUIRED_RUST_CASES:
            # The large-stream case emits observation text before its ok line.
            require(re.search(r"^test " + re.escape(case) + r" \.\.\. (?:ok|[^\n]*\nok)$", result.stdout.decode(), re.MULTILINE), "required Rust behavior did not pass: " + case)
            cases.append({"id": case, "status": "pass", "executed": True})
        run("build", ["cargo", "build", "--locked", "--manifest-path", MANIFEST])
        metadata = json.loads(run("metadata", ["cargo", "metadata", "--locked", "--manifest-path", MANIFEST, "--format-version", "1"]).stdout)
        binary = Path(metadata["target_directory"]) / "debug/fogvault-export-feasibility"
        with tempfile.TemporaryDirectory(prefix="fogvault-rust-age-interop-") as temporary:
            folder = Path(temporary)
            identity_lines = run("ephemeral-keygen", [binary, "keygen"], secret_output=True).stdout.splitlines()
            require(len(identity_lines) == 2 and identity_lines[0].startswith(b"AGE-SECRET-KEY-"), "unexpected test identity shape")
            secret, recipient = identity_lines
            cipher_path = folder / "rust.age"
            receipt = json.loads(run("rust-export", [binary, "export-records", recipient.decode(), cipher_path]).stdout)
            ciphertext = cipher_path.read_bytes()
            require(hashlib.sha256(ciphertext).hexdigest() == receipt["ciphertext_sha256"], "Rust receipt does not identify completed ciphertext")
            key_read, key_write = os.pipe()
            try:
                os.write(key_write, secret + b"\n")
                os.close(key_write)
                clear = run("go-decrypt-rust", [GO, "--decrypt", "-i", f"/dev/fd/{key_read}"], input_bytes=ciphertext, pass_fds=(key_read,)).stdout
                require(clear == (ROOT / "conformance/export-vectors-records.bin").read_bytes(), "Go did not decrypt exact Rust FVEXP001 frame")
            finally:
                os.close(key_read)
            go_cipher = run("go-encrypt-records", [GO, "--encrypt", "-r", recipient.decode()], input_bytes=clear).stdout
            go_path = folder / "go.age"
            go_path.write_bytes(go_cipher)
            go_digest = hashlib.sha256(go_cipher).hexdigest()
            activation = json.loads(run("rust-import-go", [binary, "import-records", go_path, folder / "scratch.age", folder / "active.age", go_digest], input_bytes=secret + b"\n").stdout)
            require(all(activation.get(field) is True for field in ("inner_complete", "outer_complete", "origin_verified", "stage_complete", "activated")), "Rust did not complete all import gates")
            require((folder / "active.age").read_bytes().startswith(b"age-encryption.org/v1\n") and not (folder / "scratch.age").exists(), "activation did not publish only completed encrypted staging")
            cases.append({"id": "rust_age_go_x25519_interop_both_directions", "status": "pass", "executed": True, "go_age_version": report["environment"]["go_age"], "rust_to_go_ciphertext_sha256": receipt["ciphertext_sha256"], "go_to_rust_ciphertext_sha256": go_digest, "inner_frame_bytes": len(clear), "plaintext_data_temporary_files": False, "activation": activation})
            # Python/runtime copies of synthetic plaintext/test keys are not a
            # universal zeroization guarantee. No keys or clear bytes logged.
            del secret, identity_lines, clear
        run("wasm-check", ["cargo", "check", "--locked", "--manifest-path", MANIFEST, "--target", "wasm32-unknown-unknown"])
        cases.append({"id": "rust_age_wasm_target_compiles", "status": "pass", "executed": True, "runtime_executed": False})
        report["functional_pass"] = True
        inventory = ROOT / "experiments/export-prototype/provenance/dependency-inventory.json"
        require(inventory.is_file(), "dependency/license/source inventory missing")
        locked = tomllib.loads((PROJECT / "Cargo.lock").read_text())["package"]
        declared = json.loads(inventory.read_text())
        require({(p["name"], p["version"], p.get("checksum")) for p in locked} == {(p["name"], p["version"], p.get("checksum")) for p in declared["packages"]}, "dependency inventory differs from exact lock")
        db_manifest = ROOT / "artifacts/review-readiness/dependency-audit/advisory-db-files.json"
        require(sha(db_manifest) == DB_MANIFEST_SHA, "reference advisory manifest changed")
        for item in json.loads(db_manifest.read_text()):
            require(sha(DB / item["path"]) == item["sha256"], "reference advisory content changed")
        audit = run("dependency-audit", [AUDIT, "audit", "--json", "--deny", "warnings", "--no-fetch", "--db", DB, "--file", PROJECT / "Cargo.lock"], allow_failure=True)
        audit_json = json.loads(audit.stdout)
        report["dependency_audit"] = audit_json
        if audit.returncode != 0 or audit_json["vulnerabilities"]["count"] or audit_json["warnings"]:
            cases.append({"id": "rust_age_dependency_advisory_and_license_inventory", "status": "fail", "executed": True, "package_count": len(locked), "advisories": [row["advisory"]["id"] for row in audit_json["vulnerabilities"]["list"]], "warnings": [row["advisory"]["id"] for rows in audit_json["warnings"].values() for row in rows], "suppression_applied":False})
        require(audit.returncode == 0 and audit_json["vulnerabilities"]["count"] == 0 and not audit_json["warnings"], "dependency advisory/warning check failed; no suppression applied")
        report["audit_pass"] = True
        cases.append({"id": "rust_age_dependency_advisory_and_license_inventory", "status": "pass", "executed": True, "package_count": len(locked), "advisory_revision": audit_json["database"]["last-commit"], "license_clearance": False})
        require(before == identities(), "proof sources changed during execution")
        cases.append({"id": "rust_age_source_stability", "status": "pass", "executed": True})
        require({row["id"] for row in cases} == set(CASE_IDS), "proof case inventory mismatch")
        report["pass"] = True
    except (OSError, ValueError, KeyError) as error:
        report["error"] = str(error)
    if not any(row["id"] == "rust_age_source_stability" for row in cases):
        stable = before == identities()
        cases.append({"id":"rust_age_source_stability", "status":"pass" if stable else "fail", "executed":True})
        if not stable:
            report["pass"] = False
            report["functional_pass"] = False
            report["error"] = str(report.get("error", "")) + "; proof sources changed during execution"
    report["limitations"] = ["age0.11.5 remains an upstream beta/experimental diagnostic candidate; strictdependencywarnings block production selection", "actual Rust/Go interoperability runs on one Applearm64 runtime; WASM is compile-only", "new encrypted-artifact publication proof, not native vault import/replace-existing CAS", "receipt/owner authority supplied by trusted caller; persistence/loss/freshness provider not qualified", "application chunk counters are not total process/backend memory bounds", "filesystem hard-link/sync behavior is local evidence, not cross-OS/power-cut durability", "RustSec pinned dated advisory match is not supply-chain, license or unknown-vulnerability clearance", "no P3 browser/mobile provider bridge or physical floor qualification"]
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(("PASS" if report["pass"] else "FAIL") + " Rust export proof: " + str(args.output))
    if not report["pass"]:
        print(report.get("error", "unknown failure"), file=sys.stderr)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
