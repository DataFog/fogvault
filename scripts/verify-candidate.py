#!/usr/bin/env python3
"""Build and consume the native source archive without checkout path dependencies."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from delivery_inputs import archive_files, extract_regular, hashes
from evidence import artifact_identity, git_identity, tool_versions, write_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["native"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("use a fresh report")
    output.parent.mkdir(parents=True, exist_ok=True)
    work, logs = output.with_suffix(".candidate"), output.with_suffix(".logs")
    work.mkdir(exist_ok=False)
    logs.mkdir(exist_ok=False)
    before, commands, cases = git_identity(ROOT), [], []
    package, candidate, failure = None, None, None

    def run(name, command, expected=None):
        result = subprocess.run(list(map(str, command)), cwd=ROOT, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding="utf-8")
        log = logs / (name + ".log")
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        commands.append({"id": name, "command": list(map(str, command)), "exit_code": result.returncode, "log": str(log)})
        passed = result.returncode == 0 if expected is None else result.returncode != 0 and expected in result.stderr
        if not passed:
            raise ValueError(name + " failed; see " + str(log))
        return result.stdout

    try:
        run("build-native-archive", [sys.executable, ROOT / "scripts/build-delivery.py", "--kind", "native", "--output-dir", work / "artifacts"])
        manifest = json.loads((work / "artifacts/manifest.json").read_text())
        package = work / "artifacts" / manifest["native"]
        files = archive_files(package, "fogvault-native-sdk")
        intended = {row["path"]: row["sha256"] for row in manifest["inputs"]}
        if set(files) != set(intended) | {"README.md"} or any(hashlib.sha256(files[name]).hexdigest() != digest for name, digest in intended.items()):
            raise ValueError("native source archive differs from its reviewed input inventory")
        source = work / "source"
        extract_regular(files, source)
        target = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "local-only/quality-cache/native-candidate")))
        run("native-archive-public-flow", ["cargo", "run", "--locked", "--manifest-path", source / "crates/fogvault-native/Cargo.toml",
                                           "--target-dir", target, "--example", "native_vault"])
        cases.append({"id": "native_archive_create_unlock_save_lock_reopen_read", "status": "pass", "executed": True})
        consumer = work / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(
            '[package]\nname="fogvault-installed-source-consumer"\nversion="0.0.0"\nedition="2021"\n'
            '[dependencies]\nfogvault={path=' + json.dumps(str(source / "crates/fogvault")) + '}\n'
            'fogvault-native={path=' + json.dumps(str(source / "crates/fogvault-native")) + '}\n')
        checks = [
            ("default_native_consumer", 'fn main() { let _ = std::any::type_name::<fogvault_native::Host>(); let _ = std::any::type_name::<fogvault_native::Vault>(); }', None),
            ("archive_transitive_crypto_private", 'use fogvault::experimental::crypto::password_key; fn main() {}', 'could not find `experimental`'),
            ("archive_fault_injection_private", 'fn main() { let _ = fogvault_native::CommitFault::BeforeCommit; }', 'could not find `CommitFault`'),
        ]
        for name, code, expected in checks:
            (consumer / "src/main.rs").write_text(code)
            run(name, ["cargo", "check", "--offline", "--manifest-path", consumer / "Cargo.toml", "--target-dir", target], expected)
            cases.append({"id": name, "status": "pass", "executed": True})
        if git_identity(ROOT)["input_tree_sha256"] != before["input_tree_sha256"]:
            raise ValueError("source inputs changed during native archive acceptance")
        candidate = {"package": artifact_identity(package, ROOT), "archive_inputs": hashes(files),
                     "consumer_source": str(source), "checkout_path_dependencies": False}
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = str(error)
    report = {"schema": "fogvault-native-candidate-proof/v1", "pass": failure is None, "executed": True,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "source": before,
              "candidate": candidate, "commands": commands, "cases": cases, "error": failure,
              "tools": tool_versions({"rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"]}),
              "limitations": ["Synthetic independent source-archive consumer; not registry or power-loss qualification."]}
    write_report(output, report)
    print(json.dumps({"pass": report["pass"], "output": str(output), "error": failure}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
