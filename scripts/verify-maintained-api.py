#!/usr/bin/env python3
"""Compile a real default native consumer and reject transitive diagnostic APIs."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="fogvault-api-consumer-") as directory:
        root = Path(directory)
        (root / "src").mkdir()
        manifest = ('[package]\nname="fogvault-api-consumer"\nversion="0.0.0"\nedition="2021"\n'
                    '[dependencies]\nfogvault={path=' + json.dumps(str(ROOT / "crates/fogvault")) + '}\n'
                    'fogvault-native={path=' + json.dumps(str(ROOT / "crates/fogvault-native")) + '}\n')
        (root / "Cargo.toml").write_text(manifest)
        checks = [
            ("default-native-consumer", 'fn main() { let _ = std::any::type_name::<fogvault_native::Host>(); let _ = std::any::type_name::<fogvault_native::Vault>(); }', None),
            ("transitive-crypto-remains-private", 'use fogvault::experimental::crypto::password_key; fn main() {}', 'could not find `experimental`'),
            ("native-fault-injection-remains-private", 'fn main() { let _ = fogvault_native::CommitFault::BeforeCommit; }', 'could not find `CommitFault`'),
        ]
        for identity, source, expected in checks:
            (root / "src/main.rs").write_text(source)
            result = subprocess.run(["cargo", "check", "--offline", "--manifest-path", str(root / "Cargo.toml"),
                                     "--target-dir", str(ROOT / "crates/fogvault-native/target/api-consumer")],
                                    cwd=ROOT, capture_output=True, text=True)
            passed = result.returncode == 0 if expected is None else result.returncode != 0 and expected in result.stderr
            if not passed:
                print(result.stdout + result.stderr)
                raise SystemExit(f"FAIL {identity}")
            print(f"PASS {identity}")


if __name__ == "__main__":
    main()
