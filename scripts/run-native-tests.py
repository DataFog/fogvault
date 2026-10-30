#!/usr/bin/env python3
"""Run maintained adapter unit tests plus retained consumer/integration regressions."""
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
commands = [
    ["cargo", "test", "--locked", "--manifest-path", str(ROOT / "crates/fogvault-native/Cargo.toml"), "--features", "diagnostics", "--", "--test-threads=1"],
    ["cargo", "test", "--locked", "--manifest-path", str(ROOT / "experiments/vault-prototype/Cargo.toml"), "--all-features", "--", "--test-threads=1"],
]
for command in commands:
    print("Running " + " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise SystemExit(result.returncode)
