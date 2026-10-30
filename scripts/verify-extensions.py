#!/usr/bin/env python3
"""Run packaged Chromium/Firefox extension acceptance and retain exact evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources
from delivery_inputs import npm_command


def identity():
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set([Path(__file__), ROOT / "conformance/maintained-contract.json", *maintained_sources(ROOT)]))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("use a fresh output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    before = identity()
    command = ["npm", "run", "--silent", "test:extensions", "--prefix", "packages/browser", "--", "--reporter=json"]
    command = npm_command(command)
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    raw = args.output.with_suffix(".playwright.json")
    raw.write_text(result.stdout)
    args.output.with_suffix(".stderr.log").write_text(result.stderr)
    failure, evidence = None, None
    try:
        evidence = json.loads(result.stdout)
        stats = evidence["stats"]
        if result.returncode or stats["expected"] != 2 or any(stats[key] for key in ("unexpected", "skipped", "flaky")):
            raise ValueError("both packaged extension tests must pass without skips or flakes")
        if identity() != before:
            raise ValueError("extension inputs changed during execution")
    except (ValueError, KeyError) as error:
        failure = str(error)
    report = {"schema": "fogvault-extension-proof/v1", "pass": failure is None,
              "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "source_identity": before, "command": command, "exit_code": result.returncode,
              "playwright_report": str(raw), "playwright_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
              "stats": evidence.get("stats") if evidence else None, "error": failure,
              "scope": "actual unpacked Chromium MV3 and temporary Firefox WebExtension SDK execution",
              "limitations": ["Not a signed store-installed extension or physical-device qualification.",
                              "Chrome/Edge side-load automation uses bundled Chromium as required by Playwright."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "output": str(args.output), "error": failure}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
