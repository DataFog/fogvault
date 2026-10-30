#!/usr/bin/env python3
"""Prove functional evidence and correct REJECTION of an unqualified backend.

This does not turn the underlying failed audit into a passing backend result.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CASE_IDS = ("rust-age-functional-interop-and-finality-executed",
            "rust-age-unqualified-backend-rejected-with-unsuppressed-audit",
            "rust-age-screening-input-stability")
WARNINGS = {"RUSTSEC-2026-0374", "RUSTSEC-2026-0173"}

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(value: bool, message: str) -> None:
    if not value: raise ValueError(message)

def assess(report: dict, exit_code: int) -> dict:
    require(exit_code == 1 and report.get("schema") == "fogvault-rust-export-proof/v1",
            "the underlying diagnostic must retain its failed result")
    for key in ("pass", "audit_pass", "backend_dependency_qualified", "backend_selected_for_production"):
        require(report.get(key) is False, "unqualified backend must not be accepted: " + key)
    require(report.get("functional_pass") is True, "functional proof did not complete")
    require(report.get("backend") == {"crate": "age", "version": "0.11.5", "default_features": False},
            "screened candidate identity changed; requires new disposition")
    audit = report["dependency_audit"]
    require(audit.get("vulnerabilities") == {"found": False, "count": 0, "list": []},
            "new vulnerability requires explicit disposition")
    warnings = {row["advisory"]["id"] for group in audit["warnings"].values() for row in group}
    require(warnings == WARNINGS, "warning inventory changed; requires new disposition")
    settings = audit["settings"]
    require(settings.get("ignore") == [] and settings.get("target_arch") == []
            and settings.get("target_os") == [] and settings.get("severity") is None,
            "advisory suppression/filter cannot establish rejection evidence")
    cases = {row["id"]: row for row in report["cases"]}
    require(len(cases) == len(report["cases"]), "duplicate diagnostic cases")
    failure = cases.get("rust_age_dependency_advisory_and_license_inventory", {})
    require(failure.get("status") == "fail" and failure.get("executed") is True
            and failure.get("suppression_applied") is False, "failed audit evidence missing")
    for name, row in cases.items():
        if name != "rust_age_dependency_advisory_and_license_inventory":
            require(row.get("status") == "pass" and row.get("executed") is True,
                    "functional/stability case did not execute: " + name)
    return {"warnings": sorted(warnings), "backend_selected_for_production": False,
            "underlying_report_pass": False, "functional_case_ids": sorted(
                name for name in cases if name != "rust_age_dependency_advisory_and_license_inventory")}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "use a fresh report path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    diagnostic = args.output.with_name(args.output.stem + "-rejected-diagnostic.json")
    require(not diagnostic.exists(), "diagnostic destination exists")
    result = {"schema": "fogvault-rust-export-screening/v1", "pass": False,
        "executed": True, "scope": "functional-proof-and-rejection-not-backend-qualification",
        "backend_selected_for_production": False, "underlying_audit_pass": False,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "cases": []}
    try:
        spec = importlib.util.spec_from_file_location("rust_export_diagnostic", ROOT / "scripts/verify-rust-export.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        before = runner.identities() | {"scripts/verify-export-screening.py": sha(Path(__file__))}
        command = [sys.executable, str(ROOT / "scripts/verify-rust-export.py"), "--output", str(diagnostic)]
        executed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        result["command"] = {"arguments": command, "exit_code": executed.returncode,
                             "stdout": executed.stdout, "stderr": executed.stderr}
        report = json.loads(diagnostic.read_text())
        decision = assess(report, executed.returncode)
        expected_names = set(runner.CASE_IDS)
        require({row["id"] for row in report["cases"]} == expected_names,
                "diagnostic omitted a required functional case")
        require(report["source_identity"] == runner.identities(), "stale diagnostic inputs")
        for row in report["commands"]:
            path = Path(row["log"])
            require(path.is_file() and sha(path) == row["log_sha256"], "diagnostic log changed")
        after = runner.identities() | {"scripts/verify-export-screening.py": sha(Path(__file__))}
        require(before == after, "screening inputs changed")
        result.update({"pass": True, "decision": "rejected-for-production-selection", "details": decision,
            "underlying_report": {"path": str(diagnostic), "sha256": sha(diagnostic), "pass": False},
            "source_identity": before, "executed_case_ids": list(CASE_IDS),
            "cases": [{"id": name, "status": "pass", "executed": True} for name in CASE_IDS]})
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
    result["limitations"] = ["Passing means the unqualified backend was rejected, not approved.",
        "The failed audit and its warnings remain unsuppressed in the underlying report.",
        "Production backend selection and all relevant freeze/release gates remain open."]
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"pass": result["pass"], "decision": result.get("decision"),
        "output": str(args.output), "error": result.get("error")}))
    return 0 if result["pass"] else 1

if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
