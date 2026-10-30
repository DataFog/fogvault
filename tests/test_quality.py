"""Behavioral proof for environment, whole-diff scope and the stable merge gate."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quality_entry", ROOT / "scripts/quality.py")
q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(q)


class QualityChecks(unittest.TestCase):
    def test_doctor_reports_found_expected_and_repairs_without_installing(self):
        versions = {"git": "git version 2.54.0", "rustc": "rustc 1.94.1", "cargo": "cargo 1.94.1",
                    "rustfmt": "rustfmt 1.8.0", "cargo clippy": "clippy 0.1.94"}
        probe = lambda cmd: versions.get(" ".join(cmd[:-1]))
        self.assertTrue(q.diagnose("native", probe=probe)["pass"])
        versions["rustc"] = "rustc 1.88.0"
        report = q.diagnose("native", probe=probe)
        row = next(r for r in report["checks"] if r["id"] == "rustc")
        self.assertFalse(report["pass"])
        self.assertEqual(row["expected"], q.pins()["rust"])
        self.assertIn("1.88.0", row["found"])
        self.assertTrue(row["repair"])
        versions["rustc"] = None
        self.assertFalse(q.diagnose("native", probe=probe)["pass"])

    def test_gate_requires_every_profile_and_deliberate_docs_scope(self):
        valid = {"plan": {"result": "success", "outputs": {"code": "true"}},
                 "contract": {"result": "success"}, "native": {"result": "success"},
                 "browser": {"result": "success"}, "extensions": {"result": "success"}}
        self.assertTrue(q.gate(valid)["pass"])
        for name in valid:
            for outcome in ("failure", "cancelled", "skipped", None):
                broken = copy.deepcopy(valid)
                broken[name]["result"] = outcome
                with self.assertRaises(ValueError):
                    q.gate(broken)
        docs = copy.deepcopy(valid)
        docs["plan"]["outputs"]["code"] = "false"
        for name in ("native", "browser", "extensions"):
            docs[name]["result"] = "skipped"
        self.assertTrue(q.gate(docs)["pass"])
        self.assertFalse(q.gate(docs)["code"])
        for value in (None, [], {}, {**valid, "surprise": {}}, {**valid, "browser": None}):
            with self.assertRaises(ValueError):
                q.gate(value)

    def test_missing_or_malformed_child_report_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                q.validate_full_report(root)
            nested = root / "run"
            nested.mkdir()
            p = nested / "report.json"
            for report in ({"pass": True, "executed": True},
                           {"schema": "fogvault-verifier/v1", "pass": True, "executed": True, "checks": ["bad"]}):
                p.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    q.validate_full_report(root)
            candidate = root / "candidate.json"
            candidate.write_text('{"pass":true,"executed":true}')
            with self.assertRaises(ValueError):
                q.validate_native_candidate(candidate)

    def test_full_child_proof_binds_inventory_executed_cases_sources_and_logs(self):
        v = q.verifier()
        contract = {"manifest": "experiments/vault-prototype/Cargo.toml",
                    "required_core_cases": ["synthetic_core_accept", "synthetic_core_reject"],
                    "required_native_cases": ["synthetic_native_flow"],
                    "required_fixture_cases": ["synthetic_process_fixture"],
                    "required_backup_cases": ["synthetic_backup_finality"]}
        sources = {"synthetic_input.rs": "a" * 64}
        builtins = {"consumer-pin", "core-boundary", "format-fixtures", "epoch-format-fixtures",
                    "access-format-fixtures", "password-vectors", "source-stability"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            rows = []
            for name in v.required_checks(True):
                row = {"id": name, "required": True, "executed": True, "status": "pass"}
                if name not in builtins:
                    log = run / (name + ".log")
                    log.write_text("SYNTHETIC executed command: " + name + "\n")
                    row.update(command=["synthetic-command", name], exit_code=0, log=str(log))
                groups = {"core-tests": contract["required_core_cases"],
                          "native-tests": contract["required_native_cases"] + contract["required_fixture_cases"],
                          "maintained-backup-tests": contract["required_backup_cases"]}
                if name in groups:
                    row["evidence"] = {"executed_cases": list(groups[name])}
                rows.append(row)
            good = {"schema": "fogvault-verifier/v1", "pass": True, "executed": True,
                    "source_identity": sources, "checks": rows,
                    "behavior_evidence": v.behavior_evidence(rows, contract)}
            path = run / "report.json"
            with mock.patch.object(v, "load_contract", return_value=contract), \
                    mock.patch.object(v, "verification_source_identity", return_value=sources):
                path.write_text(json.dumps(good))
                result = q.validate_full_report(root, v)
                self.assertEqual(result["behavior_evidence"], good["behavior_evidence"])
                self.assertEqual(result["report"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(len(result["logs"]), len(rows) - len(builtins))
                for log in result["logs"]:
                    self.assertEqual(log["sha256"], hashlib.sha256(Path(log["path"]).read_bytes()).hexdigest())

                def check_row(report, name="core-tests"):
                    return next(row for row in report["checks"] if row["id"] == name)

                def missing_case(report, name):
                    check_row(report, name)["evidence"]["executed_cases"].pop()
                    # Even a self-consistent summary cannot excuse omitted behavior.
                    report["behavior_evidence"] = v.behavior_evidence(report["checks"], contract)

                def missing_command(report):
                    row = check_row(report)
                    row.pop("command")
                    row.pop("log")

                mutations = {"missing-stage": lambda r: r["checks"].pop(),
                             "missing-core-case": lambda r: missing_case(r, "core-tests"),
                             "missing-native-case": lambda r: missing_case(r, "native-tests"),
                             "missing-backup-case": lambda r: missing_case(r, "maintained-backup-tests"),
                             "missing-log": lambda r: check_row(r).update(log=str(run / "absent.log")),
                             "missing-command-proof": missing_command,
                             "malformed-command": lambda r: check_row(r).update(command=[]),
                             "failed-command": lambda r: check_row(r).update(exit_code=7),
                             "inconsistent-case-inventory": lambda r: r["behavior_evidence"].update(required_case_count=999),
                             "stale-source": lambda r: r.update(source_identity={"synthetic_input.rs": "b" * 64})}
                for name, mutate in mutations.items():
                    broken = copy.deepcopy(good)
                    mutate(broken)
                    path.write_text(json.dumps(broken))
                    with self.subTest(case=name), self.assertRaises(ValueError):
                        q.validate_full_report(root, v)

    def test_scope_uses_whole_pr_and_actual_stacked_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            git("config", "user.name", "Synthetic quality test")
            git("config", "user.email", "synthetic@example.invalid")
            def commit(name):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic\n")
                git("add", ".")
                git("commit", "-qm", name)
                return git("rev-parse", "HEAD")
            base = commit("README.md")
            commit("docs/guide.md")
            with mock.patch.object(q, "ROOT", root):
                self.assertFalse(q.plan(base)["code"])
                parent = commit("unknown-input.txt")
                commit("docs/followup.md")
                self.assertTrue(q.plan(base)["code"])
                self.assertFalse(q.plan(parent)["code"])
                with self.assertRaises(ValueError):
                    q.plan("missing-target")


if __name__ == "__main__":
    unittest.main()
