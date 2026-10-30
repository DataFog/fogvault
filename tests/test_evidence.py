"""Behavioral tests for source, artifact and result evidence contracts."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.settings = {"result_schema": "synthetic-browser/v1", "required_cases": ["create", "reject"]}
        self.good = {"schema": "synthetic-browser/v1", "pass": True, "error": None,
                     "cases": [{"id": name, "status": "pass", "executed": True}
                               for name in self.settings["required_cases"]]}

    def test_browser_requires_each_successfully_executed_case(self):
        self.assertEqual(evidence.validate_browser_cases(self.good, self.settings),
                         {"cases": self.settings["required_cases"]})
        for field, value in [("status", "fail"), ("status", "skipped"), ("executed", False),
                             ("executed", 1), ("executed", None)]:
            changed = copy.deepcopy(self.good)
            changed["cases"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                evidence.validate_browser_cases(changed, self.settings)

    def test_browser_rejects_contradictions_missing_duplicates_and_wrong_schemas(self):
        changes = [lambda r: r.update(schema="other/v1"), lambda r: r.update(error="synthetic failure"),
                   lambda r: r.update({"pass": False}),
                   lambda r: r.update(**{"pass": 1}), lambda r: r["cases"].pop(),
                   lambda r: r["cases"].append(copy.deepcopy(r["cases"][0])),
                   lambda r: r["cases"].append({"id": "unexpected", "status": "pass", "executed": True}),
                   lambda r: r.update(cases=None), lambda r: r.update(cases=[None]),
                   lambda r: r["cases"][0].update(id=[])]
        for change in changes:
            changed = copy.deepcopy(self.good)
            change(changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                evidence.validate_browser_cases(changed, self.settings)
        for invalid in [None, [], True, "pass"]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence.validate_browser_cases(invalid, self.settings)

    def test_browser_contract_itself_must_be_well_formed(self):
        for settings in [None, {}, {"result_schema": 1, "required_cases": ["create"]},
                         {"result_schema": "x", "required_cases": []},
                         {"result_schema": "x", "required_cases": ["create", "create"]},
                         {"result_schema": "x", "required_cases": [["create"]]}]:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                evidence.validate_browser_cases(self.good, settings)

    def test_source_snapshot_binds_dirty_bytes_without_copying_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*arguments):
                return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.DEVNULL)
            git("init", "--quiet", "--initial-branch=main")
            git("config", "user.name", "Synthetic audit")
            git("config", "user.email", "synthetic@example.invalid")
            git("config", "core.autocrlf", "false")
            (root / ".gitignore").write_text(".env\n")
            (root / "tracked.txt").write_text("SYNTHETIC original\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "synthetic baseline")
            clean = evidence.snapshot(root)
            self.assertFalse(clean["dirty"])
            self.assertEqual(clean["ref"], "main")
            self.assertEqual(clean["commit"], git("rev-parse", "HEAD").decode().strip())
            (root / "tracked.txt").write_text("SYNTHETIC changed private contents\n")
            (root / "new file.txt").write_text("SYNTHETIC new input\n")
            (root / ".env").write_text("SYNTHETIC ignored credential\n")
            dirty = evidence.snapshot(root)
            self.assertTrue(dirty["dirty"])
            self.assertEqual(dirty["commit"], clean["commit"])
            self.assertNotEqual(dirty["input_tree_sha256"], clean["input_tree_sha256"])
            self.assertNotEqual(dirty["diff_sha256"], clean["diff_sha256"])
            self.assertIn("new file.txt", dirty["input_identity"])
            self.assertNotIn(".env", dirty["input_identity"])
            self.assertNotIn("private contents", json.dumps(dirty))
            self.assertNotIn("ignored credential", json.dumps(dirty))
            (root / "tracked.txt").unlink()
            deleted = evidence.snapshot(root)
            self.assertNotIn("tracked.txt", deleted["input_identity"])
            self.assertTrue(any("tracked.txt" in row for row in deleted["status"]))
            self.assertNotEqual(deleted["diff_sha256"], dirty["diff_sha256"])

    def test_artifact_identity_requires_current_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "synthetic.bin"
            path.write_bytes(b"SYNTHETIC artifact")
            first = evidence.artifact_identity(path, root)
            self.assertEqual(first, {"path": "synthetic.bin", "bytes": 18,
                                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            path.write_bytes(b"SYNTHETIC changed artifact")
            self.assertNotEqual(first["sha256"], evidence.artifact_identity(path)["sha256"])
            path.unlink()
            with self.assertRaises(ValueError):
                evidence.artifact_identity(path)
            with mock.patch.object(Path, "is_symlink", return_value=True), self.assertRaises(ValueError):
                evidence.artifact_identity(path)

    def test_report_capture_is_fresh_and_write_failures_propagate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            evidence.write_report(path, {"pass": True})
            self.assertEqual(json.loads(path.read_text()), {"pass": True})
            with self.assertRaises(FileExistsError):
                evidence.write_report(path, {"pass": False})
            failed = Path(directory) / "failed.json"
            with mock.patch.object(Path, "open", side_effect=OSError("synthetic capture failure")):
                with self.assertRaises(OSError):
                    evidence.write_report(failed, {"pass": True})
            with self.assertRaises(TypeError):
                evidence.write_report(failed, {"unsupported": object()})
            self.assertFalse(failed.exists())

    def test_tool_version_capture_marks_missing_and_nonzero_unavailable(self):
        result = evidence.tool_versions({"python": [sys.executable, "--version"],
                                         "failure": [sys.executable, "-c", "raise SystemExit(7)"],
                                         "missing": ["fogvault-synthetic-missing-tool"]})
        self.assertTrue(result["python"]["available"])
        self.assertFalse(result["failure"]["available"])
        self.assertEqual(result["failure"]["exit_code"], 7)
        self.assertFalse(result["missing"]["available"])


if __name__ == "__main__":
    unittest.main()
