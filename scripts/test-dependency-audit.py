#!/usr/bin/env python3
"""Advisory coverage must survive local fork renaming; no external services."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import sys

spec = importlib.util.spec_from_file_location("dependency_audit", Path(__file__).with_name("verify-dependency-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ProjectionTests(unittest.TestCase):
    def test_portable_capture_checks_evidence_without_executing_host_tool(self):
        with patch.object(audit, "run", side_effect=AssertionError("must not execute tools")), \
             patch.object(audit, "database_state", side_effect=AssertionError("must not require reference Git objects")):
            result = audit.validate_capture()
        self.assertTrue(result["pass"])
        self.assertFalse(result["audits_reexecuted"])
        self.assertEqual(result["captured_audits_validated"], 14)

    def test_portable_capture_rejects_stale_current_lock_and_failed_projected_audit(self):
        real_sha = audit.sha
        with patch.object(audit, "sha", side_effect=lambda path: "0" * 64 if path == audit.ROOT / "crates/fogvault/Cargo.lock" else real_sha(path)):
            with self.assertRaises(ValueError):
                audit.validate_capture()
        real_read = audit.read_json
        def failed_projection(relative):
            value = real_read(relative)
            if relative == f"{audit.EVIDENCE}/commands.json":
                next(row for row in value if row["name"] == "native-upstream")["exit_code"] = 1
            return value
        with patch.object(audit, "read_json", side_effect=failed_projection):
            with self.assertRaises(ValueError):
                audit.validate_capture()

    def test_preserves_members_and_versions_and_rewrites_dependency_names(self):
        original = '''version = 4
[[package]]
name = "consumer"
version = "1.0.0"
dependencies = ["fogvault-age", "serde 1.0.229"]
[[package]]
name = "fogvault-age"
version = "0.11.5"
[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
        projected, mappings = audit.upstream_projection(original)
        rows = tomllib.loads(projected)["package"]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["dependencies"], ["age", "serde 1.0.229"])
        self.assertEqual(rows[1], {"name": "age", "version": "0.11.5", "source": audit.REGISTRY})
        self.assertEqual(len(mappings), 1)
        self.assertEqual(tomllib.loads(original)["package"][1]["name"], "fogvault-age")
        registry_fork = 'version=4\n[[package]]\nname="fogvault-age"\nversion="0.11.5"\nsource="' + audit.REGISTRY + '"\nchecksum="' + "a" * 64 + '"\n'
        registry_projection, _ = audit.upstream_projection(registry_fork)
        self.assertEqual(tomllib.loads(registry_projection)["package"],
                         [{"name": "age", "version": "0.11.5", "source": audit.REGISTRY}])

    def test_rejects_version_drift_collision_and_unknown_fields(self):
        for text in [
            'version=4\n[[package]]\nname="fogvault-age"\nversion="0.12.0"',
            'version=4\n[[package]]\nname="fogvault-age"\nversion="0.11.5"\nsource="registry+https://example.test"',
            'version=4\n[[package]]\nname="fogvault-age"\nversion="0.11.5"\n[[package]]\nname="age"\nversion="0.11.5"\nsource="' + audit.REGISTRY + '"',
            'version=4\n[[package]]\nname="consumer"\nversion="1.0.0"\nunrecognized=true',
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.upstream_projection(text)

    def test_real_pinned_rustsec_finds_advisory_under_renamed_path_identity(self):
        # This known advisory proves registry-source projection is necessary:
        # cargo-audit excludes a path package even with the correct upstream name.
        original = 'version=4\n[[package]]\nname="fogvault-time-test"\nversion="0.1.45"\n'
        projected, _ = audit.upstream_projection(original, {"fogvault-time-test": ("time", "0.1.45")})
        with tempfile.TemporaryDirectory(prefix="fogvault-advisory-test-") as directory:
            path = Path(directory) / "Cargo.lock"
            path.write_text(original)
            actual_result, actual = audit.audit_lock(path)
            self.assertEqual(actual_result["exit_code"], 0)
            self.assertFalse(actual["vulnerabilities"]["found"])
            path.write_text(projected)
            result, findings = audit.audit_lock(path)
            self.assertNotEqual(result["exit_code"], 0)
            self.assertIn("RUSTSEC-2020-0071", [row["advisory"]["id"] for row in findings["vulnerabilities"]["list"]])
            with self.assertRaises(ValueError):
                audit.validate_audit(findings, result["exit_code"], 1)


if __name__ == "__main__":
    if "--portable" in sys.argv:
        # A distinct suite, not a skipped platform check or a fresh audit claim.
        names = [name for name in unittest.defaultTestLoader.getTestCaseNames(ProjectionTests)
                 if name != "test_real_pinned_rustsec_finds_advisory_under_renamed_path_identity"]
        result = unittest.TextTestRunner().run(unittest.TestSuite(ProjectionTests(name) for name in names))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
