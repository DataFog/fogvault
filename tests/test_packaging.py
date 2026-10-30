"""Reject unsafe or incomplete registry candidates before running consumers."""
import importlib.util
import io
import json
from unittest import mock
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("registry_packaging", ROOT / "scripts/verify-packaging.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class PackagingChecks(unittest.TestCase):
    def test_archive_admission_requires_registry_metadata_and_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate.crate"
            def write(manifest, license=True):
                files = {"Cargo.toml": manifest.encode(), "src/lib.rs": b""}
                if license:
                    files["LICENSE"] = b"MIT"
                with tarfile.open(archive, "w:gz") as tar:
                    for name, data in files.items():
                        member = tarfile.TarInfo("fogvault-0.1.0/" + name)
                        member.size = len(data)
                        tar.addfile(member, io.BytesIO(data))
            base = '[package]\nname="fogvault"\nversion="0.1.0"\n'
            write(base + '[dependencies.dep]\nversion="=1.0.0"\n')
            self.assertIn("LICENSE", p.admit_archive(archive, "fogvault", "0.1.0"))
            for suffix in ('[dependencies.dep]\npath="../dep"\n',
                           '[target.\'cfg(unix)\'.dependencies.dep]\ngit="https://example.com/dep"\n'):
                write(base + suffix)
                with self.assertRaises(ValueError):
                    p.admit_archive(archive, "fogvault", "0.1.0")
            write(base, license=False)
            with self.assertRaises(ValueError):
                p.admit_archive(archive, "fogvault", "0.1.0")
            write(base.replace('0.1.0', '0.2.0'))
            with self.assertRaises(ValueError):
                p.admit_archive(archive, "fogvault", "0.1.0")

    def test_registry_seeding_rejects_candidate_checksum_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "candidate"
            (source / "index").mkdir(parents=True)
            (source / "fogvault-0.1.0.crate").write_bytes(b"modified archive")
            lock = root / "Cargo.lock"
            lock.write_text('version=4\n[[package]]\nname="fogvault"\nversion="0.1.0"\nsource="' + p.REGISTRY + '"\nchecksum="' + '0' * 64 + '"\n')
            with self.assertRaisesRegex(ValueError, "checksum"):
                p.seed_registry(root / "registry", [lock], source)

    def test_registry_graph_rejects_silent_transitive_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved, candidate = root / "approved.lock", root / "candidate.lock"
            text = 'version=4\n[[package]]\nname="log"\nversion="0.4.34"\nsource="' + p.REGISTRY + '"\nchecksum="abc"\n'
            approved.write_text(text)
            candidate.write_text(text)
            self.assertEqual(p.require_preserved_graph(approved, candidate), 1)
            candidate.write_text(text.replace("0.4.34", "0.4.35"))
            with self.assertRaisesRegex(ValueError, "dependency graph"):
                p.require_preserved_graph(approved, candidate, exact=False)

    def test_quality_rejects_claimed_success_without_evidence(self):
        spec = importlib.util.spec_from_file_location("packaging_quality", ROOT / "scripts/quality.py")
        q = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(q)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            base = {"schema": "fogvault-registry-packaging/v1", "pass": True, "published": False,
                    "source": {"input_tree_sha256": "current"},
                    "cases": ["eight-verified-archives", "registry-only-default-backup-consumer",
                              "beta3-create-unlock-save-lock-reopen-read", "browser-worker-wasm-package"]}
            with mock.patch.object(q, "snapshot", return_value={"input_tree_sha256": "current"}):
                report.write_text(json.dumps(base))
                with self.assertRaisesRegex(ValueError, "omitted"):
                    q.validate_packaging(report)
                base["source"]["input_tree_sha256"] = "stale"
                report.write_text(json.dumps(base))
                with self.assertRaisesRegex(ValueError, "stale"):
                    q.validate_packaging(report)


if __name__ == "__main__":
    unittest.main()
