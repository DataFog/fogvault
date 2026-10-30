"""Positive and negative delivery admission proofs using synthetic disposable files."""
import importlib.util
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from delivery_inputs import BROWSER_ASSETS, archive_files, browser_package, extract_regular, native_sources


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("delivery_builder", ROOT / "scripts/build-delivery.py")
sdk = load("delivery_sdk", ROOT / "scripts/verify-browser-sdk.py")


def make_tar(path, files, extra=()):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
        for item in extra:
            archive.addfile(item)


def npm_files():
    manifest = {"name": "@datafog/fogvault-browser", "exports": {
        ".": {"types": "./dist/index.d.ts", "import": "./dist/client.mjs"}, "./worker": "./dist/worker.mjs"}}
    return {**{name: b"SYNTHETIC admission fixture" for name in BROWSER_ASSETS},
            "package.json": json.dumps(manifest).encode(), "LICENSE": b"SYNTHETIC license"}


class DeliveryTests(unittest.TestCase):
    def source_tree(self, directory):
        root = Path(directory)
        subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
        required = ["LICENSE", "crates/fogvault/src/lib.rs", "crates/fogvault-native/src/lib.rs",
                    "crates/fogvault-native/examples/native_vault.rs", "crates/fogvault-backup/src/lib.rs"]
        for name in required:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SYNTHETIC reviewed input\n")
        (root / ".gitignore").write_text(".env\n")
        subprocess.run(["git", "add", "--", *required, ".gitignore"], cwd=root, check=True, capture_output=True)
        return root

    def test_native_archive_uses_only_reviewed_index_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.source_tree(directory)
            private = root / "crates/fogvault-native/.env"
            private.write_text("SYNTHETIC_PRIVATE_VALUE=do-not-archive\n")
            other = root / "crates/fogvault-native/unreviewed.txt"
            other.write_text("SYNTHETIC unreviewed input\n")
            template = root / "crates/fogvault-native/.env.example"
            template.write_text("SYNTHETIC_SAFE_TEMPLATE=value\n")
            subprocess.run(["git", "add", str(template)], cwd=root, check=True, capture_output=True)
            selected = {p.relative_to(root).as_posix() for p in native_sources(root)}
            self.assertNotIn(private.relative_to(root).as_posix(), selected)
            self.assertNotIn(other.relative_to(root).as_posix(), selected)
            self.assertIn(template.relative_to(root).as_posix(), selected)
            output = root / "output"
            output.mkdir()
            with mock.patch.object(builder, "ROOT", root):
                archive, rows = builder.native_archive(output)
            members = archive_files(archive, "fogvault-native-sdk")
            self.assertEqual(set(members), {r["path"] for r in rows} | {"README.md"})
            self.assertFalse(any("SYNTHETIC_PRIVATE_VALUE".encode() in data for data in members.values()))
            subprocess.run(["git", "add", "--force", str(private)], cwd=root, check=True, capture_output=True)
            with self.assertRaisesRegex(ValueError, "private delivery path"):
                native_sources(root)

    def test_source_inventory_fails_for_missing_or_symlinked_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.source_tree(directory)
            source = root / "crates/fogvault/src/lib.rs"
            original = Path.is_symlink
            with mock.patch.object(Path, "is_symlink", lambda path: path == source or original(path)):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    native_sources(root)
            source.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                native_sources(root)

    def test_archive_rejects_traversal_private_names_links_and_duplicates_before_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, name in enumerate(("../escape", "/absolute", "package/.env", "package/../escape", "package\\escape")):
                path = root / f"bad-{index}.tgz"
                make_tar(path, [(name, b"SYNTHETIC")])
                with self.assertRaises(ValueError):
                    archive_files(path, "package")
            link = tarfile.TarInfo("package/link")
            link.type, link.linkname = tarfile.SYMTYPE, "../outside"
            make_tar(root / "link.tgz", [], [link])
            with self.assertRaises(ValueError):
                archive_files(root / "link.tgz", "package")
            make_tar(root / "duplicate.tgz", [("package/same", b"a"), ("package/same", b"b")])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                archive_files(root / "duplicate.tgz", "package")
            with self.assertRaises(ValueError):
                extract_regular({"../escape": b"SYNTHETIC"}, root / "extracted")
            self.assertFalse((root / "escape").exists())

    def test_missing_worker_or_wrong_exports_fail_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = npm_files()
            make_tar(root / "complete.tgz", [("package/" + n, d) for n, d in files.items()])
            self.assertEqual(set(browser_package(root / "complete.tgz")), set(files))
            del files["dist/worker.mjs"]
            make_tar(root / "missing.tgz", [("package/" + n, d) for n, d in files.items()])
            run = mock.Mock()
            with self.assertRaisesRegex(ValueError, "worker.mjs"):
                sdk.prepare_consumer(root, root / "missing.tgz", run)
            run.assert_not_called()
            files = npm_files()
            files["package.json"] = b'{"name":"@datafog/fogvault-browser","exports":{}}'
            make_tar(root / "exports.tgz", [("package/" + n, d) for n, d in files.items()])
            with self.assertRaisesRegex(ValueError, "exports"):
                browser_package(root / "exports.tgz")

    def test_example_rebuild_removes_stale_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(ROOT / "packages/browser/scripts/build-examples.mjs", root / "scripts/build-examples.mjs")
            (root / "dist").mkdir()
            (root / "dist/client.mjs").write_text("SYNTHETIC current asset\n")
            for relative in ("examples/website/sdk", "example-build/chrome/sdk", "examples/extension"):
                (root / relative).mkdir(parents=True)
            for relative in ("examples/website/sdk/.env", "example-build/chrome/.env", "example-build/chrome/sdk/stale.mjs"):
                (root / relative).write_text("SYNTHETIC stale file\n")
            for name in ("background.js", "main.mjs", "vault.html", "manifest.chrome.json"):
                (root / "examples/extension" / name).write_text("SYNTHETIC tracked example\n")
            subprocess.run(["node", str(root / "scripts/build-examples.mjs"), "chrome"], check=True, capture_output=True)
            for relative in ("examples/website/sdk/.env", "example-build/chrome/.env", "example-build/chrome/sdk/stale.mjs"):
                self.assertFalse((root / relative).exists())
            self.assertTrue((root / "examples/website/sdk/client.mjs").is_file())
            self.assertTrue((root / "example-build/chrome/sdk/client.mjs").is_file())

    def test_missing_locked_browser_tool_fails_without_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conformance").mkdir()
            for name in ("toolchains.json", "maintained-contract.json"):
                shutil.copyfile(ROOT / "conformance" / name, root / "conformance" / name)
            output = root / "proof.json"
            with mock.patch.object(sdk, "ROOT", root), mock.patch.object(sdk, "identity", return_value={}), \
                    mock.patch.object(sdk, "git_identity", return_value={"input_tree_sha256": "synthetic"}), \
                    mock.patch.object(sdk, "tool_versions", return_value={}), \
                    mock.patch.object(sdk.subprocess, "run", side_effect=AssertionError("must not install or run tools")), \
                    mock.patch.object(sys, "argv", ["verify-browser-sdk.py", "--output", str(output)]), redirect_stdout(io.StringIO()):
                self.assertEqual(sdk.main(), 1)
            report = json.loads(output.read_text())
            self.assertFalse(report["pass"])
            self.assertIn("npm ci", report["error"])
            self.assertEqual(report["commands"], [])


if __name__ == "__main__":
    unittest.main()
