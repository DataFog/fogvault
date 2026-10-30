#!/usr/bin/env python3
"""Build local native/browser SDK artifacts without publishing a registry release."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKIP = {"target", "node_modules", ".git", "__pycache__", ".DS_Store"}


def files(directory):
    for path in sorted(directory.rglob("*")):
        if any(part in SKIP for part in path.relative_to(directory).parts):
            continue
        if path.is_symlink():
            raise ValueError(f"symlink refused: {path}")
        if path.is_file():
            yield path


def run(command, cwd=ROOT):
    subprocess.run(command, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not output.is_relative_to(ROOT / "local-only") or output.exists():
        parser.error("output must be a fresh directory under local-only/")
    output.mkdir(parents=True)
    run(["npm", "run", "build", "--prefix", "packages/browser"])
    run(["npm", "run", "test:types", "--prefix", "packages/browser"])
    packed = subprocess.run(["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(output)],
                            cwd=ROOT / "packages/browser", check=True, capture_output=True, text=True)
    browser = json.loads(packed.stdout)[0]
    tar_path = output / "fogvault-native-sdk-source.tar.gz"
    inputs = [ROOT / "LICENSE"]
    for relative in ("crates/fogvault", "crates/fogvault-native", "crates/fogvault-backup", "conformance"):
        inputs.extend(files(ROOT / relative))
    with tar_path.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in sorted(set(inputs)):
                data = path.read_bytes()
                name = "fogvault-native-sdk/" + path.relative_to(ROOT).as_posix()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if path.stat().st_mode & 0o100 else 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
            readme = ("# Native FogVault SDK source\n\n"
                      "This source bundle contains the portable core, maintained SQLite adapter,\n"
                      "age backup package and synthetic conformance inputs. Original code is MIT;\n"
                      "vendored material retains its own notices. It is an engineering baseline,\n"
                      "not independent security approval or a registry release.\n\n"
                      "Run `cargo run --locked --manifest-path crates/fogvault-native/Cargo.toml "
                      "--example native_vault` for the synthetic standalone workflow.\n"
                      "See crates/fogvault-native/README.md for supported APIs and trust requirements.\n").encode()
            info = tarfile.TarInfo("fogvault-native-sdk/README.md")
            info.size = len(readme)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(readme))
    for browser_name in ("chrome", "firefox"):
        run(["node", "packages/browser/scripts/build-examples.mjs", browser_name])
    sources = {
        "fogvault-website-example.zip": ROOT / "packages/browser/examples/website",
        "fogvault-chromium-extension-example.zip": ROOT / "packages/browser/example-build/chrome",
        "fogvault-firefox-extension-example.zip": ROOT / "packages/browser/example-build/firefox",
    }
    for name, directory in sources.items():
        with zipfile.ZipFile(output / name, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files(directory):
                archive.writestr(path.relative_to(directory).as_posix(), path.read_bytes())
    artifacts = []
    for path in sorted(output.iterdir()):
        artifacts.append({"name": path.name, "bytes": path.stat().st_size,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {"schema": "fogvault-delivery-artifacts/v1", "license": "MIT",
                "native": "fogvault-native-sdk-source.tar.gz", "browser": browser["filename"],
                "registry_published": False, "security_qualified": False, "artifacts": artifacts}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "artifacts": artifacts}, indent=2))


if __name__ == "__main__":
    main()
