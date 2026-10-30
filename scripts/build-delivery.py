#!/usr/bin/env python3
"""Build reviewed native/browser delivery artifacts without registry publication."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from delivery_inputs import browser_package, native_sources, npm_command, regular_source, tracked_files
from evidence import artifact_identity, git_identity, tool_versions


def run(command, cwd=ROOT):
    subprocess.run(npm_command(command), cwd=cwd, check=True)


def native_archive(output: Path):
    paths = native_sources(ROOT)
    inputs = {path.relative_to(ROOT).as_posix(): path.read_bytes() for path in paths}
    tar_path = output / "fogvault-native-sdk-source.tar.gz"
    readme = ("# Native FogVault SDK source\n\n"
              "Portable core, SQLite adapter, age backup and synthetic conformance inputs.\n"
              "Original code is MIT; vendored material retains its own notices.\n"
              "This engineering candidate is not independent security approval or a registry release.\n\n"
              "Run `cargo run --locked --manifest-path crates/fogvault-native/Cargo.toml "
              "--example native_vault` for the standalone synthetic workflow.\n"
              "See crates/fogvault-native/README.md for APIs and trust requirements.\n").encode()
    with tar_path.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for relative, data in sorted({**inputs, "README.md": readme}.items()):
                info = tarfile.TarInfo("fogvault-native-sdk/" + relative)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                archive.addfile(info, io.BytesIO(data))
    return tar_path, [{"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for relative, data in sorted(inputs.items())]


def zip_bytes(path: Path, files: dict[str, bytes]):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def browser_archives(output: Path):
    run(["npm", "run", "build", "--prefix", "packages/browser"])
    packed = subprocess.run(npm_command(["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(output)]),
                            cwd=ROOT / "packages/browser", check=True, capture_output=True, text=True)
    result = json.loads(packed.stdout)
    if not isinstance(result, list) or len(result) != 1:
        raise ValueError("npm pack must produce exactly one candidate")
    filename = result[0]["filename"]
    if Path(filename).name != filename:
        raise ValueError("npm pack returned an unsafe candidate name")
    package = output / filename
    files = browser_package(package)
    sdk = {"sdk/" + name.removeprefix("dist/"): data for name, data in files.items() if name.startswith("dist/")}
    approved = {path.relative_to(ROOT).as_posix() for path in tracked_files(ROOT, ("packages/browser/examples",))}
    inputs = {}

    def example(relative):
        if relative not in approved:
            raise ValueError("example input is not in the reviewed source index: " + relative)
        source = regular_source(ROOT, relative)
        data = source.read_bytes()
        inputs[relative] = data
        return data

    website = dict(sdk)
    for name in ("index.html", "main.mjs"):
        website[name] = example("packages/browser/examples/website/" + name)
    zip_bytes(output / "fogvault-website-example.zip", website)
    for browser, filename in (("chrome", "fogvault-chromium-extension-example.zip"),
                              ("firefox", "fogvault-firefox-extension-example.zip")):
        extension = dict(sdk)
        for name in ("background.js", "main.mjs", "vault.html", f"manifest.{browser}.json"):
            extension["manifest.json" if name.startswith("manifest.") else name] = example("packages/browser/examples/extension/" + name)
        zip_bytes(output / filename, extension)
    return package, [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                     for name, data in sorted(inputs.items())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--kind", choices=("native", "browser", "all"), default="all")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not output.is_relative_to(ROOT / "local-only") or output.exists():
        parser.error("output must be a fresh directory under local-only/")
    output.mkdir(parents=True)
    before = git_identity(ROOT)
    native, browser, inputs = None, None, []
    if args.kind in {"native", "all"}:
        native, selected = native_archive(output)
        inputs.extend(selected)
    if args.kind in {"browser", "all"}:
        browser, selected = browser_archives(output)
        inputs.extend(selected)
    # Inputs are exact bytes used, not a promise that a dirty commit SHA identifies them.
    tools = {"rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"]}
    if browser:
        tools.update({"node": ["node", "--version"], "npm": npm_command(["npm", "--version"]),
                      "wasm_bindgen": ["wasm-bindgen", "--version"]})
    if git_identity(ROOT)["input_tree_sha256"] != before["input_tree_sha256"]:
        raise ValueError("reviewed source inputs changed during delivery build")
    manifest = {"schema": "fogvault-delivery-artifacts/v1", "license": "MIT", "kind": args.kind,
                "native": native.name if native else None, "browser": browser.name if browser else None,
                "source": before, "python": platform.python_version(),
                "tools": tool_versions(tools),
                "inputs": inputs, "registry_published": False, "security_qualified": False,
                "artifacts": [artifact_identity(path, ROOT) for path in sorted(output.iterdir()) if path.is_file()]}
    # Keep legacy name/bytes/SHA fields consumed by delivery users.
    for row in manifest["artifacts"]:
        row["name"] = Path(row["path"]).name
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "artifacts": manifest["artifacts"]}, indent=2))


if __name__ == "__main__":
    main()
