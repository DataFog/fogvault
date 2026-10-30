"""Approved delivery inputs and archive admission shared by packaging consumers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

SOURCE_TREES = ("crates/fogvault", "crates/fogvault-native", "crates/fogvault-backup", "conformance")
BROWSER_ASSETS = {
    "dist/client.mjs", "dist/configuration.mjs", "dist/idb.mjs", "dist/password.mjs",
    "dist/worker.mjs", "dist/worker-runtime.mjs", "dist/index.d.ts",
    "dist/wasm/fogvault_wasm.js", "dist/wasm/fogvault_wasm_bg.wasm",
}


def private_name(name: str) -> bool:
    value = name.casefold()
    if value in {".env.example", ".env.sample"}:
        return False  # Existing policy permits explicitly reviewed synthetic templates.
    return value == ".env" or value.startswith(".env.") or value in {"id_rsa", "id_ed25519", ".ds_store"}


def safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(part in {"", ".", "..", ".git", "node_modules", "target"} for part in path.parts)
            or "\\" in name or ":" in name or any(private_name(part) for part in path.parts)):
        raise ValueError(f"unsafe or private delivery path: {name}")
    return path


def regular_source(root: Path, relative: str) -> Path:
    safe_name(relative)
    path = root / relative
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"missing or escaping approved delivery input: {relative}")
    for component in (path, *path.parents):
        if component == root:
            break
        if component.is_symlink():
            raise ValueError(f"symlink delivery input refused: {relative}")
    return path


def tracked_files(root: Path, selections: tuple[str, ...]) -> list[Path]:
    """Only reviewed index paths are source inputs; ignored/untracked files never join a bundle."""
    output = subprocess.run(["git", "ls-files", "--cached", "-z", "--", *selections],
                            cwd=root, capture_output=True, check=True).stdout
    names = sorted(set(name.decode("utf-8") for name in output.split(b"\0") if name))
    return [regular_source(root, name) for name in names]


def native_sources(root: Path) -> list[Path]:
    paths = tracked_files(root, ("LICENSE", *SOURCE_TREES))
    names = {path.relative_to(root).as_posix() for path in paths}
    required = {"LICENSE", "crates/fogvault/src/lib.rs", "crates/fogvault-native/src/lib.rs",
                "crates/fogvault-native/examples/native_vault.rs", "crates/fogvault-backup/src/lib.rs"}
    if not required <= names:
        raise ValueError("native source inventory is incomplete; stage intended source files before packaging")
    return paths


def npm_command(command: list[str]) -> list[str]:
    """Invoke Windows npm batch entry points through Node, without shell quoting."""
    if os.name != "nt" or command[0] not in {"npm", "npx"}:
        return command
    shim, node = shutil.which(command[0] + ".cmd"), shutil.which("node")
    script = Path(shim).parent / "node_modules/npm/bin" / (command[0] + "-cli.js") if shim else None
    if not node or script is None or not script.is_file():
        raise ValueError("Node's npm/npx JavaScript entry point is required on Windows")
    return [node, str(script), *command[1:]]


def archive_files(path: Path, prefix: str) -> dict[str, bytes]:
    """Read regular members only, rejecting traversal, links and duplicate names before extraction."""
    files = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = safe_name(member.name)
            if member.isdir():
                continue
            if not member.isfile() or not name.is_relative_to(prefix):
                raise ValueError(f"unsupported archive member: {member.name}")
            relative = name.relative_to(prefix).as_posix()
            safe_name(relative)
            if relative in files:
                raise ValueError(f"duplicate archive member: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"unreadable archive member: {member.name}")
            files[relative] = source.read()
    return files


def browser_package(path: Path) -> dict[str, bytes]:
    files = archive_files(path, "package")
    if not BROWSER_ASSETS <= files.keys():
        raise ValueError("browser candidate lacks required assets: " + ", ".join(sorted(BROWSER_ASSETS - files.keys())))
    if "package.json" not in files or "LICENSE" not in files:
        raise ValueError("browser candidate lacks package metadata or license")
    manifest = json.loads(files["package.json"])
    if (manifest.get("name") != "@datafog/fogvault-browser"
            or manifest.get("exports", {}).get(".") != {"types": "./dist/index.d.ts", "import": "./dist/client.mjs"}
            or manifest.get("exports", {}).get("./worker") != "./dist/worker.mjs"):
        raise ValueError("browser candidate public exports do not match the supported entry points")
    return files


def extract_regular(files: dict[str, bytes], destination: Path) -> None:
    if destination.exists():
        raise ValueError("candidate extraction requires a fresh directory")
    destination.mkdir(parents=True)
    for name, data in files.items():
        relative = safe_name(name)
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
