#!/usr/bin/env python3
"""Package and consume candidate registry archives locally. Never publishes."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from delivery_inputs import archive_files, browser_package, native_sources
from evidence import artifact_identity, snapshot, tool_versions

MEMBERS = {
    "fogvault": ("crates/fogvault", "0.1.0"),
    "fogvault-native": ("crates/fogvault-native", "0.1.0"),
    "fogvault-backup": ("crates/fogvault-backup", "0.1.0"),
    **{"fogvault-" + name: ("crates/fogvault-backup/vendor/" + name + "-" + version, version)
       for name, version in (("age", "0.11.5"), ("i18n-config", "0.4.8"),
                             ("i18n-embed", "0.16.0"), ("i18n-embed-impl", "0.8.4"),
                             ("i18n-embed-fl", "0.10.1"))},
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def index_path(name):
    name = name.lower()
    if len(name) < 3:
        return str(len(name)) + "/" + name
    return "3/" + name[0] + "/" + name if len(name) == 3 else name[:2] + "/" + name[2:4] + "/" + name


def registry_identities(lock):
    return {(row["name"], row["version"], row.get("checksum"))
            for row in tomllib.loads(lock.read_text())["package"]
            if row.get("source") == REGISTRY and row["name"] not in MEMBERS}


def approved_registry_union():
    directories = ["crates/fogvault", "crates/fogvault-native", "crates/fogvault-backup", "crates/fogvault-wasm",
                   "experiments/vault-prototype", "experiments/browser-prototype", "experiments/mobile-prototype"]
    return set().union(*(registry_identities(ROOT / directory / "Cargo.lock") for directory in directories))


def require_approved_identities(lock, approved):
    if not registry_identities(lock) <= approved:
        raise ValueError("candidate introduced an unaudited registry identity or checksum")


def require_preserved_graph(approved, candidate, exact=True):
    expected, observed = registry_identities(approved), registry_identities(candidate)
    if not expected <= observed or (exact and observed != expected):
        raise ValueError("candidate changed the approved registry dependency graph")
    return len(expected)


def admit_archive(path, name, version):
    files = archive_files(path, name + "-" + version)
    package = tomllib.loads(files["Cargo.toml"].decode())
    if package["package"]["name"] != name or package["package"]["version"] != version:
        raise ValueError("candidate package identity mismatch")
    def check(value):
        if isinstance(value, dict):
            if "path" in value or "git" in value or "patch" in value:
                raise ValueError("candidate retains local or patched dependency resolution")
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    for key in ("dependencies", "dev-dependencies", "build-dependencies", "target", "patch"):
        check(package.get(key, {}))
    if not any(Path(name).name.startswith("LICENSE") for name in files):
        raise ValueError("candidate lacks license notice")
    return files


def seed_registry(registry, locks, candidate_registry):
    """Freeze locked official archives and candidate archives into a Cargo local registry."""
    registry.mkdir()
    shutil.copytree(candidate_registry / "index", registry / "index")
    for path in candidate_registry.glob("*.crate"):
        shutil.copy2(path, registry / path.name)
    packages = {}
    for lock in locks:
        for package in tomllib.loads(lock.read_text())["package"]:
            if package.get("source") == REGISTRY:
                key = package["name"], package["version"]
                if key in packages and packages[key]["checksum"] != package["checksum"]:
                    raise ValueError("conflicting locked registry checksums")
                packages[key] = package
            elif package.get("source"):
                raise ValueError("unsupported non-registry dependency")
    cache = ROOT / "local-only/quality-cache/registry-inputs"
    cache.mkdir(parents=True, exist_ok=True)
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))

    def fetch(item):
        (name, version), package = item
        filename = name + "-" + version + ".crate"
        destination = registry / filename
        if name in MEMBERS:
            if digest(destination.read_bytes()) != package["checksum"]:
                raise ValueError("candidate checksum differs from verified package lock")
            return {"name": name, "version": version, "sha256": package["checksum"], "origin": "candidate"}
        cached = cache / filename
        sources = [cached, *cargo_home.glob("registry/cache/*/" + filename)]
        data = next((p.read_bytes() for p in sources if p.is_file() and digest(p.read_bytes()) == package["checksum"]), None)
        url = "https://static.crates.io/crates/" + name + "/" + filename
        if data is None:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
        if digest(data) != package["checksum"]:
            raise ValueError("official archive checksum mismatch: " + filename)
        cached.write_bytes(data)
        destination.write_bytes(data)
        index_cache = cache / (name + ".index")
        if not index_cache.exists():
            with urllib.request.urlopen("https://index.crates.io/" + index_path(name), timeout=60) as response:
                index_cache.write_bytes(response.read())
        rows = [json.loads(line) for line in index_cache.read_bytes().splitlines()]
        row = next((row for row in rows if row["vers"] == version), None)
        if not row or row["cksum"] != package["checksum"]:
            raise ValueError("official index does not match locked archive: " + filename)
        return {"name": name, "version": version, "sha256": package["checksum"], "origin": url, "index": row}

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(fetch, sorted(packages.items())))
    grouped = {}
    for row in rows:
        if "index" in row:
            grouped.setdefault(row["name"], []).append(row.pop("index"))
    for name, versions in grouped.items():
        path = registry / "index" / index_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(row) for row in versions) + "\n")
    return rows


def execute(output):
    output.mkdir(parents=True, exist_ok=False)
    before = snapshot(ROOT)
    commands = []
    def run(name, command, cwd=ROOT, env=None):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
        log = output / (name + ".log")
        log.write_text(result.stdout + result.stderr)
        commands.append({"id": name, "command": command, "exit_code": result.returncode,
                         "log": artifact_identity(log)})
        if result.returncode:
            raise ValueError(name + " failed; see " + str(log))
        return result.stdout
    run("upstream-provenance", [sys.executable, "crates/fogvault-backup/upstream/verify.py"])
    capture = json.loads(run("advisory-origin-capture", [sys.executable, "scripts/verify-dependency-audit.py", "--verify-capture"]))
    if capture.get("pass") is not True or capture.get("audits_reexecuted") is not False or capture.get("captured_audits_validated") != 14:
        raise ValueError("advisory origin capture is incomplete")
    run("advisory-projection-tests", [sys.executable, "scripts/test-dependency-audit.py", "--portable"])
    scratch = output / "workspace"
    for source in native_sources(ROOT):
        destination = scratch / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    scratch.mkdir(exist_ok=True)
    paths = [path for path, _ in MEMBERS.values()]
    (scratch / "Cargo.toml").write_text("[workspace]\nresolver=\"2\"\nmembers=" + json.dumps(paths) + "\n")
    approved_native = ROOT / "crates/fogvault-native/Cargo.lock"
    shutil.copy2(approved_native, scratch / "Cargo.lock")
    # Resolve workspace-only dev/optional edges while preserving the actual audited
    # native graph. Offline resolution can downgrade to cached WASM test dependencies.
    run("workspace-lock-metadata", ["cargo", "metadata", "--format-version", "1", "--manifest-path", str(scratch / "Cargo.toml")])
    require_preserved_graph(approved_native, scratch / "Cargo.lock", exact=False)
    approved = approved_registry_union()
    require_approved_identities(scratch / "Cargo.lock", approved)
    run("batch-package", ["cargo", "package", "--workspace", "--locked", "--manifest-path", str(scratch / "Cargo.toml")])
    artifacts = []
    package_dir = scratch / "target/package"
    for name, (relative, version) in MEMBERS.items():
        path = package_dir / (name + "-" + version + ".crate")
        files = admit_archive(path, name, version)
        lock = package_dir / (name + "-" + version) / "Cargo.lock"
        require_approved_identities(lock, approved)
        for source in (ROOT / relative / "src").rglob("*.rs"):
            if files.get(source.relative_to(ROOT / relative).as_posix()) != source.read_bytes():
                raise ValueError("packaged Rust source differs: " + str(source))
        artifacts.append(artifact_identity(path))
    preserved = {name: require_preserved_graph(ROOT / relative / "Cargo.lock",
                 package_dir / (name + "-" + version) / "Cargo.lock")
                 for name, (relative, version) in MEMBERS.items()
                 if name in {"fogvault-native", "fogvault-backup"}}
    registry = output / "registry"
    registry_rows = seed_registry(registry, [package_dir / "fogvault-native-0.1.0/Cargo.lock",
                                           ROOT / "experiments/vault-prototype/Cargo.lock"],
                                  package_dir / "tmp-registry")
    consumer = output / "consumer"
    (consumer / ".cargo").mkdir(parents=True)
    (consumer / "src").mkdir()
    (consumer / ".cargo/config.toml").write_text('[source.crates-io]\nreplace-with="candidate"\n[source.candidate]\nlocal-registry=' + json.dumps(str(registry)) + "\n")
    (consumer / "Cargo.toml").write_text('[package]\nname="fogvault-registry-consumer"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nfogvault-native="=0.1.0"\ndatafog-core={version="=0.5.0-beta.3",default-features=false}\nzeroize="=1.9.1"\ntempfile="3"\n')
    (consumer / "src/main.rs").write_bytes((ROOT / "conformance/registry-consumer.rs").read_bytes())
    env = dict(os.environ, CARGO_HOME=str(output / "consumer-cargo-home"))
    outcome = run("registry-consumer", ["cargo", "run", "--offline", "--manifest-path", str(consumer / "Cargo.toml")], cwd=consumer, env=env)
    if "create → unlock → save → lock → reopen → read passed" not in outcome:
        raise ValueError("registry consumer omitted the complete lifecycle proof")
    require_preserved_graph(approved_native, consumer / "Cargo.lock", exact=False)
    metadata = json.loads(run("registry-metadata", ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"], cwd=consumer, env=env))
    observed = {row["name"]: row for row in metadata["packages"] if row["name"] in MEMBERS}
    if set(observed) != set(MEMBERS) or any(row.get("source") != REGISTRY for row in observed.values()):
        raise ValueError("consumer did not resolve all eight candidates through registry identities")
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("fogvault_advisory_origins", ROOT / "scripts/verify-dependency-audit.py")
    origins = module_from_spec(spec)
    spec.loader.exec_module(origins)
    projected, mappings = origins.upstream_projection((consumer / "Cargo.lock").read_text())
    if {row["actual_name"] for row in mappings} != set(origins.FORKS):
        raise ValueError("registry consumer lacks complete upstream advisory origin projection")
    projection = consumer / "upstream-advisory-projection.lock"
    projection.write_text(projected)
    browser_dir = output / "browser"
    run("browser-package", [sys.executable, "scripts/build-delivery.py", "--kind", "browser", "--output-dir", str(browser_dir)])
    candidates = list(browser_dir.glob("*.tgz"))
    if len(candidates) != 1:
        raise ValueError("expected exactly one browser package")
    archive = candidates[0]
    manifest = json.loads(browser_package(archive)["package.json"])
    if manifest.get("version") != "0.1.0" or manifest.get("private") is not False:
        raise ValueError("browser metadata is not the independent public 0.1.0 candidate")
    artifacts.append(artifact_identity(archive))
    if before["input_tree_sha256"] != snapshot(ROOT)["input_tree_sha256"]:
        raise ValueError("source inputs changed during packaging")
    return {"schema": "fogvault-registry-packaging/v1", "pass": True, "published": False,
            "source": before, "tools": tool_versions({"cargo": ["cargo", "--version"], "rustc": ["rustc", "--version"], "node": ["node", "--version"]}), "commands": commands,
            "artifacts": artifacts, "registry_inputs": registry_rows,
            "preserved_native_backend_registry_dependencies": preserved,
            "all_archive_registry_identities_in_approved_union": True,
            "advisory_capture": {"audits_reexecuted": False, "captured_audits_validated": 14},
            "registry_origin_projection": {"lock": artifact_identity(projection), "mappings": mappings},
            "cases": ["eight-verified-archives", "registry-only-default-backup-consumer",
                      "beta3-create-unlock-save-lock-reopen-read", "browser-worker-wasm-package"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "local-only"):
        parser.error("output must remain under ignored local-only/")
    output.parent.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="packaging-", dir=output.parent)) / "run"
    try:
        report = execute(run_dir)
    except Exception as error:
        report = {"schema": "fogvault-registry-packaging/v1", "pass": False,
                  "published": False, "error": str(error), "run": str(run_dir)}
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "report": str(output)}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
