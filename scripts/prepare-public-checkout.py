#!/usr/bin/env python3
"""Copy an explicit, hash-inventoried public candidate without committing or pushing.

Run from the complete research workspace. This deliberately preserves selected
historical verifier inputs at their existing relative paths. It does not certify
licenses or secrets, install host tools, recreate the RustSec Git reference, or
turn the experimental package into a release.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BASELINE = "experiments/vault-prototype/evidence/verifier-runs/20261030T064515Z-tm40qhi9/report.json"
CONSUMER = "research/consumer/datafog-core-0.5.0-beta.3"
LEGACY_P1_FIXTURE = "experiments/vault-prototype/evidence/PROTOTYPE-WIPE-ME.sqlite"
MANIFEST = "public-checkout-manifest.json"
SKIP_DIRECTORIES = {
    ".git", "target", "node_modules", "__pycache__", ".venv", "pkg",
    "evidence", "provenance", ".playwright-cli", "output", "local-only",
}
FIRST_PARTY_TREES = (
    "crates/fogvault", "conformance", "scripts", "tests", "third-party",
    "experiments/vault-prototype", "experiments/browser-prototype",
    "experiments/mobile-prototype", "experiments/export-prototype", ".github",
)
ROOT_FILES = (
    ".gitignore", "README.md", "CONTRIBUTING.md", "SECURITY.md",
    "THIRD_PARTY_NOTICES.md", "NOTICE", "LICENSE", "LICENSE-MIT",
    "LICENSE-APACHE", "PUBLIC-CHECKOUT-NOTES.md",
)
PRESENTATION_OVERLAYS = (
    "README.md", "crates/fogvault/README.md", "spec/format-profile-review.md",
    "spec/protective-transition.md", "research/review-dependencies/age-v1.3.2/provenance.json",
)
EXTRA_VERIFIER_INPUTS = (
    f"{CONSUMER}/published-source/src/workspace.rs",
    f"{CONSUMER}/release-source/LICENSE",
    LEGACY_P1_FIXTURE,
)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_path(relative: str) -> Path:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or ".." in parts or ".git" in parts:
        raise ValueError(f"unsafe input path: {relative}")
    path = ROOT / relative
    if not path.is_file() or not path.resolve().is_relative_to(ROOT):
        raise ValueError(f"missing or escaping input: {relative}")
    for component in (path, *path.parents):
        if component == ROOT:
            break
        if component.is_symlink():
            raise ValueError(f"symlink input refused: {relative}")
    return path


def tree_files(relative: str):
    directory = ROOT / relative
    if not directory.exists():
        return
    if directory.is_symlink():
        raise ValueError(f"symlink source directory refused: {relative}")
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError(f"symlink source directory refused: {parent}/{name}")
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRECTORIES)
        for name in sorted(files):
            if name == ".DS_Store" or name.endswith(".pyc") or name == ".env" or name.startswith(".env."):
                continue
            yield (Path(parent) / name).relative_to(ROOT).as_posix()


def selection(report: dict) -> tuple[list[str], dict[str, list[str]]]:
    if report.get("schema") != "fogvault-verifier/v1" or report.get("pass") is not True:
        raise ValueError("baseline must be a successful full verifier report")
    identities = report.get("source_identity")
    if not isinstance(identities, dict) or not identities:
        raise ValueError("baseline source identity is missing")
    reasons: dict[str, set[str]] = {}

    def add(relative: str, reason: str):
        source_path(relative)
        reasons.setdefault(relative, set()).add(reason)

    for relative in identities:
        add(relative, "existing-full-verifier-input")
    # The accepted report is historical provenance. Current contracts can add
    # inputs (for example, a newly captured audit after manifest metadata changes)
    # that did not exist in that older report. Derive these paths explicitly;
    # never fill the gap by copying whole research or artifact directories.
    contract = json.loads(source_path("conformance/vault-contract.json").read_text())
    for name, section in contract.items():
        if not isinstance(section, dict) or "source_files" not in section:
            continue
        source_files = section["source_files"]
        if not isinstance(source_files, list) or any(not isinstance(path, str) for path in source_files):
            raise ValueError(f"invalid current contract source files: {name}")
        for relative in source_files:
            add(relative, f"current-contract-input:{name}")
    epoch_vectors = contract.get("epoch_vectors")
    if epoch_vectors is not None:
        if not isinstance(epoch_vectors, str):
            raise ValueError("invalid current epoch fixture definition")
        epoch = json.loads(source_path(epoch_vectors).read_text())
        recipe = epoch.get("capture_recipe")
        if not isinstance(recipe, str):
            raise ValueError("current epoch fixture capture recipe missing")
        add(recipe, "current-epoch-capture-recipe")
    for directory in FIRST_PARTY_TREES:
        for relative in tree_files(directory):
            if relative.endswith(".md") and not relative.startswith(("conformance/", "third-party/")):
                continue
            add(relative, "current-first-party-tree")
    for relative in ROOT_FILES:
        if (ROOT / relative).is_file():
            add(relative, "public-presentation")
    for relative in EXTRA_VERIFIER_INPUTS:
        add(relative, "required-runtime-fixture-or-consumer-bound-or-notice")
    return sorted(reasons), {path: sorted(values) for path, values in sorted(reasons.items())}


def manifest_rows(paths: list[str], reasons: dict[str, list[str]], overrides: dict[str, str]) -> list[dict]:
    rows = []
    for relative in paths:
        path = source_path(overrides.get(relative, relative))
        rows.append({
            "path": relative, "bytes": path.stat().st_size, "sha256": sha256(path),
            "executable": bool(path.stat().st_mode & stat.S_IXUSR),
            "reasons": reasons[relative],
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=ROOT / "local-only/public-checkout")
    parser.add_argument("--source-report", type=Path, default=ROOT / BASELINE)
    parser.add_argument("--audit", type=Path, default=ROOT / "local-only/public-preparation/input-audit.json")
    parser.add_argument("--inventory-only", action="store_true", help="write the input audit without copying")
    parser.add_argument("--overlays", type=Path, default=ROOT / "local-only/public-preparation/public-docs", help="directory containing explicit reviewed presentation/provenance overlays")
    args = parser.parse_args()
    destination = args.destination.expanduser().absolute()
    local = ROOT / "local-only"
    if not destination.resolve().is_relative_to(local.resolve()) or destination.resolve() == local.resolve():
        parser.error("destination must be a new directory beneath this workspace's local-only/")
    if destination.exists() and not args.inventory_only:
        parser.error("destination exists; choose a fresh path (no implicit overwrite)")
    if any(parent.is_symlink() for parent in (destination, *destination.parents) if parent != ROOT):
        parser.error("symlink destination refused")
    audit_path = args.audit.expanduser().absolute()
    if not audit_path.resolve().is_relative_to(local.resolve()):
        parser.error("audit must stay under local-only/")
    report_path = args.source_report.expanduser().resolve()
    if not report_path.is_relative_to(ROOT):
        parser.error("source report must stay in this complete workspace")
    report = json.loads(report_path.read_text())
    paths, reasons = selection(report)
    overrides = {}
    overlay_root = args.overlays.expanduser().resolve()
    if not overlay_root.is_relative_to(local.resolve()):
        parser.error("presentation overlays must stay under local-only/")
    for relative in PRESENTATION_OVERLAYS:
        overlay = overlay_root / relative
        if overlay.is_file():
            overrides[relative] = overlay.relative_to(ROOT).as_posix()
            reasons.setdefault(relative, []).append("reviewed-public-presentation-overlay")
            if relative not in paths:
                paths.append(relative)
    paths.sort()
    generated = local / "public-preparation/generated/.gitignore"
    generated.parent.mkdir(parents=True, exist_ok=True)
    ignore = (ROOT / ".gitignore").read_text()
    ignore += "\n# Generated exact allowlist for public verifier inputs; other local material stays ignored.\n"
    ignore += "/research/**\n/artifacts/**\n/experiments/*/provenance/**\n/experiments/*/evidence/**\n"
    curated = [relative for relative in paths if relative.startswith(("research/", "artifacts/")) or "/provenance/" in relative or relative == LEGACY_P1_FIXTURE]
    directories = set()
    for relative in curated:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
        ignore += f"!/{directory}/\n"
    for relative in curated:
        ignore += f"!/{relative}\n"
    generated.write_text(ignore)
    overrides[".gitignore"] = generated.relative_to(ROOT).as_posix()
    reasons[".gitignore"] = ["generated-exact-public-input-allowlist"]
    rows = manifest_rows(paths, reasons, overrides)
    tree_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    workspace_differences = [path for path, old_hash in report["source_identity"].items() if sha256(source_path(path)) != old_hash]
    differences = [path for path, old_hash in report["source_identity"].items() if sha256(source_path(overrides.get(path, path))) != old_hash]
    overlay_rows = [{"path": relative, "workspace_sha256": sha256(source_path(relative)),
                     "public_sha256": sha256(source_path(override))}
                    for relative, override in sorted(overrides.items())]
    counts = Counter(path.split("/")[0] for path in paths)
    manifest = {
        "schema": "fogvault-public-candidate-inputs/v1",
        "status": "prepared-not-published-or-production-qualified",
        "baseline_report_sha256": sha256(report_path),
        "file_count": len(rows), "total_bytes": sum(row["bytes"] for row in rows),
        "content_identity_sha256": tree_digest, "files": rows,
        "declared_public_overlays": overlay_rows,
        "changed_baseline_input_paths": differences,
        "required_reference_checkout": {
            "path": "research/review-dependencies/advisory-db",
            "url": "https://github.com/RustSec/advisory-db.git",
            "revision": "ee1a49a2769a24a596afc1c20cb33748d2769586",
            "tree": "af3eaf8699bc8040565a708da432e04f1f19407a",
            "git_metadata_copied": False,
        },
        "notes": [
            "Selected historical verifier baselines are inputs, never substitutes for fresh execution.",
            "No .git metadata, reviewer attachments, unrelated reference repositories, build outputs or old verifier runs are copied.",
            "Pinned native verification tools target the existing Apple arm64 profile, not arbitrary hosts.",
            "First-party license selection and third-party redistribution review are separate publication decisions.",
        ],
    }
    audit = {
        "schema": "fogvault-public-preparation-audit/v1", "inventory_only": args.inventory_only,
        "candidate": manifest, "top_level_file_counts": dict(sorted(counts.items())),
        "existing_baseline_input_changes": differences,
        "workspace_baseline_input_changes": workspace_differences,
        "source_report": report_path.relative_to(ROOT).as_posix(),
        "presentation_input_overrides": overrides,
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    if args.inventory_only:
        print(f"Inventoried {len(rows)} files ({manifest['total_bytes']} bytes); audit: {audit_path}")
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=destination.name + ".preparing-", dir=destination.parent))
    for row in rows:
        source = source_path(overrides.get(row["path"], row["path"]))
        target = temporary / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if row["executable"] else 0o644)
        if sha256(source) != row["sha256"] or sha256(target) != row["sha256"]:
            raise ValueError(f"input changed during copy: {row['path']}; partial tree retained at {temporary}")
    if manifest_rows(paths, reasons, overrides) != rows:
        raise ValueError(f"input changed during copy; partial tree retained at {temporary}")
    (temporary / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.rename(destination)
    print(f"Prepared {destination}: {len(rows)} files, {manifest['total_bytes']} bytes, content identity {tree_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
