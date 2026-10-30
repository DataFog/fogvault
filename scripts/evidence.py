"""Shared fail-closed result validation and source/artifact evidence.

The source snapshot records hashes rather than patch or file contents. This keeps
dirty-tree evidence useful without copying private plaintext into reports.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def validate_browser_cases(result: object, settings: dict) -> dict:
    """Admit only a complete, actually executed browser behavior result."""
    if not isinstance(settings, dict):
        raise ValueError("browser case contract must be an object")
    expected = settings.get("required_cases")
    schema = settings.get("result_schema")
    if (not isinstance(schema, str) or not schema or not isinstance(expected, list)
            or not expected or any(not isinstance(name, str) or not name for name in expected)
            or len(expected) != len(set(expected))):
        raise ValueError("browser case contract must name a schema and distinct required cases")
    if not isinstance(result, dict) or result.get("schema") != schema or result.get("pass") is not True:
        raise ValueError("browser result has an invalid schema or did not pass")
    cases = result.get("cases")
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        raise ValueError("browser result must contain executed case objects")
    names = [case.get("id") for case in cases]
    if (any(not isinstance(name, str) or not name for name in names)
            or len(names) != len(set(names)) or set(names) != set(expected)):
        raise ValueError("browser result omitted, duplicated or added a required behavior")
    if any(case.get("status") != "pass" or case.get("executed") is not True for case in cases):
        raise ValueError("every browser behavior must pass and actually execute")
    if result.get("error") is not None:
        raise ValueError("a passing browser result cannot contain an error")
    return {"cases": list(expected)}


def _git(root: Path, *arguments: str, allow_detached: bool = False) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *arguments],
                            capture_output=True, check=False)
    if result.returncode and not (allow_detached and result.returncode == 1):
        raise ValueError("Git source evidence unavailable: " + " ".join(arguments))
    return result.stdout


def git_identity(root: Path) -> dict:
    """Identify checked-out bytes, including nonignored uncommitted inputs.

    Git metadata alone does not describe a dirty tree. The input map includes
    tracked and nonignored new files; ignored caches, credentials and evidence
    stay outside this map. A symlink is refused rather than reading its target.
    """
    root = Path(root).resolve()
    commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    ref = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD",
               allow_detached=True).decode("utf-8", "surrogateescape").strip() or "HEAD"
    status_raw = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    status = [os.fsdecode(entry) for entry in status_raw.split(b"\0") if entry]
    patch = _git(root, "diff", "--binary", "HEAD", "--")
    names = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    inputs = {}
    for raw in sorted(set(names.split(b"\0")) - {b""}):
        relative = os.fsdecode(raw)
        path = root / relative
        if path.is_symlink():
            raise ValueError("source evidence refuses a symlink input: " + relative)
        if not path.exists():
            # A tracked deletion is identified by status and the binary diff.
            continue
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError("source evidence requires an ordinary repository file: " + relative)
        with path.open("rb") as source:
            inputs[relative] = hashlib.file_digest(source, "sha256").hexdigest()
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ci_names = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_HEAD_REF",
                "GITHUB_BASE_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    return {"commit": commit, "ref": ref, "dirty": bool(status), "status": status,
            "diff_sha256": hashlib.sha256(patch).hexdigest(),
            "input_tree_sha256": hashlib.sha256(encoded).hexdigest(), "input_identity": inputs,
            "ci": {name: os.environ[name] for name in ci_names if name in os.environ}}


def snapshot(root: Path) -> dict:
    """The shared source snapshot used by local checks and CI."""
    return git_identity(root)


def artifact_identity(path: Path, root: Path | None = None) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("required artifact must be an ordinary file: " + str(path))
    display = str(path)
    if root is not None:
        display = path.resolve().relative_to(Path(root).resolve()).as_posix()
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": display, "bytes": path.stat().st_size, "sha256": digest}


def tool_versions(commands: dict[str, list[str]]) -> dict:
    result = {}
    for name, command in commands.items():
        if not command or shutil.which(command[0]) is None:
            result[name] = {"command": command, "available": False}
            continue
        try:
            run = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, check=False, timeout=30)
            result[name] = {"command": command, "available": run.returncode == 0,
                            "exit_code": run.returncode,
                            "output": (run.stdout + run.stderr).strip()}
        except (OSError, subprocess.TimeoutExpired) as error:
            result[name] = {"command": command, "available": False,
                            "error": type(error).__name__}
    return result


def write_report(path: Path, report: dict) -> None:
    """Write one fresh report, propagating capture/serialization failures."""
    encoded = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(encoded)
