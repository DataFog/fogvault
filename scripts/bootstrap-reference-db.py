#!/usr/bin/env python3
"""Fetch pinned public RustSec Git objects into ignored local verifier state.

Run explicitly before the full verifier in a clean public checkout. The vendored
advisory files stay unchanged and contain no nested Git repository. This fetch
creates no FogVault commits or refs. Audit runners themselves never fetch.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
URL = "https://github.com/RustSec/advisory-db.git"


def reference_checker():
    spec = importlib.util.spec_from_file_location(
        "fogvault_dependency_audit", ROOT / "scripts/verify-dependency-audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(command: list[str]) -> str:
    result = subprocess.run(
        ["git", *command], cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if result.returncode:
        raise ValueError(f"reference Git command failed: {result.stderr.strip()}")
    return result.stdout.strip()


def main() -> int:
    try:
        checker = reference_checker()
        database = ROOT / checker.DATABASE
        destination = ROOT / checker.DATABASE_OBJECTS
        fetched = False
        if destination.is_symlink():
            raise ValueError("reference object-store destination must not be a symlink")
        if not (database / ".git").exists() and not destination.exists():
            # Build a new private object store; never replace an existing path or
            # touch the reviewed advisory content. Temporary state is task-owned.
            for path in (destination.parent.parent, destination.parent):
                if path.is_symlink():
                    raise ValueError("reference object-store parent must not be a symlink")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = Path(tempfile.mkdtemp(prefix=".advisory-db-", dir=destination.parent))
            try:
                git(["init", "--bare", str(temporary)])
                options = ["--git-dir", str(temporary)]
                git([*options, "fetch", "--depth=1", "--no-tags", URL, checker.DB_REVISION])
                git([*options, "update-ref", "--no-deref", "HEAD", "FETCH_HEAD"])
                revision = git([*options, "rev-parse", "--verify", "HEAD"])
                tree = git([*options, "rev-parse", "--verify", "HEAD^{tree}"])
                if (revision, tree) != (checker.DB_REVISION, checker.DB_TREE):
                    raise ValueError("fetched reference revision/tree differs from the pinned database")
                if destination.exists():
                    raise ValueError("reference object-store destination appeared during fetch")
                temporary.rename(destination)
                fetched = True
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        # The exact same complete 1,405-file manifest check as the audit runner
        # verifies vendored content alongside the separately stored Git identity.
        state = checker.database_state()
        print(json.dumps({"pass": True, "reference_url": URL, "fetched": fetched,
                          "database": state, "fogvault_commits_created": False}))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"pass": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
