"""Source identities for maintained crates and browser packages, excluding generated output."""
from pathlib import Path
import os

SKIP = {".git", "target", "node_modules", "pkg", "dist", "evidence", "local-only", "__pycache__", ".venv", ".playwright-cli", "example-build", "test-results", "playwright-report"}
EXTENSIONS = {".rs", ".c", ".h", ".mjs", ".js", ".ts", ".html", ".json", ".toml", ".lock", ".sh", ".py", ".yml", ".yaml", ".ftl"}

def maintained_sources(root: Path) -> list[Path]:
    paths = {root / "scripts/source_inputs.py"}
    for base in (root / "crates", root / "packages"):
        if not base.exists():
            continue
        for parent, directories, files in os.walk(base):
            directories[:] = sorted(name for name in directories if name not in SKIP and not (name == "sdk" and Path(parent).as_posix().endswith("/examples/website")))
            for name in files:
                path = Path(parent) / name
                if path.suffix in EXTENSIONS:
                    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                        raise ValueError(f"unsafe maintained source: {path}")
                    paths.add(path)
    return sorted(paths)
