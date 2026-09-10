"""Fail when a staged delivery artifact contains forbidden local material."""
from __future__ import annotations

import sys
from pathlib import Path

FORBIDDEN_DIRS = {
    ".git", ".venv", "target", "__pycache__", ".pytest_cache",
    "workspace", "output", "demo-data", "local-keys", "dev-certs",
}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".key", ".crt", ".pem", ".log"}
FORBIDDEN_NAMES = {"ca.key", "audit-export.json"}


def violations(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in FORBIDDEN_DIRS for part in relative.parts):
            found.append(relative)
        elif path.is_file() and (
            path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name in FORBIDDEN_NAMES
        ):
            found.append(relative)
    return sorted(set(found), key=lambda value: value.as_posix())


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_delivery_package.py <staged-artifact-directory>", file=sys.stderr)
        return 2
    root = Path(argv[0])
    if not root.is_dir():
        print("staged artifact directory is unavailable", file=sys.stderr)
        return 2
    found = violations(root)
    for path in found:
        print(f"forbidden delivery entry: {path.as_posix()}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
