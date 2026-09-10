"""Verify the closed allowlist, checksums, and secret absence of a delivery."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from package_delivery import expected_paths, platform_name, verify_allowlist

SECRET_MARKERS = (b"NON_PRODUCTION_DEMO_ADMIN",)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checksums(root: Path, platform_id: str) -> None:
    rows = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    expected_names = {f"aaph-server-{platform_id}", f"aaph-agent-{platform_id}"}
    observed: set[str] = set()
    for row in rows:
        fields = row.split("  ")
        if len(fields) != 2 or len(fields[0]) != 64:
            raise RuntimeError("invalid SHA256SUMS format")
        checksum, name = fields
        if name not in expected_names or name in observed:
            raise RuntimeError(f"unexpected checksum entry: {name}")
        if sha256(root / name) != checksum:
            raise RuntimeError(f"checksum mismatch: {name}")
        observed.add(name)
    if observed != expected_names:
        raise RuntimeError("SHA256SUMS does not cover exactly both executables")


def verify_no_embedded_secrets(root: Path, repository: Path) -> None:
    markers = list(SECRET_MARKERS)
    for path in (repository / "local-keys").rglob("*.key"):
        value = path.read_bytes().strip()
        if value:
            markers.append(value)
    for packaged in root.rglob("*"):
        if packaged.is_file():
            value = packaged.read_bytes()
            for marker in markers:
                if marker in value:
                    raise RuntimeError(f"secret marker embedded in {packaged.relative_to(root)}")


def verify(root: Path, repository: Path, platform_id: str) -> None:
    verify_allowlist(root, platform_id)
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != expected_paths(platform_id):
        raise RuntimeError("delivery contents differ from the closed allowlist")
    verify_checksums(root, platform_id)
    verify_no_embedded_secrets(root, repository)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?", default=Path(__file__).parents[1] / "dist")
    args = parser.parse_args()
    repository = Path(__file__).parents[1]
    verify(args.directory.resolve(), repository, platform_name())
    print("NON_PRODUCTION_DEMO delivery verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
