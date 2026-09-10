"""Build the two allowlisted NON_PRODUCTION_DEMO delivery artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from check_delivery_package import violations

ROOT = Path(__file__).parents[1]
EVIDENCE_NAMES = {"TEST-REPORT.md", "TEST_MATRIX.md", "versions.txt", "package-manifest.json"}


def platform_name() -> str:
    system = {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower().replace("amd64", "x86_64").replace("aarch64", "arm64")
    return f"{system}-{machine}"


def run(command: list[str], *, cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed: {command!r}\n{result.stdout}\n{result.stderr}")
    return (result.stdout + result.stderr).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def expected_paths(platform_id: str) -> set[str]:
    return {
        f"aaph-server-{platform_id}", f"aaph-agent-{platform_id}", "SHA256SUMS",
        "README-DEMO.md", *(f"evidence/{name}" for name in EVIDENCE_NAMES),
    }


def verify_allowlist(root: Path, platform_id: str) -> None:
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    expected = expected_paths(platform_id)
    if actual != expected:
        extra, missing = sorted(actual - expected), sorted(expected - actual)
        raise RuntimeError(f"delivery allowlist mismatch: extra={extra}, missing={missing}")
    forbidden = violations(root)
    if forbidden:
        raise RuntimeError(f"forbidden delivery entries: {[path.as_posix() for path in forbidden]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    platform_id = platform_name()
    dist = args.dist.resolve()
    if dist == ROOT.resolve() or ROOT.resolve() not in dist.parents:
        raise SystemExit("distribution directory must remain below the repository root")
    if dist.exists():
        existing = {path.relative_to(dist).as_posix() for path in dist.rglob("*") if path.is_file()}
        if not existing <= expected_paths(platform_id):
            raise SystemExit("refusing to replace a distribution directory containing non-allowlisted files")

    with tempfile.TemporaryDirectory(prefix=".aaph-package-", dir=ROOT) as temporary:
        stage = Path(temporary) / "dist"
        evidence = stage / "evidence"
        evidence.mkdir(parents=True)
        cargo = os.environ.get("CARGO", "cargo")
        run([cargo, "build", "--locked", "--release", "-p", "aaph-server"])
        server_source = ROOT / "target" / "release" / ("aaph-server.exe" if os.name == "nt" else "aaph-server")
        server_target = stage / f"aaph-server-{platform_id}"
        shutil.copy2(server_source, server_target)

        pyinstaller_dist = Path(temporary) / "pyinstaller-dist"
        run([
            sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm",
            "--distpath", str(pyinstaller_dist), "--workpath", str(Path(temporary) / "pyinstaller-work"),
            "aaph-agent.spec",
        ], cwd=ROOT / "agent")
        agent_source = pyinstaller_dist / ("aaph-agent.exe" if os.name == "nt" else "aaph-agent")
        agent_target = stage / f"aaph-agent-{platform_id}"
        shutil.copy2(agent_source, agent_target)

        shutil.copy2(ROOT / "docs/TWO_BINARY_DEMO.md", stage / "README-DEMO.md")
        shutil.copy2(ROOT / "docs/TEST_MATRIX.md", evidence / "TEST_MATRIX.md")
        shutil.copy2(ROOT / "docs/DELIVERY_TEST_REPORT.md", evidence / "TEST-REPORT.md")
        versions = "\n".join([
            run([cargo, "--version"]), run(["rustc", "--version"]),
            run([sys.executable, "--version"]), run([sys.executable, "-m", "PyInstaller", "--version"]),
            platform.platform(),
        ]) + "\n"
        (evidence / "versions.txt").write_text(versions, encoding="utf-8")
        manifest = {
            "marker": "NON_PRODUCTION_DEMO", "platform": platform_id,
            "artifacts": [server_target.name, agent_target.name],
            "embedded_runtime_configuration": False,
        }
        (evidence / "package-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        sums = [f"{sha256(path)}  {path.name}" for path in (server_target, agent_target)]
        (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")
        verify_allowlist(stage, platform_id)
        for executable in (server_target, agent_target):
            executable.chmod(0o755)

        if dist.exists():
            shutil.rmtree(dist)
        shutil.copytree(stage, dist)
    verify_allowlist(dist, platform_id)
    print(f"NON_PRODUCTION_DEMO delivery created: {dist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
