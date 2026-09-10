"""Non-destructive checks for the future two-deliverable trust boundary."""
from __future__ import annotations

import json
import sys
from pathlib import PurePosixPath
from typing import Any

AGENT_PRIVATE_NAMES = {"signing.key", "agent.key"}
AGENT_ALLOWED_TARGETS = {
    "/run/keys/agent/signing.key",
    "/run/certs/ca.crt",
    "/run/config/agent-docker.json",
    "/run/task/task.json",
}


def mounted_sources(service: dict[str, Any]) -> set[str]:
    sources: set[str] = set()
    for volume in service.get("volumes", []):
        if isinstance(volume, str):
            sources.add(volume.split(":", 1)[0].replace("\\", "/"))
        elif isinstance(volume, dict) and isinstance(volume.get("source"), str):
            sources.add(volume["source"].replace("\\", "/"))
    return sources


def mounted_targets(service: dict[str, Any]) -> set[str]:
    targets: set[str] = set()
    for volume in service.get("volumes", []):
        if isinstance(volume, str):
            parts = volume.split(":")
            if len(parts) >= 2:
                targets.add(parts[1].replace("\\", "/"))
        elif isinstance(volume, dict) and isinstance(volume.get("target"), str):
            targets.add(volume["target"].replace("\\", "/"))
    return targets


def is_agent_private_key(source: str) -> bool:
    path = PurePosixPath(source)
    return path.name in AGENT_PRIVATE_NAMES and "agent" in path.parts


def validate(compose: dict[str, Any]) -> list[str]:
    services = compose.get("services")
    if not isinstance(services, dict):
        return ["compose services are missing"]
    if set(services) != {"server", "agent"}:
        return ["compose must contain exactly server and agent services"]
    agent = services.get("agent", {})
    errors: list[str] = []
    agent_environment = agent.get("environment", {}) if isinstance(agent, dict) else {}
    if isinstance(agent_environment, dict) and "AAPH_ADMIN_SECRET" in agent_environment:
        errors.append("agent receives the administrative recovery secret")
    if isinstance(agent_environment, dict):
        forbidden_names = sorted(name for name in agent_environment if name.startswith("AAPH_AUTHORITY_") or (name.startswith("AAPH_ADMIN_") and name != "AAPH_ADMIN_SECRET") or name in {"AAPH_PEP_WORKSPACE", "AAPH_AUTHORITY_DATABASE_URL", "AAPH_PEP_DATABASE_URL"})
        if forbidden_names:
            errors.append(f"agent receives server environment: {forbidden_names[0]}")
        if any("workspace" in str(value).lower() for value in agent_environment.values()):
            errors.append("agent environment references the workspace")
    if isinstance(agent, dict):
        forbidden_targets = sorted(mounted_targets(agent) - AGENT_ALLOWED_TARGETS)
        if forbidden_targets:
            errors.append(f"agent mounts forbidden target: {forbidden_targets[0]}")
        forbidden_sources = sorted(source for source in mounted_sources(agent) if "authority" in source.lower() or "workspace" in source.lower() or source.lower().endswith((".db", ".sqlite")))
        if forbidden_sources:
            errors.append(f"agent mounts server source: {forbidden_sources[0]}")
    for name, service in services.items():
        if name == "agent" or not isinstance(service, dict):
            continue
        private_mounts = sorted(
            source for source in mounted_sources(service) if is_agent_private_key(source)
        )
        if private_mounts:
            errors.append(f"{name} mounts agent private key: {private_mounts[0]}")
    return errors


def main() -> int:
    try:
        compose = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as error:
        print(f"delivery boundary input invalid: {error}", file=sys.stderr)
        return 2
    errors = validate(compose)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(
        "delivery boundary: exactly server/agent; agent mounts and environment "
        "contain no server, workspace, database, authority, or admin capability"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
