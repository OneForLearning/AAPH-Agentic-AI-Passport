from __future__ import annotations

import argparse
import json
import os
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from aaph_agent import AgentError
from aaph_agent.client import AaphAgent
from aaph_agent.planner import DemoVulnerablePlanner, DeterministicPlanner, TASK_FIELDS, validate_task
from aaph_agent.signing import load_key
from aaph_agent.local_llm import LocalLlmPlanner

CONFIG_FIELDS = {"schema_version", "instance_id", "server_url"}


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aaph-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--task", required=True, type=Path)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--planner", choices=("deterministic", "adversarial-demo", "local-llm"), default="deterministic")
    run.add_argument("--llm-endpoint", default="http://127.0.0.1:11434/api/generate")
    run.add_argument("--llm-model", default="qwen2.5:0.5b")
    return parser


def _object(path: Path, allowed: set[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AgentError(f"{label} unavailable or invalid") from error
    if not isinstance(value, dict) or set(value) != allowed:
        raise AgentError(f"{label} schema invalid")
    return value


def load_runtime() -> tuple[dict[str, Any], Any]:
    config_path = os.environ.get("AAPH_AGENT_CONFIG")
    key_path = os.environ.get("AAPH_AGENT_SIGNING_KEY")
    if not config_path or not key_path:
        raise AgentError("AAPH_AGENT_CONFIG and AAPH_AGENT_SIGNING_KEY are required")
    config = _object(Path(config_path), CONFIG_FIELDS, "agent configuration")
    parsed = urlsplit(config.get("server_url", ""))
    if config.get("schema_version") != 1 or parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise AgentError("agent configuration schema invalid")
    return config, load_key(Path(key_path))


def main(argv: list[str] | None = None) -> int:
    args = argument_parser().parse_args(argv)
    try:
        task = _object(args.task, TASK_FIELDS, "task")
        validate_task(task)
        actions = DeterministicPlanner().plan(task)
        if args.dry_run:
            print(json.dumps([action.__dict__ for action in actions], indent=2))
            return 0
        config, key = load_runtime()
        ca_cert = os.environ.get("AAPH_TLS_CA_CERT")
        if not ca_cert:
            raise AgentError("AAPH_TLS_CA_CERT is required")
        tls_context = ssl.create_default_context(cafile=ca_cert)
        with httpx.Client(timeout=10.0, verify=tls_context) as client:
            planners = {"deterministic": DeterministicPlanner, "adversarial-demo": DemoVulnerablePlanner}
            planner = LocalLlmPlanner(args.llm_endpoint, args.llm_model) if args.planner == "local-llm" else planners[args.planner]()
            agent = AaphAgent(config, key, client, planner)
            lines = agent.run_attack_demo(task) if args.planner == "adversarial-demo" else None
            if lines is None:
                agent.run(task)
            else:
                print("\n".join(lines))
        print("NON_PRODUCTION_DEMO: task completed")
        return 0
    except (AgentError, httpx.HTTPError, KeyError, TypeError, ValueError) as error:
        print(f"NON_PRODUCTION_DEMO: stopped safely: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
