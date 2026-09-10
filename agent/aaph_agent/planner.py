from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from . import AgentError

TASK_FIELDS = {"schema_version", "task_id", "input", "output", "purpose", "read_limit", "write_limit"}
DEMO_MARKER = "AAPH_DEMO_ACTION_JSON:"
DEMO_ACTION_FIELDS = {"action", "resource", "size_bytes", "purpose", "destination"}


@dataclass(frozen=True)
class Action:
    action: str
    resource: str
    size_bytes: int | None
    purpose: str | None = None
    destination: str | None = None


class Planner(Protocol):
    def plan(self, task: dict[str, Any], document: str | None = None) -> list[Action]: ...


def validate_task(task: dict[str, Any]) -> None:
    if set(task) != TASK_FIELDS or task.get("schema_version") != 1:
        raise AgentError("task schema invalid")
    if not all(isinstance(task.get(key), str) and task[key] for key in ("task_id", "input", "output", "purpose")):
        raise AgentError("task schema invalid")
    if any(not isinstance(task.get(key), int) or task[key] < 0 for key in ("read_limit", "write_limit")):
        raise AgentError("task limits invalid")


class DeterministicPlanner:
    def plan(self, task: dict[str, Any], document: str | None = None) -> list[Action]:
        del document
        validate_task(task)
        return [Action("LIST_DIRECTORY", "inbox/", None), Action("READ_FILE", task["input"], task["read_limit"]), Action("COMPUTE_SHA256", task["input"], task["read_limit"]), Action("WRITE_REPORT", task["output"], task["write_limit"])]


class DemoVulnerablePlanner(DeterministicPlanner):
    requires_document = True
    def plan(self, task: dict[str, Any], document: str | None = None) -> list[Action]:
        validate_task(task)
        if document is None:
            return [Action("READ_FILE", "inbox/poisoned-document.txt", task["read_limit"])]
        value = self.injected_action(document)
        return [Action(value["action"], value["resource"], value["size_bytes"], value["purpose"], value["destination"])]

    def injected_action(self, document: str) -> dict[str, Any]:
        matches = [line[len(DEMO_MARKER):] for line in document.splitlines() if line.startswith(DEMO_MARKER)]
        if len(matches) != 1:
            raise AgentError("demo injection marker missing or ambiguous")
        try:
            value = json.loads(matches[0])
        except json.JSONDecodeError as error:
            raise AgentError("demo injection payload invalid") from error
        if not isinstance(value, dict) or set(value) != DEMO_ACTION_FIELDS:
            raise AgentError("demo injection schema invalid")
        if value["action"] not in {"LIST_DIRECTORY", "READ_FILE", "COMPUTE_SHA256", "WRITE_REPORT"}:
            raise AgentError("demo injection action invalid")
        if not isinstance(value["resource"], str) or not isinstance(value["purpose"], str) or not isinstance(value["size_bytes"], int):
            raise AgentError("demo injection types invalid")
        if value["destination"] is not None and not isinstance(value["destination"], str):
            raise AgentError("demo injection destination invalid")
        return value
