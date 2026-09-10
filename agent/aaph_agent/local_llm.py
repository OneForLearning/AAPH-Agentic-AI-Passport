from __future__ import annotations

import json
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from . import AgentError
from .planner import Action, validate_task


class LocalLlm(Protocol):
    """Future local-only model boundary; no network implementation in sprint 16."""

    def complete(self, request: dict[str, Any]) -> dict[str, Any]: ...


MODEL_FIELDS = {"action", "resource", "size_bytes", "purpose", "destination"}
REGISTERED_ACTIONS = {"LIST_DIRECTORY", "READ_FILE", "COMPUTE_SHA256", "WRITE_REPORT"}


class LocalLlmPlanner:
    """Untrusted local Ollama-compatible planner with bounded responses."""

    requires_document = True

    def __init__(self, endpoint: str = "http://127.0.0.1:11434/api/generate", model: str = "qwen2.5:0.5b", *, timeout: float = 10.0, max_response_bytes: int = 16_384, transport: httpx.BaseTransport | None = None):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.fragment:
            raise AgentError("local LLM endpoint must be loopback HTTP")
        if timeout <= 0 or not 256 <= max_response_bytes <= 65_536 or not model:
            raise AgentError("local LLM configuration invalid")
        self.endpoint, self.model, self.timeout, self.max_response_bytes, self.transport = endpoint, model, timeout, max_response_bytes, transport

    def plan(self, task: dict[str, Any], document: str | None = None) -> list[Action]:
        validate_task(task)
        if document is None:
            raise AgentError("local LLM requires authorized document content")
        prompt = json.dumps({"task": task, "document": document, "instruction": "Return exactly one JSON action object."}, separators=(",", ":"))
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                with client.stream("POST", self.endpoint, json={"model": self.model, "prompt": prompt, "stream": False}) as response:
                    response.raise_for_status()
                    chunks, total = [], 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > self.max_response_bytes:
                            raise AgentError("local LLM response too large")
                        chunks.append(chunk)
        except httpx.TimeoutException as error:
            raise AgentError("local LLM timed out") from error
        except httpx.HTTPError as error:
            raise AgentError("local LLM request failed") from error
        try:
            envelope = json.loads(b"".join(chunks))
            raw = envelope["response"]
            value = json.loads(raw)
        except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as error:
            raise AgentError("local LLM output is not valid JSON") from error
        return [self._action(value)]

    @staticmethod
    def _action(value: Any) -> Action:
        if not isinstance(value, dict) or set(value) != MODEL_FIELDS:
            raise AgentError("local LLM action schema invalid")
        action, resource = value["action"], value["resource"]
        if action not in REGISTERED_ACTIONS:
            raise AgentError("local LLM action is not registered")
        if not isinstance(resource, str) or not resource or resource.startswith(("/", "\\")) or "\\" in resource or "\0" in resource or any(part in {"", ".", ".."} for part in resource.split("/")):
            raise AgentError("local LLM resource is invalid")
        size = value["size_bytes"]
        if (size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0)) or not isinstance(value["purpose"], str) or not value["purpose"] or value["destination"] is not None:
            raise AgentError("local LLM action types invalid")
        return Action(action, resource, size, value["purpose"], None)
