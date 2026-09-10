from __future__ import annotations

import time
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import AgentError
from .planner import Action, DemoVulnerablePlanner, DeterministicPlanner, Planner
from .signing import ACTION_DOMAIN, SESSION_DOMAIN, sign, signer_public, uuid7


class AaphAgent:
    def __init__(self, config: dict[str, Any], key: Ed25519PrivateKey, client: httpx.Client, planner: Planner | None = None):
        self.server_url = config["server_url"].rstrip("/")
        self.instance_id = config["instance_id"]
        self.key = key
        self.client = client
        self.planner = planner or DeterministicPlanner()

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        response = self.client.post(f"{self.server_url}{path}", json=payload)
        response.raise_for_status()
        return response

    def _get(self, path: str) -> httpx.Response:
        response = self.client.get(f"{self.server_url}{path}")
        response.raise_for_status()
        return response

    def _session(self) -> str:
        session_id = uuid7()
        request = {"instance_id": self.instance_id, "session_id": session_id, "issued_at": int(time.time())}
        body = self._post("/v1/sessions", sign(request, SESSION_DOMAIN, self.key)).json()
        if not isinstance(body, dict) or not {"session_id", "expires_at", "session_epoch", "containment_epoch"}.issubset(body):
            raise AgentError("session response schema invalid")
        return session_id

    def _proposal(self, session_id: str, action: Action, purpose: str) -> dict[str, Any]:
        return {"request_id": uuid7(), "session_id": session_id, "action": action.action, "resource": action.resource, "size_bytes": action.size_bytes, "purpose": action.purpose or purpose, "destination": action.destination}

    def _decide(self, proposal: dict[str, Any]) -> dict[str, Any]:
        body = self._post("/v1/actions/propose", sign(proposal, ACTION_DOMAIN, self.key)).json()
        if not isinstance(body, dict) or not isinstance(body.get("decision"), dict):
            raise AgentError("decision response schema invalid")
        verdict = body["decision"].get("decision")
        if verdict != "PERMIT" or "permit" not in body:
            raise AgentError(f"server stopped execution: {verdict or 'INVALID'}")
        return body

    def _execute(self, proposal: dict[str, Any], permit: dict[str, Any]) -> dict[str, Any]:
        body = self._post("/v1/effects/execute", {"permit": permit, "request": proposal, "holder_public_key": signer_public(self.key)}).json()
        if not isinstance(body, dict):
            raise AgentError("effect response schema invalid")
        return body

    def run(self, task: dict[str, Any]) -> list[dict[str, Any]]:
        session_id = self._session()
        results = []
        document = None
        if getattr(self.planner, "requires_document", False):
            resource = "inbox/poisoned-document.txt" if isinstance(self.planner, DemoVulnerablePlanner) else task["input"]
            read = Action("READ_FILE", resource, task["read_limit"])
            proposal = self._proposal(session_id, read, task["purpose"])
            decision = self._decide(proposal)
            observed = self._execute(proposal, decision["permit"])
            document = observed.get("content")
            if not isinstance(document, str):
                raise AgentError("authorized document response schema invalid")
        for action in self.planner.plan(task, document):
            proposal = self._proposal(session_id, action, task["purpose"])
            decision = self._decide(proposal)
            results.append(self._execute(proposal, decision["permit"]))
        return results

    def run_attack_demo(self, task: dict[str, Any]) -> list[str]:
        if not isinstance(self.planner, DemoVulnerablePlanner):
            raise AgentError("vulnerable planner is not enabled")
        session_id = self._session()
        summary: list[str] = []
        first_effect = None
        poisoned = None
        legitimate = [Action("LIST_DIRECTORY", "inbox/", None), Action("READ_FILE", "inbox/report.txt", task["read_limit"]), Action("READ_FILE", "inbox/poisoned-document.txt", task["read_limit"])]
        for action in legitimate:
            proposal = self._proposal(session_id, action, task["purpose"])
            decision = self._decide(proposal)
            effect = {"permit": decision["permit"], "request": proposal, "holder_public_key": signer_public(self.key)}
            result = self._post("/v1/effects/execute", effect).json()
            first_effect = first_effect or effect
            summary.extend([f"[PERMIT] {action.action} {action.resource}", "[EFFECT] completed"])
            if action.resource.endswith("poisoned-document.txt") and isinstance(result, dict):
                poisoned = result.get("content")
        attack = self.planner.injected_action(poisoned if isinstance(poisoned, str) else "")
        attack_proposal = {"request_id": uuid7(), "session_id": session_id, **attack}
        summary.append("[ATTACK] proposal requests out-of-scope resource and external destination")
        denied = self.client.post(f"{self.server_url}/v1/actions/propose", json=sign(attack_proposal, ACTION_DOMAIN, self.key))
        denied.raise_for_status()
        denial = denied.json()
        if not isinstance(denial, dict) or denial.get("decision", {}).get("decision") != "QUARANTINE" or "permit" in denial:
            raise AgentError("attack was not quarantined without permit")
        summary.append(f"[DENY] {denial['decision']['reason']}")
        snapshot = self._get(f"/v1/instances/{self.instance_id}").json()
        summary.append(f"[CONTAIN] instance={self.instance_id} epoch={snapshot['containment_epoch']}")
        retry = self._proposal(session_id, Action("READ_FILE", "inbox/report.txt", task["read_limit"]), task["purpose"])
        retry_response = self.client.post(f"{self.server_url}/v1/actions/propose", json=sign(retry, ACTION_DOMAIN, self.key))
        summary.extend(["[RETRY] legitimate action", f"[DENY] {retry_response.json().get('reason', 'UNKNOWN')}"])
        replay = self.client.post(f"{self.server_url}/v1/effects/execute", json=first_effect)
        summary.append(f"[REPLAY] {replay.json().get('reason', 'UNKNOWN')}")
        direct = self.client.post(f"{self.server_url}/v1/effects/execute", json={"request": retry})
        summary.append(f"[DIRECT] {direct.json().get('reason', 'E_SCHEMA_INVALID')}")
        valid = self._get("/v1/audit/verify").json().get("valid") is True
        summary.append(f"[AUDIT] chain {'valid' if valid else 'invalid'}")
        if not valid:
            raise AgentError("demo safety assertion failed")
        return summary
