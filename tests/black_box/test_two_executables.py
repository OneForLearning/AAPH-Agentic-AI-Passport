"""Cross-process proof for the two final AAPH executables.

The session fixture performs one ordered scenario with real TLS sockets, the
compiled Rust server and the Python agent entry point. It retains its isolated
directory when setup or an assertion fails, and removes it only after success.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "agent"))

from aaph_agent.signing import ACTION_DOMAIN, SESSION_DOMAIN, load_key, sign, signer_public, uuid7  # noqa: E402

SECRET = "DEMO_SECRET_NOT_REAL"
ADMIN_SECRET = "NON_PRODUCTION_DEMO_BLACK_BOX_ADMIN"


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout, check=False)


def _checked(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = _run(command, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed: {command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result


def _make_certificates(root: Path) -> tuple[Path, Path, Path]:
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    server_key, request, server_cert = root / "server.key", root / "server.csr", root / "server.crt"
    extensions = root / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="ascii",
    )
    _checked([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=AAPH black-box CA", "-keyout", str(ca_key), "-out", str(ca_cert),
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ])
    _checked(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(server_key), "-out", str(request)])
    _checked(["openssl", "x509", "-req", "-days", "2", "-in", str(request), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-extfile", str(extensions), "-out", str(server_cert)])
    _checked(["openssl", "verify", "-CAfile", str(ca_cert), str(server_cert)])
    return ca_cert, server_cert, server_key


def _counts(path: Path, tables: tuple[str, ...]) -> dict[str, int]:
    with sqlite3.connect(path) as database:
        return {table: int(database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables}


def _client(ca: Path) -> httpx.Client:
    return httpx.Client(verify=ssl.create_default_context(cafile=str(ca)), timeout=5.0)


@dataclass
class Evidence:
    root: Path
    legitimate: subprocess.CompletedProcess[str]
    attack: subprocess.CompletedProcess[str]
    contained_legitimate: subprocess.CompletedProcess[str]
    recovery: subprocess.CompletedProcess[str]
    recovered_legitimate: subprocess.CompletedProcess[str]
    attack_decision: dict[str, Any]
    direct_status: int
    direct_body: str
    old_permit_status: int
    old_permit_body: str
    old_session_status: int
    contained_before_restart: dict[str, Any]
    contained_after_restart: dict[str, Any]
    persistence_before: dict[str, Any]
    persistence_after: dict[str, Any]
    output_before: dict[str, bytes]
    output_after_attack: dict[str, bytes]
    permit_ids_before: set[str]
    permit_ids_after: set[str]
    audit: list[dict[str, Any]]
    audit_status: dict[str, Any]
    collected_text: str


class Scenario:
    def __init__(self, root: Path):
        self.root = root
        self.public_port = _port()
        self.admin_port = _port()
        self.server: subprocess.Popen[str] | None = None
        self.server_log = root / "server.log"
        self.log_handle: Any = None

    def start(self, executable: Path, environment: dict[str, str], ca: Path) -> None:
        self.log_handle = self.server_log.open("a", encoding="utf-8")
        self.server = subprocess.Popen([str(executable)], cwd=ROOT, env=environment, stdout=self.log_handle, stderr=subprocess.STDOUT, text=True)
        url = f"https://localhost:{self.public_port}/health"
        tls_context = ssl.create_default_context(cafile=str(ca))
        last_error: Exception | None = None
        for _ in range(100):
            if self.server.poll() is not None:
                break
            try:
                response = httpx.get(url, verify=tls_context, timeout=1.0)
                if response.status_code == 200:
                    return
            except httpx.HTTPError as error:
                last_error = error
            time.sleep(0.1)
        self.stop()
        raise RuntimeError(f"server did not become healthy: {last_error}\n{self.server_log.read_text(encoding='utf-8')}")

    def stop(self) -> None:
        if self.server is not None and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None


def _execute_scenario(root: Path) -> Evidence:
    scenario = Scenario(root)
    cert_dir, workspace = root / "certs", root / "workspace"
    authority_keys, agent_keys, config_dir = root / "authority", root / "agent", root / "config"
    for directory in (cert_dir, workspace / "inbox", workspace / "output", workspace / "secrets", config_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (workspace / "inbox" / "report.txt").write_text("Harmless black-box input.\n", encoding="utf-8")
    shutil.copy2(ROOT / "demo/workspace/inbox/poisoned-document.txt", workspace / "inbox/poisoned-document.txt")
    (workspace / "secrets" / "credentials.txt").write_text(f"{SECRET}\n", encoding="utf-8")
    for name in ("agent-manifest.json", "mandate.json", "policy.json"):
        shutil.copy2(ROOT / "config" / name, config_dir / name)
    ca, cert, tls_key = _make_certificates(cert_dir)

    cargo = os.environ.get("CARGO", "cargo")
    _checked([cargo, "build", "-p", "aaph-server"], timeout=900)
    _checked([cargo, "build", "-p", "aaph-core", "--bin", "aaph-keygen"], timeout=900)
    suffix = ".exe" if os.name == "nt" else ""
    server_bin = ROOT / "target" / "debug" / f"aaph-server{suffix}"
    keygen_bin = ROOT / "target" / "debug" / f"aaph-keygen{suffix}"
    _checked([str(keygen_bin), str(authority_keys)])
    _checked([str(keygen_bin), str(agent_keys)])

    server_env = os.environ.copy()
    server_env.update({
        "AAPH_PUBLIC_LISTEN_ADDR": f"127.0.0.1:{scenario.public_port}",
        "AAPH_ADMIN_LISTEN_ADDR": f"127.0.0.1:{scenario.admin_port}",
        "AAPH_PUBLIC_TLS_CERT": str(cert), "AAPH_PUBLIC_TLS_KEY": str(tls_key),
        "AAPH_ADMIN_TLS_CERT": str(cert), "AAPH_ADMIN_TLS_KEY": str(tls_key),
        "AAPH_AUTHORITY_DATABASE_URL": f"sqlite://{root / 'authority.db'}",
        "AAPH_PEP_DATABASE_URL": f"sqlite://{root / 'pep.db'}",
        "AAPH_CONFIG_DIR": str(config_dir), "AAPH_PEP_WORKSPACE": str(workspace),
        "AAPH_AUTHORITY_SIGNING_KEY_FILE": str(authority_keys / "signing.key"),
        "AAPH_AGENT_PUBLIC_KEY_FILE": str(agent_keys / "public.key"),
        "AAPH_ADMIN_SECRET": ADMIN_SECRET, "RUST_LOG": "info",
    })
    agent_config = root / "agent.json"
    agent_config.write_text(json.dumps({"schema_version": 1, "instance_id": "demo-instance", "server_url": f"https://localhost:{scenario.public_port}"}), encoding="utf-8")
    agent_env = os.environ.copy()
    agent_env.update({"AAPH_AGENT_CONFIG": str(agent_config), "AAPH_AGENT_SIGNING_KEY": str(agent_keys / "signing.key"), "AAPH_TLS_CA_CERT": str(ca)})
    task = str(ROOT / "demo/legitimate-task.json")
    agent_command = [sys.executable, "-m", "aaph_agent.main", "run", "--task", task]

    try:
        scenario.start(server_bin, server_env, ca)
        client = _client(ca)
        legitimate = _run(agent_command + ["--planner", "deterministic"], env=agent_env)
        output_before = {path.name: path.read_bytes() for path in (workspace / "output").iterdir() if path.is_file()}

        key = load_key(agent_keys / "signing.key")
        session_id = uuid7()
        session_request = {"instance_id": "demo-instance", "session_id": session_id, "issued_at": int(time.time())}
        session_response = client.post(f"https://localhost:{scenario.public_port}/v1/sessions", json=sign(session_request, SESSION_DOMAIN, key))
        session_response.raise_for_status()
        proposal = {"request_id": uuid7(), "session_id": session_id, "action": "READ_FILE", "resource": "inbox/report.txt", "size_bytes": 128, "purpose": "analysis", "destination": None}
        decision_response = client.post(f"https://localhost:{scenario.public_port}/v1/actions/propose", json=sign(proposal, ACTION_DOMAIN, key))
        decision_response.raise_for_status()
        old_effect = {"permit": decision_response.json()["permit"], "request": proposal, "holder_public_key": signer_public(key)}

        attack = _run(agent_command + ["--planner", "adversarial-demo"], env=agent_env)
        output_after_attack = {path.name: path.read_bytes() for path in (workspace / "output").iterdir() if path.is_file()}
        contained_before = client.get(f"https://localhost:{scenario.public_port}/v1/instances/demo-instance").json()
        contained_legitimate = _run(agent_command + ["--planner", "deterministic"], env=agent_env)
        direct = client.post(f"https://localhost:{scenario.public_port}/v1/effects/execute", json={"request": proposal})
        old_permit = client.post(f"https://localhost:{scenario.public_port}/v1/effects/execute", json=old_effect)
        audit_before = client.get(f"https://localhost:{scenario.public_port}/v1/audit/export").json()
        client.close()
        scenario.stop()

        authority_tables = ("agent_sessions", "budget_reservations", "execution_permits", "audit_events")
        pep_tables = ("effect_operations", "consumed_jtis", "consumed_nonces", "containment_events")
        persistence_before = {"authority": _counts(root / "authority.db", authority_tables), "pep": _counts(root / "pep.db", pep_tables)}
        with sqlite3.connect(root / "authority.db") as database:
            budget_before = tuple(database.execute("SELECT action_consumed,read_consumed,write_consumed FROM budget_ledgers").fetchone())
            permit_ids_before = {row[0] for row in database.execute("SELECT permit_id FROM execution_permits")}
        persistence_before["budget"] = budget_before

        scenario.start(server_bin, server_env, ca)
        client = _client(ca)
        contained_after = client.get(f"https://localhost:{scenario.public_port}/v1/instances/demo-instance").json()
        persistence_after = {"authority": _counts(root / "authority.db", authority_tables), "pep": _counts(root / "pep.db", pep_tables)}
        with sqlite3.connect(root / "authority.db") as database:
            persistence_after["budget"] = tuple(database.execute("SELECT action_consumed,read_consumed,write_consumed FROM budget_ledgers").fetchone())

        recovery_env = os.environ.copy()
        recovery_env.update({"AAPH_ADMIN_SECRET": ADMIN_SECRET, "AAPH_ADMIN_URL": f"https://localhost:{scenario.admin_port}", "AAPH_TLS_CA_CERT": str(ca), "AAPH_INSTANCE_ID": "demo-instance"})
        recovery = _run([sys.executable, str(ROOT / "tools/aaph-admin/recover.py")], env=recovery_env)
        old_session_proposal = {**proposal, "request_id": uuid7()}
        old_session = client.post(f"https://localhost:{scenario.public_port}/v1/actions/propose", json=sign(old_session_proposal, ACTION_DOMAIN, key))
        recovered_legitimate = _run(agent_command + ["--planner", "deterministic"], env=agent_env)
        audit_status = client.get(f"https://localhost:{scenario.public_port}/v1/audit/verify").json()
        audit = client.get(f"https://localhost:{scenario.public_port}/v1/audit/export").json()
        client.close()
        with sqlite3.connect(root / "authority.db") as database:
            permit_ids_after = {row[0] for row in database.execute("SELECT permit_id FROM execution_permits")}

        collected = "\n".join([legitimate.stdout, legitimate.stderr, attack.stdout, attack.stderr, contained_legitimate.stdout, contained_legitimate.stderr, recovery.stdout, recovery.stderr, recovered_legitimate.stdout, recovered_legitimate.stderr, scenario.server_log.read_text(encoding="utf-8"), json.dumps(audit), json.dumps(audit_before), direct.text, old_permit.text, *[value.decode("utf-8", errors="replace") for value in output_after_attack.values()]])
        attack_line = next(line for line in attack.stdout.splitlines() if line.startswith("[ATTACK]"))
        return Evidence(root, legitimate, attack, contained_legitimate, recovery, recovered_legitimate, {"line": attack_line}, direct.status_code, direct.text, old_permit.status_code, old_permit.text, old_session.status_code, contained_before, contained_after, persistence_before, persistence_after, output_before, output_after_attack, permit_ids_before, permit_ids_after, audit, audit_status, collected)
    finally:
        scenario.stop()


@pytest.fixture(scope="session")
def evidence(request: pytest.FixtureRequest) -> Evidence:
    root = Path(tempfile.mkdtemp(prefix="aaph-black-box-"))
    failures_before = request.session.testsfailed
    try:
        result = _execute_scenario(root)
    except Exception:
        print(f"black-box artifacts retained after setup failure: {root}", file=sys.stderr)
        raise
    yield result
    if request.session.testsfailed == failures_before:
        shutil.rmtree(root)
    else:
        print(f"black-box artifacts retained after test failure: {root}", file=sys.stderr)


def test_legitimate_task_cross_process(evidence: Evidence) -> None:
    assert evidence.legitimate.returncode == 0
    assert evidence.output_before.get("summary.txt") == b"#" * 256


def test_injection_changes_proposal_but_not_authority(evidence: Evidence) -> None:
    assert evidence.attack.returncode == 0
    assert "out-of-scope resource and external destination" in evidence.attack_decision["line"]


def test_malicious_proposal_receives_no_permit(evidence: Evidence) -> None:
    assert "[DENY] E_DESTINATION_NOT_ALLOWED" in evidence.attack.stdout
    assert "[CONTAIN] instance=demo-instance epoch=1" in evidence.attack.stdout


def test_direct_effect_without_permit_is_rejected(evidence: Evidence) -> None:
    assert evidence.direct_status == 400
    assert "E_SCHEMA_INVALID" in evidence.direct_body


def test_workspace_unchanged_after_attack(evidence: Evidence) -> None:
    assert evidence.output_after_attack == evidence.output_before
    assert SECRET not in evidence.collected_text


def test_old_permit_rejected_after_quarantine(evidence: Evidence) -> None:
    assert evidence.old_permit_status == 403
    assert "E_EPOCH_STALE" in evidence.old_permit_body
    assert evidence.contained_legitimate.returncode == 1


def test_restart_preserves_quarantine_budget_and_replay_state(evidence: Evidence) -> None:
    assert evidence.contained_before_restart == evidence.contained_after_restart
    assert evidence.contained_after_restart["state"] == "CONTAINED"
    assert evidence.persistence_before == evidence.persistence_after
    assert all(value > 0 for group in (evidence.persistence_after["authority"], evidence.persistence_after["pep"]) for value in group.values())


def test_recovery_requires_new_session(evidence: Evidence) -> None:
    assert evidence.recovery.returncode == 0
    assert '"new_session_required": true' in evidence.recovery.stdout.lower()
    assert evidence.old_session_status == 403


def test_post_recovery_legitimate_action_has_unique_ids(evidence: Evidence) -> None:
    assert evidence.recovered_legitimate.returncode == 0
    new_ids = evidence.permit_ids_after - evidence.permit_ids_before
    assert len(new_ids) == 4
    assert not (new_ids & evidence.permit_ids_before)


def test_audit_chain_reconstructs_complete_scenario(evidence: Evidence) -> None:
    assert evidence.audit_status.get("valid") is True
    assert evidence.audit_status.get("event_count") == len(evidence.audit)
    event_types = {event.get("event_type") for event in evidence.audit}
    assert {"DECISION", "PERMIT_ISSUED", "INSTANCE_CONTAINED", "INSTANCE_RECOVERED"} <= event_types
    assert SECRET not in evidence.collected_text
