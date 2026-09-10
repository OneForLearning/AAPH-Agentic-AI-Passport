import base64
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aaph_agent import AgentError
from aaph_agent.client import AaphAgent
from aaph_agent.main import load_runtime
from aaph_agent.planner import DemoVulnerablePlanner, DeterministicPlanner, validate_task
from aaph_agent.signing import ACTION_DOMAIN, b64, canonical, sign, transcript, uuid7

ROOT=Path(__file__).parents[2]
TASK=json.loads((ROOT/"demo/legitimate-task.json").read_text(encoding="utf-8"))

def test_uuid7_profile_is_canonical_and_unique():
    values={uuid7() for _ in range(100)}
    assert len(values)==100
    assert all(len(value)==36 and value[14]=="7" and value[19] in "89ab" for value in values)

def test_docker_configuration_matches_closed_schema():
    config=json.loads((ROOT/"config/agent-docker.json").read_text(encoding="utf-8"))
    assert set(config)=={"schema_version","instance_id","server_url"}
    assert config["schema_version"]==1

def test_configuration_rejects_unknown_and_legacy_urls(tmp_path,monkeypatch):
    path=tmp_path/"agent.json";key_path=tmp_path/"signing.key"
    key_path.write_text(base64.urlsafe_b64encode(bytes([1])*32).rstrip(b"=").decode(),encoding="ascii")
    monkeypatch.setenv("AAPH_AGENT_CONFIG",str(path));monkeypatch.setenv("AAPH_AGENT_SIGNING_KEY",str(key_path))
    for value in [
        {"schema_version":1,"instance_id":"demo-instance","server_url":"https://server","unknown":True},
        {"schema_version":1,"instance_id":"demo-instance","controller_url":"https://one","pep_url":"https://two"},
        {"schema_version":1,"instance_id":"demo-instance","server_url":"http://server"},
    ]:
        path.write_text(json.dumps(value),encoding="utf-8")
        with pytest.raises(AgentError): load_runtime()

def key(): return Ed25519PrivateKey.from_private_bytes(bytes([1])*32)

def test_planner_is_deterministic_and_typed():
    actions=DeterministicPlanner().plan(TASK)
    assert [(a.action,a.resource) for a in actions]==[("LIST_DIRECTORY","inbox/"),("READ_FILE","inbox/report.txt"),("COMPUTE_SHA256","inbox/report.txt"),("WRITE_REPORT","output/summary.txt")]

def test_task_schema_is_closed():
    validate_task(TASK)
    with pytest.raises(AgentError): validate_task({**TASK,"unknown":True})
    with pytest.raises(AgentError): validate_task({**TASK,"read_limit":-1})

def test_jcs_transcript_digest_and_signature_vector():
    vector=json.loads((ROOT/"fixtures/interop-action.json").read_text(encoding="utf-8"))
    assert canonical(vector["proposal"]).decode()==vector["canonical_json"]
    assert b64(__import__("hashlib").sha384(transcript(ACTION_DOMAIN,vector["proposal"])).digest())==vector["digest_sha384"]
    envelope=sign(vector["proposal"],ACTION_DOMAIN,key())
    assert envelope["signer_public_key"]==vector["public_key"]
    assert envelope["signature"]==vector["signature"]

def test_missing_configuration_fails_cleanly(monkeypatch):
    monkeypatch.delenv("AAPH_AGENT_CONFIG",raising=False);monkeypatch.delenv("AAPH_AGENT_SIGNING_KEY",raising=False)
    with pytest.raises(AgentError): load_runtime()

def test_stops_on_deny_without_contacting_pep():
    calls=[]
    def handler(request):
        calls.append(str(request.url))
        if request.url.path=="/v1/sessions": return httpx.Response(200,json={"session_id":"s","expires_at":1,"session_epoch":0,"containment_epoch":0})
        return httpx.Response(200,json={"decision":{"decision":"DENY","reason":"E_ACTION_NOT_ALLOWED"}})
    client=httpx.Client(transport=httpx.MockTransport(handler))
    agent=AaphAgent({"instance_id":"demo-instance","server_url":"http://server"},key(),client)
    with pytest.raises(AgentError): agent.run(TASK)
    assert all(url.startswith("http://server") for url in calls)

def test_legitimate_scenario_uses_only_controller_and_pep_routes():
    calls=[]
    def handler(request):
        calls.append(request.url.path)
        if request.url.path=="/v1/sessions": return httpx.Response(200,json={"session_id":"s","expires_at":1,"session_epoch":0,"containment_epoch":0})
        if request.url.path=="/v1/actions/propose": return httpx.Response(200,json={"decision":{"decision":"PERMIT"},"permit":{"marker":"redacted-test-permit"}})
        if request.url.path=="/v1/effects/execute": return httpx.Response(200,json={"ok":True})
        return httpx.Response(404)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        results=AaphAgent({"instance_id":"demo-instance","server_url":"http://server"},key(),client).run(TASK)
    assert len(results)==4
    assert set(calls)<={"/v1/sessions","/v1/actions/propose","/v1/effects/execute"}
    assert calls.count("/v1/effects/execute")==4

def test_agent_never_contacts_a_second_origin():
    origins=[]
    def handler(request):
        origins.append(f"{request.url.scheme}://{request.url.host}")
        if request.url.path=="/v1/sessions":return httpx.Response(200,json={"session_id":"s","expires_at":1,"session_epoch":0,"containment_epoch":0})
        if request.url.path=="/v1/actions/propose":return httpx.Response(200,json={"decision":{"decision":"PERMIT"},"permit":{}})
        return httpx.Response(200,json={"ok":True})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        AaphAgent({"instance_id":"demo-instance","server_url":"https://only"},key(),client).run(TASK)
    assert set(origins)=={"https://only"}

def test_package_has_no_workspace_or_admin_capability():
    package=ROOT/"agent/aaph_agent"
    source="\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    assert "AAPH_ADMIN_SECRET" not in source
    assert "AAPH_PEP_WORKSPACE" not in source
    assert "recover" not in source
    assert "subprocess" not in source

def test_agent_forwards_complete_permit_identifiers_unchanged():
    observed=[]
    permit={"marker":"NON_PRODUCTION_DEMO","artifact":{"permit_id":"01890f3e-4c00-7000-8000-000000000001","jti":"01890f3e-4c00-7000-8000-000000000002","nonce":"AAAAAAAAAAAAAAAAAAAAAA","effect_operation_id":"01890f3e-4c00-7000-8000-000000000003"},"signer_public_key":"public","signature":"signature"}
    def handler(request):
        if request.url.path=="/v1/sessions": return httpx.Response(200,json={"session_id":"s","expires_at":1,"session_epoch":0,"containment_epoch":0})
        if request.url.path=="/v1/actions/propose": return httpx.Response(200,json={"decision":{"decision":"PERMIT"},"permit":permit})
        if request.url.path=="/v1/effects/execute":
            observed.append(json.loads(request.content)["permit"])
            return httpx.Response(200,json={"ok":True})
        return httpx.Response(404)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        AaphAgent({"instance_id":"demo-instance","server_url":"http://server"},key(),client).run(TASK)
    assert observed==[permit]*4

def test_demo_marker_is_strict_and_opt_in():
    document=(ROOT/"demo/poisoned-document.txt").read_text(encoding="utf-8")
    injected=DemoVulnerablePlanner().injected_action(document)
    assert injected["resource"]=="../secrets/credentials.txt"
    assert injected["destination"]=="https://attacker.invalid/collect"
    assert len(DeterministicPlanner().plan(TASK))==4
    with pytest.raises(AgentError): DemoVulnerablePlanner().injected_action("AAPH_DEMO_ACTION_JSON:{\"action\":\"OPEN_SHELL\"}")

def test_attack_demo_same_agent_is_contained_and_cannot_bypass_pep():
    calls=[]; proposal_count=0; effect_count=0
    poison=(ROOT/"demo/poisoned-document.txt").read_text(encoding="utf-8")
    def handler(request):
        nonlocal proposal_count,effect_count
        calls.append(request.url.path)
        if request.url.path=="/v1/sessions": return httpx.Response(200,json={"session_id":"session","expires_at":1,"session_epoch":0,"containment_epoch":0})
        if request.url.path=="/v1/actions/propose":
            proposal_count+=1
            if proposal_count<=3:return httpx.Response(200,json={"decision":{"decision":"PERMIT"},"permit":{"id":proposal_count}})
            if proposal_count==4:return httpx.Response(200,json={"decision":{"decision":"QUARANTINE","reason":"E_RESOURCE_OUT_OF_SCOPE"},"containment_propagation_incomplete":False})
            return httpx.Response(403,json={"reason":"E_AGENT_CONTAINED"})
        if request.url.path=="/v1/effects/execute":
            effect_count+=1
            body=json.loads(request.content)
            if "permit" not in body:return httpx.Response(400,json={"reason":"E_SCHEMA_INVALID"})
            if effect_count>3:return httpx.Response(403,json={"reason":"E_EPOCH_STALE"})
            content=poison if effect_count==3 else None
            return httpx.Response(200,json={"content":content})
        if request.url.path=="/v1/instances/demo-instance":return httpx.Response(200,json={"state":"CONTAINED","containment_epoch":1})
        if request.url.path=="/v1/audit/verify":return httpx.Response(200,json={"valid":True,"event_count":6})
        return httpx.Response(404)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary=AaphAgent({"instance_id":"demo-instance","server_url":"http://server"},key(),client,DemoVulnerablePlanner()).run_attack_demo(TASK)
    trace="\n".join(summary)
    assert "[CONTAIN] instance=demo-instance epoch=1" in trace
    assert "[DENY] E_AGENT_CONTAINED" in trace
    assert "[REPLAY] E_EPOCH_STALE" in trace
    assert "[AUDIT] chain valid" in trace
    assert "DEMO_SECRET_NOT_REAL" not in trace
    assert set(calls)<={"/v1/sessions","/v1/actions/propose","/v1/effects/execute","/v1/instances/demo-instance","/v1/audit/verify"}
