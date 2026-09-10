import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[2]

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"demo"/f"{name}.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def test_delivery_boundary_rejects_shared_agent_private_key():
    check=load("check_delivery_boundary")
    bad={"services":{"agent":{"volumes":["./local-keys/agent/signing.key:/run/keys/agent/signing.key:ro"]},"server":{"volumes":["./local-keys/agent/signing.key:/server.key:ro"]}}}
    assert check.validate(bad)
    good={"services":{"agent":{"volumes":["./local-keys/agent/signing.key:/run/keys/agent/signing.key:ro"]},"server":{"volumes":["./local-keys/agent/public.key:/agent.pub:ro"]}}}
    assert check.validate(good)==[]

def test_agent_private_key_is_not_mounted_in_server():
    check=load("check_delivery_boundary")
    compose={"services":{"agent":{"environment":{},"volumes":["./local-keys/agent/signing.key:/run/keys/agent/signing.key:ro"]},"server":{"volumes":["./local-keys/agent/public.key:/agent.pub:ro"]}}}
    assert check.validate(compose)==[]
    compose["services"]["server"]["volumes"]=["./local-keys/agent/signing.key:/server.key:ro"]
    assert check.validate(compose)==["server mounts agent private key: ./local-keys/agent/signing.key"]

def test_agent_artifact_contains_no_admin_recovery_tool():
    dockerfile=(ROOT/"Dockerfile.agent").read_text()
    dockerignore=(ROOT/".dockerignore").read_text().splitlines()
    assert "recover.py" not in dockerfile
    assert "tools" in dockerignore

def test_delivery_dockerfiles_build_only_the_expected_runtimes():
    server=(ROOT/"Dockerfile.server").read_text(encoding="utf-8")
    agent=(ROOT/"Dockerfile.agent").read_text(encoding="utf-8")
    assert "cargo build --locked --release -p aaph-server" in server
    assert "COPY --from=build /src/target/release/aaph-server" in server
    for obsolete in ("authority-service", "remote-pep"):
        assert obsolete not in server
    for forbidden in ("local-keys", "dev-certs", "workspace", "authority.db", "pep.db", "recover.py"):
        assert forbidden not in agent

def test_pyinstaller_spec_embeds_no_sensitive_or_demo_data():
    spec=(ROOT/"agent/aaph-agent.spec").read_text(encoding="utf-8")
    assert "datas=[]" in spec.replace(" ", "")
    for forbidden in ("recover.py", ".key", "ca.crt", "legitimate-task", "poisoned"):
        assert forbidden not in spec

def test_agent_never_receives_admin_secret():
    check=load("check_delivery_boundary")
    compose={"services":{"agent":{"environment":{"AAPH_ADMIN_SECRET":"secret"}},"server":{}}}
    assert check.validate(compose)==["agent receives the administrative recovery secret"]

def test_agent_rejects_server_mounts_and_environment():
    check=load("check_delivery_boundary")
    base={"server":{},"agent":{"environment":{},"volumes":[]}}
    for volume in ("./authority.db:/run/server.db:ro","./demo/workspace:/workspace:ro","./local-keys/authority/signing.key:/key:ro"):
        compose={"services":{"server":{},"agent":{"environment":{},"volumes":[volume]}}}
        assert check.validate(compose)
    base["agent"]["environment"]={"AAPH_ADMIN_SECRET":"secret"}
    assert check.validate({"services":base})

def test_delivery_package_rejects_sensitive_material(tmp_path):
    check=load("check_delivery_package")
    safe=tmp_path/"safe";safe.mkdir();(safe/"aaph-server").write_text("binary")
    assert check.violations(safe)==[]
    (safe/"ca.key").write_text("secret")
    (safe/"ca.crt").write_text("certificate")
    assert {path.name for path in check.violations(safe)}=={"ca.key","ca.crt"}

def test_delivery_package_rejects_every_local_state_class(tmp_path):
    check=load("check_delivery_package")
    package=tmp_path/"package";package.mkdir()
    forbidden=(".git/config", ".venv/state", "target/binary", "__pycache__/x.pyc", "workspace/inbox/x", "state.db", "state.sqlite", "private.key", "server.crt", "run.log", "audit-export.json")
    for relative in forbidden:
        path=package/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text("x")
    found={path.as_posix() for path in check.violations(package)}
    assert set(forbidden)<=found

def test_packaging_allowlist_contains_only_two_binaries_and_public_evidence(monkeypatch):
    import sys
    monkeypatch.syspath_prepend(str(ROOT/"demo"))
    packaging=load("package_delivery")
    platform_id="linux-x86_64"
    assert packaging.expected_paths(platform_id)=={
        "aaph-server-linux-x86_64","aaph-agent-linux-x86_64","SHA256SUMS",
        "README-DEMO.md","evidence/TEST-REPORT.md","evidence/TEST_MATRIX.md",
        "evidence/versions.txt","evidence/package-manifest.json",
    }
    assert sys.modules.get("check_delivery_package") is not None

def test_pyinstaller_version_supports_python_314():
    requirement=(ROOT/"agent/requirements-build.txt").read_text(encoding="ascii").strip()
    assert requirement=="PyInstaller==6.22.2"

def test_delivery_checksum_verifier_rejects_tampering(tmp_path):
    import sys
    demo_path=str(ROOT/"demo")
    if demo_path not in sys.path:sys.path.insert(0,demo_path)
    verify=load("verify_delivery")
    platform_id="linux-x86_64"
    server=tmp_path/f"aaph-server-{platform_id}";server.write_bytes(b"server")
    agent=tmp_path/f"aaph-agent-{platform_id}";agent.write_bytes(b"agent")
    (tmp_path/"SHA256SUMS").write_text(
        f"{verify.sha256(server)}  {server.name}\n{verify.sha256(agent)}  {agent.name}\n",
        encoding="ascii",
    )
    verify.verify_checksums(tmp_path,platform_id)
    agent.write_bytes(b"tampered")
    import pytest
    with pytest.raises(RuntimeError,match="checksum mismatch"):
        verify.verify_checksums(tmp_path,platform_id)

def test_delivery_secret_verifier_rejects_private_key_material(tmp_path):
    import sys
    demo_path=str(ROOT/"demo")
    if demo_path not in sys.path:sys.path.insert(0,demo_path)
    verify=load("verify_delivery")
    package=tmp_path/"package";package.mkdir()
    repository=tmp_path/"repository";(repository/"local-keys").mkdir(parents=True)
    (repository/"local-keys"/"authority.key").write_bytes(b"private-value")
    (package/"binary").write_bytes(b"prefix-private-value-suffix")
    import pytest
    with pytest.raises(RuntimeError,match="secret marker embedded"):
        verify.verify_no_embedded_secrets(package,repository)
