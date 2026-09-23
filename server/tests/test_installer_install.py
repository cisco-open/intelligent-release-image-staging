# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installation transaction, permissions, custody boundaries and resume tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import cli, deploy, ubuntu
from iris_installer.state import InstallError, Journal, atomic_write, regular_bytes


def config():
    return dict(target="docker", instance="iris-test", host="127.0.0.2",
                console_bind="127.0.0.1", console_port=18080,
                recovery_recipient="age1" + "q" * 58, peer_tls="required")


def test_atomic_journal_permissions_resume_and_lock(tmp_path):
    path = tmp_path / "instance"
    with Journal(path).locked(create=True) as journal:
        journal.document = {"schema": 1, "config": config(), "completed": {}}
        journal.checkpoint("prepared", "digest")
        assert journal.path.stat().st_mode & 0o777 == 0o600
        with pytest.raises(InstallError, match="Another installer"):
            with Journal(path).locked():
                pass
    with Journal(path).locked() as resumed:
        assert resumed.document["completed"] == {"prepared": "digest"}
        resumed.pause("WAITING_FOR_SIGNING_APPROVAL")
    assert json.loads((path / "installation.json").read_text())["state"] == "WAITING_FOR_SIGNING_APPROVAL"


def test_unsafe_state_permissions_rejected(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(InstallError, match="0700"):
        with Journal(tmp_path).locked():
            pass


def test_symlink_state_and_fifo_inputs_rejected(tmp_path):
    (tmp_path / "alias").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(InstallError, match="symlinks"):
        Journal(tmp_path / "alias/child")
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    with pytest.raises(InstallError, match="regular"):
        regular_bytes(pipe)


def test_oversized_and_symlink_input_rejected(tmp_path):
    (tmp_path / "file").write_bytes(b"12345")
    with pytest.raises(InstallError, match="size limit"):
        regular_bytes(tmp_path / "file", 4)
    (tmp_path / "alias").symlink_to(tmp_path / "file")
    with pytest.raises(OSError):
        regular_bytes(tmp_path / "alias")


@pytest.mark.parametrize("change", [
    {"target": "kubernetes"}, {"host": "0.0.0.0"}, {"host": "bad\nENV=1"},
    {"instance": "../../owner"}, {"instance": "--flag"}, {"console_port": 8443},
    {"console_port": 65536}, {"recovery_recipient": "PRIVATE KEY"}, {"peer_tls": "auto"},
])
def test_invalid_configuration_fails_before_mutation(change):
    value = config()
    value.update(change)
    with pytest.raises(InstallError):
        deploy.validate_config(value)


def test_roots_are_public_distinct_and_exactly_two(tmp_path):
    (tmp_path / "root-a.pub").write_bytes(b"ssh-ed25519 AAAA a\n")
    (tmp_path / "root-b.pub").write_bytes(b"ssh-ed25519 BBBB b\n")
    assert len(deploy.read_roots(tmp_path)) == 2
    (tmp_path / "private").write_bytes(b"PRIVATE")
    with pytest.raises(InstallError):
        deploy.read_roots(tmp_path)
    (tmp_path / "private").unlink()
    (tmp_path / "root-b.pub").write_bytes(b"ssh-ed25519 AAAA another-comment\n")
    with pytest.raises(InstallError, match="distinct"):
        deploy.read_roots(tmp_path)


def test_snapshot_copies_only_manifested_source_and_detects_drift(tmp_path):
    source = tmp_path / "input"
    source.mkdir()
    (source / "file").write_bytes(b"code")
    (source / "untracked-secret").write_bytes(b"do not copy")
    manifest = {"file": hashlib.sha256(b"code").hexdigest()}
    (source / "INSTALLER-SOURCE.json").write_text(json.dumps(manifest))
    assert deploy.snapshot(source, tmp_path / "output") == manifest
    assert not (tmp_path / "output/untracked-secret").exists()
    (source / "file").write_bytes(b"tamper")
    with pytest.raises(InstallError, match="mismatch"):
        deploy.snapshot(source, tmp_path / "bad")


@pytest.mark.parametrize("name", ["/etc/passwd", "../outside", "a/../outside", "a//file"])
def test_snapshot_rejects_path_traversal(tmp_path, name):
    source = tmp_path / "input"
    source.mkdir()
    (source / "INSTALLER-SOURCE.json").write_text(json.dumps({name: "0" * 64}))
    with pytest.raises(InstallError, match="Unsafe"):
        deploy.snapshot(source, tmp_path / "output")


@pytest.fixture
def installation(tmp_path, monkeypatch):
    base = tmp_path / "instance"
    base.mkdir(mode=0o700)
    (base / "source").mkdir()
    (base / "roots").mkdir()
    (base / "source/code").write_bytes(b"code")
    roots = {"a.pub": b"ssh-ed25519 AAAA a\n", "b.pub": b"ssh-ed25519 BBBB b\n"}
    for name, data in roots.items():
        (base / "roots" / name).write_bytes(data)
    journal = Journal(base)
    journal.document = {"schema": 1, "config": config(), "completed": {}, "id": "test-id",
                        "source_manifest": {"code": hashlib.sha256(b"code").hexdigest()},
                        "root_digests": {n: hashlib.sha256(d).hexdigest() for n, d in roots.items()}}
    journal.save()
    monkeypatch.setattr(os, "chown", lambda *a: None)
    monkeypatch.setattr(ubuntu, "provision", lambda run: None)
    return deploy.DockerInstall(journal, runner=lambda *a, **k: b"")


def test_resume_refuses_source_or_root_changes(installation):
    installation.verify_inputs()
    (installation.source / "code").write_bytes(b"changed")
    with pytest.raises(InstallError, match="snapshot changed"):
        installation.verify_inputs()
    (installation.source / "code").write_bytes(b"code")
    (installation.base / "roots/a.pub").write_bytes(b"ssh-ed25519 CCCC a\n")
    with pytest.raises(InstallError, match="fingerprints changed"):
        installation.verify_inputs()


def test_prepare_uses_scoped_names_and_does_not_publish_management(installation):
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if command[:2] == ["age-keygen", "-o"]:
            Path(command[2]).write_bytes(b"private")
        if command[:2] == ["age-keygen", "-y"]:
            return b"age1primary"
        if "config" in command:
            assert kwargs["env"]["IRIS_PEER_TLS_MODE"] == "required"
            return json.dumps({"services": {
                "iris": {"ports": [{"target": 8443, "published": "8443"}]},
                "console": {"ports": [{"target": 8080, "published": "18080"}]},
            }, "volumes": {"data": {}}, "networks": {"default": {}}}).encode()
        return b""

    installation.runner = runner
    installation.prepare()
    result = json.loads(installation.compose_file.read_text())
    assert result["name"] == "iris-test"
    assert result["services"]["iris"]["container_name"] == "iris-test-server"
    assert result["services"]["console"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert all(p["target"] != 9443 for s in result["services"].values() for p in s["ports"])
    assert "private" not in installation.compose_file.read_text()
    assert (installation.base / "age.txt").stat().st_mode & 0o777 == 0o600
    installation.prepare()
    assert sum(command[:2] == ["age-keygen", "-o"] for command, _ in calls) == 1


def test_signing_pause_reuses_existing_key_and_never_initializes_producer(installation):
    (installation.base / "requests").mkdir()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if any("os.path.exists" in arg for arg in command):
            return b"True\n"
        if any("export_online_public" in arg for arg in command):
            return b"ssh-ed25519 AAAA online\n"
        if "--status" in command:
            return b'{"enabled":false,"signing_refused":true}'
        return b""

    installation.runner = runner
    assert installation.signing() is False
    assert installation.signing() is False
    assert installation.journal.document["state"] == "WAITING_FOR_SIGNING_APPROVAL"
    assert not any("--generate-online-key" in c for c in calls)
    assert not any("initialize_producer" in part for c in calls for part in c)
    assert (installation.base / "requests/online.pub").stat().st_mode & 0o777 == 0o644


def test_signing_imports_via_stdin_not_docker_cp(installation, tmp_path):
    (installation.base / "requests").mkdir()
    certificate = tmp_path / "certificate"
    certificate.write_bytes(b"public certificate")
    certificate.chmod(0o600)
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if any("os.path.exists" in arg for arg in command):
            return b"True\n"
        if any("export_online_public" in arg for arg in command):
            return b"ssh-ed25519 AAAA online\n"
        if "--status" in command:
            return b'{"enabled":true,"signing_refused":false,"state":"keylist_missing"}'
        return b""

    installation.runner = runner
    assert installation.signing(certificate)
    assert any(kw.get("input") == b"public certificate" for _, kw in calls)
    assert not any("cp" in c for c, _ in calls)
    assert any("_validated_activation_epoch" in arg for c, _ in calls for arg in c)


def test_resume_checks_everything_before_build_or_bootstrap(installation, monkeypatch):
    (installation.source / "code").write_bytes(b"changed")
    monkeypatch.setattr(installation, "build", lambda: pytest.fail("must not build"))
    with pytest.raises(InstallError):
        installation.resume()


def test_resume_phase_order_and_approval_pause(installation, monkeypatch):
    phases = []
    for method in ("verify_inputs", "verify_resource_ownership", "prepare", "build", "bootstrap"):
        monkeypatch.setattr(installation, method, lambda m=method: phases.append(m))
    monkeypatch.setattr(installation, "signing", lambda cert: False)
    monkeypatch.setattr(installation, "packages", lambda: pytest.fail("approval first"))
    assert installation.resume() == deploy.WAITING_APPROVAL
    assert phases == ["verify_inputs", "verify_resource_ownership", "prepare", "build", "bootstrap"]


def test_existing_resource_not_owned_is_refused(installation):
    def runner(command, **kwargs):
        if "ls" in command:
            return b"id"
        return b'[{"Config":{"Labels":{"com.cisco.iris.installer":"someone-else"}}}]'
    installation.runner = runner
    with pytest.raises(InstallError, match="not owned"):
        installation.verify_resource_ownership()


def test_private_ambient_configuration_not_inherited(monkeypatch):
    monkeypatch.setenv("IRIS_SKIP_XR", "1")
    monkeypatch.setenv("COMPOSE_FILE", "owner.yml")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/private-agent")
    monkeypatch.setenv("DOCKER_HOST", "tcp://other-host:2375")
    env = deploy.clean_env()
    assert not any(key in env for key in ("IRIS_SKIP_XR", "COMPOSE_FILE", "SSH_AUTH_SOCK"))
    assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"


def test_dependency_install_never_removes_an_engine(monkeypatch):
    calls = []
    monkeypatch.setattr(ubuntu, "check_platform", lambda: None)
    monkeypatch.setattr(ubuntu, "missing_packages", lambda: ["age", "rpm"])
    monkeypatch.setattr(ubuntu, "command_ok", lambda command: True)
    monkeypatch.setattr(Path, "exists", lambda path: True)
    monkeypatch.setattr(Path, "read_text", lambda path: "enabled\n")
    ubuntu.provision(lambda command, **kw: calls.append(command))
    assert calls == [["apt-get", "update"], ["apt-get", "install", "--no-remove", "-y", "age", "rpm"]]


def test_cli_install_defaults_require_peer_tls_and_local_console():
    args = cli.parser().parse_args(["install", "--host", "127.0.0.2", "--state-dir", "/state",
                                   "--roots-dir", "/roots", "--recovery-recipient", "public"])
    assert args.peer_tls == "required"
    assert args.console_bind == "127.0.0.1"
    assert not args.accept_changes


def test_package_allowlist_excludes_agent_notes_and_credentials():
    spec = importlib.util.spec_from_file_location("installer_package", REPO / "tools/build-installer-package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in ("agentinfo/HANDOFF.md", "AGENTS.md", "creds/password", "fleet/real.csv"):
        assert not module.selected(path)
    assert module.selected("fleet/devices.csv.example")
    assert module.selected("tools/iris_installer/deploy.py")
