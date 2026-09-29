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
import shutil
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import cli, deploy, ubuntu
from iris_installer.state import InstallError, Journal, atomic_write, regular_bytes


def config():
    return dict(target="docker", instance="iris-test", host="192.0.2.10",
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
    {"host": "127.0.0.2"}, {"host": "169.254.1.2"},
    {"instance": "../../owner"}, {"instance": "--flag"}, {"console_port": 8443},
    {"console_port": 65536}, {"recovery_recipient": "PRIVATE KEY"}, {"peer_tls": "auto"},
])
def test_invalid_configuration_fails_before_mutation(change):
    value = config()
    value.update(change)
    with pytest.raises(InstallError):
        deploy.validate_config(value)


@pytest.mark.parametrize("value", [{}, {"target": "docker"}, None, []])
def test_incomplete_journal_config_is_a_controlled_failure(value):
    with pytest.raises(InstallError, match="incomplete"):
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


def test_snapshot_public_directories_ignore_restrictive_umask(tmp_path):
    source = tmp_path / 'input'
    (source / 'device/agent/nested').mkdir(parents=True)
    code = source / 'device/agent/nested/code.py'
    code.write_bytes(b'public source bytes\n')
    manifest = {'device/agent/nested/code.py': hashlib.sha256(code.read_bytes()).hexdigest()}
    (source / 'INSTALLER-SOURCE.json').write_text(json.dumps(manifest))
    old = os.umask(0o077)
    try:
        output = tmp_path / 'snapshot'
        deploy.snapshot(source, output)
    finally:
        os.umask(old)
    assert all(path.stat().st_mode & 0o777 == 0o755
               for path in (output, output / 'device', output / 'device/agent', output / 'device/agent/nested'))
    assert (output / 'device/agent/nested/code.py').stat().st_mode & 0o777 == 0o644


@pytest.mark.skipif(os.geteuid() != 0, reason='real installer ownership requires root')
def test_new_install_public_roots_remain_readable_with_private_umask(tmp_path, monkeypatch):
    source, roots, state = tmp_path / 'input', tmp_path / 'approved-roots', tmp_path / 'state'
    source.mkdir()
    roots.mkdir(mode=0o700)
    (source / 'code').write_bytes(b'public code')
    (source / 'INSTALLER-SOURCE.json').write_text(json.dumps({
        'code': hashlib.sha256(b'public code').hexdigest()}))
    (roots / 'a.pub').write_bytes(b'ssh-ed25519 AAAA a\n')
    (roots / 'b.pub').write_bytes(b'ssh-ed25519 BBBB b\n')
    monkeypatch.setattr(ubuntu, 'provision', lambda *_args: None)
    monkeypatch.setattr(deploy, 'port_preflight', lambda *_args: None)
    monkeypatch.setattr(deploy, 'run', lambda *_args, **_kwargs: b'')
    monkeypatch.setattr(deploy, 'installation', lambda _journal: SimpleNamespace(resume=lambda: 20))
    args = SimpleNamespace(**config(), state_dir=state, source=source, roots_dir=roots, accept_changes=True)
    previous = os.umask(0o077)
    try:
        assert deploy.start(args) == 20
    finally:
        os.umask(previous)
    assert state.stat().st_mode & 0o777 == 0o700
    assert (state / 'installation.json').stat().st_mode & 0o777 == 0o600
    assert (state / 'roots').stat().st_mode & 0o777 == 0o755
    assert (state / 'source').stat().st_mode & 0o777 == 0o755
    assert roots.stat().st_mode & 0o777 == 0o700


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


@pytest.mark.parametrize('state', ['ok', 'unknown', 'stale'])
def test_package_gate_includes_fresh_guestshell_evidence(installation, monkeypatch, state):
    installation.journal.document['completed']['packages'] = {}
    monkeypatch.setattr(cli, 'diagnose', lambda *a, **kw: {'state': 'checks-passed'})
    calls = []
    monkeypatch.setattr(installation, 'execute', lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(installation, 'python', lambda code: json.dumps({'state': state}).encode())
    if state == 'ok':
        installation.packages()
        assert installation.journal.document['completed']['guestshell']['state'] == 'ok'
    else:
        with pytest.raises(InstallError, match='Guest Shell'):
            installation.packages()
        assert 'guestshell' not in installation.journal.document['completed']
    assert calls == [('/opt/iris/server/provision-served.sh',)]


@pytest.mark.parametrize('mask', [0o022, 0o077])
def test_prepare_uses_scoped_names_and_does_not_publish_management(installation, mask):
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
                "iris": {"ports": [{"target": 8443, "published": "8443"}], "volumes": []},
                "console": {"ports": [{"target": 8080, "published": "18080"}]},
            }, "volumes": {"data": {}}, "networks": {"default": {}}}).encode()
        return b""

    installation.runner = runner
    previous = os.umask(mask)
    try:
        installation.prepare()
    finally:
        os.umask(previous)
    result = json.loads(installation.compose_file.read_text())
    assert result["name"] == "iris-test"
    assert result["services"]["iris"]["container_name"] == "iris-test-server"
    assert result["services"]["console"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert all(p["target"] != 9443 for s in result["services"].values() for p in s["ports"])
    assert "private" not in installation.compose_file.read_text()
    assert (installation.base / "age.txt").stat().st_mode & 0o777 == 0o600
    assert installation.base.stat().st_mode & 0o777 == 0o700
    assert all((installation.base / name).stat().st_mode & 0o777 == 0o755
               for name in ('images', 'artifacts'))
    if mask == 0o077:
        assert (installation.base / 'build-home/.docker').stat().st_mode & 0o777 == 0o700
    installation.prepare()
    assert sum(command[:2] == ["age-keygen", "-o"] for command, _ in calls) == 1


def test_public_directory_permissions_never_follow_external_symlink(installation, tmp_path):
    outside = tmp_path / 'owner-directory'
    outside.mkdir(mode=0o700)
    (installation.base / 'images').symlink_to(outside, target_is_directory=True)
    with pytest.raises(InstallError, match='symlinks'):
        installation.prepare()
    assert outside.stat().st_mode & 0o777 == 0o700
    assert not (installation.base / 'age.txt').exists()


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


@pytest.mark.parametrize('phase', ['backup-pending', 'stopping', 'applying', 'recovery-required', 'restarting-server', 'restarting-console'])
def test_resume_cannot_bypass_interrupted_credential_maintenance(installation, monkeypatch, phase):
    called = []
    monkeypatch.setattr(installation, 'verify_inputs', lambda: called.append('must-not-run'))
    (installation.base / 'credential-operation.json').write_text(json.dumps({
        'phase': phase, 'instance_id': installation.journal.document['id']}))
    with pytest.raises(InstallError, match='host maintenance UI'):
        installation.resume()
    assert called == []


@pytest.mark.parametrize('kind', ['corrupt', 'symlink', 'wrong-instance'])
def test_resume_rejects_untrusted_credential_authority(installation, monkeypatch, kind):
    called = []
    monkeypatch.setattr(installation, 'verify_inputs', lambda: called.append('must-not-run'))
    target = installation.base / 'credential-operation.json'
    if kind == 'corrupt':
        target.write_text('broken')
    elif kind == 'symlink':
        target.symlink_to(installation.base / 'missing-authority')
    else:
        target.write_text(json.dumps({'phase': 'rotated', 'instance_id': 'another-deployment'}))
    with pytest.raises(InstallError, match='maintenance UI'):
        installation.resume()
    assert called == []


@pytest.mark.parametrize('phase,admitted,allowed', [('rotated', True, True), ('refused', False, True),
                                                   ('refused', True, False), ('refused', None, False)])
def test_resume_terminal_maintenance_requires_no_mutation_refusal(installation, monkeypatch, phase, admitted, allowed):
    called = []
    def next_step():
        called.append('allowed')
        raise RuntimeError('stop after admission')
    monkeypatch.setattr(installation, 'verify_inputs', next_step)
    (installation.base / 'credential-operation.json').write_text(json.dumps({
        'phase': phase, 'mutations_admitted': admitted, 'instance_id': installation.journal.document['id']}))
    if allowed:
        with pytest.raises(RuntimeError, match='stop after admission'):
            installation.resume()
        assert called == ['allowed']
    else:
        with pytest.raises(InstallError, match='maintenance UI'):
            installation.resume()
        assert called == []


def test_resume_phase_order_and_approval_pause(installation, monkeypatch):
    phases = []
    for method in ("verify_inputs", "verify_resource_ownership", "prepare", "build", "bootstrap"):
        monkeypatch.setattr(installation, method, lambda m=method: phases.append(m))
    monkeypatch.setattr(installation, "signing", lambda cert: False)
    monkeypatch.setattr(installation, "packages", lambda: pytest.fail("approval first"))
    assert installation.resume() == deploy.WAITING_APPROVAL
    assert phases == ["verify_inputs", "verify_resource_ownership", "prepare", "build", "bootstrap"]


def test_bootstrap_compares_existing_roots_and_never_force_resets(installation):
    commands = []
    installation.runner = lambda command, **kw: commands.append(command) or b""
    installation.bootstrap()
    assert all("--force" not in command for command in commands)
    assert any('cmp "$existing"' in part for command in commands for part in command)
    assert commands[-1][-1] == "iris"
    assert not any(command[-1] == "console" for command in commands)


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


def test_install_wizard_collects_public_inputs_and_approval(monkeypatch):
    answers = iter(["127.0.0.2", "/public-roots", "age1" + "q" * 58, "", "18080", "INSTALL"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    parser = cli.parser()
    args = cli.install_questions(parser.parse_args(["install"]), parser)
    assert args.state_dir == Path("/var/lib/iris-installer/iris")
    assert args.host == "127.0.0.2"
    assert args.console_bind == "127.0.0.1"
    assert args.console_port == 18080
    assert args.accept_changes


def test_noninteractive_install_refuses_to_guess_inputs(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as error:
        cli.main(["install"])
    assert error.value.code == 2


def test_install_questions_show_selected_console_address(monkeypatch):
    answers = iter(["192.0.2.10", "/public-roots", "age1" + "q" * 58, "", "", "INSTALL"])
    prompts = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def answer(prompt):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", answer)
    parser = cli.parser()
    args = cli.install_questions(parser.parse_args(["install", "--console-bind", "192.0.2.10"]), parser)
    assert args.console_bind == "192.0.2.10"
    assert any("Console listen address [192.0.2.10;" in prompt for prompt in prompts)


@pytest.mark.parametrize("command", ["custody-ui", "maintenance-ui"])
def test_removed_desktop_commands_are_not_available(command):
    with pytest.raises(SystemExit) as error:
        cli.parser().parse_args([command])
    assert error.value.code == 2


def test_package_allowlist_excludes_agent_notes_and_credentials():
    spec = importlib.util.spec_from_file_location("installer_package", REPO / "tools/build-installer-package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in ("agentinfo/HANDOFF.md", "AGENTS.md", "creds/password", "fleet/real.csv"):
        assert not module.selected(path)
    assert module.selected("fleet/devices.csv.example")
    assert module.selected("tools/iris_installer/deploy.py")


def test_finish_exports_public_browser_certificate_and_leaves_owner_unclaimed(installation):
    (installation.base / "requests").mkdir()
    commands = []
    certificate = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
    def runner(command, **kwargs):
        commands.append(command)
        if "openssl" in command:
            return certificate
        if any("get_admin" in arg for arg in command):
            return b"False\n"
        return b""
    installation.runner = runner
    assert installation.finish() == deploy.OWNER_CLAIM
    assert installation.journal.document["state"] == "OWNER_CLAIM_REQUIRED"
    assert (installation.base / "requests/console-cert.pem").read_bytes() == certificate
    assert not any("set_admin" in arg or "iris-gui-admin" in arg for command in commands for arg in command)


def test_actual_offline_custody_approval_with_disposable_test_key(tmp_path):
    from iris_installer.custody import approve
    for name in ("root", "online"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / name)], check=True)
    args = SimpleNamespace(public_key=tmp_path / "online.pub", root_key=tmp_path / "root",
                           output=tmp_path / "issued.pub")
    assert approve(args) == 0
    assert args.output.stat().st_mode & 0o777 == 0o644
    fields = subprocess.check_output(["ssh-keygen", "-Lf", str(args.output)], text=True)
    assert "iris-server" in fields
    with pytest.raises(InstallError, match="already exists"):
        approve(args)


def test_custody_refuses_world_readable_private_root(tmp_path):
    from iris_installer.custody import approve
    root = tmp_path / "root"
    root.write_text("private fixture")
    root.chmod(0o644)
    public = tmp_path / "online.pub"
    public.write_bytes(b"ssh-ed25519 AAAA online\n")
    with pytest.raises(InstallError, match="private permissions"):
        approve(SimpleNamespace(public_key=public, root_key=root, output=tmp_path / "issued.pub"))


@pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="Debian package tool required")
def test_actual_deb_contains_runnable_installer_not_untracked_secrets(tmp_path):
    spec = importlib.util.spec_from_file_location("installer_package", REPO / "tools/build-installer-package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tools").mkdir()
    shutil.copytree(REPO / "tools/iris_installer", repo / "tools/iris_installer",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(REPO / "tools/irisctl", repo / "tools/irisctl")
    shutil.copy2(REPO / "tools/iris-key-setup", repo / "tools/iris-key-setup")
    (repo / "docs/dev").mkdir(parents=True)
    (repo / "docs/dev/installer.md").write_text("Candidate installer\n")
    for name, content in (("VERSION", "2026.09.23"), ("LICENSE", "Apache-2.0"), ("NOTICE", "Notices")):
        (repo / name).write_text(content + "\n")
    for args in (["init", "-q"], ["add", "."],
                 ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True)
    (repo / "server").mkdir()
    (repo / "server/.env").write_text("secret must not ship")
    previous = os.umask(0o077)
    try:
        artifact = module.build(repo, tmp_path / "output")
    finally:
        os.umask(previous)
    extracted = tmp_path / "extracted"
    subprocess.run(["dpkg-deb", "--extract", str(artifact), str(extracted)], check=True)
    assert not (extracted / "usr/lib/iris-installer/source/server/.env").exists()
    assert (extracted / "usr/lib/iris-installer/iris_installer/cli.py").stat().st_mode & 0o777 == 0o644
    assert (extracted / "usr/lib/iris-installer").stat().st_mode & 0o777 == 0o755
    result = subprocess.run([str(extracted / "usr/bin/irisctl"), "install", "--help"],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert "--recovery-recipient" in result.stdout
    helper = extracted / "usr/bin/iris-key-setup"
    assert helper.stat().st_mode & 0o777 == 0o755
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS")}
    result = subprocess.run([str(helper), "--help"], env=environment,
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert not (extracted / "usr/lib/iris-installer/iris-custody-askpass").exists()
    assert not (extracted / "usr/share/applications/iris-offline-signing.desktop").exists()
    assert "python3-tk" not in subprocess.check_output(["dpkg-deb", "-f", str(artifact), "Depends"], text=True)
    result = subprocess.run([str(extracted / "usr/bin/irisctl"), "--help"],
                            env=environment, capture_output=True, text=True)
    assert result.returncode == 0
    assert "custody-ui" not in result.stdout and "maintenance-ui" not in result.stdout
    assert "maintenance" in result.stdout
    inventory = json.loads(artifact.with_suffix(".deb.source.json").read_text())
    assert inventory["commit"] == subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    assert inventory["files"] == json.loads(
        (extracted / "usr/lib/iris-installer/source/INSTALLER-SOURCE.json").read_text())
    control = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(artifact)])
    import io, tarfile
    with tarfile.open(fileobj=io.BytesIO(control)) as archive:
        assert not any(Path(member.name).name in ("postinst", "preinst", "postrm", "prerm") for member in archive)
