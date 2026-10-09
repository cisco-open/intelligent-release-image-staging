# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped local-key setup, with host provisioning isolated from fixture keys."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import cli, key_setup, local_setup as setup
from iris_installer.state import InstallError, Journal


def arguments(tmp_path, *extra):
    return cli.parser().parse_args([
        "setup", "--instance", "example", "--host", "192.0.2.10",
        "--console-bind", "192.0.2.10", "--state-dir", str(tmp_path / "state"),
        "--source", str(tmp_path / "source"), "--key-directory", str(tmp_path / "keys"),
        *extra])


@pytest.fixture
def keys(tmp_path):
    folder = key_setup.private_directory(tmp_path / "keys")
    # Secret values here are disposable test inputs, not production arguments.
    for name in ("root-a", "root-b"):
        directory = key_setup.private_directory(folder / name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "fixture-only",
                        "-f", str(directory / name)], check=True)
    return folder


@pytest.fixture
def fixture_prompts(tmp_path, monkeypatch):
    """Only test subprocesses use askpass, after checking the production env."""
    askpass = tmp_path / "test-askpass"
    askpass.write_text("#!/bin/sh\nprintf '%s\\n' fixture-only\n")
    askpass.chmod(0o700)
    original = subprocess.run

    def run(command, **kwargs):
        if command[0] == "ssh-keygen" and ("-y" in command or "-s" in command):
            assert kwargs["env"]["SSH_ASKPASS_REQUIRE"] == "never"
            assert "SSH_ASKPASS" not in kwargs["env"]
            kwargs["env"] = dict(kwargs["env"], SSH_ASKPASS_REQUIRE="force",
                                 SSH_ASKPASS=str(askpass), DISPLAY="fixture:0")
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.parametrize("target", ("docker", "docker-split", "kubernetes"))
def test_every_install_option_round_trips_without_private_key_directory(tmp_path, target):
    args = arguments(tmp_path, "--target", target, "--console-ssh-key", "/private/access",
                     "--kube-context", "chosen", "--kube-console-replicas", "2",
                     "--backup-root", "/private/backups", "--peer-tls", "disabled")
    args.roots_dir = tmp_path / "keys/public/roots"
    args.recovery_recipient = "age1" + "q" * 58
    args.accept_changes = True
    result = cli.parser().parse_args(setup.install_arguments(args))
    for name, value in vars(result).items():
        if name != "command":
            assert value == getattr(args, name)
    assert "key_directory" not in vars(result)


@pytest.mark.parametrize("location", ("relative", "source", "state", "images", "backups", "parent", "symlink"))
def test_private_keys_cannot_enter_deployment_or_served_folders(tmp_path, location):
    args = arguments(tmp_path, "--image-root", str(tmp_path / "images"),
                     "--backup-root", str(tmp_path / "backups"))
    args.key_directory = Path("relative") if location == "relative" else tmp_path / location
    if location == "parent":
        args.key_directory = tmp_path
    if location == "symlink":
        args.key_directory.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(InstallError):
        setup.choose_key_folder(args)


def test_folder_prompt_is_not_a_passphrase_prompt(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    args.key_directory = None
    monkeypatch.setattr("builtins.input", lambda prompt: "not-a-folder")
    with pytest.raises(InstallError, match="not a passphrase prompt"):
        setup.choose_key_folder(args)


@pytest.mark.skipif(not shutil.which("age-keygen"), reason="age required")
def test_keys_are_checked_reused_and_missing_private_material_is_never_replaced(keys, fixture_prompts):
    roots, recipient = setup.prepare_keys(keys)
    private = {name: (keys / name / name).read_bytes() for name in ("root-a", "root-b")}
    recovery = (keys / "recovery/recovery.age").read_bytes()
    assert setup.prepare_keys(keys) == (roots, recipient)
    assert (keys / "recovery/recovery.age").read_bytes() == recovery
    assert recipient.startswith("age1")
    for name, original in private.items():
        assert (keys / name / name).read_bytes() == original
        assert (keys / name / name).stat().st_mode & 0o777 == 0o600
    # Moving one key is not permission to create a replacement on a retry.
    (keys / "root-b/root-b").rename(keys / "moved-root-b")
    with pytest.raises(InstallError, match="moved or is missing"):
        setup.prepare_keys(keys)
    assert not (keys / "root-b/root-b").exists()


@pytest.mark.skipif(not shutil.which("age-keygen"), reason="age required")
def test_missing_recovery_identity_is_never_replaced(keys, fixture_prompts):
    setup.prepare_keys(keys)
    (keys / "recovery/recovery.age").rename(keys / "moved-recovery")
    with pytest.raises(InstallError, match="recovery key was moved"):
        setup.prepare_keys(keys)
    assert not (keys / "recovery/recovery.age").exists()


def signing_status(keys):
    public = key_setup.public_key((keys / "root-a/root-a.pub").read_bytes()).decode()
    return {"id": "fixture-id", "config": {"host": "192.0.2.10"},
            "request": public, "roots": {"root-a.pub": public}}


def test_local_approval_checks_actual_deployment_root_and_preserves_existing_outputs(keys, fixture_prompts, monkeypatch):
    status = signing_status(keys)
    monkeypatch.setattr(setup, "confirm", lambda prompt: True)
    first = setup.sign_request(status, keys)
    original = first.read_bytes()
    second = setup.sign_request(status, keys)
    assert first != second and first.read_bytes() == original
    info = subprocess.check_output(["ssh-keygen", "-L", "-f", str(first)])
    assert b"iris-server" in info
    status["roots"]["root-a.pub"] = "another root"
    before = set((keys / "approvals").iterdir())
    with pytest.raises(InstallError, match="does not match"):
        setup.sign_request(status, keys)
    assert set((keys / "approvals").iterdir()) == before


def test_cancelled_approval_creates_nothing(keys, fixture_prompts, monkeypatch):
    monkeypatch.setattr(setup, "confirm", lambda prompt: False)
    with pytest.raises(InstallError, match="paused"):
        setup.sign_request(signing_status(keys), keys)
    assert not (keys / "approvals").exists()


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(setup.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(setup, "confirm", lambda prompt: True)


def test_initial_setup_runs_install_then_explicit_approval_then_resume(tmp_path, terminal, monkeypatch, capsys):
    args = arguments(tmp_path)
    calls = []
    ready = {"present": True, "id": "same-id", "state": "WAITING_FOR_SIGNING_APPROVAL",
             "request": "fixture", "config": {"instance": "example", "console_bind": "192.0.2.10", "console_port": 8080}}
    states = iter([{"present": False}, ready, ready])

    def controller(command, capture=False):
        calls.append(command)
        return next(states) if capture else (20 if command[0] == "install" else 21)

    monkeypatch.setattr(setup, "controller", controller)
    monkeypatch.setattr(setup, "choose_key_folder", lambda args: tmp_path / "keys")
    monkeypatch.setattr(setup, "prepare_keys", lambda folder: (folder / "public/roots", "age1fixture"))
    monkeypatch.setattr(setup, "sign_request", lambda status, folder: tmp_path / "approval.pub")
    assert setup.run_setup(args) == 0
    assert [call[0] for call in calls] == ["setup-status", "install", "setup-status", "resume", "setup-status"]
    assert "--certificate" in calls[3]
    assert "--key-directory" not in calls[1]
    assert "No account was created or signed in" in capsys.readouterr().out


@pytest.mark.parametrize("result", (0, 21, 22, 1))
def test_existing_installation_never_recreates_keys_or_overrides_config(tmp_path, terminal, monkeypatch, result):
    args = arguments(tmp_path)
    calls = []
    status = {"present": True, "id": "same-id", "config": {"instance": "recorded", "console_bind": "192.0.2.11", "console_port": 8445}}

    def controller(command, capture=False):
        calls.append(command)
        return status if capture else result

    monkeypatch.setattr(setup, "controller", controller)
    monkeypatch.setattr(setup, "prepare_keys", lambda *a: pytest.fail("must not create keys"))
    monkeypatch.setattr(setup, "choose_key_folder", lambda *a: pytest.fail("keys not needed"))
    if result == 1:
        with pytest.raises(InstallError, match="stopped with code 1"):
            setup.run_setup(args)
    else:
        assert setup.run_setup(args) == 0
    assert calls[1] == ["resume", "--state-dir", str(args.state_dir)]
    assert args.instance == "recorded"


def test_local_setup_requires_terminal_nonroot_and_explicit_consent(tmp_path, terminal, monkeypatch):
    args = arguments(tmp_path)
    monkeypatch.setattr(setup, "controller", lambda *a, **k: pytest.fail("no host action"))
    monkeypatch.setattr(setup, "confirm", lambda prompt: False)
    assert setup.run_setup(args) == 0
    monkeypatch.setattr(setup.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(InstallError, match="interactive terminal"):
        setup.run_setup(args)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    with pytest.raises(InstallError, match="without sudo"):
        setup.run_setup(args)


def test_controller_uses_matching_executable_and_no_shell(monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kw:
                        (seen.append((command, kw)) or SimpleNamespace(returncode=0, stdout=b'{"present":false}')))
    assert setup.controller(["setup-status", "--state-dir", "/private/state"], capture=True) == {"present": False}
    command, options = seen[0]
    assert command[:2] == ["sudo", str(REPO / "tools/irisctl")]
    assert "shell" not in options


@pytest.mark.parametrize("payload", (b"null", b"[]", b'{"present":1}', b'{"present":true}', b"not json"))
def test_controller_rejects_incompatible_status_without_proceeding(monkeypatch, payload):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=payload))
    with pytest.raises(InstallError, match="Invalid setup status"):
        setup.controller(["setup-status"], capture=True)


def test_setup_status_cli_handles_privilege_failure(monkeypatch, capsys):
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    assert cli.main(["setup-status", "--state-dir", "/unneeded"]) == 1
    assert "with sudo" in capsys.readouterr().out


@pytest.mark.skipif(os.geteuid() != 0, reason="private root-owned journal")
def test_public_status_allowlists_data_and_binds_public_roots(tmp_path, keys):
    assert setup.public_status(tmp_path / "absent") == {"present": False}
    state = tmp_path / "state"
    with Journal(state).locked(create=True) as journal:
        (state / "roots").mkdir()
        roots = {}
        for name in ("root-a", "root-b"):
            data = (keys / name / (name + ".pub")).read_bytes()
            (state / "roots" / (name + ".pub")).write_bytes(data)
            roots[name + ".pub"] = hashlib.sha256(data).hexdigest()
        (state / "requests").mkdir()
        (state / "requests/online.pub").write_bytes((keys / "root-a/root-a.pub").read_bytes())
        journal.document = {"schema": 1, "id": "fixture-id", "state": "WAITING_FOR_SIGNING_APPROVAL",
                            "completed": {"never-export": "PRIVATE"}, "root_digests": roots,
                            "config": {"target": "docker", "instance": "iris", "host": "192.0.2.10",
                                       "console_bind": "127.0.0.1", "console_port": 8080,
                                       "peer_tls": "required", "recovery_recipient": "age1" + "q" * 58}}
        journal.save()
    result = setup.public_status(state)
    assert set(result) == {"present", "id", "state", "config", "input_selection", "roots", "request"}
    assert "PRIVATE" not in json.dumps(result)
    assert "recovery_recipient" not in result["config"]
    assert len(result["request"].split()) == 2
    (state / "roots/root-a.pub").write_bytes((state / "roots/root-a.pub").read_bytes() + b"\n")
    with pytest.raises(InstallError, match="roots changed"):
        setup.public_status(state)
