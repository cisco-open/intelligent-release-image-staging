# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Headless key helper: protected storage, reviewed bytes and public transfers."""

import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import key_setup as helper
from iris_installer.state import InstallError


@pytest.fixture
def root(tmp_path):
    key = tmp_path / "root-a"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "fixture-only", "-f", str(key)], check=True)
    return key


def test_encrypted_root_and_blank_passphrase_refusal(root, tmp_path):
    helper.protected_root(root)
    plain = tmp_path / "plain"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(plain)], check=True)
    with pytest.raises(InstallError, match="passphrase"):
        helper.protected_root(plain)
    with pytest.raises(InstallError, match="passphrase"):
        helper.approve("signing", Path(str(root) + ".pub"), plain, tmp_path / "never-signed")
    malformed = tmp_path / "malformed"
    malformed.write_bytes(b"not an OpenSSH key")
    malformed.chmod(0o600)
    with pytest.raises(InstallError, match="supported OpenSSH"):
        helper.protected_root(malformed)
    root.chmod(0o644)
    with pytest.raises(InstallError, match="0600"):
        helper.protected_root(root)


def test_root_resume_never_generates_or_overwrites(root, monkeypatch):
    root.parent.chmod(0o700)
    original = root.read_bytes()
    public = Path(str(root) + ".pub").read_bytes()
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert "-t" not in command
        return public if "-y" in command else None

    monkeypatch.setattr(helper, "run", run)
    assert helper.create_root("root-a", root.parent) == Path(str(root) + ".pub")
    assert root.read_bytes() == original
    assert len(calls) == 2
    (root.parent / "root-b.pub").write_bytes(public)
    with pytest.raises(InstallError, match="other signing"):
        helper.create_root("root-a", root.parent)


def test_private_storage_and_output_symlinks_refused(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o755)
    with pytest.raises(InstallError, match="0700"):
        helper.private_directory(private)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(InstallError, match="symbolic"):
        helper.private_directory(alias)
    output = tmp_path / "output"
    target = tmp_path / "target"
    target.write_bytes(b"same")
    output.symlink_to(target)
    with pytest.raises(OSError):
        helper.publish(output, b"same")


def test_publish_is_idempotent_but_never_replaces(tmp_path):
    output = tmp_path / "public"
    helper.publish(output, b"one")
    helper.publish(output, b"one")
    with pytest.raises(InstallError, match="different file"):
        helper.publish(output, b"two")
    assert output.read_bytes() == b"one"


@pytest.mark.skipif(not shutil.which("age-keygen"), reason="age required")
def test_recovery_is_resumable_private_and_independent(tmp_path, capsys):
    directory = tmp_path / "recovery"
    result = helper.create_recovery(directory)
    private = (directory / "recovery.age").read_bytes()
    assert (directory / "recovery.age").stat().st_mode & 0o777 == 0o600
    assert helper.create_recovery(directory) == result
    assert (directory / "recovery.age").read_bytes() == private
    assert "AGE-SECRET-" not in capsys.readouterr().out
    assert result.read_bytes().startswith(b"age1")


def test_approval_signs_exact_reviewed_snapshot(root, tmp_path, monkeypatch):
    request = Path(str(root) + ".pub")
    reviewed = request.read_bytes()

    def confirm(prompt):
        request.write_bytes(b"changed after review")
        return hashlib.sha256(reviewed).hexdigest()

    signed = []
    monkeypatch.setattr("builtins.input", confirm)
    monkeypatch.setattr(helper.custody, "approve", lambda args: signed.append(args.public_key.read_bytes()))
    helper.approve("signing", request, root, tmp_path / "approved.pub")
    assert signed == [reviewed]


def test_hash_mismatch_and_cancel_never_sign(root, tmp_path, monkeypatch):
    request = Path(str(root) + ".pub")
    monkeypatch.setattr("builtins.input", lambda prompt: "wrong")
    monkeypatch.setattr(helper.custody, "approve", lambda args: pytest.fail("must not sign"))
    with pytest.raises(InstallError, match="Hashes"):
        helper.approve("signing", request, root, tmp_path / "approved.pub")
    monkeypatch.setattr("builtins.input", lambda prompt: (_ for _ in ()).throw(EOFError()))
    monkeypatch.setattr(helper, "holder_machine", lambda: None)
    assert helper.main(["approve"]) == 1
    assert not (tmp_path / "approved.pub").exists()


def test_actual_certificate_and_keylist_interoperate(root, tmp_path, monkeypatch):
    # Only test fixtures use askpass. Real helper uses OpenSSH terminal prompts.
    askpass = tmp_path / "askpass"
    askpass.write_text("#!/bin/sh\nprintf '%s\\n' fixture-only\n")
    askpass.chmod(0o700)
    real_run = subprocess.run

    def fixture_run(command, **kwargs):
        if ("-s" in command and "-Y" not in command) or "sign" in command:
            assert kwargs["env"]["SSH_ASKPASS_REQUIRE"] == "never"
            assert "SSH_ASKPASS" not in kwargs["env"]
            assert "SSH_AUTH_SOCK" not in kwargs["env"]
            kwargs["env"] = dict(kwargs["env"], SSH_ASKPASS=str(askpass),
                                 SSH_ASKPASS_REQUIRE="force", DISPLAY="fixture:0")
        return real_run(command, **kwargs)

    monkeypatch.setattr(helper.custody.subprocess, "run", fixture_run)
    request = Path(str(root) + ".pub")
    monkeypatch.setattr("builtins.input", lambda prompt: hashlib.sha256(request.read_bytes()).hexdigest())
    output = tmp_path / "approved.pub"
    helper.approve("signing", request, root, output)
    cert = subprocess.check_output(["ssh-keygen", "-L", "-f", str(output)])
    assert b"iris-server" in cert
    assert helper.public_data(output).startswith(b"ssh-ed25519-cert")
    with pytest.raises(InstallError, match="already exists"):
        helper.approve("signing", request, root, output)
    krl = tmp_path / "revoked.krl"
    subprocess.run(["ssh-keygen", "-q", "-k", "-f", str(krl), str(root) + ".pub"], check=True)
    keys = helper.instruction_module()
    request = tmp_path / "keylist.payload"
    request.write_bytes(keys.build_keylist_payload(krl.read_bytes(), keylist_seq=4, issued_at=1800000000,
                                                   signer_root_id="root-a"))
    output = tmp_path / "approved.keylist"
    helper.approve("keylist", request, root, output)
    parsed = keys.parse_keylist_artifact(output.read_bytes())
    assert parsed["payload"] == request.read_bytes()
    assert keys._verify_keylist(parsed, {"root-a": Path(str(root) + ".pub").read_bytes()},
                               previous_krl=None, timeout=10, ssh_keygen="ssh-keygen") == "root-a"
    assert helper.public_data(output) == output.read_bytes()
    request.write_bytes(b"invalid")
    with pytest.raises(InstallError, match="retirement"):
        helper.approve("keylist", request, root, tmp_path / "bad")


def test_export_refuses_private_and_strips_comments(root, tmp_path):
    transfer = tmp_path / "transfer"
    transfer.mkdir()
    with pytest.raises(InstallError, match="Private"):
        helper.export_public(root, transfer)
    public = Path(str(root) + ".pub")
    result = helper.export_public(public, transfer)
    assert len(result.read_bytes().split()) == 2
    assert helper.export_public(public, transfer) == result


def test_ssh_arguments_are_pinned_and_injection_refused():
    command = helper.ssh_command("test@server.example", "print('ok')")
    assert "StrictHostKeyChecking=yes" in command
    assert "ForwardAgent=no" in command and "ClearAllForwardings=yes" in command
    for host in ("-oProxyCommand=bad", "test@host;id", "host", "user@$(id)"):
        with pytest.raises(InstallError):
            helper.ssh_command(host, "pass")
    for path in ("relative", "/tmp/a b", "/tmp/../secret", "/tmp/x;id"):
        with pytest.raises(InstallError):
            helper.remote_path(path)


def test_send_validates_before_starting_ssh(root, monkeypatch):
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **kw: pytest.fail("no SSH for private files"))
    with pytest.raises(InstallError, match="Private"):
        helper.send_public(root, "test@server", "/tmp/public")


def test_fetch_remote_filter_and_send_exclusive_write(root, tmp_path, monkeypatch):
    real_run = subprocess.run

    def local_ssh(command, **kwargs):
        assert command[0] == "ssh"
        return real_run(shlex.split(command[-1]), **kwargs)

    monkeypatch.setattr(helper.subprocess, "run", local_ssh)
    destination = tmp_path / "uploaded.pub"
    helper.send_public(Path(str(root) + ".pub"), "test@server", str(destination))
    with pytest.raises(InstallError, match="upload stopped"):
        helper.send_public(Path(str(root) + ".pub"), "test@server", str(destination))
    fetched = tmp_path / "fetched.pub"
    helper.fetch_request("test@server", str(destination), fetched)
    assert fetched.read_bytes() == destination.read_bytes()
    with pytest.raises(InstallError):
        helper.fetch_request("test@server", str(root), tmp_path / "never-written")
    assert not (tmp_path / "never-written").exists()


def test_command_environment_uses_terminal_not_askpass(monkeypatch):
    monkeypatch.setenv("SSH_ASKPASS", "/bad/program")
    monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
    seen = []
    monkeypatch.setattr(helper.subprocess, "run", lambda command, **kw: (seen.append(kw) or SimpleNamespace(returncode=0, stdout=b"ok")))
    assert helper.run(["ssh-keygen"], capture=True) == b"ok"
    assert "SSH_ASKPASS" not in seen[0]["env"]
    assert seen[0]["env"]["SSH_ASKPASS_REQUIRE"] == "never"


def test_menu_selects_retirement_without_extra_command(monkeypatch, tmp_path):
    answers = iter(("3", "2", "request", "root", "output", ""))
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr(helper, "holder_machine", lambda: None)
    captured = []
    monkeypatch.setattr(helper, "approve", lambda *args: (captured.append(args) or tmp_path / "output"))
    assert helper.main([]) == 0
    assert captured[0][0] == "keylist"


def test_cancelled_signing_creates_no_public_approval(root, tmp_path, monkeypatch):
    request = Path(str(root) + ".pub")
    monkeypatch.setattr("builtins.input", lambda prompt: hashlib.sha256(request.read_bytes()).hexdigest())
    monkeypatch.setattr(helper.custody.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1))
    output = tmp_path / "cancelled.pub"
    with pytest.raises(InstallError, match="signing failed"):
        helper.approve("signing", request, root, output)
    assert not output.exists()
