# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Offline desktop boundaries and real OpenSSH approval interoperability."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import cli, custody_gui as gui
from iris_installer.state import InstallError


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "root"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
    return path


def test_inspection_is_public_and_bound_to_exact_bytes(root):
    data, summary = gui.inspect_request("signing", str(root) + ".pub")
    assert hashlib.sha256(data).hexdigest() in summary
    assert "30 days" in summary
    with pytest.raises(InstallError, match="public key"):
        gui.inspect_request("signing", root)
    with pytest.raises(InstallError, match="Unknown"):
        gui.inspect_request("other", root)


def test_keylist_preview_uses_shared_protocol(tmp_path, root):
    krl = tmp_path / "revoked.krl"
    subprocess.run(["ssh-keygen", "-q", "-k", "-f", str(krl), str(root) + ".pub"], check=True)
    keys = gui.instruction_module()
    payload = keys.build_keylist_payload(krl.read_bytes(), keylist_seq=12, issued_at=1800000000,
                                         signer_root_id="root-a")
    request = tmp_path / "keylist.payload"
    request.write_bytes(payload)
    data, summary = gui.inspect_request("keylist", request)
    assert data == payload
    assert "sequence: 12" in summary and "root-a" in summary
    assert hashlib.sha256(krl.read_bytes()).hexdigest() in summary
    request.write_bytes(b"garbage")
    with pytest.raises(InstallError, match="retirement"):
        gui.inspect_request("keylist", request)


def test_approval_signs_reviewed_snapshot_not_changed_original(tmp_path, root, monkeypatch):
    request = Path(str(root) + ".pub")
    public, _ = gui.inspect_request("signing", request)
    request.write_bytes(b"changed after review")
    recorded = []

    def run(command, *, env):
        snapshot = Path(command[command.index("--public-key") + 1])
        recorded.append(snapshot.read_bytes())
        assert snapshot.parent.stat().st_mode & 0o777 == 0o700
        assert "approve-signing" in command
        assert env["SSH_ASKPASS_REQUIRE"] == "force"

    monkeypatch.setattr(gui, "run_local", run)
    gui.approve_public("signing", public, root, tmp_path / "approved.pub")
    assert recorded == [public]


def test_environment_cannot_supply_another_askpass_or_passphrase(monkeypatch):
    monkeypatch.setenv("SSH_ASKPASS", "/bad/program")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/bad/agent")
    monkeypatch.setenv("PASSPHRASE", "test-only-not-forwarded")
    env = gui.signing_environment()
    assert env["SSH_ASKPASS"] == str(REPO / "tools/iris-custody-askpass")
    assert "PASSPHRASE" not in env and "SSH_AUTH_SOCK" not in env


def test_run_local_redacts_diagnostics():
    with pytest.raises(InstallError) as error:
        gui.run_local(["/bin/sh", "-c", "echo private-test-marker >&2; exit 1"], env={})
    assert "private-test-marker" not in str(error.value)


def test_run_local_timeout_kills_entire_signing_session(monkeypatch):
    calls = []

    class Process:
        pid = 12345

        def communicate(self, **kwargs):
            if kwargs:
                raise subprocess.TimeoutExpired("test", 600)
            calls.append("reaped")

    monkeypatch.setattr(gui.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(gui.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    with pytest.raises(InstallError, match="timed out"):
        gui.run_local(["ssh-keygen"], env={})
    assert calls == [(12345, gui.signal.SIGKILL), "reaped"]


def test_root_generation_refuses_existing_directory_and_invalid_name(tmp_path):
    (tmp_path / "iris-root-a").mkdir()
    with pytest.raises(InstallError, match="already exists"):
        gui.generate_root(tmp_path, "root-a")
    with pytest.raises(InstallError, match="Choose root"):
        gui.generate_root(tmp_path, "../escape")


def test_actual_approval_with_encrypted_root_and_no_terminal(tmp_path, root, monkeypatch):
    encrypted = tmp_path / "encrypted-root"
    # Disposable test key only. Real passphrases use the askpass pipe.
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "fixture-only", "-f", str(encrypted)], check=True)
    helper = tmp_path / "askpass"
    helper.write_text("#!/bin/sh\nprintf '%s\\n' fixture-only\n")
    helper.chmod(0o700)
    monkeypatch.setattr(gui, "signing_environment", lambda: {
        "PATH": "/usr/bin:/bin", "SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force"})
    public, _ = gui.inspect_request("signing", str(root) + ".pub")
    output = tmp_path / "approved.pub"
    gui.approve_public("signing", public, encrypted, output)
    result = subprocess.run(["ssh-keygen", "-L", "-f", str(output)], capture_output=True, text=True, check=True)
    assert "iris-server" in result.stdout
    assert "ssh-ed25519-cert-v01@openssh.com" in result.stdout
    with pytest.raises(InstallError, match="Operation stopped"):
        gui.approve_public("signing", public, encrypted, output)


def test_cancelled_passphrase_publishes_nothing(tmp_path, root, monkeypatch):
    encrypted = tmp_path / "encrypted-root"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "fixture-only", "-f", str(encrypted)], check=True)
    monkeypatch.setattr(gui, "signing_environment", lambda: {
        "PATH": "/usr/bin:/bin", "SSH_ASKPASS": "/bin/false", "SSH_ASKPASS_REQUIRE": "force"})
    public, _ = gui.inspect_request("signing", str(root) + ".pub")
    output = tmp_path / "cancelled.pub"
    with pytest.raises(InstallError, match="Operation stopped"):
        gui.approve_public("signing", public, encrypted, output)
    assert not output.exists()


def test_actual_keylist_approval_verifies_with_server_protocol(tmp_path, root):
    krl = tmp_path / "revoked.krl"
    subprocess.run(["ssh-keygen", "-q", "-k", "-f", str(krl), str(root) + ".pub"], check=True)
    keys = gui.instruction_module()
    payload = keys.build_keylist_payload(krl.read_bytes(), keylist_seq=4, issued_at=1800000000,
                                         signer_root_id="root-a")
    output = tmp_path / "approval.envelope"
    gui.approve_public("keylist", payload, root, output)
    parsed = keys.parse_keylist_artifact(output.read_bytes())
    assert parsed["payload"] == payload
    assert keys._verify_keylist(parsed, {"root-a": Path(str(root) + ".pub").read_bytes()},
                                previous_krl=None, timeout=10, ssh_keygen="ssh-keygen") == "root-a"


def test_actual_root_generation_is_encrypted(tmp_path, monkeypatch):
    helper = tmp_path / "askpass"
    helper.write_text("#!/bin/sh\nprintf '%s\\n' fixture-only\n")
    helper.chmod(0o700)
    monkeypatch.setattr(gui, "signing_environment", lambda: {
        "PATH": "/usr/bin:/bin", "SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force"})
    result = gui.generate_root(tmp_path, "root-b")
    directory = tmp_path / "iris-root-b"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "root-b").stat().st_mode & 0o777 == 0o600
    assert "Transfer only:" in result and "root-b.pub" in result and "SHA256:" in result


def test_recovery_generation_keeps_private_bytes_out_of_result(tmp_path):
    result = gui.generate_recovery_identity(tmp_path)
    directory = tmp_path / "iris-recovery"
    identity = directory / "recovery.age"
    assert identity.stat().st_mode & 0o777 == 0o600
    assert "AGE-SECRET-KEY" not in result
    public = subprocess.check_output(["age-keygen", "-y", str(identity)]).decode().strip()
    assert public in result
    assert (directory / "recovery-recipient.pub").read_text().strip() == public
    with pytest.raises(InstallError, match="already exists"):
        gui.generate_recovery_identity(tmp_path)


def test_askpass_cancellation_empty_and_secret_pipe(monkeypatch, capsys):
    answers = iter(("", "fixture-passphrase"))
    errors = []
    destroyed = []
    window = SimpleNamespace(withdraw=lambda: None, destroy=lambda: destroyed.append(True))
    fake = SimpleNamespace(Tk=lambda: window, TclError=RuntimeError,
                           simpledialog=SimpleNamespace(askstring=lambda *a, **k: next(answers)),
                           messagebox=SimpleNamespace(showerror=lambda *a, **k: errors.append(a)))
    monkeypatch.setitem(sys.modules, "tkinter", fake)
    assert gui.askpass() == 0
    assert capsys.readouterr().out == "fixture-passphrase\n"
    assert len(errors) == 1 and destroyed == [True]
    fake.simpledialog.askstring = lambda *a, **k: None
    assert gui.askpass() == 1
    assert capsys.readouterr().out == ""


def test_cli_dispatches_desktop_without_installation(monkeypatch):
    monkeypatch.setattr(gui, "main", lambda: 42)
    assert cli.main(["custody-ui"]) == 42


def test_desktop_refuses_sudo(monkeypatch):
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    with pytest.raises(InstallError, match="without sudo"):
        gui.main()


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="local display or Xvfb required")
def test_actual_window_validation_and_worker_completion(monkeypatch):
    import tkinter as tk
    window = tk.Tk()
    try:
        app = gui.CustodyWindow(window)
        window.update()
        assert window.title() == "IRIS · Offline signing"
        window.geometry("620x500")
        window.update()
        assert int(app.status_label.cget("wraplength")) <= 572
        app.review()
        assert "Choose the request" in app.status.get()
        app.start(lambda: "Public approval saved: test.pub")
        assert app.busy
        assert "disabled" in app.approve_button.state()
        # Joining is unnecessary: Queue.get waits for exactly the one local job.
        success, result = app.events.get(timeout=5)
        app.events.put((success, result))
        app.poll()
        assert not app.busy
        assert "disabled" not in app.approve_button.state()
        assert app.status.get() == "Public approval saved: test.pub"
    finally:
        window.destroy()
