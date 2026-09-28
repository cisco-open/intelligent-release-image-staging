# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local recovery window: fixed requests, pinned socket and explicit recovery."""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import cli, maintenance_gui as gui
from iris_installer.state import InstallError


def job(**updates):
    return dict({"id": str(uuid.uuid4()), "action": "rotate", "family": "age-identity",
                 "state": "recovery-required", "proof": None}, **updates)


@pytest.mark.parametrize("updates", [{"action": "backup"}, {"state": "completed"},
    {"state": "running"}, {"family": "shell"}, {"id": "../other"}])
def test_recovery_requires_exact_interrupted_operation(updates):
    with pytest.raises(InstallError, match="interrupted rotation"):
        gui.recovery_request(job(**updates))


def test_recovery_reuses_original_identity():
    original = job()
    assert gui.recovery_request(original) == {"action": "recover-rotation", "request_id": original["id"],
                                             "family": "age-identity", "allow_downtime": True}


@pytest.fixture
def client(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "control").mkdir(mode=0o750)
    return gui.MaintenanceClient(state)


@pytest.mark.parametrize("payload", [{"action": "exec"}, {"action": "status", "path": "/other"},
    {"action": "rotate", "request_id": "a" * 36, "family": "age-identity", "allow_downtime": True},
    {"action": "recover-rotation", "request_id": "a" * 36, "family": "age-identity", "allow_downtime": 1},
    {"action": "recover-rotation", "request_id": "a" * 36, "family": "age-identity", "allow_downtime": False}])
def test_client_refuses_commands_and_unconfirmed_mutation(client, payload):
    with pytest.raises(InstallError, match="Unsupported"):
        client.call(payload)


def test_client_rejects_symlink_control_and_non_socket_endpoint(client, tmp_path):
    endpoint = client.state_dir / "control/control.sock"
    endpoint.write_text("not a socket")
    with pytest.raises(InstallError, match="Unsafe lifecycle endpoint"):
        client.call({"action": "status"})
    endpoint.unlink()
    endpoint.symlink_to(tmp_path / "untrusted")
    with pytest.raises(InstallError, match="Unsafe lifecycle endpoint"):
        client.call({"action": "status"})


def real_response(client, response, request):
    endpoint = client.state_dir / "control/control.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    listener.listen(1)
    received = []

    def serve():
        with listener.accept()[0] as connection:
            received.append(json.loads(connection.makefile("rb").readline()))
            connection.sendall(response)

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        return client.call(request), received
    finally:
        worker.join(5)
        listener.close()


def test_real_unix_rpc_is_bound_to_local_state_and_original_job(client, monkeypatch):
    monkeypatch.setenv("IRIS_LIFECYCLE_SOCKET", "/unrelated/endpoint")
    request = gui.recovery_request(job())
    result, received = real_response(client, b'{"ok":true,"result":{"job_id":"accepted"}}\n', request)
    assert received == [request]
    assert result == {"job_id": "accepted"}


@pytest.mark.parametrize("response", [b"not json\n", b'{"ok":1}\n', b'{"ok":true,"result":[]}\n',
    b'{"ok":false,"error":"PRIVATE TEST MARKER"}\n', b"x" * (128 * 1024 + 1) + b"\n"])
def test_rpc_refuses_malformed_and_redacts_worker_error(client, response):
    with pytest.raises(InstallError) as error:
        real_response(client, response, {"action": "status"})
    assert "PRIVATE TEST MARKER" not in str(error.value)


def test_non_owner_peer_is_rejected_before_sending(client, monkeypatch):
    endpoint = client.state_dir / "control/control.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))

        class Impostor:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, value): pass
            def connect(self, path): pass
            def getsockopt(self, *args): return struct.pack("3i", 123, os.geteuid() + 1, 0)
            def sendall(self, value): pytest.fail("must reject before sending")

        monkeypatch.setattr(gui.socket, "socket", lambda *args: Impostor())
        with pytest.raises(InstallError, match="another account"):
            client.call({"action": "status"})


def test_main_requires_root_before_opening_files(monkeypatch):
    monkeypatch.setattr(gui.os, "geteuid", lambda: 1000)
    with pytest.raises(InstallError, match="as root"):
        gui.main(SimpleNamespace(state_dir=Path("/should/not/read")))


def test_cli_dispatches_recovery_ui_with_explicit_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gui, "main", lambda args: 7 if args.state_dir == tmp_path else 8)
    assert cli.main(["maintenance-ui", "--state-dir", str(tmp_path)]) == 7


@pytest.fixture
def recovery_candidate(client, tmp_path, monkeypatch):
    identity = tmp_path / "recovery.age"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    identity.chmod(0o600)
    (client.state_dir / "installation.json").write_text(json.dumps({"schema": 1, "id": "test-instance", "config": {
        "recovery_recipient": "age1" + "q" * 58}, "completed": {}}))
    monkeypatch.setattr(client, "call", lambda payload: {"can_rotate": True, "families": ["age-recovery"]})
    monkeypatch.setattr(client, "snapshot", lambda: [])
    return identity, gui.recovery_identity(identity)[1]


def test_recipient_candidate_retains_same_id_and_never_sends_private_path(client, recovery_candidate):
    identity, recipient = recovery_candidate
    request = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    assert request["family"] == "age-recovery" and request["action"] == "rotate"
    assert set(request) == {"action", "request_id", "family", "allow_downtime"}
    target = client.state_dir / "recovery-candidate.json"
    saved = json.loads(target.read_text())
    imported = client.state_dir / "host-recovery-identities" / (request["request_id"] + ".age")
    assert saved == {"operation_id": request["request_id"], "identity_path": str(imported), "recipient": recipient}
    assert imported.read_bytes() == identity.read_bytes()
    assert imported.stat().st_mode & 0o777 == 0o600
    assert imported.parent.stat().st_mode & 0o777 == 0o700
    assert target.stat().st_mode & 0o777 == 0o600
    assert "AGE-SECRET-KEY" not in target.read_text()
    assert gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True) == request


def test_recipient_requires_ack_and_matching_review(client, recovery_candidate):
    identity, recipient = recovery_candidate
    with pytest.raises(InstallError, match="Confirm independent"):
        gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=False)
    with pytest.raises(InstallError, match="changed after review"):
        gui.prepare_recovery_candidate(client, identity, "another", independent_copy=True)


@pytest.mark.parametrize("intent", [False, True])
def test_failed_recipient_preflight_gets_new_id_only_without_durable_intent(client, recovery_candidate, monkeypatch, intent):
    identity, recipient = recovery_candidate
    first = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    monkeypatch.setattr(client, "snapshot", lambda: [job(id=first["request_id"], family="age-recovery", state="failed")])
    if intent:
        directory = client.state_dir / "credential-operations" / first["request_id"]
        directory.mkdir(parents=True)
        (directory / "record.json").write_text("{}")
    second = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    assert (second["request_id"] == first["request_id"]) is intent


@pytest.mark.parametrize("changes", [{}, {"phase": "preflight-refused"}, {"mutations_admitted": True},
    {"mutations_admitted": 0}, {"operation_id": "different"}, {"kind": "management-tls"},
    {"instance_id": "different"}, {"initial_clean_stop": False}])
def test_verified_terminal_refusal_allows_fresh_candidate_only_for_matching_authority(client, recovery_candidate, monkeypatch, changes):
    from iris_installer.state import atomic_write
    identity, recipient = recovery_candidate
    first = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    monkeypatch.setattr(client, "snapshot", lambda: [job(id=first["request_id"], family="age-recovery", state="failed")])
    directory = client.state_dir / "credential-operations" / first["request_id"]
    directory.mkdir(parents=True)
    record = {"schema": 1, "operation_id": first["request_id"], "kind": "age-recovery",
              "instance_id": "test-instance", "phase": "refused", "mutations_admitted": False,
              "initial_clean_stop": True, **changes}
    atomic_write(directory / "record.json", json.dumps(record).encode())
    second = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    assert (second["request_id"] != first["request_id"]) is (not changes)


def test_recipient_rejects_running_job_and_pending_candidate_replacement(client, recovery_candidate, monkeypatch, tmp_path):
    identity, recipient = recovery_candidate
    first = gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    monkeypatch.setattr(client, "snapshot", lambda: [job(state="running")])
    with pytest.raises(InstallError, match="existing operation"):
        gui.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    monkeypatch.setattr(client, "snapshot", lambda: [])
    other = tmp_path / "other.age"
    subprocess.run(["age-keygen", "-o", str(other)], check=True, capture_output=True)
    other.chmod(0o600)
    other_recipient = gui.recovery_identity(other)[1]
    with pytest.raises(InstallError, match="different recovery candidate"):
        gui.prepare_recovery_candidate(client, other, other_recipient, independent_copy=True)
    assert json.loads((client.state_dir / "recovery-candidate.json").read_text())["operation_id"] == first["request_id"]
    monkeypatch.setattr(client, "snapshot", lambda: [job(id=first["request_id"], state="rotated")])
    second = gui.prepare_recovery_candidate(client, other, other_recipient, independent_copy=True)
    assert second["request_id"] != first["request_id"]


def test_recipient_refuses_unsafe_identity_permissions_and_symlinks(client, recovery_candidate, tmp_path):
    identity, _recipient = recovery_candidate
    identity.chmod(0o644)
    with pytest.raises(InstallError, match="0600"):
        gui.recovery_identity(identity)
    alias = tmp_path / "alias"
    alias.symlink_to(identity)
    with pytest.raises(InstallError, match="symbolic"):
        gui.recovery_identity(alias)


def test_desktop_owner_is_only_accepted_from_root_sudo_context(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "4321")
    monkeypatch.setattr(gui.os, "geteuid", lambda: 1000)
    assert gui._identity_source_uids() == {1000}
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    assert gui._identity_source_uids() == {0, 4321}
    monkeypatch.setenv("SUDO_UID", "../invalid")
    assert gui._identity_source_uids() == {0}


def test_identity_size_checked_before_starting_key_reader(tmp_path, monkeypatch):
    path = tmp_path / "oversized.age"
    path.write_bytes(b"x" * 8193)
    path.chmod(0o600)
    monkeypatch.setattr(gui.subprocess, "run", lambda *a, **k: pytest.fail("must reject before spawning"))
    with pytest.raises(InstallError, match="size limit"):
        gui.recovery_identity(path, allow_desktop_owner=True)


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="local display or Xvfb required")
def test_real_window_recovery_requires_confirmation(client, monkeypatch):
    import tkinter as tk
    from tkinter import messagebox
    original = job()
    calls = []
    monkeypatch.setattr(client, "snapshot", lambda: [original])
    monkeypatch.setattr(client, "call", lambda request: calls.append(request) or {"job_id": original["id"]})
    window = tk.Tk()
    try:
        app = gui.MaintenanceWindow(window, client)
        app.events.put(app.events.get(timeout=3))
        app.poll()
        app.tree.selection_set("0")
        app.select()
        assert "disabled" not in app.recover_button.state()
        monkeypatch.setattr(messagebox, "askokcancel", lambda *a, **k: False)
        app.recover()
        assert calls == []
        monkeypatch.setattr(messagebox, "askokcancel", lambda *a, **k: True)
        app.recover()
        app.events.put(app.events.get(timeout=3))
        app.poll()
        assert calls == [gui.recovery_request(original)]
        assert "Completion requires" in app.status.get()
    finally:
        window.destroy()
