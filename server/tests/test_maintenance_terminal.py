# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Terminal recovery: fixed requests, pinned socket and explicit confirmation."""

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
from iris_installer import cli, maintenance as gui
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


def test_cli_dispatches_maintenance_with_explicit_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gui, "main", lambda args: 7 if args.state_dir == tmp_path else 8)
    assert cli.main(["maintenance", "--state-dir", str(tmp_path)]) == 7


def arguments(tmp_path, *options):
    return cli.parser().parse_args(["maintenance", "--state-dir", str(tmp_path), *options])


@pytest.fixture
def terminal_client(client, monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui, "MaintenanceClient", lambda _path: client)
    monkeypatch.setattr(client, "snapshot", lambda: [])
    return client


def test_status_is_headless_and_read_only(terminal_client, tmp_path, monkeypatch, capsys):
    original = job()
    monkeypatch.setattr(terminal_client, "snapshot", lambda: [original])
    monkeypatch.setattr(terminal_client, "call", lambda *_: pytest.fail("status mutated worker"))
    assert gui.main(arguments(tmp_path)) == 0
    assert json.loads(capsys.readouterr().out.split("\n", 1)[1])["jobs"] == [original]


@pytest.mark.parametrize("options", [
    ["recover"], ["recover", "--job-id", "../other", "--allow-downtime"],
    ["restore", "--job-id", str(uuid.uuid4())],
    ["replace-recovery", "--identity", "/no/read", "--allow-downtime"],
    ["configure-recovery", "--identity", "/no/read"],
    ["trust-signer"], ["status", "--identity", "/no/read"], ["status", "--yes"],
    ["disable-recovery", "--allow-downtime"],
])
def test_invalid_arguments_have_no_side_effects(tmp_path, monkeypatch, options):
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui, "MaintenanceClient", lambda *_: pytest.fail("opened state"))
    monkeypatch.setattr(gui, "_confirm", lambda *_: pytest.fail("asked for invalid operation"))
    with pytest.raises(InstallError):
        gui.main(arguments(tmp_path, *options))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("answer", ["no", "yes", ""])
def test_refused_confirmation_never_opens_state(tmp_path, monkeypatch, answer):
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: answer)
    monkeypatch.setattr(gui, "MaintenanceClient", lambda *_: pytest.fail("opened state"))
    with pytest.raises(InstallError, match="No changes made"):
        gui.main(arguments(tmp_path, "renew-transport", "--allow-downtime"))
    assert list(tmp_path.iterdir()) == []


def test_noninteractive_mutation_requires_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(gui, "MaintenanceClient", lambda *_: pytest.fail("opened state"))
    with pytest.raises(InstallError, match="--yes"):
        gui.main(arguments(tmp_path, "renew-transport", "--allow-downtime"))


@pytest.mark.parametrize("action", ["rotate", "restore", "renew-transport"])
def test_headless_recovery_keeps_original_id(terminal_client, tmp_path, monkeypatch, action):
    original = job(action=action, backup_id=str(uuid.uuid4()))
    calls = []
    monkeypatch.setattr(terminal_client, "snapshot", lambda: [original])
    monkeypatch.setattr(terminal_client, "call", lambda request: calls.append(request) or {})
    assert gui.main(arguments(tmp_path, "recover", "--job-id", original["id"],
                              "--allow-downtime", "--yes")) == 0
    assert calls == [gui.recovery_request(original)]


def test_headless_restore_uses_recorded_backup(terminal_client, tmp_path, monkeypatch):
    original = job(action="backup", state="captured", backup_id=str(uuid.uuid4()))
    terminal_client.backup_state = {"can_restore": True}
    calls = []
    monkeypatch.setattr(terminal_client, "snapshot", lambda: [original])
    monkeypatch.setattr(terminal_client, "call", lambda request: calls.append(request) or {})
    assert gui.main(arguments(tmp_path, "restore", "--job-id", original["id"],
                              "--allow-downtime", "--yes")) == 0
    assert calls[0]["backup_id"] == original["backup_id"]
    assert calls[0]["action"] == "restore"
    assert calls[0]["request_id"] != original["id"]


@pytest.mark.parametrize("jobs", [[], [job(state="running")]])
def test_headless_recovery_rejects_absent_or_running_job(terminal_client, tmp_path, monkeypatch, jobs):
    identifier = jobs[0]["id"] if jobs else str(uuid.uuid4())
    monkeypatch.setattr(terminal_client, "snapshot", lambda: jobs)
    monkeypatch.setattr(terminal_client, "call", lambda *_: pytest.fail("mutated worker"))
    with pytest.raises(InstallError):
        gui.main(arguments(tmp_path, "recover", "--job-id", identifier, "--allow-downtime", "--yes"))


@pytest.mark.parametrize("action,flags", [
    ("configure-recovery", ["--identity", "/private/key.age", "--independent-copy"]),
    ("disable-recovery", []), ("trust-signer", ["--signer", "/public/signer.pub"]),
])
def test_host_key_settings_work_without_display(tmp_path, monkeypatch, action, flags):
    from iris_installer import managed_worker
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(gui, "recovery_identity", lambda path, **_kwargs: (Path(path), "age1" + "q" * 58))
    monkeypatch.setattr(managed_worker, "configure_recovery", lambda *args: calls.append(args))
    monkeypatch.setattr(managed_worker, "configure_restore_signer", lambda *args: calls.append(args))
    monkeypatch.setattr(managed_worker, "inspect", lambda *_: {"available": True})
    assert gui.main(arguments(tmp_path, action, *flags, "--yes")) == 0
    assert calls == [(tmp_path, Path(flags[1]) if flags else None)]


@pytest.mark.parametrize("action", ["configure-recovery", "replace-recovery"])
def test_key_review_precedes_confirmation_without_mutation(tmp_path, monkeypatch, capsys, action):
    from iris_installer import managed_worker
    recipient = "age1" + "q" * 58
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui, "recovery_identity", lambda path, **kwargs: (Path(path), recipient))
    monkeypatch.setattr(gui.sys.stdin, "isatty", lambda: True)
    def refuse(_prompt):
        assert recipient in capsys.readouterr().out
        return "NO"
    monkeypatch.setattr("builtins.input", refuse)
    monkeypatch.setattr(gui, "MaintenanceClient", lambda *_: pytest.fail("opened socket state before approval"))
    monkeypatch.setattr(gui, "prepare_recovery_candidate", lambda *_a, **_k: pytest.fail("imported key before approval"))
    monkeypatch.setattr(managed_worker, "configure_recovery", lambda *_: pytest.fail("changed key access before approval"))
    options = [action, "--identity", "/private/key.age", "--independent-copy"]
    if action == "replace-recovery":
        options += ["--allow-downtime"]
    with pytest.raises(InstallError, match="No changes made"):
        gui.main(arguments(tmp_path, *options))
    assert list(tmp_path.iterdir()) == []


def test_key_changed_after_review_is_not_configured(tmp_path, monkeypatch):
    from iris_installer import managed_worker
    recipients = iter(["age1" + "q" * 58, "age1" + "p" * 58])
    monkeypatch.setattr(gui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gui, "recovery_identity", lambda path, **kwargs: (Path(path), next(recipients)))
    monkeypatch.setattr(managed_worker, "configure_recovery", lambda *_: pytest.fail("changed key was accepted"))
    with pytest.raises(InstallError, match="changed after review"):
        gui.main(arguments(tmp_path, "configure-recovery", "--identity", "/private/key.age",
                           "--independent-copy", "--yes"))


def test_replacement_passes_only_reviewed_recipient_to_protected_import(terminal_client, tmp_path, monkeypatch):
    identity, recipient = Path("/private/key.age"), "age1" + "q" * 58
    expected = {"action": "rotate", "family": "age-recovery",
                "request_id": str(uuid.uuid4()), "allow_downtime": True}
    monkeypatch.setattr(gui, "recovery_identity", lambda path, **kwargs: (Path(path), recipient))
    imported, requests = [], []
    def prepare(client, path, approved, **kwargs):
        imported.append((client, path, approved, kwargs))
        return expected
    monkeypatch.setattr(gui, "prepare_recovery_candidate", prepare)
    monkeypatch.setattr(terminal_client, "call", lambda request: requests.append(request) or {})
    assert gui.main(arguments(tmp_path, "replace-recovery", "--identity", str(identity),
                              "--independent-copy", "--allow-downtime", "--yes")) == 0
    assert imported == [(terminal_client, identity, recipient, {"independent_copy": True})]
    assert requests == [expected]


def test_terminal_accepts_explicit_confirmation(terminal_client, tmp_path, monkeypatch):
    original = job()
    calls = []
    monkeypatch.setattr(gui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "YES")
    monkeypatch.setattr(terminal_client, "snapshot", lambda: [original])
    monkeypatch.setattr(terminal_client, "call", lambda request: calls.append(request) or {})
    assert gui.main(arguments(tmp_path, "recover", "--job-id", original["id"], "--allow-downtime")) == 0
    assert calls == [gui.recovery_request(original)]


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


def test_caller_owner_is_only_accepted_from_root_sudo_context(monkeypatch):
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
        gui.recovery_identity(path, allow_invoking_user=True)
