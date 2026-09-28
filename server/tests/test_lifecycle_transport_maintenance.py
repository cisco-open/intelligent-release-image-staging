# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real-crypto lifecycle renewal, overlap retirement and same-ID recovery."""

import base64
import copy
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import lifecycle_network as network
from iris_installer import lifecycle_transport_maintenance as renewal
from iris_installer import maintenance_gui as gui
from iris_installer import lifecycle_worker
from iris_installer.state import InstallError, atomic_write


def runner(command, *, capture=False, **kwargs):
    result = subprocess.run(list(map(str, command)), capture_output=True, check=True, **kwargs)
    return result.stdout if capture else b""


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    base = tmp_path_factory.mktemp("original-transport")
    network.prepare_network_custody(base, "https://127.0.0.1:18443", runner)
    return base


@pytest.fixture
def deployment(tmp_path, original, monkeypatch):
    base = tmp_path / "deployment"
    base.mkdir(mode=0o700)
    shutil.copytree(original / "lifecycle-tls", base / "lifecycle-tls")
    class Worker:
        def status(self):
            return {"available": True}
        def transport_proof(self, request, peer):
            return renewal.proof_request(base, request, peer)
    custody = {p.name: p for p in (base / "lifecycle-tls").iterdir() if p.suffix in (".key", ".crt")}
    server = network.make_https_server("127.0.0.1", 0, Worker(), custody)
    url = "https://127.0.0.1:" + str(server.server_address[1])
    atomic_write(base / "lifecycle-tls/endpoint.json", json.dumps({"url": url}).encode())
    document = {"schema": 1, "id": str(uuid.uuid4()), "config": {"target": "kubernetes", "lifecycle_url": url}, "completed": {}}
    atomic_write(base / "installation.json", json.dumps(document).encode())
    pod = base / "pod-secrets"
    pod.mkdir(mode=0o700)
    for name in ("ca.crt", "client.crt", "client.key"):
        atomic_write(pod / name, custody[name].read_bytes())
    old = {name: p.read_bytes() for name, p in custody.items()}
    class Install:
        config = document["config"]
        command = staticmethod(runner)
        fail_proof = False
        old_overlap_verified = False
        require_old_connection = True
        objects = [
            {"kind": "Secret", "metadata": {"name": "iris-lifecycle"}, "data": {name: base64.b64encode(custody[name].read_bytes()).decode() for name in ("ca.crt", "client.crt", "client.key")}},
            {"kind": "Deployment", "metadata": {"name": "iris-seed-server"}, "spec": {"template": {"metadata": {}}}},
        ]
        def pin_runtime(self):
            pass
        def _recover_object_update(self):
            pass
        def manifests(self):
            return copy.deepcopy(self.objects)
        def _replace_owned(self, obj):
            self.objects = [obj if o["kind"] == obj["kind"] else o for o in self.objects]
            if obj["kind"] == "Secret":
                if self.require_old_connection:
                    assert request(server, custody)["result"]["available"] is True
                    self.old_overlap_verified = True
                for name, data in obj["data"].items():
                    atomic_write(pod / name, base64.b64decode(data))
        def kube(self, *args, **kwargs):
            assert args[:2] == ("rollout", "status")
            return b""
        def execute(self, *args, **kwargs):
            if self.fail_proof:
                self.fail_proof = False
                raise InstallError("injected proof interruption")
            environment = dict(os.environ, IRIS_LIFECYCLE_URL=url,
                IRIS_LIFECYCLE_CA=str(pod / "ca.crt"), IRIS_LIFECYCLE_CERT=str(pod / "client.crt"), IRIS_LIFECYCLE_KEY=str(pod / "client.key"))
            return runner(args, capture=True, env=environment, timeout=kwargs.get("timeout", 30))
        def _pods(self, service):
            return [{"name": "server-pod", "uid": "new-server-uid"}]
    install = Install()
    from iris_installer import deploy
    monkeypatch.setattr(deploy, "installation", lambda journal: install)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base, custody, server, install, old, url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(server, custody, payload=None):
    context = ssl.create_default_context(cafile=str(custody["ca.crt"]))
    context.load_cert_chain(str(custody["client.crt"]), str(custody["client.key"]))
    connection = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=context, timeout=3)
    try:
        connection.request("POST", "/v1/lifecycle", body=json.dumps(payload or {"action": "status"}))
        response = connection.getresponse()
        return json.loads(response.read())
    finally:
        connection.close()


def test_real_ca_and_leaf_renewal_preserves_keys_and_retires_old_client(deployment, tmp_path):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    proof = renewal.renew(base, identifier, server)
    assert proof["same_private_keys"] is True
    assert proof["old_client_retired"] is True
    assert install.old_overlap_verified
    for role in renewal.ROLES:
        assert custody[role + ".key"].read_bytes() == before[role + ".key"]
        assert custody[role + ".crt"].read_bytes() != before[role + ".crt"]
    assert request(server, custody)["result"]["available"]
    assert renewal.status(base, url, runner)["renewal_due"] is False
    stale = tmp_path / "stale"
    stale.mkdir(mode=0o700)
    for name, data in before.items():
        atomic_write(stale / name, data)
    with pytest.raises((OSError, http.client.HTTPException)):
        request(server, {name: stale / name for name in before})


def test_interrupted_rollout_recovers_same_certificates_and_overlap(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    install.fail_proof = True
    with pytest.raises(InstallError, match="injected"):
        renewal.renew(base, identifier, server)
    pointer = json.loads((base / "lifecycle-transport-operation.json").read_bytes())
    expected = pointer["after"]
    with pytest.raises(InstallError, match="same-operation"):
        renewal.renew(base, identifier, server)
    candidate, overlap = renewal.startup_custody(base, url, runner)
    assert overlap == (bytes.fromhex(pointer["before"]["client"]),)
    server.configure_transport(candidate, extra_client_digests=overlap)
    proof = renewal.renew(base, identifier, server, recovery=True)
    assert proof["worker_sha256"] == expected["worker"]
    assert proof["client_sha256"] == expected["client"]
    assert all(custody[role + ".key"].read_bytes() == before[role + ".key"] for role in renewal.ROLES)


def test_new_transport_operation_cannot_adopt_pending_management_update(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    atomic_write(base / "kube-update.json", b'{"pending":"another-operation"}')
    with pytest.raises(InstallError, match="original operation before connection renewal"):
        renewal.renew(base, identifier, server)
    assert not (base / "lifecycle-transport-operations" / identifier).exists()
    assert all(custody[name].read_bytes() == value for name, value in before.items())


def test_different_operation_cannot_take_over_pending_renewal(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    install.fail_proof = True
    with pytest.raises(InstallError):
        renewal.renew(base, identifier, server)
    with pytest.raises(InstallError, match="existing connection"):
        renewal.renew(base, str(uuid.uuid4()), server)


@pytest.mark.parametrize("same_uid", [False, True])
def test_transport_proof_is_bound_to_one_server_incarnation(deployment, same_uid):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    current = [{"name": "server-pod", "uid": "server-uid", "container_id": "first"}]
    install._pods = lambda service: copy.deepcopy(current)
    execute = install.execute
    def replaced(*args, **kwargs):
        result = execute(*args, **kwargs)
        current[0] = {"name": "server-pod", "uid": "server-uid" if same_uid else "replacement-uid", "container_id": "second"}
        return result
    install.execute = replaced
    with pytest.raises(InstallError, match="Restarted server did not prove"):
        renewal.renew(base, identifier, server)
    record = json.loads((base / "lifecycle-transport-operation.json").read_bytes())
    assert record["phase"] == "server-restarted" and record.get("proof") is None


def test_completed_record_recovers_pointer_publication_and_retires_overlap(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    proof = renewal.renew(base, identifier, server)
    pointer = base / "lifecycle-transport-operation.json"
    record = json.loads(pointer.read_bytes())
    record["phase"] = "certificates-published"
    atomic_write(pointer, json.dumps(record).encode())
    candidate, overlap = renewal.startup_custody(base, url, runner)
    server.configure_transport(candidate, extra_client_digests=overlap)
    assert renewal.renew(base, identifier, server, recovery=True) == proof
    assert json.loads(pointer.read_bytes())["phase"] == "complete"
    assert len(server.transport[1]) == 1


def test_candidate_substitution_is_refused(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    install.fail_proof = True
    with pytest.raises(InstallError):
        renewal.renew(base, identifier, server)
    candidate = base / "lifecycle-transport-operations" / identifier / "client.crt"
    atomic_write(candidate, before["client.crt"])
    with pytest.raises(InstallError, match="candidate changed"):
        renewal.renew(base, identifier, server, recovery=True)


@pytest.mark.parametrize("role", ["worker", "client", "ca"])
def test_expired_certificate_keeps_host_recovery_custody_available(deployment, role):
    base, custody, server, install, before, url = deployment
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    import datetime
    old = x509.load_pem_x509_certificate(before[role + ".crt"])
    ca_key = serialization.load_pem_private_key(before["ca.key"], password=None)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.issuer)
        .public_key(old.public_key()).serial_number(12345)
        .not_valid_before(now - datetime.timedelta(days=10)).not_valid_after(now - datetime.timedelta(days=1)))
    for extension in old.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    expired = builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    atomic_write(custody[role + ".crt"], expired, 0o644)
    install.require_old_connection = role == "worker"
    assert renewal.load_custody(base, url, runner)["worker.key"] == custody["worker.key"]
    with pytest.raises(subprocess.CalledProcessError):
        renewal.load_custody(base, url, runner, allow_expired=False)
    assert renewal.status(base, url, runner)["renewal_due"] is True
    proof = renewal.renew(base, str(uuid.uuid4()), server)
    assert proof["old_client_retired"]


def test_proof_requires_exact_tls_peer_not_body_assertion(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    renewal.renew(base, identifier, server)
    with pytest.raises(InstallError, match="does not match"):
        renewal.proof_request(base, {"action": "transport-proof", "request_id": identifier}, "a" * 64)
    with pytest.raises(InstallError, match="Invalid"):
        renewal.proof_request(base, {"action": "transport-proof", "request_id": identifier, "peer": "claimed"}, "a" * 64)


@pytest.mark.parametrize("action", ["transport-status", "renew-transport", "recover-transport"])
def test_network_certificate_cannot_authorize_host_only_renewal(deployment, action):
    base, custody, server, install, before, url = deployment
    assert request(server, custody, {"action": action})["ok"] is False


def test_host_recovery_request_has_no_private_fields():
    identifier = str(uuid.uuid4())
    assert gui.recovery_request({"id": identifier, "action": "renew-transport", "state": "recovery-required"}) == {
        "action": "recover-transport", "request_id": identifier, "allow_downtime": True}


@pytest.mark.parametrize("identifier", ["../escape", "not-a-uuid", "A" * 36, None])
def test_renewal_operation_identifier_is_bounded(identifier):
    with pytest.raises(InstallError):
        renewal._id(identifier)


def test_transport_jobs_do_not_leak_into_browser_backup_schema(tmp_path):
    for name in ("state", "backup", "recovery"):
        (tmp_path / name).mkdir(mode=0o700)
    worker = lifecycle_worker.Worker(tmp_path / "state", tmp_path / "backup", tmp_path / "recovery")
    worker.jobs = [{"id": str(uuid.uuid4()), "action": "renew-transport", "state": "renewed"}]
    assert worker.status()["jobs"] == []
    assert worker.rotation_status()["jobs"] == []


def test_worker_serializes_host_renewal_without_blocking_status(deployment, monkeypatch):
    base, custody, server, install, before, url = deployment
    for name in ("backup", "recovery"):
        (base / name).mkdir(mode=0o700)
    worker = lifecycle_worker.Worker(base, base / "backup", base / "recovery")
    worker.network_server = server
    entered, release = threading.Event(), threading.Event()
    def renew(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return {"same_private_keys": True}
    monkeypatch.setattr(renewal, "renew", renew)
    request_id = str(uuid.uuid4())
    try:
        assert worker.submit_transport({"action": "renew-transport", "request_id": request_id, "allow_downtime": True}) == {"job_id": request_id}
        assert entered.wait(3)
        assert worker.status()["available"] is True
        assert worker.transport_status()["can_renew"] is False
        with pytest.raises(InstallError, match="active maintenance"):
            worker.submit_transport({"action": "renew-transport", "request_id": str(uuid.uuid4()), "allow_downtime": True})
    finally:
        release.set()
        worker.thread.join(5)
    assert worker.jobs[0]["state"] == "renewed"


def test_non_root_unix_peer_cannot_request_host_transport_action(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an actual unprivileged peer")
    import socket
    class Worker:
        def transport_status(self):
            pytest.fail("unprivileged peer reached host certificate custody")
    path = tmp_path / "worker.sock"
    server = lifecycle_worker.make_server(path, Worker(), allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(path))
            connection.sendall(b'{"action":"transport-status"}\n')
            result = json.loads(connection.makefile("rb").readline())
        assert result["ok"] is False
        assert "requires root" in result["error"]
    finally:
        thread.join(5)
        server.server_close()


def test_durable_worker_admission_recovers_before_operation_creation(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    atomic_write(base / "lifecycle-jobs.json", json.dumps([{"id": identifier, "action": "renew-transport", "state": "recovery-required"}]).encode())
    assert renewal.renew(base, identifier, server, recovery=True)["same_private_keys"]


def test_unadmitted_missing_operation_cannot_be_recovered(deployment):
    base, custody, server, install, before, url = deployment
    with pytest.raises(InstallError, match="no admitted"):
        renewal.renew(base, str(uuid.uuid4()), server, recovery=True)


def test_initial_operation_publication_is_atomic(deployment, monkeypatch):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    atomic_write(base / "lifecycle-jobs.json", json.dumps([{"id": identifier, "action": "renew-transport", "state": "running"}]).encode())
    original_rename = renewal.os.rename
    def fail_rename(source, destination):
        if Path(destination).name == identifier:
            raise OSError("injected before publication")
        original_rename(source, destination)
    monkeypatch.setattr(renewal.os, "rename", fail_rename)
    with pytest.raises(OSError, match="injected"):
        renewal.renew(base, identifier, server)
    assert not (base / "lifecycle-transport-operations" / identifier).exists()
    monkeypatch.setattr(renewal.os, "rename", original_rename)
    assert renewal.renew(base, identifier, server, recovery=True)["same_private_keys"]


def test_pending_reissue_crash_keeps_host_startup_and_recovery_available(deployment):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    install.fail_proof = True
    with pytest.raises(InstallError):
        renewal.renew(base, identifier, server)
    directory = base / "lifecycle-transport-operations" / identifier
    record = json.loads((directory / "record.json").read_bytes())
    record["certificate_history"] = [dict(record["after"])]
    renewal._save(base, directory, record, "renewing-expired")
    atomic_write(directory / "client.crt", b"interrupted public certificate write")
    retained, overlap = renewal.startup_custody(base, url, runner)
    assert retained["client.key"] == custody["client.key"] and overlap == ()
    install.require_old_connection = False
    proof = renewal.renew(base, identifier, server, recovery=True)
    assert proof["same_private_keys"] and proof["client_sha256"] != record["certificate_history"][0]["client"]


def test_expiring_pending_candidate_has_explicit_journalled_reissue(deployment, monkeypatch):
    base, custody, server, install, before, url = deployment
    identifier = str(uuid.uuid4())
    install.fail_proof = True
    with pytest.raises(InstallError):
        renewal.renew(base, identifier, server)
    record = json.loads((base / "lifecycle-transport-operation.json").read_bytes())
    old_generation = install.manifests()[1]["spec"]["template"]["metadata"]["annotations"]["iris.cisco.com/lifecycle-renewal"]
    monkeypatch.setattr(renewal, "_expiring", lambda *args: True)
    proof = renewal.renew(base, identifier, server, recovery=True)
    renewed = json.loads((base / "lifecycle-transport-operation.json").read_bytes())
    assert renewed["certificate_history"] == [record["after"]]
    assert proof["client_sha256"] != record["after"]["client"]
    new_generation = install.manifests()[1]["spec"]["template"]["metadata"]["annotations"]["iris.cisco.com/lifecycle-renewal"]
    assert new_generation != old_generation
    assert new_generation == identifier + ":" + proof["client_sha256"]
    assert (base / "lifecycle-transport-operations" / identifier / "previous-0-client.crt").is_file()


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="local display or Xvfb required")
def test_host_window_expiry_and_renewal_confirmation(deployment, monkeypatch):
    import tkinter as tk
    from tkinter import messagebox
    base, custody, server, install, before, url = deployment
    client = gui.MaintenanceClient(base)
    client.transport_state = dict(renewal.status(base, url, runner), can_renew=True)
    calls = []
    monkeypatch.setattr(client, "snapshot", lambda: [])
    monkeypatch.setattr(client, "call", lambda request: calls.append(request) or {"job_id": request.get("request_id")})
    window = tk.Tk()
    try:
        app = gui.MaintenanceWindow(window, client)
        app.events.put(app.events.get(timeout=3))
        app.poll()
        assert "Worker" in app.transport_expiry.cget("text")
        assert "Ca" in app.transport_expiry.cget("text")
        assert "disabled" not in app.transport_button.state()
        monkeypatch.setattr(messagebox, "askokcancel", lambda *args, **kwargs: False)
        app.renew_transport()
        assert calls == []
        monkeypatch.setattr(messagebox, "askokcancel", lambda *args, **kwargs: True)
        app.renew_transport()
        app.events.put(app.events.get(timeout=3))
        app.poll()
        assert len(calls) == 1 and calls[0]["action"] == "renew-transport"
        assert set(calls[0]) == {"action", "request_id", "allow_downtime"}
    finally:
        window.destroy()
