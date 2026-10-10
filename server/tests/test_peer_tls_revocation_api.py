# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Certificate withdrawal authentication, optimistic concurrency and snapshots."""
import http.client
import json
import threading
import time
from types import SimpleNamespace

import pytest
import catalog
import gui_app
import management_api
import peer_tls_issuer
import peer_tls_revocations as revocations
import peer_tls_settings
import secrets_store
from test_gui_server import _auth, _req


class FleetRows(dict):
    pass


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("IRIS_RUN", str(tmp_path / "run"))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_PEER_TLS_MODE", "required")
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    rows = FleetRows({"edge-1": {"device_id": "edge-1"}, "edge-2": {"device_id": "edge-2"}})
    rows.jobs = []
    fleet = SimpleNamespace(get_device=rows.get, list_devices=lambda: list(rows.values()))
    srv = management_api.make_server("127.0.0.1", 0, app, fleet=fleet,
        onboard=SimpleNamespace(list_jobs=lambda: rows.jobs),
        certfile=None, audit_path=str(tmp_path / "audit.jsonl"))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address
    cookie, csrf = _auth(host, port)
    yield host, port, {"Cookie": cookie, "X-CSRF-Token": csrf}, rows, tmp_path
    srv.shutdown(); srv.server_close(); thread.join()


def payload(device="edge-1", *, revision=0, request=1):
    return {"expected_revision": revision,
            "expected_identity_sha256": revocations.device_identity(device),
            "request_id": "00000000-0000-0000-0000-%012d" % request}


def test_auth_csrf_missing_device_mode_and_payload_guards(server, monkeypatch):
    host, port, headers, rows, _ = server
    path = "/api/devices/edge-1/certificate"
    assert _req(host, port, "GET", path)[0] == 401
    assert _req(host, port, "POST", path + "/revoke", payload())[0] == 401
    assert _req(host, port, "POST", path + "/revoke", payload(), headers={"Cookie": headers["Cookie"]})[0] == 403
    assert _req(host, port, "GET", "/api/devices/missing/certificate", headers=headers)[0] == 404
    assert _req(host, port, "POST", "/api/devices/missing/certificate/revoke", payload(), headers=headers)[0] == 404
    monkeypatch.setenv("IRIS_PEER_TLS_MODE", "disabled")
    assert _req(host, port, "POST", path + "/revoke", payload(), headers=headers)[0] == 409
    monkeypatch.setenv("IRIS_PEER_TLS_MODE", "required")
    for changes in ({"expected_revision": True}, {"expected_identity_sha256": "invalid"},
                    {"request_id": "bad"}, {"extra": 1}):
        assert _req(host, port, "POST", path + "/revoke", dict(payload(), **changes), headers=headers)[0] == 400
    assert rows["edge-1"] == {"device_id": "edge-1"}
    assert revocations.Ledger().status("edge-1")["state"] == "active"


def test_revocation_retains_inventory_has_durable_retry_and_audit(server):
    host, port, headers, rows, tmp_path = server
    path = "/api/devices/edge-1/certificate"
    status, _, raw = _req(host, port, "GET", path, headers=headers)
    assert status == 200
    before = json.loads(raw)
    assert before["state"] == "active" and before["peer_tls_required"] is True
    assert before["enforcement"] == "not-applicable"
    status, _, raw = _req(host, port, "POST", path + "/revoke", payload(), headers=headers)
    assert status == 200, raw
    result = json.loads(raw)
    assert result["state"] == "revoked" and result["revision"] == 1 and result["applied"] is True
    assert result["enforcement"] == "pending"
    status, _, raw = _req(host, port, "POST", path + "/revoke", payload(), headers=headers)
    assert status == 200 and json.loads(raw)["applied"] is False
    status, _, raw = _req(host, port, "GET", path, headers=headers)
    assert status == 200 and json.loads(raw) == {k: v for k, v in result.items() if k != "applied"}
    assert "edge-1" in rows
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(event["event"] == "device_certificate_revoke" and event["actor"] == "console:admin" for event in events)
    assert _req(host, port, "POST", "/api/devices/edge-2/certificate/revoke", payload("edge-2", revision=1), headers=headers)[0] == 409
    assert _req(host, port, "POST", "/api/devices/edge-2/certificate/revoke", payload("edge-2", request=2), headers=headers)[0] == 409


def test_deleted_and_readded_inventory_id_stays_revoked(server):
    host, port, headers, rows, _ = server
    path = "/api/devices/edge-1/certificate"
    assert _req(host, port, "POST", path + "/revoke", payload(), headers=headers)[0] == 200
    rows.pop("edge-1")
    assert _req(host, port, "GET", path, headers=headers)[0] == 404
    rows["edge-1"] = {"device_id": "edge-1"}
    assert json.loads(_req(host, port, "GET", path, headers=headers)[2])["state"] == "revoked"


def test_recovery_requires_explicit_approval_and_no_prior_device_job(server):
    host, port, headers, rows, _ = server
    path = "/api/devices/edge-1/certificate"
    request = payload(revision=1, request=2)
    assert _req(host, port, "POST", path + "/reenroll", request)[0] == 401
    assert _req(host, port, "POST", path + "/reenroll", request,
                headers={"Cookie": headers["Cookie"]})[0] == 403
    assert _req(host, port, "POST", path + "/revoke", payload(), headers=headers)[0] == 200
    rows.jobs.append({"device_id": "edge-1", "state": "running"})
    assert _req(host, port, "POST", path + "/reenroll", request, headers=headers)[0] == 409
    rows.jobs.clear()
    status, _, raw = _req(host, port, "POST", path + "/reenroll", request, headers=headers)
    assert status == 200, raw
    approval = json.loads(raw)
    assert approval["state"] == "reenrollment-required" and approval["revision"] == 2
    assert approval["identity_sha256"] == revocations.device_identity("edge-1")
    assert approval["request_id"] == payload()["request_id"]
    assert approval["recovery_request_id"] == request["request_id"]
    assert approval["enforcement"] == "pending"
    # Lost-response retries remain idempotent after the new onboarding starts.
    rows.jobs.append({"device_id": "edge-1", "state": "running"})
    status, _, raw = _req(host, port, "POST", path + "/reenroll", request, headers=headers)
    assert status == 200 and json.loads(raw)["applied"] is False
    assert _req(host, port, "POST", path + "/reenroll", dict(request, expected_revision=2), headers=headers)[0] == 409


def test_unavailable_and_unknown_write_outcomes_require_read_reconciliation(server, monkeypatch):
    host, port, headers, _, _ = server
    path = "/api/devices/edge-1/certificate"
    ledger = revocations.Ledger()
    ledger.initialize()
    write = peer_tls_settings.atomic_json
    def interrupted(path, data):
        write(path, data)
        raise OSError("simulated outcome unknown")
    monkeypatch.setattr(peer_tls_settings, "atomic_json", interrupted)
    assert _req(host, port, "POST", path + "/revoke", payload(), headers=headers)[0] == 503
    monkeypatch.setattr(peer_tls_settings, "atomic_json", write)
    assert json.loads(_req(host, port, "GET", path, headers=headers)[2])["state"] == "revoked"
    ledger.path.unlink()
    assert _req(host, port, "GET", path, headers=headers)[0] == 503
    assert _req(host, port, "POST", path + "/revoke", payload(), headers=headers)[0] == 503


def test_snapshot_auth_binding_nonce_mode_cache_and_revoked_device_access(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("IRIS_PEER_TLS_MODE", "required")
    path = str(tmp_path / "secrets.json")
    store = secrets_store.load(path)
    current = secrets_store.mint(store, "edge-1", "catalog_token", time.time())
    other = secrets_store.mint(store, "edge-2", "catalog_token", time.time())
    store["devices"]["edge-1"]["catalog_token_prev"] = dict(
        store["devices"]["edge-1"]["catalog_token"], value="prior-test-token")
    secrets_store.save(store, path)
    ledger = revocations.Ledger()
    monkeypatch.setattr(peer_tls_issuer.Issuer, "revocation_snapshot",
                        lambda self, nonce: ledger.snapshot("b" * 64, nonce, now=100))
    srv = catalog.make_server("127.0.0.1", 0, catalog.CatalogStore(str(tmp_path / "state")), path)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    def get(token, query="?nonce=" + "a" * 32):
        conn = http.client.HTTPConnection(*srv.server_address)
        conn.request("GET", "/v1/devices/edge-1/peer-tls-revocations" + query,
                     headers={"Authorization": "Bearer " + token})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result
    try:
        for token in ("invalid", other, "prior-test-token"):
            assert get(token)[0] == 401
        for query in ("", "?nonce=a", "?nonce=" + "a" * 32 + "&nonce=" + "a" * 32):
            assert get(current, query)[0] == 400
        status, headers, raw = get(current)
        assert status == 200 and "no-store" in headers["Cache-Control"]
        assert json.loads(raw)["nonce"] == "a" * 32
        ledger.revoke("edge-1", **payload(), actor="operator", now=100)
        status, _, raw = get(current)
        assert status == 200
        assert revocations.device_identity("edge-1") in json.loads(raw)["snapshot"]
        monkeypatch.setenv("IRIS_PEER_TLS_MODE", "disabled")
        assert get(current)[0] == 409
        monkeypatch.setenv("IRIS_PEER_TLS_MODE", "required")
        ledger.path.unlink()
        assert get(current)[0] == 503
    finally:
        srv.shutdown(); srv.server_close(); thread.join()
