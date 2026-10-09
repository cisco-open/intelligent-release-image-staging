# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated management-handler contract for reviewed origin access."""
import json
import os
import time

import pytest

import api_routes
import auth
import origin_enforcement as oe
import peer_endpoints
import peer_policy
from test_blocklist_reconciler import _role_doc
from test_gui_server import _auth, _req, _serve_full

PATH = "/api/peer-policy/origin-enforcement"


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_HOST_IP", "192.0.2.10")
    host, port, (_, _, _, cat), stop = _serve_full(tmp_path)
    for name in ("peer-policy.json", "peer-policy.lkg.json"):
        peer_policy._atomic_write_json(os.path.join(cat.state_dir, name), _role_doc(("d1",)))
    endpoints = os.path.join(cat.state_dir, "peer-endpoints.json")
    for principal, address in ((auth.Principal("service", "seeder"), "192.0.2.10"),
                               (auth.Principal("device", "d1"), "198.51.100.20")):
        peer_endpoints.record_endpoint(endpoints, principal, address, 6881, time.time())
    cookie, csrf = _auth(host, port)
    headers = {"Cookie": cookie, "X-CSRF-Token": csrf}

    def call(method="GET", body=None, extra=None, authenticated=True, csrf_ok=True):
        hh = dict(headers) if authenticated else {}
        if not csrf_ok:
            hh.pop("X-CSRF-Token", None)
        hh.update(extra or {})
        status, response_headers, raw = _req(host, port, method, PATH, body, headers=hh)
        return status, response_headers, json.loads(raw)

    yield call, cat
    stop()


def body():
    return {"mode": "enforce", "max_new_ips": 10, "max_new_devices": 10,
            "if_policy_revision": 1, "dry_run": True}


def test_registry_canonical_routes():
    for method in ("GET", "PUT"):
        assert api_routes.management_to_legacy(method,
            "/internal/v1/peer-policy/origin-enforcement") == PATH
        assert api_routes.match("console", method,
            "/api/v1/peer-policy/origin-enforcement") is not None


def test_authentication_csrf_and_cas(api):
    call, _ = api
    assert call(authenticated=False)[0] == 401
    assert call("PUT", body(), csrf_ok=False)[0] == 403
    assert call("PUT", body())[0] == 428
    assert call("PUT", body(), {"If-Match": "*"})[0] == 412
    assert call("PUT", dict(body(), if_policy_revision=2),
                {"If-Match": oe.etag(0)})[2]["code"] == "policy_revision_conflict"


def test_native_count_only_review_commit_and_replay(api):
    call, cat = api
    status, headers, result = call()
    assert status == 200 and headers["ETag"] == oe.etag(0)
    assert result["new_ip_count"] == 1 and result["new_device_count"] == 1
    status, headers, preview = call("PUT", body(), {"If-Match": oe.etag(0)})
    assert status == 200 and preview["requires_confirmation"] is True
    assert len(preview["confirm_token"]) == 64
    control, _, _ = oe.paths(cat.state_dir)
    assert not os.path.exists(control)
    commit = dict(body(), dry_run=False, confirm_token=preview["confirm_token"])
    status, headers, result = call("PUT", commit, {"If-Match": oe.etag(0)})
    assert status == 200 and result["revision"] == 1 and result["state"] == "pending"
    assert result["applied_ip_count"] is None and headers["ETag"] == oe.etag(1)
    assert call("PUT", commit, {"If-Match": oe.etag(0)})[0] == 412
    assert "198.51.100.20" not in json.dumps(result)
    assert "192.0.2.10" not in json.dumps(result)


@pytest.mark.parametrize("update", [
    {"max_new_ips": True}, {"max_new_devices": 1001}, {"dry_run": "true"},
    {"confirm_token": []}, {"mode": "apply"}, {"if_policy_revision": -1}, {"ips": []},
])
def test_closed_typed_request(api, update):
    call, _ = api
    status, _, result = call("PUT", dict(body(), **update), {"If-Match": oe.etag(0)})
    assert status == 422 and result["code"] == "invalid_origin_enforcement"
