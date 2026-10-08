# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Queued-read refusals cross the Console's verified management TLS hop."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json

import pytest

import management_api
import gui_app
import gui_server
from projection_reads import ReadProjectionGate
from test_api_split import _certificate, _thread, _write_secret
from test_api_split import policy_tiers  # noqa: F401 - pytest fixture


@pytest.fixture
def gated_tiers(monkeypatch, request):
    gates = []

    def create_gate():
        gate = ReadProjectionGate(wait_timeout=.05)
        gates.append(gate)
        return gate

    monkeypatch.setattr(management_api.projection_reads, "ReadProjectionGate", create_gate)
    tiers = request.getfixturevalue("policy_tiers")
    assert len(gates) == 1
    return tiers[0], gates[0]


@pytest.mark.parametrize("suffix", ("/devices", "/overview", "/peer-policy"))
def test_console_forwards_bounded_read_refusal_and_recovers(gated_tiers, suffix):
    request, gate = gated_tiers
    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.enter():
            status, headers, body = pool.submit(
                request, "console", "GET", suffix).result(timeout=3)
            assert status == 503
            assert headers["Retry-After"] == "1"
            assert headers["Content-Type"].startswith("application/problem+json")
            assert body["code"] == "projection-busy"
            assert body["type"].endswith("#projection-busy")
            assert len(gate._queue) == 1
        status, _, body = request("console", "GET", suffix)
        assert status == 200
        if suffix == "/devices":
            assert body["total"] == 1
        elif suffix == "/overview":
            assert body["devices"] == 1
        else:
            assert body["roles"]["defined"] >= 1


def test_default_wait_fits_console_upstream_timeout(tmp_path, monkeypatch):
    gate = ReadProjectionGate()
    monkeypatch.setattr(management_api.projection_reads, "ReadProjectionGate", lambda: gate)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "fixture-password")
    cert, key = _certificate(tmp_path, "projection-default")
    token = tmp_path / "tier-token"
    _write_secret(token, "p" * 64)
    servers = []
    try:
        management = management_api.make_server(
            "127.0.0.1", 0, app, certfile=str(cert), keyfile=str(key),
            management_token_file=str(token))
        servers.append((management, _thread(management)))
        console = gui_server.make_server(
            "127.0.0.1", 0, "https://localhost:%d" % management.server_address[1],
            str(token), str(cert))
        servers.append((console, _thread(console)))
        # The handler passes its own timeout to the upstream helper; that
        # helper's function default is NOT the Console's forwarding budget.
        assert gate._wait_timeout < console.RequestHandlerClass.timeout

        def request(method, path, headers=None, body=None):
            connection = http.client.HTTPConnection(
                "127.0.0.1", console.server_address[1], timeout=20)
            try:
                connection.request(method, path, headers=headers or {}, body=body)
                response = connection.getresponse()
                return response.status, dict(response.getheaders()), json.loads(response.read())
            finally:
                connection.close()

        status, headers, _ = request("POST", "/api/v1/login",
            {"Content-Type": "application/json"}, json.dumps({
                "username": "admin", "password": "fixture-password"}))
        assert status == 200
        authenticated = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
        with ThreadPoolExecutor(max_workers=1) as pool:
            with gate.enter():
                status, headers, body = pool.submit(
                    request, "GET", "/api/v1/overview", authenticated).result(timeout=20)
                assert status == 503 and body["code"] == "projection-busy"
                assert headers["Retry-After"] == "1"
                assert len(gate._queue) == 1
            assert request("GET", "/api/v1/overview", authenticated)[0] == 200
        assert not management._request_lifecycle_state()["failed"]
    finally:
        for server, thread in reversed(servers):
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
