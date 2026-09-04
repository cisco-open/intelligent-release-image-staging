# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

import pytest

import api_problem
import api_routes
import artifact_server
import catalog
import gui_server
import management_api
import secrets_store
import telemetry
import tracker


def _write_secret(path, value, scope="management"):
    path.write_text(json.dumps({"scope": scope, "token": value}),
                    encoding="utf-8")
    path.chmod(0o600)


def _certificate(tmp_path, stem="tls"):
    cert = tmp_path / (stem + ".crt")
    key = tmp_path / (stem + ".key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return cert, key


def _thread(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _request(port, path, method="GET", headers=None, body=None, https=False):
    cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
    kwargs = ({"context": ssl._create_unverified_context()} if https else {})
    conn = cls("127.0.0.1", port, timeout=5, **kwargs)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    result = (response.status, dict(response.getheaders()), response.read())
    conn.close()
    return result


def test_bff_probe_body_matches_content_length_without_extra_crlf(
        tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    token = tmp_path / "token"
    ca = tmp_path / "ca.pem"
    _write_secret(token, "m" * 64)
    ca.write_text("unused for a local probe", encoding="utf-8")
    server = gui_server.make_server(
        "127.0.0.1", 0, "https://localhost:9", str(token), str(ca))
    _thread(server)
    try:
        status, headers, body = _request(server.server_address[1], "/healthz")
        assert status == 200
        assert body == b'{"ok":true}'
        assert int(headers["Content-Length"]) == len(body)
    finally:
        server.shutdown()
        server.server_close()


class _NoSessionApp:
    def session_info(self, sid):
        if sid == "valid":
            return {"username": "admin", "csrf": "csrf"}
        return None


def test_bff_unknown_and_known_routes_authenticate_before_existence(
        tmp_path, monkeypatch):
    cert, key = _certificate(tmp_path, "management")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    management = management_api.make_server(
        "127.0.0.1", 0, _NoSessionApp(), certfile=str(cert),
        keyfile=str(key), management_token_file=str(token))
    _thread(management)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    console = gui_server.make_server(
        "127.0.0.1", 0,
        "https://localhost:%d" % management.server_address[1],
        str(token), str(cert))
    _thread(console)
    try:
        results = [_request(console.server_address[1], path)
                   for path in ("/api/v1/images", "/api/v1/not-a-route",
                                "/api/v1/console-certificate",
                                "/api/v1/authorizations")]
        assert [result[0] for result in results] == [401, 401, 401, 401]
        assert all(result[1]["Content-Type"] == "application/problem+json"
                   for result in results)
        assert [json.loads(result[2])["type"] for result in results] == [
            api_problem.TYPE_BASE + "console-session-required"] * 4
        assert all(b"PRIVATE KEY" not in result[2] for result in results)
        assert api_routes.console_to_management(
            "GET", "/api/v1/console-certificate") == \
            "/internal/v1/__unregistered-browser-route"
        for path in ("/api/v1/console-certificate",
                     "/api/v1/authorizations"):
            status, headers, body = _request(
                console.server_address[1], path,
                headers={"Cookie": "iris_sid=valid"})
            assert status == 404
            assert headers["Content-Type"] == "application/problem+json"
            assert b"PRIVATE KEY" not in body
        # Arbitrary method tokens take the same authenticated path instead of
        # BaseHTTPRequestHandler's pre-auth stock 501.
        assert _request(console.server_address[1], "/api/v1/images",
                        method="TRACE")[0] == 401
        for method in ("POST", "TRACE"):
            assert _request(console.server_address[1], "/swarmmap",
                            method=method)[0] == 401
            assert api_routes.console_to_management(
                method, "/swarmmap") == \
                "/internal/v1/__unregistered-browser-route"

        # A rejected upload receives its verdict from headers alone.  Do not
        # send the declared body: a drain-before-401 bug would time out here.
        raw = socket.create_connection(
            ("127.0.0.1", console.server_address[1]), timeout=2)
        raw.settimeout(2)
        raw.sendall(
            b"POST /api/v1/images HTTP/1.1\r\nHost: console.example\r\n"
            b"Content-Length: 65536\r\nConnection: close\r\n\r\n")
        assert b" 401 " in raw.recv(4096).split(b"\r\n", 1)[0]
        raw.close()

        # Login has no session gate, but its body is still capped before the
        # BFF reads or streams a byte. A huge declaration with no body must
        # receive 413 immediately rather than pinning a worker.
        raw = socket.create_connection(
            ("127.0.0.1", console.server_address[1]), timeout=2)
        raw.settimeout(2)
        raw.sendall(
            b"POST /api/v1/login HTTP/1.1\r\nHost: console.example\r\n"
            b"Content-Type: application/json\r\nContent-Length: 1048576\r\n"
            b"Connection: close\r\n\r\n")
        assert b" 413 " in raw.recv(4096).split(b"\r\n", 1)[0]
        raw.close()
    finally:
        console.shutdown()
        console.server_close()
        management.shutdown()
        management.server_close()


def test_bff_rejects_ambiguous_framing_and_forwards_one_validated_length(
        tmp_path, monkeypatch):
    cert, key = _certificate(tmp_path, "framing-management")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    actual_headers = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            if self.path.endswith("/internal/v1/authorizations"):
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            actual_headers.append({
                "lengths": self.headers.get_all("Content-Length", []),
                "transfer_encoding": self.headers.get_all(
                    "Transfer-Encoding", []),
            })
            body = b'{}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    backend.socket = context.wrap_socket(backend.socket, server_side=True)
    _thread(backend)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    console = gui_server.make_server(
        "127.0.0.1", 0,
        "https://localhost:%d" % backend.server_address[1],
        str(token), str(cert))
    _thread(console)

    def raw_status(headers_and_body):
        sock = socket.create_connection(
            ("127.0.0.1", console.server_address[1]), timeout=2)
        sock.settimeout(2)
        try:
            sock.sendall(
                b"POST /api/v1/login HTTP/1.1\r\n"
                b"Host: console.example\r\nConnection: close\r\n" +
                headers_and_body)
            return int(sock.recv(4096).split(b" ", 2)[1])
        finally:
            sock.close()

    try:
        assert raw_status(
            b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}") == 400
        assert raw_status(
            b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n"
            b"2\r\n{}\r\n0\r\n\r\n") == 400
        assert actual_headers == []

        status, _, _ = _request(
            console.server_address[1], "/api/v1/login", method="POST",
            headers={"Content-Type": "application/json"}, body=b"{}")
        assert status == 200
        assert actual_headers == [{"lengths": ["2"],
                                   "transfer_encoding": []}]
    finally:
        console.shutdown()
        console.server_close()
        backend.shutdown()
        backend.server_close()


def test_split_login_cookie_follows_public_bff_scheme_not_tls_backend(
        tmp_path, monkeypatch):
    cert, key = _certificate(tmp_path, "cookie-management")
    combined = tmp_path / "console.pem"
    combined.write_bytes(cert.read_bytes() + key.read_bytes())
    combined.chmod(0o600)
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    app = management_api.gui_app.GuiApp(str(tmp_path / "gui-secrets.json"))
    app.set_admin("admin", "password-for-test")
    management = management_api.make_server(
        "127.0.0.1", 0, app, certfile=str(cert), keyfile=str(key),
        management_token_file=str(token))
    _thread(management)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    plain = gui_server.make_server(
        "127.0.0.1", 0,
        "https://localhost:%d" % management.server_address[1],
        str(token), str(cert))
    tls = gui_server.make_server(
        "127.0.0.1", 0,
        "https://localhost:%d" % management.server_address[1],
        str(token), str(cert), certfile=str(combined))
    _thread(plain)
    _thread(tls)
    payload = json.dumps({"username": "admin",
                          "password": "password-for-test"}).encode()
    headers = {"Content-Type": "application/json",
               # Both spoof attempts must be overwritten by the BFF.
               "X-IRIS-Client-Scheme": "https"}
    try:
        status, response_headers, _ = _request(
            plain.server_address[1], "/api/v1/login", method="POST",
            headers=headers, body=payload)
        assert status == 200
        assert "Secure" not in response_headers["Set-Cookie"]

        headers["X-IRIS-Client-Scheme"] = "http"
        status, response_headers, _ = _request(
            tls.server_address[1], "/api/v1/login", method="POST",
            headers=headers, body=payload, https=True)
        assert status == 200
        assert "Secure" in response_headers["Set-Cookie"]
    finally:
        plain.shutdown()
        plain.server_close()
        tls.shutdown()
        tls.server_close()
        management.shutdown()
        management.server_close()


def test_console_certificate_uses_default_only_on_transport_failure(tmp_path):
    cert, key = _certificate(tmp_path, "console-default")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    output = tmp_path / "runtime.pem"
    # Port 1 is not a product listener and is closed in the isolated test
    # environment. Transport failure may use the independent default.
    source = gui_server.fetch_console_certificate(
        "https://localhost:1", str(token), str(cert), str(output), timeout=1,
        default_certfile=str(cert), default_keyfile=str(key))
    assert source == "default"
    assert b"PRIVATE KEY" in output.read_bytes()


def test_console_certificate_does_not_mask_authenticated_bad_response(
        tmp_path):
    cert, key = _certificate(tmp_path, "bad-api")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)

    class BadHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"not a certificate"
            self.send_response(200)
            self.send_header("X-IRIS-Certificate-Source", "custom")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BadHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    backend.socket = context.wrap_socket(backend.socket, server_side=True)
    _thread(backend)
    output = tmp_path / "runtime.pem"
    try:
        with pytest.raises(gui_server.ConsoleConfigurationError):
            gui_server.fetch_console_certificate(
                "https://localhost:%d" % backend.server_address[1],
                str(token), str(cert), str(output),
                default_certfile=str(cert), default_keyfile=str(key))
        assert not output.exists()
    finally:
        backend.shutdown()
        backend.server_close()


def test_metrics_authentication_precedes_disabled_route_existence(tmp_path):
    token = tmp_path / "observability"
    _write_secret(token, "o" * 64, scope="observability")
    server = telemetry.make_metrics_server(
        "127.0.0.1", 0, provider=None,
        observability_token_file=str(token))
    _thread(server)
    try:
        port = server.server_address[1]
        assert _request(port, "/metrics")[0] == 401
        assert _request(port, "/metrics", headers={
            "Authorization": "Bearer " + "o" * 64})[0] == 404
        assert _request(port, "/metrics", method="POST")[0] == 401
        assert _request(port, "/metrics", method="POST", headers={
            "Authorization": "Bearer " + "o" * 64})[0] == 405
        assert _request(port, "/metrics", method="TRACE")[0] == 401
    finally:
        server.shutdown()
        server.server_close()


def test_telemetry_tls_encrypts_probes_and_bearer_routes(tmp_path):
    cert, key = _certificate(tmp_path, "telemetry")
    token = tmp_path / "observability"
    _write_secret(token, "o" * 64, scope="observability")
    server = telemetry.make_metrics_server(
        "127.0.0.1", 0, provider=lambda: "metric 1\n",
        observability_token_file=str(token), certfile=str(cert),
        keyfile=str(key), listeners={"missing": 1})
    _thread(server)
    try:
        port = server.server_address[1]
        assert _request(port, "/healthz", https=True)[0] == 200
        assert _request(port, "/metrics", https=True, headers={
            "Authorization": "Bearer " + "o" * 64})[0] == 200
        status, headers, body = _request(port, "/readyz", https=True)
        assert status == 503
        assert headers["Retry-After"] == "1"
        assert json.loads(body) == {"ok": False}
        with pytest.raises((http.client.HTTPException, ConnectionError,
                            OSError)):
            _request(port, "/healthz")
    finally:
        server.shutdown()
        server.server_close()


def test_catalog_images_and_torrents_are_assignment_bound(tmp_path):
    secret_path = tmp_path / "secrets.json"
    values = secrets_store.load(str(secret_path))
    now = time.time()
    token1 = secrets_store.mint(values, "d1", "catalog_token", now)
    token2 = secrets_store.mint(values, "d2", "catalog_token", now)
    secrets_store.mint(values, "d1", "announce_token", now)
    secrets_store.mint(values, "d2", "announce_token", now)
    secrets_store.save(values, str(secret_path))
    store = catalog.CatalogStore(str(tmp_path / "state"))
    for image_id in ("one", "two"):
        store.save_image({"id": image_id, "filename": image_id + ".bin",
                          "size": 1, "sha256": "ab" * 32,
                          "info_hash_hex": "cd" * 20,
                          "published_at": 1})
        Path(store.torrent_path(image_id)).write_bytes(b"d4:infod4:name1:xee")
    store.set_policy("d1", approved_image_id="one")
    store.set_policy("d2", approved_image_id="two")
    server = catalog.make_server(
        "127.0.0.1", 0, store, str(secret_path))
    _thread(server)
    try:
        port = server.server_address[1]
        auth1 = {"Authorization": "Bearer " + token1}
        auth2 = {"Authorization": "Bearer " + token2}
        status, _, body = _request(port, "/v1/images", headers=auth1)
        assert status == 200
        assert [row["id"] for row in json.loads(body)["images"]] == ["one"]
        assert _request(port, "/v1/images/two", headers=auth1)[0] == 404
        assert _request(port, "/v1/torrents/two.torrent", headers=auth1)[0] == 404
        assert _request(port, "/v1/images/two", headers=auth2)[0] == 200
        assert _request(
            port, "/v1/devices/d2/policy?cache_bust=1",
            headers=auth1)[0] == 401
        # Authentication precedes existence for both known and invented ids.
        assert _request(port, "/v1/images/one")[0] == 401
        assert _request(port, "/v1/images/absent")[0] == 401
    finally:
        server.shutdown()
        server.server_close()


def test_artifact_staging_resource_is_bound_to_basic_principal(tmp_path):
    secret_path = tmp_path / "secrets.json"
    values = secrets_store.load(str(secret_path))
    now = time.time()
    token1 = secrets_store.mint(values, "d1", "catalog_token", now)
    secrets_store.mint(values, "d2", "catalog_token", now)
    secrets_store.save(values, str(secret_path))
    root = tmp_path / "artifacts"
    for device in ("d1", "d2"):
        directory = root / "staging" / device
        directory.mkdir(parents=True)
        target = directory / ("iris-agent-%s.conf" % device)
        target.write_text("device=" + device, encoding="utf-8")
        target.chmod(0o600)
    server = artifact_server.make_server(
        "127.0.0.1", 0, str(root), secrets_path=str(secret_path),
        token_grace=10**12)
    _thread(server)
    basic = base64.b64encode(("d1:" + token1).encode()).decode()
    try:
        port = server.server_address[1]
        headers = {"Authorization": "Basic " + basic}
        own = "/v1/devices/d1/artifacts/staging/d1/iris-agent-d1.conf"
        other = "/v1/devices/d1/artifacts/staging/d2/iris-agent-d2.conf"
        encoded_escape = ("/v1/devices/d1/artifacts/staging/d1/"
                          "%252e%252e%252fd2%252firis-agent-d2.conf")
        status, own_headers, _ = _request(port, own, headers=headers)
        assert status == 200
        assert own_headers["Cache-Control"] == "private, no-store"
        status, response_headers, _ = _request(port, other, headers=headers)
        assert status == 403
        assert response_headers["Content-Type"] == "application/problem+json"
        assert _request(port, encoded_escape, headers=headers)[0] == 403
        assert _request(port, own)[0] == 401
        assert _request(port, "/v1/devices/d1/artifacts/missing")[0] == 401
        assert _request(port, own, method="POST")[0] == 401
        assert _request(port, own, method="POST", headers=headers)[0] == 405
        assert _request(port, own, method="TRACE")[0] == 401
    finally:
        server.shutdown()
        server.server_close()


def test_guest_shell_legacy_artifacts_are_narrow_and_not_cacheable(tmp_path):
    """Keep unchanged IOS copy HTTPS paths without reopening arbitrary files."""
    secret_path = tmp_path / "secrets.json"
    secrets_store.save(secrets_store.load(str(secret_path)), str(secret_path))
    root = tmp_path / "artifacts"
    staging = root / "staging"
    staging.mkdir(parents=True)
    (root / "bootstrap.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "private.txt").write_text("not public", encoding="utf-8")
    capability = "iris-agent-d1-" + "ab" * 16 + ".conf"
    staged = staging / capability
    staged.write_text("catalog_token=secret\n", encoding="utf-8")
    staged.chmod(0o600)
    server = artifact_server.make_server(
        "127.0.0.1", 0, str(root), secrets_path=str(secret_path))
    _thread(server)
    try:
        port = server.server_address[1]
        status, headers, _ = _request(port, "/bootstrap.sh")
        assert status == 200
        assert headers["Deprecation"] == "true"
        status, headers, body = _request(
            port, "/%73taging/" + capability)
        assert status == 200
        assert body == b"catalog_token=secret\n"
        assert headers["Cache-Control"] == "private, no-store"
        assert headers["Deprecation"] == "true"
        assert _request(port, "/private.txt")[0] == 401
        assert _request(port, "/staging/not-a-capability.conf")[0] == 401
    finally:
        server.shutdown()
        server.server_close()


def test_route_registry_does_not_widen_guest_shell_staging_capabilities():
    assert api_routes.match(
        "artifact", "GET",
        "/staging/iris-agent-edge-01-0123456789abcdef0123456789abcdef.conf")
    assert api_routes.match(
        "artifact", "HEAD",
        "/staging/rpc-secret-0123456789abcdef0123456789abcdef")
    assert api_routes.match(
        "artifact", "GET", "/staging/not-a-capability.conf") is None


def test_list_devices_get_is_side_effect_free(tmp_path):
    store = catalog.CatalogStore(str(tmp_path / "state"))
    store.record_heartbeat("d1", {"stage_state": "idle"}, now=1)
    store._pulls.put("d1", {"request_id": "a" * 32,
                            "requested_at": 1, "expires_at": 2})
    before = store._pulls.get("d1")
    assert store.list_devices(now=999)[0]["device_id"] == "d1"
    assert store._pulls.get("d1") == before


def test_versioned_staging_log_path_redacts_filename():
    secret_name = "iris-agent-d1-" + "f" * 64 + ".conf"
    rendered = artifact_server.redact_log_path(
        "/v1/devices/d1/artifacts/staging/d1/" + secret_name)
    assert rendered == "/v1/devices/<device_id>/artifacts/staging/<redacted>"
    assert secret_name not in rendered
    legacy = "iris-agent-d1-" + "ab" * 16 + ".conf"
    assert legacy not in artifact_server.redact_log_path(
        "/%73taging/" + legacy)
    assert secret_name not in artifact_server.redact_log_path(
        "/v1/devices/d1/artifacts/staging%2Fd1%2F" + secret_name)


def test_unsupported_methods_authenticate_first_across_services(tmp_path):
    now = time.time()
    secret_path = tmp_path / "secrets.json"
    values = secrets_store.load(str(secret_path))
    catalog_token = secrets_store.mint(
        values, "d1", "catalog_token", now)
    announce_token = secrets_store.mint(
        values, "d1", "announce_token", now)
    secrets_store.save(values, str(secret_path))

    store = catalog.CatalogStore(str(tmp_path / "state"))
    catalog_server = catalog.make_server(
        "127.0.0.1", 0, store, str(secret_path))
    tracker_server = tracker.make_server(
        "127.0.0.1", 0, str(secret_path))
    _thread(catalog_server)
    _thread(tracker_server)
    try:
        cport = catalog_server.server_address[1]
        tport = tracker_server.server_address[1]
        assert _request(cport, "/v1/images", method="PUT")[0] == 401
        assert _request(cport, "/v1/images", method="PUT", headers={
            "Authorization": "Bearer " + catalog_token})[0] == 405
        assert _request(cport, "/v1/images", method="TRACE")[0] == 401
        # No Authorization header follows unchanged Guest Shell query-auth
        # semantics; the legacy tracker has historically answered 403.
        assert _request(tport, "/announce", method="POST")[0] == 403
        status, headers, _ = _request(
            tport, "/announce", method="POST", headers={
                "Authorization": "Bearer " + announce_token})
        assert status == 405
        assert headers["Content-Type"] == "text/plain"
        assert _request(tport, "/announce", method="TRACE")[0] == 403
        # Guest Shell query auth remains available, but any Authorization
        # header takes precedence and cannot downgrade to the URL credential.
        legacy_path = "/announce?announce_token=" + announce_token
        status, headers, _ = _request(tport, legacy_path)
        assert status == 400  # authenticated before malformed BEP payload
        assert headers["Deprecation"] == "true"
        status, headers, _ = _request(tport, legacy_path, headers={
            "Authorization": "Bearer invalid-but-present"})
        assert status == 401
        assert "Deprecation" not in headers
        secret_path.write_text("{not json", encoding="utf-8")
        status, headers, _ = _request(tport, "/announce", headers={
            "Authorization": "Bearer " + announce_token})
        assert status == 503
        assert headers["Retry-After"] == "1"
    finally:
        catalog_server.shutdown()
        catalog_server.server_close()
        tracker_server.shutdown()
        tracker_server.server_close()
