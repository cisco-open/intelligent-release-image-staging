# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
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


def test_bulk_role_uses_the_supported_fleet_body_cap_on_the_bff():
    """A 10,000-id role request is the same bounded shape as bulk credential;
    the state-free tier must accept the 2 MiB request the state owner accepts."""
    assert gui_server._body_limit(
        "/internal/v1/devices/bulk-role") == 2 * 1024 * 1024
    assert gui_server._body_limit(
        "/internal/v1/devices/bulk-role") > gui_server._MAX_BODY


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


def test_management_does_not_fall_back_to_device_certificate(tmp_path, monkeypatch):
    device_cert, device_key = _certificate(tmp_path, "device")
    combined = tmp_path / "device.pem"
    combined.write_bytes(device_cert.read_bytes() + device_key.read_bytes())
    monkeypatch.setenv("IRIS_CERT", str(combined))
    broken = tmp_path / "management.pem"
    broken.write_text("invalid management certificate")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    with pytest.raises(management_api.ConsoleTLSError):
        management_api.make_server(
            "127.0.0.1", 0, _NoSessionApp(), certfile=str(broken),
            management_token_file=str(token))


@pytest.mark.parametrize("projection_order", ["current-only", "server-first", "console-first"])
def test_remote_console_reports_and_reloads_its_own_certificate(
        tmp_path, monkeypatch, projection_order):
    management_cert, management_key = _certificate(tmp_path, "management")
    default_cert, default_key = _certificate(tmp_path, "browser-default")
    custom_cert, custom_key = _certificate(tmp_path, "browser-custom")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    server_token = tmp_path / "server-token"
    server_previous = tmp_path / "server-previous"
    console_previous = tmp_path / "console-previous"
    _write_secret(server_token, "t" * 64)
    if projection_order == "server-first":
        _write_secret(server_token, "n" * 64)
        _write_secret(server_previous, "t" * 64)
    elif projection_order == "console-first":
        _write_secret(token, "n" * 64)
        _write_secret(console_previous, "t" * 64)
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_GUI_CERT", str(tmp_path / "server-custom.pem"))
    monkeypatch.setenv("IRIS_CERT", str(management_cert))
    monkeypatch.setenv("IRIS_TRUST_DIR", str(tmp_path / "trust"))
    monkeypatch.setenv("IRIS_CONSOLE_URL", "https://console.example.com:8080")
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    app = management_api.gui_app.GuiApp(str(tmp_path / "gui-secrets.json"))
    app.set_admin("admin", "password-for-test")
    management = management_api.make_server(
        "127.0.0.1", 0, app, certfile=str(management_cert),
        keyfile=str(management_key), management_token_file=str(server_token),
        management_previous_token_file=str(server_previous))
    _thread(management)
    backend = "https://localhost:%d" % management.server_address[1]
    runtime = tmp_path / "console-runtime.pem"
    gui_server.fetch_console_certificate(
        backend, str(token), str(management_cert), str(runtime),
        default_certfile=str(default_cert), default_keyfile=str(default_key),
        previous_token_file=str(console_previous))
    console = gui_server.make_server(
        "127.0.0.1", 0, backend, str(token), str(management_cert),
        certfile=str(runtime), default_certfile=str(default_cert),
        default_keyfile=str(default_key), previous_token_file=str(console_previous))
    _thread(console)
    port = console.server_address[1]

    def fingerprint(cert):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()

    def request(path, method="GET", body=None, headers=None):
        return _request(port, path, method=method, body=body,
                        headers=headers, https=True)

    def served_fingerprint():
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with ssl._create_unverified_context().wrap_socket(
                    sock, server_hostname="localhost") as tls:
                return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()

    try:
        assert request("/api/v1/settings")[0] == 401
        status, login_headers, body = request(
            "/api/v1/login", "POST",
            json.dumps({"username": "admin", "password": "password-for-test"}),
            {"Content-Type": "application/json"})
        assert status == 200
        auth = {"Cookie": login_headers["Set-Cookie"].split(";", 1)[0],
                "X-CSRF-Token": json.loads(body)["csrf"],
                "Content-Type": "application/json"}
        status, headers, body = request("/api/v1/settings", headers=auth)
        assert status == 200
        assert int(headers["Content-Length"]) == len(body)
        settings = json.loads(body)
        assert settings["gui_cert"]["source"] == "built-in"
        assert settings["gui_cert"]["fingerprint_sha256"] == fingerprint(default_cert)
        assert settings["gui_cert"]["fingerprint_sha256"] == served_fingerprint()
        assert settings["console_url"] == "https://console.example.com:8080"
        assert b"PRIVATE KEY" not in body
        status, _, body = request(
            "/api/v1/settings/gui-cert", "POST",
            json.dumps({"cert_pem": custom_cert.read_text(),
                        "key_pem": custom_key.read_text()}), auth)
        assert status == 200
        result = json.loads(body)
        assert result["applied"] is True and result["note"] is None
        assert result["gui_cert"]["source"] == "custom"
        assert result["gui_cert"]["fingerprint_sha256"] == fingerprint(custom_cert)
        assert served_fingerprint() == fingerprint(custom_cert)
        status, _, body = request("/api/v1/settings/gui-cert", "DELETE", headers=auth)
        assert status == 200
        result = json.loads(body)
        assert result["applied"] is True
        assert result["gui_cert"]["source"] == "built-in"
        assert result["gui_cert"]["fingerprint_sha256"] == fingerprint(default_cert)
        assert served_fingerprint() == fingerprint(default_cert)

        # A durable save can succeed while the remote Console fails to fetch it.
        upstream_request = http.client.HTTPSConnection.request
        def unavailable_certificate(self, method, url, *args, **kwargs):
            if url.endswith("/internal/v1/console-certificate"):
                raise OSError("certificate endpoint disconnected")
            return upstream_request(self, method, url, *args, **kwargs)
        monkeypatch.setattr(http.client.HTTPSConnection, "request",
                            unavailable_certificate)
        status, _, body = request(
            "/api/v1/settings/gui-cert", "POST",
            json.dumps({"cert_pem": custom_cert.read_text(),
                        "key_pem": custom_key.read_text()}), auth)
        assert status == 200
        result = json.loads(body)
        assert result["applied"] is False and "restart" in result["note"]
        assert result["gui_cert"]["fingerprint_sha256"] == fingerprint(default_cert)
        assert served_fingerprint() == fingerprint(default_cert)
        assert b"PRIVATE KEY" not in body
    finally:
        console.shutdown()
        console.server_close()
        management.shutdown()
        management.server_close()


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


@pytest.mark.parametrize("fleet_size", [1, 10_000])
def test_artifact_basic_auth_uses_bounded_live_catalog_lookup(
        tmp_path, monkeypatch, fleet_size):
    class LookupOnlyIndex(dict):
        lookups = 0

        def get(self, key, default=None):
            assert isinstance(key, bytes) and len(key) == 32
            self.lookups += 1
            return super().get(key, default)

        def __iter__(self):
            raise AssertionError("artifact authentication scanned the fleet")

        items = keys = values = __iter__

    indexes = []
    original_builder = secrets_store.build_catalog_auth_index

    def bounded_index(store):
        index = LookupOnlyIndex(original_builder(store))
        indexes.append(index)
        return index

    monkeypatch.setattr(secrets_store, "build_catalog_auth_index", bounded_index)
    store = {"devices": {}, "seeder": {}}
    for i in range(fleet_size):
        store["devices"]["d%d" % i] = {"catalog_token": {
            "value": "%032x" % i, "expires_at": 0, "revoked": False}}
    target = store["devices"]["d0"]
    target["catalog_token_prev"] = {
        "value": "previous-catalog-token", "expires_at": 0, "revoked": False}
    target["announce_token"] = {
        "value": "announce-only-token", "expires_at": 0, "revoked": False}
    secret_path = tmp_path / "secrets.json"
    secrets_store.save(store, str(secret_path))
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "iris-agent.tgz").write_bytes(b"test artifact")
    server = artifact_server.make_server(
        "127.0.0.1", 0, str(root), secrets_path=str(secret_path), token_grace=0)
    _thread(server)
    path = "/v1/devices/d0/artifacts/iris-agent.tgz"

    def basic(username, token, expected):
        encoded = base64.b64encode((username + ":" + token).encode()).decode()
        before = sum(index.lookups for index in indexes)
        status, headers, body = _request(
            server.server_address[1], path,
            headers={"Authorization": "Basic " + encoded})
        assert status == expected
        assert sum(index.lookups for index in indexes) - before == 1
        if expected == 200:
            assert body == b"test artifact"
        else:
            assert "WWW-Authenticate" in headers

    try:
        basic("d0", target["catalog_token"]["value"], 200)
        basic("d0", target["catalog_token_prev"]["value"], 200)
        basic("different-device", target["catalog_token"]["value"], 401)
        basic("d0", "unknown-password", 401)
        basic("d0", target["announce_token"]["value"], 401)
        assert len(indexes) == 1
        target["catalog_token"]["expires_at"] = 1
        secrets_store.save(store, str(secret_path))
        basic("d0", target["catalog_token"]["value"], 401)
        target["catalog_token_prev"]["revoked"] = True
        secrets_store.save(store, str(secret_path))
        basic("d0", target["catalog_token_prev"]["value"], 401)
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
    (root / "iris-signers.pem").write_text("public trust\n", encoding="utf-8")
    (root / "private.txt").write_text("not public", encoding="utf-8")
    capability = "iris-agent-d1-" + "ab" * 16 + ".conf"
    staged = staging / capability
    staged.write_text("catalog_token=secret\n", encoding="utf-8")
    staged.chmod(0o600)
    envelope = "iris-instructions-d1-" + "cd" * 16 + ".envelope"
    digest = "bundle-sha256-" + "ef" * 16
    for name, body in ((envelope, b"sealed instructions\n"),
                       (digest, (b"0" * 64) + b"\n")):
        target = staging / name
        target.write_bytes(body)
        target.chmod(0o600)
    server = artifact_server.make_server(
        "127.0.0.1", 0, str(root), secrets_path=str(secret_path))
    _thread(server)
    try:
        port = server.server_address[1]
        status, headers, _ = _request(port, "/bootstrap.sh")
        assert status == 200
        assert headers["Deprecation"] == "true"
        status, headers, body = _request(port, "/iris-signers.pem")
        assert status == 200 and body == b"public trust\n"
        assert headers["Deprecation"] == "true"
        assert _request(port, "/iris-signers.pem", method="HEAD")[0] == 200
        status, headers, body = _request(
            port, "/%73taging/" + capability)
        assert status == 200
        assert body == b"catalog_token=secret\n"
        assert headers["Cache-Control"] == "private, no-store"
        assert headers["Deprecation"] == "true"
        for name in (envelope, digest):
            status, headers, _ = _request(port, "/staging/" + name)
            assert status == 200
            assert headers["Cache-Control"] == "private, no-store"
            assert _request(port, "/staging/" + name, method="HEAD")[0] == 200
        assert _request(port, "/private.txt")[0] == 401
        assert _request(port, "/staging/not-a-capability.conf")[0] == 401
        for near in (
            envelope.replace("cd", "CD"), envelope + ".extra",
            "iris-instructions-d1-" + "a" * 31 + ".envelope",
            digest.replace("ef", "EF"), digest + ".sha256",
            "bundle-sha256-" + "f" * 31,
            "iris-agent.tgz.sha256",
        ):
            assert _request(port, "/staging/" + near)[0] == 401, near
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
        "artifact", "GET",
        "/staging/iris-instructions-edge-01-0123456789abcdef0123456789abcdef.envelope")
    assert api_routes.match(
        "artifact", "HEAD",
        "/staging/bundle-sha256-0123456789abcdef0123456789abcdef")
    assert api_routes.match("artifact", "GET", "/iris-signers.pem")
    assert api_routes.match("artifact", "HEAD", "/iris-signers.pem")
    assert api_routes.match(
        "artifact", "GET", "/staging/not-a-capability.conf") is None
    for path in (
        "/staging/iris-instructions-edge-01-0123456789ABCDEF0123456789ABCDEF.envelope",
        "/staging/iris-instructions-edge-01-0123456789abcdef0123456789abcdef.envelope/extra",
        "/staging/bundle-sha256-0123456789ABCDEF0123456789ABCDEF",
        "/staging/bundle-sha256-0123456789abcdef0123456789abcdef.sha256",
        "/iris-agent.tgz.sha256",
    ):
        assert api_routes.match("artifact", "GET", path) is None, path


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


@pytest.mark.parametrize("method,suffix", [
    ("GET", "/peer-policy/roles"), ("PUT", "/peer-policy/roles/boat"),
    ("DELETE", "/peer-policy/roles/boat"), ("PUT", "/peer-policy/qos"),
    ("POST", "/devices/d1/role"), ("POST", "/devices/bulk-role"),
    ("GET", "/devices/d1/effective-qos"), ("GET", "/peer-policy/explain"),
])
def test_role_qos_routes_map_both_tiers(method, suffix):
    assert api_routes.console_to_management(method, "/api/v1" + suffix) == \
        "/internal/v1" + suffix
    assert api_routes.management_to_legacy(method, "/internal/v1" + suffix) == \
        "/api" + suffix


@pytest.fixture
def policy_tiers(tmp_path, monkeypatch):
    import gui_app
    import gui_fleet
    import peer_policy
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    store = catalog.CatalogStore(str(tmp_path / "state"))
    fleet.upsert({"device_id": "d1", "device_ip": "192.0.2.1"})
    auth_path = os.path.join(store.state_dir, "peer-policy.json")
    lkg_path = os.path.join(store.state_dir, "peer-policy.lkg.json")
    peer_policy.define_role(auth_path, lkg_path, "boat", {"restricted": True}, "test", 1)
    cert, key = _certificate(tmp_path, "role-contract")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    management = management_api.make_server(
        "127.0.0.1", 0, app, fleet=fleet, catalog=store, certfile=str(cert),
        keyfile=str(key), management_token_file=str(token))
    _thread(management)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    console = gui_server.make_server("127.0.0.1", 0,
        "https://localhost:%d" % management.server_address[1], str(token), str(cert))
    _thread(console)
    headers = {}
    def request(tier, method, suffix, body=None, duplicates=False,
                authorized=True, declared_length=None, match=True,
                raw_response=False):
        conn = (http.client.HTTPSConnection("127.0.0.1", management.server_address[1],
                    context=ssl._create_unverified_context(), timeout=3)
                if tier == "management" else http.client.HTTPConnection(
                    "127.0.0.1", console.server_address[1], timeout=3))
        raw = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else b""
        outgoing = dict(headers) if authorized else {}
        if tier == "management":
            outgoing["Authorization"] = "Bearer " + "t" * 64
        if match:
            outgoing["If-Match"] = (management_api._revision_etag("peer-policy",
                peer_policy.load_policy(auth_path, lkg_path).document["revision"])
                if match is True else match)
        conn.putrequest(method, ("/internal/v1" if tier == "management" else "/api/v1") + suffix)
        for key, value in outgoing.items():
            conn.putheader(key, value)
        if duplicates:
            conn.putheader("If-Match", outgoing["If-Match"])
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(raw) if declared_length is None else declared_length))
        conn.endheaders(raw if declared_length is None else None)
        response = conn.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()),
                  data if raw_response else json.loads(data) if data else None)
        conn.close()
        return result
    status, response_headers, login = request("console", "POST", "/login",
        {"username": "admin", "password": "pw"})
    assert status == 200
    headers.update(Cookie=response_headers["Set-Cookie"].split(";", 1)[0])
    headers["X-CSRF-Token"] = login["csrf"]
    yield request, fleet, store
    console.shutdown(); console.server_close()
    management.shutdown(); management.server_close()


@pytest.mark.parametrize("method,suffix,body", [
    ("PUT", "/peer-policy/roles/new", {"restricted": False}),
    ("DELETE", "/peer-policy/roles/boat", {}),
    ("PUT", "/peer-policy/qos", {"qos": {"max_peers": 4}}),
    ("POST", "/devices/d1/role", {"role": "boat"}),
    ("POST", "/devices/bulk-role", {"role": "boat", "device_ids": ["d1"]}),
])
def test_policy_contract_duplicate_match_rejected_at_both_tiers(policy_tiers, method, suffix, body):
    import peer_policy
    request, fleet, store = policy_tiers
    def snapshot():
        return fleet.snapshot(), peer_policy.load_policy(
            os.path.join(store.state_dir, "peer-policy.json"),
            os.path.join(store.state_dir, "peer-policy.lkg.json")).document
    before = snapshot()
    for tier in ("management", "console"):
        status, headers, problem = request(tier, method, suffix + "?dry_run=1", body, duplicates=True)
        assert status == 412, (tier, problem)
        assert problem["code"] == "precondition_failed"
        assert headers["ETag"] == management_api._revision_etag("peer-policy", before[1]["revision"])
        status, _, problem = request(tier, method, suffix, duplicates=True,
                                      authorized=False, declared_length=4096)
        assert status == 401 and problem["code"] == "console-session-required"
    assert snapshot() == before


def test_policy_contract_live_problem_status_code_type_and_headers(policy_tiers):
    from openapi_schema_validator import OAS32Validator
    import openapi_contract
    request, _, _ = policy_tiers
    spec = openapi_contract.build_document()
    cases = [
        ("GET", "/peer-policy/explain?a=d1&b=d1", "/peer-policy/explain", None, {}, 422, "principal_unresolvable"),
        ("GET", "/devices/missing/effective-qos", "/devices/{device_id}/effective-qos", None, {}, 404, "device_not_found"),
        ("PUT", "/peer-policy/qos", "/peer-policy/qos", {"qos": {}, "role": "missing"}, {}, 404, "role_not_found"),
        ("PUT", "/peer-policy/qos", "/peer-policy/qos", {"qos": {"numwant": -1}}, {}, 422, "invalid_policy"),
        ("PUT", "/peer-policy/qos", "/peer-policy/qos", None, {"declared_length": 65537}, 413, "payload-too-large"),
        ("PUT", "/peer-policy/qos", "/peer-policy/qos", {"qos": {}}, {"match": False}, 428, "precondition_required"),
    ]
    for tier in ("management", "console"):
        prefix = "/internal/v1" if tier == "management" else "/api/v1"
        for method, suffix, pattern, body, options, expected, code in cases:
            status, headers, payload = request(tier, method, suffix, body, **options)
            assert (status, payload["code"]) == (expected, code)
            response = spec["paths"][prefix + pattern][method.lower()]["responses"][str(status)]
            assert payload["code"] in response["x-iris-problem-codes"]
            assert payload["type"] == api_problem.TYPE_BASE + payload["code"]
            schema = response["content"]["application/problem+json"]["schema"]
            if "$ref" in schema:
                schema = spec["components"]["schemas"][schema["$ref"].rsplit("/", 1)[-1]]
            OAS32Validator(schema).validate(payload)
            if "ETag" in headers:
                assert "ETag" in response.get("headers", {})


@pytest.mark.parametrize("method,suffix,template,body", [
    ("GET", "/peer-policy/roles", "/peer-policy/roles", None),
    ("GET", "/peer-policy/explain?a=d1&b=d1", "/peer-policy/explain", None),
    ("GET", "/devices/d1/effective-qos", "/devices/{device_id}/effective-qos", None),
    ("PUT", "/peer-policy/roles/boat", "/peer-policy/roles/{name}", {"restricted": True}),
    ("DELETE", "/peer-policy/roles/boat", "/peer-policy/roles/{name}", {}),
    ("PUT", "/peer-policy/qos", "/peer-policy/qos", {"qos": {}}),
    ("POST", "/devices/d1/role", "/devices/{device_id}/role", {"role": None}),
    ("POST", "/devices/bulk-role", "/devices/bulk-role", {"role": None, "device_ids": ["d1"]}),
    ("GET", "/peer-policy", "/peer-policy", None),
])
def test_final_repair_late_session_uses_exact_problem(policy_tiers, monkeypatch, method, suffix, template, body):
    import gui_app
    import openapi_contract
    request, _, _ = policy_tiers
    original = gui_app.GuiApp.session_info
    spec = openapi_contract.build_document()
    for tier in ("management", "console"):
        calls = []
        allowed = 2 if tier == "console" and method != "GET" else 1
        def recheck(app, sid):
            calls.append(sid)
            return original(app, sid) if len(calls) <= allowed else None
        with monkeypatch.context() as patch:
            patch.setattr(gui_app.GuiApp, "session_info", recheck)
            status, _, problem = request(tier, method, suffix, body)
        assert len(calls) == allowed + 1
        assert status == 401 and problem["code"] == "console-session-required"
        assert problem["type"].endswith("#console-session-required")
        prefix = "/internal/v1" if tier == "management" else "/api/v1"
        assert set(spec["paths"][prefix + template][method.lower()]["responses"]["401"]["x-iris-problem-codes"]) == {
            "console-session-required", "management-authentication-required"}


def test_final_repair_null_peers_refuses_both_tiers_without_state(policy_tiers):
    from pathlib import Path
    request, fleet, store = policy_tiers
    def state():
        return {str(p.relative_to(store.state_dir)): p.read_bytes()
                for p in Path(store.state_dir).rglob("*") if p.is_file() and not p.name.endswith(".lock")}
    before = state()
    for tier in ("management", "console"):
        for query in ("", "?dry_run=1"):
            status, _, problem = request(tier, "PUT", "/peer-policy/roles/boat" + query,
                                          {"restricted": True, "peers": None})
            assert status == 422 and problem["code"] == "invalid_policy"
            assert state() == before


def test_final_repair_future_status_view_catchup(policy_tiers):
    from pathlib import Path
    import peer_policy
    import peer_enforcement
    import peer_endpoints
    import tracker
    request, _, store = policy_tiers
    auth_path = str(Path(store.state_dir) / "peer-policy.json")
    lkg_path = str(Path(store.state_dir) / "peer-policy.lkg.json")
    status_path = str(Path(store.state_dir) / "peer-enforcement.json")
    doc = peer_policy.load_policy(auth_path, lkg_path).document
    old = peer_enforcement.build_status("enforced", "s", "h", None, 0, 1000,
        last_operation_exported_revision=doc["revision"] + 2,
        operation_ack_epoch=doc.get("operation_ack_epoch"))
    peer_enforcement.write_status(status_path, old)
    old_bytes = Path(status_path).read_bytes()
    for index, name in enumerate(("fiber", "copper", "mesh")):
        tier = "management" if index % 2 else "console"
        assert request(tier, "PUT", "/peer-policy/roles/" + name, {"restricted": True})[0] == 200
        for read_tier in ("management", "console"):
            view = request(read_tier, "GET", "/peer-policy")[2]
            assert view["outbox"]["unacknowledged"] == index + 2
            assert view["enforcement"]["last_operation_exported_revision"] == 0
        assert Path(status_path).read_bytes() == old_bytes
    class Aria:
        def get_session_id(self): return "s"
        def set_blocklist(self, ips): return {}
    rec = tracker.TrackerReconciler((auth_path, lkg_path),
        str(Path(store.state_dir) / "peer-endpoints.json"), status_path, Aria(),
        peer_endpoints.PendingEndpointQueue(), lambda: [], lambda: set(),
        audit_export=lambda entries: None, now=lambda: 1001)
    rec.run_once()
    assert request("console", "GET", "/peer-policy")[2]["outbox"]["unacknowledged"] == 0
    assert request("management", "PUT", "/peer-policy/roles/last", {"restricted": True})[0] == 200
    assert len(peer_policy.load_policy(auth_path, lkg_path).document["operation_outbox"]) == 1


def test_policy_contract_browser_transport_and_tier_auth_codes(policy_tiers, monkeypatch):
    import openapi_contract
    request, _, _ = policy_tiers
    spec = openapi_contract.build_document()
    operation = spec["paths"]["/api/v1/peer-policy/qos"]["put"]
    with monkeypatch.context() as patch:
        def unavailable(*args):
            raise gui_server.ConsoleConfigurationError("private")
        patch.setattr(gui_server, "_tls_client_context", unavailable)
        status, headers, problem = request("console", "PUT", "/peer-policy/qos", {"qos": {}})
        assert status == 503 and problem["code"] == "management-api-unavailable"
        assert problem["code"] in operation["responses"]["503"]["x-iris-problem-codes"]
        assert headers["Retry-After"] == "1" and "private" not in json.dumps(problem)
    with monkeypatch.context() as patch:
        patch.setattr(gui_server, "_token_pair", lambda *args: ("invalid", None))
        status, _, problem = request("console", "PUT", "/peer-policy/qos", {"qos": {}})
        assert status == 401 and problem["code"] == "management-authentication-required"
        assert problem["code"] in operation["responses"]["401"]["x-iris-problem-codes"]


def _state_qos_paths(store):
    return (os.path.join(store.state_dir, "peer-policy.json"),
            os.path.join(store.state_dir, "peer-policy.lkg.json"))


def _state_qos_document(store):
    import peer_policy
    return peer_policy.load_policy(*_state_qos_paths(store)).document


def _state_qos_durable_bytes(store):
    return {str(path.relative_to(store.state_dir)): path.read_bytes()
            for path in Path(store.state_dir).rglob("*")
            if path.is_file() and not path.name.endswith(".lock")}


def _state_qos_policy_bytes(store):
    # Failed writes may append audit rows. Policy, LKG/ring, roles watermark,
    # embedded outbox, and enforcement acknowledgement bytes must stay fixed.
    return {name: value for name, value in _state_qos_durable_bytes(store).items()
            if name.startswith("peer-policy") or name == "peer-enforcement.json"}


def _state_qos_problem(status, headers, payload, expected, code, revision):
    assert status == expected, payload
    assert payload["code"] == payload["error"] == code
    assert payload["status"] == expected
    assert payload["type"] == api_problem.TYPE_BASE + code
    assert headers["Content-Type"].startswith("application/problem+json")
    assert headers["ETag"] == '"iris-peer-policy-%d"' % revision


@pytest.mark.parametrize("tier", ["management", "console"])
def test_tracker_state_mutations_preserve_clear_confirm_and_expose_both_scopes(
        policy_tiers, tier):
    import copy
    request, _, store = policy_tiers
    assert request(tier, "GET", "/peer-policy")[0] == 200

    def view():
        status, _, payload = request(tier, "GET", "/peer-policy/roles")
        assert status == 200
        return payload

    assert "qos_state_default" not in view()
    assert "qos_state" not in view()["roles"]["boat"]

    def apply(body, path="/peer-policy/qos", check_guards=False):
        prior = _state_qos_document(store)
        before = _state_qos_policy_bytes(store)
        if check_guards:
            for options, status, code in (
                    ({"match": False}, 428, "precondition_required"),
                    ({"match": '"iris-peer-policy-0"'}, 412,
                     "precondition_failed"),
                    ({"duplicates": True}, 412, "precondition_failed")):
                result = request(tier, "PUT", path, body, **options)
                _state_qos_problem(*result, status, code, prior["revision"])
                assert _state_qos_policy_bytes(store) == before
        before_preview = _state_qos_durable_bytes(store)
        status, headers, preview = request(tier, "PUT", path + "?dry_run=1", body)
        assert status == 200, preview
        assert preview["dry_run"] is True and preview["qos_changed"] is True
        assert preview["requires_confirmation"] is True
        assert preview["revision"] == preview["candidate_revision"] == prior["revision"] + 1
        assert headers["ETag"] == '"iris-peer-policy-%d"' % preview["revision"]
        assert all(preview[key] == 0 for key in (
            "member_delta", "origin_access_lost", "empty_permitted_sets",
            "role_pairs_stopped"))
        assert _state_qos_durable_bytes(store) == before_preview
        if check_guards:
            result = request(tier, "PUT", path, body)
            _state_qos_problem(*result, 428, "confirmation_required", prior["revision"])
            altered = copy.deepcopy(body)
            altered["qos_state"]["seeder"]["numwant"] = 9
            altered["confirm_token"] = preview["confirm_token"]
            result = request(tier, "PUT", path, altered)
            _state_qos_problem(*result, 428, "confirmation_required", prior["revision"])
            assert _state_qos_policy_bytes(store) == before
        submitted = dict(body, confirm_token=preview["confirm_token"])
        status, headers, committed = request(tier, "PUT", path, submitted)
        assert status == 200, committed
        assert committed["dry_run"] is False and committed["ok"] is True
        after = _state_qos_document(store)
        assert committed["revision"] == after["revision"] == prior["revision"] + 1
        assert headers["ETag"] == '"iris-peer-policy-%d"' % after["revision"]
        assert after["operation_outbox"][:-1] == prior["operation_outbox"]
        assert after["operation_outbox"][-1]["revision"] == after["revision"]
        assert after["operation_outbox"][-1]["action"] == (
            "set_qos" if path == "/peer-policy/qos" else "define_role")
        return after

    for role in (None, "boat"):
        scope = {} if role is None else {"role": role}
        state = {"seeder": {"announce_min_interval_s": 80, "numwant": 8},
                 "leecher": {"announce_min_interval_s": 140}}

        def layer(document):
            return (document["roles"] if role is None else
                    document["roles"]["defs"][role])

        scalar_key = "qos_default" if role is None else "qos"
        state_key = "qos_state_default" if role is None else "qos_state"
        after = apply(dict(scope, qos={"numwant": 25}, qos_state=state),
                      check_guards=True)
        assert layer(after)[scalar_key] == {"numwant": 25}
        assert layer(after)[state_key] == state
        exposed = view()
        assert (exposed[state_key] if role is None else
                exposed["roles"][role][state_key]) == state

        replacement = {"seeder": {"numwant": 4}}
        # An explicit null role is the same global scope as an omitted role.
        state_scope = {"role": role}
        after = apply(dict(state_scope, qos_state=replacement))
        assert layer(after)[scalar_key] == {"numwant": 25}
        assert layer(after)[state_key] == replacement
        after = apply(dict(scope, qos={"announce_min_interval_s": 90}))
        assert layer(after)[scalar_key] == {"announce_min_interval_s": 90}
        assert layer(after)[state_key] == replacement
        after = apply(dict(scope, qos_state={}))
        assert state_key not in layer(after)
        assert layer(after)[scalar_key] == {"announce_min_interval_s": 90}
        exposed = view()
        assert state_key not in (exposed if role is None else exposed["roles"][role])
        after = apply(dict(scope, qos_state={"seeder": {}}))
        assert layer(after)[state_key] == {"seeder": {}}
        after = apply(dict(scope, qos={}))
        assert layer(after)[scalar_key] == {}
        assert layer(after)[state_key] == {"seeder": {}}

    definition = copy.deepcopy(_state_qos_document(store)["roles"]["defs"]["boat"])
    definition["qos_state"] = {"leecher": {"numwant": 7}}
    after = apply(definition, "/peer-policy/roles/boat")
    assert after["roles"]["defs"]["boat"]["qos_state"] == {"leecher": {"numwant": 7}}
    assert view()["roles"]["boat"]["qos_state"] == {"leecher": {"numwant": 7}}
    definition.pop("qos_state")
    after = apply(definition, "/peer-policy/roles/boat")
    assert "qos_state" not in after["roles"]["defs"]["boat"]
    assert view()["qos_state_default"] == {"seeder": {}}


@pytest.mark.parametrize("tier", ["management", "console"])
def test_tracker_state_put_errors_are_closed_typed_and_atomic(policy_tiers, tier):
    request, _, store = policy_tiers
    assert request(tier, "GET", "/peer-policy")[0] == 200
    revision = _state_qos_document(store)["revision"]
    before = _state_qos_policy_bytes(store)
    # Representative HTTP error mapping; Commit 1 and the schema tests own
    # the exhaustive state/key/type/range matrix.
    invalid = [
        ({"qos_state": None}, "invalid_policy"),
        ({"qos": {"numwant": 25}, "qos_state": None}, "invalid_policy"),
        ({"role": "boat", "qos_state": None}, "invalid_policy"),
        ({"qos_state": []}, "invalid_policy"),
        ({"qos": {"numwant": 25}, "qos_state": {"seeder": {"numwant": 3}}}, "invalid_policy"),
        ({"role": "boat", "qos": {}, "qos_state": {"seed": {}}}, "invalid_policy"),
        ({"qos": None, "qos_state": {}}, "invalid_policy"),
        ({"role": "boat", "qos": {"numwant": 4.0}, "qos_state": {}}, "invalid_policy"),
        ({}, "invalid_policy_request"),
        ({"qos_state": {}, "device_id": "d1"}, "invalid_policy_request"),
        ({"qos_state": {}, "confirm_token": []}, "invalid_policy_request"),
    ]
    for body, code in invalid:
        result = request(tier, "PUT", "/peer-policy/qos", body)
        _state_qos_problem(*result, 422, code, revision)
        assert _state_qos_policy_bytes(store) == before
    before_preview = _state_qos_durable_bytes(store)
    result = request(tier, "PUT", "/peer-policy/qos?dry_run=1", {"qos_state": None})
    _state_qos_problem(*result, 422, "invalid_policy", revision)
    assert _state_qos_durable_bytes(store) == before_preview
    for body in ([], "not-an-object", b"{", b"null"):
        result = request(tier, "PUT", "/peer-policy/qos", body)
        _state_qos_problem(*result, 422, "invalid_policy_request", revision)
    result = request(tier, "PUT", "/peer-policy/qos", {
        "role": "missing", "qos_state": {"seeder": {"numwant": 4}}})
    _state_qos_problem(*result, 404, "role_not_found", revision)
    assert _state_qos_policy_bytes(store) == before


def _state_qos_legacy_rows():
    # Literal accepted scalar wire values, independent of policy compilers.
    values = (
        ("max_peers", 10), ("per_peer_bps", 12500000), ("fanout", 1),
        ("seed_up_bps", 0), ("seed_down_bps", 0), ("leech_up_bps", 0),
        ("leech_down_bps", 0), ("overall_up_bps", 0), ("overall_down_bps", 0),
        ("max_concurrent", 100), ("request_peer_speed_limit_bps", 51200),
        ("announce_min_interval_s", 30), ("numwant", 50), ("handout_budget", 0),
        ("catalog_tick_s", 60), ("telemetry_every_ticks", 1),
        ("telemetry_pause", False), ("on_stale", "defaults"),
        ("origin_up_bps", 0), ("origin_per_torrent_up_bps", 0),
        ("origin_max_peers", 55),
    )
    result = {key: {"value": value, "source": "builtin"} for key, value in values}
    result["numwant"].update(effective_ceiling=50, runtime_request_zero="disabled",
                             constraint_source="pinned-aria2-client")
    result["announce_min_interval_s"].update(
        peerless_leecher_floor_s=120, constraint_source="pinned-aria2-client")
    result["catalog_tick_s"].update(offline_horizon_s=600, heartbeat_always=True)
    return result


@pytest.mark.parametrize("tier", ["management", "console"])
def test_tracker_state_effective_qos_expands_legacy_response_and_closes_query(
        policy_tiers, tier):
    import copy
    import peer_policy
    request, fleet, store = policy_tiers
    paths = _state_qos_paths(store)

    def legacy(device_id, expected_qos):
        revision = _state_qos_document(store)["revision"]
        expected = {"revision": revision, "degraded": False, "fail_closed": False,
                    "device_id": device_id, "qos": expected_qos,
                    "delivery_state": "pre-instructions",
                    "instruction": management_api._instruction_device_projection(
                        {}, False, 0)}
        status, headers, raw = request(tier, "GET", "/devices/%s/effective-qos" % device_id,
                                       raw_response=True)
        assert status == 200
        assert raw == json.dumps(expected).encode("utf-8")
        assert headers["ETag"] == '"iris-peer-policy-%d"' % revision
        return expected

    def queried(device_id, scalar, state, interval, interval_source, numwant, source):
        expected = copy.deepcopy(scalar)
        interval_row = {"value": interval, "source": interval_source}
        if state == "leecher":
            interval_row.update(peerless_leecher_floor_s=120,
                                constraint_source="pinned-aria2-client")
        expected.update(tracker_state=state, tracker_qos={
            "announce_min_interval_s": interval_row,
            "numwant": {"value": numwant, "source": source,
                        "effective_ceiling": min(numwant, 50),
                        "runtime_request_zero": "disabled",
                        "constraint_source": "pinned-aria2-client"}})
        status, headers, payload = request(tier, "GET",
            "/devices/%s/effective-qos?tracker_state=%s" % (device_id, state))
        assert status == 200, payload
        assert payload == expected
        assert headers["ETag"] == '"iris-peer-policy-%d"' % expected["revision"]
        assert payload["qos"]["announce_min_interval_s"]["peerless_leecher_floor_s"] == 120

    builtin = legacy("d1", _state_qos_legacy_rows())
    for state in ("seeder", "leecher"):
        queried("d1", builtin, state, 30, "builtin", 50, "builtin")
    fleet.upsert({"device_id": "d2", "device_ip": "192.0.2.2"})
    peer_policy.set_qos(*paths, {"announce_min_interval_s": 60, "numwant": 60},
                        actor="fixture", now=2)
    peer_policy.set_qos(*paths, {"announce_min_interval_s": 100, "numwant": 80},
                        actor="fixture", now=3, role="boat")
    peer_policy.set_role(*paths, "d1", "boat", actor="fixture", now=4)
    scalar_role = _state_qos_legacy_rows()
    scalar_role["announce_min_interval_s"].update(value=100, source="role:boat")
    scalar_role["numwant"].update(value=80, source="role:boat")
    scalar_role["on_stale"].update(value="keep", source="role:boat")
    scalar_global = _state_qos_legacy_rows()
    scalar_global["announce_min_interval_s"].update(value=60, source="global")
    scalar_global["numwant"].update(value=60, source="global")
    legacy("d1", scalar_role)
    legacy("d2", scalar_global)
    peer_policy.set_qos(*paths, None, actor="fixture", now=5, qos_state={
        "seeder": {"announce_min_interval_s": 80, "numwant": 4},
        "leecher": {"announce_min_interval_s": 180, "numwant": 150}})
    peer_policy.set_qos(*paths, None, actor="fixture", now=6, role="boat", qos_state={
        "seeder": {"announce_min_interval_s": 120}, "leecher": {"numwant": 6}})
    role_view = legacy("d1", scalar_role)
    global_view = legacy("d2", scalar_global)
    queried("d1", role_view, "seeder", 120, "role-state:boat:seeder", 80, "role:boat")
    queried("d1", role_view, "leecher", 100, "role:boat", 6, "role-state:boat:leecher")
    queried("d2", global_view, "seeder", 80, "global-state:seeder", 4, "global-state:seeder")
    queried("d2", global_view, "leecher", 180, "global-state:leecher", 150, "global-state:leecher")
    revision = _state_qos_document(store)["revision"]
    before = _state_qos_durable_bytes(store)
    invalid = ("?tracker_state", "?tracker_state=", "?tracker_state=Seeder",
               "?tracker_state=unknown", "?tracker_state=0",
               "?tracker_state=%20leecher%20", "?other=seeder",
               "?tracker_state=seeder&other=", "?tracker_state=seeder&tracker_state=seeder",
               "?tracker_state=seeder&tracker_state=leecher",
               "?tracker_state=leecher&tracker_state=")
    for query in invalid:
        result = request(tier, "GET", "/devices/d1/effective-qos" + query)
        _state_qos_problem(*result, 422, "invalid_policy_request", revision)
        result = request(tier, "GET", "/devices/missing/effective-qos" + query)
        _state_qos_problem(*result, 404, "device_not_found", revision)
    assert _state_qos_durable_bytes(store) == before
