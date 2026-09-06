# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Console behavior while independently mounted tier tokens change order."""

import http.client
import http.server
import json
import socket
import ssl
import subprocess
import threading
from types import SimpleNamespace

import pytest

import api_problem
import gui_server


CURRENT = "new-management-token-" + "n" * 48
PREVIOUS = "old-management-token-" + "o" * 48


def _secret(path, value):
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _certificate(path, stem):
    cert, key = path / (stem + ".crt"), path / (stem + ".key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return cert, key


def _problem(code="management-authentication-required", status=401):
    return json.dumps(api_problem.document(status, code, "Rejected")).encode()


@pytest.fixture
def overlap(tmp_path, monkeypatch):
    cert, key = _certificate(tmp_path, "management")
    current, previous = tmp_path / "current", tmp_path / "previous"
    _secret(current, CURRENT)
    _secret(previous, PREVIOUS)
    state = SimpleNamespace(
        accepted={PREVIOUS}, calls=[], bodies=[], failure=None,
        preflight_failure=None, after_preflight=None, reject_mutation=False)

    class Backend(http.server.BaseHTTPRequestHandler):
        def respond(self, status, body=b"", content_type="application/json",
                    challenge=None):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", content_type)
            if challenge is not None:
                self.send_header("WWW-Authenticate", challenge)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def run_request(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            state.calls.append((self.command, self.path, token))
            if token not in state.accepted:
                self.respond(*(state.failure or (
                    401, _problem(), "application/problem+json", "Bearer")))
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/internal/v1/authorizations":
                if state.preflight_failure is not None:
                    self.respond(*state.preflight_failure)
                    return
                if state.after_preflight is not None:
                    state.after_preflight()
                self.respond(204)
                return
            state.bodies.append(body)
            if state.reject_mutation and self.command == "PUT":
                self.respond(401, _problem(), "application/problem+json", "Bearer")
            else:
                self.respond(200, json.dumps({"received": len(body)}).encode())

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = run_request

        def log_message(self, *_args):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    backend.socket = context.wrap_socket(backend.socket, server_side=True)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    url = "https://localhost:%d" % backend.server_address[1]
    console = gui_server.make_server(
        "127.0.0.1", 0, url, str(current), str(cert),
        previous_token_file=str(previous))
    threading.Thread(target=console.serve_forever, daemon=True).start()
    state.current, state.previous, state.cert = current, previous, cert
    state.url, state.console = url, console

    def request(method="GET", path="/api/v1/session", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", console.server_address[1],
                                          timeout=3)
        try:
            conn.request(method, path, body=body)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    state.request = request
    yield state
    console.shutdown()
    console.server_close()
    backend.shutdown()
    backend.server_close()


def test_get_uses_previous_only_after_explicit_tier_rejection(overlap):
    assert overlap.request()[0] == 200
    assert [call[2] for call in overlap.calls] == [CURRENT, PREVIOUS]
    assert overlap.bodies == [b""]


@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "HEAD"])
def test_authorization_selects_token_for_one_forwarded_request(overlap, method):
    body = b"a streamed upload" * (8192 if method == "PUT" else 32)
    if method == "HEAD":
        body = None
    status, response = overlap.request(method, "/api/v1/images/upload/example", body)
    assert status == 200
    assert [call[2] for call in overlap.calls] == [CURRENT, PREVIOUS, PREVIOUS]
    assert [call[1] for call in overlap.calls[:2]] == [
        "/internal/v1/authorizations"] * 2
    assert overlap.bodies == [body or b""]
    if method == "HEAD":
        assert response == b""


@pytest.mark.parametrize("selected", [CURRENT, PREVIOUS])
def test_preflight_credential_is_pinned_when_files_change(overlap, selected):
    overlap.accepted = {selected}

    def change_projection():
        _secret(overlap.current, "unaccepted-replacement-" + "x" * 48)
        overlap.previous.write_text("")

    overlap.after_preflight = change_projection
    body = b"one browser body"
    assert overlap.request("PUT", "/api/v1/images/upload/example", body)[0] == 200
    assert overlap.calls[-1][2] == selected
    assert overlap.bodies == [body]


def test_final_mutation_tier_rejection_does_not_replay_upload(overlap):
    overlap.reject_mutation = True
    body = b"never replay this upload" * 16384
    status, response = overlap.request("PUT", "/api/v1/images/upload/example", body)
    assert status == 401
    assert json.loads(response)["type"].endswith("management-authentication-required")
    assert [call[2] for call in overlap.calls] == [CURRENT, PREVIOUS, PREVIOUS]
    assert overlap.bodies == [body]


def test_keepalive_requests_select_credentials_independently(overlap, monkeypatch):
    monkeypatch.setattr(overlap.console.RequestHandlerClass, "protocol_version", "HTTP/1.1")
    conn = http.client.HTTPConnection(*overlap.console.server_address, timeout=3)
    try:
        conn.request("PUT", "/api/v1/images/upload/example", body=b"first")
        response = conn.getresponse()
        assert response.status == 200
        response.read()
        first_socket = conn.sock
        overlap.accepted = {CURRENT}
        overlap.previous.write_text("")
        conn.request("PUT", "/api/v1/images/upload/example", body=b"second")
        response = conn.getresponse()
        assert response.status == 200
        response.read()
        assert conn.sock is first_socket
    finally:
        conn.close()
    assert [call[2] for call in overlap.calls] == [
        CURRENT, PREVIOUS, PREVIOUS, CURRENT, CURRENT]
    assert overlap.bodies == [b"first", b"second"]


@pytest.mark.parametrize("status,code", [
    (401, "console-session-required"), (403, "csrf-validation-failed"),
])
def test_preflight_rejects_before_reading_any_browser_body(overlap, status, code):
    overlap.preflight_failure = (status, _problem(code, status),
                                 "application/problem+json")
    with socket.create_connection(overlap.console.server_address, timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"PUT /api/v1/images/upload/example HTTP/1.1\r\n"
                     b"Host: console.example\r\nContent-Length: 268435456\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == status
        assert json.loads(response.read())["type"].endswith(code)
    assert [call[2] for call in overlap.calls] == [CURRENT, PREVIOUS]
    assert overlap.bodies == []


@pytest.mark.parametrize("failure", [
    (401, _problem("console-session-required"), "application/problem+json", "Bearer"),
    (401, _problem(), "application/problem+json", None),
    (401, _problem(), "application/json", "Bearer"),
    (401, b"not json", "application/problem+json", "Bearer"),
    (401, b"[]", "application/problem+json", "Bearer"),
    (401, _problem() + b" " * 65536, "application/problem+json", "Bearer"),
    (403, _problem(status=403), "application/problem+json", "Bearer"),
    (503, _problem(status=503), "application/problem+json", "Bearer"),
])
def test_other_responses_are_preserved_without_credential_retry(overlap, failure):
    overlap.failure = failure
    status, body = overlap.request()
    assert (status, body) == failure[:2]
    assert [call[2] for call in overlap.calls] == [CURRENT]


def test_retry_is_bounded_when_both_tokens_are_rejected(overlap):
    overlap.accepted = set()
    assert overlap.request()[0] == 401
    assert [call[2] for call in overlap.calls] == [CURRENT, PREVIOUS]


@pytest.mark.parametrize("retirement", ["empty", "missing", "same-current"])
def test_retired_previous_is_not_reused(overlap, retirement):
    assert overlap.request()[0] == 200
    if retirement == "missing":
        overlap.previous.unlink()
    else:
        overlap.previous.write_text(CURRENT if retirement == "same-current" else "")
    overlap.calls.clear()
    assert overlap.request()[0] == 401
    assert [call[2] for call in overlap.calls] == [CURRENT]
    overlap.accepted = {CURRENT}
    overlap.calls.clear()
    assert overlap.request()[0] == 200
    assert [call[2] for call in overlap.calls] == [CURRENT]


@pytest.mark.parametrize("which", ["current", "previous"])
@pytest.mark.parametrize("malformation", [
    "short", "wrong-scope", "oversized", "world-readable", "utf8",
    "newline", "whitespace", "control", "non-ascii", "json-newline", "json-surrogate",
])
def test_invalid_credential_files_fail_before_any_upstream_request(
        overlap, which, malformation, capsys):
    path = getattr(overlap, which)
    if malformation == "world-readable":
        path.chmod(0o644)
    elif malformation == "utf8":
        path.write_bytes(b"\xff" * 64)
    else:
        path.write_text({
            "short": "short", "wrong-scope": json.dumps({"scope": "device", "token": CURRENT}),
            "oversized": "x" * 4097,
            "newline": CURRENT + "\r\nInjected: secret",
            "whitespace": CURRENT + " secret",
            "control": CURRENT + "\x7fsecret",
            "non-ascii": CURRENT + "\u2603secret",
            "json-newline": json.dumps({"scope": "management", "token": CURRENT + "\r\nInjected: secret"}),
            "json-surrogate": json.dumps({"scope": "management", "token": CURRENT + "\ud800"}),
        }[malformation])
    status, body = overlap.request()
    ready_status, ready_body = overlap.request(path="/readyz")
    assert (status, ready_status) == (503, 503)
    assert json.loads(body)["type"].endswith("management-api-unavailable")
    assert overlap.calls == []
    captured = capsys.readouterr()
    exposed = body + ready_body + captured.out.encode() + captured.err.encode()
    assert CURRENT.encode() not in exposed
    assert PREVIOUS.encode() not in exposed
    assert b"Injected" not in exposed


@pytest.mark.parametrize("failure", ["untrusted-ca", "connection-refused"])
def test_transport_failures_do_not_try_another_credential(overlap, tmp_path, monkeypatch, failure):
    connects = []
    original = http.client.HTTPSConnection.connect

    def connect(conn):
        connects.append((conn.host, conn.port))
        return original(conn)

    monkeypatch.setattr(http.client.HTTPSConnection, "connect", connect)
    if failure == "untrusted-ca":
        other_cert, _ = _certificate(tmp_path, "untrusted")
        context = ssl.create_default_context(cafile=str(other_cert))
        monkeypatch.setattr(gui_server, "_tls_client_context", lambda _path: context)
        assert overlap.request()[0] == 503
    else:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with pytest.raises(gui_server.ConsoleConfigurationError):
            gui_server.fetch_console_certificate(
                "https://localhost:%d" % port, str(overlap.current),
                str(overlap.cert), str(tmp_path / "unused.pem"),
                previous_token_file=str(overlap.previous))
    assert len(connects) == 1
    assert overlap.calls == []


def test_main_passes_previous_mount_to_startup_and_runtime(monkeypatch):
    observed = []
    monkeypatch.setenv("IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE", "/run/tokens/previous")
    monkeypatch.setenv("IRIS_MANAGEMENT_API_TOKEN_FILE", "/run/tokens/current")
    monkeypatch.delenv("IRIS_GUI_ALLOW_PLAINTEXT", raising=False)

    def fetch(*args, **kwargs):
        observed.append(("fetch", args, kwargs))
        return "default"

    def make(*args, **kwargs):
        observed.append(("server", args, kwargs))
        return SimpleNamespace(serve_forever=lambda: None)

    monkeypatch.setattr(gui_server, "fetch_console_certificate", fetch)
    monkeypatch.setattr(gui_server, "make_server", make)
    gui_server.main()
    assert [item[0] for item in observed] == ["fetch", "server"]
    assert all(item[2]["previous_token_file"] == "/run/tokens/previous"
               for item in observed)
