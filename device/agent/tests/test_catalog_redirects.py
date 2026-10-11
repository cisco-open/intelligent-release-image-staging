# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real loopback requests must stop before forwarding catalog credentials."""
import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import catalog_client


@pytest.fixture(scope="module")
def endpoints(tmp_path_factory):
    directory = tmp_path_factory.mktemp("catalog-redirect-tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "2", "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=localhost", "-addext",
        "subjectAltName=IP:127.0.0.1,DNS:localhost",
    ], check=True, capture_output=True)

    class Handler(BaseHTTPRequestHandler):
        def request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.server.seen.append((self.command, self.path,
                                     self.headers.get("Authorization"), body))
            status, headers, payload = self.server.responses.get(
                self.path, (200, {}, b'{"ok":true}'))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            if not self.server.omit_length:
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass  # A bounded client may close before consuming the body.

        do_GET = request
        do_POST = request

        def log_message(self, *_args):
            pass

    servers, threads = [], []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    for scheme in ("http", "https"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.seen, server.responses, server.omit_length = [], {}, False
        if scheme == "https":
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server); threads.append(thread)
    try:
        yield servers, ssl.create_default_context(cafile=str(cert))
    finally:
        for server in servers:
            server.shutdown(); server.server_close()
        for thread in threads:
            thread.join(timeout=2)
            assert not thread.is_alive()


@pytest.fixture
def catalog(endpoints):
    servers, context = endpoints
    for server in servers:
        server.seen.clear(); server.responses.clear(); server.omit_length = False
    plain, secure = servers
    base = "https://127.0.0.1:%d" % secure.server_port
    client = catalog_client.CatalogClient(base, "test-catalog-token", context)
    # A real successful request seeds the cumulative Date/RTT state. A redirect
    # must not become a new authenticated clock observation or success sample.
    assert client._req("GET", "/baseline")[0] == 200
    assert client.last_authenticated_date is not None
    client.drain_rtts(); secure.seen.clear()
    return client, plain, secure


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("destination", ["same-origin", "other-host", "plaintext"])
def test_authenticated_request_refuses_every_redirect(catalog, status, method, destination):
    client, plain, secure = catalog
    locations = {
        "same-origin": "/redirect-target",
        "other-host": "https://localhost:%d/redirect-target" % secure.server_port,
        "plaintext": "http://127.0.0.1:%d/redirect-target" % plain.server_port,
    }
    path = "/v1/devices/device/" + ("policy" if method == "GET" else "heartbeat")
    secure.responses[path] = (status, {"Location": locations[destination]}, b"redirect refused")
    previous_date = client.last_authenticated_date
    with pytest.raises(catalog_client.CatalogError, match="HTTP %d" % status):
        if method == "GET":
            client.get_policy("device")
        else:
            client.heartbeat("device", {"sequence": 1})
    assert len(secure.seen) == 1
    sent_method, sent_path, sent_auth, sent_body = secure.seen[0]
    assert (sent_method, sent_path, sent_auth) == (method, path, "Bearer test-catalog-token")
    assert sent_body == (b"" if method == "GET" else json.dumps({"sequence": 1}).encode())
    assert plain.seen == []
    assert client.response_authenticated_date is None
    assert client.last_authenticated_date == previous_date
    assert client.drain_rtts() == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_plain_http_test_client_also_refuses_redirects(catalog, method):
    _client, plain, secure = catalog
    client = catalog_client.CatalogClient("http://127.0.0.1:%d" % plain.server_port, "test-only")
    plain.responses["/first"] = (302, {"Location": "/second"}, b"stop")
    status, body = client._req(method, "/first", body={"sequence": 1} if method == "POST" else None)
    assert (status, body) == (302, b"stop")
    assert len(plain.seen) == 1 and plain.seen[0][1] == "/first"
    assert secure.seen == []
    assert client.response_authenticated_date is None and client.drain_rtts() == []


@pytest.mark.parametrize("omit_length", [False, True])
def test_redirect_error_body_remains_bounded(catalog, omit_length):
    client, plain, secure = catalog
    secure.omit_length = omit_length
    secure.responses["/large"] = (
        302, {"Location": "http://127.0.0.1:%d/target" % plain.server_port},
        b"x" * (catalog_client.ERROR_RESPONSE_MAX + 1))
    with pytest.raises(catalog_client.CatalogError, match="exceeds"):
        client._req("GET", "/large")
    assert len(secure.seen) == 1 and plain.seen == []
    assert client.response_authenticated_date is None and client.drain_rtts() == []


def test_conditional_304_is_not_treated_as_redirect(catalog):
    client, _plain, secure = catalog
    path = "/v1/devices/device/instructions"
    secure.responses[path] = (304, {"ETag": '"same"'}, b"")
    status, body, headers = client.get_instructions("device", etag='"same"')
    assert status == 304 and body == b"" and headers["ETag"] == '"same"'
    assert headers["Date"]
    assert client.response_authenticated_date is not None
    assert client.last_authenticated_date == client.response_authenticated_date
    assert client.drain_rtts() == []
