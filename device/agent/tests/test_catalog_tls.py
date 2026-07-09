# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""#12 verify-if-present: the agent's catalog TLS context (iris_agent.make_catalog
_context) VERIFIES the catalog cert against the pinned CA when catalog_ca is set,
REJECTS a wrong/absent anchor, and WARNS + stays unverified when catalog_ca is
absent (locked back-compat). Uses an in-process HTTPS stub with a throwaway cert,
mirroring test_catalog_client.py's stub pattern. catalog_client is unchanged."""
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import catalog_client
import iris_agent


def _throwaway_cert(d):
    """Throwaway self-signed cert (bare crt + combined cert+key) with
    SAN=IP:127.0.0.1, mirroring the server cert shape. Returns (crt, combined)."""
    crt = os.path.join(d, "crt.pem")
    key = os.path.join(d, "key.pem")
    combined = os.path.join(d, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", key, "-out", crt, "-subj", "/CN=iris",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    with open(combined, "wb") as f:
        f.write(open(crt, "rb").read())
        f.write(open(key, "rb").read())
    return crt, combined


class _Stub(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer tok":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{}')
            return
        b = b'{"approved_image_id":"img1","install_allowed":false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


@pytest.fixture
def https_stub(tmp_path):
    crt, combined = _throwaway_cert(str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(combined)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "https://127.0.0.1:%d" % srv.server_address[1]
    yield base, crt, str(tmp_path)
    srv.shutdown()


def test_matching_cafile_verifies_and_call_succeeds(https_stub):
    base, crt, _ = https_stub
    warned = []
    ctx = iris_agent.make_catalog_context({"catalog_ca": crt}, warned.append)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert warned == []          # pinned -> no legacy warning
    client = catalog_client.CatalogClient(base, "tok", context=ctx)
    assert client.get_policy("sw1") == {"approved_image_id": "img1",
                                        "install_allowed": False}


def test_wrong_cafile_rejects(https_stub, tmp_path):
    base, crt, _ = https_stub
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    wrong_crt, _ = _throwaway_cert(str(other_dir))
    ctx = iris_agent.make_catalog_context({"catalog_ca": wrong_crt}, lambda m: None)
    client = catalog_client.CatalogClient(base, "tok", context=ctx)
    with pytest.raises(catalog_client.CatalogError):
        client.get_policy("sw1")


def test_absent_catalog_ca_warns_and_stays_unverified(https_stub):
    # The LOCKED back-compat path: no catalog_ca -> unverified context + ONE warning,
    # and the call still proceeds (the self-signed stub is accepted unverified).
    base, crt, _ = https_stub
    warned = []
    ctx = iris_agent.make_catalog_context({}, warned.append)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert len(warned) == 1 and "NOT verified" in warned[0]
    client = catalog_client.CatalogClient(base, "tok", context=ctx)
    assert client.get_policy("sw1") == {"approved_image_id": "img1",
                                        "install_allowed": False}


def test_empty_string_catalog_ca_is_treated_as_absent(https_stub):
    # agent_config DEFAULTS gives catalog_ca = "" (falsy) when unset -> unverified.
    base, crt, _ = https_stub
    warned = []
    ctx = iris_agent.make_catalog_context({"catalog_ca": ""}, warned.append)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert len(warned) == 1
