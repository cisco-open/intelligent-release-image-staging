# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""#12 FAIL CLOSED: the agent's catalog TLS context (iris_agent.make_catalog
_context) VERIFIES the catalog cert against the pinned CA when catalog_ca is
set, REJECTS a wrong anchor, and now REFUSES the connection (raises
CatalogTLSConfigError, never constructs an unverified context) when
catalog_ca is absent or empty -- replacing the old "verify-if-present"
warn-and-downgrade back-compat. Uses an in-process HTTPS stub with a
throwaway cert, mirroring test_catalog_client.py's stub pattern.
catalog_client is unchanged."""
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import catalog_client
import cli_ssh
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
        b = b'{"approved_image_id":"img1"}'
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
    assert client.get_policy("sw1") == {"approved_image_id": "img1"}


def test_wrong_cafile_rejects(https_stub, tmp_path):
    base, crt, _ = https_stub
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    wrong_crt, _ = _throwaway_cert(str(other_dir))
    ctx = iris_agent.make_catalog_context({"catalog_ca": wrong_crt}, lambda m: None)
    client = catalog_client.CatalogClient(base, "tok", context=ctx)
    with pytest.raises(catalog_client.CatalogError):
        client.get_policy("sw1")


def test_absent_catalog_ca_fails_closed(monkeypatch):
    # SECURITY (#12 fix): no catalog_ca key at all -> refuse. error() fires
    # once with an honest message, an exception is raised, and above all
    # ssl._create_unverified_context() must NEVER be called -- assert on the
    # ssl call itself so a future regression back to the silent downgrade
    # can't slip past a looser assertion.
    called = []
    monkeypatch.setattr(
        ssl, "_create_unverified_context",
        lambda *a, **k: called.append(1) or ssl.SSLContext())
    errors = []
    with pytest.raises(iris_agent.CatalogTLSConfigError) as exc_info:
        iris_agent.make_catalog_context({}, errors.append)
    assert called == []
    assert len(errors) == 1
    assert "catalog_ca" in errors[0] and "refusing" in errors[0]
    assert "catalog_ca" in str(exc_info.value)


def test_empty_string_catalog_ca_fails_closed(monkeypatch):
    # agent_config no longer backfills catalog_ca = "" for an absent key, but
    # an explicit empty string (e.g. a hand-edited conf) must refuse the same
    # way as a missing key -- "" is exactly as unpinned as absent.
    called = []
    monkeypatch.setattr(
        ssl, "_create_unverified_context",
        lambda *a, **k: called.append(1) or ssl.SSLContext())
    errors = []
    with pytest.raises(iris_agent.CatalogTLSConfigError):
        iris_agent.make_catalog_context({"catalog_ca": ""}, errors.append)
    assert called == []
    assert len(errors) == 1


def test_missing_catalog_ca_file_fails_closed(tmp_path):
    # catalog_ca points somewhere, but the pinned file isn't actually there
    # (e.g. a botched install) -- same refusal as unset, not a silent
    # downgrade.
    errors = []
    with pytest.raises(iris_agent.CatalogTLSConfigError):
        iris_agent.make_catalog_context(
            {"catalog_ca": str(tmp_path / "no-such-cert.pem")}, errors.append)
    assert len(errors) == 1


def test_build_deps_wires_the_fail_closed_context_without_a_nameerror(
        monkeypatch, tmp_path):
    # Reproduces the real on-box wiring in iris_agent.build_deps (normally
    # `# pragma: no cover`): a NameError bug there meant the fail-closed
    # error callback could never actually run -- `emit` (and the
    # `cli_execute` it wraps) weren't yet bound in build_deps' scope at the
    # point make_catalog_context's callback fires synchronously. Stubbing
    # cli_ssh.select_cli lets this run off-box without a real device; the
    # regression this guards against is CatalogTLSConfigError turning into a
    # NameError, not build_deps reaching a real switch.
    sent = []
    monkeypatch.setattr(
        cli_ssh, "select_cli",
        lambda cfg: (lambda cmd: sent.append(cmd), lambda cmds: sent.extend(cmds)))
    conf_path = str(tmp_path / "iris-agent.conf")
    cfg = {"catalog_url": "https://198.51.100.1:8443", "catalog_token": "tok",
           "device_id": "d1", "rpc_port": "6800"}
    with pytest.raises(iris_agent.CatalogTLSConfigError):
        iris_agent.build_deps(cfg, conf_path)
    assert any("TLS-ERROR" in cmd for cmd in sent), sent


@pytest.mark.parametrize(("platform", "expected_io_transfer"), [
    (None, False),
    ("iox", True),
])
def test_build_deps_returns_guestshell_and_iox_dependencies_without_nameerror(
        monkeypatch, tmp_path, platform, expected_io_transfer):
    """The shared selector wiring must survive construction on both XE paths."""
    monkeypatch.delenv("IRIS_DEVICE_PLATFORM", raising=False)
    monkeypatch.setattr(
        cli_ssh, "select_cli",
        lambda cfg: (lambda _cmd: "", lambda _cmds: None))
    monkeypatch.setattr(iris_agent, "make_catalog_context",
                        lambda _cfg, _error: None)
    cfg = {
        "catalog_url": "https://198.51.100.1:8443",
        "catalog_token": "tok",
        "device_id": "d1",
        "rpc_port": "6800",
        "rpc_secret": "rpc",
        "stage_dir": str(tmp_path),
    }
    if platform is not None:
        cfg["device_platform"] = platform

    deps = iris_agent.build_deps(cfg, str(tmp_path / "iris-agent.conf"))

    assert deps.io_transfer is expected_io_transfer
