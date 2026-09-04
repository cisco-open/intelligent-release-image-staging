# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Host-side proof that shipped aria2 pins HTTPS and forwards a Bearer.

The ordinary unit test proves the agent's JSON-RPC request.  This small local
integration test closes the other half of the contract: the exact static
aria2 binary packaged on devices validates the configured tracker certificate
and turns the per-download option into the HTTPS request. Both listeners use
ephemeral loopback ports; JSON-RPC remains loopback-only HTTP by design.
"""

import base64
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest


ARIA2 = Path(__file__).resolve().parents[3] / "deliverables" / "aria2c-x86_64"


def _bencode(value):
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, list):
        return b"l" + b"".join(_bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        return (b"d" + b"".join(_bencode(key) + _bencode(value[key])
                                 for key in sorted(value)) + b"e")
    raise TypeError(type(value))


def _free_loopback_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _certificate(tmp_path, name):
    cert = tmp_path / (name + ".pem")
    key = tmp_path / (name + ".key")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=127.0.0.1",
        "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def _start_tracker(cert, key, seen, announced, rejected=None):
    class Tracker(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            body = b"d8:intervali60e5:peers0:e"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            announced.set()

        def log_message(self, _format, *_args):
            pass

    class TLSTracker(http.server.ThreadingHTTPServer):
        def get_request(self):
            try:
                return super().get_request()
            except ssl.SSLError:
                if rejected is not None:
                    rejected.set()
                raise

    tracker = TLSTracker(("127.0.0.1", 0), Tracker)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    tracker.socket = context.wrap_socket(tracker.socket, server_side=True)
    tracker_thread = threading.Thread(target=tracker.serve_forever, daemon=True)
    tracker_thread.start()
    return tracker, tracker_thread


def _start_aria(tmp_path, ca):
    rpc_port = _free_loopback_port()
    rpc_secret = "integration-rpc-secret"
    conf = tmp_path / ("aria2-%d.conf" % rpc_port)
    conf.write_text(
        "enable-rpc=true\n"
        "rpc-listen-all=false\n"
        f"rpc-listen-port={rpc_port}\n"
        f"rpc-secret={rpc_secret}\n"
        "enable-dht=false\n"
        "enable-dht6=false\n"
        "bt-enable-lpd=false\n"
        "enable-peer-exchange=false\n"
        f"ca-certificate={ca}\n"
        "check-certificate=true\n"
        "max-tries=1\n"
        "bt-tracker-connect-timeout=2\n"
        "bt-tracker-timeout=2\n"
        "seed-time=0\n"
        "summary-interval=0\n"
        "console-log-level=error\n"
        "log-level=error\n"
        "log=-\n")
    proc = subprocess.Popen(
        [str(ARIA2), "--conf-path=" + str(conf)], cwd=tmp_path,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)

    rpc_url = f"http://127.0.0.1:{rpc_port}/jsonrpc"

    def rpc(method, params):
        request = urllib.request.Request(
            rpc_url,
            data=json.dumps({"jsonrpc": "2.0", "id": "proof",
                             "method": method,
                             "params": ["token:" + rpc_secret] + params}
                            ).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode())

    deadline = time.monotonic() + 10
    while True:
        try:
            rpc("aria2.getVersion", [])
            break
        except (OSError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                proc.terminate()
                proc.wait(timeout=3)
                raise AssertionError("shipped aria2 RPC did not start")
            time.sleep(0.05)
    return proc, rpc


def _add_torrent(rpc, tmp_path, tracker_port, bearer, name="proof.bin"):
    tracker_url = f"https://127.0.0.1:{tracker_port}/announce"
    torrent = _bencode({
        b"announce": tracker_url.encode(),
        b"info": {
            b"length": 1,
            b"name": name.encode(),
            b"piece length": 16_384,
            b"pieces": hashlib.sha1(b"x").digest(),
        },
    })
    return rpc("aria2.addTorrent", [
        base64.b64encode(torrent).decode(), [],
        {"dir": str(tmp_path),
         "header": ["Authorization: Bearer " + bearer]},
    ])


def _wait_for_header(seen, expected, start=0, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if expected in seen[start:]:
            return
        time.sleep(0.05)
    raise AssertionError("shipped aria2 did not send the expected test header")


def _stop_aria(proc, rpc):
    try:
        rpc("aria2.shutdown", [])
    except (OSError, urllib.error.URLError):
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=3)


def _stop_tracker(tracker, tracker_thread):
    tracker.shutdown()
    tracker.server_close()
    tracker_thread.join(timeout=3)


@pytest.mark.skipif(not ARIA2.is_file(), reason="shipped x86_64 aria2 is absent")
def test_shipped_aria2_pins_https_and_forwards_authorization(tmp_path):
    cert, key = _certificate(tmp_path, "tracker")
    seen = []
    announced = threading.Event()
    tracker, tracker_thread = _start_tracker(cert, key, seen, announced)
    proc, rpc = _start_aria(tmp_path, cert)
    bearer = "integration-announce-token"
    try:
        reply = _add_torrent(
            rpc, tmp_path, tracker.server_address[1], bearer)
        assert "error" not in reply
        assert announced.wait(10), "shipped aria2 never contacted HTTPS tracker"
        assert seen and all(value == "Bearer " + bearer for value in seen)
    finally:
        _stop_aria(proc, rpc)
        _stop_tracker(tracker, tracker_thread)


@pytest.mark.skipif(not ARIA2.is_file(), reason="shipped x86_64 aria2 is absent")
def test_shipped_aria2_rejects_https_tracker_with_wrong_pin(tmp_path):
    cert, key = _certificate(tmp_path, "tracker")
    wrong_cert, _ = _certificate(tmp_path, "wrong")
    seen = []
    announced = threading.Event()
    rejected = threading.Event()
    tracker, tracker_thread = _start_tracker(
        cert, key, seen, announced, rejected=rejected)
    proc, rpc = _start_aria(tmp_path, wrong_cert)
    try:
        reply = _add_torrent(
            rpc, tmp_path, tracker.server_address[1], "never-forwarded")
        assert "error" not in reply
        assert rejected.wait(5), "aria2 never attempted the TLS handshake"
        assert not announced.is_set()
        assert seen == []
    finally:
        _stop_aria(proc, rpc)
        _stop_tracker(tracker, tracker_thread)


@pytest.mark.skipif(not ARIA2.is_file(), reason="shipped x86_64 aria2 is absent")
def test_shipped_aria2_global_header_must_be_updated_before_add_torrent(
        tmp_path):
    """Prove the runtime refresh must correct aria2's global header first.

    Aria2 Next gives a global HTTP header precedence over the per-download
    header supplied to addTorrent. A daemon retaining its old global Bearer
    therefore keeps announcing with that old value even when the agent adds a
    torrent with the refreshed local value. changeGlobalOption must land before
    the add/re-add; a distinct second torrent proves the corrected request.
    """
    cert, key = _certificate(tmp_path, "global-header-tracker")
    seen = []
    announced = threading.Event()
    tracker, tracker_thread = _start_tracker(cert, key, seen, announced)
    proc, rpc = _start_aria(tmp_path, cert)
    old = "test-global-before-refresh"
    current = "test-global-after-refresh"
    try:
        changed = rpc("aria2.changeGlobalOption", [
            {"header": ["Authorization: Bearer " + old]},
        ])
        assert "error" not in changed

        first = _add_torrent(
            rpc, tmp_path, tracker.server_address[1], current,
            name="before-global-refresh.bin")
        assert "error" not in first
        _wait_for_header(seen, "Bearer " + old)
        assert "Bearer " + current not in seen

        changed = rpc("aria2.changeGlobalOption", [
            {"header": ["Authorization: Bearer " + current]},
        ])
        assert "error" not in changed
        start = len(seen)
        second = _add_torrent(
            rpc, tmp_path, tracker.server_address[1], current,
            name="after-global-refresh.bin")
        assert "error" not in second
        _wait_for_header(seen, "Bearer " + current, start=start)
    finally:
        _stop_aria(proc, rpc)
        _stop_tracker(tracker, tracker_thread)
