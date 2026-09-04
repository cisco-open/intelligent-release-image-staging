# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""One host-side proof that the shipped aria2 forwards a torrent Bearer.

The ordinary unit test proves the agent's JSON-RPC request.  This small local
integration test closes the other half of the contract: the exact static
aria2 binary packaged on devices turns that per-download option into the HTTP
tracker request.  Both listeners use ephemeral loopback ports.
"""

import base64
import hashlib
import http.server
import json
from pathlib import Path
import socket
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


@pytest.mark.skipif(not ARIA2.is_file(), reason="shipped x86_64 aria2 is absent")
def test_shipped_aria2_forwards_per_download_authorization_to_tracker(tmp_path):
    seen = []
    announced = threading.Event()

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

    tracker = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Tracker)
    tracker_thread = threading.Thread(target=tracker.serve_forever, daemon=True)
    tracker_thread.start()
    rpc_port = _free_loopback_port()
    rpc_secret = "integration-rpc-secret"
    bearer = "integration-announce-token"
    conf = tmp_path / "aria2.conf"
    conf.write_text(
        "enable-rpc=true\n"
        "rpc-listen-all=false\n"
        f"rpc-listen-port={rpc_port}\n"
        f"rpc-secret={rpc_secret}\n"
        "enable-dht=false\n"
        "enable-dht6=false\n"
        "bt-enable-lpd=false\n"
        "enable-peer-exchange=false\n"
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

    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                rpc("aria2.getVersion", [])
                break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise AssertionError("shipped aria2 RPC did not start")
                time.sleep(0.05)

        tracker_url = (f"http://127.0.0.1:{tracker.server_address[1]}"
                       "/announce")
        torrent = _bencode({
            b"announce": tracker_url.encode(),
            b"info": {
                b"length": 1,
                b"name": b"proof.bin",
                b"piece length": 16_384,
                b"pieces": hashlib.sha1(b"x").digest(),
            },
        })
        reply = rpc("aria2.addTorrent", [
            base64.b64encode(torrent).decode(), [],
            {"dir": str(tmp_path),
             "header": ["Authorization: Bearer " + bearer]},
        ])
        assert "error" not in reply
        assert announced.wait(10), "shipped aria2 never contacted the tracker"
        assert seen == ["Bearer " + bearer]
    finally:
        try:
            rpc("aria2.shutdown", [])
        except (OSError, urllib.error.URLError):
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=3)
        tracker.shutdown()
        tracker.server_close()
        tracker_thread.join(timeout=3)
