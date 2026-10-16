# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Opt-in real pinned-aria2 proof; loopback only, one 256 KiB fixture."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import urllib.request

import pytest

import auth
import bencode
import origin_enforcement as oe
import peer_endpoints
import peer_policy
import tracker
from test_blocklist_reconciler import _role_doc

pytestmark = pytest.mark.skipif(os.environ.get("IRIS_TEST_ORIGIN_NATIVE") != "1",
    reason="set IRIS_TEST_ORIGIN_NATIVE=1 for isolated pinned native RPC/peer proof")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, length):
    result = b""
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("peer disconnected")
        result += chunk
    return result


def test_reviewed_restriction_disconnects_denied_peer_and_preserves_allowed(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    binary = repo / "bin/aria2c"
    pins = (repo / "tools/aria2c.sha256").read_text()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() in pins
    rpc_port, peer_port = port(), port()
    content = b"IRIS isolated origin fixture\n" * 9000
    (tmp_path / "fixture.dat").write_bytes(content)
    piece_length = 16384
    info = {"name": "fixture.dat", "piece length": piece_length, "length": len(content),
            "pieces": b"".join(hashlib.sha1(content[i:i + piece_length]).digest()
                for i in range(0, len(content), piece_length)), "private": 1}
    torrent = bencode.encode({"info": info})
    info_hash = hashlib.sha1(bencode.encode(info)).digest()
    log = open(tmp_path / "aria2.log", "wb")
    process = subprocess.Popen([str(binary), "--no-conf", "--enable-rpc=true",
        "--rpc-listen-all=false", "--rpc-listen-port=%d" % rpc_port,
        "--rpc-secret=fixture-only-loopback", "--listen-port=%d" % peer_port,
        "--interface=127.0.0.1", "--disable-ipv6=true", "--enable-dht=false",
        "--enable-dht6=false", "--bt-enable-lpd=false", "--enable-peer-exchange=false",
        "--seed-ratio=0", "--seed-time=5", "--file-allocation=none",
        "--max-overall-upload-limit=32K", "--dir=" + str(tmp_path)],
        stdout=log, stderr=subprocess.STDOUT)
    peers = []

    def rpc(method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": "fixture", "method": method,
                           "params": ["token:fixture-only-loopback"] + params}).encode()
        with urllib.request.urlopen(urllib.request.Request(
                "http://127.0.0.1:%d/jsonrpc" % rpc_port, data=body,
                headers={"Content-Type": "application/json"}), timeout=3) as response:
            value = json.load(response)
        assert "error" not in value, value.get("error")
        return value["result"]

    def connect(address):
        sock = socket.socket()
        peers.append(sock)
        sock.settimeout(15)
        sock.bind((address, 0))
        sock.connect(("127.0.0.1", peer_port))
        identity = ("-IRTEST-" + address).encode().ljust(20, b"0")[:20]
        sock.sendall(b"\x13BitTorrent protocol" + b"\0" * 8 + info_hash + identity)
        return sock

    def handshake(sock):
        response = receive(sock, 68)
        assert response[28:48] == info_hash

    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                rpc("aria2.getSessionInfo", [])
                break
            except OSError:
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(.05)
        rpc("aria2.addTorrent", [base64.b64encode(torrent).decode(), [], {"check-integrity": "true"}])
        deadline = time.monotonic() + 10
        while not rpc("aria2.tellActive", [[]]):
            assert time.monotonic() < deadline
            time.sleep(.05)
        paths = [str(tmp_path / name) for name in ("peer-policy.json", "peer-policy.lkg.json")]
        document = _role_doc(("denied",))
        document["roles"]["qos_default"]["origin_up_bps"] = 32768
        for path in paths:
            peer_policy._atomic_write_json(path, document)
        endpoint_path = str(tmp_path / "peer-endpoints.json")
        for principal, address in ((auth.Principal("service", "seeder"), "127.0.0.1"),
                (auth.Principal("device", "denied"), "127.0.0.2"),
                (auth.Principal("device", "allowed"), "127.0.0.3")):
            peer_endpoints.record_endpoint(endpoint_path, principal, address, peer_port, time.time())
        rec = tracker.TrackerReconciler(policy_paths=tuple(paths), endpoints_path=endpoint_path,
            enforcement_path=str(tmp_path / "peer-enforcement.json"),
            aria=tracker.Aria2BlocklistAdapter(rpc), pending_queue=peer_endpoints.PendingEndpointQueue(),
            active_participants=lambda: [], revoked_principals=lambda: set(),
            protected_seeder_ip="127.0.0.1")
        store = oe.Store(str(tmp_path), "127.0.0.1")
        rec.run_once()
        denied = connect("127.0.0.2")
        handshake(denied)
        denied.sendall(struct.pack("!IB", 1, 2))  # interested
        while True:
            length = struct.unpack("!I", receive(denied, 4))[0]
            message = receive(denied, length) if length else b""
            if message[:1] == b"\x01":  # unchoke
                break
        denied.sendall(struct.pack("!IBIII", 13, 6, 0, 0, piece_length))
        while True:
            length = struct.unpack("!I", receive(denied, 4))[0]
            message = receive(denied, length) if length else b""
            if message[:1] == b"\x07":
                assert message[9:] == content[:piece_length]
                break
        request = {"mode": "enforce", "max_new_ips": 1, "max_new_devices": 1,
                   "if_policy_revision": 1, "dry_run": True}
        preview = store.change(request, [oe.etag(0)])
        store.change(dict(request, dry_run=False, confirm_token=preview["confirm_token"]), [oe.etag(0)])
        status = rec.run_once()
        assert store.read()["state"] == "enforced"
        assert status["last_effect"]["disconnected_peers"] >= 1
        with pytest.raises((EOFError, ConnectionResetError)):
            while True:
                receive(denied, 1)
        blocked = connect("127.0.0.2")
        with pytest.raises((EOFError, ConnectionResetError)):
            handshake(blocked)
        allowed = connect("127.0.0.3")
        handshake(allowed)
        request.update(mode="preflight")
        preview = store.change(request, [oe.etag(1)])
        store.change(dict(request, dry_run=False, confirm_token=preview["confirm_token"]), [oe.etag(1)])
        rec.run_once()
        restored = connect("127.0.0.2")
        handshake(restored)
        assert store.read()["state"] == "preflight"
    finally:
        for sock in peers:
            sock.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
