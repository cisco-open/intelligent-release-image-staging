#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Loopback wire/RPC regression: stalled peers must respect bt-max-peers.

Run: python3 test-peer-cap.py /absolute/path/to/aria2c [--baseline]
No external tracker or Python dependencies. --baseline expects the old defect.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def enc(v):
    if isinstance(v, int):
        return b'i' + str(v).encode() + b'e'
    if isinstance(v, bytes):
        return str(len(v)).encode() + b':' + v
    return b'd' + b''.join(enc(k) + enc(v[k]) for k in sorted(v)) + b'e'


def listener():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen(32)
    return s


def run(binary, cap, outbound=False, seed=False, mixed=False, runtime=False):
    sockets = []
    peers = []
    stopped = threading.Event()
    info = {b'name': b'payload', b'length': 16384, b'piece length': 16384,
            b'pieces': hashlib.sha1(b'x' * 16384).digest()}
    ih = hashlib.sha1(enc(info)).digest()

    def handshake(i):
        return b'\x13BitTorrent protocol' + b'\0' * 8 + ih + f'-TEST00-{i:012d}'.encode()

    def accept(s, i):
        while not stopped.is_set():
            try:
                c, _ = s.accept()
                sockets.append(c)
                c.settimeout(3)
                data = c.recv(4096)
                if not data.startswith(b'\x13BitTorrent protocol'):
                    c.close()  # trigger aria2's normal plaintext fallback
                    continue
                c.sendall(handshake(i))
            except (OSError, TimeoutError):
                pass

    if outbound:
        for i in range(18):
            s = listener()
            sockets.append(s)
            peers.append(socket.inet_aton('127.0.0.1') + struct.pack('!H', s.getsockname()[1]))
            threading.Thread(target=accept, args=(s, i), daemon=True).start()

    class Tracker(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            body = enc({b'interval': 1, b'peers': b''.join(peers)})
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
    threading.Thread(target=tracker.serve_forever, daemon=True).start()
    torrent = enc({b'announce': f'http://127.0.0.1:{tracker.server_port}/announce'.encode(), b'info': info})
    r, p = listener(), listener()
    rpcport, peerport = r.getsockname()[1], p.getsockname()[1]
    r.close()
    p.close()

    def rpc(method, args):
        data = json.dumps({'jsonrpc': '2.0', 'id': 'test', 'method': 'aria2.' + method, 'params': args}).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{rpcport}/jsonrpc', data, {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response:
            result = json.load(response)
        if 'error' in result:
            raise RuntimeError(result)
        return result['result']

    with tempfile.TemporaryDirectory(prefix='aria2-peer-cap-') as tmp:
        if seed:
            Path(tmp, 'payload').write_bytes(b'x' * 16384)
        with open(Path(tmp, 'aria2.log'), 'w') as log:
            proc = subprocess.Popen([binary, '--no-conf', '--enable-rpc', '--rpc-listen-all=false',
                f'--rpc-listen-port={rpcport}', f'--listen-port={peerport}', f'--dir={tmp}',
                '--enable-dht=false', '--enable-dht6=false', '--enable-peer-exchange=false',
                '--bt-enable-lpd=false', '--bt-tracker-interval=1', '--bt-stop-timeout=0',
                '--seed-ratio=0', '--file-allocation=none', '--check-integrity=true',
                '--summary-interval=0', f'--bt-max-peers={cap}'],
                stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        rpc('getVersion', [])
                        break
                    except OSError:
                        time.sleep(.1)
                gid = rpc('addTorrent', [base64.b64encode(torrent).decode()])
                time.sleep(1)
                if not outbound or mixed:
                    for i in range(18):
                        c = socket.create_connection(('127.0.0.1', peerport), timeout=5)
                        sockets.append(c)
                        c.sendall(handshake(i))
                        time.sleep(.15)
                counts = []
                for _ in range(8 if runtime else (160 if outbound else 88)):
                    counts.append(len(rpc('getPeers', [gid])))
                    time.sleep(.25)
                result = max(counts)
                print(json.dumps(dict(cap=cap, direction='mixed' if mixed else ('outbound' if outbound else 'inbound'),
                                      state='seed' if seed else 'stalled leecher', peak=result)), flush=True)
                if runtime:
                    assert result == 1, result
                    rpc('changeOption', [gid, {'bt-max-peers': '5'}])
                    for i in range(100, 106):
                        c = socket.create_connection(('127.0.0.1', peerport), timeout=5)
                        sockets.append(c)
                        c.sendall(handshake(i))
                        time.sleep(.15)
                    time.sleep(5)
                    raised = len(rpc('getPeers', [gid]))
                    assert raised == 5, raised
                    rpc('changeOption', [gid, {'bt-max-peers': '2'}])
                    for i in range(200, 203):
                        c = socket.create_connection(('127.0.0.1', peerport), timeout=5)
                        sockets.append(c)
                        c.sendall(handshake(i))
                        time.sleep(.15)
                    time.sleep(5)
                    lowered = len(rpc('getPeers', [gid]))
                    assert lowered == 5, lowered
                    print(json.dumps(dict(runtime_limits=[1, 5, 2],
                                          observed_peers=[result, raised, lowered],
                                          lowering='existing peers retained; new peers rejected')), flush=True)
                return result
            finally:
                proc.terminate()
                proc.wait(timeout=10)
                stopped.set()
                for s in sockets:
                    s.close()
                tracker.shutdown()
                tracker.server_close()


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    if '--runtime' in sys.argv:
        run(binary, 1, runtime=True)
        sys.exit(0)
    if '--mixed' in sys.argv:
        peak = run(binary, 10, outbound=True, mixed=True)
        assert peak == 10, peak
        sys.exit(0)
    baseline = '--baseline' in sys.argv
    cases = [(10, False, False), (10, True, False)] if baseline else [
        (10, False, False), (1, False, False), (0, False, False),
        (10, False, True), (10, True, False), (1, True, False), (0, True, False)]

    def check_case(case):
        limit, outbound, seed = case
        peak = run(binary, limit, outbound, seed)
        assert peak > limit if baseline else peak == (18 if limit == 0 else limit), (case, peak)

    if '--parallel' in sys.argv:
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(check_case, cases))
    else:
        for case in cases:
            check_case(case)
