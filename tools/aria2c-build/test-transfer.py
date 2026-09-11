#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Verify a real BitTorrent transfer between two clients capped at one peer."""
import hashlib
import importlib.util
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

spec = importlib.util.spec_from_file_location(
    'peer_cap', Path(__file__).with_name('test-peer-cap.py'))
cap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cap)


def run(binary):
    peers = set()

    class Tracker(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            port = int(parse_qs(urlsplit(self.path).query)['port'][0])
            peers.add(port)
            body = cap.enc({b'interval': 1, b'peers': b''.join(
                socket.inet_aton('127.0.0.1') + struct.pack('!H', p)
                for p in peers.copy() if p != port)})
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
    threading.Thread(target=tracker.serve_forever, daemon=True).start()
    procs = []
    with tempfile.TemporaryDirectory(prefix='aria2-transfer-') as tmp:
        root = Path(tmp)
        seed, leech = root / 'seed', root / 'leech'
        seed.mkdir()
        leech.mkdir()
        data = b'iris peer cap regression\n' * 131072
        digest = hashlib.sha256(data).hexdigest()
        (seed / 'payload').write_bytes(data)
        info = {b'name': b'payload', b'length': len(data), b'piece length': 65536,
                b'pieces': b''.join(hashlib.sha1(data[i:i + 65536]).digest()
                                   for i in range(0, len(data), 65536))}
        torrent = root / 'test.torrent'
        torrent.write_bytes(cap.enc({b'announce':
            f'http://127.0.0.1:{tracker.server_port}/announce'.encode(), b'info': info}))
        try:
            for folder in [seed, leech]:
                s = cap.listener()
                port = s.getsockname()[1]
                s.close()
                with (folder / 'log').open('w') as log:
                    procs.append(subprocess.Popen([
                        binary, '--no-conf', '--enable-dht=false', '--enable-dht6=false',
                        '--enable-peer-exchange=false', '--bt-enable-lpd=false',
                        '--bt-max-peers=1', '--bt-tracker-interval=1', '--seed-ratio=0',
                        '--file-allocation=none', '--check-integrity=true',
                        f'--listen-port={port}', f'--dir={folder}', str(torrent)],
                        stdout=log, stderr=log))
            for _ in range(120):
                time.sleep(.5)
                if ((leech / 'payload').exists() and
                        hashlib.sha256((leech / 'payload').read_bytes()).hexdigest() == digest):
                    print(f'PASS: {len(data)} bytes transferred with bt-max-peers=1; SHA256={digest}')
                    return
            for folder in [seed, leech]:
                print((folder / 'log').read_text())
            raise AssertionError('transfer did not complete within 60 seconds')
        finally:
            for proc in procs:
                proc.terminate()
            for proc in procs:
                proc.wait(timeout=10)
            tracker.shutdown()
            tracker.server_close()


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
