#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Loopback wire/RPC regression for issue #174's buffered BT handshake.

Usage: python3 test-handshake.py /path/to/aria2c [--baseline] [--log-dir DIR]
Uses only the Python standard library. --baseline requires patches 0001–0005
without 0006: the old coalesced-handshake rejection must occur, while controls
and patch 0005's admission cap must still succeed.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PROTOCOL = b'\x13BitTorrent protocol'
BITFIELD = struct.pack('!IBB', 2, 5, 0x80)
INTERESTED = struct.pack('!IB', 1, 2)
UNCHOKE = struct.pack('!IB', 1, 1)
KEEPALIVE = b'\0' * 4
MESSAGES = BITFIELD + KEEPALIVE + INTERESTED + UNCHOKE
OLD_ERROR = 'More than BtHandshakeMessage::MESSAGE_LENGTH bytes are buffered.'


def enc(value):
    if isinstance(value, int):
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    return b'd' + b''.join(enc(k) + enc(value[k]) for k in sorted(value)) + b'e'


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(predicate, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError('Timed out waiting for ' + description)


class Tracker(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = enc({b'interval': 3600, b'peers': b''})
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Harness:
    def __init__(self, binary, root, runner):
        self.root = root
        self.sockets = []
        self.next_peer = 0
        self.tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
        threading.Thread(target=self.tracker.serve_forever, daemon=True).start()
        self.rpcport = unused_port()
        self.peerport = unused_port()
        while self.peerport == self.rpcport:
            self.peerport = unused_port()
        self.info = {b'name': b'payload', b'length': 16384,
                     b'piece length': 16384,
                     b'pieces': hashlib.sha1(b'x' * 16384).digest()}
        self.infohash = hashlib.sha1(enc(self.info)).digest()
        torrent = enc({b'announce':
            f'http://127.0.0.1:{self.tracker.server_port}/announce'.encode(),
            b'info': self.info})
        self.logpath = root / 'aria2.log'
        self.output = (root / 'console.log').open('w')
        self.proc = None
        self.data = tempfile.TemporaryDirectory(prefix='aria2-handshake-data-')
        try:
            self.proc = subprocess.Popen(shlex.split(runner) + [binary,
                '--no-conf', '--enable-rpc', '--rpc-listen-all=false',
                f'--rpc-listen-port={self.rpcport}', f'--listen-port={self.peerport}',
                '--interface=127.0.0.1', f'--dir={self.data.name}',
                '--enable-dht=false', '--enable-dht6=false',
                '--enable-peer-exchange=false', '--bt-enable-lpd=false',
                '--bt-stop-timeout=0', '--seed-ratio=0', '--file-allocation=none',
                '--summary-interval=0', '--bt-max-peers=10',
                f'--log={self.logpath}', '--log-level=trace'],
                stdout=self.output, stderr=self.output)

            def ready():
                if self.proc.poll() is not None:
                    raise AssertionError(f'aria2 exited; see {root / "console.log"}')
                try:
                    return self.rpc('getVersion', [])
                except OSError:
                    return False

            wait_for(ready, 'RPC startup', timeout=10)
            self.gid = self.rpc('addTorrent', [base64.b64encode(torrent).decode()])
            wait_for(lambda: self.rpc('tellStatus', [self.gid])['status'] == 'active',
                     'torrent startup')
        except BaseException:
            self.close()
            raise

    def rpc(self, method, args):
        body = json.dumps({'jsonrpc': '2.0', 'id': 'handshake-test',
                           'method': 'aria2.' + method, 'params': args}).encode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.rpcport}/jsonrpc',
            body, {'Content-Type': 'application/json'})
        # Bypass any operator HTTP proxy: every endpoint in this test is local.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            result = json.load(response)
        if 'error' in result:
            raise AssertionError(result)
        return result['result']

    def peers(self):
        return self.rpc('getPeers', [self.gid])

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.peerport), timeout=5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sockets.append(sock)
        self.next_peer += 1
        peer_id = f'-IR174-{self.next_peer:013d}'
        return sock, peer_id, PROTOCOL + b'\0' * 8 + self.infohash + peer_id.encode()

    def response(self, sock):
        data = b''
        try:
            while len(data) < 68:
                chunk = sock.recv(68 - len(data))
                if not chunk:
                    break
                data += chunk
        except ConnectionResetError:
            pass
        return data

    def established(self, sock, peer_id, expected, response=None):
        if response is None:
            response = self.response(sock)
        assert len(response) == 68, f'Incomplete handshake: {len(response)} bytes'
        assert response[:20] == PROTOCOL and response[28:48] == self.infohash, response
        return self.state(peer_id, expected)

    def state(self, peer_id, expected):
        def ready():
            for peer in self.peers():
                if urllib.parse.unquote(peer.get('peerId', '')) == peer_id:
                    if (peer.get('handshaking') == 'false' and
                            all(peer.get(key) == value for key, value in expected.items())):
                        return peer
            return False

        peer = wait_for(ready, f'{peer_id}: handshake and RPC state {expected}')
        # peerId is exposed only once aria2 marks the handshake complete.
        assert peer['handshaking'] == 'false', peer
        return {key: peer[key] for key in expected}

    def clear_peers(self):
        for sock in self.sockets:
            sock.close()
        self.sockets.clear()
        wait_for(lambda: not self.peers(), 'peer cleanup')

    def close(self):
        for sock in self.sockets:
            sock.close()
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.output.close()
        self.tracker.shutdown()
        self.tracker.server_close()
        self.data.cleanup()


def run(binary, baseline, root, runner):
    harness = Harness(binary, root, runner)
    results = []

    def report(**result):
        results.append(result)
        print(json.dumps(result), flush=True)
        (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')

    try:
        cases = [
            # name, trailing bytes, first-fragment length, old binary rejects
            ('handshake-only-control', b'', 0, False),
            ('coalesced-bitfield', BITFIELD, 0, True),
            ('coalesced-multiple-messages', MESSAGES, 0, True),
            ('coalesced-partial-message', BITFIELD[:3], 0, True),
            ('fragmented-before-protocol-identification', MESSAGES, 13, True),
            ('fragmented-after-infohash', MESSAGES, 48, False),
        ]
        for name, trailing, split, old_rejects in cases:
            offset = harness.logpath.stat().st_size
            sock, peer_id, handshake = harness.connect()
            response = None
            if split:
                sock.sendall(handshake[:split])
                if split >= 48:
                    # The NAT-check quick reply is a deterministic barrier:
                    # aria2 has consumed the first handshake fragment.
                    response = harness.response(sock)
                    assert len(response) == 68, response
                else:
                    # Below 20 bytes no wire response is possible. Observe the
                    # first receive command in the trace before sending more;
                    # a fixed sleep can accidentally coalesce both fragments.
                    port = sock.getsockname()[1]

                    def first_fragment_received():
                        harness.peers()  # Drive RPC and flush buffered trace.
                        log = harness.logpath.read_text()[offset:]
                        accepted = re.search(
                            rf'Accepted the connection from 127\.0\.0\.1:{port}\.'
                            r'.*?Added CUID#(\d+) to receive BitTorrent/MSE handshake',
                            log, re.DOTALL)
                        return accepted and (
                            f'CUID#{accepted[1]} - socket: read:1' in log)

                    wait_for(first_fragment_received, 'first partial handshake read')
            sock.sendall(handshake[split:] + trailing)
            if baseline and old_rejects:
                response = harness.response(sock)
                # The quick-reply path can send our handshake before the
                # subsequent receiveHandshake call rejects its preset buffer.
                assert len(response) in (0, 68), response
                if response:
                    peers = harness.peers()
                    assert len(peers) == 1 and peers[0]['handshaking'] == 'true', peers
                    assert peers[0]['bitfield'] == '00', peers
                    # The old quick-reply path does not finish its buffered
                    # handshake until another socket read event. Only baseline
                    # mode sends this wakeup; fixed cases must finish unaided.
                    sock.sendall(KEEPALIVE)
                wait_for(lambda: not harness.peers() and
                         OLD_ERROR in harness.logpath.read_text()[offset:],
                         'specific buffered-handshake rejection diagnostic')
                assert not harness.peers(), f'{name}: rejected peer remained active'
                report(case=name, result='expected baseline rejection',
                       handshake_reply_bytes=len(response), diagnostic=OLD_ERROR)
            else:
                complete_message = len(trailing) >= len(BITFIELD)
                expected = {'bitfield': '80' if complete_message else '00',
                            'amInterested': 'true' if complete_message else 'false',
                            'peerInterested': 'true' if trailing == MESSAGES else 'false',
                            'peerChoking': 'false' if trailing == MESSAGES else 'true'}
                state = harness.established(sock, peer_id, expected, response)
                if name == 'coalesced-partial-message':
                    sock.sendall(BITFIELD[3:] + INTERESTED + UNCHOKE)
                    state = harness.state(peer_id, {'bitfield': '80',
                        'amInterested': 'true', 'peerInterested': 'true',
                        'peerChoking': 'false'})
                report(case=name, result='PASS', handshake_bytes=68, state=state)
            harness.clear_peers()

        sock, _, handshake = harness.connect()
        wrong_hash = handshake[:28] + bytes([handshake[28] ^ 1]) + handshake[29:]
        sock.sendall(wrong_hash + MESSAGES)
        assert harness.response(sock) == b'', 'Unknown infohash received a handshake'
        assert not harness.peers(), 'Unknown infohash was admitted'
        report(case='unknown-infohash', result='PASS', rejected=1)
        harness.clear_peers()

        # New coalesced handshakes still go through #168's admission checks.
        # Baseline uses plain handshakes because #174 is intentionally present.
        expected = {'bitfield': '00' if baseline else '80',
                    'amInterested': 'false' if baseline else 'true',
                    'peerInterested': 'false' if baseline else 'true',
                    'peerChoking': 'true' if baseline else 'false'}
        admitted = []
        for _ in range(10):
            sock, peer_id, handshake = harness.connect()
            sock.sendall(handshake + (b'' if baseline else MESSAGES))
            harness.established(sock, peer_id, expected)
            admitted.append(peer_id)
            assert len(harness.peers()) <= 10
        sock, _, handshake = harness.connect()
        sock.sendall(handshake + (b'' if baseline else MESSAGES))
        assert harness.response(sock) == b'', 'Peer 11 was admitted with bt-max-peers=10'
        for _ in range(10):
            peers = harness.peers()
            actual = {urllib.parse.unquote(peer.get('peerId', '')) for peer in peers}
            assert len(peers) == 10 and actual == set(admitted), peers
            time.sleep(.1)
        report(case='peer-cap', result='PASS', cap=10, established=10,
               rejected=1, handshake='plain' if baseline else 'coalesced')
    finally:
        harness.close()
    print(f'PASS: {"baseline defect reproduced" if baseline else "handshake regression"}; '
          f'logs: {root}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--log-dir', type=Path)
    parser.add_argument('--runner', default='', help='Optional emulator, e.g. qemu-aarch64-static')
    args = parser.parse_args()
    root = args.log_dir or Path(tempfile.mkdtemp(prefix='aria2-handshake-'))
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    print(f'Logs: {root}', flush=True)
    run(str(args.binary.resolve()), args.baseline, root, args.runner)
