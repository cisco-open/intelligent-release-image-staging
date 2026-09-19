#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Force crossed outgoing connections at bt-max-peers=1; verify data and cap.

Two transparent TCP relays release dials in pairs, so neither endpoint can
finish its incoming handshake before both outgoing slots are occupied.
No external network or device is used. --tls exercises required peer TLS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def enc(value):
    if isinstance(value, int):
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    return b'd' + b''.join(enc(k) + enc(value[k]) for k in sorted(value)) + b'e'


def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(16)
    return sock


def port():
    with listener() as sock:
        return sock.getsockname()[1]


def certificates(root):
    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
            '-subj', '/CN=collision-test-ca', '-keyout', root/'ca.key',
            '-out', root/'ca.crt')
    (root/'ext').write_text('basicConstraints=critical,CA:FALSE\n'
                           'keyUsage=critical,digitalSignature\n'
                           'extendedKeyUsage=serverAuth,clientAuth\n')
    for name in ('seed', 'leech'):
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt',
                'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN='+name,
                '-keyout', root/(name+'.key'), '-out', root/(name+'.csr'))
        openssl('x509', '-req', '-in', root/(name+'.csr'), '-CA', root/'ca.crt',
                '-CAkey', root/'ca.key', '-CAcreateserial', '-days', '1',
                '-extfile', root/'ext', '-out', root/(name+'.crt'))


def run(args, root):
    stopped = threading.Event()
    condition = threading.Condition()
    pending = [[], []]
    pairs = [0]
    processes = []
    peers = [port(), port()]
    rpcports = [port(), port()]
    relays = [listener(), listener()]
    relayports = [s.getsockname()[1] for s in relays]

    def relay(source, target, ready):
        with source:
            if not ready.wait(args.timeout):
                return
            try:
                with socket.create_connection(('127.0.0.1', target), timeout=5) as destination:
                    source.settimeout(5)
                    while not stopped.is_set():
                        readable, _, _ = select.select([source, destination], [], [], .2)
                        for current in readable:
                            data = current.recv(65536)
                            if not data:
                                # Keep a rejected outgoing slot occupied long
                                # enough for the opposite incoming handshake.
                                # Otherwise an EOF can accidentally cure the
                                # collision before both admissions run.
                                if current is destination:
                                    time.sleep(1)
                                return
                            forward = destination if current is source else source
                            if args.fragment and len(data) > 32:
                                forward.sendall(data[:32])
                                time.sleep(.01)
                                forward.sendall(data[32:])
                            else:
                                forward.sendall(data)
            except OSError:
                return

    def accept(index):
        sock = relays[index]
        sock.settimeout(.2)
        while not stopped.is_set():
            try:
                source, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            ready = threading.Event()
            threading.Thread(target=relay, args=(source, peers[index], ready), daemon=True).start()
            with condition:
                pending[index].append(ready)
                while all(pending):
                    pairs[0] += 1
                    for queue in pending:
                        queue.pop(0).set()

    class Tracker(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            caller = int(parse_qs(urlsplit(self.path).query)['port'][0])
            other = 1 - peers.index(caller)
            body = enc({b'interval': 1, b'peers': socket.inet_aton('127.0.0.1') +
                        struct.pack('!H', relayports[other])})
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
    threading.Thread(target=tracker.serve_forever, daemon=True).start()
    for index in (0, 1):
        threading.Thread(target=accept, args=(index,), daemon=True).start()
    data = b'IRIS one-peer collision regression\n' * 131072
    digest = hashlib.sha256(data).hexdigest()
    info = {b'name': b'payload', b'length': len(data), b'piece length': 65536,
            b'pieces': b''.join(hashlib.sha1(data[i:i+65536]).digest()
                               for i in range(0, len(data), 65536))}
    torrent = root/'test.torrent'
    torrent.write_bytes(enc({b'announce': f'http://127.0.0.1:{tracker.server_port}/announce'.encode(), b'info': info}))
    if args.tls:
        certificates(root)
    maximum = [0, 0]
    try:
        for index, name in enumerate(('seed', 'leech')):
            directory = root/name
            directory.mkdir()
            if index == 0:
                (directory/'payload').write_bytes(data)
            prefix = '-331A-' if index == int(args.reverse_ids) else '-331Z-'
            flags = [str(args.binary.resolve()), '--no-conf', '--enable-dht=false',
                     '--enable-dht6=false', '--enable-peer-exchange=false', '--bt-enable-lpd=false',
                     '--bt-max-peers=1', '--bt-tracker-interval=1', '--seed-ratio=0',
                     '--file-allocation=none', '--check-integrity=true', '--enable-rpc=true',
                     '--rpc-secret=collision-test', '--peer-id-prefix='+prefix,
                     '--rpc-listen-port='+str(rpcports[index]), '--listen-port='+str(peers[index]),
                     '--dir='+str(directory), '--log='+str(directory/'trace.log'), '--log-level=debug']
            if args.tls:
                flags += ['--bt-peer-tls=required', '--bt-peer-tls-cert='+str(root/(name+'.crt')),
                          '--bt-peer-tls-key='+str(root/(name+'.key')), '--bt-peer-tls-ca='+str(root/'ca.crt')]
            with (directory/'console.log').open('w') as log:
                processes.append(subprocess.Popen(flags+[str(torrent)], stdout=log, stderr=log))
        started = time.monotonic()
        while time.monotonic() - started < args.timeout:
            for index in (0, 1):
                request = urllib.request.Request(f'http://127.0.0.1:{rpcports[index]}/jsonrpc',
                    data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'aria2.tellActive',
                                     'params': ['token:collision-test', ['connections']]}).encode())
                try:
                    with urllib.request.urlopen(request, timeout=1) as response:
                        rows = json.load(response)['result']
                    for row in rows:
                        maximum[index] = max(maximum[index], int(row['connections']))
                    assert maximum[index] <= 1, maximum
                except OSError:
                    pass  # RPC may still be starting.
            target = root/'leech/payload'
            if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
                assert pairs[0] >= 1
                arbitrations = sum((root/name/'trace.log').read_text().count(
                    'Yielding pending outgoing peer slot') for name in ('seed', 'leech'))
                result = {'mode': 'required' if args.tls else 'legacy', 'reverse_ids': args.reverse_ids,
                          'fragmented': args.fragment, 'collision_yields': arbitrations,
                          'bytes': len(data), 'sha256': digest, 'crossed_dial_pairs': pairs[0],
                          'maximum_rpc_peers': maximum, 'seconds': round(time.monotonic()-started, 3)}
                (root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
                print(json.dumps(result), flush=True)
                return
            time.sleep(.1)
        raise AssertionError(f'transfer stalled after {args.timeout}s; paired dials={pairs[0]}; logs={root}')
    finally:
        stopped.set()
        for queue in pending:
            for event in queue:
                event.set()
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for sock in relays:
            sock.close()
        tracker.shutdown()
        tracker.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--reverse-ids', action='store_true')
    parser.add_argument('--fragment', action='store_true',
                        help='split relay writes to exercise partial handshakes')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--log-dir', type=Path)
    args = parser.parse_args()
    if args.log_dir:
        args.log_dir.mkdir(parents=True, exist_ok=False)
        run(args, args.log_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='iris-peer-collision-') as directory:
            run(args, Path(directory))
