#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Exercise identity withdrawal in real TLS peers sharing one loopback address.

The origin alone receives hot updates. An optional pre-feature binary remains
unaware of withdrawal, proving that enforcement belongs to the receiving peer.
Generated certificates use the SAN format issued before revocation support.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


spec = importlib.util.spec_from_file_location('revocation_reader',
    Path(__file__).with_name('test-revocation-reader.py'))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def encode(value):
    if isinstance(value, int):
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    return b'd' + b''.join(encode(key) + encode(value[key]) for key in sorted(value)) + b'e'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run(args, root):
    identities, authority = reader.certificates(root)
    names = ('local', 'withdrawn', 'allowed')
    prefixes = ('-REV0-', '-REVA-', '-REVB-')
    listen = [free_port() for _ in names]
    rpc = [free_port() for _ in names]
    processes = []
    observed = set()

    class Tracker(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            caller = int(parse_qs(urlsplit(self.path).query)['port'][0])
            observed.add(caller)
            others = ((observed.copy() - {caller}) if caller == listen[0]
                      else ({listen[0]} if listen[0] in observed else set()))
            body = encode({b'interval': 1, b'peers': b''.join(
                socket.inet_aton('127.0.0.1') + struct.pack('!H', port)
                for port in sorted(others))})
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
    threading.Thread(target=tracker.serve_forever, daemon=True).start()
    data = b'IRIS identity withdrawal must not block shared addresses\n' * 262144
    info = {b'name': b'payload', b'length': len(data), b'piece length': 65536,
            b'pieces': b''.join(hashlib.sha1(data[offset:offset+65536]).digest()
                               for offset in range(0, len(data), 65536))}
    torrent = root/'test.torrent'
    torrent.write_bytes(encode({b'announce':
        f'http://127.0.0.1:{tracker.server_port}/announce'.encode(), b'info': info}))
    sequence = []

    def publish(index, revision, denied=(), *, expires=None, raw=None):
        path = root/names[index]/'revocations'
        pending = path.with_suffix('.new')
        pending.write_bytes(raw if raw is not None else reader.snapshot(
            authority, revision=revision, identities=denied, expires=expires))
        pending.chmod(0o600)
        os.replace(pending, path)

    def call(index, method, *params):
        request = urllib.request.Request(f'http://127.0.0.1:{rpc[index]}/jsonrpc',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'aria2.' + method,
                             'params': ['token:revocation-test', *params]}).encode())
        with urllib.request.urlopen(request, timeout=2) as response:
            result = json.load(response)
        if 'error' in result:
            raise RuntimeError(result['error'])
        return result['result']

    def peers():
        rows = call(0, 'tellActive', ['gid'])
        return {unquote(peer.get('peerId', ''))[:6]
                for row in rows for peer in call(0, 'getPeers', row['gid'])}

    def wait(label, predicate, timeout=20):
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if any(process.poll() is not None for process in processes):
                raise AssertionError('A peer exited during ' + label)
            try:
                if predicate():
                    duration = round(time.monotonic()-started, 3)
                    sequence.append({'check': label, 'seconds': duration})
                    return duration
            except (OSError, urllib.error.URLError, RuntimeError):
                pass
            time.sleep(.1)
        raise AssertionError(label + ' timed out; evidence: ' + str(root))

    def state():
        return call(0, 'getPeerTLSRevocationStatus')

    try:
        for index, name in enumerate(names):
            directory = root/name
            directory.mkdir()
            publish(index, 0)
            if index == 0:
                (directory/'payload').write_bytes(data)
            binary = args.old_binary if index == 1 and args.old_binary else args.binary
            flags = [str(binary.resolve()), '--no-conf', '--enable-dht=false',
                     '--enable-dht6=false', '--enable-peer-exchange=false', '--bt-enable-lpd=false',
                     '--bt-max-peers=8', '--bt-tracker-interval=1', '--seed-ratio=0',
                     '--file-allocation=none', '--check-integrity=true', '--enable-rpc=true',
                     '--rpc-secret=revocation-test', '--peer-id-prefix='+prefixes[index],
                     '--rpc-listen-port='+str(rpc[index]), '--listen-port='+str(listen[index]),
                     '--max-overall-download-limit=32K', '--max-overall-upload-limit=128K',
                     '--dir='+str(directory), '--log='+str(directory/'trace.log'), '--log-level=info',
                     '--bt-peer-tls=required', '--bt-peer-tls-cert='+str(root/(name+'.crt')),
                     '--bt-peer-tls-key='+str(root/(name+'.key')), '--bt-peer-tls-ca='+str(root/'ca.crt')]
            if index == 0:
                rejected = subprocess.run(flags+[str(torrent)], capture_output=True, timeout=5)
                assert rejected.returncode != 0
                assert b'fresh bt-peer-tls-revocations' in rejected.stdout + rejected.stderr
                sequence.append({'check': 'required TLS refuses a missing revocation option', 'seconds': 0})
            if not (index == 1 and args.old_binary):
                flags += ['--bt-peer-tls-revocations='+str(directory/'revocations')]
            with (directory/'console.log').open('w') as output:
                processes.append(subprocess.Popen(flags+[str(torrent)], stdout=output, stderr=output))
        wait('both identities connected from the same IP',
             lambda: {'-REVA-', '-REVB-'} <= peers())
        initial = state()
        assert initial == {'supported': True, 'mode': 'required', 'state': 'valid',
            'authority': authority, 'revision': 0, 'issued_at': initial['issued_at'],
            'expires_at': initial['expires_at'], 'own_revoked': False}, initial
        wait('both peers received payload', lambda: all(
            any(int(row['completedLength']) > 0 for row in call(index, 'tellActive', ['completedLength']))
            for index in (1, 2)))
        publish(0, 1, [identities['withdrawn']])
        cutoff = wait('withdrawn identity disconnected while shared-IP peer remains',
            lambda: state()['revision'] == 1 and '-REVA-' not in peers() and '-REVB-' in peers(),
            timeout=5)
        # A new outbound TLS attempt cannot restore the withdrawn identity.
        time.sleep(3)
        assert '-REVA-' not in peers() and '-REVB-' in peers()
        publish(0, 1, raw=b'invalid\n')
        wait('invalid snapshot closes existing connections',
             lambda: state()['state'] == 'unavailable' and not peers(), timeout=5)
        publish(0, 2, [identities['withdrawn']])
        wait('fresh snapshot restores only allowed peer',
             lambda: state()['state'] == 'valid' and '-REVB-' in peers() and '-REVA-' not in peers())
        # Let all timestamps change before creating a shorter fresh lease.
        time.sleep(1.1)
        publish(0, 3, [identities['withdrawn']], expires=int(time.time())+3)
        wait('runtime acknowledges short lease', lambda: state()['revision'] == 3, timeout=3)
        wait('expired snapshot closes active peers',
             lambda: state()['state'] == 'expired' and not peers(), timeout=6)
        publish(0, 4, [identities['withdrawn']])
        wait('allowed identity reconnects after a renewed snapshot', lambda: '-REVB-' in peers())
        publish(0, 5, [identities['withdrawn'], identities['local']])
        wait('own identity withdrawal closes every peer',
             lambda: state()['own_revoked'] and not peers(), timeout=5)
        result = {'passed': True, 'withdrawal_cutoff_seconds': cutoff,
                  'old_binary_peer': bool(args.old_binary), 'shared_ip_isolation': True,
                  'checks': sequence}
        (root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result), flush=True)
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        tracker.shutdown()
        tracker.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--old-binary', type=Path)
    parser.add_argument('--log-dir', type=Path)
    args = parser.parse_args()
    if args.log_dir:
        args.log_dir.mkdir(parents=True, exist_ok=False)
        run(args, args.log_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='iris-peer-revocation-') as directory:
            run(args, Path(directory))
