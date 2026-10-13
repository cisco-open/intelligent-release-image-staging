#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Require fresh tracker announces while a real TLS peer saturates QoS.

Run with an exact candidate digest. Uses existing native certificate fixtures,
loopback HTTP tracker and mandatory hybrid peer TLS. An independent ordinary
HTTP download must remain globally capped. Retains failures and cleans children.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import struct
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main(args):
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    helper = load(Path(__file__).with_name('test-peer-collision.py'), 'existing_tls_fixture')
    reader = load(Path(__file__).with_name('test-revocation-reader.py'), 'existing_certificates')
    binary = args.binary.resolve()
    expected = args.sha256
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
    _, authority = reader.certificates(root)
    (root / 'revocations').write_bytes(reader.snapshot(authority))
    for file in root.iterdir():
        if file.is_file():
            file.chmod(0o600)
    seed = root / 'seed'; seed.mkdir(mode=0o700)
    receiver = root / 'receiver'; receiver.mkdir(mode=0o700)
    piece = b'IRIS bounded tracker timing diagnostic\n'
    piece = (piece * (65536 // len(piece) + 1))[:65536]
    pieces = 4096
    size = pieces * len(piece)
    digest = hashlib.sha256()
    with (seed / 'payload').open('xb') as output:
        for _ in range(pieces):
            output.write(piece); digest.update(piece)
    info = {b'name': b'payload', b'length': size, b'piece length': len(piece),
            b'pieces': hashlib.sha1(piece).digest() * pieces}
    ports = [helper.port(), helper.port()]
    rpcports = [helper.port(), helper.port()]
    events = []
    lock = threading.Lock()
    started = time.monotonic()

    class Tracker(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_GET(self):
            if self.path == '/payload':
                self.send_response(200)
                self.send_header('Content-Length', str(size))
                self.end_headers()
                try:
                    for _ in range(pieces):
                        self.wfile.write(piece)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            query = parse_qs(urlsplit(self.path).query)
            caller = int(query['port'][0])
            assert caller in ports
            role = ports.index(caller)
            record = {'at': time.time(), 'elapsed': time.monotonic() - started,
                      'role': 'source' if role == 0 else 'receiver',
                      'event': query.get('event', ['regular'])[0],
                      'left': int(query['left'][0]), 'downloaded': int(query['downloaded'][0]),
                      'uploaded': int(query['uploaded'][0]), 'status': 200,
                      'issuedInterval': 30, 'writeCompleted': False}
            body = helper.enc({b'interval': 30, b'min interval': 30,
                b'peers': socket.inet_aton('127.0.0.1') + struct.pack('!H', ports[1 - role])})
            try:
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
                record['writeCompleted'] = True
            finally:
                with lock:
                    events.append(record)

    tracker = ThreadingHTTPServer(('127.0.0.1', 0), Tracker)
    thread = threading.Thread(target=tracker.serve_forever, daemon=True)
    thread.start()
    torrent = root / 'fixture.torrent'
    torrent.write_bytes(helper.enc({b'announce':
        f'http://127.0.0.1:{tracker.server_port}/announce'.encode(), b'info': info}))
    processes = []
    samples = []
    result = {'nativeRegressionOnly': True, 'qualificationEligible': False,
              'ariaSha256': expected, 'openssl': ssl.OPENSSL_VERSION,
              'payloadSize': size, 'payloadSha256': digest.hexdigest(),
              'trackerInterval': 30, 'clientIntervalOverride': False,
              'receiverOverallDownBps': 524288, 'receiverTorrentDownBps': 524288,
              'peerTls': 'required', 'controlTracker': 'isolated-loopback-http', 'observationSeconds': args.seconds,
              'announces': events, 'samples': samples, 'allChildrenAbsent': False}

    def rpc(index):
        request = urllib.request.Request(f'http://127.0.0.1:{rpcports[index]}/jsonrpc', data=json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': 'aria2.tellActive',
            'params': ['token:local-tracker-diagnostic',
                       ['gid', 'status', 'completedLength', 'downloadSpeed', 'uploadSpeed', 'connections']]}).encode())
        with urllib.request.urlopen(request, timeout=1) as response:
            return json.load(response)['result']

    try:
        # Ordinary HTTP payload must still obey the aggregate cap. This group
        # is not created by TrackerWatcherCommand and cannot acquire its flag.
        httpdir = root / 'http-payload'; httpdir.mkdir(mode=0o700)
        rpcports.append(helper.port())
        http_argv = [str(binary), '--no-conf', '--enable-rpc=true', '--rpc-listen-all=false',
            '--rpc-secret=local-tracker-diagnostic', '--rpc-listen-port=' + str(rpcports[2]),
            '--max-overall-download-limit=524288', '--max-download-limit=0',
            '--file-allocation=none', '--dir=' + str(httpdir),
            f'http://127.0.0.1:{tracker.server_port}/payload']
        with (httpdir / 'console.log').open('xb') as log:
            http_process = subprocess.Popen(http_argv, stdout=log, stderr=log)
        processes.append(http_process)
        http_start = time.monotonic()
        while time.monotonic() - http_start < 10:
            assert http_process.poll() is None, 'HTTP payload bypassed its global cap or exited'
            time.sleep(.2)
        http_rows = rpc(2)
        assert len(http_rows) == 1
        http_bytes = int(http_rows[0]['completedLength'])
        http_elapsed = time.monotonic() - http_start
        result['ordinaryHttpPayload'] = {'bytes': http_bytes, 'seconds': http_elapsed,
            'globalLimit': 524288, 'perRequestLimit': 0}
        assert 524288 < http_bytes <= 524288 * (http_elapsed + 2), 'Ordinary HTTP global rate limit changed'
        http_process.terminate(); http_process.wait(timeout=10)
        processes.remove(http_process)
        for index, (directory, identity) in enumerate(((seed, 'local'), (receiver, 'allowed'))):
            argv = [str(binary), '--no-conf', '--enable-dht=false', '--enable-dht6=false',
                '--enable-peer-exchange=false', '--bt-enable-lpd=false', '--bt-max-peers=8',
                '--seed-ratio=0', '--file-allocation=none', '--check-integrity=true',
                '--enable-rpc=true', '--rpc-listen-all=false', '--rpc-secret=local-tracker-diagnostic',
                '--rpc-listen-port=' + str(rpcports[index]), '--listen-port=' + str(ports[index]),
                '--dir=' + str(directory), '--log=' + str(directory / 'aria.log'), '--log-level=info',
                '--bt-peer-tls=required', '--bt-peer-tls-cert=' + str(root / (identity + '.crt')),
                '--bt-peer-tls-key=' + str(root / (identity + '.key')), '--bt-peer-tls-ca=' + str(root / 'ca.crt'),
                '--bt-peer-tls-revocations=' + str(root / 'revocations')]
            if index == 1:
                argv += ['--max-overall-download-limit=524288', '--max-download-limit=524288']
            with (directory / 'console.log').open('xb') as log:
                processes.append(subprocess.Popen(argv + [str(torrent)], stdout=log, stderr=log))
            deadline = time.monotonic() + 15
            while True:
                assert processes[-1].poll() is None, 'Pinned aria exited at startup'
                try:
                    rows = rpc(index)
                    if rows and (index == 1 or int(rows[0]['completedLength']) == size):
                        break
                except OSError:
                    pass
                assert time.monotonic() < deadline, 'Startup deadline'
                time.sleep(.1)
        observation_start = time.monotonic()
        last_print = -30
        while time.monotonic() - observation_start < args.seconds:
            sample = {'at': time.time(), 'elapsed': time.monotonic() - started}
            for index, name in enumerate(('source', 'receiver')):
                assert processes[index].poll() is None, 'Pinned aria exited during observation'
                sample[name] = rpc(index)
            samples.append(sample)
            if sample['elapsed'] - last_print >= 30:
                print(json.dumps({'elapsed': round(sample['elapsed'], 1),
                      'receiver': sample['receiver'], 'announces': len(events)}), flush=True)
                last_print = sample['elapsed']
            time.sleep(2)
        result['observedPayloadBytes'] = max(int(row['completedLength']) for sample in samples for row in sample['receiver'])
        result['maxAnnounceGapSeconds'] = {}
        for role in ('source', 'receiver'):
            times = [event['elapsed'] for event in events if event['role'] == role]
            result['maxAnnounceGapSeconds'][role] = max((b - a for a, b in zip(times, times[1:])), default=None)
        result['finalSilentTailSeconds'] = {role: samples[-1]['elapsed'] - max(event['elapsed'] for event in events if event['role'] == role) for role in ('source', 'receiver')}
        result['observationComplete'] = True
        violations = []
        for role in ('source', 'receiver'):
            matching = [event for event in events if event['role'] == role]
            if len(matching) < 4 or not all(event['status'] == 200 and event['writeCompleted'] for event in matching):
                violations.append(role + '-announce-count-or-status')
            if result['maxAnnounceGapSeconds'][role] is None or result['maxAnnounceGapSeconds'][role] > 45:
                violations.append(role + '-announce-gap')
            if result['finalSilentTailSeconds'][role] > 45:
                violations.append(role + '-announce-silent-tail')
        if not 524288 * args.seconds * .4 < result['observedPayloadBytes'] <= 524288 * (args.seconds + 10):
            violations.append('peer-payload-rate')
        for directory in (seed, receiver):
            log = (directory / 'aria.log').read_text()
            if 'protocol=TLSv1.3 group=X25519MLKEM768 cipher=TLS_AES_' not in log or 'alpn=aria2-bt/1 peer_auth=verified' not in log:
                violations.append(directory.name + '-required-peer-tls')
        result['violations'] = violations
        result['passed'] = not violations
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
        tracker.shutdown(); tracker.server_close(); thread.join(timeout=2)
        result['allChildrenAbsent'] = all(process.poll() is not None for process in processes) and not thread.is_alive()
        result['passed'] = result.get('passed') is True and result['allChildrenAbsent']
        (root / 'result.json').write_text(json.dumps(result, sort_keys=True) + '\n')
        print(json.dumps({key: value for key, value in result.items() if key not in ('announces', 'samples')}), flush=True)
    assert result.get('passed') is True and result['allChildrenAbsent'], 'Native tracker throttle regression failed; retained result.json'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--seconds', type=int, choices=range(120, 241), default=180)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
