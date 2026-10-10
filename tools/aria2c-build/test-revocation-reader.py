#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Test the exact C++ peer-revocation parser via the static revocation probe.

Compile revocation-probe.cc with the patched source's BtPeerRevocations.cc,
OpenSSL and C++17. No IRIS deployment, credentials or external network is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True).stdout


def certificates(root):
    command('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
            '-subj', '/CN=IRIS revocation test CA', '-keyout', root/'ca.key',
            '-out', root/'ca.crt')
    identities = {name: hashlib.sha256(name.encode()).hexdigest()
                  for name in ('local', 'withdrawn', 'allowed', 'replacement')}
    for name in (*identities, 'missing', 'duplicate', 'malformed'):
        extension = ('basicConstraints=critical,CA:FALSE\n'
                     'keyUsage=critical,digitalSignature\n'
                     'extendedKeyUsage=serverAuth,clientAuth\n')
        if name in identities:
            extension += 'subjectAltName=URI:urn:iris:device:' + identities[name] + '\n'
        elif name == 'duplicate':
            extension += ('subjectAltName=URI:urn:iris:device:' + identities['allowed']
                          + ',URI:urn:iris:device:' + identities['withdrawn'] + '\n')
        elif name == 'malformed':
            extension += 'subjectAltName=URI:urn:iris:device:invalid\n'
        (root/'ext').write_text(extension)
        command('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
                'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=' + name,
                '-keyout', root/(name+'.key'), '-out', root/(name+'.csr'))
        command('openssl', 'x509', '-req', '-in', root/(name+'.csr'), '-CA', root/'ca.crt',
                '-CAkey', root/'ca.key', '-CAcreateserial', '-days', '1',
                '-extfile', root/'ext', '-out', root/(name+'.crt'))
    authority = hashlib.sha256(command('openssl', 'x509', '-in', root/'ca.crt',
                                       '-outform', 'DER')).hexdigest()
    return identities, authority


def snapshot(authority, revision=0, issued=None, expires=None, identities=()):
    issued = int(time.time()) if issued is None else issued
    expires = issued + 300 if expires is None else expires
    return ('IRIS-PEER-REVOCATIONS-1\n' + authority + '\n' + str(revision) + '\n'
            + str(issued) + '\n' + str(expires) + '\n'
            + ''.join(value + '\n' for value in sorted(identities))).encode()


class Probe:
    def __init__(self, binary, root, local='local'):
        self.process = subprocess.Popen([str(binary), str(root/'revocations'),
            str(root/'ca.crt'), str(root/(local+'.crt'))], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.root = root

    def check(self, peer='allowed'):
        self.process.stdin.write(str(self.root/(peer+'.crt')) + '\n')
        self.process.stdin.flush()
        assert select.select([self.process.stdout], [], [], 3)[0], 'Native reader did not respond'
        return json.loads(self.process.stdout.readline())

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=3) == 0
        assert self.process.stderr.read() == ''
        self.process.stdout.close()
        self.process.stderr.close()


def run(binary, root):
    ids, authority = certificates(root)
    path = root/'revocations'
    checks = 0

    def publish(value):
        pending = root/'pending'
        pending.write_bytes(value)
        pending.chmod(0o600)
        os.replace(pending, path)

    def once(value, expected=False, peer='allowed', local='local'):
        nonlocal checks
        publish(value)
        probe = Probe(binary, root, local)
        try:
            result = probe.check(peer)
            assert result['allowed'] is expected, (result, value[:150])
            checks += 1
            return result
        finally:
            probe.close()

    valid = snapshot(authority)
    once(valid, True)
    once(snapshot(authority, revision=9007199254740991), True)
    once(snapshot(authority, identities=[ids['withdrawn']]), False, 'withdrawn')
    once(snapshot(authority, identities=[ids['withdrawn']]), True, 'replacement')
    assert once(snapshot(authority, identities=[ids['local']]))['own_revoked']
    for peer in ('missing', 'duplicate', 'malformed'):
        once(valid, peer=peer)
    for local in ('missing', 'duplicate', 'malformed'):
        once(valid, local=local)
    now = int(time.time())
    invalid = [b'', valid[:-1], valid + b'\n', valid.replace(b'REVOCATIONS-1', b'REVOCATIONS-2'),
               snapshot('f'*64), snapshot(authority, revision=-1),
               snapshot(authority, revision='01'), snapshot(authority, revision='1.0'),
               snapshot(authority, revision=9007199254740992),
               snapshot(authority, issued=now-301, expires=now-1),
               snapshot(authority, issued=now+60),
               snapshot(authority, issued=now, expires=now+301),
               snapshot(authority, issued=now, expires=now),
               valid + ids['allowed'].upper().encode() + b'\n',
               valid + (ids['allowed']+'\n'+ids['allowed']+'\n').encode(),
               valid + ('f'*64+'\n'+'a'*64+'\n').encode(),
               valid + b'bad\x00identity\n', b'x'*(1024*1024+1),
               valid + ''.join(f'{i:064x}\n' for i in range(10001)).encode()]
    for value in invalid:
        once(value)
    for kind in ('absent', 'linked', 'writable', 'directory', 'fifo'):
        publish(valid)
        if kind == 'writable':
            path.chmod(0o666)
        else:
            path.unlink()
            if kind == 'linked':
                (root/'other').write_bytes(valid)
                path.symlink_to(root/'other')
            elif kind == 'directory':
                path.mkdir()
            elif kind == 'fifo':
                os.mkfifo(path)
        probe = Probe(binary, root)
        try:
            assert not probe.check()['allowed'], kind
            checks += 1
        finally:
            probe.close()
            if kind == 'directory':
                path.rmdir()
            elif path.exists() or path.is_symlink():
                path.unlink()

    # One running native reader must reject rollback/equivocation and recover
    # only when its accepted snapshot is restored or legitimately advanced.
    base = int(time.time())
    initial = snapshot(authority, issued=base)
    withdrawn = snapshot(authority, revision=1, issued=base, identities=[ids['withdrawn']])
    publish(initial)
    probe = Probe(binary, root)
    try:
        assert probe.check('withdrawn')['allowed']
        changes = [(withdrawn, 'withdrawn', False, 'valid'),
                   (withdrawn, 'allowed', True, 'valid'),
                   (initial, 'allowed', False, 'unavailable'),
                   (withdrawn, 'allowed', True, 'valid'),
                   (snapshot(authority, revision=1, issued=base), 'allowed', False, 'unavailable'),
                   (snapshot(authority, revision=2, issued=base-1,
                             identities=[ids['withdrawn']]), 'allowed', False, 'unavailable'),
                   (snapshot(authority, revision=2, issued=base,
                             identities=[ids['withdrawn']]), 'allowed', True, 'valid'),
                   (b'invalid', 'allowed', False, 'unavailable')]
        for value, peer, allowed, state in changes:
            publish(value)
            time.sleep(1.05)
            result = probe.check(peer)
            assert (result['allowed'], result['state']) == (allowed, state), result
            checks += 1
    finally:
        probe.close()
    publish(snapshot(authority, expires=int(time.time())+2))
    probe = Probe(binary, root)
    try:
        assert probe.check()['allowed']
        time.sleep(2.05)
        result = probe.check()
        assert result['state'] == 'expired' and not result['allowed'], result
        checks += 1
    finally:
        probe.close()
    print(json.dumps({'passed': checks, 'component': 'native revocation reader'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='iris-native-revocation-') as directory:
        run(args.probe.resolve(), Path(directory))
