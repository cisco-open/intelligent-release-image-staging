# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Enroll and renew a private peer identity using pre-flight catalog trust.

Stdlib and the device's OpenSSL CLI only. Private keys remain on this node.
The returned aria2 config fragment references one immutable certificate generation.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile


class PeerTLSError(Exception):
    pass


def _openssl(*args, data=None):
    try:
        return subprocess.run(['openssl', *map(str, args)], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        raise PeerTLSError('peer certificate operation failed') from None


def _valid(cert, ca, seconds=0):
    try:
        _openssl('x509', '-in', cert, '-checkend', str(seconds), '-noout')
        for purpose in ('sslclient', 'sslserver'):
            _openssl('verify', '-CAfile', ca, '-purpose', purpose, cert)
        return True
    except PeerTLSError:
        return False


def _identity_valid(cert, ca, key, device_id, seconds=0):
    if cert is None or not _valid(cert, ca, seconds):
        return False
    try:
        if any(path.is_symlink() or path.parent.is_symlink() for path in (cert, ca)):
            return False
        public = _openssl('pkey', '-in', key, '-pubout')
        identity = hashlib.sha256(device_id.encode('utf-8')).hexdigest()
        subject = _openssl('x509', '-in', cert, '-subject', '-noout', '-nameopt', 'RFC2253')
        return (public == _openssl('x509', '-in', cert, '-pubkey', '-noout')
                and subject.strip() == ('subject=CN=' + identity).encode('ascii'))
    except PeerTLSError:
        return False


def _sync_dir(path):
    import errno
    fd = os.open(str(path), os.O_RDONLY)
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
    finally:
        os.close(fd)


def _write(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def ensure(cfg, client):
    mode = cfg.get('peer_tls_mode', 'disabled')
    if mode == 'disabled':
        return 'bt-peer-tls=disabled\n'
    if mode != 'required':
        raise PeerTLSError('invalid peer TLS mode')
    root = Path(cfg['stage_dir']) / 'peer-tls'
    if not root.is_absolute() or any(c in str(root) for c in '\r\n'):
        raise PeerTLSError('invalid peer identity directory')
    if root.is_symlink():
        raise PeerTLSError('peer identity directory must not be a symlink')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise PeerTLSError('peer identity directory permissions are unsafe')
    if (root / 'enrollment.lock').is_symlink():
        raise PeerTLSError('unsafe enrollment lock')
    with (root / 'enrollment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        key = root / 'node.key'
        manifest = root / 'current.json'
        if key.is_symlink() or manifest.is_symlink():
            raise PeerTLSError('peer identity files must not be symlinks')
        if not key.exists():
            with tempfile.TemporaryDirectory(dir=str(root)) as tmp:
                pending = Path(tmp) / 'node.key'
                _write(pending, b'')
                _openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', pending)
                with pending.open('rb') as stream:
                    os.fsync(stream.fileno())
                os.replace(str(pending), str(key))
                _sync_dir(root)
        if key.stat().st_mode & 0o077:
            raise PeerTLSError('peer private key permissions are unsafe')
        cert = ca = None
        if manifest.exists():
            try:
                row = json.loads(manifest.read_text())
                generation = row['generation']
                if (not isinstance(generation, str) or len(generation) != 64
                        or any(c not in '0123456789abcdef' for c in generation)):
                    raise ValueError()
                cert, ca = root / generation / 'node.crt', root / generation / 'ca.crt'
            except (ValueError, KeyError, TypeError):
                raise PeerTLSError('invalid peer identity manifest') from None
        if not _identity_valid(cert, ca, key, cfg['device_id'], 21600):
            csr = _openssl('req', '-new', '-key', key, '-subj', '/CN=IRIS enrollment')
            try:
                response = client.enroll_peer_tls(cfg['device_id'], csr.decode('ascii'))
                if not isinstance(response, dict) or response.get('mode') != 'required':
                    raise PeerTLSError('peer enrollment response is invalid')
                leaf_bytes = response['certificate'].encode('ascii')
                ca_bytes = response['ca'].encode('ascii')
                if len(leaf_bytes) > 16384 or len(ca_bytes) > 16384:
                    raise PeerTLSError('peer enrollment response is too large')
                with tempfile.TemporaryDirectory(dir=str(root)) as tmp:
                    pending = Path(tmp)
                    _write(pending / 'node.crt', leaf_bytes)
                    _write(pending / 'ca.crt', ca_bytes)
                    if not _valid(pending / 'node.crt', pending / 'ca.crt', 21600):
                        raise PeerTLSError('peer certificate validation failed')
                    public = _openssl('pkey', '-in', key, '-pubout')
                    if public != _openssl('x509', '-in', pending / 'node.crt', '-pubkey', '-noout'):
                        raise PeerTLSError('peer certificate does not match local key')
                    identity = hashlib.sha256(cfg['device_id'].encode('utf-8')).hexdigest()
                    subject = _openssl('x509', '-in', pending / 'node.crt', '-subject', '-noout', '-nameopt', 'RFC2253')
                    if subject.strip() != ('subject=CN=' + identity).encode('ascii'):
                        raise PeerTLSError('peer certificate identity does not match')
                    if ca is not None and ca.exists():
                        old = ssl.PEM_cert_to_DER_cert(ca.read_text())
                        new = ssl.PEM_cert_to_DER_cert(ca_bytes.decode('ascii'))
                        if old != new:
                            raise PeerTLSError('peer CA changed; explicit trust rotation required')
                    generation = hashlib.sha256(leaf_bytes + ca_bytes).hexdigest()
                    destination = root / generation
                    if not destination.exists():
                        ready = pending / 'generation'
                        ready.mkdir(mode=0o700)
                        os.replace(str(pending / 'node.crt'), str(ready / 'node.crt'))
                        os.replace(str(pending / 'ca.crt'), str(ready / 'ca.crt'))
                        _sync_dir(ready)
                        os.replace(str(ready), str(destination))
                        _sync_dir(root)
                    elif ((destination / 'node.crt').read_bytes() != leaf_bytes
                          or (destination / 'ca.crt').read_bytes() != ca_bytes):
                        raise PeerTLSError('peer certificate generation is corrupt')
                    state = pending / 'current.json'
                    _write(state, json.dumps({'generation': generation}).encode('ascii'))
                    os.replace(str(state), str(manifest))
                    _sync_dir(root)
                    cert, ca = destination / 'node.crt', destination / 'ca.crt'
            except Exception:
                if not _identity_valid(cert, ca, key, cfg['device_id']):
                    raise PeerTLSError('peer enrollment unavailable and no valid identity remains') from None
                # A still-valid identity may survive transient renewal failures.
        return ('bt-peer-tls=required\nbt-peer-tls-cert=%s\nbt-peer-tls-key=%s\n'
                'bt-peer-tls-ca=%s\n' % (cert, key, ca))


def main():
    import argparse
    import sys
    from urllib.parse import urlsplit
    import agent_config
    from catalog_client import CatalogClient
    parser = argparse.ArgumentParser()
    parser.add_argument('--conf', required=True)
    args = parser.parse_args()
    try:
        cfg = agent_config.load(args.conf)
        cfg['peer_tls_mode'] = os.environ.get('IRIS_PEER_TLS_MODE', cfg.get('peer_tls_mode', 'disabled'))
        if cfg['peer_tls_mode'] == 'disabled':
            return 0
        if urlsplit(cfg['catalog_url']).scheme != 'https':
            raise PeerTLSError('peer enrollment requires verified HTTPS')
        context = ssl.create_default_context(cafile=cfg['catalog_ca'])
        client = CatalogClient(cfg['catalog_url'], cfg['catalog_token'], context=context)
        sys.stdout.write(ensure(cfg, client))
        return 0
    except Exception:
        print('peer identity unavailable; refusing unencrypted peer transport', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
