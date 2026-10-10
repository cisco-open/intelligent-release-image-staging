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
import re
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


def _subject_matches(subject, identity):
    # OpenSSL 1.0.2 (Guest Shell) inserts a space after "subject="; newer
    # versions do not. Keep the complete RFC2253 name comparison exact.
    label, separator, name = subject.strip().partition(b'=')
    return (label == b'subject' and separator == b'=' and
            name.lstrip(b' ') == ('CN=' + identity).encode('ascii'))


def _certificate_matches(cert, identity):
    subject = _openssl('x509', '-in', cert, '-subject', '-noout', '-nameopt', 'RFC2253')
    description = _openssl('x509', '-in', cert, '-text', '-noout')
    identities = re.findall(rb'URI:urn:iris:device:([^\s,]+)', description)
    return _subject_matches(subject, identity) and identities == [identity.encode('ascii')]


def _identity_valid(cert, ca, key, identity, seconds=0):
    if cert is None or not _valid(cert, ca, seconds):
        return False
    try:
        if any(path.is_symlink() or path.parent.is_symlink() for path in (cert, ca)):
            return False
        public = _openssl('pkey', '-in', key, '-pubout')
        return (public == _openssl('x509', '-in', cert, '-pubkey', '-noout')
                and _certificate_matches(cert, identity))
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
        if not key.exists() and not manifest.exists():
            with tempfile.TemporaryDirectory(dir=str(root)) as tmp:
                pending = Path(tmp) / 'node.key'
                _write(pending, b'')
                _openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', pending)
                with pending.open('rb') as stream:
                    os.fsync(stream.fileno())
                os.replace(str(pending), str(key))
                _sync_dir(root)
        if key.exists() and key.stat().st_mode & 0o077:
            raise PeerTLSError('peer private key permissions are unsafe')
        cert = ca = None
        identity = hashlib.sha256(cfg['device_id'].encode('utf-8')).hexdigest()
        if manifest.exists():
            try:
                row = json.loads(manifest.read_text())
                generation = row['generation']
                if (not isinstance(generation, str) or len(generation) != 64
                        or any(c not in '0123456789abcdef' for c in generation)):
                    raise ValueError()
                cert, ca = root / generation / 'node.crt', root / generation / 'ca.crt'
                if 'identity_sha256' in row:
                    if (row.get('device_id') != cfg['device_id']
                            or not isinstance(row['identity_sha256'], str)
                            or re.fullmatch(r'[0-9a-f]{64}', row['identity_sha256']) is None
                            or row.get('key') not in ('node.key', 'recovery.key')):
                        raise ValueError()
                    identity = row['identity_sha256']
                    key = root / row['key']
                    if key.is_symlink() or key.stat().st_mode & 0o077:
                        raise ValueError()
            except (ValueError, KeyError, TypeError):
                raise PeerTLSError('invalid peer identity manifest') from None
        from peer_revocations import refresh, identity_revoked, RevocationError
        withdrawn = False
        if ca is not None:
            try:
                revoked_path = refresh(root, ca, cfg['device_id'], client, force=True)
                withdrawn = identity_revoked(revoked_path, identity)
            except (RevocationError, OSError):
                raise PeerTLSError('peer revocation status unavailable') from None
        if withdrawn or not _identity_valid(cert, ca, key, identity, 21600):
            try:
                with tempfile.TemporaryDirectory(dir=str(root)) as tmp:
                    pending = Path(tmp)
                    enrollment_key = key
                    if withdrawn:
                        enrollment_key = pending / 'fresh.key'
                        _write(enrollment_key, b'')
                        _openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', enrollment_key)
                    csr = _openssl('req', '-new', '-key', enrollment_key, '-subj', '/CN=IRIS enrollment')
                    response = client.enroll_peer_tls(cfg['device_id'], csr.decode('ascii'))
                    if not isinstance(response, dict) or response.get('mode') != 'required':
                        raise PeerTLSError('peer enrollment response is invalid')
                    next_identity = response.get('identity_sha256',
                        hashlib.sha256(cfg['device_id'].encode('utf-8')).hexdigest())
                    if (not isinstance(next_identity, str)
                            or re.fullmatch(r'[0-9a-f]{64}', next_identity) is None
                            or withdrawn and (next_identity == identity or identity_revoked(revoked_path, next_identity))):
                        raise PeerTLSError('peer enrollment identity is unavailable')
                    leaf_bytes = response['certificate'].encode('ascii')
                    ca_bytes = response['ca'].encode('ascii')
                    if len(leaf_bytes) > 16384 or len(ca_bytes) > 16384:
                        raise PeerTLSError('peer enrollment response is too large')
                    _write(pending / 'node.crt', leaf_bytes)
                    _write(pending / 'ca.crt', ca_bytes)
                    if not _valid(pending / 'node.crt', pending / 'ca.crt', 21600):
                        raise PeerTLSError('peer certificate validation failed')
                    public = _openssl('pkey', '-in', enrollment_key, '-pubout')
                    if public != _openssl('x509', '-in', pending / 'node.crt', '-pubkey', '-noout'):
                        raise PeerTLSError('peer certificate does not match local key')
                    if not _certificate_matches(pending / 'node.crt', next_identity):
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
                    active_key = key
                    if withdrawn:
                        active_key = root / ('recovery.key' if key.name == 'node.key' else 'node.key')
                        if active_key.is_symlink():
                            raise PeerTLSError('unsafe peer recovery key')
                        with enrollment_key.open('rb') as stream:
                            os.fsync(stream.fileno())
                        os.replace(str(enrollment_key), str(active_key))
                        _sync_dir(root)
                    _write(state, json.dumps({'generation': generation, 'key': active_key.name,
                        'device_id': cfg['device_id'], 'identity_sha256': next_identity}).encode('ascii'))
                    os.replace(str(state), str(manifest))
                    _sync_dir(root)
                    cert, ca = destination / 'node.crt', destination / 'ca.crt'
                    if withdrawn:
                        key.unlink()
                        _sync_dir(root)
                    key, identity = active_key, next_identity
            except Exception:
                if withdrawn or not _identity_valid(cert, ca, key, identity):
                    raise PeerTLSError('peer enrollment unavailable and no valid identity remains') from None
                # A still-valid identity may survive transient renewal failures.
        # Certificate validity alone cannot authorize a withdrawn peer. The
        # native process also needs a finite, authenticated revocation lease.
        try:
            revocations = refresh(root, ca, cfg['device_id'], client)
        except (RevocationError, OSError):
            raise PeerTLSError('peer revocation status unavailable') from None
        return ('bt-peer-tls=required\nbt-peer-tls-cert=%s\nbt-peer-tls-key=%s\n'
                'bt-peer-tls-ca=%s\nbt-peer-tls-revocations=%s\n' % (cert, key, ca, revocations))


def main():
    import argparse
    import sys
    from urllib.parse import urlsplit
    import agent_config
    from catalog_client import CatalogClient
    parser = argparse.ArgumentParser()
    parser.add_argument('--conf', required=True)
    parser.add_argument('--start-revocation-watch', action='store_true')
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
        fragment = ensure(cfg, client)
        if args.start_revocation_watch:
            from peer_revocations import start_watcher
            start_watcher(args.conf, Path(cfg['stage_dir']) / 'peer-tls')
        sys.stdout.write(fragment)
        return 0
    except Exception:
        print('peer identity unavailable; refusing unencrypted peer transport', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
