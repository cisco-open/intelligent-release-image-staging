# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, rollback-resistant peer revocation leases from pinned catalog TLS.

The native TLS implementation reads the protected snapshot directly and closes
connections when its lease expires. A failed refresh never extends that lease.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

MAX_BYTES = 1024 * 1024
MAX_IDENTITIES = 10000
MAX_INTEGER = 9007199254740991
MAX_LIFETIME = 300
CLOCK_SKEW = 30
POLL_SECONDS = 30
MAGIC = 'IRIS-PEER-REVOCATIONS-1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
DECIMAL = re.compile(r'(0|[1-9][0-9]{0,15})\Z')


class RevocationError(Exception):
    pass


def _integer(value):
    if not isinstance(value, str) or not DECIMAL.match(value):
        raise RevocationError('invalid revocation number')
    result = int(value)
    if result > MAX_INTEGER:
        raise RevocationError('revocation number is too large')
    return result


def parse(data, authority, now):
    """Validate exactly the native snapshot grammar, including its finite lease."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BYTES:
        raise RevocationError('invalid revocation snapshot size')
    try:
        text = data.decode('ascii')
    except UnicodeError:
        raise RevocationError('invalid revocation snapshot encoding') from None
    if not text.endswith('\n') or '\r' in text:
        raise RevocationError('invalid revocation snapshot lines')
    lines = text[:-1].split('\n')
    if not 5 <= len(lines) <= 5 + MAX_IDENTITIES or lines[0] != MAGIC:
        raise RevocationError('invalid revocation snapshot format')
    if not HEX.match(lines[1]) or lines[1] != authority:
        raise RevocationError('revocation snapshot belongs to another authority')
    revision, issued, expires = [_integer(value) for value in lines[2:5]]
    if not 0 < expires - issued <= MAX_LIFETIME or issued > now + CLOCK_SKEW or expires <= now:
        raise RevocationError('revocation snapshot is not current')
    identities = lines[5:]
    if any(not HEX.match(value) for value in identities) or identities != sorted(set(identities)):
        raise RevocationError('invalid revoked certificate identities')
    digest = hashlib.sha256(('\n'.join(identities) + '\n').encode('ascii')).hexdigest()
    return {'authority': authority, 'revision': revision, 'issued_at': issued,
            'expires_at': expires, 'identities_sha256': digest}


def _read(path, limit=MAX_BYTES, private=True):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit
                or private and (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            raise RevocationError('unsafe revocation input file')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RevocationError('revocation input is too large')
    return data


def _sync(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path, data, directory_fd=None):
    if directory_fd is None:
        fd, name = tempfile.mkstemp(prefix='.revocations-', dir=str(path.parent))
    else:
        name = '.revocations-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if directory_fd is None:
            os.replace(name, str(path))
            _sync(path.parent)
        else:
            os.replace(name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
    finally:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _floor(path, authority):
    try:
        data = _read(path, 4096)
    except FileNotFoundError:
        return None
    try:
        record = json.loads(data.decode('ascii'))
    except (ValueError, UnicodeError):
        raise RevocationError('invalid saved revocation checkpoint') from None
    fields = {'schema', 'authority', 'revision', 'issued_at', 'expires_at',
              'identities_sha256', 'received_at'}
    if (not isinstance(record, dict) or set(record) != fields
            or type(record['schema']) is not int or record['schema'] != 1
            or record['authority'] != authority
            or not isinstance(record['identities_sha256'], str)
            or not HEX.match(record['identities_sha256'])
            or any(type(record[key]) is not int or not 0 <= record[key] <= MAX_INTEGER
                   for key in ('revision', 'issued_at', 'expires_at', 'received_at'))
            or not 0 < record['expires_at'] - record['issued_at'] <= MAX_LIFETIME):
        raise RevocationError('invalid saved revocation checkpoint')
    return record


def _advance(candidate, previous):
    if previous is None:
        return
    if (candidate['revision'] < previous['revision']
            or candidate['issued_at'] < previous['issued_at']
            or candidate['revision'] == previous['revision']
            and candidate['identities_sha256'] != previous['identities_sha256']):
        raise RevocationError('revocation snapshot would undo a saved update')


def refresh(root, ca, device_id, client, *, now_fn=time.time, force=False):
    """Return the native snapshot path, fetching at most once per 30 seconds.

    Only a still-valid, checkpoint-matching local lease can cover a network
    failure. The checkpoint is durable before publication to the TLS process.
    """
    root, ca = Path(root), Path(ca)
    if (not root.is_absolute() or root.resolve() != root or not root.is_dir()
            or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077):
        raise RevocationError('unsafe peer revocation directory')
    if ca.resolve() != ca:
        raise RevocationError('unsafe peer certificate authority path')
    try:
        authority = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            _read(ca, 16384, private=False).decode('ascii'))).hexdigest()
    except (ValueError, UnicodeError):
        raise RevocationError('invalid peer certificate authority') from None
    lock_path = root / 'revocations.lock'
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise RevocationError('unsafe revocation lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        directory_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_info = os.fstat(directory_fd)
            def unchanged():
                try:
                    current_root, current_lock = root.lstat(), lock_path.lstat()
                except OSError:
                    raise RevocationError('peer revocation directory changed during refresh') from None
                if ((current_root.st_dev, current_root.st_ino) !=
                        (directory_info.st_dev, directory_info.st_ino)
                        or (current_lock.st_dev, current_lock.st_ino) != (info.st_dev, info.st_ino)):
                    raise RevocationError('peer revocation directory changed during refresh')
            unchanged()
            return _refresh_locked(root, authority, device_id, client, now_fn,
                                   force, unchanged, directory_fd)
        finally:
            os.close(directory_fd)


def _refresh_locked(root, authority, device_id, client, now_fn, force, unchanged, directory_fd):
    now = int(now_fn())
    destination, checkpoint = root / 'revocations.txt', root / 'revocations-state.json'
    previous = _floor(checkpoint, authority)
    if previous is None and (destination.exists() or destination.is_symlink()):
        raise RevocationError('revocation checkpoint is missing')
    if previous is not None and now + CLOCK_SKEW < previous['received_at']:
        raise RevocationError('clock moved behind the revocation checkpoint')
    cached = None
    try:
        cached = parse(_read(destination), authority, now)
        _advance(cached, previous)
        if any(cached[key] != previous[key] for key in cached):
            cached = None
    except FileNotFoundError:
        pass
    except RevocationError:
        cached = None
    if not force and cached is not None and 0 <= now - previous['received_at'] < POLL_SECONDS:
        return str(destination)
    nonce = secrets.token_hex(16)
    try:
        response = client.get_peer_revocations(device_id, nonce)
        now = int(now_fn())
        if previous is not None and now + CLOCK_SKEW < previous['received_at']:
            raise RevocationError('clock moved behind the revocation checkpoint')
        if (not isinstance(response, dict) or set(response) != {'schema', 'nonce', 'snapshot'}
                or type(response['schema']) is not int or response['schema'] != 1
                or response['nonce'] != nonce or not isinstance(response['snapshot'], str)):
            raise RevocationError('invalid revocation response')
        data = response['snapshot'].encode('ascii')
        candidate = parse(data, authority, now)
        _advance(candidate, previous)
    except Exception:
        now = int(now_fn())
        unchanged()
        if (cached is not None and cached['expires_at'] > now
                and previous['received_at'] <= now + CLOCK_SKEW):
            return str(destination)
        raise RevocationError('no current verified peer revocation snapshot is available') from None
    record = dict(candidate, schema=1, received_at=now)
    unchanged()
    _atomic(checkpoint, json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii'), directory_fd)
    unchanged()
    _atomic(destination, data, directory_fd)
    unchanged()
    return str(destination)


def runtime_status(value, now=None):
    """Allowlist the native RPC result; never turn missing support into success."""
    fields = {'supported', 'mode', 'state', 'authority', 'revision', 'issued_at',
              'expires_at', 'own_revoked'}
    if (not isinstance(value, dict) or set(value) != fields
            or value['supported'] is not True or value['mode'] not in ('required', 'disabled')
            or value['state'] not in ('valid', 'unavailable', 'expired')
            or type(value['own_revoked']) is not bool):
        return None
    authority = value['authority']
    numbers = [value[key] for key in ('revision', 'issued_at', 'expires_at')]
    present = authority is not None or any(number is not None for number in numbers)
    if present and (not isinstance(authority, str) or not HEX.match(authority)
                    or any(type(number) is not int or not 0 <= number <= MAX_INTEGER for number in numbers)
                    or not 0 < value['expires_at'] - value['issued_at'] <= MAX_LIFETIME):
        return None
    if value['state'] in ('valid', 'expired') and (not present or value['mode'] != 'required'):
        return None
    return dict(value, observed_at=int(time.time() if now is None else now))


def identity_revoked(path, identity):
    """Read membership only from a current, locally protected native lease."""
    data = _read(Path(path))
    rows = data.decode('ascii').splitlines()
    if len(rows) < 5:
        raise RevocationError('invalid revocation snapshot')
    parse(data, rows[1], int(time.time()))
    return identity in rows[5:]


def refresh_configuration(conf, expected_root=None):
    """Refresh without waiting for a long image verification or staging tick."""
    from urllib.parse import urlsplit
    import agent_config
    from catalog_client import CatalogClient
    cfg = agent_config.load(conf)
    mode = os.environ.get('IRIS_PEER_TLS_MODE', cfg.get('peer_tls_mode', 'disabled'))
    if mode == 'disabled':
        return False
    if mode != 'required' or urlsplit(cfg['catalog_url']).scheme != 'https':
        raise RevocationError('peer revocation refresh requires verified HTTPS')
    root = Path(cfg['stage_dir']) / 'peer-tls'
    if expected_root is not None and root != Path(expected_root):
        return False
    current = json.loads(_read(root / 'current.json', 4096).decode('ascii'))
    generation = current.get('generation') if isinstance(current, dict) else None
    if not isinstance(generation, str) or not HEX.match(generation):
        raise RevocationError('invalid current peer certificate generation')
    client = CatalogClient(cfg['catalog_url'], cfg['catalog_token'],
                           context=ssl.create_default_context(cafile=cfg['catalog_ca']))
    refresh(root, root / generation / 'ca.crt', cfg['device_id'], client)
    return True


def _worker_signature(conf):
    sources = [Path(__file__).resolve().with_name(name) for name in
               ('peer_revocations.py', 'agent_config.py', 'catalog_client.py')]
    digest = hashlib.sha256(b''.join(hashlib.sha256(path.read_bytes()).digest()
                                    for path in sources)).hexdigest()
    return {'schema': 1, 'source_sha256': digest, 'conf': str(Path(conf).absolute())}


def watch(conf, root):
    """One bounded refresh worker per peer directory; exit on removal/upgrade.

    The process holds a filesystem lock, not an unverified PID. A new launcher
    may start another worker safely; only the lock holder performs requests.
    """
    root = Path(root)
    if (not root.is_absolute() or root.resolve() != root or not root.is_dir()
            or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077):
        raise RevocationError('unsafe peer revocation worker directory')
    lock_path = root / 'revocations-watch.lock'
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise RevocationError('unsafe peer revocation worker lock')
        stopped = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stopped.set())
        # Refresh helpers are imported lazily and then cached by Python. Watch
        # their source too, so a dependency-only bundle update releases the lock.
        original_source = _worker_signature(conf)
        # An older worker notices a bundle replacement at its next refresh.
        # Wait for that handover rather than exiting before it releases the lock.
        deadline = time.monotonic() + 2 * POLL_SECONDS + 35
        while not stopped.is_set():
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    return 0
                stopped.wait(1)
        if stopped.is_set():
            return 0
        lock.seek(0)
        lock.write(json.dumps(original_source, sort_keys=True).encode('ascii'))
        lock.truncate()
        lock.flush()
        while not stopped.is_set():
            try:
                current_lock = lock_path.lstat()
                if ((current_lock.st_dev, current_lock.st_ino) != (info.st_dev, info.st_ino)
                        or not Path(conf).is_file()
                        or _worker_signature(conf) != original_source):
                    return 0
            except OSError:
                return 0
            try:
                if not refresh_configuration(conf, expected_root=root):
                    return 0
            except Exception:
                # Neither a failed request nor an invalid config extends the
                # native lease. No error body, token or private path is logged.
                pass
            stopped.wait(POLL_SECONDS)
    return 0


def start_watcher(conf, root):
    # Launchers run every tick. Reuse a current lock holder instead of leaving
    # a waiting duplicate process for every tick on a busy device.
    expected = _worker_signature(conf)
    path = Path(root) / 'revocations-watch.lock'
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise RevocationError('unsafe peer revocation worker lock')
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                if info.st_size <= 4096 and json.loads(lock.read(4097)) == expected:
                    return
            except (ValueError, UnicodeError):
                pass
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--watch',
                      '--conf', str(Path(conf).absolute()), '--root', str(root)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Maintain the private peer revocation lease')
    parser.add_argument('--watch', action='store_true', required=True)
    parser.add_argument('--conf', required=True)
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    try:
        return watch(args.conf, args.root)
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
