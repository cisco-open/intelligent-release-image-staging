# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Revocation leases never acquire freshness from a failed or replayed fetch."""
import hashlib
import json
from pathlib import Path

import pytest

import peer_revocations as rev

CA = '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n'
AUTHORITY = hashlib.sha256(b'abc').hexdigest()


def snapshot(revision=1, issued=1000, expires=1300, identities=()):
    return ('\n'.join([rev.MAGIC, AUTHORITY, str(revision), str(issued), str(expires)]
                      + list(identities)) + '\n').encode('ascii')


class Client:
    def __init__(self):
        self.calls = []
        self.data = snapshot()
        self.failed = False
        self.wrong_nonce = False

    def get_peer_revocations(self, device, nonce):
        self.calls.append((device, nonce))
        if self.failed:
            raise RuntimeError('secret-must-not-escape')
        return {'schema': 1, 'nonce': '0' * 32 if self.wrong_nonce else nonce,
                'snapshot': self.data.decode('ascii')}


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / 'peer-tls'
    root.mkdir(mode=0o700)
    ca = root / 'ca.crt'
    ca.write_text(CA)
    client = Client()
    def refresh(now=1000, force=False):
        return Path(rev.refresh(root, ca, 'device-a', client,
                                now_fn=lambda: now, force=force))
    return root, client, refresh


def test_fetch_is_bound_to_nonce_and_persists_private_floor_before_reuse(cache):
    root, client, refresh = cache
    path = refresh()
    assert path.read_bytes() == snapshot()
    assert refresh(1029) == path
    assert len(client.calls) == 1
    assert len(client.calls[0][1]) == 32
    record = json.loads((root / 'revocations-state.json').read_text())
    assert record['revision'] == 1 and record['received_at'] == 1000
    assert path.stat().st_mode & 0o077 == 0
    assert (root / 'revocations-state.json').stat().st_mode & 0o077 == 0


def test_network_failure_keeps_original_expiry_and_then_stops(cache):
    root, client, refresh = cache
    path = refresh()
    original = (root / 'revocations-state.json').read_bytes()
    client.failed = True
    assert refresh(1299) == path
    assert path.read_bytes() == snapshot()
    assert (root / 'revocations-state.json').read_bytes() == original
    with pytest.raises(rev.RevocationError, match='no current verified') as error:
        refresh(1300)
    assert 'secret' not in str(error.value)


def test_wrong_nonce_cannot_publish_or_extend(cache):
    root, client, refresh = cache
    client.wrong_nonce = True
    with pytest.raises(rev.RevocationError):
        refresh()
    assert not (root / 'revocations.txt').exists()
    client.wrong_nonce = False
    refresh()
    client.wrong_nonce = True
    client.data = snapshot(issued=1050, expires=1350)
    refresh(1050)
    assert (root / 'revocations.txt').read_bytes() == snapshot()


@pytest.mark.parametrize('replacement', [
    snapshot(revision=0, issued=1050, expires=1350),
    snapshot(revision=2, issued=999, expires=1299),
    snapshot(issued=1050, expires=1350, identities=['a' * 64]),
])
def test_checkpoint_rejects_rollback_or_changed_same_revision_after_restart(cache, replacement):
    root, client, refresh = cache
    refresh()
    client.data = replacement
    # A new invocation reads the durable floor, not an in-memory singleton.
    refresh(1050)
    assert (root / 'revocations.txt').read_bytes() == snapshot()


def test_newer_generation_publishes_denials(cache):
    root, client, refresh = cache
    refresh()
    client.data = snapshot(revision=2, issued=1050, expires=1350, identities=['a' * 64])
    assert refresh(1050).read_bytes() == client.data
    assert json.loads((root / 'revocations-state.json').read_text())['revision'] == 2


def test_interrupted_publication_cannot_fall_back_behind_new_floor(cache, monkeypatch):
    root, client, refresh = cache
    refresh()
    client.data = snapshot(revision=2, issued=1050, expires=1350, identities=['a' * 64])
    original = rev._atomic
    def fail_publication(path, data, directory_fd=None):
        if path.name == 'revocations.txt':
            raise OSError('disk failure')
        return original(path, data, directory_fd)
    monkeypatch.setattr(rev, '_atomic', fail_publication)
    with pytest.raises(OSError):
        refresh(1050)
    client.failed = True
    with pytest.raises(rev.RevocationError):
        refresh(1051)
    monkeypatch.setattr(rev, '_atomic', original)
    client.failed = False
    assert refresh(1051).read_bytes() == client.data


def test_corrupt_floor_and_clock_rollback_fail_closed(cache):
    root, client, refresh = cache
    refresh()
    with pytest.raises(rev.RevocationError, match='clock moved'):
        refresh(969)
    (root / 'revocations-state.json').write_text('{}')
    with pytest.raises(rev.RevocationError, match='checkpoint'):
        refresh(1050)


def test_missing_floor_cannot_reset_known_revision_even_with_authenticated_response(cache):
    root, client, refresh = cache
    refresh()
    (root / 'revocations-state.json').unlink()
    client.data = snapshot(revision=0)
    with pytest.raises(rev.RevocationError, match='checkpoint is missing'):
        refresh(1001)
    assert len(client.calls) == 1
    assert (root / 'revocations.txt').read_bytes() == snapshot()


@pytest.mark.parametrize('failed', [True, False])
def test_slow_fetch_cannot_return_or_publish_expired_lease(cache, failed):
    root, client, refresh = cache
    refresh()
    stamps = iter([1299, 1300, 1300])
    client.failed = failed
    before = (root / 'revocations-state.json').read_bytes()
    with pytest.raises(rev.RevocationError, match='no current verified'):
        rev.refresh(root, root / 'ca.crt', 'device-a', client,
                    now_fn=lambda: next(stamps), force=True)
    assert (root / 'revocations-state.json').read_bytes() == before


@pytest.mark.parametrize('replace_lock', [False, True])
def test_inflight_fetch_cannot_publish_into_replaced_directory_or_lock(cache, replace_lock):
    root, client, refresh = cache
    fetch = client.get_peer_revocations
    def replace_during_fetch(device, nonce):
        if replace_lock:
            (root / 'revocations.lock').unlink()
            (root / 'revocations.lock').touch(mode=0o600)
        else:
            root.rename(root.with_name('old-peer-tls'))
            root.mkdir(mode=0o700)
        return fetch(device, nonce)
    client.get_peer_revocations = replace_during_fetch
    with pytest.raises(rev.RevocationError, match='changed during refresh'):
        refresh()
    assert not (root / 'revocations-state.json').exists()
    assert not (root / 'revocations.txt').exists()


def test_atomic_publication_is_bound_to_original_directory(cache, monkeypatch):
    root, client, refresh = cache
    original = rev._atomic
    old_root = root.with_name('old-peer-tls')
    def move_before_write(path, data, directory_fd=None):
        root.rename(old_root)
        root.mkdir(mode=0o700)
        return original(path, data, directory_fd)
    monkeypatch.setattr(rev, '_atomic', move_before_write)
    with pytest.raises((OSError, rev.RevocationError)):
        refresh()
    assert (old_root / 'revocations-state.json').exists()
    assert not (root / 'revocations-state.json').exists()
    assert not (root / 'revocations.txt').exists()


def test_watcher_waits_for_old_worker_handover(cache, monkeypatch):
    root, client, refresh = cache
    conf = root.parent / 'agent.conf'
    conf.touch()
    attempts, waits, refreshed = [], [], []
    def take_lock(fd, flags):
        attempts.append(flags)
        if len(attempts) < 3:
            raise BlockingIOError()
    class Event:
        def is_set(self):
            return False
        def wait(self, seconds):
            waits.append(seconds)
        def set(self):
            pass
    monkeypatch.setattr(rev.fcntl, 'flock', take_lock)
    monkeypatch.setattr(rev.threading, 'Event', Event)
    monkeypatch.setattr(rev.signal, 'signal', lambda *_: None)
    monkeypatch.setattr(rev, 'refresh_configuration',
                        lambda *args, **kwargs: refreshed.append(args) or False)
    assert rev.watch(str(conf), root) == 0
    assert len(attempts) == 3 and waits == [1, 1]
    assert len(refreshed) == 1


def test_duplicate_watcher_has_bounded_handover_wait(cache, monkeypatch):
    root, client, refresh = cache
    def take_lock(*_):
        raise BlockingIOError()
    ticks = iter([0, 1000])
    monkeypatch.setattr(rev.fcntl, 'flock', take_lock)
    monkeypatch.setattr(rev.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(rev.signal, 'signal', lambda *_: None)
    assert rev.watch('absent.conf', root) == 0


def test_dependency_only_bundle_change_releases_watcher_lock(cache, monkeypatch):
    root, client, refresh = cache
    conf = root.parent / 'agent.conf'
    conf.touch()
    changed, refreshed = [], []
    original = Path.read_bytes
    def read_source(path):
        if changed and path.name == 'catalog_client.py':
            return b'new helper source'
        return original(path)
    class Event:
        def is_set(self):
            return False
        def wait(self, seconds):
            changed.append(True)
        def set(self):
            pass
    monkeypatch.setattr(Path, 'read_bytes', read_source)
    monkeypatch.setattr(rev.threading, 'Event', Event)
    monkeypatch.setattr(rev.signal, 'signal', lambda *_: None)
    monkeypatch.setattr(rev, 'refresh_configuration',
                        lambda *args, **kwargs: refreshed.append(args) or True)
    assert rev.watch(str(conf), root) == 0
    assert len(refreshed) == 1 and changed == [True]


def test_snapshot_identity_and_runtime_authority_reject_trailing_newline():
    assert rev.HEX.match('a' * 64 + '\n') is None
    value = dict(supported=True, mode='required', state='valid', authority='a' * 64 + '\n',
                 revision=1, issued_at=1000, expires_at=1300, own_revoked=False)
    assert rev.runtime_status(value) is None


@pytest.mark.parametrize('current', [True, False])
def test_launcher_reuses_only_matching_locked_worker(cache, monkeypatch, current):
    root, client, refresh = cache
    conf = root.parent / 'agent.conf'
    signature = rev._worker_signature(conf)
    if not current:
        signature['source_sha256'] = '0' * 64
    path = root / 'revocations-watch.lock'
    path.touch(mode=0o600)
    path.write_text(json.dumps(signature))
    launched = []
    def locked(*_):
        raise BlockingIOError()
    monkeypatch.setattr(rev.fcntl, 'flock', locked)
    monkeypatch.setattr(rev.subprocess, 'Popen', lambda *args, **kwargs: launched.append((args, kwargs)))
    rev.start_watcher(conf, root)
    assert len(launched) == (0 if current else 1)
    if launched:
        assert launched[0][1]['start_new_session'] is True
        assert '--watch' in launched[0][0][0]


def test_native_status_does_not_accept_expired_without_snapshot():
    value = dict(supported=True, mode='required', state='expired', authority=None,
                 revision=None, issued_at=None, expires_at=None, own_revoked=False)
    assert rev.runtime_status(value) is None


@pytest.mark.parametrize('mutate', [
    lambda data: data[:-1],
    lambda data: data.replace(b'\n', b'\r\n'),
    lambda data: data.replace(AUTHORITY.encode(), b'0' * 64),
    lambda data: data.replace(b'\n1\n', b'\n01\n'),
    lambda data: data.replace(b'\n1000\n', b'\n1031\n'),
    lambda data: data.replace(b'\n1300\n', b'\n1301\n'),
    lambda data: data.replace(b'\n1300\n', b'\n1000\n'),
    lambda data: data + b'\n',
    lambda data: data + b'A' * 64 + b'\n',
    lambda data: data + (b'a' * 64 + b'\n') * 2,
    lambda data: data + b'b' * 64 + b'\n' + b'a' * 64 + b'\n',
    lambda data: b'\xff' + data,
    lambda data: data.replace(b'\n1\n', b'\n9007199254740992\n'),
])
def test_strict_snapshot_parser(mutate):
    with pytest.raises(rev.RevocationError):
        rev.parse(mutate(snapshot()), AUTHORITY, 1000)


def test_oversized_snapshot_and_identity_limit_fail():
    with pytest.raises(rev.RevocationError):
        rev.parse(b'x' * (rev.MAX_BYTES + 1), AUTHORITY, 1000)
    identities = ['%064x' % value for value in range(rev.MAX_IDENTITIES + 1)]
    with pytest.raises(rev.RevocationError):
        rev.parse(snapshot(identities=identities), AUTHORITY, 1000)


@pytest.mark.parametrize('target', ['revocations-state.json', 'revocations.lock'])
def test_linked_security_files_refused(cache, target):
    root, client, refresh = cache
    outside = root.parent / 'outside'
    outside.write_text('untouched')
    (root / target).symlink_to(outside)
    with pytest.raises((OSError, rev.RevocationError)):
        refresh()
    assert outside.read_text() == 'untouched'
