# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real file locks: public readers coexist without weakening write admission."""
from concurrent.futures import ThreadPoolExecutor
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import threading
import uuid

import pytest

import api_problem
import gui_tls
import tls_rotation

BUSY = 'TLS maintenance is busy; refresh shortly'


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_CONFIG', str(tmp_path))
    return tmp_path


def test_actual_status_reads_coexist_and_leave_no_journal(config, monkeypatch):
    both_loaded = threading.Barrier(3)
    release = threading.Event()
    original = tls_rotation._load

    def hold_read():
        result = original()
        both_loaded.wait(timeout=5)
        assert release.wait(timeout=5)
        return result

    monkeypatch.setattr(tls_rotation, '_load', hold_read)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(tls_rotation.status)
        second = pool.submit(tls_rotation.status)
        try:
            both_loaded.wait(timeout=5)
            # Real readers both hold their locks; writes must still fail.
            with pytest.raises(ValueError, match='^' + BUSY + '$'):
                with gui_tls.rotation_lock():
                    pytest.fail('Writer entered while readers were active')
        finally:
            release.set()
        assert first.result(timeout=5) == second.result(timeout=5) == tls_rotation._view(None)
    assert not tls_rotation.journal_path().exists()
    assert sorted(str(p.relative_to(config)) for p in config.rglob('*')) == ['tls', 'tls/.rotation.lock']


def test_status_refuses_actual_writer_and_preserves_busy_problem(config):
    class Handler:
        command = 'GET'

        def __init__(self):
            self.wfile = io.BytesIO()

        def send_response(self, status): self.status = status
        def send_header(self, name, value): pass
        def end_headers(self): pass

    # A separate open file description represents a live writer, not a mock.
    with gui_tls.rotation_lock():
        with pytest.raises(ValueError, match='^' + BUSY + '$') as error:
            tls_rotation.status()
        handler = Handler()
        api_problem.legacy(handler, 409, {'error': str(error.value)})
        assert handler.status == 409
        assert json.loads(handler.wfile.getvalue()) == {
            'type': api_problem.TYPE_BASE + 'resource-conflict', 'title': 'Resource conflict',
            'status': 409, 'code': 'resource-conflict', 'error': BUSY,
        }
    assert tls_rotation.status()['state'] == 'idle'


@pytest.mark.parametrize('shared', [False, True], ids=['writer', 'reader'])
@pytest.mark.parametrize('action', ['prepare', 'approve', 'apply', 'cancel'])
def test_all_mutations_refuse_an_active_lock_before_loading(config, monkeypatch, shared, action):
    def unexpected_load():
        pytest.fail('Mutation read state before exclusive admission')

    monkeypatch.setattr(tls_rotation, '_load', unexpected_load)
    payload = {'action': action, 'request_id': str(uuid.uuid4())}
    payload.update({'prepare': {'names': ['console.example'], 'mode': 'ca'},
                    'approve': {'certificate': 'public'}, 'apply': {'confirm': True}, 'cancel': {}}[action])
    with gui_tls.rotation_lock(shared=shared):
        with pytest.raises(ValueError, match='^' + BUSY + '$'):
            tls_rotation.operate(payload)
    assert not tls_rotation.journal_path().exists()


@pytest.mark.parametrize('shared', [False, True])
def test_lock_released_after_failed_body(config, shared):
    with pytest.raises(RuntimeError, match='body failed'):
        with gui_tls.rotation_lock(shared=shared):
            raise RuntimeError('body failed')
    with gui_tls.rotation_lock():
        pass


@pytest.mark.parametrize('shared', [False, True])
def test_existing_lock_file_still_requires_regular_nonsymlink(config, shared):
    directory = config / 'tls'; directory.mkdir()
    target = config / 'foreign'; target.write_bytes(b'preserve')
    lock = directory / '.rotation.lock'; lock.symlink_to(target)
    with pytest.raises(OSError) as error:
        with gui_tls.rotation_lock(shared=shared):
            pytest.fail('Symlink admitted')
    assert error.value.errno == errno.ELOOP
    assert target.read_bytes() == b'preserve'
    lock.unlink()
    os.mkfifo(lock, 0o600)
    with pytest.raises(ValueError, match='unsafe TLS rotation lock'):
        with gui_tls.rotation_lock(shared=shared):
            pytest.fail('FIFO admitted')


@pytest.mark.parametrize('shared', [False, True])
def test_configuration_directory_symlink_remains_refused(config, shared):
    foreign = config / 'foreign'; foreign.mkdir()
    (config / 'tls').symlink_to(foreign, target_is_directory=True)
    with pytest.raises(ValueError, match='unsafe TLS configuration directory'):
        with gui_tls.rotation_lock(shared=shared):
            pytest.fail('Symlink directory admitted')
    assert list(foreign.iterdir()) == []


def test_default_lock_is_exclusive_nonblocking_and_shared_is_keyword_only(config):
    with pytest.raises(TypeError):
        with gui_tls.rotation_lock(True):
            pass
    with gui_tls.rotation_lock():
        fd = os.open(config / 'tls/.rotation.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            os.close(fd)
