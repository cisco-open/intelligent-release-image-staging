# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deterministic real-lock reproduction of managed status/submit inversion."""

from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import lifecycle_worker, managed_worker as managed
from test_managed_worker import host


@pytest.mark.parametrize('old_order', [True, False])
def test_status_and_actual_submit_have_uniform_lock_order(host, monkeypatch, old_order):
    managed.setup(host.args)
    captured = {}
    monkeypatch.setattr(lifecycle_worker, 'serve', lambda _args: captured.setdefault('class', lifecycle_worker.Worker))
    managed.serve_managed(host.args)
    record = managed._load(host.state)
    worker = captured['class'](host.state, record['storage']['backup']['directory'],
                               record['storage']['recovery']['directory'])
    monkeypatch.setattr(managed, 'check_storage', lambda *_args: None)
    monkeypatch.setattr(worker, 'perform', lambda _job: None)
    entered, status_locked = threading.Event(), threading.Event()
    actual_lock = threading.RLock()
    outcomes = []

    class Lock:
        def __enter__(self):
            actual_lock.acquire()
            if threading.current_thread().name == 'capture-status-reader':
                status_locked.set()
            return self
        def __exit__(self, *_args):
            actual_lock.release()

    monkeypatch.setattr(managed, 'CAPTURE_PROCESS_LOCK', Lock())
    def inventory():
        # Called by the ACTUAL Worker.submit with worker.lock already held.
        entered.set()
        if old_order:
            assert status_locked.wait(2), 'old negative control did not reach status lock'
        acquired = actual_lock.acquire(timeout=0.2)
        if not acquired:
            raise RuntimeError('confirmed status/submit lock inversion')
        actual_lock.release()
        return set()
    monkeypatch.setattr(worker.retention, 'backup_ids', inventory)
    request = {'action': 'backup', 'request_id': str(uuid.uuid4()), 'allow_downtime': True}
    def submit():
        try:
            if old_order:
                # Exact pre-fix wrapper: check under capture lock, release it,
                # then enter ordinary submit (not a replacement submit body).
                with managed.CAPTURE_PROCESS_LOCK:
                    managed.check_storage(host.state, record)
                result = lifecycle_worker.Worker.submit(worker, request)
            else:
                result = worker.submit(request)
            outcomes.append(('submit', result))
        except Exception as exc:
            outcomes.append(('submit-error', str(exc)))
    def status():
        try:
            outcomes.append(('status', worker.status()))
        except Exception as exc:
            outcomes.append(('status-error', str(exc)))
    submit_thread = threading.Thread(target=submit, name='capture-submit-writer', daemon=True)
    status_thread = threading.Thread(target=status, name='capture-status-reader', daemon=True)
    submit_thread.start()
    assert entered.wait(2)
    status_thread.start()
    submit_thread.join(timeout=3)
    status_thread.join(timeout=3)
    assert not submit_thread.is_alive() and not status_thread.is_alive()
    if worker.thread is not None:
        worker.thread.join(timeout=2)
        assert not worker.thread.is_alive()
    if old_order:
        assert ('submit-error', 'confirmed status/submit lock inversion') in outcomes
        assert not worker.jobs
    else:
        assert ('submit', {'job_id': request['request_id']}) in outcomes
        assert not any(kind.endswith('-error') for kind, _value in outcomes)
    assert any(kind == 'status' for kind, _value in outcomes)
