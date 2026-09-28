# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Managed pod shutdown must not hide truncated daemon-writer operations."""

import inspect
import threading
import time
from types import SimpleNamespace

import management_api as api


def test_completed_and_never_started_writers_are_clean():
    completed = api._ManagedWriterThread(target=lambda: None)
    unused = api._ManagedWriterThread(target=lambda: None)
    completed.start()
    completed.join(timeout=2)
    assert api._drain_management_writers([completed, unused], timeout=0.1)


def test_failed_writer_remains_unclean_after_thread_has_exited(capsys):
    def fail():
        raise ValueError('sensitive fixture detail')
    thread = api._ManagedWriterThread(target=fail)
    thread.start()
    thread.join(timeout=2)
    assert not api._drain_management_writers([thread], timeout=0.1)
    assert 'sensitive fixture detail' not in capsys.readouterr().err


def test_multiple_stuck_writers_share_one_bounded_drain_deadline():
    release = threading.Event()
    threads = [api._ManagedWriterThread(target=release.wait) for _ in range(3)]
    for thread in threads:
        thread.start()
    try:
        started = time.monotonic()
        assert not api._drain_management_writers(threads, timeout=0.05)
        assert time.monotonic() - started < 1
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=2)


def test_drain_budget_is_not_restarted_for_each_writer(monkeypatch):
    clock, budgets = [10.0], []
    monkeypatch.setattr(api.time, 'monotonic', lambda: clock[0])
    def wait(timeout):
        budgets.append(timeout)
        clock[0] += timeout
        return False
    threads = [SimpleNamespace(start_attempted=True, writer_failed=False,
                               writer_finished=SimpleNamespace(wait=wait)) for _ in range(3)]
    assert not api._drain_management_writers(threads, timeout=30)
    assert budgets == [30, 0, 0]


def test_interrupted_start_is_not_mistaken_for_a_never_started_writer():
    thread = api._ManagedWriterThread(target=lambda: None)
    thread.start_attempted = True
    assert thread.ident is None
    assert not api._drain_management_writers([thread], timeout=0.01)


def test_every_management_maintenance_writer_is_tracked_before_admission():
    source = inspect.getsource(api.main)
    startup = source.split('def start_management():', 1)[1].split('scheme =', 1)[0]
    assert 'threading.Thread(' not in startup
    for target in ('instruction_keys.status_loop', 'instruction_stamper.status_loop',
                   'ca_trust_refresh_loop', 'bulkhash_refresh.bulkhash_refresh_loop',
                   'audit_export.export_loop'):
        assert 'start_writer(' + target in startup
    assert 'writer_threads = [schedule_thread, maintenance_thread]' in source
    shutdown = source.split('def shutdown_management():', 1)[1]
    assert shutdown.index('iox_controller.close()') < shutdown.index('if not clean_requests or not clean_writers or not clean_images or not clean_exports:')
    assert "raise RuntimeError('Management writers" in shutdown
    assert shutdown.index('srv.stop_request_admission()') < shutdown.index('srv.drain_requests(timeout=30)')
    assert shutdown.index('srv.drain_requests(timeout=30)') < shutdown.index('_manual_ca_writers()')
    assert shutdown.index('srv.drain_requests(timeout=30)') < shutdown.index('images.shutdown(')
    assert shutdown.index('srv.drain_requests(timeout=30)') < shutdown.index('audit_export.drain_exports(')
    assert 'writer_deadline - time.monotonic()' in shutdown


def test_manual_ca_download_is_tracked_through_its_final_audit_write(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(api, '_CA_JOBS', {})
    monkeypatch.setattr(api, '_CA_JOB_THREADS', {})
    monkeypatch.setattr(api, '_run_ca_download', lambda *args, **kwargs: (True, 'ok', 1))
    def audit(**kwargs):
        entered.set()
        release.wait()
    operation = api.start_ca_refresh('https://example.invalid/ca', audit_fn=audit)
    try:
        assert entered.wait(2)
        assert len(api._manual_ca_writers()) == 1
        assert not api._drain_management_writers(api._manual_ca_writers(), timeout=0.01)
    finally:
        release.set()
        for thread in api._manual_ca_writers():
            thread.join(timeout=2)
    assert api._drain_management_writers(api._manual_ca_writers(), timeout=0.1)
    assert api.get_ca_job(operation)['state'] == 'done'
