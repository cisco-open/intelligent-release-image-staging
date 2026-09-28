# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Nested seeder failures must reach the managed shutdown proof boundary."""

from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

import installer_shutdown
import peer_tls_seed as seed


class Child:
    def __init__(self, result=0, *, exited=False, forced=False):
        self.result = result
        self.exited = exited
        self.forced = forced
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.result if self.exited else None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        if self.forced and not self.killed:
            raise subprocess.TimeoutExpired('aria2c', timeout)
        self.exited = True
        return self.result

    def kill(self):
        self.killed = True


@pytest.mark.parametrize('code', [0])
def test_graceful_nested_exit_is_clean(code):
    child = Child(code)
    assert seed.stop_child(child)
    assert child.terminated and not child.killed


@pytest.mark.parametrize('code', [1, 7, -signal.SIGTERM, 143, -signal.SIGKILL, 137])
@pytest.mark.parametrize('exited', [False, True])
def test_nonclean_nested_exit_is_retained(code, exited):
    child = Child(code, exited=exited)
    assert not seed.stop_child(child)
    assert child.terminated is not exited


@pytest.mark.parametrize('code', [0, -signal.SIGKILL])
def test_forced_kill_never_counts_as_clean_even_if_wait_reports_zero(code):
    child = Child(code, forced=True)
    assert not seed.stop_child(child)
    assert child.terminated and child.killed


def test_real_sigterm_resistant_child_is_reaped_and_reported_unclean():
    child = subprocess.Popen([sys.executable, '-u', '-c',
        "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(30)"],
        stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'ready\n'
        assert seed.stop_child(child, timeout=0.05) is False
        assert child.returncode == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


def supervisor(tmp_path, monkeypatch, children, *, crash_first=False):
    reports = []
    state = SimpleNamespace(stopped=False, ticks=0)
    def wait(_timeout):
        state.ticks += 1
        if crash_first and state.ticks == 1:
            children[0].exited = True
        elif state.ticks == (3 if crash_first else 1):
            state.stopped = True
    event = SimpleNamespace(is_set=lambda: state.stopped, set=lambda: setattr(state, 'stopped', True), wait=wait)
    monkeypatch.setattr(seed.threading, 'Event', lambda: event)
    monkeypatch.setattr(seed.signal, 'signal', lambda *_: None)
    monkeypatch.setenv('IRIS_RUN', str(tmp_path))
    monkeypatch.setattr(seed.sys, 'argv', ['peer_tls_seed.py', 'seed-launch.sh'])
    monkeypatch.setattr(seed.settings, 'mode', lambda: 'disabled')
    monkeypatch.setattr(seed.settings, 'status_path', lambda: tmp_path / 'status.json')
    monkeypatch.setattr(seed.settings, 'atomic_json', lambda path, value: reports.append(value))
    launches = iter(children)
    monkeypatch.setattr(seed.subprocess, 'Popen', lambda *args, **kwargs: next(launches))
    return seed.main(), reports


def test_forced_nested_stop_makes_wrapper_and_managed_proof_fail(tmp_path, monkeypatch):
    result, reports = supervisor(tmp_path, monkeypatch, [Child(-signal.SIGKILL, forced=True)])
    assert result == 1 and reports[-1]['state'] == 'error'
    for name in ('state', 'run'):
        (tmp_path / name).mkdir()
    env = {'IRIS_STATE': str(tmp_path / 'state'), 'IRIS_RUN': str(tmp_path / 'run'),
           'IRIS_INSTALLER_SHUTDOWN_PROOF': str(tmp_path / 'state/installer-shutdown.json'),
           'IRIS_POD_UID': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}
    installer_shutdown.prepare(env)
    with pytest.raises(ValueError, match='cleanly'):
        installer_shutdown.record(['42:' + str(result)], env)
    assert not Path(env['IRIS_INSTALLER_SHUTDOWN_PROOF']).exists()


def test_earlier_child_crash_remains_nonclean_after_healthy_restart(tmp_path, monkeypatch):
    result, reports = supervisor(tmp_path, monkeypatch, [Child(7), Child(0)], crash_first=True)
    assert result == 1 and reports[-1]['state'] == 'error'


def test_normal_wrapper_shutdown_remains_successful(tmp_path, monkeypatch):
    result, reports = supervisor(tmp_path, monkeypatch, [Child(0)])
    assert result == 0 and reports[-1]['state'] == 'stopped'
