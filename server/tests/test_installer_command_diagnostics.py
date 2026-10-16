# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real private failure evidence; success and custom runners remain unchanged."""

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy, kube_deploy, split_deploy
from iris_installer.state import InstallError


@pytest.fixture
def private_state(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('Private managed installer evidence requires actual root')
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    return state


def fail(state, monkeypatch, stdout=b'private stdout', stderr=b'private stderr'):
    monkeypatch.setattr(deploy.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 9, stdout, stderr))
    with pytest.raises(InstallError, match='exit 9') as caught:
        deploy.run(['docker', 'compose', '-p', 'private-argv', 'build'], diagnostics_dir=state)
    return str(caught.value)


def logs(state):
    return sorted((state / 'command-failures').glob('*.log'))


def test_actual_failure_retains_output_without_terminal_or_journal_secrets(private_state, capsys):
    journal = private_state / 'installation.json'
    journal.write_bytes(b'original journal')
    command = [sys.executable, '-c',
               "import sys; print('secret-output'); print('secret-error',file=sys.stderr); sys.exit(7)",
               'secret-argument']
    with pytest.raises(InstallError, match='exit 7') as caught:
        deploy.run(command, env=dict(deploy.clean_env(), PRIVATE='secret-environment'),
                   input=b'secret-input', diagnostics_dir=private_state)
    message = str(caught.value)
    assert 'private diagnostics:' in message and 'sensitive; root only; do not publish' in message
    assert 'secret' not in message + capsys.readouterr().out
    path, = logs(private_state)
    data = path.read_bytes()
    assert b'secret-output' in data and b'secret-error' in data
    assert all(value not in data for value in (b'secret-argument', b'secret-environment', b'secret-input'))
    assert journal.read_bytes() == b'original journal'
    assert path.stat().st_uid == 0 and path.stat().st_nlink == 1
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_uid == 0 and path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('capture', [False, True])
def test_success_preserves_large_byte_exact_capture_and_creates_no_log(private_state, capture):
    size = 3 * deploy.FAILURE_TAIL_BYTES
    actual = deploy.run([sys.executable, '-c', f'import sys; sys.stdout.buffer.write(bytes(range(256))*{size // 256})'],
                        capture=capture, diagnostics_dir=private_state)
    assert actual == (bytes(range(256)) * (size // 256) if capture else b'')
    assert not (private_state / 'command-failures').exists()


def test_actual_timeout_retains_partial_output_and_suppresses_raw_exception(private_state, capsys):
    with pytest.raises(InstallError, match='timed out') as caught:
        deploy.run([sys.executable, '-c',
                    "import sys,time; print('secret-partial',flush=True); print('secret-err',file=sys.stderr,flush=True); time.sleep(5)"],
                   timeout=0.2, diagnostics_dir=private_state)
    assert caught.value.__suppress_context__ is True
    assert 'secret' not in str(caught.value) + capsys.readouterr().out
    path, = logs(private_state)
    data = path.read_bytes()
    assert b'secret-partial' in data and b'secret-err' in data
    header = json.loads(data.splitlines()[1])
    assert header['timed_out'] is True and header['returncode'] is None


def test_bounded_tails_quota_and_no_overwrite(private_state, monkeypatch):
    tail = deploy.FAILURE_TAIL_BYTES
    stdout, stderr = b'head-out' + b'o' * (tail + 20), b'head-err' + b'e' * (tail + 20)
    for _ in range(deploy.FAILURE_LOG_COUNT):
        assert 'private diagnostics:' in fail(private_state, monkeypatch, stdout, stderr)
    before = {p: p.read_bytes() for p in logs(private_state)}
    assert len(before) == deploy.FAILURE_LOG_COUNT
    for data in before.values():
        header = json.loads(data.splitlines()[1])
        assert header['stdout_bytes'] == len(stdout) and header['stderr_bytes'] == len(stderr)
        assert header['stdout_tail_truncated'] is header['stderr_tail_truncated'] is True
        assert b'head-out' not in data and b'head-err' not in data
        assert b'o' * tail in data and b'e' * tail in data
        assert len(data) <= deploy.FAILURE_LOG_BYTES
    assert 'private diagnostics unavailable' in fail(private_state, monkeypatch)
    assert {p: p.read_bytes() for p in logs(private_state)} == before


@pytest.mark.parametrize('unsafe', ['state-link', 'parent-link', 'state-mode', 'state-owner', 'parent-owner',
                                  'logs-link', 'logs-mode', 'logs-owner', 'hardlink', 'symlink', 'fifo',
                                  'directory', 'file-mode', 'file-owner', 'file-size', 'unknown-file'])
def test_unsafe_storage_never_followed_or_repaired(private_state, monkeypatch, unsafe):
    state = private_state
    logdir = state / 'command-failures'
    logdir.mkdir(mode=0o700)
    sentinel = state.parent / 'outside'
    sentinel.write_bytes(b'preserve outside')
    name = logdir / ('failure-' + 'a' * 32 + '.log')
    if unsafe == 'state-link':
        state = state.parent / 'alias'; state.symlink_to(private_state, target_is_directory=True)
    elif unsafe == 'parent-link':
        alias = state.parent / 'alias'; alias.symlink_to(state.parent, target_is_directory=True)
        state = alias / 'state'
    elif unsafe == 'state-mode': state.chmod(0o755)
    elif unsafe == 'state-owner': os.chown(state, 10001, 10001)
    elif unsafe == 'parent-owner': os.chown(state.parent, 10001, 10001)
    elif unsafe == 'logs-link':
        logdir.rmdir(); logdir.symlink_to(state.parent, target_is_directory=True)
    elif unsafe == 'logs-mode': logdir.chmod(0o755)
    elif unsafe == 'logs-owner': os.chown(logdir, 10001, 10001)
    elif unsafe == 'hardlink': os.link(sentinel, name)
    elif unsafe == 'symlink': name.symlink_to(sentinel)
    elif unsafe == 'fifo': os.mkfifo(name, 0o600)
    elif unsafe == 'directory': name.mkdir(mode=0o600)
    else:
        if unsafe == 'unknown-file': name = logdir / 'owner-file'
        name.write_bytes(b'x' * (deploy.FAILURE_LOG_BYTES + 1) if unsafe == 'file-size' else b'owner file')
        name.chmod(0o644 if unsafe == 'file-mode' else 0o600)
        if unsafe == 'file-owner': os.chown(name, 10001, 10001)
    before = set(logdir.iterdir())
    assert 'private diagnostics unavailable' in fail(state, monkeypatch)
    assert set(logdir.iterdir()) == before and sentinel.read_bytes() == b'preserve outside'


def test_uuid_collision_never_replaces_existing_failure(private_state, monkeypatch):
    monkeypatch.setattr(deploy.uuid, 'uuid4', lambda: SimpleNamespace(hex='a' * 32))
    assert 'private diagnostics:' in fail(private_state, monkeypatch, b'first')
    path, = logs(private_state); before = path.read_bytes()
    assert 'private diagnostics unavailable' in fail(private_state, monkeypatch, b'second')
    assert path.read_bytes() == before


def test_write_failure_preserves_original_exit_and_does_not_expose_output(private_state, monkeypatch, capsys):
    monkeypatch.setattr(deploy.os, 'fsync', lambda *_: (_ for _ in ()).throw(OSError('secret disk error')))
    message = fail(private_state, monkeypatch)
    assert 'exit 9' in message and 'private diagnostics unavailable' in message
    assert 'secret' not in message + capsys.readouterr().out


@pytest.mark.parametrize('cls', [deploy.DockerInstall, kube_deploy.KubeInstall, split_deploy.SplitDockerInstall])
def test_all_managed_build_layouts_bind_private_state_only_to_real_runner(cls, tmp_path, monkeypatch):
    # The subclasses inherit this exact command path for both server and Console builds.
    instance = object.__new__(cls)
    instance.base = tmp_path; instance.env = {'PATH': '/test'}
    calls = []
    def real(command, **kwargs):
        calls.append((command, kwargs)); return b'result'
    monkeypatch.setattr(deploy, 'run', real)
    instance.runner = real
    assert instance.command(['docker', 'compose', 'build'], capture=True) == b'result'
    assert calls[-1][1] == {'capture': True, 'env': instance.env, 'diagnostics_dir': tmp_path}
    instance.runner = lambda command, **kwargs: calls.append((command, kwargs)) or b''
    instance.command(['docker', 'compose', 'build'])
    assert calls[-1][1] == {'env': instance.env}


def test_unavailable_executable_does_not_expose_path_or_chain(tmp_path, capsys):
    with pytest.raises(InstallError, match='Required command is unavailable: installer command') as caught:
        deploy.run([str(tmp_path / 'secret-command')])
    assert caught.value.__suppress_context__ is True
    assert 'secret' not in str(caught.value) + capsys.readouterr().out
