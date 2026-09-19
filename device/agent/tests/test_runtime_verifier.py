# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Guest Shell verifier promotion: no fallback to stale/unusable candidates."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

import runtime_verifier as verifier


@pytest.fixture
def layout(tmp_path):
    stage, runtime = tmp_path / 'stage', tmp_path / 'exec'
    (stage / 'agent').mkdir(parents=True)
    runtime.mkdir()
    return stage, runtime, stage / 'agent' / 'ssh-keygen', runtime / verifier.NAME


def write_binary(path, data=b'\x7fELFsynthetic-new', mode=0o700):
    path.write_bytes(data)
    path.chmod(mode)


def accepted(*args, **kwargs):
    return SimpleNamespace(returncode=0)


def test_legacy_bundle_uses_system_verifier_without_promoting_stale_copy(layout, monkeypatch):
    stage, runtime, source, destination = layout
    write_binary(destination, b'old-local-verifier')
    monkeypatch.setattr(verifier.shutil, 'which', lambda name: '/system/ssh-keygen')
    assert verifier.select(str(stage), str(runtime)) == '/system/ssh-keygen'
    assert verifier.install(str(stage), str(runtime), runner=accepted) is False
    assert destination.read_bytes() == b'old-local-verifier'


def test_supplied_source_never_falls_back_when_runtime_is_missing_or_different(layout, monkeypatch):
    stage, runtime, source, destination = layout
    monkeypatch.setattr(verifier.shutil, 'which', lambda name: pytest.fail('system fallback'))
    write_binary(source)
    assert verifier.select(str(stage), str(runtime)) is None
    write_binary(destination, b'\x7fELFstale')
    assert verifier.select(str(stage), str(runtime)) is None


def test_promotion_probes_private_candidate_then_atomically_replaces_old_inode(layout):
    stage, runtime, source, destination = layout
    write_binary(source, mode=0o600)  # source need not execute on flash
    write_binary(destination, b'\x7fELFold')
    old_inode = destination.stat().st_ino
    with destination.open('rb') as old_stream:
        def probe(argv, **kwargs):
            candidate = Path(argv[0])
            assert candidate.parent.parent == runtime
            assert candidate != destination
            assert candidate.read_bytes() == source.read_bytes()
            assert stat.S_IMODE(candidate.stat().st_mode) == 0o700
            assert stat.S_IMODE(candidate.parent.stat().st_mode) == 0o700
            assert destination.read_bytes() == b'\x7fELFold'
            assert kwargs['timeout'] == 5
            assert kwargs['input'] == b'IRIS verifier capability check\n'
            assert 'verify-time=20260919000000Z' in argv
            return accepted()
        assert verifier.install(str(stage), str(runtime), runner=probe) is True
        assert old_stream.read() == b'\x7fELFold'
    assert destination.stat().st_ino != old_inode
    assert destination.read_bytes() == source.read_bytes()
    assert verifier.select(str(stage), str(runtime)) == str(destination)
    assert list(runtime.iterdir()) == [destination]


@pytest.mark.parametrize('failure', ['rejected', 'timeout', 'exec-error'])
def test_failed_candidate_preserves_old_inode_but_never_selects_it(layout, failure):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination, b'\x7fELFold')
    old_inode = destination.stat().st_ino
    def probe(argv, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        if failure == 'exec-error':
            raise OSError('wrong architecture')
        return SimpleNamespace(returncode=1)
    with pytest.raises((OSError, ValueError, subprocess.TimeoutExpired)):
        verifier.install(str(stage), str(runtime), runner=probe)
    assert destination.stat().st_ino == old_inode
    assert destination.read_bytes() == b'\x7fELFold'
    assert verifier.select(str(stage), str(runtime)) is None
    assert list(runtime.iterdir()) == [destination]


def test_identical_safe_generation_does_not_execute_or_rewrite_binary(layout):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination)
    inode = destination.stat().st_ino
    def unexpected(*args, **kwargs):
        pytest.fail('unchanged verifier was probed again')
    assert verifier.install(str(stage), str(runtime), runner=unexpected) is False
    assert destination.stat().st_ino == inode
    assert verifier.select(str(stage), str(runtime)) == str(destination)


@pytest.mark.parametrize('mode', [0o600, 0o755, 0o777])
def test_matching_runtime_with_unsafe_mode_is_rejected_then_repaired(layout, mode):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination, mode=mode)
    assert verifier.select(str(stage), str(runtime)) is None
    assert verifier.install(str(stage), str(runtime), runner=accepted)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert verifier.select(str(stage), str(runtime)) == str(destination)


def test_runtime_owned_by_another_uid_is_not_selected(layout, monkeypatch):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination)
    actual_uid = os.geteuid()
    monkeypatch.setattr(verifier.os, 'geteuid', lambda: actual_uid + 1)
    assert verifier.select(str(stage), str(runtime)) is None


@pytest.mark.parametrize('kind', ['symlink', 'dangling-symlink', 'fifo', 'oversize', 'empty'])
def test_invalid_supplied_source_is_rejected_without_system_fallback(layout, monkeypatch, kind):
    stage, runtime, source, destination = layout
    write_binary(destination)
    monkeypatch.setattr(verifier.shutil, 'which', lambda name: pytest.fail('system fallback'))
    if kind == 'symlink':
        source.symlink_to(destination)
    elif kind == 'dangling-symlink':
        source.symlink_to(stage / 'absent')
    elif kind == 'fifo':
        os.mkfifo(source)
    else:
        source.write_bytes(b'x' * (verifier.MAX_BINARY + 1) if kind == 'oversize' else b'')
    assert verifier.select(str(stage), str(runtime)) is None
    with pytest.raises((OSError, ValueError)):
        verifier.install(str(stage), str(runtime), runner=accepted)
    assert destination.read_bytes() == b'\x7fELFsynthetic-new'


def test_runtime_symlink_is_replaced_without_modifying_its_target(layout):
    stage, runtime, source, destination = layout
    write_binary(source)
    target = runtime.parent / 'other-program'
    write_binary(target, b'\x7fELFother')
    destination.symlink_to(target)
    assert verifier.select(str(stage), str(runtime)) is None
    assert verifier.install(str(stage), str(runtime), runner=accepted)
    assert not destination.is_symlink()
    assert target.read_bytes() == b'\x7fELFother'
    assert verifier.select(str(stage), str(runtime)) == str(destination)


def test_oversize_runtime_is_rejected_without_uncaught_reader_error(layout):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination, b'x' * (verifier.MAX_BINARY + 1))
    assert verifier.select(str(stage), str(runtime)) is None


def test_failed_atomic_replace_preserves_old_binary_and_cleans_candidate(layout, monkeypatch):
    stage, runtime, source, destination = layout
    write_binary(source)
    write_binary(destination, b'\x7fELFold')
    def fail_replace(*args):
        raise OSError('filesystem rejected rename')
    monkeypatch.setattr(verifier.os, 'replace', fail_replace)
    with pytest.raises(OSError):
        verifier.install(str(stage), str(runtime), runner=accepted)
    assert destination.read_bytes() == b'\x7fELFold'
    assert list(runtime.iterdir()) == [destination]
    assert verifier.select(str(stage), str(runtime)) is None


def test_actual_host_ssh_keygen_verifies_probe_before_promotion(layout):
    """Exercises actual SSHSIG; this does not establish static/ARM compatibility."""
    stage, runtime, source, destination = layout
    host = shutil.which('ssh-keygen')
    if not host:
        pytest.skip('host ssh-keygen unavailable')
    if Path(host).stat().st_size > verifier.MAX_BINARY:
        pytest.skip('host verifier exceeds target binary bound')
    probe = subprocess.run([host, '-Y', 'verify'], capture_output=True, timeout=5)
    if b'unknown option' in probe.stderr or b'invalid option' in probe.stderr:
        pytest.skip('host OpenSSH lacks SSHSIG support')
    shutil.copyfile(host, source)
    source.chmod(0o600)
    assert verifier.install(str(stage), str(runtime))
    assert verifier.select(str(stage), str(runtime)) == str(destination)
    assert source.read_bytes() == destination.read_bytes()
