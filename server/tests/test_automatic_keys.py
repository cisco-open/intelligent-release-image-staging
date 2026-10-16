# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real non-TTY OpenSSH automatic custody and fail-closed recovery."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools'))
from iris_installer import automatic_keys as helper
from iris_installer import key_setup
from iris_installer.state import InstallError

pytestmark = pytest.mark.skipif(shutil.which('ssh-keygen') is None, reason='OpenSSH required')


@pytest.fixture
def holder(tmp_path):
    tmp_path.chmod(0o700)
    directory = tmp_path / 'holder'
    public = helper.create_root('root-a', directory)
    return public.with_suffix('')


def test_real_generate_derive_and_certificate_without_terminal(tmp_path, capsys, monkeypatch):
    tmp_path.chmod(0o700)
    commands = []
    original = helper.subprocess.Popen

    def record(command, **kwargs):
        assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['start_new_session']
        assert kwargs['env']['SSH_ASKPASS_REQUIRE'] == 'force'
        assert 'SSH_AUTH_SOCK' not in kwargs['env'] and 'PYTHONPATH' not in kwargs['env']
        commands.append((command, kwargs['env']))
        return original(command, **kwargs)

    monkeypatch.setenv('SSH_AUTH_SOCK', '/untrusted-agent')
    monkeypatch.setenv('SSH_ASKPASS', '/untrusted-helper')
    monkeypatch.setenv('PYTHONPATH', '/untrusted-python')
    monkeypatch.setattr(helper.subprocess, 'Popen', record)
    first = helper.create_root('root-a', tmp_path / 'a')
    second = helper.create_root('root-b', tmp_path / 'b')
    root = first.with_suffix('')
    assert helper.root_public(root) == key_setup.public_key(first.read_bytes())
    assert helper.root_public(second.with_suffix('')) != helper.root_public(root)
    assert helper.is_managed(root)
    secrets = [path.with_suffix('.passphrase').read_bytes().strip() for path in (root, second.with_suffix(''))]
    assert all(re.fullmatch(rb'[A-Za-z0-9_-]{64}', value) for value in secrets)
    assert secrets[0] != secrets[1]
    for path in (root, root.with_suffix('.passphrase'), root.parent / helper.MARKER):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700
    assert all(value.decode() not in repr(commands) for value in secrets)
    output = tmp_path / 'certificate.pub'
    helper.sign_online(root, second, output)
    monkeypatch.setattr(helper.subprocess, 'Popen', original)
    result = subprocess.run(['/usr/bin/ssh-keygen', '-L', '-f', str(output)],
                            capture_output=True, check=True)
    assert b'iris-online' in result.stdout and b'iris-server' in result.stdout
    assert b'ED25519-CERT' in result.stdout
    capture = capsys.readouterr()
    assert not capture.out and not capture.err
    # The actual certificate has a 30-day interval, matching manual custody.
    from datetime import datetime
    interval = re.search(rb'Valid: from (\S+) to (\S+)', result.stdout)
    assert (datetime.fromisoformat(interval[2].decode()) - datetime.fromisoformat(interval[1].decode())).days == 30


def test_retry_preserves_all_completed_bytes(holder):
    before = {p.name: p.read_bytes() for p in holder.parent.iterdir()}
    assert helper.create_root('root-a', holder.parent) == holder.with_suffix('.pub')
    assert before == {p.name: p.read_bytes() for p in holder.parent.iterdir()}


def test_real_generation_under_private_caller_umask(tmp_path):
    previous = os.umask(0o077)
    try:
        public = helper.create_root('root-a', tmp_path / 'private-umask')
        assert stat.S_IMODE(public.stat().st_mode) == 0o644
        assert stat.S_IMODE(public.with_suffix('').stat().st_mode) == 0o600
        assert helper.root_public(public.with_suffix('')) == key_setup.public_key(public.read_bytes())
    finally:
        os.umask(previous)


@pytest.mark.parametrize('boundary', ['before-secret', 'before-key', 'after-private'])
def test_interrupted_initial_generation_resumes_without_replacing_key(tmp_path, monkeypatch, boundary):
    directory = tmp_path / 'holder'
    original_publish, original_run = helper._publish, helper._run

    def publish(fd, name, data, mode):
        if boundary == 'before-secret' and name.endswith('.passphrase'):
            raise RuntimeError('simulated interruption')
        return original_publish(fd, name, data, mode)

    def run(arguments, *args, **kwargs):
        if '-t' in arguments and boundary == 'before-key':
            raise RuntimeError('simulated interruption')
        result = original_run(arguments, *args, **kwargs)
        if '-t' in arguments and boundary == 'after-private':
            (directory / 'root-a.pub').unlink()
            raise RuntimeError('simulated interruption')
        return result

    with monkeypatch.context() as patch:
        patch.setattr(helper, '_publish', publish)
        patch.setattr(helper, '_run', run)
        with pytest.raises(RuntimeError, match='simulated'):
            helper.create_root('root-a', directory)
    key = directory / 'root-a'
    secret = directory / 'root-a.passphrase'
    before = {path: path.read_bytes() for path in (key, secret) if path.exists()}
    helper.create_root('root-a', directory)
    assert all(path.read_bytes() == data for path, data in before.items())
    assert json.loads((directory / helper.MARKER).read_text())['phase'] == 'complete'


@pytest.mark.parametrize('name', ['root-a', 'root-a.pub', 'root-a.passphrase', helper.MARKER])
def test_missing_completed_file_refuses_without_replacement(holder, name):
    (holder.parent / name).unlink()
    before = {p.name: p.read_bytes() for p in holder.parent.iterdir()}
    with pytest.raises(InstallError):
        helper.create_root('root-a', holder.parent)
    assert before == {p.name: p.read_bytes() for p in holder.parent.iterdir()}


@pytest.mark.parametrize('name', ['root-a', 'root-a.pub', 'root-a.passphrase', helper.MARKER])
def test_changed_completed_file_refuses_before_signing(holder, tmp_path, name):
    path = holder.parent / name
    path.write_bytes(path.read_bytes() + b'altered\n')
    output = tmp_path / 'output.pub'
    with pytest.raises(InstallError):
        helper.sign_online(holder, holder.with_suffix('.pub'), output)
    assert not output.exists()


def test_manual_root_is_never_adopted(tmp_path):
    directory = tmp_path / 'manual'
    directory.mkdir(mode=0o700)
    root = directory / 'root-a'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', 'test-only-manual', '-f', str(root)], check=True)
    before = root.read_bytes()
    assert not helper.is_managed(root)
    with pytest.raises(InstallError, match='--key-mode manual'):
        helper.create_root('root-a', directory)
    assert root.read_bytes() == before and not (directory / helper.MARKER).exists()


@pytest.mark.parametrize('name', ['root-a', 'root-a.passphrase', helper.MARKER])
@pytest.mark.parametrize('kind', ['symlink', 'permissions', 'hardlink'])
def test_unsafe_holder_file_refused(holder, tmp_path, name, kind):
    path = holder.parent / name
    if kind == 'permissions':
        path.chmod(0o644)
    elif kind == 'hardlink':
        os.link(path, tmp_path / 'linked')
    else:
        saved = tmp_path / 'saved'
        path.rename(saved)
        path.symlink_to(saved)
    with pytest.raises(InstallError):
        helper.root_public(holder)


def test_mismatched_public_and_private_not_adopted(holder, tmp_path):
    other = helper.create_root('root-b', tmp_path / 'other')
    holder.with_suffix('.pub').write_bytes(other.read_bytes())
    with pytest.raises(InstallError, match='match'):
        helper.root_public(holder)


def test_real_existing_custody_keylist_signing_no_prompt(holder, tmp_path):
    payload = tmp_path / 'payload'
    payload.write_bytes(b'public fixture payload\n')
    command = ['ssh-keygen', '-Y', 'sign', '-f', str(holder), '-n', 'iris-keylist-v1', str(payload)]
    result = helper.run_for_root(holder, command)
    assert result.returncode == 0
    allowed = tmp_path / 'allowed'
    allowed.write_bytes(b'holder ' + helper.root_public(holder))
    verify = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'holder',
                             '-n', 'iris-keylist-v1', '-s', str(payload) + '.sig'],
                            input=payload.read_bytes(), capture_output=True)
    assert verify.returncode == 0


def test_existing_output_never_replaced(holder, tmp_path):
    output = tmp_path / 'certificate.pub'
    output.write_bytes(b'keep me')
    with pytest.raises(InstallError, match='already exists'):
        helper.sign_online(holder, holder.with_suffix('.pub'), output)
    assert output.read_bytes() == b'keep me'


def test_askpass_refuses_missing_input_without_output():
    result = subprocess.run([str(helper.ASKPASS)], env={'PATH': '/usr/bin:/bin'},
                            stdin=subprocess.DEVNULL, capture_output=True)
    assert result.returncode == 1 and result.stdout == result.stderr == b''


def test_real_existing_custody_certificate_command(holder, tmp_path):
    request = tmp_path / 'online.pub'
    request.write_bytes(holder.with_suffix('.pub').read_bytes())
    result = helper.run_for_root(holder, ['ssh-keygen', '-s', str(holder), '-I', 'iris-online',
                                        '-n', 'iris-server', '-V', '+0s:+30d', str(request)])
    assert result.returncode == 0 and (tmp_path / 'online-cert.pub').is_file()


@pytest.mark.parametrize('operation', ['public', 'sign', 'generic'])
def test_key_fd_swap_rejected_before_unchecked_inode_reaches_ssh(holder, tmp_path, monkeypatch, operation):
    original_open = helper.os.open
    key_opens = 0
    output = tmp_path / 'certificate.pub'
    unrelated = tmp_path / 'unrelated'
    unrelated.write_bytes(b'not the pinned private key')
    unrelated.chmod(0o600)
    destination_open = 2 if operation == 'public' else 4

    def swap(path, flags, *args, **kwargs):
        nonlocal key_opens
        if path == holder.name and 'dir_fd' in kwargs:
            key_opens += 1
            if key_opens == destination_open:
                return original_open(unrelated, flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(helper.os, 'open', swap)
    with pytest.raises(InstallError, match='private key changed before use'):
        if operation == 'public':
            helper.root_public(holder)
        elif operation == 'sign':
            helper.sign_online(holder, holder.with_suffix('.pub'), output)
        else:
            helper.run_for_root(holder, ['ssh-keygen', '-s', str(holder), '-I', 'iris-online',
                                        '-n', 'iris-server', '-V', '+0s:+30d', str(output)])
    assert not output.exists()


@pytest.mark.parametrize('replacement', ['directory', 'parent'])
def test_named_holder_substitution_preserves_replacement(holder, tmp_path, monkeypatch, replacement):
    original_run = helper._run
    replaced = False
    victim = holder.parent if replacement == 'directory' else holder.parent.parent
    displaced = victim.with_name(victim.name + '-owned-old')
    sentinel = victim / 'keep'

    def replace(*args, **kwargs):
        nonlocal replaced
        if not replaced:
            victim.rename(displaced)
            victim.mkdir(mode=0o700)
            sentinel.write_bytes(b'keep replacement')
            replaced = True
        return original_run(*args, **kwargs)

    monkeypatch.setattr(helper, '_run', replace)
    with pytest.raises(InstallError, match='storage changed'):
        helper.root_public(holder)
    assert sentinel.read_bytes() == b'keep replacement'


@pytest.mark.parametrize('record', [None, False, {}, {'schema': 1}])
def test_malformed_record_never_falls_back_to_manual(holder, record):
    (holder.parent / helper.MARKER).write_text(json.dumps(record))
    with pytest.raises(InstallError):
        helper.is_managed(holder)


def test_failed_child_output_cannot_leak_secret(holder, monkeypatch, capsys):
    secret = holder.with_suffix('.passphrase').read_bytes()

    class Child:
        returncode = 1

        def communicate(self, **kwargs):
            return secret, secret

    monkeypatch.setattr(helper.subprocess, 'Popen', lambda *a, **k: Child())
    with pytest.raises(InstallError) as failure:
        helper.root_public(holder)
    assert secret.decode().strip() not in str(failure.value)
    captured = capsys.readouterr()
    assert not captured.out and not captured.err


@pytest.mark.parametrize('arguments', [
    ['-p'], ['-s', 'ROOT', '-I', 'wrong', '-n', 'iris-server', '-V', '+0s:+30d', '/request'],
    ['-Y', 'sign', '-f', 'ROOT', '-n', 'other-namespace', '/request'],
    ['-Y', 'sign', '-f', 'ROOT', '-n', 'iris-keylist-v1', '/request', '-f', '/other'],
])
def test_generic_runner_rejects_unrelated_operations(holder, arguments):
    command = ['ssh-keygen', *(str(holder) if item == 'ROOT' else item for item in arguments)]
    with pytest.raises(InstallError, match='unsupported'):
        helper.run_for_root(holder, command)
