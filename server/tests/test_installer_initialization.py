# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Root-owned disposable fixtures; no dependencies, services or devices changed."""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy
from iris_installer.state import InstallError

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='real installer journal ownership requires root')


@pytest.fixture
def setup(tmp_path, monkeypatch):
    source = tmp_path / 'input'
    (source / 'nested').mkdir(parents=True)
    (source / 'one').write_bytes(b'first source file')
    (source / 'nested/two').write_bytes(b'second source file')
    (source / 'nested/two').chmod(0o755)
    inventory = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                 for name in ('one', 'nested/two')}
    (source / 'INSTALLER-SOURCE.json').write_text(json.dumps(inventory))
    roots = tmp_path / 'public-roots'
    roots.mkdir()
    (roots / 'a.pub').write_bytes(b'ssh-ed25519 AAAA fixture-a\n')
    (roots / 'b.pub').write_bytes(b'ssh-ed25519 BBBB fixture-b\n')
    args = SimpleNamespace(target='docker', instance='iris-test', host='192.0.2.10',
        console_bind='127.0.0.1', console_port=18080, recovery_recipient='age1' + 'q' * 58,
        peer_tls='required', accept_changes=True, state_dir=tmp_path / 'state',
        source=source, roots_dir=roots, certificate=None)
    deployments = []
    def adapter(journal):
        assert journal.document['state'] == 'INITIALIZED'
        assert 'initialization' not in journal.document
        deployments.append(copy.deepcopy(journal.document))
        return SimpleNamespace(resume=lambda *args: 20)
    def runner(command, **kwargs):
        assert command[:2] == ['ssh-keygen', '-lf'] or (
            command[0] == 'docker' and command[2] == 'ls')
        return b''
    monkeypatch.setattr(deploy.ubuntu, 'check_platform', lambda: None)
    monkeypatch.setattr(deploy.ubuntu, 'provision', lambda *_args: None)
    monkeypatch.setattr(deploy, 'port_preflight', lambda *_args: None)
    monkeypatch.setattr(deploy, 'run', runner)
    monkeypatch.setattr(deploy, 'installation', adapter)
    return args, deployments


def _interrupt_copy(args, monkeypatch, nth):
    real_copy = deploy.shutil.copyfileobj
    calls = 0
    def interrupted(source, destination):
        nonlocal calls
        calls += 1
        record = json.loads((args.state_dir / 'installation.json').read_text())
        assert record['state'] == 'INITIALIZING'
        if calls == nth:
            destination.write(source.read(1))
            destination.flush()
            raise SystemExit('injected interruption')
        real_copy(source, destination)
    with monkeypatch.context() as scoped:
        scoped.setattr(deploy.shutil, 'copyfileobj', interrupted)
        with pytest.raises(SystemExit, match='injected interruption'):
            deploy.start(args)
    assert (args.state_dir / '.initial-input-buffer').stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('copy_number', [1, 2, 3, 4])
def test_resume_after_each_partial_source_or_public_root_copy(setup, monkeypatch, copy_number):
    args, deployments = setup
    _interrupt_copy(args, monkeypatch, copy_number)
    record = json.loads((args.state_dir / 'installation.json').read_text())
    assert deployments == []
    with pytest.raises(InstallError, match='use irisctl resume'):
        deploy.start(args)
    # Only the captured PUBLIC bytes are needed after initialization begins.
    (args.roots_dir / 'a.pub').unlink()
    (args.roots_dir / 'b.pub').unlink()
    assert deploy.resume(args) == 20
    assert deployments[0]['id'] == record['id']
    for name in ('one', 'nested/two'):
        assert (args.state_dir / 'source' / name).read_bytes() == (args.source / name).read_bytes()
    assert (args.state_dir / 'source/nested/two').stat().st_mode & 0o777 == 0o755
    assert (args.state_dir / 'roots/a.pub').read_bytes() == b'ssh-ed25519 AAAA fixture-a\n'
    assert not (args.state_dir / '.initial-input-buffer').exists()


@pytest.mark.parametrize('target', ['source/one', 'source/nested/two', 'roots/a.pub', 'roots/b.pub'])
def test_resume_after_rename_before_public_mode_is_set(setup, monkeypatch, target):
    args, deployments = setup
    original = deploy.os.replace
    def replace(source, destination):
        original(source, destination)
        if Path(destination) == args.state_dir / target:
            raise SystemExit('interrupted after rename')
    with monkeypatch.context() as scoped:
        scoped.setattr(deploy.os, 'replace', replace)
        with pytest.raises(SystemExit, match='after rename'):
            deploy.start(args)
    assert deployments == []
    assert (args.state_dir / target).stat().st_mode & 0o777 == 0o600
    assert deploy.resume(args) == 20
    expected_mode = 0o755 if target == 'source/nested/two' else 0o644
    assert (args.state_dir / target).stat().st_mode & 0o777 == expected_mode


@pytest.mark.parametrize('change', ['extra-source', 'extra-roots', 'published-source',
                                  'original-source', 'original-inventory', 'root-intent'])
def test_resume_preserves_unknown_or_changed_inputs(setup, monkeypatch, change):
    args, deployments = setup
    _interrupt_copy(args, monkeypatch, 4)
    changed = None
    if change == 'extra-source':
        changed = args.state_dir / 'source/owner-note'
    elif change == 'extra-roots':
        changed = args.state_dir / 'roots/owner-note'
    elif change == 'published-source':
        changed = args.state_dir / 'source/one'
    elif change == 'original-source':
        changed = args.source / 'one'
    elif change == 'original-inventory':
        changed = args.source / 'INSTALLER-SOURCE.json'
        changed.write_text(json.dumps({'other': '0' * 64}))
    else:
        changed = args.state_dir / 'installation.json'
        record = json.loads(changed.read_text())
        record['initialization']['public_roots']['a.pub'] = 'ssh-ed25519 CCCC changed\n'
        changed.write_text(json.dumps(record))
    if change not in ('original-inventory', 'root-intent'):
        changed.write_bytes(b'owner data must be preserved')
    before = changed.read_bytes()
    with pytest.raises(InstallError):
        deploy.resume(args)
    assert changed.read_bytes() == before
    assert deployments == []


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo'])
def test_resume_refuses_unsafe_buffer_without_touching_owner_file(setup, monkeypatch, kind):
    args, deployments = setup
    _interrupt_copy(args, monkeypatch, 1)
    owner_file = args.state_dir.parent / 'owner-file'
    owner_file.write_bytes(b'preserve owner bytes')
    owner_file.chmod(0o600)
    buffer = args.state_dir / '.initial-input-buffer'
    buffer.unlink()
    if kind == 'symlink':
        buffer.symlink_to(owner_file)
    elif kind == 'hardlink':
        os.link(owner_file, buffer)
    else:
        os.mkfifo(buffer, 0o600)
    with pytest.raises((InstallError, OSError)):
        deploy.resume(args)
    assert owner_file.read_bytes() == b'preserve owner bytes'
    assert deployments == []


def test_unknown_state_without_initialization_intent_is_never_adopted(setup):
    args, deployments = setup
    args.state_dir.mkdir(mode=0o700)
    evidence = args.state_dir / 'source'
    evidence.mkdir()
    (evidence / 'owner-file').write_bytes(b'keep this')
    with pytest.raises(InstallError, match='not empty'):
        deploy.start(args)
    assert (evidence / 'owner-file').read_bytes() == b'keep this'
    assert deployments == []


def test_resume_after_sigkill_during_source_copy(setup):
    args, deployments = setup
    code = r'''
import json, os, signal, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from iris_installer import deploy
values = json.loads(sys.argv[2])
for field in ('state_dir', 'source', 'roots_dir'):
    values[field] = Path(values[field])
args = SimpleNamespace(**values)
original = deploy.shutil.copyfileobj
calls = 0
def interrupted(source, output):
    global calls
    calls += 1
    if calls == 2:
        output.write(source.read(1))
        output.flush()
        os.fsync(output.fileno())
        os.kill(os.getpid(), signal.SIGKILL)
    original(source, output)
with patch.object(deploy.ubuntu, 'check_platform'), \
     patch.object(deploy.ubuntu, 'provision'), \
     patch.object(deploy, 'port_preflight'), \
     patch.object(deploy, 'run', return_value=b''), \
     patch.object(deploy, 'installation', side_effect=AssertionError('must not deploy')), \
     patch.object(deploy.shutil, 'copyfileobj', interrupted):
    deploy.start(args)
'''
    child = subprocess.run([sys.executable, '-c', code,
                            str(Path(__file__).resolve().parents[2] / 'tools'),
                            json.dumps(vars(args), default=str)],
                           capture_output=True, timeout=20,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    before = json.loads((args.state_dir / 'installation.json').read_text())
    assert before['state'] == 'INITIALIZING'
    assert (args.state_dir / 'source/one').read_bytes() == b'first source file'
    assert not (args.state_dir / 'source/nested/two').exists()
    assert deploy.resume(args) == 20
    assert deployments[0]['id'] == before['id']
