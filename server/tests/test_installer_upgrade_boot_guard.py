# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pre-start guard crash windows; real root-owned code execution when root."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_boot_guard as boot, upgrade_state as state
from iris_installer.state import InstallError, atomic_write

INSTANCE = '9fe66c46-d1e4-4aaf-8eb0-45b3d39f7a9d'
OPERATION = '521fba98-c945-48f8-b71b-ebf86557ae72'


@pytest.fixture
def operation(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    runtime = {'state.py': 'a' * 64}
    worker = {'unit': 'iris-lifecycle-' + INSTANCE + '.service', 'instance_id': INSTANCE}
    op = state.Operation(tmp_path, OPERATION, INSTANCE)
    op.create({'candidate': {'selection': {'runtime': runtime}}})
    op.phase('prepared')
    units = tmp_path / 'units'; units.mkdir(mode=0o755)
    monkeypatch.setattr(boot.managed_worker, 'UNIT_DIRECTORY', units)
    monkeypatch.setattr(boot.managed_worker, '_runtime_manifest', lambda: runtime)
    monkeypatch.setattr(boot.managed_worker, '_runtime', lambda *args: None)
    monkeypatch.setattr(boot.managed_worker, '_path', lambda path: path)
    monkeypatch.setattr(boot.managed_worker, '_file', lambda path, **kwargs: path.read_bytes())
    monkeypatch.setattr(boot, '_directory', lambda path: path.exists())
    control = {'loaded': [], 'failure': None, 'failed': False}
    def command(argv):
        if argv == ['systemctl', 'daemon-reload']:
            control['loaded'] = [str(units / (worker['unit'] + '.d') / boot.NAME)]
            if control['failure'] == 'daemon-reload' and not control['failed']:
                control['failed'] = True
                raise InstallError('injected daemon reload')
            return b''
        return ('DropInPaths=' + ' '.join(control['loaded']) + '\n').encode()
    monkeypatch.setattr(boot.managed_worker, 'command', command)
    return op, {'record': worker, 'boot_guard': None}, control


def test_guard_install_intent_blocks_a_different_operation_while_still_passive(operation):
    op, worker, control = operation
    control['failure'] = 'daemon-reload'
    with pytest.raises(InstallError, match='injected'):
        boot.install(op.base, op, worker)
    assert op.record['phase'] == 'prepared' and 'boot_guard_intent' in op.record
    with pytest.raises(InstallError, match='Recover'):
        state.guard(op.base)
    boot.install(op.base, op, worker)
    assert op.record['boot_guard_installed'] == op.record['boot_guard_intent']


@pytest.mark.parametrize('boundary', ['code-before', 'code-after', 'dropin-before', 'dropin-after'])
def test_guard_install_recovers_pre_and_post_publication_boundaries(operation, monkeypatch, boundary):
    op, worker, control = operation
    original = boot.atomic_write
    failed = False
    def write(path, data, *args):
        nonlocal failed
        target = 'worker-start-guard.py' if boundary.startswith('code') else boot.NAME
        if path.name != target or failed:
            return original(path, data, *args)
        failed = True
        if boundary.endswith('after'): original(path, data, *args)
        raise OSError('injected publication interruption')
    monkeypatch.setattr(boot, 'atomic_write', write)
    with pytest.raises(OSError, match='injected'):
        boot.install(op.base, op, worker)
    assert 'boot_guard_intent' in json.loads(op.path.read_bytes())
    boot.install(op.base, op, worker)
    assert op.record['boot_guard_installed'] == op.record['boot_guard_intent']


def test_tampered_guard_is_never_replaced_by_recovery(operation):
    op, worker, control = operation
    boot.install(op.base, op, worker)
    path = op.directory / 'worker-start-guard.py'
    atomic_write(path, b'not the approved guard')
    with pytest.raises(InstallError, match='code changed'):
        boot.install(op.base, op, worker)
    assert path.read_bytes() == b'not the approved guard'


def test_unknown_effective_dropin_refuses_before_any_guard_intent(operation):
    op, worker, control = operation
    control['loaded'] = ['/etc/systemd/system/unrelated.conf']
    with pytest.raises(InstallError, match='unknown'):
        boot.install(op.base, op, worker)
    assert 'boot_guard_intent' not in op.record


@pytest.mark.skipif(os.geteuid() != 0, reason='requires actual root-owned runtime and nonwritable ancestry')
@pytest.mark.parametrize('scenario,expected', [('passive', 0), ('guard-intent-old', 1), ('active-old', 1),
    ('active-new', 0), ('missing-pointer', 1), ('changed-runtime', 1), ('wrong-instance', 1)])
def test_actual_pinned_prestart_code_handles_reboot_states(scenario, expected):
    # /run is root-owned and nonwritable by other users. Ordinary pytest /tmp
    # ancestry intentionally cannot qualify this production startup guard.
    with tempfile.TemporaryDirectory(prefix='iris-upgrade-guard-test-', dir='/run') as temporary:
        base = Path(temporary)
        runtime = boot.managed_worker._runtime_manifest()
        worker = {'instance_id': INSTANCE, 'state_dir': str(base), 'runtime': {'old.py': 'a' * 64}}
        op = state.Operation(base, OPERATION, INSTANCE)
        op.create({'candidate': {'selection': {'runtime': runtime}}})
        op.phase('prepared')
        if scenario != 'passive':
            op.record['boot_guard_intent'] = {'installed': 'test-only'}
            op.phase('fencing' if scenario != 'guard-intent-old' else 'prepared')
        if scenario == 'active-new': worker['runtime'] = runtime
        if scenario == 'wrong-instance': worker['instance_id'] = OPERATION
        atomic_write(base / 'worker-service.json', state.canonical(worker))
        boot.managed_worker._runtime(base, {'runtime': runtime})
        path = op.directory / 'worker-start-guard.py'
        atomic_write(path, boot.launcher(base, OPERATION, runtime, INSTANCE))
        if scenario == 'missing-pointer': (base / 'application-upgrade.json').unlink()
        if scenario == 'changed-runtime':
            package = boot.managed_worker._runtime_directory(base, {'runtime': runtime}) / 'iris_installer'
            atomic_write(package / 'state.py', b'raise RuntimeError("must never execute changed source")')
        result = subprocess.run([sys.executable, '-I', '-B', str(path)], capture_output=True, timeout=10)
        assert result.returncode == expected
        assert result.stdout == b''
        if expected:
            assert result.stderr == b'IRIS worker start refused: recover the approved application upgrade.\n'
