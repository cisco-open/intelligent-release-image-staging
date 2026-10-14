# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pre-start guard crash windows; real root-owned code execution when root."""

import hashlib
import copy
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
from iris_installer import upgrade_runtime as runtime
from iris_installer.state import InstallError, atomic_write

INSTANCE = '9fe66c46-d1e4-4aaf-8eb0-45b3d39f7a9d'
OPERATION = '521fba98-c945-48f8-b71b-ebf86557ae72'
NEXT = '68265aa4-1b70-4c11-99b3-f3ecc951c674'
THIRD = '232aef0d-7a94-4a0e-9cc6-92344fbe26ac'


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
        if '--property=ActiveState,SubState,UnitFileState' in argv:
            return b'ActiveState=active\nSubState=running\nUnitFileState=enabled\n'
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


def completed_then_prepared(operation, *, phase='prepared', identifier=NEXT):
    old, worker, _ = operation
    boot.install(old.base, old, worker)
    old.phase('upgraded')
    previous = boot.describe(old.base, worker['record'])
    reviewed = dict(worker, boot_guard=previous)
    new = state.Operation(old.base, identifier, INSTANCE)
    new.create({'worker_before': copy.deepcopy(reviewed),
                'candidate': copy.deepcopy(old.record['candidate'])})
    new.phase(phase)
    return old, new, reviewed


@pytest.mark.parametrize('phase', ['building', 'prepared', 'cancelled'])
def test_passive_successor_retains_exact_completed_guard_without_writes(operation, phase):
    old, new, reviewed = completed_then_prepared(operation, phase=phase)
    before = {str(path): path.read_bytes() for path in old.base.rglob('*') if path.is_file()}
    assert boot.describe(old.base, reviewed['record']) == reviewed['boot_guard']
    assert state.read(old.base / 'application-upgrade.json')['operation_id'] == new.id
    assert before == {str(path): path.read_bytes() for path in old.base.rglob('*') if path.is_file()}


def test_real_worker_state_uses_running_guard_not_prepared_successor(operation, monkeypatch):
    old, worker, _ = operation
    worker['record'].update(phase='ready', recovery_identity='/root/existing-recovery.age')
    old, new, reviewed = completed_then_prepared(operation)
    monkeypatch.setattr(boot.managed_worker, '_load', lambda base: worker['record'])
    monkeypatch.setattr(boot.managed_worker, '_check_unit', lambda *args: None)
    monkeypatch.setattr(boot.managed_worker, 'check_storage', lambda *args: None)
    unit = boot.managed_worker.UNIT_DIRECTORY / worker['record']['unit']
    unit.write_bytes(b'owned unit')
    assert runtime.worker_state(old.base)['boot_guard'] == reviewed['boot_guard']
    assert reviewed['boot_guard']['operation_id'] == old.id != new.id


def test_multiple_completed_generations_select_latest_running_guard(operation):
    old, second, reviewed = completed_then_prepared(operation)
    boot.install(old.base, second, reviewed)
    second.phase('upgraded')
    selected = boot.describe(old.base, reviewed['record'])
    third = state.Operation(old.base, THIRD, INSTANCE)
    third.create({'worker_before': dict(reviewed, boot_guard=selected)})
    third.phase('prepared')
    assert boot.describe(old.base, reviewed['record']) == selected
    assert selected['operation_id'] == second.id


@pytest.mark.parametrize('phase', sorted(state.PHASES - state.PASSIVE))
def test_interrupted_or_active_successor_cannot_use_prior_guard(operation, phase):
    old, new, reviewed = completed_then_prepared(operation)
    new.phase(phase)
    with pytest.raises(InstallError, match='interrupted'):
        boot.describe(old.base, reviewed['record'])


@pytest.mark.parametrize('damage', ['fence-intent', 'missing-worker', 'changed-worker',
    'missing-guard', 'changed-digest', 'foreign-guard', 'foreign-instance', 'old-not-upgraded',
    'missing-pointer', 'changed-pointer', 'changed-launcher', 'changed-dropin', 'missing-old-record'])
def test_passive_successor_does_not_weaken_previous_authority(operation, damage):
    old, new, reviewed = completed_then_prepared(operation)
    if damage == 'fence-intent': new.record['boot_guard_intent'] = {'interrupted': True}
    elif damage == 'missing-worker': new.record.pop('worker_before')
    elif damage == 'changed-worker': new.record['worker_before']['record']['unit'] = 'foreign.service'
    elif damage == 'missing-guard': new.record['worker_before']['boot_guard'] = None
    elif damage == 'changed-digest': new.record['worker_before']['boot_guard']['launcher_sha256'] = '0' * 64
    elif damage == 'foreign-guard': new.record['worker_before']['boot_guard']['operation_id'] = new.id
    elif damage == 'foreign-instance': new.record['instance_id'] = THIRD
    elif damage == 'old-not-upgraded':
        old.record['phase'] = 'cancelled'
        atomic_write(old.path, state.canonical(old.record))
    elif damage == 'changed-launcher': atomic_write(old.directory / 'worker-start-guard.py', b'foreign')
    elif damage == 'changed-dropin':
        atomic_write(boot._paths(old.base, reviewed['record'])[1], boot.dropin(old.base, new.id), 0o644)
    elif damage == 'missing-old-record': old.path.unlink()
    if damage == 'foreign-instance':
        atomic_write(new.path, state.canonical(new.record))
        atomic_write(old.base / 'application-upgrade.json', state.canonical(state.pointer(new.record)))
    else:
        new.save()
    if damage == 'missing-pointer': (old.base / 'application-upgrade.json').unlink()
    elif damage == 'changed-pointer':
        atomic_write(old.base / 'application-upgrade.json', state.canonical(dict(state.pointer(new.record), phase='building')))
    with pytest.raises(InstallError):
        boot.describe(old.base, reviewed['record'])


def test_original_worker_without_guard_stays_without_guard(operation):
    op, reviewed, _ = operation
    assert boot.describe(op.base, reviewed['record']) is None


@pytest.mark.parametrize('phase', ['building', 'prepared', 'cancelled'])
def test_incomplete_passive_worker_preimage_refuses(operation, phase):
    old, new, reviewed = completed_then_prepared(operation, phase=phase)
    new.record.pop('worker_before')
    new.save()
    with pytest.raises(InstallError, match='preimage'):
        boot.describe(old.base, reviewed['record'])


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
