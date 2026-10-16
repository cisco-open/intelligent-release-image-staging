# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Upgrade/retention compatibility with real private journals, no host services."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_plan, upgrade_state
from iris_installer.lifecycle_worker import Worker
from iris_installer.lifecycle_retention import InventoryUnavailable, STORAGE_PROBLEM
from iris_installer.state import InstallError, atomic_write


def save(path, value):
    atomic_write(path, upgrade_plan.canonical(value))


@pytest.fixture
def owned(tmp_path):
    base = tmp_path / 'state'; base.mkdir(mode=0o700)
    roots = {name: tmp_path / name for name in ('backup', 'recovery')}
    for path in roots.values(): path.mkdir(mode=0o700)
    iid = str(uuid.uuid4())
    original = {'schema': 1, 'id': iid, 'config': {'target': 'docker', 'instance': 'owned'},
        'source_manifest': {'code.py': 'a' * 64},
        'root_digests': {'root-a.pub': 'b' * 64, 'root-b.pub': 'c' * 64},
        'completed': {'prepared': 'd' * 64, 'images': {}, 'signing': True, 'guestshell': {},
                      'packages': {name: 'e' * 64 for name in upgrade_plan.NATIVE_FILES}},
        'state': 'PRODUCTION_REVIEW_REQUIRED'}
    save(base / 'installation.json', original)
    worker_record = {'schema': 1, 'instance_id': iid, 'state_dir': str(base),
        'unit': 'iris-lifecycle-' + iid + '.service', 'recovery_identity': str(base / 'age.txt'),
        'storage': {name: {'directory': str(path)} for name, path in roots.items()}}
    save(base / 'worker-service.json', worker_record)
    worker = {'record': worker_record, 'unit_sha256': 'f' * 64}
    return SimpleNamespace(base=base, roots=roots, original=original, worker=worker)


def captured_upgrade(owned, phase='worker', partial=False):
    operation = upgrade_state.Operation(owned.base, str(uuid.uuid4()), owned.original['id'])
    original = json.loads((owned.base / 'installation.json').read_bytes())
    operation.create({'original': original, 'worker_before': owned.worker})
    operation.write_plan({'schema': upgrade_plan.SCHEMA, 'operation_id': operation.id,
        'instance_id': operation.instance, 'original': original, 'worker_before': owned.worker})
    paths = {name: str(owned.roots[kind] / ('upgrade-' + operation.id + '-1'))
             for name, kind in (('data', 'backup'), ('identity', 'recovery'))}
    operation.phase(phase, backup_attempts=[paths])
    for name, value in paths.items():
        if partial and name == 'data': continue
        directory = Path(value); directory.mkdir(mode=0o700)
        atomic_write(directory / 'preserved-archive', b'owned archive evidence')
    return operation, paths


@pytest.mark.parametrize('phase', ['worker', 'upgraded', 'recovery-required'])
@pytest.mark.parametrize('partial', [False, True])
def test_exact_upgrade_archives_are_protected_and_do_not_break_worker_status(owned, phase, partial):
    worker = Worker(owned.base, owned.roots['backup'], owned.roots['recovery'])
    operation, paths = captured_upgrade(owned, phase, partial)
    observed = worker.status()['retention']
    assert observed['capacity']['backup_used'] == 0
    assert observed['capacity']['protected_upgrade_used'] == 1
    assert observed['backups'] == []
    assert observed['busy'] is (phase != 'upgraded')
    assert observed['protected_upgrade_backups'] == [{'operation_id': operation.id, 'attempt': 1,
        'phase': phase, 'deployment_archive': not partial, 'recovery_archive': True}]
    assert worker.retention.backup_ids() == set()
    for path in paths.values():
        if Path(path).exists(): assert (Path(path) / 'preserved-archive').read_bytes() == b'owned archive evidence'


@pytest.mark.parametrize('damage', ['unrecorded', 'wrong-attempt', 'extra-attempt-field', 'missing-plan',
    'changed-plan', 'foreign-instance', 'wrong-worker-root', 'changed-original', 'symlink', 'public-directory',
    'missing-verified-side', 'missing-verified-pair', 'wrong-verified-attempt'])
def test_upgrade_prefix_never_waives_exact_archive_authority(owned, damage):
    worker = Worker(owned.base, owned.roots['backup'], owned.roots['recovery'])
    operation, paths = captured_upgrade(owned)
    if damage == 'unrecorded':
        (owned.roots['backup'] / ('upgrade-' + str(uuid.uuid4()) + '-1')).mkdir(mode=0o700)
    elif damage == 'wrong-attempt': operation.record['backup_attempts'][0]['data'] += '-other'
    elif damage == 'extra-attempt-field': operation.record['backup_attempts'][0]['extra'] = paths['data']
    elif damage == 'missing-plan': (operation.directory / 'plan.json').unlink()
    elif damage == 'changed-plan': save(operation.directory / 'plan.json', {})
    elif damage == 'foreign-instance': operation.record['instance_id'] = str(uuid.uuid4())
    elif damage == 'wrong-worker-root': operation.record['worker_before']['record']['storage']['backup']['directory'] = str(owned.base)
    elif damage == 'changed-original': operation.record['original']['state'] = 'foreign'
    elif damage == 'symlink':
        target = Path(paths['data']); target.rename(target.with_name('foreign'))
        target.symlink_to(target.with_name('foreign'))
    elif damage == 'public-directory': Path(paths['data']).chmod(0o755)
    else:
        operation.record['backup'] = {'paths': paths, 'proof': {}}
        if damage == 'wrong-verified-attempt': operation.record['backup']['paths'] = {}
        else:
            for name in ('data', 'identity') if damage == 'missing-verified-pair' else ('data',):
                path = Path(paths[name]); (path / 'preserved-archive').unlink(); path.rmdir()
    save(operation.path, operation.record)
    before = {str(p): p.read_bytes() for p in owned.base.rglob('*') if p.is_file()}
    if damage == 'unrecorded':
        # Unknown output must not hide recovery status or become an authorized
        # archive. Only the read-only projection degrades; mutation scans fail.
        observed = worker.status()['retention']
        assert observed['inventory_available'] is False
        assert observed['storage_problem'] == STORAGE_PROBLEM
        assert observed['capacity']['backup_used'] is None
        assert observed['capacity']['protected_upgrade_used'] is None
        assert observed['backups'] == observed['protected_upgrade_backups'] == []
        assert observed['busy'] is True
        with pytest.raises(InventoryUnavailable): worker.retention.backup_ids()
    else:
        with pytest.raises((InstallError, OSError)): worker.status()
    assert before == {str(p): p.read_bytes() for p in owned.base.rglob('*') if p.is_file()}


def test_unmaterialized_owned_upgrade_attempt_does_not_claim_saved_archives(owned):
    worker = Worker(owned.base, owned.roots['backup'], owned.roots['recovery'])
    operation, paths = captured_upgrade(owned)
    for value in paths.values():
        path = Path(value); (path / 'preserved-archive').unlink(); path.rmdir()
    assert worker.status()['retention']['protected_upgrade_backups'] == []
    assert worker.status()['retention']['capacity']['protected_upgrade_used'] == 0


def test_active_upgrade_blocks_retention_controls_before_any_capture(owned):
    worker = Worker(owned.base, owned.roots['backup'], owned.roots['recovery'])
    operation = upgrade_state.Operation(owned.base, str(uuid.uuid4()), owned.original['id'])
    operation.create({'original': owned.original, 'worker_before': owned.worker})
    operation.phase('fencing')
    assert worker.status()['retention']['busy'] is True
    assert worker.status()['retention']['protected_upgrade_backups'] == []


def test_console_accepts_actual_protected_upgrade_projection(owned):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Console parser contract requires Node.js')
    worker = Worker(owned.base, owned.roots['backup'], owned.roots['recovery'])
    operation, paths = captured_upgrade(owned, 'upgraded', partial=True)
    module = Path(__file__).parents[1] / 'console-ui/src/backup-retention-model.mjs'
    subprocess.run([node, '--input-type=module', '-e', '''
import assert from 'node:assert/strict';
import fs from 'node:fs';
const {retentionStatus} = await import(process.argv[1]);
const value = JSON.parse(fs.readFileSync(0, 'utf8'));
assert.deepEqual(retentionStatus(value), value);
assert.equal(value.capacity.protected_upgrade_used, 1);
assert.equal(value.capacity.backup_used, 0);
assert.equal(value.protected_upgrade_backups[0].deployment_archive, false);
assert.equal(value.protected_upgrade_backups[0].recovery_archive, true);
assert.equal(value.busy, false);
''', module.as_uri()], input=json.dumps(worker.status()['retention']),
        text=True, capture_output=True, check=True, timeout=15)
