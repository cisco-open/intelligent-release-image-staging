# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Upgrade/retention compatibility with real private journals, no host services."""

import copy
from contextlib import nullcontext
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import application_upgrade as upgrade, upgrade_plan, upgrade_state
from iris_installer.lifecycle_history import Store
from iris_installer.lifecycle_worker import Worker
from iris_installer.state import InstallError, Journal, atomic_write


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


@pytest.fixture
def preparing(owned, monkeypatch):
    save(owned.base / 'compose.json', {'owned': True})
    calls = []
    class Install:
        def __init__(self, journal):
            self.journal, self.base = journal, owned.base
            self.compose_file = owned.base / 'compose.json'
        def verify_inputs(self): pass
    monkeypatch.setattr(upgrade, '_root', lambda value: Path(value))
    monkeypatch.setattr(upgrade.managed_worker, '_service_lock', lambda _: nullcontext())
    def worker_state(_):
        # Actual worker_state calls managed_worker._load -> _installation.
        # A nested Journal lock must fail here exactly as it would on host.
        with Journal(owned.base).locked():
            return copy.deepcopy(owned.worker)
    monkeypatch.setattr(upgrade.runtime, 'worker_state', worker_state)
    monkeypatch.setattr(upgrade.restore, 'custody', lambda *a: None)
    monkeypatch.setattr(upgrade, '_idle', lambda *a: None)
    monkeypatch.setattr(upgrade.deploy, 'DockerInstall', Install)
    monkeypatch.setattr(upgrade.backup, 'capture_plan', lambda _: ({}, {}, [{'running': True}]))
    monkeypatch.setattr(upgrade.runtime, 'drain', lambda _: None)
    def selected(*args):
        calls.append('authenticated')
        assert 'lifecycle_history' not in json.loads((owned.base / 'installation.json').read_bytes())
        return {'commit': '9' * 40}, b'authenticated public proof'
    def build(install, operation, selection, source):
        calls.append('build')
        # Starting the new worker's real history store must not change the
        # approved generation, and must never be attempted under Journal.lock.
        assert 'lifecycle_history' in install.journal.document
        return {'selection': selection}
    monkeypatch.setattr(upgrade.candidate, 'selected_source', selected)
    monkeypatch.setattr(upgrade.candidate, 'build', build)
    args = SimpleNamespace(state_dir=owned.base, accept_changes=True, source=owned.base / 'candidate',
        source_proof=owned.base / 'proof', source_proof_sha256='1' * 64, source_commit='9' * 40)
    return SimpleNamespace(owned=owned, args=args, calls=calls)


def test_prepare_commits_history_before_immutable_plan_for_an_old_worker(preparing):
    p = preparing
    old_job = {'id': str(uuid.uuid4()), 'action': 'verify', 'state': 'failed', 'backup_id': str(uuid.uuid4()),
               'started_at': 1, 'finished_at': 2, 'detail': ''}
    save(p.owned.base / 'lifecycle-jobs.json', [old_job])
    assert upgrade.prepare(p.args) == 0
    pointer = json.loads((p.owned.base / 'application-upgrade.json').read_bytes())
    op = upgrade_state.Operation(p.owned.base, pointer['operation_id'], p.owned.original['id']); op.load()
    review = op.plan(op.record['plan_sha256'])
    before = (p.owned.base / 'installation.json').read_bytes()
    store = Store(p.owned.base)
    assert before == (p.owned.base / 'installation.json').read_bytes()
    assert review['original']['lifecycle_history'] == store.anchor == op.record['original']['lifecycle_history']
    assert review['original'] == dict(p.owned.original, lifecycle_history=store.anchor)
    assert json.loads((p.owned.base / 'lifecycle-jobs.json').read_bytes()) == [old_job]
    assert p.calls == ['authenticated', 'build']


def test_unauthenticated_candidate_never_initializes_history(preparing, monkeypatch):
    def refused(*args): raise InstallError('candidate refused')
    monkeypatch.setattr(upgrade.candidate, 'selected_source', refused)
    with pytest.raises(InstallError, match='candidate refused'): upgrade.prepare(preparing.args)
    assert json.loads((preparing.owned.base / 'installation.json').read_bytes()) == preparing.owned.original
    assert not (preparing.owned.base / 'lifecycle-history.sqlite3').exists()


def test_prepare_does_not_adopt_concurrent_journal_fields(preparing, monkeypatch):
    def initialize(base):
        current = json.loads((base / 'installation.json').read_bytes())
        current['unapproved'] = True; save(base / 'installation.json', current)
        return Store(base)
    monkeypatch.setattr(upgrade, 'Store', initialize)
    with pytest.raises(InstallError, match='deployment changed'): upgrade.prepare(preparing.args)
    assert not (preparing.owned.base / 'application-upgrades').exists()
    assert json.loads((preparing.owned.base / 'installation.json').read_bytes())['unapproved'] is True


def test_prepare_refuses_changed_worker_between_history_initialization_and_plan(preparing, monkeypatch):
    original = upgrade.runtime.worker_state
    calls = 0
    def worker_state(base):
        nonlocal calls
        calls += 1
        result = original(base)
        if calls == 2: result['unit_sha256'] = '0' * 64
        return result
    monkeypatch.setattr(upgrade.runtime, 'worker_state', worker_state)
    with pytest.raises(InstallError, match='managed worker changed'): upgrade.prepare(preparing.args)
    assert not (preparing.owned.base / 'application-upgrades').exists()


def test_prepare_preserves_existing_retired_request_authority(preparing, monkeypatch):
    worker = Worker(preparing.owned.base, preparing.owned.roots['backup'], preparing.owned.roots['recovery'])
    job = {'id': str(uuid.uuid4()), 'action': 'verify', 'state': 'failed', 'backup_id': str(uuid.uuid4()),
           'started_at': 1, 'finished_at': 2, 'detail': ''}
    worker.jobs = [job]; worker.save()
    worker.submit({'action': 'retire-history', 'request_id': str(uuid.uuid4()),
        'expected_revision': worker.retention.status()['revision'], 'job_ids': [job['id']]})
    paths = [worker.retention.store.path, worker.retention.store.marker, worker.record]
    before = {str(p): p.read_bytes() for p in paths}
    monkeypatch.setattr(upgrade.candidate, 'selected_source', lambda *a: ({'commit': '9' * 40}, b'public proof'))
    assert upgrade.prepare(preparing.args) == 0
    assert {str(p): p.read_bytes() for p in paths} == before
    assert Store(preparing.owned.base).retired(job['id'])


def test_prepare_refuses_lost_established_history_without_reinitializing(preparing, monkeypatch):
    store = Store(preparing.owned.base)
    store.path.unlink(); store.marker.unlink()
    before = (preparing.owned.base / 'installation.json').read_bytes()
    monkeypatch.setattr(upgrade.candidate, 'selected_source', lambda *a: ({'commit': '9' * 40}, b'public proof'))
    with pytest.raises(InstallError, match='authority is missing'): upgrade.prepare(preparing.args)
    assert before == (preparing.owned.base / 'installation.json').read_bytes()
    assert not store.path.exists() and not store.marker.exists()
