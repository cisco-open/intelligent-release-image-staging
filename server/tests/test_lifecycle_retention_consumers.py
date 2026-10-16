# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Host admission and preserved terminal authority, without live mutations."""
import json
from types import SimpleNamespace

import pytest

from test_lifecycle_retention import worker, finished, request, uid
from test_maintenance_terminal import client, recovery_candidate
from iris_installer import lifecycle_history, maintenance, image_storage, managed_worker, upgrade_runtime, restore
from iris_installer.state import Journal, InstallError, atomic_write


def pending(worker, state):
    selected = dict(action='delete-backup', request_id=uid(), expected_revision='0' * 64,
                    backup_id=uid(), confirm_delete=True)
    record = dict(request_id=selected['request_id'], action='delete-backup', state=state,
                  backup_id=selected['backup_id'], retired_count=0)
    worker.retention.store.begin(selected, record)


@pytest.mark.parametrize('state', ['running', 'recovery-required'])
@pytest.mark.parametrize('consumer', ['removal', 'image-folder', 'recovery-key', 'restore-signer', 'direct-backup-or-restore'])
def test_pending_retention_blocks_host_maintenance_before_any_mutation(worker, monkeypatch, state, consumer):
    pending(worker, state)
    monkeypatch.setattr(managed_worker, 'command', lambda *a, **k: pytest.fail('host command admitted'))
    monkeypatch.setattr(image_storage, 'require_approval', lambda *a: None)
    if consumer == 'removal': action = lambda: upgrade_runtime.jobs_idle(worker.state_dir)
    elif consumer == 'direct-backup-or-restore': action = lambda: restore.guard(worker.state_dir)
    elif consumer == 'image-folder': action = lambda: image_storage.change(SimpleNamespace(state_dir=worker.state_dir, path=worker.backup_dir))
    elif consumer == 'recovery-key': action = lambda: managed_worker._configure_recovery(worker.state_dir, None)
    else: action = lambda: managed_worker._configure_restore_signer(worker.state_dir, '/not-read')
    with pytest.raises(lifecycle_history.RetentionConflict, match='pending backup deletion'): action()


def test_read_only_guard_under_existing_lock_does_not_initialize_old_installation(tmp_path):
    base = tmp_path / 'state'; base.mkdir(mode=0o700)
    atomic_write(base / 'installation.json', json.dumps(dict(schema=1, config={}, completed={})).encode())
    with Journal(base).locked():
        before = {path.name: path.read_bytes() for path in base.iterdir()}
        lifecycle_history.guard(base)
        assert lifecycle_history.existing_store(base) is None
        assert {path.name: path.read_bytes() for path in base.iterdir()} == before


def test_read_only_guard_validates_existing_database_without_lock_reentry_or_writes(worker):
    with Journal(worker.state_dir).locked():
        before = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in worker.state_dir.iterdir()}
        lifecycle_history.guard(worker.state_dir)
        assert {path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in worker.state_dir.iterdir()} == before


def test_completed_real_shaped_transport_record_can_retire(worker):
    row = dict(finished('renew-transport'), state='renewed'); row.pop('backup_id')
    directory = worker.state_dir / 'lifecycle-transport-operations' / row['id']; directory.mkdir(parents=True)
    record = dict(schema=1, request_id=row['id'], phase='complete', instance_id='owned')
    atomic_write(directory / 'record.json', json.dumps(record).encode())
    original = (directory / 'record.json').read_bytes()
    worker.jobs = [row]; worker.save(); worker.submit(request(worker))
    assert worker.jobs == [] and worker.retention.store.retired(row['id'])
    assert (directory / 'record.json').read_bytes() == original


@pytest.mark.parametrize('state,drift', [('rotated', None), ('failed', None), ('rotated', 'instance'), ('rotated', 'family')])
def test_retired_recovery_candidate_uses_exact_preserved_terminal_authority(client, recovery_candidate, monkeypatch, state, drift):
    identity, recipient = recovery_candidate
    first = maintenance.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    installed = client.state_dir / 'installation.json'; installed.chmod(0o600)
    store = lifecycle_history.Store(client.state_dir)
    row = dict(finished('rotate'), id=first['request_id'], state=state, family='age-recovery'); row.pop('backup_id')
    directory = client.state_dir / 'credential-operations' / row['id']; directory.mkdir(parents=True)
    record = dict(schema=1, operation_id=row['id'], kind='age-recovery', instance_id='test-instance',
                  phase='rotated' if state == 'rotated' else 'refused', mutations_admitted=False, initial_clean_stop=True)
    atomic_write(directory / 'record.json', json.dumps(record).encode())
    selected = dict(action='retire-history', request_id=uid(), expected_revision='0' * 64, job_ids=[row['id']])
    intent = dict(request_id=selected['request_id'], action='retire-history', state='running', retired_count=0, backup_id=None)
    rows = [row]; store.archive(intent, rows, [row['id']], request=selected); store.reconcile(rows, lambda: None)
    assert rows == []
    if drift:
        record['instance_id' if drift == 'instance' else 'kind'] = 'different'
        atomic_write(directory / 'record.json', json.dumps(record).encode())
    second = maintenance.prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    assert (second['request_id'] != first['request_id']) is (drift is None)
    assert store.retired(row['id']) and identity.exists()
