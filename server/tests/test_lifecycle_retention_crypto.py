# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real age/OpenSSH archive deletion; local disposable fixtures only."""
import json
from types import SimpleNamespace

import pytest

from test_backup_archive import recovery
from test_lifecycle_retention import worker, finished, delete_request, uid
from iris_installer import backup, backup_archive
from iris_installer.state import InstallError, atomic_write


@pytest.mark.parametrize('damage', [None, 'wrong-pair', 'ciphertext'])
def test_real_signed_encrypted_pair_deletion_retains_all_key_custody(worker, recovery, damage):
    backup_id, inner_id = uid(), uid()
    iid = json.loads((worker.state_dir / 'installation.json').read_bytes())['id']
    signer = worker.state_dir / 'backup-custody'; signer.mkdir(mode=0o700)
    atomic_write(signer / 'signer.pub', recovery['public'].read_bytes())
    worker.identity = recovery['identity']; worker.identity_history = [worker.identity]
    keys = {path: path.read_bytes() for path in (recovery['identity'], recovery['signer'], recovery['public'])}
    for root, scope in ((worker.backup_dir, 'managed-deployment-files'), (worker.recovery_dir, 'identity-recovery')):
        backup_archive.create({'fixture': recovery['source']}, root / backup_id,
            recovery['recipient'], recovery['signer'], metadata={'scope': scope, 'instance_id': iid,
            'target': worker.target, 'backup_set_id': uid() if damage == 'wrong-pair' and root == worker.recovery_dir else inner_id})
    if damage == 'ciphertext':
        with (worker.backup_dir / backup_id / 'payload.tar.age').open('ab') as stream:
            stream.write(b'tampered')
    worker.jobs = [dict(finished('backup'), backup_id=backup_id, state='captured')]; worker.save()
    selected = delete_request(worker, backup_id)
    worker.submit(selected); worker.thread.join(15)
    assert not worker.thread.is_alive()
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == ('completed' if damage is None else 'recovery-required')
    for root in (worker.backup_dir, worker.recovery_dir):
        assert (root / backup_id).exists() is (damage is not None)
        assert not list(root.glob('.iris-*'))
    assert {path: path.read_bytes() for path in keys} == keys


def test_real_capture_second_archive_failure_can_delete_authenticated_recovery_survivor(worker, recovery, monkeypatch):
    """Exercise the real create/worker failure path; only service/image hooks are simulated."""
    journal_path = worker.state_dir / 'installation.json'
    journal = json.loads(journal_path.read_bytes())
    journal['config']['recovery_recipient'] = recovery['recipient']
    journal['completed']['images'] = {'server': 'sha256:' + 'a' * 64}
    atomic_write(journal_path, json.dumps(journal).encode())
    atomic_write(recovery['directory'] / 'age.txt', recovery['identity'].read_bytes())
    signer = worker.state_dir / 'backup-custody'; signer.mkdir(mode=0o700)
    atomic_write(signer / 'signer.pub', recovery['public'].read_bytes())
    worker.identity = recovery['identity']; worker.identity_history = [worker.identity]
    events = []
    installation = SimpleNamespace(base=recovery['directory'], config={'target': 'docker'},
        backup_export_images=lambda path: path.write_bytes(b'unit image-export bytes'))
    # Replace only this module's root admission gate, not filesystem custody's
    # actual effective UID. No host service or privilege action is performed.
    monkeypatch.setattr(backup, 'os', SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(backup, '_installation', lambda _journal: installation)
    monkeypatch.setattr(backup, 'capture_plan', lambda *_a, **_k: ({'fixture': recovery['source']}, {},
        [{'service': 'console', 'running': True}, {'service': 'iris', 'running': True}]))
    monkeypatch.setattr(backup, 'capacity_preflight', lambda *_a: None)
    monkeypatch.setattr(backup, 'initialize', lambda *_a: recovery['signer'])
    monkeypatch.setattr(backup, 'stop_writers', lambda *_a: events.append('stop'))
    monkeypatch.setattr(backup, 'restart_writer', lambda _i, row: events.append('restart:' + row['service']))
    create = backup_archive.create
    def second_fails(sources, destination, *args, **kwargs):
        events.append('data' if destination.parent == worker.backup_dir else 'recovery')
        if destination.parent == worker.backup_dir:
            raise InstallError('injected second archive failure')
        return create(sources, destination, *args, **kwargs)
    monkeypatch.setattr(backup_archive, 'create', second_fails)
    job = dict(finished('backup'), state='running'); worker.jobs = [job]; worker.save()
    worker.perform(job)
    assert events == ['stop', 'recovery', 'data', 'restart:iris', 'restart:console']
    assert job['state'] == 'failed'
    operation = json.loads((worker.state_dir / 'backup-operation.json').read_bytes())
    assert operation['state'] == 'failed' and operation['restart_required'] == []
    assert not (worker.backup_dir / job['backup_id']).exists()
    assert (worker.recovery_dir / job['backup_id']).is_dir()
    status = worker.retention.status()
    assert status['capacity']['backup_used'] == 1 and status['jobs'][0]['retire_allowed'] is False
    assert status['backups'][0]['delete_allowed'] is True
    selected = delete_request(worker, job['backup_id']); worker.submit(selected); worker.thread.join(15)
    assert not worker.thread.is_alive()
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'completed' and result['pair'][0] is None
    assert worker.retention.status()['capacity']['backup_used'] == 0
    assert worker.jobs == [] and worker.retention.store.retired(job['id'])
    assert json.loads((worker.state_dir / 'backup-operation.json').read_bytes()) == operation
    assert all(path.exists() for path in (recovery['identity'], recovery['signer'], recovery['public']))
