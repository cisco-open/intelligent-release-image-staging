# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Retention unit/security regressions; not installed-runtime qualification."""

import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer.lifecycle_history import Store, RetentionConflict, digest
from iris_installer.lifecycle_worker import Worker
from iris_installer import lifecycle_retention as retention
from iris_installer.state import InstallError, atomic_write


def uid():
    return str(uuid.uuid4())


def installation(directory):
    atomic_write(directory / 'installation.json', json.dumps(dict(schema=1, id=uid(),
        config={'target': 'docker'}, completed={})).encode())


@pytest.fixture
def worker(tmp_path):
    for name in ('state', 'data', 'recovery'):
        (tmp_path / name).mkdir(mode=0o700)
    installation(tmp_path / 'state')
    return Worker(tmp_path / 'state', tmp_path / 'data', tmp_path / 'recovery')


def finished(action='verify', **extra):
    return dict(id=uid(), action=action, backup_id=uid(), state='failed', started_at=1, finished_at=2, detail='', **extra)


def request(worker, rows=None, **extra):
    return dict(action='retire-history', request_id=uid(), expected_revision=worker.retention.status()['revision'],
                job_ids=[row['id'] for row in (worker.jobs if rows is None else rows)], **extra)


def restart(worker):
    return Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir, identity=worker.identity)


def test_one_hundred_finished_rows_can_retire_in_bounded_batches_without_replay(worker, monkeypatch):
    worker.jobs = [finished() for _ in range(100)]; worker.save()
    original = copy.deepcopy(worker.jobs)
    for _ in range(4):
        selected = request(worker, worker.jobs[:25])
        result = worker.submit(selected)['retention_operation']
        assert result['state'] == 'completed' and result['retired_count'] == 25
        assert worker.submit(dict(selected, expected_revision='0' * 64)) == {'retention_operation': result}
    worker = restart(worker)
    assert worker.jobs == [] and worker.retention.status()['capacity']['history_used'] == 0
    monkeypatch.setattr('threading.Thread.start', lambda self: None)
    for row in original:
        with pytest.raises(RetentionConflict, match='retired'):
            worker.submit(dict(action='backup', request_id=row['id'], allow_downtime=True))
    assert worker.submit(dict(action='backup', request_id=uid(), allow_downtime=True))['job_id']


def test_twenty_failed_captures_without_archives_do_not_exhaust_saved_backup_limit(worker, monkeypatch):
    worker.jobs = [finished('backup') for _ in range(20)]; worker.save()
    assert worker.retention.status()['capacity']['backup_used'] == 0
    monkeypatch.setattr('threading.Thread.start', lambda self: None)
    worker.submit(dict(action='backup', request_id=uid(), allow_downtime=True))
    assert len(worker.jobs) == 21


def managed_storage(worker):
    instance = json.loads((worker.state_dir / 'installation.json').read_bytes())['id']
    record = {'schema': 1, 'instance_id': instance, 'state_dir': str(worker.state_dir),
              'unit': 'iris-lifecycle-' + instance + '.service',
              'storage': {kind: {'directory': str(root)} for kind, root in
                          (('backup', worker.backup_dir), ('recovery', worker.recovery_dir))}}
    atomic_write(worker.state_dir / 'worker-service.json', json.dumps(record).encode())
    for root in (worker.backup_dir, worker.recovery_dir):
        atomic_write(root / '.iris-storage.json', json.dumps({'instance_id': instance}).encode())
    return record


def test_managed_storage_markers_are_not_backups_and_allow_new_capture(worker, monkeypatch):
    managed_storage(worker)
    assert worker.status()['retention']['capacity']['backup_used'] == 0
    backup_id = uid()
    for root in (worker.backup_dir, worker.recovery_dir):
        (root / backup_id).mkdir(mode=0o700)
    assert worker.status()['retention']['capacity']['backup_used'] == 1
    monkeypatch.setattr('threading.Thread.start', lambda self: None)
    assert worker.submit(dict(action='backup', request_id=uid(), allow_downtime=True))['job_id']


@pytest.mark.parametrize('change', ['foreign-instance', 'extra-field', 'public-mode', 'symlink', 'hardlink',
                                  'missing-record', 'wrong-directory', 'wrong-role', 'wrong-unit', 'other-dotfile'])
def test_only_exact_private_managed_storage_marker_is_exempt(worker, change):
    record = managed_storage(worker)
    marker = worker.backup_dir / '.iris-storage.json'
    if change == 'foreign-instance': atomic_write(marker, json.dumps({'instance_id': uid()}).encode())
    elif change == 'extra-field':
        value = json.loads(marker.read_bytes()); value['extra'] = True
        atomic_write(marker, json.dumps(value).encode())
    elif change == 'public-mode': marker.chmod(0o644)
    elif change in ('symlink', 'hardlink'):
        original = worker.state_dir / 'preserved-marker'; marker.rename(original)
        if change == 'symlink': marker.symlink_to(original)
        else: os.link(original, marker)
    elif change == 'missing-record': (worker.state_dir / 'worker-service.json').unlink()
    elif change == 'other-dotfile': atomic_write(worker.backup_dir / '.owner-note', b'preserve')
    else:
        if change == 'wrong-directory': record['storage']['backup']['directory'] = str(worker.state_dir)
        elif change == 'wrong-role': record['storage']['backup'] = record['storage']['recovery']
        else: record['unit'] = 'foreign.service'
        atomic_write(worker.state_dir / 'worker-service.json', json.dumps(record).encode())
    before = marker.read_bytes()
    if change == 'other-dotfile':
        assert worker.status()['retention']['inventory_available'] is False
    else:
        with pytest.raises((InstallError, OSError)):
            worker.status()
    with pytest.raises((InstallError, OSError)):
        worker.retention.backup_ids()
    assert marker.read_bytes() == before


@pytest.mark.parametrize('change', ['revision', 'missing', 'duplicate', 'too-many', 'active', 'same-id'])
def test_refused_selections_never_publish_intent_or_tombstone(worker, change):
    worker.jobs = [finished()]; worker.save(); selected = request(worker)
    if change == 'revision': selected['expected_revision'] = '0' * 64
    elif change == 'missing': selected['job_ids'] = [uid()]
    elif change == 'duplicate': selected['job_ids'] *= 2
    elif change == 'too-many': selected['job_ids'] = [uid() for _ in range(26)]
    elif change == 'active': worker.jobs[0]['state'] = 'running'; selected['expected_revision'] = worker.retention.status()['revision']
    else: selected['request_id'] = worker.jobs[0]['id']
    with pytest.raises(RetentionConflict): worker.submit(selected)
    assert worker.retention.store.operation(selected['request_id']) is None
    assert not worker.retention.store.retired(worker.jobs[0]['id'])


@pytest.mark.parametrize('point', ['before-list', 'after-list'])
def test_interrupted_retirement_reconciles_exact_lists_on_restart(worker, monkeypatch, point):
    worker.jobs = [finished(), finished()]; worker.save(); selected = request(worker, worker.jobs[:1])
    save = worker.save
    def interrupted():
        if point == 'after-list': save()
        raise OSError('simulated disk interruption')
    monkeypatch.setattr(worker, 'save', interrupted)
    with pytest.raises(OSError): worker.submit(selected)
    resumed = restart(worker)
    assert len(resumed.jobs) == 1
    assert resumed.retention.store.operation(selected['request_id'])['state'] == 'completed'
    assert resumed.retention.store.retired(selected['job_ids'][0])


def test_divergent_visible_history_after_retirement_intent_refuses_restart(worker, monkeypatch):
    worker.jobs = [finished()]; worker.save(); selected = request(worker)
    monkeypatch.setattr(worker, 'save', lambda: (_ for _ in ()).throw(OSError('interrupted')))
    with pytest.raises(OSError): worker.submit(selected)
    atomic_write(worker.record, json.dumps([finished()]).encode())
    with pytest.raises(InstallError, match='changed during retirement'): restart(worker)


@pytest.mark.parametrize('damage', ['database-missing', 'marker-missing', 'both-missing', 'tombstone-missing', 'operation-missing', 'row-changed', 'request-changed', 'schema', 'wal'])
def test_missing_corrupt_or_changed_authority_fails_closed(worker, damage):
    worker.jobs = [finished()]; worker.save(); selected = request(worker); worker.submit(selected)
    store = worker.retention.store
    if damage == 'database-missing': store.path.unlink()
    elif damage == 'marker-missing': store.marker.unlink()
    elif damage == 'both-missing': store.path.unlink(); store.marker.unlink()
    elif damage == 'wal': Path(str(store.path) + '-wal').write_bytes(b'not-allowed')
    else:
        with sqlite3.connect(store.path) as db:
            if damage == 'tombstone-missing': db.execute('DELETE FROM tombstones')
            elif damage == 'operation-missing': db.execute('DELETE FROM operations')
            elif damage == 'row-changed': db.execute("UPDATE tombstones SET row_json='{}'")
            elif damage == 'request-changed': db.execute("UPDATE operations SET request_json='{}'")
            else: db.execute('CREATE TABLE unauthorized (id INTEGER)')
    with pytest.raises((InstallError, OSError)): restart(worker)


def test_database_symlink_hardlink_and_writable_modes_refuse(worker, tmp_path):
    path = worker.retention.store.path
    path.chmod(0o644)
    with pytest.raises(InstallError, match='custody'): restart(worker)
    path.chmod(0o600); os.link(path, tmp_path / 'alias')
    with pytest.raises(InstallError, match='custody'): restart(worker)
    (tmp_path / 'alias').unlink(); path.rename(tmp_path / 'original'); path.symlink_to(tmp_path / 'original')
    with pytest.raises(InstallError, match='custody'): restart(worker)


def pair(worker, monkeypatch):
    backup_id = uid()
    row = finished('backup'); row.update(backup_id=backup_id, state='captured')
    worker.jobs = [row, dict(finished(), backup_id=backup_id, state='verified-files')]; worker.save()
    for root in (worker.backup_dir, worker.recovery_dir):
        directory = root / backup_id; directory.mkdir(mode=0o700)
        for name in retention.FILES: atomic_write(directory / name, (name + ':synthetic-unit').encode())
    iid = json.loads((worker.state_dir / 'installation.json').read_bytes())['id']
    worker.identity = worker.state_dir / 'private-test-identity'; worker.identity_history = [worker.identity]
    def authenticated(path, *args):
        return {'metadata': {'scope': 'managed-deployment-files' if path.parent == worker.backup_dir else 'identity-recovery',
                             'instance_id': iid, 'target': worker.target, 'backup_set_id': backup_id}}
    monkeypatch.setattr(retention.backup_archive, 'read', authenticated)
    return backup_id


def delete_request(worker, backup_id):
    return dict(action='delete-backup', request_id=uid(), expected_revision=worker.retention.status()['revision'],
                backup_id=backup_id, confirm_delete=True)


def test_delete_verifies_pair_removes_only_exact_files_and_retires_related_history(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch); original = copy.deepcopy(worker.jobs)
    marker = worker.state_dir / 'protected-old-key'; marker.write_bytes(b'preserved')
    selected = delete_request(worker, backup_id)
    worker.submit(selected); worker.thread.join(3)
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'completed' and result['retired_count'] == 2
    assert all(not (root / backup_id).exists() for root in (worker.backup_dir, worker.recovery_dir))
    assert marker.read_bytes() == b'preserved' and worker.jobs == []
    assert all(worker.retention.store.retired(row['id']) for row in original)
    assert worker.submit(selected)['retention_operation']['state'] == 'completed'


def test_partial_delete_requires_explicit_same_id_resume(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch); selected = delete_request(worker, backup_id)
    unlink = retention.os.unlink; calls = []
    def interrupted(name, *args, **kwargs):
        if name in retention.FILES:
            calls.append(name)
            if len(calls) == 2: raise OSError('simulated interruption')
        return unlink(name, *args, **kwargs)
    monkeypatch.setattr(retention.os, 'unlink', interrupted)
    worker.submit(selected); worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    assert worker.submit(selected)['retention_operation']['state'] == 'recovery-required'
    with pytest.raises(RetentionConflict, match='pending backup deletion'):
        worker.submit(dict(action='backup', request_id=uid(), allow_downtime=True))
    monkeypatch.setattr(retention.os, 'unlink', unlink)
    worker.submit(dict(selected, action='resume-delete', expected_revision=worker.retention.status()['revision']))
    worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'completed'


@pytest.mark.parametrize('damage', ['foreign-file', 'symlink', 'wrong-instance', 'changed-after-auth'])
def test_untrusted_archive_refuses_all_deletion_and_preserves_intent(worker, monkeypatch, damage):
    backup_id = pair(worker, monkeypatch); directory = worker.backup_dir / backup_id
    if damage == 'foreign-file': atomic_write(directory / 'foreign', b'preserve')
    elif damage == 'symlink':
        (directory / 'payload.tar.age').unlink(); (directory / 'payload.tar.age').symlink_to(worker.state_dir / 'installation.json')
    else:
        old = retention.backup_archive.read
        def tamper(path, *args):
            value = old(path, *args)
            if damage == 'wrong-instance': value['metadata']['instance_id'] = uid()
            elif path.parent == worker.recovery_dir: atomic_write(directory / 'payload.tar.age', b'changed')
            return value
        monkeypatch.setattr(retention.backup_archive, 'read', tamper)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    assert directory.exists() and (worker.recovery_dir / backup_id).exists()


def test_live_request_authority_is_checked_without_restart(worker):
    worker.jobs = [finished()]; worker.save(); selected = request(worker); worker.submit(selected)
    with sqlite3.connect(worker.retention.store.path) as db: db.execute('DELETE FROM tombstones')
    with pytest.raises(InstallError, match='authority is missing'):
        worker.submit(dict(action='backup', request_id=selected['job_ids'][0], allow_downtime=True))


def test_missing_captured_archives_do_not_authorize_clearing_capture_history(worker):
    worker.jobs = [dict(finished('backup'), state='captured')]; worker.save()
    value = worker.retention.status()
    assert value['capacity']['backup_used'] == 0 and value['jobs'][0]['retire_allowed'] is False
    with pytest.raises(RetentionConflict): worker.submit(request(worker))


def test_unowned_physical_archive_has_nullable_timestamp_and_no_delete_authority(worker):
    (worker.backup_dir / uid()).mkdir(mode=0o700)
    row = worker.retention.status()['backups'][0]
    assert row['created_at'] is None and row['delete_allowed'] is False


@pytest.mark.parametrize('phase', ['rotated', 'mutating'])
def test_terminal_rotation_pair_is_deletable_without_capture_row_but_unfinished_generation_is_not(worker, monkeypatch, phase):
    backup_id = pair(worker, monkeypatch)
    row = dict(finished('rotate'), state='rotated', family='management-tls'); row.pop('backup_id')
    worker.jobs = [row]; worker.save()
    directory = worker.state_dir / 'credential-operations' / row['id']; directory.mkdir(parents=True, mode=0o700)
    proof = {'operation_id': row['id'], 'kind': row['family'], 'phase': phase, 'backup_id': backup_id, 'abandoned_backup_ids': []}
    atomic_write(directory / 'record.json', json.dumps(proof).encode())
    original = (directory / 'record.json').read_bytes()
    value = worker.retention.status()
    assert value['jobs'][0]['retire_allowed'] is False
    assert value['backups'][0]['delete_allowed'] is (phase == 'rotated')
    selected = delete_request(worker, backup_id)
    if phase != 'rotated':
        with pytest.raises(RetentionConflict): worker.submit(selected)
    else:
        worker.submit(selected); worker.thread.join(3)
        assert worker.retention.store.operation(selected['request_id'])['state'] == 'completed'
        assert worker.jobs == []
    assert (directory / 'record.json').read_bytes() == original


def test_missing_inner_backup_set_id_refuses_without_removing_files(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch); old = retention.backup_archive.read
    def missing(path, *args):
        value = old(path, *args); value['metadata'].pop('backup_set_id'); return value
    monkeypatch.setattr(retention.backup_archive, 'read', missing)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    assert all(set(item.name for item in (root / backup_id).iterdir()) == set(retention.FILES)
               for root in (worker.backup_dir, worker.recovery_dir))


@pytest.mark.parametrize('survivors', [('recovery',), ('data',), ('data', 'recovery')])
def test_failed_capture_authenticates_each_survivor_and_retires_only_after_delete(worker, monkeypatch, survivors):
    backup_id = pair(worker, monkeypatch)
    worker.jobs[0]['state'] = 'failed'; worker.save()
    for name, root in (('data', worker.backup_dir), ('recovery', worker.recovery_dir)):
        if name not in survivors:
            for path in (root / backup_id).iterdir(): path.unlink()
            (root / backup_id).rmdir()
    status = worker.retention.status()
    assert status['capacity']['backup_used'] == 1
    assert status['jobs'][0]['retire_allowed'] is False
    assert status['backups'][0]['delete_allowed'] is True
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'completed' and result['partial_capture'] is True
    assert [value is not None for value in result['pair']] == [name in survivors for name in ('data', 'recovery')]
    assert worker.retention.status()['capacity']['backup_used'] == 0
    assert worker.jobs == []


@pytest.mark.parametrize('unsafe', ['captured-missing', 'recovery-required', 'restart-required', 'stopping', 'unowned', 'malformed'])
def test_partial_capture_cleanup_never_admits_unsafe_or_unowned_survivors(worker, monkeypatch, unsafe):
    backup_id = pair(worker, monkeypatch)
    worker.jobs[0]['state'] = 'failed'
    for path in (worker.backup_dir / backup_id).iterdir(): path.unlink()
    (worker.backup_dir / backup_id).rmdir()
    if unsafe == 'captured-missing': worker.jobs[0]['state'] = 'captured'
    elif unsafe == 'recovery-required': worker.jobs[0]['state'] = 'recovery-required'
    elif unsafe == 'unowned': worker.jobs = []
    elif unsafe == 'malformed': (worker.recovery_dir / backup_id / 'manifest.json.sig').unlink()
    else:
        atomic_write(worker.state_dir / 'backup-operation.json', json.dumps({
            'state': 'stopping' if unsafe == 'stopping' else 'failed',
            'restart_required': ['server'] if unsafe == 'restart-required' else []}).encode())
    worker.save()
    contents = {p.name: p.read_bytes() for p in (worker.recovery_dir / backup_id).iterdir()}
    selected = delete_request(worker, backup_id)
    if unsafe == 'malformed':
        worker.submit(selected); worker.thread.join(3)
        assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    else:
        assert worker.retention.status()['backups'][0]['delete_allowed'] is False
        with pytest.raises(RetentionConflict): worker.submit(selected)
        assert worker.retention.store.operation(selected['request_id']) is None
    assert {p.name: p.read_bytes() for p in (worker.recovery_dir / backup_id).iterdir()} == contents


def test_failed_capture_absent_side_rechecked_before_any_unlink_and_on_resume(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch)
    worker.jobs[0]['state'] = 'failed'; worker.save()
    absent = worker.recovery_dir / backup_id
    for path in absent.iterdir(): path.unlink()
    absent.rmdir()
    remove = worker.retention._remove_pair
    calls = []
    def substituted(record):
        calls.append(True)
        if len(calls) == 1:
            absent.mkdir(mode=0o700); atomic_write(absent / 'foreign-sentinel', b'preserved')
        return remove(record)
    monkeypatch.setattr(worker.retention, '_remove_pair', substituted)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'recovery-required' and result['pair'][1] is None
    assert result['removing'] == result['removed'] == []
    worker.submit(dict(selected, action='resume-delete', expected_revision=worker.retention.status()['revision']))
    worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    assert (absent / 'foreign-sentinel').read_bytes() == b'preserved'
    assert {p.name for p in (worker.backup_dir / backup_id).iterdir()} == set(retention.FILES)


def test_one_sided_delete_interruption_resumes_only_exact_intent(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch)
    worker.jobs[0]['state'] = 'failed'; worker.save()
    for path in (worker.backup_dir / backup_id).iterdir(): path.unlink()
    (worker.backup_dir / backup_id).rmdir()
    original = retention.os.unlink; calls = []
    def interrupted(path, *args, **kwargs):
        if path in retention.FILES:
            calls.append(path)
            if len(calls) == 2: raise OSError('injected interruption')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(retention.os, 'unlink', interrupted)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'recovery-required' and result['pair'][0] is None
    assert result['removed'] == ['1:manifest.json']
    worker.submit(dict(selected, action='resume-delete', expected_revision=worker.retention.status()['revision']))
    worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'completed'
    assert worker.jobs == [] and worker.retention.status()['capacity']['backup_used'] == 0


@pytest.mark.parametrize('partial', [False, True])
def test_archive_reappearing_after_last_rmdir_never_completes_or_retires_owner(worker, monkeypatch, partial):
    backup_id = pair(worker, monkeypatch)
    data = worker.backup_dir / backup_id
    if partial:
        worker.jobs[0]['state'] = 'failed'; worker.save()
        for path in data.iterdir(): path.unlink()
        data.rmdir()
    original = retention.os.rmdir; injected = []
    def changed(path, *args, **kwargs):
        selected = (path == backup_id and kwargs.get('dir_fd') is not None
            and Path(os.readlink('/proc/self/fd/' + str(kwargs['dir_fd']))) == worker.recovery_dir)
        result = original(path, *args, **kwargs)
        if selected:
            data.mkdir(mode=0o700); atomic_write(data / 'foreign-sentinel', b'keep')
            injected.append(True)
        return result
    monkeypatch.setattr(retention.os, 'rmdir', changed)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert injected == [True]
    result = worker.retention.store.operation(selected['request_id'])
    assert result['state'] == 'recovery-required'
    assert len(worker.jobs) == 2 and not worker.retention.store.retired(worker.jobs[0]['id'])
    assert (data / 'foreign-sentinel').read_bytes() == b'keep'


def test_final_directory_removal_is_fd_relative_to_exact_parent(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch); original = retention.os.rmdir; seen = []
    def checked(path, *args, **kwargs):
        if path == backup_id:
            parent = kwargs.get('dir_fd'); assert type(parent) is int
            assert Path(os.readlink('/proc/self/fd/' + str(parent))) in (worker.backup_dir, worker.recovery_dir)
            seen.append(parent)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(retention.os, 'rmdir', checked)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'completed' and len(seen) == 2


def test_actual_excess_backup_count_stays_visible_and_blocks_new_rotation(worker):
    worker.identity = worker.state_dir / 'not-opened-in-refusal'
    for _ in range(21): (worker.backup_dir / uid()).mkdir(mode=0o700)
    assert worker.retention.status()['capacity']['backup_used'] == 21
    with pytest.raises(RetentionConflict, match='Saved backup limit'):
        worker.submit(dict(action='rotate', request_id=uid(), family='management-tls', allow_downtime=True))
    assert worker.jobs == []


def test_decryption_temporary_workspace_never_becomes_a_saved_archive(worker, monkeypatch):
    backup_id = pair(worker, monkeypatch); original = retention.backup_archive.read; observed = []
    def decrypt(path, *args):
        temporary = path.parent / '.iris-restore-product-unit'; temporary.mkdir(mode=0o700)
        try:
            observed.append(worker.status()['retention']['busy'])
            return original(path, *args)
        finally:
            temporary.rmdir()
    monkeypatch.setattr(retention.backup_archive, 'read', decrypt)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert observed == [True, True] and worker.retention.store.operation(selected['request_id'])['state'] == 'completed'
    (worker.backup_dir / '.iris-restore-orphan-unit').mkdir(mode=0o700)
    status = worker.status()['retention']
    assert status['inventory_available'] is False and status['capacity']['backup_used'] is None
    with pytest.raises(RetentionConflict): worker.retention.backup_ids()


def test_substituted_parent_does_not_redirect_fd_relative_directory_removal(worker, monkeypatch, tmp_path):
    backup_id = pair(worker, monkeypatch); original = retention.os.rmdir; swapped = []
    old_parent = worker.backup_dir.with_name('data-preserved-inode')
    sentinel = tmp_path / 'foreign'; sentinel.mkdir(mode=0o700)
    (sentinel / backup_id).mkdir(mode=0o700)
    (sentinel / backup_id / 'do-not-remove').write_bytes(b'foreign')
    def replace_parent(path, *args, **kwargs):
        if path == backup_id and not swapped:
            worker.backup_dir.rename(old_parent)
            worker.backup_dir.symlink_to(sentinel, target_is_directory=True)
            swapped.append(True)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(retention.os, 'rmdir', replace_parent)
    selected = delete_request(worker, backup_id); worker.submit(selected); worker.thread.join(3)
    assert swapped and (sentinel / backup_id / 'do-not-remove').read_bytes() == b'foreign'
    assert not (old_parent / backup_id).exists()
    assert worker.retention.store.operation(selected['request_id'])['state'] == 'recovery-required'
    assert (worker.recovery_dir / backup_id).exists()


def test_sqlite_history_handles_literal_uri_metacharacters(tmp_path):
    directory = tmp_path / 'state?#%25'; directory.mkdir(mode=0o700)
    installation(directory)
    store = Store(directory)
    assert store.pending() == [] and Store(directory).database_id == store.database_id


def test_existing_installation_first_upgrade_preserves_jobs_and_pins_store(tmp_path):
    for name in ('state', 'data', 'recovery'): (tmp_path / name).mkdir(mode=0o700)
    installation(tmp_path / 'state')
    jobs = [finished()]
    atomic_write(tmp_path / 'state/lifecycle-jobs.json', json.dumps(jobs).encode())
    worker = Worker(*(tmp_path / name for name in ('state', 'data', 'recovery')))
    assert worker.jobs == jobs
    anchor = json.loads((worker.state_dir / 'installation.json').read_bytes())['lifecycle_history']
    assert anchor == {'schema': 1, 'database_id': worker.retention.store.database_id}


@pytest.mark.parametrize('point', ['before-database', 'after-database'])
def test_initialization_interruption_cannot_reset_independent_commitment(tmp_path, monkeypatch, point):
    directory = tmp_path / 'state'; directory.mkdir(mode=0o700); installation(directory)
    original = Store._initialize
    def interrupted(self, database_id):
        if point == 'after-database': original(self, database_id)
        raise OSError('interrupted initialization')
    monkeypatch.setattr(Store, '_initialize', interrupted)
    with pytest.raises(OSError): Store(directory)
    anchor = json.loads((directory / 'installation.json').read_bytes())['lifecycle_history']
    monkeypatch.setattr(Store, '_initialize', original)
    if point == 'before-database':
        with pytest.raises(InstallError, match='authority is missing'): Store(directory)
    else:
        assert Store(directory).database_id == anchor['database_id']
    assert json.loads((directory / 'installation.json').read_bytes())['lifecycle_history'] == anchor


@pytest.mark.parametrize('damage', ['tombstone-id', 'operation-id', 'operation-state', 'trigger'])
def test_hot_generation_changes_cannot_hide_retired_or_pending_authority(worker, damage):
    worker.jobs = [finished()]; worker.save(); selected = request(worker); worker.submit(selected)
    store = worker.retention.store
    assert store.retired(selected['job_ids'][0])
    assert store.operation(selected['request_id'])['state'] == 'completed'
    with sqlite3.connect(store.path) as db:
        if damage == 'tombstone-id': db.execute('UPDATE tombstones SET request_id=?', (uid(),))
        elif damage == 'operation-id': db.execute('UPDATE operations SET request_id=?', (uid(),))
        elif damage == 'operation-state': db.execute("UPDATE operations SET state='running'")
        else: db.execute('CREATE TRIGGER injected AFTER INSERT ON tombstones BEGIN DELETE FROM operations; END')
    with pytest.raises(InstallError): store.retired(selected['job_ids'][0])


def test_unchanged_status_reuses_only_verified_generation(worker, monkeypatch):
    store = worker.retention.store
    original = store._verify; calls = []
    monkeypatch.setattr(store, '_verify', lambda db: calls.append(True) or original(db))
    for _ in range(5): assert store.operation() is None
    assert calls == []
    worker.jobs = [finished()]; worker.save(); worker.submit(request(worker))
    assert calls
