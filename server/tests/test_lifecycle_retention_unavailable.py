# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual SDK restart/status regression; no deployment or custody adoption."""

import copy
import json
from pathlib import Path
import uuid

import pytest
from jsonschema import Draft202012Validator

from test_lifecycle_retention import worker, finished, managed_storage, restart
from iris_installer import backup_capture, lifecycle_retention, restore, upgrade_state
from iris_installer.lifecycle_history import RetentionConflict
from iris_installer.state import InstallError, atomic_write
import openapi_contract


def uid():
    return str(uuid.uuid4())


@pytest.mark.parametrize('action,state', [('restore', 'recovery-required'), ('verify', 'failed'), ('extract', 'failed')])
def test_restarted_read_preserves_unknown_workspace_and_exposes_honest_status(worker, action, state):
    original = finished(action, restore_authority_started=False)
    original['state'] = 'running'; original.pop('finished_at')
    worker.jobs = [original]; worker.save()
    stage = worker.backup_dir / '.iris-restore-local-control'; stage.mkdir(mode=0o700)
    partial = stage / 'unverified'; atomic_write(partial, b'private incomplete local test output')
    before = {str(path): (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) for path in stage.iterdir()}
    worker = restart(worker)
    observed = worker.status()
    assert observed['jobs'][0]['id'] == original['id'] and observed['jobs'][0]['state'] == state
    status = observed['retention']
    assert status['inventory_available'] is False and status['storage_problem'] == lifecycle_retention.STORAGE_PROBLEM
    assert status['capacity']['backup_used'] is None and status['capacity']['protected_upgrade_used'] is None
    assert status['backups'] == [] and status['protected_upgrade_backups'] == []
    assert not any(row['retire_allowed'] for row in status['jobs'])
    assert status['recoverable_job_id'] == (original['id'] if action == 'restore' else None)
    assert status['busy'] is (action == 'restore')
    assert 'restore_authority_started' not in observed['jobs'][0]
    assert {str(path): (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) for path in stage.iterdir()} == before


def test_no_prefix_adoption_counts_or_path_disclosure_and_mutations_remain_strict(worker, monkeypatch):
    worker.jobs = [finished()]; worker.save()
    complete = worker.status()['retention']; foreign = worker.backup_dir / 'private-name-canary'
    foreign.mkdir(mode=0o700); atomic_write(foreign / 'private-data', b'not an archive')
    degraded = worker.status()['retention']
    assert degraded['revision'] != complete['revision']
    assert 'canary' not in json.dumps(degraded) and 'private-data' not in json.dumps(degraded)
    with pytest.raises(lifecycle_retention.InventoryUnavailable): worker.retention.backup_ids()
    for action in ('retire-history', 'delete-backup', 'resume-delete'):
        request = {'action': action, 'request_id': uid(), 'expected_revision': degraded['revision']}
        request.update({'job_ids': [worker.jobs[0]['id']]} if action == 'retire-history' else
                       {'backup_id': worker.jobs[0]['backup_id'], 'confirm_delete': True})
        with pytest.raises(lifecycle_retention.InventoryUnavailable): worker.submit(request)
        assert worker.retention.store.operation(request['request_id']) is None
    with pytest.raises(lifecycle_retention.InventoryUnavailable):
        worker.submit({'action': 'backup', 'request_id': uid(), 'allow_downtime': True})
    worker.identity = worker.state_dir / 'local-test-key'
    monkeypatch.setattr(restore, 'custody', lambda *args: None)
    with pytest.raises(lifecycle_retention.InventoryUnavailable):
        worker.submit({'action': 'restore', 'request_id': uid(), 'backup_id': worker.jobs[0]['backup_id'],
                       'allow_downtime': True, 'confirm_restore': True})
    assert len(worker.jobs) == 1 and (foreign / 'private-data').read_bytes() == b'not an archive'


def test_child_appearing_between_strict_scan_and_status_never_admits_retirement(worker, monkeypatch):
    worker.jobs = [finished()]; worker.save()
    foreign = worker.backup_dir / 'unknown-child'; foreign.mkdir(mode=0o700)
    previous = worker.status()['retention']; foreign.rmdir()
    original = worker.retention.backup_inventory
    calls = []
    def appeared():
        observed = original(); calls.append(True)
        if len(calls) == 1: foreign.mkdir(mode=0o700)
        return observed
    monkeypatch.setattr(worker.retention, 'backup_inventory', appeared)
    selected = {'action': 'retire-history', 'request_id': uid(), 'job_ids': [worker.jobs[0]['id']],
                'expected_revision': previous['revision']}
    with pytest.raises(RetentionConflict, match='inventory is unavailable'): worker.submit(selected)
    assert worker.retention.store.operation(selected['request_id']) is None
    assert len(worker.jobs) == 1 and foreign.is_dir()


@pytest.mark.parametrize('action', ['verify', 'extract'])
def test_fresh_authenticated_read_admission_does_not_require_complete_archive_inventory(worker, monkeypatch, action):
    # Only admission is modeled: actual read/authentication remains the existing
    # product perform() path and is not replaced or claimed successful here.
    capture = finished('backup'); capture['state'] = 'captured'; worker.jobs = [capture]; worker.save()
    worker.identity = worker.state_dir / 'local-test-key'
    worker.extract_dir = worker.state_dir / 'isolated-restores'; worker.extract_dir.mkdir(mode=0o700)
    retained = worker.backup_dir / '.iris-restore-local-control'; retained.mkdir(mode=0o700)
    monkeypatch.setattr('threading.Thread.start', lambda self: None)
    request = {'action': action, 'request_id': uid(), 'backup_id': capture['backup_id']}
    assert worker.submit(request) == {'job_id': request['request_id']}
    assert worker.jobs[-1]['state'] == 'running' and worker.jobs[-1]['action'] == action
    assert retained.is_dir()


def test_same_id_restore_recovery_admission_keeps_original_guard_and_false_handoff(worker, monkeypatch):
    original = finished('restore', restore_authority_started=False, proof=None)
    original['state'] = 'running'; worker.jobs = [original]; worker.save()
    retained = worker.backup_dir / '.iris-restore-local-control'; retained.mkdir(mode=0o700)
    worker = restart(worker); worker.identity = worker.state_dir / 'local-test-key'
    monkeypatch.setattr(restore, 'custody', lambda *args: None)
    monkeypatch.setattr('threading.Thread.start', lambda self: None)
    request = {'action': 'recover-restore', 'request_id': original['id'], 'backup_id': original['backup_id'],
               'allow_downtime': True, 'confirm_restore': True}
    assert worker.submit(request) == {'job_id': original['id']}
    assert len(worker.jobs) == 1 and worker.jobs[0]['id'] == original['id']
    assert worker.jobs[0]['state'] == 'running' and worker.jobs[0]['restore_authority_started'] is False
    assert retained.is_dir() and not (worker.state_dir / 'restore-operations' / original['id']).exists()


def test_degraded_status_never_hides_damaged_storage_or_protected_operation_authority(worker, monkeypatch):
    managed_storage(worker)
    unknown = worker.backup_dir / 'unknown-child'; unknown.mkdir(mode=0o700)
    original_iterdir = Path.iterdir
    def ordered(path):
        if path == worker.backup_dir:
            return iter([unknown, *[child for child in original_iterdir(path) if child != unknown]])
        return original_iterdir(path)
    monkeypatch.setattr(Path, 'iterdir', ordered)
    atomic_write(worker.backup_dir / '.iris-storage.json', json.dumps({'instance_id': uid()}).encode())
    with pytest.raises(InstallError, match='custody'): worker.status()
    (worker.backup_dir / '.iris-storage.json').unlink()
    (worker.recovery_dir / '.iris-storage.json').unlink()
    monkeypatch.setattr(upgrade_state, 'protected_backups', lambda *args: (_ for _ in ()).throw(InstallError('Damaged operation authority')))
    with pytest.raises(InstallError, match='Damaged operation'): worker.status()


@pytest.mark.parametrize('family', ['upgrade', 'capture'])
def test_unknown_children_never_skip_final_protected_authority_recheck(worker, monkeypatch, family):
    (worker.backup_dir / 'unknown-child').mkdir(mode=0o700)
    calls = []
    if family == 'upgrade':
        def observed(*args):
            calls.append(True); return ({}, len(calls) > 1)
        monkeypatch.setattr(upgrade_state, 'protected_backups', observed)
    else:
        def observed(*args):
            calls.append(True); return {} if len(calls) == 1 else {'changed-stage': {}}
        monkeypatch.setattr(backup_capture, 'protected_stages', observed)
    with pytest.raises(InstallError, match='custody changed'): worker.status()
    assert len(calls) == 2


def test_unavailable_inventory_never_hides_job_history_errors_or_drops_upgrade_fence(worker, monkeypatch):
    (worker.backup_dir / 'unknown-child').mkdir(mode=0o700)
    monkeypatch.setattr(upgrade_state, 'protected_backups', lambda *args: ({}, True))
    row = finished('restore', restore_authority_started=False); row['state'] = 'recovery-required'
    worker.jobs = [row]
    assert worker.status()['retention']['recoverable_job_id'] is None
    row['state'] = 'failed'; path = worker.state_dir / 'restore-operations' / row['id']
    path.mkdir(parents=True, mode=0o700); atomic_write(path / 'record.json', b'not valid JSON')
    with pytest.raises(ValueError): worker.status()


def test_declared_status_schema_allows_only_explicit_unavailable_counts(worker):
    document = openapi_contract.build_document()
    schema = document['paths']['/api/v1/settings/backups']['get']['responses']['200']['content']['application/json']['schema']
    validator = Draft202012Validator(schema)
    complete = worker.status(); validator.validate(complete)
    (worker.backup_dir / 'unknown-child').mkdir(mode=0o700)
    degraded = worker.status(); validator.validate(degraded)
    for patch in ({'inventory_available': True}, {'storage_problem': None}, {'backups': [{'backup_id': uid()}]},
                  {'capacity': dict(degraded['retention']['capacity'], backup_used=0)}):
        wrong = copy.deepcopy(degraded); wrong['retention'].update(patch)
        assert list(validator.iter_errors(wrong))
    wrong = copy.deepcopy(complete); wrong['retention']['capacity']['backup_used'] = None
    assert list(validator.iter_errors(wrong))
