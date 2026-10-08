# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer CLI service handoff and explicit, bounded deployment restore controls."""

from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import cli, deploy, managed_worker, maintenance
from iris_installer.state import InstallError
import lifecycle_client


@pytest.mark.parametrize('result', [20, 21, 22, 1])
def test_resume_provisions_service_only_after_deployment_ready(monkeypatch, tmp_path, result):
    calls = []
    monkeypatch.setattr(deploy, 'resume', lambda args: result)
    monkeypatch.setattr(managed_worker, 'remember_options', lambda args: calls.append('remember'))
    monkeypatch.setattr(managed_worker, 'setup', lambda args: calls.append('setup'))
    assert cli.main(['resume', '--state-dir', str(tmp_path)]) == result
    assert calls == ['remember'] + (['setup'] if result in (21, 22) else [])


def test_service_setup_failure_is_not_success(monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, 'resume', lambda args: 21)
    monkeypatch.setattr(managed_worker, 'remember_options', lambda args: None)
    def fail(args):
        raise InstallError('Worker readiness failed')
    monkeypatch.setattr(managed_worker, 'setup', fail)
    assert cli.main(['resume', '--state-dir', str(tmp_path)]) == 1


@pytest.mark.parametrize('command,handler', [('worker-setup', 'setup'), ('worker-status', 'status'),
                                            ('worker-service', 'action'), ('managed-worker', 'serve_managed')])
def test_managed_cli_dispatch(monkeypatch, tmp_path, command, handler):
    seen = []
    monkeypatch.setattr(managed_worker, handler, lambda args: seen.append(args) or 0)
    arguments = [command, '--state-dir', str(tmp_path)]
    if command == 'worker-service':
        arguments += ['--action', 'restart']
    assert cli.main(arguments) == 0
    assert seen[0].state_dir == tmp_path


def test_restore_selection_reuses_interrupted_job_identity():
    identifier, backup = str(uuid.uuid4()), str(uuid.uuid4())
    job = {'id': identifier, 'backup_id': backup, 'action': 'restore', 'state': 'recovery-required'}
    assert maintenance.recovery_request(job) == {
        'action': 'recover-restore', 'request_id': identifier, 'backup_id': backup,
        'allow_downtime': True, 'confirm_restore': True}
    job.update(action='backup', state='captured')
    request = maintenance.restore_request(job)
    assert request['request_id'] != identifier
    assert request['action'] == 'restore' and request['backup_id'] == backup


@pytest.mark.parametrize('patch', [{'state': 'failed'}, {'backup_id': '../other'},
                                  {'backup_id': '0' * 36}, {'action': 'extract'}])
def test_restore_selection_refuses_unqualified_backups(patch):
    job = dict({'action': 'backup', 'state': 'captured', 'backup_id': str(uuid.uuid4())}, **patch)
    with pytest.raises(InstallError):
        maintenance.restore_request(job)


@pytest.mark.parametrize('action', ['restore', 'recover-restore'])
@pytest.mark.parametrize('patch', [{'allow_downtime': 1}, {'confirm_restore': False},
    {'confirm_restore': 1}, {'backup_id': '0' * 36}, {'request_id': '../other'}, {'path': '/etc'}])
def test_restore_rpc_rejects_unconfirmed_or_unbounded_request(action, patch):
    request = dict({'action': action, 'request_id': str(uuid.uuid4()), 'backup_id': str(uuid.uuid4()),
                    'allow_downtime': True, 'confirm_restore': True}, **patch)
    with pytest.raises(ValueError):
        lifecycle_client.call(request)


@pytest.mark.parametrize('action', ['restore', 'recover-restore'])
def test_host_restore_request_uses_fixed_schema(tmp_path, monkeypatch, action):
    client = maintenance.MaintenanceClient(tmp_path)
    request = {'action': action, 'request_id': str(uuid.uuid4()), 'backup_id': str(uuid.uuid4()),
               'allow_downtime': True, 'confirm_restore': True}
    for field in ('allow_downtime', 'confirm_restore'):
        with pytest.raises(InstallError, match='Unsupported deployment restore'):
            client.call(dict(request, **{field: 1}))
