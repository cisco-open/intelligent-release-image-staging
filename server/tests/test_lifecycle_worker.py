# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import lifecycle_worker as worker_module
from iris_installer.state import InstallError
import lifecycle_client
from test_gui_server import _serve_full, _auth, _req
from test_api_split import policy_tiers


@pytest.fixture
def worker(tmp_path):
    for name in ('state', 'backups', 'recovery', 'extract'):
        (tmp_path / name).mkdir(mode=0o700)
    return worker_module.Worker(tmp_path / 'state', tmp_path / 'backups', tmp_path / 'recovery')


def test_restore_requires_explicit_confirmation_and_pinned_custody(worker, monkeypatch):
    from iris_installer import restore
    request = dict(action='restore', request_id=str(uuid.uuid4()), backup_id=str(uuid.uuid4()),
                   allow_downtime=True, confirm_restore=True)
    for field in ('allow_downtime', 'confirm_restore'):
        with pytest.raises(InstallError, match='Confirm downtime'):
            worker.submit(dict(request, **{field: False}))
    with pytest.raises(InstallError, match='independent recovery'):
        worker.submit(request)
    worker.identity = worker.state_dir / 'independent'
    worker.identity_history = [worker.identity]
    def missing(*args):
        raise InstallError('independent signer required')
    monkeypatch.setattr(restore, 'custody', missing)
    with pytest.raises(InstallError, match='independent signer'):
        worker.submit(request)
    assert worker.jobs == []


def test_worker_restore_observes_duplicate_and_requires_explicit_recovery(worker, monkeypatch):
    from iris_installer import restore
    worker.identity = worker.state_dir / 'independent'
    worker.identity_history = [worker.identity]
    monkeypatch.setattr(restore, 'custody', lambda *args: worker.state_dir / 'trusted-signer')
    backup_id, operation = str(uuid.uuid4()), str(uuid.uuid4())
    worker.jobs.append(dict(id=str(uuid.uuid4()), action='backup', backup_id=backup_id, state='captured'))
    calls = []
    def perform(*args, **kwargs):
        calls.append(kwargs)
        return {'state': 'restored', 'proof': {'management_https': 'verified'}}
    monkeypatch.setattr(restore, 'restore', perform)
    request = dict(action='restore', request_id=operation, backup_id=backup_id,
                   allow_downtime=True, confirm_restore=True)
    assert worker.submit(request) == {'job_id': operation}
    worker.thread.join(3)
    assert worker.jobs[-1]['state'] == 'restored'
    assert worker.submit(request) == {'job_id': operation}
    assert len(calls) == 1
    with pytest.raises(InstallError, match='interrupted'):
        worker.submit(dict(request, action='recover-restore'))
    worker.jobs[-1]['state'] = 'recovery-required'
    worker.submit(dict(request, action='recover-restore'))
    worker.thread.join(3)
    assert calls[-1]['recovery'] is True
    assert worker.jobs[-1]['state'] == 'restored'


@pytest.mark.parametrize('handoff', [False, True, None])
def test_restore_worker_restart_obeys_private_durable_handoff(worker, monkeypatch, handoff):
    from iris_installer import restore
    worker.identity = worker.state_dir / 'independent'
    worker.identity_history = [worker.identity]
    monkeypatch.setattr(restore, 'custody', lambda *args: worker.state_dir / 'trusted-signer')
    operation, backup_id = str(uuid.uuid4()), str(uuid.uuid4())
    job = dict(id=operation, action='restore', backup_id=backup_id, state='running')
    if handoff is not None:
        job['restore_authority_started'] = handoff
    worker.jobs = [job]
    worker.save()
    restarted = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir,
                                      identity=worker.identity)
    assert restarted.jobs[0]['state'] == 'recovery-required'
    assert 'restore_authority_started' not in restarted.status()['jobs'][0]
    def backend(*args, **kwargs):
        assert kwargs['recovery'] is True
        assert kwargs['pre_authority_recovery'] is (handoff is False)
        kwargs['on_authority_started']()
        assert json.loads(restarted.record.read_bytes())[0]['restore_authority_started'] is True
        return {'state': 'restored', 'proof': {}}
    monkeypatch.setattr(restore, 'restore', backend)
    restarted.submit(dict(action='recover-restore', request_id=operation, backup_id=backup_id,
                          allow_downtime=True, confirm_restore=True))
    restarted.thread.join(3)
    assert restarted.jobs[0]['state'] == 'restored'
    assert 'restore_authority_started' not in restarted.status()['jobs'][0]


def test_failed_recovery_of_lost_started_authority_keeps_lifecycle_fenced(worker, monkeypatch):
    from iris_installer import restore
    worker.identity = worker.state_dir / 'independent'
    worker.identity_history = [worker.identity]
    monkeypatch.setattr(restore, 'custody', lambda *args: worker.state_dir / 'trusted-signer')
    operation, backup_id = str(uuid.uuid4()), str(uuid.uuid4())
    worker.jobs = [dict(id=operation, action='restore', backup_id=backup_id,
                       state='recovery-required', restore_authority_started=True)]
    def backend(*args, **kwargs):
        assert kwargs['pre_authority_recovery'] is False
        raise InstallError('Restore authority is missing')
    monkeypatch.setattr(restore, 'restore', backend)
    worker.submit(dict(action='recover-restore', request_id=operation, backup_id=backup_id,
                       allow_downtime=True, confirm_restore=True))
    worker.thread.join(3)
    assert worker.jobs[0]['state'] == 'recovery-required'
    with pytest.raises(InstallError, match='maintenance operation is active'):
        worker.submit(dict(action='backup', request_id=str(uuid.uuid4()), allow_downtime=True))


@pytest.mark.parametrize('state', ['running', 'recovery-required'])
def test_management_sync_refuses_unfinished_lifecycle(worker, state):
    worker.jobs = [{'state': state}]
    with pytest.raises(InstallError, match='active lifecycle'):
        worker.submit({'action': 'sync-management', 'request_id': str(uuid.uuid4())})


@pytest.mark.parametrize('bad', [None, 'wrong-id', 'extra', 'bad-hash', 'bool-count', 'zero-count'])
def test_management_sync_requires_exact_adapter_evidence(worker, monkeypatch, bad):
    from iris_installer import deploy
    from types import SimpleNamespace
    request_id = str(uuid.uuid4())
    expected = {'request_id': request_id, 'current_sha256': 'a' * 64, 'consumers_verified': 2}
    result = dict(expected)
    if bad == 'wrong-id':
        result['request_id'] = str(uuid.uuid4())
    elif bad == 'extra':
        result['private_token'] = 'must-not-be-returned'
    elif bad == 'bad-hash':
        result['current_sha256'] = 'invalid'
    elif bad == 'bool-count':
        result['consumers_verified'] = True
    elif bad == 'zero-count':
        result['consumers_verified'] = 0
    @contextmanager
    def locked(self):
        yield self
    monkeypatch.setattr(worker_module.Journal, 'locked', locked)
    monkeypatch.setattr(deploy, 'installation', lambda journal: SimpleNamespace(
        sync_management_operation=lambda operation: result if operation == request_id else None))
    request = {'action': 'sync-management', 'request_id': request_id}
    if bad is None:
        assert worker.submit(request) == expected
    else:
        with pytest.raises(InstallError, match='matching evidence'):
            worker.submit(request)
    assert worker.jobs == []


@pytest.mark.parametrize('extra', [{'path': '/tmp/token'}, {'token': 'not-accepted'}, {'host': 'elsewhere'}])
def test_management_sync_accepts_no_caller_selected_authority(worker, extra):
    with pytest.raises(InstallError, match='Invalid management'):
        worker.submit({'action': 'sync-management', 'request_id': str(uuid.uuid4()), **extra})


@pytest.mark.parametrize('payload', [None, [], {'action': 'exec'}, {'action': 'backup'},
    {'action': 'backup', 'allow_downtime': 1}, {'action': 'backup', 'allow_downtime': True, 'path': '/etc'},
    {'action': 'verify', 'backup_id': '../elsewhere'}])
def test_worker_refuses_arbitrary_requests_before_work(worker, payload):
    with pytest.raises(InstallError):
        worker.submit(payload)
    assert worker.status()['jobs'] == []


def test_worker_one_operation_and_durable_result(worker, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def capture(args):
        assert args.state_dir == worker.state_dir
        assert args.output.parent == worker.backup_dir
        assert args.recovery_output.parent == worker.recovery_dir
        entered.set()
        assert release.wait(3)
    monkeypatch.setattr(worker_module.backup, 'create', capture)
    try:
        payload = {'action': 'backup', 'allow_downtime': True, 'request_id': str(uuid.uuid4())}
        accepted = worker.submit(payload)
        assert entered.wait(3)
        assert worker.status()['jobs'][0]['id'] == accepted['job_id']
        assert worker.submit(payload) == accepted
        with pytest.raises(InstallError, match='active'):
            worker.submit(dict(payload, request_id=str(uuid.uuid4())))
    finally:
        release.set()
        worker.thread.join(3)
    assert worker.status()['jobs'][0]['state'] == 'captured'
    saved = json.loads(worker.record.read_text())
    assert saved == worker.status()['jobs']
    recovered = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir)
    assert recovered.submit(payload) == accepted
    assert len(recovered.jobs) == 1


def test_worker_redacts_exceptions_and_blocks_interrupted_recovery(worker, monkeypatch, capsys):
    def fail(args):
        raise RuntimeError('PRIVATE KEY sentinel')
    monkeypatch.setattr(worker_module.backup, 'create', fail)
    worker.submit({'action': 'backup', 'allow_downtime': True, 'request_id': str(uuid.uuid4())})
    worker.thread.join(3)
    assert 'sentinel' not in worker.record.read_text()
    diagnostic = capsys.readouterr().err
    assert 'RuntimeError' in diagnostic and 'sentinel' not in diagnostic
    assert worker.status()['jobs'][0]['state'] == 'failed'
    worker.jobs[0]['state'] = 'running'
    worker.save()
    recovered = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir)
    assert recovered.jobs[0]['state'] == 'recovery-required'
    with pytest.raises(InstallError, match='recovery'):
        recovered.submit({'action': 'backup', 'allow_downtime': True, 'request_id': str(uuid.uuid4())})


def test_real_unix_socket_client_and_peer_credentials(worker, tmp_path, monkeypatch):
    endpoint = tmp_path / 'control.sock'
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(endpoint))
    server = worker_module.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert lifecycle_client.status()['available']
        with pytest.raises(ValueError):
            lifecycle_client.call({'action': 'backup', 'allow_downtime': True, 'command': 'anything'})
        with pytest.raises(lifecycle_client.LifecycleUnavailable):
            lifecycle_client.call({'action': 'verify', 'backup_id': str(uuid.uuid4()), 'request_id': str(uuid.uuid4())})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert lifecycle_client.status()['available'] is False


def test_peer_uid_rejected(worker, tmp_path, monkeypatch):
    endpoint = tmp_path / 'denied.sock'
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(endpoint))
    server = worker_module.make_server(endpoint, worker, allowed_uids=())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert lifecycle_client.status()['available'] is False
        assert not worker.jobs
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_long_installation_path_binds_through_pinned_directory(worker, tmp_path, monkeypatch):
    directory = tmp_path / ('deep-installation-' * 8)
    directory.mkdir(mode=0o700)
    endpoint = directory / 'control.sock'
    assert len(os.fsencode(endpoint)) >= 108
    server = worker_module.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert endpoint.is_socket()
        monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', '/proc/self/fd/' + str(descriptor) + '/control.sock')
        assert lifecycle_client.status()['available'] is True
    finally:
        os.close(descriptor)
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_backups_http_requires_session_csrf_and_closed_request(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(tmp_path / 'absent.sock'))
    host, port, ctx, stop = _serve_full(tmp_path)
    try:
        path = '/api/settings/backups'
        assert _req(host, port, 'GET', path)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', path, body={'action': 'backup', 'allow_downtime': True}, headers={'Cookie': cookie})[0] == 403
        status, _, body = _req(host, port, 'GET', path, headers={'Cookie': cookie})
        assert status == 200 and json.loads(body)['available'] is False
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        for request in ({'action': 'status'}, {'action': 'backup', 'allow_downtime': True, 'path': '/etc'}):
            assert _req(host, port, 'POST', path, body=request, headers=headers)[0] == 400
    finally:
        stop()


def test_console_to_tls_management_to_unix_worker(worker, policy_tiers, tmp_path, monkeypatch):
    endpoint = tmp_path / 'maintenance.sock'
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(endpoint))
    monkeypatch.setattr(worker_module.backup, 'create', lambda args: 0)
    server = worker_module.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request, _fleet, _store = policy_tiers
    try:
        for tier in ('console', 'management'):
            assert request(tier, 'GET', '/settings/backups', authorized=False, match=False)[0] == 401
            status, headers, result = request(tier, 'GET', '/settings/backups', match=False)
            assert status == 200 and result['available']
        payload = {'action': 'backup', 'allow_downtime': True, 'request_id': str(uuid.uuid4())}
        result_ids = []
        for tier in ('console', 'management'):
            status, _, result = request(tier, 'POST', '/settings/backups', payload, match=False)
            assert status == 200
            result_ids.append(result['job_id'])
        worker.thread.join(3)
        assert result_ids == [payload['request_id']] * 2
        assert len(worker.jobs) == 1 and worker.jobs[0]['state'] == 'captured'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
