# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
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


def test_worker_redacts_exceptions_and_blocks_interrupted_recovery(worker, monkeypatch):
    def fail(args):
        raise RuntimeError('PRIVATE KEY sentinel')
    monkeypatch.setattr(worker_module.backup, 'create', fail)
    worker.submit({'action': 'backup', 'allow_downtime': True, 'request_id': str(uuid.uuid4())})
    worker.thread.join(3)
    assert 'sentinel' not in worker.record.read_text()
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
            lifecycle_client.call({'action': 'verify', 'backup_id': '0' * 36, 'request_id': str(uuid.uuid4())})
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
