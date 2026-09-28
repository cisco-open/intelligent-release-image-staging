# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deployment-maintenance RPC authority and durable operation boundaries."""

import json
import sys
import subprocess
import threading
import uuid
from types import SimpleNamespace

import pytest

import lifecycle_client
from test_lifecycle_worker import worker, worker_module
from iris_installer.state import InstallError
from test_gui_server import _serve_full, _auth, _req


def payload(**extra):
    return {'action': 'rotate', 'family': 'age-identity', 'request_id': str(uuid.uuid4()),
            'allow_downtime': True, **extra}


def patch_credential_implementation(monkeypatch, rotate):
    import iris_installer
    implementation = SimpleNamespace(rotate=rotate)
    # Python's relative import may reuse the package attribute even after its
    # sys.modules entry is replaced. Patch both to remain suite-order neutral.
    monkeypatch.setitem(sys.modules, 'iris_installer.credential_maintenance', implementation)
    monkeypatch.setattr(iris_installer, 'credential_maintenance', implementation, raising=False)


@pytest.mark.parametrize('extra', [{'family': 'exec'}, {'family': []}, {'path': '/etc'},
    {'request_id': '../identity'}, {'allow_downtime': 1}, {'recovery_identity': 'secret'}])
def test_rotation_request_is_closed(worker, extra):
    worker.identity = worker.state_dir / 'recovery-key'
    with pytest.raises(InstallError):
        worker.submit(payload(**extra))
    assert worker.jobs == []


def test_rotation_requires_separate_recovery_access(worker):
    assert not worker.rotation_status()['can_rotate']
    with pytest.raises(InstallError, match='recovery'):
        worker.submit(payload())


def test_rotation_runs_once_and_hides_from_backup_history(worker, monkeypatch):
    worker.identity = worker.state_dir / 'recovery-key'
    entered, release = threading.Event(), threading.Event()
    calls = []
    def rotate(*args, **kwargs):
        calls.append((args, kwargs))
        entered.set()
        assert release.wait(3)
        return {'state': 'rotated', 'proof': {'served': True}}
    patch_credential_implementation(monkeypatch, rotate)
    request = payload()
    try:
        accepted = worker.submit(request)
        assert entered.wait(3)
        assert worker.submit(request) == accepted
        with pytest.raises(InstallError, match='active'):
            worker.submit(payload())
        with pytest.raises(InstallError, match='different'):
            worker.submit(dict(request, family='management-tls'))
    finally:
        release.set()
        worker.thread.join(3)
    assert len(calls) == 1
    assert calls[0][1]['recovery_identity'] == worker.identity
    assert worker.status()['jobs'] == []
    assert worker.rotation_status()['jobs'][0]['state'] == 'rotated'
    recovered = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir,
                                     identity=worker.identity)
    assert recovered.submit(request) == accepted
    assert len(calls) == 1


def test_failed_rotation_never_reports_success_or_leaks_exception(worker, monkeypatch, capsys):
    worker.identity = worker.state_dir / 'recovery-key'
    def fail(*args, **kwargs):
        intent = worker.state_dir / 'credential-operations' / kwargs['operation_id']
        intent.mkdir(parents=True)
        (intent / 'record.json').write_text('{}')
        raise RuntimeError('PRIVATE KEY secret sentinel')
    patch_credential_implementation(monkeypatch, fail)
    worker.submit(payload())
    worker.thread.join(3)
    assert 'sentinel' not in worker.record.read_text() + capsys.readouterr().err
    assert worker.jobs[0]['state'] == 'recovery-required'
    with pytest.raises(InstallError, match='recovery'):
        worker.submit(payload())


def test_rotation_api_auth_csrf_and_validation(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(tmp_path / 'absent.sock'))
    host, port, ctx, stop = _serve_full(tmp_path)
    endpoint = '/api/settings/deployment-rotation'
    try:
        assert _req(host, port, 'GET', endpoint)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', endpoint, body=payload(), headers={'Cookie': cookie})[0] == 403
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        status, _, raw = _req(host, port, 'GET', endpoint, headers=headers)
        assert status == 200 and not json.loads(raw)['can_rotate']
        assert _req(host, port, 'POST', endpoint, body=payload(path='/etc'), headers=headers)[0] == 400
        assert _req(host, port, 'POST', endpoint, body=payload(), headers=headers)[0] == 503
    finally:
        stop()


def test_absent_worker_is_not_a_capability(monkeypatch, tmp_path):
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(tmp_path / 'absent.sock'))
    assert lifecycle_client.rotation_status() == {
        'available': False, 'target': 'unavailable', 'can_rotate': False,
        'families': [], 'jobs': [],
        'note': 'Configure the deployment worker and independent recovery access before rotation.'}


@pytest.mark.parametrize('bad', ['duplicate-data', 'duplicate-identity', 'wrong-target'])
def test_backup_verification_requires_distinct_authenticated_roles(worker, monkeypatch, bad):
    worker.identity = worker.state_dir / 'recovery-key'
    worker.identity_history = [worker.identity]
    backup_id = str(uuid.uuid4())
    worker.jobs.append({'id': str(uuid.uuid4()), 'action': 'backup', 'backup_id': backup_id,
                        'state': 'captured', 'started_at': 1, 'detail': ''})
    def read(path, *args, **kwargs):
        scope = 'identity-recovery' if path.parent == worker.recovery_dir else 'managed-deployment-files'
        if bad == 'duplicate-data':
            scope = 'managed-deployment-files'
        if bad == 'duplicate-identity':
            scope = 'identity-recovery'
        return {'metadata': {'backup_set_id': backup_id, 'instance_id': 'fixture',
            'scope': scope, 'target': 'kubernetes' if bad == 'wrong-target' else 'single-docker'}}
    monkeypatch.setattr(worker_module.backup_archive, 'read', read)
    worker.submit({'action': 'verify', 'request_id': str(uuid.uuid4()), 'backup_id': backup_id})
    worker.thread.join(3)
    assert worker.jobs[-1]['state'] == 'failed'


def test_trust_status_custody_subprocess_failure_is_bounded_503(tmp_path, monkeypatch):
    import trust_rotation
    host, port, ctx, stop = _serve_full(tmp_path)
    try:
        cookie, csrf = _auth(host, port)
        monkeypatch.setattr(trust_rotation, 'status', lambda family: trust_rotation._view(None, family))
        def unavailable():
            raise subprocess.CalledProcessError(1, ['age'], stderr=b'PRIVATE TEST MARKER')
        monkeypatch.setattr(trust_rotation, 'drain_status', unavailable)
        status, _, raw = _req(host, port, 'GET', '/api/settings/trust-rotation', headers={'Cookie': cookie})
        assert status == 503
        assert 'PRIVATE TEST MARKER' not in raw.decode()
        assert json.loads(raw)['error'] == 'service unavailable'
    finally:
        stop()


def test_recovery_requires_original_operation_and_is_idempotent(worker, monkeypatch):
    worker.identity = worker.state_dir / 'recovery-key'
    original = payload()
    worker.jobs.append({'id': original['request_id'], 'action': 'rotate', 'family': original['family'],
                        'state': 'recovery-required', 'detail': '', 'proof': None})
    worker.save()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def rotate(*args, **kwargs):
        calls.append(kwargs)
        entered.set()
        assert release.wait(3)
        return {'state': 'rotated', 'proof': {'served': True}}
    patch_credential_implementation(monkeypatch, rotate)
    request = dict(original, action='recover-rotation')
    try:
        assert worker.submit(original) == {'job_id': original['request_id']}
        assert not calls
        assert worker.submit(request) == {'job_id': original['request_id']}
        assert entered.wait(3)
        assert worker.submit(request) == {'job_id': original['request_id']}
        with pytest.raises(InstallError, match='different'):
            worker.submit(dict(request, family='management-tls'))
        with pytest.raises(InstallError, match='interrupted'):
            worker.submit(dict(request, request_id=str(uuid.uuid4())))
    finally:
        release.set()
        worker.thread.join(3)
    assert len(calls) == 1 and calls[0]['recovery'] is True
    assert calls[0]['operation_id'] == original['request_id']
    assert worker.submit(request) == {'job_id': original['request_id']}
    assert len(calls) == 1


def _stage_recipient(worker, request, replacement, recipient):
    from iris_installer.state import atomic_write
    atomic_write(worker.state_dir / 'recovery-candidate.json', json.dumps({
        'operation_id': request['request_id'], 'identity_path': str(replacement), 'recipient': recipient}).encode())


@pytest.mark.parametrize('matching', [True, False])
def test_recipient_switch_requires_matching_public_proof(worker, monkeypatch, matching):
    old = worker.state_dir / 'old.age'
    new = worker.state_dir / 'new.age'
    worker.identity = old
    request = payload(family='age-recovery')
    recipient = 'age1' + 'q' * 58
    _stage_recipient(worker, request, new, recipient)
    def rotate(*args, **kwargs):
        assert kwargs['recovery_identity'] == old
        intent = worker.state_dir / 'credential-operations' / request['request_id']
        intent.mkdir(parents=True)
        (intent / 'record.json').write_text('{}')
        return {'state': 'rotated', 'proof': {'recovery_recipient': recipient if matching else 'different'}}
    patch_credential_implementation(monkeypatch, rotate)
    worker.submit(request)
    worker.thread.join(3)
    assert worker.identity == (new if matching else old)
    assert worker.jobs[-1]['state'] == ('rotated' if matching else 'recovery-required')
    saved = json.loads(worker.custody_record.read_text())
    assert saved['operations'][request['request_id']] == str(old)
    assert saved['active'] == str(new if matching else old)
    if matching:
        assert saved['identities'] == [str(new), str(old)]


def test_restart_retains_original_identity_for_unknown_recipient_outcome(worker, monkeypatch):
    from iris_installer.state import atomic_write
    old, new = worker.state_dir / 'old.age', worker.state_dir / 'new.age'
    request = payload(family='age-recovery')
    recipient = 'age1' + 'q' * 58
    _stage_recipient(worker, request, new, recipient)
    atomic_write(worker.custody_record, json.dumps({'active': str(new), 'identities': [str(new), str(old)],
        'operations': {request['request_id']: str(old)}}).encode())
    worker.jobs.append({'id': request['request_id'], 'action': 'rotate', 'family': 'age-recovery',
                        'state': 'running', 'detail': '', 'proof': None})
    worker.save()
    restarted = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir, identity=old)
    assert restarted.identity == new
    assert restarted.jobs[0]['state'] == 'recovery-required'
    calls = []
    def rotate(*args, **kwargs):
        calls.append(kwargs)
        return {'state': 'rotated', 'proof': {'recovery_recipient': recipient}}
    patch_credential_implementation(monkeypatch, rotate)
    restarted.submit(dict(request, action='recover-rotation'))
    restarted.thread.join(3)
    assert calls[0]['recovery_identity'] == old and calls[0]['recovery'] is True
    assert restarted.identity == new and restarted.jobs[0]['state'] == 'rotated'


def test_old_backup_verification_uses_retained_matching_identity(worker, monkeypatch):
    from iris_installer.state import atomic_write
    old, new = worker.state_dir / 'old.age', worker.state_dir / 'new.age'
    atomic_write(worker.custody_record, json.dumps({'active': str(new), 'identities': [str(new), str(old)],
                                                   'operations': {}}).encode())
    backup_id = str(uuid.uuid4())
    worker.jobs.append({'id': str(uuid.uuid4()), 'action': 'backup', 'backup_id': backup_id,
                        'state': 'captured', 'detail': ''})
    worker.save()
    restarted = worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir)
    attempts = []
    def read(path, identity, signer):
        attempts.append((path, identity))
        if identity != old:
            raise InstallError('Wrong identity')
        return {'metadata': {'backup_set_id': backup_id, 'instance_id': 'test-instance',
            'target': 'single-docker', 'scope': 'identity-recovery' if path.parent == worker.recovery_dir else 'managed-deployment-files'}}
    monkeypatch.setattr(worker_module.backup_archive, 'read', read)
    restarted.submit({'action': 'verify', 'request_id': str(uuid.uuid4()), 'backup_id': backup_id})
    restarted.thread.join(3)
    assert restarted.jobs[-1]['state'] == 'verified-files'
    assert [identity for _, identity in attempts] == [new, old, old]


@pytest.mark.parametrize('access', [None, [], {},
    {'active': '/new', 'identities': ['/old'], 'operations': {}},
    {'active': 'relative', 'identities': ['relative'], 'operations': {}},
    {'active': '/new', 'identities': ['/new'], 'operations': {'bad-id': '/new'}},
    {'active': '/new', 'identities': ['/new'], 'operations': {'a' * 36: '/other'}},
    {'active': '/new', 'identities': ['/new'], 'operations': {}, 'extra': True}])
def test_malformed_recovery_access_fails_closed(worker, access):
    from iris_installer.state import atomic_write
    atomic_write(worker.custody_record, json.dumps(access).encode())
    with pytest.raises(InstallError, match='recovery access authority'):
        worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir)


def test_recovery_access_public_permissions_fail_closed(worker):
    from iris_installer.state import atomic_write
    atomic_write(worker.custody_record, json.dumps({'active': '/new', 'identities': ['/new'], 'operations': {}}).encode(), 0o644)
    with pytest.raises(InstallError, match='Unsafe recovery access'):
        worker_module.Worker(worker.state_dir, worker.backup_dir, worker.recovery_dir)
