# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Closed, authenticated backup recovery controls; capture itself is tested separately."""

import json
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import maintenance
from iris_installer.state import InstallError
import lifecycle_client
import openapi_contract
from test_gui_server import _serve_full, _auth, _req
from test_api_split import policy_tiers


def recovery_request():
    return {'action': 'recover-backup', 'request_id': str(uuid.uuid4()),
            'backup_id': str(uuid.uuid4()), 'allow_downtime': True}


def test_host_recovery_selects_original_backup_and_job():
    expected = recovery_request()
    job = {'id': expected['request_id'], 'backup_id': expected['backup_id'],
           'action': 'backup', 'state': 'recovery-required'}
    assert maintenance.recovery_request(job) == expected
    assert maintenance.recovery_request(job) == expected  # No new request ID.
    for changes in ({'state': 'captured'}, {'state': 'running'}, {'id': '../other'},
                    {'backup_id': None}, {'backup_id': '0' * 36}):
        with pytest.raises(InstallError):
            maintenance.recovery_request(dict(job, **changes))


@pytest.mark.parametrize('changes', [
    {'allow_downtime': False}, {'allow_downtime': 1}, {'request_id': '../other'},
    {'backup_id': '0' * 36}, {'backup_id': None}, {'path': '/etc'},
    {'confirm_restore': True}, {'command': 'docker start'},
])
def test_backup_recovery_refuses_invalid_requests_before_transport(tmp_path, monkeypatch, changes):
    request = dict(recovery_request(), **changes)
    monkeypatch.setattr(lifecycle_client, '_network_call', lambda *_: pytest.fail('invalid request reached transport'))
    monkeypatch.setenv('IRIS_LIFECYCLE_URL', 'https://fixture.invalid:17443')
    with pytest.raises(ValueError):
        lifecycle_client.call(request)
    client = maintenance.MaintenanceClient(tmp_path)
    with pytest.raises(InstallError, match='Unsupported interrupted backup'):
        client.call(request)


def test_backup_recovery_forwards_only_original_closed_request(monkeypatch):
    request = recovery_request()
    observed = []
    monkeypatch.setenv('IRIS_LIFECYCLE_URL', 'https://fixture.invalid:17443')
    def transport(value, endpoint):
        observed.append((value, endpoint))
        return json.dumps({'ok': True, 'result': {'job_id': value['request_id']}}).encode() + b'\n'
    monkeypatch.setattr(lifecycle_client, '_network_call', transport)
    assert lifecycle_client.call(request) == {'job_id': request['request_id']}
    assert observed == [(request, 'https://fixture.invalid:17443')]


def test_backup_recovery_requires_browser_session_and_csrf(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(lifecycle_client, 'call', lambda value: seen.append(value) or {'job_id': value['request_id']})
    host, port, _ctx, stop = _serve_full(tmp_path)
    payload = recovery_request()
    try:
        path = '/api/settings/backups'
        assert _req(host, port, 'POST', path, body=payload)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', path, body=payload, headers={'Cookie': cookie})[0] == 403
        assert seen == []
        status, _, raw = _req(host, port, 'POST', path, body=payload,
                             headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert status == 200 and json.loads(raw) == {'job_id': payload['request_id']}
        assert seen == [payload]
    finally:
        stop()


def test_backup_recovery_crosses_authenticated_console_and_management_tiers(policy_tiers, monkeypatch):
    request, _fleet, _store = policy_tiers
    seen = []
    monkeypatch.setattr(lifecycle_client, 'call', lambda value: seen.append(value) or {'job_id': value['request_id']})
    payload = recovery_request()
    for tier in ('console', 'management'):
        assert request(tier, 'POST', '/settings/backups', payload, authorized=False, match=False)[0] == 401
        status, _, result = request(tier, 'POST', '/settings/backups', payload, match=False)
        assert status == 200 and result == {'job_id': payload['request_id']}
    assert seen == [payload, payload]


def test_openapi_describes_same_job_recovery_without_restore_approval():
    document = openapi_contract.build_document()
    for prefix in ('/api/v1', '/internal/v1'):
        route = document['paths'][prefix + '/settings/backups']
        variants = route['post']['requestBody']['content']['application/json']['schema']['oneOf']
        recovery, = [item for item in variants if item['properties']['action'].get('const') == 'recover-backup']
        assert recovery['additionalProperties'] is False
        assert set(recovery['required']) == {'action', 'request_id', 'backup_id', 'allow_downtime'}
        assert recovery['properties']['allow_downtime'] == {'const': True}
        assert recovery['properties']['request_id']['format'] == 'uuid'
        status = route['get']['responses']['200']['content']['application/json']['schema']
        assert status['properties']['can_recover_backup']['type'] == 'boolean'
        assert status['properties']['retention']['properties']['recoverable_job_id']['type'] == ['string', 'null']
