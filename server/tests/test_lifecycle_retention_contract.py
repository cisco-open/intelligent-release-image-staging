# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import threading
import uuid

import pytest
from jsonschema import Draft202012Validator

from test_lifecycle_retention import worker, finished, request
from test_lifecycle_network import custody
from test_gui_server import _serve_full, _auth, _req
from iris_installer import lifecycle_worker, lifecycle_network, cli, maintenance
import lifecycle_client
import openapi_contract


@pytest.mark.parametrize('transport', ['unix', 'mtls'])
def test_real_transport_retirement_cas_and_exact_request_reconciliation(worker, tmp_path, monkeypatch, custody, transport):
    worker.jobs = [finished()]; worker.save()
    if transport == 'unix':
        endpoint = tmp_path / 'worker.sock'
        monkeypatch.delenv('IRIS_LIFECYCLE_URL', raising=False)
        monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(endpoint))
        server = lifecycle_worker.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    else:
        server = lifecycle_network.make_https_server('127.0.0.1', 0, worker, custody)
        monkeypatch.setenv('IRIS_LIFECYCLE_URL', 'https://127.0.0.1:' + str(server.server_address[1]))
        for variable, name in (('CA', 'ca.crt'), ('CERT', 'client.crt'), ('KEY', 'client.key')):
            monkeypatch.setenv('IRIS_LIFECYCLE_' + variable, str(custody[name]))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        selected = request(worker)
        with pytest.raises(lifecycle_client.LifecycleConflict):
            lifecycle_client.call(dict(selected, expected_revision='0' * 64))
        assert worker.retention.store.operation(selected['request_id']) is None
        result = lifecycle_client.call(selected)
        assert result['retention_operation']['state'] == 'completed'
        status = lifecycle_client.call({'action': 'retention-status', 'request_id': selected['request_id']})
        assert status['retention']['operation'] == result['retention_operation']
        assert lifecycle_client.call(selected) == result
    finally:
        server.shutdown(); server.server_close(); thread.join(3)


def test_http_retention_session_csrf_known_refusal_and_unknown_write(worker, tmp_path, monkeypatch):
    host, port, _context, stop = _serve_full(tmp_path)
    path = '/api/settings/backups'
    worker.jobs = [finished()]; worker.save(); selected = request(worker)
    calls = []
    def call(value):
        calls.append(value)
        return worker.submit(value)
    monkeypatch.setattr(lifecycle_client, 'call', call)
    try:
        assert _req(host, port, 'POST', path, body=selected)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', path, body=selected, headers={'Cookie': cookie})[0] == 403
        assert calls == []
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        monkeypatch.setattr(lifecycle_client, 'call', lambda value: (_ for _ in ()).throw(lifecycle_client.LifecycleConflict('Changed selection')))
        assert _req(host, port, 'POST', path, body=selected, headers=headers)[0] == 409
        monkeypatch.setattr(lifecycle_client, 'call', lambda value: (_ for _ in ()).throw(lifecycle_client.LifecycleUnavailable('Outcome unknown')))
        assert _req(host, port, 'POST', path, body=selected, headers=headers)[0] == 503
        monkeypatch.setattr(lifecycle_client, 'call', call)
        assert _req(host, port, 'POST', path, body=selected, headers=headers)[0] == 200
        observed = []
        monkeypatch.setattr(lifecycle_client, 'status', lambda request_id=None: observed.append(request_id) or worker.status(request_id))
        status, _, body = _req(host, port, 'GET', path + '?retention_request_id=' + selected['request_id'], headers=headers)
        assert status == 200 and json.loads(body)['retention']['operation']['request_id'] == selected['request_id']
        assert observed == [selected['request_id']]
        assert _req(host, port, 'GET', path + '?retention_request_id=bad', headers=headers)[0] == 400
    finally:
        stop()


def test_declared_schema_accepts_actual_status_and_closed_retention_requests(worker):
    document = openapi_contract.build_document()
    route = document['paths']['/api/v1/settings/backups']
    get_schema = route['get']['responses']['200']['content']['application/json']['schema']
    post_schema = route['post']['requestBody']['content']['application/json']['schema']
    response_schema = route['post']['responses']['200']['content']['application/json']['schema']
    worker.jobs = [finished()]; worker.save()
    Draft202012Validator(get_schema).validate(worker.status())
    selected = request(worker)
    Draft202012Validator(post_schema).validate(selected)
    result = worker.submit(selected)
    Draft202012Validator(response_schema).validate(result)
    Draft202012Validator(get_schema).validate(worker.status(selected['request_id']))
    invalid = dict(selected, path='/not-accepted')
    assert list(Draft202012Validator(post_schema).iter_errors(invalid))


@pytest.mark.parametrize('action', ['retire-history', 'delete-backup', 'resume-delete'])
def test_cli_preserves_exact_ids_revision_and_typed_selector(tmp_path, monkeypatch, action):
    selected, target = str(uuid.uuid4()), str(uuid.uuid4()); seen = []
    args = ['maintenance', '--state-dir', str(tmp_path), action, '--request-id', selected,
            '--revision', 'a' * 64, '--yes']
    args += ['--retire-job-id' if action == 'retire-history' else '--backup-id', target]
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(maintenance, 'private_directory', lambda value: value)
    monkeypatch.setattr(maintenance.MaintenanceClient, 'call', lambda self, request: seen.append(request) or {'retention_operation': {}})
    assert cli.main(args) == 0
    expected = {'action': action, 'request_id': selected, 'expected_revision': 'a' * 64}
    expected.update({'job_ids': [target]} if action == 'retire-history' else {'backup_id': target, 'confirm_delete': True})
    assert seen == [expected]


def test_cli_history_exact_request_observation_has_no_write_confirmation(tmp_path, monkeypatch):
    selected = str(uuid.uuid4()); seen = []
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(maintenance, 'private_directory', lambda value: value)
    monkeypatch.setattr(maintenance.MaintenanceClient, 'call', lambda self, request: seen.append(request) or {'retention': {}})
    assert cli.main(['maintenance', '--state-dir', str(tmp_path), 'history', '--request-id', selected]) == 0
    assert seen == [{'action': 'retention-status', 'request_id': selected}]
