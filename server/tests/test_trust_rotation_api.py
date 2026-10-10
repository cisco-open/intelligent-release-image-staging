# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Trust approvals distinguish public validation refusals from service failures."""

import json
import subprocess
import uuid

import pytest

import trust_rotation
from test_gui_server import _auth, _req, _serve_full
from test_trust_rotation import environment


ENDPOINT = '/api/settings/trust-rotation'


def test_invalid_device_certificate_is_409_and_preserves_prepared_request(environment):
    host, port, _, stop = _serve_full(environment)
    body = dict(family='device-tls', action='prepare', request_id=str(uuid.uuid4()),
                names=['distribution.example'], mode='ca')
    try:
        assert _req(host, port, 'POST', ENDPOINT, body=body)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', ENDPOINT, body=body, headers={'Cookie': cookie})[0] == 403
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        status, _, raw = _req(host, port, 'POST', ENDPOINT, body=body, headers=headers)
        prepared = json.loads(raw)
        assert status == 200 and prepared['state'] == 'awaiting-approval'
        journal = trust_rotation.journal_path('device-tls').read_bytes()
        invalid = dict(family='device-tls', action='approve', request_id=body['request_id'],
                       certificate='not a certificate')
        status, _, raw = _req(host, port, 'POST', ENDPOINT, body=invalid, headers=headers)
        assert status == 409
        assert json.loads(raw)['error'] == 'Import a bounded PEM certificate chain, leaf first'
        assert trust_rotation.journal_path('device-tls').read_bytes() == journal
        assert trust_rotation.status('device-tls') == prepared
    finally:
        stop()


@pytest.mark.parametrize('changes', [
    {'request_id': 'not-a-canonical-id'}, {'names': ['https://distribution.example']},
    {'names': ['distribution.example', 'distribution.example']},
])
def test_tls_preparation_validation_is_409_without_a_candidate(environment, changes):
    host, port, _, stop = _serve_full(environment)
    body = dict(family='device-tls', action='prepare', request_id=str(uuid.uuid4()),
                names=['distribution.example'], mode='ca')
    body.update(changes)
    try:
        cookie, csrf = _auth(host, port)
        status, _, raw = _req(host, port, 'POST', ENDPOINT, body=body,
                              headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert status == 409 and isinstance(json.loads(raw)['error'], str)
        assert not trust_rotation.journal_path('device-tls').exists()
    finally:
        stop()


@pytest.mark.parametrize('error', [OSError('private diagnostic'), ValueError('private diagnostic'),
                                  subprocess.CalledProcessError(1, ['age'], stderr='private diagnostic')])
def test_trust_service_failures_remain_bounded_503(tmp_path, monkeypatch, error):
    def unavailable(_body):
        raise error
    monkeypatch.setattr(trust_rotation, 'operate', unavailable)
    host, port, _, stop = _serve_full(tmp_path)
    try:
        cookie, csrf = _auth(host, port)
        status, _, raw = _req(host, port, 'POST', ENDPOINT,
                              body={'family': 'device-tls', 'action': 'prepare'},
                              headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert status == 503
        assert json.loads(raw)['error'] == 'service unavailable'
        assert json.loads(raw)['code'] == 'service-unavailable'
        assert b'private diagnostic' not in raw
    finally:
        stop()
