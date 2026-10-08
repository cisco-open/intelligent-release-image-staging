# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Encrypted service overrides, consumer proof and reversible pending changes."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import subprocess
import ssl
import threading
import time
import uuid
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import service_credentials as credentials
import secretfs
import secrets_store
import telemetry
import otlp
from test_api_split import _certificate
from test_tls_rotation import environment
from test_gui_server import _serve_full, _auth, _req


@pytest.fixture
def store(environment, monkeypatch):
    path, cipher = environment / 'run/secrets.json', environment / 'config/secrets.json.age'
    path.parent.mkdir(parents=True, exist_ok=True)
    cipher.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv('IRIS_SECRETS', str(path))
    monkeypatch.setenv('IRIS_SECRETS_ENC', str(cipher))
    secretfs.persist_store({'devices': {}, 'seeder': {}}, str(path),
        recipients_csv=os.environ['IRIS_AGE_RECIPIENTS'], enc_path=str(cipher))
    return path, cipher


def replace(family='metrics-token', **extra):
    return dict(family=family, action='replace', request_id=str(uuid.uuid4()), confirm=True,
        **({'token': 'b' * 64} if family == 'metrics-token' else
           {'headers': {'Authorization': 'Bearer new-fixture-value'}, 'endpoint': 'https://collector.example'}), **extra)


def operate(payload, action):
    return credentials.operate({name: payload[name] for name in ('family', 'request_id', 'confirm')} | {'action': action})


def test_metrics_overlap_real_consumer_proof_and_retirement(store, environment, monkeypatch):
    old = environment / 'mounted-token'
    old.write_text('a' * 64)
    old.chmod(0o600)
    monkeypatch.setenv('IRIS_OBSERVABILITY_TOKEN_FILE', str(old))
    payload = replace()
    result = credentials.operate(payload)
    assert result['items'][0]['previous_retained']
    assert 'b' * 64 not in json.dumps(result)
    assert credentials.operate(payload) == result
    with pytest.raises(credentials.CredentialError, match='observed'):
        operate(payload, 'retire')
    server = telemetry.make_metrics_server('127.0.0.1', 0, lambda: 'metric 1\n', observability_token_file=str(old))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = 'http://127.0.0.1:' + str(server.server_port) + '/metrics'
        for token in ('a' * 64, 'b' * 64):
            with urlopen(Request(url, headers={'Authorization': 'Bearer ' + token}), timeout=5) as response:
                assert response.status == 200
                response.read()
        deadline = time.monotonic() + 2
        while credentials.status()['items'][0]['observed_at'] is None and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        assert credentials.status()['items'][0]['observed_at'] is not None
        assert operate(payload, 'retire')['items'][0]['state'] == 'completed'
        with pytest.raises(HTTPError) as denied:
            urlopen(Request(url, headers={'Authorization': 'Bearer ' + 'a' * 64}), timeout=5)
        assert denied.value.code == 401
        with urlopen(Request(url, headers={'Authorization': 'Bearer ' + 'b' * 64}), timeout=5) as response:
            assert response.status == 200
    finally:
        server.shutdown(); server.server_close(); thread.join(5)
    assert old.read_text() == 'a' * 64, 'Never rewrite deployment-mounted credentials'
    plain = subprocess.check_output(['age', '-d', '-i', os.environ['IRIS_AGE_KEY_FILE'], str(store[1])])
    assert json.loads(plain) == secrets_store.load(str(store[0]))


def test_revert_before_retirement_restores_deployment_authority(store, environment, monkeypatch):
    old = environment / 'token'
    old.write_text('a' * 64); old.chmod(0o600)
    monkeypatch.setenv('IRIS_OBSERVABILITY_TOKEN_FILE', str(old))
    payload = replace()
    credentials.operate(payload)
    assert operate(payload, 'revert')['items'][0]['state'] == 'reverted'
    assert credentials.metrics_authorized({'Authorization': 'Bearer ' + 'a' * 64}, str(old), None)
    assert not credentials.metrics_authorized({'Authorization': 'Bearer ' + 'b' * 64}, str(old), None)
    assert operate(payload, 'revert')['items'][0]['state'] == 'reverted'
    with pytest.raises(credentials.CredentialError):
        credentials.operate(payload)


def test_default_null_mount_allows_first_metrics_adoption(store, monkeypatch):
    monkeypatch.setenv('IRIS_OBSERVABILITY_TOKEN_FILE', '/dev/null')
    monkeypatch.setenv('IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE', '/dev/null')
    payload = replace()
    result = credentials.operate(payload)
    assert result['items'][0]['state'] == 'awaiting-verification'
    assert not result['items'][0]['previous_retained']
    assert credentials.metrics_authorized({'Authorization': 'Bearer ' + payload['token']}, '/dev/null', '/dev/null')


@pytest.mark.parametrize('unsafe', ['device', 'permissions', 'scope'])
def test_adoption_does_not_ignore_unsafe_existing_credentials(store, environment, monkeypatch, unsafe):
    token = environment / 'unsafe-token'
    token.write_text('x' * 64 if unsafe != 'scope' else json.dumps({'scope': 'management', 'token': 'x' * 64}))
    token.chmod(0o644 if unsafe == 'permissions' else 0o600)
    monkeypatch.setenv('IRIS_OBSERVABILITY_TOKEN_FILE', '/dev/zero' if unsafe == 'device' else str(token))
    before = store[1].read_bytes()
    with pytest.raises(credentials.tier_auth.CredentialUnavailable):
        credentials.operate(replace())
    assert store[1].read_bytes() == before


def test_collector_bound_to_exact_destination_and_current_delivery(store):
    payload = replace('collector-headers')
    credentials.operate(payload)
    assert credentials.collector_headers(payload['endpoint'], {})[0] == {'authorization': 'Bearer new-fixture-value'}
    with pytest.raises(credentials.CredentialError):
        credentials.collector_headers('https://different.example', {})
    with pytest.raises(credentials.CredentialError):
        credentials.collector_headers('http://collector.example', {})
    credentials.observed_delivery('https://different.example/v1/logs', payload['headers'])
    credentials.observed_delivery('https://collector.example/v1/logs', {'Authorization': 'old'})
    with pytest.raises(credentials.CredentialError):
        operate(payload, 'retire')
    credentials.observed_delivery('https://collector.example/v1/logs', payload['headers'])
    assert operate(payload, 'retire')['items'][1]['state'] == 'completed'
    replacement = dict(replace('collector-headers'), headers={'Authorization': 'second'}, endpoint='https://new.example')
    credentials.operate(replacement)
    assert operate(replacement, 'revert')['items'][1]['endpoint'] == 'https://collector.example'
    assert credentials.collector_headers(payload['endpoint'], {})[0] == {'authorization': 'Bearer new-fixture-value'}


def test_real_tls_collector_delivery_and_hot_reload(store, environment, monkeypatch):
    cert, key = _certificate(environment)
    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            assert self.headers['Authorization'] == 'Bearer new-fixture-value'
            self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
        def log_message(self, *_args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Collector)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    endpoint = 'https://127.0.0.1:' + str(server.server_port)
    monkeypatch.setattr(otlp.trust, 'ssl_context', lambda: ssl.create_default_context(cafile=str(cert)))
    payload = dict(replace('collector-headers'), endpoint=endpoint)
    selected = [endpoint]
    hub = telemetry.Telemetry(dest_settings=SimpleNamespace(current=lambda: (selected[0], True)),
        headers={'Authorization': 'old'}, headers_provider=credentials.collector_headers)
    try:
        hub._refresh_exporters()
        credentials.operate(payload)
        hub._refresh_exporters()
        assert hub._log_transport._headers == {'authorization': 'Bearer new-fixture-value'}
        assert credentials.status()['items'][1]['observed_at'] is None
        otlp._http_post(endpoint + '/v1/logs', b'{}', headers=hub._log_transport._headers)
        assert credentials.status()['items'][1]['observed_at'] is not None
        operate(payload, 'retire')
        replacement = dict(replace('collector-headers'), endpoint=endpoint, headers={'Authorization': 'second'})
        credentials.operate(replacement)
        hub._refresh_exporters()
        assert hub._log_transport._headers == {'authorization': 'second'}
        operate(replacement, 'revert')
        hub._refresh_exporters()
        assert hub._log_transport._headers == {'authorization': 'Bearer new-fixture-value'}
        otlp._http_post(endpoint + '/v1/logs', b'{}', headers=hub._log_transport._headers)
        selected[0] = 'https://other.example'
        hub._refresh_exporters()
        assert hub._log_transport is None and hub.metrics_exporter is None
    finally:
        server.shutdown(); server.server_close(); thread.join(5)


@pytest.mark.parametrize('headers', [{'Authorization': 'x\r\nHost: evil'}, {'Host': 'evil'},
    {'a': 'x', 'A': 'y'}, {'a': ''}, {}, {'Content-Length': '123'}, {'a': '\x00'}])
def test_invalid_headers_never_change_encrypted_store(store, headers):
    before = store[1].read_bytes()
    with pytest.raises(credentials.CredentialError):
        credentials.operate(dict(replace('collector-headers'), headers=headers))
    assert store[1].read_bytes() == before


def test_wrong_id_and_failed_write_cannot_retire_or_replace(store, monkeypatch):
    payload = replace()
    credentials.operate(payload)
    with pytest.raises(credentials.CredentialError):
        operate(dict(payload, request_id=str(uuid.uuid4())), 'retire')
    before = store[0].read_bytes()
    def fail(*args, **kwargs):
        raise OSError('fixture storage failed')
    monkeypatch.setattr(secretfs, 'persist_store', fail)
    with pytest.raises(OSError):
        operate(payload, 'revert')
    assert store[0].read_bytes() == before


def test_http_authorization_and_no_secret_return(store, environment):
    host, port, _, stop = _serve_full(environment)
    endpoint = '/api/settings/service-credentials'
    try:
        assert _req(host, port, 'GET', endpoint)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', endpoint, body=replace(), headers={'Cookie': cookie})[0] == 403
        code, _, body = _req(host, port, 'POST', endpoint, body=replace('collector-headers'),
            headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert code == 200 and b'new-fixture-value' not in body
    finally:
        stop()


@pytest.mark.parametrize('family', ['browser', 'service'])
@pytest.mark.parametrize('failure', [subprocess.CalledProcessError(1, ['age'], stderr=b'PRIVATE FIXTURE'),
                                    subprocess.TimeoutExpired(['age'], 30, output=b'PRIVATE FIXTURE')])
def test_custody_tool_failure_is_a_redacted_http_error(store, environment, monkeypatch, family, failure):
    import tls_rotation
    module = tls_rotation if family == 'browser' else credentials
    endpoint = '/api/settings/certificates/browser/rotation' if family == 'browser' else '/api/settings/service-credentials'
    def fail(_payload):
        raise failure
    monkeypatch.setattr(module, 'operate', fail)
    host, port, _, stop = _serve_full(environment)
    try:
        cookie, csrf = _auth(host, port)
        code, _, body = _req(host, port, 'POST', endpoint, body={},
            headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert code == 503 and b'PRIVATE FIXTURE' not in body
        assert 'error' in json.loads(body)
    finally:
        stop()
