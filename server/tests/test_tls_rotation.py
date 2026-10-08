# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real age/OpenSSL public approval, restart recovery and request binding."""

import json
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import uuid

import pytest

import gui_tls
import instruction_keys as keys
import tls_rotation as rotation
from test_gui_server import _serve_full, _auth, _req
from test_api_split import policy_tiers


@pytest.fixture
def environment(tmp_path, monkeypatch):
    identity = tmp_path / 'service.age'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
    for name, value in {'IRIS_AGE_KEY_FILE': identity, 'IRIS_AGE_RECIPIENTS': recipient,
        'IRIS_CONFIG': tmp_path / 'config', 'IRIS_RUN': tmp_path / 'run',
        'IRIS_STATE': tmp_path / 'state', 'IRIS_GUI_CERT': tmp_path / 'run/tls/gui.pem'}.items():
        monkeypatch.setenv(name, str(value))
    return tmp_path


def prepare(mode='ca'):
    return rotation.operate(dict(action='prepare', request_id=str(uuid.uuid4()), names=['console.example', '127.0.0.1'], mode=mode))


def action(record, name, **values):
    return rotation.operate(dict(action=name, request_id=record['request_id'], **values))


def approve_ca(record, tmp_path, *, wrong_names=False, days=90):
    csr, cert, key = tmp_path / 'request.pem', tmp_path / 'ca.pem', tmp_path / 'ca.key'
    csr.write_text(record['csr'])
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-nodes', '-subj', '/CN=Approval test CA', '-keyout', str(key), '-out', str(cert), '-days', '365'], check=True, capture_output=True)
    command = ['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cert), '-CAkey', str(key),
        '-set_serial', '17', '-days', str(days), '-copy_extensions', 'copyall']
    if wrong_names:
        extension = tmp_path / 'wrong.ext'
        extension.write_text('subjectAltName=DNS:other.example\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        command += ['-extfile', str(extension)]
    return subprocess.check_output(command, stderr=subprocess.DEVNULL).decode() + cert.read_text()


def test_ca_workflow_public_only_and_retry(environment):
    record = prepare()
    assert record['state'] == 'awaiting-approval'
    assert set(record) == set(rotation.PUBLIC)
    assert 'PRIVATE KEY' not in json.dumps(record)
    approved = action(record, 'approve', certificate=approve_ca(record, environment))
    assert approved['state'] == 'approved'
    published = action(approved, 'apply', confirm=True)
    assert published['state'] == 'published'
    assert action(published, 'apply', confirm=True) == published
    assert rotation._load()['ciphertext'] is None
    key = subprocess.check_output(['age', '-d', '-i', os.environ['IRIS_AGE_KEY_FILE'], gui_tls._durable_key_path()])
    assert b'PRIVATE KEY' in key
    assert key.decode() not in rotation.journal_path().read_text()
    assert gui_tls.validate_pair(Path(gui_tls._durable_crt_path()).read_text(), key.decode()) is None
    assert Path(gui_tls.combined_path()).stat().st_mode & 0o777 == 0o600


def test_explicit_self_signed_and_parameter_bound_id(environment):
    record = prepare('self-signed')
    assert record['state'] == 'approved'
    retry = dict(action='prepare', request_id=record['request_id'], mode='self-signed', names=['console.example', '127.0.0.1'])
    assert rotation.operate(retry) == record
    for change in ({'mode': 'ca'}, {'names': ['other.example']}):
        with pytest.raises(rotation.RotationError):
            rotation.operate(dict(retry, **change))
    assert action(record, 'cancel')['state'] == 'cancelled'
    assert rotation._load()['ciphertext'] is None


@pytest.mark.parametrize('names', [[], ['https://host'], ['a\nother=1'], ['*.example'], ['a', 'a'], [None], ['a..b']])
def test_names_reject_injection_before_key_generation(environment, names):
    with pytest.raises(rotation.RotationError):
        rotation.operate(dict(action='prepare', request_id=str(uuid.uuid4()), mode='ca', names=names))
    assert not rotation.journal_path().exists()


def test_approval_rejects_wrong_names_short_validity_private_key_and_stale_id(environment):
    record = prepare()
    for certificate in (approve_ca(record, environment, wrong_names=True),
                        approve_ca(record, environment, days=1), '-----BEGIN PRIVATE KEY-----'):
        with pytest.raises(rotation.RotationError):
            action(record, 'approve', certificate=certificate)
    with pytest.raises(rotation.RotationError):
        action(dict(record, request_id=str(uuid.uuid4())), 'approve', certificate=approve_ca(record, environment))
    assert rotation.status()['state'] == 'awaiting-approval'


@pytest.mark.parametrize('boundary', [0, 1, 2])
def test_publication_recovers_every_file_boundary(environment, monkeypatch, boundary):
    record = prepare('self-signed')
    target = rotation._paths()[boundary]
    original = keys._atomic_write
    def fail(path, *args, **kwargs):
        if Path(path) == target:
            raise OSError('injected publication interruption')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(keys, '_atomic_write', fail)
    with pytest.raises(OSError):
        action(record, 'apply', confirm=True)
    assert rotation.status()['state'] == 'committing'
    with pytest.raises(ValueError, match='admitted'):
        gui_tls.remove_override()
    with pytest.raises(rotation.RotationError):
        action(record, 'cancel')
    monkeypatch.setattr(keys, '_atomic_write', original)
    assert action(record, 'apply', confirm=True)['state'] == 'published'


def test_external_file_change_refuses_overwrite(environment):
    record = prepare('self-signed')
    path = Path(gui_tls._durable_crt_path())
    path.write_text('operator changed certificate')
    with pytest.raises(rotation.RotationError, match='outside'):
        action(record, 'apply', confirm=True)
    assert path.read_text() == 'operator changed certificate'


def test_recovery_after_tmpfs_loss_and_validity_window(environment, monkeypatch):
    first = prepare('self-signed')
    action(first, 'apply', confirm=True)
    replacement = prepare('self-signed')
    original = keys._atomic_write
    def fail(path, *args, **kwargs):
        if Path(path) == Path(gui_tls._durable_crt_path()):
            raise OSError('interrupted durable pair')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(keys, '_atomic_write', fail)
    with pytest.raises(OSError):
        action(replacement, 'apply', confirm=True)
    monkeypatch.setattr(keys, '_atomic_write', original)
    Path(gui_tls.combined_path()).unlink()  # restart discarded derived tmpfs
    monkeypatch.setattr(rotation.time, 'time', lambda: replacement['created_at'] + 91 * 86400)
    assert action(replacement, 'apply', confirm=True)['state'] == 'published'
    assert gui_tls.active_info()['fingerprint_sha256'].replace(':', '').lower() == replacement['fingerprint_sha256']


def test_stale_approval_cannot_begin_publication(environment, monkeypatch):
    replacement = prepare('self-signed')
    monkeypatch.setattr(rotation.time, 'time', lambda: replacement['created_at'] + 84 * 86400)
    with pytest.raises(rotation.RotationError, match='seven days'):
        action(replacement, 'apply', confirm=True)
    assert rotation.status()['state'] == 'approved'
    assert not Path(gui_tls._durable_key_path()).exists()


def test_http_requires_owner_and_csrf(environment):
    host, port, _, stop = _serve_full(environment)
    endpoint = '/api/settings/certificates/browser/rotation'
    try:
        assert _req(host, port, 'GET', endpoint)[0] == 401
        assert _req(host, port, 'POST', endpoint, body={})[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', endpoint, body={}, headers={'Cookie': cookie})[0] == 403
        code, _, body = _req(host, port, 'POST', endpoint,
            headers={'Cookie': cookie, 'X-CSRF-Token': csrf}, body=dict(action='prepare',
                request_id=str(uuid.uuid4()), mode='ca', names=['console.example']))
        assert code == 200 and json.loads(body)['state'] == 'awaiting-approval'
        assert b'PRIVATE KEY' not in body
    finally:
        stop()


def test_authenticated_split_tier_request_is_public(environment, policy_tiers):
    request, _, _ = policy_tiers
    endpoint = '/settings/certificates/browser/rotation'
    assert request('console', 'GET', endpoint, authorized=False, match=False)[0] == 401
    code, headers, body = request('console', 'POST', endpoint, dict(action='prepare',
        request_id=str(uuid.uuid4()), mode='ca', names=['console.example']), match=False)
    assert code == 200 and body['state'] == 'awaiting-approval'
    assert 'no-store' in headers['Cache-Control'] and 'PRIVATE KEY' not in json.dumps(body)


def test_real_split_console_tls_reload_and_retry(environment, monkeypatch):
    import http.client
    import gui_server
    import management_api
    from test_api_split import _certificate, _write_secret, _thread, _request

    cert, key = _certificate(environment, 'management')
    default, default_key = _certificate(environment, 'browser')
    token = environment / 'tier-token'
    _write_secret(token, 't' * 64)
    app = management_api.gui_app.GuiApp(str(environment / 'gui-secrets.json'))
    app.set_admin('admin', 'isolated-test-password')
    management = management_api.make_server('127.0.0.1', 0, app,
        certfile=str(cert), keyfile=str(key), management_token_file=str(token))
    _thread(management)
    runtime = environment / 'console-serving.pem'
    runtime.write_bytes(default.read_bytes() + default_key.read_bytes())
    runtime.chmod(0o600)
    console = gui_server.make_server('127.0.0.1', 0,
        'https://localhost:' + str(management.server_address[1]), str(token), str(cert),
        certfile=str(runtime),
        default_certfile=str(default), default_keyfile=str(default_key))
    _thread(console)
    port = console.server_address[1]
    def fingerprint():
        with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
            with ssl._create_unverified_context().wrap_socket(sock, server_hostname='localhost') as tls:
                return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    try:
        code, headers, body = _request(port, '/api/v1/login', 'POST',
            {'Content-Type': 'application/json'}, json.dumps({'username': 'admin', 'password': 'isolated-test-password'}), https=True)
        assert code == 200
        auth = {'Content-Type': 'application/json', 'Cookie': headers['Set-Cookie'].split(';', 1)[0],
                'X-CSRF-Token': json.loads(body)['csrf']}
        endpoint = '/api/v1/settings/certificates/browser/rotation'
        def post(payload):
            code, _, body = _request(port, endpoint, 'POST', auth, json.dumps(payload), https=True)
            assert code == 200, body
            assert b'PRIVATE KEY' not in body
            return json.loads(body)
        original = fingerprint()
        record = post(dict(action='prepare', request_id=str(uuid.uuid4()), names=['console.example', '127.0.0.1'], mode='ca'))
        post(dict(action='approve', request_id=record['request_id'], certificate=approve_ca(record, environment)))
        send = http.client.HTTPSConnection.request
        def unavailable(self, method, url, *args, **kwargs):
            if url.endswith('/internal/v1/console-certificate'):
                raise OSError('injected unavailable certificate download')
            return send(self, method, url, *args, **kwargs)
        monkeypatch.setattr(http.client.HTTPSConnection, 'request', unavailable)
        payload = dict(action='apply', request_id=record['request_id'], confirm=True)
        published = post(payload)
        assert published['state'] == 'published' and published['applied'] is False
        assert fingerprint() == original
        monkeypatch.setattr(http.client.HTTPSConnection, 'request', send)
        published = post(payload)
        assert published['applied'] is True and fingerprint() == published['fingerprint_sha256']
        assert fingerprint() != original
    finally:
        console.shutdown()
        console.server_close()
        management.shutdown()
        management.server_close()


def test_rekey_refuses_pending_encrypted_browser_candidate(environment, monkeypatch):
    record = prepare()
    config = Path(os.environ['IRIS_CONFIG'])
    (config / 'secrets.json.age').write_bytes(b'existing encrypted state')
    before = rotation.journal_path().read_bytes()
    result = subprocess.run(['bash', str(Path(rotation.__file__).with_name('iris-bootstrap')), '--rekey'], capture_output=True)
    assert result.returncode != 0 and b'pending signer or TLS' in result.stderr
    assert rotation.journal_path().read_bytes() == before
    assert rotation.status()['request_id'] == record['request_id']
