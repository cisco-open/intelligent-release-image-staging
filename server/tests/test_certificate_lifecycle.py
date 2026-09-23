# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real disposable OpenSSH custody and authenticated HTTP renewal tests."""

import json
from pathlib import Path

import pytest

import certificate_lifecycle as lifecycle
import instruction_keys as keys
from test_instruction_keys import _paths, _root_map, _root_public, _generate, _issue, _import_cert, NOW
from test_gui_server import _serve_full, _auth, _req
from test_setup_status import CERT_A
from test_api_split import policy_tiers


@pytest.fixture
def custody(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _generate(paths)
    _import_cert(paths, public, roots['root-a'])
    Path(paths.roots_dir).mkdir(parents=True)
    for name, path in public.items():
        (Path(paths.roots_dir) / (name + '.pub')).write_bytes(path.read_bytes())
    for name, value in [('IRIS_CONFIG', paths.config_dir), ('IRIS_STATE', paths.state_dir), ('IRIS_RUN', paths.run_dir)]:
        monkeypatch.setenv(name, value)
    return paths, roots


def approval(paths, roots, start=NOW, end=None, principal='iris-server'):
    request = keys.online_renewal_request(paths)
    certificate = _issue(roots['root-a'], Path(paths.public_key), start,
                         end or start + keys.CERTIFICATE_LIFETIME_SECONDS,
                         principals=principal).read_text()
    return {key: value for key, value in dict(request, certificate=certificate).items() if key != 'public_key'}


def test_renew_same_key_and_repeat_preserves_epoch_and_secrets(custody):
    paths, roots = custody
    epoch = Path(paths.epoch)
    epoch.write_bytes(b'preserve activation and serial floors')
    before = {p: Path(p).read_bytes() for p in [paths.runtime_key, paths.encrypted_key, paths.public_key, paths.epoch]}
    request = approval(paths, roots)
    result = lifecycle.renew(request, paths=paths, now=NOW)
    assert result['applied'] and result['expires_at'] == NOW + 30 * 86400
    assert lifecycle.renew(request, paths=paths, now=NOW) == result
    for path, content in before.items():
        assert Path(path).read_bytes() == content
    assert b'PRIVATE KEY' not in json.dumps(result).encode()


@pytest.mark.parametrize('change', ['wrong-key', 'stale', 'private', 'unknown-field', 'bad-principal', 'shorter', 'cutoff'])
def test_renew_rejections_preserve_current_certificate(custody, change):
    paths, roots = custody
    previous = Path(paths.certificate).read_bytes()
    payload = approval(paths, roots,
                       start=NOW - 2 * 86400 if change == 'shorter' else NOW,
                       principal='wrong' if change == 'bad-principal' else 'iris-server')
    if change == 'wrong-key': payload['public_key_sha256'] = '0' * 64
    if change == 'stale': payload['certificate_sha256'] = '0' * 64
    if change == 'private': payload['certificate'] = Path(paths.runtime_key).read_text()
    if change == 'unknown-field': payload['root_key'] = 'must not accept'
    with pytest.raises(keys.InstructionKeyError):
        lifecycle.renew(payload, paths=paths, now=NOW + 23 * 86400 if change == 'cutoff' else NOW)
    assert Path(paths.certificate).read_bytes() == previous


def test_expired_certificate_can_be_renewed_without_reset(custody):
    paths, roots = custody
    later = NOW + 35 * 86400
    payload = approval(paths, roots, start=later)
    assert lifecycle.renew(payload, paths=paths, now=later)['applied']


def test_inventory_public_only_and_observed_scope(custody, tmp_path, monkeypatch):
    paths, roots = custody
    certificate = tmp_path / 'combined.pem'
    certificate.write_text(CERT_A + '\nPRIVATE KEY sentinel-secret\n')
    monkeypatch.setenv('IRIS_CERT', str(certificate))
    report = lifecycle.inventory(paths=paths, now=NOW)
    assert report['scope'] == 'server-certificate-files'
    rows = {row['id']: row for row in report['items']}
    assert rows['device-tls']['expires_at'] > NOW
    assert rows['management-tls']['state'] == 'unknown'
    assert rows['instruction-signer']['refuse_at'] == NOW - 3600 + 23 * 86400
    assert 'sentinel-secret' not in json.dumps(report)
    assert rows['instruction-signer']['state'] == 'within-validity'
    assert rows['root-root-a']['state'] == 'public-key-present'
    assert rows['root-root-a']['expires_at'] is None
    assert rows['root-root-a']['kind'] == 'public-key'


@pytest.mark.parametrize('now,state', [(9, 'not-yet-valid'), (10, 'within-validity'),
                                       (20, 'renewal-due'), (23, 'signing-refused'), (30, 'expired')])
def test_exact_deadlines(now, state):
    assert lifecycle.validity(10, 30, now, renew_at=20, refuse_at=23) == state


def test_routes_require_session_and_csrf(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(lifecycle, 'renew', lambda payload: called.append(payload) or {'applied': True})
    host, port, ctx, stop = _serve_full(tmp_path)
    try:
        base = '/api/settings/certificates'
        assert _req(host, port, 'GET', base)[0] == 401
        assert _req(host, port, 'POST', base + '/instruction/renew', body={})[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', base + '/instruction/renew', body={}, headers={'Cookie': cookie})[0] == 403
        assert not called
        status, _, body = _req(host, port, 'GET', base, headers={'Cookie': cookie})
        assert status == 200 and json.loads(body)['scope'] == 'server-certificate-files'
    finally:
        stop()


def test_http_renewal_real_certificate(custody, tmp_path, monkeypatch):
    paths, roots = custody
    # Fix only the clock, retaining actual cryptographic import and filesystem IO.
    original = lifecycle.renew
    monkeypatch.setattr(lifecycle, 'renew', lambda payload: original(payload, paths=paths, now=NOW))
    host, port, ctx, stop = _serve_full(tmp_path)
    try:
        cookie, csrf = _auth(host, port)
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        base = '/api/settings/certificates/instruction/'
        status, _, body = _req(host, port, 'POST', base + 'request', body={}, headers=headers)
        assert status == 200
        assert json.loads(body)['public_key'].startswith('ssh-ed25519 ')
        payload = approval(paths, roots)
        status, _, body = _req(host, port, 'POST', base + 'renew', body=payload, headers=headers)
        assert status == 200, body
        assert json.loads(body)['applied']
        status, _, body = _req(host, port, 'POST', base + 'renew', body=dict(payload, root_key='no'), headers=headers)
        assert status == 409
    finally:
        stop()


def test_renewal_through_console_and_management_tls_boundary(custody, policy_tiers, monkeypatch):
    paths, roots = custody
    request, _fleet, _store = policy_tiers
    original = lifecycle.renew
    monkeypatch.setattr(lifecycle, 'renew', lambda payload: original(payload, paths=paths, now=NOW))
    suffix = '/settings/certificates/instruction/'
    for tier in ('console', 'management'):
        assert request(tier, 'GET', '/settings/certificates', authorized=False, match=False)[0] == 401
        assert request(tier, 'POST', suffix + 'request', {}, authorized=False, match=False)[0] == 401
        status, headers, result = request(tier, 'POST', suffix + 'request', {}, match=False)
        assert status == 200 and result['public_key'].startswith('ssh-ed25519 ')
    payload = approval(paths, roots)
    for tier in ('console', 'management'):
        status, headers, result = request(tier, 'POST', suffix + 'renew', payload, match=False)
        assert status == 200 and result['applied']
        assert 'no-store' in headers['Cache-Control']
