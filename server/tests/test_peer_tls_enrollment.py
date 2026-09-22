# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Real OpenSSL/age enrollment and authorization, without device or lab access."""
import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import threading
import time

import pytest
import catalog
import peer_tls_issuer
import secrets_store

spec = importlib.util.spec_from_file_location('device_peer_tls',
    Path(__file__).resolve().parents[2] / 'device/agent/peer_tls.py')
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


@pytest.fixture
def enrollment(tmp_path, monkeypatch):
    key = tmp_path / 'age.key'
    subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(key)]).decode().strip()
    monkeypatch.setenv('IRIS_AGE_KEY_FILE', str(key))
    monkeypatch.setenv('IRIS_AGE_RECIPIENTS', recipient)
    monkeypatch.setenv('IRIS_CONFIG', str(tmp_path / 'config'))
    monkeypatch.setenv('IRIS_RUN', str(tmp_path / 'run'))
    monkeypatch.setenv('IRIS_PEER_TLS_MODE', 'required')
    issuer = peer_tls_issuer.Issuer()

    class Client:
        calls = 0
        unavailable = False
        def enroll_peer_tls(self, device, csr):
            self.calls += 1
            if self.unavailable:
                raise RuntimeError('offline')
            return issuer.issue(device, csr)

    cfg = {'peer_tls_mode': 'required', 'device_id': 'switch-a',
           'stage_dir': str(tmp_path / 'device')}
    return cfg, Client(), issuer


def test_enroll_reuse_and_encrypted_ca_recovery(enrollment):
    cfg, client, issuer = enrollment
    fragment = peer.ensure(cfg, client)
    assert 'bt-peer-tls=required\n' in fragment
    assert client.calls == 1
    assert peer.ensure(cfg, client) == fragment
    assert client.calls == 1
    ciphertext = (issuer.config / 'ca.pem.age').read_bytes()
    assert b'PRIVATE KEY' not in ciphertext
    original = issuer.prepare().read_bytes()
    issuer.prepare().unlink()
    assert issuer.prepare().read_bytes() == original
    root = Path(cfg['stage_dir']) / 'peer-tls'
    assert (root / 'node.key').stat().st_mode & 0o077 == 0


def test_renewal_outage_only_allows_valid_matching_identity(enrollment, monkeypatch):
    cfg, client, issuer = enrollment
    fragment = peer.ensure(cfg, client)
    original = peer._identity_valid
    monkeypatch.setattr(peer, '_identity_valid',
                        lambda cert, ca, key, device, seconds=0:
                        False if seconds else original(cert, ca, key, device))
    client.unavailable = True
    assert peer.ensure(cfg, client) == fragment
    cfg['device_id'] = 'switch-b'
    with pytest.raises(peer.PeerTLSError):
        peer.ensure(cfg, client)
    cfg['device_id'] = 'switch-a'
    monkeypatch.setattr(peer, '_identity_valid', lambda *a, **kw: False)
    with pytest.raises(peer.PeerTLSError):
        peer.ensure(cfg, client)


def test_wrong_key_fails_closed(enrollment, monkeypatch):
    cfg, client, issuer = enrollment
    peer.ensure(cfg, client)
    monkeypatch.setattr(peer, '_identity_valid', lambda *a, **kw: False)
    other = dict(cfg, stage_dir=cfg['stage_dir'] + '-other')
    peer.ensure(other, client)
    other_root = Path(other['stage_dir']) / 'peer-tls'
    row = json.loads((other_root / 'current.json').read_text())
    wrong_cert = (other_root / row['generation'] / 'node.crt').read_text()
    ca = (other_root / row['generation'] / 'ca.crt').read_text()
    monkeypatch.setattr(client, 'enroll_peer_tls', lambda *a: {
        'mode': 'required', 'certificate': wrong_cert, 'ca': ca})
    with pytest.raises(peer.PeerTLSError):
        peer.ensure(cfg, client)


def test_csr_cannot_choose_identity_or_ca_extensions(enrollment):
    cfg, client, issuer = enrollment
    peer.ensure(cfg, client)
    key = Path(cfg['stage_dir']) / 'peer-tls/node.key'
    csr = peer._openssl('req', '-new', '-key', key, '-subj', '/CN=attacker',
                        '-addext', 'basicConstraints=critical,CA:TRUE').decode()
    response = issuer.issue('switch-a', csr)
    description = peer._openssl('x509', '-text', '-noout', data=response['certificate'].encode())
    assert b'CA:FALSE' in description and b'CN = attacker' not in description
    with pytest.raises(peer_tls_issuer.PeerTLSError):
        issuer.issue('switch-a', 'not a CSR')


def test_catalog_endpoint_auth_rate_limit_and_no_store(enrollment, tmp_path, monkeypatch):
    cfg, client, issuer = enrollment
    peer.ensure(cfg, client)
    key = Path(cfg['stage_dir']) / 'peer-tls/node.key'
    csr = peer._openssl('req', '-new', '-key', key, '-subj', '/CN=ignored').decode()
    sp = str(tmp_path / 'secrets.json')
    store = secrets_store.load(sp)
    token = secrets_store.mint(store, 'switch-a', 'catalog_token', time.time())
    other = secrets_store.mint(store, 'switch-b', 'catalog_token', time.time())
    previous = 'previous-test-catalog-bearer'
    store['devices']['switch-a']['catalog_token_prev'] = dict(
        store['devices']['switch-a']['catalog_token'], value=previous)
    secrets_store.save(store, sp)
    srv = catalog.make_server('127.0.0.1', 0, catalog.CatalogStore(str(tmp_path / 'state')), sp)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    def request(bearer):
        conn = http.client.HTTPConnection('127.0.0.1', srv.server_address[1])
        conn.request('POST', '/v1/devices/switch-a/peer-tls', json.dumps({'csr': csr}),
                     {'Authorization': 'Bearer ' + bearer, 'Content-Type': 'application/json'})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    try:
        assert request('invalid')[0] == 401
        assert request(other)[0] == 401
        assert request(previous)[0] == 401
        monkeypatch.delenv('IRIS_PEER_TLS_MODE')
        assert request(token)[0] == 409
        monkeypatch.setenv('IRIS_PEER_TLS_MODE', 'required')
        status, headers, body = request(token)
        assert status == 200, body
        assert 'no-store' in headers['Cache-Control']
        assert json.loads(body)['mode'] == 'required'
        assert request(token)[0] == 200
        assert request(token)[0] == 429
        store['devices']['switch-a']['catalog_token']['revoked'] = True
        secrets_store.save(store, sp)
        assert request(token)[0] == 401
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join()


def test_default_off_never_creates_identity_or_contacts_catalog(tmp_path, monkeypatch):
    monkeypatch.delenv('IRIS_PEER_TLS_MODE', raising=False)
    assert peer_tls_issuer.mode() == 'disabled'
    class Refuse:
        def enroll_peer_tls(self, *args):
            raise AssertionError('default mode must not enroll')
    cfg = {'device_id': 'switch', 'stage_dir': str(tmp_path / 'device')}
    assert peer.ensure(cfg, Refuse()) == 'bt-peer-tls=disabled\n'
    assert not (tmp_path / 'device').exists()


def test_renewal_rotates_certificate_but_keeps_local_key(enrollment, monkeypatch):
    cfg, client, issuer = enrollment
    before = peer.ensure(cfg, client)
    key = Path(cfg['stage_dir']) / 'peer-tls/node.key'
    key_bytes = key.read_bytes()
    original = peer._identity_valid
    monkeypatch.setattr(peer, '_identity_valid',
                        lambda cert, ca, key, device, seconds=0:
                        False if seconds else original(cert, ca, key, device))
    after = peer.ensure(cfg, client)
    assert after != before and client.calls == 2
    assert key.read_bytes() == key_bytes
    monkeypatch.setattr(peer, '_identity_valid', original)
    assert peer.ensure(cfg, client) == after
    assert client.calls == 2


def test_unexpected_ca_change_is_not_adopted(enrollment, monkeypatch, tmp_path):
    cfg, client, issuer = enrollment
    before = peer.ensure(cfg, client)
    replacement = peer_tls_issuer.Issuer(config=tmp_path / 'other-config',
                                        runtime=tmp_path / 'other-runtime')
    monkeypatch.setattr(client, 'enroll_peer_tls', replacement.issue)
    original = peer._identity_valid
    monkeypatch.setattr(peer, '_identity_valid',
                        lambda cert, ca, key, device, seconds=0:
                        False if seconds else original(cert, ca, key, device))
    assert peer.ensure(cfg, client) == before
    monkeypatch.setattr(peer, '_identity_valid', lambda *args, **kw: False)
    with pytest.raises(peer.PeerTLSError):
        peer.ensure(cfg, client)


def test_issuer_rejects_unsupported_csr_key(enrollment, tmp_path):
    cfg, client, issuer = enrollment
    csr = peer._openssl('req', '-new', '-newkey', 'ed25519', '-nodes',
                        '-subj', '/CN=ignored', '-keyout', tmp_path / 'key')
    with pytest.raises(peer_tls_issuer.InvalidCSR):
        issuer.issue(cfg['device_id'], csr.decode())


def test_origin_supervisor_replaces_child_on_certificate_rotation(enrollment, tmp_path):
    import os
    cfg, client, issuer = enrollment
    script = tmp_path / 'seed.sh'
    starts = tmp_path / 'starts'
    script.write_text('printf "%s\\n" "$$" >> "$IRIS_TEST_STARTS"\nexec sleep 120\n')
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen(['python3', str(root / 'peer_tls_seed.py'), str(script)],
                            env=dict(os.environ, IRIS_TEST_STARTS=str(starts)),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pids = []
    try:
        deadline = time.monotonic() + 15
        while not starts.exists() and time.monotonic() < deadline:
            assert proc.poll() is None
            time.sleep(.1)
        assert starts.exists()
        pids = [int(line) for line in starts.read_text().splitlines()]
        identity = Path(os.environ['IRIS_RUN']) / 'peer-origin/peer-tls'
        state = json.loads((identity / 'current.json').read_text())
        # Simulate invalid local certificate material: renewal must replace
        # the running child instead of keeping its old SSL context forever.
        (identity / state['generation'] / 'node.crt').write_text('invalid certificate\n')
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            pids = [int(line) for line in starts.read_text().splitlines()]
            if len(pids) == 2:
                break
            assert proc.poll() is None
            time.sleep(.1)
        assert len(pids) == 2
        with pytest.raises(ProcessLookupError):
            os.kill(pids[0], 0)
    finally:
        proc.terminate()
        assert proc.wait(timeout=20) == 0
        for pid in pids:
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)


def test_origin_supervisor_applies_mode_and_stops_on_invalid_settings(enrollment, tmp_path):
    import os
    import peer_tls_settings as settings
    settings.save('disabled')
    script = tmp_path / 'mode-seed.sh'
    starts = tmp_path / 'mode-starts'
    script.write_text('printf "%s %s\\n" "$IRIS_PEER_TLS_MODE" "$$" >> "$IRIS_TEST_STARTS"\nexec sleep 120\n')
    root = Path(__file__).resolve().parents[1]
    process = subprocess.Popen(['python3', str(root/'peer_tls_seed.py'), str(script)],
                               env=dict(os.environ, IRIS_TEST_STARTS=str(starts)),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def wait_for(state, mode):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None
            if settings.origin_status() == {'state': state, 'active_mode': mode}:
                return
            time.sleep(.1)
        pytest.fail('origin did not reach expected mode/state')
    try:
        wait_for('running', 'disabled')
        first = int(starts.read_text().splitlines()[0].split()[1])
        settings.settings_path().write_text('{broken')
        wait_for('error', None)
        with pytest.raises(ProcessLookupError):
            os.kill(first, 0)
        settings.save('required')
        wait_for('running', 'required')
        assert [x.split()[0] for x in starts.read_text().splitlines()] == ['disabled', 'required']
        settings.save('disabled')
        wait_for('running', 'disabled')
        rows = starts.read_text().splitlines()
        assert [x.split()[0] for x in rows] == ['disabled', 'required', 'disabled']
        for row in rows[:-1]:
            with pytest.raises(ProcessLookupError):
                os.kill(int(row.split()[1]), 0)
    finally:
        process.terminate()
        assert process.wait(timeout=20) == 0


@pytest.mark.parametrize('prefix', [b'subject=', b'subject= '])
def test_enrollment_accepts_openssl_subject_spacing(enrollment, monkeypatch, prefix):
    cfg, client, issuer = enrollment
    original = peer._openssl
    def legacy(*args, **kwargs):
        result = original(*args, **kwargs)
        if '-subject' in args:
            result = prefix + result.partition(b'=')[2].lstrip(b' ')
        return result
    monkeypatch.setattr(peer, '_openssl', legacy)
    assert 'bt-peer-tls=required' in peer.ensure(cfg, client)
    assert 'bt-peer-tls=required' in peer.ensure(cfg, client)


@pytest.mark.parametrize('subject', [b'subject= CN=other', b'subject= CN=abc,O=extra',
                                    b'subject= CN=abc+OU=extra', b'CN=abc'])
def test_subject_spacing_does_not_weaken_exact_identity(subject):
    assert not peer._subject_matches(subject, 'abc')
