# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real age, OpenSSL and OpenSSH trust cutover and interruption tests."""

import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import pytest

import instruction_keys as keys
import secretfs
import trust_rotation as rotation
from test_instruction_keys import _key, _issue, _root_sign


@pytest.fixture
def environment(tmp_path, monkeypatch):
    identity = tmp_path / 'service.age'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
    for name, value in {'IRIS_AGE_KEY_FILE': identity, 'IRIS_AGE_RECIPIENTS': recipient,
                        'IRIS_CONFIG': tmp_path / 'config', 'IRIS_RUN': tmp_path / 'run',
                        'IRIS_STATE': tmp_path / 'state'}.items():
        monkeypatch.setenv(name, str(value))
    (tmp_path / 'config').mkdir(mode=0o700)
    (tmp_path / 'state').mkdir(mode=0o700)
    plain = tmp_path / 'secrets.json'
    plain.write_text('{"devices":{},"seeder":{}}')
    secretfs.encrypt_from(str(plain), str(tmp_path / 'config/secrets.json.age'), recipient)
    return tmp_path


def prepare(family='device-tls', **values):
    if family == 'device-tls':
        values = {'names': ['distribution.example', '127.0.0.1'], 'mode': 'self-signed', **values}
    return rotation.operate(dict(action='prepare', family=family, request_id=str(uuid.uuid4()), **values))


def test_device_tls_real_ciphertext_public_only(environment):
    record = prepare()
    assert record['state'] == 'approved'
    assert set(record) == set(rotation.PUBLIC)
    assert 'PRIVATE KEY' not in json.dumps(record)
    assert rotation.drain_status()['ready']
    result = rotation.apply_prepared('device-tls', record['request_id'])
    assert result['state'] == 'published'
    assert rotation.apply_prepared('device-tls', record['request_id']) == result
    private = subprocess.check_output(['age', '-d', '-i', os.environ['IRIS_AGE_KEY_FILE'], str(environment / 'config/tls/key.pem.age')])
    assert b'PRIVATE KEY' in private
    assert private.decode() not in rotation.journal_path('device-tls').read_text()
    assert rotation._load('device-tls')['outputs'] == {}
    assert rotation._load('device-tls')['candidate'] is None


def test_peer_issuer_replacement(environment):
    import peer_tls_issuer
    old = peer_tls_issuer.Issuer().prepare().read_bytes()
    record = prepare('peer-ca')
    assert record['state'] == 'approved'
    assert record['requires_package_rebuild'] is False
    rotation.apply_prepared('peer-ca', record['request_id'])
    runtime = environment / 'run/peer-tls/ca.pem'
    runtime.unlink()  # a recreated container has fresh tmpfs
    new = peer_tls_issuer.Issuer().prepare().read_bytes()
    assert new != old and record['certificate'].encode() in new


@pytest.mark.parametrize('boundary', [0, 1])
def test_device_cutover_recovery_each_write(environment, monkeypatch, boundary):
    record = prepare()
    target = list(rotation._targets(rotation._load('device-tls')).values())[boundary]
    original = keys._atomic_write
    def interrupted(path, *args, **kwargs):
        if Path(path) == target:
            raise OSError('injected interruption')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(keys, '_atomic_write', interrupted)
    with pytest.raises(OSError):
        rotation.apply_prepared('device-tls', record['request_id'])
    assert rotation.status('device-tls')['state'] == 'committing'
    with pytest.raises(ValueError, match='admitted'):
        rotation.operate(dict(family='device-tls', action='cancel', request_id=record['request_id']))
    monkeypatch.setattr(keys, '_atomic_write', original)
    assert rotation.apply_prepared('device-tls', record['request_id'])['state'] == 'published'


def test_device_rejects_concurrent_change(environment):
    record = prepare()
    target = environment / 'config/tls/crt.pem'
    target.parent.mkdir(exist_ok=True)
    target.write_text('changed outside request')
    with pytest.raises(ValueError, match='outside'):
        rotation.apply_prepared('device-tls', record['request_id'])
    assert target.read_text() == 'changed outside request'


def test_orphan_device_secrets_block_drain(environment):
    plain = environment / 'secrets.json'
    plain.write_text('{"devices":{"forgotten":{"catalog_token":{"revoked":true}}},"seeder":{}}')
    secretfs.encrypt_from(str(plain), str(environment / 'config/secrets.json.age'), os.environ['IRIS_AGE_RECIPIENTS'])
    assert rotation.drain_status()['blocked_device_ids'] == ['forgotten']
    record = prepare()
    with pytest.raises(ValueError, match='Remove all'):
        rotation.apply_prepared('device-tls', record['request_id'])


def setup_roots(environment, *, krl=None):
    paths = keys.InstructionPaths.from_env()
    roots = Path(paths.roots_dir)
    roots.mkdir(parents=True, mode=0o700)
    for name in ('root-a', 'root-b'):
        old = _key(environment / ('old-' + name))
        (roots / (name + '.pub')).write_bytes(Path(str(old) + '.pub').read_bytes())
    keys.generate_online_key(paths, os.environ['IRIS_AGE_RECIPIENTS'], identity_file=os.environ['IRIS_AGE_KEY_FILE'])
    Path(paths.epoch).write_text('{"epoch": 37, "sequence": 81}')
    if krl is not None:
        payload = keys.build_keylist_payload(krl, keylist_seq=23, issued_at=int(time.time()), signer_root_id='root-a')
        artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, environment / 'old-root-a'))
        keys.install_keylist(paths, artifact, keys.discover_roots(paths))
    new = {name: _key(environment / ('new-' + name)) for name in ('root-a', 'root-b')}
    record = prepare('instruction-roots', roots={name: Path(str(path) + '.pub').read_text() for name, path in new.items()}, keylist_signer='root-a')
    return paths, new, record


def approve_roots(paths, new, record, *, keylist=None):
    now = int(time.time())
    certificate = _issue(new['root-a'], Path(paths.public_key), now - 60, now - 60 + 30 * 86400).read_text()
    payload = record['keylist_payload'].encode()
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-a']))
    return rotation.operate(dict(family='instruction-roots', action='approve', request_id=record['request_id'],
                                 certificate=certificate, keylist=artifact.decode() if keylist is None else keylist))


def test_root_transition_preserves_epoch_and_has_real_approval(environment):
    paths, new, record = setup_roots(environment)
    assert record['state'] == 'awaiting-approval'
    assert record['requires_package_rebuild']
    epoch = Path(paths.epoch).read_bytes()
    approved = approve_roots(paths, new, record)
    assert approved['state'] == 'approved'
    rotation.apply_prepared('instruction-roots', record['request_id'])
    assert Path(paths.epoch).read_bytes() == epoch
    roots = keys.discover_roots(paths)
    assert roots == rotation._roots(record['roots'])
    assert keys.validate_online_certificate(paths, paths.certificate, roots)['root_id'] == 'root-a'
    assert keys.read_keylist_snapshot(paths)['keylist_seq'] == 1


@pytest.mark.parametrize('boundary', range(5))
def test_root_transition_every_publication_boundary(environment, monkeypatch, boundary):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    target = list(rotation._targets(rotation._load('instruction-roots')).values())[boundary]
    original = keys._atomic_write
    def interrupted(path, *args, **kwargs):
        if Path(path) == target:
            raise OSError('interrupted')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(keys, '_atomic_write', interrupted)
    with pytest.raises(OSError):
        rotation.apply_prepared('instruction-roots', record['request_id'])
    monkeypatch.setattr(keys, '_atomic_write', original)
    assert rotation.apply_prepared('instruction-roots', record['request_id'])['state'] == 'published'
    assert keys.validate_online_certificate(paths, paths.certificate, keys.discover_roots(paths))['root_id'] == 'root-a'


def test_root_request_rejects_private_key_and_changed_krl(environment):
    paths, new, record = setup_roots(environment)
    payload = keys.build_keylist_payload(b'', keylist_seq=99, issued_at=int(time.time()), signer_root_id='root-a')
    changed = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-a']))
    with pytest.raises(ValueError, match='exact'):
        approve_roots(paths, new, record, keylist=changed.decode())
    with pytest.raises(ValueError, match='public roots'):
        rotation._roots({'root-a': new['root-a'].read_text(), 'root-b': record['roots']['root-b']})


def test_epoch_change_blocks_root_cutover(environment):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    Path(paths.epoch).write_text('{"epoch": 38}')
    with pytest.raises(ValueError, match='epoch'):
        rotation.apply_prepared('instruction-roots', record['request_id'])


def test_root_transition_cannot_drop_revoked_keys(environment):
    victim = _key(environment / 'revoked-device')
    revoked = environment / 'revoked.krl'
    subprocess.run(['ssh-keygen', '-k', '-f', str(revoked), str(victim) + '.pub'], check=True, capture_output=True)
    original_krl = revoked.read_bytes()
    paths, new, record = setup_roots(environment, krl=original_krl)
    metadata, requested_krl = keys._parse_keylist_payload(record['keylist_payload'].encode())
    assert requested_krl == original_krl
    assert metadata['keylist_seq'] == 24
    approve_roots(paths, new, record)
    rotation.apply_prepared('instruction-roots', record['request_id'])
    installed = keys.parse_keylist_artifact(Path(paths.keylist_current).read_bytes())
    assert installed['krl'] == original_krl


@pytest.mark.parametrize('state,ready', [('active', False), ('applying', False), ('unknown', False),
                                       ('abandoned', False), ('superseded', False), ('removed', True)])
def test_drain_requires_positive_removal(environment, monkeypatch, state, ready):
    import deployment_records
    monkeypatch.setattr(deployment_records.DeploymentRecordStore, 'list', lambda self, strict: [
        {'device_id': 'd1', 'state': state, 'timestamps': {'finished_at': 200}}])
    assert rotation.drain_status()['ready'] is ready


def test_new_credential_after_removal_is_not_drain_proof(environment, monkeypatch):
    import deployment_records
    monkeypatch.setattr(deployment_records.DeploymentRecordStore, 'list', lambda self, strict: [
        {'device_id': 'd1', 'state': 'removed', 'timestamps': {'finished_at': 200}}])
    plain = environment / 'secrets.json'
    plain.write_text('{"devices":{"d1":{"catalog_token":{"created_at":201,"revoked":false}}},"seeder":{}}')
    secretfs.encrypt_from(str(plain), str(environment / 'config/secrets.json.age'), os.environ['IRIS_AGE_RECIPIENTS'])
    assert rotation.drain_status()['blocked_device_ids'] == ['d1']


def test_independent_second_root_attestation_is_real_and_fresh(environment, monkeypatch):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    first = rotation.apply_prepared('instruction-roots', record['request_id'])
    assert first['attested_root_ids'] == ['root-a']
    request = dict(family='instruction-roots', action='attestation-request', request_id=record['request_id'], root_id='root-b')
    ceremony = rotation.operate(request)
    assert rotation.operate(request) == ceremony
    payload = ceremony['payload'].encode()
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-b']))
    approval = dict(family='instruction-roots', action='attestation-apply', request_id=record['request_id'],
                    root_id='root-b', keylist=artifact.decode())
    result = rotation.operate(approval)
    assert result['attested_root_ids'] == ['root-a', 'root-b']
    assert rotation.operate(approval)['attested_root_ids'] == ['root-a', 'root-b']
    assert keys.read_keylist_snapshot(paths)['keylist_seq'] == 2
    # Freshness comes from actual signed issue times, never the UI request or a
    # cached success badge. Replaying the approval cannot extend that time.
    monkeypatch.setattr(rotation.time, 'time', lambda: record['created_at'] + 181 * 86400)
    assert rotation.status('instruction-roots')['attested_root_ids'] == []


def test_second_root_attestation_rejects_wrong_signer_and_preserves_krl(environment):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    rotation.apply_prepared('instruction-roots', record['request_id'])
    request = rotation.operate(dict(family='instruction-roots', action='attestation-request',
                                    request_id=record['request_id'], root_id='root-b'))
    payload = request['payload'].encode()
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-a']))
    with pytest.raises(keys.InstructionKeyError, match='claimed root'):
        rotation.operate(dict(family='instruction-roots', action='attestation-apply', request_id=record['request_id'],
                              root_id='root-b', keylist=artifact.decode()))
    assert rotation.status('instruction-roots')['attested_root_ids'] == ['root-a']
    assert keys.read_keylist_snapshot(paths)['keylist_seq'] == 1


def test_second_root_attestation_repairs_metadata_interruption(environment, monkeypatch):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    rotation.apply_prepared('instruction-roots', record['request_id'])
    request = rotation.operate(dict(family='instruction-roots', action='attestation-request',
                                    request_id=record['request_id'], root_id='root-b'))
    payload = request['payload'].encode()
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-b']))
    approval = dict(family='instruction-roots', action='attestation-apply', request_id=record['request_id'],
                    root_id='root-b', keylist=artifact.decode())
    original = keys._atomic_write
    def interrupted(path, *args, **kwargs):
        if Path(path) == Path(paths.keylist_state):
            raise OSError('interrupted metadata write')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(keys, '_atomic_write', interrupted)
    with pytest.raises(OSError):
        rotation.operate(approval)
    monkeypatch.setattr(keys, '_atomic_write', original)
    assert rotation.operate(approval)['attested_root_ids'] == ['root-a', 'root-b']


def test_second_root_attestation_refuses_concurrent_keylist(environment):
    paths, new, record = setup_roots(environment)
    approve_roots(paths, new, record)
    rotation.apply_prepared('instruction-roots', record['request_id'])
    request = rotation.operate(dict(family='instruction-roots', action='attestation-request',
                                    request_id=record['request_id'], root_id='root-b'))
    prepared = request['payload'].encode()
    approval = keys.assemble_keylist_artifact(prepared, _root_sign(prepared, new['root-b']))
    other = keys.build_keylist_payload(b'', keylist_seq=2, issued_at=int(time.time()), signer_root_id='root-a')
    other_artifact = keys.assemble_keylist_artifact(other, _root_sign(other, new['root-a']))
    keys.install_keylist(paths, other_artifact, keys.discover_roots(paths))
    with pytest.raises(rotation.RotationError, match='Keylist changed'):
        rotation.operate(dict(family='instruction-roots', action='attestation-apply', request_id=record['request_id'],
                              root_id='root-b', keylist=approval.decode()))
    assert Path(paths.keylist_current).read_bytes() == other_artifact


@pytest.mark.parametrize('family', ['device-tls', 'peer-ca'])
def test_bootstrap_rekey_refuses_pending_trust_candidate(environment, family):
    prepare(family)
    before = (environment / 'config/secrets.json.age').read_bytes()
    result = subprocess.run(['bash', str(Path(rotation.__file__).with_name('iris-bootstrap')), '--rekey'],
                            env=dict(os.environ, IRIS_HOST_IP='127.0.0.1'), capture_output=True)
    assert result.returncode != 0
    assert b'pending signer or TLS' in result.stderr
    assert (environment / 'config/secrets.json.age').read_bytes() == before


@pytest.mark.parametrize('kind', ['corrupt', 'symlink'])
def test_bootstrap_rekey_refuses_corrupt_or_symlink_trust_journal(environment, kind):
    path = rotation.journal_path('peer-ca')
    path.parent.mkdir()
    if kind == 'corrupt':
        path.write_text('broken')
    else:
        path.symlink_to(environment / 'secrets.json')
    before = (environment / 'config/secrets.json.age').read_bytes()
    result = subprocess.run(['bash', str(Path(rotation.__file__).with_name('iris-bootstrap')), '--rekey'],
                            env=dict(os.environ, IRIS_HOST_IP='127.0.0.1'), capture_output=True)
    assert result.returncode != 0
    assert (environment / 'config/secrets.json.age').read_bytes() == before


@pytest.mark.parametrize('kind', ['unknown', 'symlink'])
def test_bootstrap_rekey_refuses_unknown_or_symlink_ciphertext_before_any_write(environment, kind):
    directory = environment / 'config/tls'
    directory.mkdir()
    if kind == 'unknown':
        (directory / 'unknown-key.age').write_bytes(b'unknown custody')
    else:
        (directory / 'management-key.pem.age').symlink_to(environment / 'config/secrets.json.age')
    before = (environment / 'config/secrets.json.age').read_bytes()
    result = subprocess.run(['bash', str(Path(rotation.__file__).with_name('iris-bootstrap')), '--rekey'],
                            env=dict(os.environ, IRIS_HOST_IP='127.0.0.1'), capture_output=True)
    assert result.returncode != 0
    assert (environment / 'config/secrets.json.age').read_bytes() == before


@pytest.mark.parametrize('state', ['idle', 'cancelled'])
def test_existing_roots_initial_and_quarterly_attestation_need_no_root_replacement(environment, state):
    paths, _, replacement = setup_roots(environment)
    rotation.operate(dict(family='instruction-roots', action='cancel', request_id=replacement['request_id']))
    if state == 'idle':
        rotation.journal_path('instruction-roots').unlink()
    initial = rotation.status('instruction-roots')
    assert initial['state'] == state and initial['attested_root_ids'] == []
    assert initial['roots'] == {name: public.decode() for name, public in keys.discover_roots(paths).items()}
    for sequence, root_id in enumerate(('root-a', 'root-b', 'root-a'), 1):
        request_id = str(uuid.uuid4())
        ceremony = rotation.operate(dict(family='instruction-roots', action='attestation-request',
                                         request_id=request_id, root_id=root_id))
        refreshed = rotation.status('instruction-roots')
        assert refreshed['state'] == state
        assert refreshed['attestation_request_id'] == request_id and refreshed['attestation_root_id'] == root_id
        payload = ceremony['payload'].encode()
        artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, environment / ('old-' + root_id)))
        completed = rotation.operate(dict(family='instruction-roots', action='attestation-apply',
            request_id=request_id, root_id=root_id, keylist=artifact.decode()))
        assert completed['state'] == state
        assert completed['attested_root_ids'] == (['root-a'] if sequence == 1 else ['root-a', 'root-b'])
        assert keys.read_keylist_snapshot(paths)['keylist_seq'] == sequence
    assert rotation.journal_path('instruction-roots').exists() is (state == 'cancelled')


def test_stopped_admission_never_changes_durable_approval(environment):
    record = prepare()
    before = rotation.journal_path('device-tls').read_bytes()
    assert rotation.check_prepared('device-tls', record['request_id'])['ready']
    assert rotation.journal_path('device-tls').read_bytes() == before
    assert not (environment / 'config/tls/key.pem.age').exists()
