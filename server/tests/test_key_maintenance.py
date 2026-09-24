# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable scheduler, public-only operations, overlap and authorization."""

import contextlib
import json
from pathlib import Path
import os
import subprocess
from types import SimpleNamespace
import uuid

import pytest

import key_maintenance as maintenance
import instruction_keys
import instruction_rotation
import secrets_store
import secretfs
import tier_auth
from test_gui_server import _serve_full, _auth, _req
from test_instruction_rotation import custody
from test_instruction_keys import NOW as SIGNING_NOW
from test_api_split import policy_tiers

NOW = 1790200000


def policy(family='device-instruction', **values):
    return dict(id=str(uuid.uuid4()), family=family,
        target='edge-01' if family == 'device-instruction' else 'deployment',
        enabled=True, next_at=NOW + 60, interval_days=14, window_minutes=30, **values)


def install(engine, value):
    engine.update(dict(action='save-policy', revision=engine.status()['revision'], policy=value))


def test_default_disabled_and_durable_deduplication(tmp_path):
    clock, called = [NOW], []
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=lambda job, save: (called.append(job['id']) or 'completed', 'public'))
    assert engine.status()['policies'] == []
    p = policy()
    install(engine, p)
    engine.tick()
    assert called == []
    clock[0] += 60
    engine.tick()
    engine.tick()
    restarted = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=engine.adapter)
    restarted.tick()
    assert len(called) == 1
    assert restarted.status()['jobs'][0]['state'] == 'completed'
    assert engine.path.stat().st_mode & 0o777 == 0o600


def test_missed_windows_do_not_replay_backlog(tmp_path):
    clock = [NOW]
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=lambda *_: pytest.fail('missed window executed'))
    p = policy()
    install(engine, p)
    clock[0] += 100 * maintenance.DAY
    engine.tick()
    state = engine.status()
    assert state['jobs'][0]['state'] == 'missed'
    assert state['policies'][0]['next_at'] > clock[0]
    clock[0] -= 1
    with pytest.raises(maintenance.MaintenanceError, match='backwards'):
        engine.tick()


def test_revision_guard_and_closed_fields(tmp_path):
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    p = policy()
    install(engine, p)
    with pytest.raises(maintenance.MaintenanceError, match='changed'):
        engine.update(dict(action='save-policy', revision=0, policy=p))
    for field, value in [('interval_days', True), ('interval_days', 7), ('enabled', 1), ('target', '../unsafe'), ('target', {}), ('next_at', -1)]:
        with pytest.raises(maintenance.MaintenanceError):
            engine.update(dict(action='save-policy', revision=1, policy=dict(p, **{field: value})))
    with pytest.raises(maintenance.MaintenanceError):
        engine.update(dict(action='save-policy', revision=1, policy=dict(p, command='no')))


def test_running_intent_never_retried_automatically(tmp_path):
    clock = [NOW]
    def crash(job, save):
        raise KeyboardInterrupt()
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=crash)
    install(engine, policy())
    clock[0] += 60
    with pytest.raises(KeyboardInterrupt):
        engine.tick()
    assert engine.status()['jobs'][0]['state'] == 'running'
    engine.adapter = lambda *_: pytest.fail('blind retry')
    engine.tick()
    assert engine.status()['jobs'][0]['state'] == 'intervention-required'


def test_errors_never_leak_into_public_history(tmp_path):
    clock = [NOW]
    def fail(*_):
        raise OSError('PRIVATE KEY token-secret /secret/file')
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=fail)
    install(engine, policy())
    clock[0] += 60
    engine.tick()
    assert 'token-secret' not in json.dumps(engine.status())
    assert 'PRIVATE KEY' not in engine.path.read_text()


@pytest.mark.parametrize('field,value', [('family', []), ('state', {}), ('policy_id', 'bad'), ('target', []), ('after', 'private')])
def test_corrupt_journal_fails_closed(tmp_path, field, value):
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    install(engine, policy('browser-tls'))
    engine.now = lambda: NOW + 60
    engine.tick()
    data = engine.load()
    data['jobs'][0][field] = value
    engine.save(data)
    with pytest.raises(maintenance.MaintenanceError):
        engine.tick()


def test_worker_health_reports_stale_clock_and_cancelled_signer(tmp_path, monkeypatch):
    clock = [NOW]
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0], adapter=lambda *_: ('approval-required', 'public'))
    assert engine.status()['worker'] == 'not-observed'
    install(engine, policy('online-signer'))
    clock[0] += 60
    engine.tick()
    job = engine.status()['jobs'][0]
    assert engine.status()['worker'] == 'observed'
    monkeypatch.setattr(instruction_rotation, 'status', lambda: dict(request_id=job['id'], state='cancelled'))
    engine.tick()
    assert engine.status()['jobs'][0]['state'] == 'cancelled'
    clock[0] += 91
    assert engine.status()['worker'] == 'stale'
    clock[0] = NOW
    assert engine.status()['worker'] == 'clock-error'


def test_management_crash_after_replacement_can_reconcile(tmp_path, monkeypatch):
    current, previous = tmp_path / 'current', tmp_path / 'previous'
    current.write_bytes(b'a' * 40)
    current.chmod(0o600)
    monkeypatch.setenv('IRIS_MANAGEMENT_API_TOKEN_FILE', str(current))
    monkeypatch.setenv('IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE', str(previous))
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    install(engine, policy('management-token'))
    cli = maintenance._cli('iris-management-token')
    original = cli._rotate_locked
    def crash():
        original()
        raise KeyboardInterrupt()
    monkeypatch.setattr(cli, '_rotate_locked', crash)
    monkeypatch.setattr(maintenance, '_cli', lambda _: cli)
    engine.now = lambda: NOW + 60
    with pytest.raises(KeyboardInterrupt):
        engine.tick()
    engine.tick()
    job = engine.status()['jobs'][0]
    assert job['state'] == 'intervention-required' and job['after'] is None
    engine.act(dict(action='reconcile-management', job_id=job['id'], confirm=True))
    assert engine.status()['jobs'][0]['state'] == 'verification-required'
    assert previous.exists()
    engine.act(dict(action='retire-management', job_id=job['id'], confirm=True), presented=tier_auth.load_pair(str(current))[0])
    assert not previous.exists()


def test_read_only_management_mount_does_not_leave_irrecoverable_job(tmp_path, monkeypatch):
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    install(engine, policy('management-token'))
    @contextlib.contextmanager
    def readonly():
        raise OSError('Read-only credential mount')
        yield
    monkeypatch.setattr(maintenance, '_cli', lambda _: SimpleNamespace(locked=readonly))
    engine.now = lambda: NOW + 60
    engine.tick()
    job = engine.status()['jobs'][0]
    assert job['state'] == 'intervention-required' and job['before'] is None
    result = engine.act(dict(action='reconcile-management', job_id=job['id'], confirm=True))
    assert result['jobs'][0]['state'] == 'cancelled'


def test_real_age_persistence_and_producer_restamp(custody, tmp_path, monkeypatch):
    import catalog
    import instruction_stamper as stamper
    import peer_policy
    from test_instruction_stamper import Fleet
    paths, _ = custody
    Path(paths.epoch).unlink()
    path, encrypted = tmp_path / 'secrets.json', tmp_path / 'secrets.age'
    monkeypatch.setenv('IRIS_SECRETS', str(path))
    monkeypatch.setenv('IRIS_SECRETS_ENC', str(encrypted))
    store = {'devices': {}, 'seeder': {}}
    secrets_store.mint(store, 'edge-01', 'instr_key', SIGNING_NOW - 15 * maintenance.DAY)
    secretfs.persist_store(store, str(path), recipients_csv=os.environ['IRIS_AGE_RECIPIENTS'], enc_path=str(encrypted))
    producer_paths = stamper.StamperPaths.from_env()
    fleet = Fleet([{'device_id': 'edge-01', 'platform': 'guestshell', 'registered_at': SIGNING_NOW - 20}])
    cat = catalog.CatalogStore(paths.state_dir)
    peer_policy.initialize(producer_paths.policy_authoritative, producer_paths.policy_lkg)
    marker = stamper.initialize_producer('initialize', paths=producer_paths, fleet=fleet, now=lambda: SIGNING_NOW)
    producer = stamper.InstructionStamper(paths=producer_paths, fleet=fleet, catalog_store=cat, now=lambda: SIGNING_NOW + 60)
    assert producer.stamp_device('edge-01') == 'updated'
    before = dict(cat._policies.get('edge-01')['instr'])
    # Supply the real producer's test fleet; the default adapter, lock and
    # callback still execute their actual encrypted-write and restamp paths.
    monkeypatch.setattr(stamper, 'InstructionStamper', lambda **_: producer)
    engine = maintenance.Maintenance(tmp_path, now=lambda: SIGNING_NOW)
    install(engine, dict(policy(), next_at=SIGNING_NOW + 60))
    engine.now = lambda: SIGNING_NOW + 60
    engine.tick()
    assert engine.status()['jobs'][0]['state'] == 'completed'
    after = cat._policies.get('edge-01')['instr']
    assert after['epoch'] == before['epoch'] == marker['epoch']
    assert after['instr_serial'] > before['instr_serial']
    assert after['key_id'] != before['key_id']
    plaintext = subprocess.check_output(['age', '-d', '-i', os.environ['IRIS_AGE_KEY_FILE'], str(encrypted)])
    persisted = json.loads(plaintext)
    assert persisted == secrets_store.load(str(path))
    assert persisted['devices']['edge-01']['instr_key']['key_id'] == after['key_id']


def test_rekey_refuses_pending_encrypted_signer(custody, tmp_path):
    paths, _ = custody
    instruction_rotation.prepare(str(uuid.uuid4()), paths=paths, now=SIGNING_NOW)
    before = Path(paths.encrypted_key).read_bytes()
    result = subprocess.run(['bash', str(Path(maintenance.__file__).with_name('iris-bootstrap')), '--rekey'], capture_output=True)
    assert result.returncode != 0
    assert b'pending' in result.stderr.lower() or b'rotation' in result.stderr.lower()
    assert Path(paths.encrypted_key).read_bytes() == before


def test_review_is_not_reported_as_rotation_and_does_not_block_other_policy(tmp_path):
    clock = [NOW]
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    install(engine, policy('device-tls'))
    install(engine, policy('offline-roots'))
    clock[0] += 60
    engine.tick()
    engine.tick()
    jobs = engine.status()['jobs']
    assert len(jobs) == 2 and all(j['state'] == 'review-required' for j in jobs)
    engine.act(dict(action='reviewed', job_id=jobs[0]['id'], confirm=True))
    assert engine.status()['jobs'][0]['state'] == 'reviewed'


def test_real_management_rotation_requires_new_credential_for_retirement(tmp_path, monkeypatch):
    clock = [NOW]
    current, previous = tmp_path / 'current.json', tmp_path / 'previous.json'
    original = b'a' * 64
    current.write_bytes(original)
    current.chmod(0o600)
    monkeypatch.setenv('IRIS_MANAGEMENT_API_TOKEN_FILE', str(current))
    monkeypatch.setenv('IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE', str(previous))
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    install(engine, policy('management-token'))
    clock[0] += 60
    engine.tick()
    new, old = tier_auth.load_pair(str(current), str(previous))
    assert old == original and new != original
    job = engine.status()['jobs'][0]
    assert job['state'] == 'verification-required'
    request = dict(action='retire-management', job_id=job['id'], confirm=True)
    for presented in (None, original, b'x' * 64):
        with pytest.raises(maintenance.MaintenanceError):
            engine.act(request, presented=presented)
        assert previous.exists()
    assert engine.act(request, presented=new)['jobs'][0]['state'] == 'completed'
    assert not previous.exists()
    assert new.decode() not in json.dumps(engine.status())
    assert engine.act(request, presented=new)['jobs'][0]['state'] == 'completed'


def test_existing_management_overlap_is_not_overwritten(tmp_path, monkeypatch):
    clock = [NOW]
    current, previous = tmp_path / 'current', tmp_path / 'previous'
    for path, value in [(current, b'a' * 64), (previous, b'b' * 64)]:
        path.write_bytes(value)
        path.chmod(0o600)
    monkeypatch.setenv('IRIS_MANAGEMENT_API_TOKEN_FILE', str(current))
    monkeypatch.setenv('IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE', str(previous))
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    install(engine, policy('management-token'))
    clock[0] += 60
    engine.tick()
    assert current.read_bytes() == b'a' * 64 and previous.read_bytes() == b'b' * 64
    assert engine.status()['jobs'][0]['state'] == 'intervention-required'


def test_device_retry_restamps_without_generating_another_key(tmp_path, monkeypatch):
    clock, attempts = [NOW], []
    path, encrypted = tmp_path / 'secrets.json', tmp_path / 'secrets.age'
    encrypted.write_bytes(b'fixture')
    store = {'devices': {}, 'seeder': {}}
    secrets_store.mint(store, 'edge-01', 'instr_key', NOW - 15 * maintenance.DAY)
    secrets_store.save(store, str(path))
    monkeypatch.setenv('IRIS_SECRETS', str(path))
    monkeypatch.setenv('IRIS_SECRETS_ENC', str(encrypted))
    monkeypatch.setenv('IRIS_AGE_RECIPIENTS', 'test-public-recipient')
    monkeypatch.setattr(secretfs, 'persist_store', lambda store, path, **kw: secrets_store.save(store, path))
    monkeypatch.setattr(maintenance.instruction_stamper, 'rotation_context', lambda *_: contextlib.nullcontext())
    def restamp(device, key_id):
        attempts.append(key_id)
        if len(attempts) == 1:
            raise OSError('interrupted restamp')
    original_cli = maintenance._cli
    monkeypatch.setattr(maintenance, '_cli', lambda name: SimpleNamespace(resolve_default_restamp=lambda: restamp,
        handoff_restamp=lambda callback, device, key_id: callback(device, key_id)) if name == 'iris-instr-key' else original_cli(name))
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    install(engine, policy())
    clock[0] += 60
    engine.tick()
    job = engine.status()['jobs'][0]
    assert job['state'] == 'intervention-required'
    before = path.read_bytes()
    engine.act(dict(action='retry', job_id=job['id'], confirm=True))
    assert attempts[0] == attempts[1]
    assert path.read_bytes() == before
    assert engine.status()['jobs'][0]['state'] == 'completed'


def test_online_prepare_resumes_only_same_operation(tmp_path, monkeypatch):
    clock, ids = [NOW], []
    state = {'request_id': None, 'state': 'idle'}
    def prepare(identity):
        ids.append(identity)
        state.update(request_id=identity, state='awaiting-approval')
    monkeypatch.setattr(instruction_rotation, 'prepare', prepare)
    monkeypatch.setattr(instruction_rotation, 'status', lambda: state)
    engine = maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    install(engine, policy('online-signer'))
    clock[0] += 60
    engine.tick()
    engine.tick()
    assert len(ids) == 1 and engine.status()['jobs'][0]['state'] == 'approval-required'
    state.update(request_id=ids[0], state='completed')
    engine.tick()
    assert engine.status()['jobs'][0]['state'] == 'completed'


def test_routes_require_session_csrf_and_preserve_revision(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_STATE', str(tmp_path))
    host, port, ctx, stop = _serve_full(tmp_path)
    endpoint = '/api/settings/key-maintenance'
    try:
        assert _req(host, port, 'GET', endpoint)[0] == 401
        assert _req(host, port, 'POST', endpoint, body={})[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', endpoint, body={}, headers={'Cookie': cookie})[0] == 403
        status, _, body = _req(host, port, 'GET', endpoint, headers={'Cookie': cookie})
        assert status == 200 and json.loads(body)['policies'] == []
        p = policy('offline-roots')
        p['enabled'] = False
        status, _, body = _req(host, port, 'POST', endpoint, body=dict(action='save-policy', revision=0, policy=p),
            headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert status == 200 and json.loads(body)['revision'] == 1
    finally:
        stop()


def test_console_to_management_contract(policy_tiers, tmp_path, monkeypatch):
    import jsonschema
    import openapi_contract
    monkeypatch.setenv('IRIS_STATE', str(tmp_path))
    request, _, _ = policy_tiers
    endpoint = '/settings/key-maintenance'
    for tier in ('console', 'management'):
        assert request(tier, 'GET', endpoint, authorized=False, match=False)[0] == 401
        assert request(tier, 'POST', endpoint, {}, authorized=False, match=False)[0] == 401
        status, headers, data = request(tier, 'GET', endpoint, match=False)
        assert status == 200 and 'no-store' in headers['Cache-Control']
        jsonschema.validate(data, openapi_contract._maintenance_schema())
    value = dict(policy('peer-ca'), enabled=False)
    status, _, data = request('console', 'POST', endpoint, dict(action='save-policy', revision=0, policy=value), match=False)
    assert status == 200 and data['revision'] == 1
    jsonschema.validate(data, openapi_contract._maintenance_schema())
    status, _, _ = request('console', 'POST', endpoint, dict(action='save-policy', revision=0, policy=value), match=False)
    assert status == 409


def test_active_policy_can_be_disabled_without_changing_operation(tmp_path):
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    install(engine, policy('peer-ca'))
    engine.now = lambda: NOW + 60
    engine.tick()
    data = engine.status()
    install(engine, dict(data['policies'][0], enabled=False))
    assert engine.status()['jobs'] == data['jobs']
    assert engine.status()['policies'][0]['enabled'] is False
    with pytest.raises(maintenance.MaintenanceError):
        install(engine, dict(data['policies'][0], enabled=False, interval_days=30))


def test_history_retention_never_removes_active_operation(tmp_path):
    engine = maintenance.Maintenance(tmp_path, now=lambda: NOW)
    install(engine, policy('peer-ca'))
    engine.now = lambda: NOW + 60
    engine.tick()
    data = engine.load()
    active = dict(data['jobs'][0])
    data['jobs'] += [dict(active, id=str(uuid.uuid4()), state='reviewed') for _ in range(255)]
    engine.save(data)
    install(engine, policy('browser-tls'))
    engine.tick()
    assert len(engine.status()['jobs']) == 256
    assert active in engine.status()['jobs']
