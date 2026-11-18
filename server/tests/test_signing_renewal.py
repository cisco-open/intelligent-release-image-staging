# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Renewal retries use real certificates and retain the installed signing key."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

import certificate_lifecycle
import instruction_keys as keys
import signing_renewal as evidence
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import signing_renewal as host
from iris_installer.state import InstallError
from test_certificate_lifecycle import custody
from test_instruction_keys import _issue, NOW

DAY = 86400


def enrollment(paths):
    current = evidence.snapshot(paths=paths)
    return {'enabled': True, 'state': 'waiting', 'checked_at': NOW,
            'public_key_sha256': current['request']['public_key_sha256'],
            'root_public': host.normalize_public(current['roots']['root-a']),
            'pending': None, 'pending_created_at': None, 'last_success_at': None}


def test_daily_schedule_with_startup_and_failure_retry():
    files = host.unit_files({'instance_id': 'sample', 'runtime': '/safe/runtime', 'state_dir': '/safe/state'})
    timer = files['iris-signing-renewal-sample.timer'].decode()
    service = files['iris-signing-renewal-sample.service'].decode()
    assert 'OnCalendar=*-*-* 03:00:00 UTC' in timer
    assert 'Persistent=true' in timer and 'OnBootSec=2min' in timer
    assert 'Restart=on-failure' in service and 'RestartSec=1h' in service
    assert '15min' not in service


def test_due_renewal_preserves_identity_and_reconciles_lost_reply(custody):
    paths, roots = custody
    now = NOW + 20 * DAY
    before = {p: Path(p).read_bytes() for p in (paths.encrypted_key, paths.public_key, paths.runtime_key)}
    record = enrollment(paths)
    saves, signed = [], []
    def save(value): saves.append(copy.deepcopy(value))
    def sign(public):
        signed.append(public)
        return _issue(roots['root-a'], Path(paths.public_key), now, now + 30 * DAY).read_text()
    def apply(payload):
        certificate_lifecycle.renew(payload, paths=paths, now=now)
        raise InstallError('Simulated lost reply after committed import')
    with pytest.raises(InstallError, match='lost reply'):
        host.cycle(record, lambda: evidence.snapshot(paths=paths), sign, apply, save, now=now)
    # The durable approval was written before import; a restart starts here.
    resumed = saves[-1]
    assert resumed['pending'] and len(signed) == 1
    def forbidden(*args): pytest.fail('A committed approval must not be re-signed or imported')
    host.cycle(resumed, lambda: evidence.snapshot(paths=paths), forbidden, forbidden, save, now=now + 3600)
    assert resumed['pending'] is None and resumed['state'] == 'renewed'
    assert resumed['refuse_at'] == now + 23 * DAY
    assert all(Path(p).read_bytes() == data for p, data in before.items())


def test_before_due_does_not_use_root(custody):
    paths, _ = custody
    record = enrollment(paths)
    def forbidden(*args): pytest.fail('No signing before the renewal window')
    host.cycle(record, lambda: evidence.snapshot(paths=paths), forbidden, forbidden, lambda _: None, now=NOW)
    assert record['state'] == 'waiting'


@pytest.mark.parametrize('change', ['online-key', 'root'])
def test_changed_identity_requires_explicit_reenrollment(custody, change):
    paths, _ = custody
    record = enrollment(paths)
    current = evidence.snapshot(paths=paths)
    if change == 'online-key': current['request']['public_key_sha256'] = '0' * 64
    else: current['roots'] = {}
    def forbidden(*args): pytest.fail('Changed identity must never be signed')
    with pytest.raises(InstallError, match='identity changed'):
        host.cycle(record, lambda: current, forbidden, forbidden, lambda _: None, now=NOW + 20 * DAY)
    assert record['state'] == 'review-required'
    with pytest.raises(InstallError, match='enable renewal again'):
        host.cycle(record, lambda: evidence.snapshot(paths=paths), forbidden, forbidden, lambda _: None, now=NOW + 20 * DAY)


def test_pending_import_retry_reuses_approval(custody):
    paths, roots = custody
    record = enrollment(paths)
    now = NOW + 20 * DAY
    cert = _issue(roots['root-a'], Path(paths.public_key), now, now + 30 * DAY).read_text()
    request = keys.online_renewal_request(paths)
    record['pending'] = {key: request[key] for key in ('public_key_sha256', 'certificate_sha256')}
    record['pending']['certificate'] = cert
    record['pending_created_at'] = now
    def forbidden(*args): pytest.fail('Pending approval must not be replaced')
    host.cycle(record, lambda: evidence.snapshot(paths=paths), forbidden,
               lambda payload: certificate_lifecycle.renew(payload, paths=paths, now=now), lambda _: None, now=now)
    assert record['pending'] is None and record['state'] == 'renewed'
    assert Path(paths.certificate).read_text() == cert


def test_manual_renewal_supersedes_stale_pending_approval(custody):
    paths, roots = custody
    record = enrollment(paths)
    now = NOW + 20 * DAY
    request = keys.online_renewal_request(paths)
    record['pending'] = {key: request[key] for key in ('public_key_sha256', 'certificate_sha256')}
    record['pending']['certificate'] = 'obsolete public approval'
    record['pending_created_at'] = now
    fresh = dict(record['pending'], certificate=_issue(roots['root-a'], Path(paths.public_key), now, now + 30 * DAY).read_text())
    certificate_lifecycle.renew(fresh, paths=paths, now=now)
    def forbidden(*args): pytest.fail('Respect the certificate renewed by the operator')
    host.cycle(record, lambda: evidence.snapshot(paths=paths), forbidden, forbidden, lambda _: None, now=now)
    assert record['pending'] is None and record['state'] == 'waiting'


def test_renewal_status_stale_and_failure_evidence(custody):
    paths, _ = custody
    record = dict(enrollment(paths), checked_at=NOW, state='error')
    evidence.publish_status(host.public_status(record), paths=paths)
    assert evidence.status(paths=paths, now=NOW + 25 * 3600)['observed']
    assert not evidence.status(paths=paths, now=NOW + 27 * 3600)['observed']
    assert not evidence.status(paths=paths, now=NOW - 1)['observed']
    assert evidence.status(paths=paths, now=NOW)['state'] == 'error'
    with pytest.raises(keys.InstructionKeyError):
        evidence.publish_status(dict(host.public_status(record), root_key='/private'), paths=paths)


def test_readiness_requires_fresh_producer_and_signing(custody, monkeypatch):
    paths, _ = custody
    monkeypatch.setattr(keys, 'read_status_file', lambda *a, **k: {'enabled': True, 'signing_refused': False, 'state': 'keylist_missing'})
    path = Path(paths.state_dir) / 'instruction-stamper-status.json'
    path.write_text(json.dumps({'state': 'ok', 'updated_at': NOW, 'counts': {'failed': 0}, 'producer_ready': True}))
    assert evidence.readiness(paths=paths, now=NOW)['ready']
    assert not evidence.readiness(paths=paths, now=NOW + 181)['ready']
    monkeypatch.setattr(keys, 'read_status_file', lambda *a, **k: {'enabled': True, 'signing_refused': True, 'state': 'signing_refused'})
    result = evidence.readiness(paths=paths, now=NOW)
    assert not result['ready'] and result['producer_ready']


def test_pinned_holder_runtime_can_renew_with_existing_automatic_root(tmp_path, monkeypatch, packaged_askpass):
    import os
    from iris_installer import automatic_keys, managed_worker
    root = automatic_keys.create_root('root-a', tmp_path / 'holder' / 'root-a').with_suffix('')
    monkeypatch.setattr(host, 'RUNTIME', tmp_path / 'runtime')
    monkeypatch.setattr(managed_worker, '_path', lambda path: path)
    previous_umask = os.umask(0o077)
    try:
        runtime = host.install_runtime('fixture')
    finally:
        os.umask(previous_umask)
    for directory in (host.RUNTIME, host.RUNTIME/'fixture', Path(runtime), Path(runtime)/'iris_installer'):
        assert directory.stat().st_mode & 0o777 == 0o755
    assert (Path(runtime) / 'iris_installer/automatic_askpass.py').stat().st_mode & 0o111
    record = {'root_key': str(root), 'holder_uid': os.getuid(), 'runtime': runtime}
    public = host.holder(record)['public']
    record['root_public'] = public
    certificate = host.holder(record, public)['certificate']
    assert certificate.startswith('ssh-ed25519-cert-v01@openssh.com ')
    record['root_public'] = public.replace('ssh-ed25519', 'different')
    with pytest.raises(InstallError): host.holder(record, public)


from test_installer_local_setup import packaged_askpass


@pytest.mark.parametrize('committed', [False, True])
def test_long_outage_does_not_replay_expired_approval_or_delay_renewal(custody, committed):
    paths, roots = custody
    first = NOW + 20 * DAY
    later = first + 25 * DAY
    record = enrollment(paths)
    request = keys.online_renewal_request(paths)
    old = _issue(roots['root-a'], Path(paths.public_key), first, first + 30 * DAY).read_text()
    pending = {key: request[key] for key in ('public_key_sha256', 'certificate_sha256')}
    pending['certificate'] = old
    record.update(pending=pending, pending_created_at=first)
    if committed:
        certificate_lifecycle.renew(pending, paths=paths, now=first)
    signed = []
    def sign(public):
        signed.append(public)
        return _issue(roots['root-a'], Path(paths.public_key), later, later + 30 * DAY).read_text()
    host.cycle(record, lambda: evidence.snapshot(paths=paths), sign,
               lambda payload: certificate_lifecycle.renew(payload, paths=paths, now=later), lambda _: None, now=later)
    assert len(signed) == 1 and record['pending'] is None
    assert record['expires_at'] == later + 30 * DAY


def test_installer_does_not_report_ready_on_signing_failure(monkeypatch):
    from iris_installer.deploy import DockerInstall
    install = object.__new__(DockerInstall)
    install.python = lambda _code: b'{"ready": false, "signing_ready": false, "producer_ready": true}'
    with pytest.raises(InstallError, match='before onboarding'):
        install.verify_signing_ready()


def test_overview_warns_before_signing_cutoff_when_renewal_checks_are_stale(custody, monkeypatch):
    paths, _ = custody
    monkeypatch.setattr(evidence, 'readiness', lambda **kw: {'signing_ready': True, 'producer_ready': True})
    record = dict(enrollment(paths), checked_at=NOW - 27 * 3600)
    evidence.publish_status(host.public_status(record), paths=paths)
    warning = evidence.attention(paths=paths, now=NOW)
    assert warning['href'] == '#settings/certificates'
    assert 'before the signing cutoff' in warning['message']


def test_enable_starts_timer_only_after_releasing_installation_lock(custody, tmp_path, monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from iris_installer import deploy, managed_worker
    paths, _ = custody
    current = evidence.snapshot(paths=paths)
    state = tmp_path / 'installation'; state.mkdir()
    units = tmp_path / 'units'; units.mkdir()
    root = tmp_path / 'existing-root'; root.write_text('fixture path; holder mocked')
    identifier = '11111111-1111-4111-8111-111111111111'
    locked = [False]
    class Journal:
        directory = state
        document = {'id': identifier}
        def __init__(self, _path): pass
        @contextmanager
        def locked(self, **kw):
            locked[0] = True
            try: yield self
            finally: locked[0] = False
    install = SimpleNamespace(verify_signing_ownership=lambda: None, source=tmp_path/'source', config={})
    commands = []
    def command(args):
        commands.append(args)
        if args[:2] == ['systemctl', 'start']:
            assert not locked[0], 'Immediate timer trigger must be able to lock the installation'
    monkeypatch.setattr(host, 'Journal', Journal)
    monkeypatch.setattr(deploy, 'installation', lambda _j: install)
    monkeypatch.setattr(managed_worker, '_root', lambda: None)
    monkeypatch.setattr(managed_worker, 'command', command)
    monkeypatch.setattr(host, 'UNITS', units)
    monkeypatch.setattr(host, 'install_runtime', lambda _: '/root-owned/runtime')
    monkeypatch.setattr(host, 'holder', lambda _r: {'public': current['roots']['root-a']})
    monkeypatch.setattr(host.time, 'time', lambda: NOW)
    monkeypatch.setattr(host, 'server', lambda _i, action, payload=None: current if action == 'snapshot' else {})
    host.operate(SimpleNamespace(action='enable', state_dir=state, root_key=root))
    assert ['systemctl', 'enable', 'iris-signing-renewal-' + identifier + '.timer'] in commands
    assert commands[-1] == ['systemctl', 'start', 'iris-signing-renewal-' + identifier + '.timer']


def test_readiness_crosses_cutoff_between_custody_refreshes(custody):
    paths, _ = custody
    cutoff = NOW - 3600 + 23 * DAY
    keys.refresh_custody_status(paths, now=cutoff - 1)
    producer = Path(paths.state_dir) / 'instruction-stamper-status.json'
    producer.write_text(json.dumps({'updated_at': cutoff, 'producer_ready': True}))
    # A float clock is normal in the production HTTP handler.
    assert evidence.readiness(paths=paths, now=float(cutoff - 1))['signing_ready']
    assert not evidence.readiness(paths=paths, now=float(cutoff))['signing_ready']


def test_default_overview_clock_uses_integer_signing_status(custody, monkeypatch):
    import time
    from types import SimpleNamespace
    import management_api
    paths, roots = custody
    now = int(time.time())
    payload = keys.online_renewal_request(paths)
    payload.pop('public_key')
    payload['certificate'] = _issue(roots['root-a'], Path(paths.public_key), now, now + 30*DAY).read_text()
    certificate_lifecycle.renew(payload, paths=paths, now=now)
    keys.refresh_custody_status(paths, now=now)
    (Path(paths.state_dir)/'instruction-stamper-status.json').write_text(json.dumps(
        {'updated_at': now, 'producer_ready': True, 'state': 'degraded', 'counts': {'failed': 1}}))
    monkeypatch.setattr(management_api, '_ConsoleServer', lambda address, handler:
                        SimpleNamespace(RequestHandlerClass=handler))
    server = management_api.make_server('127.0.0.1', 0, SimpleNamespace())
    handler = object.__new__(server.RequestHandlerClass)
    monkeypatch.setattr(handler, '_staging_view', lambda: [])
    assert handler._overview()['signing_attention'] is None


def test_split_signing_ownership_does_not_contact_console(monkeypatch):
    from iris_installer.deploy import DockerInstall
    from iris_installer.split_deploy import SplitDockerInstall
    install = object.__new__(SplitDockerInstall)
    checked = []
    monkeypatch.setattr(DockerInstall, 'verify_resource_ownership', lambda self: checked.append('local'))
    install.remote = lambda *_a, **_k: pytest.fail('Console outage must not prevent signer renewal')
    install.verify_signing_ownership()
    assert checked == ['local']


def test_disable_stops_both_units_when_runtime_is_unavailable(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from iris_installer import deploy, managed_worker
    record = {'instance_id': 'fixture', 'runtime': '/safe/runtime', 'state_dir': str(tmp_path),
              'enabled': True, 'state': 'waiting'}
    units = tmp_path / 'units'; units.mkdir()
    monkeypatch.setattr(host, 'UNITS', units)
    monkeypatch.setattr(host, 'checked_record', lambda *a: record)
    for name, content in host.unit_files(record).items():
        (units/name).write_bytes(content)
    monkeypatch.setattr(managed_worker, '_file', lambda path, **kw: path.read_bytes())
    calls = []
    monkeypatch.setattr(managed_worker, 'command', lambda args: calls.append(args))
    def offline(_journal): raise InstallError('Docker/Kubernetes unavailable')
    monkeypatch.setattr(deploy, 'installation', offline)
    result = host.disable(SimpleNamespace(directory=tmp_path, document={'id': 'fixture'}))
    assert result['enabled'] is False and result['state'] == 'disabled'
    assert ['systemctl', 'disable', '--now', 'iris-signing-renewal-fixture.timer'] in calls
    assert ['systemctl', 'stop', 'iris-signing-renewal-fixture.service'] in calls
    assert json.loads((tmp_path/host.RECORD).read_text())['enabled'] is False
