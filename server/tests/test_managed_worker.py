# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Disposable host filesystem tests; never install a real systemd service."""

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import threading
from types import SimpleNamespace
import uuid

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools'))
from iris_installer import managed_worker as managed
from iris_installer.state import InstallError, atomic_write
REAL_PROBE = managed._probe


@pytest.fixture
def host(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('root-only service custody; run this test with sudo in a disposable test directory')
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    instance = str(uuid.uuid4())
    config = {'target': 'docker', 'instance': 'iris-test', 'host': '192.0.2.10',
              'console_bind': '127.0.0.1', 'console_port': 18080,
              'recovery_recipient': 'age1' + 'q' * 58, 'peer_tls': 'required'}
    installation = {'schema': 1, 'id': instance, 'config': config, 'completed': {},
                    'source_manifest': {}, 'root_digests': {}, 'state': 'PRODUCTION_REVIEW'}
    atomic_write(state / 'installation.json', json.dumps(installation).encode())
    units = tmp_path / 'units'
    units.mkdir(mode=0o700)
    monkeypatch.setattr(managed, 'UNIT_DIRECTORY', units)
    monkeypatch.setattr(managed, 'BACKUP_ROOT', tmp_path / 'backups')
    monkeypatch.setattr(managed, 'RECOVERY_ROOT', tmp_path / 'recovery')
    monkeypatch.setattr(managed, 'RECOVERY_ACCESS_ROOT', tmp_path / 'host-recovery')
    # Other contributor tasks may edit the shared checkout while these tests
    # run. Test a stable installer payload, as an installed package provides.
    source = tmp_path / 'installer-payload'
    source.mkdir(mode=0o700)
    for path in managed._runtime_source().glob('*.py'):
        atomic_write(source / path.name, path.read_bytes())
    monkeypatch.setattr(managed, '_runtime_source', lambda: source)
    calls = []
    original_command = managed.command

    def command(argv, **kwargs):
        calls.append(argv)
        if argv[0] != 'systemctl':
            return original_command(argv, **kwargs)
        if argv[1] == 'show':
            return b'ActiveState=active\nSubState=running\nUnitFileState=enabled\n'
        return b''

    monkeypatch.setattr(managed, 'command', command)
    monkeypatch.setattr(managed, '_probe', lambda *_args, **_kwargs: {'available': True})
    return SimpleNamespace(state=state, units=units, calls=calls, config=config,
                           args=SimpleNamespace(state_dir=state))


def test_defaults_provision_private_separate_paths_without_private_key(host):
    assert managed.setup(host.args) == 0
    record = managed._load(host.state)
    assert record['phase'] == 'ready'
    assert record['recovery_identity'] is None
    assert record['storage_layout'] == 'colocated-filesystem'
    assert record['storage']['backup']['directory'] != record['storage']['recovery']['directory']
    for target in record['storage'].values():
        path = Path(target['directory'])
        assert path.stat().st_mode & 0o777 == 0o700
        assert json.loads((path / '.iris-storage.json').read_bytes())['instance_id'] == record['instance_id']
    unit = (host.units / record['unit']).read_text()
    assert 'Restart=on-failure' in unit and 'Type=notify' in unit
    assert 'KillMode=mixed' in unit and 'TimeoutStopSec=infinity' in unit
    assert '--recovery-identity' not in unit
    assert ['systemctl', 'enable', '--now', record['unit']] in host.calls
    assert managed.inspect(host.state)['off_host_protection'] == 'not-proven'


def test_resume_preserves_runtime_and_refuses_unit_drift(host):
    managed.setup(host.args)
    record = managed._load(host.state)
    runtime = managed._runtime_directory(host.state, record)
    before = (runtime / 'launch.py').stat().st_ino
    managed.setup(host.args)
    assert (runtime / 'launch.py').stat().st_ino == before
    atomic_write(host.units / record['unit'], b'[Service]\nExecStart=/bin/false\n', 0o644)
    with pytest.raises(InstallError, match='service changed'):
        managed.setup(host.args)


@pytest.mark.parametrize('failure', ['daemon-reload', 'enable'])
def test_service_setup_resumes_after_systemd_failure(host, monkeypatch, failure):
    working = managed.command
    fail = True

    def command(argv, **kwargs):
        nonlocal fail
        if fail and argv[:2] == ['systemctl', failure]:
            fail = False
            raise InstallError('simulated service boundary')
        return working(argv, **kwargs)

    monkeypatch.setattr(managed, 'command', command)
    with pytest.raises(InstallError, match='simulated'):
        managed.setup(host.args)
    before = managed._load(host.state)
    assert before['phase'] == 'service-written'
    managed.setup(host.args)
    assert managed._load(host.state)['runtime'] == before['runtime']


def test_detached_or_replaced_storage_refuses_restart_and_setup(host, monkeypatch):
    managed.setup(host.args)
    original = managed.mount_identity
    record = managed._load(host.state)
    monkeypatch.setattr(managed, 'mount_identity', lambda path: dict(original(path), source='different-filesystem'))
    with pytest.raises(InstallError, match='mount changed'):
        managed.action(SimpleNamespace(state_dir=host.state, action='restart'))
    with pytest.raises(InstallError, match='mount changed'):
        managed.setup(host.args)
    assert ['systemctl', 'restart', record['unit']] not in host.calls


def test_explicit_targets_persist_through_offline_approval(host, tmp_path):
    data, identity = tmp_path / 'selected-data', tmp_path / 'selected-identities'
    data.mkdir(mode=0o700)
    identity.mkdir(mode=0o700)
    managed.remember_options(SimpleNamespace(state_dir=host.state, backup_root=data, recovery_root=identity))
    managed.setup(host.args)
    record = managed._load(host.state)
    assert record['storage']['backup']['root'] == str(data)
    assert record['storage']['recovery']['root'] == str(identity)
    with pytest.raises(InstallError, match='recorded backup'):
        managed.setup(SimpleNamespace(state_dir=host.state, backup_root=tmp_path / 'different'))


def test_refuses_unsafe_storage_and_foreign_target(host, tmp_path):
    alias = tmp_path / 'alias'
    alias.symlink_to(tmp_path)
    with pytest.raises(InstallError, match='symlinks'):
        managed.setup(SimpleNamespace(state_dir=host.state, backup_root=alias))
    managed.BACKUP_ROOT.mkdir(mode=0o700)
    identifier = json.loads((host.state / 'installation.json').read_bytes())['id']
    destination = managed.BACKUP_ROOT / ('iris-' + identifier)
    destination.mkdir(mode=0o700)
    atomic_write(destination / 'owner-data', b'preserve')
    with pytest.raises(InstallError, match='existing content'):
        managed.setup(host.args)
    assert (destination / 'owner-data').read_bytes() == b'preserve'


def test_explicit_runtime_refresh_is_immutable_and_resumable(host, tmp_path, monkeypatch):
    managed.setup(host.args)
    before = managed._load(host.state)
    old_path = managed._runtime_directory(host.state, before)
    source = tmp_path / 'updated-package'
    source.mkdir(mode=0o700)
    for name in before['runtime']:
        atomic_write(source / name, (managed._runtime_source() / name).read_bytes())
    atomic_write(source / '__init__.py', b'# deliberately changed fixture package\n')
    monkeypatch.setattr(managed, '_runtime_source', lambda: source)
    managed.setup(host.args)
    assert managed._load(host.state)['runtime'] == before['runtime']
    managed.setup(SimpleNamespace(state_dir=host.state, refresh_runtime=True))
    after = managed._load(host.state)
    assert after['runtime'] != before['runtime']
    assert old_path.exists()
    assert managed._runtime_directory(host.state, after).exists()
    assert ['systemctl', 'stop', before['unit']] in host.calls


def test_pinned_deployment_id_cannot_be_rebound(host):
    managed.setup(host.args)
    document = json.loads((host.state / 'installation.json').read_bytes())
    document['id'] = str(uuid.uuid4())
    atomic_write(host.state / 'installation.json', json.dumps(document).encode())
    with pytest.raises(InstallError, match='pinned deployment'):
        managed.inspect(host.state)


def test_identity_enable_disable_preserves_history_and_never_copies_key(host, tmp_path, monkeypatch):
    from iris_installer import maintenance_gui
    managed.setup(host.args)
    identity = tmp_path / 'independent-key'
    atomic_write(identity, b'private fixture identity')
    monkeypatch.setattr(maintenance_gui, 'recovery_identity', lambda value, **_kwargs: (Path(value), host.config['recovery_recipient']))
    managed.configure_recovery(host.state, identity)
    authority = json.loads((host.state / 'recovery-access.json').read_bytes())
    assert authority['active'] == str(identity)
    managed.configure_recovery(host.state)
    assert not (host.state / 'recovery-access.json').exists()
    assert identity.read_bytes() == b'private fixture identity'
    assert managed._load(host.state)['recovery_identity'] is None
    managed.configure_recovery(host.state, identity)
    assert json.loads((host.state / 'recovery-access.json').read_bytes()) == authority
    assert all(b'private fixture identity' not in path.read_bytes()
               for path in host.state.rglob('*') if path.is_file())


def test_recovery_custody_restart_rolls_forward_interrupted_record(host, tmp_path, monkeypatch):
    from iris_installer import maintenance_gui
    managed.setup(host.args)
    identity = tmp_path / 'independent-key'
    atomic_write(identity, b'fixture')
    monkeypatch.setattr(maintenance_gui, 'recovery_identity', lambda value, **_kwargs: (Path(value), host.config['recovery_recipient']))
    write = managed.atomic_write
    failed = False

    def interrupted(path, data, *args, **kwargs):
        nonlocal failed
        if Path(path).name == 'recovery-access.json' and not failed:
            failed = True
            raise OSError('simulated power loss')
        return write(path, data, *args, **kwargs)

    monkeypatch.setattr(managed, 'atomic_write', interrupted)
    with pytest.raises(OSError, match='power loss'):
        managed.configure_recovery(host.state, identity)
    assert (host.state / 'worker-custody-intent.json').exists()
    managed._apply_recovery_intent(host.state)
    assert not (host.state / 'worker-custody-intent.json').exists()
    assert json.loads((host.state / 'recovery-access.json').read_bytes())['active'] == str(identity)


def test_unit_escapes_systemd_expansions_without_shell():
    assert managed._quote('/tmp/space $thing%thing"') == '"/tmp/space $$thing%%thing\\""'


def test_managed_worker_real_unix_restart_preserves_job_recovery(host, monkeypatch):
    # A real privileged worker process, real Unix peer credentials and an actual
    # service restart; systemctl itself remains intercepted by the fixture.
    managed.setup(host.args)
    record = managed._load(host.state)
    job = {'id': str(uuid.uuid4()), 'action': 'backup', 'state': 'running'}
    atomic_write(host.state / 'lifecycle-jobs.json', json.dumps([job]).encode())
    launch = managed._runtime_directory(host.state, record) / 'launch.py'
    from iris_installer.maintenance_gui import MaintenanceClient
    for _attempt in range(2):
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(launch), str(host.state)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 12
            while True:
                try:
                    response = MaintenanceClient(host.state).call({'action': 'status'})
                    break
                except (InstallError, OSError):
                    if process.poll() is not None:
                        raise AssertionError(process.communicate()[1].decode())
                    if time.monotonic() > deadline:
                        pytest.fail('real worker did not become ready')
                    time.sleep(0.05)
            assert response['jobs'][0]['id'] == job['id']
            assert response['jobs'][0]['state'] == 'recovery-required'
            assert response['managed_service']['storage_ready'] is True
        finally:
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=12)
            assert process.returncode == 0, (stdout, stderr)
        assert not (host.state / 'control/control.sock').exists()


def test_kubernetes_readiness_uses_actual_mutual_tls(host, monkeypatch):
    from iris_installer import lifecycle_network, maintenance_gui
    managed.setup(host.args)
    record = managed._load(host.state)
    runner = lambda argv, **_kwargs: managed.command([str(part) for part in argv])
    custody = lifecycle_network.prepare_network_custody(host.state, 'https://127.0.0.1:18443', runner)
    worker = SimpleNamespace(status=lambda: {'available': True})
    server = lifecycle_network.make_https_server('127.0.0.1', 0, worker, custody)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    record.update(target='kubernetes', lifecycle_url='https://127.0.0.1:' + str(server.server_address[1]))
    monkeypatch.setattr(maintenance_gui.MaintenanceClient, 'call', lambda *_args: {'available': True})
    try:
        assert REAL_PROBE(host.state, record)['available'] is True
        record['lifecycle_url'] = 'https://127.0.0.2:' + str(server.server_address[1])
        record['listen_address'] = '127.0.0.1'
        with pytest.raises(OSError):
            REAL_PROBE(host.state, record)
        # An expired or inaccessible remote endpoint does not suppress the
        # protected Unix recovery endpoint used to renew transport credentials.
        assert REAL_PROBE(host.state, record, network=False)['available'] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def test_public_signer_is_independent_and_pinned(host, tmp_path):
    managed.setup(host.args)
    key = tmp_path / 'independent-signer'
    managed.command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    result = managed.configure_restore_signer(host.state, key.with_suffix('.pub'))
    assert result['configured'] is True
    assert (host.state / 'restore-custody/signer.pub').stat().st_mode & 0o777 == 0o600
    assert managed.configure_restore_signer(host.state, key.with_suffix('.pub')) == result
    with pytest.raises(InstallError, match='outside deployment'):
        managed.configure_restore_signer(host.state, host.state / 'restore-custody/signer.pub')
    with pytest.raises(InstallError, match='public backup signer'):
        managed.configure_restore_signer(host.state, key)


def test_explicit_desktop_identity_import_survives_source_removal(host, tmp_path, monkeypatch):
    source = tmp_path / 'desktop-recovery.age'
    managed.command(['age-keygen', '-o', str(source)])
    recipient = managed.command(['age-keygen', '-y', str(source)]).decode().strip()
    os.chown(source, 1000, 1000)
    monkeypatch.setenv('SUDO_UID', '1000')
    document = json.loads((host.state / 'installation.json').read_bytes())
    document['config']['recovery_recipient'] = recipient
    atomic_write(host.state / 'installation.json', json.dumps(document).encode())
    managed.setup(host.args)
    assert not managed.RECOVERY_ACCESS_ROOT.exists()
    managed.configure_recovery(host.state, source)
    retained = Path(managed._load(host.state)['recovery_identity'])
    assert retained != source
    assert retained.stat().st_uid == 0 and retained.stat().st_mode & 0o777 == 0o600
    assert host.state not in retained.parents
    assert retained.read_bytes() == source.read_bytes()
    original_inode = retained.stat().st_ino
    managed.configure_recovery(host.state, source)
    assert retained.stat().st_ino == original_inode
    source.unlink()
    managed.setup(host.args)
    assert managed.command(['age-keygen', '-y', str(retained)]).decode().strip() == recipient
    managed.configure_recovery(host.state)
    assert retained.exists()
    assert managed._load(host.state)['recovery_identity'] is None


def test_desktop_public_signer_import_needs_no_manual_chown(host, tmp_path, monkeypatch):
    managed.setup(host.args)
    key = tmp_path / 'desktop-signer'
    managed.command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    source = key.with_suffix('.pub')
    os.chown(source, 1000, 1000)
    monkeypatch.setenv('SUDO_UID', '1000')
    assert managed.configure_restore_signer(host.state, source)['configured'] is True
    pinned = host.state / 'restore-custody/signer.pub'
    assert pinned.stat().st_uid == 0
    assert pinned.read_bytes().split()[:2] == source.read_bytes().split()[:2]
