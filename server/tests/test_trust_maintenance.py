# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Scoped host trust adapter refuses unrelated input and repairs admitted pins."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import trust_maintenance as maintenance
from iris_installer.state import InstallError


@pytest.fixture
def installation(tmp_path):
    root = tmp_path / 'roots'
    root.mkdir()
    values = {'root-a.pub': b'old root A\n', 'root-b.pub': b'old root B\n'}
    for name, value in values.items():
        (root / name).write_bytes(value)
    document = {'root_digests': {name: hashlib.sha256(value).hexdigest() for name, value in values.items()},
                'completed': {'packages': {'test': 'hash'}, 'guestshell': {'state': 'ok'}, 'preserved': 'yes'}}
    saved = []
    journal = SimpleNamespace(document=document, save=lambda: saved.append(json.loads(json.dumps(document))))
    return SimpleNamespace(base=tmp_path, journal=journal, saved=saved,
                           env={'IRIS_DEVICE_IMAGE_OCI': str(tmp_path / 'artifacts/device.oci.tar')})


def record():
    return {'request_id': str(uuid.uuid4()), 'state': 'published', 'family': 'instruction-roots',
            'roots': {'root-a': 'approved root A\n', 'root-b': 'approved root B\n'}}


@pytest.mark.parametrize('boundary', ['root-a.pub', 'root-b.pub', 'journal'])
def test_root_pin_recovery_across_each_write(installation, monkeypatch, boundary):
    approved = record()
    original = maintenance.atomic_write
    original_save = installation.journal.save
    def interrupt(path, *args, **kwargs):
        if Path(path).name == boundary:
            raise OSError('interrupted root publication')
        return original(path, *args, **kwargs)
    def interrupt_save():
        raise OSError('interrupted checkpoint')
    monkeypatch.setattr(maintenance, 'atomic_write', interrupt)
    if boundary == 'journal':
        monkeypatch.setattr(installation.journal, 'save', interrupt_save)
    with pytest.raises(OSError):
        maintenance._sync_roots(installation, approved)
    monkeypatch.setattr(maintenance, 'atomic_write', original)
    monkeypatch.setattr(installation.journal, 'save', original_save)
    maintenance._sync_roots(installation, approved)
    for name, value in approved['roots'].items():
        assert (installation.base / 'roots' / (name + '.pub')).read_text() == value
        assert installation.journal.document['root_digests'][name + '.pub'] == hashlib.sha256(value.encode()).hexdigest()
    assert installation.journal.document['completed']['packages'] == {'test': 'hash'}
    assert installation.journal.document['completed']['preserved'] == 'yes'


def test_recovery_restores_capture_checkpoint_but_finish_invalidates_before_build(installation):
    approved = record()
    maintenance._sync_roots(installation, approved)
    installation.journal.document['completed'].pop('packages')
    maintenance._sync_roots(installation, approved)
    assert installation.journal.document['completed']['packages'] == {'test': 'hash'}
    def packages():
        assert 'packages' not in installation.journal.document['completed']
        assert 'guestshell' not in installation.journal.document['completed']
        raise InstallError('injected build failure')
    installation.packages = packages
    with pytest.raises(InstallError, match='injected build'):
        maintenance.finish(installation, 'instruction-roots', approved['request_id'])
    assert 'packages' not in installation.journal.document['completed']
    maintenance._sync_roots(installation, approved)
    assert installation.journal.document['completed']['packages'] == {'test': 'hash'}


def test_host_root_external_mutation_refused(installation):
    approved = record()
    (installation.base / 'roots/root-a.pub').write_text('not old or approved')
    with pytest.raises(InstallError, match='outside'):
        maintenance._sync_roots(installation, approved)
    assert (installation.base / 'roots/root-a.pub').read_text() == 'not old or approved'


def test_root_rebuild_uses_operation_archive_preserves_original_and_recovers_same_path(installation):
    original = Path(installation.env['IRIS_DEVICE_IMAGE_OCI'])
    original.parent.mkdir()
    original.write_bytes(b'old-root OCI')
    original.with_suffix('.tar.manifest').write_bytes(b'old-root provenance')
    approved = record()
    attempted = []
    def packages():
        archive = Path(installation.env['IRIS_DEVICE_IMAGE_OCI'])
        attempted.append(archive)
        assert archive != original
        assert archive.name == 'device-roots-' + approved['request_id'] + '.oci.tar'
        assert 'IRIS_FORCE_DEVICE_IMAGE_BUILD' not in installation.env
        assert 'packages' not in installation.journal.document['completed']
        if not archive.exists():
            archive.write_bytes(b'approved-root OCI')
            raise InstallError('interrupted after OCI build')
        assert archive.read_bytes() == b'approved-root OCI'
    installation.packages = packages
    installation.python = lambda *args: b'{"packages_verified": true}'
    with pytest.raises(InstallError, match='interrupted after OCI'):
        maintenance.finish(installation, 'instruction-roots', approved['request_id'])
    # A recovered transaction constructs a fresh DockerInstall with the default
    # archive environment. The approved operation must select its own path again.
    installation.env['IRIS_DEVICE_IMAGE_OCI'] = str(original)
    assert maintenance.finish(installation, 'instruction-roots', approved['request_id']) == {'packages_verified': True}
    assert attempted[0] == attempted[1]
    assert original.read_bytes() == b'old-root OCI'
    assert original.with_suffix('.tar.manifest').read_bytes() == b'old-root provenance'
    previous_archive = attempted[-1]
    approved = record()
    with pytest.raises(InstallError, match='interrupted after OCI'):
        maintenance.finish(installation, 'instruction-roots', approved['request_id'])
    assert attempted[-1] != previous_archive
    assert previous_archive.read_bytes() == b'approved-root OCI'


@pytest.mark.parametrize('kind', ['device-tls', 'peer-ca'])
def test_non_root_refresh_keeps_original_oci_archive(installation, kind):
    original = installation.env['IRIS_DEVICE_IMAGE_OCI']
    installation.packages = lambda: None
    installation.python = lambda *args: b'{"packages_verified": true}'
    maintenance.finish(installation, kind, record()['request_id'])
    assert installation.env['IRIS_DEVICE_IMAGE_OCI'] == original
    assert installation.journal.document['completed']['packages'] == {'test': 'hash'}


@pytest.mark.parametrize('state', [{'Running': True, 'ExitCode': 0},
                                 {'Running': False, 'ExitCode': 137},
                                 {'Running': False, 'ExitCode': 0, 'OOMKilled': True}])
def test_no_trust_mutation_without_cleanly_stopped_writers(state):
    instance = SimpleNamespace(compose=lambda *args, **kwargs: b'server-id\nconsole-id\n',
                               command=lambda *args, **kwargs: json.dumps([{'State': state}]).encode())
    with pytest.raises(InstallError, match='Cleanly stop'):
        maintenance._stopped(instance)


@pytest.mark.parametrize('recovery,initial,allowed', [(False, True, False), (True, False, False), (True, True, True)])
def test_failed_restart_recovery_needs_recorded_initial_clean_stop(recovery, initial, allowed):
    instance = SimpleNamespace(compose=lambda *args, **kwargs: b'server-id\nconsole-id\n',
        command=lambda *args, **kwargs: json.dumps([{'State': {'Running': False, 'ExitCode': 1}}]).encode(),
        credential_recovery=recovery, credential_transaction=SimpleNamespace(record={'initial_clean_stop': initial}))
    if allowed:
        maintenance._stopped(instance)
    else:
        with pytest.raises(InstallError, match='Cleanly stop'):
            maintenance._stopped(instance)


def test_explicit_recovery_still_refuses_running_writers():
    instance = SimpleNamespace(compose=lambda *args, **kwargs: b'server-id\nconsole-id\n',
        command=lambda *args, **kwargs: json.dumps([{'State': {'Running': True, 'ExitCode': 0}}]).encode(),
        credential_recovery=True, credential_transaction=SimpleNamespace(record={'initial_clean_stop': True}))
    with pytest.raises(InstallError, match='Cleanly stop'):
        maintenance._stopped(instance)


def test_recovery_requires_matching_server_publication(installation, monkeypatch):
    approved = record()
    maintenance._sync_roots(installation, approved)
    monkeypatch.setattr(maintenance, '_stopped', lambda instance: None)
    monkeypatch.setattr(maintenance, '_one_shot', lambda *args: json.dumps(dict(approved, request_id=str(uuid.uuid4()))).encode())
    with pytest.raises(InstallError, match='matching published'):
        maintenance.recover_inputs(installation, 'instruction-roots', approved['request_id'])


def test_rotation_passes_explicit_recovery_and_bounded_callbacks(installation, monkeypatch):
    from iris_installer import credential_maintenance
    calls = []
    class Transaction:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
        def run(self, apply, finish, **kwargs):
            assert apply is maintenance.apply and finish is maintenance.finish
            assert kwargs == {'recovery': True, 'pre_capture_recover': maintenance.recover_inputs,
                              'pre_apply_check': maintenance.pre_apply_check}
            return {'state': 'rotated'}
    monkeypatch.setattr(credential_maintenance, 'Transaction', Transaction)
    result = maintenance.rotate('state', 'backups', 'recovery', kind='instruction-roots',
        operation_id=record()['request_id'], recovery_identity='independent', recovery=True)
    assert result == {'state': 'rotated'}
    assert calls[0][0] == ('state', 'backups', 'recovery')
