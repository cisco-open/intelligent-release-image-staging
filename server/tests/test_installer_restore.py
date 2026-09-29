# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
from types import SimpleNamespace
import uuid
from contextlib import contextmanager

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import restore, restore_storage as storage, restore_topology
from iris_installer.state import InstallError, atomic_write


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps(value).encode())


def producer(root, serial=3):
    put(root / 'instructions-epoch.json', {'schema': 'iris-instructions-epoch/v1', 'epoch': 40, 'updated_at': 39})
    put(root / 'instructions/activation.json', {'schema': 'iris-instruction-producer/v1', 'epoch': 40,
                                             'activated_at': 39, 'mode': 'initialize'})
    put(root / 'instructions/admitted-devices.json', {'schema': 'iris-instruction-admissions/v1',
        'epoch': 40, 'devices': {'switch-1': {'state': 'active', 'registered_at': 1, 'created_at': 1}}})
    put(root / 'instructions/serial-history.d/00.json', {'switch-1': {'v': 1, 'epoch': 40,
        'high_water': serial, 'reservation': None}})
    put(root / 'fleet.json', {'switch-1': {'desired': 'historical-image'}})
    put(root / 'jobs.json', {'old': {'status': 'complete'}})


def test_restore_real_historical_state_preserves_current_replay_authority(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current, 9)
    producer(archived, 3)
    put(current / 'fleet.json', {'switch-1': {'desired': 'new-image'}})
    put(current / 'jobs.json', {'new': {'status': 'complete'}})
    result = restore.replay_overlay(current, archived)
    assert result['replay_floor'] == 'current-fenced-primary'
    assert restore._history(archived)['switch-1']['high_water'] == 9
    assert json.loads((archived / 'fleet.json').read_text())['switch-1']['desired'] == 'historical-image'
    assert json.loads((archived / 'jobs.json').read_text()) == {'old': {'status': 'complete'}}


def test_valid_empty_initialized_producer_needs_no_serial_file(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    for root in (current, archived):
        producer(root)
        shutil.rmtree(root / 'instructions/serial-history.d')
        put(root / 'instructions/admitted-devices.json', {'schema': 'iris-instruction-admissions/v1',
            'epoch': 40, 'devices': {}})
    assert restore.replay_overlay(current, archived)['current_history_rows'] == 0
    (current / 'instructions/admitted-devices.json').unlink()
    with pytest.raises(FileNotFoundError):
        restore.replay_overlay(current, archived)


@pytest.mark.parametrize('authority', ['peer-policy.json', 'deployment_records.json',
    'ca-trust-settings.json', 'audit-export-known-hosts', 'schedules.d'])
def test_other_changed_security_authorities_refuse_restore(tmp_path, authority):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current); producer(archived)
    put(current / authority, {'security': 'current'})
    put(archived / authority, {'security': 'historical'})
    with pytest.raises(InstallError, match='ownership or external trust'):
        restore.state_authority(current, archived)


def test_current_disclosure_and_execution_records_are_preserved(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current); producer(archived)
    for name in ('peer-handouts.d/00.json', 'schedule-receipts/record.d/00.json',
                 'schedule-retired.d/00.json', 'report_ledger.d/00.json'):
        put(current / name, {'new': 'authority'})
        put(archived / name, {'old': 'authority'})
    restore.state_authority(current, archived)
    assert json.loads((archived / 'peer-handouts.d/00.json').read_text()) == {'new': 'authority'}
    assert json.loads((archived / 'schedule-receipts/record.d/00.json').read_text()) == {'new': 'authority'}


def test_inventory_role_and_image_quarantine_cannot_roll_back(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current); producer(archived)
    put(current / 'fleet.json', {'switch-1': {'role': 'quarantine'}})
    with pytest.raises(InstallError, match='role authority'):
        restore.state_authority(current, archived)
    put(archived / 'fleet.json', {'switch-1': {'role': 'quarantine'}})
    put(current / 'catalog.json', {'images': {'image': {'quarantined': True}}})
    put(archived / 'catalog.json', {'images': {'image': {'quarantined': False}}})
    with pytest.raises(InstallError, match='quarantine'):
        restore.state_authority(current, archived)


@pytest.mark.parametrize('change', ['lower', 'missing', 'epoch', 'admission', 'bool'])
def test_restore_rejects_missing_corrupt_or_lower_current_replay_authority(tmp_path, change):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current, 9)
    producer(archived, 3)
    if change == 'lower':
        producer(current, 2)
    elif change == 'missing':
        (current / 'instructions/serial-history.d/00.json').unlink()
    elif change == 'epoch':
        put(current / 'instructions-epoch.json', {'schema': 'iris-instructions-epoch/v1', 'epoch': 41})
    elif change == 'admission':
        put(current / 'instructions/admitted-devices.json', {})
    else:
        producer(current, True)
    with pytest.raises(InstallError):
        restore.replay_overlay(current, archived)
    assert restore._history(archived)['switch-1']['high_water'] == 3


def test_restore_rejects_keylist_revocation_rollback(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    producer(current, 9)
    producer(archived, 3)
    for root, sequence in ((current, 2), (archived, 3)):
        payload = ('root-signed-keylist-' + str(sequence)).encode()
        atomic_write(root / 'instructions/keylist.current', payload)
        put(root / 'instructions/keylist-state.json', {'schema': 'iris-instruction-keylist-state/v1',
            'keylist_seq': sequence, 'artifact_sha256': hashlib.sha256(payload).hexdigest()})
    with pytest.raises(InstallError, match='revocation floor'):
        restore.replay_overlay(current, archived)


def test_security_generation_compares_decrypted_credentials_and_refuses_revocation(tmp_path):
    current, archived = tmp_path / 'current', tmp_path / 'archived'
    current.mkdir(); archived.mkdir()
    atomic_write(current / 'secrets.json.age', b'fresh-ciphertext')
    atomic_write(archived / 'secrets.json.age', b'old-ciphertext')
    install = SimpleNamespace(base=tmp_path, command=lambda *a, **kw: b'{"revoked":true}')
    restore._config_generation(install, current, archived, tmp_path / 'identity')
    def command(argv, **kwargs):
        return b'{"revoked":true}' if argv[-1].parent == current else b'{"revoked":false}'
    install.command = command
    with pytest.raises(InstallError, match='revocations backward'):
        restore._config_generation(install, current, archived, tmp_path / 'identity')
    atomic_write(current / 'new-security-authority', b'new')
    with pytest.raises(InstallError, match='different credential generation'):
        restore._config_generation(install, current, archived, tmp_path / 'identity')


def test_directory_publication_resumes_both_rename_boundaries(tmp_path, monkeypatch):
    live, source = tmp_path / 'live', tmp_path / 'archive'
    live.mkdir(); source.mkdir()
    atomic_write(live / 'inventory', b'current')
    atomic_write(source / 'inventory', b'historical')
    staged, retained = tmp_path / 'staged', tmp_path / 'retained'
    records = storage.inventory(source)
    storage.candidate(source, staged, records)
    before, after = storage.fingerprint(storage.inventory(live)), storage.fingerprint(records)
    original = os.rename
    def interrupted(a, b):
        original(a, b)
        if Path(b) == retained:
            raise RuntimeError('process lost after first rename')
    monkeypatch.setattr(storage.os, 'rename', interrupted)
    with pytest.raises(RuntimeError):
        storage.publish(live, staged, retained, before, after)
    assert not live.exists()
    monkeypatch.setattr(storage.os, 'rename', original)
    storage.publish(live, staged, retained, before, after)
    storage.publish(live, staged, retained, before, after)
    assert (live / 'inventory').read_bytes() == b'historical'
    assert (retained / 'inventory').read_bytes() == b'current'
    atomic_write(live / 'inventory', b'new writer')
    with pytest.raises(InstallError, match='approved'):
        storage.publish(live, staged, retained, before, after)
    assert (live / 'inventory').read_bytes() == b'new writer'


def test_partial_candidate_is_retained_and_rebuilt(tmp_path):
    source, staged = tmp_path / 'source', tmp_path / 'staged'
    source.mkdir(); staged.mkdir()
    atomic_write(source / 'value', b'complete')
    atomic_write(staged / 'value', b'partial')
    records = storage.inventory(source)
    storage.candidate(source, staged, records)
    storage.candidate(source, staged, records)
    assert (staged / 'value').read_bytes() == b'complete'
    incomplete, = tmp_path.glob('staged-incomplete-*')
    assert (incomplete / 'value').read_bytes() == b'partial'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo'])
def test_storage_inventory_refuses_unsafe_members(tmp_path, kind):
    root = tmp_path / 'root'
    root.mkdir()
    value = root / 'value'
    if kind == 'symlink':
        value.symlink_to('/etc/passwd')
    elif kind == 'hardlink':
        (root / 'original').write_bytes(b'value')
        os.link(root / 'original', value)
    else:
        os.mkfifo(value)
    with pytest.raises(InstallError):
        storage.inventory(root)


def test_kubernetes_chunk_transport_stages_and_publishes_real_files(tmp_path, monkeypatch):
    data, source = tmp_path / 'data', tmp_path / 'source'
    data.mkdir(); source.mkdir()
    (data / 'state').mkdir()
    atomic_write(data / 'state' / 'inventory', b'current')
    atomic_write(source / 'inventory', b'historical' * 500000)
    atomic_write(source / 'empty', b'')
    requests = []
    def maintenance(argv, **kwargs):
        argv = [str(value) for value in argv]
        # Exercise the exact transmitted scripts on an isolated local tree.
        argv[4] = argv[4].replace("Path('/data')", 'Path(' + repr(str(data)) + ')')
        requests.append(len(kwargs.get('input') or b''))
        return subprocess.check_output(argv, input=kwargs.get('input'))
    install = SimpleNamespace(maintenance_run=maintenance)
    operation = str(uuid.uuid4())
    records = storage.inventory(source)
    before = storage.fingerprint(storage.inventory(data / 'state'))
    after = storage.fingerprint(records)
    restore_topology.stage(install, operation, 'state', source, records)
    restore_topology.stage(install, operation, 'state', source, records)
    restore_topology.publish(install, operation, 'state', before, after)
    restore_topology.publish(install, operation, 'state', before, after)
    assert (data / 'state/inventory').read_bytes() == (source / 'inventory').read_bytes()
    assert max(requests) <= 4 * 1024 * 1024


def test_restore_requires_separately_provisioned_signer(tmp_path):
    identity = tmp_path / 'identity'
    atomic_write(identity, b'private')
    with pytest.raises(InstallError, match='Provision the independent'):
        restore.custody(tmp_path, identity)
    trust = tmp_path / 'restore-custody'
    trust.mkdir(mode=0o700)
    atomic_write(trust / 'signer.pub', b'public', 0o644)
    assert restore.custody(tmp_path, identity) == trust / 'signer.pub'
    identity.chmod(0o644)
    with pytest.raises(InstallError, match='private'):
        restore.custody(tmp_path, identity)


@pytest.mark.parametrize('phase', ['verified', 'stopping', 'stopped', 'publishing', 'restarting', 'recovery-required'])
def test_interrupted_restore_blocks_other_maintenance_entry_points(tmp_path, phase):
    operation = str(uuid.uuid4())
    record = dict(operation_id=operation, instance_id=str(uuid.uuid4()), phase=phase)
    put(tmp_path / 'restore-operation.json', record)
    put(tmp_path / 'restore-operations' / operation / 'record.json', record)
    with pytest.raises(InstallError, match='interrupted deployment restore'):
        restore.guard(tmp_path)
    with pytest.raises(InstallError, match='interrupted deployment restore'):
        restore.guard(tmp_path, operation_id=str(uuid.uuid4()))
    restore.guard(tmp_path, operation_id=operation)


@pytest.mark.parametrize('damage', ['missing-pointer', 'missing-record', 'wrong-instance', 'corrupt-record'])
def test_restore_guard_rejects_lost_or_mismatched_authority(tmp_path, damage):
    operation, instance = str(uuid.uuid4()), str(uuid.uuid4())
    record = dict(operation_id=operation, instance_id=instance, phase='publishing')
    pointer, saved = tmp_path / 'restore-operation.json', tmp_path / 'restore-operations' / operation / 'record.json'
    put(pointer, record); put(saved, record)
    if damage == 'missing-pointer':
        pointer.unlink()
    elif damage == 'missing-record':
        saved.unlink()
    elif damage == 'wrong-instance':
        put(saved, dict(record, instance_id=str(uuid.uuid4())))
    else:
        atomic_write(saved, b'not-json')
    with pytest.raises(InstallError, match='authority is unreadable'):
        restore.guard(tmp_path, operation_id=operation, instance_id=instance)


@pytest.mark.parametrize('damage', ['missing-record', 'wrong-instance', 'corrupt-record', 'corrupt-pointer'])
def test_explicit_recovery_never_repairs_invalid_authority(tmp_path, damage):
    operation, instance = str(uuid.uuid4()), str(uuid.uuid4())
    record = dict(operation_id=operation, instance_id=instance, phase='verified')
    pointer, saved = tmp_path / 'restore-operation.json', tmp_path / 'restore-operations' / operation / 'record.json'
    put(saved, record)
    if damage == 'missing-record':
        saved.unlink()
    elif damage == 'wrong-instance':
        put(saved, dict(record, instance_id=str(uuid.uuid4())))
    elif damage == 'corrupt-record':
        atomic_write(saved, b'not-json')
    else:
        atomic_write(pointer, b'not-json')
    with pytest.raises(InstallError, match='authority is unreadable'):
        restore.guard(tmp_path, operation_id=operation, instance_id=instance, recovery_record=record)


def test_generated_management_certificate_renewal_keeps_identical_trust(tmp_path):
    if not shutil.which('openssl'):
        pytest.skip('openssl is required')
    current, archived = tmp_path / 'current', tmp_path / 'archive'
    sources = {name: current / name for name in ('volume-iris-config', 'volume-iris-management-ca',
                                                'volume-iris-tier-auth')}
    for root in (current, archived):
        for name in sources:
            (root / name).mkdir(parents=True)
    config = sources['volume-iris-config'] / 'tls'
    config.mkdir()
    sources['deployment'] = current / 'compose.json'
    put(sources['deployment'], {'services': {'iris': {'environment': {'IRIS_MANAGEMENT_API_GENERATE_CERT': '1'}}}})
    def command(argv, **kwargs):
        return subprocess.check_output(list(map(str, argv)), stderr=subprocess.DEVNULL)
    command(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', tmp_path / 'key'])
    def certificate(path, serial, subject='iris'):
        command(['openssl', 'req', '-x509', '-new', '-key', tmp_path / 'key', '-days', '2',
                 '-subj', '/CN=' + subject, '-set_serial', serial,
                 '-addext', 'subjectAltName=DNS:iris,DNS:localhost', '-out', path])
    certificate(config / 'crt.pem', '1')
    certificate(sources['volume-iris-management-ca'] / 'ca.pem', '2')
    certificate(archived / 'volume-iris-management-ca/ca.pem', '3')
    install = SimpleNamespace(config={'target': 'docker'}, command=command)
    assert restore._management_generation(install, sources, archived) is True
    certificate(archived / 'volume-iris-management-ca/ca.pem', '4', 'other')
    with pytest.raises(InstallError, match='trust properties'):
        restore._management_generation(install, sources, archived)
    certificate(archived / 'volume-iris-management-ca/ca.pem', '3')
    atomic_write(config / 'management-crt.pem', b'durable identity')
    with pytest.raises(InstallError, match='credential generation'):
        restore._management_generation(install, sources, archived)
    (config / 'management-crt.pem').unlink()
    atomic_write(sources['volume-iris-tier-auth'] / 'current.json', b'changed-token')
    with pytest.raises(InstallError, match='credential generation'):
        restore._management_generation(install, sources, archived)


def test_direct_capture_credential_and_resume_refuse_pending_restore(tmp_path, monkeypatch):
    from iris_installer import backup, credential_maintenance, deploy
    operation, instance = str(uuid.uuid4()), str(uuid.uuid4())
    record = dict(operation_id=operation, instance_id=instance, phase='publishing')
    put(tmp_path / 'restore-operation.json', record)
    put(tmp_path / 'restore-operations' / operation / 'record.json', record)
    journal = SimpleNamespace(directory=tmp_path, document={'id': instance})
    @contextmanager
    def locked(*args, **kwargs):
        yield journal
    factory = lambda *args: SimpleNamespace(locked=locked)
    monkeypatch.setattr(credential_maintenance, 'Journal', factory)
    monkeypatch.setattr(deploy, 'Journal', factory)
    monkeypatch.setattr(deploy.os, 'geteuid', lambda: 0)
    adapter = SimpleNamespace(base=tmp_path, capture_plan=lambda: pytest.fail('must not capture'))
    with pytest.raises(InstallError, match='interrupted deployment restore'):
        backup.capture_plan(adapter)
    transaction = credential_maintenance.Transaction.__new__(credential_maintenance.Transaction)
    transaction.base = tmp_path
    with pytest.raises(InstallError, match='interrupted deployment restore'):
        transaction.run(None, None)
    with pytest.raises(InstallError, match='interrupted deployment restore'):
        deploy.resume(SimpleNamespace(state_dir=tmp_path, certificate=None))


def test_kubernetes_recovery_matches_stopped_replica_state_but_not_changed_authority(tmp_path):
    original = [dict(kind='Deployment', metadata={'name': 'iris-server'}, spec={'replicas': 1,
                     'template': {'spec': {'containers': [{'image': 'sha256:original'}]}}}),
                dict(kind='Secret', metadata={'name': 'iris-management'}, data={'key': 'original'})]
    current = json.loads(json.dumps(original))
    current[0]['spec']['replicas'] = 0
    current.append(dict(kind='NetworkPolicy', metadata={'name': 'iris-maintenance-isolation'}, spec={}))
    prior, live = tmp_path / 'prior', tmp_path / 'live'
    put(prior, original); put(live, current)
    assert restore._kubernetes_resources(prior) == restore._kubernetes_resources(live)
    current[1]['data']['key'] = 'changed'
    put(live, current)
    assert restore._kubernetes_resources(prior) != restore._kubernetes_resources(live)
    current[1]['data']['key'] = 'original'
    current[0]['spec']['template']['spec']['containers'][0]['image'] = 'sha256:changed'
    put(live, current)
    assert restore._kubernetes_resources(prior) != restore._kubernetes_resources(live)


@pytest.fixture
def transaction(tmp_path, monkeypatch):
    from iris_installer import backup_archive
    for executable in ('age', 'age-keygen', 'ssh-keygen'):
        if not shutil.which(executable):
            pytest.skip(executable + ' is required')
    base, backups, recovery = [tmp_path / name for name in ('state', 'backups', 'recovery')]
    for directory in (base, backups, recovery):
        directory.mkdir(mode=0o700)
    service, independent, signer = base / 'age.txt', tmp_path / 'independent', tmp_path / 'signer'
    for path in (service, independent):
        subprocess.run(['age-keygen', '-o', str(path)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', independent]).decode().strip()
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)], check=True)
    (base / 'restore-custody').mkdir(mode=0o700)
    shutil.copyfile(str(signer) + '.pub', base / 'restore-custody/signer.pub')
    (base / 'restore-custody/signer.pub').chmod(0o644)
    instance = str(uuid.uuid4())
    document = dict(schema=1, id=instance, config={'target': 'docker', 'recovery_recipient': recipient},
                    completed={'images': {'server': 'sha256:' + 'a' * 64}}, root_digests={})
    put(base / 'installation.json', document)
    sources = {name: base / name for name in ('source', 'roots', 'images', 'artifacts',
               'volume-iris-config', 'volume-iris-state', 'volume-iris-images',
               'volume-iris-tier-auth', 'volume-iris-management-ca')}
    for directory in sources.values():
        directory.mkdir(mode=0o700)
    sources.update(deployment=base / 'compose.json', environment=base / 'compose.env', installation=base / 'installation.json')
    atomic_write(sources['deployment'], b'{}')
    atomic_write(sources['environment'], b'IRIS_TEST=1\n')
    producer(sources['volume-iris-state'], 3)
    atomic_write(sources['volume-iris-config'] / 'account', b'owner-unchanged')
    atomic_write(sources['images'] / 'image.bin', b'original-image')
    volumes = {name: str(path) for name, path in sources.items() if name.startswith('volume-')}
    set_id, backup_id, operation = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    meta = dict(backup_set_id=set_id, instance_id=instance, target='single-docker', volumes=volumes,
                image_ids=document['completed']['images'], scope='managed-deployment-files')
    backup_archive.create(sources, backups / backup_id, recipient, signer, metadata=meta)
    backup_archive.create({'service-identity': service, 'backup-signer': signer}, recovery / backup_id,
                          recipient, signer, metadata=dict(meta, scope='identity-recovery'))
    producer(sources['volume-iris-state'], 9)
    put(sources['volume-iris-state'] / 'fleet.json', {'switch-1': {'desired': 'new-image'}})
    put(sources['volume-iris-state'] / 'jobs.json', {'new': {'status': 'complete'}})
    atomic_write(sources['images'] / 'image.bin', b'damaged-image')
    calls = []
    def command(argv, **kwargs):
        return subprocess.check_output([str(value) for value in argv], input=kwargs.get('input'))
    install = SimpleNamespace(base=base, config=document['config'], command=command,
                              verify_resource_ownership=lambda: calls.append('ownership'))
    install.compose = lambda *args, **kwargs: calls.append(args)
    def installation(journal):
        install.journal = journal
        return install
    monkeypatch.setattr(restore.backup, '_installation', installation)
    monkeypatch.setattr(restore.backup, 'capture_plan', lambda _: (sources, volumes, []))
    monkeypatch.setattr(restore, '_pin_runtime', lambda _: None)
    monkeypatch.setattr(restore, '_fence', lambda *args: calls.append('fenced'))
    monkeypatch.setattr(restore, '_producer_proof', lambda _: {'signing_authority': 'verified'})
    monkeypatch.setattr(restore, '_consumer_proof', lambda _: {'management_https': 'verified', 'certificate_sha256': 'c' * 64})
    # Exercise the real locked transaction and cryptographic archives as the
    # test user; only the host-root admission constructor is bypassed.
    tx = restore.Transaction.__new__(restore.Transaction)
    tx.base, tx.backups, tx.recoveries = base, backups, recovery
    tx.id, tx.backup_id, tx.identity = operation, backup_id, independent
    tx.signer = restore.custody(base, independent)
    tx.directory, tx.record = base / 'restore-operations' / operation, None
    return tx, sources, calls, install


def test_complete_transaction_restores_data_restarts_and_authenticates_console(transaction):
    tx, sources, calls, install = transaction
    result = tx.run()
    assert result['state'] == 'restored'
    assert result['proof']['management_https'] == 'verified'
    assert (sources['images'] / 'image.bin').read_bytes() == b'original-image'
    assert json.loads((sources['volume-iris-state'] / 'fleet.json').read_text())['switch-1']['desired'] == 'historical-image'
    assert json.loads((sources['volume-iris-state'] / 'jobs.json').read_text()) == {'old': {'status': 'complete'}}
    assert (sources['volume-iris-config'] / 'account').read_bytes() == b'owner-unchanged'
    assert restore._history(sources['volume-iris-state'])['switch-1']['high_water'] == 9
    assert calls[0] == 'fenced'
    assert [call[-1] for call in calls if isinstance(call, tuple) and call[0] == 'up'] == ['iris', 'console']
    assert tx.run(recovery=True) == result


def test_explicit_recovery_repairs_first_record_pointer_crash_window(transaction, monkeypatch):
    tx, sources, calls, install = transaction
    write = restore.atomic_write
    def crash(path, value, *args, **kwargs):
        if path == tx.base / 'restore-operation.json':
            raise OSError('injected process loss before pointer publication')
        return write(path, value, *args, **kwargs)
    monkeypatch.setattr(restore, 'atomic_write', crash)
    with pytest.raises(OSError, match='injected process loss'):
        tx.run()
    assert not calls
    with pytest.raises(InstallError, match='authority is unreadable'):
        restore.guard(tx.base)
    monkeypatch.setattr(restore, 'atomic_write', write)
    assert tx.run(recovery=True)['state'] == 'restored'
    restore.guard(tx.base)


def test_failed_post_start_proof_stops_services_and_recovery_never_replays_backup(transaction, monkeypatch):
    tx, sources, calls, install = transaction
    def failed(_):
        put(sources['volume-iris-state'] / 'new-writer.json', {'committed': True})
        producer(sources['volume-iris-state'], 15)
        raise InstallError('consumer unavailable')
    monkeypatch.setattr(restore, '_consumer_proof', failed)
    with pytest.raises(InstallError, match='consumer unavailable'):
        tx.run()
    assert tx.record['phase'] == 'recovery-required'
    assert tx.record['published'] is True
    assert calls[-1][0] == 'stop'
    monkeypatch.setattr(restore, '_consumer_proof', lambda _: {'management_https': 'verified', 'certificate_sha256': 'c' * 64})
    result = tx.run(recovery=True)
    assert result['state'] == 'restored'
    assert (sources['volume-iris-state'] / 'new-writer.json').is_file()
    assert restore._history(sources['volume-iris-state'])['switch-1']['high_water'] == 15


def test_security_mismatch_refuses_before_live_mutation_and_resumes_original(transaction):
    tx, sources, calls, install = transaction
    atomic_write(sources['volume-iris-config'] / 'account', b'new-owner-credential')
    with pytest.raises(InstallError, match='credential generation'):
        tx.run()
    assert tx.record['phase'] == 'refused'
    assert tx.record['mutations_admitted'] is False
    assert (sources['images'] / 'image.bin').read_bytes() == b'damaged-image'
    assert (sources['volume-iris-config'] / 'account').read_bytes() == b'new-owner-credential'
    assert calls[-1][-1] == 'console'
