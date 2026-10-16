# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real finalization, trust journals and cache CAS; native SDKs are simulated."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from test_installer_prebuilt_backup import caches, installation, roots
from test_installer_restore import transaction, put
from iris_installer import backup_archive, deploy, device_finalize, packaging_inputs, prebuilt_backup
from iris_installer import prebuilt_device, prebuilt_trust, trust_maintenance
from iris_installer import restore_storage as storage
from iris_installer.state import InstallError, Journal, atomic_write

JOB = '87a3dc21-6475-4f91-a2ad-336d8d722833'
NEXT = '4938f427-f7d1-4ff7-a344-12dbbed94371'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def replacement(request=JOB, start=3):
    roots = {}
    algorithm = b'ssh-ed25519'
    for index, name in enumerate(('root-a', 'root-b'), start):
        wire = len(algorithm).to_bytes(4, 'big') + algorithm + (32).to_bytes(4, 'big') + bytes([index]) * 32
        roots[name] = 'ssh-ed25519 ' + base64.b64encode(wire).decode() + '\n'
    return {'request_id': request, 'family': 'instruction-roots', 'state': 'published', 'roots': roots}


@pytest.fixture
def rotating(caches, monkeypatch):
    obj = object.__new__(deploy.DockerInstall)
    obj.__dict__.update(caches.__dict__)
    obj.source = obj.base / 'source'; obj.source.mkdir()
    obj.config, obj.env = {}, {'PATH': '/usr/bin:/bin'}
    artifacts = obj.base / 'artifacts'; artifacts.mkdir()
    generated = obj.journal.document['completed']['prebuilt-package-generated']
    deploy._publish_prebuilt_packages(obj.base / generated['directory'], artifacts, generated['hashes'])
    obj.journal.checkpoint('guestshell', {'state': 'ok'})
    tool = obj.base / 'licensed-ioxclient'; tool.write_bytes(b'#!/bin/sh\nexit 93\n'); tool.chmod(0o700)
    obj.journal.document['prebuilt_ioxclient'] = str(tool); obj.journal.save()
    tool_sha = digest(tool.read_bytes())
    def prepare_inputs(kit, output):
        output.mkdir(mode=0o700); archive = output / 'appmgr.tar.gz'; archive.write_bytes(b'synthetic SDK input')
        return packaging_inputs.PackagingInputs(archive, 'c' * 64, 'd' * 40, tool_sha, kit.receipt())
    monkeypatch.setattr(packaging_inputs, 'prepare_packaging_inputs', prepare_inputs)
    obj.wrapper_calls = []
    def runner(command, **kwargs):
        # Only licensed native wrapper generation is simulated. Actual neutral
        # OCI finalization, provenance validator and publication run unchanged.
        assert command[0] == 'bash'
        args = dict(zip(command[2::2], command[3::2]))
        runtime = Path(args['--finalized-dir'])
        raw = (runtime / prebuilt_device.RECEIPT).read_bytes()
        assert digest(raw) == args['--finalization-sha256']
        receipt = json.loads(raw)
        assert receipt['root_files_sha256'] == obj.journal.document['root_digests']
        obj.wrapper_calls.append(command)
        name = 'iris-xr.rpm' if command[1].endswith('build-xr-package.sh') else 'iris-' + args['--arch'] + '.tar'
        output = Path(args['--out'] if name.endswith('.rpm') else args['--artifacts-dir'])
        data = ('synthetic wrapper ' + name + receipt['archive_sha256']).encode()
        (output / name).write_bytes(data)
        values = dict(format='iris-device-wrapper-v2', wrapper_kind='xr-appmgr' if name.endswith('.rpm') else 'iox',
            wrapper_file=name, wrapper_sha256=digest(data), platform='linux/arm64' if name == 'iris-arm64.tar' else 'linux/amd64',
            canonical_index_digest=receipt['index_digest'], canonical_archive_sha256=receipt['archive_sha256'],
            canonical_neutral_source_sha256=receipt['neutral_source_sha256'], canonical_finalization_sha256=digest(raw))
        (output / (name + '.manifest')).write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
        return b''
    obj.runner = runner
    obj.packages = lambda: (obj._acquire_prebuilt_packages(), obj.journal.checkpoint('guestshell', {'state': 'ok'}))
    obj.python = lambda *_: b'{"explicit_runtime_consumer_test_boundary":true}'
    return obj


def commit(obj, request=JOB, start=3):
    trust_maintenance._sync_roots(obj, replacement(request, start))
    trust_maintenance.finish(obj, 'instruction-roots', request)


def test_actual_successor_finalization_wrappers_resume_backup_and_second_generation(rotating, monkeypatch):
    obj = rotating
    original = deepcopy(obj.journal.document['completed'])
    original_paths = prebuilt_backup.capture_sources(obj)
    original_bytes = {str(path): path.read_bytes() for root in original_paths.values() for path in root.iterdir()}
    commit(obj)
    state = obj.journal.document[prebuilt_trust.FIELD]
    assert state['current'] == JOB and state['history'][JOB]['previous'] is None
    assert state['history'][JOB]['completed'] == {name: original[name] for name in prebuilt_trust.STAGES}
    runtime = obj.base / ('prebuilt-device-runtime-' + JOB)
    assert prebuilt_device.prepare_runtime(obj)[0] == runtime
    assert prebuilt_backup.capture_sources(obj)[prebuilt_backup.RUNTIME] == runtime
    assert all(Path(path).read_bytes() == raw for path, raw in original_bytes.items())
    # A fresh process reads the persisted selection, without finish's env.
    journal = Journal(obj.base); journal.document = json.loads(journal.path.read_bytes())
    obj.journal = journal; obj.env = {'PATH': '/usr/bin:/bin'}
    calls = len(obj.wrapper_calls)
    obj._acquire_prebuilt_packages()
    assert len(obj.wrapper_calls) == calls == 3
    authority = prebuilt_backup.authority(obj)
    assert prebuilt_backup.assert_archive_authority(obj, journal.document) == authority
    stale = deepcopy(journal.document); stale.pop(prebuilt_trust.FIELD)
    with pytest.raises(InstallError, match='generation differs'):
        prebuilt_backup.assert_archive_authority(obj, stale)
    commit(obj, NEXT, 5)
    assert obj.journal.document[prebuilt_trust.FIELD]['history'][NEXT]['previous'] == JOB
    assert runtime.is_dir() and prebuilt_device.prepare_runtime(obj)[0].name.endswith(NEXT)
    assert all(Path(path).read_bytes() == raw for path, raw in original_bytes.items())


@pytest.mark.parametrize('boundary', ['root-a.pub', 'journal-finalization', 'publication'])
def test_interrupted_exact_generation_resumes_without_replacing_old_caches(rotating, monkeypatch, boundary):
    obj = rotating
    prior = {str(path): path.read_bytes() for root in prebuilt_backup.capture_sources(obj).values() for path in root.iterdir()}
    original_write = trust_maintenance.atomic_write
    checkpoint = obj.journal.checkpoint
    publish = deploy._publish_prebuilt_packages
    if boundary == 'root-a.pub':
        def interrupt(path, *args, **kwargs):
            if Path(path).name == boundary: raise InstallError('test interruption')
            return original_write(path, *args, **kwargs)
        monkeypatch.setattr(trust_maintenance, 'atomic_write', interrupt)
    elif boundary == 'journal-finalization':
        def interrupt(stage, value):
            if stage == 'prebuilt-device-runtime': raise InstallError('test interruption')
            checkpoint(stage, value)
        monkeypatch.setattr(obj.journal, 'checkpoint', interrupt)
    else:
        def interrupt(*args, **kwargs):
            publish(*args, **kwargs)
            raise InstallError('test interruption')
        monkeypatch.setattr(deploy, '_publish_prebuilt_packages', interrupt)
    with pytest.raises(InstallError, match='test interruption'): commit(obj)
    assert obj.journal.document[prebuilt_trust.FIELD]['current'] == JOB
    monkeypatch.setattr(trust_maintenance, 'atomic_write', original_write)
    monkeypatch.setattr(obj.journal, 'checkpoint', checkpoint)
    monkeypatch.setattr(deploy, '_publish_prebuilt_packages', publish)
    obj.journal.document = json.loads(obj.journal.path.read_bytes())
    commit(obj)
    assert prebuilt_backup.capture_sources(obj)[prebuilt_backup.RUNTIME].name.endswith(JOB)
    assert all(Path(path).read_bytes() == raw for path, raw in prior.items())


@pytest.mark.parametrize('change', ['roots', 'request', 'transition', 'old-cache-inode', 'old-cache-byte', 'source', 'foreign-artifact', 'historical-input'])
def test_wrong_generation_or_custody_refuses_before_next_build(rotating, change):
    obj = rotating
    trust_maintenance._sync_roots(obj, replacement())
    state = obj.journal.document[prebuilt_trust.FIELD]
    if change == 'roots': obj.journal.document['root_digests']['root-a.pub'] = '0' * 64
    elif change == 'request': state['current'] = NEXT
    elif change == 'transition': (obj.base / ('trust-roots-' + JOB + '.json')).write_text('{}')
    elif change == 'historical-input': state['history'][JOB]['completed']['prebuilt-package-intent']['finalization_sha256'] = '0' * 64
    elif change.startswith('old-cache'):
        target = obj.base / 'prebuilt-device-runtime' / prebuilt_device.ARCHIVE
        target.chmod(0o600)
        if change.endswith('inode'):
            other = target.with_suffix('.new'); other.write_bytes(target.read_bytes()); other.chmod(0o444); other.replace(target)
        else: target.write_bytes(b'foreign'); target.chmod(0o444)
    elif change == 'source': obj.journal.document['source_manifest']['server/instruction_keys.py'] = '0' * 64
    else:
        target = obj.base / 'artifacts/iris-xr.rpm'; target.chmod(0o600); target.write_bytes(b'foreign'); target.chmod(0o444)
    with pytest.raises((InstallError, OSError)):
        trust_maintenance.finish(obj, 'instruction-roots', JOB)
    assert obj.wrapper_calls == []


def test_same_byte_published_predecessor_replacement_during_cas_is_refused(rotating, monkeypatch):
    obj = rotating
    trust_maintenance._sync_roots(obj, replacement())
    snapshot = device_finalize._snapshot
    def substituted(source, destination, maximum):
        result = snapshot(source, destination, maximum)
        if Path(destination).parent.name.startswith('.iris-native-'):
            target = obj.base / 'artifacts' / Path(destination).name
            other = target.with_suffix('.same'); other.write_bytes(target.read_bytes()); other.chmod(0o444); other.replace(target)
        return result
    monkeypatch.setattr(device_finalize, '_snapshot', substituted)
    with pytest.raises(InstallError, match='changed'):
        trust_maintenance.finish(obj, 'instruction-roots', JOB)
    assert 'packages' not in obj.journal.document['completed']


def test_only_exact_existing_recovery_transaction_can_plan_with_predecessor_caches(rotating):
    obj = rotating
    prior = prebuilt_backup.capture_sources(obj)
    trust_maintenance._sync_roots(obj, replacement())
    # Normal backup cannot certify an incomplete successor.
    with pytest.raises(InstallError, match='complete recorded native generation'):
        prebuilt_backup.capture_sources(obj)
    record = {'operation_id': JOB, 'kind': 'instruction-roots', 'instance_id': obj.journal.document['id'],
              'mutations_admitted': True, 'initial_clean_stop': True, 'phase': 'recovery-required'}
    directory = obj.base / 'credential-operations' / JOB; directory.mkdir(mode=0o700, parents=True)
    atomic_write(directory / 'record.json', json.dumps(record).encode())
    atomic_write(obj.base / 'credential-operation.json', json.dumps(record).encode())
    obj.credential_recovery = True
    obj.credential_transaction = SimpleNamespace(id=JOB, kind='instruction-roots', record=record)
    assert prebuilt_backup.capture_sources(obj) == prior
    for key, value in [('operation_id', NEXT), ('instance_id', NEXT), ('mutations_admitted', False),
                       ('initial_clean_stop', False), ('phase', 'rotated')]:
        old = record[key]; record[key] = value
        with pytest.raises(InstallError): prebuilt_backup.capture_sources(obj)
        record[key] = old
    atomic_write(obj.base / 'credential-operation.json', b'{}')
    with pytest.raises(InstallError): prebuilt_backup.capture_sources(obj)


def test_predecessor_cache_drift_during_packaging_refuses_before_publication(rotating):
    obj = rotating
    original = {name: (obj.base / 'artifacts' / name).read_bytes() for name in deploy.NATIVE_FILES}
    trust_maintenance._sync_roots(obj, replacement())
    runner = obj.runner
    def changed(command, **kwargs):
        result = runner(command, **kwargs)
        if command[1].endswith('build-xr-package.sh'):
            old = obj.base / 'prebuilt-device-runtime' / prebuilt_device.ARCHIVE
            replacement = old.with_suffix('.same')
            replacement.write_bytes(old.read_bytes()); replacement.chmod(0o444); replacement.replace(old)
        return result
    obj.runner = changed
    with pytest.raises(InstallError): trust_maintenance.finish(obj, 'instruction-roots', JOB)
    assert {name: (obj.base / 'artifacts' / name).read_bytes() for name in deploy.NATIVE_FILES} == original
    assert 'packages' not in obj.journal.document['completed']


@pytest.mark.parametrize('history', ['absent', 'reconstructed'])
def test_completed_generation_restore_does_not_require_historical_inodes(rotating, history):
    obj = rotating
    predecessor = prebuilt_backup.capture_sources(obj)
    commit(obj)
    sources = prebuilt_backup.capture_sources(obj)
    archived = deepcopy(obj.journal.document)
    extracted = obj.base / 'verified-backup'; extracted.mkdir(mode=0o700)
    records = {name: storage.inventory(path) for name, path in sources.items()}
    for name, path in sources.items():
        shutil.copytree(path, extracted / name)
    # Only the two current caches are backup components. A completed predecessor
    # is historical metadata, not a permanent live inode or restore prerequisite.
    for path in predecessor.values():
        retained = path.with_name(path.name + '-test-retained'); path.rename(retained)
        if history == 'reconstructed':
            shutil.copytree(retained, path)
    for path in sources.values():
        path.rename(path.with_name(path.name + '-test-retained'))
    before = obj.journal.path.read_bytes()
    identity, plan = prebuilt_backup.prepare_restore(obj, extracted, archived, NEXT, records.__getitem__)
    assert {item['prebuilt_cache'] for item in plan} == prebuilt_backup.COMPONENTS
    for item in plan:
        prebuilt_backup.publish_missing(obj, item, identity, NEXT)
    assert prebuilt_backup.capture_sources(obj) == sources
    assert obj.journal.path.read_bytes() == before
    assert all(storage.inventory(path) == records[name] for name, path in sources.items())
    calls = len(obj.wrapper_calls)
    commit(obj)  # Same-ID finish and fresh resume do not re-enter predecessor CAS.
    assert len(obj.wrapper_calls) == calls
    commit(obj, NEXT, 5)
    assert prebuilt_backup.capture_sources(obj)[prebuilt_backup.RUNTIME].name.endswith(NEXT)


def test_real_encrypted_restore_recovers_current_generation_without_old_caches(rotating, transaction, monkeypatch):
    # Reuse the existing real locked restore/age/signature fixture. Deployment
    # stop/start and runtime consumer probes retain that fixture's explicit mocks.
    obj = rotating
    commit(obj)
    tx, sources, _, install = transaction
    original = json.loads(tx.base.joinpath('installation.json').read_bytes())
    document = deepcopy(obj.journal.document)
    document.update(id=original['id'], config=original['config'])
    document['completed'].update(original['completed'])
    put(tx.base / 'installation.json', document)
    for path in (obj.base / 'roots').iterdir():
        shutil.copy2(path, sources['roots'] / path.name)
    for name, path in prebuilt_backup.capture_sources(obj).items():
        target = tx.base / path.name
        shutil.copytree(path, target); sources[name] = target
    # No predecessor cache or old transition file is restored or adopted here.
    assert not (tx.base / 'prebuilt-device-runtime').exists()
    install._verified_kit = obj._verified_kit
    install.journal = Journal(tx.base); install.journal.document = document
    archived = tx.backups / tx.backup_id
    metadata = backup_archive.read(archived, tx.identity, tx.signer)['metadata']
    archived.rename(archived.with_name(archived.name + '-source-fixture'))
    backup_archive.create(sources, archived, original['config']['recovery_recipient'],
                          tx.base.parent / 'signer', metadata=metadata)
    expected = {name: storage.inventory(sources[name]) for name in prebuilt_backup.COMPONENTS}
    for name in expected:
        path = sources[name]; path.rename(path.with_name(path.name + '-test-retained'))
    monkeypatch.setattr(prebuilt_device, 'prepare_runtime', lambda *_: pytest.fail('Restore cannot finalize'))
    monkeypatch.setattr(deploy.DockerInstall, 'acquire_packages', lambda *_: pytest.fail('Restore cannot package'))
    before = (tx.base / 'installation.json').read_bytes()
    assert tx.run()['state'] == 'restored'
    assert (tx.base / 'installation.json').read_bytes() == before
    assert {item['prebuilt_cache'] for item in tx.record['plan'] if 'prebuilt_cache' in item} == prebuilt_backup.COMPONENTS
    assert all(storage.inventory(sources[name]) == rows for name, rows in expected.items())
    assert prebuilt_backup.capture_sources(install) == {name: sources[name] for name in expected}


@pytest.mark.parametrize('change', ['none', 'missing', 'foreign'])
def test_partial_publication_keeps_exact_old_or_new_admission(rotating, monkeypatch, change):
    obj = rotating
    replace = deploy.os.replace
    first, second = sorted(deploy.NATIVE_FILES)[:2]
    def interrupted(source, destination, **kwargs):
        result = replace(source, destination, **kwargs)
        if destination == first and 'src_dir_fd' in kwargs:
            raise InstallError('test partial publication')
        return result
    monkeypatch.setattr(deploy.os, 'replace', interrupted)
    with pytest.raises(InstallError, match='test partial publication'):
        commit(obj)
    assert not prebuilt_trust.publication_complete(obj)
    assert 'packages' not in obj.journal.document['completed']
    monkeypatch.setattr(deploy.os, 'replace', replace)
    if change == 'none':
        commit(obj)
        assert prebuilt_trust.publication_complete(obj)
    else:
        path = obj.base / 'artifacts' / second
        if change == 'missing': path.unlink()
        else: path.chmod(0o600); path.write_bytes(b'foreign artifact'); path.chmod(0o444)
        with pytest.raises(InstallError): commit(obj)
        assert 'packages' not in obj.journal.document['completed']
