# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Current-journal cache custody and same-deployment encrypted restore fixtures."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from test_installer_prebuilt_device import installation, roots
from test_installer_restore import transaction, put
from iris_installer import backup, backup_archive, deploy, prebuilt_backup as subject
from iris_installer import prebuilt_device, restore, restore_storage as storage
from iris_installer.state import InstallError, Journal


@pytest.fixture
def caches(installation):
    obj = installation
    obj.journal.document.update(release_kit={'directory': str(obj._verified_kit.directory),
        'verifier': '/usr/bin/gh', 'trusted_root': '/independent/trusted-root.json'},
        prebuilt_ioxclient='/retained/licensed/ioxclient')
    directory, final_sha = prebuilt_device.prepare_runtime(obj)
    receipt = json.loads((directory / prebuilt_device.RECEIPT).read_bytes())
    native = obj.base / 'prebuilt-native-packages-fixture1'
    native.mkdir(mode=0o700)
    for name in deploy.NATIVE_PACKAGES:
        data = ('fixture native wrapper ' + name).encode()
        (native / name).write_bytes(data)
        values = dict(format='iris-device-wrapper-v2', wrapper_kind='xr-appmgr' if name.endswith('.rpm') else 'iox',
            wrapper_file=name, wrapper_sha256=hashlib.sha256(data).hexdigest(),
            platform='linux/arm64' if name == 'iris-arm64.tar' else 'linux/amd64',
            canonical_index_digest=receipt['index_digest'], canonical_archive_sha256=receipt['archive_sha256'],
            canonical_neutral_source_sha256=receipt['neutral_source_sha256'], canonical_finalization_sha256=final_sha)
        (native / (name + '.manifest')).write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
    for path in native.iterdir():
        path.chmod(0o444)
    hashes = deploy._finalized_package_hashes(native, receipt, final_sha)
    obj.journal.document['completed'].update({
        'prebuilt-package-intent': dict(schema=1, kit=obj._verified_kit.receipt(), finalization_sha256=final_sha,
                                       appmgr_sha256='c' * 64, appmgr_revision='d' * 40, ioxclient_sha256='e' * 64),
        'prebuilt-package-generated': dict(schema=1, directory=native.name, hashes=hashes), 'packages': hashes})
    obj.journal.save()
    return obj


@pytest.mark.parametrize('target', ['docker', 'docker-split', 'kubernetes'])
def test_capture_adds_only_exact_recorded_cache_components_for_every_topology(caches, monkeypatch, target):
    caches.config = {'target': target}
    caches.capture_plan = lambda: ({'installation': caches.journal.path}, {}, [])
    orphan = caches.base / 'prebuilt-native-packages-unknown1'
    orphan.mkdir(mode=0o700)
    (orphan / 'owner').write_bytes(b'never adopt')
    monkeypatch.setattr(prebuilt_device, 'prepare_runtime', lambda *a: pytest.fail('No finalization'))
    sources, volumes, containers = backup.capture_plan(caches)
    assert set(sources) == {'installation', *subject.COMPONENTS}
    assert sources[subject.NATIVE].name == 'prebuilt-native-packages-fixture1'
    assert orphan not in sources.values() and volumes == {} and containers == []


def test_source_capture_and_legacy_journal_remain_unchanged(tmp_path):
    journal = SimpleNamespace(document={'completed': {}})
    install = SimpleNamespace(base=tmp_path, journal=journal, capture_plan=lambda: ({'source': tmp_path}, {}, []))
    assert backup.capture_plan(install) == ({'source': tmp_path}, {}, [])


@pytest.mark.parametrize('component', [subject.RUNTIME, subject.NATIVE])
@pytest.mark.parametrize('damage', ['missing', 'bytes', 'partial', 'extra', 'mode', 'symlink', 'hardlink'])
def test_capture_refuses_missing_or_altered_caches_without_adoption(caches, component, damage):
    paths = subject.capture_sources(caches)
    path = paths[component]
    file = next(path.iterdir())
    if damage == 'missing':
        path.rename(path.with_name(path.name + '-kept'))
    elif damage == 'bytes':
        file.chmod(0o600); file.write_bytes(b'changed'); file.chmod(0o444)
    elif damage == 'partial':
        file.unlink()
    elif damage == 'extra':
        (path / 'owner').write_bytes(b'keep')
    elif damage == 'mode':
        path.chmod(0o755)
    elif damage == 'symlink':
        kept = path.with_name(path.name + '-kept')
        path.rename(kept); path.symlink_to(kept, target_is_directory=True)
    else:
        os.link(file, caches.base / 'alias')
    with pytest.raises(InstallError):
        subject.capture_sources(caches)
    if damage == 'missing':
        assert subject.capture_sources(caches, allow_missing=True) == paths
    else:
        with pytest.raises(InstallError):
            subject.capture_sources(caches, allow_missing=True)


@pytest.mark.parametrize('stage', subject.STAGES)
def test_incomplete_or_malformed_generation_records_refuse_capture(caches, stage):
    caches.journal.document['completed'][stage] = None
    with pytest.raises(InstallError):
        subject.capture_sources(caches)


@pytest.fixture
def prebuilt_transaction(transaction, caches, monkeypatch):
    tx, sources, calls, install = transaction
    original = json.loads((tx.base / 'installation.json').read_bytes())
    document = deepcopy(caches.journal.document)
    document.update(id=original['id'], config=original['config'])
    document['completed'].update(original['completed'])
    put(tx.base / 'installation.json', document)
    for path in (caches.base / 'roots').iterdir():
        shutil.copy2(path, sources['roots'] / path.name)
    for name, path in subject.capture_sources(caches).items():
        target = tx.base / path.name
        shutil.copytree(path, target)
        sources[name] = target
    install._verified_kit = caches._verified_kit
    install.journal = Journal(tx.base)
    install.journal.document = document
    # Recreate only this disposable fixture's data backup, retaining the old set.
    archived = tx.backups / tx.backup_id
    metadata = backup_archive.read(archived, tx.identity, tx.signer)['metadata']
    archived.rename(archived.with_name(archived.name + '-source-fixture'))
    backup_archive.create(sources, archived, original['config']['recovery_recipient'],
                          tx.base.parent / 'signer', metadata=metadata)
    # Prove restore does not require the licensed executable or rebuild helpers.
    monkeypatch.setattr(prebuilt_device, 'prepare_runtime', lambda *a: pytest.fail('Restore cannot finalize'))
    monkeypatch.setattr(deploy.DockerInstall, 'acquire_packages', lambda *a: pytest.fail('Restore cannot package'))
    return tx, sources, calls, install


@pytest.mark.parametrize('missing', [(), (subject.NATIVE,), tuple(sorted(subject.COMPONENTS))])
def test_same_deployment_restore_preserves_or_recovers_exact_cache_bytes(prebuilt_transaction, missing):
    tx, sources, calls, install = prebuilt_transaction
    expected = {name: storage.inventory(sources[name]) for name in subject.COMPONENTS}
    inodes = {name: sources[name].stat().st_ino for name in subject.COMPONENTS}
    journal_before = (tx.base / 'installation.json').read_bytes()
    for name in missing:
        sources[name].rename(sources[name].with_name(sources[name].name + '-retained-fixture'))
    assert tx.run()['state'] == 'restored'
    assert (tx.base / 'installation.json').read_bytes() == journal_before
    for name in subject.COMPONENTS:
        assert storage.inventory(sources[name]) == expected[name]
        if name not in missing:
            assert sources[name].stat().st_ino == inodes[name]
    assert {item['prebuilt_cache'] for item in tx.record['plan'] if 'prebuilt_cache' in item} == set(missing)
    assert subject.capture_sources(install) == {name: sources[name] for name in subject.COMPONENTS}


@pytest.mark.parametrize('boundary', ['before', 'after'])
def test_missing_cache_publication_recovers_interruption_without_replaying_bytes(prebuilt_transaction, monkeypatch, boundary):
    tx, sources, calls, install = prebuilt_transaction
    target = sources[subject.NATIVE]
    expected = storage.inventory(target)
    target.rename(target.with_name(target.name + '-retained-fixture'))
    publish = subject.finalizer._publish
    def interrupted(descriptor, source, destination):
        if destination == target.name:
            if boundary == 'after':
                publish(descriptor, source, destination)
            raise OSError('fixture cache publication interrupted')
        return publish(descriptor, source, destination)
    monkeypatch.setattr(subject.finalizer, '_publish', interrupted)
    with pytest.raises(OSError, match='cache publication interrupted'):
        tx.run()
    assert tx.record['phase'] == 'recovery-required'
    monkeypatch.setattr(subject.finalizer, '_publish', publish)
    assert tx.run(recovery=True)['state'] == 'restored'
    assert storage.inventory(target) == expected


@pytest.mark.parametrize('change', ['selection', 'locator', 'generated', 'root', 'source'])
def test_backup_cannot_replace_current_prebuilt_authority(caches, change):
    archived = deepcopy(caches.journal.document)
    if change == 'selection': archived['input_selection']['kit']['manifest_sha256'] = 'f' * 64
    elif change == 'locator': archived['release_kit']['directory'] = '/other/kit'
    elif change == 'generated': archived['completed']['prebuilt-package-generated']['directory'] = 'prebuilt-native-packages-other000'
    elif change == 'root': archived['root_digests']['root-a.pub'] = 'f' * 64
    else: archived['source_manifest']['extra'] = 'f' * 64
    with pytest.raises(InstallError, match='differs from this deployment'):
        subject.assert_archive_authority(caches, archived)


def test_tampered_present_cache_is_preserved_during_restore(prebuilt_transaction):
    tx, sources, calls, install = prebuilt_transaction
    path = sources[subject.NATIVE] / 'iris-xr.rpm'
    path.chmod(0o600); path.write_bytes(b'owner evidence'); path.chmod(0o444)
    with pytest.raises(InstallError, match='cache bytes changed'):
        tx.run()
    assert path.read_bytes() == b'owner evidence'
    assert not any('prebuilt_cache' in item for item in tx.record.get('plan', []))


def test_changed_generation_after_staging_refuses_explicit_recovery(prebuilt_transaction, monkeypatch):
    tx, sources, calls, install = prebuilt_transaction
    target = sources[subject.NATIVE]
    target.rename(target.with_name(target.name + '-retained-fixture'))
    monkeypatch.setattr(subject, 'publish_missing', lambda *a: (_ for _ in ()).throw(OSError('interrupted')))
    with pytest.raises(OSError):
        tx.run()
    document = json.loads((tx.base / 'installation.json').read_bytes())
    document['release_kit']['directory'] = '/changed/kit'
    put(tx.base / 'installation.json', document)
    calls.clear()
    with pytest.raises(InstallError, match='restore generation changed'):
        tx.run(recovery=True)
    assert calls == [] and not target.exists()


@pytest.mark.parametrize('missing_live', [False, True])
def test_older_backup_without_cache_payloads_only_supports_intact_generation(caches, tmp_path, missing_live):
    extracted = tmp_path / 'old-extracted'
    extracted.mkdir()
    if missing_live:
        native = subject.capture_sources(caches)[subject.NATIVE]
        native.rename(native.with_name(native.name + '-retained-fixture'))
    arguments = (caches, extracted, deepcopy(caches.journal.document),
                 '12345678-1234-1234-1234-123456789abc',
                 lambda name: pytest.fail('An old backup has no cache records'))
    if missing_live:
        with pytest.raises(InstallError, match='backup lacks a missing recorded cache'):
            subject.prepare_restore(*arguments)
    else:
        identity, plan = subject.prepare_restore(*arguments)
        assert identity == subject.authority(caches) and plan == []


@pytest.mark.parametrize('change', ['archive-bytes', 'archive-partial', 'staged-bytes', 'appeared-cache'])
def test_restore_never_adopts_altered_backup_candidate_or_new_directory(caches, tmp_path, change):
    extracted = tmp_path / 'extracted'
    extracted.mkdir()
    sources = subject.capture_sources(caches)
    records = {}
    for name, source in sources.items():
        records[name] = storage.inventory(source)
        shutil.copytree(source, extracted / name)
    target = sources[subject.NATIVE]
    target.rename(target.with_name(target.name + '-retained-fixture'))
    archived = deepcopy(caches.journal.document)
    operation = '12345678-1234-1234-1234-123456789abc'
    if change.startswith('archive-'):
        path = extracted / subject.NATIVE / 'iris-xr.rpm'
        if change == 'archive-bytes':
            path.chmod(0o600); path.write_bytes(b'tampered archived wrapper')
        else:
            path.unlink()
        with pytest.raises((InstallError, OSError)):
            subject.prepare_restore(caches, extracted, archived, operation, records.__getitem__)
        assert not target.exists()
        return
    identity, plan = subject.prepare_restore(caches, extracted, archived, operation, records.__getitem__)
    item, = plan
    if change == 'staged-bytes':
        file = Path(item['staged']) / 'iris-xr.rpm'
        file.chmod(0o600); file.write_bytes(b'owner evidence'); file.chmod(0o444)
    else:
        # Even byte-identical new live content cannot be adopted while the
        # operation's approved candidate still awaits exclusive publication.
        shutil.copytree(extracted / subject.NATIVE, target)
        file = target / 'iris-xr.rpm'
    original = file.read_bytes()
    with pytest.raises(InstallError):
        subject.publish_missing(caches, item, identity, operation)
    assert file.read_bytes() == original


def test_parent_replacement_cannot_publish_unverified_substitute_cache(caches, tmp_path, monkeypatch):
    extracted = tmp_path / 'extracted'
    extracted.mkdir()
    sources = subject.capture_sources(caches)
    records = {}
    for name, source in sources.items():
        records[name] = storage.inventory(source)
        shutil.copytree(source, extracted / name)
    target = sources[subject.NATIVE]
    target.rename(target.with_name(target.name + '-retained-fixture'))
    operation = '12345678-1234-1234-1234-123456789abc'
    identity, plan = subject.prepare_restore(caches, extracted, deepcopy(caches.journal.document),
                                             operation, records.__getitem__)
    item, = plan
    staged = Path(item['staged'])
    moved = tmp_path.with_name(tmp_path.name + '-held-original')
    inventory = storage.inventory
    def replaced(directory):
        result = inventory(directory)
        if directory == staged:
            tmp_path.rename(moved)
            tmp_path.mkdir(mode=0o700)
            staged.mkdir(mode=0o700)
            (staged / 'owner').write_bytes(b'unverified replacement must remain')
        return result
    monkeypatch.setattr(storage, 'inventory', replaced)
    with pytest.raises(InstallError, match='parent changed'):
        subject.publish_missing(caches, item, identity, operation)
    assert (staged / 'owner').read_bytes() == b'unverified replacement must remain'
    assert not target.exists()
    assert (moved / staged.name).is_dir()
