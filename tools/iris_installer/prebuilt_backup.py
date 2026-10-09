# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Capture and recover only the current journal's immutable prebuilt caches.

Recovery is part of the existing same-deployment restore transaction. It never
replaces a present cache, adopts a directory, changes the journal, or runs a
finalizer or native packaging program. External release trust remains external.
"""

from copy import deepcopy
import os
from pathlib import Path
import re
import stat

from . import device_context, device_finalize as finalizer, prebuilt_device
from . import prebuilt_install, release_kit, restore_storage as storage
from .state import InstallError, regular_bytes


RUNTIME = prebuilt_device.OUTPUT
NATIVE = 'prebuilt-native-packages'
COMPONENTS = frozenset((RUNTIME, NATIVE))
STAGES = ('prebuilt-device-intent', RUNTIME, 'prebuilt-package-intent',
          'prebuilt-package-generated', 'packages')


def fail(message):
    raise InstallError('Prebuilt backup: ' + message)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def authority(installation):
    """Validate the protected journal without generating or publishing bytes."""
    from .deploy import NATIVE_FILES
    document = installation.journal.document
    if not prebuilt_install.selected(document):
        return None
    selection = prebuilt_install.public_selection(document)
    kit = prebuilt_install._kit(installation)
    completed = document['completed']
    if any(name not in completed for name in STAGES):
        fail('complete recorded native generation is required')
    intent = prebuilt_device._intent(installation, kit)
    result, native, generated = (completed[RUNTIME], completed['prebuilt-package-intent'],
                                  completed['prebuilt-package-generated'])
    if completed['prebuilt-device-intent'] != intent:
        fail('finalized inputs differ from current release, roots or source')
    if (not isinstance(result, dict)
            or set(result) != {'schema', 'intent', 'finalization_sha256', 'archive_sha256', 'archive_size'}
            or type(result['schema']) is not int or result['schema'] != 1 or result['intent'] != intent
            or not _sha(result['finalization_sha256']) or not _sha(result['archive_sha256'])
            or type(result['archive_size']) is not int
            or not 0 < result['archive_size'] <= finalizer.MAX_ARCHIVE):
        fail('recorded finalized runtime is invalid')
    if (not isinstance(native, dict)
            or set(native) != {'schema', 'kit', 'finalization_sha256', 'appmgr_sha256', 'appmgr_revision', 'ioxclient_sha256'}
            or type(native['schema']) is not int or native['schema'] != 1 or native['kit'] != kit.receipt()
            or native['finalization_sha256'] != result['finalization_sha256']
            or not _sha(native['appmgr_sha256']) or not _sha(native['ioxclient_sha256'])
            or not isinstance(native['appmgr_revision'], str)
            or not re.fullmatch(r'[0-9a-f]{40}', native['appmgr_revision'])):
        fail('recorded native inputs are invalid')
    if (not isinstance(generated, dict) or set(generated) != {'schema', 'directory', 'hashes'}
            or type(generated['schema']) is not int or generated['schema'] != 1
            or not isinstance(generated['directory'], str)
            or not re.fullmatch(r'prebuilt-native-packages-[a-z0-9_]{8}', generated['directory'])
            or not isinstance(generated['hashes'], dict) or set(generated['hashes']) != NATIVE_FILES
            or not all(_sha(value) for value in generated['hashes'].values())
            or completed['packages'] != generated['hashes']):
        fail('recorded native generation is invalid')
    return deepcopy({**selection, 'id': document['id'], 'source_manifest': document['source_manifest'],
                     'root_digests': document['root_digests'],
                     'completed': {name: completed[name] for name in STAGES}})


def _specifications(installation, identity):
    completed = identity['completed']
    result, generated = completed[RUNTIME], completed['prebuilt-package-generated']
    return {
        RUNTIME: (installation.base / RUNTIME,
                  {prebuilt_device.ARCHIVE: result['archive_sha256'],
                   prebuilt_device.RECEIPT: result['finalization_sha256']}),
        NATIVE: (installation.base / generated['directory'], generated['hashes']),
    }


def _check_directory(directory, hashes, *, allow_missing=False):
    directory = Path(directory)
    if not directory.exists() and not directory.is_symlink():
        if allow_missing:
            return False
        fail('recorded cache is missing')
    before = directory.lstat()
    if (directory.resolve() != directory or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700
            or set(path.name for path in directory.iterdir()) != set(hashes)):
        fail('cache has unexpected files or custody; preserve it')
    for name, expected in hashes.items():
        path = directory / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
            fail('cache file custody changed; preserve it')
        maximum = 65536 if name.endswith(('.manifest', '.json')) else finalizer.MAX_ARCHIVE
        if prebuilt_device._file_hash(path, maximum)[0] != expected:
            fail('cache bytes changed; preserve them')
    finalizer._unchanged(directory, before)
    return True


def _check_components(paths, identity, *, allow_missing=False):
    from .deploy import _finalized_package_hashes
    completed = identity['completed']
    result, generated = completed[RUNTIME], completed['prebuilt-package-generated']
    available = {name: _check_directory(path, hashes, allow_missing=allow_missing)
                 for name, (path, hashes) in paths.items()}
    if available[RUNTIME]:
        directory = paths[RUNTIME][0]
        if prebuilt_device._read_result(directory, completed['prebuilt-device-intent']) != result:
            fail('finalized runtime differs from its recorded result')
        receipt = device_context.validate_receipt(finalizer._load(regular_bytes(directory / prebuilt_device.RECEIPT, 65536)))
        if available[NATIVE] and _finalized_package_hashes(paths[NATIVE][0], receipt, result['finalization_sha256']) != generated['hashes']:
            fail('native provenance differs from the finalized runtime')
    return available


def capture_sources(installation, *, allow_missing=False):
    identity = authority(installation)
    if identity is None:
        return {}
    paths = _specifications(installation, identity)
    _check_components(paths, identity, allow_missing=allow_missing)
    return {name: path for name, (path, _) in paths.items()}


def assert_archive_authority(installation, archived):
    """The backup may supply bytes, never a replacement input selection."""
    if not isinstance(archived, dict) or not isinstance(archived.get('completed'), dict):
        fail('backup installation journal is invalid')
    current = authority(installation)
    selected = prebuilt_install.public_selection(archived)
    if current is None:
        if selected != {'input_selection': release_kit.selection()}:
            fail('backup input selection differs from this deployment')
        return None
    recorded = {**selected, 'id': archived.get('id'), 'source_manifest': archived.get('source_manifest'),
                'root_digests': archived.get('root_digests'),
                'completed': {name: archived.get('completed', {}).get(name) for name in STAGES}}
    if recorded != current:
        fail('backup selection or generation differs from this deployment')
    return current


def prepare_restore(installation, extracted, archived, operation_id, records):
    """Stage only wholly absent caches, under the current same-generation journal."""
    identity = assert_archive_authority(installation, archived)
    if identity is None:
        if any((extracted / name).exists() for name in COMPONENTS):
            fail('source backup contains unexpected prebuilt caches')
        return None, []
    live = _specifications(installation, identity)
    available = _check_components(live, identity, allow_missing=True)
    archived_paths = {}
    for name, (_, hashes) in live.items():
        path = extracted / name
        if path.exists() or path.is_symlink():
            storage.apply_metadata(path, records(name))
            archived_paths[name] = (path, hashes)
        elif not available[name]:
            fail('backup lacks a missing recorded cache')
    # Older backups omitted caches. An intact same-generation installation can
    # still roll back data; missing caches need a complete cache-bearing backup.
    if archived_paths:
        if set(archived_paths) != COMPONENTS:
            fail('backup contains an incomplete prebuilt cache set')
        _check_components(archived_paths, identity)
    plan = []
    for name, present in available.items():
        if present:
            continue
        destination = live[name][0]
        staged = destination.with_name('.iris-restore-' + operation_id + '-' + name)
        entries = records(name)
        storage.candidate(extracted / name, staged, entries)
        plan.append({'prebuilt_cache': name, 'target': str(destination), 'staged': str(staged),
                     'after': storage.fingerprint(entries)})
    return identity, plan


def assert_restore_authority(installation, recorded):
    if authority(installation) != recorded:
        fail('restore generation changed; preserve the approved operation')


def publish_missing(installation, item, recorded, operation_id):
    """Exclusive publication; interruption may reuse only this approved result."""
    assert_restore_authority(installation, recorded)
    specifications = _specifications(installation, recorded)
    name = item.get('prebuilt_cache')
    if name not in specifications:
        fail('restore cache component is invalid')
    target, hashes = specifications[name]
    staged = target.with_name('.iris-restore-' + operation_id + '-' + name)
    if (set(item) != {'prebuilt_cache', 'target', 'staged', 'after'}
            or item['target'] != str(target) or item['staged'] != str(staged) or not _sha(item['after'])):
        fail('restore cache paths differ from the recorded generation')
    descriptor = release_kit._protected_directory(target.parent)
    try:
        held = os.fstat(descriptor)
        already_published = target.exists() or target.is_symlink()
        if already_published:
            if staged.exists() or staged.is_symlink():
                fail('a cache appeared before publication; preserve it')
            candidate = target
        else:
            candidate = staged
        _check_directory(candidate, hashes)
        if storage.fingerprint(storage.inventory(candidate)) != item['after']:
            fail('restore cache candidate changed')
        current = target.parent.lstat()
        if (target.parent.resolve() != target.parent
                or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            fail('restore cache parent changed')
        if not already_published:
            finalizer._publish(descriptor, staged.name, target.name)
    finally:
        os.close(descriptor)
