# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Select an exact successor native generation for approved root maintenance.

Original finalized runtimes, native caches and their checkpoints are retained.
Only the protected trust transaction can reserve a successor. Ordinary resume
and backup readers use the same durable selector and never infer it from roots.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import device_finalize as f
from .state import InstallError, regular_bytes

FIELD = 'prebuilt_trust_generations'
STAGES = ('prebuilt-device-intent', 'prebuilt-device-runtime',
          'prebuilt-package-intent', 'prebuilt-package-generated', 'packages')


def fail():
    raise InstallError('Prebuilt trust generation changed; preserve the installation and recover the approved operation')


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            fail()
    except ValueError:
        fail()
    return value


def _hashes(value):
    if (not isinstance(value, dict) or len(value) != 2
            or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.pub', name)
                   or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                   for name, digest in value.items())):
        fail()
    return value


def runtime_name(document):
    state = document.get(FIELD)
    if state is None:
        return 'prebuilt-device-runtime'
    if not isinstance(state, dict) or set(state) != {'current', 'history'}:
        fail()
    return 'prebuilt-device-runtime-' + _uuid(state['current'])


def _generation(completed, roots):
    """Validate journal metadata without requiring historical cache inodes."""
    from .deploy import NATIVE_FILES
    if not isinstance(completed, dict) or set(completed) != set(STAGES):
        fail()
    intent = completed['prebuilt-device-intent']
    result = completed['prebuilt-device-runtime']
    generated = completed['prebuilt-package-generated']
    native_inputs = completed['prebuilt-package-intent']
    if (not isinstance(intent, dict) or intent.get('root_files_sha256') != roots
            or not isinstance(result, dict)
            or set(result) != {'schema', 'intent', 'finalization_sha256', 'archive_sha256', 'archive_size'}
            or type(result['schema']) is not int or result['schema'] != 1 or result['intent'] != intent
            or any(not isinstance(result[key], str) or not re.fullmatch('[0-9a-f]{64}', result[key])
                   for key in ('finalization_sha256', 'archive_sha256'))
            or type(result['archive_size']) is not int or not 0 < result['archive_size'] <= f.MAX_ARCHIVE
            or not isinstance(generated, dict) or set(generated) != {'schema', 'directory', 'hashes'}
            or type(generated['schema']) is not int or generated['schema'] != 1
            or not isinstance(generated['directory'], str)
            or not re.fullmatch(r'prebuilt-native-packages-[a-z0-9_]{8}', generated['directory'])
            or set(generated.get('hashes', {})) != NATIVE_FILES
            or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                   for value in generated['hashes'].values())
            or completed['packages'] != generated['hashes']):
        fail()
    if (not isinstance(native_inputs, dict)
            or set(native_inputs) != {'schema', 'kit', 'finalization_sha256', 'appmgr_sha256', 'appmgr_revision', 'ioxclient_sha256'}
            or type(native_inputs['schema']) is not int or native_inputs['schema'] != 1
            or native_inputs['kit'] != intent.get('kit')
            or native_inputs['finalization_sha256'] != result.get('finalization_sha256')
            or any(not isinstance(native_inputs[key], str) or not re.fullmatch('[0-9a-f]{64}', native_inputs[key])
                   for key in ('appmgr_sha256', 'ioxclient_sha256'))
            or not isinstance(native_inputs['appmgr_revision'], str)
            or not re.fullmatch('[0-9a-f]{40}', native_inputs['appmgr_revision'])):
        fail()


def _published(document, row):
    completed = document['completed']
    if any(name not in completed for name in STAGES):
        return False
    # The old package checkpoint temporarily survives host-root synchronization.
    # Only the exact successor's final package checkpoint ends predecessor CAS.
    if completed['packages'] == row['completed']['packages']:
        return False
    current = {name: completed[name] for name in STAGES}
    _generation(current, row['after'])
    expected = dict(row['completed']['prebuilt-device-intent'], root_files_sha256=row['after'])
    if current['prebuilt-device-intent'] != expected:
        fail()
    return True


def _caches(installation, row):
    """Read only the exact previous two caches through existing validators."""
    from . import prebuilt_device as d, device_context
    from .deploy import _finalized_package_hashes
    completed = row['completed']
    _generation(completed, row['before'])
    intent, result = completed['prebuilt-device-intent'], completed['prebuilt-device-runtime']
    generated = completed['prebuilt-package-generated']
    directory = installation.base / ('prebuilt-device-runtime' + ('-' + row['previous'] if row['previous'] else ''))
    native = installation.base / generated['directory']
    paths = {directory: {d.ARCHIVE: result['archive_sha256'], d.RECEIPT: result['finalization_sha256']},
             native: generated['hashes']}
    snapshot = {}
    for root, files in paths.items():
        info = root.lstat()
        if (root.resolve() != root or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or set(os.listdir(root)) != set(files)):
            fail()
        snapshot[str(root.relative_to(installation.base))] = list(f._fingerprint(info))
        for name, digest in files.items():
            path = root / name
            meta = path.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_nlink != 1
                    or stat.S_IMODE(meta.st_mode) != 0o444
                    or d._file_hash(path, 65536 if name.endswith(('.json', '.manifest')) else f.MAX_ARCHIVE)[0] != digest):
                fail()
            snapshot[str(path.relative_to(installation.base))] = list(f._fingerprint(meta))
        f._unchanged(root, info)
    if d._read_result(directory, intent) != result:
        fail()
    receipt = device_context.validate_receipt(f._load(regular_bytes(directory / d.RECEIPT, 65536)))
    if _finalized_package_hashes(native, receipt, result['finalization_sha256']) != generated['hashes']:
        fail()
    for relative, identity in snapshot.items():
        if list(f._fingerprint((installation.base / relative).lstat())) != identity:
            fail()
    return snapshot


def selected(installation, *, in_transition=False):
    document = installation.journal.document
    state = document.get(FIELD)
    if state is None:
        return None
    runtime_name(document)
    history = state['history']
    if not isinstance(history, dict) or not 1 <= len(history) <= 100 or state['current'] not in history:
        fail()
    current, seen = state['current'], set()
    while current is not None:
        _uuid(current)
        if current in seen or current not in history:
            fail()
        seen.add(current); row = history[current]
        if (not isinstance(row, dict) or set(row) != {'previous', 'before', 'after', 'transition_sha256', 'completed', 'caches'}
                or not isinstance(row['completed'], dict) or set(row['completed']) != set(STAGES)
                or not isinstance(row['transition_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['transition_sha256'])
                or _hashes(row['before']) == _hashes(row['after']) or set(row['before']) != set(row['after'])):
            fail()
        _generation(row['completed'], row['before'])
        transition = {'before': row['before'], 'after': row['after'], 'packages_before': row['completed']['packages']}
        if hashlib.sha256(json.dumps(transition, sort_keys=True).encode()).hexdigest() != row['transition_sha256']:
            fail()
        # A backup retains the completed current generation, not every old
        # inode. Old cache identities remain acquisition evidence in the journal;
        # only an unfinished current publication still depends on those inodes.
        if current == state['current'] and not _published(document, row):
            raw = regular_bytes(installation.base / ('trust-roots-' + current + '.json'), 65536)
            if hashlib.sha256(raw).hexdigest() != row['transition_sha256'] or _caches(installation, row) != row['caches']:
                fail()
        previous = row['previous']
        if previous is not None and (previous not in history or history[previous]['after'] != row['before']):
            fail()
        current = previous
    row = history[state['current']]
    if (seen != set(history) or document.get('root_digests') not in
            ([row['before'], row['after']] if in_transition else [row['after']])):
        fail()
    return row


def reserve(installation, request_id, transition):
    """Journal old generation before resetting only current acquisition slots."""
    from . import prebuilt_install, prebuilt_backup
    if not prebuilt_install.selected(installation.journal.document):
        return
    request_id = _uuid(request_id)
    document = installation.journal.document
    state = document.get(FIELD)
    if state is not None and state.get('current') == request_id:
        row = selected(installation, in_transition=True)
        if transition != {'before': row['before'], 'after': row['after'], 'packages_before': row['completed']['packages']}:
            fail()
        return
    prior = selected(installation) if state is not None else None
    if (not isinstance(transition, dict) or set(transition) != {'before', 'after', 'packages_before'}
            or document['root_digests'] != transition['before'] or transition['before'] == transition['after']):
        fail()
    # Authenticate the completed old acquisition before preserving its slots.
    prebuilt_backup.capture_sources(installation)
    completed = document['completed']
    if transition['packages_before'] != completed.get('packages'):
        fail()
    raw = regular_bytes(installation.base / ('trust-roots-' + request_id + '.json'), 65536)
    if json.loads(raw) != transition:
        fail()
    row = {'previous': state['current'] if prior is not None else None,
           'before': deepcopy(transition['before']), 'after': deepcopy(transition['after']),
           'transition_sha256': hashlib.sha256(raw).hexdigest(),
           'completed': {name: deepcopy(completed[name]) for name in STAGES}}
    row['caches'] = _caches(installation, row)
    history = deepcopy(state['history']) if state is not None else {}
    if request_id in history or len(history) >= 100:
        fail()
    history[request_id] = row
    for name in STAGES[:-1]:
        completed.pop(name)
    # packages remains the old cold-backup checkpoint until finish invalidates
    # it. The old immutable native cache authorizes the later six-file CAS.
    document[FIELD] = {'current': request_id, 'history': history}
    installation.journal.save()


def predecessor_packages(installation):
    row = selected(installation)
    return None if row is None or _published(installation.journal.document, row) else deepcopy(row['completed']['packages'])


def publication_complete(installation):
    row = selected(installation)
    return row is not None and _published(installation.journal.document, row)


def recovery_sources(installation):
    """Structural source plan during exact stopped-writer trust recovery only.

    The existing transaction has already authenticated its original cold backup.
    A partially generated successor is not a complete backup generation: keep
    using the held predecessor caches while the same operation finishes it.
    """
    if getattr(installation, 'credential_recovery', False) is not True:
        return None
    transaction = getattr(installation, 'credential_transaction', None)
    if transaction is None or getattr(transaction, 'kind', None) != 'instruction-roots':
        return None
    row = selected(installation)
    if row is None or _published(installation.journal.document, row):
        return None
    request_id = installation.journal.document[FIELD]['current']
    record = transaction.record
    if (transaction.id != request_id or record.get('operation_id') != request_id
            or record.get('kind') != 'instruction-roots' or record.get('mutations_admitted') is not True
            or record.get('initial_clean_stop') is not True
            or record.get('instance_id') != installation.journal.document['id']
            or record.get('phase') in ('rotated', 'refused', 'backup-pending')
            or json.loads(regular_bytes(installation.base / 'credential-operations' / request_id / 'record.json')) != record
            or json.loads(regular_bytes(installation.base / 'credential-operation.json')) != record):
        fail()
    return {'prebuilt-device-runtime': installation.base / ('prebuilt-device-runtime' + ('-' + row['previous'] if row['previous'] else '')),
            'prebuilt-native-packages': installation.base / row['completed']['prebuilt-package-generated']['directory']}
