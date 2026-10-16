# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Resume deployment-specific public trust finalization without rebuilding.

Native wrapper generation and native signatures remain separate operations.
Only the authenticated neutral runtime and the recorded public roots enter this
cache. Interrupted publication is recovered by reproducing its exact bytes.
"""

import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from . import device_finalize
from .prebuilt_install import _kit
from .state import InstallError, regular_bytes


OUTPUT = 'prebuilt-device-runtime'
ARCHIVE = 'iris-device.oci.tar'
RECEIPT = ARCHIVE + '.finalization.json'
HEX = re.compile(r'[0-9a-f]{64}')


def _file_hash(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise InstallError('Finalized runtime contains an invalid file')
        value, size = hashlib.sha256(), 0
        while block := os.read(descriptor, 1024 * 1024):
            size += len(block)
            if size > maximum:
                raise InstallError('Finalized runtime exceeds its size limit')
            value.update(block)
        after = os.fstat(descriptor)
        if (device_finalize._fingerprint(before) != device_finalize._fingerprint(after)
                or size != before.st_size):
            raise InstallError('Finalized runtime changed during verification')
        named = Path(path).lstat()
        if device_finalize._fingerprint(named) != device_finalize._fingerprint(before):
            raise InstallError('Finalized runtime changed during verification')
        return value.hexdigest(), size
    finally:
        os.close(descriptor)


def _intent(installation, kit):
    from .deploy import read_roots
    asset = kit.asset('device-runtime')
    if (asset.format != 'oci-archive' or asset.platforms != ('linux/amd64', 'linux/arm64')
            or not HEX.fullmatch(asset.neutral_source_sha256)):
        raise InstallError('Authenticated kit does not identify a neutral dual-architecture runtime')
    roots = {name: hashlib.sha256(data).hexdigest()
             for name, data in read_roots(installation.base / 'roots').items()}
    if roots != installation.journal.document['root_digests']:
        raise InstallError('Public roots changed before device finalization')
    manifest = installation.journal.document['source_manifest']
    module_digest = hashlib.sha256(Path(device_finalize.__file__).read_bytes()).hexdigest()
    renderer_digest = hashlib.sha256(Path(device_finalize.instruction_module().__file__).read_bytes()).hexdigest()
    if (manifest.get('tools/iris_installer/device_finalize.py') != module_digest
            or manifest.get('server/instruction_keys.py') != renderer_digest):
        raise InstallError('Finalizer or public trust renderer differs from the recorded source')
    return {'schema': 1, 'kit': kit.receipt(), 'base_archive_sha256': asset.sha256,
            'base_index_digest': asset.image_digest, 'neutral_source_sha256': asset.neutral_source_sha256,
            'root_files_sha256': roots, 'finalizer_source_commit': kit.commit,
            'finalizer_module_sha256': module_digest, 'trust_renderer_sha256': renderer_digest}


def _read_result(directory, intent):
    directory = Path(directory)
    info = directory.lstat()
    if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or set(path.name for path in directory.iterdir()) != {ARCHIVE, RECEIPT}):
        raise InstallError('Finalized runtime directory has unexpected contents')
    raw = regular_bytes(directory / RECEIPT, 65536)
    try:
        receipt = device_finalize._load(raw)
    except InstallError:
        raise InstallError('Finalized runtime receipt is invalid') from None
    if (not isinstance(receipt, dict) or receipt.get('format') != 'iris-device-finalized-v1'
            or any(receipt.get(key) != value for key, value in intent.items() if key not in ('schema', 'kit'))
            or not isinstance(receipt.get('platforms'), dict)
            or set(receipt['platforms']) != {'amd64', 'arm64'}
            or not isinstance(receipt.get('archive_sha256'), str)
            or not HEX.fullmatch(receipt['archive_sha256'])
            or type(receipt.get('archive_size')) is not int):
        raise InstallError('Finalized runtime receipt differs from the recorded inputs')
    archive_hash, size = _file_hash(directory / ARCHIVE, device_finalize.MAX_ARCHIVE)
    if (archive_hash, size) != (receipt['archive_sha256'], receipt['archive_size']):
        raise InstallError('Finalized runtime archive differs from its receipt')
    receipt_hash, receipt_size = _file_hash(directory / RECEIPT, 65536)
    if receipt_hash != hashlib.sha256(raw).hexdigest() or receipt_size != len(raw):
        raise InstallError('Finalized runtime receipt changed during verification')
    return {'schema': 1, 'intent': intent, 'finalization_sha256': receipt_hash,
            'archive_sha256': archive_hash, 'archive_size': size}


def prepare_runtime(installation):
    """Return the private finalized directory and its journal-pinned receipt."""
    kit = _kit(installation)
    intent = _intent(installation, kit)
    completed = installation.journal.document['completed']
    pending, stage = 'prebuilt-device-intent', 'prebuilt-device-runtime'
    from .prebuilt_trust import selected, runtime_name
    selected(installation)
    output = installation.base / runtime_name(installation.journal.document)
    if pending in completed and completed[pending] != intent:
        raise InstallError('Device finalization inputs changed; preserve the existing journal')
    saved = completed.get(stage)
    if saved is not None:
        if pending not in completed or saved != _read_result(output, intent):
            raise InstallError('Recorded device finalization changed; refusing to reuse it')
        return output, saved['finalization_sha256']
    if pending not in completed:
        if output.exists() or output.is_symlink():
            raise InstallError('An unrecorded finalized runtime exists; refusing adoption')
        installation.journal.checkpoint(pending, intent)
    with tempfile.TemporaryDirectory(prefix='device-finalization-', dir=installation.base) as temporary:
        scratch = Path(temporary)
        neutral = scratch / 'neutral.oci.tar'
        kit.copy_asset('device-runtime', neutral)
        recovering = output.exists() or output.is_symlink()
        target = scratch / 'reproduced' if recovering else output
        device_finalize.finalize(
            neutral, installation.base / 'roots', target,
            expected_archive_sha256=intent['base_archive_sha256'],
            neutral_source_sha256=intent['neutral_source_sha256'],
            finalizer_source_commit=kit.commit)
        evidence = _read_result(target, intent)
        if recovering and _read_result(output, intent) != evidence:
            raise InstallError('Interrupted finalization differs from reproduced bytes; nothing was replaced')
    installation.journal.checkpoint(stage, evidence)
    return output, evidence['finalization_sha256']
