# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Keep the exact local k3s runtime available across a stopped restore."""

import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import time
from pathlib import Path

from . import backup_archive
from .state import InstallError, regular_bytes

PIN = 'io.cri-containerd.pinned=pinned'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def _references(install):
    completed = install.journal.document['completed']
    refs = completed.get('kube-images', {})
    sources = completed.get('images', {})
    if (set(refs) != {'iris', 'console'} or not isinstance(sources, dict) or not sources
            or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in sources.values())
            or any(not isinstance(v, str) or not re.fullmatch(r'[^@\s]+@sha256:[0-9a-f]{64}', v)
                   for v in refs.values())):
        raise InstallError('Restore requires the recorded immutable Kubernetes runtime')
    return dict(refs), dict(sources)


def _images(install):
    raw = install.command(['k3s', 'ctr', 'images', 'list'], capture=True)
    if len(raw) > 4 * 1024 * 1024:
        raise InstallError('Kubernetes image inventory exceeds the read limit')
    result = {}
    lines = raw.decode().splitlines()
    if not lines or lines[0].split()[:3] != ['REF', 'TYPE', 'DIGEST']:
        raise InstallError('Kubernetes image inventory has no expected header')
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 3 or not DIGEST.fullmatch(fields[2]) or fields[0] in result:
            raise InstallError('Kubernetes image inventory is ambiguous')
        result[fields[0]] = fields[2]
    return result


def _matches(images, reference):
    expected = reference.rsplit('@', 1)[1]
    if reference in images and images[reference] != expected:
        raise InstallError('Recorded Kubernetes image reference has changed content')
    return images.get(reference) == expected


def _archive_roots(path, expected):
    """Check every exported image root before importing an authenticated archive."""
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise InstallError('Unsafe authenticated container image archive')
    selected = {}
    wanted = {'index.json', 'manifest.json', *('blobs/sha256/' + value[7:] for value in expected),
              *(value[7:] + '.json' for value in expected)}
    with tarfile.open(path) as archive:
        for count, member in enumerate(archive):
            if count >= 8192:
                raise InstallError('Container image archive has too many members')
            if member.name in wanted:
                if member.name in selected or not member.isfile() or not 0 < member.size <= 1024 * 1024:
                    raise InstallError('Ambiguous container image archive identity')
                selected[member.name] = archive.extractfile(member).read()
    try:
        if 'index.json' in selected:
            roots = json.loads(selected['index.json'])['manifests']
            if (not isinstance(roots, list) or len(roots) != len(expected)
                    or {row['digest'] for row in roots} != expected
                    or any('sha256:' + hashlib.sha256(selected['blobs/sha256/' + value[7:]]).hexdigest() != value
                           for value in expected)):
                raise ValueError()
        else:
            roots = json.loads(selected['manifest.json'])
            configs = [row['Config'] for row in roots]
            if (len(configs) != len(expected) or len(set(configs)) != len(configs)
                    or {('sha256:' + name[:-5]) for name in configs if re.fullmatch(r'[0-9a-f]{64}\.json', name)} != expected
                    or any(hashlib.sha256(selected[name]).hexdigest() != name[:-5] for name in configs)):
                raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise InstallError('Authenticated image archive differs from the recorded runtime') from None


def _import_missing(install, transaction, verified, references, sources):
    if shutil.disk_usage(transaction.directory).free < verified['bytes'] + 1024 ** 3:
        raise InstallError('Insufficient space to recover authenticated Kubernetes images')
    backup = transaction.backups / transaction.backup_id
    expected = transaction.record['data_sha256']
    if backup_archive.authenticate(backup, transaction.signer)['payload_sha256'] != expected:
        raise InstallError('Approved restore backup bytes changed')
    with tempfile.TemporaryDirectory(prefix='restore-runtime-', dir=transaction.directory) as temporary:
        extracted = Path(temporary) / 'data'
        report = backup_archive.read(backup, transaction.identity, transaction.signer,
                                     destination=extracted, max_bytes=verified['bytes'])
        if (report['metadata'] != verified['metadata'] or report['bytes'] != verified['bytes']
                or backup_archive.authenticate(backup, transaction.signer)['payload_sha256'] != expected):
            raise InstallError('Authenticated restore runtime changed during recovery')
        archive = extracted / 'container-images'
        inventory = json.loads(regular_bytes(extracted / 'RESTORE-INVENTORY.json', backup_archive.MAX_MANIFEST))
        rows = [row for row in inventory['files'] if row['name'] == 'container-images']
        if len(rows) != 1 or rows[0]['type'] != 'file':
            raise InstallError('Authenticated backup has no exact container image archive')
        before = archive.stat()
        if before.st_size != rows[0]['size']:
            raise InstallError('Authenticated image archive size changed')
        _archive_roots(archive, set(sources.values()))
        digest = hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != rows[0]['sha256']:
            raise InstallError('Authenticated image archive bytes changed')
        # No Docker dependency: the signed backup already carries the exact
        # immutable builds. Pin at import so kubelet cannot collect them again.
        install.command(['k3s', 'ctr', 'images', 'import', '--digests', '--label', PIN, archive])
        images = _images(install)
        for reference in references.values():
            if _matches(images, reference):
                continue
            digest = reference.rsplit('@', 1)[1]
            candidates = sorted(name for name, value in images.items() if value == digest)
            if not candidates:
                raise InstallError('Authenticated import did not restore the required Kubernetes digest')
            install.command(['k3s', 'ctr', 'images', 'tag', candidates[0], reference])


def prepare(install, transaction, verified):
    """Called after restore authentication and before any writer is stopped."""
    if install.config['kube_image_import'] != 'k3s':
        return
    install.verify_resource_ownership()
    references, sources = _references(install)
    images = _images(install)
    present = [_matches(images, value) for value in references.values()]
    if not all(present):
        _import_missing(install, transaction, verified, references, sources)
    protect_runtime(install)
    if _references(install) != (references, sources):
        raise InstallError('Recorded Kubernetes runtime changed during restore preparation')


def protect_runtime(install):
    """Pin both local workloads before any backup, rotation or restore stop."""
    if install.config['kube_image_import'] != 'k3s':
        return
    install.verify_resource_ownership()
    references, sources = _references(install)
    images = _images(install)
    present = [_matches(images, reference) for reference in references.values()]
    if not all(present):
        raise InstallError('Required Kubernetes image is unavailable before stopping services')
    for reference in references.values():
        install.command(['k3s', 'ctr', 'images', 'label', reference, PIN])
    # CRI is kubelet's authority for image GC; a ctr label alone is insufficient.
    deadline = time.monotonic() + 10
    while True:
        pinned = True
        for reference in references.values():
            value = json.loads(install.command(['k3s', 'crictl', 'inspecti', reference], capture=True))
            status = value.get('status', {})
            if (reference not in status.get('repoDigests', []) or not DIGEST.fullmatch(str(status.get('id', '')))):
                raise InstallError('CRI image identity does not match the recorded runtime')
            pinned = pinned and status.get('pinned') is True
        if pinned:
            break
        if time.monotonic() >= deadline:
            raise InstallError('Kubernetes runtime images are not protected from automatic collection')
        time.sleep(.1)
    if _references(install) != (references, sources):
        raise InstallError('Recorded Kubernetes runtime changed during image protection')
    install.verify_resource_ownership()
