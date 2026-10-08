# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Fenced, resumable directory publication with retained original bytes.

The lifecycle transaction must stop every consumer before calling these
functions. Every admitted path comes from the deployment adapter, never RPC.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import uuid

from .state import InstallError, atomic_write


def inventory(root):
    """Describe exact bytes and custody; reject links and special files."""
    root = Path(root)
    if root.resolve() != root:
        raise InstallError('Restore storage traverses a link')
    records = []
    def visit(path, name):
        info = path.lstat()
        if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or stat.S_IMODE(info.st_mode) & 0o7000
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise InstallError('Restore storage contains unsupported custody')
        record = dict(name=name, type='directory' if path.is_dir() else 'file',
                      mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
                      size=0, sha256=None)
        records.append(record)
        if len(records) > 100000:
            raise InstallError('Restore component exceeds its file limit')
        if record['type'] == 'directory':
            for child in sorted(path.iterdir()):
                visit(child, child.name if not name else name + '/' + child.name)
        else:
            value = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    value.update(chunk)
            record.update(size=info.st_size, sha256=value.hexdigest())
        after = path.lstat()
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallError('Restore storage changed during verification')
    visit(root, '')
    return records


def fingerprint(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_metadata(root, records):
    for record in reversed(records):
        path = root / record['name']
        os.chown(path, record['uid'], record['gid'])
        path.chmod(record['mode'])
        if record['type'] == 'file':
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            sync(path)


def candidate(source, target, records):
    """Create a fresh same-filesystem candidate, restoring authenticated modes."""
    source, target = Path(source), Path(target)
    if target.exists() or target.is_symlink():
        if inventory(target) == records:
            return
        # A crash during preparation cannot authorize partial bytes. Retain
        # that exact operation candidate for diagnosis, then stage afresh.
        os.rename(target, target.with_name(target.name + '-incomplete-' + str(uuid.uuid4())))
        sync(target.parent)
    shutil.copytree(source, target)
    apply_metadata(target, records)
    if inventory(target) != records:
        raise InstallError('Restore candidate differs from its authenticated inventory')
    sync(target.parent)


def publish(target, staged, retained, before, after):
    """Resume either side of a rename; never overwrite unexpected live bytes."""
    target, staged, retained = map(Path, (target, staged, retained))
    if len({target.parent, staged.parent, retained.parent}) != 1:
        raise InstallError('Restore publication must remain on its storage filesystem')
    def actual(path):
        return fingerprint(inventory(path)) if path.exists() or path.is_symlink() else None
    current, pending, old = actual(target), actual(staged), actual(retained)
    if old is not None and old != before:
        raise InstallError('Retained restore preimage changed')
    if old == before and current == after and pending is None:
        return
    if current == before and pending == after and old is None:
        os.rename(target, retained)
        sync(target.parent)
        current, old = None, before
    if current is None and old == before and pending == after:
        os.rename(staged, target)
        sync(target.parent)
        return
    raise InstallError('Restore publication differs from the approved original or candidate')
