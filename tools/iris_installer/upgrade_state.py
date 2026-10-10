# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable application-upgrade authority shared by CLI and pinned workers."""

import json
import os
from pathlib import Path
import stat

from .state import InstallError, atomic_write, regular_bytes
from .upgrade_plan import SCHEMA, canonical, identifier, sha256

PHASES = frozenset(('building', 'prepared', 'fencing', 'backing-up', 'stopped',
    'publishing', 'published', 'starting', 'verifying', 'worker', 'finishing',
    'upgraded', 'cancelled', 'recovery-required'))
PASSIVE = frozenset(('building', 'prepared', 'cancelled', 'upgraded'))
LIMIT = 16 * 1024 * 1024


def private_directory(path):
    path = Path(path).absolute()
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise InstallError('Unsafe application upgrade custody; preserve the directory')
    return path


def read(path):
    info = Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise InstallError('Unsafe application upgrade record; preserve the file')
    try:
        return json.loads(regular_bytes(path, LIMIT))
    except (OSError, ValueError):
        raise InstallError('Unreadable application upgrade authority; preserve the operation') from None


def validate(record, *, operation_id=None, instance_id=None):
    if (not isinstance(record, dict) or type(record.get('schema')) is not int
            or record['schema'] != 1 or not isinstance(record.get('phase'), str) or record['phase'] not in PHASES):
        raise InstallError('Unsupported application upgrade authority')
    identifier(record.get('operation_id'))
    identifier(record.get('instance_id'))
    if ((operation_id is not None and operation_id != record['operation_id'])
            or (instance_id is not None and instance_id != record['instance_id'])):
        raise InstallError('Application upgrade belongs to another operation or installation')
    return record


def pointer(record):
    return {name: record[name] for name in ('operation_id', 'instance_id', 'phase')}


def guard(state_dir, *, operation_id=None, instance_id=None, recovery_record=None, inspection=False):
    """Only the explicit same-ID backend may repair a record→pointer crash.

    Preparation builds isolated candidates and does not pause application use.
    From the first fence intent onwards every other maintenance write refuses.
    A missing or invalid pointer is never interpreted as an idle deployment.
    """
    base = Path(state_dir)
    directory = base / 'application-upgrades'
    current = base / 'application-upgrade.json'
    try:
        exists = current.exists() or current.is_symlink()
        if not directory.exists() and not directory.is_symlink():
            if exists:
                raise InstallError('Application upgrade records are missing; preserve state')
            return
        private_directory(directory)
        operations = sorted(directory.iterdir())
        if not operations and not exists:
            return
        if exists:
            selected = read(current)
            if not isinstance(selected, dict) or set(selected) != {'operation_id', 'instance_id', 'phase'}:
                raise InstallError('Invalid application upgrade pointer')
            validate(dict(selected, schema=1), instance_id=instance_id)
        elif recovery_record is not None:
            selected = pointer(validate(recovery_record, operation_id=operation_id, instance_id=instance_id))
        else:
            raise InstallError('Application upgrade pointer is missing; recover the approved operation')
        seen = False
        pending = False
        recovery_seen = False
        for operation in operations:
            identifier(operation.name)
            private_directory(operation)
            saved = validate(read(operation / 'record.json'), operation_id=operation.name,
                             instance_id=selected['instance_id'])
            if operation.name == selected['operation_id']:
                seen = True
                if (canonical(pointer(saved)) != canonical(selected)
                        and not (recovery_record is not None and operation.name == operation_id)):
                    raise InstallError('Application upgrade pointer differs from its record; recover the exact operation')
            blocked = saved['phase'] not in PASSIVE or (
                saved['phase'] in ('building', 'prepared') and 'boot_guard_intent' in saved)
            if blocked and operation.name != operation_id:
                pending = True
                if not inspection:
                    raise InstallError('Recover the interrupted application upgrade before other maintenance')
            if recovery_record is not None and operation.name == operation_id:
                if canonical(saved) != canonical(recovery_record) or saved['instance_id'] != instance_id:
                    raise InstallError('Application upgrade recovery authority changed')
                recovery_seen = True
        if not seen or (recovery_record is not None and not recovery_seen):
            raise InstallError('Application upgrade pointer has no matching operation')
        if selected['phase'] not in PASSIVE and selected['operation_id'] != operation_id:
            pending = True
            if not inspection:
                raise InstallError('Recover the interrupted application upgrade before other maintenance')
        if recovery_record is not None:
            atomic_write(current, canonical(pointer(recovery_record)))
        return pending
    except OSError:
        raise InstallError('Application upgrade custody is unavailable; preserve state') from None


def protected_backups(state_dir, backup_dir, recovery_dir):
    """Observe only exact approved upgrade capture paths; never adopt or delete.

    These archives have separate recovery authority and are not ordinary UUID
    worker backups. A prefix alone grants no exception to the storage census.
    """
    base = private_directory(state_dir)
    installation = read(base / 'installation.json')
    instance = identifier(installation.get('id'))
    pending = bool(guard(base, instance_id=instance, inspection=True))
    directory = base / 'application-upgrades'
    if not directory.exists():
        return {}, pending
    result = {}
    for child in sorted(directory.iterdir()):
        private_directory(child)
        operation = Operation(base, identifier(child.name), instance)
        operation.record = validate(read(operation.path), operation_id=operation.id, instance_id=instance)
        attempts = operation.record.get('backup_attempts', [])
        if not isinstance(attempts, list) or len(attempts) > 3:
            raise InstallError('Invalid application upgrade backup attempts; preserve custody')
        if not attempts:
            continue
        review = operation.plan(operation.record.get('plan_sha256'))
        worker = review.get('worker_before', {}).get('record', {})
        if (review.get('schema') != SCHEMA or review.get('original', {}).get('id') != instance
                or canonical(review.get('original')) != canonical(operation.record.get('original'))
                or canonical(review.get('worker_before')) != canonical(operation.record.get('worker_before'))
                or worker.get('instance_id') != instance or worker.get('state_dir') != str(base)
                or worker.get('unit') != 'iris-lifecycle-' + instance + '.service'
                or any(worker.get('storage', {}).get(kind, {}).get('directory') != str(path)
                       for kind, path in (('backup', backup_dir), ('recovery', recovery_dir)))):
            raise InstallError('Application upgrade backup ownership differs from its approved plan')
        verified = operation.record.get('backup')
        if verified is not None and (not isinstance(verified, dict) or verified.get('paths') not in attempts):
            raise InstallError('Application upgrade verified backup differs from its recorded attempts')
        for index, attempt in enumerate(attempts, 1):
            suffix = 'upgrade-' + operation.id + '-' + str(index)
            expected = {'data': str(Path(backup_dir) / suffix), 'identity': str(Path(recovery_dir) / suffix)}
            if attempt != expected:
                raise InstallError('Application upgrade archive path differs from its exact owned attempt')
            if verified is not None and verified['paths'] == attempt:
                for path in expected.values():
                    # A successful authenticated capture cannot silently lose
                    # a side and become an apparently unused storage slot.
                    private_directory(path)
            public = {'operation_id': operation.id, 'attempt': index, 'phase': operation.record['phase']}
            for name, path in expected.items():
                result[path] = (public, 'deployment_archive' if name == 'data' else 'recovery_archive')
        if canonical(read(operation.path)) != canonical(operation.record):
            raise InstallError('Application upgrade authority changed during backup observation')
    if bool(guard(base, instance_id=instance, inspection=True)) != pending:
        raise InstallError('Application upgrade state changed during backup observation')
    return result, pending


class Operation:
    """Caller holds the installation and service locks around every write."""

    def __init__(self, base, operation_id, instance_id):
        self.base = private_directory(base)
        self.id, self.instance = identifier(operation_id), identifier(instance_id)
        self.directory = self.base / 'application-upgrades' / self.id
        self.path = self.directory / 'record.json'
        self.record = None

    def create(self, values):
        guard(self.base, instance_id=self.instance)
        parent = self.directory.parent
        parent.mkdir(mode=0o700, exist_ok=True)
        private_directory(parent)
        pending = self.base / ('.upgrade-intent-' + self.id)
        pending.mkdir(mode=0o700)
        self.record = dict(values, schema=1, operation_id=self.id, instance_id=self.instance,
                           phase='building')
        validate(self.record, operation_id=self.id, instance_id=self.instance)
        atomic_write(pending / 'record.json', canonical(self.record))
        from .restore_storage import sync
        sync(pending)
        os.rename(pending, self.directory)
        sync(parent)
        sync(self.base)
        atomic_write(self.base / 'application-upgrade.json', canonical(pointer(self.record)))

    def load(self, *, recover=False):
        private_directory(self.directory)
        self.record = validate(read(self.path), operation_id=self.id, instance_id=self.instance)
        guard(self.base, operation_id=self.id, instance_id=self.instance,
              recovery_record=self.record if recover else None)
        return self.record

    def save(self):
        validate(self.record, operation_id=self.id, instance_id=self.instance)
        atomic_write(self.path, canonical(self.record))
        # The record precedes its pointer; explicit recovery repairs only this
        # known, validated window and cannot replace conflicting custody.
        atomic_write(self.base / 'application-upgrade.json', canonical(pointer(self.record)))

    def phase(self, phase, **evidence):
        self.record.update(evidence, phase=phase)
        self.save()

    def write_plan(self, plan):
        payload = canonical(plan)
        path = self.directory / 'plan.json'
        if path.exists() or path.is_symlink():
            if regular_bytes(path, LIMIT) != payload:
                raise InstallError('The reviewed application upgrade plan cannot be replaced')
        else:
            atomic_write(path, payload)
        import hashlib
        self.phase('prepared', plan_sha256=hashlib.sha256(payload).hexdigest())

    def plan(self, expected):
        import hashlib
        sha256(expected)
        payload = regular_bytes(self.directory / 'plan.json', LIMIT)
        if (hashlib.sha256(payload).hexdigest() != expected
                or self.record.get('plan_sha256') != expected):
            raise InstallError('The application upgrade plan does not match the explicit approval')
        value = read(self.directory / 'plan.json')
        if (not isinstance(value, dict) or value.get('operation_id') != self.id or value.get('instance_id') != self.instance):
            raise InstallError('The application upgrade plan belongs to another deployment')
        return value
