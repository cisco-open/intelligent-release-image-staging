# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit history retirement and exact, recoverable on-host archive deletion."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

from . import backup_archive
from .lifecycle_history import Store, RetentionConflict, digest, identifier, public_operation
from .state import InstallError, Journal, regular_bytes


TERMINAL = {'captured', 'verified-files', 'verified-isolated-files', 'failed', 'restored', 'rotated', 'renewed'}
FILES = ('manifest.json', 'manifest.json.sig', 'payload.tar.age')


def _exists(path):
    return path.exists() or path.is_symlink()


def _identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]


class Retention:
    def __init__(self, worker):
        self.worker = worker
        self.store = Store(worker.state_dir)
        self.store.reconcile(worker.jobs, worker.save)
        for record in self.store.pending():
            if record['action'] != 'delete-backup':
                raise InstallError('Incomplete maintenance history retirement requires inspection')
            record['state'] = 'recovery-required'
            self.store.update(record)

    def guard(self, request_id=None):
        if request_id is not None:
            if self.store.retired(request_id) or self.store.operation(request_id) is not None:
                raise RetentionConflict('This maintenance request ID is retired or belongs to a retention operation; use a new request ID')
        if self.store.pending():
            raise RetentionConflict('Finish the pending backup deletion before another maintenance operation')

    def busy(self):
        return bool(self.store.pending()) or any(row.get('state') in ('running', 'recovery-required') for row in self.worker.jobs)

    def _operation_safe(self, job):
        action = job.get('action')
        directory = {'restore': 'restore-operations', 'rotate': 'credential-operations',
                     'renew-transport': 'lifecycle-transport-operations'}.get(action)
        if directory is None:
            if action == 'backup':
                path = self.worker.state_dir / 'backup-operation.json'
                if _exists(path):
                    operation = json.loads(regular_bytes(path))
                    if operation.get('restart_required') or operation.get('state') == 'stopping':
                        return False
            return True
        path = self.worker.state_dir / directory / identifier(job['id']) / 'record.json'
        if not _exists(path):
            return job['state'] == 'failed' and not job.get('restore_authority_started')
        operation = json.loads(regular_bytes(path))
        identity_field = 'request_id' if action == 'renew-transport' else 'operation_id'
        if operation.get(identity_field) != job['id']:
            return False
        if job['state'] == 'failed':
            return operation.get('phase') == 'refused' and not operation.get('mutations_admitted', False)
        expected = {'restore': 'restored', 'rotate': 'rotated', 'renew-transport': 'complete'}[action]
        return operation.get('phase') == expected

    def rotation_backups(self, job):
        if job.get('action') != 'rotate':
            return set()
        path = self.worker.state_dir / 'credential-operations' / identifier(job['id']) / 'record.json'
        if not _exists(path):
            return set()
        operation = json.loads(regular_bytes(path))
        if operation.get('operation_id') != job['id'] or operation.get('kind') != job.get('family'):
            raise InstallError('Credential backup ownership does not match its maintenance operation')
        values = [operation.get('backup_id'), *operation.get('abandoned_backup_ids', [])]
        return {identifier(value) for value in values if value is not None}

    def owners(self, backup_id):
        result = []
        for row in self.worker.jobs:
            if (row.get('action') == 'backup' and row.get('backup_id') == backup_id
                    or row.get('action') == 'rotate' and backup_id in self.rotation_backups(row)):
                result.append(row)
        return result

    def ownership(self, backup_id):
        rows = self.owners(backup_id)
        result = []
        for row in rows:
            proof = {'job_id': row['id'], 'job_sha256': digest(row)}
            if row['action'] == 'rotate':
                raw = regular_bytes(self.worker.state_dir / 'credential-operations' / row['id'] / 'record.json')
                proof['operation_sha256'] = hashlib.sha256(raw).hexdigest()
            result.append(proof)
        return result

    def deletable_owner(self, row):
        return (self._operation_safe(row) and (row['state'] in ('captured', 'rotated')
                or row.get('action') == 'backup' and row['state'] == 'failed'))

    def eligible(self, job, *, deleting=None):
        if job.get('state') not in TERMINAL:
            return False, 'This operation is running or needs recovery.'
        if not self._operation_safe(job):
            return False, 'Keep this row until its protected operation has completed.'
        backup_id = job.get('backup_id')
        if job.get('action') == 'backup' and backup_id != deleting:
            if job['state'] == 'captured' or any(_exists(root / identifier(backup_id)) for root in (self.worker.backup_dir, self.worker.recovery_dir)):
                return False, 'Delete the saved backup separately before clearing its capture row.'
        if job.get('action') == 'rotate':
            if any(value != deleting and any(_exists(root / value) for root in (self.worker.backup_dir, self.worker.recovery_dir))
                   for value in self.rotation_backups(job)):
                return False, 'Delete the saved rotation backups separately before clearing this row.'
        return True, ''

    def _storage_marker(self, path, kind):
        """Recognize only the managed worker's independently recorded custody."""
        def document(candidate):
            with os.fdopen(os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
                    raise InstallError('Unsafe managed backup custody file')
                raw = stream.read(4 * 1024 * 1024 + 1)
                signature = lambda value: (*_identity(value), value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                if (len(raw) > 4 * 1024 * 1024 or signature(before) != signature(os.fstat(stream.fileno()))
                        or signature(before) != signature(candidate.lstat())):
                    raise InstallError('Managed backup custody changed during observation')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise InstallError('Invalid managed backup custody')
            return value

        installation = document(self.worker.state_dir / 'installation.json')
        record = document(self.worker.state_dir / 'worker-service.json')
        instance = identifier(installation.get('id'))
        storage = record.get('storage')
        if (record.get('schema') != 1 or record.get('instance_id') != instance
                or record.get('state_dir') != str(self.worker.state_dir)
                or record.get('unit') != 'iris-lifecycle-' + instance + '.service'
                or not isinstance(storage, dict) or not isinstance(storage.get(kind), dict)
                or storage[kind].get('directory') != str(path.parent)
                or document(path) != {'instance_id': instance}):
            raise InstallError('Managed backup custody does not match this deployment')

    def backup_ids(self):
        found = set()
        for kind, root in (('backup', self.worker.backup_dir), ('recovery', self.worker.recovery_dir)):
            backup_archive.private_directory(root)
            for path in root.iterdir():
                if path.name == '.iris-storage.json':
                    self._storage_marker(path, kind)
                    continue
                if (path.name.startswith(('.iris-backup-', '.iris-verify-', '.iris-restore-'))
                        and (self.store.pending() or any(row.get('state') == 'running' for row in self.worker.jobs))):
                    # Product-owned temporary authentication/capture workspaces
                    # are not saved backup sets. Never delete them here.
                    backup_archive.private_directory(path)
                    continue
                # No guessing about unmanaged children or partial staging.
                identifier(path.name)
                backup_archive.private_directory(path)
                found.add(path.name)
        return found

    def status(self, request_id=None):
        pending = self.store.pending()
        physical = self.backup_ids()
        jobs = []
        busy = bool(pending) or any(row.get('state') in ('running', 'recovery-required') for row in self.worker.jobs)
        for row in self.worker.jobs:
            allowed, reason = self.eligible(row)
            jobs.append({'id': row['id'], 'action': row['action'], 'state': row['state'],
                         'backup_id': row.get('backup_id'), 'family': row.get('family'),
                         'finished_at': row.get('finished_at'), 'retire_allowed': allowed and not busy,
                         'retire_reason': 'Finish the active maintenance operation first.' if busy else reason})
        backups = []
        for backup_id in sorted(physical):
            owners = self.owners(backup_id)
            both = all(_exists(root / backup_id) for root in (self.worker.backup_dir, self.worker.recovery_dir))
            partial_capture = (len(owners) == 1 and owners[0].get('action') == 'backup'
                               and owners[0]['state'] == 'failed')
            allowed = (len(owners) == 1 and self.deletable_owner(owners[0])
                       and (both or partial_capture) and not busy and self.worker.identity is not None)
            if allowed:
                reason = ''
            elif busy:
                reason = 'Finish the active maintenance operation first.'
            elif self.worker.identity is None:
                reason = 'Set up recovery access on the installer host before deleting backups.'
            elif len(owners) != 1:
                reason = 'This backup is not linked to a single operation in this deployment.'
            elif not self.deletable_owner(owners[0]):
                reason = 'This backup is still protected for maintenance or recovery.'
            else:
                reason = 'This backup is missing an archive. Keep it for recovery review.'
            backups.append({'backup_id': backup_id, 'created_at': owners[0].get('finished_at') if owners else None,
                            'delete_allowed': allowed,
                            'delete_reason': reason})
        revision = digest({'jobs': self.worker.jobs, 'backups': backups, 'pending': pending})
        return {'schema': 1, 'revision': revision, 'busy': busy,
                'capacity': {'history_used': len(self.worker.jobs), 'history_limit': 100,
                             'backup_used': len(physical), 'backup_limit': 20},
                'jobs': jobs, 'backups': backups, 'operation': public_operation(self.store.operation(request_id))}

    def submit(self, request):
        action = request.get('action')
        base = {'action', 'request_id', 'expected_revision'}
        expected = base | ({'job_ids'} if action == 'retire-history' else {'backup_id', 'confirm_delete'})
        if action not in ('retire-history', 'delete-backup', 'resume-delete') or set(request) != expected:
            raise RetentionConflict('Choose history retirement or one exact saved backup')
        request_id = identifier(request['request_id'])
        if not isinstance(request['expected_revision'], str) or not re.fullmatch('[0-9a-f]{64}', request['expected_revision']):
            raise RetentionConflict('Refresh maintenance history before continuing')
        if action == 'retire-history':
            values = request['job_ids']
            if not isinstance(values, list) or not 1 <= len(values) <= 25 or any(not isinstance(v, str) for v in values) or len(set(values)) != len(values):
                raise RetentionConflict('Select between one and 25 distinct finished operations')
            for value in values:
                identifier(value)
        else:
            identifier(request['backup_id'])
            if request['confirm_delete'] is not True:
                raise RetentionConflict('Confirm deletion of the selected on-host backup archives')
        with self.worker.lock:
            normalized = dict(request, action='delete-backup') if action == 'resume-delete' else request
            previous = self.store.observe(normalized)
            if previous is not None and action != 'resume-delete':
                return {'retention_operation': public_operation(previous)}
            current = self.status()
            if current['revision'] != request['expected_revision']:
                raise RetentionConflict('Maintenance history changed. Refresh and review the selection again.')
            if action == 'resume-delete':
                if previous is None or previous['action'] != 'delete-backup' or previous['state'] != 'recovery-required':
                    raise RetentionConflict('Choose the exact interrupted backup deletion')
                if any(row['state'] in ('running', 'recovery-required') for row in self.worker.jobs):
                    raise RetentionConflict('Finish the active maintenance operation first')
                previous['state'] = 'running'
                self.store.update(previous)
                self._start(previous)
                return {'retention_operation': public_operation(previous)}
            if previous is not None or current['busy']:
                raise RetentionConflict('Finish the active maintenance operation first')
            if any(row['id'] == request_id for row in self.worker.jobs):
                raise RetentionConflict('Request ID belongs to an existing maintenance operation')
            record = {'request_id': request_id, 'action': action, 'state': 'running', 'retired_count': 0,
                      'backup_id': request.get('backup_id'), 'started_at': int(time.time())}
            if action == 'retire-history':
                selected = [row for row in self.worker.jobs if row['id'] in request['job_ids']]
                if len(selected) != len(request['job_ids']) or not all(self.eligible(row)[0] for row in selected):
                    raise RetentionConflict('Only the exact selected finished operations can be cleared')
                with Journal(self.worker.state_dir).locked():
                    self.store.archive(record, copy.deepcopy(self.worker.jobs), request['job_ids'], request=request)
                    self.store.reconcile(self.worker.jobs, self.worker.save)
                return {'retention_operation': public_operation(self.store.operation(request_id))}
            candidate = next((row for row in current['backups'] if row['backup_id'] == request['backup_id']), None)
            if not candidate or not candidate['delete_allowed']:
                raise RetentionConflict('Choose an owned finished backup from this deployment')
            with Journal(self.worker.state_dir).locked():
                record['ownership'] = self.ownership(request['backup_id'])
                owner = self.owners(request['backup_id'])[0]
                record['partial_capture'] = owner['action'] == 'backup' and owner['state'] == 'failed'
                self.store.begin(request, record)
            self._start(record)
            return {'retention_operation': public_operation(record)}

    def _start(self, record):
        self.worker.thread = threading.Thread(target=self.delete, args=(record['request_id'],), daemon=False)
        self.worker.thread.start()

    def _pair(self, record):
        identifier(record['backup_id'])
        return [self.worker.backup_dir / record['backup_id'], self.worker.recovery_dir / record['backup_id']]

    def _snapshot(self, path):
        backup_archive.private_directory(path)
        if {item.name for item in path.iterdir()} != set(FILES):
            raise InstallError('Backup contains unexpected or incomplete files')
        result = {'directory': _identity(path.lstat()), 'files': {}}
        for name in FILES:
            selected = path / name
            fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or before.st_nlink != 1 or before.st_mode & 0o077):
                    raise InstallError('Backup file custody is unsafe')
                value = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    value.update(block)
                after = os.fstat(stream.fileno())
                signature = lambda row: (_identity(row), row.st_size, row.st_mtime_ns, row.st_ctime_ns)
                if signature(before) != signature(after) or signature(before) != signature(selected.lstat()):
                    raise InstallError('Backup changed during deletion review')
                result['files'][name] = {'identity': _identity(before), 'size': before.st_size, 'sha256': value.hexdigest()}
        return result

    def _prepare_pair(self, record, journal):
        pair = self._pair(record)
        before = [self._snapshot(path) if _exists(path) else None for path in pair]
        if not any(before) or (not all(before) and not record.get('partial_capture', False)):
            raise InstallError('Backup pair is missing an archive outside a failed capture')
        selected = None
        signer = self.worker.state_dir / 'backup-custody/signer.pub'
        for identity in self.worker.identity_history:
            try:
                selected = [backup_archive.read(path, identity, signer)['metadata'] if snapshot is not None else None
                            for path, snapshot in zip(pair, before)]
                break
            except (InstallError, OSError, ValueError):
                continue
        if selected is None or journal.document is None:
            raise InstallError('Every saved backup archive must authenticate before deletion')
        set_ids = set()
        for metadata, scope in zip(selected, ('managed-deployment-files', 'identity-recovery')):
            if metadata is None:
                continue
            set_ids.add(identifier(metadata.get('backup_set_id')))
            if (metadata.get('scope') != scope or metadata.get('instance_id') != journal.document['id']
                    or metadata.get('target') != self.worker.target):
                raise InstallError('Backup archive does not belong to this deployment')
        if len(set_ids) != 1:
            raise InstallError('Backup archives do not belong to the same capture')
        if before != [self._snapshot(path) if _exists(path) else None for path in pair]:
            raise InstallError('Backup changed during authentication')
        record.update(pair=before, removing=[], removed=[])
        self.store.update(record)

    def _remove_pair(self, record):
        # Check every originally absent side before unlinking either side,
        # including explicit recovery after an interrupted deletion.
        for path, snapshot in zip(self._pair(record), record['pair']):
            if snapshot is None and _exists(path):
                raise InstallError('An absent failed-capture archive appeared during deletion')
        for index, path in enumerate(self._pair(record)):
            snapshot = record['pair'][index]
            if snapshot is None:
                continue
            directory_key = str(index) + ':directory'
            if not _exists(path):
                if directory_key not in record['removing']:
                    raise InstallError('Backup directory vanished outside this deletion')
                continue
            backup_archive.private_directory(path)
            if _identity(path.lstat()) != snapshot['directory']:
                raise InstallError('Backup directory identity changed')
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except BaseException:
                os.close(parent)
                raise
            try:
                if _identity(os.fstat(fd)) != snapshot['directory']:
                    raise InstallError('Opened backup directory identity changed')
                if set(os.listdir(fd)) - set(FILES):
                    raise InstallError('Unexpected backup contents; deletion stopped')
                for name in FILES:
                    key = str(index) + ':' + name
                    expected = snapshot['files'][name]
                    try:
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    except FileNotFoundError:
                        if key not in record['removing']:
                            raise InstallError('Backup file vanished outside this deletion') from None
                        continue
                    with os.fdopen(child, 'rb') as stream:
                        info = os.fstat(stream.fileno())
                        value = hashlib.sha256()
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            value.update(block)
                        if (_identity(info) != expected['identity'] or info.st_nlink != 1 or info.st_size != expected['size']
                                or value.hexdigest() != expected['sha256'] or _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != expected['identity']):
                            raise InstallError('Backup file changed before deletion')
                        if key not in record['removing']:
                            record['removing'].append(key); self.store.update(record)
                        os.unlink(name, dir_fd=fd); os.fsync(fd)
                        record['removed'].append(key); self.store.update(record)
                if os.listdir(fd) or _identity(path.lstat()) != snapshot['directory']:
                    raise InstallError('Backup directory changed before removal')
                if directory_key not in record['removing']:
                    record['removing'].append(directory_key); self.store.update(record)
                if _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != snapshot['directory']:
                    raise InstallError('Backup directory identity changed before removal')
                os.rmdir(path.name, dir_fd=parent)
                os.fsync(parent)
                if _identity(os.stat(path.parent, follow_symlinks=False)) != _identity(os.fstat(parent)):
                    raise InstallError('Backup parent changed during directory removal')
                if os.fstat(fd).st_nlink != 0:
                    raise InstallError('Removed backup directory still has an unexpected link')
                try:
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise InstallError('Backup directory reappeared after removal')
                record['removed'].append(directory_key); self.store.update(record)
            finally:
                os.close(fd); os.close(parent)

    def delete(self, request_id):
        record = self.store.operation(request_id)
        try:
            with Journal(self.worker.state_dir).locked() as journal:
                owners = self.owners(record['backup_id'])
                if (not owners or self.ownership(record['backup_id']) != record['ownership']
                        or not all(self.deletable_owner(row) for row in owners)):
                    raise InstallError('Related maintenance operation still needs its archive')
                if 'pair' not in record:
                    self._prepare_pair(record, journal)
                self._remove_pair(record)
                if any(_exists(path) for path in self._pair(record)):
                    raise InstallError('A backup archive reappeared before deletion completed')
                with self.worker.lock:
                    selected = [row for row in self.worker.jobs if row.get('backup_id') == record['backup_id']
                                or row in owners and self.eligible(row, deleting=record['backup_id'])[0]]
                    if not all(self.eligible(row, deleting=record['backup_id'])[0] for row in selected):
                        raise InstallError('Related maintenance operation still needs its history')
                    self.store.archive(record, copy.deepcopy(self.worker.jobs), [row['id'] for row in selected])
                    self.store.reconcile(self.worker.jobs, self.worker.save)
        except Exception:
            # Retain the exact irreversible intent. Only explicit same-ID
            # resume can continue; no automatic retry or broad file cleanup.
            with self.worker.lock:
                current = self.store.operation(request_id)
                if current['state'] != 'completed':
                    current['state'] = 'recovery-required'
                    self.store.update(current)
