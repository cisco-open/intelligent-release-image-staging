# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, non-reusable maintenance request IDs and explicit retirement intents.

The visible worker list is bounded; this private SQLite authority is not. No
security operation record, recovery key or archive is removed by this module.
"""

from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from .backup_archive import private_directory
from .state import InstallError, Journal, atomic_write, regular_bytes


class RetentionConflict(InstallError):
    """A safe, non-secret refusal rather than a storage availability failure."""


def identifier(value):
    if not isinstance(value, str):
        raise RetentionConflict('Choose an exact maintenance request ID')
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise RetentionConflict('Choose an exact maintenance request ID') from None
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(encoded(value).encode('ascii')).hexdigest()


def _private_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise InstallError('Maintenance history custody is unsafe; preserve it for recovery')
    return info.st_dev, info.st_ino


SCHEMA = {
    'metadata': 'CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), database_id TEXT NOT NULL, tombstone_count INTEGER NOT NULL, tombstone_digest TEXT NOT NULL, operation_count INTEGER NOT NULL)',
    'tombstones': 'CREATE TABLE tombstones (sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, row_json TEXT NOT NULL, row_sha256 TEXT NOT NULL, chain_sha256 TEXT NOT NULL)',
    'operations': 'CREATE TABLE operations (sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, request_json TEXT NOT NULL, record_json TEXT NOT NULL, record_sha256 TEXT NOT NULL, state TEXT NOT NULL)',
}
EMPTY = hashlib.sha256(b'').hexdigest()
INDEX = 'CREATE INDEX operation_state ON operations(state)'


def _generation(path):
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


class Store:
    def __init__(self, state_dir, *, initialize=True):
        self.base = private_directory(state_dir)
        self.read_only = not initialize
        self.path = self.base / 'lifecycle-history.sqlite3'
        self.marker = self.base / 'lifecycle-history-initialized.json'
        with (Journal(self.base).locked() if initialize else nullcontext(None)) as journal:
            document = journal.document if journal is not None else json.loads(regular_bytes(self.base / 'installation.json'))
            if document is None:
                raise InstallError('Maintenance history requires the existing installation journal')
            _private_file(self.base / 'installation.json')
            anchor = document.get('lifecycle_history')
            db_present = self.path.exists() or self.path.is_symlink()
            marker_present = self.marker.exists() or self.marker.is_symlink()
            if anchor is None:
                if not initialize or db_present or marker_present:
                    raise InstallError('Maintenance history initialization authority is missing')
                anchor = {'schema': 1, 'database_id': str(uuid.uuid4())}
                # Commit first in independent, existing installation custody.
                # An interruption never grants permission to start over.
                journal.document['lifecycle_history'] = anchor
                journal.save()
                self._initialize(anchor['database_id'])
            elif not db_present or not marker_present:
                raise InstallError('Maintenance history authority is missing; preserve remaining custody')
            if (not isinstance(anchor, dict) or set(anchor) != {'schema', 'database_id'}
                    or anchor['schema'] != 1):
                raise InstallError('Maintenance history installation commitment is invalid')
            self.anchor = anchor
        self.marker_identity = _private_file(self.marker)
        self.marker_raw = regular_bytes(self.marker, 4096)
        try:
            marker = json.loads(self.marker_raw)
            if set(marker) != {'schema', 'database_id'} or marker['schema'] != 1:
                raise ValueError()
            self.database_id = identifier(marker['database_id'])
            if marker != self.anchor:
                raise ValueError()
        except (ValueError, TypeError, RetentionConflict):
            raise InstallError('Maintenance history initialization marker is invalid') from None
        self.identity = _private_file(self.path)
        self.verified_generation = None
        with self.connection() as db:
            pass

    def _initialize(self, database_id):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        # A crash before the final marker is intentionally not an empty new
        # database on restart. Preserve the partial authority for inspection.
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA user_version=1')
            for sql in SCHEMA.values():
                db.execute(sql)
            db.execute(INDEX)
            db.execute('INSERT INTO metadata VALUES (1,?,?,?,0)', (database_id, 0, EMPTY))
        atomic_write(self.marker, encoded({'schema': 1, 'database_id': database_id}).encode('ascii'))

    @contextmanager
    def connection(self):
        installation = self.base / 'installation.json'
        _private_file(installation)
        try:
            if json.loads(regular_bytes(installation)).get('lifecycle_history') != self.anchor:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise InstallError('Maintenance history installation commitment changed') from None
        if _private_file(self.marker) != self.marker_identity or regular_bytes(self.marker, 4096) != self.marker_raw:
            raise InstallError('Maintenance history initialization authority changed')
        if _private_file(self.path) != self.identity:
            raise InstallError('Maintenance history database identity changed')
        for suffix in ('-wal', '-shm'):
            if Path(str(self.path) + suffix).exists() or Path(str(self.path) + suffix).is_symlink():
                raise InstallError('Unexpected maintenance history journal format')
        journal = Path(str(self.path) + '-journal')
        if journal.exists() or journal.is_symlink():
            _private_file(journal)
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri() + ('?mode=ro' if self.read_only else '?mode=rw'), uri=True, timeout=1)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA foreign_keys=ON')
            if db.execute('PRAGMA journal_mode').fetchone() != ('delete',):
                raise InstallError('Unexpected maintenance history journal format')
            db.execute('PRAGMA synchronous=FULL')
            # Hold a write reservation through the read/write transaction so a
            # second SQLite writer cannot change membership after validation.
            db.execute('BEGIN' if self.read_only else 'BEGIN IMMEDIATE')
            generation = _generation(self.path)
            if generation != self.verified_generation:
                self._verify(db)
                if _generation(self.path) != generation:
                    raise InstallError('Maintenance history changed during validation')
                self.verified_generation = generation
            counts = db.execute('SELECT database_id,tombstone_count,operation_count FROM metadata WHERE id=1').fetchone()
            if counts != (self.database_id, db.execute('SELECT count(*) FROM tombstones').fetchone()[0],
                          db.execute('SELECT count(*) FROM operations').fetchone()[0]):
                raise InstallError('Maintenance history request authority is missing')
            yield db
            db.commit()
            # Never certify a generation by merely seeing our commit succeed:
            # the next access independently validates all changed bytes.
            if db.total_changes:
                self.verified_generation = None
            if _private_file(self.path) != self.identity:
                raise InstallError('Maintenance history database identity changed')
        except sqlite3.Error:
            if db is not None:
                db.rollback()
            raise InstallError('Maintenance history storage unavailable; preserve its database and journal') from None
        except BaseException:
            if db is not None:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def _verify(self, db):
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or db.execute('PRAGMA user_version').fetchone() != (1,):
            raise InstallError('Maintenance history database integrity check failed')
        tables = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
        objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE type!='table' ORDER BY name").fetchall()
        if tables != SCHEMA or objects != [('index', 'operation_state', INDEX),
                ('index', 'sqlite_autoindex_operations_1', None),
                ('index', 'sqlite_autoindex_tombstones_1', None)]:
            raise InstallError('Maintenance history schema is unsupported')
        metadata = db.execute('SELECT database_id,tombstone_count,tombstone_digest FROM metadata WHERE id=1').fetchone()
        chain, count = EMPTY, 0
        for sequence, request_id, raw, row_hash, chain_hash in db.execute('SELECT * FROM tombstones ORDER BY sequence'):
            count += 1
            try:
                row = json.loads(raw)
                identifier(request_id)
                if sequence != count or row['id'] != request_id or digest(row) != row_hash or encoded(row) != raw:
                    raise ValueError()
                chain = digest([chain, request_id, row_hash])
                if chain != chain_hash:
                    raise ValueError()
            except (ValueError, KeyError, TypeError, RetentionConflict):
                raise InstallError('Retired maintenance request authority changed') from None
        if metadata != (self.database_id, count, chain):
            raise InstallError('Retired maintenance request authority is missing')
        for request_id, request_raw, record_raw, record_hash, state in db.execute('SELECT request_id,request_json,record_json,record_sha256,state FROM operations'):
            try:
                request, record = json.loads(request_raw), json.loads(record_raw)
                if (identifier(request_id) != request['request_id'] or request_id != record['request_id']
                        or digest(record) != record_hash or digest(request) != record['request_sha256']
                        or encoded(request) != request_raw or encoded(record) != record_raw
                        or state != record['state'] or state not in ('running', 'completed', 'recovery-required')):
                    raise ValueError()
            except (ValueError, KeyError, TypeError, RetentionConflict):
                raise InstallError('Maintenance retirement intent is invalid') from None

    def retired(self, request_id):
        return self.retired_job(request_id) is not None

    def retired_job(self, request_id):
        with self.connection() as db:
            row = db.execute('SELECT row_json,row_sha256 FROM tombstones WHERE request_id=?', (identifier(request_id),)).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
            if digest(value) != row[1] or value['id'] != request_id:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise InstallError('Retired maintenance request authority changed') from None
        return value

    def operation(self, request_id=None):
        with self.connection() as db:
            if request_id is None:
                row = db.execute('SELECT record_json,record_sha256 FROM operations ORDER BY sequence DESC LIMIT 1').fetchone()
            else:
                row = db.execute('SELECT record_json,record_sha256 FROM operations WHERE request_id=?', (identifier(request_id),)).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        if digest(value) != row[1]:
            raise InstallError('Maintenance retirement intent changed')
        return value

    def pending(self):
        with self.connection() as db:
            rows = db.execute("SELECT record_json,record_sha256 FROM operations WHERE state IN ('running','recovery-required') ORDER BY sequence LIMIT 2").fetchall()
        result = []
        for raw, expected in rows:
            record = json.loads(raw)
            if digest(record) != expected:
                raise InstallError('Maintenance retirement intent changed')
            if record['state'] != 'completed':
                result.append(record)
        if len(result) > 1:
            raise InstallError('Multiple unresolved maintenance retirement operations')
        return result

    def observe(self, request):
        with self.connection() as db:
            row = db.execute('SELECT request_json FROM operations WHERE request_id=?', (request['request_id'],)).fetchone()
        if row is None:
            if self.retired(request['request_id']):
                raise RetentionConflict('This request ID belongs to retired maintenance history')
            return None
        original = json.loads(row[0])
        record = self.operation(request['request_id'])
        if digest(original) != record['request_sha256']:
            raise InstallError('Maintenance retirement request binding changed')
        # A repeat is observation, not permission to replay a destructive step.
        compared = {key: value for key, value in request.items() if key != 'expected_revision'}
        expected = {key: value for key, value in original.items() if key != 'expected_revision'}
        if compared != expected:
            raise RetentionConflict('Request ID belongs to a different maintenance operation')
        return record

    def begin(self, request, record):
        record['request_sha256'] = digest(request)
        with self.connection() as db:
            db.execute('INSERT INTO operations (request_id,request_json,record_json,record_sha256,state) VALUES (?,?,?,?,?)',
                       (request['request_id'], encoded(request), encoded(record), digest(record), record['state']))
            db.execute('UPDATE metadata SET operation_count=operation_count+1 WHERE id=1')

    def update(self, record):
        with self.connection() as db:
            result = db.execute('UPDATE operations SET record_json=?,record_sha256=?,state=? WHERE request_id=?',
                                (encoded(record), digest(record), record['state'], record['request_id']))
            if result.rowcount != 1:
                raise InstallError('Maintenance retirement intent is missing')

    def archive(self, record, before, selected_ids, *, request=None):
        selected = [row for row in before if row['id'] in selected_ids]
        after = [row for row in before if row['id'] not in selected_ids]
        record.update(before=before, after=after, retirement_phase='prepared')
        if request is not None:
            record['request_sha256'] = digest(request)
        with self.connection() as db:
            if request is not None:
                db.execute('INSERT INTO operations (request_id,request_json,record_json,record_sha256,state) VALUES (?,?,?,?,?)',
                           (request['request_id'], encoded(request), encoded(record), digest(record), record['state']))
                db.execute('UPDATE metadata SET operation_count=operation_count+1 WHERE id=1')
            count, chain = db.execute('SELECT tombstone_count,tombstone_digest FROM metadata WHERE id=1').fetchone()
            for row in selected:
                count += 1
                row_hash = digest(row)
                chain = digest([chain, row['id'], row_hash])
                db.execute('INSERT INTO tombstones VALUES (?,?,?,?,?)',
                           (count, row['id'], encoded(row), row_hash, chain))
            db.execute('UPDATE metadata SET tombstone_count=?,tombstone_digest=? WHERE id=1', (count, chain))
            db.execute('UPDATE operations SET record_json=?,record_sha256=?,state=? WHERE request_id=?',
                       (encoded(record), digest(record), record['state'], record['request_id']))
        return after

    def reconcile(self, jobs, save):
        for record in self.pending():
            if record.get('retirement_phase') != 'prepared':
                continue
            if jobs != record['before'] and jobs != record['after']:
                raise InstallError('Maintenance history changed during retirement; preserve its journal')
            jobs[:] = record['after']
            save()
            record.update(state='completed', retired_count=len(record['before']) - len(record['after']), retirement_phase='completed')
            # Tombstones retain exact rows; completed intents need no duplicate
            # copy of the entire visible list forever.
            del record['before'], record['after']
            self.update(record)


def existing_store(state_dir):
    """Read established custody only; safe while an installer lock is held."""
    # Legacy entry points retain their existing state-directory validation.
    # Only an established retention authority adds new custody requirements.
    base = Path(state_dir)
    installed = base / 'installation.json'
    document = json.loads(regular_bytes(installed)) if installed.exists() or installed.is_symlink() else {}
    if document.get('lifecycle_history') is None:
        if any(path.exists() or path.is_symlink() for path in (
                base / 'lifecycle-history.sqlite3', base / 'lifecycle-history-initialized.json')):
            raise InstallError('Maintenance history initialization authority is missing')
        return None
    return Store(base, initialize=False)


def guard(state_dir):
    store = existing_store(state_dir)
    if store is not None and store.pending():
        raise RetentionConflict('Finish or resume the pending backup deletion before host maintenance')


def public_operation(record):
    if record is None:
        return None
    return {key: record[key] for key in ('request_id', 'action', 'state', 'retired_count', 'backup_id')}
