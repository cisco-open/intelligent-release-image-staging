# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Keyed incremental durable state — the one way per-device/per-principal
state is written and read.

Every per-device store used to be a single whole-fleet JSON document
(``devices.json``, ``policy.json``, ``pull_requests.json``, ``telemetry.json``,
``report_ledger.json``, ``peer-endpoints.json``, and — last, issue #125 —
``fleet.json``, the operator inventory itself). A device hot path — a
tracker announce, a catalog heartbeat, a terminal report — held ONE global
``flock`` on that document while it parsed the whole fleet, mutated one row,
and re-serialised the whole fleet back out. Cost per device operation grew
with fleet size and every writer in the fleet serialised behind one lock.

This module replaces that document with a **bucketed shard directory**:
``<state>/devices.json`` becomes ``<state>/devices.d/<bb>.json``, where the
bucket ``bb`` is ``crc32(key) % SHARD_COUNT`` (crc32, not ``hash()``, so the
placement is stable across processes and restarts). A shard holds
``{key: row}`` for the keys that land in it, so:

* a write parses and rewrites ~``fleet / SHARD_COUNT`` rows instead of the
  whole fleet, and takes only that shard's lock — writers for different
  devices no longer serialise;
* a whole-fleet read (console listing, reconciler derivation, purge) costs
  what the single document cost, because it is the same bytes in
  ``SHARD_COUNT`` pieces;
* nothing about the durability contract changes: each shard is written to a
  unique temp file in the same directory and ``os.replace``d into place
  (never a partial-write window), with ``allow_nan=False``.

**Fail closed.** A shard that EXISTS but cannot be opened, parsed, or whose
top level is not an object raises the owner's error type (``error=``) rather
than reading as empty — and, because the writer read it first, it is never
overwritten by the next writer. A missing shard is the empty store (first
boot). The same rule covers the legacy document during migration: an
unreadable ``devices.json`` fails closed and is left on disk for the operator,
never migrated to an empty shard set.

**Migration.** The first operation on a store whose legacy whole-fleet
document still exists migrates it: under the legacy document's own lock (the
same lock name the old whole-document writers took, so an older process still
serialises with us) each row is placed into its shard, and the legacy file is
then renamed to ``<name>.json.migrated`` — renamed, not deleted, so an
operator can always see what was converted. A row that already exists in a
shard WINS over the legacy copy: shard rows are by definition newer than the
document that is being retired.

**Rollback guard.** A rename-away is not the end of the story: code from
before this migration reads a MISSING legacy document (``devices.json`` and
friends) as an EMPTY store, not as an error. Roll that older code back onto a
migrated data directory and it would start clean and silently present a fleet
with no devices, no policy and no telemetry — the real data sitting one
rename away under ``<name>.json.migrated``, discoverable only if the operator
already knows to look. So migration leaves a placeholder file at the retired
legacy path: deliberately not valid JSON, so any reader built to fail closed
on an unparseable state file (the pre-#51/#52/#53/#56/#58
``CatalogStore._read`` and ``peer_endpoints._load``, both of which treat a
*missing* file as ``{}`` but an *existing-and-unreadable* one as corruption)
trips that same fail-closed path instead of reading an empty store. The
placeholder carries the recovery instructions in the clear, so ``cat``-ing
the file the error points at is enough to find them. See
``docs/zensical/operations.md`` ("Rollback after the shard migration") for
the full procedure.
"""
import contextlib
import fcntl
import json
import os
import tempfile
import zlib

# Number of shard files a store is spread over. 256 keeps a shard small at the
# supported fleet size (10,000 devices -> ~39 rows per shard) while keeping a
# whole-fleet scan to 256 file opens rather than one per device.
SHARD_COUNT = 256


class KeyedStateError(RuntimeError):
    """Existing keyed state is unreadable and must not be overwritten."""


#: Sentinel an ``update``/``sweep`` callback returns to delete the row.
DELETE = object()


def shard_dir(path):
    """The shard directory for the legacy whole-fleet document at *path*
    (``.../devices.json`` -> ``.../devices.d``)."""
    base = path[:-len(".json")] if path.endswith(".json") else path
    return base + ".d"


def bucket_of(key, shards=SHARD_COUNT):
    """Stable shard index for *key*. crc32 (not ``hash()``, which is salted
    per process) so a key lands in the same shard in every process and after
    every restart."""
    return zlib.crc32(key.encode("utf-8")) % shards


@contextlib.contextmanager
def file_lock(path):
    """Exclusive advisory ``flock`` on ``<path>.lock`` — the same discipline
    (and the same sidecar naming) as ``secrets_store.store_lock``, so a lock
    taken here and one taken there on the same path are the same lock."""
    lock_path = path + ".lock"
    d = os.path.dirname(lock_path) or "."
    os.makedirs(d, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class KeyedState:
    """A ``{key: row}`` store spread over :data:`SHARD_COUNT` shard files.

    *path* is the LEGACY whole-fleet document path; the shards live in
    :func:`shard_dir` of it and the legacy file is migrated away on first use.
    *error* is the exception type raised for unreadable/corrupt state (the
    owner's own type, so ``catalog.StateFileError`` and
    ``peer_endpoints.EndpointStoreError`` keep their existing meaning).
    *validate*, when given, is called as ``validate(key, row)`` for every row
    read out of a shard and may raise ``ValueError`` to declare the row
    corrupt — which takes the same fail-closed path as unparsable JSON.
    *legacy_extract* maps a legacy whole-fleet document to ``{key: row}``
    (default: the document itself).
    """

    def __init__(self, path, error=KeyedStateError, validate=None,
                 legacy_extract=None, shards=SHARD_COUNT, indent=2):
        self.legacy_path = path
        self.dir = shard_dir(path)
        self.error = error
        self.shards = shards
        self.indent = indent
        self._validate = validate
        self._legacy_extract = legacy_extract
        self._migrated = False

    # -- shard I/O ---------------------------------------------------------

    def _shard_path(self, bucket):
        return os.path.join(self.dir, "%02x.json" % bucket)

    def _read_json(self, path):
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise self.error("keyed state unreadable: %s (%s)"
                             % (path, type(exc).__name__))
        if not isinstance(data, dict):
            raise self.error("keyed state is not a JSON object: %s" % path)
        return data

    def _read_shard(self, bucket):
        data = self._read_json(self._shard_path(bucket))
        if data is None:
            return {}
        if self._validate is not None:
            for key, row in data.items():
                try:
                    self._validate(key, row)
                except ValueError as exc:
                    raise self.error("keyed state row is corrupt: %s (%s)"
                                     % (self._shard_path(bucket), exc))
        return data

    def _write_shard(self, bucket, rows):
        path = self._shard_path(bucket)
        if not rows:
            # An empty shard is removed so a whole-fleet scan stays
            # proportional to the rows that actually exist.
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            return
        os.makedirs(self.dir, exist_ok=True)
        mode = None
        try:
            mode = os.stat(path).st_mode
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".shard-",
                                   suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                # allow_nan=False: a NaN/Infinity that slipped past ingest
                # would otherwise be written as a bare token no JSON parser
                # accepts, poisoning every reader of the shard.
                json.dump(rows, f, indent=self.indent, sort_keys=True,
                          allow_nan=False)
            if mode is not None:
                os.chmod(tmp, mode)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # -- legacy migration --------------------------------------------------

    def _ensure_migrated(self):
        """Fold a legacy whole-fleet document into shards, once."""
        if self._migrated:
            return
        migrated_path = self.legacy_path + ".migrated"
        if os.path.exists(migrated_path):
            # Already migrated (this process or another, this run or an
            # earlier one). ``self.legacy_path`` may still exist -- as the
            # rollback guard left by _leave_rollback_guard() below -- but it
            # is retired and must never be read as the source of truth again.
            self._migrated = True
            return
        if not os.path.exists(self.legacy_path):
            self._migrated = True
            return
        with file_lock(self.legacy_path):
            if os.path.exists(migrated_path):
                self._migrated = True
                return
            if not os.path.exists(self.legacy_path):
                self._migrated = True
                return
            # Fail closed: an unreadable legacy document raises here and is
            # left exactly where it is. It is never migrated as empty and the
            # rename below never runs, so nothing is lost.
            doc = self._read_json(self.legacy_path)
            rows = doc if doc is not None else {}
            if self._legacy_extract is not None:
                rows = self._legacy_extract(rows)
            if not isinstance(rows, dict):
                raise self.error("legacy state is not a JSON object: %s"
                                 % self.legacy_path)
            by_bucket = {}
            for key, row in rows.items():
                if not isinstance(key, str):
                    raise self.error("legacy state has a non-string key: %s"
                                     % self.legacy_path)
                if self._validate is not None:
                    # A corrupt ROW in the legacy document fails closed here,
                    # before anything is written and before the rename: a bad
                    # row must never be laundered into a shard by migration.
                    try:
                        self._validate(key, row)
                    except ValueError as exc:
                        raise self.error(
                            "legacy state row is corrupt: %s (%s)"
                            % (self.legacy_path, exc))
                by_bucket.setdefault(bucket_of(key, self.shards), {})[key] = row
            for bucket, incoming in by_bucket.items():
                with file_lock(self._shard_path(bucket)):
                    current = self._read_shard(bucket)
                    # A row already in a shard is newer than the document
                    # being retired, so it wins.
                    merged = dict(incoming)
                    merged.update(current)
                    self._write_shard(bucket, merged)
            os.replace(self.legacy_path, migrated_path)
            self._leave_rollback_guard(migrated_path)
            self._migrated = True

    def _leave_rollback_guard(self, migrated_path):
        """Leave a placeholder at the just-retired ``self.legacy_path`` so
        that OLDER (pre-migration) code, which reads a MISSING legacy
        document as an empty store, instead finds a file that EXISTS but is
        deliberately not valid state, and fails closed on it exactly as it
        already does for a corrupt file. See the module docstring
        ("Rollback guard") for why this is possible without touching that
        old code.

        Best-effort: the migration above already committed (the rename
        happened, the shards hold every row); a failure here (read-only
        filesystem, out of space) must not undo that or raise out of an
        otherwise-successful migration. It only narrows what the guard
        covers, which callers cannot observe from here anyway.
        """
        text = (
            "This file is deliberately not valid JSON.\n"
            "\n"
            "IRIS migrated this state store to per-device shards under\n"
            "%s/. The original whole-fleet document was renamed, not\n"
            "deleted, and is intact at:\n"
            "\n"
            "    %s\n"
            "\n"
            "You are seeing this placeholder because something tried to\n"
            "read %s directly -- most likely code from before the shard\n"
            "migration. That old code treats a MISSING file as an empty\n"
            "fleet, so this file exists to make it fail loudly instead of\n"
            "silently reporting no devices, no policy and no telemetry.\n"
            "\n"
            "If you are rolling back to that older code, restore the\n"
            "original document first:\n"
            "\n"
            "    mv %s %s\n"
            "\n"
            "See docs/zensical/operations.md, \"Rollback after the shard\n"
            "migration\", for the full recovery procedure.\n"
            % (self.dir, migrated_path, self.legacy_path,
               migrated_path, self.legacy_path)
        )
        try:
            d = os.path.dirname(self.legacy_path) or "."
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".rollback-guard-",
                                       suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(text)
                os.replace(tmp, self.legacy_path)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        except OSError:
            pass

    # -- keyed operations (one shard each) ---------------------------------

    def get(self, key):
        """The row for *key*, or ``None``. Reads exactly one shard."""
        self._ensure_migrated()
        return self._read_shard(bucket_of(key, self.shards)).get(key)

    def put(self, key, value):
        """Replace the row for *key*. Locks and rewrites exactly one shard."""
        self.update(key, lambda _old: value)

    def update(self, key, fn):
        """Read-modify-write *key* under its shard's lock.

        ``fn(old_row_or_None)`` returns the new row, :data:`DELETE` to remove
        it, or ``None`` to leave the store untouched. Returns whatever ``fn``
        returned, so a caller can report what it decided."""
        self._ensure_migrated()
        bucket = bucket_of(key, self.shards)
        with file_lock(self._shard_path(bucket)):
            rows = self._read_shard(bucket)
            new = fn(rows.get(key))
            if new is None:
                return None
            if new is DELETE:
                if rows.pop(key, None) is None:
                    return DELETE
            else:
                rows[key] = new
            self._write_shard(bucket, rows)
            return new

    def delete(self, key):
        """Remove *key*'s row. Returns True iff it existed."""
        self._ensure_migrated()
        bucket = bucket_of(key, self.shards)
        with file_lock(self._shard_path(bucket)):
            rows = self._read_shard(bucket)
            if key not in rows:
                return False
            del rows[key]
            self._write_shard(bucket, rows)
            return True

    def update_many(self, keys, fn):
        """Read-modify-write every key in *keys*, grouped by shard so a shard
        holding several requested keys is locked, read, and rewritten ONCE —
        the batch counterpart of :meth:`update`. Where ``update`` costs one
        shard per key and ``sweep`` costs every shard in the store regardless
        of which keys the caller actually wants, this costs one shard per
        DISTINCT bucket the requested keys land in — never more than
        :data:`SHARD_COUNT`, however large *keys* is. It exists for a caller
        that must apply the same kind of change to a CHOSEN subset of the
        store in one call (a console bulk reassignment across a selected set
        of devices) rather than either one key or literally every key.

        ``fn(key, old_row_or_None)`` has the exact contract :meth:`update`'s
        callback does: return the new row, :data:`DELETE`, or ``None`` to
        leave that key untouched. It is called once per occurrence of a key
        in *keys* (a repeated key is called again, seeing the previous
        occurrence's result — the same outcome N calls to :meth:`update`
        would produce). Unlike :meth:`sweep`, an exception out of ``fn``
        propagates immediately: whichever shard was mid-write is never
        written (its lock is released and the shard is left exactly as it
        was), but any EARLIER shard in this call already committed stays
        committed. A caller that needs per-key partial-failure reporting
        instead of a hard abort must catch inside its own ``fn`` and encode
        the failure in what it returns (``None`` — no write for that key) —
        see ``gui_fleet.FleetStore.bulk_upsert`` for that pattern.

        Returns ``{key: fn's return value}`` for every key actually passed to
        ``fn`` (so a repeated key's LAST result is what appears)."""
        self._ensure_migrated()
        by_bucket = {}
        for key in keys:
            by_bucket.setdefault(bucket_of(key, self.shards), []).append(key)
        results = {}
        for bucket, bucket_keys in by_bucket.items():
            with file_lock(self._shard_path(bucket)):
                rows = self._read_shard(bucket)
                dirty = False
                for key in bucket_keys:
                    new = fn(key, rows.get(key))
                    if new is None:
                        continue
                    if new is DELETE:
                        if rows.pop(key, None) is not None:
                            dirty = True
                        results[key] = DELETE
                        continue
                    rows[key] = new
                    dirty = True
                    results[key] = new
                if dirty:
                    self._write_shard(bucket, rows)
        return results

    # -- whole-fleet operations (never on a per-device hot path) -----------

    def _buckets(self):
        try:
            with os.scandir(self.dir) as it:
                names = [e.name for e in it
                         if e.is_file() and e.name.endswith(".json")
                         and not e.name.startswith(".")]
        except FileNotFoundError:
            return []
        out = []
        for name in names:
            try:
                out.append(int(name[:-len(".json")], 16))
            except ValueError:
                continue
        return sorted(out)

    def snapshot(self):
        """Every row, as one ``{key: row}`` dict. O(fleet) — console listings,
        reconciler derivation and purge only, never a per-device request."""
        self._ensure_migrated()
        out = {}
        for bucket in self._buckets():
            out.update(self._read_shard(bucket))
        return out

    def sweep(self, fn):
        """Apply ``fn(key, row)`` to every row, one shard at a time, each
        under its own lock (so a sweep never blocks the whole fleet's writers
        at once). ``fn`` returns the new row, :data:`DELETE`, or ``None`` to
        leave the row unchanged. Returns the number of rows changed."""
        self._ensure_migrated()
        changed = 0
        for bucket in self._buckets():
            with file_lock(self._shard_path(bucket)):
                rows = self._read_shard(bucket)
                dirty = False
                for key in list(rows):
                    new = fn(key, rows[key])
                    if new is None:
                        continue
                    if new is DELETE:
                        del rows[key]
                    else:
                        rows[key] = new
                    dirty = True
                    changed += 1
                if dirty:
                    self._write_shard(bucket, rows)
        return changed


def change_key(path):
    """Cheap change-detection key for the keyed store at *path*, for a poller
    that wants to skip work when nothing on disk moved.

    The whole-document equivalent was ``(st_mtime_ns, st_size)`` of one file.
    A keyed store is a directory, so the key is the directory's own stat --
    every shard write is an ``os.replace`` INTO it, which POSIX requires to
    update the directory's mtime -- plus each shard's ``(name, mtime_ns,
    size)``, which makes the key exact rather than merely
    timestamp-resolution-good. Missing directory -> a sentinel, and a legacy
    whole-fleet document that has not been migrated yet is folded in so the
    key still moves while it is still the source of truth."""
    out = []
    try:
        st = os.stat(path)
        out.append(("", st.st_mtime_ns, st.st_size))
    except OSError:
        pass
    d = shard_dir(path)
    try:
        st = os.stat(d)
        out.append((".", st.st_mtime_ns, st.st_size))
        with os.scandir(d) as it:
            for e in it:
                if e.name.endswith(".json") and not e.name.startswith("."):
                    est = e.stat()
                    out.append((e.name, est.st_mtime_ns, est.st_size))
    except OSError:
        pass
    if not out:
        return None
    return tuple(sorted(out))


def read_all(path):
    """Best-effort whole-fleet read for an out-of-process READER (the
    telemetry sidecar): the shard directory for *path*, falling back to the
    legacy document while it is still there. Never raises — an unreadable
    shard contributes nothing, exactly as the readers' previous
    ``open(...)/json.load`` in a ``try`` did. Writers must use
    :class:`KeyedState`, which fails closed instead."""
    out = {}
    # The legacy document first, then the shards on top: during the migration
    # window both exist, and a shard row always wins over the copy in the
    # document being retired.
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            out.update(data)
    except Exception:
        pass
    try:
        with os.scandir(shard_dir(path)) as it:
            names = sorted(e.path for e in it
                           if e.is_file() and e.name.endswith(".json")
                           and not e.name.startswith("."))
    except OSError:
        names = []
    for name in names:
        try:
            with open(name) as f:
                data = json.load(f)
            if isinstance(data, dict):
                out.update(data)
        except Exception:
            continue
    return out
