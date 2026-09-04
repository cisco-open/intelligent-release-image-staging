# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded (circular) JSONL audit trail for IRIS console and broker events.

Each append_event() call appends ONE line:
  {"ts": <epoch_int>, "event": <str>, ["device_id": <str>,]
   ...optional structured fields..., "result": "ok"|"fail"}

Structured fields (all optional, omitted when None):
  actor     -- who acted: "console:admin", "device:<id>", "system"
  category  -- one of AUDIT_CATEGORIES; legacy broker events ("mint",
               "refresh", "refresh_fail", "revoke", "auth_fail") are
               auto-mapped so existing call sites need no change
  action    -- verb within the category (e.g. "update", "delete")
  target    -- object acted on (e.g. an image id, a settings key)
  detail    -- short free-text context (keep it short; it lives on disk
               for the whole retention window)
  ts        -- event epoch seconds (defaults to now)

Bounding (the "circular" part) -- two independent limits keep the file
finite regardless of clock games:
  * retention window: entries older than AUDIT_RETENTION_DAYS (env
    IRIS_AUDIT_RETENTION_DAYS, default 90) are dropped by ts;
  * hard cap: at most AUDIT_MAX_EVENTS (env IRIS_AUDIT_MAX_EVENTS,
    default 50000) entries survive a prune, evicting the OLDEST BY FILE
    POSITION (append order) -- a forged far-future ts cannot shield an
    entry from eviction, and a wildly wrong clock cannot mass-delete
    fresh entries below the cap either.

Both env overrides parse the same way: a missing, non-integer or
NON-POSITIVE value falls back to the compiled default, as
catalog.handler_timeout() and peer_endpoints.endpoint_ttl() do.  0 is not
"unlimited" for the cap and not "keep nothing" for the retention window --
it is simply not a value either knob accepts.

Pruning is AMORTIZED: rewriting the whole file on every append would turn
each one-line append into an O(file) copy, so append_event() only prunes on
every PRUNE_EVERY-th append per path per process (plus explicit prune()
calls).  Between prunes the file may exceed the cap by at most
PRUNE_EVERY - 1 entries, which is bounded and acceptable.  read_events()
never prunes -- reads stay cheap and side-effect free.

Concurrency: the file is written by BOTH the catalog and the gui processes
(and their threads).  append_event() and prune() therefore serialize on the
same advisory flock sidecar used by every shared store in this repo
(secrets_store.store_lock).  The prune rewrite is atomic
(tempfile.mkstemp in the same directory + os.replace, mode preserved --
same pattern as catalog._atomic_write_json), so read_events() can read
WITHOUT the lock: it always sees a complete pre- or post-prune file, and
a torn in-flight append only affects the final line, which the
garbage-tolerant parser skips.

NEVER log token values, or any prefix of them. The audit log carries only
short non-secret ids/hashes. Callers deriving old_id/new_id from a token MUST
pass a truncated hash, e.g. hashlib.sha256(value.encode()).hexdigest()[:8]
(correlatable across events but non-secret) -- never value[:8], which would
leak 32 bits of a live secret onto the unencrypted /etc/iris volume.
"""
import json
import os
import tempfile
import threading
import time

import secrets_store

# Defaults; overridable per-call-site via environment (read at call time so
# long-lived processes and tests pick changes up without a reimport).
AUDIT_RETENTION_DAYS = 90       # env IRIS_AUDIT_RETENTION_DAYS
AUDIT_MAX_EVENTS = 50000        # env IRIS_AUDIT_MAX_EVENTS
PRUNE_EVERY = 100               # appends between amortized prunes (per process)

# Vocabulary for the structured "category" field (GUI filter values).
AUDIT_CATEGORIES = ("auth", "device", "image", "onboard", "settings",
                    "telemetry", "token")

# Legacy broker events -> category, so pre-existing call sites (catalog.py
# token lifecycle) land in the structured vocabulary unchanged.
_EVENT_CATEGORY = {
    "mint": "token",
    "refresh": "token",
    "refresh_fail": "token",
    "revoke": "token",
    "auth_fail": "auth",
}

# abspath -> appends since the last prune in THIS process (amortization
# counter; mutated only while holding store_lock, so it is race-free across
# this process's threads -- other processes keep their own counters, which
# only affects WHEN a prune happens, never correctness).
_appends_since_prune = {}


def _retention_seconds():
    """Retention window in seconds, honoring IRIS_AUDIT_RETENTION_DAYS.

    A missing, non-integer or NON-POSITIVE value falls back to
    AUDIT_RETENTION_DAYS -- the same rule catalog.handler_timeout() and
    peer_endpoints.endpoint_ttl() apply, so one number means one thing across
    the server.  0 used to mean "drop everything but the last few seconds",
    the opposite of what 0 meant to the adjacent cap knob."""
    raw = os.environ.get("IRIS_AUDIT_RETENTION_DAYS")
    try:
        days = int(raw) if raw else AUDIT_RETENTION_DAYS
    except (TypeError, ValueError):
        return AUDIT_RETENTION_DAYS * 86400
    return (days if days > 0 else AUDIT_RETENTION_DAYS) * 86400


def _max_events():
    """Hard entry cap, honoring IRIS_AUDIT_MAX_EVENTS.

    A missing, non-integer or NON-POSITIVE value falls back to
    AUDIT_MAX_EVENTS.  0 used to disable the cap entirely (kept[-0:] is the
    whole list), so the audit file grew without bound while the very same
    value on IRIS_AUDIT_RETENTION_DAYS threw the trail away.  Neither reading
    is safe to guess at: an operator who wants an effectively unbounded trail
    sets a large number."""
    raw = os.environ.get("IRIS_AUDIT_MAX_EVENTS")
    try:
        cap = int(raw) if raw else AUDIT_MAX_EVENTS
    except (TypeError, ValueError):
        return AUDIT_MAX_EVENTS
    return cap if cap > 0 else AUDIT_MAX_EVENTS


# ---------------------------------------------------------------------------
# In-process line index (read-path accelerator)
#
# Every visible Monitoring tab asked for a histogram AND a page of events
# every 10 s, and each of those calls re-read and re-JSON-parsed the WHOLE
# trail: at the module's own 50k design cap that was ~250 ms of CPU per call,
# and the amortized no-op prune() paid the same ~250 ms while HOLDING the
# cross-process audit flock that device token refresh also takes -- console
# polling contending with credential rotation.
#
# The index is what removes the repeated parse.  It is an in-PROCESS,
# append-incremental summary of the file: one tuple per readable line,
#
#     (byte offset, byte length, ts or None, category)
#
# which is everything read_events() and histogram() filter on.  A poll then
# costs O(bytes appended since the last poll) plus one cheap tuple scan;
# only the handful of lines that actually make it onto the requested PAGE
# are JSON-parsed, and histogram() parses nothing at all.
#
# It is a cache, never a source of truth, and it is rebuilt from scratch
# whenever the file it describes is not a strict extension of what was
# indexed.  "Strict extension" is checked on the SAME open fd the caller
# then reads from (os.fstat, not os.stat), against four things: device+inode
# (a prune replaces the file via os.replace, so its rewrite always lands on
# a new inode), a size that has not shrunk, the first bytes of the file, and
# a newline immediately before the last indexed byte.  Anything else falls
# back to the original streaming scan, which is still what every result is
# defined by (test_audit.py cross-checks the two): an unreadable file, or a
# trail past INDEX_MAX_ENTRIES, which is marked unindexable until the file is
# replaced so the fallback does not also pay for an index nobody can use.
#
# Lockless with respect to the audit flock, exactly as read_events() always
# was; _INDEX_LOCK is a plain in-process mutex serializing refreshes between
# this process's threads.  Lock order is store_lock -> _INDEX_LOCK (prune
# takes both, readers take only the latter), never the reverse.
# ---------------------------------------------------------------------------

INDEX_MAX_ENTRIES = 200000   # ~30 MB of tuples; beyond this, stream instead
INDEX_MAX_PATHS = 8          # distinct trails cached per process
_INDEX_HEAD = 512            # leading bytes compared to detect a replacement

_INDEX_LOCK = threading.Lock()
_INDEX = {}                  # abspath -> _Index


class _Index(object):
    """Summary of the lines of one audit file, in file order."""
    __slots__ = ("dev", "ino", "consumed", "head", "entries", "garbage",
                 "disabled")

    def __init__(self, dev, ino):
        self.dev = dev
        self.ino = ino
        self.consumed = 0    # bytes indexed: always just past a newline
        self.head = None     # first _INDEX_HEAD bytes of the file
        self.entries = []    # (offset, length, ts_or_None, category)
        self.garbage = 0     # lines every reader skips (corrupt / not an object)
        self.disabled = False   # over the ceiling: this file is scanned, not
                                # indexed, until it is replaced


_BLANK = object()       # a line that is nothing to anyone
_GARBAGE = object()     # a line every reader skips and prune drops


def _index_line(offset, line):
    """Summarize one raw line (no trailing newline) as an index entry,
    _BLANK, or _GARBAGE.

    Mirrors the skip rules every consumer already applies: a blank line is
    nothing at all (prune drops it without counting it), a line that is not
    a JSON object is garbage, and a non-numeric ts is recorded as None --
    read_events() still returns such an event when no ts filter is given,
    while prune() drops it, so both need to see it."""
    stripped = line.strip()
    if not stripped:
        return _BLANK
    try:
        ev = json.loads(stripped)
    except ValueError:
        return _GARBAGE
    if not isinstance(ev, dict):
        return _GARBAGE
    ts = ev.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        ts = None
    return (offset, len(line), ts, ev.get("category"))


def _index_extends(f, idx, size):
    """True when the file behind *f* is the one *idx* describes, grown."""
    if size < idx.consumed:
        return False
    if idx.head is not None:
        f.seek(0)
        if f.read(len(idx.head)) != idx.head:
            return False
    if idx.consumed:
        f.seek(idx.consumed - 1)
        if f.read(1) != b"\n":
            return False
    return True


def _index_grow(idx, f, size):
    """Index the complete lines in [idx.consumed, size).

    The index is mutated only once the whole span has been summarized, so a
    read that fails part way leaves it exactly as it was rather than
    half-extended -- entries recorded against bytes that `consumed` still
    says are unread would be indexed twice on the next pass."""
    base = idx.consumed
    f.seek(base)
    data = f.read(size - base)
    entries, garbage, start = [], 0, 0
    while True:
        nl = data.find(b"\n", start)
        if nl < 0:
            break                      # torn/in-flight tail: leave unconsumed
        rec = _index_line(base + start, data[start:nl])
        if rec is _GARBAGE:
            garbage += 1
        elif rec is not _BLANK:
            entries.append(rec)
        start = nl + 1
    if base == 0:
        idx.head = data[:_INDEX_HEAD]
    idx.entries.extend(entries)
    idx.garbage += garbage
    idx.consumed = base + start


def _indexed(path):
    """Open *path* and return (fh, entries, count, garbage), or None.

    The caller owns *fh* and MUST close it.  Reads addressed by the returned
    offsets go to that same fd, so a concurrent prune replacing the file
    cannot make them read a different file's bytes: the fd keeps the inode
    the index was built from.  *count* pins how much of *entries* belongs to
    the caller's snapshot (another thread may append more; it never rewrites
    what is already there)."""
    try:
        f = open(path, "rb")
    except Exception:
        return None            # missing/unreadable: the scan says [] too
    try:
        st = os.fstat(f.fileno())
        key = os.path.abspath(path)
        with _INDEX_LOCK:
            idx = _INDEX.get(key)
            same_file = (idx is not None and idx.dev == st.st_dev
                         and idx.ino == st.st_ino)
            if same_file and idx.disabled:
                # Known too big to index: go straight to the scan rather than
                # rebuilding an index this call is only going to throw away.
                f.close()
                return None
            if not same_file or not _index_extends(f, idx, st.st_size):
                idx = _Index(st.st_dev, st.st_ino)
                if len(_INDEX) >= INDEX_MAX_PATHS:
                    _INDEX.clear()
                _INDEX[key] = idx
            if st.st_size > idx.consumed:
                _index_grow(idx, f, st.st_size)
            if len(idx.entries) > INDEX_MAX_ENTRIES:
                idx.disabled = True
                idx.entries = []        # release it; a holder keeps its own
                idx.garbage = 0
                f.close()
                return None
            # An unconsumed tail is a torn in-flight append: no reader can
            # use it, but prune() DOES drop it, so it counts as garbage for
            # the caller even though it is not (yet) indexable.
            pending = 1 if st.st_size > idx.consumed else 0
            return f, idx.entries, len(idx.entries), idx.garbage + pending
    except Exception:
        # Never raise out of a read path: read_events()/histogram() are
        # documented not to, and every answer is still reachable by scan.
        f.close()
        return None


def append_event(path, event, device_id=None, secret_name=None, old_id=None,
                 new_id=None, src_ip=None, result="ok", actor=None,
                 category=None, action=None, target=None, detail=None,
                 ts=None):
    """Append one JSONL event line to *path* (bounded store, see module doc).

    Backwards compatible with the original broker signature: (path, event,
    device_id) positional plus secret_name/old_id/new_id/src_ip/result kwargs
    keep working unchanged; device_id is now optional so console actions
    without a device can be logged.  New structured kwargs are additive.

    Parent directories are created if they do not exist.
    None-valued optional fields are omitted from the record.
    Amortized: every PRUNE_EVERY-th append per path also prunes the file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    if category is None:
        category = _EVENT_CATEGORY.get(event)

    ev = {
        "ts":    int(ts if ts is not None else time.time()),
        "event": event,
    }
    if device_id is not None:
        ev["device_id"] = device_id
    if actor is not None:
        ev["actor"] = actor
    if category is not None:
        ev["category"] = category
    if action is not None:
        ev["action"] = action
    if target is not None:
        ev["target"] = target
    if detail is not None:
        ev["detail"] = detail
    if secret_name is not None:
        ev["secret_name"] = secret_name
    if old_id is not None:
        ev["old_id"] = old_id
    if new_id is not None:
        ev["new_id"] = new_id
    if src_ip is not None:
        ev["src_ip"] = src_ip
    ev["result"] = result

    key = os.path.abspath(path)
    with secrets_store.store_lock(path):
        # If a previous writer crashed mid-line the file ends without a
        # newline; appending straight after it would merge — and corrupt —
        # THIS event too.  Terminate the torn tail first (it stays corrupt
        # on its own line and is skipped by readers / dropped by prune).
        lead = ""
        try:
            with open(path, "rb") as rf:
                rf.seek(-1, os.SEEK_END)
                if rf.read(1) != b"\n":
                    lead = "\n"
        except OSError:
            pass  # file missing or empty: nothing to repair

        with open(path, "a") as f:
            f.write(lead + json.dumps(ev) + "\n")

        n = _appends_since_prune.get(key, 0) + 1
        if n >= PRUNE_EVERY:
            _prune_locked(path, time.time())
            n = 0
        _appends_since_prune[key] = n


def prune(path, now=None):
    """Prune *path* down to the retention window and entry cap.

    Takes the store lock; the rewrite is atomic and mode-preserving.  A
    no-op (nothing to drop, file absent) does not rewrite the file.
    Returns the number of lines dropped.  *now* is injectable for tests.
    """
    if now is None:
        now = time.time()
    with secrets_store.store_lock(path):
        return _prune_locked(path, now)


def _prune_locked(path, now):
    """Prune implementation; caller MUST hold secrets_store.store_lock(path).

    A line survives iff it parses to a JSON object with a numeric ts within
    the retention window; corrupt lines are dropped (they are unreadable to
    every consumer anyway).  The cap then keeps the newest-by-position tail.
    """
    cutoff = now - _retention_seconds()
    cap = _max_events()
    indexed = _indexed(path)
    if indexed is not None:
        # Cheap NEGATIVE check first. This runs on the amortized append path
        # while the cross-process audit flock is held, so the common "nothing
        # has aged out yet" case must not cost a full re-parse of the trail
        # -- device token refresh blocks behind exactly this lock.
        fh, entries, count, garbage = indexed
        fh.close()
        if garbage == 0 and count <= cap and not any(
                entries[i][2] is None or entries[i][2] < cutoff
                for i in range(count)):
            return 0

    try:
        with open(path) as f:
            raw = f.readlines()
    except OSError:
        return 0

    total = 0
    kept = []
    for line in raw:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            ev = json.loads(line)
        except ValueError:
            continue  # corrupt line: drop
        if not isinstance(ev, dict):
            continue
        ts = ev.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue  # no usable timestamp: cannot ever expire, drop
        if ts < cutoff:
            continue
        kept.append(line)

    # cap is always >= 1: non-positive env values take the default
    if len(kept) > cap:
        kept = kept[-cap:]  # evict oldest by append order (clock-game proof)

    dropped = total - len(kept)
    if dropped <= 0:
        return 0

    _atomic_write_lines(path, kept)
    return dropped


HISTOGRAM_MAX_BUCKETS = 200


def histogram(path, since_ts, until_ts, buckets, category=None):
    """Bin events from *path* into evenly-spaced buckets over
    [since_ts, until_ts), NEWEST-agnostic (returned oldest-first by bucket
    start).  Returns a list of {"start": int, "count": int}, one per bucket,
    including buckets with zero events.

    *buckets* is clamped to [1, HISTOGRAM_MAX_BUCKETS].  category filters as
    in read_events().  Events with ts outside the window, or with a
    non-numeric/garbage ts, are ignored.  Never raises; a missing/unreadable
    file yields all-zero buckets.
    """
    n = max(1, min(int(buckets), HISTOGRAM_MAX_BUCKETS))
    span = until_ts - since_ts
    width = span / n if span > 0 else 0

    starts = [since_ts + i * width for i in range(n)]
    counts = [0] * n

    indexed = _indexed(path)
    if indexed is not None:
        # The index already carries every field this bins on, so a poll
        # parses no JSON at all -- it walks tuples.
        fh, entries, count, _ = indexed
        fh.close()
        for i in range(count):
            ts = entries[i][2]
            if ts is None or ts < since_ts or ts >= until_ts:
                continue
            if category is not None and entries[i][3] != category:
                continue
            idx = int((ts - since_ts) / width) if width > 0 else 0
            if idx >= n:
                idx = n - 1
            counts[idx] += 1
        return [{"start": int(starts[i]), "count": counts[i]} for i in range(n)]

    try:
        with open(path) as f:
            raw = f.readlines()
    except Exception:
        raw = []

    for line in raw:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        ts = ev.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        if ts < since_ts or ts >= until_ts:
            continue
        if category is not None and ev.get("category") != category:
            continue
        if width > 0:
            idx = int((ts - since_ts) / width)
        else:
            idx = 0
        if idx >= n:
            idx = n - 1
        counts[idx] += 1

    return [{"start": int(starts[i]), "count": counts[i]} for i in range(n)]


def _atomic_write_lines(path, lines):
    """Atomically replace *path* with *lines* via a UNIQUE temp file in the
    same directory + os.replace (same pattern as catalog._atomic_write_json),
    preserving the target file's mode."""
    d = os.path.dirname(os.path.abspath(path))
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".audit-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for line in lines:
                f.write(line + "\n")
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def read_events(path, limit=200, before_ts=None, after_ts=None, category=None):
    """Return up to *limit* events from *path*, NEWEST FIRST (reverse append
    order).  Never raises; a missing/unreadable file yields [].

    before_ts: only events with ts strictly below it (pagination cursor --
    pass the ts of the oldest event from the previous page).
    after_ts:  only events with ts greater than or equal to it (inclusive
    lower bound -- combine with before_ts to select a window).
    category:  only events whose category equals it (see AUDIT_CATEGORIES).
    limit:     None means unlimited.

    Garbage tolerant: corrupt lines (torn tail of an in-flight append, junk)
    are skipped.  Lockless by design -- see the module docstring.
    """
    if limit is not None and limit <= 0:
        return []

    indexed = _indexed(path)
    if indexed is not None:
        fh, entries, count, _ = indexed
        try:
            out = []
            for i in range(count - 1, -1, -1):
                offset, length, ts, cat = entries[i]
                if before_ts is not None or after_ts is not None:
                    if ts is None:
                        continue
                    if before_ts is not None and ts >= before_ts:
                        continue
                    if after_ts is not None and ts < after_ts:
                        continue
                if category is not None and cat != category:
                    continue
                # Only the lines that made the page are read and parsed.
                fh.seek(offset)
                try:
                    ev = json.loads(fh.read(length).strip())
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                out.append(ev)
                if limit is not None and len(out) >= limit:
                    break
            return out
        except OSError:
            pass            # torn read: fall through to the streaming scan
        finally:
            fh.close()

    try:
        with open(path) as f:
            raw = f.readlines()
    except Exception:
        return []

    out = []
    for line in reversed(raw):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        if before_ts is not None or after_ts is not None:
            ts = ev.get("ts")
            if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                continue
            if before_ts is not None and ts >= before_ts:
                continue
            if after_ts is not None and ts < after_ts:
                continue
        if category is not None and ev.get("category") != category:
            continue
        out.append(ev)
        if limit is not None and len(out) >= limit:
            break
    return out
