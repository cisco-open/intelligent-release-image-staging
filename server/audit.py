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
    days = AUDIT_RETENTION_DAYS
    raw = os.environ.get("IRIS_AUDIT_RETENTION_DAYS")
    if raw:
        try:
            days = int(raw)
        except ValueError:
            pass
    return days * 86400


def _max_events():
    cap = AUDIT_MAX_EVENTS
    raw = os.environ.get("IRIS_AUDIT_MAX_EVENTS")
    if raw:
        try:
            cap = int(raw)
        except ValueError:
            pass
    return cap


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
    try:
        with open(path) as f:
            raw = f.readlines()
    except OSError:
        return 0

    cutoff = now - _retention_seconds()
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

    cap = _max_events()
    if cap >= 0 and len(kept) > cap:
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
    try:
        with open(path) as f:
            raw = f.readlines()
    except Exception:
        return []

    if limit is not None and limit <= 0:
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
