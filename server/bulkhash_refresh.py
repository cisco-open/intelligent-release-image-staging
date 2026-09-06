# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Bulk Hash reconciliation pipeline (KGV reconciler Task 3): the
settings store for the refresh schedule, the pure schedule-math the
scheduler loop uses, and ``run_refresh`` -- the SINGLE entry point that
scheduled (``bulkhash_refresh_loop``), manual (a future console "Refresh
now" route), and offline (a future uploaded-tar route) callers all share.

Layering: server/bulkhash.py (Task 1, merged) owns fetch/verify_tar/parse/
reconcile -- pure, no HTTP-server or catalog coupling, ALL failures raise
``BulkHashError``. server/catalog.py (Task 2, merged)'s
``CatalogStore.apply_hash_verification`` owns applying verdicts to the
catalog (quarantine, wire fields, convergence). This module is the glue: it
owns the schedule (when to run), the single-flight lock (at most one run at
a time), and enforces Task 1's two binding caller obligations on every
call -- verify_tar must succeed before parse ever runs, and the catalog's
image list is filtered to hashed/well-formed entries before reconcile ever
sees it (reconcile() raises on any image missing a sha512 or carrying a
non-int size; a single legacy row must never block every other verdict).

Settings live in ``$IRIS_STATE/bulkhash-schedule.json`` (the
telemetry_destination.py / audit_export.py tolerant-read + atomic-write
idiom): ``{"mode": "off"|"daily"|"weekly", "hour_utc": 0-23, "last_run":
{"at", "source", "outcome", "matched", "mismatched", "not_in_feed"}}``.
``outcome`` is ``"ok"`` or ``"fail: <reason>"`` (the audit_export.py
last_result convention -- one human-readable string, not a separate
detail field the schema does not have); on failure matched/mismatched/
not_in_feed are None (nothing was reconciled).

The schema has no weekday field, so "weekly" runs on a fixed anchor day
(Monday UTC) -- ``hour_utc`` still controls the time of day. This is a
Task 3 design choice (documented here since the brief did not specify a
weekday), not a value a caller can currently configure.

Stdlib only; imports bulkhash and (by the caller passing a CatalogStore
instance) indirectly interacts with catalog.py's API, but never imports
catalog.py or gui_server.py itself -- gui_server.py's bootstrap wires this
module's ``run_refresh``/``bulkhash_refresh_loop`` to a real CatalogStore
and starts the daemon thread (the ca_trust_refresh_loop idiom)."""
import calendar
import json
import os
import shutil
import tempfile
import threading
import time

import bulkhash

# ---------------------------------------------------------------------------
# Feed endpoint + pinned verification certificate
# ---------------------------------------------------------------------------

# Documented alongside the pinned cert itself (server/certs/
# cisco_bulkhash_verify.pem's provenance header): a live download of this
# exact URL on 2026-08-29 is what that cert was extracted from.
FEED_URL = ("https://tools.cisco.com/cscrdr/security/center/files/trust/"
            "Cisco_BulkHash_CSV.tar")
_CERT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "certs",
    "cisco_bulkhash_verify.pem")
# bulkhash.fetch's urlopen timeout is per socket operation, not a total
# transfer deadline, so this stays generous even though the real feed's CSV
# is tens of MB -- matches bulkhash._OPENSSL_TIMEOUT's "generous but
# bounded" precedent in the same feature area.
_FETCH_TIMEOUT = 60
_DETAIL_MAX = 200        # bounded failure-detail length (audit_export.py's
                         # _stderr_snippet / _FAIL_DETAIL_MAX precedent)


# ---------------------------------------------------------------------------
# Settings store: $IRIS_STATE/bulkhash-schedule.json
# ---------------------------------------------------------------------------

BASENAME = "bulkhash-schedule.json"
MODES = ("off", "daily", "weekly")

_DEFAULT_LAST_RUN = {"at": None, "source": None, "outcome": None,
                     "matched": None, "mismatched": None,
                     "not_in_feed": None}

# Serializes every read-modify-write of the settings file (audit_export.py's
# SETTINGS_LOCK idiom): a console save of mode/hour_utc (a future task) and
# a run recording its last_run must not interleave and drop one write.
SETTINGS_LOCK = threading.Lock()


def settings_path(state_dir):
    return os.path.join(state_dir, BASENAME)


def _tolerant_last_run(raw):
    out = dict(_DEFAULT_LAST_RUN)
    if not isinstance(raw, dict):
        return out
    at = raw.get("at")
    if isinstance(at, (int, float)) and not isinstance(at, bool):
        out["at"] = int(at)
    source = raw.get("source")
    if isinstance(source, str):
        out["source"] = source
    outcome = raw.get("outcome")
    if isinstance(outcome, str):
        out["outcome"] = outcome
    for key in ("matched", "mismatched", "not_in_feed"):
        val = raw.get(key)
        if isinstance(val, int) and not isinstance(val, bool):
            out[key] = val
    return out


def read_settings(path):
    """Tolerant read: missing/unreadable file, corrupt JSON, non-dict
    documents and wrong-typed fields all collapse to sane defaults (mode
    "off", hour_utc 0, an empty last_run) -- a garbage settings file can
    only ever disable scheduled runs, never break a caller. A settings
    reader never raises."""
    out = {"mode": "off", "hour_utc": 0, "last_run": dict(_DEFAULT_LAST_RUN)}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    if not isinstance(data, dict):
        return out
    mode = data.get("mode")
    if mode in MODES:
        out["mode"] = mode
    hour = data.get("hour_utc")
    if isinstance(hour, int) and not isinstance(hour, bool) and 0 <= hour <= 23:
        out["hour_utc"] = hour
    out["last_run"] = _tolerant_last_run(data.get("last_run"))
    return out


def write_settings(path, mode, hour_utc, last_run):
    """Atomic write: mkstemp in the same dir + os.replace (house idiom)."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".bulkhash-schedule-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"mode": mode, "hour_utc": hour_utc,
                      "last_run": last_run}, f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _record_last_run(path, last_run):
    """last_run update, preserving whatever mode/hour_utc are currently on
    record (a run must never clobber a concurrent schedule edit, and must
    never invent settings a console save hasn't made yet). NOT guarded --
    write_settings's makedirs/mkstemp/json.dump/os.replace can all raise
    (ENOSPC, a read-only state dir, ...); `_try_record_last_run` below is
    the guarded call site every caller in this module actually uses."""
    with SETTINGS_LOCK:
        current = read_settings(path)
        write_settings(path, current["mode"], current["hour_utc"], last_run)


def _try_record_last_run(path, last_run):
    """Best-effort wrapper: persisting last_run must never itself take down
    run_refresh (which promises it never raises) -- guarded the same way
    the audit_fn calls right next to every caller of this are already
    guarded. On the failure path this matters doubly: without this guard,
    an I/O error here would REPLACE the original pipeline failure (the
    exception run_refresh is already handling) and skip the audit_fn call
    that follows it -- the real failure would be neither recorded nor
    logged. Swallowing here means the in-memory result run_refresh returns
    (and the audit_fn call) always reflect the true outcome even when
    persisting it to disk did not stick."""
    try:
        _record_last_run(path, last_run)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Pure schedule math (no I/O, no wall-clock read -- `now` is always passed
# in, epoch seconds, the house convention: time.time()/time.gmtime()
# throughout this codebase, never the stdlib `datetime` module)
# ---------------------------------------------------------------------------

# time.struct_time.tm_wday: Monday=0 .. Sunday=6. The schedule schema has no
# weekday field (see module docstring) -- "weekly" always lands here.
_WEEKLY_ANCHOR_WEEKDAY = 0


def next_run_at(mode, hour_utc, now):
    """The next epoch-seconds UTC instant `run_refresh` should fire for
    `mode` at `hour_utc` (0-23), STRICTLY after `now` (also epoch seconds)
    -- or None for mode "off" (or any other unrecognized mode). Computed
    entirely in UTC via time.gmtime/calendar.timegm, never the host's local
    timezone, so "midnight UTC" means the same instant regardless of where
    this process runs.

    daily: today's hour_utc:00:00 UTC if that is still ahead of `now`,
    otherwise tomorrow's.
    weekly: the next occurrence of hour_utc:00:00 UTC on the fixed anchor
    weekday (_WEEKLY_ANCHOR_WEEKDAY) that is still ahead of `now` -- today's,
    if today IS the anchor weekday and its slot has not passed yet,
    otherwise next week's."""
    if mode not in ("daily", "weekly"):
        return None
    try:
        hour = int(hour_utc) % 24
    except (TypeError, ValueError):
        hour = 0
    tm = time.gmtime(now)
    midnight = calendar.timegm(
        (tm.tm_year, tm.tm_mon, tm.tm_mday, 0, 0, 0, 0, 0, 0))
    candidate = midnight + hour * 3600
    if mode == "weekly":
        days_ahead = (_WEEKLY_ANCHOR_WEEKDAY - tm.tm_wday) % 7
        candidate += days_ahead * 86400
        step = 7 * 86400
    else:
        step = 86400
    if candidate <= now:
        candidate += step
    return candidate


# ---------------------------------------------------------------------------
# Catalog image list -> bulkhash.reconcile()-ready tuples
# ---------------------------------------------------------------------------

def _reconcile_input(images):
    """catalog.list_images() entries (dicts keyed "id", "filename", "size",
    "sha512", ...) -> bulkhash.reconcile()-ready (image_id, filename, size,
    sha512) tuples, pre-filtering out anything reconcile() would otherwise
    raise BulkHashError on -- Task 1's binding caller obligation: it raises
    on ANY image lacking a sha512 or carrying a size that cannot be coerced
    to int. A filtered image simply gets no verdict this run; one legacy or
    still-hashing catalog entry must never block every other image's
    verdict."""
    out = []
    for entry in images:
        sha512 = entry.get("sha512")
        if not isinstance(sha512, str) or not sha512.strip():
            continue
        try:
            size = int(entry.get("size"))
        except (TypeError, ValueError):
            continue
        out.append((entry.get("id"), entry.get("filename"), size, sha512))
    return out


# ---------------------------------------------------------------------------
# run_refresh: the single entry point (scheduled / manual / offline)
# ---------------------------------------------------------------------------

# Single-flight guard for the whole process. There is exactly one
# CatalogStore/gui_server process in production (mirrors tracker.py's
# per-instance _run_lock/_running, but run_refresh is a module-level
# function, not a method on a persistent reconciler object, so the guard is
# module-level state rather than per-instance).
_RUN_LOCK = threading.Lock()
_RUN_CONDITION = threading.Condition(_RUN_LOCK)
_RUNNING = False
# Every wait=True caller registers only after its image is durable in the
# catalog.  A run records the latest registration it can cover immediately
# BEFORE reading the catalog: registrations made later must force a newer
# snapshot even if that run succeeds.  Successful coverage is kept per state
# directory so a test/embedding with a second catalog can never borrow the
# first catalog's result.  Failed runs are deliberately never entered here.
_WAIT_GENERATION = 0
_SUCCESSFUL_COVERAGE = {}


def _failure_detail(exc):
    text = str(exc) or exc.__class__.__name__
    text = " ".join(text.split())
    return text[:_DETAIL_MAX]


def run_refresh(source, state_dir, catalog, tar_path=None, feed_url=FEED_URL,
                cert_path=_CERT_PATH, timeout=_FETCH_TIMEOUT, audit_fn=None,
                wait=False, now_fn=time.time, _fetch_fn=bulkhash.fetch,
                _verify_fn=bulkhash.verify_tar, _parse_fn=bulkhash.parse,
                _reconcile_fn=bulkhash.reconcile):
    """The single entry point for every Cisco Bulk Hash reconciliation run:
    scheduled (`bulkhash_refresh_loop`, source="scheduled"), manual (a
    console "Refresh now" route, source="manual" -- a later task), and
    offline (an uploaded tar, source="offline" -- a later task supplies
    `tar_path` so the fetch step is skipped and this exact same pipeline
    runs against the uploaded file instead).

    Guarded by a process-wide lock: at most one run in flight at a time. By
    default, a call that arrives while another is already running does
    nothing -- touches neither the catalog nor last_run -- and returns
    immediately with `{"outcome": "already_running"}` (the in-flight run's
    own last_run write, whenever it finishes, is unaffected).  A caller that
    must reconcile newly-created catalog content may pass ``wait=True``.  The
    caller registers after its content is durable.  If an in-flight run has
    not taken its catalog snapshot yet, that one successful run can cover the
    caller; otherwise one waiter takes a fresh snapshot.  Other concurrent
    waiters covered by that snapshot reuse its successful result instead of
    downloading and reconciling the same feed serially.  A failed result is
    never reused.  This is used by Console publish jobs so every newly imported
    image is known to have been present in the successful snapshot they accept.

    Pipeline, each stage fail-closed: fetch the feed to a private temp file
    (skipped when `tar_path` is given) -> verify_tar (MUST succeed before
    parse ever runs -- Task 1's binding ordering obligation) -> parse ->
    filter the catalog's image list to hashed, well-formed entries (Task
    1's other binding obligation) -> reconcile -> apply_hash_verification.
    ANY exception anywhere in that chain (a BulkHashError from
    fetch/verify_tar/parse, or anything else -- fail-closed defense in
    depth, matching ca_trust_refresh_loop's/audit_export.export_loop's own
    broad `except Exception`) means apply_hash_verification is never
    reached in that run, so the catalog is left completely untouched;
    run_refresh records the failure into last_run, reports it to `audit_fn`
    when given (the ca_trust_refresh_loop/audit_export.py "logged" idiom),
    and returns normally -- run_refresh itself never raises, so neither the
    scheduler loop nor a future console route needs its own try/except.

    Returns `{"outcome": "ok", "matched": int, "mismatched": int,
    "not_in_feed": int}` on success, or `{"outcome": "fail", "detail": str,
    "matched": None, "mismatched": None, "not_in_feed": None}` on failure --
    genuinely never raises, including if persisting last_run itself fails
    (see `_try_record_last_run`).

    `_fetch_fn`/`_verify_fn`/`_parse_fn`/`_reconcile_fn` are test-only
    injection seams (leading underscore: not part of this function's public
    API -- Tasks 4/5 must not pass them)."""
    global _RUNNING, _WAIT_GENERATION
    coverage_key = os.path.realpath(os.fspath(state_dir))
    request_generation = None
    with _RUN_CONDITION:
        if wait:
            _WAIT_GENERATION += 1
            request_generation = _WAIT_GENERATION
        while True:
            if request_generation is not None:
                covered = _SUCCESSFUL_COVERAGE.get(coverage_key)
                if covered is not None and covered[0] >= request_generation:
                    return dict(covered[1])
            if not _RUNNING:
                _RUNNING = True
                break
            if not wait:
                return {"outcome": "already_running"}
            _RUN_CONDITION.wait()

    # A one-item list lets the exact pre-list_images snapshot point report its
    # generation back without changing run_refresh's public result shape.
    snapshot_generation = [None]

    def mark_snapshot():
        with _RUN_CONDITION:
            snapshot_generation[0] = _WAIT_GENERATION

    result = None
    try:
        result = _run_refresh_locked(
            source, state_dir, catalog, tar_path=tar_path, feed_url=feed_url,
            cert_path=cert_path, timeout=timeout, audit_fn=audit_fn,
            now_fn=now_fn, fetch_fn=_fetch_fn, verify_fn=_verify_fn,
            parse_fn=_parse_fn, reconcile_fn=_reconcile_fn,
            snapshot_fn=mark_snapshot)
    finally:
        with _RUN_CONDITION:
            if result is not None and result.get("outcome") == "ok" \
                    and snapshot_generation[0] is not None:
                _SUCCESSFUL_COVERAGE[coverage_key] = (
                    snapshot_generation[0], dict(result))
            _RUNNING = False
            _RUN_CONDITION.notify_all()
    return result


def _run_refresh_locked(source, state_dir, catalog, tar_path, feed_url,
                        cert_path, timeout, audit_fn, now_fn, fetch_fn,
                        verify_fn, parse_fn, reconcile_fn, snapshot_fn):
    spath = settings_path(state_dir)
    tmp_dir = None
    try:
        fetched_path = tar_path
        if fetched_path is None:
            tmp_dir = tempfile.mkdtemp(prefix="bulkhash-refresh-")
            fetched_path = os.path.join(tmp_dir, "feed.tar")
            fetch_fn(feed_url, timeout, fetched_path)
        verify_fn(fetched_path, cert_path)     # raises before parse ever runs
        rows = parse_fn(fetched_path)
        # This stamp MUST precede list_images().  A wait=True import registers
        # only after publishing its catalog row, so every generation included
        # here is visible to the following read.  Stamping afterward could
        # falsely cover a row published between the read and the stamp.
        snapshot_fn()
        images = _reconcile_input(catalog.list_images())
        verdicts = reconcile_fn(rows, images)
        matched = sum(1 for v in verdicts.values()
                     if v["state"] == bulkhash.STATE_VERIFIED)
        mismatched = sum(1 for v in verdicts.values()
                         if v["state"] == bulkhash.STATE_MISMATCH)
        not_in_feed = sum(1 for v in verdicts.values()
                          if v["state"] == bulkhash.STATE_NOT_IN_FEED)
        catalog.apply_hash_verification(verdicts, source=source,
                                        now=now_fn())
    except Exception as exc:
        detail = _failure_detail(exc)
        _try_record_last_run(spath, {
            "at": int(now_fn()), "source": source,
            "outcome": "fail: %s" % detail, "matched": None,
            "mismatched": None, "not_in_feed": None})
        if audit_fn is not None:
            try:
                audit_fn(event="bulkhash-refresh", category="settings",
                         action="refresh", target="bulkhash", actor="system",
                         result="fail", detail=detail)
            except Exception:
                pass
        return {"outcome": "fail", "detail": detail, "matched": None,
               "mismatched": None, "not_in_feed": None}
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    _try_record_last_run(spath, {
        "at": int(now_fn()), "source": source, "outcome": "ok",
        "matched": matched, "mismatched": mismatched,
        "not_in_feed": not_in_feed})
    if audit_fn is not None:
        try:
            audit_fn(event="bulkhash-refresh", category="settings",
                     action="refresh", target="bulkhash", actor="system",
                     result="ok",
                     detail="matched=%d mismatched=%d not_in_feed=%d"
                            % (matched, mismatched, not_in_feed))
        except Exception:
            pass
    return {"outcome": "ok", "matched": matched, "mismatched": mismatched,
           "not_in_feed": not_in_feed}


# ---------------------------------------------------------------------------
# bulkhash_refresh_loop: the scheduler daemon thread (ca_trust_refresh_loop
# idiom -- gui_server.py's bootstrap starts this the same way)
# ---------------------------------------------------------------------------

# Bounds two things: how promptly an "off"-mode loop notices a mode/hour_utc
# edit, and how promptly a still-counting-down daily/weekly wait notices one
# (a change made mid-countdown is picked up within this many seconds of the
# NEXT tick, not only once the stale target arrives -- which could otherwise
# be up to a week away).
_IDLE_RECHECK_SECONDS = 300


def bulkhash_refresh_loop(stop_event, state_dir, catalog, audit_fn=None,
                          idle_recheck=_IDLE_RECHECK_SECONDS,
                          now_fn=time.time, next_run_at_fn=next_run_at,
                          run_refresh_fn=None):
    """Daemon thread: sleeps to the next scheduled slot (or `idle_recheck`
    while mode="off", or while still counting down to a slot more than
    `idle_recheck` away), re-reading the schedule from disk at the top of
    EVERY iteration -- a console edit (a later task) takes effect without
    restarting this process. Never dies: run_refresh already records and
    reports its own failures, so this loop only guards against
    run_refresh_fn raising unexpectedly (it should not, by contract, but a
    daemon scheduler thread dying silently would be far worse than a
    swallowed exception -- the ca_trust_refresh_loop precedent).

    Stale-target guard: `target` is computed from the schedule BEFORE the
    wait, so an operator edit made WHILE counting down to it (flipping
    mode="off", or pushing hour_utc later) must not let that now-stale
    target still fire once the wait elapses. After waking (not stopped),
    the schedule is re-read; if mode/hour_utc changed from what `target`
    was computed against, this cycle is skipped with no run -- the next
    iteration reads the schedule fresh and recomputes correctly from
    there (including, if still due under the NEW settings, promptly)."""
    run_refresh_fn = run_refresh_fn or run_refresh
    spath = settings_path(state_dir)
    while True:
        settings = read_settings(spath)
        now = now_fn()
        target = next_run_at_fn(settings["mode"], settings["hour_utc"], now)
        if target is None:
            delay = idle_recheck
        else:
            delay = min(idle_recheck, max(0.0, target - now))
        if stop_event.wait(delay):
            return
        if target is None:
            continue    # was just an idle recheck; nothing was scheduled
        fresh = read_settings(spath)
        if (fresh["mode"] != settings["mode"]
                or fresh["hour_utc"] != settings["hour_utc"]):
            continue    # schedule changed mid-countdown -- target is stale
        if now_fn() >= target:
            try:
                run_refresh_fn("scheduled", state_dir, catalog,
                               audit_fn=audit_fn)
            except Exception:
                pass   # this loop must never die; run_refresh itself is
                       # the one responsible for recording/logging failures
