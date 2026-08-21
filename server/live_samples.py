# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Live transfer samples: catalog-side ingest state for the streaming
telemetry feature (spec sections 6.1-6.4). Ephemeral by design: the table is
in-memory, the snapshot file is plain JSON regenerated continuously (age
encryption in this repo covers the secrets store only), carries no secrets
and no IPs, and is safe on tmpfs. Stdlib only; imports nothing from
catalog.py (catalog imports this module)."""
import json
import math
import os
import re
import tempfile
import threading

TICK_SECONDS = 60
TIER_TICKS = {"good": 1, "constrained": 4}
SNAPSHOT_WRITE_INTERVAL = 15        # writer cadence; hub staleness keys on THIS
_LOG_EVERY = 600                    # rate limit for write-failure log lines (s)
_IMAGE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX32 = re.compile(r"^[a-f0-9]{32}$")
_MAX_SAMPLE_BYTES = 1024
V2_ENVELOPE_MAX_BYTES = 8192        # whole telemetry_observation member (spec §10)
LIVE_VALUE_VALIDITY = 120           # fixed, server receipt-keyed (spec §3B/§4)
RETENTION_CAP = 900                 # retention seconds ceiling (spec §3B)
_INT_BOUNDS = {"done_bytes": 2 ** 53, "down_bps": 10 ** 12,
               "up_bps": 10 ** 12, "peers": 1024}
_PHASES = ("downloading", "seeding")

# v2 telemetry_observation envelope (spec §10.1).
OBS_STATES = ("observed", "not_due", "paused", "disabled",
              "not_active", "rpc_unavailable")
SAMPLING_CLASSES = ("good", "constrained")
ARIA_STATUSES = ("active", "waiting", "paused", "complete", "error", "removed")
LIVE_PEER_ROWS_HARD_CAP = 32        # LIVE_PEER_ROWS_MAX = min(configured, 32)
_ARIA_INT_BOUNDS = {"completed_content_bytes": 2 ** 53,
                    "total_content_bytes": 2 ** 53,
                    "receive_bps": 10 ** 12, "send_bps": 10 ** 12,
                    "connections": 1024}
_PEER_ROW_BPS_CAP = 10 ** 12


def live_peer_rows_max(configured_max):
    """LIVE_PEER_ROWS_MAX = min(configured_max, 32) (spec §10, bounds)."""
    try:
        cfg = int(configured_max)
    except (TypeError, ValueError):
        cfg = LIVE_PEER_ROWS_HARD_CAP
    return max(0, min(cfg, LIVE_PEER_ROWS_HARD_CAP))



def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".live-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _bounded_int(value, cap):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("not an int")
    if not 0 <= value <= cap:
        raise ValueError("out of bounds")
    return value


def sanitize_sample(data, approved_image_id):
    """Server-side re-validation of one legacy **v1** device sample (spec 6.1 /
    §10.1c). Whitelists the eight v1 fields, checks enums exactly, bounds every
    numeric, validates image_id against SERVER truth (the policy assignment),
    and tags the result ``schema:"v1"`` so downstream never reinterprets a v1
    field as a v2 measurement. Raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError("sample must be an object")
    if data.get("v") != 1:
        raise ValueError("unknown sample version")
    image_id = data.get("image_id")
    if not isinstance(image_id, str) or not _IMAGE_RE.match(image_id):
        raise ValueError("bad image_id")
    if not approved_image_id or image_id != approved_image_id:
        raise ValueError("image_id is not the device's assigned image")
    if data.get("phase") not in _PHASES:
        raise ValueError("bad phase")
    if data.get("tier") not in TIER_TICKS:
        raise ValueError("bad tier")
    out = {"v": 1, "schema": "v1", "image_id": image_id, "phase": data["phase"],
           "tier": data["tier"]}
    for key, cap in _INT_BOUNDS.items():
        out[key] = _bounded_int(data.get(key), cap)
    if len(json.dumps(out)) > _MAX_SAMPLE_BYTES:
        raise ValueError("sample too large")
    return out


def sanitize_observation(data, approved_image_id, configured_max_peers):
    """Server-side re-validation of one v2 ``telemetry_observation`` envelope
    (spec §3A/§10.1). State-first: ``aria``/``peer_connections``/``sampling_class``
    exist ONLY under ``obs_state == observed``; a state-only envelope invents no
    transfer fields. Returns ``(clean, peer_connections_truncated)``.

    Whole-envelope size is bounded at ``V2_ENVELOPE_MAX_BYTES`` (rejected, never
    partially parsed). ``peer_connections`` beyond ``LIVE_PEER_ROWS_MAX`` are
    TRUNCATED to the prefix and flagged, not rejected. Every enum/type/bound
    failure, or aria/peers present when not observed, or missing required-under-
    observed fields, raises ValueError (a bad envelope is rejected-and-counted;
    the caller leaves prior good data untouched). No secret or token is ever in
    a raised message."""
    if not isinstance(data, dict):
        raise ValueError("observation must be an object")
    # Whole-envelope byte bound FIRST (never partially parse an oversize body).
    if len(json.dumps(data)) > V2_ENVELOPE_MAX_BYTES:
        raise ValueError("observation envelope too large")
    if data.get("v") != 2:
        raise ValueError("unknown observation version")
    obs_state = data.get("obs_state")
    if obs_state not in OBS_STATES:
        raise ValueError("bad obs_state")
    observed_at = data.get("observed_at")
    if isinstance(observed_at, bool) or not isinstance(observed_at,
                                                       (int, float)):
        raise ValueError("bad observed_at")
    out = {"v": 2, "schema": "v2", "obs_state": obs_state,
           "observed_at": float(observed_at)}

    tid = data.get("transfer_id")
    if tid is not None:
        if not isinstance(tid, str) or not _HEX32.match(tid):
            raise ValueError("bad transfer_id")
        out["transfer_id"] = tid
    image_id = data.get("image_id")
    if image_id is not None:
        if not isinstance(image_id, str) or not _IMAGE_RE.match(image_id):
            raise ValueError("bad image_id")
        if not approved_image_id or image_id != approved_image_id:
            raise ValueError("image_id is not the device's assigned image")
        out["image_id"] = image_id

    if obs_state != "observed":
        # State-only: aria / peer_connections / sampling_class forbidden.
        for forbidden in ("aria", "peer_connections", "sampling_class",
                          "sample_seq"):
            if forbidden in data:
                raise ValueError("%s forbidden when not observed" % forbidden)
        return out, False

    # observed: sample_seq + sampling_class required.
    seq = data.get("sample_seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("bad sample_seq")
    out["sample_seq"] = seq
    sampling_class = data.get("sampling_class")
    if sampling_class not in SAMPLING_CLASSES:
        raise ValueError("bad sampling_class")
    out["sampling_class"] = sampling_class
    sid = data.get("aria_session_id")
    if sid is not None:
        if not isinstance(sid, str) or not re.match(r"^[a-f0-9]{1,64}$", sid):
            raise ValueError("bad aria_session_id")
        out["aria_session_id"] = sid

    aria_in = data.get("aria")
    if not isinstance(aria_in, dict):
        raise ValueError("observed requires aria")
    aria = {}
    status = aria_in.get("status")
    if status is not None:
        if status not in ARIA_STATUSES:
            raise ValueError("bad aria.status")
        aria["status"] = status
    for key, cap in _ARIA_INT_BOUNDS.items():
        aria[key] = _bounded_int(aria_in.get(key), cap)
    out["aria"] = aria

    cap_rows = live_peer_rows_max(configured_max_peers)
    peers_in = data.get("peer_connections", [])
    if not isinstance(peers_in, list):
        raise ValueError("bad peer_connections")
    truncated = len(peers_in) > cap_rows
    rows = []
    for row in peers_in[:cap_rows]:
        if not isinstance(row, dict):
            raise ValueError("bad peer_connection row")
        ip = row.get("ip")
        if not isinstance(ip, str) or not ip or len(ip) > 64:
            raise ValueError("bad peer_connection ip")
        clean = {"ip": ip}
        for key in ("send_bps", "receive_bps"):
            if key in row:
                clean[key] = _bounded_int(row[key], _PEER_ROW_BPS_CAP)
        name = row.get("peer_client_name")
        if isinstance(name, str):
            clean["peer_client_name"] = name[:64]
        prog = row.get("progress")
        if prog is not None:
            if isinstance(prog, bool) or not isinstance(prog, (int, float)) \
                    or not math.isfinite(prog) or not 0 <= prog <= 100:
                raise ValueError("bad peer_connection progress")
            clean["progress"] = float(prog)
        rows.append(clean)
    out["peer_connections"] = rows
    if truncated:
        out["peer_connections_truncated"] = True
    return out, truncated


def _sampling_class_of(entry):
    """Derived sampling class of a stored observation for retention math. v2
    carries it directly; v1 maps its legacy ``tier`` (good/constrained)."""
    sc = entry.get("sampling_class")
    if sc in TIER_TICKS:
        return sc
    tier = entry.get("tier")
    return tier if tier in TIER_TICKS else "good"


def _retention_seconds(sampling_class, stream_every):
    """Cadence-aware retention (spec §3B/§10):
    min(RETENTION_CAP, max(TIER_TICKS[class], stream_every) * 60 * 3)."""
    ticks = max(TIER_TICKS.get(sampling_class, 1), int(stream_every))
    return min(RETENTION_CAP, ticks * TICK_SECONDS * 3)


class LiveTable:
    """In-memory {device_id: canonical device observation state}. Thread-safe
    (the catalog handler runs threaded). Freshness is RECEIPT-based (spec §4):

    - Only an ``observed`` envelope (re)sets the current rate/counters and its
      ``LIVE_VALUE_VALIDITY`` window; ``not_due`` never extends validity.
    - ``paused``/``disabled``/``not_active`` withdraw the live value now;
      ``rpc_unavailable`` marks unavailable and never retains an old rate.
    - An out-of-order (older-or-equal) ``sample_seq`` for a KNOWN transfer_id
      cannot replace a newer observation.
    - Retention (display context) scales with the device's cadence and is
      capped at RETENTION_CAP; entries older than retention are evicted.

    v1 rollout entries carry no ``sample_seq`` (no reorder protection) and fall
    back to receipt validity + retention exactly as spec §10.1c requires; their
    fields are never reinterpreted as v2."""

    _WITHDRAW_STATES = ("paused", "disabled", "not_active", "rpc_unavailable")
    _RATE_KEYS = ("aria", "peer_connections", "peer_connections_truncated")

    def __init__(self):
        self._lock = threading.Lock()
        self._samples = {}
        self._rejected = 0

    def observe(self, device_id, clean, now, stream_every):
        """Apply one sanitized observation (v1 sample or v2 envelope). Returns
        True if the stored state was updated, False if the update was dropped
        (out-of-order/duplicate seq for a known transfer)."""
        now = float(now)
        with self._lock:
            prior = self._samples.get(device_id)
            obs_state = clean.get("obs_state", "observed")   # v1 -> observed

            # Reorder protection: same transfer, older-or-equal seq -> drop.
            if obs_state == "observed" and "sample_seq" in clean and prior \
                    and prior.get("transfer_id") == clean.get("transfer_id") \
                    and "last_observed_seq" in prior \
                    and clean["sample_seq"] <= prior["last_observed_seq"]:
                return False

            entry = dict(clean)
            entry["received_at"] = now
            entry["retention_seconds"] = _retention_seconds(
                _sampling_class_of(clean), stream_every)

            if obs_state == "observed":
                entry["valid"] = True
                entry["observed_received_at"] = now
                if "sample_seq" in clean:
                    entry["last_observed_seq"] = clean["sample_seq"]
            else:
                # Withdrawal / not_due / rpc_unavailable: no fresh rate.
                entry["valid"] = False
                for key in self._RATE_KEYS:
                    entry.pop(key, None)
                # retention still keyed on the LAST observed receipt so a
                # withdrawn row ages out on its own cadence, not immediately.
                if prior and "observed_received_at" in prior:
                    entry["observed_received_at"] = prior["observed_received_at"]
                    entry["retention_seconds"] = prior.get(
                        "retention_seconds", entry["retention_seconds"])
                if prior and "last_observed_seq" in prior:
                    entry["last_observed_seq"] = prior["last_observed_seq"]
            self._samples[device_id] = entry
            return True

    def withdraw(self, device_id, obs_state="not_active"):
        """Server cross-check withdrawal (spec §3A): mark a device's live value
        invalid without inventing transfer fields (telemetry flags/global pause
        say off, or the device is unassigned/error). No-op if unknown."""
        with self._lock:
            prior = self._samples.get(device_id)
            if prior is None:
                return
            prior["valid"] = False
            prior["obs_state"] = obs_state
            for key in self._RATE_KEYS:
                prior.pop(key, None)

    def reject(self):
        with self._lock:
            self._rejected += 1

    def size(self):
        with self._lock:
            return len(self._samples)

    def _compute_valid(self, entry, now):
        # An explicitly withdrawn / non-observed entry is never valid
        # regardless of receipt age (spec §3A/§4 withdrawal).
        if not entry.get("valid") or entry.get("obs_state") not in \
                (None, "observed"):
            return False
        base = entry.get("observed_received_at", entry.get("received_at", 0.0))
        return base + LIVE_VALUE_VALIDITY >= now

    def snapshot(self, now):
        with self._lock:
            dead = []
            for d, e in self._samples.items():
                base = e.get("observed_received_at",
                             e.get("received_at", 0.0))
                if now - base > e.get("retention_seconds", RETENTION_CAP):
                    dead.append(d)
            for d in dead:
                del self._samples[d]
            samples = {}
            for d, e in self._samples.items():
                out = dict(e)
                out["valid"] = self._compute_valid(e, now)
                samples[d] = out
            return {"written_at": float(now),
                    "counters": {"samples_rejected_total": self._rejected},
                    "samples": samples}


class StreamSettings:
    """Cache-keyed reader of telemetry-settings.json (written by the console,
    spec 6.4). Missing file -> defaults with cache invalidation; unchanged
    file key -> cached tuple. Cache key is (mtime_ns, inode, size) matching
    the trust.ssl_context convention. Garbage file -> defaults."""

    def __init__(self, path):
        self.path = path
        self._cache_key = None
        self._value = (1, False)

    def read(self):
        try:
            st = os.stat(self.path)
            cache_key = (st.st_mtime_ns, st.st_ino, st.st_size)
        except OSError:
            self._cache_key = None
            return (1, False)
        if cache_key != self._cache_key:
            every, pause = 1, False
            try:
                with open(self.path) as f:
                    data = json.load(f)
                raw = data.get("stream_every")
                if isinstance(raw, int) and not isinstance(raw, bool) \
                        and 1 <= raw <= 60:
                    every = raw
                pause = data.get("stream_pause") is True
            except (OSError, ValueError, AttributeError):
                pass
            self._cache_key, self._value = cache_key, (every, pause)
        return self._value


def write_settings(path, every, pause):
    _atomic_write_json(path, {"stream_every": int(every),
                              "stream_pause": bool(pause)})


def writer_loop(table, path, interval, stop_event):
    """Snapshot the live table every `interval` seconds while it is
    non-empty, PLUS one final write when it just emptied — written_at must
    stay fresh on a quiet-but-valid table so the hub's staleness rule only
    fires when the catalog actually stopped writing (spec 6.3/7.1). Failures
    skip the cycle (best-effort; never kills the thread) and surface as one
    rate-limited stderr line per _LOG_EVERY seconds (spec section 9)."""
    import sys
    import time
    was_nonempty = False
    last_err = 0.0
    while not stop_event.wait(interval):
        try:
            snap = table.snapshot(time.time())
            nonempty = bool(snap["samples"])
            if nonempty or was_nonempty:
                _atomic_write_json(path, snap)
            was_nonempty = nonempty
        except Exception as exc:
            now = time.time()
            if now - last_err >= _LOG_EVERY:
                last_err = now
                print("live-samples snapshot write failed (skipped): %s"
                      % exc, file=sys.stderr, flush=True)
