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
import os
import re
import tempfile
import threading

TICK_SECONDS = 60
TIER_TICKS = {"good": 1, "constrained": 4}
SNAPSHOT_WRITE_INTERVAL = 15        # writer cadence; hub staleness keys on THIS
_LOG_EVERY = 600                    # rate limit for write-failure log lines (s)
_TTL_INTERVALS = 3                  # entries live 3 x effective interval
_IMAGE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_SAMPLE_BYTES = 1024
_INT_BOUNDS = {"done_bytes": 2 ** 53, "down_bps": 10 ** 12,
               "up_bps": 10 ** 12, "peers": 1024}
_PHASES = ("downloading", "seeding")


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
    """Server-side re-validation of one device sample (spec 6.1). Whitelists
    the eight v1 fields, checks enums exactly, bounds every numeric, and
    validates image_id against SERVER truth (the policy assignment) — never
    against anything else in the same request body. Raises ValueError."""
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
    out = {"v": 1, "image_id": image_id, "phase": data["phase"],
           "tier": data["tier"]}
    for key, cap in _INT_BOUNDS.items():
        out[key] = _bounded_int(data.get(key), cap)
    if len(json.dumps(out)) > _MAX_SAMPLE_BYTES:
        raise ValueError("sample too large")
    return out


class LiveTable:
    """In-memory {device_id: latest sample}. Thread-safe (the catalog handler
    runs threaded). Eviction TTL scales with the device's effective cadence
    so constrained or stream_every-stretched devices are not evicted between
    their own legitimate samples (spec 6.2)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._samples = {}
        self._rejected = 0

    def update(self, device_id, sample, now, stream_every):
        eff = max(TIER_TICKS[sample["tier"]], int(stream_every)) * TICK_SECONDS
        with self._lock:
            self._samples[device_id] = dict(
                sample, received_at=float(now), effective_interval=eff)

    def reject(self):
        with self._lock:
            self._rejected += 1

    def size(self):
        with self._lock:
            return len(self._samples)

    def snapshot(self, now):
        with self._lock:
            dead = [d for d, e in self._samples.items()
                    if now - e["received_at"] > _TTL_INTERVALS
                    * e["effective_interval"]]
            for d in dead:
                del self._samples[d]
            return {"written_at": float(now),
                    "counters": {"samples_rejected_total": self._rejected},
                    "samples": {d: dict(e)
                                for d, e in self._samples.items()}}


class StreamSettings:
    """mtime-cached reader of telemetry-settings.json (written by the console,
    spec 6.4). Missing/garbage file -> defaults; values clamped."""

    def __init__(self, path):
        self.path = path
        self._mtime = None
        self._value = (1, False)

    def read(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return (1, False)
        if mtime != self._mtime:
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
            self._mtime, self._value = mtime, (every, pause)
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
