# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Process-local aggregate token buckets for Console API admission."""

import math
import os
import threading
import time


def _rate_from_env(env, name):
    raw = env.get(name, "0").strip()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError("%s must be a finite non-negative number" % name)
    if not math.isfinite(value) or value < 0:
        raise ValueError("%s must be a finite non-negative number" % name)
    return value


def _burst_from_env(env, name):
    raw = env.get(name, "1").strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError("%s must be an integer from 1 to 1000" % name)
    if not 1 <= value <= 1000:
        raise ValueError("%s must be an integer from 1 to 1000" % name)
    return value


class AggregateRateLimiter:
    """Shared read/write/total buckets, with atomic all-or-nothing admission.

    Disabled rates (zero) impose no limit. Buckets hold at most their
    configured burst and are process-local; no per-user or per-IP state is
    retained. One lock protects refill, test, and debit across every bucket so
    requests cannot evade the total budget by alternating read and write
    routes.
    """

    def __init__(self, read_rate=0, write_rate=0, total_rate=0,
                 read_burst=1, write_burst=1, total_burst=1,
                 clock=time.monotonic):
        configs = {
            "read": (read_rate, read_burst),
            "write": (write_rate, write_burst),
            "total": (total_rate, total_burst),
        }
        self._buckets = {}
        for name, (rate, burst) in configs.items():
            if not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate < 0:
                raise ValueError("%s rate must be finite and non-negative" % name)
            if type(burst) is not int or not 1 <= burst <= 1000:
                raise ValueError("%s burst must be an integer from 1 to 1000" % name)
            self._buckets[name] = {"rate": float(rate), "capacity": burst,
                                   "tokens": float(burst), "updated": None}
        self._clock = clock
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(
            read_rate=_rate_from_env(env, "IRIS_API_RATE_READ"),
            write_rate=_rate_from_env(env, "IRIS_API_RATE_WRITE"),
            total_rate=_rate_from_env(env, "IRIS_API_RATE_TOTAL"),
            read_burst=_burst_from_env(env, "IRIS_API_BURST_READ"),
            write_burst=_burst_from_env(env, "IRIS_API_BURST_WRITE"),
            total_burst=_burst_from_env(env, "IRIS_API_BURST_TOTAL"),
        )

    def admit(self, method):
        """Return ``(allowed, retry_after_seconds)`` for one registered route."""
        kind = "read" if method in ("GET", "HEAD") else "write"
        with self._lock:
            selected = (self._buckets[kind], self._buckets["total"])
            # Read the clock under the same lock as refill/debit. Clamp a
            # backwards-moving test or system clock to the latest selected
            # bucket timestamp so concurrent calls can never refill twice
            # by installing an older timestamp after a newer one.
            updated = [bucket["updated"] for bucket in selected
                       if bucket["updated"] is not None]
            now = max([self._clock(), *updated])
            for bucket in selected:
                if bucket["rate"] <= 0:
                    continue
                if bucket["updated"] is None:
                    bucket["updated"] = now
                else:
                    elapsed = max(0.0, now - bucket["updated"])
                    bucket["tokens"] = min(
                        bucket["capacity"],
                        bucket["tokens"] + elapsed * bucket["rate"])
                    bucket["updated"] = now

            waits = []
            for bucket in selected:
                if bucket["rate"] <= 0 or bucket["tokens"] >= 1:
                    continue
                waits.append((1 - bucket["tokens"]) / bucket["rate"])
            if waits:
                return False, max(1, int(math.ceil(max(waits))))

            for bucket in selected:
                if bucket["rate"] > 0:
                    bucket["tokens"] -= 1
            return True, 0
