# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Console-editable OTLP telemetry destination override (design 2026-08-19,
feature B). The console (gui_server process) writes
$IRIS_STATE/telemetry-destination.json; the tracker's Telemetry hub hot-reads
it (mtime-cached) at the top of every sample() pass. Per-field semantics:
null means "inherit the deployment env" (IRIS_OTLP_ENDPOINT /
IRIS_OBSERVABILITY); an absent file reproduces the env-only behavior
exactly. Endpoint values are not secrets (collector auth headers stay
env-only). Stdlib only; imports nothing from gui_server or telemetry (both
import this module — the live_samples.py layering rule)."""
import json
import os
import tempfile

BASENAME = "telemetry-destination.json"


def settings_path(state_dir):
    return os.path.join(state_dir, BASENAME)


def read(path):
    """Tolerant read: missing file, unreadable file, corrupt JSON, non-dict
    documents and wrong-typed fields all collapse to per-field None
    ("inherit env") — a garbage override can only ever fall back to the
    deployment default, never break the sampler."""
    out = {"endpoint": None, "enabled": None}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    if not isinstance(data, dict):
        return out
    endpoint = data.get("endpoint")
    if isinstance(endpoint, str) and endpoint.strip():
        out["endpoint"] = endpoint.strip()
    enabled = data.get("enabled")
    if isinstance(enabled, bool):
        out["enabled"] = enabled
    return out


def write(path, endpoint, enabled):
    """Atomic write (mkstemp + os.replace in the same dir — the
    live_samples._atomic_write_json discipline) so the hub's mtime-cached
    reader can never observe a half-written file. Validation (URL shape,
    trailing-slash strip) is the console handler's job — this module stores
    exactly what it is given."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".telemetry-dest-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"endpoint": endpoint, "enabled": enabled}, f,
                      sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def clear(path):
    """Remove the override ("Revert to deployment default"). Idempotent."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


class DestinationSettings:
    """mtime-cached reader (the live_samples.StreamSettings idiom) consulted
    by the hub at the top of each sample() pass. Missing file -> (None, None)
    without disturbing the cache key; unchanged mtime -> cached tuple."""

    def __init__(self, path):
        self.path = path
        self._mtime = None
        self._value = (None, None)

    def current(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return (None, None)
        if mtime != self._mtime:
            data = read(self.path)
            self._mtime = mtime
            self._value = (data["endpoint"], data["enabled"])
        return self._value
