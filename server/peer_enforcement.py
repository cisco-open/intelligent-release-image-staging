# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tracker-written / GUI-read peer enforcement status (``peer-enforcement.json``,
spec 10.5b / 13).

The tracker is the sole writer; the GUI reads it for status. The file exposes
``desired_ip_count`` only — the **raw denied-IP list is never stored or
exposed**. ``build_status`` rejects any attempt to pass a raw IP list and
refuses to construct a false ``enforced`` claim (``enforced`` requires both a
current ``aria_session_id`` and a ``desired_hash``). Atomic write under advisory
``fcntl.flock`` (same discipline as ``secrets_store``)."""
import contextlib
import fcntl
import json
import os
import tempfile

SCHEMA = 1
STATES = ("enforced", "degraded", "pending", "rpc_unavailable", "fail_closed")


class EnforcementError(ValueError):
    """Raised on an invalid state or a false ``enforced`` claim."""


def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".peer-enforcement-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@contextlib.contextmanager
def _lock(path):
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


def build_status(state, aria_session_id, desired_hash, applied_revision,
                 desired_ip_count, now, last_operation_exported_revision=0,
                 conflicts=None, last_effect=None, last_error=None, **reject):
    """Construct the exact enforcement status object (spec 10.5b).

    ``desired_ip_count`` is a count only. Passing any raw IP list (e.g.
    ``denied_ips=``) raises. An ``enforced`` state with no current session or no
    desired hash is a false claim and raises — a fail-closed/pending/no-address
    situation can never report ``enforced``.
    """
    if reject:
        raise EnforcementError(
            "unexpected argument(s): %s (raw IP lists are forbidden)"
            % ", ".join(sorted(reject)))
    if state not in STATES:
        raise EnforcementError("bad enforcement state: %r" % state)
    if isinstance(desired_ip_count, bool) or not isinstance(
            desired_ip_count, int):
        raise EnforcementError("desired_ip_count must be an int")
    if state == "enforced" and (not aria_session_id or not desired_hash):
        raise EnforcementError(
            "enforced requires a current session and desired hash")
    return {
        "schema": SCHEMA,
        "updated_at": float(now),
        "state": state,
        "aria_session_id": aria_session_id,
        "desired_hash": desired_hash,
        "applied_revision": applied_revision,
        "desired_ip_count": desired_ip_count,
        "last_reconciled_at": float(now),
        "last_operation_exported_revision": last_operation_exported_revision,
        "conflicts": list(conflicts) if conflicts else [],
        "last_effect": last_effect,
        "last_error": last_error,
    }


def write_status(path, status):
    """Atomically persist ``status`` under the advisory lock (tracker only)."""
    with _lock(path):
        _atomic_write_json(path, status)


def read_status(path):
    """GUI reader. Returns the parsed status dict, or ``None`` if the file is
    missing or corrupt."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data
