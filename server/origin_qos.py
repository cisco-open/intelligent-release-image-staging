# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Origin-seeder QoS desired state and count-only durable status.

The desired hash binds the exact aria2 option strings and the complete sorted
set of live download GIDs. GIDs are used only in memory and are never written
to ``origin-qos.json``.
"""
import collections
import contextlib
import fcntl
import hashlib
import json
import os
import re
import tempfile
import types

import peer_policy

SCHEMA = 1
STATES = ("enforced", "degraded", "rpc_unavailable")
GLOBAL_OPTION_KEYS = frozenset(("max-overall-upload-limit",))
DOWNLOAD_OPTION_KEYS = frozenset(("max-upload-limit", "bt-max-peers"))
_GID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ERROR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

DesiredState = collections.namedtuple(
    "DesiredState",
    ["global_options", "download_options", "target_gids", "desired_hash"])
ApplyOutcome = collections.namedtuple(
    "ApplyOutcome",
    ["attempted", "success", "global_applied", "applied_download_count",
     "last_error"])


class OriginQosError(ValueError):
    """Raised when desired state or persisted status violates its schema."""


def _canonical_hash(global_options, download_options, target_gids):
    body = json.dumps({
        "global_options": dict(global_options),
        "download_options": dict(download_options),
        "target_gids": list(target_gids),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def validate_target_gids(values):
    """Return a sorted complete GID tuple or reject any malformed member."""
    if isinstance(values, (str, bytes)):
        raise OriginQosError("target_gids must be a collection")
    try:
        gids = list(values)
    except TypeError as exc:
        raise OriginQosError("target_gids must be a collection") from exc
    if any(not isinstance(gid, str) or not _GID_RE.fullmatch(gid)
           for gid in gids):
        raise OriginQosError("bad target gid")
    if len(gids) != len(set(gids)):
        raise OriginQosError("duplicate target gid")
    return tuple(sorted(gids))


def build_desired(policy_document, target_gids):
    """Compile the three global origin controls to exact aria2 string values."""
    qos = peer_policy.compile_qos(policy_document, None)
    global_options = {
        "max-overall-upload-limit": str(qos["origin_up_bps"]),
    }
    download_options = {
        "max-upload-limit": str(qos["origin_per_torrent_up_bps"]),
        "bt-max-peers": str(qos["origin_max_peers"]),
    }
    gids = validate_target_gids(target_gids)
    desired_hash = _canonical_hash(global_options, download_options, gids)
    return DesiredState(
        types.MappingProxyType(global_options),
        types.MappingProxyType(download_options), gids, desired_hash)


def apply_desired(aria, desired, session_id):
    """Attempt one complete global plus per-download apply.

    A global failure stops the pass. Per-download failures do not prevent the
    remaining targets from being attempted, but any failure makes the entire
    pass unsuccessful so the caller retries the full set.
    """
    if not session_id:
        return ApplyOutcome(False, False, False, 0,
                            "AriaSessionUnavailable")
    try:
        aria.set_global_options(dict(desired.global_options))
    except Exception as exc:
        return ApplyOutcome(True, False, False, 0, type(exc).__name__)

    applied = 0
    last_error = None
    for gid in desired.target_gids:
        try:
            aria.set_download_options(gid, dict(desired.download_options))
            applied += 1
        except Exception as exc:
            if last_error is None:
                last_error = type(exc).__name__
    return ApplyOutcome(
        True, last_error is None, True, applied, last_error)


def _count(name, value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OriginQosError("%s must be a nonnegative int" % name)
    return value


def validate_error_code(value):
    """Return a bare non-address-bearing error code, or reject the value."""
    if value is not None and (
            not isinstance(value, str) or not _ERROR_RE.fullmatch(value)):
        raise OriginQosError("bad last_error")
    return value


def build_status(state, aria_session_id, desired_hash, global_option_count,
                 target_download_count, applied_download_count, now,
                 last_error=None, **reject):
    """Construct the exact address-free ``origin-qos.json`` object."""
    if reject:
        raise OriginQosError(
            "unexpected argument(s): %s" % ", ".join(sorted(reject)))
    if state not in STATES:
        raise OriginQosError("bad origin QoS state: %r" % state)
    global_count = _count("global_option_count", global_option_count)
    target_count = _count("target_download_count", target_download_count)
    applied_count = _count("applied_download_count", applied_download_count)
    if global_count > len(GLOBAL_OPTION_KEYS):
        raise OriginQosError("global_option_count exceeds desired option count")
    if applied_count > target_count:
        raise OriginQosError("applied_download_count exceeds target count")
    if aria_session_id is not None and (
            not isinstance(aria_session_id, str) or not aria_session_id):
        raise OriginQosError("bad aria_session_id")
    if desired_hash is not None and (
            not isinstance(desired_hash, str) or not desired_hash):
        raise OriginQosError("bad desired_hash")
    last_error = validate_error_code(last_error)
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise OriginQosError("now must be numeric")
    if state == "enforced" and (
            not aria_session_id or not desired_hash
            or global_count != len(GLOBAL_OPTION_KEYS)
            or applied_count != target_count or last_error is not None):
        raise OriginQosError(
            "enforced requires current session, hash, and complete apply")
    return {
        "schema": SCHEMA,
        "updated_at": float(now),
        "state": state,
        "aria_session_id": aria_session_id,
        "desired_hash": desired_hash,
        "global_option_count": global_count,
        "target_download_count": target_count,
        "applied_download_count": applied_count,
        "last_reconciled_at": float(now),
        "last_error": last_error,
    }


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=".origin-qos-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(obj, handle, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@contextlib.contextmanager
def _lock(path):
    lock_path = path + ".lock"
    directory = os.path.dirname(lock_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def write_status(path, status):
    """Atomically persist one already constructor-validated status object."""
    with _lock(path):
        _atomic_write_json(path, status)


def read_status(path):
    """Return the parsed status dict, or ``None`` when missing or corrupt."""
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
