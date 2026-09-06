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
import ipaddress
import math
import os
import re
import tempfile

import peer_endpoints
import reconciler_status as status_codes

SCHEMA = 1
STATES = ("enforced", "degraded", "pending", "rpc_unavailable", "fail_closed")
MUTUAL_ORIGIN_MODE = "preflight"
_MUTUAL_ORIGIN_KEYS = frozenset((
    "mode", "newly_denied_device_count", "newly_denied_device_ids"))
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class EnforcementError(ValueError):
    """Raised on an invalid state or a false ``enforced`` claim."""


def _count(value):
    if type(value) is not int or value < 0:
        raise EnforcementError("expected nonnegative integer")
    return value


def _timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise EnforcementError("expected finite nonnegative timestamp")
    return float(value)


def _conflicts(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise EnforcementError("bad conflicts")
    fields = {"ipv4", "reason", "permitted_principal_type", "permitted_principal_id",
              "denied_principal_type", "denied_principal_id", "global_block_applied"}
    result = []
    for row in value:
        if not isinstance(row, dict) or set(row) != fields:
            raise EnforcementError("bad conflict fields")
        if row["reason"] != "shared_permit_deny" or row["global_block_applied"] is not False:
            raise EnforcementError("bad conflict meaning")
        if not isinstance(row["ipv4"], str):
            raise EnforcementError("bad conflict address")
        ipaddress.IPv4Address(row["ipv4"])
        for prefix in ("permitted", "denied"):
            kind, identity = row[prefix + "_principal_type"], row[prefix + "_principal_id"]
            if kind not in ("device", "service", "legacy") or not isinstance(identity, str) or not identity:
                raise EnforcementError("bad conflict principal")
        result.append(dict(row))
    return result


def validate_mutual_origin(value):
    """Return a defensive copy of the exact B6 preflight observation.

    Typed device ids are retained for the authenticated ``/swarm`` identity
    join. Management readers project only the count; no address is accepted.
    """
    if not isinstance(value, dict) or set(value) != _MUTUAL_ORIGIN_KEYS:
        raise EnforcementError("bad mutual_origin fields")
    if value.get("mode") != MUTUAL_ORIGIN_MODE:
        raise EnforcementError("bad mutual_origin mode")
    count = value.get("newly_denied_device_count")
    ids = value.get("newly_denied_device_ids")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise EnforcementError("bad newly_denied_device_count")
    if not isinstance(ids, list) or len(ids) > peer_endpoints.SUPPORTED_DEVICES:
        raise EnforcementError("bad newly_denied_device_ids")
    if any(not isinstance(device_id, str)
           or not _DEVICE_ID_RE.fullmatch(device_id) for device_id in ids):
        raise EnforcementError("bad newly denied device id")
    if ids != sorted(ids) or len(ids) != len(set(ids)) or count != len(ids):
        raise EnforcementError("mutual_origin count/order mismatch")
    return {
        "mode": MUTUAL_ORIGIN_MODE,
        "newly_denied_device_count": count,
        "newly_denied_device_ids": list(ids),
    }


def mutual_origin_from_status(status):
    """Read only a validated preflight object from an untrusted status dict."""
    try:
        return validate_mutual_origin(status.get("mutual_origin"))
    except (AttributeError, EnforcementError):
        return validate_mutual_origin({
            "mode": MUTUAL_ORIGIN_MODE,
            "newly_denied_device_count": 0,
            "newly_denied_device_ids": [],
        })


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
                 conflicts=None, last_effect=None, last_error=None,
                 mutual_origin=None, operation_ack_epoch=None, **reject):
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
    _count(desired_ip_count)
    _count(last_operation_exported_revision)
    if applied_revision is not None:
        _count(applied_revision)
    for value in (aria_session_id, desired_hash):
        if value is not None and (not isinstance(value, str) or not value):
            raise EnforcementError("bad session/hash")
    try:
        status_codes.validate_error_code(last_error, status_codes.PEER_ERROR_CODES)
    except ValueError as exc:
        raise EnforcementError("bad last_error") from exc
    now = _timestamp(now)
    conflicts = _conflicts(conflicts)
    if last_effect is not None:
        if not isinstance(last_effect, dict) or set(last_effect) != {"disconnected_peers", "removed_peers"}:
            raise EnforcementError("bad last_effect")
        last_effect = {key: _count(value) for key, value in last_effect.items()}
    if state == "enforced" and (not aria_session_id or not desired_hash or last_error is not None):
        raise EnforcementError(
            "enforced requires a current session and desired hash")
    if mutual_origin is None:
        mutual_origin = {
            "mode": MUTUAL_ORIGIN_MODE,
            "newly_denied_device_count": 0,
            "newly_denied_device_ids": [],
        }
    mutual_origin = validate_mutual_origin(mutual_origin)
    status_codes.validate_ack_epoch(operation_ack_epoch)
    result = {
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
        "mutual_origin": mutual_origin,
    }
    if operation_ack_epoch is not None:
        result["operation_ack_epoch"] = operation_ack_epoch
    return result


def write_status(path, status):
    """Atomically persist ``status`` under the advisory lock (tracker only)."""
    with _lock(path):
        _atomic_write_json(path, status)


def parse_status(value):
    """Validate the complete unit before any field, including its ack, is used."""
    try:
        if not isinstance(value, dict) or type(value["schema"]) is not int or value["schema"] != SCHEMA:
            return None
        updated = _timestamp(value["updated_at"])
        if not isinstance(value["conflicts"], list):
            return None
        if "mutual_origin" in value:
            validate_mutual_origin(value["mutual_origin"])
        checked = build_status(**{key: value[key] for key in (
            "state", "aria_session_id", "desired_hash", "applied_revision",
            "desired_ip_count", "last_operation_exported_revision", "conflicts",
            "last_effect", "last_error")}, now=value["last_reconciled_at"],
            mutual_origin=value.get("mutual_origin"),
            operation_ack_epoch=value.get("operation_ack_epoch"))
        checked["updated_at"] = updated
        return checked
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def read_status(path):
    """Return a semantically validated canonical record, else ``None``."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return parse_status(data)
