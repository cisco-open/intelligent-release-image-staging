# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable typed principal->endpoint map (spec 6 / 10.5) plus the tracker-owned
bounded latest-per-principal pending retry queue (spec 7 failure posture).

Ownership (spec 0): the tracker writes ``peer-endpoints.json`` on a successful
authenticated announce from an **attributable** principal (device / service); a
``legacy`` principal writes no endpoint. Every write is a full read-modify-write
serialized by a per-file advisory ``fcntl.flock`` (same discipline as
``secrets_store``); there is no process-local persistence lock.

Retention (spec 7 retirement): endpoints are pruned only when older than
``ENDPOINT_TTL``; revoke/delete never removes rows. Re-onboard clears a device's
old rows via ``clear_principal`` before new credentials become usable.

Principals are accepted structurally (any object exposing ``.type``/``.id``) so
this module stays decoupled from the identity lane's ``auth.Principal``;
integration later passes the real ``auth.Principal`` unchanged.
"""
import contextlib
import fcntl
import json
import os
import tempfile

ENDPOINT_CAP = 4              # endpoints per principal, newest-first
ENDPOINT_TTL = 900           # seconds; default, overridable via env
MAX_PRINCIPALS = 10000       # durable-map and pending-queue LRU cap

_SCHEMA = 1


def endpoint_ttl():
    """Effective endpoint TTL, honoring ``IRIS_ENDPOINT_TTL`` (spec 6). A
    missing or non-integer value falls back to :data:`ENDPOINT_TTL`."""
    raw = os.environ.get("IRIS_ENDPOINT_TTL")
    if raw is None:
        return ENDPOINT_TTL
    try:
        return int(raw)
    except (TypeError, ValueError):
        return ENDPOINT_TTL


def principal_key(principal):
    """``"<type>:<id>"`` map key. ``device:seeder`` is deliberately distinct
    from ``service:seeder`` (spec 0a typed namespace)."""
    return "%s:%s" % (principal.type, principal.id)


def _attributable(principal):
    return principal.type in ("device", "service")


# ---------------------------------------------------------------------------
# Atomic, flocked read-modify-write
# ---------------------------------------------------------------------------

def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".peer-endpoints-", suffix=".tmp")
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


def _load(path):
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("not a dict")
        principals = data.get("principals")
        if not isinstance(principals, dict):
            principals = {}
        return {"schema": _SCHEMA,
                "updated_at": data.get("updated_at", 0.0),
                "principals": principals}
    except (OSError, ValueError):
        return {"schema": _SCHEMA, "updated_at": 0.0, "principals": {}}


def _endpoint(ipv4, port, now):
    return {"ipv4": ipv4, "port": int(port),
            "observed_at": float(now), "source": "announce"}


# ---------------------------------------------------------------------------
# Durable map mutations
# ---------------------------------------------------------------------------

def record_endpoint(path, principal, ipv4, port, now):
    """Persist ``principal``'s latest announce endpoint. Returns ``True`` if a
    durable write occurred, ``False`` for a non-attributable (legacy) principal
    which is never persisted (spec 6). Newest-first, capped at
    :data:`ENDPOINT_CAP`; a repeated IP refreshes ``observed_at`` in place. The
    whole map is bounded to :data:`MAX_PRINCIPALS`; overflow evicts the
    least-recently-updated principal."""
    if not _attributable(principal):
        return False
    key = principal_key(principal)
    with _lock(path):
        doc = _load(path)
        principals = doc["principals"]
        entry = principals.get(key)
        if entry is None:
            entry = {"principal_type": principal.type,
                     "principal_id": principal.id,
                     "updated_at": float(now), "endpoints": []}
        eps = [e for e in entry["endpoints"] if e.get("ipv4") != ipv4]
        eps.insert(0, _endpoint(ipv4, port, now))
        entry["endpoints"] = eps[:ENDPOINT_CAP]
        entry["updated_at"] = float(now)
        principals[key] = entry
        _enforce_principal_cap(principals, keep=key)
        doc["updated_at"] = float(now)
        _atomic_write_json(path, doc)
    return True


def _enforce_principal_cap(principals, keep):
    while len(principals) > MAX_PRINCIPALS:
        victim = min(
            (k for k in principals if k != keep),
            key=lambda k: principals[k].get("updated_at", 0.0),
            default=None)
        if victim is None:
            break
        del principals[victim]


def clear_principal(path, principal):
    """Remove **all** rows for ``principal`` (re-onboard clear, spec 7 item 4).
    This is the only identity-targeted removal; there is no remove-on-revoke."""
    key = principal_key(principal)
    with _lock(path):
        doc = _load(path)
        if key in doc["principals"]:
            del doc["principals"][key]
            _atomic_write_json(path, doc)


def prune(path, now):
    """Drop endpoints older than the effective TTL; remove principals left with
    no fresh endpoints (spec 6 prune)."""
    ttl = endpoint_ttl()
    with _lock(path):
        doc = _load(path)
        principals = doc["principals"]
        changed = False
        for key in list(principals):
            entry = principals[key]
            fresh = [e for e in entry["endpoints"]
                     if now - e.get("observed_at", 0.0) <= ttl]
            if len(fresh) != len(entry["endpoints"]):
                changed = True
            if fresh:
                entry["endpoints"] = fresh
            else:
                del principals[key]
                changed = True
        if changed:
            _atomic_write_json(path, doc)


def fresh_endpoints(path, now):
    """Read-only view of ``{key: {principal_type, principal_id, endpoints}}``
    holding only endpoints within the effective TTL. Missing file -> ``{}``.
    Does not mutate the durable file (a pure snapshot for derivation)."""
    ttl = endpoint_ttl()
    doc = _load(path)
    out = {}
    for key, entry in doc["principals"].items():
        fresh = [e for e in entry["endpoints"]
                 if now - e.get("observed_at", 0.0) <= ttl]
        if fresh:
            out[key] = {"principal_type": entry["principal_type"],
                        "principal_id": entry["principal_id"],
                        "endpoints": fresh}
    return out


# ---------------------------------------------------------------------------
# Tracker-owned bounded latest-per-principal pending retry queue (spec 7)
# ---------------------------------------------------------------------------

class PendingEndpointQueue:
    """In-memory, bounded, latest-per-principal queue of endpoint tuples whose
    durable write has not yet succeeded (spec 7 failure posture).

    It stores no secret. It is owned and wired by the tracker (Task 14); loss on
    tracker restart is accepted (the next announce rebuilds it). Overflow beyond
    ``cap`` (default :data:`MAX_PRINCIPALS`) deterministically evicts the
    oldest-enqueued principal. The snapshot shape matches
    :func:`fresh_endpoints` so the reconciler can consume pending tuples
    immediately for derivation.
    """

    def __init__(self, cap=None):
        self.cap = MAX_PRINCIPALS if cap is None else cap
        # insertion-ordered dict; re-enqueue replaces in place (keeps position)
        self._items = {}

    def __len__(self):
        return len(self._items)

    def enqueue(self, principal, ipv4, port, now):
        key = principal_key(principal)
        self._items[key] = {"principal_type": principal.type,
                            "principal_id": principal.id,
                            "endpoint": _endpoint(ipv4, port, now)}
        while len(self._items) > self.cap:
            oldest = next(iter(self._items))
            del self._items[oldest]

    def resolve(self, principal):
        self._items.pop(principal_key(principal), None)

    def snapshot(self):
        return {key: {"principal_type": v["principal_type"],
                      "principal_id": v["principal_id"],
                      "endpoints": [dict(v["endpoint"])]}
                for key, v in self._items.items()}

    def items(self):
        """(key, principal_type, principal_id, endpoint) tuples for retry."""
        return [(k, v["principal_type"], v["principal_id"], v["endpoint"])
                for k, v in list(self._items.items())]

    def _drop_key(self, key):
        self._items.pop(key, None)


class _StructPrincipal:
    __slots__ = ("type", "id")

    def __init__(self, type_, id_):
        self.type = type_
        self.id = id_


def retry_pending(path, queue, now=None, writer=None):
    """Attempt the durable write for every pending principal without requiring a
    new announce (spec 7 ``<=2s`` retry). Removes from the queue only those whose
    durable write succeeds; a failing write leaves the tuple queued. Returns the
    list of resolved principal keys.

    The write always uses the endpoint's ORIGINAL ``observed_at`` — never the
    current pass time — so a stuck retry cannot silently extend the endpoint's
    TTL past its first observation. ``now`` is therefore ignored for the persisted
    timestamp and is accepted only for signature compatibility.

    ``writer`` is an injectable ``record_endpoint``-shaped callable (defaults to
    :func:`record_endpoint`) so the tracker can honor failure-injection while
    reusing this exact retry/timestamp logic.
    """
    write = writer or record_endpoint
    resolved = []
    for key, ptype, pid, endpoint in queue.items():
        principal = _StructPrincipal(ptype, pid)
        try:
            write(path, principal, endpoint["ipv4"],
                  endpoint["port"], endpoint["observed_at"])
        except OSError:
            continue
        queue._drop_key(key)
        resolved.append(key)
    return resolved
