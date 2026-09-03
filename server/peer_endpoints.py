# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable typed principal->endpoint map (spec 6 / 10.5) plus the tracker-owned
bounded latest-per-principal pending retry queue (spec 7 failure posture).

Ownership (spec 0): the tracker writes the durable endpoint map on a successful
authenticated announce from an **attributable** principal (device / service); a
``legacy`` principal writes no endpoint.

The map is KEYED INCREMENTAL state (:mod:`keyed_state`): it lives in
``peer-endpoints.d/`` as bucketed shards, one row per principal, and an
announce locks, parses and rewrites only the shard its principal lands in.
It used to be one ``peer-endpoints.json`` document that every announce
re-parsed, re-validated, re-serialised and replaced under a single global
lock, so the tracker's critical path cost O(fleet) per announce and every
announce in the fleet serialised behind one writer. A legacy
``peer-endpoints.json`` is migrated into the shards on first use (see
:mod:`keyed_state`); the durability contract is unchanged — atomic
temp+``os.replace`` per shard, and a shard that exists but cannot be read
fails closed as :class:`EndpointStoreError` rather than being overwritten.

Retention (spec 7 retirement): endpoints age out of the fresh view, and are
pruned from disk by the tracker's maintenance pass, once older than
``ENDPOINT_TTL`` -- EXCEPT rows the caller's ``keep`` predicate claims (the
reconciler passes one that names every revoked principal and every principal
the current policy denies at that address, so a quarantined or revoked device
that simply stops announcing keeps its seeder block until it is re-onboarded
or un-quarantined, not merely until the TTL lapses). Revoke/delete never
removes rows. Re-onboard clears a device's old rows via ``clear_principal``
before new credentials become usable.

Principals are accepted structurally (any object exposing ``.type``/``.id``) so
this module stays decoupled from the identity lane's ``auth.Principal``;
integration later passes the real ``auth.Principal`` unchanged.
"""
import ipaddress
import math
import os
import threading

import keyed_state

ENDPOINT_CAP = 4              # endpoints per principal, newest-first
ENDPOINT_TTL = 900           # seconds; default, overridable via env

# Supported fleet size. This is the DEVICE count IRIS is sized for, and it is
# deliberately not the store's capacity: at a full fleet the map also holds the
# ``service:seeder`` principal (and any future service principal), so a
# capacity equal to the device count would start evicting live device rows --
# and churn the LRU -- at exactly the fleet size the product claims to support.
SUPPORTED_DEVICES = 10000
# Headroom for non-device principals above the supported device count. Only a
# handful of service principals exist today (``service:seeder``); the slack is
# for principals added later, so raising the fleet size never silently
# re-introduces the boundary bug.
SERVICE_PRINCIPAL_HEADROOM = 256
# Durable-map and pending-queue capacity.
MAX_PRINCIPALS = SUPPORTED_DEVICES + SERVICE_PRINCIPAL_HEADROOM

_SCHEMA = 1


class EndpointStoreError(ValueError):
    """Existing endpoint state is corrupt and must not be overwritten."""


def endpoint_ttl():
    """Effective endpoint TTL, honoring ``IRIS_ENDPOINT_TTL`` (spec 6). A
    missing, non-integer or non-positive value falls back to
    :data:`ENDPOINT_TTL`: with a TTL of 0 or less no row is ever fresh, so a
    valid policy would apply an EMPTY blocklist under an ``enforced`` status
    and the maintenance deadline would fire on every 2 s poll."""
    raw = os.environ.get("IRIS_ENDPOINT_TTL")
    if raw is None:
        return ENDPOINT_TTL
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return ENDPOINT_TTL
    return value if value >= 1 else ENDPOINT_TTL


def principal_key(principal):
    """``"<type>:<id>"`` map key. ``device:seeder`` is deliberately distinct
    from ``service:seeder`` (spec 0a typed namespace)."""
    return "%s:%s" % (principal.type, principal.id)


def _attributable(principal):
    return principal.type in ("device", "service")


# ---------------------------------------------------------------------------
# Keyed incremental durable state
# ---------------------------------------------------------------------------

def _validate_entry(key, entry):
    """Structural validation of ONE principal row, applied to every row read
    out of a shard. A row the reconciler would otherwise trip over (KeyError
    on a missing ipv4, TypeError on a string observed_at, AddressValueError on
    a non-IPv4 rule) is store corruption and takes the same fail-closed path
    as bad JSON."""
    if not isinstance(key, str) or not isinstance(entry, dict):
        raise ValueError("bad principal")
    if not isinstance(entry.get("endpoints"), list):
        raise ValueError("bad endpoints")
    if not isinstance(entry.get("principal_type"), str) \
            or not isinstance(entry.get("principal_id"), str):
        raise ValueError("bad principal identity")
    for ep in entry["endpoints"]:
        if not isinstance(ep, dict):
            raise ValueError("bad endpoint")
        try:
            ipaddress.IPv4Address(ep.get("ipv4"))
        except (ipaddress.AddressValueError, ValueError, TypeError):
            raise ValueError("bad endpoint ipv4")
        port = ep.get("port")
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            raise ValueError("bad endpoint port")
        observed = ep.get("observed_at")
        if isinstance(observed, bool) \
                or not isinstance(observed, (int, float)) \
                or not math.isfinite(observed):
            raise ValueError("bad endpoint observed_at")


def _legacy_principals(doc):
    """The ``principals`` map out of a legacy whole-document
    ``peer-endpoints.json``, for the one-time migration into shards. A
    document that is not the expected schema is corruption, not an empty
    store: it fails closed and is left on disk untouched."""
    if not isinstance(doc, dict) or doc.get("schema") != _SCHEMA:
        raise EndpointStoreError("endpoint store is corrupt")
    principals = doc.get("principals")
    if not isinstance(principals, dict):
        raise EndpointStoreError("endpoint store is corrupt")
    return principals


_STATES = {}
_STATES_LOCK = threading.Lock()


def _state(path):
    """The :class:`keyed_state.KeyedState` for *path*, memoised per path so a
    process pays the legacy-migration check once rather than per announce."""
    with _STATES_LOCK:
        state = _STATES.get(path)
        if state is None:
            state = keyed_state.KeyedState(
                path, error=EndpointStoreError, validate=_validate_entry,
                legacy_extract=_legacy_principals, indent=None)
            _STATES[path] = state
        return state


def change_key(path):
    """Cheap change-detection key for the durable map (see
    :func:`keyed_state.change_key`), for the reconciler's dead-poll gate."""
    return keyed_state.change_key(path)


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

    def mutate(entry):
        if entry is None:
            entry = {"principal_type": principal.type,
                     "principal_id": principal.id,
                     "updated_at": float(now), "endpoints": []}
        eps = [e for e in entry["endpoints"] if e.get("ipv4") != ipv4]
        eps.insert(0, _endpoint(ipv4, port, now))
        entry["endpoints"] = eps[:ENDPOINT_CAP]
        entry["updated_at"] = float(now)
        return entry

    _state(path).update(key, mutate)
    return True


def _enforce_principal_cap(state, rows):
    """Trim the map back to :data:`MAX_PRINCIPALS`, evicting the
    least-recently-updated principals.

    This runs in :func:`prune` -- the tracker's periodic maintenance pass --
    and no longer on the announce path: an announce touches only its own
    principal's shard and so cannot see (or afford to count) the whole map.
    The bound is still real, because the pass runs at least every
    ``min(endpoint_ttl(), MAINTENANCE_INTERVAL_CAP)`` seconds and the number
    of principals that can ever appear is bounded by the number of minted
    credentials -- an announce cannot invent an identity. *rows* is the
    ``{key: updated_at}`` the sweep already collected, so enforcing the cap
    costs no extra scan."""
    if len(rows) <= MAX_PRINCIPALS:
        return
    victims = sorted(rows, key=lambda k: rows[k])[:len(rows) - MAX_PRINCIPALS]
    for key in victims:
        state.delete(key)


def clear_principal(path, principal):
    """Remove **all** rows for ``principal`` (re-onboard clear, spec 7 item 4).
    This is the only identity-targeted removal; there is no remove-on-revoke."""
    _state(path).delete(principal_key(principal))


def _is_fresh(entry, ep, now, ttl, keep):
    """TTL filter shared by prune/fresh_endpoints: within the TTL, or claimed
    by the caller's ``keep(principal_type, principal_id, ipv4)`` predicate
    (a revoked/denied principal's row is retained regardless of age)."""
    if now - ep.get("observed_at", 0.0) <= ttl:
        return True
    if keep is None:
        return False
    try:
        return bool(keep(entry["principal_type"], entry["principal_id"],
                         ep["ipv4"]))
    except Exception:
        return True     # an undecidable row is retained, never silently aged


def prune(path, now, keep=None):
    """Drop endpoints older than the effective TTL; remove principals left with
    no fresh endpoints (spec 6 prune), then enforce :data:`MAX_PRINCIPALS`.
    Called by the tracker's maintenance pass. Rows claimed by ``keep`` (see
    :func:`fresh_endpoints`) survive the TTL. The sweep takes one shard lock
    at a time, so pruning never blocks the whole fleet's announces at once."""
    ttl = endpoint_ttl()
    state = _state(path)
    updated_at = {}

    def visit(key, entry):
        fresh = [e for e in entry["endpoints"]
                 if _is_fresh(entry, e, now, ttl, keep)]
        if not fresh:
            return keyed_state.DELETE
        updated_at[key] = entry.get("updated_at", 0.0)
        if len(fresh) == len(entry["endpoints"]):
            return None         # unchanged: leave the shard alone
        entry["endpoints"] = fresh
        return entry

    state.sweep(visit)
    _enforce_principal_cap(state, updated_at)


def fresh_endpoints(path, now, keep=None):
    """Read-only view of ``{key: {principal_type, principal_id, endpoints}}``
    holding only endpoints within the effective TTL, plus every row the
    optional ``keep(principal_type, principal_id, ipv4)`` predicate claims
    regardless of age (the reconciler's revoked/denied retention). Missing
    file -> ``{}``. Does not mutate the durable file (a pure snapshot for
    derivation)."""
    ttl = endpoint_ttl()
    out = {}
    for key, entry in _state(path).snapshot().items():
        fresh = [e for e in entry["endpoints"]
                 if _is_fresh(entry, e, now, ttl, keep)]
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
        self._lock = threading.Lock()

    def __len__(self):
        with self._lock:
            return len(self._items)

    def enqueue(self, principal, ipv4, port, now):
        key = principal_key(principal)
        with self._lock:
            self._items[key] = {"principal_type": principal.type,
                                "principal_id": principal.id,
                                "endpoint": _endpoint(ipv4, port, now)}
            while len(self._items) > self.cap:
                oldest = next(iter(self._items))
                del self._items[oldest]

    def resolve(self, principal):
        with self._lock:
            self._items.pop(principal_key(principal), None)

    def snapshot(self):
        with self._lock:
            return {key: {"principal_type": v["principal_type"],
                          "principal_id": v["principal_id"],
                          "endpoints": [dict(v["endpoint"])]}
                    for key, v in self._items.items()}

    def items(self):
        """(key, principal_type, principal_id, endpoint) tuples for retry."""
        with self._lock:
            return [(k, v["principal_type"], v["principal_id"], v["endpoint"])
                    for k, v in self._items.items()]

    def _drop_key(self, key, endpoint=None):
        with self._lock:
            current = self._items.get(key)
            if current is not None and (endpoint is None or
                                        current["endpoint"] is endpoint):
                self._items.pop(key, None)
                return True
            return False


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
        except (OSError, EndpointStoreError):
            continue
        if queue._drop_key(key, endpoint):
            resolved.append(key)
    return resolved
