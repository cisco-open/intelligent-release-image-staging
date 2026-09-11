# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Typed peer-policy evaluator and durable prior-committed LKG transaction
(spec 0a / 7 / 10.4).

The evaluator is pure and deterministic: it maps a typed principal
(``.type``/``.id``) + effective IPv4 through its assigned ACL's ordered rules
(first match wins, implicit permit) and returns ``(decision, matched_seq)``.
``mutual_permit`` requires both sides to permit.

Persistence follows the ``secrets_store`` discipline (atomic temp-file +
``os.replace`` under a per-file advisory ``fcntl.flock``). The commit transaction
runs under a single umbrella flock and writes the **prior committed
authoritative** policy to ``peer-policy.lkg.json`` and its five-document ring
first, then atomically replaces ``peer-policy.json`` with the candidate — the
atomic replace is the commit; an uncommitted candidate is never loadable.

Read precedence (spec 7): valid authoritative always wins; corrupt authoritative
with a valid LKG uses the prior LKG and marks ``degraded``; both corrupt while
the files exist yields ``fail_closed`` (no candidates); neither file present
materializes the validated base (open discovery), with the roles-ever watermark
distinguishing a fresh install from missing restored state.

Principals are accepted structurally so this module stays decoupled from the
identity lane; integration passes the real ``auth.Principal`` unchanged.
"""
import collections
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import tempfile
import types
from collections.abc import Mapping

import peer_endpoints
import reconciler_status

SCHEMA = 1
MAX_ACLS = 64
MAX_RULES_PER_ACL = 256
OUTBOX_CAP = 256
MAX_ROLES = 256
MAX_ROLE_PEERS = 64
MAX_QUARANTINED_DEVICES = peer_endpoints.SUPPORTED_DEVICES
LKG_RING_SIZE = 5
BLAST_RADIUS_CONFIRM_THRESHOLD = 0
RESERVED_QUARANTINE = "quarantine"
RESERVED_ROLE_NAMES = frozenset(
    ("default", "quarantine", "origin", "seeder", "legacy"))

_ACL_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ROLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
# IPv4Network accepts bare addresses, prefix lengths (including zero padding),
# and contiguous dotted netmasks/hostmasks. Preserve the supplied valid text.
_ROLE_NET_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
ROLE_NET_MAX_PREFIX_DIGITS = 32
_ROLE_NET_MASKS = sorted({str(mask) for prefix in range(33)
    for mask in (ipaddress.IPv4Network("0.0.0.0/%d" % prefix).netmask,
                 ipaddress.IPv4Network("0.0.0.0/%d" % prefix).hostmask)})
ROLE_NET_PATTERN = (r"^(?:" + _ROLE_NET_OCTET + r"\.){3}" + _ROLE_NET_OCTET
    + r"(?:/(?:(?=[0-9]{1,%d}$(?![\s\S]))0*(?:[0-9]|[12][0-9]|3[0-2])|" % ROLE_NET_MAX_PREFIX_DIGITS
    + "|".join(mask.replace(".", r"\.") for mask in _ROLE_NET_MASKS) + r"))?$(?![\s\S])")
_ACTIONS = ("permit", "deny")
_MATCH_TYPES = ("device", "service", "host", "cidr", "any", "role")

PER_TORRENT_RATE_KEYS = (
    "seed_up_bps", "seed_down_bps", "leech_up_bps", "leech_down_bps")
_GLOBAL_ROLE_DEVICE = frozenset(("global", "role", "device"))
_GLOBAL_ROLE = frozenset(("global", "role"))
_GLOBAL_ONLY = frozenset(("global",))

QOS_DEFAULTS = {
    "max_peers": 10,
    "per_peer_bps": 12_500_000,
    "fanout": 1,
    "seed_up_bps": 0,
    "seed_down_bps": 0,
    "leech_up_bps": 0,
    "leech_down_bps": 0,
    "overall_up_bps": 0,
    "overall_down_bps": 0,
    "max_concurrent": 100,
    "request_peer_speed_limit_bps": 51_200,
    "announce_min_interval_s": 30,
    "numwant": 50,
    "handout_budget": 0,
    "catalog_tick_s": 60,
    "telemetry_every_ticks": 1,
    "telemetry_pause": False,
    "on_stale": "defaults",
    "origin_up_bps": 0,
    "origin_per_torrent_up_bps": 0,
    "origin_max_peers": 55,
}

QOS_UNITS = {
    "max_peers": "connections_per_torrent",
    "per_peer_bps": "bytes_per_second",
    "fanout": "multiplier",
    "seed_up_bps": "bytes_per_second",
    "seed_down_bps": "bytes_per_second",
    "leech_up_bps": "bytes_per_second",
    "leech_down_bps": "bytes_per_second",
    "overall_up_bps": "bytes_per_second",
    "overall_down_bps": "bytes_per_second",
    "max_concurrent": "torrents",
    "request_peer_speed_limit_bps": "bytes_per_second",
    "announce_min_interval_s": "seconds",
    "numwant": "peers_per_announce",
    "handout_budget": "handouts_per_window",
    "catalog_tick_s": "seconds",
    "telemetry_every_ticks": "ticks",
    "telemetry_pause": "boolean",
    "on_stale": "enum",
    "origin_up_bps": "bytes_per_second",
    "origin_per_torrent_up_bps": "bytes_per_second",
    "origin_max_peers": "connections_per_torrent",
}

_RATE_KEYS = frozenset(
    key for key, unit in QOS_UNITS.items() if unit == "bytes_per_second")
_MIN_RATE_BPS = 8192

_QOS_RANGES = {
    "max_peers": (1, 1000),
    "per_peer_bps": (0, 10_000_000_000),
    "fanout": (1, 1000),
    "seed_up_bps": (0, 10_000_000_000),
    "seed_down_bps": (0, 10_000_000_000),
    "leech_up_bps": (0, 10_000_000_000),
    "leech_down_bps": (0, 10_000_000_000),
    "overall_up_bps": (0, 10_000_000_000),
    "overall_down_bps": (0, 10_000_000_000),
    "max_concurrent": (1, 1000),
    "request_peer_speed_limit_bps": (0, 1_000_000_000),
    "announce_min_interval_s": (10, 300),
    "numwant": (4, 200),
    "handout_budget": (0, 1000),
    "catalog_tick_s": (60, 900),
    "telemetry_every_ticks": (1, 60),
    "origin_up_bps": (0, 10_000_000_000),
    "origin_per_torrent_up_bps": (0, 10_000_000_000),
    "origin_max_peers": (1, 1000),
}

_TRACKER_QOS_KEYS = ("announce_min_interval_s", "numwant")
_TRACKER_STATES = frozenset(("seeder", "leecher"))
_QOS_STATE_UNSET = object()

_QOS_SCOPES = {
    key: _GLOBAL_ROLE_DEVICE for key in (
        "max_peers", "per_peer_bps", "fanout", *PER_TORRENT_RATE_KEYS,
        "overall_up_bps", "overall_down_bps", "max_concurrent",
        "catalog_tick_s", "telemetry_every_ticks", "telemetry_pause")}
_QOS_SCOPES.update({
    key: _GLOBAL_ROLE for key in (
        "request_peer_speed_limit_bps", "announce_min_interval_s",
        "numwant", "handout_budget")})
_QOS_SCOPES.update({
    key: _GLOBAL_ONLY for key in (
        "on_stale", "origin_up_bps", "origin_per_torrent_up_bps",
        "origin_max_peers")})

_QUARANTINE_RULES = [{"seq": 10, "action": "deny", "match": {"type": "any"}}]


class PolicyError(ValueError):
    """A policy schema or lifecycle refusal with a stable machine code."""

    def __init__(self, message, code="invalid_policy", **details):
        self.code = code
        self.details = details
        super().__init__(message)


class PolicyDegradedError(PolicyError):
    """Raised when mutation is unsafe because authoritative policy is invalid."""


class OperationBacklogFull(Exception):
    """Raised when 256 unacknowledged outbox operations block a mutation."""


class RevisionConflict(Exception):
    """Raised when an optimistic mutation does not match the live revision."""

    def __init__(self, revision):
        self.revision = revision
        super().__init__("policy revision conflict")


class RoleInUse(PolicyError):
    """A role still has members or references and cannot be deleted."""

    def __init__(self, role, member_count, referring_roles,
                 referring_schedules=()):
        self.role = role
        self.member_count = member_count
        self.referring_roles = tuple(sorted(referring_roles))
        self.referring_schedules = tuple(sorted(referring_schedules))
        super().__init__(
            "role is in use", code="role_in_use", role=role,
            member_count=member_count,
            referring_roles=list(self.referring_roles),
            referring_schedules=list(self.referring_schedules))


PolicyResult = collections.namedtuple(
    "PolicyResult", ["document", "degraded", "fail_closed", "roles"],
    defaults=(None,))


class FrozenMapping(Mapping):
    """Small immutable O(1)-lookup mapping safe to share across readers."""

    __slots__ = ("_data",)

    def __init__(self, values):
        object.__setattr__(self, "_data", types.MappingProxyType(dict(values)))

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __setattr__(self, name, value):
        raise TypeError("FrozenMapping is immutable")

    def __deepcopy__(self, memo):
        return self

    def __repr__(self):
        return "FrozenMapping(%r)" % dict(self._data)


CompiledRoles = collections.namedtuple(
    "CompiledRoles",
    ["acl_by_role", "role_of", "restricted", "sorted_rules",
     "members_by_role"], defaults=(None,))

BlastRadius = collections.namedtuple(
    "BlastRadius",
    ["member_delta", "origin_access_lost", "empty_permitted_sets",
     "role_pairs_stopped", "qos_changed", "requires_confirmation",
     "confirm_token"])


# ---------------------------------------------------------------------------
# Base document + validation
# ---------------------------------------------------------------------------

def base_document():
    """The validated base policy: reserved immutable quarantine + empty
    assignments + empty outbox (spec 7 fresh init)."""
    return {
        "schema": SCHEMA,
        "revision": 1,
        "acls": {RESERVED_QUARANTINE: {
            "reserved": True,
            "description": "reserved: fully isolate an assigned device",
            "rules": [dict(r) for r in _QUARANTINE_RULES]}},
        "assignments": {},
        "seeder_assignment": None,
        "operation_outbox": [],
    }


def validate_role_name(name, invalid_message="bad role name"):
    """Return a valid role name or raise a structured policy error."""
    if not isinstance(name, str) or not _ROLE_NAME_RE.fullmatch(name):
        raise PolicyError(invalid_message)
    if name in RESERVED_ROLE_NAMES:
        raise PolicyError("reserved role name", code="role_reserved_name",
                          role=name)
    return name


def _validate_rule(rule):
    if not isinstance(rule, dict):
        raise PolicyError("rule must be an object")
    if not isinstance(rule.get("seq"), int) or isinstance(rule["seq"], bool):
        raise PolicyError("rule seq must be int")
    if rule.get("action") not in _ACTIONS:
        raise PolicyError("bad action")
    match = rule.get("match")
    if not isinstance(match, dict) or match.get("type") not in _MATCH_TYPES:
        raise PolicyError("bad match type")
    mtype = match["type"]
    if mtype == "any":
        return
    value = match.get("value")
    if not isinstance(value, str) or not value:
        raise PolicyError("match value required")
    if mtype == "host":
        ipaddress.IPv4Address(value)
    elif mtype == "cidr":
        ipaddress.IPv4Network(value, strict=False)
    elif mtype == "role":
        validate_role_name(value)


def _validate_qos(qos, scope):
    if not isinstance(qos, dict):
        raise PolicyError("bad qos")
    unknown = set(qos) - set(_QOS_SCOPES)
    if unknown:
        raise PolicyError("unknown qos key: %s" % sorted(unknown)[0])
    for key, value in qos.items():
        if scope not in _QOS_SCOPES[key]:
            raise PolicyError("qos key not allowed at %s scope: %s" %
                              (scope, key))
        if key == "telemetry_pause":
            if not isinstance(value, bool):
                raise PolicyError("telemetry_pause must be bool")
            continue
        if key == "on_stale":
            if value not in ("keep", "defaults"):
                raise PolicyError("bad on_stale")
            continue
        if not isinstance(value, int) or isinstance(value, bool):
            raise PolicyError("qos value must be int: %s" % key)
        minimum, maximum = _QOS_RANGES[key]
        if not minimum <= value <= maximum:
            raise PolicyError("qos value out of range: %s" % key)
        if key in _RATE_KEYS and value != 0 and value < _MIN_RATE_BPS:
            raise PolicyError("qos rate must be zero or at least %d: %s" %
                              (_MIN_RATE_BPS, key))
        if key == "catalog_tick_s" and value % 60:
            raise PolicyError("catalog_tick_s must be a launcher tick multiple")


def _validate_qos_state(qos_state):
    if not isinstance(qos_state, dict):
        raise PolicyError("bad qos state")
    if set(qos_state) - _TRACKER_STATES:
        raise PolicyError("unknown tracker state")
    for state, values in qos_state.items():
        if not isinstance(values, dict):
            raise PolicyError("bad tracker state qos: %s" % state)
        if set(values) - set(_TRACKER_QOS_KEYS):
            raise PolicyError("unknown tracker state qos key")
        for key, value in values.items():
            if not isinstance(value, int) or isinstance(value, bool):
                raise PolicyError("tracker state qos value must be int: %s" %
                                  key)
            minimum, maximum = _QOS_RANGES[key]
            if not minimum <= value <= maximum:
                raise PolicyError(
                    "tracker state qos value out of range: %s" % key)


def _validate_quarantined_devices(value, enforce_limit=True):
    """Validate the optional independent quarantine membership map."""
    if not isinstance(value, dict):
        raise PolicyError("bad quarantined_devices")
    for device_id, present in value.items():
        if not isinstance(device_id, str):
            raise PolicyError("bad quarantined device id")
        if present is not True:
            raise PolicyError("bad quarantined device membership")
    if enforce_limit and len(value) > MAX_QUARANTINED_DEVICES:
        raise PolicyError("too many quarantined devices")


def is_quarantined(doc, device_id):
    """Return whether a device has canonical or legacy quarantine intent."""
    membership = doc.get("quarantined_devices", {})
    canonical = isinstance(membership, dict) \
        and membership.get(device_id) is True
    assignments = doc.get("assignments", {})
    legacy = isinstance(assignments, dict) \
        and assignments.get(device_id) == RESERVED_QUARANTINE
    return canonical or legacy


def ordinary_assignment(doc, device_id):
    """Return a device's ordinary assignment, excluding legacy quarantine."""
    assignments = doc.get("assignments", {})
    if not isinstance(assignments, dict):
        return None
    assigned = assignments.get(device_id)
    return None if assigned == RESERVED_QUARANTINE else assigned


def quarantine_device_ids(doc):
    """Return a detached union of canonical and legacy quarantine IDs."""
    membership = doc.get("quarantined_devices", {})
    device_ids = {
        device_id for device_id, present in membership.items()
        if present is True} if isinstance(membership, dict) else set()
    assignments = doc.get("assignments", {})
    if isinstance(assignments, dict):
        device_ids.update(
            device_id for device_id, assigned in assignments.items()
            if assigned == RESERVED_QUARANTINE)
    return device_ids


def _normalize_quarantine(candidate):
    """Move legacy quarantine rows within one detached mutation candidate."""
    assignments = candidate.get("assignments")
    if not isinstance(assignments, dict):
        raise PolicyError("bad assignments")
    if "quarantined_devices" in candidate:
        membership = candidate["quarantined_devices"]
        # Validate malformed callback-owned state before a legacy row with the
        # same ID could overwrite it. Final validation enforces cardinality.
        _validate_quarantined_devices(membership, enforce_limit=False)
    else:
        membership = {}
    legacy_ids = []
    for device_id, assigned in assignments.items():
        if assigned == RESERVED_QUARANTINE:
            if not isinstance(device_id, str):
                raise PolicyError("bad quarantined device id")
            legacy_ids.append(device_id)
    if not legacy_ids:
        return candidate
    normalized_assignments = dict(assignments)
    normalized_membership = dict(membership)
    for device_id in legacy_ids:
        normalized_assignments.pop(device_id)
        normalized_membership[device_id] = True
    candidate["assignments"] = normalized_assignments
    candidate["quarantined_devices"] = normalized_membership
    return candidate


def _set_quarantine_membership(candidate, device_id, quarantined):
    """Update membership on an already-normalized detached candidate."""
    membership = dict(candidate.get("quarantined_devices", {}))
    if quarantined:
        membership[device_id] = True
        candidate["quarantined_devices"] = membership
    else:
        membership.pop(device_id, None)
        if membership:
            candidate["quarantined_devices"] = membership
        else:
            candidate.pop("quarantined_devices", None)


def _qos_layers(doc, device_id):
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    if not isinstance(roles, dict):
        roles = {}
    defs = roles.get("defs", {})
    role_of = roles.get("role_of", {})
    if not isinstance(defs, dict):
        defs = {}
    if not isinstance(role_of, dict):
        role_of = {}
    role = role_of.get(device_id)
    definition = defs.get(role, {})
    if not isinstance(definition, dict):
        definition = {}
    global_qos = roles.get("qos_default", {})
    role_qos = definition.get("qos", {})
    device_qos = roles.get("qos_device", {}).get(device_id, {}) \
        if isinstance(roles.get("qos_device", {}), dict) else {}
    layers = [global_qos if isinstance(global_qos, dict) else {},
              role_qos if isinstance(role_qos, dict) else {},
              device_qos if isinstance(device_qos, dict) else {}]
    if "on_stale" in definition:
        layers.insert(2, {"on_stale": definition["on_stale"]})
    return role, definition, layers


def _compile_qos_layers(role, definition, layers, sources=None):
    effective = {key: {"value": value, "source": "builtin"}
                 for key, value in QOS_DEFAULTS.items()}
    if role is not None and definition.get("restricted", False):
        effective["on_stale"] = {"value": "keep", "source": "role:%s" % role}
    derived = {key: False for key in PER_TORRENT_RATE_KEYS}
    for index, layer in enumerate(layers):
        source = sources[index] if sources is not None else "builtin"
        for key, value in layer.items():
            effective[key] = {"value": value, "source": source}
        for key in PER_TORRENT_RATE_KEYS:
            if key in layer:
                derived[key] = False
            elif "per_peer_bps" in layer or ("fanout" in layer and derived[key]):
                derived[key] = True
                effective[key] = {
                    "value": effective["per_peer_bps"]["value"] *
                             effective["fanout"]["value"],
                    "source": source,
                    "derived_from": {
                        name: dict(effective[name])
                        for name in ("per_peer_bps", "fanout")}}
    return effective if sources is not None else {
        key: row["value"] for key, row in effective.items()}


def explain_qos(doc, device_id):
    """Compile values and provenance using the same merge as enforcement."""
    role, definition, layers = _qos_layers(doc, device_id)
    sources = ["global", "role:%s" % role, "device:%s" % device_id]
    if "on_stale" in definition:
        sources.insert(2, "role:%s" % role)
    return _compile_qos_layers(role, definition, layers, sources=sources)


def compile_qos(doc, device_id):
    """Compile QoS without mutating *doc*.

    Persisted layers override in global, role, then device order. Built-in
    ``per_peer_bps`` is descriptive and never creates a cap. Once an operator
    explicitly supplies that modelling input, each absent per-torrent rate is
    derived from the effective ``per_peer_bps * fanout``; an explicit rate at
    the same or a more-specific layer wins.
    """
    return _compile_qos_layers(*_qos_layers(doc, device_id))


def _tracker_qos_layers(doc, device_id, state):
    if not isinstance(state, str) or state not in _TRACKER_STATES:
        raise PolicyError("bad tracker state")
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    if not isinstance(roles, dict):
        roles = {}
    defs = roles.get("defs", {})
    role_of = roles.get("role_of", {})
    if not isinstance(defs, dict):
        defs = {}
    if not isinstance(role_of, dict):
        role_of = {}
    role = role_of.get(device_id) if isinstance(device_id, str) else None
    definition = defs.get(role, {})
    if not isinstance(definition, dict):
        definition = {}

    def selected_state(values):
        if not isinstance(values, dict):
            return {}
        selected = values.get(state, {})
        return selected if isinstance(selected, dict) else {}

    global_qos = roles.get("qos_default", {})
    role_qos = definition.get("qos", {})
    return (
        (global_qos if isinstance(global_qos, dict) else {}, "global"),
        (selected_state(roles.get("qos_state_default", {})),
         "global-state:%s" % state),
        (role_qos if isinstance(role_qos, dict) else {}, "role:%s" % role),
        (selected_state(definition.get("qos_state", {})),
         "role-state:%s:%s" % (role, state)),
    )


def explain_tracker_qos(doc, device_id, state):
    """Compile tracker cadence values and their scalar/state provenance."""
    effective = {
        key: {"value": QOS_DEFAULTS[key], "source": "builtin"}
        for key in _TRACKER_QOS_KEYS}
    for layer, source in _tracker_qos_layers(doc, device_id, state):
        for key in _TRACKER_QOS_KEYS:
            if key in layer:
                effective[key] = {"value": layer[key], "source": source}
    return effective


def compile_tracker_qos(doc, device_id, state):
    """Compile the two tracker cadence values without mutating *doc*."""
    return {
        key: row["value"]
        for key, row in explain_tracker_qos(doc, device_id, state).items()}


def _validate_compiled_qos(qos):
    if qos["fanout"] > qos["max_peers"]:
        raise PolicyError("fanout exceeds max_peers")
    for key in PER_TORRENT_RATE_KEYS:
        if qos[key] > _QOS_RANGES[key][1]:
            raise PolicyError(
                "derived per-torrent rate out of range: %s" % key)


def role_origin_enabled(doc, role):
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    defs = roles.get("defs", {}) if isinstance(roles, dict) else {}
    definition = defs.get(role, {}) if isinstance(defs, dict) else {}
    if not isinstance(definition, dict) \
            or not definition.get("restricted", False):
        return True
    return definition.get("origin", True)


def _role_reaches_origin(doc, start):
    definitions = _role_defs(doc)
    pending = [start]
    seen = set()
    while pending:
        role = pending.pop()
        if role in seen:
            continue
        seen.add(role)
        if role_origin_enabled(doc, role):
            return True
        pending.extend(
            candidate for candidate in definitions
            if candidate not in seen and
            _role_pair_permitted(doc, role, candidate))
    return False


def policy_warnings(doc):
    """Return advisory, machine-readable warnings for a valid role graph."""
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    defs = roles.get("defs", {}) if isinstance(roles, dict) else {}
    if not isinstance(defs, dict):
        return []
    result = []
    for name in sorted(defs):
        definition = defs[name]
        if not isinstance(definition, dict) \
                or not definition.get("restricted", False) \
                or definition.get("origin", True):
            continue
        if not _role_reaches_origin(doc, name):
            result.append({"code": "origin_unreachable", "role": name})
    return result


def _validate_roles(roles):
    """Validate the optional role model without materialising defaults.

    Keeping the entire section optional preserves the byte-for-byte legacy
    document. QoS values are validated by the QoS grammar; this function owns
    the role names, references, membership map and network hints.
    """
    if not isinstance(roles, dict):
        raise PolicyError("bad roles")
    if set(roles) - {
            "defs", "role_of", "qos_default", "qos_device",
            "qos_state_default"}:
        raise PolicyError("bad roles key")
    defs = roles.get("defs", {})
    if not isinstance(defs, dict) or len(defs) > MAX_ROLES:
        raise PolicyError("bad role defs")
    for name, definition in defs.items():
        validate_role_name(name)
        if not isinstance(definition, dict):
            raise PolicyError("bad role definition")
        if set(definition) - {
                "restricted", "peers", "origin", "nets", "on_stale", "qos",
                "qos_state"}:
            raise PolicyError("bad role definition key")
        restricted = definition.get("restricted", False)
        if not isinstance(restricted, bool):
            raise PolicyError("restricted must be bool")
        origin = definition.get("origin", True)
        if not isinstance(origin, bool):
            raise PolicyError("origin must be bool")
        peers = definition.get("peers", [name])
        if not isinstance(peers, list) or len(peers) > MAX_ROLE_PEERS:
            raise PolicyError("bad role peers")
        seen_peers = set()
        for peer in peers:
            validate_role_name(peer, "bad peer role name")
            if peer in seen_peers:
                raise PolicyError("duplicate role peer")
            seen_peers.add(peer)
            if peer not in defs:
                raise PolicyError("peer references unknown role")
        if name not in seen_peers:
            raise PolicyError("role peers must contain itself",
                              code="role_isolated", role=name)
        nets = definition.get("nets", [])
        if not isinstance(nets, list):
            raise PolicyError("bad role nets")
        for net in nets:
            validate_role_net(net)
        if "on_stale" in definition \
                and definition["on_stale"] not in ("keep", "defaults"):
            raise PolicyError("bad on_stale")
        _validate_qos(definition.get("qos", {}), "role")
        _validate_qos_state(definition.get("qos_state", {}))

    # An unrestricted role has an implicit permit ACL, so its side of every
    # relation is already open. Two restricted roles must name one another in
    # both directions; lifecycle writes normalize this before validation.
    for name, definition in defs.items():
        if not definition.get("restricted", False):
            continue
        for peer in definition.get("peers", [name]):
            peer_def = defs[peer]
            if peer != name and peer_def.get("restricted", False) \
                    and name not in peer_def.get("peers", [peer]):
                raise PolicyError(
                    "asymmetric role peers", code="asymmetric_peers",
                    role=name, peer=peer)

    role_of = roles.get("role_of", {})
    if not isinstance(role_of, dict):
        raise PolicyError("bad role_of")
    for device_id, role in role_of.items():
        if not isinstance(device_id, str) or not device_id:
            raise PolicyError("bad role device id")
        validate_role_name(role, "bad role assignment")
        if role not in defs:
            raise PolicyError("assignment to unknown role")
    _validate_qos(roles.get("qos_default", {}), "global")
    _validate_qos_state(roles.get("qos_state_default", {}))
    qos_device = roles.get("qos_device", {})
    if not isinstance(qos_device, dict):
        raise PolicyError("bad qos_device")
    for device_id, qos in qos_device.items():
        if not isinstance(device_id, str) or not device_id \
                or not isinstance(qos, dict):
            raise PolicyError("bad device qos")
        _validate_qos(qos, "device")

    # Cross-field constraints are checked after all layers are known.
    global_qos = roles.get("qos_default", {})
    global_effective = _compile_qos_layers(
        None, {}, [global_qos, {}, {}])
    _validate_compiled_qos(global_effective)
    for name, definition in defs.items():
        layers = [global_qos, definition.get("qos", {})]
        if "on_stale" in definition:
            layers.append({"on_stale": definition["on_stale"]})
        effective = _compile_qos_layers(name, definition, layers)
        _validate_compiled_qos(effective)
        if definition.get("restricted", False) and \
                effective["catalog_tick_s"] > \
                peer_endpoints.endpoint_ttl() / 3.0:
            raise PolicyError("catalog_tick_s exceeds endpoint TTL third")
    for device_id in set(qos_device) | set(role_of):
        qos = compile_qos({"roles": roles}, device_id)
        _validate_compiled_qos(qos)
        role = role_of.get(device_id)
        definition = defs.get(role, {})
        if definition.get("restricted", False) and \
                qos["catalog_tick_s"] > peer_endpoints.endpoint_ttl() / 3.0:
            raise PolicyError("catalog_tick_s exceeds endpoint TTL third")


def validate_document(doc, warning_sink=None):
    """Raise :class:`PolicyError` on any schema/bounds/immutability violation.
    Quarantine is reserved and immutable (rename/delete/rule-edit rejected)."""
    if not isinstance(doc, dict):
        raise PolicyError("document must be an object")
    if doc.get("schema") != SCHEMA:
        raise PolicyError("bad schema")
    if not isinstance(doc.get("revision"), int) or isinstance(
            doc["revision"], bool):
        raise PolicyError("bad revision")
    acls = doc.get("acls")
    if not isinstance(acls, dict) or len(acls) > MAX_ACLS:
        raise PolicyError("bad acls")
    # immutable quarantine must be present and exactly the reserved shape
    q = acls.get(RESERVED_QUARANTINE)
    if q is None:
        raise PolicyError("reserved quarantine missing")
    if q.get("reserved") is not True or q.get("rules") != _QUARANTINE_RULES:
        raise PolicyError("quarantine is immutable")
    for name, acl in acls.items():
        if not _ACL_NAME_RE.match(name):
            raise PolicyError("bad acl name")
        rules = acl.get("rules")
        if not isinstance(rules, list) or len(rules) > MAX_RULES_PER_ACL:
            raise PolicyError("bad rules")
        seqs = set()
        for rule in rules:
            _validate_rule(rule)
            if rule["seq"] in seqs:
                raise PolicyError("duplicate seq")
            seqs.add(rule["seq"])
    assignments = doc.get("assignments")
    if not isinstance(assignments, dict):
        raise PolicyError("bad assignments")
    for dev, acl_name in assignments.items():
        if acl_name not in acls:
            raise PolicyError("assignment to unknown acl")
    if "quarantined_devices" in doc:
        _validate_quarantined_devices(doc["quarantined_devices"])
    seeder = doc.get("seeder_assignment")
    if seeder is not None and seeder not in acls:
        raise PolicyError("seeder assignment to unknown acl")
    outbox = doc.get("operation_outbox")
    if not isinstance(outbox, list) or len(outbox) > OUTBOX_CAP:
        raise PolicyError("bad operation_outbox")
    try:
        reconciler_status.validate_ack_epoch(doc.get("operation_ack_epoch"))
    except ValueError as exc:
        raise PolicyError("bad operation_ack_epoch") from exc
    if "roles" in doc:
        _validate_roles(doc["roles"])
    if warning_sink is not None:
        warning_sink.extend(policy_warnings(doc))
    return doc


# ---------------------------------------------------------------------------
# Pure evaluator
# ---------------------------------------------------------------------------

def _virtual_role_acl(name, definition, unknown=False):
    if unknown:
        return {
            "virtual": True,
            "role": name,
            "role_unknown": True,
            "rules": [{"seq": 40, "action": "deny",
                       "match": {"type": "any"}}],
        }
    rules = [{"seq": 10, "action": "permit",
              "match": {"type": "role", "value": name}}]
    if definition.get("origin", True):
        rules.append({"seq": 20, "action": "permit",
                      "match": {"type": "service", "value": "seeder"}})
    for peer in definition.get("peers", [name]):
        if peer != name:
            rules.append({"seq": 30, "action": "permit",
                          "match": {"type": "role", "value": peer}})
    rules.append({"seq": 40, "action": "deny", "match": {"type": "any"}})
    return {"virtual": True, "role": name, "role_unknown": False,
            "rules": rules}


def compile_roles(doc):
    """Compile virtual role ACLs and pre-sort stored ACL rules.

    The result is deliberately detached from persistence: it is returned on
    :class:`PolicyResult`, never cached globally and never inserted into *doc*.
    Invalid raw dictionaries can still be evaluated by ad-hoc callers; a
    device mapped to an unknown role receives a deny-only virtual ACL so that
    corruption cannot turn a restriction into implicit permit.
    """
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    if not isinstance(roles, dict):
        roles = {}
    defs = roles.get("defs", {})
    role_of = roles.get("role_of", {})
    if not isinstance(defs, dict):
        defs = {}
    if not isinstance(role_of, dict):
        role_of = {}
    role_of = dict(role_of)

    acl_by_role = {}
    restricted = set()
    for name, definition in defs.items():
        if isinstance(definition, dict) and definition.get("restricted", False):
            restricted.add(name)
            acl_by_role[name] = _virtual_role_acl(name, definition)
    unknown_roles = {role for role in role_of.values()
                     if isinstance(role, str) and role not in defs}
    for role in sorted(unknown_roles):
        restricted.add(role)
        acl_by_role[role] = _virtual_role_acl(role, {}, unknown=True)

    sorted_rules = {}
    acls = doc.get("acls", {}) if isinstance(doc, dict) else {}
    if isinstance(acls, dict):
        for name, acl in acls.items():
            if isinstance(acl, dict) and isinstance(acl.get("rules"), list):
                sorted_rules[name] = sorted(
                    acl["rules"], key=lambda rule: rule.get("seq", 0))
    members = {name: set() for name in defs}
    for device_id, role in role_of.items():
        if isinstance(role, str):
            members.setdefault(role, set()).add(device_id)
    members_by_role = FrozenMapping({
        role: frozenset(device_ids)
        for role, device_ids in members.items()})
    return CompiledRoles(acl_by_role, role_of, frozenset(restricted),
                         sorted_rules, members_by_role)


def _compiled_roles(doc, compiled):
    return compiled if compiled is not None else compile_roles(doc)


def _assigned_acl(doc, principal, compiled=None):
    """Return the ACL bound to ``principal`` or ``None``. Only device and
    service principals have an assignment slot; legacy has none (spec 0a)."""
    compiled = _compiled_roles(doc, compiled)
    if principal.type == "device":
        if is_quarantined(doc, principal.id):
            return doc.get("acls", {}).get(RESERVED_QUARANTINE)
        name = ordinary_assignment(doc, principal.id)
        if name is not None:
            return doc.get("acls", {}).get(name)
        role = compiled.role_of.get(principal.id)
        return compiled.acl_by_role.get(role)
    elif principal.type == "service":
        name = doc.get("seeder_assignment")
    else:  # legacy
        return None
    if name is None:
        return None
    return doc.get("acls", {}).get(name)


def _rule_matches(rule, principal, ipv4, compiled=None, subject_role=None):
    match = rule["match"]
    mtype = match["type"]
    if mtype == "any":
        return True
    if mtype == "device":
        return principal.type == "device" and principal.id == match["value"]
    if mtype == "service":
        return principal.type == "service" and principal.id == match["value"]
    if mtype == "role":
        if subject_role is None and compiled is not None \
                and principal.type == "device":
            subject_role = compiled.role_of.get(principal.id)
        return principal.type == "device" and subject_role == match["value"]
    if mtype == "host":
        return ipv4 == match["value"]
    if mtype == "cidr":
        try:
            return ipaddress.IPv4Address(ipv4) in ipaddress.IPv4Network(
                match["value"], strict=False)
        except (ipaddress.AddressValueError, ValueError):
            return False
    return False


def evaluate(doc, principal, ipv4, compiled=None):
    """Evaluate ``principal`` + ``ipv4`` against its assigned ACL. Returns
    ``(decision, matched_seq)``; no match is ``("permit", None)``."""
    return evaluate_for(doc, principal, principal, ipv4, compiled=compiled)


def evaluate_for(doc, owner_principal, subject_principal, subject_ipv4,
                 compiled=None):
    """Evaluate ``subject`` against the ACL assigned to ``owner``."""
    compiled = _compiled_roles(doc, compiled)
    acl = _assigned_acl(doc, owner_principal, compiled=compiled)
    if acl is None:
        return ("permit", None)
    acl_name = effective_acl_name(doc, owner_principal, compiled=compiled)
    rules = compiled.sorted_rules.get(acl_name, acl["rules"])
    subject_role = (compiled.role_of.get(subject_principal.id)
                    if subject_principal.type == "device" else None)
    for rule in rules:
        if _rule_matches(rule, subject_principal, subject_ipv4,
                         compiled=compiled, subject_role=subject_role):
            return (rule["action"], rule["seq"])
    return ("permit", None)


def effective_acl_name(doc, principal, compiled=None):
    """Name the single stored or virtual ACL effective for ``principal``."""
    compiled = _compiled_roles(doc, compiled)
    if principal.type == "device":
        if is_quarantined(doc, principal.id):
            return RESERVED_QUARANTINE
        assigned = ordinary_assignment(doc, principal.id)
        if assigned is not None:
            return assigned if assigned in doc.get("acls", {}) else None
        role = compiled.role_of.get(principal.id)
        if role in compiled.acl_by_role:
            return "role:%s" % role
        return None
    if principal.type == "service":
        assigned = doc.get("seeder_assignment")
        if assigned is not None:
            return assigned if assigned in doc.get("acls", {}) else None
    return None


def acl_source(doc, principal, compiled=None):
    """Describe whether the effective ACL came from an assignment or role."""
    compiled = _compiled_roles(doc, compiled)
    name = effective_acl_name(doc, principal, compiled=compiled)
    if name is None:
        return "none"
    if name.startswith("role:"):
        return name
    return "assignment:%s" % name


def mutual_permit(doc, requester_principal, requester_ipv4,
                  candidate_principal, candidate_ipv4, compiled=None):
    """True iff the requester's ACL permits the candidate AND the candidate's
    ACL permits the requester (spec 7). A ``fail_closed`` sentinel document
    (see :func:`load_policy`) denies all mutual discovery."""
    if doc.get("_fail_closed"):
        return False
    req = evaluate_for(doc, requester_principal,
                       candidate_principal, candidate_ipv4, compiled)[0]
    cand = evaluate_for(doc, candidate_principal,
                        requester_principal, requester_ipv4, compiled)[0]
    return req == "permit" and cand == "permit"


# ---------------------------------------------------------------------------
# Atomic, flocked persistence
# ---------------------------------------------------------------------------

def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".peer-policy-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def roles_watermark_path(auth_path):
    """Path of the durable evidence that roles have existed on this server."""
    stem = auth_path[:-5] if auth_path.endswith(".json") else auth_path
    return stem + ".roles-ever"


def roles_ever_configured(auth_path):
    """Treat any watermark inode as set; corruption must fail conservatively."""
    return os.path.exists(roles_watermark_path(auth_path))


def _write_roles_watermark(auth_path):
    """Durably create the roles-ever marker before a role-bearing commit."""
    path = roles_watermark_path(auth_path)
    if os.path.exists(path):
        return
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=".peer-policy-roles-ever-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b"roles-ever-v1\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def lkg_ring_path(lkg_path):
    """Directory holding the five prior committed policy documents."""
    stem = lkg_path[:-5] if lkg_path.endswith(".json") else lkg_path
    return stem + ".d"


def lkg_revision_path(lkg_path, revision):
    if not isinstance(revision, int) or isinstance(revision, bool) \
            or revision < 1:
        raise PolicyError("bad LKG revision")
    return os.path.join(lkg_ring_path(lkg_path), "%020d.json" % revision)


def lkg_ring_revisions(lkg_path):
    """Return retained ring revisions in ascending order."""
    directory = lkg_ring_path(lkg_path)
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    revisions = []
    for name in names:
        match = re.fullmatch(r"([0-9]{20})\.json", name)
        if match and int(match.group(1)) >= 1:
            revisions.append(int(match.group(1)))
    return sorted(revisions)


def _write_lkg_ring(lkg_path, doc):
    directory = lkg_ring_path(lkg_path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    _atomic_write_json(lkg_revision_path(lkg_path, doc["revision"]), doc)


def _prune_lkg_ring(lkg_path):
    revisions = lkg_ring_revisions(lkg_path)
    for revision in revisions[:-LKG_RING_SIZE]:
        try:
            os.remove(lkg_revision_path(lkg_path, revision))
        except FileNotFoundError:
            pass


def read_lkg_revision(lkg_path, revision):
    """Read one retained, validated historical policy document."""
    path = lkg_revision_path(lkg_path, revision)
    doc = _read_valid(path)
    if doc is None:
        raise PolicyError("LKG revision is missing or invalid",
                          code="lkg_revision_unavailable",
                          revision=revision)
    return doc


@contextlib.contextmanager
def _umbrella_lock(path):
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


def _read_valid(path):
    """Return a validated document from ``path`` or ``None`` if the file is
    missing/corrupt/invalid."""
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    try:
        return validate_document(doc)
    except PolicyError:
        return None


def _fail_closed_document():
    doc = base_document()
    doc["_fail_closed"] = True
    return doc


# ---------------------------------------------------------------------------
# Initialization + read precedence
# ---------------------------------------------------------------------------

def initialize(auth_path, lkg_path):
    """Write the validated base policy to both files (spec 7 fresh init)."""
    with _umbrella_lock(auth_path):
        base = base_document()
        _atomic_write_json(lkg_path, base)
        _atomic_write_json(auth_path, base)


def _initialize_if_absent(auth_path, lkg_path):
    """Initialize only when both policy files remain absent under the lock."""
    with _umbrella_lock(auth_path):
        if os.path.exists(auth_path) or os.path.exists(lkg_path):
            return None
        roles_lost = roles_ever_configured(auth_path)
        document = base_document()
        _atomic_write_json(lkg_path, document)
        _atomic_write_json(auth_path, document)
        return PolicyResult(
            document, degraded=roles_lost, fail_closed=False,
            roles=compile_roles(document))


def load_policy(auth_path, lkg_path):
    """Resolve the active :class:`PolicyResult` honoring read precedence.

    - Neither file exists -> materialize the validated base to both (open
      discovery); a roles-ever watermark marks this as degraded state loss,
      while its absence is a non-degraded fresh install.
    - Valid authoritative -> use it, not degraded.
    - Corrupt authoritative + valid LKG -> use LKG, ``degraded=True``.
    - Both corrupt while a file exists -> ``fail_closed=True`` (no candidates).
    """
    auth_exists = os.path.exists(auth_path)
    lkg_exists = os.path.exists(lkg_path)
    if not auth_exists and not lkg_exists:
        initialized = _initialize_if_absent(auth_path, lkg_path)
        if initialized is not None:
            return initialized
    authoritative = _read_valid(auth_path)
    if authoritative is not None:
        roles_lost = ((roles_ever_configured(auth_path) or
                       authoritative.get("roles_present") is True) and
                      "roles" not in authoritative)
        return PolicyResult(authoritative, degraded=roles_lost,
                            fail_closed=False,
                            roles=compile_roles(authoritative))
    lkg = _read_valid(lkg_path)
    if lkg is not None:
        return PolicyResult(lkg, degraded=True, fail_closed=False,
                            roles=compile_roles(lkg))
    document = _fail_closed_document()
    return PolicyResult(document, degraded=True, fail_closed=True,
                        roles=compile_roles(document))


# ---------------------------------------------------------------------------
# Commit transaction + outbox
# ---------------------------------------------------------------------------

def _new_event_id():
    return secrets.token_hex(8)  # nonsecret 16 hex chars


def _prune_acked(outbox, acked_revision):
    return [e for e in outbox if e["revision"] > acked_revision]


def commit_mutation(auth_path, lkg_path, action, target, actor, now,
                    mutate, acked_revision=0, expected_revision=None,
                    dry_run=False, precommit=None):
    """Commit one policy mutation under a single umbrella flock (spec 7).

    Loads and validates the current committed authoritative, prunes outbox
    entries at/below ``acked_revision``, and — if 256 unacked entries remain —
    raises :class:`OperationBacklogFull` before any write. Otherwise applies
    ``mutate(candidate)``, increments ``revision``, appends a stable outbox
    entry, validates the candidate, writes the **prior committed authoritative**
    to LKG first, then atomically replaces the authoritative file with the
    candidate (the atomic replace is the commit). ``dry_run`` returns the exact
    validated candidate without writing it. ``precommit(prior, candidate)``
    runs while the same lock is held, over detached copies, so a confirmation
    check cannot race the subsequent authoritative replace or mutate it.
    """
    with _umbrella_lock(auth_path):
        auth_exists = os.path.exists(auth_path)
        lkg_exists = os.path.exists(lkg_path)
        prior = _read_valid(auth_path)
        if prior is None:
            if auth_exists or lkg_exists:
                if _read_valid(lkg_path) is not None:
                    raise PolicyDegradedError(
                        "authoritative policy invalid; repair before mutation")
                raise PolicyError("policy state invalid; mutation denied")
            prior = base_document()
        if expected_revision is not None and prior["revision"] != expected_revision:
            raise RevisionConflict(prior["revision"])
        # An ack watermark above this document's own revision cannot be real
        # (a restored/reset document with a stale enforcement status); pruning on
        # it would silently discard every unacknowledged entry.
        outbox = _prune_acked(list(prior.get("operation_outbox", [])),
                              effective_acked(prior, acked_revision))
        if len(outbox) >= OUTBOX_CAP:
            raise OperationBacklogFull("256 unacknowledged operations")

        candidate = json.loads(json.dumps(prior))  # deep copy
        candidate["operation_outbox"] = outbox
        _normalize_quarantine(candidate)
        mutate(candidate)
        _normalize_quarantine(candidate)
        if "roles" in candidate or prior.get("roles_present") is True:
            candidate["roles_present"] = True
        candidate["revision"] = prior["revision"] + 1
        candidate["operation_outbox"].append({
            "event_id": _new_event_id(),
            "revision": candidate["revision"],
            "action": action, "target": target, "actor": actor,
            "created_at": float(now)})
        # Every committed snapshot gets a branch-unique acknowledgement epoch,
        # including direct writes without supplied status. Restoring an exact
        # predecessor and repeating an action must not recreate the old epoch.
        # Like event_id/revision, this bookkeeping is excluded from confirmation.
        candidate["operation_ack_epoch"] = hashlib.sha256(
            candidate["operation_outbox"][-1]["event_id"].encode()).hexdigest()[:32]
        validate_document(candidate)

        if precommit is not None:
            precommit(json.loads(json.dumps(prior)),
                      json.loads(json.dumps(candidate)))
        if dry_run:
            return candidate

        # Evidence and recovery records become durable before the candidate.
        # A failure therefore leaves the authoritative policy at ``prior``;
        # it can never leave active roles without their roles-ever marker.
        if candidate.get("roles_present") is True:
            _write_roles_watermark(auth_path)
        _atomic_write_json(lkg_path, prior)
        _write_lkg_ring(lkg_path, prior)
        # The authoritative replace is the commit point.
        _atomic_write_json(auth_path, candidate)
        # Pruning after the commit means an interrupted write can only retain
        # extra recovery state; it cannot discard a useful old document. A
        # retention cleanup failure cannot turn a successful commit into an
        # apparent failure that an API caller might retry.
        try:
            _prune_lkg_ring(lkg_path)
        except OSError:
            pass
        return candidate


# ---------------------------------------------------------------------------
# Role and QoS lifecycle
# ---------------------------------------------------------------------------

def _ensure_roles(doc):
    roles = doc.setdefault("roles", {})
    if not isinstance(roles, dict):
        raise PolicyError("bad roles")
    roles.setdefault("defs", {})
    roles.setdefault("role_of", {})
    roles.setdefault("qos_default", {})
    roles.setdefault("qos_device", {})
    doc["roles_present"] = True
    return roles


def validate_role_net(value):
    """Validate the shared wire grammar without rewriting valid policy text."""
    if not isinstance(value, str) or not re.fullmatch(ROLE_NET_PATTERN, value):
        raise PolicyError("bad role net")
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError as exc:
        raise PolicyError("bad role net") from exc


def _ordered_peers(name, peers):
    return [name] + sorted(peer for peer in set(peers) if peer != name)


def _put_role(candidate, name, definition):
    validate_role_name(name)
    if not isinstance(definition, dict):
        raise PolicyError("bad role definition")
    definition = json.loads(json.dumps(definition))
    roles = _ensure_roles(candidate)
    defs = roles["defs"]
    if not isinstance(defs, dict):
        raise PolicyError("bad role defs")

    supplied_peers = definition.get("peers", [name])
    if not isinstance(supplied_peers, list):
        raise PolicyError("bad role peers")
    if name not in supplied_peers:
        raise PolicyError("role peers must contain itself",
                          code="role_isolated", role=name)
    seen = set()
    for peer in supplied_peers:
        validate_role_name(peer, "bad peer role name")
        if peer in seen:
            raise PolicyError("duplicate role peer")
        seen.add(peer)
        if peer != name and peer not in defs:
            raise PolicyError("peer references unknown role")
    definition["peers"] = _ordered_peers(name, supplied_peers)
    defs[name] = definition

    # Store an undirected graph. Adding or removing an edge on one endpoint
    # performs the reciprocal edit in the same candidate document.
    wanted = set(definition["peers"])
    for other_name, other_def in defs.items():
        if other_name == name:
            continue
        peers = other_def.get("peers", [other_name])
        if not isinstance(peers, list):
            raise PolicyError("bad role peers")
        peers = set(peers)
        if other_name in wanted:
            peers.add(name)
        else:
            peers.discard(name)
        other_def["peers"] = _ordered_peers(other_name, peers)


def define_role(auth_path, lkg_path, name, definition, actor, now,
                acked_revision=0, expected_revision=None, dry_run=False,
                precommit=None):
    """Create or replace a role, normalizing all peer edges atomically."""
    return commit_mutation(
        auth_path, lkg_path, action="define_role", target="role:%s" % name,
        actor=actor, now=now,
        mutate=lambda candidate: _put_role(
            candidate, name, definition),
        acked_revision=acked_revision, expected_revision=expected_revision,
        dry_run=dry_run, precommit=precommit)


def _require_known_role(roles, role):
    validate_role_name(role)
    if role not in roles.get("defs", {}):
        raise PolicyError("unknown role", code="role_not_found", role=role)


def set_role(auth_path, lkg_path, device_id, role, actor, now,
             acked_revision=0, expected_revision=None, dry_run=False,
             precommit=None):
    """Assign one device to a role, or clear it when ``role is None``."""
    if not isinstance(device_id, str) or not device_id:
        raise PolicyError("bad role device id")

    def _mutate(candidate):
        roles = _ensure_roles(candidate)
        if role is None:
            roles["role_of"].pop(device_id, None)
            return
        _require_known_role(roles, role)
        roles["role_of"][device_id] = role

    action = "clear_role" if role is None else "set_role"
    return commit_mutation(
        auth_path, lkg_path, action=action, target=device_id, actor=actor,
        now=now, mutate=_mutate, acked_revision=acked_revision,
        expected_revision=expected_revision, dry_run=dry_run,
        precommit=precommit)


def _checked_device_ids(device_ids):
    if not isinstance(device_ids, (list, tuple)):
        raise PolicyError("bad role members")
    result = []
    seen = set()
    for device_id in device_ids:
        if not isinstance(device_id, str) or not device_id:
            raise PolicyError("bad role device id")
        if device_id not in seen:
            seen.add(device_id)
            result.append(device_id)
    return result


def set_roles_bulk(auth_path, lkg_path, role, device_ids, actor, now,
                   acked_revision=0, expected_revision=None, dry_run=False,
                   precommit=None):
    """Assign or clear a batch as one revision and one outbox event."""
    device_ids = _checked_device_ids(device_ids)

    def _mutate(candidate):
        roles = _ensure_roles(candidate)
        if role is None:
            for device_id in device_ids:
                roles["role_of"].pop(device_id, None)
        else:
            _require_known_role(roles, role)
            for device_id in device_ids:
                roles["role_of"][device_id] = role

    return commit_mutation(
        auth_path, lkg_path, action="set_roles_bulk",
        target="role:" if role is None else "role:%s" % role,
        actor=actor, now=now, mutate=_mutate,
        acked_revision=acked_revision, expected_revision=expected_revision,
        dry_run=dry_run, precommit=precommit)


def set_role_members(auth_path, lkg_path, role, device_ids, actor, now,
                     acked_revision=0, expected_revision=None, dry_run=False,
                     precommit=None):
    """Replace one role's full member set in one commit."""
    device_ids = _checked_device_ids(device_ids)

    def _mutate(candidate):
        roles = _ensure_roles(candidate)
        _require_known_role(roles, role)
        role_of = roles["role_of"]
        for device_id in [key for key, value in role_of.items()
                          if value == role]:
            role_of.pop(device_id)
        for device_id in device_ids:
            role_of[device_id] = role

    return commit_mutation(
        auth_path, lkg_path, action="set_role_members",
        target="role:%s" % role, actor=actor, now=now, mutate=_mutate,
        acked_revision=acked_revision, expected_revision=expected_revision,
        dry_run=dry_run, precommit=precommit)


def delete_role(auth_path, lkg_path, name, actor, now, acked_revision=0,
                expected_revision=None, referring_schedules=(), dry_run=False,
                precommit=None):
    """Delete an unreferenced role or raise :class:`RoleInUse`."""
    validate_role_name(name)

    def _mutate(candidate):
        roles = _ensure_roles(candidate)
        _require_known_role(roles, name)
        member_count = sum(
            role == name for role in roles["role_of"].values())
        referring_roles = [
            role for role, definition in roles["defs"].items()
            if role != name and name in definition.get("peers", [role])]
        if member_count or referring_roles or referring_schedules:
            raise RoleInUse(name, member_count, referring_roles,
                            referring_schedules)
        del roles["defs"][name]

    return commit_mutation(
        auth_path, lkg_path, action="delete_role",
        target="role:%s" % name, actor=actor, now=now, mutate=_mutate,
        acked_revision=acked_revision, expected_revision=expected_revision,
        dry_run=dry_run, precommit=precommit)


def set_qos(auth_path, lkg_path, qos, actor, now, role=None, device_id=None,
            acked_revision=0, expected_revision=None, dry_run=False,
            precommit=None, qos_state=_QOS_STATE_UNSET):
    """Replace scalar and optional tracker-state QoS in one policy commit."""
    scalar_supplied = qos is not None
    state_supplied = qos_state is not _QOS_STATE_UNSET and qos_state is not None
    if not scalar_supplied and not state_supplied:
        raise PolicyError("qos or qos_state required")
    if scalar_supplied and not isinstance(qos, dict):
        raise PolicyError("bad qos")
    if state_supplied and not isinstance(qos_state, dict):
        raise PolicyError("bad qos state")
    if role is not None and device_id is not None:
        raise PolicyError("ambiguous qos scope")
    if device_id is not None and state_supplied:
        raise PolicyError("tracker state qos has no device scope")
    replacement = json.loads(json.dumps(qos)) if scalar_supplied else None
    state_replacement = json.loads(json.dumps(qos_state)) \
        if state_supplied else None

    def _mutate(candidate):
        roles = _ensure_roles(candidate)
        if role is not None:
            _require_known_role(roles, role)
            definition = roles["defs"][role]
            if scalar_supplied:
                definition["qos"] = replacement
            if state_supplied:
                if state_replacement:
                    definition["qos_state"] = state_replacement
                else:
                    definition.pop("qos_state", None)
        elif device_id is not None:
            if not isinstance(device_id, str) or not device_id:
                raise PolicyError("bad device qos id")
            roles["qos_device"][device_id] = replacement
        else:
            if scalar_supplied:
                roles["qos_default"] = replacement
            if state_supplied:
                if state_replacement:
                    roles["qos_state_default"] = state_replacement
                else:
                    roles.pop("qos_state_default", None)

    target = ("role:%s" % role if role is not None else
              device_id if device_id is not None else "qos:global")
    return commit_mutation(
        auth_path, lkg_path, action="set_qos", target=target, actor=actor,
        now=now, mutate=_mutate, acked_revision=acked_revision,
        expected_revision=expected_revision, dry_run=dry_run,
        precommit=precommit)


def restore_lkg_revision(auth_path, lkg_path, revision, actor, now,
                         acked_revision=0, expected_revision=None,
                         dry_run=False, precommit=None):
    """Restore historical policy content as a new monotonic commit."""
    historical = read_lkg_revision(lkg_path, revision)

    def _mutate(candidate):
        live_revision = candidate["revision"]
        live_outbox = candidate["operation_outbox"]
        replacement = {
            key: json.loads(json.dumps(value))
            for key, value in historical.items()
            if key not in ("revision", "operation_outbox")
            and not key.startswith("_")}
        candidate.clear()
        candidate.update(replacement)
        candidate["revision"] = live_revision
        candidate["operation_outbox"] = live_outbox

    return commit_mutation(
        auth_path, lkg_path, action="restore",
        target="revision:%d" % revision, actor=actor, now=now,
        mutate=_mutate, acked_revision=acked_revision,
        expected_revision=expected_revision, dry_run=dry_run,
        precommit=precommit)


# ---------------------------------------------------------------------------
# Pure blast-radius preview
# ---------------------------------------------------------------------------

def _role_of_map(doc):
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    role_of = roles.get("role_of", {}) if isinstance(roles, dict) else {}
    return role_of if isinstance(role_of, dict) else {}


def _role_defs(doc):
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    defs = roles.get("defs", {}) if isinstance(roles, dict) else {}
    return defs if isinstance(defs, dict) else {}


def _qos_policy_content(doc):
    roles = doc.get("roles", {}) if isinstance(doc, dict) else {}
    if not isinstance(roles, dict):
        roles = {}
    role_qos = {}
    for name, definition in _role_defs(doc).items():
        values = {}
        if definition.get("qos"):
            values["qos"] = definition["qos"]
        if "qos_state" in definition:
            values["qos_state"] = definition["qos_state"]
        if "on_stale" in definition:
            values["on_stale"] = definition["on_stale"]
        if values:
            role_qos[name] = values
    content = {
        "qos_default": roles.get("qos_default", {}),
        "qos_device": {
            device_id: qos
            for device_id, qos in roles.get("qos_device", {}).items()
            if qos},
        "roles": role_qos,
    }
    if "qos_state_default" in roles:
        content["qos_state_default"] = roles["qos_state_default"]
    return content


def _token_policy_content(doc):
    return {
        key: value for key, value in doc.items()
        if key not in ("revision", "operation_outbox", "operation_ack_epoch")}


def _role_pair_permitted(doc, left, right):
    defs = _role_defs(doc)

    def permits(owner, subject):
        definition = defs.get(owner)
        if not isinstance(definition, dict) \
                or not definition.get("restricted", False):
            return True
        return subject in definition.get("peers", [owner])

    return permits(left, right) and permits(right, left)


_BlastPrincipal = collections.namedtuple("_BlastPrincipal", ["type", "id"])


def _origin_access(doc, device_id, compiled):
    return mutual_permit(
        doc, _BlastPrincipal("device", device_id), "0.0.0.0",
        _BlastPrincipal("service", "seeder"), "0.0.0.0",
        compiled=compiled)


def _device_rule_mask(match, all_mask, device_bits, role_masks):
    """Compile one ACL match to an address-blind device bitmask."""
    match_type = match["type"]
    if match_type == "any":
        return all_mask
    if match_type == "device":
        return device_bits.get(match["value"], 0)
    if match_type == "role":
        return role_masks.get(match["value"], 0)
    if match_type == "service":
        return 0
    if match_type == "host":
        return all_mask if match["value"] == "0.0.0.0" else 0
    if match_type == "cidr":
        return all_mask if ipaddress.IPv4Address("0.0.0.0") in \
            ipaddress.IPv4Network(match["value"], strict=False) else 0
    return 0


def _effective_acl_rules(doc, acl_name, compiled):
    if acl_name is None:
        return ()
    if acl_name.startswith("role:"):
        acl = compiled.acl_by_role.get(acl_name[5:])
        return acl.get("rules", ()) if acl is not None else ()
    return compiled.sorted_rules.get(acl_name, ())


def _permitted_subject_mask(doc, acl_name, compiled, all_mask, device_bits,
                            role_masks):
    """Apply first-match ACL rules to all known devices in parallel."""
    unresolved = all_mask
    permitted = 0
    for rule in _effective_acl_rules(doc, acl_name, compiled):
        matched = unresolved & _device_rule_mask(
            rule["match"], all_mask, device_bits, role_masks)
        if rule["action"] == "permit":
            permitted |= matched
        unresolved &= ~matched
        if not unresolved:
            break
    return permitted | unresolved


def _permitted_sets(doc, devices, origin_access, compiled):
    """Map devices to whether origin or any other known device is permitted.

    Each bit represents one policy-visible device. ACL first-match evaluation
    produces one outbound bitmask per effective stored/virtual ACL; pairwise
    mask algebra then finds mutual counterparts without a device-by-device
    walk. Host and CIDR rules use neutral ``0.0.0.0`` because this pure preview
    has no endpoint inventory.
    """
    ordered_devices = sorted(devices)
    device_bits = {
        device_id: 1 << index
        for index, device_id in enumerate(ordered_devices)}
    all_mask = (1 << len(ordered_devices)) - 1
    role_masks = collections.defaultdict(int)
    owner_acl = {}
    members_by_acl = collections.defaultdict(int)
    for device_id in ordered_devices:
        bit = device_bits[device_id]
        role = compiled.role_of.get(device_id)
        if role is not None:
            role_masks[role] |= bit
        acl_name = effective_acl_name(
            doc, _BlastPrincipal("device", device_id), compiled=compiled)
        owner_acl[device_id] = acl_name
        members_by_acl[acl_name] |= bit

    permitted_by_acl = {
        acl_name: _permitted_subject_mask(
            doc, acl_name, compiled, all_mask, device_bits, role_masks)
        for acl_name in members_by_acl}
    peer_access = 0
    for acl_name, owners in members_by_acl.items():
        outgoing = permitted_by_acl[acl_name]
        for candidate_acl, candidate_members in members_by_acl.items():
            candidates = outgoing & candidate_members
            if not candidates:
                continue
            accepted_owners = owners & permitted_by_acl[candidate_acl]
            if not candidates & (candidates - 1):
                accepted_owners &= ~candidates
            peer_access |= accepted_owners

    origin_mask = 0
    for device_id, permitted in origin_access.items():
        if permitted:
            origin_mask |= device_bits[device_id]
    permitted_mask = origin_mask | peer_access
    return {
        device_id: bool(permitted_mask & device_bits[device_id])
        for device_id in ordered_devices}


def _mutual_role_edges(doc):
    """Return mutual conceptual role pairs, including unassigned devices."""
    role_names = sorted(set(_role_defs(doc)) | {"default"})
    return {
        (left, right)
        for index, left in enumerate(role_names)
        for right in role_names[index + 1:]
        if _role_pair_permitted(doc, left, right)}


def blast_radius(prior, candidate, threshold):
    """Return role-write impact, QoS drift, and a bound confirm token.

    ``threshold`` is deliberately supplied by the caller; the policy core has
    no UI or deployment-specific policy. Confirmation is needed when a topology
    count or the QoS-change indicator is strictly greater than that threshold.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or threshold < 0:
        raise PolicyError("bad blast-radius threshold")
    validate_document(prior)
    validate_document(candidate)
    prior_roles = _role_of_map(prior)
    candidate_roles = _role_of_map(candidate)
    role_devices = set(prior_roles) | set(candidate_roles)
    member_delta = sum(
        prior_roles.get(device_id) != candidate_roles.get(device_id)
        for device_id in role_devices)

    devices = (role_devices | set(prior.get("assignments", {})) |
               set(candidate.get("assignments", {})) |
               quarantine_device_ids(prior) |
               quarantine_device_ids(candidate))
    prior_compiled = compile_roles(prior)
    candidate_compiled = compile_roles(candidate)
    prior_origin = {
        device_id: _origin_access(prior, device_id, prior_compiled)
        for device_id in devices}
    candidate_origin = {
        device_id: _origin_access(candidate, device_id, candidate_compiled)
        for device_id in devices}
    origin_access_lost = sum(
        prior_origin[device_id] and not candidate_origin[device_id]
        for device_id in devices)

    prior_permitted_sets = _permitted_sets(
        prior, devices, prior_origin, prior_compiled)
    candidate_permitted_sets = _permitted_sets(
        candidate, devices, candidate_origin, candidate_compiled)
    empty_permitted_sets = sum(
        prior_permitted_sets[device_id] and
        not candidate_permitted_sets[device_id]
        for device_id in devices)

    role_pairs_stopped = len(
        _mutual_role_edges(prior) - _mutual_role_edges(candidate))

    counts = (member_delta, origin_access_lost, empty_permitted_sets,
              role_pairs_stopped)
    qos_changed = _qos_policy_content(prior) != _qos_policy_content(candidate)
    requires_confirmation = max(counts + (int(qos_changed),)) > threshold
    token = None
    if requires_confirmation:
        payload = {
            "prior_revision": prior.get("revision"),
            "candidate": _token_policy_content(candidate),
            "counts": counts,
            "qos_changed": qos_changed,
            "threshold": threshold,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = hashlib.sha256(encoded).hexdigest()
    return BlastRadius(
        member_delta, origin_access_lost, empty_permitted_sets,
        role_pairs_stopped, qos_changed, requires_confirmation, token)


def confirm_blast_radius(prior, candidate, threshold, token):
    """Return whether *token* confirms this exact candidate and threshold."""
    preview = blast_radius(prior, candidate, threshold)
    if not preview.requires_confirmation:
        return True
    return isinstance(token, str) and secrets.compare_digest(
        preview.confirm_token, token)


def _ack_parts(acknowledgement):
    if isinstance(acknowledgement, dict):
        return (acknowledgement.get("last_operation_exported_revision"),
                acknowledgement.get("operation_ack_epoch"))
    return acknowledgement, None


def effective_acked(doc, acked_revision):
    """Sanitize an outbox ack watermark against the document it is applied to.

    ``last_operation_exported_revision`` is persisted in the enforcement status
    file, SEPARATELY from the policy document, so a restored/reset document can
    carry a revision BELOW a watermark written for an older, higher-revisioned
    document. Such a watermark cannot describe this document, and honoring it is
    doubly destructive: ``pending_exports`` selects ``revision > acked`` so every
    export is suppressed, and ``_prune_acked`` then silently DISCARDS every
    outbox entry at the next write. The outbox contract is at-least-once and
    never-lost, so an impossible watermark fails safe to 0 — nothing counts as
    acknowledged and the entries re-export. A non-int or negative watermark, or a
    document with no usable revision, fails safe the same way.
    """
    acked_revision, epoch = _ack_parts(acked_revision)
    if type(acked_revision) is not int or acked_revision < 0:
        return 0
    revision = doc.get("revision") if isinstance(doc, dict) else None
    if type(revision) is not int:
        return 0
    # Legacy scalar/no-epoch pairs remain compatible until the first mutation.
    # Thereafter only a tracker acknowledgement for the current snapshot epoch
    # can prune. Old status cannot age into trust after consecutive commits.
    if epoch != doc.get("operation_ack_epoch"):
        return 0
    return 0 if acked_revision > revision else acked_revision


def pending_exports(doc, exported_revision):
    """Outbox entries with ``revision > exported_revision``, in revision order
    (at-least-once; re-exportable, never lost). The watermark is sanitized
    against *doc* first, so an impossible one cannot suppress every export."""
    exported_revision = effective_acked(doc, exported_revision)
    return sorted((e for e in doc.get("operation_outbox", [])
                   if e["revision"] > exported_revision),
                  key=lambda e: e["revision"])


def unassign_device(auth_path, lkg_path, device_id, actor, now,
                    acked_revision=0):
    """Remove ``device_id``'s four policy slots as a system cleanup action.

    Retirement clears its ordinary ACL, quarantine membership, role membership,
    and device QoS. A no-op mutation still commits a revision so the outbox
    records the cleanup; the reserved quarantine ACL is never touched. Runs
    under the same umbrella lock and preserves the operation outbox via
    :func:`commit_mutation`.

    This is the device-retirement counterpart to an operator assignment: after a
    device's secrets are durably revoked, its endpoint rows are retained and the
    revoked-credential principal is derived-denied regardless of assignment, so
    dropping the assignment here can never re-permit the device — it only tidies
    policy. Returns the committed document.
    """
    def _mutate(candidate):
        candidate.get("assignments", {}).pop(device_id, None)
        _set_quarantine_membership(candidate, device_id, False)
        roles = candidate.get("roles")
        if isinstance(roles, dict):
            role_of = roles.get("role_of")
            if isinstance(role_of, dict):
                role_of.pop(device_id, None)
            qos_device = roles.get("qos_device")
            if isinstance(qos_device, dict):
                qos_device.pop(device_id, None)

    return commit_mutation(
        auth_path, lkg_path, action="unassign", target=device_id,
        actor=actor, now=now, mutate=_mutate, acked_revision=acked_revision)
