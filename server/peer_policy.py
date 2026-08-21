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
authoritative** policy to ``peer-policy.lkg.json`` first, then atomically
replaces ``peer-policy.json`` with the candidate — the atomic replace is the
commit; an uncommitted candidate is never loadable and never lands in LKG.

Read precedence (spec 7): valid authoritative always wins; corrupt authoritative
with a valid LKG uses the prior LKG and marks ``degraded``; both corrupt while
the files exist yields ``fail_closed`` (no candidates); neither file present
materializes the validated base (open discovery).

Principals are accepted structurally so this module stays decoupled from the
identity lane; integration passes the real ``auth.Principal`` unchanged.
"""
import collections
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import secrets
import tempfile

SCHEMA = 1
MAX_ACLS = 64
MAX_RULES_PER_ACL = 256
OUTBOX_CAP = 256
RESERVED_QUARANTINE = "quarantine"

_ACL_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ACTIONS = ("permit", "deny")
_MATCH_TYPES = ("device", "service", "host", "cidr", "any")

_QUARANTINE_RULES = [{"seq": 10, "action": "deny", "match": {"type": "any"}}]


class PolicyError(ValueError):
    """Raised when a policy document fails schema/bounds/immutability checks."""


class OperationBacklogFull(Exception):
    """Raised when 256 unacknowledged outbox operations block a mutation."""


class RevisionConflict(Exception):
    """Raised when an optimistic mutation does not match the live revision."""

    def __init__(self, revision):
        self.revision = revision
        super().__init__("policy revision conflict")


PolicyResult = collections.namedtuple(
    "PolicyResult", ["document", "degraded", "fail_closed"])


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


def ensure_reserved(doc):
    """Materialize the reserved quarantine ACL if absent (spec 7)."""
    acls = doc.setdefault("acls", {})
    q = acls.get(RESERVED_QUARANTINE)
    if q is None or q.get("reserved") is not True \
            or q.get("rules") != _QUARANTINE_RULES:
        acls[RESERVED_QUARANTINE] = {
            "reserved": True,
            "description": "reserved: fully isolate an assigned device",
            "rules": [dict(r) for r in _QUARANTINE_RULES]}
    return doc


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


def validate_document(doc):
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
    seeder = doc.get("seeder_assignment")
    if seeder is not None and seeder not in acls:
        raise PolicyError("seeder assignment to unknown acl")
    outbox = doc.get("operation_outbox")
    if not isinstance(outbox, list) or len(outbox) > OUTBOX_CAP:
        raise PolicyError("bad operation_outbox")
    return doc


# ---------------------------------------------------------------------------
# Pure evaluator
# ---------------------------------------------------------------------------

def _assigned_acl(doc, principal):
    """Return the ACL bound to ``principal`` or ``None``. Only device and
    service principals have an assignment slot; legacy has none (spec 0a)."""
    if principal.type == "device":
        name = doc.get("assignments", {}).get(principal.id)
    elif principal.type == "service":
        name = doc.get("seeder_assignment")
    else:  # legacy
        return None
    if name is None:
        return None
    return doc.get("acls", {}).get(name)


def _rule_matches(rule, principal, ipv4):
    match = rule["match"]
    mtype = match["type"]
    if mtype == "any":
        return True
    if mtype == "device":
        return principal.type == "device" and principal.id == match["value"]
    if mtype == "service":
        return principal.type == "service" and principal.id == match["value"]
    if mtype == "host":
        return ipv4 == match["value"]
    if mtype == "cidr":
        try:
            return ipaddress.IPv4Address(ipv4) in ipaddress.IPv4Network(
                match["value"], strict=False)
        except (ipaddress.AddressValueError, ValueError):
            return False
    return False


def evaluate(doc, principal, ipv4):
    """Evaluate ``principal`` + ``ipv4`` against its assigned ACL. Returns
    ``(decision, matched_seq)``; no match is ``("permit", None)``."""
    acl = _assigned_acl(doc, principal)
    if acl is None:
        return ("permit", None)
    for rule in sorted(acl["rules"], key=lambda r: r["seq"]):
        if _rule_matches(rule, principal, ipv4):
            return (rule["action"], rule["seq"])
    return ("permit", None)


def mutual_permit(doc, requester_principal, requester_ipv4,
                  candidate_principal, candidate_ipv4):
    """True iff the requester's ACL permits the candidate AND the candidate's
    ACL permits the requester (spec 7). A ``fail_closed`` sentinel document
    (see :func:`load_policy`) denies all mutual discovery."""
    if doc.get("_fail_closed"):
        return False
    req = evaluate(doc, candidate_principal, candidate_ipv4)[0]
    cand = evaluate(doc, requester_principal, requester_ipv4)[0]
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


def load_policy(auth_path, lkg_path):
    """Resolve the active :class:`PolicyResult` honoring read precedence.

    - Neither file exists -> materialize the validated base to both (open
      discovery), ``degraded=False``, ``fail_closed=False``.
    - Valid authoritative -> use it, not degraded.
    - Corrupt authoritative + valid LKG -> use LKG, ``degraded=True``.
    - Both corrupt while a file exists -> ``fail_closed=True`` (no candidates).
    """
    auth_exists = os.path.exists(auth_path)
    lkg_exists = os.path.exists(lkg_path)
    if not auth_exists and not lkg_exists:
        initialize(auth_path, lkg_path)
        return PolicyResult(base_document(), degraded=False, fail_closed=False)
    authoritative = _read_valid(auth_path)
    if authoritative is not None:
        return PolicyResult(authoritative, degraded=False, fail_closed=False)
    lkg = _read_valid(lkg_path)
    if lkg is not None:
        return PolicyResult(lkg, degraded=True, fail_closed=False)
    return PolicyResult(_fail_closed_document(), degraded=True,
                        fail_closed=True)


# ---------------------------------------------------------------------------
# Commit transaction + outbox
# ---------------------------------------------------------------------------

def _new_event_id():
    return secrets.token_hex(8)  # nonsecret 16 hex chars


def _prune_acked(outbox, acked_revision):
    return [e for e in outbox if e["revision"] > acked_revision]


def commit_mutation(auth_path, lkg_path, action, target, actor, now,
                    mutate, acked_revision=0, expected_revision=None):
    """Commit one policy mutation under a single umbrella flock (spec 7).

    Loads and validates the current committed authoritative, prunes outbox
    entries at/below ``acked_revision``, and — if 256 unacked entries remain —
    raises :class:`OperationBacklogFull` before any write. Otherwise applies
    ``mutate(candidate)``, increments ``revision``, appends a stable outbox
    entry, validates the candidate, writes the **prior committed authoritative**
    to LKG first, then atomically replaces the authoritative file with the
    candidate (the atomic replace is the commit).
    """
    with _umbrella_lock(auth_path):
        prior = _read_valid(auth_path)
        if prior is None:
            prior = base_document()
            _atomic_write_json(auth_path, prior)
        if expected_revision is not None and prior["revision"] != expected_revision:
            raise RevisionConflict(prior["revision"])
        outbox = _prune_acked(list(prior.get("operation_outbox", [])),
                              acked_revision)
        if len(outbox) >= OUTBOX_CAP:
            raise OperationBacklogFull("256 unacknowledged operations")

        candidate = json.loads(json.dumps(prior))  # deep copy
        candidate["operation_outbox"] = outbox
        mutate(candidate)
        candidate["revision"] = prior["revision"] + 1
        candidate["operation_outbox"].append({
            "event_id": _new_event_id(),
            "revision": candidate["revision"],
            "action": action, "target": target, "actor": actor,
            "created_at": float(now)})
        validate_document(candidate)

        # LKG = prior committed authoritative (never the candidate)
        _atomic_write_json(lkg_path, prior)
        # commit
        _atomic_write_json(auth_path, candidate)
        return candidate


def pending_exports(doc, exported_revision):
    """Outbox entries with ``revision > exported_revision``, in revision order
    (at-least-once; re-exportable, never lost)."""
    return sorted((e for e in doc.get("operation_outbox", [])
                   if e["revision"] > exported_revision),
                  key=lambda e: e["revision"])


def unassign_device(auth_path, lkg_path, device_id, actor, now,
                    acked_revision=0):
    """Remove ``device_id``'s ACL assignment as a system cleanup action (spec §7
    retirement). Safe/optimistic: a no-op mutation (device not assigned) still
    commits a revision so the outbox records the cleanup; the reserved
    quarantine ACL is never touched. Runs under the same umbrella lock and
    preserves the operation outbox via :func:`commit_mutation`.

    This is the device-retirement counterpart to an operator assignment: after a
    device's secrets are durably revoked, its endpoint rows are retained and the
    revoked-credential principal is derived-denied regardless of assignment, so
    dropping the assignment here can never re-permit the device — it only tidies
    policy. Returns the committed document.
    """
    def _mutate(candidate):
        candidate.get("assignments", {}).pop(device_id, None)

    return commit_mutation(
        auth_path, lkg_path, action="unassign", target=device_id,
        actor=actor, now=now, mutate=_mutate, acked_revision=acked_revision)
