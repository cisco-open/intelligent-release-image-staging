# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure blocklist reconciler derivation and aria2 apply (spec 5 / 7 / 13).

The tracker is the ONLY reconciler and the ONLY writer of the aria2 blocklist
RPC (spec 0); this module holds the pure derivation and the apply/ack logic it
calls. Nothing here shares in-memory state across processes.

Derivation modes:

- **Valid-policy mode.** Derive the complete denied-IP set from durable policy +
  all fresh durable and pending attributable endpoints, considering all fresh
  permitted and denied principals, always excluding the protected current
  non-legacy service-seeder address. A principal whose credentials are all
  revoked is derived-denied regardless of policy. A shared permit/deny IP is
  **not** globally blocked (a conflict is recorded, ``global_block_applied``
  false). A valid empty policy applies an empty list — the only empty apply.

- **fail_closed mode.** Never clears existing blocks; derives an emergency deny
  list from every fresh attributable non-service endpoint (device/legacy) plus
  every active/pending non-seeder/non-legacy endpoint, excluding only the
  protected current non-legacy service-seeder address, and applies the full list
  on fresh sessions/recovery. If no address is known, it stays fail-closed with
  no false enforcement claim (``apply_empty`` is False, so nothing is applied).

Acknowledgement (spec 13): success = a non-error RPC return for the desired
canonical set in the current aria session. The returned revision and effect
counters are audit signals, never the success authority.
"""
import collections
import hashlib
import ipaddress

import peer_policy

DerivedSet = collections.namedtuple(
    "DerivedSet",
    ["denied_ips", "conflicts", "apply_empty", "fail_closed",
     "prospective_denied_ips", "prospective_conflicts",
     "newly_denied_device_ids"],
    defaults=((), (), ()))

ApplyOutcome = collections.namedtuple(
    "ApplyOutcome", ["applied", "success", "aria_session_id", "desired_hash",
                     "applied_revision", "last_effect", "last_error"])

_SESSION_UNSET = object()


def _endpoint_ips(snapshot):
    """Yield (key, principal_type, principal_id, ipv4) for every endpoint in a
    fresh-endpoints-style snapshot (durable or pending)."""
    for key, entry in snapshot.items():
        for ep in entry.get("endpoints", []):
            yield (key, entry["principal_type"], entry["principal_id"],
                   ep["ipv4"])


class _Struct:
    __slots__ = ("type", "id")

    def __init__(self, type_, id_):
        self.type = type_
        self.id = id_


def derive_denied_set(policy_result, durable_endpoints, pending_endpoints,
                      active_participants, revoked_principals,
                      protected_seeder_ip):
    """Return a :class:`DerivedSet` (spec 5). ``policy_result`` is a
    :class:`peer_policy.PolicyResult`; ``*_endpoints`` are fresh-endpoints-style
    snapshots; ``active_participants`` is a list of
    ``{principal_type, principal_id, ipv4}``; ``revoked_principals`` is a set of
    ``"<type>:<id>"`` keys whose credentials are all revoked."""
    if policy_result.fail_closed:
        return _derive_emergency(
            durable_endpoints, pending_endpoints, active_participants,
            protected_seeder_ip)
    return _derive_valid(
        policy_result, durable_endpoints, pending_endpoints,
        revoked_principals, protected_seeder_ip)


def denied_retention(policy_result, revoked_principals):
    """Endpoint-row retention predicate for ``peer_endpoints.fresh_endpoints``
    / ``prune`` (``keep(principal_type, principal_id, ipv4) -> bool``).

    A row is kept past ``ENDPOINT_TTL`` while its principal is revoked or
    while the current valid policy denies that principal at that address
    (its own ACL -- the quarantine assignment). Without this the seeder block
    for a quarantined or revoked device lapsed 15 minutes after its last
    attributable announce, i.e. exactly when the device stopped cooperating;
    the device still holds the seeder's address and the info_hash and needs
    no tracker to connect. The row ages out normally once the device is
    un-quarantined, and ``clear_principal`` drops it on re-onboard."""
    revoked = set(revoked_principals or ())
    doc = policy_result.document
    compiled = policy_result.roles or peer_policy.compile_roles(doc)

    def keep(ptype, pid, ipv4):
        if "%s:%s" % (ptype, pid) in revoked:
            return True
        if policy_result.fail_closed:
            return False
        return peer_policy.evaluate(
            doc, _Struct(ptype, pid), ipv4,
            compiled=compiled)[0] == "deny"
    return keep


def denied_endpoint_ips(policy_result, durable_endpoints, revoked_principals):
    """Every address a durable endpoint row attributes to a DEVICE principal
    that is revoked or that the policy denies at that address.

    Unlike :func:`derive_denied_set` this ignores shared permit/deny
    conflicts and the protected seeder address: it answers the fail-closed
    question the tracker asks before a ``legacy`` credential (a previous
    seeder token, which any device that ever received a torrent carrying it
    still holds) may discover peers or be discovered -- "did a quarantined or
    revoked device announce from this address?"."""
    revoked = set(revoked_principals or ())
    doc = policy_result.document
    compiled = policy_result.roles or peer_policy.compile_roles(doc)
    out = set()
    for key, ptype, pid, ip in _endpoint_ips(durable_endpoints):
        if ptype != "device":
            continue
        if key in revoked or (not policy_result.fail_closed and
                              peer_policy.evaluate(
                                  doc, _Struct(ptype, pid), ip,
                                  compiled=compiled)[0] == "deny"):
            out.add(ip)
    return out


def _resolved_set(denied_by_ip, permitted_by_ip):
    """Resolve shared-address conflicts for one independent classification."""
    denied_ips = []
    conflicts = []
    for ip in sorted(denied_by_ip):
        if ip in permitted_by_ip:
            denied_key = sorted(denied_by_ip[ip])[0]
            permitted_key = sorted(permitted_by_ip[ip])[0]
            dt, di = denied_key.split(":", 1)
            pt, pi = permitted_key.split(":", 1)
            conflicts.append({
                "ipv4": ip, "reason": "shared_permit_deny",
                "permitted_principal_type": pt, "permitted_principal_id": pi,
                "denied_principal_type": dt, "denied_principal_id": di,
                "global_block_applied": False})
            continue
        denied_ips.append(ip)
    return denied_ips, conflicts


def _derive_valid(policy_result, durable_endpoints, pending_endpoints,
                  revoked_principals, protected_seeder_ip):
    doc = policy_result.document
    compiled = policy_result.roles or peer_policy.compile_roles(doc)
    seeder = _Struct("service", "seeder")
    revoked_principals = set(revoked_principals or ())
    # Merge durable + pending; a key present in both contributes both IPs.
    current_denied_by_ip = {}
    current_permitted_by_ip = {}
    prospective_denied_by_ip = {}
    prospective_permitted_by_ip = {}
    device_ids_by_ip = {}
    for snapshot in (durable_endpoints, pending_endpoints):
        for key, ptype, pid, ip in _endpoint_ips(snapshot):
            if ip == protected_seeder_ip:
                continue  # protected service-seeder address never blocked
            principal = _Struct(ptype, pid)
            revoked = key in revoked_principals
            decision = peer_policy.evaluate(
                doc, principal, ip, compiled=compiled)[0]
            current_denied = revoked or decision == "deny"
            if current_denied:
                current_denied_by_ip.setdefault(ip, set()).add(key)
            else:
                current_permitted_by_ip.setdefault(ip, set()).add(key)

            prospective_denied = current_denied or not peer_policy.mutual_permit(
                doc, seeder, protected_seeder_ip, principal, ip,
                compiled=compiled)
            if prospective_denied:
                prospective_denied_by_ip.setdefault(ip, set()).add(key)
            else:
                prospective_permitted_by_ip.setdefault(ip, set()).add(key)
            if ptype == "device":
                device_ids_by_ip.setdefault(ip, set()).add(pid)

    denied_ips, conflicts = _resolved_set(
        current_denied_by_ip, current_permitted_by_ip)
    prospective_denied_ips, prospective_conflicts = _resolved_set(
        prospective_denied_by_ip, prospective_permitted_by_ip)
    newly_denied_ips = set(prospective_denied_ips) - set(denied_ips)
    newly_denied_device_ids = sorted({
        device_id for ip in newly_denied_ips
        for device_id in device_ids_by_ip.get(ip, ())})
    # valid policy always applies (valid-empty is a real apply)
    return DerivedSet(denied_ips=sorted(denied_ips), conflicts=conflicts,
                      apply_empty=True, fail_closed=False,
                      prospective_denied_ips=sorted(prospective_denied_ips),
                      prospective_conflicts=prospective_conflicts,
                      newly_denied_device_ids=newly_denied_device_ids)


def _derive_emergency(durable_endpoints, pending_endpoints,
                      active_participants, protected_seeder_ip):
    ips = set()
    # every fresh attributable non-service endpoint (durable/pending)
    for snapshot in (durable_endpoints, pending_endpoints):
        for _key, ptype, _pid, ip in _endpoint_ips(snapshot):
            if ptype == "service":
                continue
            if ip == protected_seeder_ip:
                continue
            ips.add(ip)
    # every active/pending non-seeder/non-legacy... spec: active non-service
    for p in active_participants:
        ptype = p.get("principal_type")
        ip = p.get("ipv4")
        if not ip or ip == protected_seeder_ip:
            continue
        if ptype == "service":
            continue
        ips.add(ip)
    denied = sorted(ips)
    # If no address is known, nothing is applied -> no false success. Otherwise
    # the full emergency list is applied on fresh sessions/recovery.
    return DerivedSet(denied_ips=denied, conflicts=[],
                      apply_empty=bool(denied), fail_closed=True,
                      prospective_denied_ips=[], prospective_conflicts=[],
                      newly_denied_device_ids=[])


# ---------------------------------------------------------------------------
# Canonicalization / hashing / apply
# ---------------------------------------------------------------------------

def canonical_hash(denied_ips):
    """Stable hash of the sorted, normalized desired rule set (spec 13)."""
    canonical = "\n".join(sorted(set(denied_ips)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _validate_ips(denied_ips):
    for ip in denied_ips:
        ipaddress.IPv4Address(ip)  # raises ValueError on a bad rule


def _safe_session_id(aria):
    """Probe the aria session id without ever letting a transport exception —
    whose message may embed the RPC secret — escape or be recorded. Only the
    successful session string is returned; any failure yields ``None`` (the
    exception, and therefore any secret in it, is dropped)."""
    try:
        return aria.get_session_id()
    except Exception:
        return None


def apply_blocklist(aria, denied_ips, apply_empty, session_id=_SESSION_UNSET):
    """Full-replace apply of the desired list via ``aria.set_blocklist`` (spec
    5/13). Validates every IP first (one bad rule rejects the whole call). When
    there is nothing to apply and ``apply_empty`` is False (fail-closed, no known
    address), the RPC is never called and no success is claimed.

    Success = the RPC returned without error for the desired canonical set in the
    current aria session; the returned revision and effect counters are audit
    signals only.
    """
    _validate_ips(denied_ips)
    ordered = sorted(set(denied_ips))
    desired_hash = canonical_hash(ordered)

    if not ordered and not apply_empty:
        return ApplyOutcome(
            applied=False, success=False, aria_session_id=None,
            desired_hash=desired_hash, applied_revision=None,
            last_effect=None, last_error=None)

    session = (_safe_session_id(aria) if session_id is _SESSION_UNSET
               else session_id)
    try:
        ret = aria.set_blocklist(ordered)
    except Exception as exc:  # RPC failure is never success / never permit-all
        return ApplyOutcome(
            applied=True, success=False, aria_session_id=session,
            desired_hash=desired_hash, applied_revision=None,
            last_effect=None, last_error=type(exc).__name__)

    return ApplyOutcome(
        applied=True, success=True, aria_session_id=session,
        desired_hash=desired_hash,
        applied_revision=ret.get("revision"),
        last_effect={"disconnected_peers": ret.get("disconnectedPeers", 0),
                     "removed_peers": ret.get("removedPeers", 0)},
        last_error=None)
