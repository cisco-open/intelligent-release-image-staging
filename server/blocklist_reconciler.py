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
    "DerivedSet", ["denied_ips", "conflicts", "apply_empty", "fail_closed"])

ApplyOutcome = collections.namedtuple(
    "ApplyOutcome", ["applied", "success", "aria_session_id", "desired_hash",
                     "applied_revision", "last_effect", "last_error"])


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
        policy_result.document, durable_endpoints, pending_endpoints,
        revoked_principals, protected_seeder_ip)


def _derive_valid(doc, durable_endpoints, pending_endpoints,
                  revoked_principals, protected_seeder_ip):
    # Merge durable + pending; a key present in both contributes both IPs.
    denied_by_ip = {}   # ip -> set of denied principal keys
    permitted_by_ip = {}  # ip -> set of permitted principal keys
    for snapshot in (durable_endpoints, pending_endpoints):
        for key, ptype, pid, ip in _endpoint_ips(snapshot):
            if ip == protected_seeder_ip:
                continue  # protected service-seeder address never blocked
            principal = _Struct(ptype, pid)
            revoked = key in revoked_principals
            decision = peer_policy.evaluate(doc, principal, ip)[0]
            if revoked or decision == "deny":
                denied_by_ip.setdefault(ip, set()).add(key)
            else:
                permitted_by_ip.setdefault(ip, set()).add(key)

    denied_ips = []
    conflicts = []
    for ip in sorted(denied_by_ip):
        if ip in permitted_by_ip:
            # shared permit/deny -> skip global block, record conflict
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
    # valid policy always applies (valid-empty is a real apply)
    return DerivedSet(denied_ips=sorted(denied_ips), conflicts=conflicts,
                      apply_empty=True, fail_closed=False)


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
                      apply_empty=bool(denied), fail_closed=True)


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


def apply_blocklist(aria, denied_ips, apply_empty):
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

    session = aria.get_session_id()
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
