# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Token auth shared by tracker and catalog.

New agents carry credentials in Authorization headers.  The tracker also keeps
the previous query-token resolver solely for unchanged Guest Shell bundles;
both paths use a digest-keyed, collision-detecting index and verify the matched
credential with a constant-time comparison.
"""
from typing import NamedTuple
from urllib.parse import parse_qs, parse_qsl

import secrets_store as _ss


class Principal(NamedTuple):
    """A typed authenticated identity (spec §0a).

    Never a bare string, so a device literally named ``seeder``
    (``Principal("device", "seeder")``) can never collide with the service
    seeder (``Principal("service", "seeder")``). Types:

      * ``device``  — an announce/catalog credential owned by a fleet device.
      * ``service`` — the current, non-legacy seeder credential (id ``seeder``).
      * ``legacy``  — a previous/legacy announce token; ``id`` is a nonsecret
        endpoint-derived key set at tracker integration, never a token value.
    """
    type: str
    id: str


class AuthContext(NamedTuple):
    """Resolved typed authentication result (spec §6).

    Carries the typed principal, the owning secret name, and the auth scope. It
    never carries the token value or the record, so it is safe to log/audit.
    """
    principal: Principal
    secret_name: str
    scope: str


class AnnounceAuthError(Exception):
    """Announce credential resolution failed (ambiguous / invalid / none).

    Maps to a tracker 403. The message is deliberately token-free — no announce
    token value, record, or query URL is ever included.

    ``expired`` classifies the refusal for metrics only (IRIS-111): True iff
    at least one presented credential value resolved to a KNOWN record (not
    revoked) that failed validity solely because ``now`` is past its
    ``expires_at`` + grace -- as opposed to a value absent from the index
    entirely (bogus/unknown) or a revoked record. It never affects the
    refusal itself, which stays exactly as strict either way; it only lets a
    caller count "a real, expired credential was presented" separately from
    "someone sent garbage" -- see tracker.py's on_announce_refused and
    metrics.py's iris_tracker_announces_refused_expired_total.
    """
    expired = False


# Query parameter names (spec §6): IRIS carries its credential in a DEDICATED
# `announce_token=` param, distinct from aria2's BEP-style `key=`.
_DEDICATED_PARAM = "announce_token"
_LEGACY_PARAM = "key"


def _raw_pairs(query):
    """All (name, value) query pairs, blanks preserved, order kept.

    Uses keep_blank_values so a blank `announce_token=` is a real occurrence —
    never collapsed away as parse_qs(...)[0] would.
    """
    return parse_qsl(query, keep_blank_values=True)


def _resolve_valid_credential(index, store, value, now, grace):
    """Return (Principal, secret_name, legacy_bool) for a valid, non-revoked
    announce credential, or None. Raises nothing (index built by caller).

    *store* is unused here (the *index* already carries the resolved record);
    it is retained only to keep the positional signature stable for existing
    callers/tests. Do not rely on it for resolution."""
    entry = _ss.credential_for(index, value)
    if entry is None:
        return None
    principal, secret_name, record, legacy = entry
    if not _ss.valid(record, now, grace):
        return None
    return (principal, secret_name, legacy)


def _known_expired(index, value, now, grace):
    """True iff *value* resolves to a KNOWN, non-revoked record whose only
    reason for failing _resolve_valid_credential is that it has expired.

    Classification only (IRIS-111): re-derives the same lookup
    _resolve_valid_credential already did, purely to distinguish "a real
    credential that timed out" from "unknown/garbage" or "revoked" for the
    refused-announce counters. Never influences the auth decision itself,
    and never returns or logs the value."""
    entry = _ss.credential_for(index, value)
    if entry is None:
        return False
    _principal, _secret_name, record, _legacy = entry
    if record.get("revoked"):
        return False
    expires_at = record.get("expires_at", 0)
    if expires_at == 0:
        return False
    return now >= expires_at + grace


def resolve_announce_principal(query, index, store, now=None, grace=None,
                               legacy_id=None):
    """Resolve the announce credential in *query* to a typed AuthContext.

    *index* must be the strict announce index (secrets_store.build_announce_index);
    it already raises token-free on duplicate value ownership. Resolution order
    follows spec §6 exactly (see module docstring of the resolver tests).

    A legacy (previous-token) credential resolves to a ``legacy`` principal whose
    id is *legacy_id* (an endpoint-derived nonsecret key supplied at tracker
    integration); when unknown the id is left empty. Raises AnnounceAuthError
    (token-free) on any ambiguous/invalid/absent outcome.

    *store* is unused (resolution is driven entirely by *index*); it is kept only
    to preserve the positional signature for existing callers.
    """
    now = 0 if now is None else now
    grace = 0 if grace is None else grace

    pairs = _raw_pairs(query)
    dedicated = [v for (k, v) in pairs if k == _DEDICATED_PARAM]

    # Step 1: two or more dedicated occurrences (blank or not) -> ambiguous.
    if len(dedicated) >= 2:
        raise AnnounceAuthError("ambiguous announce credential: "
                                "multiple announce_token parameters")

    # Step 2: exactly one non-blank dedicated -> resolve ONLY that value.
    if len(dedicated) == 1 and dedicated[0] != "":
        resolved = _resolve_valid_credential(
            index, store, dedicated[0], now, grace)
        if resolved is None:
            err = AnnounceAuthError("invalid announce credential")
            err.expired = _known_expired(index, dedicated[0], now, grace)
            raise err
        return _context(resolved, legacy_id)

    # Step 3: exactly one blank dedicated OR no dedicated -> legacy scan.
    # Step 4: legacy `key=` scan — accept iff exactly one unique valid value.
    legacy_values = {v for (k, v) in pairs if k == _LEGACY_PARAM and v != ""}
    valid_hits = {}
    for value in legacy_values:
        resolved = _resolve_valid_credential(index, store, value, now, grace)
        if resolved is not None:
            valid_hits[value] = resolved
    if len(valid_hits) == 1:
        (resolved,) = valid_hits.values()
        return _context(resolved, legacy_id)
    if len(valid_hits) == 0:
        err = AnnounceAuthError("no valid announce credential")
        err.expired = any(_known_expired(index, v, now, grace)
                          for v in legacy_values)
        raise err
    raise AnnounceAuthError("ambiguous announce credential: "
                            "multiple valid legacy keys")


def _context(resolved, legacy_id):
    principal, secret_name, legacy = resolved
    if legacy:
        return AuthContext(Principal("legacy", legacy_id or ""),
                           secret_name, "announce")
    return AuthContext(principal, secret_name, "announce")


def resolve_catalog_auth(store, index, token, now, grace):
    """Resolve *token* to a validated catalog ``AuthContext`` or ``None``.

    *index* is the STRICT catalog auth index
    (``secrets_store.build_catalog_auth_index``): a mapping
    ``{digest: (Principal, secret_name, record)}`` that already fails token-free
    on duplicate value ownership. This is the sole catalog authorization
    surface (spec §6) — never the broad ``secrets_store.build_index``.

    Resolution validates the actual live record from the strict index for
    expiry/revoke via ``secrets_store.valid`` and returns a typed
    ``AuthContext`` (scope ``"catalog"``) that never carries the token value or
    the record. Default-deny: a token-free/absent/invalid lookup returns None.

    *store* is retained for signature/parity with the announce resolvers; the
    strict index already carries the live record, so resolution is driven
    entirely by *index*.
    """
    entry = _ss.credential_for(index, token)
    if entry is None:
        return None
    principal, secret_name, record = entry
    if not _ss.valid(record, now, grace):
        return None
    return AuthContext(principal=principal, secret_name=secret_name,
                       scope="catalog")


def resolve_announce_bearer(token, index, store, now=None, grace=None,
                            legacy_id=None):
    """Resolve a header-carried announce credential without scanning the fleet.

    The strict digest index selects at most one record, whose live credential
    is verified before checking expiry, revocation, and principal scope.
    """
    now = 0 if now is None else now
    grace = 0 if grace is None else grace
    if not isinstance(token, str) or not token:
        raise AnnounceAuthError("missing announce credential")
    hit = _ss.credential_for(index, token)
    if hit is None:
        raise AnnounceAuthError("invalid announce credential")
    principal, secret_name, record, legacy = hit
    if not _ss.valid(record, now, grace):
        err = AnnounceAuthError("invalid announce credential")
        expires_at = record.get("expires_at", 0)
        err.expired = bool(
            not record.get("revoked") and expires_at != 0
            and now >= expires_at + grace)
        raise err
    return _context((principal, secret_name, legacy), legacy_id)


def authorize(index, store, token, device_id, scope, now, grace):
    """Return True iff *token* is valid for *device_id* with *scope*.

    Checks (in order):
      1. token exists in *index* (record_for)
      2. record is not expired / revoked (valid)
      3. record's device_id matches *device_id*
      4. SECRET_TYPES[secret_name]["scope"] == scope

    Default-deny: any lookup failure returns False.
    """
    result = _ss.record_for(index, store, token)
    if result is None:
        return False
    rec_device_id, secret_name, record = result
    if not _ss.valid(record, now, grace):
        return False
    if rec_device_id != device_id:
        return False
    stype = _ss.SECRET_TYPES.get(secret_name)
    if stype is None:
        return False
    return stype["scope"] == scope


def check_announce_key(query, index, store, now=None, grace=None):
    """Check whether the ?key= in *query* is a valid announce token.

    Looks the key up in the secrets store and validates scope "announce" plus
    expiry/revoke state. Announce auth is scope-only: the tracker announce
    carries no device_id, so (unlike authorize) we don't bind to a device —
    just require a valid, non-revoked announce-scoped token.
    """
    key = parse_qs(query).get("key", [None])[0]
    if key is None:
        return False
    result = _ss.record_for(index, store, key)
    if result is None:
        return False
    _, secret_name, record = result
    if not _ss.valid(record, now, grace):
        return False
    stype = _ss.SECRET_TYPES.get(secret_name)
    if stype is None:
        return False
    return stype["scope"] == "announce"
