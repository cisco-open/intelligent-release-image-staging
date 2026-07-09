# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Token auth shared by the tracker (announce ?key=) and catalog (Bearer header).
Tokens live one-per-line in a file; '#' comments and blank lines are ignored.
Matching is constant-time via hmac.compare_digest.

Phase 1A additions:
  - authorize(index, store, token, device_id, scope, now, grace)
  - check_announce_key updated to accept BOTH legacy (query, tokens_set) AND
    new (query, index, store, now, grace) — existing callers are unaffected.
"""
import hmac
from urllib.parse import parse_qs

import secrets_store as _ss


def load_tokens(path):
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return set()
    out = set()
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def _any_match(candidate, tokens):
    for t in tokens:
        if hmac.compare_digest(candidate, t):
            return t
    return None


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


def check_announce_key(query, tokens_or_index, store=None, now=None, grace=None):
    """Check whether the ?key= in *query* is a valid announce token.

    Two call signatures:
      Legacy:  check_announce_key(query, tokens_set)
      New:     check_announce_key(query, index, store, now, grace)

    The new form looks up the key in the secrets store and validates scope
    "announce" + expiry/revoke state.  The legacy form uses _any_match over
    a plain set (backward-compatible for existing callers).
    """
    key = parse_qs(query).get("key", [None])[0]
    if key is None:
        return False

    # New store-backed path: store is not None
    if store is not None:
        index = tokens_or_index
        result = _ss.record_for(index, store, key)
        if result is None:
            return False
        # announce auth is scope-only: the tracker announce carries no device_id, so (unlike authorize) we don't bind to a device — just require a valid, non-revoked announce-scoped token.
        _, secret_name, record = result
        if not _ss.valid(record, now, grace):
            return False
        stype = _ss.SECRET_TYPES.get(secret_name)
        if stype is None:
            return False
        return stype["scope"] == "announce"

    # Legacy path: tokens_or_index is a plain set
    return _any_match(key, tokens_or_index) is not None


def check_bearer(headers, tokens):
    value = headers.get("Authorization", "")
    prefix = "Bearer "
    if not value.startswith(prefix):
        return None
    return _any_match(value[len(prefix):], tokens)
