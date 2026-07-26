# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Token auth shared by the tracker (announce ?key=) and catalog (Bearer header).
Tokens are resolved via the secrets store's reverse index — a dict keyed by the
random token value (secrets_store.record_for) — then validated for scope and
expiry/revoke state."""
from urllib.parse import parse_qs

import secrets_store as _ss


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
