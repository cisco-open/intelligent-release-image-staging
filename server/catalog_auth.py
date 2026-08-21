# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Typed catalog authorization context and strict credential indexes.

This module provides the *strict, collision-detecting* authorization surface
the catalog uses for every authorization decision (spec §6): a typed
``Principal``, an ``AuthContext``, and ``build_catalog_auth_index`` /
``build_announce_index`` that **fail token-free on duplicate value ownership**
rather than silently overwriting a dict key.

Compatibility note (branch integration): the final identity lane may land its
own ``auth.Principal`` / ``auth.AuthContext`` and
``secrets_store.build_catalog_auth_index`` / ``build_announce_index``. This
module is intentionally the single, importable home for those on the torrent
lane; when the identity lane lands, catalog.py's import can be re-pointed at the
reconciled location without changing behavior. It does NOT re-implement token
validation — it reuses ``secrets_store.valid`` and the existing record shapes.

Stdlib only; pure functions (no I/O)."""
import collections

import secrets_store as _ss


class DuplicateCredentialError(Exception):
    """Raised when two distinct records share the same secret value.

    A silent dict overwrite could mis-attribute a principal, so every strict
    index raises this instead. The message never contains a token value."""


Principal = collections.namedtuple("Principal", ["type", "id"])
"""A typed authenticated principal.

``type`` is one of ``"device"``, ``"service"``, ``"legacy"``; ``id`` is the
device id, the service id (``"seeder"``), or a nonsecret endpoint-derived key
for legacy participants (spec §0a)."""


AuthContext = collections.namedtuple(
    "AuthContext", ["principal", "secret_name", "scope"])
"""Resolved authorization result for a catalog request (spec §6)."""


# Catalog-scoped secret names recognized by the strict catalog auth index.
# ``catalog_token_prev`` is the overlap-window stash written by
# _handle_token_refresh; it carries no SECRET_TYPES entry and declares its scope
# via the record's ``_scope`` field.
_CATALOG_SECRET_NAMES = ("catalog_token", "catalog_token_prev")


def _record_scope(secret_name, record):
    stype = _ss.SECRET_TYPES.get(secret_name, {})
    return stype.get("scope") or record.get("_scope", "")


def build_catalog_auth_index(store):
    """Return ``{value: AuthContext}`` for every catalog-scoped credential.

    Covers device ``catalog_token`` and ``catalog_token_prev`` for each device.
    The seeder pseudo-device holds no catalog token, so it is not indexed here.

    Raises ``DuplicateCredentialError`` if two records share a value (hard
    auth/config error — never a silent overwrite). No token value appears in
    the error."""
    index = {}
    for device_id, secrets_dict in store.get("devices", {}).items():
        for secret_name, record in secrets_dict.items():
            if secret_name not in _CATALOG_SECRET_NAMES:
                continue
            value = record.get("value")
            if value is None:
                continue
            scope = _record_scope(secret_name, record)
            if scope != "catalog":
                continue
            if value in index:
                raise DuplicateCredentialError(
                    "duplicate catalog credential value ownership")
            index[value] = AuthContext(
                principal=Principal("device", device_id),
                secret_name=secret_name,
                scope="catalog")
    return index


def resolve_catalog_auth(store, index, token, now, grace):
    """Resolve *token* to a validated ``AuthContext`` or ``None``.

    Uses the strict catalog auth *index*; validates the live record for
    expiry/revoke via ``secrets_store.valid``. Default-deny."""
    ctx = index.get(token)
    if ctx is None:
        return None
    device_secrets = store.get("devices", {}).get(ctx.principal.id, {})
    record = device_secrets.get(ctx.secret_name)
    if record is None:
        return None
    if not _ss.valid(record, now, grace):
        return None
    return ctx


def build_announce_index(store):
    """Return ``{value: (Principal, secret_name, record, legacy_bool)}``.

    Covers device ``announce_token`` records (legacy=False), the seeder
    **current** ``announce_token`` (service:seeder, legacy=False), and every
    seeder ``announce_token_previous`` record (service:seeder,
    ``announce_token_previous``, legacy=True) if present (spec §6 seeder
    overlap). Returns live record objects so validity is checked at use time.

    Raises ``DuplicateCredentialError`` on duplicate value ownership."""
    index = {}

    def _put(value, entry):
        if value is None:
            return
        if value in index:
            raise DuplicateCredentialError(
                "duplicate announce credential value ownership")
        index[value] = entry

    for device_id, secrets_dict in store.get("devices", {}).items():
        rec = secrets_dict.get("announce_token")
        if isinstance(rec, dict):
            _put(rec.get("value"),
                 (Principal("device", device_id), "announce_token", rec, False))

    seeder = store.get("seeder", {})
    cur = seeder.get("announce_token")
    if isinstance(cur, dict):
        _put(cur.get("value"),
             (Principal("service", "seeder"), "announce_token", cur, False))
    prev_list = seeder.get("announce_token_previous")
    if isinstance(prev_list, list):
        for rec in prev_list:
            if isinstance(rec, dict):
                _put(rec.get("value"),
                     (Principal("service", "seeder"),
                      "announce_token_previous", rec, True))
    return index


def device_announce_value(store, device_id, now, grace):
    """Return the device's current, valid announce_token value, or None.

    A device with no minted/valid announce credential returns None so the
    caller can fail closed (spec §6: never seeder fallback)."""
    rec = store.get("devices", {}).get(device_id, {}).get("announce_token")
    if not isinstance(rec, dict):
        return None
    if not _ss.valid(rec, now, grace):
        return None
    return rec.get("value")
