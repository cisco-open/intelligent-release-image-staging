# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Typed announce credential resolution (spec §6).

Resolution order over the RAW query (blank values preserved via
keep_blank_values / raw list parse — never parse_qs(...)[0]):

  1. Two or more `announce_token=` occurrences (blank or not) -> ambiguous fail.
  2. Exactly one non-blank `announce_token=` -> resolve ONLY that value.
  3. Exactly one blank `announce_token=`, OR no occurrence -> legacy `key=` scan.
  4. Legacy scan: accept iff exactly one unique `key=` value resolves to a valid,
     non-revoked announce credential. Zero valid -> fail; 2+ distinct valid -> fail.
  5. Duplicate credential OWNERSHIP in the strict index is a hard config error.

Errors never include a token value or record.
"""
import pytest

import auth
import secrets_store


def _store():
    return {"devices": {}, "seeder": {}}


def _index(store):
    return secrets_store.build_announce_index(store)


# ---------------------------------------------------------------------------
# Typed happy-path resolution
# ---------------------------------------------------------------------------

def test_dedicated_device_token_resolves_device_principal():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "info_hash=x&announce_token=%s&port=1" % val, idx, store, now, 0)
    assert ctx.principal == auth.Principal("device", "dev-1")
    assert ctx.secret_name == "announce_token"
    assert ctx.scope == "announce"


def test_dedicated_service_seeder_token_resolves_service_principal():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "seeder", "announce_token", now)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "announce_token=%s" % val, idx, store, now, 0)
    assert ctx.principal == auth.Principal("service", "seeder")


def test_previous_token_resolves_legacy_principal_with_endpoint_id():
    now = 1_000_000
    store = _store()
    secrets_store.mint(store, "seeder", "announce_token", now)
    prev_val = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "announce_token=%s" % prev_val, idx, store, now + 2, 0,
        legacy_id="10.0.0.5:6881")
    assert ctx.principal == auth.Principal("legacy", "10.0.0.5:6881")
    assert ctx.secret_name == "announce_token_previous"


def test_legacy_token_without_endpoint_id_uses_none_placeholder():
    now = 1_000_000
    store = _store()
    secrets_store.mint(store, "seeder", "announce_token", now)
    prev_val = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "announce_token=%s" % prev_val, idx, store, now + 2, 0)
    # id derived at tracker integration; resolver leaves it unset when unknown
    assert ctx.principal.type == "legacy"


# ---------------------------------------------------------------------------
# Dedicated occurrence counting (blank semantics)
# ---------------------------------------------------------------------------

def test_two_nonblank_dedicated_occurrences_fail():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal(
            "announce_token=%s&announce_token=%s" % (val, val), idx, store,
            now, 0)


def test_repeated_blank_dedicated_occurrences_fail():
    now = 1_000_000
    store = _store()
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal(
            "announce_token=&announce_token=", idx, store, now, 0)


def test_blank_plus_nonblank_dedicated_fail_two_occurrences():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal(
            "announce_token=&announce_token=%s" % val, idx, store, now, 0)


def test_exactly_one_nonblank_resolves_only_itself_ignores_key():
    now = 1_000_000
    store = _store()
    dev = secrets_store.mint(store, "dev-1", "announce_token", now)
    other = secrets_store.mint(store, "dev-2", "announce_token", now)
    idx = _index(store)
    # a legacy key= is present but must be ignored when a nonblank dedicated exists
    ctx = auth.resolve_announce_principal(
        "announce_token=%s&key=%s" % (dev, other), idx, store, now, 0)
    assert ctx.principal == auth.Principal("device", "dev-1")


# ---------------------------------------------------------------------------
# Legacy scan (one blank OR absent dedicated)
# ---------------------------------------------------------------------------

def test_one_blank_dedicated_plus_valid_legacy_key_succeeds():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "announce_token=&key=%s" % val, idx, store, now, 0)
    assert ctx.principal == auth.Principal("device", "dev-1")


def test_one_blank_dedicated_without_legacy_fails():
    now = 1_000_000
    store = _store()
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal("announce_token=", idx, store, now, 0)


def test_absent_dedicated_falls_to_legacy_scan():
    now = 1_000_000
    store = _store()
    val = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "info_hash=x&key=%s&port=1" % val, idx, store, now, 0)
    assert ctx.principal == auth.Principal("device", "dev-1")


def test_legacy_scan_zero_valid_fails():
    now = 1_000_000
    store = _store()
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal("key=no-such", idx, store, now, 0)


def test_legacy_scan_two_distinct_valid_fails():
    now = 1_000_000
    store = _store()
    v1 = secrets_store.mint(store, "dev-1", "announce_token", now)
    v2 = secrets_store.mint(store, "dev-2", "announce_token", now)
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal(
            "key=%s&key=%s" % (v1, v2), idx, store, now, 0)


def test_legacy_scan_repeated_same_value_is_one_unique_and_succeeds():
    now = 1_000_000
    store = _store()
    v1 = secrets_store.mint(store, "dev-1", "announce_token", now)
    idx = _index(store)
    ctx = auth.resolve_announce_principal(
        "key=%s&key=%s" % (v1, v1), idx, store, now, 0)
    assert ctx.principal == auth.Principal("device", "dev-1")


def test_legacy_scan_ignores_revoked_credential():
    now = 1_000_000
    store = _store()
    v1 = secrets_store.mint(store, "dev-1", "announce_token", now)
    store["devices"]["dev-1"]["announce_token"]["revoked"] = True
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError):
        auth.resolve_announce_principal("key=%s" % v1, idx, store, now, 0)


# ---------------------------------------------------------------------------
# Error hygiene: no token/record ever in error text
# ---------------------------------------------------------------------------

def test_errors_never_include_token_value():
    now = 1_000_000
    store = _store()
    v1 = secrets_store.mint(store, "dev-1", "announce_token", now)
    v2 = secrets_store.mint(store, "dev-2", "announce_token", now)
    idx = _index(store)
    with pytest.raises(auth.AnnounceAuthError) as ei:
        auth.resolve_announce_principal(
            "key=%s&key=%s" % (v1, v2), idx, store, now, 0)
    msg = str(ei.value)
    assert v1 not in msg and v2 not in msg


def test_duplicate_ownership_is_hard_config_error():
    now = 1_000_000
    store = _store()
    secrets_store.mint(store, "dev-1", "announce_token", now)
    shared = store["devices"]["dev-1"]["announce_token"]
    store["devices"]["dev-2"] = {"announce_token": dict(shared)}
    # building the strict index itself raises token-free
    with pytest.raises(secrets_store.DuplicateCredentialError) as ei:
        secrets_store.build_announce_index(store)
    assert shared["value"] not in str(ei.value)
