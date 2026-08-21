# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Strict catalog authorization index (spec §6): covers `catalog_token` and
`catalog_token_prev` across devices, returns typed `Principal`, and fails
token-free on duplicate value ownership rather than silently overwriting."""
import pytest

import auth
import secrets_store


def _store_with_catalog(now):
    store = {"devices": {}, "seeder": {}}
    val = secrets_store.mint(store, "dev-1", "catalog_token", now)
    return store, val


def test_index_resolves_current_catalog_token_typed():
    now = 1_000_000
    store, val = _store_with_catalog(now)
    idx = secrets_store.build_catalog_auth_index(store)
    principal, secret_name, record = idx[val]
    assert principal == auth.Principal("device", "dev-1")
    assert secret_name == "catalog_token"
    assert record["value"] == val


def test_index_resolves_catalog_token_prev():
    now = 1_000_000
    store, cur = _store_with_catalog(now)
    prev_val = "prevvalue0000000000000000000000a"
    store["devices"]["dev-1"]["catalog_token_prev"] = {
        "value": prev_val,
        "created_at": now,
        "expires_at": now + 300,
        "revoked": False,
    }
    idx = secrets_store.build_catalog_auth_index(store)
    principal, secret_name, record = idx[prev_val]
    assert principal == auth.Principal("device", "dev-1")
    assert secret_name == "catalog_token_prev"


def test_index_covers_current_and_prev_across_devices():
    now = 1_000_000
    store = {"devices": {}, "seeder": {}}
    v1 = secrets_store.mint(store, "dev-1", "catalog_token", now)
    v2 = secrets_store.mint(store, "dev-2", "catalog_token", now)
    p1 = "prev1000000000000000000000000000"
    store["devices"]["dev-1"]["catalog_token_prev"] = {
        "value": p1, "created_at": now, "expires_at": now + 300,
        "revoked": False}
    idx = secrets_store.build_catalog_auth_index(store)
    assert idx[v1][0] == auth.Principal("device", "dev-1")
    assert idx[v2][0] == auth.Principal("device", "dev-2")
    assert idx[p1][0] == auth.Principal("device", "dev-1")
    assert idx[p1][1] == "catalog_token_prev"


def test_index_ignores_non_catalog_secrets():
    now = 1_000_000
    store = {"devices": {}, "seeder": {}}
    av = secrets_store.mint(store, "dev-1", "announce_token", now)
    cv = secrets_store.mint(store, "dev-1", "catalog_token", now)
    idx = secrets_store.build_catalog_auth_index(store)
    assert cv in idx
    assert av not in idx


def test_index_raises_token_free_on_duplicate_ownership():
    now = 1_000_000
    store, val = _store_with_catalog(now)
    # dev-2 shares dev-1's catalog value (misconfiguration / attack)
    store["devices"]["dev-2"] = {
        "catalog_token": dict(store["devices"]["dev-1"]["catalog_token"])}
    with pytest.raises(Exception) as ei:
        secrets_store.build_catalog_auth_index(store)
    assert val not in str(ei.value)


def test_index_raises_on_current_prev_collision():
    now = 1_000_000
    store, val = _store_with_catalog(now)
    # catalog_token_prev reuses the current value on the same device
    store["devices"]["dev-1"]["catalog_token_prev"] = dict(
        store["devices"]["dev-1"]["catalog_token"])
    with pytest.raises(Exception) as ei:
        secrets_store.build_catalog_auth_index(store)
    assert val not in str(ei.value)
