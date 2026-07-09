# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import auth
import secrets_store


def test_load_tokens_ignores_comments_and_blanks(tmp_path):
    p = tmp_path / "tokens.txt"
    p.write_text("# a comment\n\nabc123\n  def456  \n")
    assert auth.load_tokens(str(p)) == {"abc123", "def456"}


def test_load_tokens_missing_file_is_empty(tmp_path):
    assert auth.load_tokens(str(tmp_path / "nope.txt")) == set()


def test_check_announce_key():
    tokens = {"abc123"}
    assert auth.check_announce_key("info_hash=x&key=abc123&port=1", tokens)
    assert not auth.check_announce_key("info_hash=x&key=wrong", tokens)
    assert not auth.check_announce_key("info_hash=x", tokens)  # no key


def test_check_bearer():
    tokens = {"abc123"}
    assert auth.check_bearer({"Authorization": "Bearer abc123"}, tokens) == "abc123"
    assert auth.check_bearer({"Authorization": "Bearer wrong"}, tokens) is None
    assert auth.check_bearer({}, tokens) is None
    assert auth.check_bearer({"Authorization": "abc123"}, tokens) is None


# ---------------------------------------------------------------------------
# Helpers for Task 5/6 authorize / check_announce_key (store-backed)
# ---------------------------------------------------------------------------

def _make_store_and_index(device_id, secret_name, now, override_record=None):
    """Return (store, index, token_value) with a freshly minted secret."""
    store = {"devices": {}, "seeder": {}}
    val = secrets_store.mint(store, device_id, secret_name, now)
    if override_record is not None:
        if device_id == "seeder":
            store["seeder"][secret_name].update(override_record)
        else:
            store["devices"][device_id][secret_name].update(override_record)
    index = secrets_store.build_index(store)
    return store, index, val


# ---------------------------------------------------------------------------
# Task 5: authorize — happy paths
# ---------------------------------------------------------------------------

def test_authorize_valid_catalog_token():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    assert auth.authorize(index, store, val, "dev-1", "catalog", now + 1, 300)


def test_authorize_never_expiring_announce_token():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "announce_token", now)
    # ttl==0 → expires_at==0 → never expires; test with far-future now
    assert auth.authorize(index, store, val, "dev-1", "announce",
                          now + 10_000_000, 0)


# ---------------------------------------------------------------------------
# Task 5: authorize — denial cases
# ---------------------------------------------------------------------------

def test_authorize_expired_outside_grace():
    now = 1_000_000
    ttl = secrets_store.SECRET_TYPES["catalog_token"]["ttl"]
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    future = now + ttl + 400   # beyond ttl + grace(300)
    assert not auth.authorize(index, store, val, "dev-1", "catalog", future, 300)


def test_authorize_expired_within_grace():
    now = 1_000_000
    ttl = secrets_store.SECRET_TYPES["catalog_token"]["ttl"]
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    future = now + ttl + 100   # within grace(300)
    assert auth.authorize(index, store, val, "dev-1", "catalog", future, 300)


def test_authorize_exactly_at_grace_boundary_deny():
    now = 1_000_000
    ttl = secrets_store.SECRET_TYPES["catalog_token"]["ttl"]
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    at_boundary = now + ttl + 300  # exactly at expires_at+grace → strict < → deny
    assert not auth.authorize(index, store, val, "dev-1", "catalog",
                              at_boundary, 300)


def test_authorize_revoked_deny():
    now = 1_000_000
    store, index, val = _make_store_and_index(
        "dev-1", "catalog_token", now, override_record={"revoked": True})
    assert not auth.authorize(index, store, val, "dev-1", "catalog", now + 1, 300)


def test_authorize_wrong_device_deny():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    assert not auth.authorize(index, store, val, "dev-2", "catalog", now + 1, 300)


def test_authorize_wrong_scope_catalog_for_announce_deny():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "catalog_token", now)
    # Token has scope "catalog"; asking for "announce" should deny
    assert not auth.authorize(index, store, val, "dev-1", "announce", now + 1, 300)


def test_authorize_wrong_scope_announce_for_catalog_deny():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "announce_token", now)
    # Token has scope "announce"; asking for "catalog" should deny
    assert not auth.authorize(index, store, val, "dev-1", "catalog", now + 1, 300)


def test_authorize_unknown_token_deny():
    store = {"devices": {}, "seeder": {}}
    index = secrets_store.build_index(store)
    assert not auth.authorize(index, store, "no-such-token", "dev-1",
                              "catalog", 1_000_000, 300)


# ---------------------------------------------------------------------------
# Task 6: check_announce_key (store-backed) — new signature
# ---------------------------------------------------------------------------

def test_check_announce_key_store_valid():
    now = 1_000_000
    store, index, val = _make_store_and_index("dev-1", "announce_token", now)
    query = "info_hash=x&key=%s&port=1" % val
    assert auth.check_announce_key(query, index, store, now + 1, 0)


def test_check_announce_key_store_revoked_deny():
    now = 1_000_000
    store, index, val = _make_store_and_index(
        "dev-1", "announce_token", now, override_record={"revoked": True})
    query = "info_hash=x&key=%s&port=1" % val
    assert not auth.check_announce_key(query, index, store, now + 1, 0)


def test_check_announce_key_store_missing_key_deny():
    store = {"devices": {}, "seeder": {}}
    index = secrets_store.build_index(store)
    assert not auth.check_announce_key("info_hash=x&port=1", index, store,
                                       1_000_000, 0)


def test_check_announce_key_store_seeder_token_accepted():
    now = 1_000_000
    store, index, val = _make_store_and_index("seeder", "announce_token", now)
    query = "info_hash=x&key=%s&port=1" % val
    assert auth.check_announce_key(query, index, store, now + 1, 0)


# ---------------------------------------------------------------------------
# Task 6: check_announce_key legacy (tokens set) — back-compat
# ---------------------------------------------------------------------------

def test_check_announce_key_legacy_still_works():
    tokens = {"abc123"}
    assert auth.check_announce_key("info_hash=x&key=abc123&port=1", tokens)
    assert not auth.check_announce_key("info_hash=x&key=wrong", tokens)
    assert not auth.check_announce_key("info_hash=x", tokens)  # no key
