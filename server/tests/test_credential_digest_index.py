# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Strict credential lookup stays bounded and verifies the selected live token."""

from urllib.parse import urlencode

import pytest

import auth
import catalog
import secrets_store


PATHS = ("query", "legacy", "bearer", "catalog", "refresh")


class LookupOnlyIndex(dict):
    """Measure lookup work; any fleet iteration is a test failure."""

    def __init__(self, entries):
        super().__init__(entries)
        self.lookups = 0

    def get(self, key, default=None):
        assert isinstance(key, bytes) and len(key) == 32
        self.lookups += 1
        return super().get(key, default)

    def __iter__(self):
        raise AssertionError("credential resolution iterated over the fleet")

    items = keys = values = __iter__


def _fixture(path, fleet_size=1):
    scope = "catalog" if path in ("catalog", "refresh") else "announce"
    store = {"devices": {}, "seeder": {}}
    for i in range(fleet_size):
        store["devices"]["dev-%d" % i] = {
            scope + "_token": {
                "value": "%032x" % i, "expires_at": 0, "revoked": False}}
    builder = (secrets_store.build_catalog_auth_index if scope == "catalog"
               else secrets_store.build_announce_index)
    index = LookupOnlyIndex(builder(store))
    record = store["devices"]["dev-%d" % (fleet_size - 1)][scope + "_token"]
    return store, index, record


def _resolve(path, token, index, store, now=100, grace=0):
    if path == "catalog":
        return auth.resolve_catalog_auth(store, index, token, now, grace)
    if path == "refresh":
        return catalog._resolve_refresh_auth(store, index, token, now, grace)
    if path == "bearer":
        return auth.resolve_announce_bearer(token, index, store, now, grace)
    field = "key" if path == "legacy" else "announce_token"
    return auth.resolve_announce_principal(
        urlencode({field: token}), index, store, now, grace)


def _refused(path, token, index, store, *, expired=False, now=100, grace=0):
    if path in ("catalog", "refresh"):
        assert _resolve(path, token, index, store, now, grace) is None
    else:
        with pytest.raises(auth.AnnounceAuthError) as error:
            _resolve(path, token, index, store, now, grace)
        assert error.value.expired is expired
        if isinstance(token, str) and token:
            assert token not in str(error.value)


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("fleet_size", [1, 10_000])
def test_accepted_unknown_expired_and_revoked_lookup_work_is_bounded(
        path, fleet_size):
    store, index, record = _fixture(path, fleet_size)
    token = record["value"]
    context = _resolve(path, token, index, store)
    assert context.principal == auth.Principal("device", "dev-%d" % (fleet_size - 1))
    assert context.scope == ("catalog" if path in ("catalog", "refresh")
                             else "announce")
    assert index.lookups == 1

    index.lookups = 0
    _refused(path, "unknown-credential", index, store)
    expected = 2 if path in ("query", "legacy", "refresh") else 1
    assert index.lookups == expected

    # Reuse the built index: these mutations must take effect immediately.
    record["expires_at"] = 90
    index.lookups = 0
    _refused(path, token, index, store, expired=True, now=100, grace=10)
    assert index.lookups == expected
    assert _resolve(path, token, index, store, now=99, grace=10) is not None

    record["revoked"] = True
    index.lookups = 0
    _refused(path, token, index, store, expired=False, now=100, grace=10)
    assert index.lookups == expected


@pytest.mark.parametrize("path", PATHS)
def test_live_token_replacement_does_not_authorize_stale_index_value(path):
    store, index, record = _fixture(path)
    old_token = record["value"]
    record["value"] = "replacement-credential"
    _refused(path, old_token, index, store)
    _refused(path, record["value"], index, store)


@pytest.mark.parametrize("builder,scope", [
    (secrets_store.build_announce_index, "announce"),
    (secrets_store.build_catalog_auth_index, "catalog"),
])
def test_distinct_credentials_with_same_digest_fail_closed(monkeypatch, builder, scope):
    monkeypatch.setattr(secrets_store, "_credential_digest", lambda value: b"x" * 32)
    store = {"devices": {
        "device-a": {scope + "_token": {"value": "first-secret"}},
        "device-b": {scope + "_token": {"value": "second-secret"}},
    }, "seeder": {}}
    with pytest.raises(secrets_store.DuplicateCredentialError) as error:
        builder(store)
    assert "first-secret" not in str(error.value)
    assert "second-secret" not in str(error.value)


@pytest.mark.parametrize("path", PATHS)
def test_digest_collision_does_not_accept_wrong_token_or_classify_it_expired(
        monkeypatch, path):
    monkeypatch.setattr(secrets_store, "_credential_digest", lambda value: b"x" * 32)
    store, index, record = _fixture(path)
    assert _resolve(path, record["value"], index, store) is not None
    _refused(path, "wrong-credential-with-same-digest", index, store)
    record["expires_at"] = 50
    _refused(path, "wrong-credential-with-same-digest", index, store, expired=False)


@pytest.mark.parametrize("scope,builder", [
    ("announce", secrets_store.build_announce_index),
    ("catalog", secrets_store.build_catalog_auth_index),
])
def test_index_keys_have_fixed_digest_size(scope, builder):
    store = {"devices": {
        "a": {scope + "_token": {"value": "a"}},
        "b": {scope + "_token": {"value": "b" * 512}},
    }, "seeder": {}}
    index = builder(store)
    assert len(index) == 2
    assert all(isinstance(key, bytes) and len(key) == 32 for key in index)
    assert secrets_store.credential_for(index, "a")[0].id == "a"
    assert secrets_store.credential_for(index, "b" * 512)[0].id == "b"


@pytest.mark.parametrize("value", [None, "", b"bytes", 7, [], {}, "\ud800"])
@pytest.mark.parametrize("path", ["bearer", "catalog", "refresh"])
def test_malformed_presented_tokens_fail_closed(path, value):
    store, index, _ = _fixture(path)
    _refused(path, value, index, store)
    assert index.lookups == 0


@pytest.mark.parametrize("scope,builder", [
    ("announce", secrets_store.build_announce_index),
    ("catalog", secrets_store.build_catalog_auth_index),
])
def test_malformed_stored_tokens_are_not_authentication_credentials(scope, builder):
    store = {"devices": {}, "seeder": {}}
    for i, value in enumerate([None, "", b"bytes", 7, [], {}, "\ud800"]):
        store["devices"][str(i)] = {scope + "_token": {"value": value}}
    assert builder(store) == {}


def test_selected_live_token_is_verified_with_constant_time_comparison(monkeypatch):
    store, index, record = _fixture("catalog", 10_000)
    original = secrets_store.hmac.compare_digest
    comparisons = []

    def compared(candidate, expected):
        comparisons.append((candidate, expected))
        return original(candidate, expected)

    monkeypatch.setattr(secrets_store.hmac, "compare_digest", compared)
    assert _resolve("catalog", record["value"], index, store) is not None
    encoded = record["value"].encode("utf-8")
    assert comparisons == [(encoded, encoded)]
    assert index.lookups == 1
