# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Seeder announce-token overlap (spec §6): additive `announce_token_previous`
list, previous records bounded by SEEDER_PREV_TTL and carrying a nonsecret
`record_id`, rotate that retires expired records and refuses to evict a
still-valid previous, and targeted revoke by value/record."""
import json
import re

import pytest

import auth
import secrets_store


def _seeded_store(now):
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", now)
    return store


# ---------------------------------------------------------------------------
# rotate_announce
# ---------------------------------------------------------------------------

def test_rotate_preserves_old_as_a_previous_valid_for_a_bounded_window():
    # Was test_rotate_preserves_old_as_valid_nonexpiring_previous: it asserted
    # expires_at == 0 "until explicit revoke", which no shipped command does.
    now = 1_000_000
    store = _seeded_store(now)
    old_val = store["seeder"]["announce_token"]["value"]

    new_val = secrets_store.rotate_announce(store, now + 10)

    # current changed and is distinct
    assert new_val != old_val
    assert store["seeder"]["announce_token"]["value"] == new_val
    # old value preserved as a previous record, newest-first
    prev = store["seeder"]["announce_token_previous"]
    assert isinstance(prev, list) and len(prev) == 1
    rec = prev[0]
    assert rec["value"] == old_val
    assert rec["revoked"] is False
    assert rec["rotated_at"] == now + 10
    # nonsecret record_id: 16 hex chars (token_hex(8))
    assert re.fullmatch(r"[0-9a-f]{16}", rec["record_id"])
    # bounded from the rotation that retired it -- the current token stays
    # non-expiring, its predecessor does not
    assert rec["expires_at"] == now + 10 + secrets_store.SEEDER_PREV_TTL
    assert store["seeder"]["announce_token"]["expires_at"] == 0
    # valid throughout the overlap, and only then
    assert secrets_store.valid(rec, now + 10 + secrets_store.SEEDER_PREV_TTL - 1, 0)
    assert not secrets_store.valid(rec, now + 10 + secrets_store.SEEDER_PREV_TTL, 0)
    assert not secrets_store.valid(rec, now + 10_000_000, 0)


def test_expired_previous_is_dropped_on_the_next_rotation_pass():
    """The retention window is a recovery overlap, not a second permanent key:
    an expired previous is retired by the rotation pass and never counted
    against SEEDER_PREV_CAP."""
    now = 1_000_000
    store = _seeded_store(now)
    v0 = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    v1 = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 2)          # at the cap (2)
    assert len(store["seeder"]["announce_token_previous"]) == 2

    # a third rotation inside the window is still refused (both still live)
    with pytest.raises(Exception):
        secrets_store.rotate_announce(store, now + 3)

    # ... but once the window has passed, the pass retires them itself: no
    # operator revoke, and neither old value survives.
    later = now + secrets_store.SEEDER_PREV_TTL + 10
    retiring = store["seeder"]["announce_token"]["value"]
    v2 = secrets_store.rotate_announce(store, later)
    prev = store["seeder"]["announce_token_previous"]
    # only the just-retired current is left: both expired records are gone
    assert [r["value"] for r in prev] == [retiring]
    assert store["seeder"]["announce_token"]["value"] == v2
    # and the retired values are no longer resolvable at all
    idx = secrets_store.build_announce_index(store)
    assert v0 not in idx and v1 not in idx


def test_expired_previous_stops_authenticating_before_it_is_dropped():
    """Enforcement does not wait for the next rotation: the record stays
    visible (an operator can still see what was retired and when) but `valid`
    -- the check every announce goes through -- refuses it."""
    now = 1_000_000
    store = _seeded_store(now)
    old = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    rec = secrets_store.build_announce_index(store)[old][2]
    inside = now + 1 + secrets_store.SEEDER_PREV_TTL - 1
    outside = now + 1 + secrets_store.SEEDER_PREV_TTL
    assert secrets_store.valid(rec, inside, 0)
    assert not secrets_store.valid(rec, outside, 0)


def test_legacy_nonexpiring_previous_is_bounded_on_load(tmp_path):
    """A store written before the bound carries expires_at == 0 on its
    previous records -- indefinitely valid. Loading one stamps the window from
    the record's OWN rotation stamp, so the deadline is identical in every
    process and cannot roll forward one load at a time."""
    now = 1_000_000
    store = _seeded_store(now)
    old = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    # model the pre-fix on-disk shape
    store["seeder"]["announce_token_previous"][0]["expires_at"] = 0
    path = str(tmp_path / "secrets.json")
    secrets_store.save(store, path)

    rec = secrets_store.load(path)["seeder"]["announce_token_previous"][0]
    assert rec["value"] == old
    assert rec["expires_at"] == (now + 1) + secrets_store.SEEDER_PREV_TTL
    # a second load computes the SAME deadline (no rolling extension)
    again = secrets_store.load(path)["seeder"]["announce_token_previous"][0]
    assert again["expires_at"] == rec["expires_at"]


def test_previous_without_a_rotation_stamp_is_not_honoured(tmp_path):
    """A window cannot be computed for a record carrying no timestamp, so it
    is treated as already expired rather than as a permanent credential."""
    path = str(tmp_path / "secrets.json")
    with open(path, "w") as fh:
        json.dump({"devices": {}, "seeder": {"announce_token_previous": [
            {"value": "P" * 32, "revoked": False}]}}, fh)
    rec = secrets_store.load(path)["seeder"]["announce_token_previous"][0]
    assert not secrets_store.valid(rec, 1_000_000, 300)


def test_rotate_newest_first_order():
    now = 1_000_000
    store = _seeded_store(now)
    v0 = store["seeder"]["announce_token"]["value"]
    v1 = secrets_store.rotate_announce(store, now + 1)  # current becomes v1
    prev = store["seeder"]["announce_token_previous"]
    # v0 rotated out first; then rotating again would push v1 in front of v0
    secrets_store.revoke_announce_value(store, v0)      # free a slot (cap 2)
    v2 = secrets_store.rotate_announce(store, now + 2)
    prev = store["seeder"]["announce_token_previous"]
    # newest-first: v1 ahead of the (revoked, pruned or trailing) v0
    assert prev[0]["value"] == v1
    assert store["seeder"]["announce_token"]["value"] == v2


def test_rotate_refuses_to_evict_valid_previous():
    now = 1_000_000
    store = _seeded_store(now)
    secrets_store.rotate_announce(store, now + 1)   # 1 previous
    secrets_store.rotate_announce(store, now + 2)   # 2 previous (cap)
    assert len(store["seeder"]["announce_token_previous"]) == 2
    # a third rotation would evict a still-valid previous -> must raise
    with pytest.raises(Exception):
        secrets_store.rotate_announce(store, now + 3)
    # nothing mutated: still exactly 2 previous
    assert len(store["seeder"]["announce_token_previous"]) == 2


def test_rotate_initializes_previous_list_when_absent():
    now = 1_000_000
    store = _seeded_store(now)
    assert "announce_token_previous" not in store["seeder"]
    secrets_store.rotate_announce(store, now + 1)
    assert isinstance(store["seeder"]["announce_token_previous"], list)


# ---------------------------------------------------------------------------
# revoke by value / record_id
# ---------------------------------------------------------------------------

def test_revoke_announce_record_targets_only_named_record():
    now = 1_000_000
    store = _seeded_store(now)
    v0 = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)   # v0 -> previous[0]
    v1 = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 2)   # v1 -> previous[0], v0 -> [1]
    prev = store["seeder"]["announce_token_previous"]
    assert {r["value"] for r in prev} == {v0, v1}
    # revoke exactly one previous by its record_id
    target = next(r for r in prev if r["value"] == v1)
    secrets_store.revoke_announce_record(store, target["record_id"])
    assert target["revoked"] is True
    other = next(r for r in prev if r["record_id"] != target["record_id"])
    assert other["value"] == v0
    assert other["revoked"] is False


def test_revoke_announce_value_library_compat():
    # library support only; never an operational Day-1 flow
    now = 1_000_000
    store = _seeded_store(now)
    old = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    secrets_store.revoke_announce_value(store, old)
    rec = store["seeder"]["announce_token_previous"][0]
    assert rec["value"] == old
    assert rec["revoked"] is True


# ---------------------------------------------------------------------------
# announce index resolves current + previous with legacy flags
# ---------------------------------------------------------------------------

def test_announce_index_resolves_current_and_previous_with_legacy_flags():
    now = 1_000_000
    store = _seeded_store(now)
    dev_val = secrets_store.mint(store, "dev-1", "announce_token", now)
    cur_val = store["seeder"]["announce_token"]["value"]
    prev_val = cur_val
    new_cur = secrets_store.rotate_announce(store, now + 1)

    idx = secrets_store.build_announce_index(store)

    # device current -> device principal, legacy False
    p, sname, rec, legacy = idx[dev_val]
    assert p == auth.Principal("device", "dev-1")
    assert sname == "announce_token"
    assert legacy is False

    # seeder current -> service principal, legacy False
    p, sname, rec, legacy = idx[new_cur]
    assert p == auth.Principal("service", "seeder")
    assert legacy is False

    # seeder previous -> service principal, legacy True, previous secret name
    p, sname, rec, legacy = idx[prev_val]
    assert p == auth.Principal("service", "seeder")
    assert sname == "announce_token_previous"
    assert legacy is True


def test_announce_index_raises_on_duplicate_value_ownership():
    now = 1_000_000
    store = _seeded_store(now)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    # force a collision: dev-2 shares dev-1's announce value
    shared = store["devices"]["dev-1"]["announce_token"]["value"]
    store["devices"]["dev-2"] = {
        "announce_token": dict(store["devices"]["dev-1"]["announce_token"])}
    assert store["devices"]["dev-2"]["announce_token"]["value"] == shared
    with pytest.raises(Exception) as ei:
        secrets_store.build_announce_index(store)
    # token-free error: the secret value never appears in the message
    assert shared not in str(ei.value)


def test_revoked_previous_pruned_on_load(tmp_path):
    now = 1_000_000
    store = _seeded_store(now)
    old = store["seeder"]["announce_token"]["value"]
    secrets_store.rotate_announce(store, now + 1)
    secrets_store.revoke_announce_value(store, old)
    path = str(tmp_path / "secrets.json")
    secrets_store.save(store, path)
    reloaded = secrets_store.load(path)
    prev = reloaded["seeder"].get("announce_token_previous", [])
    # revoked previous dropped; non-revoked retained
    assert all(not r.get("revoked") for r in prev)
    assert old not in [r["value"] for r in prev]


def test_device_seeder_distinct_from_service_seeder():
    now = 1_000_000
    store = _seeded_store(now)
    # a device literally named "seeder" lives under store["devices"]["seeder"];
    # store["seeder"] is the SERVICE seeder — the two must never collide.
    # mint() routes id "seeder" to the service slot, so build the device record
    # directly to model a fleet device whose id is the string "seeder".
    store["devices"]["seeder"] = {
        "announce_token": {
            "value": "devseeder000000000000000000000000",
            "created_at": now, "expires_at": 0, "revoked": False}}
    idx = secrets_store.build_announce_index(store)
    p_service, _, _, _ = idx[store["seeder"]["announce_token"]["value"]]
    p_device, _, _, _ = idx[store["devices"]["seeder"]["announce_token"]["value"]]
    assert p_service == auth.Principal("service", "seeder")
    assert p_device == auth.Principal("device", "seeder")
    assert p_service != p_device
