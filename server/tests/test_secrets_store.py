# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import glob
import json
import os
import threading

import secrets_store


# ---------------------------------------------------------------------------
# Task 1: load/save/build_index
# ---------------------------------------------------------------------------

def test_load_missing_returns_skeleton(tmp_path):
    store = secrets_store.load(str(tmp_path / "nope.json"))
    assert store == {"devices": {}, "seeder": {}}


def test_load_corrupt_returns_skeleton(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("NOT JSON {{}")
    store = secrets_store.load(str(p))
    assert store == {"devices": {}, "seeder": {}}


def test_load_roundtrip(tmp_path):
    p = tmp_path / "s.json"
    data = {"devices": {"dev-1": {"catalog_token": {"value": "tok",
                                                      "created_at": 1,
                                                      "expires_at": 0,
                                                      "revoked": False}}},
            "seeder": {}}
    secrets_store.save(data, str(p))
    loaded = secrets_store.load(str(p))
    assert loaded == data


def test_save_atomic_no_tmp_left(tmp_path):
    p = tmp_path / "s.json"
    secrets_store.save({"devices": {}, "seeder": {}}, str(p))
    assert p.exists()
    assert not (tmp_path / "s.json.tmp").exists()


def test_save_overwrite(tmp_path):
    p = tmp_path / "s.json"
    secrets_store.save({"devices": {}, "seeder": {}}, str(p))
    store2 = {"devices": {"dev-1": {}}, "seeder": {}}
    secrets_store.save(store2, str(p))
    assert secrets_store.load(str(p)) == store2


def test_build_index_device_mapping():
    store = {
        "devices": {
            "dev-1": {
                "catalog_token": {"value": "val-cat", "created_at": 0,
                                  "expires_at": 0, "revoked": False},
                "announce_token": {"value": "val-ann", "created_at": 0,
                                   "expires_at": 0, "revoked": False},
            }
        },
        "seeder": {
            "announce_token": {"value": "val-seed", "created_at": 0,
                               "expires_at": 0, "revoked": False},
        },
    }
    idx = secrets_store.build_index(store)
    assert idx["val-cat"] == ("dev-1", "catalog_token")
    assert idx["val-ann"] == ("dev-1", "announce_token")
    assert idx["val-seed"] == ("seeder", "announce_token")


def test_build_index_empty_store():
    idx = secrets_store.build_index({"devices": {}, "seeder": {}})
    assert idx == {}


def test_build_index_unknown_value_absent():
    idx = secrets_store.build_index({"devices": {}, "seeder": {}})
    assert "missing" not in idx


# ---------------------------------------------------------------------------
# Task 2: mint, record_for, valid
# ---------------------------------------------------------------------------

def test_mint_catalog_token_sets_fields():
    store = {"devices": {}, "seeder": {}}
    now = 1_000_000
    ttl = secrets_store.SECRET_TYPES["catalog_token"]["ttl"]
    val = secrets_store.mint(store, "dev-1", "catalog_token", now)
    rec = store["devices"]["dev-1"]["catalog_token"]
    assert rec["value"] == val
    assert rec["created_at"] == now
    assert rec["expires_at"] == now + ttl
    assert rec["revoked"] is False
    assert len(val) == 32  # token_hex(16) → 32 hex chars


def test_mint_announce_token_no_expiry():
    store = {"devices": {}, "seeder": {}}
    now = 1_000_000
    secrets_store.mint(store, "dev-1", "announce_token", now)
    rec = store["devices"]["dev-1"]["announce_token"]
    assert rec["expires_at"] == 0  # ttl==0 → never expires


def test_mint_unique_values():
    store = {"devices": {}, "seeder": {}}
    v1 = secrets_store.mint(store, "dev-1", "catalog_token", 1_000_000)
    store2 = {"devices": {}, "seeder": {}}
    v2 = secrets_store.mint(store2, "dev-2", "catalog_token", 1_000_000)
    assert v1 != v2


def test_mint_seeder():
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", 0)
    assert "announce_token" in store["seeder"]


def test_record_for_finds_device():
    store = {"devices": {}, "seeder": {}}
    val = secrets_store.mint(store, "dev-1", "catalog_token", 0)
    idx = secrets_store.build_index(store)
    result = secrets_store.record_for(idx, store, val)
    assert result is not None
    device_id, secret_name, record = result
    assert device_id == "dev-1"
    assert secret_name == "catalog_token"
    assert record["value"] == val


def test_record_for_finds_seeder():
    store = {"devices": {}, "seeder": {}}
    val = secrets_store.mint(store, "seeder", "announce_token", 0)
    idx = secrets_store.build_index(store)
    result = secrets_store.record_for(idx, store, val)
    assert result is not None
    device_id, secret_name, _ = result
    assert device_id == "seeder"
    assert secret_name == "announce_token"


def test_record_for_returns_none_unknown():
    store = {"devices": {}, "seeder": {}}
    idx = secrets_store.build_index(store)
    assert secrets_store.record_for(idx, store, "nope") is None


def _make_record(value="tok", created_at=0, expires_at=0, revoked=False):
    return {"value": value, "created_at": created_at,
            "expires_at": expires_at, "revoked": revoked}


def test_valid_not_revoked_no_expiry():
    rec = _make_record(expires_at=0, revoked=False)
    assert secrets_store.valid(rec, now=9999, grace=0) is True


def test_valid_revoked_always_false():
    rec = _make_record(expires_at=0, revoked=True)
    assert secrets_store.valid(rec, now=0, grace=300) is False


def test_valid_within_expiry():
    rec = _make_record(expires_at=1000, revoked=False)
    assert secrets_store.valid(rec, now=500, grace=0) is True


def test_valid_expired_outside_grace():
    rec = _make_record(expires_at=1000, revoked=False)
    # now=1300, grace=100 → expires_at+grace=1100 < 1300 → invalid
    assert secrets_store.valid(rec, now=1300, grace=100) is False


def test_valid_expired_within_grace():
    rec = _make_record(expires_at=1000, revoked=False)
    # now=1050, grace=100 → now < 1100 → valid
    assert secrets_store.valid(rec, now=1050, grace=100) is True


def test_valid_exactly_at_grace_boundary():
    rec = _make_record(expires_at=1000, revoked=False)
    # now==expires_at+grace=1100 → strict < → invalid
    assert secrets_store.valid(rec, now=1100, grace=100) is False


# ---------------------------------------------------------------------------
# Task 3: rotate_catalog, revoke
# ---------------------------------------------------------------------------

def test_rotate_catalog_mints_new_value():
    store = {"devices": {}, "seeder": {}}
    now = 1_000_000
    old_val = secrets_store.mint(store, "dev-1", "catalog_token", now)
    overlap = 120
    new_val = secrets_store.rotate_catalog(store, "dev-1", now + 1, overlap)
    assert new_val != old_val


def test_rotate_catalog_old_expires_at_set():
    store = {"devices": {}, "seeder": {}}
    now = 1_000_000
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    # Capture the old record DICT before rotation (it's mutated in-place)
    old_record = store["devices"]["dev-1"]["catalog_token"]
    overlap = 120
    secrets_store.rotate_catalog(store, "dev-1", now + 1, overlap)
    assert old_record["expires_at"] == (now + 1) + overlap


def test_rotate_catalog_new_value_len_32():
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "dev-1", "catalog_token", 0)
    new_val = secrets_store.rotate_catalog(store, "dev-1", 1, 120)
    assert len(new_val) == 32


def test_revoke_sets_all_device_records():
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "dev-1", "catalog_token", 0)
    secrets_store.mint(store, "dev-1", "announce_token", 0)
    secrets_store.revoke(store, "dev-1")
    for rec in store["devices"]["dev-1"].values():
        assert rec["revoked"] is True


def test_revoke_leaves_other_devices_untouched():
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "dev-1", "catalog_token", 0)
    secrets_store.mint(store, "dev-2", "catalog_token", 0)
    secrets_store.revoke(store, "dev-1")
    assert store["devices"]["dev-2"]["catalog_token"]["revoked"] is False


def test_revoke_leaves_seeder_untouched():
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", 0)
    secrets_store.mint(store, "dev-1", "catalog_token", 0)
    secrets_store.revoke(store, "dev-1")
    assert store["seeder"]["announce_token"]["revoked"] is False


def test_revoke_unknown_device_noop():
    store = {"devices": {}, "seeder": {}}
    # Should not raise
    secrets_store.revoke(store, "nonexistent")


def test_secret_types_registry():
    st = secrets_store.SECRET_TYPES
    assert "catalog_token" in st
    assert "announce_token" in st
    assert "rpc_secret" in st
    assert st["catalog_token"]["scope"] == "catalog"
    assert st["announce_token"]["scope"] == "announce"
    assert st["rpc_secret"]["scope"] == "local"
    assert st["catalog_token"]["ttl"] > 0
    assert st["announce_token"]["ttl"] == 0
    assert st["rpc_secret"]["ttl"] == 0


# ---------------------------------------------------------------------------
# CRITICAL 1: float-epoch regression tests (PR review finding)
# ---------------------------------------------------------------------------

def test_mint_produces_int_epochs_when_now_is_float():
    """mint() must coerce float now to int epochs so the store never holds
    a float.  A float expires_at (e.g. 1782731311.9) causes int("1782731311.9")
    ValueError in the agent's run_once on the next tick."""
    store = {"devices": {}, "seeder": {}}
    now_float = 1_782_731_311.9
    secrets_store.mint(store, "dev-1", "catalog_token", now_float)
    rec = store["devices"]["dev-1"]["catalog_token"]
    assert isinstance(rec["created_at"], int), (
        "created_at must be int, got %r" % type(rec["created_at"]))
    assert isinstance(rec["expires_at"], int), (
        "expires_at must be int, got %r" % type(rec["expires_at"]))
    # Values must equal the truncated second, not rounded
    assert rec["created_at"] == int(now_float)
    ttl = secrets_store.SECRET_TYPES["catalog_token"]["ttl"]
    assert rec["expires_at"] == int(now_float) + ttl


def test_rotate_catalog_old_expires_at_is_int_when_now_is_float():
    """rotate_catalog's overlap assignment must also produce an int."""
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "dev-1", "catalog_token", 1_000_000)
    old_record = store["devices"]["dev-1"]["catalog_token"]
    overlap = 120
    secrets_store.rotate_catalog(store, "dev-1", 1_782_731_311.9, overlap)
    assert isinstance(old_record["expires_at"], int), (
        "old expires_at must be int after rotate, got %r"
        % type(old_record["expires_at"]))
    assert old_record["expires_at"] == int(1_782_731_311.9) + overlap


def test_mint_seeder_produces_int_epochs_when_now_is_float():
    """Same guarantee for the seeder pseudo-device."""
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", 1_782_731_311.9)
    rec = store["seeder"]["announce_token"]
    assert isinstance(rec["created_at"], int)
    # announce_token has ttl==0 -> expires_at==0 (int)
    assert isinstance(rec["expires_at"], int)
    assert rec["expires_at"] == 0


# ---------------------------------------------------------------------------
# Concurrency: unique temp file + advisory lock (review finding — race)
# ---------------------------------------------------------------------------

def test_save_uses_unique_temp_not_shared_dot_tmp(tmp_path, monkeypatch):
    """Two concurrent save() calls to the same path must never share one
    fixed `path + '.tmp'` file (which they would truncate/interleave).  We
    intercept os.replace to capture the temp path each call used and assert
    the two calls used DISTINCT temp paths."""
    p = str(tmp_path / "s.json")
    seen = []
    real_replace = os.replace

    def spy_replace(src, dst):
        seen.append(src)
        return real_replace(src, dst)

    monkeypatch.setattr(secrets_store.os, "replace", spy_replace)
    secrets_store.save({"devices": {"a": {}}, "seeder": {}}, p)
    secrets_store.save({"devices": {"b": {}}, "seeder": {}}, p)

    assert len(seen) == 2
    assert seen[0] != seen[1], (
        "save() reused a shared temp path %r; concurrent writers would "
        "clobber each other's temp file" % seen[0])
    # No stray fixed .tmp must be left behind either.
    assert not os.path.exists(p + ".tmp")
    assert not glob.glob(str(tmp_path / "*.tmp"))


def test_concurrent_token_rotations_under_lock_lose_nothing(tmp_path):
    """N threads each rotate a DIFFERENT device's catalog token concurrently,
    each doing the full locked load->rotate->save cycle.  With no lock the
    whole-file last-writer-wins race drops most rotations; with the lock the
    final on-disk store must contain a (rotated) catalog_token for every
    device and be valid JSON."""
    p = str(tmp_path / "secrets.json")
    n = 24
    # Seed a store with one catalog_token per device.
    store = {"devices": {}, "seeder": {}}
    for i in range(n):
        secrets_store.mint(store, "dev-%d" % i, "catalog_token", 1_000_000)
    secrets_store.save(store, p)

    barrier = threading.Barrier(n)
    errors = []

    def rotate(i):
        try:
            barrier.wait()
            with secrets_store.store_lock(p):
                s = secrets_store.load(p)
                secrets_store.rotate_catalog(s, "dev-%d" % i, 1_000_100, 120)
                secrets_store.save(s, p)
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    threads = [threading.Thread(target=rotate, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    # File is valid JSON and every device survived (no lost updates).
    final = secrets_store.load(p)
    assert len(final["devices"]) == n
    for i in range(n):
        assert "catalog_token" in final["devices"]["dev-%d" % i]
