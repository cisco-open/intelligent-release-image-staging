# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Scaling regressions for the per-device hot paths (issues #51/#52/#53/#56/
#58): a tracker announce, a catalog heartbeat, a policy read, a terminal
report and a credential resolution must not cost the whole fleet.

Every assertion here is deterministic — bytes and files touched, and index
builds counted — never wall time.
"""
import builtins
import collections
import json
import os
from pathlib import Path

import pytest

import catalog
import credential_cache
import keyed_state
import peer_endpoints
import secrets_store

Principal = collections.namedtuple("Principal", ["type", "id"])

FLEET = 2000            # large enough that a whole-fleet rewrite is obvious


def _seed(path, rows):
    """Put *rows* into the keyed store at *path* without paying the hot path."""
    d = keyed_state.shard_dir(path)
    os.makedirs(d, exist_ok=True)
    buckets = {}
    for key, row in rows.items():
        buckets.setdefault(keyed_state.bucket_of(key), {})[key] = row
    for bucket, rs in buckets.items():
        with open(os.path.join(d, "%02x.json" % bucket), "w") as f:
            json.dump(rs, f)


def _shard_bytes(path):
    """{shard file name: content} for the keyed store at *path*."""
    d = keyed_state.shard_dir(path)
    out = {}
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            with open(os.path.join(d, name)) as f:
                out[name] = f.read()
    return out


def _assert_touched_one_shard(path, before, key):
    """Exactly the shard holding *key* changed, and it holds only its own
    bucket's share of the fleet — the write cost is fleet/SHARD_COUNT, not
    fleet."""
    after = _shard_bytes(path)
    mine = "%02x.json" % keyed_state.bucket_of(key)
    changed = [n for n in set(before) | set(after)
               if before.get(n) != after.get(n)]
    assert changed == [mine], changed
    rewritten = json.loads(after[mine])
    # A whole-fleet document would have had every row in it.
    assert len(rewritten) < FLEET // 10, len(rewritten)


# ---------------------------------------------------------------------------
# #53: a tracker announce writes one principal's shard, not the whole map
# ---------------------------------------------------------------------------

def _endpoint_rows(n):
    return {"device:d%05d" % i: {
        "principal_type": "device", "principal_id": "d%05d" % i,
        "updated_at": 1000.0,
        "endpoints": [{"ipv4": "10.%d.%d.%d" % (0, i // 256 % 256, i % 256),
                       "port": 6881, "observed_at": 1000.0,
                       "source": "announce"}]} for i in range(n)}


def test_announce_writes_only_its_own_principal_shard(tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    _seed(path, _endpoint_rows(FLEET))
    before = _shard_bytes(path)
    peer_endpoints.record_endpoint(
        path, Principal("device", "d00500"), "10.9.9.9", 6881, 2000.0)
    _assert_touched_one_shard(path, before, "device:d00500")
    assert peer_endpoints.fresh_endpoints(path, 2000.0)[
        "device:d00500"]["endpoints"][0]["ipv4"] == "10.9.9.9"


# ---------------------------------------------------------------------------
# #51: capacity is above the supported fleet size, so a full fleet plus the
# service principals never evicts a live device row
# ---------------------------------------------------------------------------

def test_full_supported_fleet_plus_service_principal_is_retained(tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    rows = _endpoint_rows(peer_endpoints.SUPPORTED_DEVICES)
    _seed(path, rows)
    # The seeder announces on a store already holding a full device fleet.
    peer_endpoints.record_endpoint(
        path, Principal("service", "seeder"), "10.90.168.20", 6881, 1000.0)
    peer_endpoints.prune(path, now=1000.0)      # the cap's enforcement point
    keys = set(peer_endpoints._state(path).snapshot())
    assert "service:seeder" in keys
    assert len(keys) == peer_endpoints.SUPPORTED_DEVICES + 1
    assert "device:d00000" in keys              # no live device was evicted


def test_capacity_exceeded_still_evicts_least_recently_updated(tmp_path,
                                                               monkeypatch):
    # The bound is still real: it is enforced by the maintenance pass.
    path = str(tmp_path / "peer-endpoints.json")
    monkeypatch.setattr(peer_endpoints, "MAX_PRINCIPALS", 4)
    for i in range(6):
        peer_endpoints.record_endpoint(
            path, Principal("device", "d%d" % i), "10.0.0.%d" % i, 6881,
            1000.0 + i)
    peer_endpoints.prune(path, now=1005.0)
    keys = set(peer_endpoints._state(path).snapshot())
    assert len(keys) == 4
    assert keys == {"device:d2", "device:d3", "device:d4", "device:d5"}


# ---------------------------------------------------------------------------
# #52: a heartbeat, and the policy read behind it, cost one shard each
# ---------------------------------------------------------------------------

def _fleet_store(tmp_path, n=FLEET):
    store = catalog.CatalogStore(str(tmp_path))
    _seed(store.devices_path,
          {"d%05d" % i: {"device_id": "d%05d" % i, "last_seen": 1000.0,
                         "stage_state": "ready"} for i in range(n)})
    _seed(store.policy_path,
          {"d%05d" % i: {"approved_image_id": "img-a",
                         "approved_image_ids": ["img-a"],
                         "plans": {"img-a": {"plan_id": "a" * 32,
                                             "transfer_id": "b" * 32,
                                             "planned_at": 1000.0,
                                             "info_hash": "c" * 40}}}
           for i in range(n)})
    return store


def test_heartbeat_writes_only_its_own_device_shard(tmp_path):
    store = _fleet_store(tmp_path)
    before = _shard_bytes(store.devices_path)
    store.record_heartbeat("d00500", {"stage_state": "staging"}, now=2000.0)
    _assert_touched_one_shard(store.devices_path, before, "d00500")
    assert store.get_device("d00500")["stage_state"] == "staging"
    assert store.get_device("d00499")["stage_state"] == "ready"


def test_heartbeat_pull_check_does_not_rewrite_the_fleet(tmp_path):
    """The pull-directive check used to reap the WHOLE fleet's expired
    directives on every heartbeat, rewriting the document each time."""
    store = _fleet_store(tmp_path, n=200)
    for i in range(200):
        store.request_report("d%05d" % i, 1000.0)
    before = _shard_bytes(store.pull_path)
    # Long past every directive's TTL: the old reap would have rewritten the
    # whole store; only this device's own row may be reclaimed.
    assert store.pending_report("d00100", 1000.0 + 10 * store.PULL_TTL) is None
    after = _shard_bytes(store.pull_path)
    changed = [n for n in set(before) | set(after)
               if before.get(n) != after.get(n)]
    mine = "%02x.json" % keyed_state.bucket_of("d00100")
    assert changed == [mine]
    # ...and the shard it re-parsed and rewrote held only its own bucket's
    # share of the fleet, not every device's directive.
    assert len(json.loads(before[mine])) < 20
    assert store._pulls.get("d00100") is None
    assert store._pulls.get("d00101") is not None       # untouched


def test_policy_read_does_not_parse_the_fleet(tmp_path):
    store = _fleet_store(tmp_path)
    opened = []
    real_open = keyed_state.KeyedState._read_shard

    def counting(self, bucket):
        rows = real_open(self, bucket)
        opened.append((bucket, len(rows)))
        return rows

    keyed_state.KeyedState._read_shard = counting
    try:
        view = store.device_policy_view("d00500")
    finally:
        keyed_state.KeyedState._read_shard = real_open
    assert view["approved_image_ids"] == ["img-a"]
    assert view["plans"]["img-a"]["transfer_id"] == "b" * 32
    # ONE read, of one bucket's share of the fleet (it used to be two
    # whole-fleet parses of policy.json per device poll).
    assert [b for b, _ in opened] == [keyed_state.bucket_of("d00500")]
    assert opened[0][1] < FLEET // 10


# ---------------------------------------------------------------------------
# #58: a terminal report writes one device's ring and one ledger row
# ---------------------------------------------------------------------------

def _v2(rid, tid):
    return {"schema": "v2", "report_id": rid, "transfer_id": tid,
            "event": "staging-complete", "image_id": "img-a"}


def test_report_persistence_writes_only_its_own_device_shards(tmp_path):
    store = _fleet_store(tmp_path)
    _seed(store.telemetry_path,
          {"d%05d" % i: [_v2("%032x" % (i * 7), "%032x" % (i * 7 + 1))]
           for i in range(FLEET)})
    _seed(store.report_ledger_path,
          {"d%05d" % i: ["%032x" % (i * 7)] for i in range(FLEET)})
    tel_before = _shard_bytes(store.telemetry_path)
    led_before = _shard_bytes(store.report_ledger_path)
    store.record_telemetry("d00500", _v2("f" * 32, "e" * 32))
    _assert_touched_one_shard(store.telemetry_path, tel_before, "d00500")
    _assert_touched_one_shard(store.report_ledger_path, led_before, "d00500")
    assert len(store.get_telemetry("d00500")) == 2
    assert len(store.get_telemetry("d00499")) == 1
    # And the retry is still a no-op, per device.
    store.record_telemetry("d00500", _v2("f" * 32, "e" * 32))
    assert len(store.get_telemetry("d00500")) == 2


# ---------------------------------------------------------------------------
# #56: credential resolution is O(1) per request and never serves a stale
# authorization decision
# ---------------------------------------------------------------------------

def _secrets(path, n, extra=None):
    store = {"devices": {}, "seeder": {}}
    for i in range(n):
        store["devices"]["d%05d" % i] = {
            "catalog_token": {"value": "%032x" % (i * 3), "created_at": 0,
                              "expires_at": 0, "revoked": False}}
    if extra:
        extra(store)
    secrets_store.save(store, path)
    return store


def test_credential_index_is_built_once_until_the_store_changes(tmp_path):
    path = str(tmp_path / "secrets.json")
    _secrets(path, FLEET)
    res = credential_cache.CredentialResolver(path)
    builds = []

    def counting(store):
        builds.append(1)
        return secrets_store.build_catalog_auth_index(store)

    for _ in range(50):
        store, index = res.view("catalog", counting)
        assert secrets_store.credential_for(index, "%032x" % 0)[0].id == "d00000"
    assert len(builds) == 1                     # 50 requests, one index build


def test_a_revoke_lands_on_the_very_next_request(tmp_path):
    path = str(tmp_path / "secrets.json")
    _secrets(path, 50)
    res = credential_cache.CredentialResolver(path)
    _, index = res.view("catalog", secrets_store.build_catalog_auth_index)
    token = "%032x" % (3 * 3)
    assert secrets_store.valid(secrets_store.credential_for(index, token)[2], 1000.0, 0)
    # Another process revokes the device (iris-revoke), replacing the file.
    fresh = secrets_store.load(path)
    secrets_store.revoke(fresh, "d00003")
    secrets_store.save(fresh, path)
    _, index = res.view("catalog", secrets_store.build_catalog_auth_index)
    assert not secrets_store.valid(secrets_store.credential_for(index, token)[2], 1000.0, 0)


def test_duplicate_credential_ownership_fails_closed_every_time(tmp_path):
    path = str(tmp_path / "secrets.json")

    def collide(store):
        store["devices"]["d00001"]["catalog_token"]["value"] = "%032x" % 0

    _secrets(path, 10, extra=collide)
    res = credential_cache.CredentialResolver(path)
    for _ in range(3):          # not just the first request
        with pytest.raises(secrets_store.DuplicateCredentialError):
            res.view("catalog", secrets_store.build_catalog_auth_index)


def test_corrupt_store_fails_closed_and_is_not_cached_as_empty(tmp_path):
    path = str(tmp_path / "secrets.json")
    _secrets(path, 10)
    res = credential_cache.CredentialResolver(path)
    res.view("catalog", secrets_store.build_catalog_auth_index)
    with open(path, "w") as f:
        f.write("{ corrupt")
    with pytest.raises(secrets_store.StoreCorruptError):
        res.view("catalog", secrets_store.build_catalog_auth_index)
    # Repairing it brings the real store back, not an empty one.
    _secrets(path, 10)
    _, index = res.view("catalog", secrets_store.build_catalog_auth_index)
    assert len(index) == 10


# ---------------------------------------------------------------------------
# Migration: a whole-fleet document from an earlier release is folded into
# shards on first use, without an operator step and without data loss
# ---------------------------------------------------------------------------

def test_legacy_devices_document_is_migrated_on_first_use(tmp_path):
    legacy = {"d1": {"device_id": "d1", "last_seen": 1.0,
                     "stage_state": "ready"},
              "d2": {"device_id": "d2", "last_seen": 2.0,
                     "stage_state": "staging"}}
    path = str(tmp_path / "devices.json")
    with open(path, "w") as f:
        json.dump(legacy, f)
    store = catalog.CatalogStore(str(tmp_path))
    assert store.get_device("d2")["stage_state"] == "staging"
    assert {d["device_id"] for d in store.list_devices()} == {"d1", "d2"}
    # The original is renamed, never deleted, and the shards now hold it.
    with open(path + ".migrated") as f:
        assert json.load(f) == legacy
    assert keyed_state.read_all(path) == legacy
    # The legacy path itself still exists -- as the rollback guard, not the
    # original document (see the migration/rollback tests below).
    assert os.path.exists(path)


def test_legacy_endpoint_document_is_migrated_on_first_use(tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    rows = _endpoint_rows(3)
    with open(path, "w") as f:
        json.dump({"schema": 1, "updated_at": 1000.0, "principals": rows}, f)
    fresh = peer_endpoints.fresh_endpoints(path, now=1000.0)
    assert set(fresh) == set(rows)
    assert os.path.exists(path + ".migrated")
    assert os.path.exists(path)              # rollback guard, not the doc


def test_an_unreadable_legacy_document_fails_closed_and_is_left_alone(tmp_path):
    path = str(tmp_path / "devices.json")
    with open(path, "w") as f:
        f.write("{ corrupt")
    store = catalog.CatalogStore(str(tmp_path))
    with pytest.raises(catalog.StateFileError):
        store.get_device("d1")
    with pytest.raises(catalog.StateFileError):
        store.record_heartbeat("d1", {"stage_state": "ready"}, now=1.0)
    assert open(path).read() == "{ corrupt"      # never migrated, never lost
    assert not os.path.exists(path + ".migrated")


def test_a_corrupt_legacy_endpoint_row_is_never_laundered_into_a_shard(tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    with open(path, "w") as f:
        json.dump({"schema": 1, "updated_at": 0.0, "principals": {
            "device:x": {"principal_type": "device", "principal_id": "x",
                         "updated_at": 0.0,
                         "endpoints": [{"ipv4": "fe80::1", "port": 6881,
                                        "observed_at": 0.0}]}}}, f)
    with pytest.raises(peer_endpoints.EndpointStoreError):
        peer_endpoints.fresh_endpoints(path, now=0.0)
    assert os.path.exists(path)
    assert not os.path.exists(path + ".migrated")
    assert not os.path.exists(keyed_state.shard_dir(path))


# ---------------------------------------------------------------------------
# Rollback guard: after migration, code from before it must refuse to start
# rather than silently present an empty fleet (issue filed against this
# migration: the legacy reader treats a MISSING document as {}, and the
# rename-away used to make every migrated document look exactly like that).
# ---------------------------------------------------------------------------

def _legacy_style_read(path):
    """The pre-#51/#52/#53/#56/#58 whole-fleet reader's exact contract
    (``catalog.CatalogStore._read`` / ``peer_endpoints._load`` before this
    migration): a MISSING file is the empty store; an EXISTING file that
    cannot be parsed as JSON, or whose top level is not a dict, raises. This
    is deliberately reimplemented here rather than imported -- it no longer
    exists in this codebase, and the whole point is to prove what *that*
    code, unchanged, does when pointed at a post-migration data directory."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise RuntimeError("state file unreadable: %s (%s)"
                           % (path, type(exc).__name__))
    if not isinstance(data, dict):
        raise RuntimeError("state file is not a JSON object: %s" % path)
    return data


def test_rollback_onto_a_migrated_devices_store_refuses_rather_than_empty(
        tmp_path):
    legacy = {"d1": {"device_id": "d1", "last_seen": 1.0,
                     "stage_state": "ready"}}
    path = str(tmp_path / "devices.json")
    with open(path, "w") as f:
        json.dump(legacy, f)
    catalog.CatalogStore(str(tmp_path)).get_device("d1")   # migrates
    assert os.path.exists(path + ".migrated")

    # This is the bug as filed: without the guard, the legacy path is simply
    # gone, and the pre-migration reader's FileNotFoundError branch returns
    # {} -- a fleet with no devices -- instead of raising.
    with pytest.raises(RuntimeError):
        _legacy_style_read(path)

    # The data is not lost: it is one rename away.
    with open(path + ".migrated") as f:
        assert json.load(f) == legacy


def test_rollback_onto_a_migrated_endpoint_store_refuses_rather_than_empty(
        tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    rows = _endpoint_rows(2)
    doc = {"schema": 1, "updated_at": 1000.0, "principals": rows}
    with open(path, "w") as f:
        json.dump(doc, f)
    peer_endpoints.fresh_endpoints(path, now=1000.0)        # migrates
    assert os.path.exists(path + ".migrated")

    with pytest.raises(RuntimeError):
        _legacy_style_read(path)

    with open(path + ".migrated") as f:
        assert json.load(f) == doc


def test_rollback_guard_names_the_migrated_file_for_the_operator(tmp_path):
    path = str(tmp_path / "devices.json")
    with open(path, "w") as f:
        json.dump({"d1": {"device_id": "d1"}}, f)
    catalog.CatalogStore(str(tmp_path)).get_device("d1")
    with open(path) as f:
        guard_text = f.read()
    # An operator who only sees the exception (pointing at `path`) and cats
    # the file needs the restore command in front of them, not a second
    # lookup.
    assert path + ".migrated" in guard_text
    assert "mv " in guard_text
    assert "docs/zensical/operations.md" in guard_text


def test_migration_is_one_shot_even_across_process_restarts(tmp_path):
    """A second KeyedState instance (a fresh process after a restart) must
    not choke on the rollback guard it finds sitting at the legacy path --
    it has to recognise the store as already migrated and read straight
    through to the shards, never re-attempting migration or raising."""
    legacy = {"d1": {"device_id": "d1", "last_seen": 1.0,
                     "stage_state": "ready"}}
    path = str(tmp_path / "devices.json")
    with open(path, "w") as f:
        json.dump(legacy, f)
    catalog.CatalogStore(str(tmp_path)).get_device("d1")   # migrates
    guard_mtime = os.stat(path).st_mtime_ns

    # A brand new store instance, as a restarted process would construct.
    store2 = catalog.CatalogStore(str(tmp_path))
    assert store2.get_device("d1")["stage_state"] == "ready"
    store2.record_heartbeat("d1", {"stage_state": "staging"}, now=2.0)
    assert store2.get_device("d1")["stage_state"] == "staging"
    # The guard was left alone -- not rewritten, not treated as a legacy
    # document to re-migrate.
    assert os.stat(path).st_mtime_ns == guard_mtime


# ---------------------------------------------------------------------------
# update_many: batch read-modify-write of a CHOSEN key subset, grouped by
# shard (issue #125's FleetStore.bulk_upsert is the first consumer; tested
# directly here against a bare KeyedState since the primitive itself is
# general-purpose, not FleetStore-specific).
# ---------------------------------------------------------------------------

def test_update_many_writes_each_touched_shard_exactly_once(tmp_path):
    """N keys spread across the store are updated in ONE update_many() call:
    the number of shard WRITES must equal the number of DISTINCT buckets
    those keys land in, not the number of keys -- the whole point over N
    calls to update(), which would rewrite a shard holding several chosen
    keys once per key landing in it."""
    path = str(tmp_path / "widgets.json")
    n = 300
    keys = ["w%05d" % i for i in range(n)]
    _seed(path, {k: {"n": 0} for k in keys})
    state = keyed_state.KeyedState(path)
    write_calls = []
    real_write = keyed_state.KeyedState._write_shard

    def counting(self, bucket, rows):
        write_calls.append(bucket)
        return real_write(self, bucket, rows)

    keyed_state.KeyedState._write_shard = counting
    try:
        results = state.update_many(keys, lambda k, row: {"n": row["n"] + 1})
    finally:
        keyed_state.KeyedState._write_shard = real_write
    assert set(results) == set(keys)
    assert all(v["n"] == 1 for v in results.values())
    distinct_buckets = {keyed_state.bucket_of(k) for k in keys}
    assert len(write_calls) == len(distinct_buckets) <= keyed_state.SHARD_COUNT
    assert len(write_calls) < n           # strictly fewer writes than keys
    for k in keys:
        assert state.get(k)["n"] == 1     # every key actually applied


def test_update_many_leaves_other_keys_in_a_touched_shard_alone(tmp_path):
    """A shard holding both a requested key and an UNREQUESTED one must come
    back out with the unrequested row untouched -- update_many only touches
    the keys it was asked for, not every row sharing its bucket."""
    path = str(tmp_path / "widgets.json")
    mine = keyed_state.bucket_of("target")
    # A neighbor sharing target's bucket (search nearby names; bucket space
    # is small enough this always finds one quickly).
    neighbor = next(k for k in ("neighbor%d" % i for i in range(1000))
                    if keyed_state.bucket_of(k) == mine)
    _seed(path, {"target": {"n": 0}, neighbor: {"n": 0}})
    state = keyed_state.KeyedState(path)
    state.update_many(["target"], lambda k, row: {"n": row["n"] + 1})
    assert state.get("target")["n"] == 1
    assert state.get(neighbor)["n"] == 0


def test_update_many_none_leaves_the_key_untouched(tmp_path):
    """fn returning None (the update()/sweep() convention) means "leave this
    key exactly as it is" -- not written, and a shard where every key's fn
    returned None is never rewritten at all."""
    path = str(tmp_path / "widgets.json")
    _seed(path, {"a": {"n": 1}, "b": {"n": 2}})
    state = keyed_state.KeyedState(path)
    before = _shard_bytes(path)
    results = state.update_many(["a", "b"], lambda k, row: None)
    assert results == {}
    assert _shard_bytes(path) == before   # byte-for-byte: no shard rewritten


def test_update_many_delete_removes_the_row(tmp_path):
    path = str(tmp_path / "widgets.json")
    _seed(path, {"a": {"n": 1}, "b": {"n": 2}})
    state = keyed_state.KeyedState(path)

    def fn(k, row):
        return keyed_state.DELETE if k == "a" else None

    results = state.update_many(["a", "b"], fn)
    assert results == {"a": keyed_state.DELETE}
    assert state.get("a") is None
    assert state.get("b")["n"] == 2


def test_update_many_repeated_key_sees_its_own_prior_result(tmp_path):
    """A key appearing twice in *keys* is called twice, the second call
    seeing the first call's return value as its "old row" -- the same
    outcome N calls to update() would produce."""
    path = str(tmp_path / "widgets.json")
    _seed(path, {"a": {"n": 0}})
    state = keyed_state.KeyedState(path)
    results = state.update_many(["a", "a", "a"], lambda k, row: {"n": row["n"] + 1})
    assert results == {"a": {"n": 3}}
    assert state.get("a")["n"] == 3


def test_update_many_a_corrupt_shard_aborts_without_rewriting_it(tmp_path):
    """An exception out of fn's underlying read (a shard that fails to
    parse) propagates immediately: that shard is left exactly as it was.
    A DIFFERENT shard already written earlier in the SAME call stays
    committed -- update_many groups by shard and commits each one as it
    goes, it does not buffer every shard's write until the whole batch
    succeeds (matching update_many's own docstring, and mirroring
    update()'s single-key fail-closed contract)."""
    path = str(tmp_path / "widgets.json")
    good_key = next(k for k in ("g%d" % i for i in range(1000))
                    if keyed_state.bucket_of(k) != keyed_state.bucket_of("bad"))
    _seed(path, {"bad": {"n": 1}, good_key: {"n": 1}})
    shard = os.path.join(keyed_state.shard_dir(path),
                         "%02x.json" % keyed_state.bucket_of("bad"))
    with open(shard, "w") as f:
        f.write("{ corrupt")
    state = keyed_state.KeyedState(path)
    # good_key's shard is processed FIRST and commits; "bad" is second and
    # raises -- proving the earlier commit survives the later failure.
    with pytest.raises(keyed_state.KeyedStateError):
        state.update_many([good_key, "bad"], lambda k, row: {"n": row["n"] + 1})
    assert open(shard).read() == "{ corrupt"   # untouched
    assert state.get(good_key)["n"] == 2       # already-committed write survives


def test_task13_behavioral_red_durable_write_fsyncs_file_then_directory(
        tmp_path, monkeypatch):
    path = str(tmp_path / "durable.json")
    events = []
    real_fsync = os.fsync
    real_replace = os.replace

    def fsync(fd):
        mode = os.fstat(fd).st_mode
        events.append("directory" if os.path.isdir("/proc/self/fd/%d" % fd)
                      else "file")
        return real_fsync(fd)

    def replace(source, target):
        events.append("replace")
        return real_replace(source, target)

    monkeypatch.setattr(keyed_state.os, "fsync", fsync)
    monkeypatch.setattr(keyed_state.os, "replace", replace)
    state = keyed_state.KeyedState(path, durable=True)
    state.put("device-1", {"serial": 1})

    assert events[-3:] == ["file", "replace", "directory"]


def test_task13_default_keyed_state_remains_backwards_compatible_without_fsync(
        tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(keyed_state.os, "fsync", lambda _fd: calls.append(1))
    state = keyed_state.KeyedState(str(tmp_path / "ordinary.json"))
    state.put("a", {"n": 1})
    assert calls == []


def test_task13_durable_empty_shard_removal_fsyncs_directory(
        tmp_path, monkeypatch):
    state = keyed_state.KeyedState(
        str(tmp_path / "durable.json"), durable=True)
    state.put("a", {"n": 1})
    calls = []
    real = keyed_state._fsync_directory

    def record(path):
        calls.append(path)
        return real(path)

    monkeypatch.setattr(keyed_state, "_fsync_directory", record)
    assert state.delete("a")
    assert calls == [state.dir]


@pytest.mark.parametrize("failure_point", ["file", "directory"])
def test_task13_durable_fsync_failures_propagate_with_honest_visibility(
        tmp_path, monkeypatch, failure_point):
    state = keyed_state.KeyedState(
        str(tmp_path / "durable.json"), durable=True)
    real_fsync = os.fsync
    calls = []

    def fail(fd):
        kind = ("directory" if os.path.isdir("/proc/self/fd/%d" % fd)
                else "file")
        calls.append(kind)
        if kind == failure_point:
            raise OSError("injected %s fsync" % kind)
        return real_fsync(fd)

    monkeypatch.setattr(keyed_state.os, "fsync", fail)
    with pytest.raises(OSError, match="injected"):
        state.put("a", {"n": 1})
    restarted = keyed_state.KeyedState(
        str(tmp_path / "durable.json"), durable=True)
    if failure_point == "file":
        assert restarted.get("a") is None
    else:
        assert restarted.get("a") == {"n": 1}


# ---------------------------------------------------------------------------
# #245: a read-only export snapshot must distinguish unavailable data from an
# empty store, or the exporter forgets delivered reports and replays the ring.
# ---------------------------------------------------------------------------

def _snapshot_disk(root):
    """Include names, contents and mtimes so reads cannot silently migrate."""
    snapshot = {}
    for entry in [root, *sorted(root.rglob("*"))]:
        stat = entry.stat()
        snapshot[str(entry.relative_to(root))] = (
            stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size,
            entry.read_bytes() if entry.is_file() else None)
    return snapshot


def _strict_fixture_rows():
    first = "first-device"
    second = next("other-device-%d" % i for i in range(1000)
                  if keyed_state.bucket_of("other-device-%d" % i)
                  != keyed_state.bucket_of(first))
    return {first: [_v2("a" * 32, "b" * 32)],
            second: [_v2("c" * 32, "d" * 32)]}


@pytest.mark.parametrize("layout", ["fresh", "empty-shards", "empty-legacy"])
def test_strict_read_accepts_known_empty_store_without_creating_files(
        tmp_path, monkeypatch, layout):
    path = str(tmp_path / "telemetry.json")
    if layout == "empty-shards":
        _seed(path, {})
    elif layout == "empty-legacy":
        Path(path).write_text("{}")
    before = _snapshot_disk(tmp_path)

    def unexpected_snapshot(*args, **kwargs):
        pytest.fail("read_all must never invoke the migrating writer snapshot")

    monkeypatch.setattr(keyed_state.KeyedState, "snapshot", unexpected_snapshot)
    assert keyed_state.read_all(path, strict=True) == {}
    assert _snapshot_disk(tmp_path) == before


def test_strict_read_legacy_document_is_read_only(tmp_path, monkeypatch):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    Path(path).write_text(json.dumps(rows))
    before = _snapshot_disk(tmp_path)

    def unexpected_snapshot(*args, **kwargs):
        pytest.fail("a read-only snapshot must not migrate the legacy document")

    monkeypatch.setattr(keyed_state.KeyedState, "snapshot", unexpected_snapshot)
    assert keyed_state.read_all(path, strict=True) == rows
    assert _snapshot_disk(tmp_path) == before


def test_strict_read_merges_legacy_and_shards_without_migration(tmp_path):
    path = str(tmp_path / "telemetry.json")
    legacy = {"legacy-only": [_v2("a" * 32, "b" * 32)],
              "overlap": [_v2("c" * 32, "d" * 32)]}
    shards = {"shard-only": [_v2("e" * 32, "f" * 32)],
              "overlap": [_v2("1" * 32, "2" * 32)]}
    Path(path).write_text(json.dumps(legacy))
    _seed(path, shards)
    before = _snapshot_disk(tmp_path)
    assert keyed_state.read_all(path, strict=True) == dict(legacy, **shards)
    assert _snapshot_disk(tmp_path) == before


def test_strict_read_migrated_store_does_not_open_retired_legacy_guard(
        tmp_path, monkeypatch):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    Path(path + ".migrated").write_text(json.dumps({"retired-device": []}))
    Path(path).write_text("IRIS rollback guard: this is deliberately not JSON")
    before = _snapshot_disk(tmp_path)
    original_open = builtins.open
    opened = []

    def open_without_guard(filename, *args, **kwargs):
        opened.append(os.fspath(filename))
        if os.fspath(filename) == path:
            raise PermissionError("the retired guard must not be opened")
        return original_open(filename, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", open_without_guard)
        assert keyed_state.read_all(path, strict=True) == rows
    assert path not in opened
    assert _snapshot_disk(tmp_path) == before


@pytest.mark.parametrize("layout", ["missing-parent", "migrated-missing-shards"])
def test_strict_read_missing_store_infrastructure_is_not_empty(tmp_path, layout):
    if layout == "missing-parent":
        path = str(tmp_path / "missing" / "telemetry.json")
    else:
        path = str(tmp_path / "telemetry.json")
        Path(path + ".migrated").write_text("{}")
    before = _snapshot_disk(tmp_path)
    with pytest.raises(keyed_state.KeyedStateError):
        keyed_state.read_all(path, strict=True)
    assert keyed_state.read_all(path) == {}
    assert _snapshot_disk(tmp_path) == before


@pytest.mark.parametrize("source", ["legacy", "shard"])
@pytest.mark.parametrize("bad_json", ["{ broken", "[]", "null", "42", '"text"'])
def test_strict_read_rejects_corrupt_or_nonobject_source_without_partial_result(
        tmp_path, source, bad_json):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    expected_best_effort = dict(rows)
    if source == "legacy":
        damaged = Path(path)
    else:
        bad_key = next(iter(rows))
        damaged = Path(keyed_state.shard_dir(path)) / (
            "%02x.json" % keyed_state.bucket_of(bad_key))
        del expected_best_effort[bad_key]
    damaged.write_text(bad_json)
    before = _snapshot_disk(tmp_path)
    with pytest.raises(keyed_state.KeyedStateError):
        keyed_state.read_all(path, strict=True)
    assert keyed_state.read_all(path) == expected_best_effort
    assert _snapshot_disk(tmp_path) == before


@pytest.mark.parametrize("source", ["legacy", "shard"])
def test_strict_read_permission_failure_aborts_complete_snapshot(
        tmp_path, monkeypatch, source):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    expected_best_effort = dict(rows)
    if source == "legacy":
        Path(path).write_text(json.dumps({"legacy-only": []}))
        unreadable = path
    else:
        bad_key = next(iter(rows))
        unreadable = os.path.join(keyed_state.shard_dir(path),
                                 "%02x.json" % keyed_state.bucket_of(bad_key))
        del expected_best_effort[bad_key]
    before = _snapshot_disk(tmp_path)
    original_open = builtins.open

    def fail_open(filename, *args, **kwargs):
        if os.fspath(filename) == unreadable:
            raise PermissionError("injected unreadable report source")
        return original_open(filename, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", fail_open)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
        assert keyed_state.read_all(path) == expected_best_effort
    assert _snapshot_disk(tmp_path) == before


@pytest.mark.parametrize("failure", ["permission", "missing", "mid-iteration"])
def test_strict_read_directory_scan_failure_is_not_empty(
        tmp_path, monkeypatch, failure):
    path = str(tmp_path / "telemetry.json")
    _seed(path, _strict_fixture_rows())
    directory = keyed_state.shard_dir(path)
    original_scandir = os.scandir
    before = _snapshot_disk(tmp_path)

    class InterruptedScan:
        def __enter__(self):
            self.entries = original_scandir(directory)
            return self

        def __exit__(self, *args):
            self.entries.close()

        def __iter__(self):
            yield next(self.entries)
            raise OSError("injected directory iteration failure")

    def fail_scandir(filename):
        if os.fspath(filename) != directory:
            return original_scandir(filename)
        if failure == "mid-iteration":
            return InterruptedScan()
        error = PermissionError if failure == "permission" else FileNotFoundError
        raise error("injected report directory failure")

    with monkeypatch.context() as patch:
        patch.setattr(keyed_state.os, "scandir", fail_scandir)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
        assert keyed_state.read_all(path) == {}
    assert _snapshot_disk(tmp_path) == before


def test_strict_read_listed_shard_disappearing_aborts_instead_of_returning_partial(
        tmp_path, monkeypatch):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    victim = sorted(Path(keyed_state.shard_dir(path)).glob("*.json"))[-1]
    lost_rows = json.loads(victim.read_text())
    original_open = builtins.open
    removed = []

    def disappearing_open(filename, *args, **kwargs):
        if os.fspath(filename) == str(victim) and not removed:
            victim.unlink()
            removed.append(str(victim))
        return original_open(filename, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", disappearing_open)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
    assert removed == [str(victim)]
    assert keyed_state.read_all(path) == {
        key: row for key, row in rows.items() if key not in lost_rows}


@pytest.mark.parametrize(("source", "transition"), [
    ("legacy", "appears"), ("shard", "appears"),
    ("shard", "disappears"), ("shard", "replaced"),
])
def test_strict_read_migration_marker_change_aborts_snapshot(
        tmp_path, monkeypatch, source, transition):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    legacy = json.dumps({"legacy-only": []})
    Path(path).write_text(legacy)
    marker = Path(path + ".migrated")
    if transition != "appears":
        marker.write_text("{}")
    target = path if source == "legacy" else str(
        sorted(Path(keyed_state.shard_dir(path)).glob("*.json"))[0])
    before_shards = _shard_bytes(path)
    original_open = builtins.open
    changed = []

    def transition_open(filename, *args, **kwargs):
        if os.fspath(filename) == target and not changed:
            changed.append(transition)
            if transition == "appears":
                marker.write_text("{}")
            elif transition == "disappears":
                marker.unlink()
            else:
                replacement = tmp_path / "replacement-marker"
                replacement.write_text("{}")
                os.replace(replacement, marker)
        return original_open(filename, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", transition_open)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
    assert changed == [transition]
    assert _shard_bytes(path) == before_shards
    assert Path(path).read_text() == legacy


@pytest.mark.parametrize("replaced", ["parent", "shard-directory"])
def test_strict_read_directory_replacement_during_scan_aborts_snapshot(
        tmp_path, monkeypatch, replaced):
    parent = tmp_path / "store"
    parent.mkdir()
    path = str(parent / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    directory = keyed_state.shard_dir(path)
    original_scandir = os.scandir
    changed = []

    def replace_before_scan(filename):
        if os.fspath(filename) == directory and not changed:
            changed.append(replaced)
            if replaced == "parent":
                os.rename(parent, tmp_path / "retired-store")
                parent.mkdir()
            else:
                os.rename(directory, parent / "retired-shards")
            os.mkdir(directory)
        return original_scandir(filename)

    with monkeypatch.context() as patch:
        patch.setattr(keyed_state.os, "scandir", replace_before_scan)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
    assert changed == [replaced]


def test_strict_read_accepts_normal_atomic_shard_update_during_scan(
        tmp_path, monkeypatch):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    _seed(path, rows)
    key = next(iter(rows))
    shard = Path(keyed_state.shard_dir(path)) / (
        "%02x.json" % keyed_state.bucket_of(key))
    updated_ring = [_v2("e" * 32, "f" * 32)]
    original_open = builtins.open
    updated = []

    def update_before_open(filename, *args, **kwargs):
        if os.fspath(filename) == str(shard) and not updated:
            updated.append(key)
            temporary = shard.with_suffix(".next")
            temporary.write_text(json.dumps({key: updated_ring}))
            os.replace(temporary, shard)
        return original_open(filename, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", update_before_open)
        assert keyed_state.read_all(path, strict=True) == dict(
            rows, **{key: updated_ring})
    assert updated == [key]


def test_strict_read_symlink_target_disappearing_during_scan_is_not_hidden(
        tmp_path, monkeypatch):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    missing_key = next(iter(rows))
    missing_row = rows.pop(missing_key)
    _seed(path, rows)
    directory = keyed_state.shard_dir(path)
    target = tmp_path / "disappearing-shard-target"
    target.write_text(json.dumps({missing_key: missing_row}))
    candidate = Path(directory) / (
        "%02x.json" % keyed_state.bucket_of(missing_key))
    candidate.symlink_to(target)
    original_scandir = os.scandir
    removed = []

    class VanishingTargetScan:
        def __enter__(self):
            self.entries = original_scandir(directory)
            return self

        def __exit__(self, *args):
            self.entries.close()

        def __iter__(self):
            for entry in self.entries:
                if entry.name == candidate.name and not removed:
                    target.unlink()
                    removed.append(entry.name)
                yield entry

    def scan_with_vanishing_target(filename):
        if os.fspath(filename) == directory:
            return VanishingTargetScan()
        return original_scandir(filename)

    with monkeypatch.context() as patch:
        patch.setattr(keyed_state.os, "scandir", scan_with_vanishing_target)
        with pytest.raises(keyed_state.KeyedStateError):
            keyed_state.read_all(path, strict=True)
        # DirEntry.is_file() returns False for the now-dangling symlink,
        # silently losing a device if it is used to filter candidate shards.
        assert keyed_state.read_all(path) == rows
    assert removed == [candidate.name]
    assert candidate.is_symlink()
    assert not target.exists()


def test_strict_read_nonregular_json_candidate_is_not_silently_ignored(tmp_path):
    path = str(tmp_path / "telemetry.json")
    rows = _strict_fixture_rows()
    nonregular_key = next(iter(rows))
    del rows[nonregular_key]
    _seed(path, rows)
    candidate = Path(keyed_state.shard_dir(path)) / (
        "%02x.json" % keyed_state.bucket_of(nonregular_key))
    candidate.mkdir()
    before = _snapshot_disk(tmp_path)

    with pytest.raises(keyed_state.KeyedStateError):
        keyed_state.read_all(path, strict=True)
    assert keyed_state.read_all(path) == rows
    assert _snapshot_disk(tmp_path) == before
