# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Scaling regressions for the per-device hot paths (issues #51/#52/#53/#56/
#58): a tracker announce, a catalog heartbeat, a policy read, a terminal
report and a credential resolution must not cost the whole fleet.

Every assertion here is deterministic — bytes and files touched, and index
builds counted — never wall time.
"""
import collections
import json
import os

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
        assert index["%032x" % 0][0].id == "d00000"
    assert len(builds) == 1                     # 50 requests, one index build


def test_a_revoke_lands_on_the_very_next_request(tmp_path):
    path = str(tmp_path / "secrets.json")
    _secrets(path, 50)
    res = credential_cache.CredentialResolver(path)
    _, index = res.view("catalog", secrets_store.build_catalog_auth_index)
    token = "%032x" % (3 * 3)
    assert secrets_store.valid(index[token][2], 1000.0, 0)
    # Another process revokes the device (iris-revoke), replacing the file.
    fresh = secrets_store.load(path)
    secrets_store.revoke(fresh, "d00003")
    secrets_store.save(fresh, path)
    _, index = res.view("catalog", secrets_store.build_catalog_auth_index)
    assert not secrets_store.valid(index[token][2], 1000.0, 0)


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
    # The document is renamed, never deleted, and the shards now hold it.
    assert not os.path.exists(path)
    with open(path + ".migrated") as f:
        assert json.load(f) == legacy
    assert keyed_state.read_all(path) == legacy


def test_legacy_endpoint_document_is_migrated_on_first_use(tmp_path):
    path = str(tmp_path / "peer-endpoints.json")
    rows = _endpoint_rows(3)
    with open(path, "w") as f:
        json.dump({"schema": 1, "updated_at": 1000.0, "principals": rows}, f)
    fresh = peer_endpoints.fresh_endpoints(path, now=1000.0)
    assert set(fresh) == set(rows)
    assert not os.path.exists(path)
    assert os.path.exists(path + ".migrated")


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
