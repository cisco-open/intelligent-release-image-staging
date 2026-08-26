# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the durable typed principal->endpoint map (spec 6/10.5) and the
tracker-owned bounded latest-per-principal pending retry queue (spec 7 failure
posture). The identity lane later supplies auth.Principal; to keep this lane
isolated the store accepts any object exposing ``.type``/``.id`` (a local
namedtuple fake stands in here)."""
import collections
import glob
import json
import os
import threading

import pytest

import peer_endpoints

# Local structural fake for the typed principal (identity lane supplies the
# real auth.Principal later; integration must accept auth.Principal).
Principal = collections.namedtuple("Principal", ["type", "id"])

DEV = Principal("device", "iris8kv-3")
DEV2 = Principal("device", "iris8kv-9")
SVC = Principal("service", "seeder")
LEGACY = Principal("legacy", "100.92.100.77:6881")
# A device literally named "seeder" is distinct from service:seeder.
DEV_SEEDER = Principal("device", "seeder")


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "peer-endpoints.json")


def _read(path):
    with open(path) as f:
        return json.load(f)


class TestConstants:
    def test_bounds_match_spec(self):
        assert peer_endpoints.ENDPOINT_CAP == 4
        assert peer_endpoints.ENDPOINT_TTL == 900
        assert peer_endpoints.MAX_PRINCIPALS == 10000

    def test_ttl_env_override(self, monkeypatch):
        monkeypatch.setenv("IRIS_ENDPOINT_TTL", "123")
        assert peer_endpoints.endpoint_ttl() == 123

    def test_ttl_env_default_when_absent(self, monkeypatch):
        monkeypatch.delenv("IRIS_ENDPOINT_TTL", raising=False)
        assert peer_endpoints.endpoint_ttl() == 900

    def test_ttl_env_ignored_when_garbage(self, monkeypatch):
        monkeypatch.setenv("IRIS_ENDPOINT_TTL", "not-a-number")
        assert peer_endpoints.endpoint_ttl() == 900


class TestKeyAndRecord:
    def test_principal_key_typed(self):
        assert peer_endpoints.principal_key(DEV) == "device:iris8kv-3"
        assert peer_endpoints.principal_key(SVC) == "service:seeder"

    def test_device_seeder_distinct_from_service_seeder(self):
        assert (peer_endpoints.principal_key(DEV_SEEDER)
                != peer_endpoints.principal_key(SVC))
        assert peer_endpoints.principal_key(DEV_SEEDER) == "device:seeder"


class TestDurableWrite:
    @pytest.mark.parametrize("operation", ["record", "clear", "prune", "read"])
    def test_corruption_fails_closed_without_overwrite(self, store_path,
                                                       operation):
        corrupt = b"{ definitely corrupt"
        with open(store_path, "wb") as f:
            f.write(corrupt)
        calls = {
            "record": lambda: peer_endpoints.record_endpoint(
                store_path, DEV, "10.0.0.1", 6881, 1.0),
            "clear": lambda: peer_endpoints.clear_principal(store_path, DEV),
            "prune": lambda: peer_endpoints.prune(store_path, 1.0),
            "read": lambda: peer_endpoints.fresh_endpoints(store_path, 1.0),
        }
        with pytest.raises(peer_endpoints.EndpointStoreError):
            calls[operation]()
        assert open(store_path, "rb").read() == corrupt

    def test_records_attributable_device_endpoint(self, store_path):
        peer_endpoints.record_endpoint(
            store_path, DEV, "100.92.100.16", 6881, now=1000.0)
        doc = _read(store_path)
        assert doc["schema"] == 1
        assert doc["updated_at"] == 1000.0
        p = doc["principals"]["device:iris8kv-3"]
        assert p["principal_type"] == "device"
        assert p["principal_id"] == "iris8kv-3"
        assert p["updated_at"] == 1000.0
        assert p["endpoints"] == [
            {"ipv4": "100.92.100.16", "port": 6881,
             "observed_at": 1000.0, "source": "announce"}]

    def test_records_service_seeder_endpoint(self, store_path):
        peer_endpoints.record_endpoint(
            store_path, SVC, "100.90.168.20", 6881, now=1000.0)
        doc = _read(store_path)
        assert "service:seeder" in doc["principals"]

    def test_legacy_principal_never_persisted(self, store_path):
        peer_endpoints.record_endpoint(
            store_path, LEGACY, "100.92.100.77", 6881, now=1000.0)
        # No durable file is created for a legacy-only write, or if the file
        # exists it holds no legacy principal.
        if os.path.exists(store_path):
            assert _read(store_path)["principals"] == {}

    def test_legacy_write_returns_false(self, store_path):
        assert peer_endpoints.record_endpoint(
            store_path, LEGACY, "100.92.100.77", 6881, now=1000.0) is False
        assert peer_endpoints.record_endpoint(
            store_path, DEV, "100.92.100.16", 6881, now=1000.0) is True

    def test_atomic_no_tmp_left(self, store_path):
        peer_endpoints.record_endpoint(
            store_path, DEV, "100.92.100.16", 6881, now=1000.0)
        d = os.path.dirname(store_path)
        assert glob.glob(os.path.join(d, ".peer-endpoints*.tmp")) == []


class TestNewestFirstCap:
    def test_new_ip_prepended_newest_first(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.2", 6881, 1001.0)
        eps = _read(store_path)["principals"]["device:iris8kv-3"]["endpoints"]
        assert [e["ipv4"] for e in eps] == ["10.0.0.2", "10.0.0.1"]

    def test_same_ip_refreshes_not_duplicates(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1005.0)
        eps = _read(store_path)["principals"]["device:iris8kv-3"]["endpoints"]
        assert len(eps) == 1
        assert eps[0]["observed_at"] == 1005.0

    def test_endpoint_cap_evicts_oldest(self, store_path):
        for i in range(6):
            peer_endpoints.record_endpoint(
                store_path, DEV, "10.0.0.%d" % i, 6881, 1000.0 + i)
        eps = _read(store_path)["principals"]["device:iris8kv-3"]["endpoints"]
        assert len(eps) == peer_endpoints.ENDPOINT_CAP
        # newest-first, oldest (10.0.0.0, 10.0.0.1) evicted
        assert [e["ipv4"] for e in eps] == [
            "10.0.0.5", "10.0.0.4", "10.0.0.3", "10.0.0.2"]


class TestTTLPrune:
    def test_prune_drops_expired_endpoints(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.2", 6881, 2000.0)
        # now well past TTL for 10.0.0.1 but not 10.0.0.2
        peer_endpoints.prune(store_path, now=2000.0 + 500)
        eps = _read(store_path)["principals"]["device:iris8kv-3"]["endpoints"]
        assert [e["ipv4"] for e in eps] == ["10.0.0.2"]

    def test_principal_removed_when_no_fresh_endpoints(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.prune(store_path, now=1000.0 + 901)
        assert _read(store_path)["principals"] == {}

    def test_fresh_endpoints_reader(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.2", 6881, 2000.0)
        fresh = peer_endpoints.fresh_endpoints(store_path, now=2000.0 + 500)
        assert fresh == {"device:iris8kv-3": {
            "principal_type": "device", "principal_id": "iris8kv-3",
            "endpoints": [{"ipv4": "10.0.0.2", "port": 6881,
                           "observed_at": 2000.0, "source": "announce"}]}}

    def test_fresh_endpoints_missing_file(self, store_path):
        assert peer_endpoints.fresh_endpoints(store_path, now=1.0) == {}


class TestMaxPrincipalsLRU:
    def test_overflow_evicts_least_recently_updated(self, store_path,
                                                    monkeypatch):
        monkeypatch.setattr(peer_endpoints, "MAX_PRINCIPALS", 3)
        for i in range(3):
            peer_endpoints.record_endpoint(
                store_path, Principal("device", "d%d" % i),
                "10.0.0.%d" % i, 6881, now=1000.0 + i)
        # touch d0 so it is no longer least-recently-updated
        peer_endpoints.record_endpoint(
            store_path, Principal("device", "d0"), "10.0.0.100", 6881, 1010.0)
        # a 4th distinct principal overflows; d1 (oldest updated) is evicted
        peer_endpoints.record_endpoint(
            store_path, Principal("device", "d3"), "10.0.0.3", 6881, 1011.0)
        keys = set(_read(store_path)["principals"])
        assert "device:d1" not in keys
        assert keys == {"device:d0", "device:d2", "device:d3"}


class TestReOnboardClear:
    def test_clear_principal_removes_all_rows(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.record_endpoint(store_path, DEV2, "10.0.0.9", 6881, 1000.0)
        peer_endpoints.clear_principal(store_path, DEV)
        keys = set(_read(store_path)["principals"])
        assert keys == {"device:iris8kv-9"}

    def test_clear_missing_principal_is_noop(self, store_path):
        peer_endpoints.record_endpoint(store_path, DEV, "10.0.0.1", 6881, 1000.0)
        peer_endpoints.clear_principal(store_path, DEV2)
        assert set(_read(store_path)["principals"]) == {"device:iris8kv-3"}


class TestNoRemovalOnRevokeDelete:
    def test_no_public_delete_or_revoke_removal_api(self):
        # Retirement retains rows until TTL (spec 7). There is deliberately no
        # remove-on-revoke / remove-on-delete primitive; only prune (TTL) and
        # clear_principal (re-onboard) remove rows.
        for name in ("remove_on_revoke", "remove_on_delete",
                     "delete_endpoint", "revoke_endpoint"):
            assert not hasattr(peer_endpoints, name)


# --------------------------------------------------------------------------
# Tracker-owned bounded latest-per-principal pending retry queue
# --------------------------------------------------------------------------

class TestPendingQueue:
    def test_fresh_instance_empty(self):
        q = peer_endpoints.PendingEndpointQueue()
        assert q.snapshot() == {}
        assert len(q) == 0

    def test_enqueue_latest_per_principal_replacement(self):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1000.0)
        q.enqueue(DEV, "10.0.0.2", 6881, now=1001.0)
        snap = q.snapshot()
        assert list(snap) == ["device:iris8kv-3"]
        assert snap["device:iris8kv-3"]["endpoints"][0]["ipv4"] == "10.0.0.2"

    def test_snapshot_shape_matches_fresh_endpoints(self):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.2", 6881, now=1001.0)
        assert q.snapshot() == {"device:iris8kv-3": {
            "principal_type": "device", "principal_id": "iris8kv-3",
            "endpoints": [{"ipv4": "10.0.0.2", "port": 6881,
                           "observed_at": 1001.0, "source": "announce"}]}}

    def test_cap_is_max_principals(self):
        assert peer_endpoints.PendingEndpointQueue().cap \
            == peer_endpoints.MAX_PRINCIPALS

    def test_deterministic_overflow_evicts_oldest_pending(self):
        q = peer_endpoints.PendingEndpointQueue(cap=2)
        q.enqueue(Principal("device", "a"), "10.0.0.1", 6881, now=1.0)
        q.enqueue(Principal("device", "b"), "10.0.0.2", 6881, now=2.0)
        q.enqueue(Principal("device", "c"), "10.0.0.3", 6881, now=3.0)
        assert set(q.snapshot()) == {"device:b", "device:c"}

    def test_success_removes_only_matching_principal(self):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1.0)
        q.enqueue(DEV2, "10.0.0.9", 6881, now=1.0)
        q.resolve(DEV)
        assert set(q.snapshot()) == {"device:iris8kv-9"}

    def test_resolve_missing_is_noop(self):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1.0)
        q.resolve(DEV2)
        assert set(q.snapshot()) == {"device:iris8kv-3"}

    def test_pending_available_for_derivation(self):
        # The reconciler may use the pending tuple immediately for enforcement.
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1.0)
        snap = q.snapshot()
        assert snap["device:iris8kv-3"]["endpoints"][0]["ipv4"] == "10.0.0.1"


class TestRetryWithoutAnnounce:
    def test_concurrent_newer_enqueue_survives_successful_retry(self,
                                                               store_path):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1.0)
        writing = threading.Event()
        release = threading.Event()

        def blocked_writer(*args):
            writing.set()
            assert release.wait(2)

        thread = threading.Thread(target=peer_endpoints.retry_pending,
                                  args=(store_path, q),
                                  kwargs={"writer": blocked_writer})
        thread.start()
        assert writing.wait(2)
        q.enqueue(DEV, "10.0.0.2", 6881, now=2.0)
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        endpoint = q.snapshot()["device:iris8kv-3"]["endpoints"][0]
        assert endpoint["ipv4"] == "10.0.0.2"

    def test_retry_drains_to_durable_and_resolves(self, store_path):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1000.0)
        # The retry primitive attempts the durable write for each pending
        # principal and removes those that succeed. It requires no new announce.
        wrote = peer_endpoints.retry_pending(store_path, q, now=1000.0)
        assert wrote == ["device:iris8kv-3"]
        assert q.snapshot() == {}
        eps = _read(store_path)["principals"]["device:iris8kv-3"]["endpoints"]
        assert eps[0]["ipv4"] == "10.0.0.1"

    def test_retry_keeps_pending_when_write_fails(self, store_path,
                                                  monkeypatch):
        q = peer_endpoints.PendingEndpointQueue()
        q.enqueue(DEV, "10.0.0.1", 6881, now=1000.0)

        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(peer_endpoints, "_atomic_write_json", boom)
        wrote = peer_endpoints.retry_pending(store_path, q, now=1000.0)
        assert wrote == []
        # Loss is not accepted here (only restart loss is); the tuple stays.
        assert set(q.snapshot()) == {"device:iris8kv-3"}

    def test_retry_empty_queue_noop(self, store_path):
        q = peer_endpoints.PendingEndpointQueue()
        assert peer_endpoints.retry_pending(store_path, q, now=1.0) == []
        assert not os.path.exists(store_path)
