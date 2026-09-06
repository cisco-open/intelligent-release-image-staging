# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Role-aware tracker cadence, selection, attribution, and benchmark tests."""
import copy
import hashlib
import http.client
import json
import os
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote_from_bytes

import auth
import bencode
import peer_endpoints
import peer_policy
from peer_registry import PeerRegistry
import secrets_store
import tracker


INFO_HASH_BYTES = hashlib.sha1(b"iris-tracker-role-test").digest()
INFO_HASH = quote_from_bytes(INFO_HASH_BYTES)
INFO_HASH_HEX = INFO_HASH_BYTES.hex()


def _paths(tmp_path):
    return (str(tmp_path / "peer-policy.json"),
            str(tmp_path / "peer-policy.lkg.json"))


def _document(defs=None, role_of=None, qos_default=None, assignments=None):
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": defs or {},
        "role_of": role_of or {},
        "qos_default": qos_default or {},
        "qos_device": {},
    }
    doc["assignments"].update(assignments or {})
    peer_policy.validate_document(doc)
    return doc


def _write_document(paths, doc):
    for path in paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(doc, f, sort_keys=True)


def _mint(path, device_id, now=None):
    now = time.time() if now is None else now
    store = secrets_store.load(path)
    token = secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.save(store, path)
    return token


def _legacy_token(path, now=None):
    now = time.time() if now is None else now
    store = secrets_store.load(path)
    secrets_store.mint(store, "seeder", "announce_token", now)
    secrets_store.rotate_announce(store, now)
    secrets_store.save(store, path)
    return store["seeder"]["announce_token_previous"][0]["value"]


def _serve(tmp_path, registry, paths=None, endpoints_path=None):
    secrets_path = str(tmp_path / "secrets.json")
    server = tracker.make_server(
        "127.0.0.1", 0, secrets_path, registry=registry,
        policy_paths=paths, endpoints_path=endpoints_path,
        scrape_authorizer=lambda _device_id, _info_hash: True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1], secrets_path


def _announce(port, token, peer_id="requester", peer_port=6881, left=1,
              extra=""):
    path = ("/announce?info_hash=%s&peer_id=%s&port=%s&left=%s"
            "&announce_token=%s%s" %
            (INFO_HASH, peer_id, peer_port, left, token, extra))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, bencode.decode(body)


class TestPolicySnapshot:
    def test_reuses_whole_result_and_invalidates_on_either_inode(self,
                                                                  tmp_path):
        paths = _paths(tmp_path)
        peer_policy.initialize(*paths)
        snapshot = tracker.PolicySnapshot(*paths)
        first = snapshot.load()
        assert snapshot.load() is first
        assert first.roles is snapshot.load().roles

        for path in paths:
            before = os.stat(path)
            replacement = path + ".replacement"
            with open(path, "rb") as source, open(replacement, "wb") as target:
                target.write(source.read())
            os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(replacement, path)
            changed = snapshot.load()
            assert changed is not first
            first = changed

    def test_post_load_restat_retries_a_concurrent_replace(self, tmp_path):
        paths = _paths(tmp_path)
        for path in paths:
            Path(path).write_text("stable")
        first = peer_policy.PolicyResult(
            peer_policy.base_document(), False, False, object())
        second = peer_policy.PolicyResult(
            peer_policy.base_document(), False, False, object())
        calls = []

        def loader(auth_path, _lkg_path):
            calls.append(True)
            if len(calls) == 1:
                replacement = auth_path + ".replacement"
                Path(replacement).write_text("changed generation")
                os.replace(replacement, auth_path)
                return first
            return second

        snapshot = tracker.PolicySnapshot(*paths, loader=loader)
        assert snapshot.load() is second
        assert len(calls) == 2
        assert snapshot.load() is second

    def test_neither_file_initialization_is_cached_under_post_write_keys(
            self, tmp_path):
        paths = _paths(tmp_path)
        snapshot = tracker.PolicySnapshot(*paths)
        first = snapshot.load()
        assert os.path.exists(paths[0])
        assert os.path.exists(paths[1])
        assert snapshot.load() is first
        assert first.document == peer_policy.base_document()

    def test_corrupt_lkg_fallback_and_repair_invalidate(self, tmp_path):
        paths = _paths(tmp_path)
        peer_policy.initialize(*paths)
        Path(paths[0]).write_text("{broken")
        snapshot = tracker.PolicySnapshot(*paths)
        degraded = snapshot.load()
        assert degraded.degraded is True
        repaired = copy.deepcopy(peer_policy.base_document())
        repaired["revision"] = 9
        replacement = paths[0] + ".replacement"
        with open(replacement, "w") as f:
            json.dump(repaired, f)
        os.replace(replacement, paths[0])
        healthy = snapshot.load()
        assert healthy.degraded is False
        assert healthy.document["revision"] == 9

    def test_concurrent_readers_load_and_compile_one_result(self, tmp_path):
        paths = _paths(tmp_path)
        for path in paths:
            Path(path).write_text("stable")
        result = peer_policy.PolicyResult(
            peer_policy.base_document(), False, False, object())
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def loader(_auth_path, _lkg_path):
            calls.append(True)
            entered.set()
            assert release.wait(timeout=5)
            return result

        snapshot = tracker.PolicySnapshot(*paths, loader=loader)
        returned = []
        threads = [threading.Thread(target=lambda: returned.append(
            snapshot.load())) for _ in range(8)]
        for thread in threads:
            thread.start()
        assert entered.wait(timeout=5)
        release.set()
        for thread in threads:
            thread.join(timeout=5)
        assert calls == [True]
        assert returned == [result] * 8


def test_jitter_is_clamped_to_schema_bounds_and_rounded():
    assert tracker.jittered_interval(10, factor=0.9) == 10
    assert tracker.jittered_interval(300, factor=1.1) == 300
    assert tracker.jittered_interval(100, factor=0.9) == 90
    assert tracker.jittered_interval(100, factor=1.1) == 110


def test_role_cadence_applies_to_both_states_and_invalid_port(monkeypatch,
                                                               tmp_path):
    paths = _paths(tmp_path)
    doc = _document(
        defs={"boat": {"restricted": True, "peers": ["boat"],
                       "origin": True,
                       "qos": {"announce_min_interval_s": 120}}},
        role_of={"d1": "boat"},
        qos_default={"announce_min_interval_s": 90})
    _write_document(paths, doc)
    registry = PeerRegistry()
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "d1")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        for left, peer_id in ((0, "seed"), (100, "leech")):
            status, body = _announce(
                port, token, peer_id=peer_id, peer_port=6881, left=left)
            assert status == 200
            assert body[b"interval"] == 120
            assert body[b"min interval"] == 120
        status, body = _announce(
            port, token, peer_id="bad-port", peer_port=70000, left=0)
        assert status == 200
        assert body[b"interval"] == body[b"min interval"] == 120
        rows = registry.snapshot()[INFO_HASH_HEX]
        assert {row["interval"] for row in rows} == {120}
        assert all(row["peer_id"] != "bad-port" for row in rows)
    finally:
        server.shutdown()


def test_service_and_unmapped_legacy_use_global_cadence(monkeypatch,
                                                         tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document(
        qos_default={"announce_min_interval_s": 90}))
    registry = PeerRegistry()
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    legacy_token = _legacy_token(secrets_path)
    service_token = secrets_store.load(
        secrets_path)["seeder"]["announce_token"]["value"]
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        for token, peer_id in ((service_token, "service"),
                               (legacy_token, "legacy")):
            status, body = _announce(port, token, peer_id=peer_id)
            assert status == 200
            assert body[b"interval"] == body[b"min interval"] == 90
    finally:
        server.shutdown()


def test_policy_absent_preserves_registry_numwant_cap(monkeypatch, tmp_path):
    registry = PeerRegistry(randbelow=lambda _size: 0)
    now = time.time()
    for index in range(100):
        registry.announce(
            INFO_HASH_HEX, "p%d" % index, "10.0.0.%d" % (index + 1),
            6000 + index, principal=auth.Principal("device", "d%d" % index),
            now=now)
    server, port, secrets_path = _serve(tmp_path, registry)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value)
    try:
        status, body = _announce(port, token, extra="&numwant=100")
        assert status == 200
        assert len(body[b"peers"]) == 100
    finally:
        server.shutdown()


def test_role_numwant_is_an_exact_client_ceiling_in_both_encodings(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    members = {"requester": "boat"}
    members.update({"d%d" % index: "boat" for index in range(10)})
    _write_document(paths, _document(
        defs={"boat": {"restricted": True, "peers": ["boat"],
                       "origin": False, "qos": {"numwant": 4}}},
        role_of=members))
    registry = PeerRegistry(randbelow=lambda _size: 0)
    for index in range(10):
        registry.announce(
            INFO_HASH_HEX, "p%d" % index, "10.0.0.%d" % (index + 1),
            6000 + index, principal=auth.Principal("device", "d%d" % index),
            now=time.time())
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        for requested, expected in ((-1, 0), (0, 0), (3, 3), (4, 4),
                                    (10, 4), (200, 4)):
            status, body = _announce(
                port, token, extra="&numwant=%d" % requested)
            assert status == 200
            assert len(body[b"peers"]) == expected
        status, compact = _announce(
            port, token, extra="&numwant=10&compact=1")
        assert status == 200
        assert len(compact[b"peers"]) == 4 * 6
    finally:
        server.shutdown()


def _large_role_document(size=10_000):
    role_of = {"large-%d" % index: "large" for index in range(size)}
    role_of.update({"requester": "small", "allowed": "small"})
    return _document(
        defs={
            "small": {"restricted": True, "peers": ["small"],
                      "origin": False},
            "large": {"restricted": True, "peers": ["large"],
                      "origin": False},
        }, role_of=role_of)


def test_sparse_restricted_role_uses_current_compiled_member_index(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _large_role_document())
    registry = PeerRegistry(randbelow=lambda _size: 0)
    now = time.time()
    for index in range(10_000):
        registry.announce(
            INFO_HASH_HEX, "large-p%d" % index,
            "10.%d.%d.%d" %
            (index // 65536, (index // 256) % 256, index % 256),
            6000 + index % 1000,
            principal=auth.Principal("device", "large-%d" % index), now=now)
    registry.announce(
        INFO_HASH_HEX, "allowed-peer", "192.0.2.20", 6882,
        principal=auth.Principal("device", "allowed"), now=now)
    real_mutual = tracker._peer_policy.mutual_permit
    calls = []

    def counted(*args, **kwargs):
        calls.append(kwargs.get("compiled"))
        return real_mutual(*args, **kwargs)

    monkeypatch.setattr(tracker._peer_policy, "mutual_permit", counted)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert [peer[b"port"] for peer in body[b"peers"]] == [6882]
        assert 0 < len(calls) <= 2
        assert all(compiled is not None for compiled in calls)
    finally:
        server.shutdown()


def test_origin_enabled_role_candidate_set_includes_service_seeder(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document(
        defs={"small": {"restricted": True, "peers": ["small"],
                        "origin": True}},
        role_of={"requester": "small"}))
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "origin", "192.0.2.10", 6999,
        principal=auth.Principal("service", "seeder"), now=time.time())
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert [peer[b"port"] for peer in body[b"peers"]] == [6999]
    finally:
        server.shutdown()


def test_explicit_assignment_shadows_restricted_role_candidate_index(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    doc = _document(
        defs={
            "small": {"restricted": True, "peers": ["small"],
                      "origin": False},
            "large": {"restricted": False},
        }, role_of={"requester": "small", "outside": "large"})
    doc["acls"]["open"] = {"rules": []}
    doc["assignments"]["requester"] = "open"
    peer_policy.validate_document(doc)
    _write_document(paths, doc)
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "outside", "192.0.2.20", 7000,
        principal=auth.Principal("device", "outside"), now=time.time())
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert [peer[b"port"] for peer in body[b"peers"]] == [7000]
    finally:
        server.shutdown()


def test_policy_role_change_reindexes_existing_registry_record_immediately(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    doc = _document(
        defs={
            "small": {"restricted": True, "peers": ["small"],
                      "origin": False},
            "large": {"restricted": True, "peers": ["large"],
                      "origin": False},
        }, role_of={"requester": "small", "candidate": "small"})
    _write_document(paths, doc)
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "candidate", "192.0.2.20", 7001,
        principal=auth.Principal("device", "candidate"), now=time.time())
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        assert len(_announce(port, token)[1][b"peers"]) == 1
        peer_policy.set_role(
            paths[0], paths[1], "candidate", "large", "test", time.time())
        assert _announce(port, token)[1][b"peers"] == []
    finally:
        server.shutdown()


def test_large_allowed_role_reuses_one_maintained_registry_index(monkeypatch,
                                                                 tmp_path):
    paths = _paths(tmp_path)
    role_of = {"candidate-%d" % index: "large" for index in range(10_000)}
    role_of["requester"] = "small"
    _write_document(paths, _document(
        defs={
            "small": {"restricted": True, "peers": ["small", "large"],
                      "origin": False},
            "large": {"restricted": True, "peers": ["large", "small"],
                      "origin": False},
        }, role_of=role_of))
    registry = PeerRegistry(randbelow=lambda _size: 0)
    now = time.time()
    for index in range(10_000):
        registry.announce(
            INFO_HASH_HEX, "p%d" % index,
            "10.%d.%d.%d" %
            (index // 65536, (index // 256) % 256, index % 256),
            6000 + index % 1000,
            principal=auth.Principal("device", "candidate-%d" % index),
            now=now)
    server, port, secrets_path = _serve(tmp_path, registry, paths)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value)
    calls = []
    real_mutual = tracker._peer_policy.mutual_permit

    def counted(*args, **kwargs):
        calls.append(True)
        return real_mutual(*args, **kwargs)

    monkeypatch.setattr(tracker._peer_policy, "mutual_permit", counted)
    try:
        for _index in range(20):
            status, body = _announce(port, token, extra="&numwant=50")
            assert status == 200
            assert len(body[b"peers"]) == 50
        assert registry._role_index_builds == 1
        assert len(calls) == 20 * 50
    finally:
        server.shutdown()


def test_legacy_candidate_attributed_to_permitted_role_is_sparse_candidate(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document(
        defs={"small": {"restricted": True, "peers": ["small"],
                        "origin": False}},
        role_of={"requester": "small", "legacy-device": "small"}))
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    peer_endpoints.record_endpoint(
        endpoints_path, auth.Principal("device", "legacy-device"),
        "192.0.2.20", 7002, time.time())
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "legacy-candidate", "192.0.2.20", 7002,
        principal=auth.Principal("legacy", "192.0.2.20:7002"),
        now=time.time())
    server, port, secrets_path = _serve(
        tmp_path, registry, paths, endpoints_path=endpoints_path)
    token = _mint(secrets_path, "requester")
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert [peer[b"port"] for peer in body[b"peers"]] == [7002]
    finally:
        server.shutdown()


def test_ordinary_device_announces_never_scan_legacy_attribution(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document())
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "candidate", "192.0.2.20", 7006,
        principal=auth.Principal("device", "candidate"), now=time.time())
    scans = []

    def counted(*args, **kwargs):
        scans.append(True)
        return tracker.LegacyAttributions({}, False, frozenset())

    monkeypatch.setattr(tracker, "legacy_attributions", counted)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value)
    server, port, secrets_path = _serve(
        tmp_path, registry, paths, endpoints_path=endpoints_path)
    token = _mint(secrets_path, "requester")
    try:
        for _index in range(20):
            status, body = _announce(port, token)
            assert status == 200
            assert [peer[b"port"] for peer in body[b"peers"]] == [7006]
        assert scans == []
    finally:
        server.shutdown()


def _revoked_candidate_fixture(tmp_path, shared=False):
    paths = _paths(tmp_path)
    _write_document(paths, _document())
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    secrets_path = str(tmp_path / "secrets.json")
    _mint(secrets_path, "revoked-device")
    if shared:
        _mint(secrets_path, "open-device")
    store = secrets_store.load(secrets_path)
    secrets_store.revoke(store, "revoked-device")
    secrets_store.save(store, secrets_path)
    owners = ["revoked-device"]
    if shared:
        owners.append("open-device")
    for device_id in owners:
        peer_endpoints.record_endpoint(
            endpoints_path, auth.Principal("device", device_id),
            "192.0.2.27", 7007, time.time())
    registry = PeerRegistry(randbelow=lambda _size: 0)
    registry.announce(
        INFO_HASH_HEX, "legacy", "192.0.2.27", 7007,
        principal=auth.Principal("legacy", "192.0.2.27:7007"),
        now=time.time())
    server, port, _ = _serve(
        tmp_path, registry, paths, endpoints_path=endpoints_path)
    requester = _mint(secrets_path, "requester")
    return server, port, requester


def test_revoked_legacy_candidate_is_never_handed_to_open_requester(
        monkeypatch, tmp_path):
    server, port, token = _revoked_candidate_fixture(tmp_path)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value)
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert body[b"peers"] == []
    finally:
        server.shutdown()


def test_shared_ip_with_one_revoked_attribution_is_deny_wins(monkeypatch,
                                                              tmp_path):
    server, port, token = _revoked_candidate_fixture(tmp_path, shared=True)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value)
    try:
        status, body = _announce(port, token)
        assert status == 200
        assert body[b"peers"] == []
    finally:
        server.shutdown()


def test_restricted_legacy_requester_gets_empty_and_registry_fact(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document(
        defs={"small": {"restricted": True, "peers": ["small"],
                        "origin": False}},
        role_of={"legacy-device": "small", "candidate": "small"}))
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    peer_endpoints.record_endpoint(
        endpoints_path, auth.Principal("device", "legacy-device"),
        "127.0.0.1", 6881, time.time())
    registry = PeerRegistry()
    registry.announce(
        INFO_HASH_HEX, "candidate", "192.0.2.20", 7003,
        principal=auth.Principal("device", "candidate"), now=time.time())
    server, port, secrets_path = _serve(
        tmp_path, registry, paths, endpoints_path=endpoints_path)
    token = _legacy_token(secrets_path)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        status, body = _announce(port, token, peer_id="legacy")
        assert status == 200
        assert body[b"peers"] == []
        row = next(row for row in registry.snapshot()[INFO_HASH_HEX]
                   if row["peer_id"] == "legacy")
        assert row["principal_type"] == "legacy"
        assert row["legacy_restricted"] is True
    finally:
        server.shutdown()


def test_shared_ip_legacy_attribution_is_deny_wins(monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    _write_document(paths, _document(
        defs={
            "closed": {"restricted": True, "peers": ["closed"],
                       "origin": False},
            "open": {"restricted": False},
        }, role_of={"closed-device": "closed", "open-device": "open"}))
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    now = time.time()
    for device_id in ("closed-device", "open-device"):
        peer_endpoints.record_endpoint(
            endpoints_path, auth.Principal("device", device_id),
            "127.0.0.1", 6881, now)
    registry = PeerRegistry()
    registry.announce(
        INFO_HASH_HEX, "open", "192.0.2.20", 7004,
        principal=auth.Principal("device", "open-device"), now=now)
    server, port, secrets_path = _serve(
        tmp_path, registry, paths, endpoints_path=endpoints_path)
    token = _legacy_token(secrets_path)
    monkeypatch.setattr(
        tracker, "jittered_interval", lambda value, factor=None: value,
        raising=False)
    try:
        status, body = _announce(port, token, peer_id="legacy")
        assert status == 200
        assert body[b"peers"] == []
        row = next(row for row in registry.snapshot()[INFO_HASH_HEX]
                   if row["peer_id"] == "legacy")
        assert row["legacy_restricted"] is True
    finally:
        server.shutdown()


def test_restricted_attribution_is_retained_past_endpoint_ttl(monkeypatch,
                                                               tmp_path):
    paths = _paths(tmp_path)
    doc = _document(
        defs={"closed": {"restricted": True, "peers": ["closed"],
                         "origin": False}},
        role_of={"device-1": "closed"})
    _write_document(paths, doc)
    policy = peer_policy.load_policy(*paths)
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    peer_endpoints.record_endpoint(
        endpoints_path, auth.Principal("device", "device-1"),
        "192.0.2.25", 6881, 0)
    secrets_path = str(tmp_path / "secrets.json")
    _legacy_token(secrets_path, now=0)
    monkeypatch.setenv("IRIS_ENDPOINT_TTL", "1")
    view = tracker.legacy_attributions(
        policy, endpoints_path, secrets_store.load(secrets_path), now=100)
    assert [principal.id for principal in view.by_ip["192.0.2.25"]] == [
        "device-1"]


class _Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class _NoopAria:
    def get_session_id(self):
        return "session"

    def set_blocklist(self, _ips):
        return {}


def _maintenance_reconciler(tmp_path, paths, endpoints_path, clock,
                            retention_until, revoked=None):
    return tracker.TrackerReconciler(
        policy_paths=paths,
        endpoints_path=endpoints_path,
        enforcement_path=str(tmp_path / "peer-enforcement.json"),
        aria=_NoopAria(),
        pending_queue=peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: [],
        revoked_principals=lambda: set(revoked or ()),
        legacy_retention_until=lambda: retention_until,
        now=clock)


def test_role_only_retention_prunes_at_previous_token_bound_and_reused_ip(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    doc = _document(
        defs={"closed": {"restricted": True, "peers": ["closed"],
                         "origin": False}},
        role_of={"old-device": "closed"})
    _write_document(paths, doc)
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    peer_endpoints.record_endpoint(
        endpoints_path, auth.Principal("device", "old-device"),
        "192.0.2.28", 6881, 0)
    secrets_path = str(tmp_path / "secrets.json")
    _legacy_token(secrets_path, now=0)
    store = secrets_store.load(secrets_path)
    deadline = tracker._legacy_token_deadline(store, grace=0)
    assert deadline == secrets_store.SEEDER_PREV_TTL
    monkeypatch.setenv("IRIS_ENDPOINT_TTL", "180")
    clock = _Clock(181)
    reconciler = _maintenance_reconciler(
        tmp_path, paths, endpoints_path, clock, deadline)

    reconciler.run_once()
    assert "device:old-device" in peer_endpoints._state(
        endpoints_path).snapshot()

    clock.value = deadline
    reconciler.run_once()
    assert "device:old-device" not in peer_endpoints._state(
        endpoints_path).snapshot()

    peer_endpoints.record_endpoint(
        endpoints_path, auth.Principal("device", "new-device"),
        "192.0.2.28", 6881, deadline)
    view = tracker.legacy_attributions(
        peer_policy.load_policy(*paths), endpoints_path, store, deadline)
    assert view.by_ip["192.0.2.28"] == (
        auth.Principal("device", "new-device"),)


def test_maintenance_keeps_revoked_and_explicitly_denied_rows_indefinitely(
        monkeypatch, tmp_path):
    paths = _paths(tmp_path)
    doc = _document(assignments={
        "denied-device": peer_policy.RESERVED_QUARANTINE})
    _write_document(paths, doc)
    endpoints_path = str(tmp_path / "peer-endpoints.json")
    for device_id, ip in (("denied-device", "192.0.2.29"),
                          ("revoked-device", "192.0.2.30")):
        peer_endpoints.record_endpoint(
            endpoints_path, auth.Principal("device", device_id), ip, 6881, 0)
    monkeypatch.setenv("IRIS_ENDPOINT_TTL", "180")
    clock = _Clock(secrets_store.SEEDER_PREV_TTL + 100)
    reconciler = _maintenance_reconciler(
        tmp_path, paths, endpoints_path, clock, retention_until=0,
        revoked={"device:revoked-device"})
    reconciler.run_once()
    rows = peer_endpoints._state(endpoints_path).snapshot()
    assert set(rows) == {"device:denied-device", "device:revoked-device"}


def test_expired_previous_seeder_token_cannot_use_retained_attribution(
        tmp_path):
    registry = PeerRegistry()
    server, port, secrets_path = _serve(tmp_path, registry)
    expired_at = time.time() - secrets_store.SEEDER_PREV_TTL - 1000
    token = _legacy_token(secrets_path, now=expired_at)
    try:
        status, _body = _announce(port, token, peer_id="expired-legacy")
        assert status == 403
        assert registry.snapshot() == {}
    finally:
        server.shutdown()


def _benchmark_endpoint_backed(rounds=7, iterations=50,
                               endpoint_rows=10_000):
    with tempfile.TemporaryDirectory(prefix="iris-task4-endpoint-benchmark-") \
            as raw:
        root = Path(raw)
        paths = _paths(root)
        peer_policy.initialize(*paths)
        endpoints_path = str(root / "peer-endpoints.json")
        now = time.time()
        for index in range(endpoint_rows):
            peer_endpoints.record_endpoint(
                endpoints_path, auth.Principal("device", "old-%d" % index),
                "10.%d.%d.%d" %
                (index // 65536, (index // 256) % 256, index % 256),
                6000 + index % 1000, now)
        registry = PeerRegistry(randbelow=lambda _size: 0)
        registry.announce(
            INFO_HASH_HEX, "candidate", "192.0.2.20", 7008,
            principal=auth.Principal("device", "candidate"), now=now)
        secrets_path = str(root / "secrets.json")
        token = _mint(secrets_path, "requester", now=now)
        scans = {"count": 0}
        real_fresh = tracker._peer_endpoints.fresh_endpoints

        def counted(*args, **kwargs):
            scans["count"] += 1
            return real_fresh(*args, **kwargs)

        tracker._peer_endpoints.fresh_endpoints = counted
        server = tracker.make_server(
            "127.0.0.1", 0, secrets_path, registry=registry,
            policy_paths=paths, endpoints_path=endpoints_path,
            scrape_authorizer=lambda _device_id, _info_hash: True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        try:
            _announce(port, token)
            elapsed = []
            for _round in range(rounds):
                started = time.perf_counter()
                for _iteration in range(iterations):
                    status, body = _announce(port, token)
                    if status != 200 or len(body[b"peers"]) != 1:
                        raise AssertionError("endpoint benchmark response changed")
                elapsed.append(time.perf_counter() - started)
        finally:
            server.shutdown()
            tracker._peer_endpoints.fresh_endpoints = real_fresh
    return {
        "elapsed_seconds": elapsed,
        "median_seconds": statistics.median(elapsed),
        "median_announces_per_second": iterations / statistics.median(elapsed),
        "attribution_scans": scans["count"],
    }


def _benchmark_restricted_role(rounds=7, iterations=50,
                               swarm_size=10_000):
    with tempfile.TemporaryDirectory(prefix="iris-task4-role-benchmark-") as raw:
        root = Path(raw)
        paths = _paths(root)
        role_of = {"candidate-%d" % index: "large"
                   for index in range(swarm_size)}
        role_of["requester"] = "small"
        _write_document(paths, _document(
            defs={
                "small": {"restricted": True,
                          "peers": ["small", "large"], "origin": False},
                "large": {"restricted": True,
                          "peers": ["large", "small"], "origin": False},
            }, role_of=role_of))
        now = time.time()
        registry = PeerRegistry()
        for index in range(swarm_size):
            registry.announce(
                INFO_HASH_HEX, "p%d" % index,
                "10.%d.%d.%d" %
                (index // 65536, (index // 256) % 256, index % 256),
                6000 + index % 1000,
                principal=auth.Principal(
                    "device", "candidate-%d" % index), now=now)
        secrets_path = str(root / "secrets.json")
        token = _mint(secrets_path, "requester", now=now)
        server = tracker.make_server(
            "127.0.0.1", 0, secrets_path, registry=registry,
            policy_paths=paths,
            scrape_authorizer=lambda _device_id, _info_hash: True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        try:
            _announce(port, token)
            elapsed = []
            for _round in range(rounds):
                started = time.perf_counter()
                for _iteration in range(iterations):
                    status, body = _announce(port, token)
                    if status != 200 or len(body[b"peers"]) != 50:
                        raise AssertionError("role benchmark response changed")
                elapsed.append(time.perf_counter() - started)
        finally:
            server.shutdown()
    return {
        "elapsed_seconds": elapsed,
        "median_seconds": statistics.median(elapsed),
        "median_announces_per_second": iterations / statistics.median(elapsed),
        "role_index_builds": registry._role_index_builds,
    }


def run_hot_path_benchmarks():
    return {"endpoint_empty": _benchmark_endpoint_backed(endpoint_rows=0),
            "endpoint_10000": _benchmark_endpoint_backed(),
            "restricted_role": _benchmark_restricted_role()}


# ---------------------------------------------------------------------------
# Frozen same-body 10,000-peer benchmark. Timing is recorded outside pytest;
# deterministic algorithmic ceilings live in the tests above.
# ---------------------------------------------------------------------------

def _benchmark_registry(rounds=7, iterations=1000, swarm_size=10_000):
    now = time.time()
    registry = PeerRegistry()
    for index in range(swarm_size):
        registry.announce(
            INFO_HASH_HEX, "p%d" % index,
            "10.%d.%d.%d" %
            (index // 65536, (index // 256) % 256, index % 256),
            6000 + index % 1000,
            principal=auth.Principal("device", "d%d" % index), now=now)
    requester = auth.Principal("device", "benchmark-requester")
    registry.select_peers(
        INFO_HASH_HEX, "requester", requester, "192.0.2.1",
        predicate=lambda *_args: True, numwant=50, now=now)
    prune_calls = {"count": 0}
    predicate_calls = {"count": 0}
    real_prune = registry._prune

    def counted_prune(*args, **kwargs):
        prune_calls["count"] += 1
        return real_prune(*args, **kwargs)

    def predicate(*_args):
        predicate_calls["count"] += 1
        return True

    registry._prune = counted_prune
    elapsed = []
    for _round in range(rounds):
        started = time.perf_counter()
        for _iteration in range(iterations):
            peers = registry.select_peers(
                INFO_HASH_HEX, "requester", requester, "192.0.2.1",
                predicate=predicate, numwant=50, now=now)
            if len(peers) != 50:
                raise AssertionError("benchmark selection returned wrong count")
        elapsed.append(time.perf_counter() - started)
    total = rounds * iterations
    return {
        "elapsed_seconds": elapsed,
        "median_seconds": statistics.median(elapsed),
        "median_announces_per_second": iterations / statistics.median(elapsed),
        "read_prune_sweeps": prune_calls["count"],
        "predicate_calls": predicate_calls["count"],
        "predicate_calls_per_selection": predicate_calls["count"] / total,
    }


def _benchmark_http(rounds=7, iterations=50, swarm_size=10_000):
    with tempfile.TemporaryDirectory(prefix="iris-task4-benchmark-") as raw:
        root = Path(raw)
        paths = _paths(root)
        peer_policy.initialize(*paths)
        secrets_path = str(root / "secrets.json")
        token = _mint(secrets_path, "benchmark-requester")
        now = time.time()
        registry = PeerRegistry()
        for index in range(swarm_size):
            registry.announce(
                INFO_HASH_HEX, "p%d" % index,
                "10.%d.%d.%d" %
                (index // 65536, (index // 256) % 256, index % 256),
                6000 + index % 1000,
                principal=auth.Principal("device", "d%d" % index), now=now)
        server = tracker.make_server(
            "127.0.0.1", 0, secrets_path, registry=registry,
            policy_paths=paths,
            scrape_authorizer=lambda _device_id, _info_hash: True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        try:
            _announce(port, token, peer_id="benchmark-requester")
            elapsed = []
            for _round in range(rounds):
                started = time.perf_counter()
                for _iteration in range(iterations):
                    status, body = _announce(
                        port, token, peer_id="benchmark-requester")
                    if status != 200 or len(body[b"peers"]) != 50:
                        raise AssertionError("HTTP benchmark response changed")
                elapsed.append(time.perf_counter() - started)
        finally:
            server.shutdown()
    return {
        "elapsed_seconds": elapsed,
        "median_seconds": statistics.median(elapsed),
        "median_announces_per_second": iterations / statistics.median(elapsed),
    }


def run_benchmark():
    return {"registry": _benchmark_registry(), "http": _benchmark_http()}


if __name__ == "__main__" and "--benchmark" in sys.argv:
    print(json.dumps(run_benchmark(), sort_keys=True, indent=2))

if __name__ == "__main__" and "--task4-hot-benchmark" in sys.argv:
    print(json.dumps(run_hot_path_benchmarks(), sort_keys=True, indent=2))
