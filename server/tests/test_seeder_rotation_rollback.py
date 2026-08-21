# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the seeder-announce rotation core: recovery manifest, durable-first
secret persist, raw-span-verified canonical replacement, serial remove/add,
exact-byte rollback, and hard double-failure no-go (spec §6).

Pure/injectable: no real aria2, no real secretfs, no tracker registry."""
import hashlib
import json

import pytest

import bencode
import rotate_seeder_announce as rot
import secrets_store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical(announce=b"http://h:6969/announce?announce_token=OLD"):
    info = bencode.encode({"name": "img.bin", "piece length": 16384,
                           "pieces": b"\x00" * 20, "length": 100})
    return b"d8:announce" + bencode.encode(announce) + b"4:info" + info + b"e"


def _seeder_store(tmp_path, value="OLD"):
    store = {"devices": {}, "seeder": {"announce_token": {
        "value": value, "created_at": 1, "expires_at": 0, "revoked": False}}}
    sp = str(tmp_path / "secrets.json")
    secrets_store.save(store, sp)
    return sp


class FakeSeeder:
    """Records force-remove / add calls and can be told to fail specific ones."""

    def __init__(self):
        self.events = []
        self.fail_add_values = set()      # announce_token values whose add fails
        self.fail_add_gids = set()        # torrent ids whose add fails

    def remove(self, gid):
        self.events.append(("remove", gid))

    def add(self, torrent_bytes, image_dir):
        meta = bencode.decode(torrent_bytes)
        ann = meta[b"announce"]
        tid = meta[b"info"][b"name"]
        self.events.append(("add", tid, ann))
        for v in self.fail_add_values:
            if v.encode() in ann:
                raise RuntimeError("aria2 add failed")
        return "gid-1"


# ---------------------------------------------------------------------------
# rotate_announce (local, additive store shape)
# ---------------------------------------------------------------------------

def test_rotate_announce_keeps_previous_and_mints_current():
    store = {"devices": {}, "seeder": {"announce_token": {
        "value": "OLD", "created_at": 1, "expires_at": 0, "revoked": False}}}
    new = rot.rotate_announce(store, now=100)
    assert store["seeder"]["announce_token"]["value"] == new
    assert new != "OLD"
    prev = store["seeder"]["announce_token_previous"]
    assert prev[0]["value"] == "OLD"
    assert prev[0]["expires_at"] == 0  # non-expiring
    assert prev[0]["rotated_at"] == 100
    assert "record_id" in prev[0]


def test_rotate_announce_refuses_when_two_valid_previous():
    store = {"devices": {}, "seeder": {
        "announce_token": {"value": "CUR", "created_at": 1,
                           "expires_at": 0, "revoked": False},
        "announce_token_previous": [
            {"value": "P1", "created_at": 1, "expires_at": 0,
             "revoked": False, "record_id": "a"},
            {"value": "P2", "created_at": 1, "expires_at": 0,
             "revoked": False, "record_id": "b"}]}}
    with pytest.raises(rot.RotationError):
        rot.rotate_announce(store, now=100)


# ---------------------------------------------------------------------------
# Recovery manifest — written FIRST, nonsecret only
# ---------------------------------------------------------------------------

def test_manifest_written_before_any_mutation(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)

    order = []

    def fake_persist(store, path):
        order.append("persist")
        secrets_store.save(store, path)

    seeder = FakeSeeder()
    orig_add = seeder.add

    def tracking_add(b, d):
        order.append("add")
        return orig_add(b, d)
    seeder.add = tracking_add

    def tracking_manifest_write(path, manifest):
        order.append("manifest")
        rot._atomic_write_json(path, manifest)

    deps = rot.RotationDeps(
        persist=fake_persist, seeder_remove=seeder.remove,
        seeder_add=seeder.add, swarm_probe=lambda: True,
        manifest_write=tracking_manifest_write, now=lambda: 100)

    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget(
            image_id="img1", path=str(torrent),
            image_dir=str(tmp_path), gid="gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    assert order[0] == "manifest", "manifest must be written before mutations"
    assert order.index("manifest") < order.index("persist")
    assert order.index("persist") < order.index("add")


def test_manifest_contains_no_tokens_or_urls(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    text = open(manifest_path).read()
    assert "announce_token" not in text
    assert "http://" not in text
    # new current token value must not appear
    store = secrets_store.load(sp)
    assert store["seeder"]["announce_token"]["value"] not in text


# ---------------------------------------------------------------------------
# Durable secret persist BEFORE canonical mutation
# ---------------------------------------------------------------------------

def test_durable_persist_before_canonical_replacement(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)
    order = []
    seeder = FakeSeeder()

    def fake_persist(store, path):
        order.append("persist")
        secrets_store.save(store, path)

    def tracking_add(b, d):
        order.append("add")
        return FakeSeeder.add(seeder, b, d)

    deps = rot.RotationDeps(
        persist=fake_persist, seeder_remove=seeder.remove,
        seeder_add=tracking_add, swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    assert order == ["persist", "add"]


# ---------------------------------------------------------------------------
# Raw-span verified replacement + announce_token= current
# ---------------------------------------------------------------------------

def test_replacement_preserves_info_hash_and_uses_current_token(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)
    old_info = bencode.decode(canon)[b"info"]
    old_hash = hashlib.sha1(bencode.encode(old_info)).hexdigest()

    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    # The add carried the NEW current token, info hash unchanged.
    new_tok = secrets_store.load(sp)["seeder"]["announce_token"]["value"]
    add_ev = [e for e in seeder.events if e[0] == "add"][0]
    ann = add_ev[2]
    assert ("announce_token=%s" % new_tok).encode() in ann
    # canonical file on disk now updated + info hash identical
    updated = torrent.read_bytes()
    up_hash = hashlib.sha1(
        bencode.encode(bencode.decode(updated)[b"info"])).hexdigest()
    assert up_hash == old_hash


# ---------------------------------------------------------------------------
# Serial force-remove then add
# ---------------------------------------------------------------------------

def test_serial_remove_then_add_per_torrent(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    t1 = tmp_path / "a.torrent"
    t1.write_bytes(_canonical())
    t2 = tmp_path / "b.torrent"
    t2.write_bytes(_canonical())
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("a", str(t1), str(tmp_path), "gidA"),
                  rot.TorrentTarget("b", str(t2), str(tmp_path), "gidB")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    kinds = [e[0] for e in seeder.events]
    assert kinds == ["remove", "add", "remove", "add"]


# ---------------------------------------------------------------------------
# Rollback: new-add failure restores EXACT old bytes and attempts old add
# ---------------------------------------------------------------------------

def test_new_add_failure_restores_old_bytes_and_readds(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)

    seeder = FakeSeeder()
    # Fail the NEW add (which carries the new current token).
    store0 = secrets_store.load(sp)
    # new value not known yet; fail by detecting the OLD token is absent:
    # instead, mark: fail any add whose announce lacks 'OLD'.
    class FailNewSeeder(FakeSeeder):
        def add(self, torrent_bytes, image_dir):
            meta = bencode.decode(torrent_bytes)
            ann = meta[b"announce"]
            self.events.append(("add", meta[b"info"][b"name"], ann))
            if b"announce_token=OLD" not in ann:
                raise RuntimeError("new add failed")
            return "gid-old-readd"
    seeder = FailNewSeeder()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    # Old bytes restored on disk EXACTLY.
    assert torrent.read_bytes() == canon
    # An old re-add was attempted (the second add carrying OLD).
    adds = [e for e in seeder.events if e[0] == "add"]
    assert any(b"announce_token=OLD" in e[2] for e in adds)
    # Rollback succeeded -> not a hard no-go, but rotation did not fully apply.
    assert result.rolled_back is True
    assert result.hard_no_go is False


# ---------------------------------------------------------------------------
# Double failure: old re-add ALSO fails -> hard no-go
# ---------------------------------------------------------------------------

def test_double_failure_is_hard_no_go(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    t1 = tmp_path / "a.torrent"
    t1.write_bytes(canon)
    t2 = tmp_path / "b.torrent"
    t2.write_bytes(canon)

    class FailAllAdds(FakeSeeder):
        def add(self, torrent_bytes, image_dir):
            meta = bencode.decode(torrent_bytes)
            self.events.append(("add", meta[b"info"][b"name"],
                                meta[b"announce"]))
            raise RuntimeError("add failed")
    seeder = FailAllAdds()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("a", str(t1), str(tmp_path), "gidA"),
                  rot.TorrentTarget("b", str(t2), str(tmp_path), "gidB")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    assert result.hard_no_go is True
    assert result.maintenance_frozen is True
    assert result.served_claimed is False
    # Old canonical bytes preserved on disk for the failed torrent.
    assert t1.read_bytes() == canon
    # Remaining torrents were NOT processed after the hard stop.
    processed = [e for e in seeder.events if e[0] == "remove"]
    assert ("remove", "gidB") not in processed
    # Manifest preserved.
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] in ("hard_no_go", "double_failure")


def test_result_never_claims_served_on_double_failure(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    t1 = tmp_path / "a.torrent"
    t1.write_bytes(canon)

    class FailAllAdds(FakeSeeder):
        def add(self, torrent_bytes, image_dir):
            self.events.append(("add", None, bencode.decode(
                torrent_bytes)[b"announce"]))
            raise RuntimeError("add failed")
    seeder = FailAllAdds()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("a", str(t1), str(tmp_path), "gidA")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    assert result.served_claimed is False


# ---------------------------------------------------------------------------
# Injectable loopback /swarm probe interface (deferred integration)
# ---------------------------------------------------------------------------

def test_swarm_probe_is_injectable_and_not_required_for_core(tmp_path):
    # Core rotation completes with an injected probe; the helper never imports
    # or touches a tracker in-process registry.
    import inspect
    src = inspect.getsource(rot)
    assert "PeerRegistry" not in src
    assert "import tracker" not in src
    # Probe is part of the deps contract.
    assert "swarm_probe" in rot.RotationDeps._fields
