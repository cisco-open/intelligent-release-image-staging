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
        seeder_add=seeder.add, swarm_probe=lambda expected: True,
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
        swarm_probe=lambda expected: True,
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
        seeder_add=tracking_add, swarm_probe=lambda expected: True,
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
        swarm_probe=lambda expected: True,
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
        swarm_probe=lambda expected: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("a", str(t1), str(tmp_path), "gidA"),
                  rot.TorrentTarget("b", str(t2), str(tmp_path), "gidB")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    kinds = [e[0] for e in seeder.events]
    assert kinds == ["remove", "add", "remove", "add"]


def test_success_claims_served_only_after_probe(tmp_path):
    sp = _seeder_store(tmp_path)
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(_canonical())
    calls = []
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda expected: (calls.append(expected) or True),
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    result = rot.rotate_seeder_announce(
        sp, str(tmp_path / "recovery.json"),
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert result.served_claimed is True
    assert calls == [{rot._info_hash(torrent.read_bytes())}]
    assert seeder.events[-1][0] == "add"


@pytest.mark.parametrize("swarm_probe", [None, object(), lambda: True])
def test_absent_or_misconfigured_probe_never_claims_served(tmp_path,
                                                           swarm_probe):
    sp = _seeder_store(tmp_path)
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(_canonical())
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=swarm_probe, manifest_write=rot._atomic_write_json,
        now=lambda: 100)
    result = rot.rotate_seeder_announce(
        sp, str(tmp_path / "recovery.json"),
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert result.served_claimed is False
    assert result.hard_no_go is True


def test_failed_probe_freezes_and_never_claims_served(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(_canonical())
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda expected: (_ for _ in ()).throw(TimeoutError()),
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert (result.maintenance_frozen, result.hard_no_go,
            result.served_claimed) == (True, True, False)
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == manifest["error"] == "swarm_probe_failed"


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
        swarm_probe=lambda expected: True,
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
        swarm_probe=lambda expected: True,
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
        swarm_probe=lambda expected: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("a", str(t1), str(tmp_path), "gidA")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    assert result.served_claimed is False


# ---------------------------------------------------------------------------
# Multi-torrent double failure: a LATER torrent double-fails after an EARLIER
# torrent was already applied. The safe contract restores the exact old
# canonical bytes for EVERY previously applied torrent (and attempts to re-add
# them), aborts the remaining torrents, preserves the manifest, stays frozen,
# reports all affected torrents explicitly, and never claims served — even
# though serving repair (a re-add that itself failed) may still be required.
# ---------------------------------------------------------------------------

def test_multi_torrent_later_double_failure_restores_all_applied(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    # Two distinct canonical torrents so we can prove per-file restoration.
    canon0 = _canonical(
        announce=b"http://h:6969/announce?announce_token=OLD")
    info1 = bencode.encode({"name": "img1.bin", "piece length": 16384,
                            "pieces": b"\x11" * 20, "length": 200})
    canon1 = (b"d8:announce"
              + bencode.encode(b"http://h:6969/announce?announce_token=OLD")
              + b"4:info" + info1 + b"e")
    t0 = tmp_path / "t0.torrent"
    t0.write_bytes(canon0)
    t1 = tmp_path / "t1.torrent"
    t1.write_bytes(canon1)

    # Seeder behaviour:
    #  - torrent0 new-add (name img.bin, NEW token): succeeds.
    #  - torrent1 new-add (name img1.bin, NEW token): fails.
    #  - torrent1 old re-add (name img1.bin, OLD token): ALSO fails -> double.
    #  - torrent0 restore re-add (name img.bin, OLD token): must be attempted.
    class SelectiveSeeder(FakeSeeder):
        def add(self, torrent_bytes, image_dir):
            meta = bencode.decode(torrent_bytes)
            name = meta[b"info"][b"name"]
            ann = meta[b"announce"]
            self.events.append(("add", name, ann))
            if name == b"img1.bin":
                # Both the new add and the old re-add of torrent1 fail.
                raise RuntimeError("torrent1 add failed")
            return "gid-ok"
    seeder = SelectiveSeeder()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        swarm_probe=lambda expected: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img0", str(t0), str(tmp_path), "gid0"),
                  rot.TorrentTarget("img1", str(t1), str(tmp_path), "gid1")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    # Hard no-go, frozen, never served.
    assert result.hard_no_go is True
    assert result.maintenance_frozen is True
    assert result.served_claimed is False

    # EVERY previously applied torrent's EXACT old canonical bytes are restored
    # on disk — even torrent0, which applied successfully.
    assert t0.read_bytes() == canon0
    assert t1.read_bytes() == canon1

    # torrent0 (already applied) had a restore re-add attempted with OLD bytes.
    t0_readds = [e for e in seeder.events
                 if e[0] == "add" and e[1] == b"img.bin"
                 and b"announce_token=OLD" in e[2]]
    assert t0_readds, "applied torrent0 must be restored/re-added with old bytes"

    # All affected torrents are reported explicitly (both t0 and t1).
    affected_ids = {a["image_id"] for a in result.affected}
    assert affected_ids == {"img0", "img1"}
    # torrent0's re-add succeeded (restored); torrent1's re-add failed (repair
    # still required) — both surfaced, never masked as served.
    by_id = {a["image_id"]: a for a in result.affected}
    assert by_id["img1"]["restore_readd_ok"] is False
    assert by_id["img0"]["restore_readd_ok"] is True

    # Manifest preserved with the double-failure phase and frozen flag.
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == "double_failure"
    assert manifest["maintenance_frozen"] is True
    assert manifest["served_claimed"] is False


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


# ---------------------------------------------------------------------------
# F3: production durable-first persist wiring (secretfs.persist_store semantics)
# ---------------------------------------------------------------------------

def test_durable_persist_adapter_uses_secretfs_not_plaintext_save(
        tmp_path, monkeypatch):
    """The production persist adapter routes through secretfs.persist_store
    (durable-encrypted-first) — never the plaintext-only secrets_store.save."""
    import secretfs
    calls = {"persist_store": 0, "save": 0}

    def fake_persist_store(store, plain_path, recipients_csv=None,
                           enc_path=None, age_bin=secretfs.AGE_BIN):
        calls["persist_store"] += 1
        # Emulate the durable-first commit without touching secrets_store.save.
        with open(plain_path, "w") as f:
            json.dump(store, f)

    def poisoned_save(store, path):
        calls["save"] += 1
        raise AssertionError("operational path must not call secrets_store.save")

    monkeypatch.setattr(secretfs, "persist_store", fake_persist_store)
    monkeypatch.setattr(secrets_store, "save", poisoned_save)

    persist = rot.durable_persist(
        recipients_csv="age1recipient", enc_path=str(tmp_path / "s.age"))
    persist({"seeder": {}}, str(tmp_path / "secrets.json"))
    assert calls["persist_store"] == 1
    assert calls["save"] == 0


def test_durable_persist_adapter_requires_recipients_and_enc_path(tmp_path):
    """The adapter refuses to build a plaintext-only operational persist: it
    demands recipients AND an enc path so it cannot silently degrade."""
    with pytest.raises(ValueError):
        rot.durable_persist(recipients_csv="", enc_path=str(tmp_path / "s.age"))
    with pytest.raises(ValueError):
        rot.durable_persist(recipients_csv="age1r", enc_path="")


def test_production_deps_persist_is_durable(tmp_path):
    """production_deps wires the durable adapter as its persist — the seam a
    test could override, but whose default is never plaintext-only save."""
    deps = rot.production_deps(
        seeder_remove=lambda gid: None,
        seeder_add=lambda b, d: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"))
    # The persist closure carries the durable marker (introspectable seam).
    assert getattr(deps.persist, "_durable", False) is True


def test_production_deps_default_probe_requires_typed_swarm_proof(tmp_path):
    calls = []
    deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
        swarm_sender=lambda url, timeout: (calls.append((url, timeout)) or
                                           _serving_swarm(["abc"])))
    assert deps.swarm_probe({"abc"}) is True
    assert calls == [(rot.DEFAULT_SWARM_URL, 2.0)]

    # The default probe cannot be satisfied by a malformed/misidentified
    # observation even when the transport itself succeeds.
    bad_deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "bad.age"),
        swarm_sender=lambda url, timeout: {"server": {}})
    assert bad_deps.swarm_probe({"abc"}) is False


def test_production_deps_accepts_explicit_expected_hash_probe(tmp_path):
    seen = []
    deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
        swarm_probe=lambda expected: (seen.append(expected) or True))
    assert deps.swarm_probe({"abc"}) is True
    assert seen == [{"abc"}]


def test_durable_failure_leaves_canonical_bytes_and_plaintext_untouched(
        tmp_path, monkeypatch):
    """If the encrypted durable persist fails, rotation aborts BEFORE any
    canonical torrent mutation: the live plaintext secrets and every canonical
    torrent file are left byte-identical to their pre-rotation state."""
    import secretfs

    sp = _seeder_store(tmp_path)
    plaintext_before = open(sp, "rb").read()
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)

    def failing_persist_store(store, plain_path, recipients_csv=None,
                              enc_path=None, age_bin=secretfs.AGE_BIN):
        # Emulate encrypt_from raising (bad recipient / age failure): the real
        # persist_store leaves plain_path untouched and re-raises.
        raise RuntimeError("age encrypt failed")

    monkeypatch.setattr(secretfs, "persist_store", failing_persist_store)

    seeder = FakeSeeder()
    persist = rot.durable_persist(
        recipients_csv="age1recipient", enc_path=str(tmp_path / "s.age"))
    deps = rot.RotationDeps(
        persist=persist, seeder_remove=seeder.remove,
        seeder_add=seeder.add, swarm_probe=lambda expected: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    with pytest.raises(RuntimeError):
        rot.rotate_seeder_announce(
            secrets_path=sp, manifest_path=manifest_path,
            torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                        "gid-old")],
            tracker_announce_base="http://h:6969/announce", deps=deps)

    # No canonical mutation, no live-plaintext divergence.
    assert torrent.read_bytes() == canon
    assert open(sp, "rb").read() == plaintext_before
    # The seeder was never touched (durable persist precedes all add/remove).
    assert seeder.events == []


def test_durable_failure_rollback_ordering_precedes_seeder(tmp_path,
                                                           monkeypatch):
    """Ordering: durable persist is attempted (and here fails) before any
    seeder remove/add — proving secretfs failure short-circuits the mutation
    path entirely."""
    import secretfs
    order = []

    def failing_persist_store(store, plain_path, recipients_csv=None,
                              enc_path=None, age_bin=secretfs.AGE_BIN):
        order.append("persist")
        raise RuntimeError("durable failed")

    monkeypatch.setattr(secretfs, "persist_store", failing_persist_store)

    sp = _seeder_store(tmp_path)
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)
    seeder = FakeSeeder()

    def tracking_remove(gid):
        order.append("remove")
    persist = rot.durable_persist(
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"))
    deps = rot.RotationDeps(
        persist=persist, seeder_remove=tracking_remove,
        seeder_add=seeder.add, swarm_probe=lambda expected: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    with pytest.raises(RuntimeError):
        rot.rotate_seeder_announce(
            secrets_path=sp, manifest_path=str(tmp_path / "r.json"),
            torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                        "gid-old")],
            tracker_announce_base="http://h:6969/announce", deps=deps)
    assert order == ["persist"]  # never reached remove/add


# ---------------------------------------------------------------------------
# F1 / contract: `announce_token=` torrents are NOT deployable until the tracker
# resolver integration lands. The core helper mints/embeds the credential but
# the live wiring (CLI) refuses to perform a real rotation, and the module
# documents that the tracker-side consumer is a separate integration.
# ---------------------------------------------------------------------------

def test_announce_token_not_deployable_until_tracker_resolver(monkeypatch,
                                                              capsys):
    # The CLI is a non-operational core helper until the deployment/tracker
    # wiring lands; it must not perform a live rotation and must say so.
    rc = rot.main(["--state", "/tmp/x", "--secrets", "/tmp/y"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "live wiring pending" in err
    # Source/contract: the module states the tracker-side consumer is deferred
    # and the deployment path leaves the probe uncalled until then.
    import inspect
    src = inspect.getsource(rot)
    assert "announce_token" in src
    assert "deferred" in src or "later task" in src


# ---------------------------------------------------------------------------
# Loopback /swarm live verification (spec §6 step 5): the probe proves a
# current, non-legacy service-seeder observation via the /swarm contract only,
# never the tracker's in-process registry. It succeeds ONLY on a
# principal_type='service', principal_id='seeder' observation (deduped under the
# canonical `server` source) proving the relevant canonical torrents serve.
# ---------------------------------------------------------------------------

def _serving_swarm(info_hashes, rpc_up=True, extra_peers=None):
    return {
        "now": 100.0,
        "server": {"host": "100.90.168.20", "server_observation": {
            "observed_at": 100.0, "rpc_up": rpc_up,
            "tracker_observation": {"principal_type": "service",
                                    "principal_id": "seeder",
                                    "observed_info_hashes": list(info_hashes),
                                    "last_seen": 100.0},
            "aria_session_id": "s1", "global": {},
            "torrent": [{"info_hash": h, "image": "cat9k.bin",
                         "upload_length_bytes": 1, "lifetime": "control-state"}
                        for h in info_hashes]}},
        "images": [{"image": "cat9k.bin", "info_hash": h, "total_bytes": 1,
                    "seeders": 0, "leechers": 0,
                    "peers": list(extra_peers or [])}
                   for h in info_hashes],
    }


def test_is_seeder_serving_true_when_server_source_proves_torrents():
    doc = _serving_swarm(["abc", "def"])
    assert rot.is_seeder_serving(doc, ["abc", "def"]) is True


def test_is_seeder_serving_false_when_rpc_down():
    doc = _serving_swarm(["abc"], rpc_up=False)
    assert rot.is_seeder_serving(doc, ["abc"]) is False


def test_is_seeder_serving_false_when_expected_torrent_missing():
    doc = _serving_swarm(["abc"])
    assert rot.is_seeder_serving(doc, ["abc", "def"]) is False


def test_is_seeder_serving_requires_current_typed_service_marker():
    doc = _serving_swarm(["abc"])
    del doc["server"]["server_observation"]["tracker_observation"]
    assert rot.is_seeder_serving(doc, ["abc"]) is False


def test_is_seeder_serving_requires_exact_active_hashes():
    doc = _serving_swarm(["abc", "stale"])
    assert rot.is_seeder_serving(doc, ["abc"]) is False


def test_is_seeder_serving_false_on_empty_expected():
    assert rot.is_seeder_serving(_serving_swarm(["abc"]), []) is False


def test_is_seeder_serving_rejects_legacy_or_device_seeder_row():
    # A seeder announcing on a WRONG/legacy or unattributed credential is NOT
    # deduped: it shows up as a legacy ring peer with role=seeder for the
    # expected torrent. That is a genuine conflict with the canonical dedup ->
    # fail.
    legacy_seeder_peer = {"ip": "100.90.168.20", "port": 6881,
                          "tracker": {"principal_type": "legacy",
                                      "participant_class": "legacy_unattributed",
                                      "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[legacy_seeder_peer])
    assert rot.is_seeder_serving(doc, ["abc"]) is False


def test_is_seeder_serving_rejects_service_seeder_ring_row():
    # A service:seeder that appears as an UN-deduped ring row (rather than under
    # the canonical `server` source) means the current-seeder identity is not
    # cleanly proven -> fail.
    svc_seeder_peer = {"ip": "100.90.168.20", "port": 6881,
                       "tracker": {"principal_type": "service",
                                   "principal_id": "seeder",
                                   "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[svc_seeder_peer])
    assert rot.is_seeder_serving(doc, ["abc"]) is False


def test_is_seeder_serving_allows_completed_device_seeder_row():
    # A typed DEVICE principal that has finished its download (left=0) becomes a
    # role=seeder ring peer. That is a legitimate completed downloader — it does
    # NOT disprove the origin service seeder, whose identity is already proven by
    # the canonical `server` source proof (rpc_up + expected control-state
    # torrents). The probe must succeed and ignore device ring rows.
    completed_device_seeder = {
        "ip": "100.92.100.14", "port": 6881,
        "tracker": {"principal_type": "device", "principal_id": "d1",
                    "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[completed_device_seeder])
    assert rot.is_seeder_serving(doc, ["abc"]) is True


def test_is_seeder_serving_allows_leecher_ring_peers():
    leecher = {"ip": "100.92.100.14", "port": 6881,
               "tracker": {"principal_type": "device", "principal_id": "d1",
                           "role": "leecher", "left": 5}}
    doc = _serving_swarm(["abc"], extra_peers=[leecher])
    assert rot.is_seeder_serving(doc, ["abc"]) is True


def test_is_seeder_serving_false_on_garbage():
    assert rot.is_seeder_serving(None, ["abc"]) is False
    assert rot.is_seeder_serving({}, ["abc"]) is False


def test_make_swarm_probe_polls_with_injectable_sender_and_succeeds():
    calls = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], url="http://127.0.0.1:9101/swarm", timeout=1.0, retries=3,
        sender=lambda u, t: (calls.append((u, t)) or doc),
        sleep=lambda s: None)
    assert probe() is True
    assert calls == [("http://127.0.0.1:9101/swarm", 1.0)]


def test_make_swarm_probe_retries_then_fails_closed():
    attempts = {"n": 0}
    sleeps = []

    def sender(url, timeout):
        attempts["n"] += 1
        raise OSError("connection refused")

    probe = rot.make_swarm_probe(["abc"], retries=3, timeout=0.5,
                                 sender=sender, sleep=sleeps.append)
    assert probe() is False
    assert attempts["n"] == 3
    assert sleeps == [0.5, 0.5]      # slept between attempts, not after last


def test_make_swarm_probe_succeeds_after_transient_failure():
    doc = _serving_swarm(["abc"])
    seq = [OSError("nope"), doc]

    def sender(url, timeout):
        v = seq.pop(0)
        if isinstance(v, Exception):
            raise v
        return v

    probe = rot.make_swarm_probe(["abc"], retries=3, sender=sender,
                                 sleep=lambda s: None)
    assert probe() is True


def test_swarm_probe_never_leaks_token_or_url_in_output(capsys):
    # The probe prints nothing; any error is swallowed to a bool. The default
    # URL constant carries no token.
    assert "token" not in rot.DEFAULT_SWARM_URL.lower()
    probe = rot.make_swarm_probe(
        ["abc"], sender=lambda u, t: (_ for _ in ()).throw(OSError("x")),
        sleep=lambda s: None, retries=1)
    assert probe() is False
    assert capsys.readouterr().out == ""


def test_make_swarm_probe_honors_iris_swarm_url_env(monkeypatch):
    # When no explicit url is passed, the probe resolves IRIS_SWARM_URL at
    # construction so an operator override reaches the sender.
    monkeypatch.setenv("IRIS_SWARM_URL", "http://127.0.0.1:9999/swarm")
    seen = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], sender=lambda u, t: (seen.append(u) or doc),
        sleep=lambda s: None, retries=1)
    assert probe() is True
    assert seen == ["http://127.0.0.1:9999/swarm"]


def test_make_swarm_probe_explicit_url_overrides_env(monkeypatch):
    monkeypatch.setenv("IRIS_SWARM_URL", "http://127.0.0.1:9999/swarm")
    seen = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], url="http://127.0.0.1:1234/swarm",
        sender=lambda u, t: (seen.append(u) or doc),
        sleep=lambda s: None, retries=1)
    assert probe() is True
    assert seen == ["http://127.0.0.1:1234/swarm"]


def test_make_swarm_probe_never_leaks_env_url_on_error(monkeypatch, capsys):
    # A secret-bearing IRIS_SWARM_URL must never surface in output/errors.
    monkeypatch.setenv("IRIS_SWARM_URL",
                       "http://user:s3cr3t-token@127.0.0.1:9999/swarm")
    probe = rot.make_swarm_probe(
        ["abc"], sender=lambda u, t: (_ for _ in ()).throw(OSError("x")),
        sleep=lambda s: None, retries=1)
    assert probe() is False
    out = capsys.readouterr()
    assert "s3cr3t-token" not in (out.out + out.err)
