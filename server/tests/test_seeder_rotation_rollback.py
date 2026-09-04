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


def _recovery_catalog(tmp_path, image_dir=None):
    image_dir = image_dir or tmp_path
    (image_dir / "img.bin").write_bytes(b"image")
    (tmp_path / "catalog.json").write_text(json.dumps({"images": {
        "img": {"filename": "img.bin", "source_dir": str(image_dir)}}}))


class FakeSeeder:
    """Records force-remove / add calls and can be told to fail specific ones."""

    def __init__(self):
        self.events = []
        self.credential_digests = []

    def remove(self, gid):
        self.events.append(("remove", gid))

    def set_credential(self, announce_token):
        self.credential_digests.append(
            hashlib.sha256(announce_token.encode()).hexdigest())

    def add(self, torrent_bytes, image_dir, announce_token):
        meta = bencode.decode(torrent_bytes)
        ann = meta[b"announce"]
        tid = meta[b"info"][b"name"]
        token_digest = hashlib.sha256(announce_token.encode()).hexdigest()
        self.events.append(("add", tid, ann, token_digest))
        return "gid-1"


def test_rpc_add_sets_current_bearer_as_per_download_option(capsys):
    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if method == "aria2.changeGlobalOption":
            return "OK"
        return "new-gid"

    _remove, add, set_credential = rot._seeder_rpc_ops(rpc)
    torrent = _canonical(b"https://10.0.0.5:6969/announce")
    token = "test-current-bearer"

    set_credential(token)
    assert add(torrent, "/images", token) == "new-gid"
    assert [method for method, _params in calls] == [
        "aria2.changeGlobalOption", "aria2.addTorrent"]
    global_header = calls[0][1][0]["header"][0].rsplit(" ", 1)[1]
    assert hashlib.sha256(global_header.encode()).digest() == \
        hashlib.sha256(token.encode()).digest()
    method, params = calls[1]
    assert method == "aria2.addTorrent"
    assert params[2]["dir"] == "/images"
    headers = params[2]["header"]
    assert len(headers) == 1
    scheme, supplied = headers[0].rsplit(" ", 1)
    assert scheme == "Authorization: Bearer"
    assert hashlib.sha256(supplied.encode()).digest() == \
        hashlib.sha256(token.encode()).digest()
    assert token.encode() not in __import__("base64").b64decode(params[0])
    captured = capsys.readouterr()
    assert token not in captured.out + captured.err


def test_rpc_add_rejects_header_injection_before_rpc(capsys):
    _remove, add, _set_credential = rot._seeder_rpc_ops(
        lambda *args: pytest.fail("RPC called with unsafe bearer"))
    unsafe = "credential\r\nX-Injected: value"

    with pytest.raises(ValueError, match="credential unavailable"):
        add(_canonical(), "/images", unsafe)
    assert unsafe not in capsys.readouterr().err


def test_global_credential_update_requires_aria_acknowledgement():
    _remove, _add, set_credential = rot._seeder_rpc_ops(
        lambda method, params: None)

    with pytest.raises(RuntimeError, match="global credential update failed"):
        set_credential("CURRENT")


def test_recovery_token_loader_uses_current_not_previous(tmp_path):
    path = _seeder_store(tmp_path, value="CURRENT")
    store = secrets_store.load(path)
    store["seeder"]["announce_token_previous"] = [{
        "value": "PREVIOUS", "created_at": 1, "expires_at": 1000,
        "revoked": False,
    }]
    secrets_store.save(store, path)

    value = rot._current_announce_token(path, now=100)
    assert hashlib.sha256(value.encode()).digest() == \
        hashlib.sha256(b"CURRENT").digest()


# ---------------------------------------------------------------------------
# rotate_announce (local, additive store shape)
# ---------------------------------------------------------------------------

def test_rotate_announce_keeps_previous_and_mints_current():
    # Was asserting expires_at == 0 ("non-expiring"): that WAS the defect --
    # nothing retired a previous, so every rotation left a permanent credential.
    store = {"devices": {}, "seeder": {"announce_token": {
        "value": "OLD", "created_at": 1, "expires_at": 0, "revoked": False}}}
    new = rot.rotate_announce(store, now=100)
    assert store["seeder"]["announce_token"]["value"] == new
    assert new != "OLD"
    prev = store["seeder"]["announce_token_previous"]
    assert prev[0]["value"] == "OLD"
    # bounded recovery overlap, measured from this rotation
    assert prev[0]["expires_at"] == 100 + secrets_store.SEEDER_PREV_TTL
    assert prev[0]["rotated_at"] == 100
    assert "record_id" in prev[0]


def test_rotate_announce_retires_an_expired_previous_instead_of_refusing():
    """An expired previous is a dead credential: the pass drops it rather than
    counting it against the cap, so rotation never needs a manual revoke to
    proceed and the old value stops resolving."""
    old = 1000
    store = {"devices": {}, "seeder": {
        "announce_token": {"value": "CUR", "created_at": old,
                           "expires_at": 0, "revoked": False},
        "announce_token_previous": [
            {"value": "P1", "created_at": old, "rotated_at": old,
             "expires_at": old + secrets_store.SEEDER_PREV_TTL,
             "revoked": False, "record_id": "a"},
            {"value": "P2", "created_at": old, "rotated_at": old,
             "expires_at": old + secrets_store.SEEDER_PREV_TTL,
             "revoked": False, "record_id": "b"}]}}
    later = old + secrets_store.SEEDER_PREV_TTL + 1
    new = rot.rotate_announce(store, now=later)
    prev = store["seeder"]["announce_token_previous"]
    assert [r["value"] for r in prev] == ["CUR"]
    assert store["seeder"]["announce_token"]["value"] == new


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


@pytest.mark.parametrize("bad_previous", [{"value": "P1"}, "P1", 7])
def test_rotate_announce_refuses_malformed_previous_container(bad_previous):
    store = {"devices": {}, "seeder": {
        "announce_token": {"value": "CUR", "created_at": 1,
                           "expires_at": 0, "revoked": False},
        "announce_token_previous": bad_previous}}

    with pytest.raises(rot.RotationError,
                       match="invalid previous seeder credential state"):
        rot.rotate_announce(store, now=100)
    assert store["seeder"]["announce_token_previous"] == bad_previous
    assert store["seeder"]["announce_token"]["value"] == "CUR"


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

    def tracking_add(b, d, token):
        order.append("add")
        return orig_add(b, d, token)
    seeder.add = tracking_add

    orig_set_credential = seeder.set_credential

    def tracking_set_credential(token):
        order.append("set_credential")
        return orig_set_credential(token)
    seeder.set_credential = tracking_set_credential

    def tracking_manifest_write(path, manifest):
        order.append("manifest")
        rot._atomic_write_json(path, manifest)

    deps = rot.RotationDeps(
        persist=fake_persist, seeder_remove=seeder.remove,
        seeder_add=seeder.add, seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=tracking_manifest_write, now=lambda: 100)

    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget(
            image_id="img1", path=str(torrent),
            image_dir=str(tmp_path), gid="gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    assert order[0] == "manifest", "manifest must be written before mutations"
    assert order.index("manifest") < order.index("persist")
    assert order.index("persist") < order.index("set_credential")
    assert order.index("set_credential") < order.index("add")


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
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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


def test_manifest_has_durable_exact_backup_and_new_digest(tmp_path):
    sp = _seeder_store(tmp_path)
    torrent = tmp_path / "img.torrent"
    old = _canonical()
    torrent.write_bytes(old)
    seeder = FakeSeeder()
    manifest_path = str(tmp_path / "recovery.json")
    rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "old-gid")],
        "http://h:6969/announce",
        rot.RotationDeps(lambda s, p: secrets_store.save(s, p), seeder.remove,
                         seeder.add, seeder.set_credential,
                         lambda expected, boundary: True,
                         rot._atomic_write_json, lambda: 100))
    manifest = json.load(open(manifest_path))
    row = manifest["torrents"][0]
    assert open(row["backup_path"], "rb").read() == old
    assert row["old_sha256"] == hashlib.sha256(old).hexdigest()
    assert row["new_sha256"] == hashlib.sha256(torrent.read_bytes()).hexdigest()
    assert row["live_gid"] == "gid-1"


@pytest.mark.parametrize("phase", [
    "started", "secret_rotated", "seeder_credential_updated",
    "new_canonical_written", "removing_old",
    "old_removed", "adding_new", "applied", "swarm_probe_failed",
    "rolling_back", "rolled_back", "hard_no_go", "double_failure"])
def test_recover_restores_backup_and_reconciles_active_gid(tmp_path, phase):
    old = _canonical()
    _recovery_catalog(tmp_path)
    canonical = tmp_path / "torrents" / "img.torrent"
    canonical.parent.mkdir()
    canonical.write_bytes(b"changed")
    recovery = tmp_path / "seeder-rotation-recovery"
    recovery.mkdir()
    backup = recovery / "0000.torrent"
    backup.write_bytes(old)
    manifest_path = tmp_path / "seeder-rotation-recovery.json"
    rot._atomic_write_json(str(manifest_path), {
        "version": 2, "phase": phase, "maintenance_frozen": True,
        "torrents": [{"image_id": "img", "path": str(canonical),
                      "image_dir": str(tmp_path), "gid": "old-gid",
                      "info_hash": rot._info_hash(old),
                      "backup_path": str(backup),
                      "old_sha256": hashlib.sha256(old).hexdigest(),
                      "status": "adding_new"}]})
    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if method == "aria2.changeGlobalOption":
            return "OK"
        if method == "aria2.tellActive":
            return [{"gid": "current-gid", "infoHash": rot._info_hash(old)}]
        if method == "aria2.addTorrent":
            return "restored-gid"
        if method == "aria2.tellStatus":
            return {"gid": "restored-gid", "infoHash": rot._info_hash(old)}

    result = rot.recover_rotation(str(manifest_path), str(tmp_path), rpc,
                                  "CURRENT")
    assert result is True
    assert canonical.read_bytes() == old
    assert ("aria2.forceRemove", ["current-gid"]) in calls
    methods = [method for method, _params in calls]
    assert methods.index("aria2.changeGlobalOption") < \
        methods.index("aria2.forceRemove") < methods.index("aria2.addTorrent")
    add_options = next(params[2] for method, params in calls
                       if method == "aria2.addTorrent")
    header_value = add_options["header"][0].rsplit(" ", 1)[1]
    assert hashlib.sha256(header_value.encode()).digest() == \
        hashlib.sha256(b"CURRENT").digest()
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == "recovered"
    assert manifest["maintenance_frozen"] is True
    assert manifest["torrents"][0]["restored_gid"] == "restored-gid"


@pytest.mark.parametrize("backup_path", ["../escape.torrent", "/tmp/escape.torrent"])
def test_recover_rejects_backup_path_outside_recovery_dir(tmp_path, backup_path):
    manifest_path = tmp_path / "seeder-rotation-recovery.json"
    rot._atomic_write_json(str(manifest_path), {
        "version": 2, "phase": "started", "torrents": [{
            "path": str(tmp_path / "torrents" / "img.torrent"),
            "image_dir": str(tmp_path), "backup_path": backup_path,
            "old_sha256": "0" * 64, "info_hash": "0" * 40}]})
    with pytest.raises(ValueError):
        rot.recover_rotation(str(manifest_path), str(tmp_path), lambda *a: [],
                             "CURRENT")
    assert json.load(open(manifest_path))["phase"] == "started"


def test_recover_failure_keeps_actionable_manifest(tmp_path):
    old = _canonical()
    _recovery_catalog(tmp_path)
    recovery = tmp_path / "seeder-rotation-recovery"
    recovery.mkdir()
    backup = recovery / "0000.torrent"
    backup.write_bytes(old)
    canonical = tmp_path / "torrents" / "img.torrent"
    canonical.parent.mkdir()
    canonical.write_bytes(old)
    manifest_path = tmp_path / "seeder-rotation-recovery.json"
    rot._atomic_write_json(str(manifest_path), {
        "version": 2, "phase": "old_removed", "torrents": [{
            "image_id": "img", "path": str(canonical),
            "image_dir": str(tmp_path), "backup_path": str(backup),
            "old_sha256": hashlib.sha256(old).hexdigest(),
            "info_hash": rot._info_hash(old)}]})

    def rpc(method, params):
        if method == "aria2.changeGlobalOption":
            return "OK"
        if method == "aria2.tellActive":
            return []
        raise RuntimeError("second failure")

    assert rot.recover_rotation(str(manifest_path), str(tmp_path), rpc,
                                "CURRENT") is False
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == "repair_needed"
    assert manifest["maintenance_frozen"] is True
    assert manifest["torrents"][0]["status"] == "restore_failed"


@pytest.mark.parametrize("image_dir", ["", "/tmp/attacker-controlled", "gone"])
def test_recover_rejects_invalid_image_dir_before_write_or_rpc(tmp_path, image_dir):
    old = _canonical()
    _recovery_catalog(tmp_path)
    recovery = tmp_path / "seeder-rotation-recovery"
    recovery.mkdir()
    backup = recovery / "0000.torrent"
    backup.write_bytes(old)
    canonical = tmp_path / "torrents" / "img.torrent"
    canonical.parent.mkdir()
    canonical.write_bytes(b"changed")
    manifest_path = tmp_path / "seeder-rotation-recovery.json"
    rot._atomic_write_json(str(manifest_path), {
        "version": 2, "phase": "started", "torrents": [{
            "image_id": "img", "path": str(canonical),
            "image_dir": str(tmp_path / image_dir) if image_dir == "gone" else image_dir,
            "backup_path": str(backup), "old_sha256": hashlib.sha256(old).hexdigest(),
            "info_hash": rot._info_hash(old)}]})
    checkpoint = tmp_path / "identity-compatible-ready"
    checkpoint.write_text("ready\n")

    with pytest.raises(ValueError, match="invalid recovery manifest image directory"):
        rot.recover_rotation(str(manifest_path), str(tmp_path),
                             lambda *args: pytest.fail("RPC called"),
                             "CURRENT")
    assert canonical.read_bytes() == b"changed"
    assert checkpoint.exists()


def test_recover_retracts_deployment_gate_after_validated_recovery_starts(tmp_path):
    old = _canonical()
    _recovery_catalog(tmp_path)
    recovery = tmp_path / "seeder-rotation-recovery"
    recovery.mkdir()
    backup = recovery / "0000.torrent"
    backup.write_bytes(old)
    canonical = tmp_path / "torrents" / "img.torrent"
    canonical.parent.mkdir()
    canonical.write_bytes(b"changed")
    manifest_path = tmp_path / "seeder-rotation-recovery.json"
    rot._atomic_write_json(str(manifest_path), {
        "version": 2, "phase": "started", "torrents": [{
            "image_id": "img", "path": str(canonical), "image_dir": str(tmp_path),
            "backup_path": str(backup), "old_sha256": hashlib.sha256(old).hexdigest(),
            "info_hash": rot._info_hash(old)}]})
    (tmp_path / "identity-compatible-ready").write_text("ready\n")

    def rpc(method, params):
        if method == "aria2.changeGlobalOption":
            return "OK"
        if method == "aria2.tellActive":
            return []
        if method == "aria2.addTorrent":
            return "restored-gid"
        if method == "aria2.tellStatus":
            return {"gid": "restored-gid", "infoHash": rot._info_hash(old)}

    assert rot.recover_rotation(str(manifest_path), str(tmp_path), rpc,
                                "CURRENT") is True
    assert not (tmp_path / "identity-compatible-ready").exists()


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

    def tracking_add(b, d, token):
        order.append("add")
        return FakeSeeder.add(seeder, b, d, token)

    deps = rot.RotationDeps(
        persist=fake_persist, seeder_remove=seeder.remove,
        seeder_add=tracking_add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)
    assert order == ["persist", "add"]


def test_global_credential_failure_precedes_torrent_mutation(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    original = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(original)
    order = []

    def persist(store, path):
        order.append("persist")
        secrets_store.save(store, path)

    def fail_global_update(token):
        order.append("set_credential")
        raise RuntimeError("bounded RPC failed")

    deps = rot.RotationDeps(
        persist=persist,
        seeder_remove=lambda gid: pytest.fail("remove reached"),
        seeder_add=lambda data, directory, token: pytest.fail("add reached"),
        seeder_set_credential=fail_global_update,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    with pytest.raises(RuntimeError, match="bounded RPC failed"):
        rot.rotate_seeder_announce(
            sp, manifest_path,
            [rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                               "gid-old")],
            "http://h:6969/announce", deps)

    assert order == ["persist", "set_credential"]
    assert torrent.read_bytes() == original
    assert json.load(open(manifest_path))["phase"] == "secret_rotated"


# ---------------------------------------------------------------------------
# Raw-span verified replacement + token-free canonical announce
# ---------------------------------------------------------------------------

def test_replacement_preserves_info_hash_without_embedding_token(tmp_path):
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
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    # The rotated current remains in the secret store; neither it nor any
    # credential is embedded in the torrent handed to aria2.
    new_tok = secrets_store.load(sp)["seeder"]["announce_token"]["value"]
    add_ev = [e for e in seeder.events if e[0] == "add"][0]
    ann = add_ev[2]
    assert ann == b"http://h:6969/announce"
    assert new_tok.encode() not in ann
    assert add_ev[3] == hashlib.sha256(new_tok.encode()).hexdigest()
    assert seeder.credential_digests == [
        hashlib.sha256(new_tok.encode()).hexdigest()]
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
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: (
            calls.append((expected, not_before)) or True),
        manifest_write=rot._atomic_write_json, now=iter([100, 101]).__next__)
    result = rot.rotate_seeder_announce(
        sp, str(tmp_path / "recovery.json"),
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert result.served_claimed is True
    assert calls == [({rot._info_hash(torrent.read_bytes())}, 101)]
    assert seeder.events[-1][0] == "add"


@pytest.mark.parametrize("swarm_probe", [
    None, object(), lambda: True, lambda expected, not_before: False])
def test_absent_or_misconfigured_probe_never_claims_served(tmp_path,
                                                           swarm_probe):
    sp = _seeder_store(tmp_path)
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(_canonical())
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
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
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: (_ for _ in ()).throw(TimeoutError()),
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert (result.maintenance_frozen, result.hard_no_go,
            result.served_claimed) == (True, True, False)
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == manifest["error"] == "swarm_probe_failed"


def test_post_add_probe_boundary_failure_is_hard_no_go(tmp_path):
    """A false post-add proof freezes maintenance rather than claiming served."""
    sp = _seeder_store(tmp_path)
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(_canonical())
    calls = []
    seeder = FakeSeeder()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: (
            calls.append((expected, not_before)) or False),
        manifest_write=rot._atomic_write_json, now=iter([100, 101]).__next__)
    result = rot.rotate_seeder_announce(
        sp, str(tmp_path / "recovery.json"),
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid")],
        "http://h:6969/announce", deps)
    assert calls == [({rot._info_hash(torrent.read_bytes())}, 101)]
    assert (result.hard_no_go, result.maintenance_frozen,
            result.served_claimed) == (True, True, False)


# ---------------------------------------------------------------------------
# Rollback: new-add failure restores EXACT old bytes and attempts an old-byte
# add with the current persisted bearer
# ---------------------------------------------------------------------------

def test_new_add_failure_restores_old_bytes_and_readds(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)

    # Fail the first add, then allow the rollback re-add of the old bytes.
    # Both calls must receive the new durably persisted current bearer.
    class FailNewSeeder(FakeSeeder):
        def __init__(self):
            super().__init__()
            self.add_count = 0

        def add(self, torrent_bytes, image_dir, announce_token):
            meta = bencode.decode(torrent_bytes)
            ann = meta[b"announce"]
            token_digest = hashlib.sha256(announce_token.encode()).hexdigest()
            self.events.append(("add", meta[b"info"][b"name"], ann,
                                token_digest))
            self.add_count += 1
            if self.add_count == 1:
                raise RuntimeError("new add failed")
            return "gid-old-readd"
    seeder = FailNewSeeder()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        secrets_path=sp, manifest_path=manifest_path,
        torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                    "gid-old")],
        tracker_announce_base="http://h:6969/announce", deps=deps)

    # Old bytes restored on disk EXACTLY.
    assert torrent.read_bytes() == canon
    # An old-byte re-add was attempted and both RPC calls used the new current
    # credential. The value itself is never copied into the event/audit shape.
    adds = [e for e in seeder.events if e[0] == "add"]
    current = secrets_store.load(sp)["seeder"]["announce_token"]["value"]
    current_digest = hashlib.sha256(current.encode()).hexdigest()
    assert len(adds) == 2
    assert {event[3] for event in adds} == {current_digest}
    assert b"announce_token=OLD" in adds[1][2]
    # Rollback succeeded -> not a hard no-go, but rotation did not fully apply.
    assert result.rolled_back is True
    assert result.hard_no_go is False


def test_later_new_add_failure_rolls_back_every_prior_applied_torrent(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon0 = _canonical()
    info1 = bencode.encode({"name": "img1.bin", "piece length": 16384,
                            "pieces": b"\x33" * 20, "length": 200})
    canon1 = (b"d8:announce"
              + bencode.encode(
                  b"http://h:6969/announce?announce_token=OLD")
              + b"4:info" + info1 + b"e")
    t0, t1 = tmp_path / "t0.torrent", tmp_path / "t1.torrent"
    t0.write_bytes(canon0)
    t1.write_bytes(canon1)
    events = []

    def remove(gid):
        events.append(("remove", gid))

    def add(torrent_bytes, image_dir, announce_token):
        meta = bencode.decode(torrent_bytes)
        name = meta[b"info"][b"name"]
        old_bytes = b"announce_token=OLD" in meta[b"announce"]
        events.append(("add", name, old_bytes))
        if name == b"img1.bin" and not old_bytes:
            raise RuntimeError("later new add failed")
        if name == b"img.bin" and not old_bytes:
            return "new-live-gid0"
        return "restored-" + name.decode()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=remove, seeder_add=add,
        seeder_set_credential=lambda _token: None,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img0", str(t0), str(tmp_path), "old-gid0"),
         rot.TorrentTarget("img1", str(t1), str(tmp_path), "old-gid1")],
        "http://h:6969/announce", deps)

    assert t0.read_bytes() == canon0
    assert t1.read_bytes() == canon1
    assert ("remove", "new-live-gid0") in events
    assert ("add", b"img.bin", True) in events
    assert result.rolled_back is True
    assert result.hard_no_go is False
    assert all(item["restore_readd_ok"] for item in result.affected)
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == "rolled_back"
    assert manifest["maintenance_frozen"] is False


def test_rollback_add_without_gid_is_hard_no_go(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img1.torrent"
    torrent.write_bytes(canon)

    add_calls = []

    def add(torrent_bytes, image_dir, announce_token):
        add_calls.append(hashlib.sha256(announce_token.encode()).hexdigest())
        if len(add_calls) == 1:
            raise RuntimeError("new add failed")
        return None

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=lambda gid: None, seeder_add=add,
        seeder_set_credential=lambda token: None,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img1", str(torrent), str(tmp_path), "gid-old")],
        "http://h:6969/announce", deps)

    assert result.hard_no_go is True
    assert result.served_claimed is False
    assert result.affected[0]["restore_readd_ok"] is False


def test_restore_of_prior_applied_torrent_requires_returned_gid(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon0 = _canonical()
    info1 = bencode.encode({"name": "img1.bin", "piece length": 16384,
                            "pieces": b"\x33" * 20, "length": 200})
    canon1 = (b"d8:announce"
              + bencode.encode(b"http://h:6969/announce?announce_token=OLD")
              + b"4:info" + info1 + b"e")
    t0, t1 = tmp_path / "t0.torrent", tmp_path / "t1.torrent"
    t0.write_bytes(canon0)
    t1.write_bytes(canon1)

    def add(torrent_bytes, image_dir, announce_token):
        meta = bencode.decode(torrent_bytes)
        if meta[b"info"][b"name"] == b"img1.bin":
            raise RuntimeError("later torrent add failed")
        if b"announce_token=OLD" in meta[b"announce"]:
            return None
        return "new-live-gid0"

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=lambda gid: None, seeder_add=add,
        seeder_set_credential=lambda token: None,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img0", str(t0), str(tmp_path), "old-gid0"),
         rot.TorrentTarget("img1", str(t1), str(tmp_path), "old-gid1")],
        "http://h:6969/announce", deps)

    by_id = {item["image_id"]: item for item in result.affected}
    assert result.hard_no_go is True
    assert by_id["img0"]["restore_readd_ok"] is False


# ---------------------------------------------------------------------------
# Double failure: old-byte re-add ALSO fails -> hard no-go
# ---------------------------------------------------------------------------

def test_first_remove_failure_restores_bytes_without_unsafe_readd(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    torrent = tmp_path / "img.torrent"
    torrent.write_bytes(canon)
    seeder = FakeSeeder()

    def remove_fails(gid):
        seeder.events.append(("remove", gid))
        raise RuntimeError("aria RPC response is uncertain")

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=remove_fails, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img", str(torrent), str(tmp_path), "gid-old")],
        "http://h:6969/announce", deps)

    assert torrent.read_bytes() == canon
    assert [event for event in seeder.events if event[0] == "add"] == []
    assert result.hard_no_go is True
    assert result.maintenance_frozen is True
    assert result.served_claimed is False
    assert result.affected == [{"image_id": "img", "gid": "gid-old",
                                "restore_readd_ok": False}]
    manifest = json.load(open(manifest_path))
    assert manifest["phase"] == "hard_no_go"
    assert manifest["error"] == "remove_failed"
    assert manifest["torrents"][0]["status"] == "remove_failed"
    assert "aria RPC" not in json.dumps(manifest)


def test_later_remove_failure_restores_and_repairs_prior_applied(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon0, canon1 = _canonical(), _canonical()
    t0, t1 = tmp_path / "a.torrent", tmp_path / "b.torrent"
    t0.write_bytes(canon0)
    t1.write_bytes(canon1)
    seeder = FakeSeeder()

    def remove_fails_on_second(gid):
        seeder.events.append(("remove", gid))
        if gid == "gid1":
            raise RuntimeError("uncertain")

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=remove_fails_on_second, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img0", str(t0), str(tmp_path), "gid0"),
         rot.TorrentTarget("img1", str(t1), str(tmp_path), "gid1")],
        "http://h:6969/announce", deps)

    assert t0.read_bytes() == canon0 and t1.read_bytes() == canon1
    old_adds = [event for event in seeder.events if event[0] == "add"
                and b"announce_token=OLD" in event[2]]
    assert old_adds, "the prior applied torrent must be repaired"
    assert {item["image_id"] for item in result.affected} == {"img0", "img1"}
    assert {item["image_id"]: item["restore_readd_ok"] for item in result.affected} == {
        "img0": True, "img1": False}

def test_double_failure_is_hard_no_go(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon = _canonical()
    t1 = tmp_path / "a.torrent"
    t1.write_bytes(canon)
    t2 = tmp_path / "b.torrent"
    t2.write_bytes(canon)

    class FailAllAdds(FakeSeeder):
        def add(self, torrent_bytes, image_dir, announce_token):
            meta = bencode.decode(torrent_bytes)
            self.events.append(("add", meta[b"info"][b"name"],
                                meta[b"announce"], hashlib.sha256(
                                    announce_token.encode()).hexdigest()))
            raise RuntimeError("add failed")
    seeder = FailAllAdds()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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
        def add(self, torrent_bytes, image_dir, announce_token):
            self.events.append(("add", None, bencode.decode(
                torrent_bytes)[b"announce"], hashlib.sha256(
                    announce_token.encode()).hexdigest()))
            raise RuntimeError("add failed")
    seeder = FailAllAdds()
    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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
    #  - torrent1 old-byte re-add (name img1.bin, CURRENT bearer): ALSO fails.
    #  - torrent0 restore re-add (name img.bin, CURRENT bearer): is attempted.
    class SelectiveSeeder(FakeSeeder):
        def add(self, torrent_bytes, image_dir, announce_token):
            meta = bencode.decode(torrent_bytes)
            name = meta[b"info"][b"name"]
            ann = meta[b"announce"]
            self.events.append(("add", name, ann, hashlib.sha256(
                announce_token.encode()).hexdigest()))
            if name == b"img1.bin":
                # Both the new add and the old-byte re-add of torrent1 fail.
                raise RuntimeError("torrent1 add failed")
            return "gid-ok"
    seeder = SelectiveSeeder()

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=seeder.remove, seeder_add=seeder.add,
        seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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

    # torrent0 (already applied) had a restore re-add attempted with OLD bytes
    # but the new/current bearer persisted for the whole recovery sequence.
    t0_readds = [e for e in seeder.events
                 if e[0] == "add" and e[1] == b"img.bin"
                 and b"announce_token=OLD" in e[2]]
    assert t0_readds, "applied torrent0 must be restored/re-added with old bytes"
    current = secrets_store.load(sp)["seeder"]["announce_token"]["value"]
    current_digest = hashlib.sha256(current.encode()).hexdigest()
    assert {event[3] for event in seeder.events if event[0] == "add"} == \
        {current_digest}

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


def test_later_rollback_removes_new_live_gid_not_pre_rotation_gid(tmp_path):
    sp = _seeder_store(tmp_path)
    manifest_path = str(tmp_path / "recovery.json")
    canon0 = _canonical()
    info1 = bencode.encode({"name": "img1.bin", "piece length": 16384,
                            "pieces": b"\x22" * 20, "length": 200})
    canon1 = (b"d8:announce"
              + bencode.encode(b"http://h:6969/announce?announce_token=OLD")
              + b"4:info" + info1 + b"e")
    t0, t1 = tmp_path / "t0.torrent", tmp_path / "t1.torrent"
    t0.write_bytes(canon0)
    t1.write_bytes(canon1)
    events = []

    def remove(gid):
        events.append(("remove", gid))
        if gid == "old-gid0" and len(events) > 2:
            raise AssertionError("rollback used stale pre-rotation gid")

    def add(torrent_bytes, image_dir, announce_token):
        meta = bencode.decode(torrent_bytes)
        name, announce = meta[b"info"][b"name"], meta[b"announce"]
        events.append(("add", name, announce))
        if name == b"img1.bin":
            raise RuntimeError("later torrent add fails")
        if b"announce_token=OLD" in announce:
            return "restored-gid0"
        return "new-live-gid0"

    deps = rot.RotationDeps(
        persist=lambda s, p: secrets_store.save(s, p),
        seeder_remove=remove, seeder_add=add,
        seeder_set_credential=lambda token: None,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)

    result = rot.rotate_seeder_announce(
        sp, manifest_path,
        [rot.TorrentTarget("img0", str(t0), str(tmp_path), "old-gid0"),
         rot.TorrentTarget("img1", str(t1), str(tmp_path), "old-gid1")],
        "http://h:6969/announce", deps)

    assert result.hard_no_go is True
    assert ("remove", "new-live-gid0") in events
    assert t0.read_bytes() == canon0


# ---------------------------------------------------------------------------
# Injectable loopback /swarm probe interface (deferred integration)
# ---------------------------------------------------------------------------

def test_swarm_probe_is_injectable_and_not_required_for_core(tmp_path):
    # Core rotation completes with an injected probe; the helper never imports
    # or touches a tracker in-process registry.
    import inspect
    src = inspect.getsource(rot)
    assert "PeerRegistry" not in src
    assert "\nimport tracker\n" not in src
    assert "\nfrom tracker import" not in src
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
        seeder_add=lambda b, d, token: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
        seeder_set_credential=lambda token: None)
    # The persist closure carries the durable marker (introspectable seam).
    assert getattr(deps.persist, "_durable", False) is True


def test_production_deps_default_probe_requires_typed_swarm_proof(tmp_path):
    calls = []
    deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d, token: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
        seeder_set_credential=lambda token: None,
        swarm_sender=lambda url, timeout: (calls.append((url, timeout)) or
                                            _serving_swarm(["abc"],
                                                          last_seen=101)))
    assert deps.swarm_probe({"abc"}, 100) is True
    assert calls == [(rot.DEFAULT_SWARM_URL, 2.0)]

    # The default probe cannot be satisfied by a malformed/misidentified
    # observation even when the transport itself succeeds.
    bad_deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d, token: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "bad.age"),
        seeder_set_credential=lambda token: None,
        swarm_sleep=lambda seconds: None,
        swarm_sender=lambda url, timeout: {"server": {}})
    assert bad_deps.swarm_probe({"abc"}, 100) is False


def test_production_deps_preserves_fractional_rotation_boundary(tmp_path,
                                                                monkeypatch):
    """An announce earlier in the same second must not satisfy the strict
    post-rotation identity proof."""
    import time

    monkeypatch.setattr(time, "time", lambda: 100.75)
    deps = rot.production_deps(
        seeder_remove=lambda gid: None, seeder_add=lambda b, d, token: None,
        recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
        seeder_set_credential=lambda token: None,
        swarm_sleep=lambda seconds: None,
        swarm_sender=lambda url, timeout: _serving_swarm(
            ["abc"], last_seen_by_info_hash={"abc": 100.5}))

    boundary = deps.now()
    assert boundary == 100.75
    assert deps.swarm_probe({"abc"}, boundary) is False


def test_production_deps_rejects_arbitrary_swarm_probe(tmp_path):
    with pytest.raises(TypeError):
        rot.production_deps(
            seeder_remove=lambda gid: None,
            seeder_add=lambda b, d, token: None,
            recipients_csv="age1r", enc_path=str(tmp_path / "s.age"),
            seeder_set_credential=lambda token: None,
            swarm_probe=lambda expected, not_before: True)


def test_production_deps_requires_global_credential_updater(tmp_path):
    with pytest.raises(TypeError, match="credential updater"):
        rot.production_deps(
            seeder_remove=lambda gid: None,
            seeder_add=lambda b, d, token: None,
            recipients_csv="age1r", enc_path=str(tmp_path / "s.age"))


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
        seeder_add=seeder.add, seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
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
        seeder_add=seeder.add, seeder_set_credential=seeder.set_credential,
        swarm_probe=lambda expected, not_before: True,
        manifest_write=rot._atomic_write_json, now=lambda: 100)
    with pytest.raises(RuntimeError):
        rot.rotate_seeder_announce(
            secrets_path=sp, manifest_path=str(tmp_path / "r.json"),
            torrents=[rot.TorrentTarget("img1", str(torrent), str(tmp_path),
                                        "gid-old")],
            tracker_announce_base="http://h:6969/announce", deps=deps)
    assert order == ["persist"]  # never reached remove/add


# ---------------------------------------------------------------------------
# CLI contract: a maintenance-freeze acknowledgement is mandatory before any
# rotation work. Tracker credentials stay in aria2 headers, never torrent URLs.
# ---------------------------------------------------------------------------

def test_cli_requires_maintenance_freeze_acknowledgment(tmp_path, capsys):
    """Argument validation exits before catalog/RPC/manifest mutation."""
    with pytest.raises(SystemExit) as raised:
        rot.main(["--state", str(tmp_path), "--secrets", str(tmp_path / "s")])
    assert raised.value.code == 2
    assert not list(tmp_path.iterdir())
    assert "maintenance-frozen" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Loopback /swarm live verification (spec §6 step 5): the probe proves a
# current, non-legacy service-seeder observation via the /swarm contract only,
# never the tracker's in-process registry. It succeeds ONLY on a
# principal_type='service', principal_id='seeder' observation (deduped under the
# canonical `server` source) proving the relevant canonical torrents serve.
# ---------------------------------------------------------------------------

def _serving_swarm(info_hashes, rpc_up=True, extra_peers=None, last_seen=100.0,
                   last_seen_by_info_hash=None):
    if last_seen_by_info_hash is None:
        last_seen_by_info_hash = {h: last_seen for h in info_hashes}
    return {
        "now": 100.0,
        "server": {"host": "192.0.2.10", "server_observation": {
            "observed_at": 100.0, "rpc_up": rpc_up,
            "tracker_observation": {"principal_type": "service",
                                    "principal_id": "seeder",
                                    "observed_info_hashes": list(info_hashes),
                                    "last_seen": last_seen,
                                    "last_seen_by_info_hash": last_seen_by_info_hash},
            "aria_session_id": "s1", "global": {},
            "torrent": [{"info_hash": h, "image": "cat9k.bin",
                         "upload_length_bytes": 1, "lifetime": "control-state"}
                        for h in info_hashes]}},
        "images": [{"image": "cat9k.bin", "info_hash": h, "total_bytes": 1,
                    "seeders": 0, "leechers": 0,
                    "peers": list(extra_peers or [])}
                   for h in info_hashes],
    }


def test_is_seeder_serving_requires_post_rotation_service_marker():
    for last_seen in (99, 100):
        assert rot.is_seeder_serving(_serving_swarm(["abc"],
                                                     last_seen=last_seen),
                                    ["abc"], 100) is False
    assert rot.is_seeder_serving(_serving_swarm(["abc"], last_seen=101),
                                ["abc"], 100) is True


@pytest.mark.parametrize("value", [float("nan"), float("inf"),
                                  float("-inf"), True])
def test_is_seeder_serving_rejects_nonfinite_or_bool_boundaries(value):
    assert rot.is_seeder_serving(_serving_swarm(["abc"], last_seen=101),
                                 ["abc"], value) is False


@pytest.mark.parametrize("value", [float("nan"), float("inf"),
                                  float("-inf"), True])
def test_is_seeder_serving_rejects_nonfinite_or_bool_last_seen(value):
    assert rot.is_seeder_serving(_serving_swarm(
        ["abc"], last_seen_by_info_hash={"abc": value}), ["abc"], 99) is False


def test_is_seeder_serving_requires_each_hash_post_rotation():
    doc = _serving_swarm(["abc", "def"], last_seen=101,
                         last_seen_by_info_hash={"abc": 101, "def": 100})
    assert rot.is_seeder_serving(doc, ["abc", "def"], 100) is False


def test_is_seeder_serving_accepts_each_hash_post_rotation():
    doc = _serving_swarm(["abc", "def"],
                         last_seen_by_info_hash={"abc": 101, "def": 102})
    assert rot.is_seeder_serving(doc, ["abc", "def"], 100) is True


def test_is_seeder_serving_aggregate_cannot_mask_stale_hash():
    doc = _serving_swarm(["abc", "def"], last_seen=999,
                         last_seen_by_info_hash={"abc": 101, "def": 99})
    assert rot.is_seeder_serving(doc, ["abc", "def"], 100) is False


def test_is_seeder_serving_requires_per_hash_freshness_map():
    doc = _serving_swarm(["abc"])
    del doc["server"]["server_observation"]["tracker_observation"]["last_seen_by_info_hash"]
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_true_when_server_source_proves_torrents():
    doc = _serving_swarm(["abc", "def"])
    assert rot.is_seeder_serving(doc, ["abc", "def"], 99) is True


def test_is_seeder_serving_false_when_rpc_down():
    doc = _serving_swarm(["abc"], rpc_up=False)
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_false_when_expected_torrent_missing():
    doc = _serving_swarm(["abc"])
    assert rot.is_seeder_serving(doc, ["abc", "def"], 99) is False


def test_is_seeder_serving_requires_current_typed_service_marker():
    doc = _serving_swarm(["abc"])
    del doc["server"]["server_observation"]["tracker_observation"]
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_requires_exact_active_hashes():
    doc = _serving_swarm(["abc", "stale"])
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_false_on_empty_expected():
    assert rot.is_seeder_serving(_serving_swarm(["abc"]), [], 99) is False


def test_is_seeder_serving_rejects_legacy_or_device_seeder_row():
    # A seeder announcing on a WRONG/legacy or unattributed credential is NOT
    # deduped: it shows up as a legacy ring peer with role=seeder for the
    # expected torrent. That is a genuine conflict with the canonical dedup ->
    # fail.
    legacy_seeder_peer = {"ip": "192.0.2.10", "port": 6881,
                          "tracker": {"principal_type": "legacy",
                                      "participant_class": "legacy_unattributed",
                                      "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[legacy_seeder_peer])
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_rejects_service_seeder_ring_row():
    # A service:seeder that appears as an UN-deduped ring row (rather than under
    # the canonical `server` source) means the current-seeder identity is not
    # cleanly proven -> fail.
    svc_seeder_peer = {"ip": "192.0.2.10", "port": 6881,
                       "tracker": {"principal_type": "service",
                                   "principal_id": "seeder",
                                   "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[svc_seeder_peer])
    assert rot.is_seeder_serving(doc, ["abc"], 99) is False


def test_is_seeder_serving_allows_completed_device_seeder_row():
    # A typed DEVICE principal that has finished its download (left=0) becomes a
    # role=seeder ring peer. That is a legitimate completed downloader — it does
    # NOT disprove the origin service seeder, whose identity is already proven by
    # the canonical `server` source proof (rpc_up + expected control-state
    # torrents). The probe must succeed and ignore device ring rows.
    completed_device_seeder = {
        "ip": "198.51.100.14", "port": 6881,
        "tracker": {"principal_type": "device", "principal_id": "d1",
                    "role": "seeder", "left": 0}}
    doc = _serving_swarm(["abc"], extra_peers=[completed_device_seeder])
    assert rot.is_seeder_serving(doc, ["abc"], 99) is True


def test_is_seeder_serving_allows_leecher_ring_peers():
    leecher = {"ip": "198.51.100.14", "port": 6881,
               "tracker": {"principal_type": "device", "principal_id": "d1",
                           "role": "leecher", "left": 5}}
    doc = _serving_swarm(["abc"], extra_peers=[leecher])
    assert rot.is_seeder_serving(doc, ["abc"], 99) is True


def test_is_seeder_serving_false_on_garbage():
    assert rot.is_seeder_serving(None, ["abc"], 99) is False
    assert rot.is_seeder_serving({}, ["abc"], 99) is False


def test_make_swarm_probe_polls_with_injectable_sender_and_succeeds():
    calls = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], 99, url="http://127.0.0.1:9101/swarm", timeout=1.0, retries=3,
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

    probe = rot.make_swarm_probe(["abc"], 99, retries=3, timeout=0.5,
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

    probe = rot.make_swarm_probe(["abc"], 99, retries=3, sender=sender,
                                 sleep=lambda s: None)
    assert probe() is True


def test_swarm_probe_never_leaks_token_or_url_in_output(capsys):
    # The probe prints nothing; any error is swallowed to a bool. The default
    # URL constant carries no token.
    assert "token" not in rot.DEFAULT_SWARM_URL.lower()
    probe = rot.make_swarm_probe(
        ["abc"], 99, sender=lambda u, t: (_ for _ in ()).throw(OSError("x")),
        sleep=lambda s: None, retries=1)
    assert probe() is False
    assert capsys.readouterr().out == ""


def test_make_swarm_probe_honors_iris_swarm_url_env(monkeypatch):
    # When no explicit url is passed, the probe resolves IRIS_SWARM_URL at
    # construction so an operator override reaches the sender.
    monkeypatch.setenv("IRIS_SWARM_URL", "https://127.0.0.1:9101/swarm")
    seen = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], 99, sender=lambda u, t: (seen.append(u) or doc),
        sleep=lambda s: None, retries=1)
    assert probe() is True
    assert seen == ["https://127.0.0.1:9101/swarm"]


def test_make_swarm_probe_explicit_url_overrides_env(monkeypatch):
    monkeypatch.setenv("IRIS_SWARM_URL", "https://127.0.0.1:9101/swarm")
    seen = []
    doc = _serving_swarm(["abc"])
    probe = rot.make_swarm_probe(
        ["abc"], 99, url="http://127.0.0.1:1234/swarm",
        sender=lambda u, t: (seen.append(u) or doc),
        sleep=lambda s: None, retries=1)
    assert probe() is True
    assert seen == ["http://127.0.0.1:1234/swarm"]


def test_make_swarm_probe_never_leaks_env_url_on_error(monkeypatch, capsys):
    # A credential-bearing URL is rejected before any sender can receive it,
    # and its value must never surface in output/errors.
    monkeypatch.setenv("IRIS_SWARM_URL",
                       "http://user:s3cr3t-token@127.0.0.1:9999/swarm")
    with pytest.raises(ValueError, match="invalid local swarm URL"):
        rot.make_swarm_probe(
            ["abc"], 99,
            sender=lambda u, t: (_ for _ in ()).throw(OSError("x")),
            sleep=lambda s: None, retries=1)
    out = capsys.readouterr()
    assert "s3cr3t-token" not in (out.out + out.err)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:9101/swarm",
    "https://telemetry.example:9101/swarm",
    "https://127.0.0.1:9102/swarm",
    "https://127.0.0.1:9101/healthz",
    "https://127.0.0.1:9101/swarm?next=https://example.test",
])
def test_default_swarm_url_rejects_nonlocal_or_wrong_origin(monkeypatch, url):
    monkeypatch.setenv("IRIS_SWARM_URL", url)
    with pytest.raises(ValueError, match="invalid local swarm URL"):
        rot._default_swarm_url()
