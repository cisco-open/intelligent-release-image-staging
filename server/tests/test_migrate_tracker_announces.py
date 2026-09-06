# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os

import bencode
import migrate_tracker_announces as migration
import torrent_personalize


def _torrent(announce=b"http://10.0.0.1:6969/announce?key=old"):
    return bencode.encode({
        b"announce": announce,
        b"announce-list": [[announce]],
        b"info": {
            b"length": 4,
            b"name": b"image.bin",
            b"piece length": 16384,
            b"pieces": hashlib.sha1(b"data").digest(),
        },
    })


def _raw_info_hash(data):
    start, end = torrent_personalize.scan_top_level(data)["info"]
    return hashlib.sha1(data[start:end]).digest()


def test_migrate_rewrites_outer_announce_without_changing_swarm(tmp_path):
    torrents = tmp_path / "torrents"
    torrents.mkdir()
    path = torrents / "image.torrent"
    original = _torrent()
    path.write_bytes(original)
    os.chmod(path, 0o640)

    changed = migration.migrate(
        str(tmp_path), "https://10.0.0.1:6969/announce")

    upgraded = path.read_bytes()
    meta = bencode.decode(upgraded)
    assert changed == 1
    assert meta[b"announce"] == b"https://10.0.0.1:6969/announce"
    assert b"announce-list" not in meta
    assert _raw_info_hash(upgraded) == _raw_info_hash(original)
    assert path.stat().st_mode & 0o777 == 0o640
    assert not list(torrents.glob(".tracker-announce-*.tmp"))


def test_migrate_is_idempotent(tmp_path):
    torrents = tmp_path / "torrents"
    torrents.mkdir()
    path = torrents / "image.torrent"
    current = _torrent(b"https://10.0.0.1:6969/announce")
    # personalize once so the announce-list is already removed too.
    current = torrent_personalize.personalize(
        current, "https://10.0.0.1:6969/announce")
    path.write_bytes(current)

    assert migration.migrate(
        str(tmp_path), "https://10.0.0.1:6969/announce") == 0
    assert path.read_bytes() == current


def test_malformed_torrent_fails_without_replacing_it(tmp_path):
    torrents = tmp_path / "torrents"
    torrents.mkdir()
    path = torrents / "broken.torrent"
    path.write_bytes(b"not-bencode")

    try:
        migration.migrate(str(tmp_path),
                          "https://10.0.0.1:6969/announce")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed canonical torrent was accepted")
    assert path.read_bytes() == b"not-bencode"


def test_main_derives_https_announce_and_does_not_echo_bad_override(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)
    assert migration.main([str(tmp_path)]) == 0
    assert "0 canonical" in capsys.readouterr().out

    secret_url = "http://10.0.0.5:6969/announce?key=do-not-print"
    monkeypatch.setenv("IRIS_TRACKER_ANNOUNCE", secret_url)
    assert migration.main([str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert secret_url not in captured.err
    assert "do-not-print" not in captured.err


def test_main_migrates_orphan_and_quarantined_torrents(tmp_path, monkeypatch):
    torrents = tmp_path / "torrents"
    torrents.mkdir()
    active = torrents / "active.torrent"
    orphan = torrents / "orphan.torrent"
    quarantined = torrents / "quarantined.torrent"
    active.write_bytes(_torrent())
    orphan.write_bytes(_torrent())
    quarantined.write_bytes(_torrent())
    (tmp_path / "catalog.json").write_text(
        '{"images":{"active":{},"quarantined":{"quarantined":true}}}')
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)

    assert migration.main([str(tmp_path)]) == 0
    assert bencode.decode(active.read_bytes())[b"announce"] == \
        b"https://10.0.0.5:6969/announce"
    assert bencode.decode(orphan.read_bytes())[b"announce"] == \
        b"https://10.0.0.5:6969/announce"
    assert bencode.decode(quarantined.read_bytes())[b"announce"] == \
        b"https://10.0.0.5:6969/announce"


def test_main_fails_closed_on_malformed_dormant_torrent(tmp_path, monkeypatch):
    torrents = tmp_path / "torrents"
    torrents.mkdir()
    (torrents / "orphan.torrent").write_bytes(b"malformed orphan")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)

    assert migration.main([str(tmp_path)]) == 1


def test_entrypoint_completes_migration_before_any_network_service():
    server_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(server_dir, "docker-entrypoint.sh"),
              encoding="utf-8") as stream:
        entrypoint = stream.read()
    with open(os.path.join(server_dir, "seed-launch.sh"),
              encoding="utf-8") as stream:
        seed_launch = stream.read()

    migration_pos = entrypoint.index("migrate_tracker_announces.py")
    service_starts = [entrypoint.index(marker) for marker in (
        "python3 tracker.py & T=$!",
        "python3 catalog.py & C=$!",
        "bash seed-launch.sh & S=$!",
        "python3 artifact_server.py & A=$!",
        "python3 management_api.py & M=$!",
    )]
    assert all(migration_pos < start for start in service_starts)
    assert "migrate_tracker_announces.py" not in seed_launch
