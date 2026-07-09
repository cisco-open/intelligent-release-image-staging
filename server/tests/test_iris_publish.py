# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import shutil
import time

import pytest

import bencode
import catalog
import publish
import secrets_store


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_end_to_end(tmp_path):
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image payload" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    captured = {}

    def fake_seeder(torrent_bytes, image_dir):
        captured["bytes"] = torrent_bytes
        captured["dir"] = image_dir

    entry = publish.publish(
        str(img), store,
        tracker_url="http://127.0.0.1:6969/announce?key=tok",
        image_id=None, signature_verified=False, seeder=fake_seeder)

    # id derived from filename (strip .SPA.bin)
    assert entry["id"] == "cat9k_iosxe.26.01.01"
    # sha256 correct
    assert entry["sha256"] == hashlib.sha256(img.read_bytes()).hexdigest()
    # info_hash matches sha1 of the torrent's info dict
    torrent_path = store.torrent_path(entry["id"])
    meta = bencode.decode(open(torrent_path, "rb").read())
    assert entry["info_hash_hex"] == \
        hashlib.sha1(bencode.encode(meta[b"info"])).hexdigest()
    # catalog persisted + seeder invoked with the image's dir
    assert store.get_image("cat9k_iosxe.26.01.01") is not None
    assert captured["dir"] == str(tmp_path)


def test_derive_id_strips_known_suffixes():
    assert publish.derive_id("cat9k_iosxe.26.01.01.SPA.bin") == "cat9k_iosxe.26.01.01"
    assert publish.derive_id("C9800-SW-iosxe-wlc.26.01.01.SPA.bin") == \
        "C9800-SW-iosxe-wlc.26.01.01"
    assert publish.derive_id("plain.bin") == "plain"


def test_default_tracker_url_from_secrets_store(tmp_path, monkeypatch):
    # The secrets-broker store (tokens.txt retired): the seeder pseudo-device
    # holds the announce_token that keys the private tracker URL.
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", int(time.time()))
    tok = store["seeder"]["announce_token"]["value"]
    sec = tmp_path / "secrets.json"
    secrets_store.save(store, str(sec))
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    monkeypatch.setenv("IRIS_TOKENS", str(tmp_path / "no-such-tokens.txt"))
    assert publish.default_tracker_url() == \
        "http://10.0.0.5:6969/announce?key=%s" % tok


def test_default_tracker_url_legacy_tokens_fallback(tmp_path, monkeypatch):
    # Pre-broker installs with no secrets.json fall back to tokens.txt.
    toks = tmp_path / "tokens.txt"
    toks.write_text("# header comment\nLEGACYSEEDTOK\n")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "absent.json"))
    monkeypatch.setenv("IRIS_TOKENS", str(toks))
    assert publish.default_tracker_url() == \
        "http://10.0.0.5:6969/announce?key=LEGACYSEEDTOK"


def test_default_tracker_url_none_without_host_ip(monkeypatch):
    monkeypatch.delenv("IRIS_HOST_IP", raising=False)
    assert publish.default_tracker_url() is None


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_seeder_failure_does_not_commit_catalog(tmp_path):
    """If the seeder add fails, publish must NOT persist the catalog entry."""
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    def failing_seeder(torrent_bytes, image_dir):
        raise RuntimeError("aria2 RPC unreachable")

    with pytest.raises(RuntimeError, match="aria2 RPC unreachable"):
        publish.publish(
            str(img), store,
            tracker_url="http://127.0.0.1:6969/announce?key=tok",
            image_id=None, signature_verified=False, seeder=failing_seeder)

    # The catalog must NOT contain the entry — no advertised-but-unseeded window.
    assert store.get_image("cat9k_iosxe.26.01.01") is None


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_seeder_called_before_catalog_commit(tmp_path):
    """Seeder is invoked (and succeeds) before the catalog entry is persisted."""
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    call_order = []

    original_save = store.save_image

    def tracking_save(entry):
        call_order.append("catalog")
        original_save(entry)

    store.save_image = tracking_save

    def tracking_seeder(torrent_bytes, image_dir):
        call_order.append("seeder")

    publish.publish(
        str(img), store,
        tracker_url="http://127.0.0.1:6969/announce?key=tok",
        image_id=None, signature_verified=False, seeder=tracking_seeder)

    assert call_order == ["seeder", "catalog"], (
        "seeder must be called before catalog.save_image; got %s" % call_order)


def test_default_rpc_secret_env_wins(monkeypatch):
    monkeypatch.setenv("IRIS_RPC_SECRET", "ENVSECRET")
    assert publish.default_rpc_secret() == "ENVSECRET"


def test_default_rpc_secret_explicit_file(tmp_path, monkeypatch):
    f = tmp_path / "rpc-secret"
    f.write_text("FILESECRET\n")
    monkeypatch.delenv("IRIS_RPC_SECRET", raising=False)
    monkeypatch.setenv("IRIS_RPC_SECRET_FILE", str(f))
    assert publish.default_rpc_secret() == "FILESECRET"


def test_default_rpc_secret_missing_returns_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("IRIS_RPC_SECRET", raising=False)
    monkeypatch.setenv("IRIS_RPC_SECRET_FILE", str(tmp_path / "absent"))
    assert publish.default_rpc_secret() == ""
