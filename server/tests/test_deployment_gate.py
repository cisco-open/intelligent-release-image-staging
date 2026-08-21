# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Deployment gate: the catalog refuses to serve any PERSONALIZED (device)
torrent before the explicit checkpoint, and proves zero personalized GETs were
served pre-open (spec §6). The canonical (service) path is unaffected."""
import os

import bencode
import catalog
import auth


def _valid_torrent_bytes(announce=b"http://old:6969/announce"):
    info = bencode.encode({"name": "img.bin", "piece length": 16384,
                           "pieces": b"\x00" * 20, "length": 100})
    return b"d8:announce" + bencode.encode(announce) + b"4:info" + info + b"e"


def _catalog_with_torrent(tmp_path, deployment_open):
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(_valid_torrent_bytes())
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    os.environ["IRIS_HOST_IP"] = "10.5.5.5"
    return catalog.Catalog(s, str(tmp_path / "secrets.json"),
                           deployment_open=deployment_open)


def _device_ctx():
    return auth.AuthContext(
        principal=auth.Principal("device", "dev-g"),
        secret_name="catalog_token", scope="catalog")


def _device_store(now=0):
    import time
    now = now or time.time()
    return {"devices": {"dev-g": {"announce_token": {
        "value": "ANNG", "created_at": now, "expires_at": 0,
        "revoked": False}}}, "seeder": {}}


def test_personalized_get_refused_before_checkpoint(tmp_path):
    cat = _catalog_with_torrent(tmp_path, deployment_open=False)
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=_device_ctx(), store_dict=_device_store())
    status = result[0]
    assert status == 503
    # Proof: zero personalized GETs served before open.
    assert cat.personalized_served_count == 0


def test_personalized_get_served_after_checkpoint(tmp_path):
    cat = _catalog_with_torrent(tmp_path, deployment_open=False)
    # Pre-open attempt refused, counter stays zero.
    cat.route_get("/v1/torrents/img1.torrent",
                  auth_ctx=_device_ctx(), store_dict=_device_store())
    assert cat.personalized_served_count == 0
    # Reach the checkpoint, then serve.
    cat.open_deployment()
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=_device_ctx(), store_dict=_device_store())
    assert result[0] == 200
    assert cat.personalized_served_count == 1
    assert b"announce_token=ANNG" in bencode.decode(result[2])[b"announce"]


def test_canonical_get_unaffected_by_gate(tmp_path):
    # A service principal receives canonical bytes even before the checkpoint.
    cat = _catalog_with_torrent(tmp_path, deployment_open=False)
    ctx = auth.AuthContext(
        principal=auth.Principal("service", "seeder"),
        secret_name="catalog_token", scope="catalog")
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=ctx, store_dict={})
    assert result[0] == 200
    assert result[2] == _valid_torrent_bytes()  # canonical, no personalization
    assert cat.personalized_served_count == 0


def test_make_server_can_start_closed(tmp_path):
    import threading
    import http.client
    import secrets_store
    import time
    sp = str(tmp_path / "secrets.json")
    now = time.time()
    store = secrets_store.load(sp)
    dev = store["devices"].setdefault("dev-g", {})
    dev["catalog_token"] = {"value": "ctok", "created_at": now,
                            "expires_at": now + 3600, "revoked": False}
    dev["announce_token"] = {"value": "ANNG", "created_at": now,
                             "expires_at": 0, "revoked": False}
    secrets_store.save(store, sp)
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(_valid_torrent_bytes())
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    os.environ["IRIS_HOST_IP"] = "10.5.5.5"
    srv = catalog.make_server("127.0.0.1", 0, s, sp, deployment_open=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                       timeout=5)
        c.request("GET", "/v1/torrents/img1.torrent",
                  headers={"Authorization": "Bearer ctok"})
        r = c.getresponse()
        assert r.status == 503
    finally:
        srv.shutdown()
