# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Response-header contract for personalized torrents (spec §6).

A device-specific personalized torrent MUST carry ``Cache-Control: private,
no-store`` and ``Vary: Authorization`` so proxies/browsers never cache another
device's body, and MUST NOT leak the announce token or URL. A canonical
(service) response carries no such personalization headers."""
import os
import threading
import time

import bencode
import catalog
import auth
import secrets_store


def _valid_torrent_bytes(announce=b"http://old:6969/announce"):
    info = bencode.encode({"name": "img.bin", "piece length": 16384,
                           "pieces": b"\x00" * 20, "length": 100})
    return b"d8:announce" + bencode.encode(announce) + b"4:info" + info + b"e"


def test_personalized_headers_present_via_route(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(_valid_torrent_bytes())
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    os.environ["IRIS_HOST_IP"] = "10.9.9.9"
    now = time.time()
    store_dict = {"devices": {"dev-h": {"announce_token": {
        "value": "ANNH", "created_at": now, "expires_at": 0,
        "revoked": False}}}, "seeder": {}}
    cat = catalog.Catalog(s, str(tmp_path / "secrets.json"))
    ctx = auth.AuthContext(
        principal=auth.Principal("device", "dev-h"),
        secret_name="catalog_token", scope="catalog")
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=ctx, store_dict=store_dict)
    assert len(result) == 4, "personalized response must carry extra headers"
    status, ctype, body, headers = result
    assert status == 200
    hdrs = dict(headers)
    assert hdrs["Cache-Control"] == "private, no-store"
    assert hdrs["Vary"] == "Authorization"
    assert b"ANNH" in bencode.decode(body)[b"announce"]


def test_canonical_response_has_no_personalization_headers(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(_valid_torrent_bytes())
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    cat = catalog.Catalog(s, str(tmp_path / "secrets.json"))
    ctx = auth.AuthContext(
        principal=auth.Principal("service", "seeder"),
        secret_name="catalog_token", scope="catalog")
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=ctx, store_dict={})
    assert len(result) == 3  # no extra personalization headers
