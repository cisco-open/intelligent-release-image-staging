# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json

import reseed_input


def _state(tmp_path):
    st = tmp_path / "state"
    (st / "torrents").mkdir(parents=True)
    return st


def test_resolves_image_only_in_upload_dir(tmp_path):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "img.bin").write_bytes(b"x")
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(
        json.dumps({"images": {"img": {"filename": "img.bin"}}}))
    lines = reseed_input.build(str(st), "%s:%s" % (uploads, tmp_path / "bundled"), "/def")
    assert lines == [str(st / "torrents" / "img.torrent"), " dir=" + str(uploads)]


def test_upload_dir_wins_on_basename_collision(tmp_path):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    bundled = tmp_path / "bundled"; bundled.mkdir()
    (uploads / "img.bin").write_bytes(b"upload")
    (bundled / "img.bin").write_bytes(b"bundled")
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(
        json.dumps({"images": {"img": {"filename": "img.bin"}}}))
    # caller lists uploads first -> uploads wins on collision
    lines = reseed_input.build(str(st), "%s:%s" % (uploads, bundled), "/def")
    assert (" dir=" + str(uploads)) in lines
    assert (" dir=" + str(bundled)) not in lines


def test_falls_back_to_default_when_image_missing(tmp_path):
    st = _state(tmp_path)
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(
        json.dumps({"images": {"img": {"filename": "img.bin"}}}))
    lines = reseed_input.build(str(st), str(tmp_path / "nope"), "/def")
    assert " dir=/def" in lines


def test_no_torrents_yields_no_lines(tmp_path):
    st = _state(tmp_path)
    assert reseed_input.build(str(st), str(tmp_path), "/def") == []
