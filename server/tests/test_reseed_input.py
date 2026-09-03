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


def test_recorded_source_dir_beats_the_basename_walk(tmp_path):
    """A catalog entry that records where it was published FROM must be re-seeded
    from exactly that directory. Resolving by basename would pick the uploads
    dir's same-named file and, because the seeder runs with
    bt-seed-unverified, serve the wrong bytes under the right piece hashes."""
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    ro_root = tmp_path / "opt-images" / "iosxe"; ro_root.mkdir(parents=True)
    (uploads / "img.bin").write_bytes(b"unrelated-same-name")
    (ro_root / "img.bin").write_bytes(b"the-published-one")
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {
        "img": {"filename": "img.bin", "source_dir": str(ro_root)}}}))
    lines = reseed_input.build(str(st), "%s:%s" % (uploads, tmp_path / "opt-images"),
                               "/def")
    assert lines == [str(st / "torrents" / "img.torrent"), " dir=" + str(ro_root)]


def test_stale_source_dir_falls_back_to_the_walk(tmp_path):
    """If the recorded directory is gone (mount removed, image relocated), fall
    back to the basename walk rather than emitting a path that does not exist."""
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "img.bin").write_bytes(b"x")
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {
        "img": {"filename": "img.bin",
                "source_dir": str(tmp_path / "gone-away")}}}))
    lines = reseed_input.build(str(st), str(uploads), "/def")
    assert lines == [str(st / "torrents" / "img.torrent"), " dir=" + str(uploads)]


# ---------------------------------------------------------------------------
# The catalog is the authority on WHAT the restart re-seeds: a quarantine
# force-removed its torrent from the seeder on purpose, and a torrent file
# with no catalog row was left by a publish that failed after mktorrent ran.
# ---------------------------------------------------------------------------

def test_quarantined_image_is_not_reseeded_on_restart(tmp_path):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "ok.bin").write_bytes(b"x")
    (uploads / "bad.bin").write_bytes(b"y")
    (st / "torrents" / "ok.torrent").write_bytes(b"d")
    (st / "torrents" / "bad.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {
        "ok": {"filename": "ok.bin", "source_dir": str(uploads)},
        "bad": {"filename": "bad.bin", "source_dir": str(uploads),
                "quarantined": True, "quarantine_actions_complete": True}}}))
    skipped = []
    lines = reseed_input.build(str(st), str(uploads), "/def", skipped=skipped)
    assert lines == [str(st / "torrents" / "ok.torrent"), " dir=" + str(uploads)]
    assert skipped == [("bad", "quarantined")]


def test_released_quarantine_is_reseeded_again(tmp_path):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "img.bin").write_bytes(b"x")
    (st / "torrents" / "img.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {
        "img": {"filename": "img.bin", "source_dir": str(uploads),
                "quarantined": False}}}))
    assert reseed_input.build(str(st), str(uploads), "/def") == [
        str(st / "torrents" / "img.torrent"), " dir=" + str(uploads)]


def test_torrent_without_a_catalog_row_is_not_reseeded(tmp_path):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "orphan.bin").write_bytes(b"x")
    (st / "torrents" / "orphan.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {}}))
    skipped = []
    assert reseed_input.build(str(st), str(uploads), "/def", skipped=skipped) == []
    assert skipped == [("orphan", "no catalog entry")]


def test_no_catalog_means_nothing_is_authorized(tmp_path):
    st = _state(tmp_path)
    (st / "torrents" / "orphan.torrent").write_bytes(b"d")
    assert reseed_input.build(str(st), str(tmp_path), "/def") == []


def test_main_reports_skips_on_stderr_only(tmp_path, capsys):
    st = _state(tmp_path)
    uploads = tmp_path / "uploads"; uploads.mkdir()
    (uploads / "ok.bin").write_bytes(b"x")
    (st / "torrents" / "ok.torrent").write_bytes(b"d")
    (st / "torrents" / "bad.torrent").write_bytes(b"d")
    (st / "catalog.json").write_text(json.dumps({"images": {
        "ok": {"filename": "ok.bin", "source_dir": str(uploads)},
        "bad": {"filename": "bad.bin", "source_dir": str(uploads),
                "quarantined": True}}}))
    assert reseed_input.main([str(st), str(uploads), "/def"]) == 0
    out = capsys.readouterr()
    assert out.out.splitlines() == [str(st / "torrents" / "ok.torrent"),
                                    " dir=" + str(uploads)]
    assert "skipping bad.torrent: quarantined" in out.err
