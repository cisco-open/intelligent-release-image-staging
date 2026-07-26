# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import io
import os
import threading
import time

import gui_images


def _chunks(data, n=3):
    """Return a reader() callable yielding *data* in n-byte chunks then b''."""
    buf = io.BytesIO(data)
    return lambda: buf.read(n)


def test_valid_filename():
    svc = gui_images.ImageService("/tmp/state-x", "/tmp/imgs-x")
    assert svc.valid_filename("cat9k_iosxe.26.01.01.SPA.bin") is True
    assert svc.valid_filename("bad name.bin") is False      # space
    assert svc.valid_filename("../etc/passwd") is False     # slash
    assert svc.valid_filename("..") is False
    assert svc.valid_filename("") is False


def test_save_stream_writes_file(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    path = svc.save_stream("img.bin", _chunks(b"hello-image-bytes"))
    assert path == str(tmp_path / "imgs" / "img.bin")
    with open(path, "rb") as f:
        assert f.read() == b"hello-image-bytes"


def test_save_stream_rejects_bad_filename(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    try:
        svc.save_stream("../evil", _chunks(b"x"))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_save_stream_enforces_size_cap(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    try:
        svc.save_stream("img.bin", _chunks(b"0123456789"), max_bytes=4)
        assert False, "expected ValueError"
    except ValueError:
        pass
    import os
    assert not os.path.exists(str(tmp_path / "imgs" / "img.bin"))


def test_save_stream_rejects_incomplete_upload(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    try:
        svc.save_stream("img.bin", _chunks(b"12345"), expected=100)
        assert False, "expected ValueError"
    except ValueError:
        pass
    import os
    assert not os.path.exists(str(tmp_path / "imgs" / "img.bin"))


import time as _time


def _wait_job(svc, job_id, timeout=3.0):
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        job = svc.get_job(job_id)
        if job and job["state"] in ("done", "error"):
            return job
        _time.sleep(0.01)
    return svc.get_job(job_id)


def test_start_publish_runs_and_completes(tmp_path):
    calls = {}

    def fake_publish(image_path, store, tracker_url, **kw):
        calls["image_path"] = image_path
        calls["tracker_url"] = tracker_url
        return {"id": "img1", "filename": "img.bin", "sha256": "ab"}

    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  tracker_url_fn=lambda: "http://t:6969/announce?key=k",
                                  publish_fn=fake_publish)
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    job_id = svc.start_publish(p)
    job = _wait_job(svc, job_id)
    assert job["state"] == "done"
    assert job["image_id"] == "img1"
    assert calls["image_path"] == p
    assert calls["tracker_url"] == "http://t:6969/announce?key=k"


def test_start_publish_error_when_no_tracker_url(tmp_path):
    def fake_publish(*a, **k):
        raise AssertionError("must not be called without a tracker url")

    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  tracker_url_fn=lambda: None,
                                  publish_fn=fake_publish)
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    job = _wait_job(svc, svc.start_publish(p))
    assert job["state"] == "error"
    assert "tracker" in job["message"].lower()


def test_start_publish_error_propagates_message(tmp_path):
    def boom(*a, **k):
        raise RuntimeError("mktorrent exploded")

    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  tracker_url_fn=lambda: "http://t/announce?key=k",
                                  publish_fn=boom)
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    job = _wait_job(svc, svc.start_publish(p))
    assert job["state"] == "error"
    assert "mktorrent exploded" in job["message"]


def test_get_job_unknown_returns_none(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    assert svc.get_job("nope") is None


def test_old_terminal_jobs_are_evicted(tmp_path):
    clock = {"t": 1000}
    svc = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: "http://t/announce?key=k",
        publish_fn=lambda ip, s, u, **k: {"id": "img1"},
        now_fn=lambda: clock["t"])
    p1 = svc.image_path("a.bin"); open(p1, "wb").close()
    j1 = svc.start_publish(p1)
    assert _wait_job(svc, j1)["state"] == "done"
    assert svc.get_job(j1) is not None            # retained while fresh
    clock["t"] = 1000 + 3601                       # advance past the TTL
    p2 = svc.image_path("b.bin"); open(p2, "wb").close()
    j2 = svc.start_publish(p2)                     # triggers the sweep
    assert _wait_job(svc, j2)["state"] == "done"
    assert svc.get_job(j1) is None                # j1 evicted
    assert svc.get_job(j2) is not None            # j2 retained


def test_delete_image_removes_everything(tmp_path):
    removed = {}
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  seeder_remove_fn=lambda ih: removed.setdefault("ih", ih))
    # publish an entry + its files
    store = svc._store()
    store.save_image({"id": "img1", "filename": "img1.bin", "size": 3,
                      "sha256": "ab", "info_hash_hex": "deadbeef", "published_at": 1})
    imgfile = svc.image_path("img1.bin"); open(imgfile, "wb").write(b"abc")
    open(store.torrent_path("img1"), "wb").write(b"d")
    assert svc.delete_image("img1") == []            # deleted, not blocked
    assert store.get_image("img1") is None
    import os
    assert not os.path.exists(imgfile)
    assert not os.path.exists(store.torrent_path("img1"))
    assert removed["ih"] == "deadbeef"               # seeder told to stop


def test_delete_image_blocked_when_assigned(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  seeder_remove_fn=lambda ih: None)
    store = svc._store()
    store.save_image({"id": "img1", "filename": "img1.bin", "info_hash_hex": "x",
                      "published_at": 1})
    store.set_policy("d1", approved_image_id="img1")
    store.set_policy("d2", approved_image_id="img1")
    assert svc.delete_image("img1") == ["d1", "d2"]   # blocked; lists devices
    assert store.get_image("img1") is not None         # nothing removed


def test_delete_image_ignores_stale_policy_with_live_fleet(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  seeder_remove_fn=lambda ih: None)
    store = svc._store()
    store.save_image({"id": "img1", "filename": "img1.bin", "info_hash_hex": "x",
                      "published_at": 1})
    store.set_policy("d1", approved_image_id="img1")   # d1 later removed from fleet
    # live fleet no longer contains d1 -> the stale policy must not block deletion
    assert svc.delete_image("img1", live_device_ids=set()) == []
    assert store.get_image("img1") is None
    # but a device still present in the live fleet does block
    store.save_image({"id": "img2", "filename": "img2.bin", "info_hash_hex": "y",
                      "published_at": 1})
    store.set_policy("d2", approved_image_id="img2")
    assert svc.delete_image("img2", live_device_ids={"d2"}) == ["d2"]
    assert store.get_image("img2") is not None


def test_delete_image_not_found(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  seeder_remove_fn=lambda ih: None)
    try:
        svc.delete_image("nope")
        assert False
    except KeyError:
        pass


# ---- image_publish_finished audit emission (issue #19) ----
# Publish is async: without this emission a failed publish would leave NO
# audit trace after the image_upload event.

def test_publish_finished_emits_audit_ok(tmp_path):
    clock = {"t": 1000}
    calls = []

    def fake_publish(image_path, store, tracker_url, **kw):
        clock["t"] += 52
        return {"id": "imgX", "filename": "img.bin", "sha256": "ab"}

    svc = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: "http://t:6969/announce?key=k",
        publish_fn=fake_publish, now_fn=lambda: clock["t"],
        audit_fn=lambda **kw: calls.append(kw))
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    assert _wait_job(svc, svc.start_publish(p))["state"] == "done"
    ev = [c for c in calls if c["event"] == "image_publish_finished"][0]
    assert ev["category"] == "image" and ev["action"] == "publish"
    assert ev["actor"] == "system" and ev["target"] == "img.bin"
    assert ev["result"] == "ok"
    assert ev["detail"] == "published id imgX in 52s"


def test_publish_finished_emits_audit_fail(tmp_path):
    calls = []

    def boom(*a, **k):
        raise RuntimeError("mktorrent exploded")

    svc = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: "http://t:6969/announce?key=k",
        publish_fn=boom, now_fn=lambda: 1000,
        audit_fn=lambda **kw: calls.append(kw))
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    assert _wait_job(svc, svc.start_publish(p))["state"] == "error"
    ev = [c for c in calls if c["event"] == "image_publish_finished"][0]
    assert ev["result"] == "fail"
    assert ev["detail"] == "publish failed after 0s: mktorrent exploded"


def test_publish_audit_fn_raising_does_not_break_job(tmp_path):
    def boom_audit(**kw):
        raise OSError("audit sink unavailable")

    svc = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: "http://t:6969/announce?key=k",
        publish_fn=lambda ip, s, u, **k: {"id": "img1"},
        audit_fn=boom_audit)
    p = svc.image_path("img.bin")
    open(p, "wb").close()
    assert _wait_job(svc, svc.start_publish(p))["state"] == "done"


def test_get_image_passthrough(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"))
    assert svc.get_image("nope") is None
    svc._store().save_image({"id": "img1", "filename": "img1.bin",
                             "published_at": 1})
    assert svc.get_image("img1")["filename"] == "img1.bin"


# ---- import of images already on disk ----

def _svc_with_roots(tmp_path, seed_import=True):
    """ImageService over an images volume plus a separate read-only-style
    import root, both populated with one .bin."""
    vol = tmp_path / "imgs"
    imp = tmp_path / "opt-images"
    vol.mkdir(parents=True)
    if seed_import:
        (imp / "iosxe" / "c9300").mkdir(parents=True)
        (imp / "iosxe" / "c9300" / "cat9k.26.01.01.SPA.bin").write_bytes(b"c9k")
    (vol / "orphan.26.01.01.SPA.bin").write_bytes(b"orphaned-upload")
    return gui_images.ImageService(str(tmp_path / "state"), str(vol),
                                   import_root=str(imp))


def test_list_importable_finds_both_roots_and_recurses(tmp_path):
    found = {c["filename"]: c for c in _svc_with_roots(tmp_path).list_importable()}
    assert set(found) == {"orphan.26.01.01.SPA.bin", "cat9k.26.01.01.SPA.bin"}
    assert found["orphan.26.01.01.SPA.bin"]["root"] == "volume"
    assert found["cat9k.26.01.01.SPA.bin"]["root"] == "import"
    assert found["orphan.26.01.01.SPA.bin"]["size"] == len(b"orphaned-upload")


def test_list_importable_is_sorted_by_filename(tmp_path):
    svc = _svc_with_roots(tmp_path)
    names = [c["filename"] for c in svc.list_importable()]
    assert names == sorted(names)


def test_list_importable_excludes_non_images(tmp_path):
    svc = _svc_with_roots(tmp_path, seed_import=False)
    vol = tmp_path / "imgs"
    (vol / "notes.txt").write_bytes(b"x")
    (vol / "abc123.torrent").write_bytes(b"x")
    (vol / ".hidden.bin").write_bytes(b"x")
    (vol / ".upload-abc.tmp").write_bytes(b"x")
    (vol / "bad name.bin").write_bytes(b"x")
    names = [c["filename"] for c in svc.list_importable()]
    assert names == ["orphan.26.01.01.SPA.bin"]


def test_list_importable_excludes_already_published(tmp_path):
    svc = _svc_with_roots(tmp_path, seed_import=False)
    svc._store().save_image({"id": "orphan.26.01.01",
                             "filename": "orphan.26.01.01.SPA.bin",
                             "published_at": 1})
    assert svc.list_importable() == []


def test_list_importable_reports_unreadable_file_as_skipped(tmp_path):
    """A file the process cannot READ is not importable. Listing only needs the
    directory, so an unreadable image would otherwise pass discovery and fail
    deep inside publish with a bare PermissionError — which is exactly what
    happens to root-owned 0600 images left behind by a pre-non-root container."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    unreadable = tmp_path / "imgs" / "locked.26.01.01.SPA.bin"
    unreadable.write_bytes(b"cannot-read-me")
    os.chmod(str(unreadable), 0o000)
    try:
        assert "locked.26.01.01.SPA.bin" not in \
            [c["filename"] for c in svc.list_importable()]
        assert svc.is_importable_path(str(unreadable)) is False
        skipped = {s["filename"]: s["reason"] for s in svc.list_skipped()}
        assert skipped["locked.26.01.01.SPA.bin"] == "not readable by the server"
    finally:
        os.chmod(str(unreadable), 0o644)


def test_list_importable_rejects_symlink_escaping_root(tmp_path):
    svc = _svc_with_roots(tmp_path, seed_import=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"not-ours")
    os.symlink(str(outside / "secret.bin"),
               str(tmp_path / "imgs" / "escape.bin"))
    names = [c["filename"] for c in svc.list_importable()]
    assert names == ["orphan.26.01.01.SPA.bin"]


def test_identical_roots_are_scanned_once(tmp_path):
    """The Kubernetes configmap points IRIS_IMAGES_DIR and IMAGES_ROOT at the
    same directory. Walking it twice would make every file collide with itself
    and be refused as ambiguous, so nothing would ever be importable there."""
    vol = tmp_path / "data-images"
    vol.mkdir()
    (vol / "same.26.01.01.SPA.bin").write_bytes(b"one-copy")
    svc = gui_images.ImageService(str(tmp_path / "state"), str(vol),
                                  import_root=str(vol))
    found = svc.list_importable()
    assert [c["filename"] for c in found] == ["same.26.01.01.SPA.bin"]
    assert svc.list_skipped() == []
    assert svc.is_importable_path(found[0]["path"]) is True


def test_import_root_nested_inside_the_volume_is_scanned_once(tmp_path):
    """Same hazard if the import root is a SUBDIRECTORY of the uploads volume —
    os.walk of the parent already yields those files."""
    vol = tmp_path / "imgs"
    nested = vol / "staged"
    nested.mkdir(parents=True)
    (nested / "nested.26.01.01.SPA.bin").write_bytes(b"x")
    svc = gui_images.ImageService(str(tmp_path / "state"), str(vol),
                                  import_root=str(nested))
    assert [c["filename"] for c in svc.list_importable()] == \
        ["nested.26.01.01.SPA.bin"]
    assert svc.list_skipped() == []


def test_list_importable_tolerates_missing_import_root(tmp_path):
    svc = gui_images.ImageService(str(tmp_path / "state"), str(tmp_path / "imgs"),
                                  import_root=str(tmp_path / "absent"))
    open(svc.image_path("only.bin"), "wb").close()
    assert [c["filename"] for c in svc.list_importable()] == ["only.bin"]


def test_delete_of_in_place_image_never_touches_a_volume_twin(tmp_path):
    """An image published in place from the read-only root must not take a
    same-named file in the uploads volume with it on delete — that file is
    exactly what a catalog-wipe recovery depends on."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    src = tmp_path / "opt-images" / "iosxe"
    src.mkdir(parents=True, exist_ok=True)
    in_place = src / "twin.26.01.01.SPA.bin"
    in_place.write_bytes(b"the-published-one")
    volume_twin = tmp_path / "imgs" / "twin.26.01.01.SPA.bin"
    volume_twin.write_bytes(b"unrelated-orphan-do-not-delete")
    svc._store().save_image({"id": "twin.26.01.01",
                             "filename": "twin.26.01.01.SPA.bin",
                             "source_dir": str(src), "published_at": 1})
    assert svc.delete_image("twin.26.01.01") == []
    assert volume_twin.exists(), "deleted an unrelated file in the uploads volume"
    assert in_place.exists(), "removed the operator's file from the import root"


def test_delete_of_uploaded_image_still_removes_its_file(tmp_path):
    svc = _svc_with_roots(tmp_path, seed_import=False)
    up = tmp_path / "imgs" / "uploaded.26.01.01.SPA.bin"
    up.write_bytes(b"uploaded")
    svc._store().save_image({"id": "uploaded.26.01.01",
                             "filename": "uploaded.26.01.01.SPA.bin",
                             "source_dir": str(tmp_path / "imgs"),
                             "published_at": 1})
    assert svc.delete_image("uploaded.26.01.01") == []
    assert not up.exists()


def test_delete_legacy_entry_without_source_dir_removes_volume_file(tmp_path):
    """Entries published before source_dir was recorded keep the old behaviour:
    the uploads-volume file is removed."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    up = tmp_path / "imgs" / "legacy.26.01.01.SPA.bin"
    up.write_bytes(b"legacy")
    svc._store().save_image({"id": "legacy.26.01.01",
                             "filename": "legacy.26.01.01.SPA.bin",
                             "published_at": 1})
    assert svc.delete_image("legacy.26.01.01") == []
    assert not up.exists()


def test_publish_records_the_source_directory(tmp_path):
    import publish
    seeded = {}
    root = tmp_path / "ro-root"
    root.mkdir()
    img = root / "rec.26.01.01.SPA.bin"
    img.write_bytes(b"bytes")
    store = gui_images.ImageService(str(tmp_path / "state"),
                                    str(tmp_path / "imgs"))._store()
    entry = publish.publish(str(img), store, "http://t:6969/announce?key=k",
                            seeder=lambda b, d: seeded.setdefault("dir", d))
    assert entry["source_dir"] == str(root)
    assert store.get_image(entry["id"])["source_dir"] == str(root)


def test_list_importable_excludes_derived_id_collision(tmp_path):
    """The catalog is keyed on derive_id(), which strips .SPA.bin OR .bin — so
    foo.bin collides with a published foo.SPA.bin even though the basenames
    differ. Importing it would overwrite the live entry's hashes/info_hash."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    (tmp_path / "imgs" / "twin.bin").write_bytes(b"other-release")
    svc._store().save_image({"id": "twin", "filename": "twin.SPA.bin",
                             "published_at": 1})
    names = [c["filename"] for c in svc.list_importable()]
    assert "twin.bin" not in names
    assert svc.is_importable_path(str(tmp_path / "imgs" / "twin.bin")) is False
    skipped = {s["filename"]: s["reason"] for s in svc.list_skipped()}
    assert skipped["twin.bin"] == "already published"


def test_list_importable_excludes_ambiguous_basenames(tmp_path):
    """Same basename in both roots: reseed_input resolves a torrent back to a
    directory by BASENAME (first root wins), so importing either one creates a
    catalog entry the restart re-seed cannot disambiguate — and aria2 seeds
    unverified. Fail closed rather than seed the wrong bytes."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    (tmp_path / "opt-images").mkdir(parents=True, exist_ok=True)
    (tmp_path / "opt-images" / "orphan.26.01.01.SPA.bin").write_bytes(b"different")
    assert svc.list_importable() == []
    reasons = {s["reason"] for s in svc.list_skipped()}
    assert reasons == {"ambiguous name in more than one location"}
    for p in (str(tmp_path / "imgs" / "orphan.26.01.01.SPA.bin"),
              str(tmp_path / "opt-images" / "orphan.26.01.01.SPA.bin")):
        assert svc.is_importable_path(p) is False


def test_list_importable_excludes_two_candidates_sharing_a_derived_id(tmp_path):
    """foo.SPA.bin and foo.bin both derive to id 'foo' — importing one then the
    other would silently overwrite the first entry."""
    svc = _svc_with_roots(tmp_path, seed_import=False)
    os.remove(str(tmp_path / "imgs" / "orphan.26.01.01.SPA.bin"))
    (tmp_path / "imgs" / "foo.SPA.bin").write_bytes(b"a")
    (tmp_path / "imgs" / "foo.bin").write_bytes(b"b")
    assert svc.list_importable() == []
    assert {s["reason"] for s in svc.list_skipped()} == {
        "ambiguous name in more than one location"}


def test_list_importable_excludes_in_flight_publish(tmp_path):
    """A publish is async; the catalog entry appears only when it finishes. A
    second import of the same id in that window must not be offered."""
    started = []
    svc = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        import_root=str(tmp_path / "absent"),
        tracker_url_fn=lambda: "http://t/announce?key=k",
        publish_fn=lambda p, s, u, **k: started.append(p) or _block())
    p = svc.image_path("slow.26.01.01.SPA.bin")
    open(p, "wb").close()
    assert [c["filename"] for c in svc.list_importable()] == \
        ["slow.26.01.01.SPA.bin"]
    svc.start_publish(p)
    for _ in range(200):
        if started:
            break
        time.sleep(0.01)
    assert svc.list_importable() == []
    assert svc.is_importable_path(p) is False
    assert svc.publish_in_flight("slow.26.01.01") is True
    _release()


_GATE = threading.Event()


def _block():
    _GATE.wait(timeout=5)
    return {"id": "slow.26.01.01"}


def _release():
    _GATE.set()


def test_importable_path_identifies_candidates_only(tmp_path):
    """The route authorizes by candidate identity, never by path prefix."""
    svc = _svc_with_roots(tmp_path)
    good = svc.list_importable()[0]["path"]
    assert svc.is_importable_path(good) is True
    assert svc.is_importable_path(str(tmp_path / "imgs" / "nope.bin")) is False
    # a prefix of a real root, but not a discovered candidate
    assert svc.is_importable_path(
        str(tmp_path / "imgs" / ".." / "outside" / "secret.bin")) is False
