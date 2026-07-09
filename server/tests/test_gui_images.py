# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import io

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
