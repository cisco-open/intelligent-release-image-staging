# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Publishing and hash verification cannot outlive clean backup proof."""
import threading
import time

import pytest

import gui_images


def service(tmp_path, publish=None, verify=None):
    return gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "images"),
        tracker_url_fn=lambda: "https://tracker.invalid/announce",
        publish_fn=publish or (lambda *_args: {"id": "test"}),
        verification_fn=verify)


@pytest.mark.parametrize("phase", ["publish", "verify", "finish"])
def test_shutdown_waits_through_last_publisher_write(tmp_path, monkeypatch, phase):
    entered, release = threading.Event(), threading.Event()

    def blocked(*_args):
        entered.set()
        release.wait(5)
        return {"id": "test", "outcome": "ok"}

    images = service(tmp_path, publish=blocked if phase == "publish" else None,
                     verify=blocked if phase == "verify" else None)
    if phase == "finish":
        original = images._finish

        def finish(*args, **kwargs):
            blocked()
            return original(*args, **kwargs)

        monkeypatch.setattr(images, "_finish", finish)
    images.start_publish(str(tmp_path / "test.bin"))
    try:
        assert entered.wait(2)
        assert images.shutdown(timeout=0.02) is False
        with pytest.raises(ValueError, match="shutting down"):
            images.start_publish(str(tmp_path / "another.bin"))
    finally:
        release.set()
    assert images.shutdown(timeout=2) is True


def test_sticky_uncaught_publisher_failure_cannot_be_laundered(tmp_path):
    class Crash(BaseException):
        pass

    def crash(*_args):
        raise Crash()

    images = service(tmp_path, publish=crash)
    images.start_publish(str(tmp_path / "test.bin"))
    assert images.shutdown(timeout=2) is False
    assert not images._publish_active


@pytest.mark.parametrize("uncertain", [True, False])
def test_interrupted_thread_launch_is_never_clean(tmp_path, monkeypatch, uncertain):
    images = service(tmp_path)
    exception = KeyboardInterrupt if uncertain else RuntimeError

    def fail(_thread):
        raise exception()

    monkeypatch.setattr(gui_images.threading.Thread, "start", fail)
    with pytest.raises(exception):
        images.start_publish(str(tmp_path / "test.bin"))
    assert images.shutdown(timeout=0.02) is False
    assert bool(images._publish_active) is uncertain


def test_shutdown_deadline_includes_lock_contention(tmp_path):
    images = service(tmp_path)
    images._lock.acquire()
    try:
        started = time.monotonic()
        assert images.shutdown(timeout=0.02) is False
        assert time.monotonic() - started < 0.5
    finally:
        images._lock.release()
    assert images.shutdown(timeout=0.02) is True


def test_admission_is_registered_before_thread_launch(tmp_path, monkeypatch):
    images = service(tmp_path)
    original = threading.Thread.start

    def start(thread):
        assert images._publish_active
        assert images.shutdown(timeout=0.01) is False
        return original(thread)

    monkeypatch.setattr(gui_images.threading.Thread, "start", start)
    images.start_publish(str(tmp_path / "test.bin"))
    assert images.shutdown(timeout=2) is True
