# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Manual audit-export writes are part of the managed shutdown proof."""
import threading

import pytest

import audit_export


@pytest.fixture(autouse=True)
def isolated_jobs(monkeypatch):
    lock = threading.Lock()
    monkeypatch.setattr(audit_export, "_JOBS", {})
    monkeypatch.setattr(audit_export, "_JOBS_LOCK", lock)
    monkeypatch.setattr(audit_export, "_EXPORT_CONDITION", threading.Condition(lock))
    monkeypatch.setattr(audit_export, "_EXPORT_ACTIVE", set())
    monkeypatch.setattr(audit_export, "_EXPORT_FAILED", False)
    monkeypatch.setattr(audit_export, "_EXPORT_CLOSING", False)


@pytest.mark.parametrize("phase", ["export", "audit"])
def test_manual_export_drain_waits_through_final_audit_write(tmp_path, phase):
    entered, release = threading.Event(), threading.Event()

    def block(*_args, **_kwargs):
        entered.set()
        release.wait(5)
        return True, "ok"

    audit_export.start_export(
        "unused", {}, "", str(tmp_path),
        export_fn=block if phase == "export" else lambda *a, **kw: (True, "ok"),
        audit_fn=block if phase == "audit" else None)
    try:
        assert entered.wait(2)
        assert audit_export.drain_exports(timeout=0.02) is False
        with pytest.raises(ValueError, match="shutting down"):
            audit_export.start_export("unused", {}, "", str(tmp_path))
    finally:
        release.set()
    assert audit_export.drain_exports(timeout=2) is True


def test_uncaught_export_failure_remains_nonclean_after_callback_exits(tmp_path):
    def crash(*_args, **_kwargs):
        raise KeyboardInterrupt()

    audit_export.start_export("unused", {}, "", str(tmp_path), export_fn=crash)
    assert audit_export.drain_exports(timeout=2) is False
    assert not audit_export._EXPORT_ACTIVE


@pytest.mark.parametrize("uncertain", [True, False])
def test_export_launch_failure_refuses_clean_stop(tmp_path, monkeypatch, uncertain):
    exception = KeyboardInterrupt if uncertain else RuntimeError

    def fail(_thread):
        raise exception()

    monkeypatch.setattr(audit_export.threading.Thread, "start", fail)
    with pytest.raises(exception):
        audit_export.start_export("unused", {}, "", str(tmp_path))
    assert audit_export.drain_exports(timeout=0.02) is False
    assert bool(audit_export._EXPORT_ACTIVE) is uncertain


def test_shutdown_cannot_observe_false_idle_before_thread_start(tmp_path, monkeypatch):
    original = threading.Thread.start

    def start(thread):
        assert audit_export._EXPORT_ACTIVE
        assert audit_export.drain_exports(timeout=0.01) is False
        return original(thread)

    monkeypatch.setattr(audit_export.threading.Thread, "start", start)
    audit_export.start_export("unused", {}, "", str(tmp_path),
                              export_fn=lambda *a, **kw: (True, "ok"))
    assert audit_export.drain_exports(timeout=2) is True
