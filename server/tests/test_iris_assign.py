# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""CLI and shared assignment transaction, fleet lifetime, and audit tests."""
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import types
from importlib.machinery import SourceFileLoader

import pytest

import bulkhash
import catalog
import gui_fleet

_CLI_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "iris-assign")


def _load_cli():
    loader = SourceFileLoader("iris_assign", _CLI_PATH)
    mod = types.ModuleType("iris_assign")
    mod.__file__ = _CLI_PATH
    loader.exec_module(mod)
    return mod


def _entry(image_id="img1", sha512="aa" * 64, **over):
    e = {"id": image_id, "filename": image_id + ".bin", "size": 5,
         "sha256": "ab" * 32, "sha512": sha512,
         "cisco_signature_verified": False,
         "info_hash_hex": "cc" * 20, "published_at": 111}
    e.update(over)
    return e


def _verdict(state, feed_sha512="bb" * 64, publish_date="2026-08-01",
            deferral=False):
    return {"state": state, "feed_sha512": feed_sha512,
            "publish_date": publish_date, "deferral": deferral}


def test_assigning_a_quarantined_image_prints_verdict_and_exits_1(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH)}, source="scheduled",
        now=1000)
    assert store.get_image("img1")["quarantined"] is True

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "img1" in err
    assert "quarantined" in err
    assert "mismatch" in err
    # nothing was persisted -- the device keeps no assignment at all
    assert store.get_policy("sw-1").get("approved_image_id") is None


def test_quarantined_and_since_deferred_image_notes_the_deferral(
        tmp_path, monkeypatch, capsys):
    """quarantined=True and hash_verification.deferral=True can co-occur:
    a first mismatch (deferral=False) quarantines the image, then a LATER
    feed refresh reports the same mismatch now deferred by Cisco --
    apply_hash_verification always refreshes hash_verification, but only
    ever ADDS a quarantine, never lifts one, on a later deferral. The CLI's
    printed reason should surface that deferral, not just the bare state."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, deferral=False)},
        source="scheduled", now=1000)
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, deferral=True)},
        source="scheduled", now=2000)
    entry = store.get_image("img1")
    assert entry["quarantined"] is True
    assert entry["hash_verification"]["deferral"] is True

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 1
    assert "deferred" in capsys.readouterr().err


def test_assigning_a_verified_image_still_succeeds(tmp_path, monkeypatch,
                                                    capsys):
    """The QuarantinedImage try/except must not disturb the happy path."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 0
    assert store.get_policy("sw-1").get("approved_image_id") == "img1"


@pytest.fixture(autouse=True)
def inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_AUDIT", str(tmp_path / "audit.jsonl"))
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "sw-1", "device_ip": "192.0.2.1"})
    return fleet


def _events(tmp_path):
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    for event in events:
        detail, suffix = event["detail"].split("; before_ids=", 1)
        before, suffix = suffix.split("; after_ids=", 1)
        after, removed = suffix.split("; removed_ids=", 1)
        event["before_image_ids"] = json.loads(before)
        event["after_image_ids"] = json.loads(after)
        event["removed_image_ids"] = json.loads(removed)
        event["detail"] = detail
    return events


def _images(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    for iid in ("a", "b", "c", "d"):
        store.save_image(_entry(iid))
    return store


def test_cli_merge_replace_and_plural_listing(tmp_path, capsys):
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a", "b", "c"])
    cli = _load_cli()
    assert cli.main(["sw-1", "d", "b"]) == 0
    assert store.get_policy("sw-1")["approved_image_ids"] == ["a", "b", "c", "d"]
    cli.main([])
    listing = capsys.readouterr().out
    assert "published images:" in listing and "assignments:" in listing
    assert "a, b, c, d" in listing
    assert cli.main(["--replace", "sw-1", "d"]) == 0
    assert store.get_policy("sw-1")["approved_image_ids"] == ["d"]
    events = _events(tmp_path)
    assert len(events) == 2
    assert events[1]["before_image_ids"] == ["a", "b", "c", "d"]
    assert events[1]["after_image_ids"] == ["d"]
    assert events[1]["removed_image_ids"] == ["a", "b", "c"]
    assert events[1]["detail"] == "assigned 1 image(s): d.bin; removed: a.bin, b.bin, c.bin"
    assert events[1]["actor"] == "cli:iris-assign"


@pytest.mark.parametrize("conflicts", [1, 2])
def test_cli_retries_exactly_one_conflict(tmp_path, monkeypatch, conflicts):
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a"])
    original = catalog.CatalogStore.set_policy
    calls = []
    def conflicting(self, device_id, **kwargs):
        calls.append(kwargs)
        if len(calls) <= conflicts:
            original(self, device_id, approved_image_ids=["a", "b"])
            raise catalog.PolicyConflict(["a", "b"])
        return original(self, device_id, **kwargs)
    monkeypatch.setattr(catalog.CatalogStore, "set_policy", conflicting)
    assert _load_cli().main(["sw-1", "c"]) == (0 if conflicts == 1 else 1)
    assert len(calls) == 2
    assert calls[1]["expect_image_ids"] == ["a", "b"]
    events = _events(tmp_path)
    assert len(events) == 1
    assert events[0]["result"] == ("ok" if conflicts == 1 else "fail")
    assert events[0]["before_image_ids"] == ["a", "b"]
    assert store.get_policy("sw-1")["approved_image_ids"] == (["a", "b", "c"] if conflicts == 1 else ["a", "b"])


def test_missing_fleet_refuses_without_policy_or_mint(tmp_path, monkeypatch):
    store = _images(tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("missing fleet device minted identifiers")
    monkeypatch.setattr(catalog.secrets, "token_hex", forbidden)
    assert _load_cli().main(["typo", "a"]) == 1
    assert store.read_policy_row_snapshot("typo") is None
    events = _events(tmp_path)
    assert len(events) == 1
    assert events[0]["result"] == "fail"
    assert events[0]["detail"] == "assignment failed: no such fleet device"


def test_unchanged_assignment_mints_nothing_even_for_legacy_row(tmp_path, monkeypatch):
    store = _images(tmp_path)
    store._policies.put("sw-1", {"approved_image_id": "a"})
    before = store.read_policy_row_snapshot("sw-1")
    def forbidden(*args, **kwargs):
        pytest.fail("unchanged application minted identifiers")
    monkeypatch.setattr(catalog.secrets, "token_hex", forbidden)
    assert _load_cli().main(["sw-1", "a"]) == 0
    assert store.read_policy_row_snapshot("sw-1") == before
    assert len(_events(tmp_path)) == 1


def test_service_transaction_result_and_sanitized_audit(tmp_path, inventory):
    import assignment_service
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a", "b"])
    store.save_image(_entry("c", filename="c.bin\n\x1b[31m"))
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    result = service.apply("sw-1", ["c"], actor="console:operator")
    assert result.before_ids == ["a", "b"]
    assert result.after_ids == ["c"]
    assert result.removed_ids == ["a", "b"]
    events = _events(tmp_path)
    assert len(events) == 1
    assert events[0]["actor"] == "console:operator"
    assert events[0]["category"] == "device" and events[0]["event"] == "device_assign"
    assert events[0]["action"] == "assign" and events[0]["result"] == "ok"
    assert "\n" not in events[0]["detail"] and "\x1b" not in events[0]["detail"]


def test_membership_guard_serializes_delete_and_refuses_waiting_assignment(tmp_path, inventory, monkeypatch):
    import assignment_service
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a"])
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    started = threading.Event()
    done = threading.Event()
    def assign():
        started.set()
        try:
            with pytest.raises(assignment_service.MissingFleetDevice):
                service.apply("sw-1", ["b"], actor="console:test")
        finally:
            done.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with assignment_service.membership_guard(inventory):
            future = pool.submit(assign)
            assert started.wait(2)
            assert not done.wait(0.05)
            inventory.delete("sw-1")
            store.purge_device("sw-1")
        future.result(timeout=2)
    assert store.read_policy_row_snapshot("sw-1") is None
    assert len(_events(tmp_path)) == 1


def test_assignment_holds_membership_until_commit(tmp_path, inventory, monkeypatch):
    import assignment_service
    store = _images(tmp_path)
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()
    original = store.set_policy
    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return original(*args, **kwargs)
    monkeypatch.setattr(store, "set_policy", paused)
    def delete():
        with assignment_service.membership_guard(inventory):
            inventory.delete("sw-1")
            store.purge_device("sw-1")
        deleted.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        applying = pool.submit(service.apply, "sw-1", ["a"], actor="console:test")
        assert entered.wait(2)
        deleting = pool.submit(delete)
        assert not deleted.wait(0.05)
        release.set()
        applying.result(timeout=2)
        deleting.result(timeout=2)
    assert store.read_policy_row_snapshot("sw-1") is None


def test_service_result_uses_committed_row_not_optimistic_read(tmp_path, inventory, monkeypatch):
    import assignment_service
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a"])
    original = store.set_policy
    def concurrent_update(*args, **kwargs):
        original("sw-1", approved_image_ids=["a", "b"])
        return original(*args, **kwargs)
    monkeypatch.setattr(store, "set_policy", concurrent_update)
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    result = service.apply("sw-1", ["c"], actor="console:test", plural=False)
    assert result.before_ids == ["a", "b"]
    assert result.removed_ids == ["a", "b"]
    event = _events(tmp_path)[0]
    assert event["before_image_ids"] == ["a", "b"]
    assert event["detail"] == "assigned c.bin (5 B) id=c, was a.bin"


def test_service_unassign_exact_audit_and_failed_audit_is_best_effort(tmp_path, inventory, monkeypatch):
    import assignment_service
    store = _images(tmp_path)
    store.set_policy("sw-1", approved_image_ids=["a", "b"])
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    service.apply("sw-1", [], actor="console:test")
    events = _events(tmp_path)
    assert len(events) == 1
    assert events[0]["action"] == "unassign"
    assert events[0]["detail"] == "unassigned (was a.bin, b.bin)"
    assert events[0]["removed_image_ids"] == ["a", "b"]
    def failed_audit(*args, **kwargs):
        raise OSError("sensitive diagnostic")
    monkeypatch.setattr(assignment_service.audit, "append_event", failed_audit)
    assert service.apply("sw-1", ["a"], actor="console:test").after_ids == ["a"]
    with pytest.raises(assignment_service.MissingFleetDevice):
        service.apply("missing", ["a"], actor="console:test")


def test_service_failure_audit_does_not_include_exception_diagnostics(tmp_path, inventory, monkeypatch):
    import assignment_service
    store = _images(tmp_path)
    service = assignment_service.AssignmentService(store, inventory, str(tmp_path / "audit.jsonl"))
    def failed_write(*args, **kwargs):
        raise RuntimeError("password=not-for-audit\nTOKEN=secret")
    monkeypatch.setattr(store, "set_policy", failed_write)
    with pytest.raises(RuntimeError):
        service.apply("sw-1", ["a"], actor="console:test")
    events = _events(tmp_path)
    assert len(events) == 1
    assert events[0]["detail"] == "assignment failed: assignment state unavailable"
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "password" not in raw and "TOKEN" not in raw
