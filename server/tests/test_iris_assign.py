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


def _service(tmp_path, inventory):
    import assignment_service
    return assignment_service.AssignmentService(
        _images(tmp_path), inventory, str(tmp_path / "audit.jsonl"),
        authority_path=str(tmp_path / "assignment-authority.sqlite3"))


def _scheduled(generation=0, occurrence="occ-1", guard=None):
    import assignment_service
    return assignment_service.ScheduledAssignmentContext(
        schedule_id="schedule-1", schedule_rev=1, occurrence_id=occurrence,
        expected_manual_generation=generation, commit_guard=guard)


def test_manual_generation_persists_and_accepted_noop_advances(tmp_path, inventory):
    service = _service(tmp_path, inventory)
    assert service.capture_schedule_state("sw-1") == {
        "manual_generation": 0, "before_image_ids": []}
    service.apply("sw-1", ["a"], actor="cli:test")
    row = service.store.read_policy_row_snapshot("sw-1")
    service.apply("sw-1", ["a"], actor="console:test")
    assert service.store.read_policy_row_snapshot("sw-1") == row
    restarted = _service(tmp_path, inventory)
    assert restarted.capture_schedule_state("sw-1") == {
        "manual_generation": 2, "before_image_ids": ["a"]}
    assert len(_events(tmp_path)) == 2


@pytest.mark.parametrize("failure", ["invalid", "conflict", "quarantine", "cap", "error"])
def test_rejected_manual_assignment_does_not_advance_generation(
        tmp_path, inventory, monkeypatch, failure):
    service = _service(tmp_path, inventory)
    service.apply("sw-1", ["a"], actor="manual")
    kwargs = {}
    images = ["b"]
    if failure == "invalid":
        images = ["absent"]
    elif failure == "conflict":
        kwargs["expect_image_ids"] = []
    elif failure == "quarantine":
        service.store.apply_hash_verification(
            {"b": _verdict(bulkhash.STATE_MISMATCH)}, source="scheduled", now=1000)
    elif failure == "cap":
        images = ["a"] * 11
    else:
        def fail(*args, **kwargs):
            raise OSError("uncertain storage failure")
        monkeypatch.setattr(service.store, "set_policy", fail)
    with pytest.raises(Exception):
        service.apply("sw-1", images, actor="manual", **kwargs)
    import sqlite3
    with sqlite3.connect(service.authority_path) as conn:
        assert conn.execute("SELECT manual_generation FROM authority WHERE device_id='sw-1'").fetchone() == (1,)
    if failure != "error":
        assert service.capture_schedule_state("sw-1")["manual_generation"] == 1
    assert len(_events(tmp_path)) == 2


def test_manual_noop_after_capture_supersedes_schedule_without_retry(tmp_path, inventory, monkeypatch):
    import assignment_service
    service = _service(tmp_path, inventory)
    service.apply("sw-1", ["a"], actor="manual")
    captured = service.capture_schedule_state("sw-1")
    service.apply("sw-1", ["a"], actor="manual")
    def forbidden(*args, **kwargs):
        pytest.fail("manual override reached catalog write")
    monkeypatch.setattr(service.store, "set_policy", forbidden)
    result = service.apply("sw-1", ["b"], actor="schedule", mode="merge",
                           retry_conflict=True,
                           scheduled_context=_scheduled(captured["manual_generation"]))
    assert isinstance(result, assignment_service.ScheduledAssignmentRefusal)
    assert result.reason == "manual_override"
    assert len(_events(tmp_path)) == 3


def test_scheduled_guard_and_generation_hold_through_commit(tmp_path, inventory, monkeypatch):
    import contextlib
    service = _service(tmp_path, inventory)
    entered, release, manual_done = (threading.Event() for _ in range(3))
    guarded = []
    @contextlib.contextmanager
    def guard():
        guarded.append(True)
        try:
            yield
        finally:
            guarded.pop()
    original = service.store.set_policy
    def paused(*args, **kwargs):
        if kwargs["approved_image_ids"] == ["a"]:
            assert guarded == [True]
            entered.set()
            assert release.wait(2)
        return original(*args, **kwargs)
    monkeypatch.setattr(service.store, "set_policy", paused)
    def manual():
        service.apply("sw-1", ["b"], actor="manual")
        manual_done.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        scheduled = pool.submit(service.apply, "sw-1", ["a"], actor="schedule",
                                scheduled_context=_scheduled(guard=guard))
        assert entered.wait(2)
        manual_future = pool.submit(manual)
        assert not manual_done.wait(0.05)
        release.set()
        assert scheduled.result(timeout=2).after_ids == ["a"]
        manual_future.result(timeout=2)
    assert service.store.get_policy("sw-1")["approved_image_ids"] == ["b"]
    assert service.capture_schedule_state("sw-1")["manual_generation"] == 1


def test_completed_occurrence_replays_durable_result_without_write_or_audit(tmp_path, inventory, monkeypatch):
    service = _service(tmp_path, inventory)
    result = service.apply("sw-1", ["a"], actor="schedule", scheduled_context=_scheduled())
    restarted = _service(tmp_path, inventory)
    def forbidden(*args, **kwargs):
        pytest.fail("completed occurrence wrote catalog again")
    monkeypatch.setattr(restarted.store, "set_policy", forbidden)
    replay = restarted.apply("sw-1", ["a"], actor="schedule", scheduled_context=_scheduled())
    assert replay == result
    assert restarted.capture_schedule_state("sw-1")["manual_generation"] == 0
    assert len(_events(tmp_path)) == 1
    changed = restarted.apply("sw-1", ["b"], actor="schedule", scheduled_context=_scheduled())
    assert changed.reason == "conflict"


@pytest.mark.parametrize("manual", [False, True])
def test_crash_after_catalog_write_never_infers_success_from_current_ids(
        tmp_path, inventory, monkeypatch, manual):
    import assignment_service
    service = _service(tmp_path, inventory)
    original = service.store.set_policy
    class SimulatedCrash(BaseException):
        pass
    def crash(*args, **kwargs):
        original(*args, **kwargs)
        raise SimulatedCrash()
    monkeypatch.setattr(service.store, "set_policy", crash)
    with pytest.raises(SimulatedCrash):
        service.apply("sw-1", ["a"], actor="manual" if manual else "schedule",
                      scheduled_context=None if manual else _scheduled())
    restarted = _service(tmp_path, inventory)
    assert restarted.store.get_policy("sw-1")["approved_image_ids"] == ["a"]
    result = restarted.apply("sw-1", ["a"], actor="schedule", scheduled_context=_scheduled())
    assert isinstance(result, assignment_service.ScheduledAssignmentRefusal)
    assert result.reason == "conflict"
    if manual:
        with pytest.raises(assignment_service.AssignmentAuthorityUnavailable):
            restarted.capture_schedule_state("sw-1")
        restarted.apply("sw-1", ["a"], actor="manual")
        assert restarted.capture_schedule_state("sw-1")["manual_generation"] == 1


def test_waiting_schedule_checks_generation_after_manual_commit(tmp_path, inventory, monkeypatch):
    service = _service(tmp_path, inventory)
    captured = service.capture_schedule_state("sw-1")
    entered, release, schedule_started = (threading.Event() for _ in range(3))
    original = service.store.set_policy
    calls = []
    def paused(*args, **kwargs):
        calls.append(kwargs["approved_image_ids"])
        entered.set()
        assert release.wait(2)
        return original(*args, **kwargs)
    monkeypatch.setattr(service.store, "set_policy", paused)
    def schedule():
        schedule_started.set()
        return service.apply("sw-1", ["b"], actor="schedule", retry_conflict=True,
                             scheduled_context=_scheduled(captured["manual_generation"]))
    with ThreadPoolExecutor(max_workers=2) as pool:
        manual = pool.submit(service.apply, "sw-1", ["a"], actor="manual")
        assert entered.wait(2)
        scheduled = pool.submit(schedule)
        assert schedule_started.wait(2)
        assert not scheduled.done()
        release.set()
        manual.result(timeout=2)
        assert scheduled.result(timeout=2).reason == "manual_override"
    assert calls == [["a"]]


@pytest.mark.parametrize("conflicts", [1, 2])
def test_scheduled_merge_retries_one_catalog_conflict_without_generation_change(
        tmp_path, inventory, monkeypatch, conflicts):
    service = _service(tmp_path, inventory)
    original = service.store.set_policy
    calls = []
    def conflicting(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) <= conflicts:
            original("sw-1", approved_image_ids=["b"])
            raise catalog.PolicyConflict(["b"])
        return original(*args, **kwargs)
    monkeypatch.setattr(service.store, "set_policy", conflicting)
    if conflicts == 1:
        result = service.apply("sw-1", ["a"], actor="schedule", mode="merge",
                               retry_conflict=True, scheduled_context=_scheduled())
        assert result.before_ids == ["b"] and result.after_ids == ["b", "a"]
    else:
        with pytest.raises(catalog.PolicyConflict):
            service.apply("sw-1", ["a"], actor="schedule", mode="merge",
                          retry_conflict=True, scheduled_context=_scheduled())
    assert len(calls) == 2
    assert service.capture_schedule_state("sw-1")["manual_generation"] == 0
    assert len(_events(tmp_path)) == 1


def test_scheduled_assignment_rechecks_quarantine_at_catalog_write(tmp_path, inventory, monkeypatch):
    service = _service(tmp_path, inventory)
    original = service.store.set_policy
    def quarantine(*args, **kwargs):
        service.store.apply_hash_verification(
            {"a": _verdict(bulkhash.STATE_MISMATCH)}, source="scheduled", now=1000)
        return original(*args, **kwargs)
    monkeypatch.setattr(service.store, "set_policy", quarantine)
    with pytest.raises(catalog.QuarantinedImage):
        service.apply("sw-1", ["a"], actor="schedule", scheduled_context=_scheduled())
    assert service.store.get_policy("sw-1")["approved_image_ids"] == []
    assert len(_events(tmp_path)) == 1


def test_absent_authority_keeps_manual_compatibility_but_refuses_schedule(tmp_path, inventory):
    import assignment_service
    service = assignment_service.AssignmentService(_images(tmp_path), inventory)
    assert service.apply("sw-1", ["a"], actor="manual").after_ids == ["a"]
    with pytest.raises(assignment_service.AssignmentAuthorityUnavailable):
        service.capture_schedule_state("sw-1")
    with pytest.raises(assignment_service.AssignmentAuthorityUnavailable):
        service.apply("sw-1", ["b"], actor="schedule", scheduled_context=_scheduled())
    assert service.store.get_policy("sw-1")["approved_image_ids"] == ["a"]


def test_corrupt_authority_refuses_all_mutations(tmp_path, inventory):
    import assignment_service
    service = _service(tmp_path, inventory)
    (tmp_path / "assignment-authority.sqlite3").write_text("corrupt authority")
    with pytest.raises(assignment_service.AssignmentAuthorityUnavailable):
        service.capture_schedule_state("sw-1")
    with pytest.raises(assignment_service.AssignmentAuthorityUnavailable):
        service.apply("sw-1", ["a"], actor="manual")
    assert service.store.get_policy("sw-1")["approved_image_ids"] == []


def test_refused_commit_guard_leaves_no_occurrence_claim(tmp_path, inventory):
    import contextlib
    service = _service(tmp_path, inventory)
    @contextlib.contextmanager
    def refusal():
        raise RuntimeError("final authority refused")
        yield
    with pytest.raises(RuntimeError):
        service.apply("sw-1", ["a"], actor="schedule",
                      scheduled_context=_scheduled(guard=refusal))
    assert service.apply("sw-1", ["a"], actor="schedule",
                         scheduled_context=_scheduled()).after_ids == ["a"]
    assert len(_events(tmp_path)) == 2


def test_recurring_claims_remain_until_explicit_acknowledgement(
        tmp_path, inventory, monkeypatch):
    import sqlite3
    service = _service(tmp_path, inventory)
    original = service.store.set_policy
    class SimulatedCrash(BaseException):
        pass
    def crash(*args, **kwargs):
        raise SimulatedCrash()
    monkeypatch.setattr(service.store, "set_policy", crash)
    with pytest.raises(SimulatedCrash):
        service.apply("sw-1", ["a"], actor="schedule",
                      scheduled_context=_scheduled(occurrence="ambiguous"))
    monkeypatch.setattr(service.store, "set_policy", original)
    from dataclasses import replace
    service.apply("sw-1", ["a"], actor="schedule", scheduled_context=replace(
        _scheduled(occurrence="foreign-schedule"), schedule_id="schedule-2"))
    inventory.upsert({"device_id": "sw-2", "device_ip": "192.0.2.2"})
    service.apply("sw-2", ["a"], actor="schedule",
                  scheduled_context=_scheduled(occurrence="foreign-device"))
    for number in range(10):
        service.apply("sw-1", ["a"], actor="schedule",
                      scheduled_context=_scheduled(occurrence="occ-%d" % number))
    with sqlite3.connect(service.authority_path) as conn:
        rows = conn.execute("SELECT occurrence_id, result_json IS NULL FROM claims "
                            "ORDER BY occurrence_id").fetchall()
    assert rows == [("ambiguous", 1), ("foreign-device", 0),
                    ("foreign-schedule", 0)] + [("occ-%d" % n, 0) for n in range(10)]
    # Simulate restart after newer occurrences commit, before the older
    # terminal receipt was saved: replay still uses the durable original result.
    restarted = _service(tmp_path, inventory)
    def forbidden(*args, **kwargs):
        pytest.fail("unacknowledged occurrence repeated its catalog write")
    monkeypatch.setattr(restarted.store, "set_policy", forbidden)
    assert restarted.apply("sw-1", ["a"], actor="schedule",
                           scheduled_context=_scheduled(occurrence="occ-0")).after_ids == ["a"]
    assert restarted.acknowledge_schedule_result("ambiguous", "sw-1") is False
    assert restarted.acknowledge_schedule_result("occ-0", "sw-2") is True
    assert restarted.acknowledge_schedule_result("occ-0", "sw-1") is True
    assert restarted.acknowledge_schedule_result("occ-0", "sw-1") is True
    with sqlite3.connect(service.authority_path) as conn:
        retained = conn.execute("SELECT occurrence_id, result_json IS NULL FROM claims "
                               "ORDER BY occurrence_id").fetchall()
    assert retained == [row for row in rows if row[0] != "occ-0"]
    assert service.apply("sw-1", ["a"], actor="schedule",
                         scheduled_context=_scheduled(occurrence="ambiguous")).reason == "conflict"



def test_acknowledged_recurring_results_do_not_accumulate(tmp_path, inventory):
    import sqlite3
    service = _service(tmp_path, inventory)
    for number in range(10):
        occurrence = "occ-%d" % number
        service.apply("sw-1", ["a"], actor="schedule",
                      scheduled_context=_scheduled(occurrence=occurrence))
        assert service.acknowledge_schedule_result(occurrence, "sw-1") is True
    with sqlite3.connect(service.authority_path) as conn:
        assert conn.execute("SELECT count(*) FROM claims").fetchone() == (0,)
    assert service.capture_schedule_state("sw-1")["manual_generation"] == 0
    assert len(_events(tmp_path)) == 10
