# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Runner behavior against real durable stores and inert fake executors."""
import contextlib
import importlib
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schedules
import schedule_runner

NOW = 1788955200  # Wednesday 2026-09-09 12:00 UTC


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class Executor:
    def __init__(self):
        self.dispatched = []
        self.polled = []
        self.cancelled = []
        self.results = {}
        self.poll_results = {}
        self.on_dispatch = None
        self.validation = None

    def validate(self, schedule, preview, phase):
        assert phase == "window_start"
        return self.validation

    def dispatch(self, schedule, occurrence, device_id, prior_receipt):
        self.dispatched.append((occurrence["id"], device_id, prior_receipt))
        assert occurrence["actor"] == "schedule:" + schedule["id"]
        if self.on_dispatch:
            self.on_dispatch(occurrence, device_id, prior_receipt)
        return self.results.get(device_id, {"status": "ok", "reason": "assigned"})

    def poll(self, receipt):
        self.polled.append(receipt)
        return self.poll_results.get(receipt["device_id"], {"status": "deferred", "reason": "device_busy"})

    def cancel_queued(self, occurrence_id, job_ids):
        self.cancelled.append((occurrence_id, job_ids))


@pytest.fixture
def setup(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    clock = Clock()
    executor = Executor()
    snapshots = []

    def resolver(row):
        snapshots.append(row["id"])
        return {"revision": 8, "now": clock.now, "device_ids": ["edge-1", "edge-2"]}

    @contextlib.contextmanager
    def role_guard(row):
        yield

    runner = schedule_runner.ScheduleRunner(store, resolver, executor=executor,
        role_guard=role_guard, now_fn=clock)
    return store, clock, executor, snapshots, runner


def create(store, identifier="s-main", *, at=NOW, window=100, bind="late", ids=None,
           created_at=NOW-60, when=None, **extra):
    definition = {"kind": "assign", "target": {"bind": bind, "filters": {"role": "edge"}},
                  "payload": {"image_ids": ["image-1"]},
                  "when": when or {"kind": "once", "at": at, "window_seconds": window}}
    definition.update(extra)
    return store.create(identifier, definition, actor="console:departed", now=created_at,
        preview={"revision": 2, "now": created_at, "device_ids": ids if ids is not None else ["edge-1"]})


def occurrence(store, identifier="s-main"):
    return schedules.OccurrenceStore(store.state_dir).list(identifier)[-1]


def receipts(store, occ):
    return schedules.ReceiptStore(store.state_dir).list(occ["id"])["receipts"]


def test_import_construction_and_idle_are_inert(setup, monkeypatch):
    store, clock, executor, reads, runner = setup
    monkeypatch.setattr(threading.Thread, "start", lambda *_: pytest.fail("thread started"))
    importlib.reload(schedule_runner)
    assert not list(Path(store.state_dir).iterdir())
    create(store, at=NOW+1000)
    assert runner.run_once() == runner.idle_recheck
    assert not reads and not executor.dispatched
    assert runner.last_error is None


def test_due_order_and_immediate_receipts(setup):
    store, clock, executor, reads, runner = setup
    create(store, "z-earlier", at=NOW-10)
    create(store, "a-later", at=NOW)
    def check(occ, did, prior):
        evidence = schedules.ReceiptStore(store.state_dir)
        assert evidence.get(occ["id"], did)["status"] == "intent"
        if did == "edge-2":
            assert evidence.get(occ["id"], "edge-1")["status"] == "ok"
    executor.on_dispatch = check
    runner.run_once()
    assert reads == ["z-earlier", "a-later"]
    assert len(executor.dispatched) == 4
    assert occurrence(store, "a-later")["state"] == "completed"
    assert occurrence(store, "z-earlier")["actor"] == "schedule:z-earlier"
    runner.run_once()
    assert len(executor.dispatched) == 4


@pytest.mark.parametrize("offset,expected", [(-1, None), (0, "completed"), (99, "completed"), (100, "missed")])
def test_once_half_open_window(setup, offset, expected):
    store, clock, executor, reads, runner = setup
    create(store)
    clock.now = NOW + offset
    runner.run_once()
    found = schedules.OccurrenceStore(store.state_dir).list()
    assert (found[-1]["state"] if found else None) == expected
    if expected in (None, "missed"):
        assert not reads and not executor.dispatched


def test_weekly_backlog_is_bounded_and_records_missed_without_resolve(setup):
    store, clock, executor, reads, runner = setup
    create(store, created_at=NOW-4*7*86400,
        when={"kind": "recurring", "weekday": 2, "hour": 12, "minute": 0,
              "tz": "UTC", "window_seconds": 100})
    runner.max_claims = 2
    assert runner.run_once() <= runner.poll_interval
    assert len(schedules.OccurrenceStore(store.state_dir).list()) == 2
    assert not reads and not executor.dispatched
    runner.run_once()
    assert len(schedules.OccurrenceStore(store.state_dir).list()) == 4
    assert not reads
    runner.run_once()
    assert [r["state"] for r in schedules.OccurrenceStore(store.state_dir).list()] == ["missed"]*4 + ["completed"]
    assert len(reads) == 1


@pytest.mark.parametrize("bind,ids,delta", [("late", ["edge-1", "edge-2"], {"added":1,"removed":1}),
                                             ("early", ["edge-1", "gone"], {"added":0,"removed":0})])
def test_binding_revision_delta_and_frozen_recovery(setup, bind, ids, delta):
    store, clock, executor, reads, runner = setup
    create(store, bind=bind, ids=["edge-1", "gone"])
    executor.results = {did: {"status":"submitted", "reason":"queued", "job_id":"job-"+did} for did in ids}
    runner.run_once()
    first = occurrence(store)
    assert first["target_snapshot"] == {"revision":8,"now":NOW,"device_ids":ids}
    assert first["preview"]["revision"] == 2 and first["delta"] == delta
    restarted = schedule_runner.ScheduleRunner(store, lambda _: pytest.fail("rebound"),
        executor=executor, role_guard=runner.role_guard, now_fn=clock)
    assert restarted.recover() == [first["id"]]
    assert restarted.recover() == []
    restarted.run_once()
    assert len(executor.dispatched) == 2
    assert occurrence(store)["target_snapshot"] == first["target_snapshot"]


def test_early_binding_keeps_its_target_when_registration_lookup_changes(setup):
    store, clock, executor, _reads, runner = setup
    create(store, bind="early", ids=["edge-1", "gone"])
    runner.resolve_target = lambda _row: {
        "revision": 8, "now": clock.now, "device_ids": ["edge-1"],
        "registration_ids": {"edge-1": "a" * 32},
    }

    runner.run_once()

    frozen = occurrence(store)
    assert frozen["target_snapshot"]["device_ids"] == ["edge-1", "gone"]
    assert frozen["target_snapshot"]["registration_ids"] == {
        "edge-1": "a" * 32, "gone": None}
    assert frozen["delta"] == {"added": 0, "removed": 0}


@pytest.mark.parametrize("mutation", ["delete", "edit", "recreate"])
def test_definition_change_during_resolution_prevents_stale_claim(setup, mutation):
    store, clock, executor, reads, runner = setup
    original = create(store)
    def change(row):
        if mutation == "edit":
            store.patch(row["id"], {"payload":{"image_ids":["other"]}}, expected_rev=row["rev"])
        else:
            store.delete(row["id"], expected_rev=row["rev"])
            if mutation == "recreate":
                create(store)
        return row["preview"]
    runner.resolve_target = change
    runner.run_once()
    assert not executor.dispatched
    assert not schedules.OccurrenceStore(store.state_dir).list()
    if mutation == "recreate":
        assert store.get(original["id"])["generation"] != original["generation"]


def test_role_guard_covers_target_resolution_through_durable_claim(
        tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    clock = Clock()
    executor = Executor()
    create(store)
    authority = threading.Lock()
    resolving = threading.Event()
    release = threading.Event()
    writer_entered = threading.Event()
    writer_saw_claim = []

    @contextlib.contextmanager
    def role_guard(_row):
        with authority:
            yield

    def resolver(_row):
        resolving.set()
        assert release.wait(2)
        return {"revision": 8, "now": clock.now,
                "device_ids": ["edge-1"]}

    runner = schedule_runner.ScheduleRunner(
        store, resolver, executor=executor, role_guard=role_guard,
        now_fn=clock)

    def writer():
        with authority:
            writer_entered.set()
            writer_saw_claim.extend(
                schedules.OccurrenceStore(tmp_path).list())

    runner_thread = threading.Thread(target=runner.run_once)
    writer_thread = threading.Thread(target=writer)
    runner_thread.start()
    assert resolving.wait(2)
    writer_thread.start()
    assert not writer_entered.wait(.05)
    release.set()
    runner_thread.join(2)
    writer_thread.join(2)
    assert not runner_thread.is_alive() and not writer_thread.is_alive()
    assert writer_entered.is_set() and len(writer_saw_claim) == 1


def test_claim_cursor_failure_reuses_binding(setup, monkeypatch):
    store, clock, executor, reads, runner = setup
    create(store)
    write = store._progress.put
    monkeypatch.setattr(store._progress, "put", lambda *_: (_ for _ in ()).throw(OSError()))
    assert runner.run_once() > 0
    claimed = occurrence(store)
    assert not executor.dispatched
    monkeypatch.setattr(store._progress, "put", write)
    runner.resolve_target = lambda _: pytest.fail("rebound after crash")
    runner.run_once()
    assert occurrence(store)["id"] == claimed["id"]
    assert len(executor.dispatched) == 2
    assert store.progress("s-main")["last_slot"] == NOW


def test_role_refusal_never_dispatches_and_creator_is_not_authority(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    @contextlib.contextmanager
    def missing(_):
        raise schedule_runner.ExecutionRefused("role_missing")
        yield
    runner.role_guard = missing
    assert runner.run_once() > 0
    assert not executor.dispatched and runner.last_error == "role_missing"
    runner.role_guard = lambda _: contextlib.nullcontext()
    runner.run_once()
    assert len(executor.dispatched) == 2
    assert occurrence(store)["schedule"]["created_by"] == "console:departed"


def test_default_guard_refuses_role_target(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    runner = schedule_runner.ScheduleRunner(store, runner.resolve_target, executor=executor, now_fn=clock)
    runner.run_once()
    assert runner.last_error == "role_authority_unavailable" and not executor.dispatched


@pytest.mark.parametrize("unavailable", ["executor", "gate"])
def test_unavailable_executor_or_gate_is_visible_without_dispatch(setup, unavailable):
    store, clock, executor, reads, runner = setup
    kwargs = {}
    if unavailable == "gate":
        kwargs["after"] = {"schedule_id":"s-before", "condition":"min_staged_ratio", "min_staged_ratio":.9,
            "max_errored_ratio":.1, "max_missing_ratio":.05, "deadline_seconds":20}
    create(store, **kwargs)
    if unavailable == "executor":
        runner.executor = schedule_runner.UnavailableExecutor()
    runner.run_once()
    assert not executor.dispatched
    assert {r["reason"] for r in receipts(store, occurrence(store))} == {unavailable+"_unavailable"}
    assert occurrence(store)["state"] in ("failed", "stalled")


def test_window_closes_between_devices_and_only_owned_queue_is_cancelled(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"submitted", "reason":"queued", "job_id":"owned-job"}
    executor.on_dispatch = lambda *_: setattr(clock, "now", NOW+100)
    runner.run_once()
    occ = occurrence(store)
    assert [d[1] for d in executor.dispatched] == ["edge-1"]
    assert schedules.ReceiptStore(store.state_dir).get(occ["id"], "edge-2")["reason"] == "window_closed"
    assert executor.cancelled and executor.cancelled[-1] == (occ["id"], ["owned-job"])
    executor.poll_results["edge-1"] = {"status":"ok", "reason":"onboarded"}
    store.delete("s-main", expected_rev=1)
    runner.run_once()
    assert schedules.ReceiptStore(store.state_dir).get(occ["id"], "edge-1")["status"] == "ok"
    assert len(executor.dispatched) == 1


def test_restart_resumes_only_unfinished_intent_inside_window(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    def crash(occ, did, prior):
        if did == "edge-2":
            raise OSError("crash between intent and admission")
    executor.on_dispatch = crash
    runner.run_once()
    assert [r["status"] for r in receipts(store, occurrence(store))] == ["ok", "intent"]
    executor.on_dispatch = None
    restarted = schedule_runner.ScheduleRunner(store, lambda _: pytest.fail("rebound"),
        executor=executor, role_guard=runner.role_guard, now_fn=clock)
    restarted.run_once()
    assert [d[1] for d in executor.dispatched] == ["edge-1", "edge-2", "edge-2"]
    assert occurrence(store)["state"] == "completed"


def test_restart_outside_window_polls_uncertain_intent_without_readmission(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.on_dispatch = lambda *_: (_ for _ in ()).throw(OSError("uncertain admission"))
    runner.run_once()
    clock.now = NOW+101
    executor.on_dispatch = None
    executor.poll_results["edge-1"] = {"status":"retry", "reason":"no_admitted_work", "manual_generation":0}
    restarted = schedule_runner.ScheduleRunner(store, lambda _: pytest.fail("rebound"),
        executor=executor, role_guard=runner.role_guard, now_fn=clock)
    restarted.run_once()
    assert len(executor.dispatched) == 1
    assert {r["reason"] for r in receipts(store, occurrence(store))} == {"window_closed"}


def test_submitted_work_survives_definition_deletion_and_restart(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results = {d:{"status":"submitted", "reason":"queued", "job_id":"job-"+d} for d in ["edge-1","edge-2"]}
    runner.run_once()
    occ = occurrence(store)
    store.delete("s-main", expected_rev=1)
    executor.poll_results = {d:{"status":"ok", "reason":"onboarded"} for d in ["edge-1","edge-2"]}
    restarted = schedule_runner.ScheduleRunner(store, lambda _: pytest.fail("resolve deleted"), executor=executor, now_fn=clock)
    restarted.run_once()
    assert len(executor.dispatched) == 2
    assert all(r["status"] == "ok" for r in receipts(store, occ))


@pytest.mark.parametrize("stage", ["list", "math", "resolve", "dispatch", "receipt", "reporter"])
def test_complete_pass_exception_guard_and_backoff(setup, monkeypatch, stage):
    store, clock, executor, reads, runner = setup
    create(store)
    boom = lambda *_a, **_k: (_ for _ in ()).throw(OSError("private diagnostic"))
    if stage == "list": monkeypatch.setattr(store, "list", boom)
    elif stage == "math": monkeypatch.setattr(schedules, "occurrence_slot", boom)
    elif stage == "resolve": runner.resolve_target = boom
    elif stage in ("dispatch", "reporter"):
        executor.on_dispatch = boom
        if stage == "reporter": runner.error_fn = boom
    elif stage == "receipt": monkeypatch.setattr(runner.receipts, "begin", boom)
    first = runner.run_once()
    second = runner.run_once()
    assert 0 < first <= second <= runner.idle_recheck
    assert runner.last_error == "schedule_runner_error"


def test_dispatch_budget_is_bounded_and_reaffirm_does_not_replay(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    runner.max_dispatches = 1
    runner.run_once()
    assert len(executor.dispatched) == 1
    store.reaffirm("s-main", "console:new", expected_rev=1)
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["edge-1", "edge-2"]
    runner.run_once()
    assert len(executor.dispatched) == 2


def test_run_clears_wake_before_scan_and_stop_wakes_wait(setup):
    store, clock, executor, reads, runner = setup
    calls = []
    stop = threading.Event()
    class Event:
        def clear(self): calls.append("clear")
        def set(self): calls.append("wake")
        def wait(self, delay):
            calls.append(("wait", delay))
            stop.set()
    runner.wake_event = Event()
    original = store.list
    def listed():
        calls.append("list")
        runner.wake()
        return original()
    store.list = listed
    runner.run(stop)
    assert calls[:3] == ["clear", "list", "wake"]
    assert calls[-1] == ("wait", runner.idle_recheck)
    runner.stop()
    assert calls[-1] == "wake"


def test_deferred_intent_is_durable_and_retry_is_bounded(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"deferred", "reason":"device_busy", "retry_at":NOW+10}
    runner.run_once()
    occ = occurrence(store)
    first = schedules.ReceiptStore(store.state_dir).get(occ["id"], "edge-1")
    assert first["status"] == "intent" and first["reason"] == "device_busy"
    assert first["rev"] == 2
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["edge-1", "edge-2"]
    clock.now += 10
    executor.results.pop("edge-1")
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["edge-1", "edge-2", "edge-1"]
    assert occurrence(store)["state"] == "completed"


def test_dispatch_recovery_can_request_durable_successor(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"retry", "reason":"resume_required", "manual_generation":4}
    runner.run_once()
    prior = schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-1")
    assert prior["attempt"] == 2 and prior["status"] == "intent"
    assert len(prior["predecessors"]) == 1 and prior["manual_generation"] == 4
    executor.results.pop("edge-1")
    runner.run_once()
    assert occurrence(store)["state"] == "completed"


def test_poll_retry_preserves_old_job_and_record_before_new_admission(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"submitted", "reason":"queued", "job_id":"old-job", "record_id":"old-record"}
    runner.run_once()
    executor.poll_results["edge-1"] = {"status":"retry", "reason":"resume_required", "manual_generation":4}
    runner.run_once()
    successor = schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-1")
    assert successor["predecessors"][0]["job_id"] == "old-job"
    assert successor["predecessor_record_id"] == "old-record"
    executor.results["edge-1"] = {"status":"submitted", "reason":"queued", "job_id":"new-job", "record_id":"new-record"}
    runner.run_once()
    bound = schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-1")
    assert bound["job_id"] == "new-job" and bound["record_id"] == "new-record"


def test_clock_rollback_never_readmits_but_still_polls_running_completion(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"submitted", "reason":"queued", "job_id":"job-1"}
    runner.max_dispatches = 1
    runner.run_once()
    clock.now = NOW-1
    executor.poll_results["edge-1"] = {"status":"ok", "reason":"onboarded"}
    runner.run_once()
    saved = schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-1")
    assert saved["status"] == "ok" and len(executor.dispatched) == 1
    assert schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-2") is None


def test_rich_preview_facts_are_validation_only(setup):
    store, clock, executor, reads, runner = setup
    create(store, bind="early", ids=["frozen"])
    runner.resolve_target = lambda _: {"revision":8, "now":NOW, "device_ids":["late"],
        "missing_os_family":2, "role_drift":1, "quarantined_ids":["frozen"]}
    seen = []
    executor.validate = lambda row, snapshot, phase: seen.append(snapshot)
    runner.run_once()
    assert seen[0]["device_ids"] == ["frozen"] and seen[0]["role_drift"] == 1
    assert set(occurrence(store)["target_snapshot"]) == {"revision", "now", "device_ids"}


def test_zero_target_cannot_make_missing_executor_successful(setup):
    store, clock, executor, reads, runner = setup
    create(store, ids=[])
    runner.resolve_target = lambda _: {"revision":8,"now":NOW,"device_ids":[]}
    runner.executor = schedule_runner.UnavailableExecutor()
    runner.run_once()
    assert occurrence(store)["state"] == "failed"


def test_resolution_crossing_end_records_missed_without_admission(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    def resolve(row):
        clock.now = NOW+100
        return {"revision":8,"now":NOW,"device_ids":["edge-1"]}
    runner.resolve_target = resolve
    runner.run_once()
    assert occurrence(store)["state"] == "missed" and "target_snapshot" not in occurrence(store)
    assert not executor.dispatched


def test_stop_interrupts_real_wait_without_waiting_idle_interval(setup):
    store, clock, executor, reads, runner = setup
    started = threading.Event()
    original = store.list
    def listed():
        started.set()
        return original()
    store.list = listed
    thread = threading.Thread(target=runner.run, args=(threading.Event(),))
    thread.start()
    try:
        assert started.wait(2)
        runner.stop()
        thread.join(2)
        assert not thread.is_alive()
    finally:
        runner.stop()
        thread.join(2)


def test_one_broken_schedule_does_not_starve_other_due_work(setup):
    store, clock, executor, reads, runner = setup
    create(store, "a-broken")
    create(store, "z-good")
    original = runner.resolve_target
    def resolve(row):
        if row["id"] == "a-broken":
            raise OSError("unavailable target state")
        return original(row)
    runner.resolve_target = resolve
    assert runner.run_once() > 0
    assert runner.last_error == "schedule_runner_error"
    assert occurrence(store, "z-good")["state"] == "completed"
    assert len(executor.dispatched) == 2


def test_small_budget_does_not_starve_device_behind_deferred_target(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    runner.max_dispatches = 1
    executor.results["edge-1"] = {"status":"deferred", "reason":"device_busy"}
    runner.run_once()
    clock.now += 1
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["edge-1", "edge-2"]


def test_bad_executor_result_keeps_intent_for_reconciliation(setup):
    store, clock, executor, reads, runner = setup
    create(store)
    executor.results["edge-1"] = {"status":"submitted", "reason":"queued"}
    runner.run_once()
    saved = schedules.ReceiptStore(store.state_dir).get(occurrence(store)["id"], "edge-1")
    assert saved["status"] == "intent" and "job_id" not in saved
    assert runner.last_error == "schedule_runner_error"


def test_dispatch_budget_rotates_between_occurrences_after_initial_due_order(setup):
    store, clock, executor, reads, runner = setup
    create(store, "a-old", at=NOW-10)
    create(store, "z-young")
    runner.resolve_target = lambda row: {"revision":8, "now":clock.now, "device_ids":[row["id"]]}
    runner.max_dispatches = 1
    executor.results["a-old"] = {"status":"deferred", "reason":"device_busy"}
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["a-old"]
    clock.now += 1
    runner.run_once()
    assert [d[1] for d in executor.dispatched] == ["a-old", "z-young"]
    assert occurrence(store, "z-young")["state"] == "completed"
    assert occurrence(store, "a-old")["state"] == "running"


def test_expired_owned_queue_is_cancelled_before_a_failing_poll(setup):
    store, clock, executor, reads, runner = setup
    create(store, window=10)
    executor.results = {d:{"status":"submitted", "reason":"queued", "job_id":"job-"+d}
                        for d in ("edge-1", "edge-2")}
    runner.run_once()
    oid = occurrence(store)["id"]
    actions = []
    def cancel(occurrence_id, job_ids):
        actions.append(("cancel", occurrence_id, job_ids))
    def failed_poll(receipt):
        actions.append(("poll", receipt["device_id"]))
        raise OSError("job state unavailable")
    executor.cancel_queued = cancel
    executor.poll = failed_poll
    clock.now += 10
    runner.run_once()
    assert actions[0] == ("cancel", oid, ["job-edge-1", "job-edge-2"])
    assert actions[1][0] == "poll"
    assert runner.last_error == "schedule_runner_error"
    assert all(r["status"] == "submitted" for r in receipts(store, occurrence(store)))


@pytest.mark.parametrize("status", ["submitted", "running"])
def test_poll_retry_delay_is_honored_without_delaying_window_cancellation(setup, status):
    store, clock, executor, reads, runner = setup
    create(store, window=10)
    executor.results = {d:{"status":status, "reason":"queued", "job_id":"job-"+d}
                        for d in ("edge-1", "edge-2")}
    runner.run_once()
    executor.poll_results = {d:{"status":"deferred", "reason":"device_busy", "retry_at":NOW+30}
                             for d in ("edge-1", "edge-2")}
    clock.now += 1
    runner.run_once()
    assert len(executor.polled) == 2
    clock.now += 1
    runner.run_once()
    assert len(executor.polled) == 2
    clock.now = NOW+10
    runner.run_once()
    assert len(executor.polled) == 2
    if status == "submitted":
        assert executor.cancelled[-1] == (occurrence(store)["id"], ["job-edge-1", "job-edge-2"])
    else:
        assert not executor.cancelled
    executor.poll_results = {d:{"status":"ok", "reason":"onboarded"} for d in ("edge-1", "edge-2")}
    clock.now = NOW+30
    runner.run_once()
    assert len(executor.polled) == 4
    assert occurrence(store)["state"] == "completed"


# ---- Task 24: deployment waves -------------------------------------------
# The gate is an operational signal about a PRECEDING occurrence, never an
# authority over this one: it decides when to admit work, never what that work
# is allowed to do. Every assertion below is written from that side.

PRECEDING = "b" * 32


def gate(**overrides):
    after = {"schedule_id": "s-before", "condition": "min_staged_ratio",
             "min_staged_ratio": .9, "max_errored_ratio": .1,
             "max_missing_ratio": .05, "deadline_seconds": 60}
    after.update(overrides)
    return after


def counts(total=10, staged=0, errored=0, missing=0, occurrence_id=PRECEDING,
           schedule_id="s-before"):
    return {"schedule_id": schedule_id, "occurrence_id": occurrence_id,
            "total": total, "staged": staged, "errored": errored,
            "missing": missing}


class WaveExecutor(Executor):
    """An executor that can also answer the gate's count question."""
    def __init__(self, counted=None):
        super().__init__()
        self.counted = counted if counted is not None else counts()
        self.asked = []
        self.refuse = None

    def wave_counts(self, schedule, occurrence):
        assert occurrence["schedule_id"] == schedule["id"]
        self.asked.append(occurrence["id"])
        if self.refuse:
            raise schedule_runner.ExecutionRefused(self.refuse)
        return dict(self.counted)


@pytest.fixture
def wave_setup(setup):
    store, clock, _, reads, runner = setup
    executor = WaveExecutor()
    runner.executor = executor
    runner.wave_recheck = 1
    return store, clock, executor, reads, runner


def annotated(store, identifier="s-main"):
    return (occurrence(store, identifier).get("annotations") or {}).get("wave")


def test_wave_gate_is_documented_as_an_operational_signal():
    assert "not a security boundary" in schedule_runner.__doc__


def test_wave_gate_holds_inside_the_window_until_the_counts_arrive(wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(), window=300)
    executor.counted = counts(staged=5)

    runner.run_once()
    assert not executor.dispatched and not receipts(store, occurrence(store))
    assert occurrence(store)["state"] == "running"
    assert annotated(store) == dict(counts(staged=5), gate="held",
                                    observed_at=NOW)

    executor.counted = counts(staged=9)
    clock.now += 1
    runner.run_once()
    assert len(executor.dispatched) == 2
    assert annotated(store)["gate"] == "open"
    assert occurrence(store)["state"] == "completed"
    assert executor.asked == [occurrence(store)["id"]] * 2


def test_wave_gate_counts_missing_apart_from_errored(wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(max_errored_ratio=0, max_missing_ratio=.1),
           window=300)
    # One dark device is not one failed device: folding the two together
    # would refuse this wave on evidence nobody produced.
    executor.counted = counts(staged=9, missing=1)
    runner.run_once()
    assert len(executor.dispatched) == 2
    assert annotated(store) == dict(counts(staged=9, missing=1), gate="open",
                                    observed_at=NOW)

    store.delete("s-main", expected_rev=store.get("s-main")["rev"])
    create(store, "s-other", after=gate(max_errored_ratio=0,
                                        max_missing_ratio=.1), window=300)
    executor.counted = counts(staged=9, errored=1)
    clock.now += 1
    runner.run_once()
    assert annotated(store, "s-other")["gate"] == "held"
    assert not receipts(store, occurrence(store, "s-other"))


def test_wave_deadline_stalls_the_occurrence_with_its_counts(wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(deadline_seconds=30), window=300)
    executor.counted = counts(staged=1, errored=2, missing=3)
    runner.run_once()
    assert occurrence(store)["state"] == "running"

    clock.now = NOW + 30
    runner.run_once()
    assert not executor.dispatched
    evidence = receipts(store, occurrence(store))
    assert {row["status"] for row in evidence} == {"skipped"}
    assert {row["reason"] for row in evidence} == {"wave_deadline"}
    assert all(row["wave"] == dict(counts(staged=1, errored=2, missing=3),
                                   gate="held", observed_at=NOW + 30)
               for row in evidence)
    assert occurrence(store)["state"] == "stalled"


def test_wave_gate_never_retracts_work_it_already_admitted(wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(), window=300)
    executor.counted = counts(staged=10)
    executor.results["edge-1"] = {"status": "submitted", "reason": "queued",
                                  "job_id": "job-edge-1"}
    runner.run_once()
    assert len(executor.asked) == 1 and len(executor.dispatched) == 2

    executor.counted = counts(staged=0, errored=10)
    executor.poll_results["edge-1"] = {"status": "ok", "reason": "assigned"}
    clock.now += 1
    runner.run_once()
    assert executor.asked == [occurrence(store)["id"]]
    assert occurrence(store)["state"] == "completed"


def test_wave_gate_held_at_window_close_stalls_rather_than_completes(
        wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(deadline_seconds=600), window=10)
    executor.counted = counts(staged=1)
    runner.run_once()
    clock.now = NOW + 10
    runner.run_once()
    assert not executor.dispatched
    assert {row["reason"] for row in receipts(store, occurrence(store))} == \
        {"window_closed"}
    assert occurrence(store)["state"] == "stalled"


def test_wave_gate_evidence_loss_retries_and_still_honors_the_deadline(
        wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(deadline_seconds=30), window=300)
    executor.counted = counts(staged=1)
    runner.run_once()
    executor.refuse = "staging_evidence_unavailable"
    clock.now += 1
    runner.run_once()
    assert runner.last_error == "staging_evidence_unavailable"
    assert not receipts(store, occurrence(store))
    assert occurrence(store)["state"] == "running"

    clock.now = NOW + 30
    runner.run_once()
    evidence = receipts(store, occurrence(store))
    assert {row["reason"] for row in evidence} == {"wave_deadline"}
    # The last durable counts are reported, never a fabricated all-clear.
    assert all(row["wave"] == dict(counts(staged=1), gate="held",
                                   observed_at=NOW) for row in evidence)
    assert occurrence(store)["state"] == "stalled"


def test_wave_gate_without_a_preceding_occurrence_is_not_an_all_clear(
        wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(min_staged_ratio=0, deadline_seconds=30),
           window=300)
    executor.counted = counts(total=0, occurrence_id=None)
    runner.run_once()
    assert not executor.dispatched
    assert annotated(store)["gate"] == "held"

    # An empty preceding target set HAS run and has nothing left to wait for.
    executor.counted = counts(total=0)
    clock.now += 1
    runner.run_once()
    assert len(executor.dispatched) == 2


def test_wave_gate_rejects_counts_it_cannot_trust(wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(), window=300)
    executor.counted = counts(total=1, staged=2)
    assert runner.run_once() > 0
    assert runner.last_error == "schedule_runner_error"
    assert not executor.dispatched and not receipts(store, occurrence(store))


class ChainExecutor(WaveExecutor):
    """Counts a preceding occurrence from its own durable evidence."""
    def __init__(self, store):
        super().__init__()
        self.occurrences = schedules.OccurrenceStore(store.state_dir)
        self.evidence = schedules.ReceiptStore(store.state_dir)

    def wave_counts(self, schedule, occurrence):
        preceding = schedule["after"]["schedule_id"]
        rows = [row for row in self.occurrences.list(preceding)
                if row["state"] != "missed"
                and row["scheduled_at"] <= occurrence["scheduled_at"]]
        if not rows:
            return counts(total=0, occurrence_id=None, schedule_id=preceding)
        latest = rows[-1]
        targets = latest["target_snapshot"]["device_ids"]
        done = [self.evidence.get(latest["id"], did) for did in targets]
        return counts(total=len(targets), schedule_id=preceding,
                      occurrence_id=latest["id"],
                      staged=sum(1 for row in done
                                 if row and row["status"] == "ok"),
                      errored=sum(1 for row in done
                                  if row and row["status"] == "error"))


def test_wave_chain_orders_core_before_distribution_before_access(setup):
    store, clock, _, reads, runner = setup
    executor = ChainExecutor(store)
    runner.executor = executor
    runner.wave_recheck = 1
    create(store, "s-core", at=NOW, window=300)
    create(store, "s-dist", at=NOW + 1, window=300,
           after=gate(schedule_id="s-core", deadline_seconds=200))
    create(store, "s-access", at=NOW + 2, window=300,
           after=gate(schedule_id="s-dist", deadline_seconds=200))
    executor.results["edge-1"] = {"status": "submitted", "reason": "queued",
                                  "job_id": "job-edge-1"}

    runner.run_once()
    clock.now = NOW + 2
    runner.run_once()
    assert occurrence(store, "s-core")["state"] == "running"
    assert annotated(store, "s-dist")["gate"] == "held"
    assert annotated(store, "s-access")["gate"] == "held"
    assert not receipts(store, occurrence(store, "s-dist"))
    assert not receipts(store, occurrence(store, "s-access"))

    executor.poll_results["edge-1"] = {"status": "ok", "reason": "assigned"}
    for step in range(5):
        clock.now = NOW + 3 + step
        runner.run_once()
    assert [occurrence(store, name)["state"]
            for name in ("s-core", "s-dist", "s-access")] == ["completed"] * 3
    assert annotated(store, "s-dist")["gate"] == "open"
    assert annotated(store, "s-access")["gate"] == "open"


def test_wave_gate_rereads_on_its_own_cadence_not_every_wake(setup):
    store, clock, _, reads, runner = setup
    executor = WaveExecutor()
    runner.executor = executor
    create(store, after=gate(deadline_seconds=30), window=300)
    executor.counted = counts(staged=1)

    for offset in range(6):
        clock.now = NOW + offset
        runner.run_once()
    # Six wakes, one read: the heartbeat authority and the swarm are whole
    # fleet reads, and devices report on a cadence of their own.
    assert len(executor.asked) == 1
    assert occurrence(store)["state"] == "running"

    clock.now = NOW + runner.wave_recheck
    runner.run_once()
    assert len(executor.asked) == 2

    # The deadline is never throttled: the counts that stall an occurrence
    # are read at the moment they are recorded.
    executor.counted = counts(staged=4)
    clock.now = NOW + 30
    runner.run_once()
    assert len(executor.asked) == 3
    assert occurrence(store)["state"] == "stalled"
    assert all(row["wave"]["staged"] == 4
               for row in receipts(store, occurrence(store)))


def test_wave_gate_that_opened_stays_open_across_an_interrupted_pass(
        wave_setup):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(), window=300)
    executor.counted = counts(staged=10)
    answered = executor.wave_counts

    def stop_after_the_decision(schedule, occurrence):
        result = answered(schedule, occurrence)
        runner.stop()
        return result

    executor.wave_counts = stop_after_the_decision
    runner.run_once()
    assert not receipts(store, occurrence(store))
    assert annotated(store)["gate"] == "open"

    # The decision is durable, so a pass that admitted nothing before it was
    # interrupted does not re-litigate it against counts that moved since.
    executor.wave_counts = lambda *_: pytest.fail("the gate reopened")
    runner._stop.clear()
    executor.counted = counts(staged=0, errored=10)
    clock.now += 1
    runner.run_once()
    assert len(executor.dispatched) == 2
    assert occurrence(store)["state"] == "completed"


@pytest.mark.parametrize("restart_before_admission", [False, True])
def test_quarantine_annotation_preserves_an_open_wave_gate(
        wave_setup, restart_before_admission):
    store, clock, executor, reads, runner = wave_setup
    create(store, after=gate(), window=300)
    executor.counted = counts(staged=10)

    def validate(schedule, snapshot, phase):
        # Production window-start validation records this diagnostic after
        # the preceding wave's staging gate has opened durably.
        assert phase == "window_start"
        runner.occurrences.annotate_all_targets_quarantined(
            snapshot["occurrence_id"], len(snapshot["device_ids"]), now=clock.now)
        if restart_before_admission:
            runner.stop()

    executor.validate = validate
    runner.run_once()
    recorded = occurrence(store)
    assert recorded["annotations"]["all_targets_quarantined"] == 2
    assert recorded["annotations"]["wave"]["gate"] == "open"
    if restart_before_admission:
        assert not receipts(store, recorded)
        executor.validate = lambda *_: None
        executor.wave_counts = lambda *_: pytest.fail("durable open gate was lost")
        clock.now += 1
        recovered = schedule_runner.ScheduleRunner(
            store, runner.resolve_target, executor=executor,
            role_guard=runner.role_guard, now_fn=clock)
        recovered.run_once()
    assert len(executor.dispatched) == 2
    assert occurrence(store)["state"] == "completed"
    assert all(row["status"] == "ok" for row in receipts(store, occurrence(store)))
