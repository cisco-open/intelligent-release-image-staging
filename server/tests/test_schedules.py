# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Schedule authority, durable progress, and local-clock boundary contracts."""
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import json
import threading

import pytest

import schedules


def epoch(text):
    return int(dt.datetime.fromisoformat(text).timestamp())


NOW = epoch("2026-09-09T12:00:00+00:00")


def definition(**changes):
    value = {"kind": "assign", "target": {"filters": {"role": "boat"}},
             "payload": {"image_ids": ["image-a"]},
             "when": {"kind": "once", "at": NOW + 60,
                      "window_seconds": 7200}}
    value.update(changes)
    return value


def create(store, **changes):
    return store.create("s-boat", definition(**changes), actor="console:alice",
                        now=NOW, preview={"revision": 4, "now": NOW,
                                          "device_ids": ["edge-1", "edge-2"]})


def test_closed_row_defaults_and_detached_reads(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    assert set(row) == {"id", "generation", "rev", "kind", "target", "payload",
                        "when", "state", "created_by", "created_at", "preview"}
    assert row["rev"] == 1 and row["state"] == "pending"
    assert row["target"] == {"filters": {"role": "boat"}, "device_ids": [], "bind": "late"}
    assert row["payload"]["mode"] == "merge"
    assert row["when"]["tz"] == "UTC"
    assert schedules.schedule_etag(row) == '"iris-schedule-s-boat-1"'
    row["payload"]["image_ids"].append("image-b")
    assert store.get("s-boat")["payload"]["image_ids"] == ["image-a"]
    assert (tmp_path / "schedules.d").is_dir()


@pytest.mark.parametrize("key", ["install", "activate", "reload", "boot", "env", "script", "command"])
@pytest.mark.parametrize("location", ["root", "target", "filters", "payload", "when", "after"])
def test_closed_keys_reject_execution_controls(key, location):
    value = definition()
    target = value if location == "root" else value["target"] if location == "target" else value["target"]["filters"] if location == "filters" else value.setdefault(location, {})
    target[key] = "arbitrary"
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.normalize_definition(value)


@pytest.mark.parametrize("changes", [
    {"kind": "install"}, {"kind": "undeploy"}, {"state": "running"},
    {"payload": {"image_ids": ["image-a"], "mode": "append"}},
    {"payload": {"image_ids": ["image-a", "image-a"]}},
    {"payload": {"image_ids": []}},
    {"target": {"filters": {"role": ["boat"]}}},
    {"target": {"device_ids": ["../device"]}},
    {"target": {"device_ids": ["edge-1"], "bind": "eventual"}},
    {"when": {"kind": "once", "at": True, "window_seconds": 30}},
    {"when": {"kind": "once", "at": NOW, "window_seconds": False}},
    {"when": {"kind": "recurring", "weekday": True, "hour": 2, "minute": 0}},
    {"when": {"kind": "recurring", "weekday": 7, "hour": 2, "minute": 0, "window_seconds": 60}},
    {"when": {"kind": "once", "at": NOW, "window_seconds": 60, "tz": "../UTC"}},
    {"after": {"schedule_id": "s-core", "condition": "min_staged_ratio",
               "min_staged_ratio": True, "max_errored_ratio": .1,
               "max_missing_ratio": .1, "deadline_seconds": 3600}},
    {"after": {"schedule_id": "s-core", "condition": "min_staged_ratio",
               "min_staged_ratio": float("nan"), "max_errored_ratio": .1,
               "max_missing_ratio": .1, "deadline_seconds": 3600}},
])
def test_invalid_definitions(changes):
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.normalize_definition(definition(**changes))


def test_onboard_defaults_and_required_blast_bound():
    value = schedules.normalize_definition(definition(kind="onboard", payload={"max_devices": 250}))
    assert value["payload"] == {"telemetry": True, "telemetry_stream": False,
                                "mode": "new-only", "max_devices": 250}
    for payload in ({}, {"max_devices": True}, {"max_devices": 1, "mode": "reconcile"},
                    {"max_devices": 1, "telemetry": 1}):
        with pytest.raises(schedules.ScheduleValidationError):
            schedules.normalize_definition(definition(kind="onboard", payload=payload))


def test_explicit_ids_and_filters_remain_an_intersection():
    target = schedules.normalize_definition(definition(target={
        "filters": {"role": "boat"}, "device_ids": ["edge-2"], "bind": "early"}))["target"]
    assert target == {"filters": {"role": "boat"}, "device_ids": ["edge-2"], "bind": "early"}
    assert schedules.normalize_definition(definition(target={"device_ids": ["edge-1"]}))["target"]["filters"] == {}
    assert schedules.normalize_definition(definition(target={"filters": {}, "device_ids": []}))["target"] == {
        "filters": {}, "device_ids": [], "bind": "late"}


@pytest.mark.parametrize("field", ["id", "generation", "rev", "created_by", "created_at", "preview"])
def test_clients_cannot_write_authority_metadata(tmp_path, field):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    with pytest.raises(schedules.ScheduleValidationError):
        store.patch("s-boat", {field: "forged"}, expected_rev=1)
    assert store.get("s-boat") == row


@pytest.mark.parametrize("schedule_id", ["", "../x", "x/y", "x\n", "x" * 65, True])
def test_ids_are_not_paths(tmp_path, schedule_id):
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.ScheduleStore(tmp_path).create(schedule_id, definition(), actor="console:alice", now=NOW)


def test_crud_cas_reaffirm_and_recreate_generation(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    original = create(store)
    with pytest.raises(schedules.ScheduleConflict):
        create(store)
    updated = store.patch("s-boat", {"state": "paused"}, expected_rev=1)
    assert updated["rev"] == 2
    for action in (lambda: store.put("s-boat", definition(), expected_rev=1),
                   lambda: store.patch("s-boat", {"state": "pending"}, expected_rev=1),
                   lambda: store.reaffirm("s-boat", "console:bob", expected_rev=1),
                   lambda: store.delete("s-boat", expected_rev=1)):
        with pytest.raises(schedules.ScheduleRevisionConflict) as error:
            action()
        assert error.value.revision == 2 and error.value.status == 412
    replaced = store.put("s-boat", definition(), expected_rev=2)
    assert replaced["created_by"] == "console:alice" and replaced["rev"] == 3
    reaffirmed = store.reaffirm("s-boat", "console:bob", expected_rev="*")
    assert reaffirmed["created_by"] == "console:bob" and reaffirmed["rev"] == 4
    assert store.delete("s-boat", expected_rev=4) is True
    assert store.get("s-boat") is None
    assert create(store)["generation"] != original["generation"]


def test_compare_and_write_are_locked_per_row(tmp_path):
    create(schedules.ScheduleStore(tmp_path))
    barrier = threading.Barrier(2)
    def edit():
        store = schedules.ScheduleStore(tmp_path)
        barrier.wait()
        try:
            return store.patch("s-boat", {"state": "paused"}, expected_rev=1)["rev"]
        except schedules.ScheduleRevisionConflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: edit(), range(2)))
    assert sorted(results, key=str) == [2, "conflict"]
    store = schedules.ScheduleStore(tmp_path)
    store.create("s-other", definition(), actor="cli:iris-schedule", now=NOW, preview={"revision": 0, "now": NOW, "device_ids": []})
    assert store.patch("s-other", {"state": "paused"}, expected_rev=1)["rev"] == 2


def test_bad_candidate_never_poisons_store_and_role_scan_includes_paused(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    original = create(store)
    with pytest.raises(schedules.ScheduleValidationError):
        store.patch("s-boat", {"payload": {"image_ids": [True]}}, expected_rev=1)
    assert store.get("s-boat") == original
    store.patch("s-boat", {"state": "paused"}, expected_rev=1)
    assert store.referring_schedules("boat") == ["s-boat"]
    assert store.referring_schedules("fiber") == []


def test_corrupt_state_fails_closed(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    create(store)
    shard = next((tmp_path / "schedules.d").glob("*.json"))
    data = json.loads(shard.read_text())
    data["s-boat"]["rev"] = True
    shard.write_text(json.dumps(data))
    with pytest.raises(schedules.ScheduleStateError):
        store.get("s-boat")


def weekly(tz, weekday, hour, minute, created_at=0):
    return dict(definition(when={"kind": "recurring", "tz": tz,
                                "weekday": weekday, "hour": hour, "minute": minute,
                                "window_seconds": 7200}), created_at=created_at)


@pytest.mark.parametrize("tz,local_date,hour,minute,expected,resolution", [
    ("Europe/Stockholm", "2026-03-29", 2, 30, "2026-03-29T01:00:00+00:00", "gap"),
    ("Europe/Stockholm", "2026-10-25", 2, 30, "2026-10-25T00:30:00+00:00", "fold"),
    ("Australia/Lord_Howe", "2026-10-04", 2, 15, "2026-10-03T15:30:00+00:00", "gap"),
    ("Australia/Lord_Howe", "2026-04-05", 1, 45, "2026-04-04T14:45:00+00:00", "fold"),
])
def test_dst_resolves_first_valid_or_first_fold(tz, local_date, hour, minute, expected, resolution):
    expected = epoch(expected)
    schedule = weekly(tz, 6, hour, minute)
    slot = schedules.occurrence_slot(schedule, expected - 1)
    assert slot["scheduled_at"] == expected and slot["resolution"] == resolution
    assert slot["local_time"].startswith(local_date)
    assert schedules.next_fire(schedule, expected + 1800) == expected
    later = schedules.occurrence_slot(schedule, expected + 3600, after_epoch=expected)
    assert later["scheduled_at"] > expected + 6 * 86400


def test_once_window_is_half_open_and_missed_is_visible():
    schedule = definition()
    at = NOW + 60
    assert schedules.next_fire(schedule, at - 1) == at
    assert schedules.next_fire(schedule, at) == at
    assert schedules.next_fire(schedule, at + 7199) == at
    assert schedules.next_fire(schedule, at + 7200) is None
    assert schedules.occurrence_slot(schedule, at + 7200)["status"] == "missed"
    assert schedules.occurrence_slot(schedule, at, after_epoch=at) is None


def test_weekly_catchup_cursor_and_creation_floor():
    schedule = weekly("UTC", 2, 12, 0, created_at=NOW - 8 * 86400)
    assert schedules.next_fire(schedule, NOW + 1) == NOW
    assert schedules.occurrence_slot(schedule, NOW + 7200)["status"] == "missed"
    assert schedules.next_fire(schedule, NOW + 7200) == NOW + 7 * 86400
    missed = schedules.occurrence_slot(schedule, NOW + 1, after_epoch=NOW - 14 * 86400)
    assert missed["scheduled_at"] == NOW - 7 * 86400 and missed["status"] == "missed"
    schedule["created_at"] = NOW + 1
    assert schedules.next_fire(schedule, NOW + 1) == NOW + 7 * 86400
    schedule["state"] = "paused"
    assert schedules.next_fire(schedule, NOW + 1) is None


def test_occurrences_and_per_device_receipts_survive_restart_and_read_caps(tmp_path):
    row = create(schedules.ScheduleStore(tmp_path))
    occurrences = schedules.OccurrenceStore(tmp_path)
    slot = schedules.occurrence_slot(row, NOW + 60)
    occurrence = occurrences.create(row, slot, {"revision": 8, "now": NOW + 60,
                                                "device_ids": ["edge-2", "edge-3"]}, now=NOW + 60)
    oid = occurrence["id"]
    assert occurrence["delta"] == {"added": 1, "removed": 1}
    assert occurrence["actor"] == "schedule:s-boat"
    assert occurrences.create(row, slot, {"revision": 9, "now": NOW + 60,
                                         "device_ids": ["different"]}, now=NOW + 60) == occurrence
    occurrences.transition(oid, "running", now=NOW + 60, expected_state="pending")
    receipts = schedules.ReceiptStore(tmp_path)
    first = receipts.record(oid, "edge-2", status="ok", reason="assigned", now=NOW + 61)
    receipts.record(oid, "edge-3", status="skipped", reason="device_revoked", now=NOW + 62)
    assert receipts.record(oid, "edge-2", status="error", reason="conflict", now=NOW + 63) == first
    assert schedules.OccurrenceStore(tmp_path).recover_interrupted(now=NOW + 90) == [oid]
    assert schedules.OccurrenceStore(tmp_path).get(oid)["state"] == "interrupted"
    restarted = schedules.ReceiptStore(tmp_path)
    page = restarted.list(oid, limit=1)
    assert page["total"] == 2 and page["truncated"] is True and len(page["receipts"]) == 1
    assert restarted.completed_device_ids(oid) == {"edge-2", "edge-3"}
    occurrences.transition(oid, "running", now=NOW + 100, expected_state="interrupted")
    occurrences.transition(oid, "completed", now=NOW + 101, expected_state="running")
    with pytest.raises(schedules.ScheduleConflict):
        occurrences.transition(oid, "running", now=NOW + 102)
    assert occurrences.latest_slot(row) == slot["scheduled_at"]


def test_early_binding_retains_preview_and_definition_edits_do_not_replay_slot(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store, target={"device_ids": ["edge-1"], "bind": "early"})
    occurrences = schedules.OccurrenceStore(tmp_path)
    slot = schedules.occurrence_slot(row, NOW + 60)
    first = occurrences.create(row, slot, {"revision": 7, "now": NOW + 60,
                                          "device_ids": ["edge-3"]}, now=NOW + 60)
    assert first["target_snapshot"]["device_ids"] == ["edge-1", "edge-2"]
    assert first["target_snapshot"]["revision"] == 7
    assert first["preview"]["revision"] == 4
    changed = store.patch("s-boat", {"state": "pending"}, expected_rev=1)
    second = occurrences.create(changed, slot, changed["preview"], now=NOW + 60)
    assert first == second
    assert first["schedule"]["rev"] == 1


def test_claim_checks_live_revision_and_keeps_crash_retry_identity(tmp_path, monkeypatch):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    slot = schedules.occurrence_slot(row, NOW + 60)
    snapshot = {"revision": 9, "now": NOW + 60, "device_ids": ["edge-2"]}
    with pytest.raises(schedules.ScheduleRevisionConflict):
        store.claim_occurrence("s-boat", expected_rev=9, expected_generation=row["generation"], slot=slot,
                               target_snapshot=snapshot, now=NOW + 60)
    original = store._progress.put
    monkeypatch.setattr(store._progress, "put", lambda *_: (_ for _ in ()).throw(OSError("simulated crash")))
    with pytest.raises(OSError):
        store.claim_occurrence("s-boat", expected_rev=1, expected_generation=row["generation"], slot=slot,
                               target_snapshot=snapshot, now=NOW + 60)
    existing = schedules.OccurrenceStore(tmp_path).list()[0]
    monkeypatch.setattr(store._progress, "put", original)
    resumed = store.claim_occurrence("s-boat", expected_rev=1, expected_generation=row["generation"], slot=slot,
                                     target_snapshot=dict(snapshot, device_ids=["changed"]), now=NOW + 61)
    assert resumed == existing
    assert store.progress("s-boat")["last_slot"] == slot["scheduled_at"]
    store.reaffirm("s-boat", "console:bob", expected_rev=1)
    assert store.claim_occurrence("s-boat", expected_rev=2, expected_generation=row["generation"], slot=slot,
                                  target_snapshot=snapshot, now=NOW + 62) == existing


def receipt_occurrence(tmp_path):
    row = create(schedules.ScheduleStore(tmp_path), when={"kind": "once", "at": NOW, "window_seconds": 7200})
    return schedules.OccurrenceStore(tmp_path).create(row, schedules.occurrence_slot(row, NOW), row["preview"], now=NOW)["id"]


def test_receipt_intent_submission_terminal_are_monotonic_across_restart(tmp_path):
    store = schedules.ReceiptStore(tmp_path)
    oid = receipt_occurrence(tmp_path)
    intent = store.begin(oid, "edge-1", now=NOW)
    assert intent["status"] == "intent" and intent["completed_at"] is None
    assert store.completed_device_ids(oid) == set()
    submitted = store.record(oid, "edge-1", status="submitted", reason="queued",
                             expected_status="intent", expected_rev=intent["rev"], job_id="job-1", record_id="record-1", now=NOW + 1)
    restarted = schedules.ReceiptStore(tmp_path)
    assert restarted.get(oid, "edge-1") == submitted
    assert restarted.begin(oid, "edge-1", now=NOW + 2) == submitted
    with pytest.raises(schedules.ScheduleConflict):
        restarted.record(oid, "edge-1", status="submitted", reason="queued",
                          expected_status="intent", job_id="stale-job", now=NOW + 3)
    with pytest.raises(schedules.ScheduleConflict):
        restarted.record(oid, "edge-1", status="ok", reason="onboarded",
                          expected_rev=intent["rev"], now=NOW + 3)
    terminal = restarted.record(oid, "edge-1", status="ok", reason="onboarded",
                                 expected_status="submitted", expected_rev=submitted["rev"], now=NOW + 4)
    assert terminal["job_id"] == "job-1" and terminal["record_id"] == "record-1"
    assert restarted.record(oid, "edge-1", status="error", reason="conflict", now=NOW + 5) == terminal
    assert restarted.completed_device_ids(oid) == {"edge-1"}


def test_delete_recreate_same_name_and_epoch_cannot_reuse_occurrence(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    first = create(store)
    slot = schedules.occurrence_slot(first, NOW + 60)
    store.claim_occurrence("s-boat", expected_rev=1, expected_generation=first["generation"], slot=slot,
                           target_snapshot=first["preview"], now=NOW + 60)
    store.delete("s-boat", expected_rev=1)
    second = create(store)
    assert store.progress("s-boat") is None
    assert schedules.occurrence_id(first, slot["scheduled_at"]) != schedules.occurrence_id(second, slot["scheduled_at"])


def test_claim_rejects_future_or_obsolete_slot(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    slot = schedules.occurrence_slot(row, NOW)
    with pytest.raises(schedules.ScheduleConflict):
        store.claim_occurrence("s-boat", expected_rev=1, expected_generation=row["generation"], slot=slot, target_snapshot=row["preview"], now=NOW)
    changed = store.patch("s-boat", {"when": {"kind": "once", "at": NOW + 90, "window_seconds": 60}}, expected_rev=1)
    with pytest.raises(schedules.ScheduleConflict):
        store.claim_occurrence("s-boat", expected_rev=changed["rev"], expected_generation=row["generation"], slot=slot, target_snapshot=row["preview"], now=NOW + 100)


@pytest.mark.parametrize("metadata", [{"actor": "alice"}, {"actor": "console:alice\n"}, {"now": True}])
def test_invalid_server_metadata_refused_before_write(tmp_path, metadata):
    store = schedules.ScheduleStore(tmp_path)
    kwargs = {"actor": "console:alice", "now": NOW, **metadata}
    with pytest.raises(schedules.ScheduleValidationError):
        store.create("s-boat", definition(), **kwargs)
    assert store.list() == []


def test_retarget_requires_fresh_server_preview(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    target = {"filters": {"role": "fiber"}, "bind": "early"}
    with pytest.raises(schedules.ScheduleValidationError):
        store.patch("s-boat", {"target": target}, expected_rev=1)
    assert store.get("s-boat") == row
    changed = store.patch("s-boat", {"target": target}, expected_rev=1,
                           preview={"revision": 8, "now": NOW + 1, "device_ids": ["edge-3"]})
    assert changed["preview"]["device_ids"] == ["edge-3"]


def test_retired_revision_floor_prevents_etag_and_claim_aba(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    old = create(store)
    slot = schedules.occurrence_slot(old, NOW + 60)
    store.delete(old["id"], expected_rev=old["rev"])
    fresh = create(store)
    assert fresh["rev"] > old["rev"]
    with pytest.raises(schedules.ScheduleRevisionConflict):
        store.patch(old["id"], {"state": "paused"}, expected_rev=old["rev"])
    with pytest.raises(schedules.ScheduleConflict):
        store.claim_occurrence(old["id"], expected_rev=fresh["rev"], expected_generation=old["generation"],
                               slot=slot, target_snapshot=old["preview"], now=NOW + 60)
    with pytest.raises(schedules.ScheduleValidationError):
        store.claim_occurrence(old["id"], expected_rev="*", expected_generation=fresh["generation"],
                               slot=slot, target_snapshot=fresh["preview"], now=NOW + 60)


def test_delete_crash_after_floor_write_preserves_live_row_and_safe_recreate(tmp_path, monkeypatch):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    write = store._rows._write_shard
    monkeypatch.setattr(store._rows, "_write_shard", lambda *_: (_ for _ in ()).throw(OSError("crash before delete")))
    with pytest.raises(OSError):
        store.delete("s-boat", expected_rev=1)
    assert store.get("s-boat") == row
    assert store._retired.get("s-boat") == {"revision": 1}
    monkeypatch.setattr(store._rows, "_write_shard", write)
    changed = store.patch("s-boat", {"state": "paused"}, expected_rev=1)
    store.delete("s-boat", expected_rev=changed["rev"])
    assert create(schedules.ScheduleStore(tmp_path))["rev"] > changed["rev"]


def test_create_requires_explicit_validated_preview_even_for_early(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    with pytest.raises(schedules.ScheduleValidationError):
        store.create("s-empty", definition(), actor="console:alice", now=NOW)
    empty = store.create("s-empty", definition(), actor="console:alice", now=NOW,
                          preview={"revision": 0, "now": NOW, "device_ids": []})
    assert empty["preview"]["device_ids"] == []


@pytest.mark.parametrize("image_id", ["_image", ".image", "-image", "i" * 128])
def test_catalog_image_id_grammar_is_not_device_grammar(image_id):
    assert schedules.normalize_definition(definition(payload={"image_ids": [image_id]}))["payload"]["image_ids"] == [image_id]


@pytest.mark.parametrize("image_id", ["i" * 129, "a/b", "a b", True])
def test_invalid_catalog_image_ids_refused(image_id):
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.normalize_definition(definition(payload={"image_ids": [image_id]}))


def test_reserved_service_id_cannot_be_a_device_target_or_preview():
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.normalize_definition(definition(target={"device_ids": ["seeder"]}))
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.normalize_snapshot({"revision": 1, "now": NOW, "device_ids": ["seeder"]})


def test_receipt_updates_require_cas_and_cannot_replace_ownership(tmp_path):
    oid = receipt_occurrence(tmp_path)
    store = schedules.ReceiptStore(tmp_path)
    intent = store.begin(oid, "edge-1", now=NOW, manual_generation=4, before_image_ids=["_old"])
    with pytest.raises(schedules.ScheduleConflict):
        store.record(oid, "edge-1", status="submitted", reason="queued", now=NOW + 1, job_id="job-1")
    submitted = store.record(oid, "edge-1", status="submitted", reason="queued", now=NOW + 1,
                             expected_rev=intent["rev"], job_id="job-1", record_id="record-1")
    with pytest.raises(schedules.ScheduleConflict):
        store.record(oid, "edge-1", status="running", reason="running", now=NOW + 2,
                      expected_rev=submitted["rev"], job_id="job-2")
    successor = store.successor_attempt(oid, "edge-1", expected_rev=submitted["rev"], now=NOW + 3,
                                         manual_generation=4, predecessor_record_id="record-1")
    assert successor["attempt"] == 2 and successor["status"] == "intent"
    assert successor["predecessors"][0]["job_id"] == "job-1"
    assert successor["predecessors"][0]["record_id"] == "record-1"
    assert successor["predecessor_record_id"] == "record-1"
    assert "job_id" not in successor and "record_id" not in successor
    with pytest.raises(schedules.ScheduleConflict):
        store.record(oid, "edge-1", status="ok", reason="onboarded", now=NOW + 4, expected_rev=submitted["rev"])
    bound = store.record(oid, "edge-1", status="submitted", reason="queued", now=NOW + 4,
                         expected_rev=successor["rev"], job_id="job-2", record_id="record-1")
    terminal = store.record(oid, "edge-1", status="ok", reason="assigned", now=NOW + 5,
                            expected_rev=bound["rev"], after_image_ids=["_new"], removed_image_ids=["_old"])
    assert schedules.ReceiptStore(tmp_path).get(oid, "edge-1") == terminal
    assert terminal["before_image_ids"] == ["_old"] and terminal["after_image_ids"] == ["_new"]
    with pytest.raises(schedules.ScheduleConflict):
        store.successor_attempt(oid, "edge-1", expected_rev=terminal["rev"], now=NOW + 6, manual_generation=4)


def test_receipt_rejects_freeform_diagnostics(tmp_path):
    oid = receipt_occurrence(tmp_path)
    with pytest.raises(TypeError):
        schedules.ReceiptStore(tmp_path).record(oid, "edge-1", status="error", reason="failed", now=NOW, detail="arbitrary diagnostic")


def test_missed_occurrence_records_no_fabricated_target_and_cannot_dispatch(tmp_path):
    store = schedules.ScheduleStore(tmp_path)
    row = create(store)
    expired = NOW + 60 + 7200
    slot = schedules.occurrence_slot(row, expired)
    missed = store.claim_occurrence("s-boat", expected_rev=1, expected_generation=row["generation"],
                                     slot=slot, target_snapshot=None, now=expired)
    assert missed["state"] == "missed"
    assert "target_snapshot" not in missed and "delta" not in missed
    with pytest.raises(schedules.ScheduleConflict):
        schedules.OccurrenceStore(tmp_path).transition(missed["id"], "running", now=expired)
    with pytest.raises(schedules.ScheduleConflict):
        schedules.ReceiptStore(tmp_path).begin(missed["id"], "edge-1", now=expired)


def test_unbound_occurrence_is_only_legal_after_window_expiry(tmp_path):
    row = create(schedules.ScheduleStore(tmp_path))
    slot = schedules.occurrence_slot(row, NOW + 60)
    with pytest.raises(schedules.ScheduleValidationError):
        schedules.OccurrenceStore(tmp_path).create(row, slot, None, now=NOW + 60)


def test_weekly_prior_window_remains_due_before_fall_back_slot():
    schedule = weekly("Europe/Stockholm", 6, 3, 0)
    schedule["when"]["window_seconds"] = 7 * 86400
    previous = epoch("2026-10-18T01:00:00+00:00")
    future = epoch("2026-10-25T02:00:00+00:00")
    now = epoch("2026-10-25T00:30:00+00:00")
    slot = schedules.occurrence_slot(schedule, now)
    assert slot["scheduled_at"] == previous and slot["status"] == "due"
    assert schedules.next_fire(schedule, now) == previous
    assert schedules.next_fire(schedule, previous + 7 * 86400) == future
    schedule["created_at"] = previous + 1
    assert schedules.next_fire(schedule, now) == future
