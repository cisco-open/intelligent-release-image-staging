# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Integrated scheduled assignment/onboarding authority and recovery tests."""
import contextlib
import copy
import hashlib
import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

import assignment_service
import catalog
import deployment_records
import gui_fleet
import gui_onboard
import management_api
import schedule_runner
import schedules


NOW = 1_788_883_200


class _Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class _Policy:
    def __init__(self, quarantined=()):
        self.document = {
            "quarantined_devices": {did: True for did in quarantined}}
        self.roles = SimpleNamespace(role_of={})


def _role_guard(policy):
    @contextlib.contextmanager
    def guard(_schedule):
        yield policy
    return guard


def _image(image_id):
    return {
        "id": image_id, "filename": image_id + ".bin", "size": 5,
        "sha256": "ab" * 32, "sha512": "cd" * 64,
        "cisco_signature_verified": False,
        "info_hash_hex": "ef" * 20, "published_at": NOW,
    }


def _definition(kind="assign", device_ids=None, **payload):
    if kind == "assign":
        body = {"image_ids": payload.pop("image_ids", ["image-a"]),
                "mode": payload.pop("mode", "merge")}
    else:
        body = {"telemetry": payload.pop("telemetry", True),
                "telemetry_stream": payload.pop("telemetry_stream", False),
                "mode": "new-only",
                "max_devices": payload.pop("max_devices", 10)}
    assert not payload
    return {
        "kind": kind,
        "target": {"filters": {}, "device_ids": list(device_ids or []),
                   "bind": "late"},
        "payload": body,
        "when": {"kind": "once", "at": NOW, "tz": "UTC",
                 "window_seconds": 300},
        "state": "pending",
    }


def _make_schedule(state, definition, device_ids):
    store = schedules.ScheduleStore(state)
    store.create(
        "nightly", definition, actor="console:test", now=NOW - 1,
        preview={"revision": 1, "now": NOW - 1,
                 "device_ids": list(device_ids)})
    return store


def _base_executor(tmp_path, *, store, fleet, policy, writer,
                   submission=None, onboard=None, records=None, clock=None):
    secrets_path = tmp_path / "secrets.json"
    if not secrets_path.exists():
        secrets_path.write_text(json.dumps({"devices": {}, "seeder": {}}))
    return management_api._ScheduledExecutor(
        schedule_store=store,
        occurrence_store=schedules.OccurrenceStore(tmp_path),
        receipt_store=schedules.ReceiptStore(tmp_path),
        role_guard=_role_guard(policy),
        role_policy_snapshot=lambda: policy,
        fleet=fleet, secrets_path=str(secrets_path),
        assignment_writer=writer, submission=submission, onboard=onboard,
        record_store=records, now_fn=clock or _Clock())


def _run_schedule(store, executor, policy, clock, ids):
    runner = schedule_runner.ScheduleRunner(
        store,
        lambda _row: {"revision": 2, "now": clock.now,
                      "device_ids": list(ids),
                      "missing_os_family": 0, "role_drift": 0,
                      "quarantined_ids": sorted(
                          set(ids).intersection(
                              policy.document["quarantined_devices"]))},
        executor=executor, role_guard=_role_guard(policy), now_fn=clock,
        poll_interval=.01)
    runner.run_once()
    return runner


def test_assignment_runs_once_records_quarantine_and_reclaims_claim(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, str(tmp_path / "audit.jsonl"),
        authority_path=str(authority))
    definition = _definition(device_ids=["edge-1"])
    store = _make_schedule(tmp_path, definition, ["edge-1"])
    clock = _Clock()
    policy = _Policy(["edge-1"])
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])

    receipt_store = schedules.ReceiptStore(tmp_path)
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    prepared = receipt_store.get(occurrence["id"], "edge-1")
    assert prepared["status"] == "intent"
    assert prepared["reason"] == "assignment_prepared"
    assert prepared["fleet_registered_at"] == \
        fleet.get_device("edge-1")["registered_at"]
    clock.now += 1
    runner.run_once()

    receipt = receipt_store.get(occurrence["id"], "edge-1")
    assert receipt["status"] == "ok"
    assert receipt["after_image_ids"] == ["image-a"]
    assert receipt["notes"] == ["peer_quarantined"]
    assert schedules.OccurrenceStore(tmp_path).get(
        occurrence["id"])["annotations"] == {
            "all_targets_quarantined": 1}
    assert images.get_policy("edge-1")["approved_image_ids"] == ["image-a"]
    with sqlite3.connect(authority) as connection:
        assert connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0
    events = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(events) == 1


def test_due_assignment_intents_keep_their_own_baselines(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    for image_id in ("image-a", "image-b"):
        images.save_image(_image(image_id))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, str(tmp_path / "audit.jsonl"),
        authority_path=str(authority))
    store = schedules.ScheduleStore(tmp_path)
    for schedule_id, image_id in (("first", "image-a"),
                                  ("second", "image-b")):
        store.create(
            schedule_id,
            _definition(device_ids=["edge-1"], image_ids=[image_id]),
            actor="console:test", now=NOW - 1,
            preview={"revision": 1, "now": NOW - 1,
                     "device_ids": ["edge-1"]})
    clock, policy, errors = _Clock(), _Policy(), []
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = schedule_runner.ScheduleRunner(
        store,
        lambda _row: {"revision": 2, "now": clock.now,
                      "device_ids": ["edge-1"], "missing_os_family": 0,
                      "role_drift": 0, "quarantined_ids": []},
        executor=executor, role_guard=_role_guard(policy), now_fn=clock,
        poll_interval=.01, error_fn=errors.append)

    runner.run_once()
    occurrence_store = schedules.OccurrenceStore(tmp_path)
    receipt_store = schedules.ReceiptStore(tmp_path)
    occurrences = occurrence_store.list()
    assert len(occurrences) == 2
    assert [receipt_store.get(row["id"], "edge-1")["before_image_ids"]
            for row in occurrences] == [[], []]

    clock.now += 1
    runner.run_once()
    runner.run_once()

    occurrences = occurrence_store.list()
    assert {row["state"] for row in occurrences} == {"completed"}
    receipts = [receipt_store.get(row["id"], "edge-1")
                for row in occurrences]
    assert [row["status"] for row in receipts] == ["ok", "ok"]
    assert [row["before_image_ids"] for row in receipts] == [[], []]
    assert [row["removed_image_ids"] for row in receipts] == [[], []]
    assert set(images.get_policy("edge-1")["approved_image_ids"]) == {
        "image-a", "image-b"}
    assert runner.last_error is None and errors == []
    with sqlite3.connect(authority) as connection:
        assert connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0
    audit_events = [json.loads(line) for line in
                    (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert len(audit_events) == 2
    assert any(('before_ids=["image-a"]' in event["detail"] or
                'before_ids=["image-b"]' in event["detail"])
               for event in audit_events)


def test_overlapping_scheduled_replace_keeps_prepared_cas(
        tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    for image_id in ("base", "image-a", "image-b"):
        images.save_image(_image(image_id))
    images.set_policy("edge-1", approved_image_ids=["base"])
    original_set_policy = images.set_policy
    policy_calls = []

    def observe_policy_write(*args, **kwargs):
        policy_calls.append(copy.deepcopy(kwargs))
        return original_set_policy(*args, **kwargs)

    monkeypatch.setattr(images, "set_policy", observe_policy_write)
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, str(tmp_path / "audit.jsonl"),
        authority_path=str(authority))
    store = schedules.ScheduleStore(tmp_path)
    definitions = (
        ("merge", NOW - 1,
         _definition(device_ids=["edge-1"], image_ids=["image-b"])),
        ("replace", NOW,
         _definition(device_ids=["edge-1"], image_ids=["image-a"],
                     mode="replace")),
    )
    for schedule_id, scheduled_at, definition in definitions:
        definition["when"]["at"] = scheduled_at
        store.create(
            schedule_id, definition, actor="console:test", now=NOW - 2,
            preview={"revision": 1, "now": NOW - 2,
                     "device_ids": ["edge-1"]})
    clock, policy, errors = _Clock(), _Policy(), []
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)

    def make_runner():
        return schedule_runner.ScheduleRunner(
            store,
            lambda _row: {"revision": 2, "now": clock.now,
                          "device_ids": ["edge-1"],
                          "missing_os_family": 0, "role_drift": 0,
                          "quarantined_ids": []},
            executor=executor, role_guard=_role_guard(policy), now_fn=clock,
            poll_interval=.01, error_fn=errors.append)

    runner = make_runner()
    runner.run_once()
    occurrence_store = schedules.OccurrenceStore(tmp_path)
    receipt_store = schedules.ReceiptStore(tmp_path)
    occurrences = {row["schedule_id"]: row
                   for row in occurrence_store.list()}
    assert set(occurrences) == {"merge", "replace"}
    assert all(receipt_store.get(row["id"], "edge-1")[
                   "before_image_ids"] == ["base"]
               for row in occurrences.values())

    # A restarted runner orders the two active occurrences by scheduled time,
    # so the earlier merge commits before the overlapping replacement.
    clock.now += 1
    runner = make_runner()
    runner.run_once()
    runner.run_once()

    merge_receipt = receipt_store.get(
        occurrences["merge"]["id"], "edge-1")
    replace_receipt = receipt_store.get(
        occurrences["replace"]["id"], "edge-1")
    assert merge_receipt["status"] == "ok"
    assert merge_receipt["before_image_ids"] == ["base"]
    assert merge_receipt["after_image_ids"] == ["base", "image-b"]
    assert replace_receipt["status"] == "skipped"
    assert replace_receipt["reason"] == "conflict"
    assert replace_receipt["before_image_ids"] == ["base"]
    assert replace_receipt["after_image_ids"] == ["base", "image-b"]
    assert replace_receipt["removed_image_ids"] == []
    assert images.get_policy("edge-1")["approved_image_ids"] == [
        "base", "image-b"]
    assert [call["expect_image_ids"] for call in policy_calls] == [
        ["base"], ["base"], ["base"]]
    assert {row["state"] for row in occurrence_store.list()} == {
        "completed"}
    assert runner.last_error is None and errors == []
    with sqlite3.connect(authority) as connection:
        assert connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0
    events = [json.loads(line) for line in
              (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [event["result"] for event in events] == ["ok", "fail"]
    assert 'before_ids=["base"]' in events[0]["detail"]
    assert 'after_ids=["base", "image-b"]' in events[0]["detail"]
    assert 'before_ids=["base", "image-b"]' in events[1]["detail"]
    assert 'after_ids=["base", "image-b"]' in events[1]["detail"]


def test_manual_assignment_generation_wins_after_prepared_intent(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    for image_id in ("image-a", "manual", "old"):
        images.save_image(_image(image_id))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, authority_path=str(authority))
    writer.apply("edge-1", ["old"], actor="console:owner", mode="replace")
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    clock, policy = _Clock(), _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    assignment_service.AssignmentService(
        images, fleet, authority_path=str(authority)).apply(
            "edge-1", ["manual"], actor="console:owner", mode="replace")
    clock.now += 1
    runner.run_once()

    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "manual_override"
    assert receipt["before_image_ids"] == ["old"]
    assert receipt["after_image_ids"] == ["manual"]
    assert receipt["removed_image_ids"] == ["old"]
    assert images.get_policy("edge-1")["approved_image_ids"] == ["manual"]


@pytest.mark.parametrize("authority_loss", ("missing", "missing-devices"))
def test_prepared_assignment_refuses_lost_revocation_authority(
        tmp_path, authority_loss):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    writer = assignment_service.AssignmentService(
        images, fleet,
        authority_path=str(tmp_path / "assignment-authority.sqlite3"))
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    policy = _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])

    # A known revocation set must not become known-empty if its durable
    # authority disappears between preparation and commit admission.
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps({
        "devices": {"edge-1": {"catalog_token": {
            "value": "test-only", "created_at": NOW,
            "expires_at": 0, "revoked": True}}},
        "seeder": {}}))
    if authority_loss == "missing":
        secrets_path.unlink()
    else:
        secrets_path.write_text("{}")
    clock.now += 1
    runner.run_once()

    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "error"
    assert receipt["reason"] == "revocation_unavailable"
    assert images.get_policy("edge-1")["approved_image_ids"] == []


class _Creds:
    def __init__(self):
        self.profile = {"device_user": "admin", "device_pass": "test-only",
                        "enable_secret": "enable"}

    def get_secrets(self, profile_id):
        return self.profile if profile_id == "lab" else None

    def list_profiles(self):
        return [{"id": "lab"}]


def _onboard_components(tmp_path, fleet, clock, platform="guestshell"):
    creds = _Creds()
    records = deployment_records.DeploymentRecordStore(
        str(tmp_path), now_fn=clock)
    if platform == "iox":
        (tmp_path / "iris-arm64.tar").write_bytes(b"test-package")
    onboard = gui_onboard.OnboardService(
        fleet, creds, device_install="/fake/device-install.sh",
        crt_public="/fake/crt.pem", host_ip="192.0.2.10",
        mint_fn=lambda did: "TOKEN-" + did,
        run_fn=lambda _path, _env, _output: 0,
        probe_fn=lambda _device, _env: True,
        guestshell_preflight_fn=lambda _device, _env, _resolved: {
            "status": "passed", "device_identity": "FOC0000TEST"},
        record_store=records, max_concurrent=2, now_fn=clock,
        artifacts_dir=str(tmp_path),
        iox_controller=object() if platform == "iox" else None)

    def plan(device_id, device):
        if platform == "xr-appmgr":
            resolved = {
                "management_type": "xr-host",
                "device_ip": device["device_ip"],
                "model": device["model"], "platform": platform,
                "renderer": "v1",
            }
        else:
            resolved = {
                "management_type": "routed", "device_ip": device["device_ip"],
                "iris_vlan": device["iris_vlan"], "svi_ip": device["svi_ip"],
                "svi_mask": device["svi_mask"], "svi_igp": "",
                "app_ip": device["app_ip"], "app_mask": device["app_mask"],
                "app_gateway": device["app_gateway"], "inband_vlan": "",
                "vpg_number": "", "nat_interface": "", "swarm_port": "6881",
                "ios_ssh_host": "", "model": device["model"],
                "platform": platform, "renderer": "v1",
            }
        value = {"device_id": device_id,
                 "inventory_revision": fleet.revision(),
                 "resolved": resolved,
                 "ownership": "creates only a clean IRIS-owned VLAN and SVI"}
        value["plan_hash"] = hashlib.sha256(
            json.dumps(value, sort_keys=True).encode()).hexdigest()
        return value

    def apply_preflight(value, evidence):
        updated = dict(value)
        updated["resolved"] = gui_onboard.bind_preflight(
            value["resolved"], evidence)
        body = {key: item for key, item in updated.items()
                if key != "plan_hash"}
        updated["plan_hash"] = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()).hexdigest()
        return updated

    def resources(resolved):
        if resolved["platform"] == "xr-appmgr":
            return [{"kind": "xr-appmgr", "ownership": "iris-created",
                     "id": "iris"}]
        if resolved["platform"] == "iox":
            return [{"kind": "iox-app", "ownership": "iris-created",
                     "id": "iris"}]
        return [
            {"kind": "vlan", "ownership": "iris-created",
             "id": resolved["iris_vlan"]},
            {"kind": "svi", "ownership": "iris-created",
             "ip": resolved["svi_ip"]},
            {"kind": "guestshell", "ownership": "iris-created"},
        ]

    submission = management_api._OnboardSubmissionAdapter(
        fleet, creds, records, onboard, None, plan_fn=plan,
        apply_preflight_fn=apply_preflight,
        owned_resources_fn=resources,
        teardown_resolved_fn=lambda row: row["resolved"],
        audit_path=None, now_fn=clock)
    return onboard, records, submission


def _routed_device(*, role=None):
    row = {
        "device_id": "edge-1", "device_ip": "192.0.2.1",
        "model": "C9300", "management_type": "routed",
        "credential_profile_id": "lab", "iris_vlan": "666",
        "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
        "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
        "app_gateway": "10.0.0.2"}
    if role is not None:
        row["role"] = role
    return row


def _claim(store, device_ids):
    row = store.get("nightly")
    slot = schedules.occurrence_slot(row, NOW)
    return store.claim_occurrence(
        row["id"], expected_rev=row["rev"],
        expected_generation=row["generation"], slot=slot,
        target_snapshot={"revision": 2, "now": NOW,
                         "device_ids": list(device_ids)}, now=NOW)


def test_onboard_queue_to_terminal_receipt_keeps_occurrence_provenance(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert(_routed_device())
    clock, policy = _Clock(), _Policy()
    onboard, records, submission = _onboard_components(tmp_path, fleet, clock)
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    try:
        prepared = schedules.ReceiptStore(tmp_path).get(
            schedules.OccurrenceStore(tmp_path).list()[0]["id"], "edge-1")
        assert prepared["reason"] == "onboard_prepared"
        assert not onboard.list_jobs()
        clock.now += 1
        runner.run_once()
        deadline = time.time() + 3
        while time.time() < deadline and not all(
                job["state"] in ("done", "error", "cancelled")
                for job in onboard.list_jobs()):
            time.sleep(.01)
        runner.run_once()
        occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
        receipt = schedules.ReceiptStore(tmp_path).get(
            occurrence["id"], "edge-1")
        assert receipt["status"] == "ok"
        record = records.get(receipt["record_id"], strict=True)
        assert record["state"] == "active"
        assert receipt["fleet_registration_id"] == fleet.get_device(
            "edge-1")["registration_id"]
        assert record["fleet_registration_id"] == receipt[
            "fleet_registration_id"]
        assert record["schedule_provenance"] == {
            "schema_version": 1, "schedule_id": "nightly",
            "schedule_rev": 1, "occurrence_id": occurrence["id"],
            "device_id": "edge-1"}
    finally:
        onboard.shutdown()


def test_early_bound_assignment_ignores_later_role_change(tmp_path):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1",
                  "role": "boat"})
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    writer = assignment_service.AssignmentService(
        images, fleet,
        authority_path=str(tmp_path / "assignment-authority.sqlite3"))
    definition = _definition(device_ids=["edge-1"])
    definition["target"]["filters"] = {"role": "boat"}
    store = _make_schedule(tmp_path, definition, ["edge-1"])
    policy = _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    fleet.upsert({"device_id": "edge-1", "role": "fiber"})
    clock.now += 1
    runner.run_once()
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "ok"
    assert images.get_policy("edge-1")["approved_image_ids"] == ["image-a"]


def test_assignment_refuses_device_id_reused_after_preparation(tmp_path):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    original = {"device_id": "edge-1", "device_ip": "192.0.2.1"}
    fleet.upsert(original)
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, authority_path=str(authority))
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    policy = _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    first_stamp = fleet.get_device("edge-1")["registered_at"]
    first_registration_id = fleet.get_device("edge-1")["registration_id"]
    fleet.delete("edge-1")
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.99"})
    replacement = fleet.get_device("edge-1")
    assert replacement["registered_at"] == first_stamp
    assert replacement["registration_id"] != first_registration_id
    clock.now += 1
    runner.run_once()
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "skipped" and receipt["reason"] == "conflict"
    assert receipt["fleet_registration_id"] == first_registration_id
    assert images.get_policy("edge-1")["approved_image_ids"] == []


def test_terminal_assignment_without_prepared_claim_needs_no_authority_db(
        tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    images = catalog.CatalogStore(str(tmp_path))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, authority_path=str(authority))
    store = _make_schedule(
        tmp_path, _definition(device_ids=["gone"]), ["gone"])
    clock, policy = _Clock(), _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    _run_schedule(store, executor, policy, clock, ["gone"])
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(occurrence["id"], "gone")
    assert receipt["status"] == "skipped" and receipt["reason"] == "vanished"
    assert schedules.OccurrenceStore(tmp_path).get(
        occurrence["id"])["state"] == "completed"
    assert not authority.exists()


def test_prepared_assignment_closes_without_admitting_catalog_write(tmp_path):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, str(tmp_path / "audit.jsonl"),
        authority_path=str(authority))
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    policy = _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    clock.now = NOW + 300
    runner.run_once()
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "window_closed"
    assert images.get_policy("edge-1")["approved_image_ids"] == []
    assert not (tmp_path / "audit.jsonl").exists()


def test_assignment_crash_replays_durable_result_and_frozen_quarantine_note(
        tmp_path):
    class SimulatedCrash(BaseException):
        pass

    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    authority = tmp_path / "assignment-authority.sqlite3"
    writer = assignment_service.AssignmentService(
        images, fleet, str(tmp_path / "audit.jsonl"),
        authority_path=str(authority))
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    policy = _Policy(["edge-1"])
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    original_record = runner.receipts.record

    def crash_before_terminal_receipt(*args, **kwargs):
        if kwargs.get("status") in schedules.TERMINAL_RECEIPT_STATES:
            raise SimulatedCrash()
        return original_record(*args, **kwargs)

    runner.receipts.record = crash_before_terminal_receipt
    clock.now += 1
    with pytest.raises(SimulatedCrash):
        runner.run_once()
    assert images.get_policy("edge-1")["approved_image_ids"] == ["image-a"]
    with sqlite3.connect(authority) as connection:
        request = json.loads(connection.execute(
            "SELECT request_json FROM claims").fetchone()[0])
    assert request["fleet_registration_id"] == fleet.get_device(
        "edge-1")["registration_id"]
    policy.document["quarantined_devices"] = {}
    clock.now = NOW + 300
    restarted_executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=writer,
        clock=clock)
    restarted = schedule_runner.ScheduleRunner(
        store, lambda _row: {"revision": 2, "now": clock.now,
                            "device_ids": ["edge-1"]},
        executor=restarted_executor, role_guard=_role_guard(policy),
        now_fn=clock)
    restarted.run_once()
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt = schedules.ReceiptStore(tmp_path).get(
        occurrence["id"], "edge-1")
    assert receipt["status"] == "ok" and receipt["reason"] == "assigned"
    assert receipt["notes"] == ["peer_quarantined"]
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 1
    with sqlite3.connect(authority) as connection:
        assert connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0


def test_queued_onboard_authority_refuses_plan_drift_but_not_role_drift(
        tmp_path):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert(_routed_device(role="boat"))
    policy = _Policy()
    onboard, records, submission = _onboard_components(tmp_path, fleet, clock)
    definition = _definition("onboard", ["edge-1"])
    definition["target"]["filters"] = {"role": "boat"}
    store = _make_schedule(tmp_path, definition, ["edge-1"])
    occurrence = _claim(store, ["edge-1"])
    prior = schedules.ReceiptStore(tmp_path).begin(
        occurrence["id"], "edge-1", now=NOW)
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    plan = submission._plan("edge-1", fleet.get_device("edge-1"))
    callbacks = executor._onboard_callbacks(
        occurrence["schedule"], occurrence, "edge-1", prior,
        executor._provenance(occurrence["schedule"], occurrence, "edge-1"),
        plan, None, fleet.get_device("edge-1")["registered_at"])
    authority_guard, authority_check = callbacks[:2]
    try:
        fleet.upsert({"device_id": "edge-1", "role": "fiber"})
        with authority_guard("execution"):
            authority_check("execution")
        fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.99"})
        with pytest.raises(gui_onboard.ScheduledAdmissionError,
                           match="conflict"):
            with authority_guard("execution"):
                authority_check("execution")
    finally:
        onboard.shutdown()


def test_queued_onboard_refuses_same_second_replacement_and_identifies_legacy(
        tmp_path, monkeypatch):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert(_routed_device())
    fleet._devices.update("edge-1", lambda row: {
        key: value for key, value in row.items()
        if key != "registration_id"})
    assert "registration_id" not in fleet.get_device("edge-1")
    policy = _Policy()
    onboard, records, submission = _onboard_components(tmp_path, fleet, clock)
    ran = []
    onboard._run = lambda *_args: ran.append(True) or 0
    monkeypatch.setattr(onboard, "_ensure_workers", lambda: None)
    monkeypatch.setattr(onboard, "_ensure_maintenance", lambda: None)
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    occurrence = _claim(store, ["edge-1"])
    prior = schedules.ReceiptStore(tmp_path).begin(
        occurrence["id"], "edge-1", now=NOW)
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    try:
        prepared = executor._dispatch_onboard(
            occurrence["schedule"], occurrence, "edge-1", prior)
        assert prepared["status"] == "prepared"
        assert not onboard.list_jobs()
        prior = schedules.ReceiptStore(tmp_path).record(
            occurrence["id"], "edge-1", status="intent",
            reason=prepared["reason"], now=NOW,
            expected_rev=prior["rev"],
            fleet_registered_at=prepared["fleet_registered_at"],
            fleet_registration_id=prepared["fleet_registration_id"])
        result = executor._dispatch_onboard(
            occurrence["schedule"], occurrence, "edge-1", prior)
        assert result["status"] == "submitted"
        original = fleet.get_device("edge-1")
        assert len(original["registration_id"]) == 32
        record = records.get(result["record_id"], strict=True)
        assert record["fleet_registration_id"] == original[
            "registration_id"]
        assert result["fleet_registration_id"] == original[
            "registration_id"]

        fleet.delete("edge-1")
        fleet.upsert(_routed_device())
        replacement = fleet.get_device("edge-1")
        assert replacement["registered_at"] == original["registered_at"]
        assert replacement["registration_id"] != original[
            "registration_id"]

        onboard._work_queue.get_nowait()()
        job = onboard.get_job(result["job_id"])
        assert job["state"] == "cancelled"
        assert job["admission_reason"] == "conflict"
        assert ran == []
    finally:
        onboard.shutdown()


def test_legacy_interrupted_onboard_uses_registered_at_for_replacement(
        tmp_path):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert(_routed_device())
    original = fleet.get_device("edge-1")
    policy = _Policy()
    onboard, records, submission = _onboard_components(tmp_path, fleet, clock)
    io_calls = []
    onboard._run = lambda *_args: io_calls.append("installer") or 0
    onboard._probe = lambda *_args: io_calls.append("probe") or True
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    occurrence = _claim(store, ["edge-1"])
    prior = schedules.ReceiptStore(tmp_path).begin(
        occurrence["id"], "edge-1", now=NOW)
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    provenance = executor._provenance(
        occurrence["schedule"], occurrence, "edge-1")
    plan = submission._plan("edge-1", original)
    admitted = records.admit_scheduled({
        "controller_id": "iris", "device_id": "edge-1",
        "fleet_registered_at": original["registered_at"],
        "inventory_revision": plan["inventory_revision"],
        "plan_hash": plan["plan_hash"], "resolved": plan["resolved"],
        "preflight": {"status": "pending"},
        "resources": submission._owned_resources(plan["resolved"]),
    }, provenance=provenance, attempt=prior["attempt"],
        authorize=lambda *_args: None)
    records.transition(admitted["record"]["record_id"], "applying")
    records.recover_interrupted()

    clock.now = NOW + 1
    fleet.delete("edge-1")
    fleet.upsert(_routed_device())
    replacement = fleet.get_device("edge-1")
    assert original["registered_at"] == NOW
    assert replacement["registered_at"] == NOW + 1
    try:
        result = executor._dispatch_onboard(
            occurrence["schedule"], occurrence, "edge-1", prior)
        assert result == {"status": "skipped", "reason": "conflict"}
        assert records.get(admitted["record"]["record_id"], strict=True)[
            "state"] == "unknown"
        assert not onboard.list_jobs()
        assert io_calls == []
    finally:
        onboard.shutdown()


def test_iox_restart_after_submitted_receipt_crash_refuses_replacement(
        tmp_path, monkeypatch):
    class SimulatedCrash(BaseException):
        pass

    class Controller:
        def __init__(self):
            self.calls = 0

        def run_install(self, *_args):
            self.calls += 1
            raise AssertionError("replacement reached the IOx controller")

    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    device = _routed_device()
    device.update({"platform": "iox", "model": "IE-3400"})
    fleet.upsert(device)
    original = fleet.get_device("edge-1")
    policy = _Policy()
    onboard, records, submission = _onboard_components(
        tmp_path, fleet, clock, platform="iox")
    controller = Controller()
    onboard._iox_controller = controller
    installer_calls = []
    onboard._run = lambda *_args: installer_calls.append(True) or 0
    monkeypatch.setattr(onboard, "_ensure_workers", lambda: None)
    monkeypatch.setattr(onboard, "_ensure_maintenance", lambda: None)
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    runner = _run_schedule(store, executor, policy, clock, ["edge-1"])
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    receipt_store = schedules.ReceiptStore(tmp_path)
    prepared = receipt_store.get(occurrence["id"], "edge-1")
    assert prepared["status"] == "intent"
    assert prepared["reason"] == "onboard_prepared"
    assert prepared["fleet_registration_id"] == original["registration_id"]
    assert not onboard.list_jobs()

    original_record = runner.receipts.record

    def crash_before_submitted_receipt(*args, **kwargs):
        if kwargs.get("status") == "submitted":
            raise SimulatedCrash()
        return original_record(*args, **kwargs)

    runner.receipts.record = crash_before_submitted_receipt
    clock.now += 1
    with pytest.raises(SimulatedCrash):
        runner.run_once()
    assert [job["state"] for job in onboard.list_jobs()] == ["queued"]
    assert receipt_store.get(occurrence["id"], "edge-1") == prepared
    onboard.shutdown()

    clock.now += 1
    fleet.delete("edge-1")
    fleet.upsert(device)
    replacement = fleet.get_device("edge-1")
    assert replacement["registration_id"] != original["registration_id"]
    restarted_onboard, restarted_records, restarted_submission = \
        _onboard_components(tmp_path, fleet, clock, platform="iox")
    restarted_onboard._iox_controller = controller
    restarted_onboard._run = lambda *_args: installer_calls.append(True) or 0
    restarted_executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=restarted_submission, onboard=restarted_onboard,
        records=restarted_records, clock=clock)
    restarted = schedule_runner.ScheduleRunner(
        store, lambda _row: {
            "revision": 2, "now": clock.now, "device_ids": ["edge-1"]},
        executor=restarted_executor, role_guard=_role_guard(policy),
        now_fn=clock, poll_interval=.01)
    try:
        restarted.run_once()
        receipt = receipt_store.get(occurrence["id"], "edge-1")
        assert receipt["status"] == "skipped"
        assert receipt["reason"] == "conflict"
        assert receipt["fleet_registration_id"] == original[
            "registration_id"]
        assert not restarted_onboard.list_jobs()
        assert controller.calls == 0
        assert installer_calls == []
    finally:
        restarted_onboard.shutdown()


@pytest.mark.parametrize("mutation", ("plan", "registration"))
def test_interrupted_applying_onboard_never_retargets_from_fresh_plan(
        tmp_path, mutation):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    fleet.upsert(_routed_device())
    policy = _Policy()
    onboard, records, submission = _onboard_components(tmp_path, fleet, clock)
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    occurrence = _claim(store, ["edge-1"])
    prior = schedules.ReceiptStore(tmp_path).begin(
        occurrence["id"], "edge-1", now=NOW)
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    provenance = executor._provenance(
        occurrence["schedule"], occurrence, "edge-1")
    plan = submission._plan("edge-1", fleet.get_device("edge-1"))
    candidate = {
        "controller_id": "iris", "device_id": "edge-1",
        "fleet_registered_at": fleet.get_device("edge-1")["registered_at"],
        "fleet_registration_id": fleet.get_device(
            "edge-1")["registration_id"],
        "inventory_revision": plan["inventory_revision"],
        "plan_hash": plan["plan_hash"], "resolved": plan["resolved"],
        "preflight": {"status": "pending"},
        "resources": submission._owned_resources(plan["resolved"])}
    admitted = records.admit_scheduled(
        candidate, provenance=provenance, attempt=prior["attempt"],
        authorize=lambda *_args: None)
    records.transition(admitted["record"]["record_id"], "applying")
    records.recover_interrupted()
    if mutation == "plan":
        fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.99"})
    else:
        original = fleet.get_device("edge-1")
        fleet.delete("edge-1")
        fleet.upsert(_routed_device())
        replacement = fleet.get_device("edge-1")
        assert replacement["registered_at"] == original["registered_at"]
        assert replacement["registration_id"] != original["registration_id"]
    try:
        result = executor._dispatch_onboard(
            occurrence["schedule"], occurrence, "edge-1", prior)
        assert result == {"status": "skipped", "reason": "conflict"}
        assert records.get(
            admitted["record"]["record_id"], strict=True)["state"] == "unknown"
        assert not onboard.list_jobs()
    finally:
        onboard.shutdown()


@pytest.mark.parametrize("platform", ("guestshell", "xr-appmgr"))
def test_interrupted_applying_collision_keeps_occurrence_teardown_authority(
        tmp_path, monkeypatch, platform):
    clock = _Clock()
    fleet = gui_fleet.FleetStore(str(tmp_path), now_fn=clock)
    if platform == "guestshell":
        fleet.upsert(_routed_device())
    else:
        fleet.upsert({
            "device_id": "edge-1", "device_ip": "192.0.2.1",
            "model": "8010",
            "platform": "xr-appmgr", "management_type": "xr-host",
            "credential_profile_id": "lab",
        })
        fleet.update_observation("edge-1", os_family="xr")
    policy = _Policy()
    onboard, records, submission = _onboard_components(
        tmp_path, fleet, clock, platform=platform)
    store = _make_schedule(
        tmp_path, _definition("onboard", ["edge-1"]), ["edge-1"])
    occurrence = _claim(store, ["edge-1"])
    prior = schedules.ReceiptStore(tmp_path).begin(
        occurrence["id"], "edge-1", now=NOW)
    executor = _base_executor(
        tmp_path, store=store, fleet=fleet, policy=policy, writer=None,
        submission=submission, onboard=onboard, records=records, clock=clock)
    provenance = executor._provenance(
        occurrence["schedule"], occurrence, "edge-1")
    plan = submission._plan("edge-1", fleet.get_device("edge-1"))
    initial_evidence = (
        {"status": "passed", "device_identity": "FOC0000TEST",
         "detected_model": "C9300"}
        if platform == "guestshell" else
        {"status": "passed", "detected_model": "8010"})
    admitted_plan = submission._apply_preflight(plan, initial_evidence)
    candidate = {
        "controller_id": "iris", "device_id": "edge-1",
        "fleet_registered_at": fleet.get_device("edge-1")["registered_at"],
        "inventory_revision": admitted_plan["inventory_revision"],
        "plan_hash": admitted_plan["plan_hash"],
        "resolved": admitted_plan["resolved"],
        "preflight": initial_evidence,
        "resources": submission._owned_resources(admitted_plan["resolved"]),
    }
    admitted = records.admit_scheduled(
        candidate, provenance=provenance, attempt=prior["attempt"],
        authorize=lambda *_args: None)
    record_id = admitted["record"]["record_id"]
    records.transition(record_id, "applying")
    records.recover_interrupted()

    def probe(_argv, input=None, **_kwargs):
        if platform == "guestshell":
            sections = (
                ("VERSION", "Cisco IOS XE Software\n"
                 "cisco C9300 (X86) processor\n"
                 "Processor board ID FOC0000TEST\n"),
                ("RUNNING", "app-hosting appid guestshell\n"),
                ("APPS", "guestshell RUNNING\n"),
                ("FILES", "Directory of bootflash:/guest-share/\niris/\n"),
            )
        else:
            sections = (
                ("VERSION", "Cisco IOS XR Software, Version 25.4.2 LNT\n"
                 "cisco 8010 (VXR) processor\n"),
                ("APPS", "iris docker iris-xr Up app_manager\n"),
                ("SOURCES", "iris-xr 0.1.0 ThinXR app_manager\n"),
            )
        return SimpleNamespace(returncode=0, stdout="\n".join(
            "__IRIS_PREFLIGHT_%s__\n%s" % section for section in sections))

    monkeypatch.setattr(gui_onboard.subprocess, "run", probe)
    if platform == "guestshell":
        onboard._guestshell_preflight = lambda dev, env, resolved: (
            gui_onboard._default_guestshell_preflight(
                dev, env, resolved, onboard.repo_root))
    else:
        onboard._xr_preflight = lambda dev, env, resolved: (
            gui_onboard._default_xr_preflight(
                dev, env, resolved, onboard.repo_root))
    try:
        result = executor._dispatch_onboard(
            occurrence["schedule"], occurrence, "edge-1", prior)
        assert result["status"] in ("submitted", "running", "error")
        job = onboard.get_job(result["job_id"])
        if job["state"] not in ("done", "error", "cancelled"):
            deadline = time.time() + 3
            while time.time() < deadline:
                job = onboard.get_job(result["job_id"])
                if job["state"] in ("done", "error", "cancelled"):
                    break
                time.sleep(.01)
        assert job["state"] == "error"
        record = records.get(record_id, strict=True)
        assert record["state"] == "unknown"
        assert record["recovery"]["interrupted_from"] == "applying"
        assert records.recoverable_for_device("edge-1")["record_id"] == \
            record_id
    finally:
        onboard.shutdown()


def test_onboard_growth_and_iox_artifact_are_checked_at_both_boundaries(
        tmp_path):
    devices = {
        "iox-1": {"device_id": "iox-1", "model": "IE-3400",
                  "management_type": "inband"}}

    class Fleet:
        path = str(tmp_path / "fleet.json")

        def get_device(self, device_id):
            return devices.get(device_id)

    class Submission:
        @staticmethod
        def _plan(device_id, device):
            return {"resolved": {"platform": "iox", "model": device["model"]}}

    onboard = SimpleNamespace(max_concurrent=2, artifacts_dir=str(tmp_path))
    store = _make_schedule(
        tmp_path, _definition("onboard", ["iox-1"], max_devices=2),
        ["iox-1"])
    policy = _Policy()
    executor = _base_executor(
        tmp_path, store=store, fleet=Fleet(), policy=policy, writer=None,
        submission=Submission(), onboard=onboard, clock=_Clock())
    definition = _definition("onboard", ["iox-1"], max_devices=2)
    snapshot = {"revision": 1, "now": NOW, "device_ids": ["iox-1"],
                "quarantined_ids": []}
    with pytest.raises(schedules.ScheduleValidationError,
                       match="iox_package_missing"):
        executor.validate(definition, snapshot, "creation")
    (tmp_path / "iris-arm64.tar").write_bytes(b"package")
    assert executor.validate(definition, snapshot, "creation") is None

    row = store.get("nightly")
    grown = dict(snapshot, device_ids=["iox-1", "new"])
    assert executor.validate(row, grown, "window_start")["reason"] == \
        "target_growth_exceeded"
    zero = dict(row, preview={"revision": 1, "now": NOW,
                             "device_ids": []})
    assert executor.validate(zero, snapshot, "window_start")["reason"] == \
        "target_growth_exceeded"


def test_terminal_acknowledgement_retries_after_receipt_save(tmp_path):
    store = _make_schedule(
        tmp_path, _definition(device_ids=["edge-1"]), ["edge-1"])
    policy, clock = _Policy(), _Clock()

    class Executor:
        def __init__(self):
            self.acks = 0

        def validate(self, *_args):
            return None

        def dispatch(self, *_args):
            return {"status": "ok", "reason": "assigned"}

        def acknowledge(self, _receipt):
            self.acks += 1
            if self.acks == 1:
                raise OSError("crash after receipt save")

        def cancel_queued(self, *_args):
            return None

    executor = Executor()
    runner = schedule_runner.ScheduleRunner(
        store, lambda _row: {"revision": 1, "now": NOW,
                            "device_ids": ["edge-1"]},
        executor=executor, role_guard=_role_guard(policy), now_fn=clock)
    runner.run_once()
    assert executor.acks == 1
    occurrence = schedules.OccurrenceStore(tmp_path).list()[0]
    assert occurrence["state"] == "running"
    runner.run_once()
    assert executor.acks == 2
    assert schedules.OccurrenceStore(tmp_path).get(
        occurrence["id"])["state"] == "completed"


# ---- Task 24: wave counts ------------------------------------------------
# The counts answer one question about a PRECEDING occurrence: how much of it
# actually landed. They are read from evidence that is allowed to be absent,
# so every classification below has to say what it does when the evidence is
# simply not there.

_WAVE_SLOT = {"scheduled_at": NOW, "window_end": NOW + 300, "status": "due",
              "resolution": "normal", "tz": "UTC",
              "local_time": "2026-09-08 00:00", "next_at": None}


def _preceding(tmp_path, *, ids, kind="assign", image_ids=("image-a",),
               outcomes=None):
    """Create a real preceding occurrence with its per-device evidence."""
    store = schedules.ScheduleStore(tmp_path)
    definition = _definition(kind=kind, device_ids=list(ids),
                             **({"image_ids": list(image_ids)}
                                if kind == "assign" else {}))
    row = store.create("first", definition, actor="console:test", now=NOW - 1,
                       preview={"revision": 1, "now": NOW - 1,
                                "device_ids": list(ids)})
    occurrences = schedules.OccurrenceStore(tmp_path)
    occurrence = occurrences.create(
        row, dict(_WAVE_SLOT),
        {"revision": 1, "now": NOW, "device_ids": list(ids)}, now=NOW)
    evidence = schedules.ReceiptStore(tmp_path)
    for device_id, (status, reason) in (outcomes or {}).items():
        evidence.record(occurrence["id"], device_id, status=status,
                        reason=reason, now=NOW)
    return store, occurrence


def _gated(tmp_path, store, *, ids, **overrides):
    after = {"schedule_id": "first", "condition": "min_staged_ratio",
             "min_staged_ratio": .9, "max_errored_ratio": .1,
             "max_missing_ratio": .05, "deadline_seconds": 60}
    after.update(overrides)
    definition = dict(_definition(device_ids=list(ids)), after=after)
    return store.create("second", definition, actor="console:test",
                        now=NOW - 1,
                        preview={"revision": 1, "now": NOW - 1,
                                 "device_ids": list(ids)})


def _wave_executor(tmp_path, store, images, fleet, *, heartbeats,
                   swarm=None, clock=None):
    return management_api._ScheduledExecutor(
        schedule_store=store,
        occurrence_store=schedules.OccurrenceStore(tmp_path),
        receipt_store=schedules.ReceiptStore(tmp_path),
        role_guard=_role_guard(_Policy()),
        role_policy_snapshot=_Policy,
        fleet=fleet, secrets_path=str(tmp_path / "secrets.json"),
        assignment_writer=None, submission=None, onboard=None,
        record_store=None, now_fn=clock or _Clock(), catalog=images,
        heartbeat_fn=lambda: heartbeats,
        swarm_fn=(lambda: swarm) if swarm is not None else None)


def _wave_fixture(tmp_path, *, heartbeats, ids=("edge-1", "edge-2"),
                  kind="assign", outcomes=None, swarm=None, **overrides):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    for device_id in ids:
        fleet.upsert({"device_id": device_id, "device_ip": "192.0.2.1"})
    store, occurrence = _preceding(tmp_path, ids=ids, kind=kind,
                                   outcomes=outcomes)
    gated = _gated(tmp_path, store, ids=ids, **overrides)
    executor = _wave_executor(tmp_path, store, images, fleet,
                              heartbeats=heartbeats, swarm=swarm)
    return executor, gated, occurrence


def _staged(device_id, image_ids=("image-a",), **extra):
    row = {"device_id": device_id, "last_seen": NOW,
           "staged_image_ids": list(image_ids), "errored_image_ids": [],
           "stage_state": "ready"}
    row.update(extra)
    return row


def _gate_occurrence(executor, gated):
    occurrences = executor.occurrences
    return occurrences.create(
        gated, dict(_WAVE_SLOT, scheduled_at=NOW + 1,
                    window_end=NOW + 301),
        {"revision": 1, "now": NOW + 1,
         "device_ids": gated["preview"]["device_ids"]}, now=NOW + 1)


def test_wave_counts_read_staging_without_demanding_corroboration(tmp_path):
    executor, gated, preceding = _wave_fixture(
        tmp_path, heartbeats=[_staged("edge-1"),
                              dict(_staged("edge-2"), staged_image_ids=[],
                                   stage_state="downloading")])
    occurrence = _gate_occurrence(executor, gated)

    # No tracker row for either device: the registry is in-memory and empty
    # for one prune horizon after a restart, so silence there says nothing.
    assert executor.wave_counts(gated, occurrence) == {
        "schedule_id": "first", "occurrence_id": preceding["id"],
        "total": 2, "staged": 1, "errored": 0, "missing": 0}


def test_wave_counts_let_the_tracker_contradict_a_staged_claim(tmp_path):
    swarm = {"images": [{"info_hash": "ef" * 20, "peers": [
        {"device_id": "edge-1",
         "tracker": {"left": 4096, "principal_type": "device"}}]}]}
    executor, gated, preceding = _wave_fixture(
        tmp_path, heartbeats=[_staged("edge-1"), _staged("edge-2")],
        swarm=swarm)
    occurrence = _gate_occurrence(executor, gated)
    result = executor.wave_counts(gated, occurrence)
    assert (result["staged"], result["errored"], result["missing"]) == \
        (1, 0, 0)

    swarm["images"][0]["peers"][0]["tracker"]["left"] = 0
    assert executor.wave_counts(gated, occurrence)["staged"] == 2


def test_wave_counts_separate_a_dark_device_from_a_failed_one(tmp_path):
    executor, gated, preceding = _wave_fixture(
        tmp_path, ids=("edge-1", "edge-2", "edge-3", "edge-4"),
        outcomes={"edge-4": ("skipped", "vanished")},
        heartbeats=[
            dict(_staged("edge-1"), staged_image_ids=[],
                 errored_image_ids=["image-a"], stage_state="error"),
            dict(_staged("edge-2"), last_seen=NOW - 601,
                 staged_image_ids=[], stage_state="downloading"),
            dict(_staged("edge-3"), staged_image_ids=[],
                 stage_state="downloading"),
            _staged("edge-4")])
    occurrence = _gate_occurrence(executor, gated)
    result = executor.wave_counts(gated, occurrence)
    # edge-3 is still downloading: neither staged, failed, nor dark.
    assert (result["total"], result["staged"], result["errored"],
            result["missing"]) == (4, 1, 1, 1)


def test_wave_counts_treat_an_unheard_device_as_missing(tmp_path):
    executor, gated, preceding = _wave_fixture(
        tmp_path, heartbeats=[_staged("edge-1")])
    occurrence = _gate_occurrence(executor, gated)
    result = executor.wave_counts(gated, occurrence)
    assert (result["staged"], result["missing"]) == (1, 1)


def test_wave_counts_use_the_onboarding_outcome_for_an_onboard_wave(tmp_path):
    executor, gated, preceding = _wave_fixture(
        tmp_path, kind="onboard",
        outcomes={"edge-1": ("ok", "onboarded"), "edge-2": ("error", "failed")},
        heartbeats=[_staged("edge-1"), _staged("edge-2")])
    occurrence = _gate_occurrence(executor, gated)
    result = executor.wave_counts(gated, occurrence)
    assert (result["staged"], result["errored"]) == (1, 1)


def test_wave_counts_report_no_preceding_occurrence_rather_than_zero(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    images = catalog.CatalogStore(str(tmp_path))
    store = schedules.ScheduleStore(tmp_path)
    gated = _gated(tmp_path, store, ids=["edge-1"])
    executor = _wave_executor(tmp_path, store, images, fleet, heartbeats=[])
    occurrence = _gate_occurrence(executor, gated)
    assert executor.wave_counts(gated, occurrence) == {
        "schedule_id": "first", "occurrence_id": None, "total": 0,
        "staged": 0, "errored": 0, "missing": 0}


def test_wave_counts_refuse_rather_than_guess_without_heartbeats(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    images = catalog.CatalogStore(str(tmp_path))
    images.save_image(_image("image-a"))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    store, _ = _preceding(tmp_path, ids=["edge-1"])
    gated = _gated(tmp_path, store, ids=["edge-1"])
    executor = _wave_executor(tmp_path, store, images, fleet, heartbeats=None)
    occurrence = _gate_occurrence(executor, gated)
    with pytest.raises(schedule_runner.ExecutionRefused) as raised:
        executor.wave_counts(gated, occurrence)
    assert raised.value.reason == "staging_evidence_unavailable"
