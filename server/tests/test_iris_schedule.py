# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Direct-store schedule CLI and container packaging contracts."""
import csv
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import subprocess
import sys

import gui_fleet
import peer_policy
import schedules


SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(SERVER_DIR, "iris-schedule")
SCHEDULE_TEMPLATE = os.path.join(
    os.path.dirname(SERVER_DIR), "fleet", "schedules.csv.example")
NOW = 1_788_883_200


def _run(tmp_path, *args):
    return _run_state(tmp_path, *args)


def _run_state(state_path, *args):
    env = dict(os.environ, IRIS_STATE=str(state_path),
               IRIS_SCHEDULE_NOW=str(NOW))
    return subprocess.run([sys.executable, CLI, *args], env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False)


def _cli_module():
    loader = importlib.machinery.SourceFileLoader("iris_schedule_cli", CLI)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _definition():
    return {"kind": "assign", "target": {"filters": {}, "device_ids": []},
            "payload": {"image_ids": ["image-a"]},
            "when": {"kind": "once", "at": NOW + 60,
                     "window_seconds": 3600}}


def _onboard_definition(max_devices):
    return {"kind": "onboard",
            "target": {"filters": {}, "device_ids": []},
            "payload": {"max_devices": max_devices},
            "when": {"kind": "once", "at": NOW + 60,
                     "window_seconds": 3600}}


def test_schedule_cli_is_executable_spdx_and_docker_installs_dependencies():
    assert os.path.isfile(CLI) and os.access(CLI, os.X_OK)
    text = open(CLI, encoding="utf-8").read()
    assert text.startswith("#!/usr/bin/env python3\n\n# Copyright 2026 Cisco")
    assert "SPDX-License-Identifier: Apache-2.0" in text
    dockerfile = open(os.path.join(SERVER_DIR, "Dockerfile"),
                      encoding="utf-8").read()
    assert re.search(r"^ARG TZDATA_VERSION=[^\s]+$", dockerfile, re.MULTILINE)
    assert '"tzdata=${TZDATA_VERSION}"' in dockerfile
    assert "/opt/iris/server/iris-schedule" in dockerfile


def test_schedule_cli_crud_cas_and_authoritative_preview(tmp_path):
    gui_fleet.FleetStore(str(tmp_path)).upsert(
        {"device_id": "edge-1", "device_ip": "192.0.2.1", "model": "C9300"})
    definition = tmp_path / "schedule.json"
    definition.write_text(json.dumps(_definition()), encoding="utf-8")
    created = _run(tmp_path, "create", "s-one", "--file", str(definition))
    assert created.returncode == 0, created.stderr
    row = json.loads(created.stdout)["schedule"]
    assert row["created_by"] == "cli:iris-schedule"
    assert row["preview"]["device_ids"] == ["edge-1"]
    assert row["etag"] == '"iris-schedule-s-one-1"'

    listed = json.loads(_run(tmp_path, "list").stdout)
    assert listed["total"] == 1 and listed["schedules"][0]["id"] == "s-one"
    assert json.loads(_run(tmp_path, "get", "s-one").stdout)["schedule"]["rev"] == 1

    patch = tmp_path / "patch.json"
    patch.write_text('{"state":"paused"}', encoding="utf-8")
    stale = _run(tmp_path, "patch", "s-one", "--file", str(patch),
                 "--if-match", '"iris-schedule-s-one-99"')
    assert stale.returncode != 0 and "precondition_failed" in stale.stderr
    changed = _run(tmp_path, "patch", "s-one", "--file", str(patch), "--force")
    assert changed.returncode == 0, changed.stderr
    assert json.loads(changed.stdout)["schedule"]["rev"] == 2
    reaffirmed = _run(tmp_path, "reaffirm", "s-one")
    assert reaffirmed.returncode == 0 and \
        json.loads(reaffirmed.stdout)["schedule"]["rev"] == 3
    deleted = _run(tmp_path, "delete", "s-one", "--if-match",
                   '"iris-schedule-s-one-3"')
    assert deleted.returncode == 0 and json.loads(deleted.stdout)["deleted"] is True


def test_schedule_cli_requires_exact_same_id_strong_etag(tmp_path):
    definition = tmp_path / "schedule.json"
    definition.write_text(json.dumps(_definition()), encoding="utf-8")
    created = _run(tmp_path, "create", "s-one", "--file", str(definition))
    assert created.returncode == 0, created.stderr
    patch = tmp_path / "patch.json"
    patch.write_text('{"state":"paused"}', encoding="utf-8")
    for bad in ('W/"iris-schedule-s-one-1"',
                '"iris-schedule-s-one-1", "other"',
                '"iris-schedule-s-other-1"', "iris-schedule-s-one-1",
                ' "iris-schedule-s-one-1"', '"iris-schedule-s-one-1" ',
                '"iris-schedule-s-one-99"', "*"):
        refused = _run(tmp_path, "patch", "s-one", "--file", str(patch),
                       "--if-match", bad)
        assert refused.returncode == 1
        assert json.loads(refused.stderr)["error"]["code"] == \
            "precondition_failed"
    assert schedules.ScheduleStore(tmp_path).get("s-one")["rev"] == 1
    exclusive = _run(tmp_path, "delete", "s-one", "--force",
                     "--if-match", '"iris-schedule-s-one-1"')
    assert exclusive.returncode == 2
    assert json.loads(exclusive.stderr)["error"]["code"] == \
        "invalid_arguments"


def test_schedule_cli_default_cas_is_numeric_and_force_is_wildcard(
        tmp_path, monkeypatch, capsys):
    module = _cli_module()
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_SCHEDULE_NOW", str(NOW))
    schedules.ScheduleStore(tmp_path).create(
        "s-one", _definition(), actor="cli:iris-schedule", now=NOW,
        preview={"revision": 0, "now": NOW, "device_ids": []})
    patch = tmp_path / "patch.json"
    patch.write_text('{"state":"paused"}', encoding="utf-8")
    expected = []
    original = module.schedules.ScheduleStore.patch

    def recording_patch(store, schedule_id, change, *, expected_rev,
                        preview=None):
        expected.append(expected_rev)
        return original(store, schedule_id, change, expected_rev=expected_rev,
                        preview=preview)

    monkeypatch.setattr(module.schedules.ScheduleStore, "patch", recording_patch)
    assert module.main(["patch", "s-one", "--file", str(patch)]) == 0
    assert module.main(["patch", "s-one", "--file", str(patch),
                        "--force"]) == 0
    capsys.readouterr()
    assert expected == [1, "*"]


def test_schedule_cli_delete_uses_role_coordinator(
        tmp_path, monkeypatch, capsys):
    module = _cli_module()
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_SCHEDULE_NOW", str(NOW))
    schedules.ScheduleStore(tmp_path).create(
        "s-one", _definition(), actor="cli:iris-schedule", now=NOW,
        preview={"revision": 0, "now": NOW, "device_ids": []})
    calls = []

    def coordinated_delete(coordinator, schedule_id, *, expected_rev):
        calls.append((schedule_id, expected_rev))
        return coordinator.schedule_store.delete(
            schedule_id, expected_rev=expected_rev)

    monkeypatch.setattr(
        module.role_management.RoleCoordinator, "delete_schedule",
        coordinated_delete, raising=False)
    assert module.main(["delete", "s-one"]) == 0
    capsys.readouterr()
    assert calls == [("s-one", 1)]
    assert schedules.ScheduleStore(tmp_path).get("s-one") is None


def test_schedule_cli_validates_create_put_patch_and_import_before_mutation(
        tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    for index in (1, 2):
        fleet.upsert({"device_id": "edge-%d" % index,
                      "device_ip": "192.0.2.%d" % index})

    invalid_path = tmp_path / "invalid-onboard.json"
    invalid_path.write_text(json.dumps(_onboard_definition(1)),
                            encoding="utf-8")
    refused = _run(
        tmp_path, "create", "s-refused", "--file", str(invalid_path))
    assert refused.returncode == 2
    assert json.loads(refused.stderr)["error"]["code"] == "invalid_schedule"
    assert "max_devices_exceeded" in refused.stderr
    assert schedules.ScheduleStore(tmp_path).get("s-refused") is None

    valid_path = tmp_path / "valid-onboard.json"
    valid_path.write_text(json.dumps(_onboard_definition(2)), encoding="utf-8")
    created = _run(
        tmp_path, "create", "s-onboard", "--file", str(valid_path))
    assert created.returncode == 0, created.stderr
    before = schedules.ScheduleStore(tmp_path).get("s-onboard")

    refused_put = _run(
        tmp_path, "put", "s-onboard", "--file", str(invalid_path))
    assert refused_put.returncode == 2
    assert "max_devices_exceeded" in refused_put.stderr
    assert schedules.ScheduleStore(tmp_path).get("s-onboard") == before

    patch_path = tmp_path / "invalid-payload.json"
    patch_path.write_text('{"payload":{"max_devices":1}}', encoding="utf-8")
    refused_patch = _run(
        tmp_path, "patch", "s-onboard", "--file", str(patch_path))
    assert refused_patch.returncode == 2
    assert "max_devices_exceeded" in refused_patch.stderr
    assert schedules.ScheduleStore(tmp_path).get("s-onboard") == before

    destination = tmp_path / "import-state"
    destination.mkdir()
    import_fleet = gui_fleet.FleetStore(str(destination))
    for index in (1, 2):
        import_fleet.upsert({"device_id": "edge-%d" % index,
                             "device_ip": "192.0.2.%d" % index})
    source = tmp_path / "validation.csv"
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=(
        "id", "kind", "target", "payload", "when", "after", "state"))
    writer.writeheader()
    for schedule_id, definition in (
            ("s-assign", _definition()),
            ("s-onboard", _onboard_definition(1))):
        normalized = schedules.normalize_definition(definition)
        writer.writerow({
            "id": schedule_id, "kind": normalized["kind"],
            "target": json.dumps(normalized["target"]),
            "payload": json.dumps(normalized["payload"]),
            "when": json.dumps(normalized["when"]), "after": "",
            "state": normalized["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    refused_import = _run_state(destination, "import", str(source))
    assert refused_import.returncode == 2
    assert "max_devices_exceeded" in refused_import.stderr
    assert schedules.ScheduleStore(destination).list() == []


def test_schedule_cli_status_target_refuses_create_and_retarget(tmp_path):
    status_definition = _definition()
    status_definition["target"] = {
        "filters": {"status": "not-enrolled"}, "device_ids": []}
    definition = tmp_path / "status.json"
    definition.write_text(json.dumps(status_definition), encoding="utf-8")
    refused = _run(tmp_path, "create", "s-status", "--file", str(definition))
    assert refused.returncode == 1
    assert json.loads(refused.stderr)["error"]["code"] == \
        "schedule_target_status_unavailable"
    assert schedules.ScheduleStore(tmp_path).list() == []

    normal = tmp_path / "normal.json"
    normal.write_text(json.dumps(_definition()), encoding="utf-8")
    assert _run(tmp_path, "create", "s-one", "--file", str(normal)).returncode == 0
    before = schedules.ScheduleStore(tmp_path).get("s-one")
    target_patch = tmp_path / "target.json"
    target_patch.write_text(json.dumps({"target": status_definition["target"]}),
                            encoding="utf-8")
    retarget = _run(tmp_path, "patch", "s-one", "--file", str(target_patch))
    assert retarget.returncode == 1
    assert json.loads(retarget.stderr)["error"]["code"] == \
        "schedule_target_status_unavailable"
    assert schedules.ScheduleStore(tmp_path).get("s-one") == before


def test_schedule_csv_prevalidation_round_trip_and_partial_report(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    source = tmp_path / "schedules.csv"
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=(
        "id", "kind", "target", "payload", "when", "after", "state"))
    writer.writeheader()
    for identifier in ("s-b", "s-a"):
        definition = schedules.normalize_definition(_definition())
        writer.writerow({"id": identifier, "kind": definition["kind"],
                         "target": json.dumps(definition["target"]),
                         "payload": json.dumps(definition["payload"]),
                         "when": json.dumps(definition["when"]), "after": "",
                         "state": definition["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    imported = _run(tmp_path, "import", str(source))
    assert imported.returncode == 0, imported.stderr
    report = json.loads(imported.stdout)
    assert [item["id"] for item in report["results"]] == ["s-a", "s-b"]
    exported = _run(tmp_path, "export")
    assert exported.returncode == 0
    exported_rows = list(csv.DictReader(io.StringIO(exported.stdout)))
    assert [row["id"] for row in exported_rows] == ["s-a", "s-b"]
    for row in exported_rows:
        for field in ("target", "payload", "when"):
            assert row[field] == json.dumps(
                json.loads(row[field]), sort_keys=True, separators=(",", ":"))

    destination = tmp_path / "round-trip-state"
    destination.mkdir()
    round_trip = tmp_path / "round-trip.csv"
    round_trip.write_text(exported.stdout, encoding="utf-8")
    restored = _run_state(destination, "import", str(round_trip))
    assert restored.returncode == 0, restored.stderr
    assert _run_state(destination, "export").stdout == exported.stdout

    invalid = tmp_path / "invalid.csv"
    invalid.write_text(source.read_text(encoding="utf-8") +
                       's-b,install,{},{},{},,pending\n', encoding="utf-8")
    before = schedules.ScheduleStore(tmp_path).list()
    refused = _run(tmp_path, "import", str(invalid))
    assert refused.returncode != 0
    assert schedules.ScheduleStore(tmp_path).list() == before


def test_schedule_csv_import_accepts_tracked_comment_preamble(tmp_path):
    peer_policy.define_role(
        str(tmp_path / "peer-policy.json"),
        str(tmp_path / "peer-policy.lkg.json"), "boat",
        {"restricted": True}, "test", NOW)
    imported = _run(tmp_path, "import", SCHEDULE_TEMPLATE)
    assert imported.returncode == 0, imported.stderr
    report = json.loads(imported.stdout)
    assert [(row["id"], row["status"]) for row in report["results"]] == [
        ("s-boat", "applied")]
    row = schedules.ScheduleStore(tmp_path).get("s-boat")
    assert row["target"]["filters"] == {"role": "boat"}
    assert row["when"]["tz"] == "Europe/Stockholm"


def test_schedule_csv_round_trips_target_above_default_field_limit(tmp_path):
    default_limit = csv.field_size_limit()
    device_ids = ["edge-%056d" % index for index in range(2100)]
    definition = _definition()
    definition["target"] = {"filters": {}, "device_ids": device_ids}
    definition = schedules.normalize_definition(definition)
    target_json = json.dumps(
        definition["target"], sort_keys=True, separators=(",", ":"))
    assert default_limit < len(target_json) <= default_limit + 4096
    schedules.ScheduleStore(tmp_path).create(
        "s-large", definition, actor="cli:iris-schedule", now=NOW,
        preview={"revision": 0, "now": NOW, "device_ids": []})

    exported = _run(tmp_path, "export")
    assert exported.returncode == 0, exported.stderr
    source = tmp_path / "large.csv"
    source.write_text(exported.stdout, encoding="utf-8")
    module = _cli_module()
    assert module._csv_rows(source)[0] == ("s-large", definition)
    assert csv.field_size_limit() == default_limit

    destination = tmp_path / "large-round-trip-state"
    destination.mkdir()
    imported = _run_state(destination, "import", str(source))
    assert imported.returncode == 0, imported.stderr
    restored = schedules.ScheduleStore(destination).get("s-large")
    assert {key: restored[key] for key in schedules.DEFINITION_KEYS
            if key in restored} == definition
    assert _run_state(destination, "export").stdout == exported.stdout


def test_schedule_csv_reimport_preserves_unchanged_early_binding(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    definition = _definition()
    definition["target"] = {"filters": {}, "device_ids": [], "bind": "early"}
    source = tmp_path / "early.csv"
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=(
        "id", "kind", "target", "payload", "when", "after", "state"))
    writer.writeheader()
    normalized = schedules.normalize_definition(definition)
    writer.writerow({"id": "s-early", "kind": normalized["kind"],
                     "target": json.dumps(normalized["target"]),
                     "payload": json.dumps(normalized["payload"]),
                     "when": json.dumps(normalized["when"]), "after": "",
                     "state": normalized["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    assert _run(tmp_path, "import", str(source)).returncode == 0
    frozen = schedules.ScheduleStore(tmp_path).get("s-early")["preview"]
    assert frozen["device_ids"] == ["edge-1"]

    fleet.upsert({"device_id": "edge-2", "device_ip": "192.0.2.2"})
    reimported = _run(tmp_path, "import", str(source))
    assert reimported.returncode == 0, reimported.stderr
    row = schedules.ScheduleStore(tmp_path).get("s-early")
    assert row["preview"] == frozen


def test_schedule_csv_prevalidates_references_and_all_target_authorities(
        tmp_path):
    source = tmp_path / "invalid-reference.csv"
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=(
        "id", "kind", "target", "payload", "when", "after", "state"))
    writer.writeheader()
    definition = schedules.normalize_definition(_definition())
    after = {"schedule_id": "missing", "condition": "min_staged_ratio",
             "min_staged_ratio": 1, "max_errored_ratio": 0,
             "max_missing_ratio": 0, "deadline_seconds": 60}
    writer.writerow({"id": "s-a", "kind": definition["kind"],
                     "target": json.dumps(definition["target"]),
                     "payload": json.dumps(definition["payload"]),
                     "when": json.dumps(definition["when"]),
                     "after": json.dumps(after), "state": definition["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    refused = _run(tmp_path, "import", str(source))
    assert refused.returncode == 2
    assert json.loads(refused.stderr)["error"]["code"] == \
        "invalid_schedule_csv"
    assert schedules.ScheduleStore(tmp_path).list() == []

    status = dict(definition)
    status["target"] = {"filters": {"status": "not-enrolled"},
                        "device_ids": [], "bind": "late"}
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=writer.fieldnames)
    writer.writeheader()
    for schedule_id, item in (("s-a", definition), ("s-z", status)):
        writer.writerow({"id": schedule_id, "kind": item["kind"],
                         "target": json.dumps(item["target"]),
                         "payload": json.dumps(item["payload"]),
                         "when": json.dumps(item["when"]), "after": "",
                         "state": item["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    unavailable = _run(tmp_path, "import", str(source))
    assert unavailable.returncode == 1
    assert json.loads(unavailable.stderr)["error"]["code"] == \
        "schedule_target_status_unavailable"
    assert schedules.ScheduleStore(tmp_path).list() == []


def test_schedule_csv_partial_report_is_ordered_and_continues(
        tmp_path, monkeypatch, capsys):
    module = _cli_module()
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_SCHEDULE_NOW", str(NOW))
    source = tmp_path / "partial.csv"
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=module.CSV_FIELDS)
    writer.writeheader()
    definition = schedules.normalize_definition(_definition())
    for schedule_id in ("s-c", "s-a", "s-b"):
        writer.writerow({"id": schedule_id, "kind": definition["kind"],
                         "target": json.dumps(definition["target"]),
                         "payload": json.dumps(definition["payload"]),
                         "when": json.dumps(definition["when"]), "after": "",
                         "state": definition["state"]})
    source.write_text(out.getvalue(), encoding="utf-8")
    original = module.schedules.ScheduleStore.create

    def conflicting_create(store, schedule_id, candidate, **kwargs):
        if schedule_id == "s-b":
            raise schedules.ScheduleConflict("concurrent create")
        return original(store, schedule_id, candidate, **kwargs)

    monkeypatch.setattr(module.schedules.ScheduleStore, "create",
                        conflicting_create)
    assert module.main(["import", str(source)]) == 1
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert [(row["id"], row["status"]) for row in report["results"]] == [
        ("s-a", "applied"), ("s-b", "conflict"), ("s-c", "applied")]
    assert (report["applied"], report["conflicts"], report["errors"]) == \
        (2, 1, 0)
    assert json.loads(output.err)["error"]["code"] == \
        "schedule_import_partial"
    assert [row["id"] for row in schedules.ScheduleStore(tmp_path).list()] == [
        "s-a", "s-c"]


def test_iris_role_import_refuses_to_remove_scheduled_role(tmp_path):
    role_cli = os.path.join(SERVER_DIR, "iris-role")
    env = dict(os.environ, IRIS_STATE=str(tmp_path))
    defined = subprocess.run([sys.executable, role_cli, "define", "boat"],
                             env=env, text=True, capture_output=True, check=False)
    assert defined.returncode == 0, defined.stderr
    schedules.ScheduleStore(tmp_path).create(
        "s-boat", {**_definition(), "target": {"filters": {"role": "boat"},
                                             "device_ids": []}},
        actor="cli:iris-schedule", now=NOW,
        preview={"revision": 0, "now": NOW, "device_ids": []})
    empty = tmp_path / "roles.csv"
    empty.write_text("role,restricted,peers,origin,nets,on_stale\n",
                     encoding="utf-8")
    result = subprocess.run(
        [sys.executable, role_cli, "import", str(empty), "--dry-run"],
        env=env, text=True, capture_output=True, check=False)
    assert result.returncode != 0
    assert "role_in_use" in result.stderr
