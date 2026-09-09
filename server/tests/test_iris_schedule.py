# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Direct-store schedule CLI and container packaging contracts."""
import csv
import io
import json
import os
import subprocess
import sys

import gui_fleet
import schedules


SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(SERVER_DIR, "iris-schedule")
NOW = 1_788_883_200


def _run(tmp_path, *args):
    env = dict(os.environ, IRIS_STATE=str(tmp_path), IRIS_SCHEDULE_NOW=str(NOW))
    return subprocess.run([sys.executable, CLI, *args], env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False)


def _definition():
    return {"kind": "assign", "target": {"filters": {}, "device_ids": []},
            "payload": {"image_ids": ["image-a"]},
            "when": {"kind": "once", "at": NOW + 60,
                     "window_seconds": 3600}}


def test_schedule_cli_is_executable_spdx_and_docker_installs_dependencies():
    assert os.path.isfile(CLI) and os.access(CLI, os.X_OK)
    text = open(CLI, encoding="utf-8").read()
    assert text.startswith("#!/usr/bin/env python3\n\n# Copyright 2026 Cisco")
    assert "SPDX-License-Identifier: Apache-2.0" in text
    dockerfile = open(os.path.join(SERVER_DIR, "Dockerfile"),
                      encoding="utf-8").read()
    assert " tzdata" in dockerfile
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
    assert [row["id"] for row in csv.DictReader(io.StringIO(exported.stdout))] == [
        "s-a", "s-b"]

    invalid = tmp_path / "invalid.csv"
    invalid.write_text(source.read_text(encoding="utf-8") +
                       's-b,install,{},{},{},,pending\n', encoding="utf-8")
    before = schedules.ScheduleStore(tmp_path).list()
    refused = _run(tmp_path, "import", str(invalid))
    assert refused.returncode != 0
    assert schedules.ScheduleStore(tmp_path).list() == before


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

