# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run console and API status derivations against the same device records."""
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

import catalog
import gui_app
import gui_fleet
import management_api


APP = Path(__file__).resolve().parents[1] / "webroot" / "app.js"
PLATFORMS = ("guestshell", "iox", "router", "xr-appmgr")


@pytest.fixture
def handler_factory(monkeypatch, tmp_path):
    # Exercise the real handler closure and stores without opening a socket.
    monkeypatch.setattr(management_api, "_ConsoleServer", lambda address, handler:
                        SimpleNamespace(RequestHandlerClass=handler))
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))

    def make(**kwargs):
        server = management_api.make_server("127.0.0.1", 0, app,
                                             now_fn=lambda: 1000, **kwargs)
        return object.__new__(server.RequestHandlerClass)

    return make


def javascript_status(rows):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for console status behavior tests")
    source = APP.read_text()
    start = source.index("  function rowAssignedIds(d)")
    end = source.index("  // ---- Status pill grammar", start)
    drawer_start = source.index("  function deployImageRows(d)")
    drawer_end = source.index("\n  function ", drawer_start + 1)
    script = (source[start:end] + source[drawer_start:drawer_end]
              + "\nconst esc = value => String(value);"
              + "\nconst imageLabel = value => String(value);"
              + "\nconst rows = " + json.dumps(rows) + ";"
              + "\nprocess.stdout.write(JSON.stringify(rows.map(d => ({"
              + "key: deviceStatus(d, 1000).key, drawer: deployImageRows(d)}))));")
    result = subprocess.run([node], input=script, text=True, capture_output=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_console_and_api_status_agree_for_every_runtime(handler_factory):
    scenarios = [
        ({}, "not-enrolled", None),
        ({"last_seen": 990}, "unassigned", None),
        ({"last_seen": 990, "stage_state": "ready", "current_image_id": "old"},
         "unassigned", None),
        ({"last_seen": 990, "stage_state": "ready", "current_image_id": "old",
          "assigned_image_ids": ["new"], "staged_image_ids": ["old"],
          "errored_image_ids": []}, "waiting-staging", "pending"),
        ({"last_seen": 990, "stage_state": "unassigned",
          "assigned_image_ids": ["new"]}, "waiting-staging", "pending"),
        ({"last_seen": 990, "stage_state": "ready", "current_image_id": "old",
          "assigned_image_ids": ["new"]}, "waiting-staging", "pending"),
        ({"last_seen": 990, "stage_state": "staging", "current_image_id": "old",
          "assigned_image_ids": ["new"]}, "staging", "pending"),
        ({"assigned_image_ids": ["new"]}, "not-enrolled", "pending"),
        ({"last_seen": 990, "stage_state": "error", "current_image_id": "a",
          "assigned_image_ids": ["a"]}, "placement-failed", "error"),
        ({"last_seen": 990, "stage_state": "copy_failed", "current_image_id": "a",
          "assigned_image_ids": ["a"]}, "placement-failed", "copy_failed"),
        ({"last_seen": 990, "stage_state": "ready", "current_image_id": "a",
          "assigned_image_ids": ["a"]}, "deployed", "ready"),
        ({"last_seen": 990, "stage_state": "staging", "current_image_id": "a",
          "assigned_image_ids": ["a"]}, "staging", "staging"),
        ({"last_seen": 990, "stage_state": "error", "current_image_id": "a",
          "assigned_image_ids": ["a"], "staged_image_ids": ["a"],
          "errored_image_ids": ["a"]}, "image-failed", "error"),
    ]
    rows = [dict(fields, platform=platform, device_id=platform + str(i))
            for platform in PLATFORMS for i, (fields, _, _) in enumerate(scenarios)]
    rendered = javascript_status(rows)
    handler = handler_factory()
    for row, actual, (_, expected, image_state) in zip(
            rows, rendered, scenarios * len(PLATFORMS)):
        assert handler._device_status_key(row) == expected, row
        assert actual["key"] == expected, row
        if image_state:
            assert "<td>" + image_state + "</td>" in actual["drawer"], row


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("image_ids", [("a",), ("a", "b")])
def test_second_device_starting_does_not_restage_completed_device(
        tmp_path, handler_factory, platform, image_ids):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    cat = catalog.CatalogStore(str(tmp_path))
    for image_id in image_ids:
        cat.save_image({"id": image_id, "filename": image_id + ".bin"})
    for did in ("first", "second"):
        fleet.upsert({"device_id": did, "device_ip": "10.0.0.1", "platform": platform})
        cat.set_policy(did, approved_image_ids=list(image_ids))
    complete = {"stage_state": "ready", "current_image_id": "a"}
    active = {"stage_state": "staging", "current_image_id": "a"}
    if len(image_ids) > 1:
        complete.update(staged_image_ids=list(image_ids), errored_image_ids=[])
        active.update(staged_image_ids=[], errored_image_ids=[])
    cat.record_heartbeat("first", complete, now=990)
    handler = handler_factory(fleet=fleet, catalog=cat)
    before = handler._device_view()[0]
    assert handler._overview()["staged"] == 1
    assert handler._overview()["staging_now"] == 0
    cat.record_heartbeat("second", active, now=991)
    rows = {row["device_id"]: row for row in handler._device_view()}
    assert rows["first"] == before
    assert handler._device_status_key(rows["first"]) == "deployed"
    assert handler._device_status_key(rows["second"]) == "staging"
    assert handler._overview()["staged"] == 1
    assert handler._overview()["staging_now"] == 1
    assert [item["key"] for item in javascript_status(list(rows.values()))] == ["deployed", "staging"]


def test_rollout_rejects_retained_staged_membership_with_current_error(
        tmp_path, handler_factory):
    cat = catalog.CatalogStore(str(tmp_path))
    cat.save_image({"id": "a", "filename": "a.bin"})
    handler = handler_factory(catalog=cat)
    handler._device_view = lambda: [{
        "assigned_image_ids": ["a"], "staged_image_ids": ["a"],
        "errored_image_ids": ["a"], "stage_state": "error", "last_seen": 990,
    }]
    assert handler._overview()["rollout"] == [
        {"image_id": "a", "filename": "a.bin", "assigned": 1, "staged": 0}]


def test_overview_waits_for_activity_and_excludes_current_image_errors(handler_factory):
    handler = handler_factory()
    rows = [
        {"device_id": "pending", "last_seen": 990, "stage_state": "ready",
         "assigned_image_ids": ["old", "new"], "staged_image_ids": ["old"],
         "errored_image_ids": []},
        {"device_id": "failed", "last_seen": 990, "stage_state": "error",
         "assigned_image_ids": ["a"], "staged_image_ids": ["a"],
         "errored_image_ids": ["a"]},
    ]
    handler._device_view = lambda: rows
    overview = handler._overview()
    assert overview["assigned"] == 2
    assert overview["staged"] == 0
    assert overview["staging_now"] == 0
    assert not handler._row_has_staged(rows[1], "a")


def test_offline_and_terminal_devices_are_not_currently_staging(handler_factory):
    handler = handler_factory()
    handler._device_view = lambda: [
        {"last_seen": 390, "stage_state": "staging", "assigned_image_id": "a"},
        {"last_seen": 990, "stage_state": "copy_failed", "assigned_image_id": "a"},
        {"last_seen": 990, "stage_state": "error", "assigned_image_id": "a"},
    ]
    assert handler._overview()["staging_now"] == 0
