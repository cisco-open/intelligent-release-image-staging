# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Overview avoids unused device detail without changing staging semantics."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import catalog
import gui_app
import gui_fleet
import management_api


@pytest.fixture
def projection(tmp_path, monkeypatch):
    # Real stores and handler closure, without network or running background jobs.
    monkeypatch.setattr(management_api, "_ConsoleServer", lambda address, handler:
                        SimpleNamespace(RequestHandlerClass=handler))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    fleet = gui_fleet.FleetStore(str(tmp_path))
    cat = catalog.CatalogStore(str(tmp_path))
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    for image_id in ("a", "b", "c"):
        cat.save_image({"id": image_id, "filename": image_id + ".bin"})
    scenarios = [
        ([], None, None),
        (["a"], None, {"action": "onboard", "state": "done", "finished_at": 995}),
        (["a"], {"stage_state": "ready", "current_image_id": "a"}, None),
        (["a", "b"], {"stage_state": "staging", "staged_image_ids": ["a"], "errored_image_ids": []}, None),
        (["a", "b"], {"stage_state": "error", "staged_image_ids": ["a"], "errored_image_ids": ["b"]}, None),
        (["a", "b"], {"stage_state": "staging", "staged_image_ids": ["a", "b"], "errored_image_ids": []}, None),
        (["a"], {"stage_state": "staging", "staged_image_ids": [], "errored_image_ids": [], "last_seen": 390}, None),
        (["a"], {"stage_state": "flash_full", "staged_image_ids": [], "errored_image_ids": ["a"]}, None),
        ([], {"stage_state": "unassigned"}, None),
        (["a"], {"stage_state": "ready", "staged_image_ids": ["a"], "errored_image_ids": ["a"]}, None),
        (["a"], {"stage_state": "staging"}, None),
        (["b"], {"stage_state": "ready", "current_image_id": "b"}, {"action": "onboard", "state": "done", "finished_at": 995}),
    ]
    jobs, records = {}, []
    for platform in ("guestshell", "iox", "router", "xr-appmgr"):
        for index, (assigned, heartbeat, job) in enumerate(scenarios):
            device_id = platform + "-%02d" % index
            device = {"device_id": device_id, "device_ip": "192.0.2.1",
                      "platform": platform, "model": "C9300"}
            if index % 3 != 2:
                # The fleet's explicit OS wins over a conflicting record.
                records.append({"device_id": device_id, "state": "active",
                                "timestamps": {"planned_at": 1},
                                "resolved": {"platform": platform, "os_family": "xr"}})
            fleet.upsert(device)
            if index % 3 == 0:
                fleet.update_observation(device_id, os_family="xe")
            if assigned:
                cat.set_policy(device_id, approved_image_ids=assigned)
            if heartbeat is not None:
                # Heartbeat targeting/assignment lookalikes are not authority.
                cat.record_heartbeat(device_id, dict(
                    {"model": "NCS-540", "os_family": "xr", "assigned_image_ids": ["c"]},
                    **heartbeat), now=990)
            if job:
                jobs[device_id] = job
    # Stray reports/assignments must not invent a member of the managed fleet.
    cat.record_heartbeat("not-in-fleet", {"stage_state": "staging"}, now=990)
    cat.set_policy("not-in-fleet", approved_image_ids=["a"])
    onboard = SimpleNamespace(latest_jobs_by_device=Mock(return_value=jobs))
    record_store = SimpleNamespace(list=Mock(return_value=records))
    server = management_api.make_server("127.0.0.1", 0, app, fleet=fleet,
                                        catalog=cat, onboard=onboard,
                                        record_store=record_store,
                                        now_fn=lambda: 1000)
    handler = object.__new__(server.RequestHandlerClass)
    return handler, fleet, cat, onboard, record_store


def test_overview_light_projection_matches_detailed_rows_and_expected_totals(projection, monkeypatch):
    handler, _fleet, _cat, _onboard, _records = projection
    rows = {row["device_id"]: row for row in handler._device_view()}
    light = handler._staging_view()
    assert len(light) == len(rows) == 48
    for row in light:
        assert row == {key: rows[row["device_id"]][key] for key in row}
        assert "instruction" not in row and "install_options" not in row
    actual = handler._overview()
    assert actual == {
        "images": 3, "devices": 48, "assigned": 40, "staged": 12,
        "staging_now": 12, "awaiting_heartbeat": 8,
        "rollout": [
            {"image_id": "a", "filename": "a.bin", "assigned": 36, "staged": 16},
            {"image_id": "b", "filename": "b.bin", "assigned": 16, "staged": 8},
            {"image_id": "c", "filename": "c.bin", "assigned": 0, "staged": 0},
        ],
        "swarm_map_url": "/swarmmap",
    }
    # Compare the entire result against the former full-detail input path.
    monkeypatch.setattr(handler, "_staging_view", handler._device_view)
    assert handler._overview() == actual


def test_overview_does_not_build_or_read_unconsumed_detail(projection, monkeypatch):
    handler, fleet, cat, onboard, records = projection
    unused = Mock(side_effect=AssertionError("unused detail read"))
    records.list = unused
    monkeypatch.setattr(management_api, "trusted_target_projection", unused)
    monkeypatch.setattr(management_api, "_instruction_device_projection", unused)
    monkeypatch.setattr(management_api.role_management, "drift_report", unused)
    readers = []
    for owner, name in ((fleet, "snapshot"), (cat, "list_images"),
                        (cat, "list_devices"), (cat, "list_policies")):
        reader = Mock(wraps=getattr(owner, name))
        monkeypatch.setattr(owner, name, reader)
        readers.append(reader)
    assert handler._overview()["devices"] == 48
    assert unused.call_count == 0
    for reader in readers:
        reader.assert_called_once_with()
    onboard.latest_jobs_by_device.assert_called_once_with()
    # The detail endpoint still requires its authoritative deployment record.
    with pytest.raises(AssertionError, match="unused detail"):
        handler._device_page(limit=1)


def test_unfiltered_inventory_classifies_only_requested_rows(projection, monkeypatch):
    handler, _fleet, _cat, _onboard, _records = projection
    classify = Mock(wraps=management_api.gui_onboard.family)
    monkeypatch.setattr(management_api.gui_onboard, "family", classify)
    rows, total, _revision, facts = handler._device_page(limit=1)
    assert total == 48 and len(rows) == 1
    assert facts == {"missing_os_family": 16, "role_drift": 0}
    assert classify.call_count == 1
    # Filtering can inspect every row; it retains the same full-match facts.
    _, filtered_total, _, filtered_facts = handler._device_page(
        limit=1, filters={"model_family": "C9xxx"})
    assert filtered_total == total and filtered_facts == facts


def test_overview_observes_new_assignments_heartbeats_and_fleet_members(projection):
    handler, fleet, cat, _onboard, _records = projection
    assert handler._overview()["staged"] == 12
    cat.record_heartbeat("guestshell-03", {
        "stage_state": "ready", "staged_image_ids": ["a", "b"],
        "errored_image_ids": []}, now=999)
    assert handler._overview()["staged"] == 13
    cat.set_policy("guestshell-03", approved_image_ids=["c"])
    assert handler._overview()["staged"] == 12
    fleet.upsert({"device_id": "new", "device_ip": "192.0.2.2"})
    assert handler._overview()["devices"] == 49


@pytest.mark.parametrize("owner,name", [("fleet", "snapshot"),
                                       ("catalog", "list_images"),
                                       ("catalog", "list_devices"),
                                       ("catalog", "list_policies"),
                                       ("onboard", "latest_jobs_by_device")])
def test_overview_does_not_replace_failed_source_reads_with_zero(projection, monkeypatch, owner, name):
    handler, fleet, cat, onboard, _records = projection
    assert handler._overview()["devices"] == 48
    source = {"fleet": fleet, "catalog": cat, "onboard": onboard}[owner]
    monkeypatch.setattr(source, name,
                        Mock(side_effect=OSError("fixture read failure")))
    with pytest.raises(OSError, match="fixture read failure"):
        handler._overview()


def test_staging_projection_preserves_missing_reports_and_newest_job():
    device = {"device_id": "fixture", "onboard_action": "onboard",
              "onboard_state": "done", "onboard_finished_at": 123,
              "assigned_image_id": "not-policy-authority"}
    row = management_api._device_staging_projection(device, {}, {}, None)
    assert row["onboard_action"] == "onboard"
    assert row["onboard_state"] == "done"
    assert row["onboard_finished_at"] == 123
    assert row["assigned_image_id"] is None
    assert row["staged_image_ids"] is None
    assert row["errored_image_ids"] is None

    row = management_api._device_staging_projection(
        device, {"approved_image_ids": ["approved"]},
        {"staged_image_ids": [], "errored_image_ids": [],
         "assigned_image_ids": ["not-policy-authority"]},
        {"action": "undeploy", "state": "done", "finished_at": 456})
    assert row["assigned_image_ids"] == ["approved"]
    assert row["staged_image_ids"] == []
    assert row["errored_image_ids"] == []
    assert (row["onboard_action"], row["onboard_state"],
            row["onboard_finished_at"]) == ("undeploy", "done", 456)
