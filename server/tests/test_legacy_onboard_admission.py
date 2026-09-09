# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Legacy inventory must be complete before onboarding has side effects."""
from types import SimpleNamespace

import pytest

import gui_app
import gui_fleet
import gui_onboard
import management_api


LEGACY = {
    "device_id": "old", "device_ip": "192.0.2.20",
    "management_type": "legacy_routed", "vlan": "666",
    "svi_ip": "192.0.2.21", "svi_mask": "255.255.255.252",
    "guest_ip": "192.0.2.22", "model": "C9300",
}


def _forbidden(*args, **kwargs):
    pytest.fail("onboarding side effect before legacy admission")


@pytest.mark.parametrize("field,value", [
    ("device_id", "bad/id"), ("device_ip", "2001:db8::1"),
    ("vlan", "0"), ("vlan", "4095"), ("vlan", True),
    ("svi_ip", "bad"), ("svi_mask", "255.0.255.0"),
    ("guest_ip", "bad"), ("app_mask", "255.0.255.0"),
    ("app_gateway", "bad"), ("app_gateway", False), ("app_mask", False),
    ("iris_vlan", "667"), ("app_ip", "192.0.2.23"),
] + [(field, "") for field in
     ("device_ip", "vlan", "svi_ip", "svi_mask", "guest_ip")])
def test_legacy_admission_rejects_invalid_complete_fields(field, value):
    row = dict(LEGACY, **{field: value})
    with pytest.raises(ValueError, match="^unclassified_management_type$"):
        gui_onboard.validate_legacy_onboard_target(row, "old")


@pytest.mark.parametrize("entry", ["start", "build_env"])
@pytest.mark.parametrize("resolved", [False, True])
def test_legacy_admission_refuses_before_job_or_mint(monkeypatch, entry, resolved):
    bare = {"device_id": "old", "device_ip": "192.0.2.20",
            "management_type": "legacy_routed", "credential_profile_id": "lab"}
    fleet_row = dict(LEGACY, credential_profile_id="lab") if resolved else bare
    fleet = SimpleNamespace(get_device=lambda _did: fleet_row)
    creds = SimpleNamespace(get_secrets=lambda _pid: {
        "device_user": "test", "device_pass": "fixture"})
    service = gui_onboard.OnboardService(
        fleet, creds, host_ip="192.0.2.1", mint_fn=_forbidden,
        run_fn=_forbidden, probe_fn=_forbidden)
    monkeypatch.setattr(gui_onboard.secrets, "token_hex", _forbidden)
    try:
        kwargs = {"resolved": bare} if resolved else {}
        with pytest.raises(ValueError, match="^unclassified_management_type$"):
            if entry == "start":
                service.start("old", prepare=_forbidden, **kwargs)
            else:
                service._build_env("old", **kwargs)
        assert service._jobs == {}
        assert service._workers == []
    finally:
        service.shutdown()


@pytest.mark.parametrize("with_records", [False, True])
def test_legacy_admission_adapter_rejects_before_submission(tmp_path, with_records):
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    fleet.upsert({"device_id": "old", "device_ip": "192.0.2.20"})
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    onboard = SimpleNamespace(start=_forbidden)
    records = SimpleNamespace(create=_forbidden) if with_records else None
    srv = management_api.make_server(
        "127.0.0.1", 0, app, fleet=fleet, onboard=onboard,
        record_store=records, certfile=None)
    try:
        status, body = srv.onboard_submission.submit_device(
            "old", "onboard", {}, actor="console:test")
        assert (status, body) == (409, {"error": "unclassified_management_type"})
    finally:
        srv.server_close()


def test_legacy_admission_complete_csv_export_preserves_execution_inputs(tmp_path):
    original = gui_fleet.FleetStore(str(tmp_path / "original"))
    original.import_csv(
        "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model\n"
        "old,192.0.2.20,666,192.0.2.21,255.255.255.252,192.0.2.22,C9300\n")
    restored = gui_fleet.FleetStore(str(tmp_path / "restored"))
    restored.import_csv(original.export_csv())
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    calls = []
    onboard = SimpleNamespace(start=lambda did, **kw: calls.append((did, kw)) or "job")
    srv = management_api.make_server(
        "127.0.0.1", 0, app, fleet=restored, onboard=onboard, certfile=None)
    try:
        adapter = srv.onboard_submission
        for row in (original.get_device("old"), restored.get_device("old")):
            plan = adapter._plan("old", row)["resolved"]
            assert plan["management_type"] == "routed"
            assert plan["iris_vlan"] == "666"
            assert plan["app_ip"] == "192.0.2.22"
            assert plan["app_mask"] == "255.255.255.252"
            assert plan["app_gateway"] == "192.0.2.21"
        assert adapter.submit_device("old", "onboard", {}) == (200, {"job_id": "job"})
        assert len(calls) == 1
    finally:
        srv.server_close()


def test_legacy_admission_does_not_gate_recorded_teardown():
    bare = {"device_id": "old", "device_ip": "192.0.2.20",
            "management_type": "legacy_routed", "credential_profile_id": "lab"}
    fleet = SimpleNamespace(get_device=lambda _did: bare)
    creds = SimpleNamespace(get_secrets=lambda _pid: {
        "device_user": "test", "device_pass": "fixture"})
    service = gui_onboard.OnboardService(fleet, creds, host_ip="192.0.2.1",
                                         mint_fn=_forbidden)
    try:
        _, env = service._build_env("old", mint=False, resolved=bare)
        assert env["CATALOG_TOKEN"] == ""
        assert env["DEVICE_IP"] == "192.0.2.20"
    finally:
        service.shutdown()


def test_legacy_admission_queued_job_uses_admitted_resolved_snapshot(monkeypatch):
    fleet_row = dict(LEGACY, credential_profile_id="lab")
    resolved = dict(LEGACY)
    fleet = SimpleNamespace(get_device=lambda _did: fleet_row)
    creds = SimpleNamespace(get_secrets=lambda _pid: {
        "device_user": "test", "device_pass": "fixture"})
    executions = []
    service = gui_onboard.OnboardService(
        fleet, creds, host_ip="192.0.2.1", mint_fn=lambda _did: "fixture",
        run_fn=lambda _path, env, _line: executions.append(env.copy()) or 0,
        probe_fn=lambda _dev, _env: "C9300",
        guestshell_preflight_fn=lambda *_args: {
            "status": "passed", "device_identity": "FOC0000TEST"})
    monkeypatch.setattr(service, "_ensure_workers", lambda: None)
    monkeypatch.setattr(service, "_ensure_maintenance", lambda: None)
    job_id = service.start("old", resolved=resolved)
    work = service._work_queue.get_nowait()
    try:
        # A queued execution must neither follow caller mutation nor become
        # incomplete when the mutable inventory is edited after admission.
        resolved["device_ip"] = "198.51.100.99"
        resolved.pop("guest_ip")
        fleet_row.pop("svi_ip")
        work()
        assert service.get_job(job_id)["state"] == "done"
        assert len(executions) == 1
        assert executions[0]["DEVICE_IP"] == "192.0.2.20"
        assert executions[0]["APP_IP"] == "192.0.2.22"
        assert executions[0]["APP_GATEWAY"] == "192.0.2.21"
    finally:
        service._work_queue.task_done()
        service.shutdown()


@pytest.mark.parametrize("with_records", [False, True])
def test_legacy_admission_preserves_adapter_agent_teardown(tmp_path, with_records):
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    fleet.upsert({"device_id": "old", "device_ip": "192.0.2.20", "model": "C9300"})
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    calls = []
    onboard = SimpleNamespace(start=lambda did, **kw: calls.append((did, kw)) or "job")
    records = SimpleNamespace(create=_forbidden) if with_records else None
    srv = management_api.make_server(
        "127.0.0.1", 0, app, fleet=fleet, onboard=onboard,
        record_store=records, certfile=None)
    try:
        assert srv.onboard_submission.submit_device(
            "old", "undeploy", {"force": True}) == (200, {"job_id": "job"})
        assert calls[0][1]["action"] == "undeploy"
    finally:
        srv.server_close()
