# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Schedule HTTP, target-resolution, route, and role-integrity contracts."""
import contextlib
import http.client
import inspect
import json
import os
import threading

import pytest

import api_problem
import api_routes
import catalog
import gui_app
import gui_fleet
import management_api
import peer_policy
import role_management
import schedule_runner
import schedules


NOW = 1_788_883_200


class _Records:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def list(self, strict=False):
        assert strict is True
        return list(self.rows)


class _Onboard:
    def latest_jobs_by_device(self):
        return {}


def _definition(device_ids=None, role="boat"):
    filters = {} if role is None else {"role": role}
    return {
        "kind": "assign",
        "target": {"filters": filters,
                   "device_ids": list(device_ids or []), "bind": "late"},
        "payload": {"image_ids": ["image-a"], "mode": "merge"},
        "when": {"kind": "once", "at": NOW + 60,
                 "tz": "UTC", "window_seconds": 3600},
        "state": "pending",
    }


def _request(server, method, path, body=None, headers=None, raw=None):
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=5)
    request_headers = dict(headers or {})
    if raw is None and body is not None:
        raw = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    connection.request(method, path, body=raw, headers=request_headers)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


@pytest.fixture
def schedule_api(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    state = tmp_path / "state"
    state.mkdir()
    secrets_path = tmp_path / "secrets.json"
    app = gui_app.GuiApp(str(secrets_path), now_fn=lambda: NOW)
    app.set_admin("alice", "password")
    fleet = gui_fleet.FleetStore(str(state))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1",
                  "model": "C9300", "role": "boat"})
    fleet.upsert({"device_id": "edge-2", "device_ip": "192.0.2.2",
                  "model": "C9300", "role": "fiber"})
    cat = catalog.CatalogStore(str(state))
    auth_path = state / "peer-policy.json"
    lkg_path = state / "peer-policy.lkg.json"
    peer_policy.define_role(str(auth_path), str(lkg_path), "boat",
                            {"restricted": True}, "test", NOW)
    peer_policy.define_role(str(auth_path), str(lkg_path), "fiber",
                            {"restricted": True}, "test", NOW)
    schedule_wakes = []
    server = management_api.make_server(
        "127.0.0.1", 0, app, fleet=fleet, catalog=cat,
        onboard=_Onboard(), record_store=_Records(), now_fn=lambda: NOW,
        certfile=None, schedule_wake=lambda: schedule_wakes.append("wake"))
    server._test_schedule_wakes = schedule_wakes
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    login_status, login_headers, login_body = _request(
        server, "POST", "/api/login",
        {"username": "alice", "password": "password"})
    assert login_status == 200
    auth = {
        "Cookie": login_headers["Set-Cookie"].split(";", 1)[0],
        "X-CSRF-Token": json.loads(login_body)["csrf"],
    }
    try:
        yield server, app, auth
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_all_nine_schedule_operations_are_registered_for_both_tiers():
    operations = {
        ("GET", "/schedules"), ("POST", "/schedules"),
        ("GET", "/schedules/{id}"), ("PUT", "/schedules/{id}"),
        ("PATCH", "/schedules/{id}"), ("DELETE", "/schedules/{id}"),
        ("GET", "/schedules/{id}/occurrences"),
        ("GET", "/schedules/{id}/receipts"),
        ("POST", "/schedules/{id}/reaffirm"),
    }
    for method, suffix in operations:
        public = suffix.replace("{id}", "s-boat")
        assert api_routes.match("console", method, "/api/v1" + public)
        assert api_routes.match("management", method,
                                "/internal/v1" + public)
        assert api_routes.console_to_management(
            method, "/api/v1" + public) == "/internal/v1" + public


def test_schedule_crud_target_preview_creator_and_strong_cas(schedule_api):
    server, app, auth = schedule_api
    assert _request(server, "GET", "/api/schedules")[0] == 401
    assert _request(server, "POST", "/api/schedules",
                    {"id": "denied", **_definition()})[0] == 401
    no_csrf = {"Cookie": auth["Cookie"]}
    assert _request(server, "POST", "/api/schedules",
                    {"id": "denied", **_definition()}, no_csrf)[0] == 403

    created_status, created_headers, created_raw = _request(
        server, "POST", "/api/schedules",
        {"id": "s-boat", **_definition(["edge-1", "edge-2"])}, auth)
    assert created_status == 201
    assert created_headers["Location"] == "/api/schedules/s-boat"
    assert created_headers["ETag"] == '"iris-schedule-s-boat-1"'
    created = json.loads(created_raw)
    assert set(created) == {"schedule", "target_facts"}
    assert created["schedule"]["created_by"] == "console:alice"
    assert created["schedule"]["creator_exists"] is True
    assert created["schedule"]["preview"] == {
        "revision": 2, "now": NOW, "device_ids": ["edge-1"]}
    assert created["schedule"]["etag"] == created_headers["ETag"]
    assert created["target_facts"]["role_drift"] == 1
    assert set(created["target_facts"]) == {
        "missing_os_family", "role_drift", "quarantined_ids"}
    with server.schedule_role_guard(created["schedule"]):
        runner_preview = server.schedule_target_resolver(created["schedule"])
    assert runner_preview["device_ids"] == ["edge-1"]
    assert set(runner_preview) == {
        "revision", "now", "device_ids", "missing_os_family",
        "role_drift", "quarantined_ids"}

    listed_status, _, listed_raw = _request(
        server, "GET", "/api/schedules", headers={"Cookie": auth["Cookie"]})
    assert listed_status == 200
    listed = json.loads(listed_raw)
    assert listed["total"] == 1 and listed["schedules"] == [created["schedule"]]
    got_status, got_headers, got_raw = _request(
        server, "GET", "/api/schedules/s-boat",
        headers={"Cookie": auth["Cookie"]})
    assert got_status == 200 and got_headers["ETag"] == created_headers["ETag"]
    assert json.loads(got_raw)["schedule"] == created["schedule"]

    for bad_match in (None, 'W/"iris-schedule-s-boat-1"',
                      '"iris-schedule-s-boat-1", "other"',
                      '"iris-schedule-s-boat-99"'):
        headers = dict(auth)
        if bad_match is not None:
            headers["If-Match"] = bad_match
        status, response_headers, raw = _request(
            server, "PATCH", "/api/schedules/s-boat",
            {"state": "paused"}, headers)
        assert status == (428 if bad_match is None else 412)
        assert response_headers["ETag"] == created_headers["ETag"]
        assert json.loads(raw)["code"] == (
            "precondition_required" if bad_match is None
            else "precondition_failed")

    changed_status, changed_headers, changed_raw = _request(
        server, "PATCH", "/api/schedules/s-boat",
        {"target": {"filters": {"role": "fiber"},
                    "device_ids": ["edge-1", "edge-2"], "bind": "early"}},
        dict(auth, **{"If-Match": "*"}))
    assert changed_status == 200
    changed = json.loads(changed_raw)
    assert changed_headers["ETag"] == '"iris-schedule-s-boat-2"'
    assert changed["schedule"]["preview"]["device_ids"] == ["edge-2"]
    assert changed["target_facts"]["role_drift"] == 1

    put_status, put_headers, put_raw = _request(
        server, "PUT", "/api/schedules/s-boat", _definition(["edge-1"]),
        dict(auth, **{"If-Match": changed_headers["ETag"]}))
    assert put_status == 200
    put = json.loads(put_raw)["schedule"]
    assert put["created_by"] == "console:alice"
    assert put_headers["ETag"] == '"iris-schedule-s-boat-3"'

    app.set_admin("bob", "new-password")
    login_status, login_headers, login_body = _request(
        server, "POST", "/api/login",
        {"username": "bob", "password": "new-password"})
    assert login_status == 200
    bob = {"Cookie": login_headers["Set-Cookie"].split(";", 1)[0],
           "X-CSRF-Token": json.loads(login_body)["csrf"]}
    orphaned = json.loads(_request(
        server, "GET", "/api/schedules/s-boat",
        headers={"Cookie": bob["Cookie"]})[2])["schedule"]
    assert orphaned["creator_exists"] is False
    affirmed_status, affirmed_headers, affirmed_raw = _request(
        server, "POST", "/api/schedules/s-boat/reaffirm", {},
        dict(bob, **{"If-Match": put_headers["ETag"]}))
    assert affirmed_status == 200
    affirmed = json.loads(affirmed_raw)["schedule"]
    assert affirmed["created_by"] == "console:bob"
    assert affirmed["creator_exists"] is True
    assert affirmed_headers["ETag"] == '"iris-schedule-s-boat-4"'

    refused_delete, _, refused_raw = _request(
        server, "DELETE", "/api/schedules/s-boat", {},
        dict(bob, **{"If-Match": affirmed_headers["ETag"]}))
    assert refused_delete == 400
    assert json.loads(refused_raw)["code"] == "invalid-request"

    deleted_status, deleted_headers, deleted_raw = _request(
        server, "DELETE", "/api/schedules/s-boat",
        headers=dict(bob, **{"If-Match": affirmed_headers["ETag"]}))
    assert deleted_status == 204 and deleted_raw == b""
    assert deleted_headers["ETag"] == affirmed_headers["ETag"]
    assert _request(server, "GET", "/api/schedules/s-boat",
                    headers={"Cookie": bob["Cookie"]})[0] == 404
    assert server._test_schedule_wakes == ["wake"] * 5


def test_put_preserves_unchanged_early_target_preview(schedule_api):
    server, _app, auth = schedule_api
    definition = _definition()
    definition["target"]["bind"] = "early"
    status, headers, raw = _request(
        server, "POST", "/api/schedules",
        {"id": "s-early", **definition}, auth)
    assert status == 201
    frozen = json.loads(raw)["schedule"]["preview"]
    assert frozen["device_ids"] == ["edge-1"]

    gui_fleet.FleetStore(server.schedule_store.state_dir).upsert(
        {"device_id": "edge-3", "device_ip": "192.0.2.3",
         "model": "C9300", "role": "boat"})
    definition["payload"] = {"image_ids": ["image-b"], "mode": "merge"}
    changed_status, _, changed_raw = _request(
        server, "PUT", "/api/schedules/s-early", definition,
        dict(auth, **{"If-Match": headers["ETag"]}))
    assert changed_status == 200
    assert json.loads(changed_raw)["schedule"]["preview"] == frozen


def test_schedule_runner_role_guard_translates_only_expected_refusals():
    @contextlib.contextmanager
    def refused(_schedule):
        raise role_management.RoleManagementError(
            "missing", code="role_not_found", status=422)
        yield

    with pytest.raises(schedule_runner.ExecutionRefused) as exc:
        with management_api._runner_schedule_role_guard(refused, _definition()):
            pass
    assert exc.value.reason == "role_not_found"
    with pytest.raises(schedule_runner.ExecutionRefused) as absent:
        with management_api._runner_schedule_role_guard(None, _definition()):
            pass
    assert absent.value.reason == "role_authority_unavailable"


def test_schedule_daemon_lifecycle_is_ordered_after_deployment_recovery():
    source = inspect.getsource(management_api.main)
    assert source.index("record_store.recover_interrupted()") < \
        source.index("schedule_runner.ScheduleRunner(") < \
        source.index("schedule_thread.start()")
    assert "schedule_wake=schedule_wake_event.set" in source
    shutdown = source.split("def shutdown_management():", 1)[1]
    assert shutdown.index("schedule_service.stop()") < \
        shutdown.index("schedule_thread.join(timeout=10)") < \
        shutdown.index("onboard.shutdown()")


def test_callback_disappearance_is_precondition_failure(schedule_api,
                                                        monkeypatch):
    server, _app, auth = schedule_api
    status, headers, _ = _request(
        server, "POST", "/api/schedules",
        {"id": "s-race", **_definition(["edge-1"])}, auth)
    assert status == 201
    real_patch = server.schedule_store.patch

    def disappear(schedule_id, patch, **kwargs):
        server.schedule_store.delete(schedule_id, expected_rev="*")
        raise schedules.ScheduleNotFound("deleted during conditional write")

    monkeypatch.setattr(server.schedule_store, "patch", disappear)
    try:
        status, response_headers, raw = _request(
            server, "PATCH", "/api/schedules/s-race", {"state": "paused"},
            dict(auth, **{"If-Match": headers["ETag"]}))
    finally:
        monkeypatch.setattr(server.schedule_store, "patch", real_patch)
    assert status == 412
    assert "ETag" not in response_headers
    assert json.loads(raw)["code"] == "precondition_failed"


def test_conflict_reread_failure_is_stable_unavailable(schedule_api,
                                                       monkeypatch):
    server, _app, auth = schedule_api
    status, headers, _ = _request(
        server, "POST", "/api/schedules",
        {"id": "s-reread", **_definition(["edge-1"])}, auth)
    assert status == 201
    real_get = server.schedule_store.get

    def conflict(*_args, **_kwargs):
        raise schedules.ScheduleRevisionConflict("s-reread", 1)

    calls = {"count": 0}

    def first_get_then_fail(schedule_id):
        calls["count"] += 1
        if calls["count"] == 1:
            return real_get(schedule_id)
        raise schedules.ScheduleStateError("reread unavailable")

    monkeypatch.setattr(server.schedule_store, "get", first_get_then_fail)
    monkeypatch.setattr(server.schedule_store, "patch", conflict)
    status, _, raw = _request(
        server, "PATCH", "/api/schedules/s-reread", {"state": "paused"},
        dict(auth, **{"If-Match": headers["ETag"]}))
    assert status == 503
    assert json.loads(raw)["code"] == "schedule_state_unavailable"


def test_cross_occurrence_receipts_are_visible_and_capped(schedule_api):
    server, _app, auth = schedule_api
    status, _, raw = _request(
        server, "POST", "/api/schedules",
        {"id": "s-history", **_definition(["edge-1"])}, auth)
    assert status == 201
    row = json.loads(raw)["schedule"]
    row = {key: value for key, value in row.items()
           if key not in ("etag", "creator_exists")}
    occurrences = schedules.OccurrenceStore(server.schedule_store.state_dir)
    receipts = schedules.ReceiptStore(server.schedule_store.state_dir)
    for index in range(2):
        slot = schedules.occurrence_slot(row, NOW + 60)
        slot = dict(slot, scheduled_at=slot["scheduled_at"] + index,
                    window_end=slot["window_end"] + index,
                    local_time=slot["local_time"] if index == 0
                    else slot["local_time"] + "+retry")
        occurrence = occurrences.create(
            row, slot, row["preview"], now=NOW + 60 + index)
        receipts.record(occurrence["id"], "edge-1", status="ok",
                        reason="assigned", now=NOW + 61 + index)
    got_status, _, got_raw = _request(
        server, "GET", "/api/schedules/s-history/receipts?limit=1&offset=0",
        headers={"Cookie": auth["Cookie"]})
    assert got_status == 200
    page = json.loads(got_raw)
    assert page["schedule_id"] == "s-history"
    assert page["total"] == 2 and page["truncated"] is True
    assert len(page["receipts"]) == 1
    assert page["receipts"][0]["schedule_id"] == "s-history"
    assert page["receipts"][0]["occurrence_id"]
    assert page["receipts"][0]["scheduled_at"] == NOW + 60


def test_receiptless_occurrences_remain_visible_after_schedule_delete(
        schedule_api):
    server, _app, auth = schedule_api
    status, headers, raw = _request(
        server, "POST", "/api/schedules",
        {"id": "s-evidence", **_definition(["edge-1"])}, auth)
    assert status == 201
    row = json.loads(raw)["schedule"]
    row = {key: value for key, value in row.items()
           if key not in ("etag", "creator_exists")}
    occurrences = schedules.OccurrenceStore(server.schedule_store.state_dir)
    slot = schedules.occurrence_slot(row, NOW + 60)
    missed = occurrences.create(row, slot, None, now=slot["window_end"])
    retry_slot = dict(slot, scheduled_at=slot["scheduled_at"] + 1,
                      window_end=slot["window_end"] + 1,
                      local_time=slot["local_time"] + "+empty")
    empty = occurrences.create(
        row, retry_slot,
        {"revision": row["preview"]["revision"], "now": NOW + 61,
         "device_ids": []}, now=NOW + 61)
    occurrences.transition(empty["id"], "failed", now=NOW + 62,
                           expected_state="pending")

    deleted, _, _ = _request(
        server, "DELETE", "/api/schedules/s-evidence", headers=dict(
            auth, **{"If-Match": headers["ETag"]}))
    assert deleted == 204
    cookie = {"Cookie": auth["Cookie"]}
    receipt_status, _, receipt_raw = _request(
        server, "GET", "/api/schedules/s-evidence/receipts", headers=cookie)
    assert receipt_status == 200
    assert json.loads(receipt_raw)["total"] == 0

    history_status, _, history_raw = _request(
        server, "GET",
        "/api/schedules/s-evidence/occurrences?limit=1&offset=0",
        headers=cookie)
    assert history_status == 200
    history = json.loads(history_raw)
    assert history["total"] == 2 and history["truncated"] is True
    assert history["occurrences"][0]["id"] == missed["id"]
    assert history["occurrences"][0]["state"] == "missed"
    assert "target_snapshot" not in history["occurrences"][0]
    _, _, second_raw = _request(
        server, "GET",
        "/api/schedules/s-evidence/occurrences?limit=1&offset=1",
        headers=cookie)
    second = json.loads(second_raw)["occurrences"][0]
    assert second["state"] == "failed"
    assert second["target_snapshot"]["device_ids"] == []
    assert _request(
        server, "GET", "/api/schedules/s-evidence/occurrences?limit=101",
        headers=cookie)[0] == 422


def test_role_delete_and_replace_include_schedule_references(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    auth_path = str(tmp_path / "peer-policy.json")
    lkg_path = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.define_role(auth_path, lkg_path, "boat",
                            {"restricted": True}, "test", NOW)
    store = schedules.ScheduleStore(tmp_path)
    store.create("s-boat", _definition(), actor="cli:iris-schedule", now=NOW,
                 preview={"revision": 0, "now": NOW, "device_ids": []})
    manager = role_management.RoleCoordinator(
        fleet, auth_path, lkg_path, schedule_store=store, now_fn=lambda: NOW)
    with pytest.raises(role_management.RoleManagementError) as deleted:
        manager.delete_role("boat", actor="test")
    assert deleted.value.code == "role_in_use"
    assert deleted.value.result["referring_schedules"] == ["s-boat"]
    with pytest.raises(role_management.RoleManagementError) as replaced:
        manager.replace_definitions({}, actor="test")
    assert replaced.value.code == "role_in_use"
    assert replaced.value.result["referring_schedules"] == ["s-boat"]


def test_schedule_problem_type_is_stable(schedule_api):
    server, _app, auth = schedule_api
    status, headers, raw = _request(
        server, "POST", "/api/schedules",
        {"id": "bad", **_definition(), "created_by": "forged"}, auth)
    assert status == 422
    assert headers["Content-Type"] == "application/problem+json"
    problem = json.loads(raw)
    assert problem["type"] == api_problem.TYPE_BASE + "invalid_schedule"
    assert problem["code"] == "invalid_schedule"

    for body, expected_status, expected_code in (
            ({"id": "bad/id", **_definition()}, 422, "invalid_schedule"),
            ({"id": "unknown-role", **_definition(role="missing")},
             422, "role_not_found")):
        status, _, raw = _request(
            server, "POST", "/api/schedules", body, auth)
        assert (status, json.loads(raw)["code"]) == (
            expected_status, expected_code)
    status, _, raw = _request(
        server, "POST", "/api/schedules", raw=b"[]", headers=auth)
    assert (status, json.loads(raw)["code"]) == (400, "invalid-request")

    valid = {"id": "duplicate", **_definition(role=None)}
    assert _request(server, "POST", "/api/schedules", valid, auth)[0] == 201
    status, _, raw = _request(server, "POST", "/api/schedules", valid, auth)
    assert (status, json.loads(raw)["code"]) == (409, "schedule_conflict")


def test_target_resolution_fails_closed_without_process_authorities(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "edge-1", "device_ip": "192.0.2.1"})
    policy = peer_policy.load_policy(
        str(tmp_path / "peer-policy.json"),
        str(tmp_path / "peer-policy.lkg.json"))
    cat = catalog.CatalogStore(str(tmp_path))
    base = dict(fleet=fleet, record_store=_Records(), role_policy=policy,
                now=NOW, heartbeat_rows=[], revoked_principals=set())
    with pytest.raises(management_api.ScheduleTargetError) as status_error:
        management_api.resolve_schedule_target(
            {"filters": {"status": "not-enrolled"}, "device_ids": [],
             "bind": "late"}, catalog=cat, jobs=None, **base)
    assert status_error.value.code == "schedule_target_status_unavailable"
    with pytest.raises(management_api.ScheduleTargetError) as heartbeat_error:
        management_api.resolve_schedule_target(
            {"filters": {"q": "edge"}, "device_ids": [], "bind": "late"},
            catalog=None, jobs={}, **base)
    assert heartbeat_error.value.code == "schedule_target_heartbeat_unavailable"
    assert schedules.ScheduleStore(tmp_path).list() == []
