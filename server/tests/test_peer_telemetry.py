# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import copy
import json
from types import SimpleNamespace

import pytest

import catalog
import instructions
import live_samples
import peer_policy


def observation(**changes):
    value = {"v": 2, "obs_state": "observed", "observed_at": 1000,
             "transfer_id": "a" * 32, "image_id": "image", "sample_seq": 1,
             "sampling_class": "good", "aria": {"status": "active",
                 "completed_content_bytes": 10, "total_content_bytes": 100,
                 "receive_bps": 123, "send_bps": 0, "connections": 8},
             "peer_connections": [{"ip": "192.0.2.%d" % n,
                                    "receive_bps": n} for n in range(1, 9)]}
    value.update(changes)
    return value


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.setattr(catalog.time, "time", lambda: 1000)
    row = {"approved_image_ids": ["image"], "instr": {"part": {
        "control_override": {"peer_telemetry_interval_s": 10}}}}
    record = {"last_seen": 990, "telemetry_enabled": True,
              "telemetry_stream_enabled": True, "model": "preserve"}
    store = SimpleNamespace(read_policy_row_snapshot=lambda did: row,
                            get_device=lambda did: record)
    table = live_samples.LiveTable()
    cat = catalog.Catalog(store, "/nonexistent-secrets", audit_path="/dev/null",
                          live_table=table)
    cat._heartbeat_delivery_context = lambda row: (None, None, (1, False))
    cat._peer_telemetry_control = lambda row, now: dict(
        telemetry_every_ticks=1, telemetry_pause=False,
        **row["instr"]["part"]["control_override"])
    return cat, table, row, record


def post(runtime, obs=None):
    status, _ctype, body = runtime[0].route_post(
        "/v1/devices/router/live-telemetry",
        json.dumps({"telemetry_observation": observation() if obs is None else obs}).encode())
    return status, json.loads(body)


def test_accelerated_ingest_preserves_device_record_and_all_peer_rows(runtime):
    before = copy.deepcopy(runtime[3])
    assert post(runtime)[0] == 200
    entry = runtime[1].snapshot(1000)["samples"]["router"]
    assert len(entry["peer_connections"]) == 8
    assert entry["interval_s"] == 10
    assert runtime[3] == before
    assert post(runtime, observation(sample_seq=0))[0] == 200
    assert runtime[1].snapshot(1000)["samples"]["router"]["last_sample_seq"] == 1


@pytest.mark.parametrize("change", ["default", "unassigned", "disabled", "paused", "old"])
def test_server_checks_assignment_flags_and_heartbeat_lease(runtime, change):
    if change == "default": runtime[2]["instr"]["part"]["control_override"].clear()
    elif change == "unassigned": runtime[2]["approved_image_ids"] = []
    elif change == "disabled": runtime[3]["telemetry_enabled"] = False
    elif change == "paused": runtime[3]["telemetry_stream_enabled"] = False
    elif change == "old": runtime[3]["last_seen"] = 800
    assert post(runtime)[0] == 409
    assert not runtime[1].snapshot(1000)["samples"]


def test_wrong_image_and_malformed_envelopes_are_rejected(runtime):
    assert post(runtime, observation(image_id="other"))[0] == 400
    assert post(runtime, {"v": 99})[0] == 400
    assert runtime[1].snapshot(1000)["counters"]["samples_rejected_total"] == 2


def test_normal_heartbeat_cadence_is_not_the_peer_row_cap(runtime):
    cat, table, row, record = runtime
    cat.store.record_heartbeat = lambda did, data: None
    cat.store.pending_report = lambda did, now: None
    status, _, _ = cat.route_post("/v1/devices/router/heartbeat", json.dumps({
        "telemetry_enabled": True, "telemetry_stream_enabled": True,
        "telemetry_observation": observation()}).encode())
    assert status == 200
    assert len(table.snapshot(1000)["samples"]["router"]["peer_connections"]) == 8
    assert table.snapshot(1000)["samples"]["router"]["interval_s"] == 60


def test_slow_heartbeat_reports_its_actual_configured_interval(runtime):
    cat, table, row, record = runtime
    cat.store.record_heartbeat = lambda did, data: None
    cat.store.pending_report = lambda did, now: None
    cat._heartbeat_delivery_context = lambda row: (None, None, (5, False))
    assert cat.route_post("/v1/devices/router/heartbeat", json.dumps({
        "telemetry_observation": observation(sampling_class="constrained")}).encode())[0] == 200
    assert table.snapshot(1000)["samples"]["router"]["interval_s"] == 300


@pytest.mark.parametrize("fields", [{"errored_image_ids": ["image"]},
    {"current_image_id": "image", "stage_error": "copy failed"},
    {"current_image_id": "image", "stage_state": "error"}])
def test_accelerated_ingest_rejects_errored_image(runtime, fields):
    runtime[3].update(fields)
    assert post(runtime)[0] == 400
    assert not runtime[1].snapshot(1000)["samples"]


@pytest.mark.parametrize("value", [10, 60])
def test_signed_optional_control_and_device_policy_agree(value):
    instructions.validate_control({"peer_telemetry_interval_s": value}, partial=True)
    peer_policy._validate_qos({"peer_telemetry_interval_s": value}, "device")
    for scope in ("global", "role"):
        with pytest.raises(peer_policy.PolicyError):
            peer_policy._validate_qos({"peer_telemetry_interval_s": value}, scope)


@pytest.mark.parametrize("value", [True, "10", 0, 5, 11, 61, None])
def test_invalid_intervals_are_rejected_by_both_validators(value):
    with pytest.raises(instructions.InstructionError):
        instructions.validate_control({"peer_telemetry_interval_s": value}, partial=True)
    with pytest.raises(peer_policy.PolicyError):
        peer_policy._validate_qos({"peer_telemetry_interval_s": value}, "device")
