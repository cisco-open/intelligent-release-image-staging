# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 19 — durable frozen v2 terminal report (spec §10.2 / §2 / §10.2b).

The agent freezes the full v2 report body (report_id + report_created_at) in
state and CHECKPOINTS it BEFORE the first POST; retries are byte-identical.
Completion/seeding share one frozen payload; a pull mints a fresh random report
per server request_id and reuses it for a repeated same request. Verification is
two independent persisted facts; avg_bps / sha_ok / the generic tier are retired.
"""
import re

import telemetry_report

HEX32 = re.compile(r"^[a-f0-9]{32}$")

_CFG = {"device_id": "sw1", "agent_version": "2026.08.20"}


def _state():
    return {
        "link": {"rtt_ms": [20.0, 24.0, 28.0], "fail_streak": 2,
                 "report_fail_streak": 1},
        "img1": {"copied": True, "tele": {
            "transfer_id": "a" * 32,
            "started_ts": 1000.0, "done_ts": 1100.0,
            "completed_content_bytes": 1288490188,
            "total_content_bytes": 1288490188,
            "content_sha256_state": "verified",
            "ios_copy_verify_state": "ok",
            "peers_v2": {"10.0.0.9": {"first_observed": 1010.0,
                                      "last_observed": 1090.0,
                                      "observations": 71}}}}}


def test_build_report_v2_exact_schema():
    state = _state()
    rep = telemetry_report.build_report_v2(
        _CFG, state, "img1", "staging-complete", 1200.5, "a" * 32, "b" * 32)
    assert rep["v"] == 2
    assert rep["report_id"] == "b" * 32
    assert rep["transfer_id"] == "a" * 32
    assert rep["report_request_id"] is None
    assert rep["report_created_at"] == 1200.5
    assert rep["image_id"] == "img1"
    assert rep["event"] == "staging-complete"
    assert rep["window"] == {"start": 1000.0, "end": 1100.0, "complete": True}
    assert rep["content"] == {"completed_content_bytes": 1288490188,
                              "total_content_bytes": 1288490188}
    assert rep["content_sha256"] == {"state": "verified", "algo": "sha256"}
    assert rep["ios_copy_verify"] == {"state": "ok"}
    assert rep["sampling"]["sampling_class"] in ("good", "constrained")
    assert rep["sampling"]["catalog_rtt_ms_median"] == 24
    assert rep["sampling"]["catalog_rtt_samples"] == 3
    assert rep["sampling"]["heartbeat_fail_streak"] == 2
    assert rep["sampling"]["report_fail_streak"] == 1
    assert rep["stage_state"] == "ready"
    assert rep["peers"] == [{"ip": "10.0.0.9", "first_observed": 1010.0,
                             "last_observed": 1090.0, "observations": 71}]
    assert rep["peers_total"] == 1
    assert rep["peers_truncated"] is False and rep["peers_saturated"] is False
    assert rep["agent"] == {"version": "2026.08.20", "runtime_mode": "guestshell"}
    # retired fields are absent
    assert "avg_bps" not in rep and "sha_ok" not in rep
    assert "tier" not in rep and "link" not in rep and "transfer" not in rep


def test_not_checked_content_sha256_omits_algo():
    state = {"img1": {"tele": {}}}
    rep = telemetry_report.build_report_v2(
        _CFG, state, "img1", "seeding-only", 1.0, "a" * 32, "b" * 32)
    assert rep["content_sha256"] == {"state": "not_checked"}
    assert rep["ios_copy_verify"] == {"state": "not_run"}


def test_peers_truncated_and_saturated_flags():
    tele = {"peers_v2": {}}
    for i in range(telemetry_report.STATE_PEER_SET_CAP):
        tele["peers_v2"]["10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256)] = {
            "first_observed": 1.0, "last_observed": 2.0, "observations": 1}
    state = {"img1": {"tele": tele}}
    rep = telemetry_report.build_report_v2(
        _CFG, state, "img1", "staging-complete", 1.0, "a" * 32, "b" * 32)
    assert len(rep["peers"]) == telemetry_report.PEER_CAP        # cap 64 named
    assert rep["peers_total"] == telemetry_report.STATE_PEER_SET_CAP
    assert rep["peers_truncated"] is True
    assert rep["peers_saturated"] is True


def test_freeze_report_stable_and_read_back():
    state = _state()
    rep = telemetry_report.build_report_v2(
        _CFG, state, "img1", "staging-complete", 1.0, "a" * 32, "b" * 32)
    telemetry_report.freeze_report(state, "img1", rep)
    assert telemetry_report.frozen_report(state, "img1") is rep


def test_freeze_pull_report_reuses_same_request_new_for_different():
    state = _state()
    r1 = telemetry_report.build_report_v2(
        _CFG, state, "img1", "pull", 1.0, "a" * 32, "c" * 32,
        report_request_id="d" * 32)
    telemetry_report.freeze_pull_report(state, "d" * 32, r1)
    # same request id -> the frozen body is returned
    assert telemetry_report.frozen_pull_report(state, "d" * 32) is r1
    # a different request id -> nothing frozen yet
    assert telemetry_report.frozen_pull_report(state, "e" * 32) is None


def test_pull_request_id_parsing():
    assert telemetry_report.pull_request_id({"report_request_id": "f" * 32}) \
        == "f" * 32
    assert telemetry_report.pull_request_id({"report_request_id": "short"}) is None
    assert telemetry_report.pull_request_id({}) is None
    assert telemetry_report.pull_request_id(None) is None


def test_mint_id_shape():
    assert HEX32.match(telemetry_report.mint_id())
