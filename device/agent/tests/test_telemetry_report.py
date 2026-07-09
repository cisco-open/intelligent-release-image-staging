# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure-function tests for the device telemetry-report module (issue #13):
toggle parsing, RTT/failure bookkeeping, link-tier classifier boundaries,
per-peer rate integration (clamp + top-20/'other' collapse), report shape,
trimming, pull-flag parsing and defer backoff."""
import json

import pytest

import telemetry_report


# ---- enabled(): conf toggle, default on ----

@pytest.mark.parametrize("val", ["off", "OFF", " Off ", "0", "false",
                                 "FALSE", "no", " NO "])
def test_enabled_false_values(val):
    assert telemetry_report.enabled({"telemetry": val}) is False


@pytest.mark.parametrize("val", ["on", "ON", "1", "true", "yes", "banana", ""])
def test_enabled_anything_else_is_on(val):
    assert telemetry_report.enabled({"telemetry": val}) is True


def test_enabled_defaults_on_when_key_absent():
    # Already-deployed devices have no `telemetry` line -> default on.
    assert telemetry_report.enabled({}) is True


# ---- record_rtt / record_failure / record_success ----

def test_record_rtt_caps_at_rtt_keep():
    state = {}
    for i in range(10):
        telemetry_report.record_rtt(state, float(i))
    assert state["link"]["rtt_ms"] == [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]
    assert len(state["link"]["rtt_ms"]) == telemetry_report.RTT_KEEP


def test_record_rtt_and_failure_share_link_dict():
    state = {}
    telemetry_report.record_rtt(state, 12.5)
    telemetry_report.record_failure(state)
    assert state["link"] == {"rtt_ms": [12.5], "fail_streak": 1}


def test_failure_streak_counts_and_resets():
    state = {}
    for _ in range(3):
        telemetry_report.record_failure(state)
    assert state["link"]["fail_streak"] == 3
    telemetry_report.record_success(state)
    assert state["link"]["fail_streak"] == 0


def test_record_success_on_fresh_state():
    state = {}
    telemetry_report.record_success(state)
    assert state["link"]["fail_streak"] == 0


# ---- classify(): tier boundaries, first match wins ----

def _link_state(rtts=(), streak=0):
    return {"link": {"rtt_ms": list(rtts), "fail_streak": streak}}


def test_classify_good_defaults():
    assert telemetry_report.classify({}, None) == "good"
    assert telemetry_report.classify(_link_state([10.0, 20.0, 30.0]),
                                     5000000) == "good"


def test_classify_rtt_boundary():
    # median EXACTLY 250 ms is NOT constrained (strict >); just above is.
    assert telemetry_report.classify(
        _link_state([250.0, 250.0, 250.0]), None) == "good"
    assert telemetry_report.classify(
        _link_state([250.1, 250.1, 250.1]), None) == "constrained"


def test_classify_even_sample_count_uses_midpoint_median():
    # median([200, 320]) = 260 > 250; median([200, 300]) = 250 -> good.
    assert telemetry_report.classify(
        _link_state([200.0, 320.0]), None) == "constrained"
    assert telemetry_report.classify(
        _link_state([200.0, 300.0]), None) == "good"


def test_classify_throughput_boundary():
    # avg EXACTLY 1 MiB/s is NOT constrained (strict <); one byte less is.
    assert telemetry_report.classify(
        _link_state([10.0]), telemetry_report.SLOW_BPS) == "good"
    assert telemetry_report.classify(
        _link_state([10.0]), telemetry_report.SLOW_BPS - 1) == "constrained"


def test_classify_zero_or_none_avg_bps_not_constraining():
    # No completed download yet -> throughput unknown, never constraining.
    assert telemetry_report.classify(_link_state([10.0]), 0) == "good"
    assert telemetry_report.classify(_link_state([10.0]), None) == "good"


def test_classify_fail_streak_boundary():
    assert telemetry_report.classify(
        _link_state([10.0], streak=2), 5000000) == "good"
    assert telemetry_report.classify(
        _link_state([10.0], streak=3), 5000000) == "bad"


def test_classify_bad_wins_over_constrained():
    assert telemetry_report.classify(
        _link_state([900.0], streak=3), 1000) == "bad"


# ---- integrate_peers(): rate integration + top-20/'other' collapse ----

def _rows(n):
    # n synthetic getPeers rows, aria2-style (ALL values strings); peer i
    # downloads at i*100 B/s so ranking by total bytes is deterministic.
    return [{"ip": "10.0.0.%d" % i, "downloadSpeed": str(i * 100),
             "uploadSpeed": "0"} for i in range(1, n + 1)]


def test_heal_drops_fabricated_rows_and_resets_sample_ts():
    """State written by the old pull-sampling bug: a completed transfer whose
    last_sample_ts postdates done_ts (the fixed agent never samples a
    staging-complete transfer after completion) with fabricated zero-rx/
    nonzero-tx rows injected post-completion. heal() removes exactly those
    rows and clamps last_sample_ts back to done_ts."""
    tele = {"event": "staging-complete", "done_ts": 100.0,
            "last_sample_ts": 5000.0,
            "peers": {"10.0.0.1": [0, 0],              # real (fast dl, w=0)
                      "10.0.0.7": [0, 12109529520]}}   # fabricated seeding row
    assert telemetry_report.heal_post_completion_contamination(tele) is True
    assert "10.0.0.7" not in tele["peers"]
    assert tele["peers"]["10.0.0.1"] == [0, 0]
    assert tele["last_sample_ts"] == 100.0
    # idempotent: a healed tele is no longer detected
    assert telemetry_report.heal_post_completion_contamination(tele) is False


def test_heal_leaves_seeding_only_transfers_alone():
    # seeding-only devices legitimately keep sampling after done_ts — their
    # post-completion tx is REAL and must never be healed away
    tele = {"event": "seeding-only", "done_ts": 100.0,
            "last_sample_ts": 5000.0,
            "peers": {"10.0.0.7": [0, 999999]}}
    assert telemetry_report.heal_post_completion_contamination(tele) is False
    assert tele["peers"] == {"10.0.0.7": [0, 999999]}


def test_heal_leaves_clean_completed_transfers_alone():
    tele = {"event": "staging-complete", "done_ts": 100.0,
            "last_sample_ts": 100.0,
            "peers": {"10.0.0.1": [500, 3]}}
    assert telemetry_report.heal_post_completion_contamination(tele) is False
    assert tele["peers"] == {"10.0.0.1": [500, 3]}


def test_heal_tolerates_empty_or_incomplete_tele():
    assert telemetry_report.heal_post_completion_contamination({}) is False
    assert telemetry_report.heal_post_completion_contamination(
        {"event": "staging-complete"}) is False


def test_integrate_peers_first_sample_has_no_baseline():
    tele = {}
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1", "downloadSpeed": "1000",
                "uploadSpeed": "9"}], 100.0)
    # no last_sample_ts -> elapsed 0 -> row appears with zero bytes
    assert tele["peers"]["10.0.0.1"] == [0, 0]
    assert tele["last_sample_ts"] == 100.0


def test_integrate_peers_accumulates_across_samples():
    tele = {}
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1", "downloadSpeed": "1000",
                "uploadSpeed": "0"}], 100.0)
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1", "downloadSpeed": "1000",
                "uploadSpeed": "50"}], 160.0)
    assert tele["peers"]["10.0.0.1"] == [60000, 3000]
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1", "downloadSpeed": "500",
                "uploadSpeed": "0"}], 220.0)
    assert tele["peers"]["10.0.0.1"] == [90000, 3000]


def test_integrate_peers_elapsed_clamped():
    # A stalled tick (1 h gap) integrates at most ELAPSED_CLAMP seconds.
    tele = {"last_sample_ts": 1000.0}
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1", "downloadSpeed": "100",
                "uploadSpeed": "7"}], 1000.0 + 3600.0)
    assert tele["peers"]["10.0.0.1"] == [18000, 1260]   # rate * 180
    assert tele["last_sample_ts"] == 4600.0


def test_integrate_peers_tolerates_missing_fields():
    tele = {"last_sample_ts": 0.0}
    telemetry_report.integrate_peers(
        tele, [{"ip": "10.0.0.1"},                            # no speeds -> 0
               {"ip": "10.0.0.2", "downloadSpeed": "", "uploadSpeed": ""},
               {"downloadSpeed": "999", "uploadSpeed": "1"}], # no ip -> skip
        10.0)
    assert tele["peers"] == {"10.0.0.1": [0, 0], "10.0.0.2": [0, 0]}


def test_integrate_peers_collapses_beyond_cap_into_other():
    tele = {"last_sample_ts": 0.0}
    telemetry_report.integrate_peers(tele, _rows(25), 10.0)
    assert len(tele["peers"]) == telemetry_report.PEER_CAP
    assert "10.0.0.5" not in tele["peers"]              # bottom-5 evicted
    assert tele["peers"]["10.0.0.6"] == [6000, 0]       # smallest survivor
    assert tele["peers"]["10.0.0.25"] == [25000, 0]     # biggest
    # evicted i=1..5: (1+2+3+4+5) * 100 B/s * 10 s = 15000 rx over 5 peers
    assert tele["other"] == [15000, 0, 5]


def test_integrate_peers_other_accumulates_across_collapses():
    tele = {"last_sample_ts": 0.0}
    telemetry_report.integrate_peers(tele, _rows(25), 10.0)
    telemetry_report.integrate_peers(tele, _rows(25), 20.0)
    # i=1..5 re-appear fresh and lose again to the accumulated top-20; a
    # re-evicted peer is re-counted ('other' is approximate by design).
    assert tele["other"] == [30000, 0, 10]
    assert tele["peers"]["10.0.0.25"] == [50000, 0]
    assert len(tele["peers"]) == telemetry_report.PEER_CAP


def test_integrate_peers_no_other_at_or_below_cap():
    tele = {"last_sample_ts": 0.0}
    telemetry_report.integrate_peers(tele, _rows(20), 10.0)
    assert len(tele["peers"]) == 20
    assert "other" not in tele


# ---- build_report(): exact shape per spec section 2 ----

def test_build_report_exact_shape(monkeypatch):
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    # total_bytes == sum of rx weights (123456789 + 50 + 999) so the rescale
    # is the identity here — this test pins row shape/order + per-row avg_bps;
    # dedicated tests below exercise the proportional rescale + remainder.
    state = {
        "link": {"rtt_ms": [10.0, 12.0, 20.0], "fail_streak": 0},
        "img-1": {"copied": True,
                  "tele": {"peers": {"10.0.0.8": [50, 100],
                                     "10.0.0.7": [123456789, 0]},
                           "other": [999, 1, 3],
                           "total_bytes": 123457838, "elapsed_s": 300.52,
                           "avg_bps": 4000000, "sha_ok": True}},
    }
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 1783000000.7)
    assert rep == {
        "ts": 1783000000,
        "image_id": "img-1",
        "event": "staging-complete",
        "transfer": {"total_bytes": 123457838, "elapsed_s": 300.5,
                     "avg_bps": 4000000, "sha_ok": True,
                     "stage_state": "ready"},
        "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 3,
                 "hb_failures": 0, "trimmed": False},
        "peers": [{"ip": "10.0.0.7", "rx_bytes": 123456789, "tx_bytes": 0,
                   "avg_bps": 410811},
                  {"ip": "10.0.0.8", "rx_bytes": 50, "tx_bytes": 100,
                   "avg_bps": 0},
                  {"ip": "other(3)", "rx_bytes": 999, "tx_bytes": 1,
                   "avg_bps": 3}],
        "agent": {"version": "unknown", "runtime_mode": "guestshell"},
    }
    # per-peer rx sums to the accurate total exactly (rescale invariant)
    assert sum(p["rx_bytes"] for p in rep["peers"]) == 123457838
    json.dumps(rep)   # must be JSON-serializable as-is (POST body)
    # build_report is a pure READ — state must be untouched
    assert state["img-1"]["tele"]["peers"]["10.0.0.7"] == [123456789, 0]
    assert "trimmed" not in state["link"]


def test_build_report_defaults_on_bare_state(monkeypatch):
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    rep = telemetry_report.build_report({}, {}, "img-x", "pull", 5.9)
    assert rep == {
        "ts": 5, "image_id": "img-x", "event": "pull",
        "transfer": {"total_bytes": 0, "elapsed_s": 0.0, "avg_bps": 0,
                     "sha_ok": False, "stage_state": "staging"},
        "link": {"tier": "good", "rtt_ms_median": 0, "rtt_samples": 0,
                 "hb_failures": 0, "trimmed": False},
        "peers": [],
        "agent": {"version": "unknown", "runtime_mode": "guestshell"},
    }


def test_build_report_seeding_only_stage_state(monkeypatch):
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = {"img-1": {"blocked_no_space": True, "tele": {}}}
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "seeding-only", 60.0)
    assert rep["transfer"]["stage_state"] == "flash_full_seeding_only"
    assert rep["event"] == "seeding-only"


def test_build_report_runtime_mode_env_then_conf(monkeypatch):
    # Mirrors cli_ssh.select_cli: env IRIS_RUNTIME_MODE > conf runtime_mode
    # > 'guestshell'. The IE-3400 IOx image bakes the env var in.
    monkeypatch.setenv("IRIS_RUNTIME_MODE", "container")
    rep = telemetry_report.build_report({}, {}, "i", "pull", 1.0)
    assert rep["agent"]["runtime_mode"] == "container"
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    rep = telemetry_report.build_report({"runtime_mode": "container"},
                                        {}, "i", "pull", 1.0)
    assert rep["agent"]["runtime_mode"] == "container"


# ---- build_report(): per-peer rx attributed from the accurate total ----
# The raw rate-integration weights (rx_weight/tx) only APPROXIMATE bytes; the
# accurate figure is transfer.total_bytes. build_report rescales each peer's
# rx so the per-peer rx sums to total exactly, and derives per-peer avg_bps =
# rx_bytes / max(elapsed_s, 1). tx is the raw accumulated upload (not rescaled).

def _tele_state(peers, other=None, total=0, elapsed=0.0, img="img-1"):
    tele = {"peers": dict(peers), "total_bytes": total, "elapsed_s": elapsed}
    if other is not None:
        tele["other"] = list(other)
    return {"img-1": {"copied": True, "tele": tele}}


def test_build_report_single_peer_zero_weight_gets_full_total(monkeypatch):
    # Fast download / no per-peer samples ever landed: the ONE peer row has a
    # zero rx weight but must still be attributed the whole accurate total.
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.5": [0, 0]}, total=1000, elapsed=250.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert rep["peers"] == [{"ip": "10.0.0.5", "rx_bytes": 1000,
                             "tx_bytes": 0, "avg_bps": 4}]   # 1000 / 250


def test_build_report_two_peer_weighted_rx_is_proportional(monkeypatch):
    # rx weights 3:1 over an accurate total of 1000 -> 750 / 250, summing to
    # total exactly. avg_bps = rx / elapsed (elapsed 250 -> 3 / 1).
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    # tx chosen so the rx+tx display sort keeps 10.0.0.1 first (23 > 6).
    state = _tele_state({"10.0.0.1": [3, 20], "10.0.0.2": [1, 5]},
                        total=1000, elapsed=250.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert rep["peers"] == [
        {"ip": "10.0.0.1", "rx_bytes": 750, "tx_bytes": 20, "avg_bps": 3},
        {"ip": "10.0.0.2", "rx_bytes": 250, "tx_bytes": 5, "avg_bps": 1}]
    assert sum(p["rx_bytes"] for p in rep["peers"]) == 1000
    # tx is the RAW accumulated upload — never rescaled
    assert [p["tx_bytes"] for p in rep["peers"]] == [20, 5]


def test_build_report_two_peer_zero_weight_splits_total_evenly(monkeypatch):
    # Neither peer accumulated any rx weight -> split the accurate total evenly
    # across the real peer rows (not 'other').
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [0, 0], "10.0.0.2": [0, 0]},
                        total=1000, elapsed=200.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    rx = sorted(p["rx_bytes"] for p in rep["peers"])
    assert rx == [500, 500]
    assert sum(p["rx_bytes"] for p in rep["peers"]) == 1000
    for p in rep["peers"]:
        assert p["avg_bps"] == 2                          # 500 / 200


def test_build_report_zero_weight_odd_total_even_split_remainder(monkeypatch):
    # Even split of an ODD total still sums to total exactly (remainder to the
    # first real row).
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [0, 0], "10.0.0.2": [0, 0]},
                        total=1001, elapsed=1.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert sum(p["rx_bytes"] for p in rep["peers"]) == 1001
    assert sorted(p["rx_bytes"] for p in rep["peers"]) == [500, 501]


def test_build_report_remainder_goes_to_largest_row_sum_equals_total(
        monkeypatch):
    # weights 10:6:3 over total 100 round to 53+32+16 = 101 (one over); the -1
    # remainder lands on the largest-weight row so the sum is exactly total.
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [10, 0], "10.0.0.2": [6, 0],
                         "10.0.0.3": [3, 0]}, total=100, elapsed=1.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    rx = {p["ip"]: p["rx_bytes"] for p in rep["peers"]}
    assert rx == {"10.0.0.1": 52, "10.0.0.2": 32, "10.0.0.3": 16}
    assert sum(rx.values()) == 100


def test_build_report_other_row_shares_the_total_and_gets_avg_bps(monkeypatch):
    # The 'other(N)' pseudo-row participates in the rescale (its rx weight
    # counts toward sum_w) and gets its own avg_bps.
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [3, 0]}, other=[1, 5, 4],
                        total=1000, elapsed=250.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert rep["peers"] == [
        {"ip": "10.0.0.1", "rx_bytes": 750, "tx_bytes": 0, "avg_bps": 3},
        {"ip": "other(4)", "rx_bytes": 250, "tx_bytes": 5, "avg_bps": 1}]
    assert sum(p["rx_bytes"] for p in rep["peers"]) == 1000


def test_build_report_zero_weight_but_only_other_leaves_no_real_split(
        monkeypatch):
    # sum_w == 0 with NO real peer rows (only an 'other' with zero weight):
    # there is nothing to attribute to -> peers stays empty.
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({}, other=[0, 3, 2], total=1000, elapsed=10.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert rep["peers"] == []


def test_build_report_zero_total_leaves_rows_at_zero(monkeypatch):
    # total_bytes 0 (never completed) -> every attributed rx is 0, avg_bps 0.
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [5, 7]}, total=0, elapsed=10.0)
    rep = telemetry_report.build_report({}, state, "img-1", "pull", 100.0)
    assert rep["peers"] == [{"ip": "10.0.0.1", "rx_bytes": 0,
                             "tx_bytes": 7, "avg_bps": 0}]


def test_build_report_avg_bps_clamps_elapsed_at_one_second(monkeypatch):
    # elapsed 0 must not divide-by-zero: avg_bps = rx / max(elapsed, 1).
    monkeypatch.delenv("IRIS_RUNTIME_MODE", raising=False)
    state = _tele_state({"10.0.0.1": [0, 0]}, total=1000, elapsed=0.0)
    rep = telemetry_report.build_report({}, state, "img-1",
                                        "staging-complete", 100.0)
    assert rep["peers"][0]["rx_bytes"] == 1000
    assert rep["peers"][0]["avg_bps"] == 1000            # 1000 / max(0, 1)


# ---- trim_report(): constrained-tier payload ----

def test_trim_report_drops_peers_marks_trimmed_copies():
    full = {"ts": 1, "image_id": "i", "event": "pull",
            "transfer": {"total_bytes": 9},
            "link": {"tier": "constrained", "rtt_ms_median": 300,
                     "rtt_samples": 8, "hb_failures": 0, "trimmed": False},
            "peers": [{"ip": "10.0.0.1", "rx_bytes": 5, "tx_bytes": 0}],
            "agent": {"version": "unknown", "runtime_mode": "guestshell"}}
    trimmed = telemetry_report.trim_report(full)
    assert trimmed["peers"] == []
    assert trimmed["link"]["trimmed"] is True
    assert trimmed["link"]["tier"] == "constrained"
    assert trimmed["transfer"] == full["transfer"]
    # the ORIGINAL stays intact (a later pull can still send full detail)
    assert full["peers"] == [{"ip": "10.0.0.1", "rx_bytes": 5, "tx_bytes": 0}]
    assert full["link"]["trimmed"] is False


# ---- pull_requested(): garbage-tolerant heartbeat-response parsing ----

@pytest.mark.parametrize("resp", [None, "ok", "", [], {}, 42,
                                  {"report_requested": "yes"},
                                  {"report_requested": 1},
                                  {"report_requested": False},
                                  {"report_requested": None},
                                  ["report_requested"]])
def test_pull_requested_rejects_garbage(resp):
    # captive-portal 200s hand back arbitrary bodies; only an explicit JSON
    # true may trigger a pull ({'report_requested': 1} is NOT `is True`).
    assert telemetry_report.pull_requested(resp) is False


def test_pull_requested_true_only_for_dict_true():
    assert telemetry_report.pull_requested({"report_requested": True}) is True
    assert telemetry_report.pull_requested(
        {"ok": True, "report_requested": True}) is True


# ---- next_backoff_ts(): defer schedule for the 'bad' tier ----

def test_next_backoff_ts_doubles_then_caps():
    t = telemetry_report
    now = 1000.0
    assert t.next_backoff_ts(0, now) == now + 60
    assert t.next_backoff_ts(1, now) == now + 120
    assert t.next_backoff_ts(2, now) == now + 240
    assert t.next_backoff_ts(3, now) == now + 480
    assert t.next_backoff_ts(4, now) == now + 960     # 16-tick cap reached
    assert t.next_backoff_ts(5, now) == now + 960     # stays capped
    assert t.next_backoff_ts(t.MAX_ATTEMPTS, now) == now + 960


# ---- constants are the cross-task contract; pin them ----

def test_module_constants_pin_contract_values():
    t = telemetry_report
    assert (t.PEER_CAP, t.RTT_KEEP, t.GZIP_MIN, t.JITTER_MAX) == \
        (20, 8, 1024, 10.0)
    assert (t.RTT_CONSTRAINED_MS, t.SLOW_BPS, t.FAIL_STREAK_BAD) == \
        (250, 1048576, 3)
    assert (t.BACKOFF_CAP_TICKS, t.MAX_ATTEMPTS) == (16, 60)
    assert (t.ELAPSED_CLAMP, t.TICK_SECONDS) == (180.0, 60)
