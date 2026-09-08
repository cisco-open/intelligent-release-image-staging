# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure-function tests for the device telemetry-report module (issue #13):
toggle parsing, RTT/failure bookkeeping, link-tier classifier boundaries,
peer participation observation (dedup + STATE_PEER_SET_CAP), pull-flag
parsing and defer backoff."""
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


# ---- observe_peers(): participation observation only ----
# Per-peer BYTES are deliberately not tracked: aria2 1.37 exposes only
# instantaneous per-peer speeds, and integrating those over the one-shot
# 60 s tick cadence fabricated data (the even-split fallback fired on every
# multi-peer lab transfer). Only participation is measured.

def test_observe_peers_records_ips_in_observation_order():
    tele = {}
    telemetry_report.observe_peers(
        tele, [{"ip": "10.0.0.2"}, {"ip": "10.0.0.1"}])
    telemetry_report.observe_peers(
        tele, [{"ip": "10.0.0.3"}, {"ip": "10.0.0.1"}])
    assert tele["peers"] == {"10.0.0.2": 1, "10.0.0.1": 2, "10.0.0.3": 1}
    assert list(tele["peers"]) == ["10.0.0.2", "10.0.0.1", "10.0.0.3"]


def test_observe_peers_skips_rows_without_ip():
    tele = {}
    telemetry_report.observe_peers(
        tele, [{"ip": ""}, {}, {"ip": "10.0.0.1"}])
    assert tele["peers"] == {"10.0.0.1": 1}


def test_observe_peers_caps_distinct_ips_at_set_cap():
    tele = {}
    telemetry_report.observe_peers(
        tele, [{"ip": "10.0.%d.%d" % (i // 250, i % 250)}
               for i in range(telemetry_report.STATE_PEER_SET_CAP + 40)])
    assert len(tele["peers"]) == telemetry_report.STATE_PEER_SET_CAP
    # known ips keep counting even when the set is full; new ips are dropped
    first = next(iter(tele["peers"]))
    telemetry_report.observe_peers(
        tele, [{"ip": first}, {"ip": "203.0.113.9"}])
    assert tele["peers"][first] == 2
    assert "203.0.113.9" not in tele["peers"]


def test_observe_peers_discards_legacy_byte_accumulator_state():
    # pre-participation agents persisted {ip: [rx, tx]} + 'other' +
    # 'last_sample_ts'; the accumulators are fabricated -> discard in place,
    # never migrate, never crash (state survives upgrades by design)
    tele = {"peers": {"10.0.0.1": [500, 3]}, "other": [15000, 0, 5],
            "last_sample_ts": 100.0}
    telemetry_report.observe_peers(tele, [{"ip": "10.0.0.9"}])
    assert tele["peers"] == {"10.0.0.9": 1}
    assert "other" not in tele and "last_sample_ts" not in tele


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

@pytest.mark.parametrize("tick_seconds", [1, 60, 300, 900])
def test_next_backoff_ts_doubles_then_caps_in_mechanical_ticks(tick_seconds):
    t = telemetry_report
    now = 1000.0
    for attempts, multiplier in ((0, 1), (1, 2), (2, 4), (3, 8),
                                 (4, 16), (5, 16), (t.MAX_ATTEMPTS, 16)):
        assert t.next_backoff_ts(
            attempts, now, tick_seconds=tick_seconds
        ) == now + multiplier * tick_seconds


# ---- constants are the cross-task contract; pin them ----

def test_module_constants_pin_contract_values():
    t = telemetry_report
    assert (t.PEER_CAP, t.RTT_KEEP, t.GZIP_MIN, t.JITTER_MAX) == \
        (64, 8, 1024, 10.0)
    assert (t.RTT_CONSTRAINED_MS, t.SLOW_BPS, t.FAIL_STREAK_BAD) == \
        (250, 1048576, 3)
    assert (t.BACKOFF_CAP_TICKS, t.MAX_ATTEMPTS) == (16, 60)
    assert t.STATE_PEER_SET_CAP == 512


# ---- live streaming samples (device transfer telemetry spec, section 5) ----

class TestStreamOptIn:
    def test_default_off(self):
        assert not telemetry_report.stream_enabled({"telemetry": "on"})

    def test_explicit_values_enable(self):
        for v in ("on", "1", "true", "YES", " On "):
            cfg = {"telemetry": "on", "telemetry_stream": v}
            assert telemetry_report.stream_enabled(cfg), v

    def test_garbage_stays_off_fail_closed(self):
        for v in ("enabled", "On!", "", "  ", "off", "0", "no", None, 1):
            cfg = {"telemetry": "on", "telemetry_stream": v}
            assert not telemetry_report.stream_enabled(cfg), v

    def test_requires_master_toggle(self):
        assert not telemetry_report.stream_enabled(
            {"telemetry": "off", "telemetry_stream": "on"})


class TestStreamDirectives:
    def test_parse_defaults_on_garbage(self):
        for resp in (None, [], "x", 7,
                     {"stream_every": "4"}, {"stream_every": True},
                     {"stream_every": 0}, {"stream_every": 61},
                     {"stream_pause": 1}, {"stream_pause": "true"}):
            assert telemetry_report.parse_stream_directives(resp) == (1, False)

    def test_parse_valid(self):
        assert telemetry_report.parse_stream_directives(
            {"stream_every": 10, "stream_pause": True}) == (10, True)

    def test_store_overwrites_always_and_none_leaves_untouched(self):
        state = {}
        telemetry_report.store_directives(state, {"stream_every": 5}, 100.0)
        assert state["stream_directives"] == {
            "every": 5, "pause": False, "received_ts": 100.0}
        telemetry_report.store_directives(state, None, 200.0)
        assert state["stream_directives"]["received_ts"] == 100.0
        telemetry_report.store_directives(state, {}, 300.0)
        assert state["stream_directives"] == {
            "every": 1, "pause": False, "received_ts": 300.0}

    @pytest.mark.parametrize("tick_seconds", [1, 60, 300, 900])
    def test_active_fresh_for_exactly_three_mechanical_ticks(
            self, tick_seconds):
        state = {}
        telemetry_report.store_directives(
            state, {"stream_every": 8, "stream_pause": True}, 1000.0)
        assert telemetry_report.active_directives(
            state, 1000.0 + 3 * tick_seconds,
            tick_seconds=tick_seconds) == (8, True)
        assert telemetry_report.active_directives(
            state, 1000.001 + 3 * tick_seconds,
            tick_seconds=tick_seconds) == (1, False)

    def test_future_directive_timestamp_fails_safely(self):
        state = {}
        telemetry_report.store_directives(
            state, {"stream_every": 8, "stream_pause": True}, 1001.0)
        assert telemetry_report.active_directives(
            state, 1000.0, tick_seconds=300) == (1, False)

    def test_active_tolerates_hand_edited_state(self):
        for junk in ("x", {"every": "9", "received_ts": "soon"},
                     {"every": 99, "pause": True, "received_ts": 100.0}):
            state = {"stream_directives": junk}
            every, pause = telemetry_report.active_directives(
                state, 100.0, tick_seconds=60)
            assert every == 1


class TestShouldSample:
    def test_bad_tier_never_samples(self):
        assert not telemetry_report.should_sample(
            {}, {}, "bad", 0.0, tick_seconds=60)

    def test_pause_suppresses(self):
        state = {}
        telemetry_report.store_directives(state, {"stream_pause": True}, 100.0)
        assert not telemetry_report.should_sample(
            state, {}, "good", 100.0, tick_seconds=60)

    @pytest.mark.parametrize("tick_seconds", [1, 60, 300, 900])
    def test_good_tier_every_tick_with_half_tick_slop(
            self, tick_seconds):
        tele = {"stream_last_ts": 1000.0}
        boundary = 1000.0 + 0.5 * tick_seconds
        assert telemetry_report.should_sample(
            {}, tele, "good", boundary, tick_seconds=tick_seconds)
        assert not telemetry_report.should_sample(
            {}, tele, "good", boundary - 0.001,
            tick_seconds=tick_seconds)

    def test_constrained_every_fourth_tick(self):
        tele = {"stream_last_ts": 1000.0}
        assert not telemetry_report.should_sample(
            {}, tele, "constrained", 2049.999, tick_seconds=300)
        assert telemetry_report.should_sample(
            {}, tele, "constrained", 2050.0, tick_seconds=300)

    def test_stream_every_stretches_good_tier(self):
        state = {}
        # The heartbeat has renewed this directive inside its three-tick
        # freshness window even though the last sample is much older.
        telemetry_report.store_directives(state, {"stream_every": 10}, 3000.0)
        tele = {"stream_last_ts": 1000.0}
        assert not telemetry_report.should_sample(
            state, tele, "good", 3849.999, tick_seconds=300)
        assert telemetry_report.should_sample(
            state, tele, "good", 3850.0, tick_seconds=300)

    def test_future_sample_timestamp_fails_safely(self):
        assert not telemetry_report.should_sample(
            {}, {"stream_last_ts": 1001.0}, "good", 1000.0,
            tick_seconds=300)


class TestConfDefault:
    def test_telemetry_stream_defaults_off(self):
        import agent_config
        assert agent_config.DEFAULTS["telemetry_stream"] == "off"
