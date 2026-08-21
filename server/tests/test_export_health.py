# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 23: per-signal OTLP export health (design §10.10). Logs and metrics are
INDEPENDENT signals (off|ok|degraded); the aggregate is worst_of so a metrics
success can never mask a logs failure. Disabling a signal sets it off while
retaining its historic last success. Audit transitions fire exactly once per
signal edge and once per aggregate edge, and never carry secrets."""

import telemetry


class _Q:
    """Minimal log-queue stand-in exposing queued/dropped_total."""
    def __init__(self, queued=0, dropped=0):
        self.queued = queued
        self.dropped_total = dropped


def _health(**kw):
    return telemetry.ExportHealth(**kw)


def test_signals_independent_worst_of_metrics_cannot_mask_logs():
    h = _health()
    h.record(False, "logs", 100.0)          # logs degraded
    h.record(True, "metrics", 101.0)        # metrics ok
    d = h.as_dict()
    assert d["aggregate_rule"] == "worst_of"
    assert d["signals"]["logs"]["state"] == "degraded"
    assert d["signals"]["metrics"]["state"] == "ok"
    assert d["state"] == "degraded"         # worst-of, not masked


def test_signal_starts_off_until_first_attempt():
    d = _health().as_dict()
    assert d["signals"]["logs"]["state"] == "off"
    assert d["signals"]["metrics"]["state"] == "off"
    assert d["state"] == "off"


def test_queue_depth_and_drops_surface_on_logs_signal():
    h = _health(log_queue=_Q(queued=12, dropped=4))
    h.record(True, "logs", 100.0)
    logs = h.as_dict()["signals"]["logs"]
    assert logs["queued"] == 12
    assert logs["dropped_total"] == 4
    # metrics signal has no queue fields
    assert "queued" not in h.as_dict()["signals"]["metrics"]


def test_disable_sets_off_but_retains_last_success():
    h = _health()
    h.record(True, "logs", 150.0)
    assert h.as_dict()["signals"]["logs"]["last_success_ts"] == 150.0
    h.disable("logs")
    logs = h.as_dict()["signals"]["logs"]
    assert logs["state"] == "off"
    assert logs["last_success_ts"] == 150.0     # historic success retained


def test_recovery_sequence_logs_fail_then_success():
    edges = []
    h = _health(on_transition=lambda name: edges.append(name))
    h.record(False, "logs", 100.0)          # -> degraded (edge)
    h.record(False, "logs", 101.0)          # still degraded (no edge)
    h.record(True, "logs", 102.0)           # -> ok (recovery edge)
    d = h.as_dict()
    assert d["signals"]["logs"]["state"] == "ok"
    assert d["signals"]["logs"]["fail_streak"] == 0
    # exactly one degrade edge + one recovery edge per signal transition
    assert edges.count("otlp-export-degraded") == 1
    assert edges.count("otlp-export-recovered") == 1


def test_audit_transition_once_per_edge_no_secrets():
    names = []
    h = _health(on_transition=lambda name: names.append(name))
    for _ in range(5):
        h.record(False, "logs", 100.0)      # only the first is an edge
    assert names.count("otlp-export-degraded") == 1
    # transition names carry no header/URL/token text
    assert all("Bearer" not in n and "http" not in n and "token" not in n
               for n in names)


def test_healthz_shape_matches_spec():
    h = _health(log_queue=_Q(queued=12, dropped=0))
    h.record(False, "logs", 100.0)
    h.record(True, "metrics", 195.0)
    d = h.as_dict()
    assert set(d) >= {"state", "aggregate_rule", "signals"}
    assert set(d["signals"]) == {"logs", "metrics"}
    logs = d["signals"]["logs"]
    assert set(logs) >= {"state", "last_success_ts", "fail_streak",
                         "queued", "dropped_total", "failures_total"}
