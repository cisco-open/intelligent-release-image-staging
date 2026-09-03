# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 14: the sole tracker reconcile loop, pending endpoint retries, and the
policy operation-outbox export (spec §0 / §7 / §13).

The tracker is the ONLY blocklist reconciler and the ONLY writer of the aria2
blocklist RPC. These tests drive :class:`tracker.TrackerReconciler` directly
(deterministic ``run_once``) and end-to-end via its background loop to prove the
≤2-second cross-process durable polling, the local-wake path, no overlapping
runs, startup/session/RPC recovery full apply, fail-closed emergency apply that
never clears blocks, pending-retry-without-announce, and revision-ordered outbox
export gated on both intended enqueue and the audit contract.
"""
import json
import os
import threading
import time

import auth
import peer_endpoints
import peer_policy
import peer_enforcement
import telemetry
import tracker
from peer_registry import PeerRegistry


# ---------------------------------------------------------------------------
# Fakes / fixtures
# ---------------------------------------------------------------------------

class FakeAria:
    """Records setBtPeerBlocklist calls; models a mutable session id."""

    def __init__(self, session="sess-1", raise_on_call=False):
        self.session = session
        self.raise_on_call = raise_on_call
        self.calls = []
        self.revision = 7

    def get_session_id(self):
        return self.session

    def set_blocklist(self, ips):
        self.calls.append(list(ips))
        if self.raise_on_call:
            raise RuntimeError("rpc down")
        return {"revision": self.revision, "disconnectedPeers": 0,
                "removedPeers": 0}


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _paths(tmp_path):
    return {
        "policy": str(tmp_path / "peer-policy.json"),
        "lkg": str(tmp_path / "peer-policy.lkg.json"),
        "endpoints": str(tmp_path / "peer-endpoints.json"),
        "enforcement": str(tmp_path / "peer-enforcement.json"),
        "audit": str(tmp_path / "audit.jsonl"),
    }


def _make_reconciler(tmp_path, aria, clock=None, active_provider=None,
                      revoked_provider=None, protected_seeder_ip=None,
                      pending=None, audit_ok=True, emit_policy_event=None):
    p = _paths(tmp_path)
    peer_policy.initialize(p["policy"], p["lkg"])
    audit_calls = []

    def audit_export(entries):
        audit_calls.append(list(entries))
        if not audit_ok:
            raise RuntimeError("audit failed")

    rec = tracker.TrackerReconciler(
        policy_paths=(p["policy"], p["lkg"]),
        endpoints_path=p["endpoints"],
        enforcement_path=p["enforcement"],
        aria=aria,
        pending_queue=pending if pending is not None
        else peer_endpoints.PendingEndpointQueue(),
        active_participants=active_provider or (lambda: []),
        revoked_principals=revoked_provider or (lambda: set()),
        protected_seeder_ip=protected_seeder_ip,
        audit_export=audit_export,
        emit_policy_event=emit_policy_event,
        now=clock or time.time)
    return rec, p, audit_calls


def _quarantine(policy, lkg, device_id, now):
    def mutate(doc):
        doc["assignments"][device_id] = peer_policy.RESERVED_QUARANTINE

    return peer_policy.commit_mutation(
        policy, lkg, "assign", device_id, "op", now, mutate)


def _dev(id_):
    return auth.Principal("device", id_)


# ---------------------------------------------------------------------------
# Sole construction + serialized run
# ---------------------------------------------------------------------------

def test_reconciler_applies_valid_empty_on_startup(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria)
    rec.run_once()
    # A valid (empty) policy forces one full apply on startup, even empty.
    assert aria.calls == [[]]
    status = peer_enforcement.read_status(p["enforcement"])
    assert status["state"] == "enforced"
    assert status["desired_ip_count"] == 0


def test_quarantined_device_endpoint_is_blocked(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    assert aria.calls[-1] == ["10.0.0.9"]
    assert peer_enforcement.read_status(p["enforcement"])["desired_ip_count"] == 1


def test_corrupt_endpoints_retain_blocklist_and_report_fail_closed(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    assert aria.calls == [["10.0.0.9"]]
    with open(p["endpoints"], "w") as f:
        f.write("{ corrupt")
    status = rec.run_once()
    assert aria.calls == [["10.0.0.9"]]
    assert status["state"] == "fail_closed"
    assert status["last_error"] == "EndpointStoreError"
    assert status["desired_ip_count"] == 1


def test_shared_ip_conflict_applies_other_blocks_but_reports_degraded(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    for device_id in ("denied-shared", "denied-only"):
        _quarantine(p["policy"], p["lkg"], device_id, 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("denied-shared"),
                                   "10.0.0.9", 6881, 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("permitted"),
                                   "10.0.0.9", 6881, 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("denied-only"),
                                   "10.0.0.10", 6881, 1000.0)
    status = rec.run_once()
    assert aria.calls[-1] == ["10.0.0.10"]
    assert status["state"] == "degraded"
    assert len(status["conflicts"]) == 1


def test_running_flag_prevents_overlap_and_schedules_rerun(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria)
    # Simulate a run already in progress; a request_run must not run
    # concurrently but must mark dirty so exactly one rerun happens afterwards.
    assert rec.request_run() is True     # claim the (simulated) in-progress run
    scheduled = rec.request_run()
    assert scheduled is False            # did not claim a second concurrent run
    assert rec._dirty is True
    # releasing + draining the dirty flag triggers exactly one more run
    with rec._run_lock:
        rec._running = False
    ran = rec.drain_pending()
    assert ran is True
    assert rec._dirty is False


# ---------------------------------------------------------------------------
# Startup / session change / RPC recovery force full apply
# ---------------------------------------------------------------------------

def test_session_change_forces_full_reapply(tmp_path):
    aria = FakeAria(session="sess-1")
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    n = len(aria.calls)
    # No durable change; same session -> may skip a redundant apply, but a
    # session change must always force a full reapply of the valid desired list.
    aria.session = "sess-2"
    rec.run_once()
    assert len(aria.calls) == n + 1
    assert aria.calls[-1] == ["10.0.0.9"]


def test_rpc_unreachable_then_reachable_reapplies(tmp_path):
    aria = FakeAria(raise_on_call=True)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["state"] in ("degraded", "rpc_unavailable")
    # recovery: RPC now succeeds -> full reapply
    aria.raise_on_call = False
    rec.run_once()
    assert aria.calls[-1] == ["10.0.0.9"]
    assert peer_enforcement.read_status(p["enforcement"])["state"] == "enforced"


# ---------------------------------------------------------------------------
# fail_closed emergency: never clears, emergency deny
# ---------------------------------------------------------------------------

def test_fail_closed_never_clears_and_emergency_denies(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    peer_endpoints.record_endpoint(p["endpoints"], _dev("d1"),
                                   "10.0.0.9", 6881, 1000.0)
    # Corrupt BOTH policy files -> fail_closed.
    with open(p["policy"], "w") as f:
        f.write("{ broken")
    with open(p["lkg"], "w") as f:
        f.write("{ broken")
    rec.run_once()
    # emergency list includes the fresh attributable non-service endpoint
    assert aria.calls[-1] == ["10.0.0.9"]
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["state"] == "fail_closed"


def test_fail_closed_no_known_address_no_false_enforced(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria)
    with open(p["policy"], "w") as f:
        f.write("{ broken")
    with open(p["lkg"], "w") as f:
        f.write("{ broken")
    rec.run_once()
    # nothing to apply and no address known -> no RPC call, no false success
    assert aria.calls == []
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["state"] == "fail_closed"


# ---------------------------------------------------------------------------
# Pending endpoint retry without a new announce
# ---------------------------------------------------------------------------

def test_pending_endpoint_retried_each_pass_without_announce(tmp_path):
    aria = FakeAria()
    pending = peer_endpoints.PendingEndpointQueue()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 pending=pending)
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    # a pending (not-yet-durable) endpoint for the quarantined device
    pending.enqueue(_dev("bad"), "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    # pending affects desired immediately
    assert aria.calls[-1] == ["10.0.0.9"]
    # retry made it durable; queue drained
    assert len(pending) == 0
    snap = peer_endpoints.fresh_endpoints(p["endpoints"], 1000.0)
    assert "device:bad" in snap


def test_pending_degrades_until_durable(tmp_path):
    aria = FakeAria()
    pending = peer_endpoints.PendingEndpointQueue()
    calls = {"n": 0}

    def flaky_record(path, principal, ipv4, port, now):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return peer_endpoints.record_endpoint(path, principal, ipv4, port, now)

    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 pending=pending)
    rec._record_endpoint = flaky_record
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    pending.enqueue(_dev("bad"), "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    # first retry failed -> still pending, status degraded
    assert len(pending) == 1
    assert peer_enforcement.read_status(p["enforcement"])["state"] == "degraded"
    rec.run_once()
    assert len(pending) == 0
    assert peer_enforcement.read_status(p["enforcement"])["state"] == "enforced"


# ---------------------------------------------------------------------------
# Outbox export, revision order, ack watermark, restart replay
# ---------------------------------------------------------------------------

def test_outbox_exports_in_revision_order_and_advances_ack(tmp_path):
    aria = FakeAria()
    rec, p, audit_calls = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    _quarantine(p["policy"], p["lkg"], "b", 1000.0)
    rec.run_once()
    exported = audit_calls[-1]
    revs = [e["revision"] for e in exported]
    assert revs == sorted(revs)
    assert revs[-1] >= 3
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["last_operation_exported_revision"] == revs[-1]


def test_multiple_operations_before_poll_all_exported(tmp_path):
    aria = FakeAria()
    rec, p, audit_calls = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    _quarantine(p["policy"], p["lkg"], "b", 1000.0)
    _quarantine(p["policy"], p["lkg"], "c", 1000.0)
    rec.run_once()
    exported = audit_calls[-1]
    # every outbox revision above the (zero) ack is exported at least once
    assert len(exported) >= 3


def test_ack_not_advanced_when_audit_contract_fails(tmp_path):
    aria = FakeAria()
    hub = telemetry.Telemetry(PeerRegistry())
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 audit_ok=False,
                                 emit_policy_event=hub.emit_policy_event)
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    st = peer_enforcement.read_status(p["enforcement"])
    # audit failed -> ack revision NOT advanced (replay on next pass)
    assert st["last_operation_exported_revision"] == 0
    assert hub.log_queue.queued == 0       # audit is intentionally first


def test_policy_operation_audits_then_queues_canonical_stable_event(tmp_path):
    aria = FakeAria()
    hub = telemetry.Telemetry(PeerRegistry())
    rec, p, audit_calls = _make_reconciler(
        tmp_path, aria, clock=Clock(1000.0),
        emit_policy_event=hub.emit_policy_event)
    committed = _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    assert audit_calls
    event = hub.log_queue.snapshot()[0]
    assert event["eventName"] == "iris.peer.policy"
    assert telemetry._otlp_record_event_id(event) == \
        committed["operation_outbox"][-1]["event_id"]
    attrs = {attr["key"]: attr["value"] for attr in event["attributes"]}
    assert attrs["iris.enforcement.state"] == {"stringValue": "enforced"}
    assert "10.0.0" not in json.dumps(event)
    assert peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"] == \
        committed["operation_outbox"][-1]["revision"]


def test_ack_not_advanced_when_policy_queue_emit_fails(tmp_path):
    aria = FakeAria()
    rec, p, audit_calls = _make_reconciler(
        tmp_path, aria, clock=Clock(1000.0),
        emit_policy_event=lambda entry, status: (_ for _ in ()).throw(
            RuntimeError("queue failed")))
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    assert audit_calls
    assert peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"] == 0


def test_disabled_transport_still_accepts_and_acks_policy_event(tmp_path):
    aria = FakeAria()
    hub = telemetry.Telemetry(PeerRegistry())
    rec, p, _ = _make_reconciler(
        tmp_path, aria, clock=Clock(1000.0),
        emit_policy_event=hub.emit_policy_event)
    committed = _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    assert hub.exporter is None
    assert telemetry._otlp_record_event_id(hub.log_queue.snapshot()[0]) == \
        committed["operation_outbox"][-1]["event_id"]
    assert peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"] == \
        committed["operation_outbox"][-1]["revision"]


def test_policy_queue_replay_keeps_persisted_event_id(tmp_path):
    aria = FakeAria()
    emitted = []
    rec, p, _ = _make_reconciler(
        tmp_path, aria, clock=Clock(1000.0),
        emit_policy_event=lambda entry, status: emitted.append(
            entry["event_id"]) or False)
    committed = _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    assert emitted == [committed["operation_outbox"][-1]["event_id"]]
    assert peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"] == 0
    rec._emit_policy_event = lambda entry, status: emitted.append(entry["event_id"])
    rec.run_once()
    assert emitted == [committed["operation_outbox"][-1]["event_id"]] * 2


def test_export_replays_after_restart(tmp_path):
    aria = FakeAria()
    rec, p, audit_calls = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                           audit_ok=False)
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    first = audit_calls[-1]
    # "restart": build a fresh reconciler over the same files; the un-acked
    # entries must replay with stable event_ids.
    aria2 = FakeAria()
    p2 = _paths(tmp_path)
    ok_audit = []
    rec2 = tracker.TrackerReconciler(
        policy_paths=(p2["policy"], p2["lkg"]),
        endpoints_path=p2["endpoints"], enforcement_path=p2["enforcement"],
        aria=aria2, pending_queue=peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: [], revoked_principals=lambda: set(),
        protected_seeder_ip=None,
        audit_export=lambda entries: ok_audit.append(list(entries)),
        now=Clock(1001.0))
    rec2.run_once()
    replayed = ok_audit[-1]
    assert {e["event_id"] for e in first} == {e["event_id"] for e in replayed}


# ---------------------------------------------------------------------------
# Cross-process ≤2 second durable polling + local wake, real background loop
# ---------------------------------------------------------------------------

def test_cross_process_policy_observed_within_two_seconds(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.start()
    try:
        # an independent process writes a quarantine assignment + endpoint
        _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
        peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                       "10.0.0.9", 6881, 1000.0)
        deadline = time.time() + 3.5
        seen = False
        while time.time() < deadline:
            st = peer_enforcement.read_status(p["enforcement"])
            if st and st.get("desired_ip_count") == 1:
                seen = True
                break
            time.sleep(0.1)
        assert seen, "tracker did not observe durable policy within ~2s"
    finally:
        rec.stop()


def test_local_wake_runs_immediately(tmp_path):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.start()
    try:
        _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
        peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                       "10.0.0.9", 6881, 1000.0)
        rec.wake()   # tracker-authored change: immediate wake, no poll wait
        deadline = time.time() + 1.0
        seen = False
        while time.time() < deadline:
            st = peer_enforcement.read_status(p["enforcement"])
            if st and st.get("desired_ip_count") == 1:
                seen = True
                break
            time.sleep(0.02)
        assert seen
    finally:
        rec.stop()


# ---------------------------------------------------------------------------
# Dead-poll gate: an idle bare poll with nothing to do does no RPC work, but
# maintenance/recovery semantics still eventually run (spec §0 / §7 / §13).
# ---------------------------------------------------------------------------

class CountingAria(FakeAria):
    """FakeAria that also counts get_session_id probes (RPC touches)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.session_probes = 0

    def get_session_id(self):
        self.session_probes += 1
        return super().get_session_id()


def test_idle_bare_poll_does_not_run_reconcile(tmp_path):
    """A steady-state bare poll (<=2s, unchanged stat keys, empty pending, no
    dirty/wake, healthy known RPC/session) must NOT invoke run_once /
    getSessionInfo / reconcile: the gate suppresses the redundant per-2s RPC."""
    aria = CountingAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    # First converged pass: healthy, known session, empty pending.
    rec.run_once()
    calls_before = len(aria.calls)
    probes_before = aria.session_probes

    # Simulate a converged loop: seed poll keys and a far-future maintenance
    # deadline so only a genuine change would justify running.
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    rec._next_maintenance = 1_000_000.0

    # Ten consecutive idle bare polls (waked=False) with nothing changed.
    for _ in range(10):
        assert rec._poll_should_run(waked=False) is False
    # No apply and no session probe happened from the gate deciding "skip".
    assert len(aria.calls) == calls_before
    assert aria.session_probes == probes_before


def test_external_file_change_still_runs_on_bare_poll(tmp_path):
    """An external (other-process) durable stat change must still execute on a
    bare poll even without a local wake."""
    aria = CountingAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.run_once()
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    rec._next_maintenance = 1_000_000.0
    # Another process writes a quarantine + endpoint.
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    assert rec._poll_should_run(waked=False) is True


def test_pending_work_still_runs_on_bare_poll(tmp_path):
    """Outstanding pending work must run on a bare poll (retry-without-announce
    semantics), even with unchanged stat keys."""
    aria = CountingAria()
    pending = peer_endpoints.PendingEndpointQueue()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 pending=pending)
    rec.run_once()
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    rec._next_maintenance = 1_000_000.0
    pending.enqueue(_dev("bad"), "10.0.0.9", 6881, 1000.0)
    assert rec._poll_should_run(waked=False) is True


def test_rpc_recovery_still_runs_on_bare_poll(tmp_path):
    """A prior RPC failure (unhealthy) must let a bare poll run so recovery is
    detected without waiting for a file change or a wake."""
    aria = CountingAria(raise_on_call=True)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()   # RPC down -> unhealthy
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    rec._next_maintenance = 1_000_000.0
    # Nothing changed on disk, no wake, but unhealthy RPC -> must still run.
    assert rec._poll_should_run(waked=False) is True


def test_wake_always_runs_even_when_idle(tmp_path):
    """A local wake always runs regardless of the gate."""
    aria = CountingAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.run_once()
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    rec._next_maintenance = 1_000_000.0
    assert rec._poll_should_run(waked=True) is True


def test_maintenance_deadline_is_bounded_not_never(tmp_path):
    """The maintenance deadline must be a bounded finite value (endpoint TTL /
    periodic health), never disabled, so TTL prune / recovery eventually runs
    even with no file change and no wake."""
    aria = CountingAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.run_once()
    # A finite, bounded next deadline was scheduled.
    assert rec._next_maintenance is not None
    assert rec._next_maintenance < float("inf")
    # It is within one endpoint-TTL horizon of now (bounded upper bound).
    assert rec._next_maintenance <= 1000.0 + peer_endpoints.endpoint_ttl()


def test_reached_maintenance_deadline_runs_on_bare_poll(tmp_path):
    """When the bounded maintenance deadline has passed, a bare poll runs so
    endpoint TTL prune / periodic reconciliation happens without a change."""
    aria = CountingAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock)
    rec.run_once()
    rec._poll_keys = (tracker._stat_key(p["policy"]),
                      tracker._stat_key(p["endpoints"]))
    # Advance time past the maintenance deadline.
    clock.t = rec._next_maintenance + 1.0
    assert rec._poll_should_run(waked=False) is True


# ---------------------------------------------------------------------------
# Retry pending must preserve the ORIGINAL observed_at (retry cannot extend
# endpoint TTL beyond the moment of first observation).
# ---------------------------------------------------------------------------

def test_retry_pending_preserves_original_observed_at(tmp_path):
    """A pending endpoint enqueued at t0 that only becomes durable on a later
    pass at t1 must be persisted with observed_at == t0, NOT t1 — otherwise a
    stuck retry would silently extend the endpoint's TTL indefinitely."""
    aria = FakeAria()
    pending = peer_endpoints.PendingEndpointQueue()
    calls = {"n": 0}

    def flaky_record(path, principal, ipv4, port, now):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return peer_endpoints.record_endpoint(path, principal, ipv4, port, now)

    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock, pending=pending)
    rec._record_endpoint = flaky_record
    # Enqueue at t0 = 1000.0 (the true observation time).
    pending.enqueue(_dev("bad"), "10.0.0.9", 6881, 1000.0)
    rec.run_once()                 # first retry fails, stays pending
    assert len(pending) == 1
    # A much later pass finally writes it durably.
    clock.t = 1500.0
    rec.run_once()
    assert len(pending) == 0
    doc = json.loads(open(p["endpoints"]).read())
    ep = doc["principals"]["device:bad"]["endpoints"][0]
    # observed_at must be the original t0, not the retry pass time (1500.0).
    assert ep["observed_at"] == 1000.0


# ---------------------------------------------------------------------------
# _active_participants must be defensive: a malformed/legacy registry row with
# missing typed fields cannot crash the emergency (fail-closed) pass.
# ---------------------------------------------------------------------------

class _FakeRegistry:
    def __init__(self, snapshot):
        self._snap = snapshot

    def snapshot(self):
        return self._snap


def test_active_participants_tolerates_malformed_rows():
    """Missing/None typed fields (legacy residue, partial rows) must be skipped
    or defaulted — never raise KeyError."""
    reg = _FakeRegistry({
        "hashA": [
            {"principal_type": "device", "principal_id": "d1", "ip": "10.0.0.1"},
            {"principal_id": "d2", "ip": "10.0.0.2"},          # no type
            {"principal_type": "device", "ip": "10.0.0.3"},    # no id
            {"principal_type": "device", "principal_id": "d4"},  # no ip
            {},                                                  # empty
        ],
    })
    rows = tracker._active_participants(reg)
    # No crash; valid rows survive, and every emitted row exposes the three keys.
    for r in rows:
        assert "principal_type" in r
        assert "principal_id" in r
        assert "ipv4" in r
    ips = {r["ipv4"] for r in rows}
    assert "10.0.0.1" in ips


def test_emergency_pass_survives_malformed_active_row(tmp_path):
    """A malformed active participant row must not crash the fail-closed
    emergency reconcile pass."""
    aria = FakeAria()

    def bad_active():
        return [{"ip": "10.0.0.5"}]  # missing principal_type/id (legacy-ish)

    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 active_provider=bad_active)
    with open(p["policy"], "w") as f:
        f.write("{ broken")
    with open(p["lkg"], "w") as f:
        f.write("{ broken")
    # Must not raise.
    rec.run_once()
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["state"] == "fail_closed"


# ---------------------------------------------------------------------------
# No-leak: an aria RPC exception whose message embeds the RPC secret must never
# surface in the enforcement status / error / output (only the exception TYPE).
# ---------------------------------------------------------------------------

SECRET_SENTINEL = "SUPER-SECRET-RPC-TOKEN-abc123"


class LeakyAria:
    """Every RPC entry point raises an exception whose message embeds the RPC
    secret, exactly as a naive transport error would."""

    class _Boom(RuntimeError):
        pass

    def get_session_id(self):
        raise self._Boom("connect failed url=http://x/?secret=%s"
                          % SECRET_SENTINEL)

    def set_blocklist(self, ips):
        raise self._Boom("apply failed url=http://x/?secret=%s"
                          % SECRET_SENTINEL)


def test_session_probe_exception_never_leaks_secret(tmp_path):
    aria = LeakyAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    # Probe + apply both raise with the secret in the message — must not raise
    # and must not persist the secret anywhere.
    rec.run_once()
    raw = open(p["enforcement"]).read()
    assert SECRET_SENTINEL not in raw
    st = peer_enforcement.read_status(p["enforcement"])
    for field in ("last_error", "last_effect", "aria_session_id",
                  "desired_hash"):
        assert SECRET_SENTINEL not in json.dumps(st.get(field))
    # The recorded error, if any, is the exception TYPE name only.
    assert st.get("last_error") in (None, "_Boom")


# ---------------------------------------------------------------------------
# Outbox ack watermark: a later status write with NO new operations must never
# reset the previously-acked revision back down (regression).
# ---------------------------------------------------------------------------

def test_ack_watermark_preserved_across_non_operation_passes(tmp_path):
    aria = FakeAria()
    rec, p, audit_calls = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    _quarantine(p["policy"], p["lkg"], "b", 1000.0)
    rec.run_once()
    acked = peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"]
    assert acked >= 3
    # Several subsequent passes with NO new policy operations must preserve the
    # watermark — a status write must not reset it to 0.
    for _ in range(3):
        rec.run_once()
        st = peer_enforcement.read_status(p["enforcement"])
        assert st["last_operation_exported_revision"] == acked


def test_ack_watermark_survives_status_only_write_after_audit_disabled(tmp_path):
    """Even if the audit exporter is unavailable on a later pass (best-effort
    off), a status-only write must not reset the prior ack watermark."""
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    acked = peer_enforcement.read_status(
        p["enforcement"])["last_operation_exported_revision"]
    assert acked >= 2
    # Drop the audit exporter; a further pass writes status only.
    rec._audit_export = None
    rec.run_once()
    st = peer_enforcement.read_status(p["enforcement"])
    assert st["last_operation_exported_revision"] == acked


# ---------------------------------------------------------------------------
# IRIS-04-001: the sole reconcile loop survives a failed pass
# ---------------------------------------------------------------------------

def test_loop_survives_write_status_failure_and_recovers(tmp_path, monkeypatch):
    """ENOSPC (any OSError) from write_status used to unwind the reconciler
    thread for good while peer-enforcement.json kept its last `enforced`
    claim. The loop must live on and apply the next change once the disk is
    writable again."""
    aria = FakeAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock)
    rec.run_once()
    assert peer_enforcement.read_status(p["enforcement"])["state"] == "enforced"

    def enospc(path, status):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(tracker._peer_enforcement, "write_status", enospc)
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    rec._safe_run()                    # what _loop calls: must not raise
    assert rec._next_maintenance is None       # next poll retries
    assert rec._poll_should_run(waked=False) is True
    monkeypatch.undo()
    rec._safe_run()
    status = peer_enforcement.read_status(p["enforcement"])
    assert status["state"] == "enforced"
    assert status["desired_ip_count"] == 1
    assert aria.calls[-1] == ["10.0.0.9"]


def test_failed_pass_is_recorded_as_degraded_with_error_type(tmp_path,
                                                            monkeypatch):
    """When the failure is not in the status writer itself the degraded
    status (last_error = exception TYPE, never its text) reaches the file, so
    the console does not keep showing a frozen `enforced`."""
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    rec.run_once()

    def boom(*args, **kwargs):
        raise RuntimeError("secret-bearing rpc text")
    monkeypatch.setattr(tracker._reconciler, "derive_denied_set", boom)
    rec._safe_run()
    status = peer_enforcement.read_status(p["enforcement"])
    assert status["state"] == "degraded"
    assert status["last_error"] == "RuntimeError"
    with open(p["enforcement"]) as f:
        assert "secret-bearing" not in f.read()
    monkeypatch.undo()
    assert rec._safe_run() is None
    assert peer_enforcement.read_status(p["enforcement"])["state"] == "enforced"


def test_loop_thread_stays_alive_across_a_failing_pass(tmp_path, monkeypatch):
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria)
    calls = {"n": 0}
    real = tracker._reconciler.derive_denied_set

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("first pass breaks")
        return real(*args, **kwargs)
    monkeypatch.setattr(tracker._reconciler, "derive_denied_set", flaky)
    rec.start()
    try:
        deadline = time.time() + 5
        while calls["n"] < 2 and time.time() < deadline:
            rec.wake()
            time.sleep(0.05)
        assert calls["n"] >= 2
        assert rec._thread.is_alive()
    finally:
        rec.stop()


def test_entry_level_corrupt_endpoint_file_is_fail_closed_not_a_crash(tmp_path):
    """A schema-valid endpoint file whose ROW is malformed (missing ipv4, a
    string observed_at, a non-IPv4 rule) used to escape run_once as
    KeyError / TypeError / AddressValueError. It is store corruption and
    takes the fail_closed path like unparseable JSON."""
    aria = FakeAria()
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0))
    _quarantine(p["policy"], p["lkg"], "x", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("x"),
                                   "10.0.0.9", 6881, 1000.0)
    rec.run_once()
    assert aria.calls == [["10.0.0.9"]]
    for row in ({"port": 6881, "observed_at": 1000.0},
                {"ipv4": "10.0.0.1", "port": 6881, "observed_at": "now"},
                {"ipv4": "fe80::1", "port": 6881, "observed_at": 1000.0}):
        with open(p["endpoints"], "w") as f:
            json.dump({"schema": 1, "updated_at": 0.0, "principals": {
                "device:x": {"principal_type": "device", "principal_id": "x",
                             "updated_at": 0.0, "endpoints": [row]}}}, f)
        status = rec.run_once()
        assert status["state"] == "fail_closed"
        assert status["last_error"] == "EndpointStoreError"
        assert aria.calls == [["10.0.0.9"]]      # never cleared


# ---------------------------------------------------------------------------
# IRIS-04-005: a quarantined/revoked device's block does not lapse on TTL
# ---------------------------------------------------------------------------

def test_quarantined_device_block_survives_endpoint_ttl(tmp_path):
    aria = FakeAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock)
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("good"),
                                   "10.0.0.8", 6881, 1000.0)
    assert rec.run_once()["desired_ip_count"] == 1
    clock.t = 1000.0 + peer_endpoints.endpoint_ttl() + 1
    rec._next_maintenance = None          # a maintenance-driven pass (prunes)
    status = rec.run_once()
    assert status["desired_ip_count"] == 1
    assert aria.calls[-1] == ["10.0.0.9"]
    # The permitted device's expired row was pruned; the denied one was kept.
    with open(p["endpoints"]) as f:
        assert list(json.load(f)["principals"]) == ["device:bad"]


def test_revoked_device_block_survives_endpoint_ttl(tmp_path):
    aria = FakeAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(
        tmp_path, aria, clock=clock, revoked_provider=lambda: {"device:gone"})
    peer_endpoints.record_endpoint(p["endpoints"], _dev("gone"),
                                   "10.0.0.7", 6881, 1000.0)
    assert rec.run_once()["desired_ip_count"] == 1
    clock.t = 1000.0 + peer_endpoints.endpoint_ttl() + 1
    assert rec.run_once()["desired_ip_count"] == 1
    assert aria.calls[-1] == ["10.0.0.7"]


def test_unquarantined_device_row_then_ages_out(tmp_path):
    aria = FakeAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock)
    _quarantine(p["policy"], p["lkg"], "bad", 1000.0)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("bad"),
                                   "10.0.0.9", 6881, 1000.0)
    clock.t = 1000.0 + peer_endpoints.endpoint_ttl() + 1
    assert rec.run_once()["desired_ip_count"] == 1

    def unassign(doc):
        doc["assignments"].pop("bad", None)
    peer_policy.commit_mutation(p["policy"], p["lkg"], "unassign", "bad",
                                "op", clock.t, unassign)
    status = rec.run_once()
    assert status["desired_ip_count"] == 0
    assert aria.calls[-1] == []


# ---------------------------------------------------------------------------
# IRIS-04-006: the maintenance pass prunes the durable map; wakes only read
# ---------------------------------------------------------------------------

def test_maintenance_pass_prunes_expired_rows_but_wake_pass_does_not(tmp_path):
    aria = FakeAria()
    clock = Clock(1000.0)
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=clock)
    peer_endpoints.record_endpoint(p["endpoints"], _dev("a"),
                                   "10.0.0.1", 6881, 1000.0)
    rec.run_once()
    clock.t = 1000.0 + peer_endpoints.endpoint_ttl() + 1
    # Wake-driven pass (deadline still in the future): read only.
    rec._next_maintenance = clock.t + 30
    before = os.stat(p["endpoints"]).st_mtime_ns
    rec.run_once()
    assert os.stat(p["endpoints"]).st_mtime_ns == before
    with open(p["endpoints"]) as f:
        assert "device:a" in json.load(f)["principals"]
    # Maintenance-driven pass: the expired row leaves the file.
    rec._next_maintenance = clock.t - 1
    rec.run_once()
    with open(p["endpoints"]) as f:
        assert json.load(f)["principals"] == {}
