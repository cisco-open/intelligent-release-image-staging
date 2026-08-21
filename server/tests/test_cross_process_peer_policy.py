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
import tracker


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
                     pending=None, audit_ok=True):
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
    rec, p, _ = _make_reconciler(tmp_path, aria, clock=Clock(1000.0),
                                 audit_ok=False)
    _quarantine(p["policy"], p["lkg"], "a", 1000.0)
    rec.run_once()
    st = peer_enforcement.read_status(p["enforcement"])
    # audit failed -> ack revision NOT advanced (replay on next pass)
    assert st["last_operation_exported_revision"] == 0


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
