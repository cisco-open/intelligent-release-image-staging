# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact reviewed origin approval, bounded retention and native apply proof."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import auth
import origin_enforcement as oe
import peer_endpoints
import peer_policy
from test_blocklist_reconciler import _role_doc
from test_cross_process_peer_policy import Clock, FakeAria, _make_reconciler

ORIGIN = "192.0.2.10"
DEVICE = "198.51.100.20"


@pytest.fixture
def fixture(tmp_path):
    clock, aria = Clock(), FakeAria()
    rec, paths, _ = _make_reconciler(tmp_path, aria, clock=clock,
                                   protected_seeder_ip=ORIGIN)
    doc = _role_doc(("d1", "d2"))
    peer_policy._atomic_write_json(paths["policy"], doc)
    peer_policy._atomic_write_json(paths["lkg"], doc)
    for principal, address in ((auth.Principal("service", "seeder"), ORIGIN),
                               (auth.Principal("device", "d1"), DEVICE)):
        peer_endpoints.record_endpoint(paths["endpoints"], principal, address, 6881, clock())
    store = oe.Store(str(tmp_path), ORIGIN, now=clock)
    return store, rec, aria, paths, clock


def request(store, **changes):
    current = store.read()
    return dict(mode="enforce", max_new_ips=10, max_new_devices=10,
                if_policy_revision=current["policy_revision"], dry_run=True, **changes)


def approve(store, mode="enforce", **options):
    current = store.read()
    body = request(store)
    body.update(mode=mode, **options)
    preview = store.change(body, [oe.etag(current["revision"])])
    return store.change(dict(body, dry_run=False, confirm_token=preview["confirm_token"]),
                        [oe.etag(current["revision"])])


def test_default_is_inert_and_commit_is_not_apply_proof(fixture):
    store, rec, aria, _, _ = fixture
    assert store.read()["mode"] == "preflight"
    rec.run_once()
    assert aria.calls == [[]]
    result = approve(store)
    assert result["revision"] == 1 and result["state"] == "pending"
    assert result["applied_ip_count"] is None
    assert aria.calls == [[]]
    rec.run_once()
    assert aria.calls[-1] == [DEVICE]
    result = store.read()
    assert result["state"] == "enforced" and result["applied_ip_count"] == 1
    assert result["last_verified_at"] == 1000
    serialized = json.dumps(result)
    assert DEVICE not in serialized and ORIGIN not in serialized and "sess-1" not in serialized


@pytest.mark.parametrize("shape", ["device-deny-seeder", "self-only", "role-origin-false", "seeder-deny-device"])
def test_all_four_mutual_origin_policy_shapes_apply_only_after_review(fixture, shape):
    store, rec, aria, paths, _ = fixture
    doc = _role_doc(("d1",)) if shape == "role-origin-false" else peer_policy.base_document()
    if shape == "device-deny-seeder":
        rules = [{"seq": 10, "action": "deny", "match": {"type": "service", "value": "seeder"}},
                 {"seq": 20, "action": "permit", "match": {"type": "any"}}]
    elif shape == "self-only":
        rules = [{"seq": 10, "action": "permit", "match": {"type": "device", "value": "d1"}},
                 {"seq": 20, "action": "deny", "match": {"type": "any"}}]
    elif shape == "seeder-deny-device":
        rules = [{"seq": 10, "action": "deny", "match": {"type": "device", "value": "d1"}},
                 {"seq": 20, "action": "permit", "match": {"type": "any"}}]
    if shape != "role-origin-false":
        doc["acls"]["review"] = {"rules": rules}
        if shape == "seeder-deny-device":
            doc["seeder_assignment"] = "review"
        else:
            doc["assignments"]["d1"] = "review"
    peer_policy.validate_document(doc)
    for path in (paths["policy"], paths["lkg"]):
        peer_policy._atomic_write_json(path, doc)
    rec.run_once()
    assert aria.calls[-1] == []
    approve(store)
    rec.run_once()
    assert aria.calls[-1] == [DEVICE] and store.read()["state"] == "enforced"


@pytest.mark.parametrize("matches,status", [([], 428), (["*"], 412),
    (['W/"origin-enforcement-0"'], 412), ([oe.etag(0), oe.etag(0)], 412)])
def test_strong_control_cas(fixture, matches, status):
    store = fixture[0]
    with pytest.raises(oe.OriginError) as error:
        store.change(request(store), matches)
    assert error.value.status == status


def test_equal_counts_different_ip_invalidates_preview(fixture):
    store, _, _, paths, clock = fixture
    body = request(store)
    preview = store.change(body, [oe.etag(0)])
    peer_endpoints.clear_principal(paths["endpoints"], auth.Principal("device", "d1"))
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "d1"),
                                   "198.51.100.21", 6881, clock())
    with pytest.raises(oe.OriginError, match="origin_review_stale"):
        store.change(dict(body, dry_run=False, confirm_token=preview["confirm_token"]), [oe.etag(0)])


def test_equal_counts_different_device_invalidates_preview(fixture):
    store, _, _, paths, clock = fixture
    body = request(store)
    preview = store.change(body, [oe.etag(0)])
    peer_endpoints.clear_principal(paths["endpoints"], auth.Principal("device", "d1"))
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "d2"),
                                   DEVICE, 6881, clock())
    with pytest.raises(oe.OriginError, match="origin_review_stale"):
        store.change(dict(body, dry_run=False, confirm_token=preview["confirm_token"]), [oe.etag(0)])


def test_both_budgets_and_retained_counts(fixture):
    store, rec, _, paths, clock = fixture
    body = request(store)
    blocked = store.change(dict(body, max_new_devices=0), [oe.etag(0)])
    assert blocked["blockers"] == ["device_budget_exceeded"]
    blocked = store.change(dict(body, max_new_ips=0), [oe.etag(0)])
    assert blocked["blockers"] == ["ip_budget_exceeded"]
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "d2"),
                                   DEVICE, 6881, clock())
    preview = store.change(dict(body, max_new_devices=0), [oe.etag(1)])
    assert preview["new_ip_count"] == 0 and preview["retained_ip_count"] == 1
    assert preview["new_device_count"] == 1 and preview["proposed_device_count"] == 2
    assert preview["blockers"] == ["device_budget_exceeded"]


def test_initial_mixed_nat_refused_and_later_mixed_nat_unblocks(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "allowed"),
                                   DEVICE, 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == []
    result = store.read()
    assert result["state"] == "degraded" and result["reason"] == "shared_address"
    assert result["applied_ip_count"] is None
    preview = store.change(request(store), [oe.etag(1)])
    assert preview["confirm_token"] is None and "shared_address" in preview["blockers"]
    with pytest.raises(oe.OriginError, match="origin_enforcement_blocked"):
        store.change(dict(request(store), dry_run=False, confirm_token="a" * 64), [oe.etag(1)])


def test_exact_approval_retained_after_device_endpoint_ttl(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    clock.t += peer_endpoints.endpoint_ttl() + 1
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("service", "seeder"),
                                   ORIGIN, 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == [DEVICE]
    assert store.read()["state"] == "enforced"
    assert "device:d1" not in peer_endpoints.fresh_endpoints(paths["endpoints"], clock())


def test_new_endpoint_does_not_expand_approved_blocklist(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "d2"),
                                   "198.51.100.21", 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == [DEVICE]
    result = store.read()
    assert result["state"] == "review_required" and result["reason"] == "endpoint_set_changed"


def test_shared_nat_exclusion_outlives_allowed_endpoint_ttl(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "allowed"),
                                   DEVICE, 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == []
    clock.t += peer_endpoints.endpoint_ttl() + 1
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("service", "seeder"),
                                   ORIGIN, 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == []
    assert store.read()["reason"] == "shared_address"
    # A process/session restart still cannot infer that a shared NAT became
    # dedicated merely because the permitted participant stopped announcing.
    rec._last_hash = None
    aria.session = "sess-2"
    rec.run_once()
    assert aria.calls[-1] == [] and store.read()["state"] == "degraded"


def test_shared_address_is_unblocked_even_when_seeder_observation_expires(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    clock.t += peer_endpoints.endpoint_ttl() + 1
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "allowed"),
                                   DEVICE, 6881, clock())
    rec.run_once()
    assert aria.calls[-1] == []
    assert store.read()["reason"] == "origin_unobserved"


def test_known_shared_address_is_unblocked_when_configured_origin_becomes_unknown(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "allowed"),
                                   DEVICE, 6881, clock())
    rec._protected_seeder_ip = None
    rec.run_once()
    assert aria.calls[-1] == []
    assert oe.read_json(store.status_path)["reason"] == "origin_unknown"


def test_policy_change_freezes_prior_exact_set_until_review(fixture):
    store, rec, aria, paths, _ = fixture
    approve(store)
    rec.run_once()
    peer_policy.commit_mutation(paths["policy"], paths["lkg"], "edit", "policy", "test", 1001,
                               lambda doc: doc["roles"]["defs"]["boat"].update(origin=True))
    rec.run_once()
    assert aria.calls[-1] == [DEVICE]
    assert store.read()["reason"] == "policy_changed"
    approve(store)
    rec.run_once()
    assert aria.calls[-1] == [] and store.read()["state"] == "enforced"


@pytest.mark.parametrize("revoked", [False, True])
def test_stale_origin_approval_does_not_suppress_new_baseline_denial(fixture, revoked):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "new-deny"),
                                   "198.51.100.99", 6881, clock())
    peer_policy.commit_mutation(paths["policy"], paths["lkg"], "edit", "policy", "test", 1001,
        lambda doc: doc.update(quarantined_devices={} if revoked else {"new-deny": True}))
    if revoked:
        rec._revoked_principals = lambda: {"device:new-deny"}
    rec.run_once()
    assert aria.calls[-1] == [DEVICE, "198.51.100.99"]
    assert store.read()["reason"] == "policy_changed"


def test_fresh_install_preview_cannot_deadlock_on_policy_initialization(tmp_path):
    code = """
import origin_enforcement as oe, sys
store = oe.Store(sys.argv[1], '192.0.2.10')
result = store.change(dict(mode='enforce', max_new_ips=10, max_new_devices=10,
    if_policy_revision=1, dry_run=True), [oe.etag(0)])
assert result['blockers'] == ['origin_unobserved']
"""
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])),
        timeout=3, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_missing_control_never_resets_an_applied_origin_list(fixture):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    Path(store.control_path).unlink()
    before = copy.deepcopy(aria.calls)
    assert rec.run_once()["state"] == "degraded"
    assert aria.calls == before
    with pytest.raises(oe.OriginError):
        store.read()


def test_missing_application_journal_cannot_reuse_a_healthy_status(fixture):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    Path(store.application_path).unlink()
    before = copy.deepcopy(aria.calls)
    with pytest.raises(oe.OriginError):
        store.read()
    assert rec.run_once()["state"] == "degraded" and aria.calls == before


@pytest.mark.parametrize("boundary", [1, 2, 3])
@pytest.mark.parametrize("after_write", [False, True])
def test_initial_commit_crash_boundaries_preserve_retryable_preflight_or_committed_cas(
        fixture, monkeypatch, boundary, after_write):
    store, _, aria, _, _ = fixture
    body = request(store)
    preview = store.change(body, [oe.etag(0)])
    native_write, writes = oe.write_json, []

    def interrupted(path, value):
        writes.append(path)
        if len(writes) == boundary and not after_write:
            raise OSError("fixture interrupted before write")
        native_write(path, value)
        if len(writes) == boundary and after_write:
            raise OSError("fixture interrupted after write")

    with monkeypatch.context() as patch:
        patch.setattr(oe, "write_json", interrupted)
        with pytest.raises(OSError):
            store.change(dict(body, dry_run=False, confirm_token=preview["confirm_token"]),
                         [oe.etag(0)])
    current = store.read()
    assert aria.calls == []  # A management write never applies native blocks.
    if boundary == 3 and after_write:
        assert current["revision"] == 1 and current["mode"] == "enforce"
        with pytest.raises(oe.OriginError, match="precondition_failed"):
            store.change(dict(body, dry_run=False, confirm_token=preview["confirm_token"]),
                         [oe.etag(0)])
    else:
        assert current["revision"] == 0 and current["mode"] == "preflight"
        assert approve(store)["revision"] == 1


def test_private_fifo_read_is_rejected_without_waiting_for_a_writer(tmp_path):
    fifo = tmp_path / "control.fifo"
    os.mkfifo(fifo)
    code = """
import origin_enforcement as oe, sys
try:
    oe.read_json(sys.argv[1])
except oe.OriginError as exc:
    assert exc.status == 503
else:
    raise AssertionError('FIFO accepted')
"""
    result = subprocess.run([sys.executable, "-c", code, str(fifo)],
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])),
        timeout=3, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_uncertain_apply_with_unknown_origin_keeps_live_state_untouched(fixture):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "d2"),
                                   "198.51.100.21", 6881, clock())
    approve(store)
    runtime = rec._origin_enforcement
    policy = peer_policy.load_policy(paths["policy"], paths["lkg"])
    endpoints = peer_endpoints.fresh_endpoints(paths["endpoints"], clock())
    import blocklist_reconciler as br
    baseline = br.derive_denied_set(policy, endpoints, {}, [], set(), ORIGIN)
    assert runtime.prepare(policy, endpoints, {}, set(), ORIGIN, baseline) is not None
    assert runtime.before_apply(aria.session)
    # The RPC reached aria2, then the tracker died before persisting its ack.
    aria.set_blocklist([DEVICE, "198.51.100.21"])
    rec._protected_seeder_ip = None
    before = copy.deepcopy(aria.calls)
    rec.run_once()
    assert aria.calls == before
    assert oe.read_json(store.application_path)["intent"] is not None
    assert oe.read_json(store.status_path)["reason"] == "application_state_unavailable"
    rec._protected_seeder_ip = ORIGIN
    rec.run_once()
    assert aria.calls[-1] == [DEVICE, "198.51.100.21"]
    assert store.read()["state"] == "enforced"


@pytest.mark.parametrize("unknown", [None, "", "0.0.0.0", "224.0.0.1", "not-an-ip"])
def test_unknown_origin_cannot_enable(fixture, unknown):
    store = fixture[0]
    store.origin = unknown
    preview = store.change(request(store), [oe.etag(0)])
    assert "origin_unknown" in preview["blockers"] and preview["confirm_token"] is None


def test_lost_origin_preserves_exact_applied_fallback(fixture):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    rec._protected_seeder_ip = None
    aria.session = "sess-2"
    status = rec.run_once()
    assert aria.calls[-1] == [DEVICE]
    assert status["state"] == "degraded"
    assert oe.read_json(store.status_path)["reason"] == "origin_unknown"


def test_changed_valid_observed_origin_cannot_reuse_older_healthy_get_proof(fixture):
    store, rec, _, paths, clock = fixture
    approve(store)
    rec.run_once()
    store.origin = "192.0.2.11"
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("service", "seeder"),
                                   store.origin, 6881, clock())
    result = store.read()
    assert result["state"] == "degraded" and result["reason"] == "origin_mismatch"
    assert result["applied_ip_count"] is None and result["last_verified_at"] is None
    # A fresh explicit review can approve the now-observed new origin. The old
    # acknowledgement alone cannot authorize it or appear as its apply proof.
    preview = store.change(request(store), [oe.etag(1)])
    assert preview["blockers"] == [] and preview["confirm_token"] is not None


def test_failed_rpc_session_change_and_stale_proof_not_healthy(fixture):
    store, rec, aria, _, clock = fixture
    approve(store)
    aria.raise_on_call = True
    rec.run_once()
    assert store.read()["state"] != "enforced"
    aria.raise_on_call = False
    rec.run_once()
    assert store.read()["state"] == "enforced"
    aria.session = "sess-2"
    aria.raise_on_call = True
    rec.run_once()
    assert store.read()["state"] != "enforced"
    clock.t += 121
    assert store.read()["last_verified_at"] is None


@pytest.mark.parametrize("which", ["control_path", "application_path"])
def test_corrupt_private_state_does_not_clear_current_blocklist(fixture, which):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    oe.write_json(getattr(store, which), {"invalid": True})
    before = copy.deepcopy(aria.calls)
    assert rec.run_once()["state"] == "degraded"
    assert aria.calls == before


@pytest.mark.parametrize("which", ["control_path", "application_path"])
def test_json_null_is_corrupt_not_missing_private_state(fixture, which):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    oe.write_json(getattr(store, which), None)
    before = copy.deepcopy(aria.calls)
    assert rec.run_once()["state"] == "degraded" and aria.calls == before
    with pytest.raises(oe.OriginError):
        store.read()


def test_null_control_before_first_apply_cannot_reset_approval(fixture):
    store = fixture[0]
    approve(store)
    oe.write_json(store.control_path, None)
    with pytest.raises(oe.OriginError):
        oe.load_control(store.control_path)


def test_reviewed_disable_releases_only_origin_blocks(fixture):
    store, rec, aria, paths, clock = fixture
    doc = peer_policy.load_policy(paths["policy"], paths["lkg"]).document
    doc["quarantined_devices"] = {"quarantined": True}
    for path in (paths["policy"], paths["lkg"]):
        peer_policy._atomic_write_json(path, doc)
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "quarantined"),
                                   "198.51.100.99", 6881, clock())
    approve(store)
    rec.run_once()
    assert aria.calls[-1] == [DEVICE, "198.51.100.99"]
    approve(store, mode="preflight")
    rec.run_once()
    assert aria.calls[-1] == ["198.51.100.99"]
    assert store.read()["state"] == "preflight"


def test_disable_preview_has_exact_zero_target_counts_without_fresh_seeder(fixture):
    store, rec, _, _, clock = fixture
    approve(store)
    rec.run_once()
    clock.t += peer_endpoints.endpoint_ttl() + 1
    preview = store.change(dict(request(store), mode="preflight"), [oe.etag(1)])
    assert preview["blockers"] == [] and preview["confirm_token"] is not None
    assert all(preview[name] == 0 for name in ("new_ip_count", "new_device_count",
               "retained_ip_count", "proposed_ip_count", "proposed_device_count"))
    approve(store, mode="preflight")
    rec.run_once()
    assert store.read()["state"] == "preflight"


def test_binding_and_journal_limits_reject_bad_types(fixture):
    store = fixture[0]
    approve(store)
    control = oe.load_control(store.control_path)
    for mutation in (lambda row: row.update(revision=True),
                     lambda row: row.update(max_new_ips=1001),
                     lambda row: row["approval"].update(origin_ipv4="0.0.0.0"),
                     lambda row: row["approval"]["bindings"][0].update(principals=["device:d1"] * 2)):
        value = copy.deepcopy(control)
        mutation(value)
        with pytest.raises(oe.OriginError):
            oe.validate_control(value)


def test_binding_edges_are_bounded_not_just_unique_ips_and_devices(monkeypatch):
    monkeypatch.setattr(oe, "MAX_BINDINGS", 2)
    with pytest.raises(oe.OriginError):
        oe.validate_bindings([{"ipv4": "198.51.100.1", "principals": ["device:a", "device:b"]},
                              {"ipv4": "198.51.100.2", "principals": ["device:a"]}])


def test_application_journal_can_read_two_maximum_binding_snapshots(tmp_path):
    # Use the longest legal IDs and one row per binding, the largest JSON
    # overhead per binding. A legal interrupted transition must be recoverable.
    import ipaddress
    devices = ["device:" + ("d%05d" % index).ljust(64, "x") for index in range(oe.MAX_DEVICES)]
    bindings = [{"ipv4": str(ipaddress.IPv4Address(0xc6330000 + index)),
                 "principals": [devices[index % len(devices)]]} for index in range(oe.MAX_BINDINGS)]
    bindings.sort(key=lambda row: row["ipv4"])
    applied_ips = sorted(str(ipaddress.IPv4Address(0xc6330000 + index))
                         for index in range(oe.MAX_APPLIED_IPS))
    row = {"revision": 1, "control_hash": "b" * 64,
           "policy_hash": "a" * 64, "ips": applied_ips,
           "bindings": bindings, "session": "s" * 128, "verified_at": 1000}
    value = {"schema": 1, "last_applied": row,
             "intent": dict(row, verified_at=None), "shared_revision": 1,
             "shared_ips": [item["ipv4"] for item in bindings]}
    path = str(tmp_path / "application.json")
    oe.write_json(path, value)
    assert os.path.getsize(path) > oe.MAX_BYTES
    assert oe.load_application(path) == value


def test_unrelated_shared_addresses_do_not_accumulate_in_origin_latch(fixture):
    store, rec, _, paths, clock = fixture
    approve(store)
    rec.run_once()
    for index in range(1, 9):
        address = "203.0.113.%d" % index
        for name in ("d2", "allowed"):
            peer_endpoints.clear_principal(paths["endpoints"], auth.Principal("device", name))
            peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", name),
                                           address, 6881, clock())
        rec.run_once()
        application = oe.load_application(store.application_path, required=True)
        assert application["shared_ips"] == []
        assert oe.read_json(store.status_path)["reason"] == "shared_address"


def test_aggregate_applied_cap_refuses_before_rpc_and_keeps_journal_valid(fixture, monkeypatch):
    store, rec, aria, paths, clock = fixture
    approve(store)
    rec.run_once()
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "quarantined"),
                                   "198.51.100.99", 6881, clock())
    peer_policy.commit_mutation(paths["policy"], paths["lkg"], "edit", "policy", "test", 1001,
                               lambda doc: doc.update(quarantined_devices={"quarantined": True}))
    monkeypatch.setattr(oe, "MAX_APPLIED_IPS", 1)
    before = copy.deepcopy(aria.calls)
    rec.run_once()
    assert aria.calls == before
    assert oe.read_json(store.status_path)["reason"] == "retention_capacity_exceeded"
    oe.load_application(store.application_path, required=True)


@pytest.mark.parametrize("rollback", ["zero", "positive", "same-revision-content"])
def test_stale_or_mixed_control_cannot_clear_or_reapprove_newer_application(fixture, rollback):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    old_control = oe.load_control(store.control_path)
    if rollback == "positive":
        approve(store)
        rec.run_once()
    elif rollback == "zero":
        old_control = oe.default_control()
    else:
        old_control["max_new_ips"] += 1
    oe.write_json(store.control_path, old_control)
    before = copy.deepcopy(aria.calls)
    assert rec.run_once()["state"] == "degraded" and aria.calls == before
    with pytest.raises(oe.OriginError):
        store.read()
    with pytest.raises(oe.OriginError):
        store.change(dict(mode="preflight", max_new_ips=10, max_new_devices=10,
            if_policy_revision=1, dry_run=True), [oe.etag(old_control["revision"])])


def test_stale_control_cannot_ignore_a_newer_uncertain_intent(fixture):
    store, rec, aria, _, _ = fixture
    approve(store)
    rec.run_once()
    old_control = oe.load_control(store.control_path)
    approve(store)
    aria.raise_on_call = True
    rec.run_once()
    assert oe.load_application(store.application_path)["intent"]["revision"] == 2
    oe.write_json(store.control_path, old_control)
    before = copy.deepcopy(aria.calls)
    assert rec.run_once()["state"] == "degraded" and aria.calls == before
    with pytest.raises(oe.OriginError):
        store.read()


@pytest.mark.parametrize("field,value", [
    ("state", ["enforced"]), ("reason", ["apply_failed"]),
    ("applied_ip_count", True), ("applied_ip_count", 0),
    ("applied_device_count", 999), ("last_verified_at", float("nan")),
    ("last_verified_at", 99999), ("last_verified_at", 10 ** 400),
    ("updated_at", -1), ("revision", True),
])
def test_malformed_or_inconsistent_application_proof_is_never_healthy(fixture, field, value):
    store, rec, _, _, _ = fixture
    approve(store)
    rec.run_once()
    proof = oe.read_json(store.status_path)
    proof[field] = value
    oe.write_json(store.status_path, proof)
    result = store.read()
    assert result["state"] != "enforced"
    assert result["applied_ip_count"] is None and result["last_verified_at"] is None
