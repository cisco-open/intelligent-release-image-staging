# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import deployment_receipts
import pytest


def _receipt(**overrides):
    receipt = {
        "controller_id": "controller-1",
        "device_id": "edge-01",
        "inventory_revision": 12,
        "plan_hash": "a" * 64,
        "resolved": {"platform": "guestshell", "attachment": "inband", "renderer": "v1"},
        "preflight": {"device_identity": "digest"},
        "resources": [{"kind": "guestshell", "ownership": "iris-created"}],
    }
    receipt.update(overrides)
    return receipt


def test_create_persists_non_secret_planned_receipt(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    created = store.create(_receipt(receipt_id="r1"))
    assert created["state"] == "planned"
    assert created["timestamps"] == {"planned_at": 100, "finished_at": None}
    assert store.get("r1") == created


def test_transitions_and_active_lookup(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="r1"))
    store.transition("r1", "applying")
    active = store.transition("r1", "active", {"config_digest": "digest"})
    assert active["evidence"] == {"config_digest": "digest"}
    assert store.active_for_device("edge-01")["receipt_id"] == "r1"
    # active may re-enter applying (undeploy) but never jump back to planned
    with pytest.raises(ValueError, match="invalid receipt transition"):
        store.transition("r1", "planned")


def test_active_receipt_can_be_removed_after_undeploy(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    store.create(_receipt(receipt_id="r1"))
    store.transition("r1", "applying")
    store.transition("r1", "active")
    store.transition("r1", "applying")
    assert store.transition("r1", "removed")["state"] == "removed"


def test_receipt_keeps_immutable_resolved_network(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    created = store.create(_receipt(receipt_id="r1", resolved={
        "attachment": "routed", "iris_vlan": "666", "svi_ip": "192.0.2.1",
        "svi_mask": "255.255.255.252", "app_ip": "192.0.2.2",
        "app_mask": "255.255.255.252", "app_gateway": "192.0.2.1",
        "platform": "guestshell", "renderer": "v1"}))
    assert created["resolved"]["iris_vlan"] == "666"


def test_update_planned_atomically_refreshes_execution_evidence(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="r1"))
    updated = store.update_planned(
        "r1", plan_hash="b" * 64,
        resolved={"platform": "router", "device_identity": "9ABC123"},
        preflight={"status": "passed", "device_identity": "9ABC123"},
        resources=[{"kind": "virtualportgroup", "ownership": "iris-created"}])
    assert updated["state"] == "planned"
    assert updated["plan_hash"] == "b" * 64
    assert updated["resolved"]["device_identity"] == "9ABC123"
    assert store.get("r1") == updated


def test_update_planned_refuses_after_apply_started_or_with_secrets(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    store.create(_receipt(receipt_id="r1"))
    with pytest.raises(ValueError, match="secrets"):
        store.update_planned(
            "r1", plan_hash="b" * 64, resolved={},
            preflight={"token": "nope"}, resources=[])
    store.transition("r1", "applying")
    with pytest.raises(ValueError, match="only planned"):
        store.update_planned(
            "r1", plan_hash="b" * 64, resolved={},
            preflight={}, resources=[])


def test_cancelled_planned_receipt_can_be_retired(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    store.create(_receipt(receipt_id="r1"))
    assert store.transition("r1", "removed")["state"] == "removed"


def test_adopt_creates_active_receipt_for_existing_deployment(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    adopted = store.adopt(_receipt(receipt_id="a1"))
    assert adopted["state"] == "active" and adopted["adopted"] is True
    assert store.active_for_device("edge-01")["receipt_id"] == "a1"
    store.transition("a1", "applying")
    assert store.transition("a1", "removed")["state"] == "removed"


def test_recovery_marks_only_interrupted_work_unknown(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 200)
    store.create(_receipt(receipt_id="planned"))
    store.create(_receipt(receipt_id="applying", device_id="edge-02"))
    store.transition("applying", "applying")
    store.create(_receipt(receipt_id="active", device_id="edge-03"))
    store.transition("active", "applying")
    store.transition("active", "active")
    assert set(store.recover_interrupted()) == {"planned", "applying"}
    assert store.get("planned")["state"] == "unknown"
    assert store.get("applying")["state"] == "unknown"
    assert store.get("active")["state"] == "active"


@pytest.mark.parametrize("bad", [
    _receipt(password="nope"),
    _receipt(preflight={"token": "nope"}),
    _receipt(inventory_revision="12"),
])
def test_create_rejects_secrets_and_invalid_shape(tmp_path, bad):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    with pytest.raises(ValueError):
        store.create(bad)


# --- Re-onboard lifecycle: a device is re-onboarded (idempotent teardown +
# redeploy), so the NEW receipt's activation must retire the old active one.
# Without this, actives accumulate and active_for_device() refuses undeploy
# ("multiple active receipts") — the lab-observed IOx undeploy failure. ---

def test_activation_supersedes_prior_active_for_device(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    store.create(_receipt(receipt_id="new"))
    store.transition("new", "applying")
    store.transition("new", "active")
    assert store.get("old")["state"] == "superseded"
    assert store.get("new")["state"] == "active"
    assert store.active_for_device("edge-01")["receipt_id"] == "new"


def test_activation_leaves_other_devices_actives_alone(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="other", device_id="edge-99"))
    store.transition("other", "applying")
    store.transition("other", "active")
    store.create(_receipt(receipt_id="mine"))
    store.transition("mine", "applying")
    store.transition("mine", "active")
    assert store.get("other")["state"] == "active"
    assert store.active_for_device("edge-99")["receipt_id"] == "other"


def test_superseded_is_terminal(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    store.create(_receipt(receipt_id="new"))
    store.transition("new", "applying")
    store.transition("new", "active")
    for state in ("active", "applying", "removed", "needs-reconcile"):
        with pytest.raises(ValueError, match="invalid receipt transition"):
            store.transition("old", state)


def test_adopt_supersedes_existing_active(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_receipt(receipt_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    adopted = store.adopt(_receipt(receipt_id="a1"))
    assert adopted["state"] == "active"
    assert store.get("old")["state"] == "superseded"
    assert store.active_for_device("edge-01")["receipt_id"] == "a1"


def test_recover_interrupted_collapses_legacy_duplicate_actives(tmp_path):
    # Simulate the on-disk legacy state written by the pre-supersede code:
    # two actives for one device (differing activation times) — undeploy was
    # refused for exactly this shape on the lab server. Startup recovery must
    # keep the NEWEST active and retire the rest, deterministically.
    import json as _json
    legacy = {"receipts": {
        "r-old": dict(_receipt(receipt_id="r-old"), state="active",
                      timestamps={"planned_at": 10, "finished_at": 100}),
        "r-new": dict(_receipt(receipt_id="r-new"), state="active",
                      timestamps={"planned_at": 20, "finished_at": 200}),
        "r-other": dict(_receipt(receipt_id="r-other", device_id="edge-99"),
                        state="active",
                        timestamps={"planned_at": 10, "finished_at": 50}),
    }}
    path = tmp_path / "deployment_receipts.json"
    path.write_text(_json.dumps(legacy))
    store = deployment_receipts.ReceiptStore(str(tmp_path), now_fn=lambda: 300)
    store.recover_interrupted()
    assert store.get("r-old")["state"] == "superseded"
    assert store.get("r-new")["state"] == "active"
    assert store.get("r-other")["state"] == "active"   # single active untouched
    assert store.active_for_device("edge-01")["receipt_id"] == "r-new"


def test_interrupted_work_can_still_be_torn_down(tmp_path):
    """A controller restart during an onboard leaves the receipt 'unknown' while
    the device is already configured. That receipt records what IRIS created, so
    it MUST still authorize a teardown — otherwise the device is stranded: a
    router cannot be adopted and its preflight refuses a re-onboard, leaving no
    Console path at all."""
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    created = store.create(_receipt())
    store.transition(created["receipt_id"], "applying")
    store.recover_interrupted()
    assert store.get(created["receipt_id"])["state"] == "unknown"
    # not active, so it must not masquerade as one
    assert store.active_for_device("edge-01") is None
    # but it IS recoverable, and a teardown can run to completion
    rec = store.recoverable_for_device("edge-01")
    assert rec["receipt_id"] == created["receipt_id"]
    store.transition(created["receipt_id"], "applying")
    store.transition(created["receipt_id"], "removed")
    assert store.get(created["receipt_id"])["state"] == "removed"


def test_needs_reconcile_and_drifted_can_be_torn_down(tmp_path):
    """needs-reconcile was terminal, which made a drift-detected deployment
    permanently unmanageable. Reconciling IS undeploying, so it must lead
    somewhere."""
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    for state in ("needs-reconcile", "drifted"):
        rid = store.create(_receipt(device_id="edge-%s" % state))["receipt_id"]
        store.transition(rid, "applying")
        store.transition(rid, "active")
        store.transition(rid, state)
        assert store.recoverable_for_device("edge-%s" % state)["receipt_id"] == rid
        store.transition(rid, "applying")
        store.transition(rid, "removed")
        assert store.get(rid)["state"] == "removed"


def test_recoverable_prefers_the_active_receipt(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    stale = store.create(_receipt(receipt_id="r-stale"))["receipt_id"]
    store.transition(stale, "applying")
    store.recover_interrupted()          # -> unknown
    live = store.create(_receipt(receipt_id="r-live"))["receipt_id"]
    store.transition(live, "applying")
    store.transition(live, "active")
    assert store.recoverable_for_device("edge-01")["receipt_id"] == live


def test_recoverable_is_none_when_nothing_is_left(tmp_path):
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    rid = store.create(_receipt())["receipt_id"]
    store.transition(rid, "applying")
    store.transition(rid, "removed")
    assert store.recoverable_for_device("edge-01") is None


def test_recoverable_refuses_to_guess_between_two_candidates(tmp_path):
    """Two recoverable receipts means we cannot prove which one describes the
    box; guessing could tear down resources the other receipt owns."""
    store = deployment_receipts.ReceiptStore(str(tmp_path))
    for rid in ("r-a", "r-b"):
        made = store.create(_receipt(receipt_id=rid))["receipt_id"]
        store.transition(made, "applying")
    store.recover_interrupted()
    try:
        store.recoverable_for_device("edge-01")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "edge-01" in str(exc)
