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
