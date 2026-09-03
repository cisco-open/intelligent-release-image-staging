# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import deployment_records
import pytest


def _record(**overrides):
    record = {
        "controller_id": "controller-1",
        "device_id": "edge-01",
        "inventory_revision": 12,
        "plan_hash": "a" * 64,
        "resolved": {"platform": "guestshell", "management_type": "inband", "renderer": "v1"},
        "preflight": {"device_identity": "digest"},
        "resources": [{"kind": "guestshell", "ownership": "iris-created"}],
    }
    record.update(overrides)
    return record


def test_create_persists_non_secret_planned_record(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    created = store.create(_record(record_id="r1"))
    assert created["state"] == "planned"
    assert created["timestamps"] == {"planned_at": 100, "finished_at": None}
    assert store.get("r1") == created


def test_transitions_and_active_lookup(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="r1"))
    store.transition("r1", "applying")
    active = store.transition("r1", "active", {"config_digest": "digest"})
    assert active["evidence"] == {"config_digest": "digest"}
    assert store.active_for_device("edge-01")["record_id"] == "r1"
    # active may re-enter applying (undeploy) but never jump back to planned
    with pytest.raises(ValueError, match="invalid record transition"):
        store.transition("r1", "planned")


def test_active_record_can_be_removed_after_undeploy(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r1"))
    store.transition("r1", "applying")
    store.transition("r1", "active")
    store.transition("r1", "applying")
    assert store.transition("r1", "removed")["state"] == "removed"


def test_record_keeps_immutable_resolved_network(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    created = store.create(_record(record_id="r1", resolved={
        "management_type": "routed", "iris_vlan": "666", "svi_ip": "192.0.2.1",
        "svi_mask": "255.255.255.252", "app_ip": "192.0.2.2",
        "app_mask": "255.255.255.252", "app_gateway": "192.0.2.1",
        "platform": "guestshell", "renderer": "v1"}))
    assert created["resolved"]["iris_vlan"] == "666"


def test_update_planned_atomically_refreshes_execution_evidence(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="r1"))
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
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r1"))
    with pytest.raises(ValueError, match="secrets"):
        store.update_planned(
            "r1", plan_hash="b" * 64, resolved={},
            preflight={"token": "nope"}, resources=[])
    store.transition("r1", "applying")
    with pytest.raises(ValueError, match="only planned"):
        store.update_planned(
            "r1", plan_hash="b" * 64, resolved={},
            preflight={}, resources=[])


def test_cancelled_planned_record_can_be_retired(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r1"))
    assert store.transition("r1", "removed")["state"] == "removed"


def test_adopt_creates_active_record_for_existing_deployment(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    adopted = store.adopt(_record(record_id="a1"))
    assert adopted["state"] == "active" and adopted["adopted"] is True
    assert store.active_for_device("edge-01")["record_id"] == "a1"
    store.transition("a1", "applying")
    assert store.transition("a1", "removed")["state"] == "removed"


def test_recovery_marks_only_interrupted_work_unknown(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 200)
    store.create(_record(record_id="planned"))
    store.create(_record(record_id="applying", device_id="edge-02"))
    store.transition("applying", "applying")
    store.create(_record(record_id="active", device_id="edge-03"))
    store.transition("active", "applying")
    store.transition("active", "active")
    assert set(store.recover_interrupted()) == {"planned", "applying"}
    assert store.get("planned")["state"] == "unknown"
    assert store.get("applying")["state"] == "unknown"
    assert store.get("active")["state"] == "active"


@pytest.mark.parametrize("bad", [
    _record(password="nope"),
    _record(preflight={"token": "nope"}),
    _record(inventory_revision="12"),
])
def test_create_rejects_secrets_and_invalid_shape(tmp_path, bad):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    with pytest.raises(ValueError):
        store.create(bad)


# --- Re-onboard lifecycle: a device is re-onboarded (idempotent teardown +
# redeploy), so the NEW record's activation must retire the old active one.
# Without this, actives accumulate and active_for_device() refuses undeploy
# ("multiple active records") — the lab-observed IOx undeploy failure. ---

def test_activation_supersedes_prior_active_for_device(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    store.create(_record(record_id="new"))
    store.transition("new", "applying")
    store.transition("new", "active")
    assert store.get("old")["state"] == "superseded"
    assert store.get("new")["state"] == "active"
    assert store.active_for_device("edge-01")["record_id"] == "new"


def test_activation_leaves_other_devices_actives_alone(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="other", device_id="edge-99"))
    store.transition("other", "applying")
    store.transition("other", "active")
    store.create(_record(record_id="mine"))
    store.transition("mine", "applying")
    store.transition("mine", "active")
    assert store.get("other")["state"] == "active"
    assert store.active_for_device("edge-99")["record_id"] == "other"


def test_superseded_is_terminal(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    store.create(_record(record_id="new"))
    store.transition("new", "applying")
    store.transition("new", "active")
    for state in ("active", "applying", "removed", "needs-reconcile"):
        with pytest.raises(ValueError, match="invalid record transition"):
            store.transition("old", state)


def test_adopt_supersedes_existing_active(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    store.create(_record(record_id="old"))
    store.transition("old", "applying")
    store.transition("old", "active")
    adopted = store.adopt(_record(record_id="a1"))
    assert adopted["state"] == "active"
    assert store.get("old")["state"] == "superseded"
    assert store.active_for_device("edge-01")["record_id"] == "a1"


def test_recover_interrupted_collapses_legacy_duplicate_actives(tmp_path):
    # Simulate the on-disk legacy state written by the pre-supersede code:
    # two actives for one device (differing activation times) — undeploy was
    # refused for exactly this shape on the lab server. Startup recovery must
    # keep the NEWEST active and retire the rest, deterministically.
    import json as _json
    legacy = {"records": {
        "r-old": dict(_record(record_id="r-old"), state="active",
                      timestamps={"planned_at": 10, "finished_at": 100}),
        "r-new": dict(_record(record_id="r-new"), state="active",
                      timestamps={"planned_at": 20, "finished_at": 200}),
        "r-other": dict(_record(record_id="r-other", device_id="edge-99"),
                        state="active",
                        timestamps={"planned_at": 10, "finished_at": 50}),
    }}
    path = tmp_path / "deployment_records.json"
    path.write_text(_json.dumps(legacy))
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 300)
    store.recover_interrupted()
    assert store.get("r-old")["state"] == "superseded"
    assert store.get("r-new")["state"] == "active"
    assert store.get("r-other")["state"] == "active"   # single active untouched
    assert store.active_for_device("edge-01")["record_id"] == "r-new"


def test_interrupted_work_can_still_be_torn_down(tmp_path):
    """A controller restart during an onboard leaves the record 'unknown' while
    the device is already configured. That record still describes what IRIS
    created, so it MUST still authorize a teardown — otherwise the device is
    stranded: a router cannot be adopted and its preflight refuses a
    re-onboard, leaving no Console path at all."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    created = store.create(_record())
    store.transition(created["record_id"], "applying")
    store.recover_interrupted()
    assert store.get(created["record_id"])["state"] == "unknown"
    # not active, so it must not masquerade as one
    assert store.active_for_device("edge-01") is None
    # but it IS recoverable, and a teardown can run to completion
    rec = store.recoverable_for_device("edge-01")
    assert rec["record_id"] == created["record_id"]
    store.transition(created["record_id"], "applying")
    store.transition(created["record_id"], "removed")
    assert store.get(created["record_id"])["state"] == "removed"


def test_needs_reconcile_and_drifted_can_be_torn_down(tmp_path):
    """needs-reconcile was terminal, which made a drift-detected deployment
    permanently unmanageable. Reconciling IS undeploying, so it must lead
    somewhere."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    for state in ("needs-reconcile", "drifted"):
        rid = store.create(_record(device_id="edge-%s" % state))["record_id"]
        store.transition(rid, "applying")
        store.transition(rid, "active")
        store.transition(rid, state)
        assert store.recoverable_for_device("edge-%s" % state)["record_id"] == rid
        store.transition(rid, "applying")
        store.transition(rid, "removed")
        assert store.get(rid)["state"] == "removed"


def test_recoverable_prefers_the_active_record(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    stale = store.create(_record(record_id="r-stale"))["record_id"]
    store.transition(stale, "applying")
    store.recover_interrupted()          # -> unknown
    live = store.create(_record(record_id="r-live"))["record_id"]
    store.transition(live, "applying")
    store.transition(live, "active")
    assert store.recoverable_for_device("edge-01")["record_id"] == live


def test_recoverable_is_none_when_nothing_is_left(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    rid = store.create(_record())["record_id"]
    store.transition(rid, "applying")
    store.transition(rid, "removed")
    assert store.recoverable_for_device("edge-01") is None


def test_recoverable_refuses_to_guess_between_two_candidates(tmp_path):
    """Two recoverable records means we cannot prove which one describes the
    box; guessing could tear down resources the other record owns."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    for rid in ("r-a", "r-b"):
        made = store.create(_record(record_id=rid))["record_id"]
        store.transition(made, "applying")
    store.recover_interrupted()
    try:
        store.recoverable_for_device("edge-01")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "edge-01" in str(exc)


def test_an_applying_record_authorizes_teardown(tmp_path):
    """An onboard that dies mid-run leaves its record in `applying`. That
    record already carries the ownership proof teardown validates, and it is
    the ONLY durable record that IRIS mutated the device -- so teardown must be
    able to read it.

    Before this, `applying` became readable only via recover_interrupted(),
    which runs once at process start. With no restart the marker was written,
    never read, and never would be: the device could not be undeployed (no
    readable record), could not be adopted (routers never can) and could not be
    re-onboarded (preflight refuses the live Guest Shell). That is exactly how
    100.90.168.116 was stranded in the lab.
    """
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r-applying", device_id="dev-1"))
    store.transition("r-applying", "applying")
    got = store.recoverable_for_device("dev-1")
    assert got is not None, "an applying record must authorize teardown"
    assert got["record_id"] == "r-applying"
    assert got["state"] == "applying"


def test_applying_can_still_be_closed_out_as_removed(tmp_path):
    """Teardown closes the record with `removed`; that edge must already exist
    so the rescue path does not dead-end."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r-close", device_id="dev-2"))
    store.transition("r-close", "applying")
    store.transition("r-close", "removed")
    assert store.recoverable_for_device("dev-2") is None


# ---------------------------------------------------------------------------
# retire_device: a record must not outlive the device it describes
# ---------------------------------------------------------------------------

def test_retire_device_abandons_a_recoverable_record(tmp_path):
    """A record left in a recoverable state is what onboard refuses on and
    what undeploy renders teardown from. Once the device is gone from the
    fleet it describes nothing IRIS manages, so it must stop doing both --
    otherwise the next device registered under that id inherits it."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    rid = store.create(_record())["record_id"]
    store.transition(rid, "applying")
    store.transition(rid, "needs-reconcile")
    assert store.recoverable_for_device("edge-01") is not None

    assert store.retire_device("edge-01", "device deleted from the fleet") == [rid]

    assert store.recoverable_for_device("edge-01") is None
    retired = store.get(rid)
    assert retired["state"] == "abandoned"
    assert retired["evidence"] == {"status": "abandoned",
                                   "reason": "device deleted from the fleet"}
    assert retired["timestamps"]["finished_at"] > 0


def test_retire_device_keeps_the_record(tmp_path):
    """Abandoned, not deleted: the record is the only list of what IRIS built
    on that box (the VirtualPortGroup, the NAT stanza, the app address), and an
    operator who deleted a still-configured device is the one who needs it."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    rid = store.create(_record())["record_id"]
    store.retire_device("edge-01", "device deleted from the fleet")
    kept = store.get(rid)
    assert kept is not None
    assert kept["resources"] == [{"kind": "guestshell", "ownership": "iris-created"}]
    assert kept["resolved"]["management_type"] == "inband"
    assert store.list("edge-01") == [kept]


def test_retire_device_leaves_terminal_records_untouched(tmp_path):
    """A record that already told its story keeps it. Restamping a 'removed'
    record as abandoned would claim IRIS never tore that deployment down."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    done = store.create(_record())["record_id"]
    store.transition(done, "applying")
    store.transition(done, "removed")
    live = store.create(_record())["record_id"]

    assert store.retire_device("edge-01", "device deleted from the fleet") == [live]
    assert store.get(done)["state"] == "removed"
    assert store.get(live)["state"] == "abandoned"


def test_retire_device_only_touches_the_named_device(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    mine = store.create(_record())["record_id"]
    theirs = store.create(_record(device_id="edge-02"))["record_id"]

    assert store.retire_device("edge-01", "device deleted from the fleet") == [mine]
    assert store.get(theirs)["state"] == "planned"


def test_retire_device_resolves_multiple_recoverable_records(tmp_path):
    """Two recoverable records refuse onboard, undeploy AND adopt, and nothing
    else in the product resolves them. Retiring the device clears all of them
    at once, which is the only exit from that state."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    first = store.create(_record())["record_id"]
    store.transition(first, "applying")
    second = store.create(_record())["record_id"]
    store.transition(second, "applying")
    with pytest.raises(ValueError, match="multiple recoverable records"):
        store.recoverable_for_device("edge-01")

    assert sorted(store.retire_device("edge-01", "forced teardown")) == sorted(
        [first, second])
    assert store.recoverable_for_device("edge-01") is None


def test_retire_device_is_a_no_op_for_an_unknown_device(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    assert store.retire_device("never-existed", "device deleted from the fleet") == []


def test_abandoned_is_terminal(tmp_path):
    """Nothing follows abandonment: the record can never become teardown
    authority again, which is the whole point of the state."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    rid = store.create(_record())["record_id"]
    store.retire_device("edge-01", "device deleted from the fleet")
    for state in ("applying", "active", "needs-reconcile", "removed", "planned"):
        with pytest.raises(ValueError, match="invalid record transition"):
            store.transition(rid, state)


def test_abandoned_record_never_blocks_or_authorises(tmp_path):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    rid = store.create(_record())["record_id"]
    store.transition(rid, "applying")
    store.transition(rid, "active")
    store.retire_device("edge-01", "device deleted from the fleet")
    assert store.active_for_device("edge-01") is None
    assert store.recoverable_for_device("edge-01") is None


def test_unparseable_store_refuses_writes_and_is_left_intact(tmp_path):
    """A present-but-corrupt deployment_records.json used to read as an
    EMPTY store, and the next create/transition rewrote it with one record --
    deleting every device's teardown authority in one silent step."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="r1"))
    with open(store.path, "w") as stream:
        stream.write("{not json")
    for write in (lambda: store.create(_record(record_id="r2")),
                  lambda: store.adopt(_record(record_id="r3")),
                  lambda: store.transition("r1", "applying"),
                  lambda: store.update_planned(
                      "r1", plan_hash="b" * 64, resolved={}, preflight={},
                      resources=[]),
                  lambda: store.recover_interrupted(),
                  lambda: store.retire_device("edge-01", "test")):
        with pytest.raises(ValueError, match="unreadable"):
            write()
    with open(store.path) as stream:
        assert stream.read() == "{not json"
    # reads degrade to an empty view rather than raising
    assert store.get("r1") is None and store.list() == []
    assert store.recoverable_for_device("edge-01") is None
    # ... except for a caller that asks for strict, which must be able to tell
    # "this device has no record" apart from "no record is readable at all"
    # before it advises an operator to adopt the device (issue #103).
    with pytest.raises(deployment_records.RecordStoreUnreadable,
                       match="unreadable"):
        store.recoverable_for_device("edge-01", strict=True)
    with pytest.raises(deployment_records.RecordStoreUnreadable):
        store.active_for_device("edge-01", strict=True)
    with pytest.raises(deployment_records.RecordStoreUnreadable):
        store.list(strict=True)
    # and the strict write failures are the same distinguishable type
    assert issubclass(deployment_records.RecordStoreUnreadable, ValueError)
    with pytest.raises(deployment_records.RecordStoreUnreadable):
        store.create(_record(record_id="r4"))
    # a missing file is still an empty store that writes can create
    import os
    os.unlink(store.path)
    assert store.create(_record(record_id="r9"))["state"] == "planned"


def test_activation_abandons_stale_recoverable_siblings(tmp_path):
    """A sibling left unknown/needs-reconcile/drifted survived a successful
    re-onboard, so once the new record was removed it resurfaced as teardown
    authority -- a full recorded teardown rendered from its stale VLAN/SVI
    numbers against a box that no longer carries any of it."""
    store = deployment_records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    for record_id, stale in (("u", "unknown"), ("n", "needs-reconcile"),
                             ("d", "drifted")):
        store.create(_record(record_id=record_id))
        if stale == "drifted":
            store.transition(record_id, "unknown")   # drifted is not reachable from planned
        store.transition(record_id, stale)
    store.create(_record(record_id="p"))                 # a queued job's record
    store.create(_record(record_id="other", device_id="edge-02"))
    store.transition("other", "unknown")

    store.create(_record(record_id="b"))
    store.transition("b", "applying")
    store.transition("b", "active")
    for record_id in ("u", "n", "d"):
        retired = store.get(record_id)
        assert retired["state"] == "abandoned", record_id
        assert "activation of record b" in retired["evidence"]["reason"]
        assert retired["timestamps"]["finished_at"] == 100
    assert store.get("p")["state"] == "planned"          # in flight: untouched
    assert store.get("other")["state"] == "unknown"      # other device: untouched

    store.transition("b", "applying")
    store.transition("b", "removed")
    assert store.recoverable_for_device("edge-01") is None
