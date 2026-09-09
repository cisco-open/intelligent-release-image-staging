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
    192.0.2.116 was stranded in the lab.
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


# ---------------------------------------------------------------------------
# Workstream B red freeze: IOx verification authority belongs to the durable
# deployment-record store.  These fixtures write the real bounded transcript
# framing so the store tests exercise committed evidence rather than accepting
# caller assertions.
# ---------------------------------------------------------------------------

_IOX_CONTROLLER = "c" * 32
_IOX_ATTEMPT = "a" * 32
_IOX_BOARD = "FOC0123ABCD"


def _iox_json_record(record):
    import json
    import struct

    payload = json.dumps(record, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert 1 <= len(payload) <= 65536
    return struct.pack("!I", len(payload)) + payload


def _iox_transcript(tmp_path, state="enabled", command_id=1,
                    attempt_id=_IOX_ATTEMPT, board_identity=_IOX_BOARD,
                    controller_id=_IOX_CONTROLLER):
    import base64
    import os

    transcript_dir = tmp_path / "iox" / "transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(tmp_path / "iox"), 0o700)
    os.chmod(str(transcript_dir), 0o700)
    command = b"show app-hosting verification"
    payload = ("App signature verification: %s\n" % state).encode("ascii")
    prefix = (b"edge#\nedge#terminal length 0\nedge#\n"
              b"edge#terminal width 512\nedge#\nedge#" + command + b"\n")
    suffix = b"edge#\nedge#exit\n"
    stdout = prefix + payload + suffix
    payload_offset = len(prefix)
    records = [
        {"schema_version": 1, "type": "header", "id": attempt_id,
         "attempt_id": attempt_id, "controller_id": controller_id,
         "created_at": 10},
        {"schema_version": 1, "type": "command_start",
         "command_id": command_id, "kind": "ssh",
         "purpose": "verification_read", "board_identity": board_identity,
         "record_id": None, "transaction_id": None, "revision": None,
         "phase": None, "started_at": 11},
        {"schema_version": 1, "type": "stream", "command_id": command_id,
         "stream": "stdout", "offset": 0,
         "data_b64": base64.b64encode(stdout).decode("ascii")},
        {"schema_version": 1, "type": "command_end",
         "command_id": command_id, "finished_at": 12, "returncode": 0,
         "timed_out": False, "stdout_truncated": False,
         "stderr_truncated": False, "framing_complete": True,
         "error_category": None, "stdout_observed_bytes": len(stdout),
         "stderr_observed_bytes": 0, "stdout_dropped_bytes": 0,
         "stderr_dropped_bytes": 0,
         "payload_spans": [{"offset": payload_offset,
                            "length": len(payload)}],
         "observed_state": state, "transition_response": None},
    ]
    path = transcript_dir / (attempt_id + ".transcript")
    content = b"".join(_iox_json_record(record) for record in records)
    with open(str(path), "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(str(path), 0o600)
    transcript_ref = {
        "id": attempt_id,
        "attempt_id": attempt_id,
        "stored_bytes": len(content),
        "observed_bytes": len(stdout),
        "dropped_bytes": 0,
        "truncated": False,
    }
    observation = {
        "state": state,
        "observed_at": 12,
        "command_id": command_id,
        "transcript_id": attempt_id,
        "stdout_offset": payload_offset,
        "stdout_length": len(payload),
        "stderr_offset": 0,
        "stderr_length": 0,
        "returncode": 0,
        "timed_out": False,
        "truncated": False,
        "framing_complete": True,
    }
    return transcript_ref, observation


def _append_iox_read(tmp_path, journal, previous_ref, command_id=2,
                     state="enabled"):
    import base64
    import os

    command = b"show app-hosting verification"
    attempt_id = previous_ref["id"]
    board_identity = journal["board_identity"]
    payload = ("App signature verification: %s\n" % state).encode("ascii")
    prefix = (b"edge#\nedge#terminal length 0\nedge#\n"
              b"edge#terminal width 512\nedge#\nedge#" + command + b"\n")
    stdout = prefix + payload + b"edge#\nedge#exit\n"
    payload_offset = len(prefix)
    records = [
        {"schema_version": 1, "type": "command_start",
         "command_id": command_id, "kind": "ssh",
         "purpose": "verification_read", "board_identity": board_identity,
         "record_id": journal["record_id"],
         "transaction_id": journal["transaction_id"],
         "revision": journal["revision"], "phase": journal["phase"],
         "started_at": 13},
        {"schema_version": 1, "type": "stream", "command_id": command_id,
         "stream": "stdout", "offset": 0,
         "data_b64": base64.b64encode(stdout).decode("ascii")},
        {"schema_version": 1, "type": "command_end",
         "command_id": command_id, "finished_at": 14, "returncode": 0,
         "timed_out": False, "stdout_truncated": False,
         "stderr_truncated": False, "framing_complete": True,
         "error_category": None, "stdout_observed_bytes": len(stdout),
         "stderr_observed_bytes": 0, "stdout_dropped_bytes": 0,
         "stderr_dropped_bytes": 0,
         "payload_spans": [{"offset": payload_offset,
                            "length": len(payload)}],
         "observed_state": state, "transition_response": None},
    ]
    path = tmp_path / "iox" / "transcripts" / (attempt_id + ".transcript")
    content = b"".join(_iox_json_record(record) for record in records)
    with open(str(path), "ab") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    transcript_ref = dict(previous_ref)
    transcript_ref["stored_bytes"] += len(content)
    transcript_ref["observed_bytes"] += len(stdout)
    observation = {
        "state": state, "observed_at": 14, "command_id": command_id,
        "transcript_id": attempt_id, "stdout_offset": payload_offset,
        "stdout_length": len(payload), "stderr_offset": 0,
        "stderr_length": 0, "returncode": 0, "timed_out": False,
        "truncated": False, "framing_complete": True,
    }
    return transcript_ref, observation


def _iox_wrapper(sign=False, cert=False):
    return {"wrapper_sha256": "b" * 64,
            "package_sign_present": sign,
            "package_cert_present": cert}


def _begin_iox(tmp_path, state="enabled", now=100):
    transcript_ref, observation = _iox_transcript(tmp_path, state=state)
    store = deployment_records.DeploymentRecordStore(
        str(tmp_path), now_fn=lambda: now)
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER,
                         resolved={"platform": "iox", "device_ip": "192.0.2.10",
                                   "device_identity": _IOX_BOARD}))
    journal = store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD,
                              _iox_wrapper(), observation, transcript_ref)
    return store, journal, transcript_ref, observation


def _begin_named_iox(store, tmp_path, index, state="enabled"):
    attempt_id = "%032x" % (index + 1)
    board_identity = "FOC%08d" % (index + 1)
    record_id = "iox-r%d" % (index + 1)
    transcript_ref, observation = _iox_transcript(
        tmp_path, state=state, attempt_id=attempt_id,
        board_identity=board_identity)
    store.create(_record(
        record_id=record_id, controller_id=_IOX_CONTROLLER,
        device_id="edge-%02d" % (index + 1),
        resolved={"platform": "iox", "device_ip": "192.0.2.%d" % (index + 10),
                  "device_identity": board_identity}))
    journal = store.iox_begin(
        record_id, _IOX_CONTROLLER, board_identity, _iox_wrapper(),
        observation, transcript_ref)
    return journal, transcript_ref


def _corrupt_persisted_journal(store, corruption):
    import json

    if corruption == "duplicate-key":
        with open(store.path) as stream:
            raw = stream.read()
        needle = '"schema_version": 1'
        assert raw.count(needle) == 1
        raw = raw.replace(
            needle, '"schema_version": 1,\n      "schema_version": 1', 1)
        with open(store.path, "w") as stream:
            stream.write(raw)
        return

    with open(store.path) as stream:
        document = json.load(stream)
    journal = document["records"]["iox-r1"]["iox_verification"]
    if corruption == "unknown-schema":
        journal["schema_version"] = 2
    elif corruption == "missing-key":
        journal.pop("revision")
    elif corruption == "unknown-key":
        journal["caller_authority"] = True
    elif corruption == "invalid-nested-type":
        journal["initial_observation"]["command_id"] = True
    elif corruption == "inconsistent-derived-state":
        journal["unresolved"] = True
    elif corruption == "containing-record-mismatch":
        journal["record_id"] = "another-record"
    else:
        raise AssertionError("unknown fixture corruption: %s" % corruption)
    with open(store.path, "w") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)


def test_iox_begin_persists_the_exact_closed_journal(tmp_path):
    store, journal, transcript_ref, observation = _begin_iox(tmp_path)
    assert set(journal) == {
        "schema_version", "transaction_id", "revision", "record_id",
        "controller_id", "board_identity", "wrapper_sha256",
        "package_sign_present", "package_cert_present", "prior_state",
        "current_state", "phase", "unresolved", "created_at", "updated_at",
        "observed_at", "terminal_at", "initial_observation",
        "pre_disable_observation", "disable_confirmation",
        "restore_observation", "error", "transcript_refs"}
    assert journal["schema_version"] == 1
    assert journal["record_id"] == "iox-r1"
    assert journal["controller_id"] == _IOX_CONTROLLER
    assert journal["board_identity"] == _IOX_BOARD
    assert journal["revision"] == 0
    assert journal["phase"] == "observed"
    assert journal["unresolved"] is False
    assert journal["prior_state"] == journal["current_state"] == "enabled"
    assert journal["initial_observation"] == observation
    assert journal["transcript_refs"] == [transcript_ref]
    assert journal["pre_disable_observation"] is None
    assert journal["disable_confirmation"] is None
    assert journal["restore_observation"] is None
    assert journal["error"] is None and journal["terminal_at"] is None
    assert store.get("iox-r1")["iox_verification"] == journal


@pytest.mark.parametrize("make_record", [
    lambda: _record(record_id="bad-create", controller_id=_IOX_CONTROLLER,
                    iox_verification={}),
    lambda: _record(record_id="bad-adopt", controller_id=_IOX_CONTROLLER,
                    iox_verification={}),
])
def test_generic_create_and_adopt_cannot_manufacture_iox_authority(
        tmp_path, make_record):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    record = make_record()
    operation = store.adopt if record["record_id"] == "bad-adopt" else store.create
    with pytest.raises(ValueError, match="iox_verification|journal|authority"):
        operation(record)


@pytest.mark.parametrize("corrupt", [
    lambda observation, transcript_ref, wrapper: observation.update(
        {"caller_state": "enabled"}),
    lambda observation, transcript_ref, wrapper: observation.update(
        {"command_id": True}),
    lambda observation, transcript_ref, wrapper: transcript_ref.update(
        {"path": "/tmp/not-authority"}),
    lambda observation, transcript_ref, wrapper: wrapper.update(
        {"trusted": True}),
])
def test_iox_begin_rejects_unknown_keys_and_invalid_nested_types(tmp_path, corrupt):
    transcript_ref, observation = _iox_transcript(tmp_path)
    wrapper = _iox_wrapper()
    corrupt(observation, transcript_ref, wrapper)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER))
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError):
        store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD, wrapper,
                        observation, transcript_ref)
    assert open(store.path, "rb").read() == before


@pytest.mark.parametrize("corruption", [
    "unknown-schema",
    "missing-key",
    "unknown-key",
    "duplicate-key",
    "invalid-nested-type",
    "inconsistent-derived-state",
    "containing-record-mismatch",
])
def test_persisted_malformed_journal_blocks_whole_store_authority_and_writes(
        tmp_path, corruption):
    store, journal, _transcript_ref, _observation = _begin_iox(tmp_path)
    store.create(_record(record_id="plain", device_id="edge-02"))
    _corrupt_persisted_journal(store, corruption)
    corrupt_bytes = open(store.path, "rb").read()

    # Both reads name unrelated scopes.  They still scan every record and fail
    # closed rather than hiding malformed authority outside the requested row.
    reads = (
        lambda: store.iox_summary("edge-02"),
        lambda: store.iox_obligations("UNRELATED-BOARD"),
    )
    for read in reads:
        with pytest.raises(ValueError):
            read()
        assert open(store.path, "rb").read() == corrupt_bytes

    # Ordinary lifecycle writes must not carry corrupt authority forward, and
    # a journal event must not repair it from caller-supplied evidence.
    error = {"category": "journal_unreadable", "detail": "fixture",
             "at": 100, "transcript_id": _IOX_ATTEMPT}
    writes = (
        lambda: store.create(_record(record_id="unrelated", device_id="edge-03")),
        lambda: store.transition("plain", "applying"),
        lambda: store.iox_event(
            "iox-r1", journal["transaction_id"], 0, "observed", "error",
            {"error": error, "transcript_refs": []}),
    )
    for write in writes:
        with pytest.raises(ValueError):
            write()
        assert open(store.path, "rb").read() == corrupt_bytes


def test_iox_event_is_strict_cas_and_failed_validation_writes_nothing(tmp_path):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    error = {"category": "readback_unknown", "detail": "bounded failure",
             "at": 100, "transcript_id": _IOX_ATTEMPT}
    updated = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "error",
        {"error": error, "transcript_refs": []})
    assert updated["revision"] == 1
    assert updated["phase"] == "observed"
    assert updated["error"] == error
    before = open(store.path, "rb").read()
    with pytest.raises(deployment_records.StaleIoxRevision):
        store.iox_event(
            "iox-r1", journal["transaction_id"], 0, "observed", "error",
            {"error": error, "transcript_refs": []})
    assert open(store.path, "rb").read() == before
    with pytest.raises(ValueError):
        store.iox_event(
            "iox-r1", journal["transaction_id"], 1, "observed", "error",
            {"error": error, "transcript_refs": [], "extra": True})
    assert open(store.path, "rb").read() == before


@pytest.mark.parametrize("event,evidence", [
    ("installing", {}),
    ("ownership_probe", {}),
    ("restore_intent", {"observation": None, "transcript_refs": []}),
    ("restored", {"observation": None, "transcript_refs": []}),
    ("relinquished", {"observation": None, "transcript_refs": []}),
    ("indeterminate", {"observation": None,
                       "error": {"category": "transport", "detail": "x",
                                 "at": 100, "transcript_id": _IOX_ATTEMPT},
                       "transcript_refs": []}),
    ("reconcile_enabled", {"observation": None,
                           "acknowledge_external_resolution": True,
                           "transcript_refs": []}),
    ("invented_event", {}),
])
def test_iox_event_table_rejects_unreachable_edges_without_a_write(
        tmp_path, event, evidence):
    store, journal, _transcript_ref, _observation = _begin_iox(tmp_path)
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError):
        store.iox_event("iox-r1", journal["transaction_id"], 0, "observed",
                        event, evidence)
    assert open(store.path, "rb").read() == before


def test_authority_bearing_event_rejects_missing_or_fabricated_capability(tmp_path):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    transcript_ref, fresh = _append_iox_read(tmp_path, journal, transcript_ref)
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "disable_intent",
        {"observation": fresh, "retry_command": None,
         "transcript_refs": [transcript_ref]})
    # A caller cannot turn a persisted phase or arbitrary object into proof that
    # a disable command and its readback happened in this live attempt.
    evidence = {"confirmation": {
        "confirmed_at": 20, "pre_disable_command_id": 2,
        "disable_command_id": 3, "disabled_readback_command_id": 4,
        "transition_response": "disabled_successfully"},
        "transcript_refs": [transcript_ref]}
    for capability in (None, object()):
        before = open(store.path, "rb").read()
        with pytest.raises(ValueError):
            store.iox_event(
                "iox-r1", journal["transaction_id"], 1, "disable_intent",
                "disable_confirmed", evidence, capability=capability)
        assert open(store.path, "rb").read() == before


def test_terminal_diagnostic_retains_phase_ownership_and_terminal_time(tmp_path):
    store, journal, _transcript_ref, _observation = _begin_iox(
        tmp_path, state="disabled", now=100)
    terminal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "unchanged",
        {"reason": "initially_disabled", "observation": None,
         "transcript_refs": []})
    assert terminal["phase"] == "unchanged"
    assert terminal["unresolved"] is False
    terminal_at = terminal["terminal_at"]
    ownership = (terminal["prior_state"], terminal["current_state"],
                 terminal["disable_confirmation"])
    diagnosed = store.iox_event(
        "iox-r1", journal["transaction_id"], 1, "unchanged", "error",
        {"error": {"category": "transport", "detail": "later cleanup failed",
                   "at": 100, "transcript_id": _IOX_ATTEMPT},
         "transcript_refs": []})
    assert diagnosed["phase"] == "unchanged"
    assert diagnosed["terminal_at"] == terminal_at
    assert (diagnosed["prior_state"], diagnosed["current_state"],
            diagnosed["disable_confirmation"]) == ownership


@pytest.mark.parametrize("rewrite", [
    "update_planned", "activation", "recover_interrupted", "removed",
    "superseded", "retire_device",
])
def test_lifecycle_rewrites_retain_terminal_iox_journal_bytes(tmp_path, rewrite):
    store, journal, _transcript_ref, _observation = _begin_iox(
        tmp_path, state="disabled")
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "unchanged",
        {"reason": "initially_disabled", "observation": None,
         "transcript_refs": []})

    if rewrite == "update_planned":
        store.update_planned(
            "iox-r1", plan_hash="f" * 64,
            resolved={"platform": "iox", "device_ip": "192.0.2.10",
                      "device_identity": _IOX_BOARD},
            preflight={"device_identity": _IOX_BOARD},
            resources=[{"kind": "iox-app", "ownership": "iris-created"}])
    elif rewrite == "activation":
        store.transition("iox-r1", "applying")
        store.transition("iox-r1", "active")
    elif rewrite == "recover_interrupted":
        store.recover_interrupted()
    elif rewrite == "removed":
        store.transition("iox-r1", "removed")
    elif rewrite == "superseded":
        store.transition("iox-r1", "applying")
        store.transition("iox-r1", "active")
        store.create(_record(record_id="new", controller_id=_IOX_CONTROLLER))
        store.transition("new", "applying")
        store.transition("new", "active")
        assert store.get("iox-r1")["state"] == "superseded"
    else:
        assert rewrite == "retire_device"
        assert store.retire_device("edge-01", "device retired") == ["iox-r1"]
        assert store.get("iox-r1")["state"] == "abandoned"

    assert store.get("iox-r1")["iox_verification"] == journal


@pytest.mark.parametrize("deployment_state", [
    "removed", "superseded", "abandoned",
])
def test_terminal_deployment_record_keeps_unresolved_journal_recoverable(
        tmp_path, deployment_state):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    if deployment_state == "removed":
        store.transition("iox-r1", "removed")
    elif deployment_state == "abandoned":
        assert store.retire_device("edge-01", "device retired") == ["iox-r1"]
    else:
        assert deployment_state == "superseded"
        store.transition("iox-r1", "applying")
        store.transition("iox-r1", "active")
        store.create(_record(record_id="successor"))
        store.transition("successor", "applying")
        store.transition("successor", "active")

    assert store.get("iox-r1")["state"] == deployment_state
    assert store.recover_interrupted() == []
    transcript_ref, fresh = _append_iox_read(
        tmp_path, journal, transcript_ref)
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed",
        "disable_intent", {"observation": fresh, "retry_command": None,
                           "transcript_refs": [transcript_ref]})
    assert journal["unresolved"] is True
    obligations = store.iox_obligations(_IOX_BOARD)
    assert obligations == [journal]

    # IOx recovery remains independent of the deployment lifecycle.  A
    # terminal deployment row must still accept journal events so recovery can
    # preserve diagnostics and ultimately discharge the board obligation.
    diagnosed = store.iox_event(
        "iox-r1", journal["transaction_id"], journal["revision"],
        "disable_intent", "error",
        {"error": {"category": "transport", "detail": "recovery read failed",
                   "at": 101, "transcript_id": _IOX_ATTEMPT},
         "transcript_refs": []})
    assert diagnosed["revision"] == journal["revision"] + 1
    assert diagnosed["phase"] == "disable_intent"
    assert diagnosed["unresolved"] is True
    assert store.get("iox-r1")["state"] == deployment_state


def test_terminal_deployment_and_verification_accept_later_diagnostic(tmp_path):
    store, journal, _transcript_ref, _observation = _begin_iox(
        tmp_path, state="disabled", now=100)
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "unchanged",
        {"reason": "initially_disabled", "observation": None,
         "transcript_refs": []})
    store.transition("iox-r1", "removed")
    terminal_at = journal["terminal_at"]
    diagnosed = store.iox_event(
        "iox-r1", journal["transaction_id"], journal["revision"],
        "unchanged", "error",
        {"error": {"category": "transport", "detail": "cleanup read failed",
                   "at": 102, "transcript_id": _IOX_ATTEMPT},
         "transcript_refs": []})
    assert diagnosed["phase"] == "unchanged"
    assert diagnosed["unresolved"] is False
    assert diagnosed["terminal_at"] == terminal_at
    assert store.get("iox-r1")["state"] == "removed"


def test_iox_summary_is_the_exact_safe_public_projection(tmp_path):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    transcript_ref, fresh = _append_iox_read(tmp_path, journal, transcript_ref)
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "disable_intent",
        {"observation": fresh, "retry_command": None,
         "transcript_refs": [transcript_ref]})
    other_board = "AAA0000AAAA"
    other_ref, other_observation = _iox_transcript(
        tmp_path, attempt_id="e" * 32, board_identity=other_board)
    store.create(_record(record_id="iox-r2", controller_id=_IOX_CONTROLLER,
                         resolved={"platform": "iox", "device_ip": "192.0.2.11",
                                   "device_identity": other_board}))
    other = store.iox_begin("iox-r2", _IOX_CONTROLLER, other_board,
                            _iox_wrapper(), other_observation, other_ref)
    other_ref, other_fresh = _append_iox_read(
        tmp_path, other, other_ref, state="enabled")
    store.iox_event(
        "iox-r2", other["transaction_id"], 0, "observed", "disable_intent",
        {"observation": other_fresh, "retry_command": None,
         "transcript_refs": [other_ref]})
    summary = store.iox_summary("edge-01")
    assert len(summary) == 2
    assert [item["board_identity"] for item in summary] == [other_board, _IOX_BOARD]
    item = summary[1]
    assert set(item) == {
        "schema_version", "record_id", "transaction_id", "revision",
        "board_identity", "prior_state", "current_state", "phase",
        "unresolved", "created_at", "updated_at", "observed_at",
        "terminal_at", "error_category"}
    for key in ("controller_id", "wrapper_sha256", "package_sign_present",
                "package_cert_present", "initial_observation",
                "disable_confirmation", "transcript_refs"):
        assert key not in item
    assert item["transaction_id"] == journal["transaction_id"]
    assert item["error_category"] is None


def test_conflicting_board_obligation_refuses_second_transaction(tmp_path):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    transcript_ref, fresh = _append_iox_read(tmp_path, journal, transcript_ref)
    store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed", "disable_intent",
        {"observation": fresh, "retry_command": None,
         "transcript_refs": [transcript_ref]})
    second_ref, second_observation = _iox_transcript(
        tmp_path, attempt_id="e" * 32)
    store.create(_record(record_id="iox-r2", device_id="edge-02",
                         controller_id=_IOX_CONTROLLER))
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError, match="obligation|conflict|board"):
        store.iox_begin("iox-r2", _IOX_CONTROLLER, _IOX_BOARD, _iox_wrapper(),
                        second_observation, second_ref)
    assert open(store.path, "rb").read() == before


def test_store_capacity_defaults_are_frozen():
    assert deployment_records._STORE_MAX_BYTES == 64 * 1024 * 1024
    assert deployment_records._STORE_ORDINARY_MAX_BYTES == 48 * 1024 * 1024
    assert deployment_records._STORE_MAX_RECORDS == 8192
    assert deployment_records._RECORD_MAX_BYTES == 128 * 1024
    assert deployment_records._IOX_MAX_UNRESOLVED == 512


def test_iox_record_size_bound_is_checked_before_replacement(
        tmp_path, monkeypatch):
    monkeypatch.setattr(deployment_records, "_RECORD_MAX_BYTES", 1024)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="small"))
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError, match="record|size|limit"):
        store.create(_record(record_id="oversize",
                            resolved={"platform": "iox", "padding": "x" * 2048}))
    assert open(store.path, "rb").read() == before


def test_iox_authority_scan_rejects_records_above_injected_limit(
        tmp_path, monkeypatch):
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    for index in range(3):
        store.create(_record(record_id="r%d" % index,
                             device_id="edge-%d" % index))
    monkeypatch.setattr(deployment_records, "_STORE_MAX_RECORDS", 2)
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError, match="record|limit|too many"):
        store.iox_summary("edge-0000")
    assert open(store.path, "rb").read() == before


def test_unresolved_journal_count_uses_injected_lower_limit(
        tmp_path, monkeypatch):
    monkeypatch.setattr(deployment_records, "_IOX_MAX_UNRESOLVED", 2)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    transactions = []
    for index in range(3):
        journal, transcript_ref = _begin_named_iox(store, tmp_path, index)
        transcript_ref, fresh = _append_iox_read(
            tmp_path, journal, transcript_ref)
        transactions.append((journal, transcript_ref, fresh))

    for journal, transcript_ref, fresh in transactions[:2]:
        updated = store.iox_event(
            journal["record_id"], journal["transaction_id"], 0, "observed",
            "disable_intent",
            {"observation": fresh, "retry_command": None,
             "transcript_refs": [transcript_ref]})
        assert updated["unresolved"] is True

    journal, transcript_ref, fresh = transactions[2]
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError, match="unresolved|limit|capacity"):
        store.iox_event(
            journal["record_id"], journal["transaction_id"], 0, "observed",
            "disable_intent",
            {"observation": fresh, "retry_command": None,
             "transcript_refs": [transcript_ref]})
    assert open(store.path, "rb").read() == before


def test_ordinary_admission_stops_before_journal_recovery_reserve(
        tmp_path, monkeypatch):
    store, journal, transcript_ref, _observation = _begin_iox(tmp_path)
    transcript_ref, fresh = _append_iox_read(
        tmp_path, journal, transcript_ref)
    journal = store.iox_event(
        "iox-r1", journal["transaction_id"], 0, "observed",
        "disable_intent", {"observation": fresh, "retry_command": None,
                           "transcript_refs": [transcript_ref]})
    store.create(_record(record_id="plain", device_id="edge-02"))
    current_size = len(open(store.path, "rb").read())
    total_limit = current_size + 16 * 1024
    ordinary_limit = max(1, current_size // 2)
    assert total_limit < deployment_records._STORE_MAX_BYTES
    assert ordinary_limit < deployment_records._STORE_ORDINARY_MAX_BYTES
    monkeypatch.setattr(deployment_records, "_STORE_MAX_BYTES", total_limit)
    monkeypatch.setattr(
        deployment_records, "_STORE_ORDINARY_MAX_BYTES", ordinary_limit)

    before = open(store.path, "rb").read()
    ordinary_writes = (
        lambda: store.create(_record(
            record_id="ordinary", device_id="edge-03")),
        lambda: store.update_planned(
            "plain", plan_hash="d" * 64,
            resolved={"platform": "iox", "padding": "x" * 2048},
            preflight={"device_identity": "OTHER"}, resources=[]),
    )
    for write in ordinary_writes:
        with pytest.raises(ValueError, match="ordinary|reserve|size|limit"):
            write()
        assert open(store.path, "rb").read() == before

    # The unresolved journal may still consume the space deliberately held
    # back from ordinary records and evidence.
    updated = store.iox_event(
        "iox-r1", journal["transaction_id"], journal["revision"],
        "disable_intent", "error",
        {"error": {"category": "transport",
                   "detail": "recovery evidence remains writable",
                   "at": 101, "transcript_id": _IOX_ATTEMPT},
         "transcript_refs": []})
    assert updated["revision"] == journal["revision"] + 1
    assert updated["unresolved"] is True
    assert len(open(store.path, "rb").read()) <= total_limit


def test_iox_durable_write_orders_flushed_file_replace_and_parent_sync(
        tmp_path, monkeypatch):
    import os
    import stat

    transcript_ref, observation = _iox_transcript(tmp_path)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER))
    events = []
    real_fsync = deployment_records.os.fsync
    real_replace = deployment_records.os.replace

    def tracked_fsync(fd):
        mode = os.fstat(fd).st_mode
        if stat.S_ISDIR(mode):
            events.append("parent_fsync")
        else:
            # Seeing the new journal through the descriptor proves the buffered
            # writer was flushed before the file durability barrier.
            with open("/proc/self/fd/%d" % fd, "rb") as check:
                assert b'"iox_verification"' in check.read()
            events.append("file_fsync")
        return real_fsync(fd)

    def tracked_replace(*args, **kwargs):
        events.append("replace")
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(deployment_records.os, "fsync", tracked_fsync)
    monkeypatch.setattr(deployment_records.os, "replace", tracked_replace)
    store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD, _iox_wrapper(),
                    observation, transcript_ref)
    assert events == ["file_fsync", "replace", "parent_fsync"]


def test_failed_file_sync_preserves_previous_store_bytes(tmp_path, monkeypatch):
    transcript_ref, observation = _iox_transcript(tmp_path)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER))
    before = open(store.path, "rb").read()

    def fail_fsync(_fd):
        raise OSError("injected file sync failure")

    monkeypatch.setattr(deployment_records.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="injected file sync failure"):
        store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD, _iox_wrapper(),
                        observation, transcript_ref)
    assert open(store.path, "rb").read() == before


def test_failed_replace_preserves_previous_store_bytes(tmp_path, monkeypatch):
    transcript_ref, observation = _iox_transcript(tmp_path)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER))
    before = open(store.path, "rb").read()

    def fail_replace(_source, _destination):
        raise OSError("injected replace failure")

    monkeypatch.setattr(deployment_records.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replace failure"):
        store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD, _iox_wrapper(),
                        observation, transcript_ref)
    assert open(store.path, "rb").read() == before


def test_failed_parent_sync_reports_uncertain_committed_write_without_rollback(
        tmp_path, monkeypatch):
    import os
    import stat

    transcript_ref, observation = _iox_transcript(tmp_path)
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    store.create(_record(record_id="iox-r1", controller_id=_IOX_CONTROLLER))
    before = open(store.path, "rb").read()
    real_fsync = deployment_records.os.fsync

    def fail_parent_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected parent sync failure")
        return real_fsync(fd)

    monkeypatch.setattr(deployment_records.os, "fsync", fail_parent_sync)
    with pytest.raises(OSError, match="injected parent sync failure"):
        store.iox_begin("iox-r1", _IOX_CONTROLLER, _IOX_BOARD, _iox_wrapper(),
                        observation, transcript_ref)
    after = open(store.path, "rb").read()
    assert after != before
    assert b'"iox_verification"' in after


def test_iox_store_lock_wait_honors_supplied_absolute_deadline(
        tmp_path, monkeypatch):
    import errno
    import fcntl

    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    with store._store_lock():
        pass
    clock = [0.0]
    attempts = []

    def blocked(unused_fd, operation):
        if operation & fcntl.LOCK_NB:
            attempts.append(clock[0])
            raise OSError(errno.EAGAIN, "held by another controller")

    monkeypatch.setattr(deployment_records.fcntl, "flock", blocked)
    monkeypatch.setattr(
        deployment_records.time, "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(ValueError, match="store lock timed out"):
        store.iox_obligations(
            "BOARD-DEADLINE", deadline=0.025,
            monotonic_fn=lambda: clock[0])
    assert attempts == [0.0, 0.01, 0.02]
    assert clock[0] == 0.025
