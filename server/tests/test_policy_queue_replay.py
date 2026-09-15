# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import types

import otlp
import peer_policy
import telemetry
import tracker


def test_duplicate_acceptance_is_opt_in_and_zero_capacity_still_refuses():
    queue = otlp.LogQueue(event_key=lambda event: event["id"])
    assert queue.emit({"id": "one"}) is True
    assert queue.emit({"id": "one"}) is False
    assert queue.emit({"id": "one"}, accept_duplicate=True) is True
    assert queue.queued == 1
    assert otlp.LogQueue(max_queue=0).emit({}, accept_duplicate=True) is False


def test_inflight_replay_acknowledges_without_duplicate_insertion():
    queue = otlp.LogQueue(event_key=lambda event: event["id"])
    queue.emit({"id": "one"})
    def send(batch):
        assert queue.emit({"id": "one"}, accept_duplicate=True) is True
        assert queue.queued == 1
    assert queue.flush(send) == 1
    assert queue.queued == 0
    # Delivered/evicted is not falsely acknowledged: it must be inserted again.
    assert queue.emit({"id": "one"}, accept_duplicate=True) is True
    assert queue.queued == 1


def test_retained_ancestor_ack_advances_without_replaying_accepted_prefix(tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    queue = otlp.LogQueue(event_key=telemetry._otlp_record_event_id)
    hub = types.SimpleNamespace(log_queue=queue)
    exporter = types.SimpleNamespace(
        _audit_export=lambda entries: None,
        _emit_policy_event=lambda entry, status:
            telemetry.Telemetry.emit_policy_event(hub, entry, status))
    def mutate(device):
        return peer_policy.unassign_device(auth, lkg, device, "console:test", 1000)
    first = mutate("one")
    policy = peer_policy.load_policy(auth, lkg)
    ack = tracker.TrackerReconciler._export_outbox(exporter, policy, 0, {})
    assert ack == first["revision"]
    second = mutate("two")  # retains the exact acknowledged event as proof
    prior_ack = {"last_operation_exported_revision": ack,
                 "operation_ack_epoch": first["operation_ack_epoch"]}
    assert peer_policy.effective_acked(second, prior_ack) == ack
    policy = peer_policy.load_policy(auth, lkg)
    assert tracker.TrackerReconciler._export_outbox(exporter, policy, prior_ack, {}) == second["revision"]
    assert queue.queued == 2


def test_six_hundred_retirements_with_fifty_write_ack_lag_stay_bounded(
        tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    exporter = types.SimpleNamespace(
        _audit_export=lambda _entries: None,
        _emit_policy_event=lambda _entry, _status: True)
    ack = 0
    max_outbox = 0

    for index in range(1, 601):
        committed = peer_policy.unassign_device(
            auth, lkg, "synthetic-%03d" % index, "test", 1000.0 + index,
            acked_revision=ack)
        max_outbox = max(max_outbox, len(committed["operation_outbox"]))
        assert len(committed["operation_outbox"]) < peer_policy.OUTBOX_CAP

        if index % 50 == 25:
            # Export captures a snapshot, then writers make 25 more commits
            # before its acknowledgement becomes visible to the next writer.
            policy = peer_policy.load_policy(auth, lkg)
        if index % 50 == 0:
            ack = tracker.TrackerReconciler._export_outbox(
                exporter, policy, ack, {})
            assert ack == policy.document["revision"]
            ack = {
                "last_operation_exported_revision": ack,
                "operation_ack_epoch": policy.document[
                    "operation_ack_epoch"],
            }

    assert committed["revision"] == 601
    assert max_outbox <= 75
