# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Outbox acknowledgement lineage and bounded retirement replay contracts."""
import copy
import hashlib
import pytest

import peer_policy


def _commit(auth, lkg, target, acked_revision=0):
    return peer_policy.commit_mutation(
        auth, lkg, action="unassign", target=target, actor="test",
        now=1000.0, mutate=lambda _candidate: None,
        acked_revision=acked_revision)


def _ack(doc, revision=None):
    return {
        "last_operation_exported_revision": (
            doc["revision"] if revision is None else revision),
        "operation_ack_epoch": doc["operation_ack_epoch"],
    }


def _event_epoch(event):
    return hashlib.sha256(event["event_id"].encode()).hexdigest()[:32]


def test_older_ack_is_validated_by_its_retained_outbox_event(tmp_path):
    auth, lkg = str(tmp_path / "policy.json"), str(tmp_path / "policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    first = _commit(auth, lkg, "first")
    second = _commit(auth, lkg, "second")
    ack = _ack(first)

    assert peer_policy.effective_acked(second, ack) == first["revision"]
    assert peer_policy.pending_exports(second, ack) == [
        event for event in second["operation_outbox"]
        if event["revision"] > first["revision"]]


def test_older_ack_without_anchor_fails_safe_to_zero(tmp_path):
    auth, lkg = str(tmp_path / "policy.json"), str(tmp_path / "policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    first = _commit(auth, lkg, "first")
    second = _commit(auth, lkg, "second")
    missing = copy.deepcopy(second)
    missing["operation_outbox"] = [
        event for event in missing["operation_outbox"]
        if event["revision"] != first["revision"]]

    assert peer_policy.effective_acked(missing, _ack(first)) == 0
    assert peer_policy.pending_exports(missing, _ack(first)) == missing[
        "operation_outbox"]


def test_ancestor_proof_rejects_divergent_branch_after_restore_and_regrowth(
        tmp_path):
    main_auth = str(tmp_path / "main-policy.json")
    main_lkg = str(tmp_path / "main-policy.lkg.json")
    branch_auth = str(tmp_path / "branch-policy.json")
    branch_lkg = str(tmp_path / "branch-policy.lkg.json")
    peer_policy.initialize(main_auth, main_lkg)
    peer_policy.initialize(branch_auth, branch_lkg)

    main_first = _commit(main_auth, main_lkg, "main-first")
    _commit(main_auth, main_lkg, "main-second")
    branch_first = _commit(branch_auth, branch_lkg, "branch-first")
    _commit(branch_auth, branch_lkg, "branch-second")
    # Revisions match, but event IDs (and therefore branch epochs) differ.
    assert branch_first["revision"] == main_first["revision"]
    assert _event_epoch(branch_first["operation_outbox"][0]) != \
        _event_epoch(main_first["operation_outbox"][0])

    restored = peer_policy.restore_lkg_revision(
        main_auth, main_lkg, main_first["revision"], actor="test",
        now=1001.0, expected_revision=3)
    regrown = _commit(main_auth, main_lkg, "after-restore")
    assert restored["revision"] == 4
    assert regrown["revision"] == 5

    # Same revision from the discarded branch cannot prune this branch's
    # events, even after restore and another commit.
    assert peer_policy.effective_acked(regrown, _ack(branch_first)) == 0
    # The exact retained ancestor from the live branch remains usable.
    assert peer_policy.effective_acked(regrown, _ack(main_first)) == \
        main_first["revision"]


def test_future_ack_revision_is_rejected_even_with_current_epoch(tmp_path):
    auth, lkg = str(tmp_path / "policy.json"), str(tmp_path / "policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    current = _commit(auth, lkg, "one")
    assert peer_policy.effective_acked(current, {
        "last_operation_exported_revision": current["revision"] + 1,
        "operation_ack_epoch": current["operation_ack_epoch"],
    }) == 0


def test_current_epoch_keeps_partial_watermark_compatibility(tmp_path):
    auth, lkg = str(tmp_path / "policy.json"), str(tmp_path / "policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    current = _commit(auth, lkg, "one")
    assert peer_policy.effective_acked(current, _ack(current, 1)) == 1


@pytest.mark.parametrize("epoch", [None, "é" * 32, "bad", 42, "f" * 32])
def test_malformed_or_unrelated_ack_is_not_ancestry(tmp_path, epoch):
    auth, lkg = str(tmp_path / "policy.json"), str(tmp_path / "policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    first = _commit(auth, lkg, "first")
    second = _commit(auth, lkg, "second")
    ack = dict(_ack(first), operation_ack_epoch=epoch)
    assert peer_policy.effective_acked(second, ack) == 0
