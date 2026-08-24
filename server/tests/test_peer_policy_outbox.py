# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Policy operation outbox: bounded at-least-once export ledger (spec 7 / 10.4 /
10.5b). Multiple mutations before a tracker poll, revision-ordered stable export,
ack-prune on next mutation, 256-unacked rejection, and restart replay."""
import collections
import json
import os

import pytest

import peer_policy

Principal = collections.namedtuple("Principal", ["type", "id"])


@pytest.fixture
def paths(tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    return auth, lkg


def _assign(auth, lkg, dev, actor="console:admin", now=1000.0):
    peer_policy.commit_mutation(
        auth, lkg, action="assign", target=dev, actor=actor, now=now,
        mutate=lambda d: d["assignments"].__setitem__(dev, "quarantine"))


def _read(path):
    with open(path) as f:
        return json.load(f)


class TestOutboxShape:
    def test_no_singular_last_operation_field(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        doc = _read(auth)
        assert "last_operation" not in doc
        assert isinstance(doc["operation_outbox"], list)

    def test_entry_fields(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1", actor="console:admin", now=1234.0)
        entry = _read(auth)["operation_outbox"][-1]
        assert set(entry) == {"event_id", "revision", "action", "target",
                              "actor", "created_at"}
        assert entry["revision"] == 2
        assert entry["action"] == "assign"
        assert entry["target"] == "iris8kv-1"
        assert entry["actor"] == "console:admin"
        assert entry["created_at"] == 1234.0
        # nonsecret 16-hex event id
        assert len(entry["event_id"]) == 16
        int(entry["event_id"], 16)


class TestOrderedExport:
    def test_multiple_mutations_before_poll_export_in_revision_order(self,
                                                                    paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        _assign(auth, lkg, "iris8kv-3")
        doc = _read(auth)
        pending = peer_policy.pending_exports(doc, exported_revision=1)
        assert [e["revision"] for e in pending] == [2, 3, 4]
        # stable event ids
        ids = [e["event_id"] for e in pending]
        assert len(set(ids)) == 3

    def test_pending_exports_respects_watermark(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        doc = _read(auth)
        pending = peer_policy.pending_exports(doc, exported_revision=2)
        assert [e["revision"] for e in pending] == [3]

    def test_reexport_after_crash_same_event_ids(self, paths):
        # at-least-once: exporting again without advancing watermark yields the
        # same stable event ids (never lost, may repeat).
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        doc = _read(auth)
        first = peer_policy.pending_exports(doc, exported_revision=1)
        second = peer_policy.pending_exports(doc, exported_revision=1)
        assert [e["event_id"] for e in first] == [e["event_id"] for e in second]


class TestAckPrune:
    def test_acked_entries_pruned_on_next_mutation(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")   # rev 2
        _assign(auth, lkg, "iris8kv-2")   # rev 3
        # tracker acked through revision 3
        # next mutation prunes entries at/below the acked watermark
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-4", actor="a",
            now=1.0, acked_revision=3,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-4",
                                                          "quarantine"))
        outbox = _read(auth)["operation_outbox"]
        assert [e["revision"] for e in outbox] == [4]

    def test_unacked_entries_retained(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-4", actor="a",
            now=1.0, acked_revision=0,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-4",
                                                          "quarantine"))
        outbox = _read(auth)["operation_outbox"]
        assert [e["revision"] for e in outbox] == [2, 3, 4]


class TestBacklogFull:
    def test_256_unacked_rejects_without_file_change(self, paths):
        auth, lkg = paths
        doc = peer_policy.load_policy(auth, lkg).document
        # stuff 256 unacked entries directly
        doc["operation_outbox"] = [
            {"event_id": "%016x" % i, "revision": i + 2, "action": "assign",
             "target": "d%d" % i, "actor": "a", "created_at": 1.0}
            for i in range(256)]
        doc["revision"] = 257
        peer_policy._atomic_write_json(auth, doc)
        before = _read(auth)
        with pytest.raises(peer_policy.OperationBacklogFull):
            peer_policy.commit_mutation(
                auth, lkg, action="assign", target="x", actor="a", now=1.0,
                acked_revision=0,
                mutate=lambda d: d["assignments"].__setitem__("x",
                                                              "quarantine"))
        # no file change
        assert _read(auth) == before

    def test_ack_relieves_backlog(self, paths):
        auth, lkg = paths
        doc = peer_policy.load_policy(auth, lkg).document
        doc["operation_outbox"] = [
            {"event_id": "%016x" % i, "revision": i + 2, "action": "assign",
             "target": "d%d" % i, "actor": "a", "created_at": 1.0}
            for i in range(256)]
        doc["revision"] = 257
        peer_policy._atomic_write_json(auth, doc)
        # ack all -> prune allows the mutation
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="x", actor="a", now=1.0,
            acked_revision=257,
            mutate=lambda d: d["assignments"].__setitem__("x", "quarantine"))
        outbox = _read(auth)["operation_outbox"]
        assert [e["revision"] for e in outbox] == [258]


class TestRestartRetainsEntries:
    def test_entries_survive_reload(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        # simulate restart: fresh load from disk
        reloaded = peer_policy.load_policy(auth, lkg).document
        assert [e["revision"] for e in reloaded["operation_outbox"]] == [2, 3]


class TestImpossibleAckWatermark:
    """`last_operation_exported_revision` is persisted in the enforcement status
    file, separately from the policy document. A restored/reset document can sit
    BELOW a watermark written for an older, higher-revisioned one. Honoring such a
    watermark is doubly destructive: it suppresses every export AND silently
    discards every unacknowledged entry at the next write. It must fail safe."""

    def test_watermark_above_document_revision_does_not_suppress_export(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        doc = _read(auth)
        assert doc["revision"] == 2
        # a watermark carried over from a higher-revisioned document
        assert [e["revision"] for e in peer_policy.pending_exports(doc, 306)] == [2]
        assert peer_policy.pending_exports(doc, 306) == \
            peer_policy.pending_exports(doc, 0)

    def test_impossible_watermark_does_not_discard_entries(self, paths):
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        before = [e["event_id"] for e in _read(auth)["operation_outbox"]]
        assert len(before) == 2
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-3", actor="a",
            now=1.0, acked_revision=306,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-3",
                                                          "quarantine"))
        outbox = _read(auth)["operation_outbox"]
        assert [e["event_id"] for e in outbox][:2] == before
        assert [e["revision"] for e in outbox] == [2, 3, 4]

    def test_legitimate_watermark_still_prunes(self, paths):
        """Regression guard: the fix must not disable ordinary ack-pruning."""
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        _assign(auth, lkg, "iris8kv-2")
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-3", actor="a",
            now=1.0, acked_revision=3,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-3",
                                                          "quarantine"))
        assert [e["revision"] for e in _read(auth)["operation_outbox"]] == [4]

    def test_watermark_equal_to_revision_is_honored(self, paths):
        """The boundary is `>`, not `>=`: acking the current revision is real."""
        auth, lkg = paths
        _assign(auth, lkg, "iris8kv-1")
        doc = _read(auth)
        assert peer_policy.pending_exports(doc, doc["revision"]) == []

    @pytest.mark.parametrize("bad", [-1, "306", True, None, 3.5])
    def test_junk_watermark_fails_safe_to_zero(self, bad):
        doc = {"revision": 9, "operation_outbox": [
            {"revision": 4, "event_id": "a", "action": "assign",
             "target": "d", "actor": "x", "created_at": 1.0}]}
        assert peer_policy.effective_acked(doc, bad) == 0
        assert len(peer_policy.pending_exports(doc, bad)) == 1

    def test_document_without_usable_revision_fails_safe(self):
        assert peer_policy.effective_acked({}, 5) == 0
        assert peer_policy.effective_acked({"revision": "9"}, 5) == 0
        assert peer_policy.effective_acked(None, 5) == 0

    def test_effective_acked_passes_through_a_real_watermark(self):
        assert peer_policy.effective_acked({"revision": 9}, 4) == 4
        assert peer_policy.effective_acked({"revision": 9}, 9) == 9
        assert peer_policy.effective_acked({"revision": 9}, 0) == 0
