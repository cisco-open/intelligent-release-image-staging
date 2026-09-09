# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Cross-store role write contracts.

These tests deliberately exercise the coordinator rather than duplicating its
two-store sequence in an API or CLI fixture.  The role transaction lock must
always be the outer lock: role-management -> fleet/keyed state or peer-policy.
"""
import collections
import importlib
import json
import os
import threading
import time

import pytest

import assignment_service
import catalog
import gui_fleet
import keyed_state
import peer_policy


Principal = collections.namedtuple("Principal", ["type", "id"])


def _module():
    # Kept inside a helper so the prescribed red run reports missing behavior
    # as test failures instead of aborting collection before the other red
    # assertions execute.
    return importlib.import_module("role_management")


def _paths(tmp_path):
    state = str(tmp_path)
    return (os.path.join(state, "peer-policy.json"),
            os.path.join(state, "peer-policy.lkg.json"))


def _write_roles(tmp_path, definitions):
    auth_path, lkg_path = _paths(tmp_path)
    for name, definition in definitions:
        peer_policy.define_role(
            auth_path, lkg_path, name, definition,
            actor="test", now=1.0)
    return auth_path, lkg_path


def _fleet(tmp_path, count=1):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    for index in range(count):
        fleet.upsert({"device_id": "d%02d" % index,
                      "device_ip": "10.0.0.%d" % (index + 1)})
    return fleet


def _manager(tmp_path, fleet=None, now=10.0):
    mod = _module()
    auth_path, lkg_path = _paths(tmp_path)
    return mod.RoleCoordinator(
        fleet or gui_fleet.FleetStore(str(tmp_path)), auth_path, lkg_path,
        now_fn=lambda: now)


def _policy(auth_path, lkg_path):
    return peer_policy.load_policy(auth_path, lkg_path)


@pytest.mark.parametrize("direction", ["tighten", "relax", "neutral"])
@pytest.mark.parametrize("bulk", [False, True])
def test_final_repair_backlog_preflight_preserves_fleet(tmp_path, direction, bulk):
    from pathlib import Path
    fleet = _fleet(tmp_path, 2)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True}), ("open", {"restricted": False})])
    manager = _manager(tmp_path, fleet)
    ids = ["d00", "d01"] if bulk else ["d00"]
    if direction == "relax":
        manager.set_roles(dict.fromkeys(ids, "boat"), actor="test")
    target = "boat" if direction == "tighten" else "open"
    doc = _policy(auth_path, lkg_path).document
    doc["revision"] = 300
    doc["operation_ack_epoch"] = "a" * 32
    doc["operation_outbox"] = [dict(doc["operation_outbox"][0], revision=i + 1,
                                    event_id="%016x" % i) for i in range(peer_policy.OUTBOX_CAP)]
    Path(auth_path).write_text(json.dumps(doc))
    manager.acked_revision_fn = lambda: {"last_operation_exported_revision": 400,
                                       "operation_ack_epoch": "a" * 32}
    def state():
        return {str(p): p.read_bytes() for p in tmp_path.rglob("*")
                if p.is_file() and not p.name.endswith(".lock")}
    before = state()
    with pytest.raises(_module().RoleManagementError) as caught:
        if bulk:
            manager.set_roles(dict.fromkeys(ids, target), actor="test")
        else:
            manager.set_role(ids[0], target, actor="test")
    assert caught.value.code == "operation_backlog_full"
    assert caught.value.partial is False
    assert state() == before
    with pytest.raises(peer_policy.OperationBacklogFull):
        manager.set_roles(dict.fromkeys(ids, target), actor="test", dry_run=True)
    assert state() == before


def test_role_transaction_lock_is_outer_to_fleet_and_policy(tmp_path,
                                                            monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    mod = _module()
    held = {"role": False}
    real_lock = mod.secrets_store.store_lock
    real_bulk = fleet.bulk_upsert
    real_commit = peer_policy.commit_mutation

    class Marker:
        def __init__(self, path):
            self.is_role_lock = os.path.basename(path) == "role-management"

        def __enter__(self):
            if self.is_role_lock:
                assert held["role"] is False
                held["role"] = True
        def __exit__(self, *_):
            if self.is_role_lock:
                held["role"] = False

    monkeypatch.setattr(mod.secrets_store, "store_lock", Marker)

    def bulk(*args, **kwargs):
        assert held["role"] is True
        return real_bulk(*args, **kwargs)

    def commit(*args, **kwargs):
        assert held["role"] is True
        return real_commit(*args, **kwargs)

    monkeypatch.setattr(fleet, "bulk_upsert", bulk)
    monkeypatch.setattr(peer_policy, "commit_mutation", commit)
    manager = mod.RoleCoordinator(fleet, auth_path, lkg_path, now_fn=lambda: 10)
    manager.set_roles({"d00": "boat"}, actor="test")
    assert held["role"] is False
    # Keep a reference so an accidental replacement of the real lock helper
    # is visible to linters and reviewers; this test intentionally substitutes
    # only the outer lock and observes both nested stores.
    assert callable(real_lock)


def test_bulk_role_mapping_is_one_revision_and_one_outbox_event(tmp_path):
    fleet = _fleet(tmp_path, 3)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]}),
        ("fiber", {"restricted": False, "peers": ["fiber"]}),
    ])
    before = _policy(auth_path, lkg_path).document
    result = _manager(tmp_path, fleet).set_roles(
        {"d00": "boat", "d01": "fiber", "d02": "boat"}, actor="test")
    after = _policy(auth_path, lkg_path).document
    assert result["ok"] is True and result["applied"] == 3
    assert after["revision"] == before["revision"] + 1
    assert len(after["operation_outbox"]) == len(before["operation_outbox"]) + 1
    assert after["roles"]["role_of"] == {
        "d00": "boat", "d01": "fiber", "d02": "boat"}


def test_add_or_tighten_declares_before_policy_and_reports_failed_phase2(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])

    real_commit = peer_policy.commit_mutation
    def fail(*_args, **_kwargs):
        if _kwargs.get("dry_run"):
            assert fleet.get_device("d00").get("role") is None
            return real_commit(*_args, **_kwargs)
        assert fleet.get_device("d00")["role"] == "boat"
        raise OSError("injected policy write failure after Fleet")

    monkeypatch.setattr(peer_policy, "commit_mutation", fail)
    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).set_role("d00", "boat", actor="test")
    assert caught.value.status == 503
    assert caught.value.partial is True
    assert caught.value.result["role_drift"] == {
        "count": 1, "device_ids": ["d00"], "truncated": False}


def test_remove_or_relax_compiles_before_fleet_and_reports_failed_phase2(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "boat", actor="test")

    def fail(*_args, **_kwargs):
        assert _policy(auth_path, lkg_path).roles.role_of.get("d00") is None
        raise gui_fleet.FleetStateError("fleet unavailable")

    monkeypatch.setattr(fleet, "bulk_upsert", fail)
    with pytest.raises(_module().RoleManagementError) as caught:
        manager.set_role("d00", None, actor="test")
    assert caught.value.status == 503
    assert caught.value.partial is True
    assert fleet.get_device("d00")["role"] == "boat"
    assert caught.value.result["role_drift"]["device_ids"] == ["d00"]


def test_explicit_single_role_clear_converges_fleet_and_policy(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "boat", actor="test")
    before = _policy(auth_path, lkg_path).document
    result = manager.set_role("d00", None, actor="test")
    after = _policy(auth_path, lkg_path).document
    assert result["ok"] is True and result["direction"] == "relax"
    assert result["role_drift"]["count"] == 0
    assert "role" not in fleet.get_device("d00")
    assert "d00" not in after["roles"]["role_of"]
    assert after["revision"] == before["revision"] + 1


def test_explicit_mixed_bulk_clear_and_relax_converges(tmp_path):
    fleet = _fleet(tmp_path, 2)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]}),
        ("fiber", {"restricted": False, "peers": ["fiber"]}),
    ])
    manager = _manager(tmp_path, fleet)
    manager.set_roles({"d00": "boat", "d01": "boat"}, actor="test")
    before = _policy(auth_path, lkg_path).document
    result = manager.set_roles(
        {"d00": None, "d01": "fiber"}, actor="test")
    after = _policy(auth_path, lkg_path).document
    assert result["ok"] is True and result["direction"] == "relax"
    assert result["role_drift"]["count"] == 0
    assert "role" not in fleet.get_device("d00")
    assert fleet.get_device("d01")["role"] == "fiber"
    assert after["roles"]["role_of"] == {"d01": "fiber"}
    assert after["revision"] == before["revision"] + 1


def test_generic_device_upsert_with_explicit_null_role_clears(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "boat", actor="test")
    result = manager.upsert_device(
        {"device_id": "d00", "role": None}, actor="test")
    assert result["ok"] is True and result["direction"] == "relax"
    assert result["role_drift"]["count"] == 0
    assert "role" not in fleet.get_device("d00")
    assert "d00" not in _policy(auth_path, lkg_path).roles.role_of


def test_invalid_generic_upsert_is_rejected_before_relaxing_role(tmp_path):
    """A bad fleet field must not land a policy-first relaxation.

    Generic upsert deliberately compiles a relaxing role change before the
    fleet write.  Validate the complete operator input before entering that
    sequence, so a future/unknown field cannot leave policy relaxed while the
    inventory write is refused.
    """
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "boat", actor="test")
    before_fleet = fleet.get_device("d00")
    before_policy = _policy(auth_path, lkg_path).document

    with pytest.raises(ValueError, match="unknown|field"):
        manager.upsert_device(
            {"device_id": "d00", "role": None,
             "future_policy_bypass": "not allowed"},
            actor="test")

    assert fleet.get_device("d00") == before_fleet
    assert _policy(auth_path, lkg_path).document == before_policy


def test_mixed_direction_and_incomparable_role_changes_are_stable_422(tmp_path):
    fleet = _fleet(tmp_path, 4)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("tight", {"restricted": True, "origin": False,
                   "peers": ["tight"]}),
        ("left-peer", {"restricted": True, "peers": ["left-peer"]}),
        ("left", {"restricted": True,
                  "peers": ["left", "left-peer"]}),
        ("right-peer", {"restricted": True, "origin": False,
                        "peers": ["right-peer"]}),
        ("right", {"restricted": True, "origin": False,
                   "peers": ["right", "right-peer"]}),
    ])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "tight", actor="test")
    with pytest.raises(_module().RoleManagementError) as mixed:
        manager.set_roles({"d00": None, "d01": "tight"}, actor="test")
    assert mixed.value.status == 422
    assert mixed.value.code == "mixed_role_direction"
    # Seed the starting restricted membership directly. Going from
    # unrestricted to ``left`` also gains the existing ``left-peer`` cohort,
    # so the full mutual-edge classifier correctly refuses that combined
    # add/remove operation as incomparable.
    fleet.bulk_set_roles({"d01": "left", "d02": "left-peer",
                          "d03": "right-peer"})
    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "d01", "test", 11,
        lambda candidate: candidate["roles"]["role_of"].update({
            "d01": "left", "d02": "left-peer", "d03": "right-peer"}))
    with pytest.raises(_module().RoleManagementError) as incomparable:
        manager.set_role("d01", "right", actor="test")
    assert incomparable.value.status == 422
    assert incomparable.value.code == "incomparable_role_change"
    assert "split" in str(incomparable.value).lower()
    assert _policy(auth_path, lkg_path).roles.role_of["d01"] == "left"


def test_restricted_role_direction_uses_actual_reachable_populations():
    mod = _module()
    document = peer_policy.base_document()
    document["roles"] = {
        "defs": {
            "isolated-a": {"restricted": True, "origin": False,
                           "peers": ["isolated-a"]},
            "isolated-b": {"restricted": True, "origin": False,
                           "peers": ["isolated-b"]},
            "connected-a": {"restricted": True, "origin": False,
                            "peers": ["connected-a", "connected-b"]},
            "connected-b": {"restricted": True, "origin": False,
                            "peers": ["connected-a", "connected-b"]},
        },
        "role_of": {}, "qos_default": {}, "qos_device": {},
    }
    document["roles_present"] = True
    peer_policy.validate_document(document)
    assert mod._change_direction(
        document, "isolated-a", "isolated-b") == "incomparable"
    assert mod._change_direction(
        document, "connected-a", "connected-b") == "neutral"


def test_bulk_direction_computes_each_distinct_transition_once(tmp_path,
                                                               monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("a", {"restricted": True, "origin": False,
               "peers": ["a"]}),
        ("b", {"restricted": True, "origin": False,
               "peers": ["b"]}),
    ])
    document = _policy(auth_path, lkg_path).document
    document["roles"]["defs"]["a"]["peers"] = ["a", "b"]
    document["roles"]["defs"]["b"]["peers"] = ["a", "b"]
    document["roles"]["role_of"] = {
        "d%05d" % index: "a" for index in range(10_000)}
    peer_policy.validate_document(document)
    mod = _module()
    calls = []
    real_change_direction = mod._change_direction

    def counted(*args, **kwargs):
        calls.append(args[1:])
        return real_change_direction(*args, **kwargs)

    monkeypatch.setattr(mod, "_change_direction", counted)
    mapping = {"d%05d" % index: "b" for index in range(10_000)}
    assert _manager(tmp_path, fleet)._direction(document, mapping) == "neutral"
    assert calls == [("a", "b", False)]


def test_idempotent_role_retry_does_not_grow_policy_revision_or_outbox(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "boat", actor="test")
    before = _policy(auth_path, lkg_path).document
    result = manager.set_role("d00", "boat", actor="test")
    after = _policy(auth_path, lkg_path).document
    assert result["ok"] is True
    assert result["direction"] == "neutral"
    assert result["revision"] == before["revision"]
    assert after["revision"] == before["revision"]
    assert after["operation_outbox"] == before["operation_outbox"]


def test_migration_confirmation_binds_actual_shadow_removal_candidate(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "origin": False,
                  "peers": ["boat"]}),
        ("other", {"restricted": True, "origin": False,
                   "peers": ["other"]}),
    ])

    def assign(candidate):
        candidate["acls"]["old"] = {
            "rules": [{"seq": 10, "action": "permit",
                       "match": {"type": "any"}}]}
        candidate["assignments"]["d00"] = "old"

    peer_policy.commit_mutation(
        auth_path, lkg_path, "assign", "d00", "test", 2, assign)
    manager = _manager(tmp_path, fleet)
    preview = manager.migrate_assignment(
        "old", "boat", actor="test", dry_run=True)
    assert preview["shadowed_inert"] == ["d00"]
    assert preview["newly_restricted"] == ["d00"]
    assert preview["origin_access_lost"] == 1

    real_commit = peer_policy.commit_mutation

    def tamper_release(*args, **kwargs):
        if kwargs.get("action") == "migrate_release":
            real_mutate = kwargs["mutate"]

            def tamper(candidate):
                real_mutate(candidate)
                candidate["roles"]["role_of"]["d00"] = "other"

            kwargs["mutate"] = tamper
        return real_commit(*args, **kwargs)

    monkeypatch.setattr(peer_policy, "commit_mutation", tamper_release)
    with pytest.raises(_module().RoleManagementError) as caught:
        manager.migrate_assignment(
            "old", "boat", actor="test", dry_run=False,
            confirm_token=preview["confirm_token"])
    assert caught.value.code == "confirmation_required"
    assert caught.value.partial is True
    live = _policy(auth_path, lkg_path).document
    assert live["roles"]["role_of"]["d00"] == "boat"
    assert live["assignments"]["d00"] == "old"


def test_unknown_role_and_nonquarantine_shadow_refuse_before_writes(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    before = fleet.snapshot(), _policy(auth_path, lkg_path).document
    with pytest.raises(_module().RoleManagementError) as missing:
        manager.set_role("d00", "missing", actor="test")
    assert missing.value.code == "role_not_found"
    assert (fleet.snapshot(), _policy(auth_path, lkg_path).document) == before

    def assign(candidate):
        candidate["acls"]["manual"] = {
            "rules": [{"seq": 10, "action": "permit",
                       "match": {"type": "any"}}]}
        candidate["assignments"]["d00"] = "manual"
    peer_policy.commit_mutation(
        auth_path, lkg_path, "assign", "d00", "test", 20, assign)
    before = fleet.snapshot(), _policy(auth_path, lkg_path).document
    with pytest.raises(_module().RoleManagementError) as shadow:
        manager.set_role("d00", "boat", actor="test")
    assert shadow.value.status == 409
    assert shadow.value.code == "role_shadowed_by_assignment"
    assert (fleet.snapshot(), _policy(auth_path, lkg_path).document) == before


def test_role_drift_is_bounded_sorted_and_quarantine_is_not_shadow_drift(tmp_path):
    fleet = _fleet(tmp_path, 14)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    doc = _policy(auth_path, lkg_path).document
    doc["roles"]["role_of"] = {
        "d%02d" % index: "boat" for index in range(14)}
    doc["assignments"]["d00"] = peer_policy.RESERVED_QUARANTINE
    peer_policy.validate_document(doc)
    peer_policy._atomic_write_json(auth_path, doc)
    drift = _manager(tmp_path, fleet).role_drift()
    assert drift == {"count": 14,
                     "device_ids": ["d%02d" % index for index in range(10)],
                     "truncated": True}

    fleet.bulk_upsert(["d%02d" % index for index in range(14)], {"role": "boat"})
    assert _manager(tmp_path, fleet).role_drift() == {
        "count": 0, "device_ids": [], "truncated": False}


def test_role_dry_run_and_csv_preview_write_nothing(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    before = fleet.snapshot(), _policy(auth_path, lkg_path).document
    preview = manager.set_role("d00", "boat", actor="test", dry_run=True)
    assert preview["dry_run"] is True
    assert preview["direction"] == "tighten"
    assert (fleet.snapshot(), _policy(auth_path, lkg_path).document) == before

    row = fleet.get_device("d00")
    row["role"] = "boat"
    csv_text = ",".join(gui_fleet.CSV_V2_COLS) + "\n" + \
        ",".join(str(row.get(key, "")) for key in gui_fleet.CSV_V2_COLS) + "\n"
    preview = manager.import_csv(csv_text, actor="test", dry_run=True)
    assert preview["dry_run"] is True and preview["stats"]["imported"] == 1
    assert (fleet.snapshot(), _policy(auth_path, lkg_path).document) == before


def test_csv_import_synchronizes_multiple_roles_with_one_policy_event(tmp_path):
    fleet = _fleet(tmp_path, 2)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": False, "peers": ["boat"]}),
        ("fiber", {"restricted": False, "peers": ["fiber"]}),
    ])
    rows = []
    for index, role in enumerate(("boat", "fiber")):
        row = fleet.get_device("d%02d" % index)
        row["role"] = role
        rows.append(",".join(str(row.get(key, ""))
                             for key in gui_fleet.CSV_V2_COLS))
    before = _policy(auth_path, lkg_path).document
    result = _manager(tmp_path, fleet).import_csv(
        ",".join(gui_fleet.CSV_V2_COLS) + "\n" + "\n".join(rows) + "\n",
        actor="test")
    after = _policy(auth_path, lkg_path).document
    assert result["ok"] is True and result["stats"]["imported"] == 2
    assert after["revision"] == before["revision"] + 1
    assert len(after["operation_outbox"]) == len(before["operation_outbox"]) + 1
    assert {fleet.get_device("d00")["role"],
            fleet.get_device("d01")["role"]} == {"boat", "fiber"}


def test_blank_csv_has_no_membership_opinion_during_existing_drift(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    peer_policy.set_role(
        auth_path, lkg_path, "d00", "boat", actor="test", now=2.0)
    row = fleet.get_device("d00")
    text = ",".join(gui_fleet.CSV_V2_COLS) + "\n" + \
        ",".join(str(row.get(key, ""))
                 for key in gui_fleet.CSV_V2_COLS) + "\n"
    before = _policy(auth_path, lkg_path).document
    result = _manager(tmp_path, fleet).import_csv(text, actor="test")
    after = _policy(auth_path, lkg_path).document
    assert after == before
    assert fleet.get_device("d00").get("role") is None
    assert result["role_drift"] == {
        "count": 1, "device_ids": ["d00"], "truncated": False}


@pytest.mark.parametrize("ingress", ["set", "generic", "csv"])
def test_every_fleet_first_ingress_cas_protects_its_classified_revision(
        tmp_path, monkeypatch, ingress):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": False, "peers": ["boat"]})])
    manager = _manager(tmp_path, fleet)
    real_commit = peer_policy.commit_mutation

    def interleave():
        real_commit(
            auth_path, lkg_path, "assign", "racer", "test", 20,
            lambda candidate: candidate["assignments"].__setitem__(
                "racer", peer_policy.RESERVED_QUARANTINE))

    if ingress == "set":
        real_write = fleet.bulk_upsert
        def raced_write(*args, **kwargs):
            result = real_write(*args, **kwargs)
            interleave()
            return result
        monkeypatch.setattr(fleet, "bulk_upsert", raced_write)
        invoke = lambda: manager.set_role("d00", "boat", actor="test")
        device_id = "d00"
    elif ingress == "generic":
        real_write = fleet.upsert
        def raced_write(*args, **kwargs):
            result = real_write(*args, **kwargs)
            interleave()
            return result
        monkeypatch.setattr(fleet, "upsert", raced_write)
        invoke = lambda: manager.upsert_device(
            {"device_id": "new", "device_ip": "10.0.0.9", "role": "boat"},
            actor="test")
        device_id = "new"
    else:
        row = fleet.get_device("d00")
        row["role"] = "boat"
        text = ",".join(gui_fleet.CSV_V2_COLS) + "\n" + \
            ",".join(str(row.get(key, ""))
                     for key in gui_fleet.CSV_V2_COLS) + "\n"
        real_write = fleet.import_parsed_csv
        def raced_write(*args, **kwargs):
            result = real_write(*args, **kwargs)
            interleave()
            return result
        monkeypatch.setattr(fleet, "import_parsed_csv", raced_write)
        invoke = lambda: manager.import_csv(text, actor="test")
        device_id = "d00"

    with pytest.raises(_module().RoleManagementError) as caught:
        invoke()
    assert caught.value.code == "revision_conflict"
    assert caught.value.partial is True
    assert fleet.get_device(device_id)["role"] == "boat"
    assert device_id not in _policy(auth_path, lkg_path).roles.role_of


def _two_shard_ids(fleet):
    first = "d00"
    first_bucket = keyed_state.bucket_of(first, fleet._devices.shards)
    second = next("d%02d" % index for index in range(1, 100)
                  if keyed_state.bucket_of(
                      "d%02d" % index, fleet._devices.shards) != first_bucket)
    return first, second


def _three_shard_ids(fleet):
    result = []
    buckets = set()
    for index in range(100):
        device_id = "d%02d" % index
        bucket = keyed_state.bucket_of(device_id, fleet._devices.shards)
        if bucket not in buckets:
            result.append(device_id)
            buckets.add(bucket)
        if len(result) == 3:
            return tuple(result)
    raise AssertionError("could not find three distinct fleet shards")


def test_bulk_second_shard_failure_reports_exact_live_outcomes_and_drift(
        tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    first, second = _two_shard_ids(fleet)
    for index, device_id in enumerate((first, second), 1):
        fleet.upsert({"device_id": device_id,
                      "device_ip": "10.0.0.%d" % index})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    real_write = fleet._devices._write_shard
    calls = {"count": 0}
    def fail_second(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("second shard failed")
        return real_write(*args, **kwargs)
    monkeypatch.setattr(fleet._devices, "_write_shard", fail_second)

    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).set_roles(
            {first: "boat", second: "boat"}, actor="test")
    body = caught.value.result
    assert caught.value.partial is True
    assert body["applied"] == 1 and len(body["failed"]) == 1
    assert body["role_drift"]["count"] == 1
    assert sum(fleet.get_device(d).get("role") == "boat"
               for d in (first, second)) == 1
    assert _policy(auth_path, lkg_path).roles.role_of == {}


def test_bulk_partial_counts_unvisited_already_satisfied_row_as_applied(
        tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    first, second, satisfied = _three_shard_ids(fleet)
    for index, device_id in enumerate((first, second, satisfied), 1):
        fleet.upsert({"device_id": device_id,
                      "device_ip": "10.0.0.%d" % index,
                      "role": "boat" if device_id == satisfied else None})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": False, "peers": ["boat"]})])
    peer_policy.set_role(
        auth_path, lkg_path, satisfied, "boat", actor="test", now=2)
    real_write = fleet._devices._write_shard
    calls = {"count": 0}
    def fail_second(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("second shard failed")
        return real_write(*args, **kwargs)
    monkeypatch.setattr(fleet._devices, "_write_shard", fail_second)

    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).set_roles(
            {first: "boat", second: "boat", satisfied: "boat"},
            actor="test")
    assert caught.value.result["applied"] == 2
    assert set(caught.value.result["failed"]) == {second}
    assert caught.value.result["role_drift"] == {
        "count": 1, "device_ids": [first], "truncated": False}


def test_csv_second_shard_failure_reports_exact_live_rows_and_stats(
        tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    first, second = _two_shard_ids(fleet)
    for index, device_id in enumerate((first, second), 1):
        fleet.upsert({"device_id": device_id,
                      "device_ip": "10.0.0.%d" % index})
    _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    rows = []
    for device_id in (first, second):
        row = fleet.get_device(device_id)
        row["role"] = "boat"
        rows.append(",".join(str(row.get(key, ""))
                             for key in gui_fleet.CSV_V2_COLS))
    text = ",".join(gui_fleet.CSV_V2_COLS) + "\n" + "\n".join(rows) + "\n"
    real_write = fleet._devices._write_shard
    calls = {"count": 0}
    def fail_second(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("second shard failed")
        return real_write(*args, **kwargs)
    monkeypatch.setattr(fleet._devices, "_write_shard", fail_second)

    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).import_csv(text, actor="test")
    body = caught.value.result
    assert caught.value.partial is True
    assert body["applied"] == body["stats"]["imported"] == 1
    assert body["stats"]["updated"] == 1
    assert len(body["failed"]) == 1
    assert body["role_drift"]["count"] == 1


def test_unrestricted_direction_includes_restricted_candidate_side_edges(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path, 2)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("u1", {"restricted": False, "peers": ["u1"]}),
        ("u2", {"restricted": False, "peers": ["u2"]}),
        ("r", {"restricted": True, "peers": ["r", "u1"]}),
    ])
    manager = _manager(tmp_path, fleet)
    manager.set_role("d00", "u2", actor="test")
    fleet.bulk_upsert(["d01"], {"role": "r"})
    peer_policy.set_role(
        auth_path, lkg_path, "d01", "r", actor="test", now=3)
    real_commit = peer_policy.commit_mutation
    def fail_change(*args, **kwargs):
        if kwargs.get("action") == "set_roles_bulk":
            raise peer_policy.OperationBacklogFull("full")
        return real_commit(*args, **kwargs)
    monkeypatch.setattr(peer_policy, "commit_mutation", fail_change)

    with pytest.raises(_module().RoleManagementError) as caught:
        manager.set_role("d00", "u1", actor="test")
    assert caught.value.code == "operation_backlog_full"
    assert fleet.get_device("d00")["role"] == "u2"
    assert _policy(auth_path, lkg_path).roles.role_of["d00"] == "u2"


def test_restricted_boundary_uses_full_signature_and_rejects_added_edge(
        tmp_path):
    fleet = _fleet(tmp_path, 3)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("peer", {"restricted": True, "peers": ["peer"]}),
        ("target", {"restricted": True,
                    "peers": ["target", "peer"]}),
    ])
    fleet.bulk_upsert(["d01"], {"role": "peer"})
    peer_policy.set_role(
        auth_path, lkg_path, "d01", "peer", actor="test", now=3)
    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).set_role("d00", "target", actor="test")
    assert caught.value.code == "incomparable_role_change"
    assert fleet.get_device("d00").get("role") is None

    fleet.bulk_upsert(["d00"], {"role": "target"})
    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "d00", "test", 12,
        lambda candidate: candidate["roles"]["role_of"].__setitem__(
            "d00", "target"))
    with pytest.raises(_module().RoleManagementError) as reverse:
        _manager(tmp_path, fleet).set_role("d00", None, actor="test")
    assert reverse.value.code == "incomparable_role_change"
    assert fleet.get_device("d00")["role"] == "target"


@pytest.mark.parametrize("source,target", [("u", "r"), ("r", "u")])
def test_restricted_boundary_keeps_other_members_of_old_and_new_cohorts(
        tmp_path, source, target):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    for index, (device_id, role) in enumerate((
            ("moving", source), ("u-peer", "u"), ("r-peer", "r")), 1):
        fleet.upsert({"device_id": device_id,
                      "device_ip": "10.0.0.%d" % index, "role": role})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("u", {"restricted": False, "peers": ["u"]}),
        ("r", {"restricted": True, "peers": ["r"]}),
    ])
    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "roles", "test", 3,
        lambda candidate: candidate["roles"]["role_of"].update({
            "moving": source, "u-peer": "u", "r-peer": "r"}))
    before = fleet.snapshot(), _policy(auth_path, lkg_path).document

    with pytest.raises(_module().RoleManagementError) as caught:
        _manager(tmp_path, fleet).set_role("moving", target, actor="test")
    assert caught.value.code == "incomparable_role_change"
    assert (fleet.snapshot(), _policy(auth_path, lkg_path).document) == before


def test_zero_member_migration_preview_and_apply_are_write_free(tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    peer_policy.commit_mutation(
        auth_path, lkg_path, "define", "old", "test", 2,
        lambda candidate: candidate["acls"].__setitem__(
            "old", {"rules": [{"seq": 10, "action": "deny",
                                "match": {"type": "any"}}]}))
    manager = _manager(tmp_path, fleet)
    before = _policy(auth_path, lkg_path).document
    preview = manager.migrate_assignment("old", "boat", actor="test")
    applied = manager.migrate_assignment(
        "old", "boat", actor="test", dry_run=False)
    assert preview["devices"] == applied["devices"] == []
    assert preview["ok"] is applied["ok"] is True
    assert _policy(auth_path, lkg_path).document == before


def test_migration_second_shard_failure_reports_live_partial_and_drift(
        tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    first, second = _two_shard_ids(fleet)
    for index, device_id in enumerate((first, second), 1):
        fleet.upsert({"device_id": device_id,
                      "device_ip": "10.0.0.%d" % index})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    def assign(candidate):
        candidate["acls"]["old"] = {
            "rules": [{"seq": 10, "action": "deny",
                       "match": {"type": "any"}}]}
        candidate["assignments"].update({first: "old", second: "old"})
    peer_policy.commit_mutation(
        auth_path, lkg_path, "assign", "old", "test", 2, assign)
    manager = _manager(tmp_path, fleet)
    preview = manager.migrate_assignment("old", "boat", actor="test")
    real_write = fleet._devices._write_shard
    calls = {"count": 0}
    def fail_second(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("second shard failed")
        return real_write(*args, **kwargs)
    monkeypatch.setattr(fleet._devices, "_write_shard", fail_second)

    with pytest.raises(_module().RoleManagementError) as caught:
        manager.migrate_assignment(
            "old", "boat", actor="test", dry_run=False,
            confirm_token=preview["confirm_token"])
    assert caught.value.partial is True
    assert caught.value.result["applied"] == 1
    assert len(caught.value.result["failed"]) == 1
    assert caught.value.result["role_drift"] == {
        "count": 1, "device_ids": [first], "truncated": False}


def test_quarantine_waiting_on_retirement_rechecks_device_under_outer_lock(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _paths(tmp_path)
    manager = _manager(tmp_path, fleet)
    entered_delete = threading.Event()
    allow_delete = threading.Event()
    real_delete = fleet.delete

    def blocked_delete(device_id):
        entered_delete.set()
        assert allow_delete.wait(3)
        return real_delete(device_id)
    monkeypatch.setattr(fleet, "delete", blocked_delete)
    retired = {}
    quarantined = {}

    def retire():
        retired["result"] = manager.retire_device("d00", actor="test")
    def quarantine():
        try:
            manager.set_quarantine("d00", True, actor="test",
                                   expected_revision=1)
        except Exception as exc:
            quarantined["error"] = exc

    first = threading.Thread(target=retire)
    second = threading.Thread(target=quarantine)
    first.start()
    assert entered_delete.wait(3)
    second.start()
    time.sleep(0.05)
    assert second.is_alive()
    allow_delete.set()
    first.join(3)
    second.join(3)
    assert retired["result"]["deleted"] is True
    assert quarantined["error"].code == "unknown_device"
    live = _policy(auth_path, lkg_path).document
    assert fleet.get_device("d00") is None
    assert "d00" not in live["assignments"]


def test_retirement_holds_membership_through_catalog_purge(
        tmp_path, monkeypatch):
    fleet = _fleet(tmp_path)
    manager = _manager(tmp_path, fleet)
    store = catalog.CatalogStore(str(tmp_path))
    for image_id in ("img1", "img2"):
        store.save_image({
            "id": image_id, "filename": image_id + ".bin", "size": 5,
            "sha256": "ab" * 32, "cisco_signature_verified": False,
            "info_hash_hex": "cc" * 20, "published_at": 111})
    store.set_policy("d00", approved_image_ids=["img1"])
    service = assignment_service.AssignmentService(store, fleet)
    entered_delete = threading.Event()
    allow_delete = threading.Event()
    real_delete = fleet.delete

    def blocked_delete(device_id):
        entered_delete.set()
        assert allow_delete.wait(3)
        return real_delete(device_id)

    monkeypatch.setattr(fleet, "delete", blocked_delete)
    outcomes = {}

    def retire():
        try:
            outcomes["retire"] = manager.retire_device(
                "d00", actor="test", catalog=store)
        except Exception as exc:
            outcomes["retire_error"] = exc

    def assign():
        try:
            service.apply("d00", ["img2"], actor="test")
        except Exception as exc:
            outcomes["assign_error"] = exc

    retiring = threading.Thread(target=retire)
    assigning = threading.Thread(target=assign)
    retiring.start()
    assert entered_delete.wait(3)
    assigning.start()
    time.sleep(0.05)
    assert assigning.is_alive(), "assignment bypassed retirement membership guard"
    allow_delete.set()
    retiring.join(3)
    assigning.join(3)

    assert "retire_error" not in outcomes
    assert outcomes["retire"]["deleted"] is True
    assert outcomes["retire"]["catalog_purged"] is True
    assert isinstance(outcomes.get("assign_error"),
                      assignment_service.MissingFleetDevice)
    assert fleet.get_device("d00") is None
    assert store.read_policy_row_snapshot("d00") is None


def test_role_confirmation_capture_runs_inside_policy_transaction(tmp_path, monkeypatch):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    fleet.upsert({"device_id": "d1", "device_ip": "192.0.2.1"})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    coordinator = _module().RoleCoordinator(fleet, auth_path, lkg_path)
    original = peer_policy.commit_mutation
    inside = []
    original_blast = peer_policy.blast_radius
    def blast(*args, **kwargs):
        assert inside, "preview must use the locked transaction candidate"
        return original_blast(*args, **kwargs)
    def commit(*args, **kwargs):
        hook = kwargs.get("precommit")
        assert hook is not None
        def checked(prior, candidate):
            inside.append(True)
            try:
                hook(prior, candidate)
            finally:
                inside.pop()
        kwargs["precommit"] = checked
        return original(*args, **kwargs)
    monkeypatch.setattr(peer_policy, "commit_mutation", commit)
    monkeypatch.setattr(peer_policy, "blast_radius", blast)
    preview = coordinator.set_role("d1", "boat", "test", dry_run=True)
    assert preview["requires_confirmation"]
    assert not fleet.get_device("d1").get("role")


# ---------------------------------------------------------------------------
# Workstream D: quarantine is operation history over an independent set
# ---------------------------------------------------------------------------

def test_quarantine_repeats_preserve_changing_ordinary_acl_and_event_contract(
        tmp_path):
    fleet = _fleet(tmp_path)
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]})])
    fleet.bulk_upsert(["d00"], {"role": "boat"})

    def seed(candidate):
        candidate["acls"]["manual-a"] = {"rules": []}
        candidate["acls"]["manual-b"] = {"rules": []}
        candidate["assignments"]["d00"] = "manual-a"
        candidate["roles"]["role_of"]["d00"] = "boat"

    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "d00", "test", 2.0, seed)
    manager = _manager(tmp_path, fleet, now=10.0)
    before = _policy(auth_path, lkg_path).document
    first = manager.set_quarantine(
        "d00", True, actor="console:test",
        expected_revision=before["revision"])
    assert first["revision"] == before["revision"] + 1
    assert first["assignments"]["d00"] == "manual-a"
    assert first["quarantined_devices"] == {"d00": True}
    assert peer_policy.effective_acl_name(
        first, Principal("device", "d00")) == "quarantine"
    event = first["operation_outbox"][-1]
    assert set(event) == {
        "event_id", "revision", "action", "target", "actor", "created_at"}
    assert (event["action"], event["target"], event["actor"]) == \
        ("assign", "d00", "console:test")

    repeated = manager.set_quarantine(
        "d00", True, actor="console:test",
        expected_revision=first["revision"])
    assert repeated["revision"] == first["revision"] + 1
    assert repeated["assignments"]["d00"] == "manual-a"
    assert repeated["quarantined_devices"] == {"d00": True}
    assert repeated["operation_outbox"][-1]["action"] == "assign"
    assert repeated["operation_ack_epoch"] != first["operation_ack_epoch"]

    changed = peer_policy.commit_mutation(
        auth_path, lkg_path, "assign", "d00", "test", 11.0,
        lambda candidate: candidate["assignments"].__setitem__(
            "d00", "manual-b"))
    assert changed["quarantined_devices"] == {"d00": True}
    assert peer_policy.effective_acl_name(
        changed, Principal("device", "d00")) == \
        "quarantine"

    released = manager.set_quarantine(
        "d00", False, actor="console:test",
        expected_revision=changed["revision"])
    assert released["assignments"]["d00"] == "manual-b"
    assert "quarantined_devices" not in released
    assert peer_policy.effective_acl_name(
        released, Principal("device", "d00")) == \
        "manual-b"
    assert released["operation_outbox"][-1]["action"] == "unassign"

    repeated_release = manager.set_quarantine(
        "d00", False, actor="console:test",
        expected_revision=released["revision"])
    assert repeated_release["revision"] == released["revision"] + 1
    assert repeated_release["assignments"]["d00"] == "manual-b"
    assert "quarantined_devices" not in repeated_release
    assert repeated_release["operation_outbox"][-1]["action"] == "unassign"
    with pytest.raises(_module().RoleManagementError) as caught:
        manager.set_quarantine(
            "d00", True, actor="console:test",
            expected_revision=released["revision"])
    assert caught.value.code == "revision_conflict"
    assert _policy(auth_path, lkg_path).document == repeated_release


@pytest.mark.parametrize("order", ["assignment-first", "quarantine-first"])
@pytest.mark.parametrize("quarantined", [True, False])
def test_competing_assignment_and_quarantine_serialize_without_lost_update(
        tmp_path, monkeypatch, order, quarantined):
    fleet = _fleet(tmp_path)
    fleet.bulk_upsert(["d00"], {"role": "boat"})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]}),
        ("fiber", {"restricted": False, "peers": ["fiber"]}),
    ])

    def seed(candidate):
        candidate["acls"].update({
            "manual-a": {"rules": []}, "manual-b": {"rules": []}})
        candidate["assignments"]["d00"] = "manual-a"
        candidate["roles"]["role_of"]["d00"] = "boat"
        if not quarantined:
            candidate["quarantined_devices"] = {"d00": True}

    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "d00", "test", 2.0, seed)
    manager = _manager(tmp_path, fleet, now=10.0)
    before = _policy(auth_path, lkg_path).document
    entered_first = threading.Event()
    competitor_started = threading.Event()
    release_first = threading.Event()
    real_commit = peer_policy.commit_mutation
    results = {}
    errors = []
    conflicts = []
    assignment_actor = "assignment-thread"
    quarantine_actor = "quarantine-thread"

    def assignment_mutation(candidate):
        candidate["assignments"]["d00"] = "manual-b"
        if order == "assignment-first":
            entered_first.set()
            assert release_first.wait(3)

    def controlled_commit(*args, **kwargs):
        actor = kwargs.get("actor")
        if actor == (quarantine_actor if order == "assignment-first"
                     else assignment_actor):
            competitor_started.set()
        if actor == quarantine_actor and order == "quarantine-first":
            original_mutation = kwargs["mutate"]
            def controlled_quarantine(candidate):
                original_mutation(candidate)
                entered_first.set()
                assert release_first.wait(3)
            kwargs["mutate"] = controlled_quarantine
        return real_commit(*args, **kwargs)

    monkeypatch.setattr(peer_policy, "commit_mutation", controlled_commit)

    def assign():
        try:
            results["assignment"] = peer_policy.commit_mutation(
                auth_path, lkg_path, action="assign", target="d00",
                actor=assignment_actor, now=11.0,
                mutate=assignment_mutation)
        except Exception as exc:
            errors.append(exc)

    def change_quarantine():
        expected_revision = before["revision"]
        for attempt in range(2):
            try:
                results["quarantine"] = manager.set_quarantine(
                    "d00", quarantined, actor=quarantine_actor,
                    expected_revision=expected_revision)
                return
            except _module().RoleManagementError as exc:
                if attempt == 0 and exc.code == "revision_conflict":
                    conflicts.append(exc.code)
                    expected_revision = _policy(
                        auth_path, lkg_path).document["revision"]
                    continue
                errors.append(exc)
                return

    assignment_thread = threading.Thread(target=assign)
    quarantine_thread = threading.Thread(target=change_quarantine)
    first = assignment_thread if order == "assignment-first" \
        else quarantine_thread
    second = quarantine_thread if order == "assignment-first" \
        else assignment_thread
    first.start()
    assert entered_first.wait(3)
    second.start()
    assert competitor_started.wait(3)
    assert second.is_alive()
    release_first.set()
    first.join(3)
    second.join(3)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert set(results) == {"assignment", "quarantine"}
    assert conflicts == (["revision_conflict"]
                         if order == "assignment-first" else [])
    live = _policy(auth_path, lkg_path).document
    assert live["revision"] == before["revision"] + 2
    assert live["assignments"] == {"d00": "manual-b"}
    if quarantined:
        assert live["quarantined_devices"] == {"d00": True}
    else:
        assert "quarantined_devices" not in live
    expected_events = [
        ("assign", "d00", assignment_actor),
        ("assign" if quarantined else "unassign",
         "d00", quarantine_actor),
    ]
    if order == "quarantine-first":
        expected_events.reverse()
    events = live["operation_outbox"][-2:]
    assert [event["revision"] for event in events] == [
        before["revision"] + 1, before["revision"] + 2]
    assert [(event["action"], event["target"], event["actor"])
            for event in events] == expected_events

    if quarantined:
        with pytest.raises(_module().RoleManagementError) as shadow:
            manager.set_role("d00", "fiber", actor="test")
        assert shadow.value.status == 409
        assert shadow.value.code == "role_shadowed_by_assignment"
        assert fleet.get_device("d00")["role"] == "boat"
        assert _policy(auth_path, lkg_path).document == live


def test_pure_revoke_clears_only_ordinary_assignment_and_retains_quarantine(
        tmp_path):
    fleet = _fleet(tmp_path)
    fleet.bulk_upsert(["d00"], {"role": "boat"})
    auth_path, lkg_path = _write_roles(tmp_path, [
        ("boat", {"restricted": True, "peers": ["boat"]}),
        ("fiber", {"restricted": False, "peers": ["fiber"]}),
    ])

    def seed(candidate):
        candidate["acls"]["manual"] = {"rules": []}
        candidate["assignments"]["d00"] = "manual"
        candidate["quarantined_devices"] = {"d00": True}
        candidate["roles"]["role_of"]["d00"] = "boat"
        candidate["roles"]["qos_device"]["d00"] = {"max_peers": 4}

    peer_policy.commit_mutation(
        auth_path, lkg_path, "seed", "d00", "test", 2.0, seed)
    manager = _manager(tmp_path, fleet)
    before = _policy(auth_path, lkg_path).document
    assert manager.role_drift() == {
        "count": 1, "device_ids": ["d00"], "truncated": False}
    revoked = manager.clear_assignment_for_revoke("d00", actor="iris-revoke")
    assert revoked["revision"] == before["revision"] + 1
    assert "d00" not in revoked["assignments"]
    assert revoked["quarantined_devices"] == {"d00": True}
    assert revoked["roles"]["role_of"]["d00"] == "boat"
    assert revoked["roles"]["qos_device"]["d00"] == {"max_peers": 4}
    assert revoked["operation_outbox"][-1]["action"] == "unassign"
    assert peer_policy.evaluate(
        revoked, Principal("device", "d00"),
        "10.0.0.1") == ("deny", 10)
    assert manager.role_drift() == {
        "count": 0, "device_ids": [], "truncated": False}

    unchanged = manager.clear_assignment_for_revoke(
        "d00", actor="iris-revoke")
    assert unchanged == revoked
    assert _policy(auth_path, lkg_path).document == revoked

    changed_role = manager.set_role("d00", "fiber", actor="test")
    assert changed_role["ok"] is True
    assert changed_role["direction"] == "neutral"
    assert fleet.get_device("d00")["role"] == "fiber"
    after_role = _policy(auth_path, lkg_path).document
    assert after_role["roles"]["role_of"]["d00"] == "fiber"
    assert after_role["quarantined_devices"] == {"d00": True}
    assert peer_policy.evaluate(
        after_role, Principal("device", "d00"),
        "10.0.0.1") == ("deny", 10)

    legacy = json.loads(json.dumps(after_role))
    legacy["revision"] = after_role["revision"] + 10
    legacy.pop("quarantined_devices")
    legacy["assignments"]["d00"] = peer_policy.RESERVED_QUARANTINE
    peer_policy.validate_document(legacy)
    peer_policy._atomic_write_json(auth_path, legacy)
    peer_policy._atomic_write_json(lkg_path, legacy)
    raw_bytes = (open(auth_path, "rb").read(),
                 open(lkg_path, "rb").read())

    legacy_unchanged = manager.clear_assignment_for_revoke(
        "d00", actor="iris-revoke")
    assert legacy_unchanged == legacy
    assert legacy_unchanged["revision"] == legacy["revision"]
    assert legacy_unchanged["assignments"] == {
        "d00": peer_policy.RESERVED_QUARANTINE}
    assert "quarantined_devices" not in legacy_unchanged
    assert (open(auth_path, "rb").read(),
            open(lkg_path, "rb").read()) == raw_bytes
    assert peer_policy.evaluate(
        legacy_unchanged, Principal("device", "d00"),
        "10.0.0.1") == ("deny", 10)
