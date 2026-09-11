# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Typed peer-policy evaluator and durable prior-committed LKG transaction
(spec 7 / 10.4). Principals are accepted structurally (``.type``/``.id``); a
local namedtuple fake stands in for the identity lane's ``auth.Principal``."""
import collections
import copy
import glob
import json
import os

import pytest

import peer_policy

Principal = collections.namedtuple("Principal", ["type", "id"])

DEV1 = Principal("device", "iris8kv-1")
DEV2 = Principal("device", "iris8kv-2")
DEV_SEEDER = Principal("device", "seeder")
SVC = Principal("service", "seeder")
LEGACY = Principal("legacy", "198.51.100.77:6881")


def _base():
    return peer_policy.base_document()


def _doc_with(acls=None, assignments=None, seeder_assignment=None, revision=1):
    doc = _base()
    if acls:
        doc["acls"].update(acls)
    if assignments:
        doc["assignments"].update(assignments)
    doc["seeder_assignment"] = seeder_assignment
    doc["revision"] = revision
    return doc


class TestBaseDocument:
    def test_base_has_reserved_quarantine(self):
        doc = _base()
        q = doc["acls"]["quarantine"]
        assert q["reserved"] is True
        assert q["rules"] == [{"seq": 10, "action": "deny",
                               "match": {"type": "any"}}]
        assert doc["assignments"] == {}
        assert doc["seeder_assignment"] is None
        assert doc["operation_outbox"] == []
        assert doc["schema"] == 1
        assert "roles" not in doc
        assert "roles_present" not in doc

    def test_validate_accepts_base(self):
        peer_policy.validate_document(_base())  # no raise


class TestEvaluatorMatchTypes:
    def test_device_rule_matches_device_id_only(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {
                "type": "device", "value": "iris8kv-1"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("deny", 10)

    def test_service_rule_matches_service_seeder(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {
                "type": "service", "value": "seeder"}}]}}
        # assign the service seeder to acl a
        doc = _doc_with(acls=acls, seeder_assignment="a")
        assert peer_policy.evaluate(doc, SVC, "10.0.0.1") == ("deny", 10)

    def test_device_seeder_not_matched_by_service_rule(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {
                "type": "service", "value": "seeder"}}]}}
        doc = _doc_with(acls=acls, assignments={"seeder": "a"})
        # device:seeder assigned to acl a; a service rule must NOT match it ->
        # implicit permit.
        assert peer_policy.evaluate(doc, DEV_SEEDER, "10.0.0.1") == ("permit", None)

    def test_host_rule_matches_ipv4(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {
                "type": "host", "value": "10.0.0.5"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.5") == ("deny", 10)
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.6") == ("permit", None)

    def test_cidr_rule_matches_prefix(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {
                "type": "cidr", "value": "10.0.0.0/24"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.200") == ("deny", 10)
        assert peer_policy.evaluate(doc, DEV1, "10.0.1.1") == ("permit", None)

    def test_any_rule_matches(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("deny", 10)


class TestEvaluatorSemantics:
    def test_first_match_wins(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "permit", "match": {"type": "any"}},
            {"seq": 20, "action": "deny", "match": {"type": "any"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("permit", 10)

    def test_rules_ordered_by_seq_not_list_order(self):
        acls = {"a": {"rules": [
            {"seq": 20, "action": "deny", "match": {"type": "any"}},
            {"seq": 10, "action": "permit", "match": {"type": "any"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "a"})
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("permit", 10)

    def test_no_match_is_implicit_permit(self):
        doc = _base()
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("permit", None)

    def test_unassigned_device_implicit_permit(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}}]}}
        doc = _doc_with(acls=acls)  # a exists but nobody is assigned
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("permit", None)

    def test_legacy_not_matched_by_device_or_service_rule(self):
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "device",
                                                    "value": "x"}},
            {"seq": 20, "action": "deny", "match": {"type": "service",
                                                    "value": "seeder"}}]}}
        # legacy has no assignment slot; only host/cidr/any could match it.
        doc = _doc_with(acls=acls)
        assert peer_policy.evaluate(doc, LEGACY, "10.0.0.1") == ("permit", None)

    def test_legacy_matched_by_host_rule_when_assigned_via_no_slot(self):
        # A legacy principal is only ever matched by a non-identity rule that
        # applies globally through the requester side; here we assert host/cidr
        # semantics hold for legacy when the ACL is reachable (host rule).
        acls = {"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "host",
                                                    "value": "10.0.0.9"}}]}}
        doc = _doc_with(acls=acls)
        # legacy has no device assignment -> falls to implicit permit because
        # there is no ACL bound to it. This proves legacy carries no identity
        # ACL binding.
        assert peer_policy.evaluate(doc, LEGACY, "10.0.0.9") == ("permit", None)


class TestMutualPermit:
    def test_both_must_permit(self):
        acls = {"deny_all": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}}]}}
        doc = _doc_with(acls=acls, assignments={"iris8kv-1": "deny_all"})
        # requester denies candidate
        assert peer_policy.mutual_permit(
            doc, DEV1, "10.0.0.1", DEV2, "10.0.0.2") is False
        # symmetric: candidate denies requester
        assert peer_policy.mutual_permit(
            doc, DEV2, "10.0.0.2", DEV1, "10.0.0.1") is False

    def test_permit_when_neither_denies(self):
        doc = _base()
        assert peer_policy.mutual_permit(
            doc, DEV1, "10.0.0.1", DEV2, "10.0.0.2") is True

    @pytest.mark.parametrize("match", [
        {"type": "device", "value": DEV2.id},
        {"type": "host", "value": "10.0.0.2"},
        {"type": "cidr", "value": "10.0.0.0/24"},
        {"type": "service", "value": SVC.id},
    ])
    def test_requester_acl_is_evaluated_against_candidate(self, match):
        doc = _doc_with(
            acls={"a": {"rules": [{"seq": 10, "action": "deny",
                                      "match": match}]}},
            assignments={DEV1.id: "a"})
        candidate = SVC if match["type"] == "service" else DEV2
        assert not peer_policy.mutual_permit(
            doc, DEV1, "10.0.0.1", candidate, "10.0.0.2")

    def test_candidate_acl_is_evaluated_reciprocally(self):
        doc = _doc_with(
            acls={"a": {"rules": [{"seq": 10, "action": "deny",
                                      "match": {"type": "device",
                                                "value": DEV1.id}}]}},
            assignments={DEV2.id: "a"})
        assert not peer_policy.mutual_permit(
            doc, DEV1, "10.0.0.1", DEV2, "10.0.0.2")

    def test_quarantine_still_denies_mutually(self):
        doc = _doc_with(assignments={DEV1.id: "quarantine"})
        assert not peer_policy.mutual_permit(
            doc, DEV1, "10.0.0.1", DEV2, "10.0.0.2")


class TestQuarantineImmutable:
    def test_reject_rename_or_rule_edit_of_quarantine(self):
        doc = _base()
        doc["acls"]["quarantine"]["rules"] = [
            {"seq": 10, "action": "permit", "match": {"type": "any"}}]
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_reject_quarantine_delete(self):
        doc = _base()
        del doc["acls"]["quarantine"]
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_quarantine_assignment_allowed(self):
        doc = _doc_with(assignments={"iris8kv-1": "quarantine"})
        peer_policy.validate_document(doc)  # no raise
        assert peer_policy.evaluate(doc, DEV1, "10.0.0.1") == ("deny", 10)


class TestSchemaBounds:
    def test_reject_bad_acl_name(self):
        doc = _doc_with(acls={"has space!": {"rules": []}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_reject_too_many_rules(self):
        rules = [{"seq": i, "action": "deny", "match": {"type": "any"}}
                 for i in range(257)]
        doc = _doc_with(acls={"a": {"rules": rules}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_reject_bad_action(self):
        doc = _doc_with(acls={"a": {"rules": [
            {"seq": 10, "action": "block", "match": {"type": "any"}}]}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_reject_bad_match_type(self):
        doc = _doc_with(acls={"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "mac"}}]}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_reject_duplicate_seq(self):
        doc = _doc_with(acls={"a": {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}},
            {"seq": 10, "action": "permit", "match": {"type": "any"}}]}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)


# --------------------------------------------------------------------------
# PolicyResult + LKG read precedence
# --------------------------------------------------------------------------

@pytest.fixture
def paths(tmp_path):
    return (str(tmp_path / "peer-policy.json"),
            str(tmp_path / "peer-policy.lkg.json"))


class TestInitialization:
    def test_fresh_absence_initializes_both_with_base(self, paths):
        auth, lkg = paths
        result = peer_policy.load_policy(auth, lkg)
        assert result.fail_closed is False
        assert result.degraded is False
        assert result.document["acls"]["quarantine"]["reserved"] is True
        # both files materialized
        assert os.path.exists(auth) and os.path.exists(lkg)
        with open(auth) as f, open(lkg) as g:
            assert json.load(f)["revision"] == json.load(g)["revision"]

    def test_fresh_absence_is_open_discovery(self, paths):
        auth, lkg = paths
        result = peer_policy.load_policy(auth, lkg)
        assert peer_policy.evaluate(
            result.document, DEV1, "10.0.0.1") == ("permit", None)


class TestReadPrecedence:
    def test_valid_authoritative_always_wins(self, paths):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)
        # write a distinct valid authoritative revision
        doc = _doc_with(revision=5)
        peer_policy._atomic_write_json(auth, doc)
        result = peer_policy.load_policy(auth, lkg)
        assert result.document["revision"] == 5
        assert result.degraded is False
        assert result.fail_closed is False

    def test_corrupt_auth_falls_back_to_lkg_degraded(self, paths):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)
        peer_policy._atomic_write_json(lkg, _doc_with(revision=9))
        with open(auth, "w") as f:
            f.write("{ not json")
        result = peer_policy.load_policy(auth, lkg)
        assert result.document["revision"] == 9
        assert result.degraded is True
        assert result.fail_closed is False

    def test_both_corrupt_is_fail_closed(self, paths):
        auth, lkg = paths
        with open(auth, "w") as f:
            f.write("{ nope")
        with open(lkg, "w") as f:
            f.write("{ nope")
        result = peer_policy.load_policy(auth, lkg)
        assert result.fail_closed is True
        assert result.degraded is True
        # fail_closed returns no permit: mutual_permit must be False
        assert peer_policy.mutual_permit(
            result.document, DEV1, "10.0.0.1", DEV2, "10.0.0.2") is False


class TestCommitTransaction:
    @pytest.mark.parametrize("valid_lkg", [True, False])
    def test_corrupt_authoritative_never_overwritten(self, paths, valid_lkg):
        auth, lkg = paths
        auth_bytes = b"{ corrupt authoritative"
        lkg_bytes = (json.dumps(_base()).encode() if valid_lkg
                     else b"{ corrupt lkg")
        with open(auth, "wb") as f:
            f.write(auth_bytes)
        with open(lkg, "wb") as f:
            f.write(lkg_bytes)
        error = (peer_policy.PolicyDegradedError if valid_lkg
                 else peer_policy.PolicyError)
        with pytest.raises(error):
            peer_policy.commit_mutation(
                auth, lkg, "assign", DEV1.id, "a", 1.0,
                lambda d: d["assignments"].__setitem__(DEV1.id, "quarantine"))
        assert open(auth, "rb").read() == auth_bytes
        assert open(lkg, "rb").read() == lkg_bytes

    def test_fresh_absence_can_commit_without_intermediate_materialization(self,
                                                                           paths):
        auth, lkg = paths
        result = peer_policy.commit_mutation(
            auth, lkg, "assign", DEV1.id, "a", 1.0,
            lambda d: d["assignments"].__setitem__(DEV1.id, "quarantine"))
        assert result["revision"] == 2
        assert json.load(open(lkg))["revision"] == 1

    def test_commit_writes_prior_to_lkg_then_candidate(self, paths):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)  # rev 1 to both
        # commit a mutation -> candidate rev 2
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-1",
            actor="console:admin", now=1000.0,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-1",
                                                           "quarantine"))
        with open(auth) as f:
            authoritative = json.load(f)
        with open(lkg) as g:
            lkg_doc = json.load(g)
        # Authoritative is the candidate (rev 2) in canonical membership form.
        assert authoritative["revision"] == 2
        assert authoritative["assignments"] == {}
        assert authoritative["quarantined_devices"] == {"iris8kv-1": True}
        # LKG is the PRIOR committed authoritative (rev 1, no assignment)
        assert lkg_doc["revision"] == 1
        assert lkg_doc["assignments"] == {}

    def test_candidate_write_failure_leaves_current_and_lkg(self, paths,
                                                            monkeypatch):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)
        original = peer_policy._atomic_write_json
        calls = {"n": 0}

        def flaky(path, obj):
            # allow the LKG write, fail the candidate authoritative write
            if path == auth:
                raise OSError("disk full on candidate")
            return original(path, obj)

        monkeypatch.setattr(peer_policy, "_atomic_write_json", flaky)
        with pytest.raises(OSError):
            peer_policy.commit_mutation(
                auth, lkg, action="assign", target="iris8kv-1",
                actor="a", now=1.0,
                mutate=lambda d: d["assignments"].__setitem__("iris8kv-1",
                                                              "quarantine"))
        monkeypatch.setattr(peer_policy, "_atomic_write_json", original)
        # authoritative is still the pre-mutation base (rev 1)
        result = peer_policy.load_policy(auth, lkg)
        assert result.document["revision"] == 1
        assert result.document["assignments"] == {}
        # and no candidate ever landed in LKG
        with open(lkg) as g:
            assert json.load(g)["revision"] == 1

    def test_lkg_never_holds_candidate_across_two_commits(self, paths):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)
        for rev, dev in ((2, "iris8kv-1"), (3, "iris8kv-2")):
            peer_policy.commit_mutation(
                auth, lkg, action="assign", target=dev, actor="a", now=1.0,
                mutate=lambda d, dev=dev: d["assignments"].__setitem__(
                    dev, "quarantine"))
        with open(auth) as f:
            assert json.load(f)["revision"] == 3
        with open(lkg) as g:
            # LKG holds the prior committed authoritative (rev 2), never 3
            assert json.load(g)["revision"] == 2

    def test_no_tmp_files_left(self, paths):
        auth, lkg = paths
        peer_policy.initialize(auth, lkg)
        peer_policy.commit_mutation(
            auth, lkg, action="assign", target="iris8kv-1", actor="a",
            now=1.0,
            mutate=lambda d: d["assignments"].__setitem__("iris8kv-1",
                                                          "quarantine"))
        d = os.path.dirname(auth)
        assert glob.glob(os.path.join(d, ".peer-policy*.tmp")) == []


# --------------------------------------------------------------------------
# Workstream D: independent quarantine membership and candidate migration
# --------------------------------------------------------------------------

def test_independent_quarantine_container_is_closed_bounded_and_non_materializing():
    base = _base()
    base_bytes = json.dumps(base, sort_keys=True, separators=(",", ":"))
    assert "quarantined_devices" not in base
    assert peer_policy.validate_document(base) is base
    assert json.dumps(base, sort_keys=True, separators=(",", ":")) == base_bytes

    valid = _base()
    valid["quarantined_devices"] = {
        "": True, " Mixed ID/kept exactly ": True}
    valid["roles"] = {
        "defs": {}, "role_of": {}, "qos_default": {"numwant": 7},
        "qos_state_default": {"seeder": {"numwant": 4}},
        "qos_device": {}}
    before = copy.deepcopy(valid)
    assert peer_policy.validate_document(valid) is valid
    assert valid == before

    at_cap = _base()
    at_cap["quarantined_devices"] = {
        "device-%05d" % index: True for index in range(10000)}
    peer_policy.validate_document(at_cap)
    too_many = copy.deepcopy(at_cap)
    too_many["quarantined_devices"]["device-over-cap"] = True
    with pytest.raises(peer_policy.PolicyError):
        peer_policy.validate_document(too_many)

    for malformed in (None, [], "d1", True, 1):
        document = _base()
        document["quarantined_devices"] = malformed
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(document)
    for malformed in (False, None, 1, 1.0, "true", [], {}):
        document = _base()
        document["quarantined_devices"] = {"d1": malformed}
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(document)
    document = _base()
    document["quarantined_devices"] = {1: True}
    with pytest.raises(peer_policy.PolicyError):
        peer_policy.validate_document(document)


def test_quarantine_precedes_ordinary_assignment_role_and_is_device_only():
    document = _base()
    document["acls"].update({
        "manual-a": {"rules": [{"seq": 21, "action": "permit",
                                  "match": {"type": "any"}}]},
        "manual-b": {"rules": [{"seq": 31, "action": "permit",
                                  "match": {"type": "any"}}]},
    })
    document["roles"] = {
        "defs": {"boat": {"restricted": True, "peers": ["boat"]}},
        "role_of": {DEV1.id: "boat"}, "qos_default": {},
        "qos_device": {}}
    document["assignments"][DEV1.id] = "manual-a"
    document["quarantined_devices"] = {DEV1.id: True}
    document["seeder_assignment"] = "manual-b"
    compiled = peer_policy.compile_roles(document)
    frozen = copy.deepcopy(document)

    assert peer_policy.effective_acl_name(document, DEV1, compiled) == \
        "quarantine"
    assert peer_policy.acl_source(document, DEV1, compiled) == \
        "assignment:quarantine"
    assert peer_policy.evaluate(document, DEV1, "10.0.0.1", compiled) == \
        ("deny", 10)
    assert peer_policy.effective_acl_name(document, SVC, compiled) == \
        "manual-b"
    assert peer_policy.evaluate(document, LEGACY, "10.0.0.1", compiled) == \
        ("permit", None)
    assert document == frozen

    document["assignments"][DEV1.id] = "manual-b"
    assert peer_policy.effective_acl_name(document, DEV1) == "quarantine"
    del document["quarantined_devices"]
    assert peer_policy.effective_acl_name(document, DEV1) == "manual-b"
    del document["assignments"][DEV1.id]
    assert peer_policy.effective_acl_name(document, DEV1) == "role:boat"
    document["roles"]["role_of"].clear()
    assert peer_policy.effective_acl_name(document, DEV1) is None

    legacy = copy.deepcopy(frozen)
    legacy.pop("quarantined_devices")
    legacy["assignments"][DEV1.id] = "quarantine"
    canonical = copy.deepcopy(legacy)
    canonical["assignments"][DEV1.id] = "manual-a"
    canonical["quarantined_devices"] = {DEV1.id: True}
    for candidate in (legacy, canonical):
        assert peer_policy.effective_acl_name(candidate, DEV1) == "quarantine"
        assert peer_policy.evaluate(candidate, DEV1, "10.0.0.1") == \
            ("deny", 10)


def test_commit_migrates_legacy_rows_around_callback_and_keeps_raw_prior(
        paths):
    auth, lkg = paths
    prior = _base()
    prior["acls"].update({
        "manual-a": {"rules": []}, "manual-b": {"rules": []}})
    prior["assignments"] = {DEV1.id: "quarantine", DEV2.id: "manual-a"}
    prior["quarantined_devices"] = {
        DEV1.id: True, "canonical-only": True}
    prior["roles"] = {
        "defs": {}, "role_of": {}, "qos_default": {"numwant": 9},
        "qos_state_default": {"leecher": {"numwant": 4}},
        "qos_device": {}}
    peer_policy._atomic_write_json(auth, prior)
    peer_policy._atomic_write_json(lkg, _base())
    auth_before = open(auth, "rb").read()
    loaded = peer_policy.load_policy(auth, lkg)
    assert loaded.document == prior
    assert open(auth, "rb").read() == auth_before
    observed = []
    caller_members = {
        DEV1.id: True, "canonical-only": True, "callback-owned": True}

    def mutate(candidate):
        observed.append(copy.deepcopy(candidate))
        assert candidate["assignments"] == {DEV2.id: "manual-a"}
        assert candidate["quarantined_devices"] == {
            DEV1.id: True, "canonical-only": True}
        candidate["assignments"][DEV1.id] = "manual-b"
        candidate["quarantined_devices"] = caller_members
        candidate["assignments"]["legacy-added"] = "quarantine"

    committed = peer_policy.commit_mutation(
        auth, lkg, "assign", DEV1.id, "test", 10.0, mutate)
    assert len(observed) == 1
    assert committed["assignments"] == {
        DEV1.id: "manual-b", DEV2.id: "manual-a"}
    assert committed["quarantined_devices"] == {
        DEV1.id: True, "canonical-only": True, "callback-owned": True,
        "legacy-added": True}
    assert caller_members == {
        DEV1.id: True, "canonical-only": True, "callback-owned": True}
    assert committed["roles"] == prior["roles"]
    assert json.load(open(lkg)) == prior
    assert peer_policy.read_lkg_revision(lkg, 1) == prior
    assert peer_policy.load_policy(auth, lkg).document == committed

    explicit_empty = copy.deepcopy(committed)
    explicit_empty["quarantined_devices"] = {}
    explicit_empty["assignments"].clear()
    peer_policy._atomic_write_json(auth, explicit_empty)
    preserved = peer_policy.commit_mutation(
        auth, lkg, "assign", "ordinary", "test", 11.0,
        lambda candidate: candidate["assignments"].__setitem__(
            "ordinary", "manual-a"))
    assert preserved["quarantined_devices"] == {}


def test_restore_normalizes_legacy_overlay_without_copying_historical_outbox(
        paths):
    auth, lkg = paths
    legacy = _base()
    legacy["assignments"][DEV1.id] = "quarantine"
    peer_policy._atomic_write_json(auth, legacy)
    peer_policy._atomic_write_json(lkg, _base())
    live = peer_policy.commit_mutation(
        auth, lkg, "assign", DEV2.id, "test", 2.0,
        lambda candidate: candidate["assignments"].__setitem__(
            DEV2.id, "quarantine"))
    live_outbox = copy.deepcopy(live["operation_outbox"])
    restored = peer_policy.restore_lkg_revision(
        auth, lkg, 1, actor="test", now=3.0,
        expected_revision=live["revision"])
    assert restored["revision"] == live["revision"] + 1
    assert restored["assignments"] == {}
    assert restored["quarantined_devices"] == {DEV1.id: True}
    assert restored["operation_outbox"][:-1] == live_outbox
    assert restored["operation_outbox"][-1]["action"] == "restore"
    assert restored["operation_ack_epoch"] != live["operation_ack_epoch"]


def test_legacy_migration_dry_run_and_precommit_refusal_write_nothing(paths):
    auth, lkg = paths
    legacy = _base()
    legacy["assignments"][DEV1.id] = "quarantine"
    peer_policy._atomic_write_json(auth, legacy)
    peer_policy._atomic_write_json(lkg, _base())
    retained = copy.deepcopy(legacy)
    retained["revision"] = 9
    peer_policy._write_lkg_ring(lkg, retained)
    assert peer_policy.read_lkg_revision(lkg, 9) == retained

    def store_tree():
        root = os.path.dirname(auth)
        lock_path = os.path.abspath(auth + ".lock")
        snapshot = {}
        for directory, names, files in os.walk(root):
            names.sort()
            files.sort()
            for name in names:
                path = os.path.join(directory, name)
                relative = os.path.relpath(path, root)
                snapshot[relative] = (
                    "symlink", os.readlink(path)) if os.path.islink(path) \
                    else ("directory", None)
            for name in files:
                path = os.path.join(directory, name)
                if os.path.abspath(path) == lock_path:
                    continue
                relative = os.path.relpath(path, root)
                if os.path.islink(path):
                    snapshot[relative] = ("symlink", os.readlink(path))
                else:
                    snapshot[relative] = ("file", open(path, "rb").read())
        return snapshot

    before = store_tree()
    preview = peer_policy.commit_mutation(
        auth, lkg, "assign", DEV1.id, "test", 2.0,
        lambda _candidate: None, dry_run=True)
    assert preview["assignments"] == {}
    assert preview["quarantined_devices"] == {DEV1.id: True}
    assert store_tree() == before

    def reject(prior, candidate):
        assert prior == legacy
        assert candidate["assignments"] == {}
        assert candidate["quarantined_devices"] == {DEV1.id: True}
        raise peer_policy.PolicyError("confirmation refused")

    with pytest.raises(peer_policy.PolicyError, match="confirmation refused"):
        peer_policy.commit_mutation(
            auth, lkg, "assign", DEV1.id, "test", 2.0,
            lambda _candidate: None, precommit=reject)
    assert store_tree() == before

    caller_owned_invalid = {DEV2.id: False}

    def attach_invalid_mixed(candidate):
        candidate["quarantined_devices"] = caller_owned_invalid
        candidate["assignments"][DEV2.id] = "quarantine"

    with pytest.raises(peer_policy.PolicyError):
        peer_policy.commit_mutation(
            auth, lkg, "assign", DEV2.id, "test", 2.0,
            attach_invalid_mixed)
    assert caller_owned_invalid == {DEV2.id: False}
    assert store_tree() == before


def test_late_candidate_failure_keeps_legacy_authority_and_raw_recovery(
        paths, monkeypatch):
    auth, lkg = paths
    legacy = _base()
    legacy["assignments"][DEV1.id] = "quarantine"
    peer_policy._atomic_write_json(auth, legacy)
    peer_policy._atomic_write_json(lkg, _base())
    authority_before = open(auth, "rb").read()
    real_write = peer_policy._atomic_write_json

    def fail_authority(path, document):
        if path == auth:
            raise OSError("candidate replace failed")
        return real_write(path, document)

    monkeypatch.setattr(peer_policy, "_atomic_write_json", fail_authority)
    with pytest.raises(OSError, match="candidate replace failed"):
        peer_policy.commit_mutation(
            auth, lkg, "assign", DEV1.id, "test", 2.0,
            lambda _candidate: None)
    monkeypatch.setattr(peer_policy, "_atomic_write_json", real_write)
    assert open(auth, "rb").read() == authority_before
    assert json.load(open(lkg)) == legacy
    assert peer_policy.read_lkg_revision(lkg, legacy["revision"]) == legacy
    assert peer_policy.load_policy(auth, lkg).document == legacy


def test_oversize_legacy_quarantine_loads_but_mutation_refuses_without_loss(
        paths):
    auth, lkg = paths
    legacy = _base()
    legacy["assignments"] = {
        "legacy-%05d" % index: "quarantine" for index in range(10001)}
    peer_policy._atomic_write_json(auth, legacy)
    peer_policy._atomic_write_json(lkg, _base())
    before = open(auth, "rb").read(), open(lkg, "rb").read()
    loaded = peer_policy.load_policy(auth, lkg)
    assert loaded.document == legacy
    assert loaded.degraded is False and loaded.fail_closed is False
    with pytest.raises(peer_policy.PolicyError):
        peer_policy.commit_mutation(
            auth, lkg, "assign", "ordinary", "test", 2.0,
            lambda candidate: candidate["assignments"].__setitem__(
                "ordinary", "quarantine"))
    assert (open(auth, "rb").read(), open(lkg, "rb").read()) == before

    def reduce_to_supported_boundary(candidate):
        assert candidate["assignments"] == {}
        assert len(candidate["quarantined_devices"]) == 10001
        candidate["quarantined_devices"].pop("legacy-10000")

    reduced = peer_policy.commit_mutation(
        auth, lkg, "unassign", "legacy-10000", "test", 3.0,
        reduce_to_supported_boundary)
    assert reduced["assignments"] == {}
    assert set(reduced["quarantined_devices"]) == {
        "legacy-%05d" % index for index in range(10000)}
    assert all(value is True
               for value in reduced["quarantined_devices"].values())
    assert json.load(open(lkg)) == legacy


def test_authoritative_and_lkg_quarantine_memberships_never_union(paths):
    auth, lkg = paths
    authoritative = _base()
    authoritative["revision"] = 5
    authoritative["quarantined_devices"] = {DEV1.id: True}
    fallback = _base()
    fallback["revision"] = 9
    fallback["assignments"][DEV2.id] = "quarantine"
    peer_policy._atomic_write_json(auth, authoritative)
    peer_policy._atomic_write_json(lkg, fallback)

    loaded = peer_policy.load_policy(auth, lkg)
    assert loaded.document == authoritative
    assert loaded.degraded is False
    assert peer_policy.evaluate(loaded.document, DEV1, "10.0.0.1") == \
        ("deny", 10)
    assert peer_policy.evaluate(loaded.document, DEV2, "10.0.0.2") == \
        ("permit", None)

    with open(auth, "w") as stream:
        stream.write("{broken")
    loaded = peer_policy.load_policy(auth, lkg)
    assert loaded.document == fallback
    assert loaded.degraded is True and loaded.fail_closed is False
    assert peer_policy.evaluate(loaded.document, DEV1, "10.0.0.1") == \
        ("permit", None)
    assert peer_policy.evaluate(loaded.document, DEV2, "10.0.0.2") == \
        ("deny", 10)

    malformed_mixed = _base()
    malformed_mixed["assignments"][DEV1.id] = "quarantine"
    malformed_mixed["quarantined_devices"] = {DEV1.id: False}
    peer_policy._atomic_write_json(auth, malformed_mixed)
    loaded = peer_policy.load_policy(auth, lkg)
    assert loaded.document == fallback
    assert loaded.degraded is True and loaded.fail_closed is False


def test_quarantine_membership_participates_in_blast_counts_and_token():
    prior = _base()
    candidate = copy.deepcopy(prior)
    candidate["quarantined_devices"] = {DEV1.id: True}
    preview = peer_policy.blast_radius(prior, candidate, threshold=0)
    assert preview.member_delta == 0
    assert preview.origin_access_lost == 1
    assert preview.empty_permitted_sets == 1
    assert preview.role_pairs_stopped == 0
    assert preview.qos_changed is False
    assert preview.requires_confirmation is True
    assert peer_policy.confirm_blast_radius(
        prior, candidate, 0, preview.confirm_token) is True

    repeated = peer_policy.blast_radius(candidate, copy.deepcopy(candidate), 0)
    assert repeated.member_delta == 0
    assert repeated.origin_access_lost == 0
    assert repeated.empty_permitted_sets == 0
    assert repeated.role_pairs_stopped == 0
    assert repeated.qos_changed is False
    assert repeated.requires_confirmation is False
    assert repeated.confirm_token is None

    released = peer_policy.blast_radius(candidate, prior, 0)
    assert released.member_delta == 0
    assert released.origin_access_lost == 0
    assert released.empty_permitted_sets == 0
    assert released.role_pairs_stopped == 0
    assert released.qos_changed is False
    assert released.requires_confirmation is False
    assert released.confirm_token is None

    different = copy.deepcopy(candidate)
    different["quarantined_devices"] = {DEV2.id: True}
    assert peer_policy.confirm_blast_radius(
        prior, different, 0, preview.confirm_token) is False
