# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Role grammar and virtual ACL evaluation for peer policy."""
import collections
import copy
import json

import pytest

import peer_policy


Principal = collections.namedtuple("Principal", ["type", "id"])

BOAT1 = Principal("device", "boat-01")
BOAT2 = Principal("device", "boat-02")
FIBER1 = Principal("device", "fiber-01")
SEEDER = Principal("service", "seeder")
LEGACY = Principal("legacy", "192.0.2.1:6881")


def _roles_doc():
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": {
            "boat": {
                "restricted": True,
                "peers": ["boat", "fiber"],
                "origin": True,
                "nets": ["10.77.0.0/24"],
            },
            "fiber": {"restricted": False},
        },
        "role_of": {
            "boat-01": "boat",
            "boat-02": "boat",
            "fiber-01": "fiber",
        },
        "qos_default": {},
        "qos_device": {},
    }
    return doc


class TestRoleGrammar:
    def test_accepts_optional_roles_and_role_assignments(self):
        doc = _roles_doc()
        assert peer_policy.validate_document(doc) is doc

    def test_refuses_role_assignment_to_unknown_definition(self):
        doc = _roles_doc()
        doc["roles"]["role_of"]["boat-01"] = "missing"
        with pytest.raises(peer_policy.PolicyError, match="unknown role"):
            peer_policy.validate_document(doc)

    @pytest.mark.parametrize("name", ["Boat", "-boat", "boat role", "", "x" * 33])
    def test_refuses_bad_role_names(self, name):
        doc = _roles_doc()
        doc["roles"]["defs"][name] = {"restricted": False}
        with pytest.raises(peer_policy.PolicyError, match="role name"):
            peer_policy.validate_document(doc)

    def test_role_rule_uses_role_name_grammar(self):
        doc = _roles_doc()
        doc["acls"]["role-reader"] = {"rules": [{
            "seq": 10,
            "action": "permit",
            "match": {"type": "role", "value": "boat"},
        }]}
        peer_policy.validate_document(doc)
        doc["acls"]["role-reader"]["rules"][0]["match"]["value"] = "Boat!"
        with pytest.raises(peer_policy.PolicyError, match="role"):
            peer_policy.validate_document(doc)

    def test_role_and_peer_counts_are_bounded(self):
        doc = _roles_doc()
        doc["roles"]["defs"] = {
            "r%03d" % i: {"restricted": False} for i in range(257)}
        doc["roles"]["role_of"] = {}
        with pytest.raises(peer_policy.PolicyError, match="role defs"):
            peer_policy.validate_document(doc)

        doc = _roles_doc()
        extra = ["r%02d" % i for i in range(64)]
        doc["roles"]["defs"].update(
            {name: {"restricted": False} for name in extra})
        doc["roles"]["defs"]["boat"]["peers"] = ["boat"] + extra
        with pytest.raises(peer_policy.PolicyError, match="role peers"):
            peer_policy.validate_document(doc)

    def test_non_string_peer_is_a_policy_error(self):
        doc = _roles_doc()
        doc["roles"]["defs"]["boat"]["peers"] = ["boat", {}]
        with pytest.raises(peer_policy.PolicyError, match="peer role"):
            peer_policy.validate_document(doc)


class TestCompiledRoles:
    def test_compiles_the_canonical_virtual_acl(self):
        compiled = peer_policy.compile_roles(_roles_doc())
        assert compiled.acl_by_role["boat"]["rules"] == [
            {"seq": 10, "action": "permit",
             "match": {"type": "role", "value": "boat"}},
            {"seq": 20, "action": "permit",
             "match": {"type": "service", "value": "seeder"}},
            {"seq": 30, "action": "permit",
             "match": {"type": "role", "value": "fiber"}},
            {"seq": 40, "action": "deny", "match": {"type": "any"}},
        ]
        assert "fiber" not in compiled.acl_by_role
        assert compiled.restricted == frozenset(["boat"])
        assert compiled.role_of["boat-01"] == "boat"

    def test_origin_false_omits_the_seeder_rule(self):
        doc = _roles_doc()
        doc["roles"]["defs"]["boat"]["origin"] = False
        rules = peer_policy.compile_roles(doc).acl_by_role["boat"]["rules"]
        assert not any(r["match"].get("type") == "service" for r in rules)
        assert peer_policy.evaluate_for(
            doc, BOAT1, SEEDER, "10.0.0.1") == ("deny", 40)

    def test_stored_acl_rules_are_pre_sorted(self):
        doc = _roles_doc()
        doc["acls"]["manual"] = {"rules": [
            {"seq": 20, "action": "deny", "match": {"type": "any"}},
            {"seq": 10, "action": "permit", "match": {"type": "any"}},
        ]}
        compiled = peer_policy.compile_roles(doc)
        assert [r["seq"] for r in compiled.sorted_rules["manual"]] == [10, 20]

    def test_load_policy_attaches_the_index_once(self, tmp_path, monkeypatch):
        auth = str(tmp_path / "peer-policy.json")
        lkg = str(tmp_path / "peer-policy.lkg.json")
        peer_policy._atomic_write_json(auth, _roles_doc())
        calls = []
        real_compile = peer_policy.compile_roles

        def counted(doc):
            calls.append(doc)
            return real_compile(doc)

        monkeypatch.setattr(peer_policy, "compile_roles", counted)
        result = peer_policy.load_policy(auth, lkg)
        assert len(calls) == 1
        assert isinstance(result.roles, peer_policy.CompiledRoles)
        assert result.roles.role_of["boat-01"] == "boat"

    def test_legacy_three_argument_policy_result_is_compatible(self):
        result = peer_policy.PolicyResult(_roles_doc(), False, False)
        assert result.roles is None


class TestRoleEvaluation:
    def test_role_rule_matches_only_a_device_principal(self):
        rule = {"seq": 10, "action": "permit",
                "match": {"type": "role", "value": "boat"}}
        compiled = peer_policy.compile_roles(_roles_doc())
        assert peer_policy._rule_matches(
            rule, BOAT2, "10.0.0.2", compiled=compiled)
        assert not peer_policy._rule_matches(
            rule, SEEDER, "10.0.0.2", compiled=compiled)
        assert not peer_policy._rule_matches(
            rule, LEGACY, "10.0.0.2", compiled=compiled)

    def test_virtual_acl_permits_declared_roles_and_denies_others(self):
        doc = _roles_doc()
        compiled = peer_policy.compile_roles(doc)
        assert peer_policy.evaluate_for(
            doc, BOAT1, BOAT2, "10.77.0.2", compiled=compiled) == ("permit", 10)
        assert peer_policy.evaluate_for(
            doc, BOAT1, FIBER1, "10.0.0.3", compiled=compiled) == ("permit", 30)
        stranger = Principal("device", "core-01")
        assert peer_policy.evaluate_for(
            doc, BOAT1, stranger, "10.0.0.4", compiled=compiled) == ("deny", 40)

    def test_explicit_assignment_shadows_the_role(self):
        doc = _roles_doc()
        doc["acls"]["manual"] = {"rules": [
            {"seq": 7, "action": "permit", "match": {"type": "any"}}]}
        doc["assignments"][BOAT1.id] = "manual"
        compiled = peer_policy.compile_roles(doc)
        assert peer_policy._assigned_acl(doc, BOAT1, compiled=compiled) \
            is doc["acls"]["manual"]
        assert peer_policy.effective_acl_name(doc, BOAT1, compiled) == "manual"
        assert peer_policy.acl_source(doc, BOAT1, compiled) == "assignment:manual"
        assert peer_policy.evaluate_for(
            doc, BOAT1, FIBER1, "10.0.0.3", compiled) == ("permit", 7)

    def test_releasing_assignment_falls_back_to_role(self):
        doc = _roles_doc()
        doc["assignments"][BOAT1.id] = "quarantine"
        assert peer_policy.effective_acl_name(doc, BOAT1) == "quarantine"
        del doc["assignments"][BOAT1.id]
        assert peer_policy.effective_acl_name(doc, BOAT1) == "role:boat"
        assert peer_policy.acl_source(doc, BOAT1) == "role:boat"

    def test_unassigned_and_service_sources(self):
        doc = _roles_doc()
        assert peer_policy.effective_acl_name(doc, FIBER1) is None
        assert peer_policy.acl_source(doc, FIBER1) == "none"
        doc["seeder_assignment"] = "quarantine"
        assert peer_policy.effective_acl_name(doc, SEEDER) == "quarantine"
        assert peer_policy.acl_source(doc, SEEDER) == "assignment:quarantine"

    def test_mutual_role_denial_is_symmetric(self):
        doc = _roles_doc()
        doc["roles"]["defs"]["boat"]["peers"] = ["boat"]
        compiled = peer_policy.compile_roles(doc)
        assert not peer_policy.mutual_permit(
            doc, BOAT1, "10.77.0.1", FIBER1, "10.0.0.1", compiled)
        assert not peer_policy.mutual_permit(
            doc, FIBER1, "10.0.0.1", BOAT1, "10.77.0.1", compiled)

    def test_compiled_and_raw_fallbacks_are_equivalent_and_pure(self):
        doc = _roles_doc()
        compiled = peer_policy.compile_roles(doc)
        doc_before = copy.deepcopy(doc)
        compiled_before = copy.deepcopy(compiled)
        fixtures = [
            (BOAT1, BOAT2, "10.77.0.2"),
            (BOAT1, FIBER1, "10.0.0.3"),
            (FIBER1, BOAT1, "10.77.0.1"),
            (BOAT1, SEEDER, "10.0.0.1"),
        ]
        for owner, subject, ipv4 in fixtures:
            assert peer_policy.evaluate_for(doc, owner, subject, ipv4) == \
                peer_policy.evaluate_for(
                    doc, owner, subject, ipv4, compiled=compiled)
        assert doc == doc_before
        assert compiled == compiled_before

    def test_unknown_role_fails_closed_and_is_identifiable(self):
        doc = _roles_doc()
        doc["roles"]["role_of"][BOAT1.id] = "missing"
        compiled = peer_policy.compile_roles(doc)
        acl = peer_policy._assigned_acl(doc, BOAT1, compiled)
        assert acl["role_unknown"] is True
        assert peer_policy.effective_acl_name(doc, BOAT1, compiled) == \
            "role:missing"
        assert peer_policy.acl_source(doc, BOAT1, compiled) == "role:missing"
        assert peer_policy.evaluate_for(
            doc, BOAT1, BOAT2, "10.77.0.2", compiled) == ("deny", 40)


def test_role_free_base_document_and_evaluation_are_unchanged():
    doc = peer_policy.base_document()
    encoded = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    assert "roles" not in doc
    assert "roles_present" not in doc
    assert peer_policy.compile_roles(doc).role_of == {}
    assert peer_policy.evaluate(doc, BOAT1, "10.0.0.1") == ("permit", None)
    assert json.dumps(doc, sort_keys=True, separators=(",", ":")) == encoded
