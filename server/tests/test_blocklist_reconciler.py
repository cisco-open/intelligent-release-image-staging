# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pure blocklist reconciler derivation (spec 5 / 7 / 13). Valid
and fail-closed (emergency) denied-set derivation, protected service-seeder
exclusion, shared-IP conflict skip, valid-empty-only empty apply, and the
corrected acknowledgement semantics. Principals are structural namedtuples
(the identity lane supplies auth.Principal later)."""
import collections

import pytest

import blocklist_reconciler as br
import peer_policy

Principal = collections.namedtuple("Principal", ["type", "id"])


def _pr(document, degraded=False, fail_closed=False):
    return peer_policy.PolicyResult(document, degraded, fail_closed)


def _endpoints(*rows):
    """Build a fresh-endpoints-style snapshot from (key,type,id,ip) rows."""
    out = {}
    for key, ptype, pid, ip in rows:
        out[key] = {"principal_type": ptype, "principal_id": pid,
                    "endpoints": [{"ipv4": ip, "port": 6881,
                                   "observed_at": 1000.0,
                                   "source": "announce"}]}
    return out


def _quarantine_doc(*device_ids):
    doc = peer_policy.base_document()
    for d in device_ids:
        doc["assignments"][d] = "quarantine"
    return doc


def test_canonical_quarantine_flows_through_shared_evaluator():
    doc = peer_policy.base_document()
    doc["quarantined_devices"] = {"bad": True}
    policy = peer_policy.PolicyResult(
        doc, False, False, peer_policy.compile_roles(doc))
    durable = _endpoints(
        ("device:bad", "device", "bad", "198.51.100.16"))
    result = br.derive_denied_set(
        policy, durable_endpoints=durable, pending_endpoints={},
        active_participants=[], revoked_principals=set(),
        protected_seeder_ip=SEEDER_IP)
    assert result.denied_ips == ["198.51.100.16"]
    assert result.conflicts == []
    keep = br.denied_retention(policy, set())
    assert keep("device", "bad", "198.51.100.16") is True


SEEDER = Principal("service", "seeder")
SEEDER_IP = "192.0.2.10"

_UNKNOWN_SEEDER_ADDRESSES = [
    None, "", " ", "iris.example", "REPLACE_WITH_STATIC_EXTERNAL_IP",
    "::1", "::ffff:10.9.9.9", "999.0.0.1", "10.0.0", "010.0.0.1",
    "10.9.9.9/32", 0, 1, 168364297, True, False, b"10.9.9.9", [], {},
]


def _role_doc(device_ids=("boat-1",), origin=False):
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": {
            "boat": {
                "restricted": True,
                "peers": ["boat"],
                "origin": origin,
            },
            "open": {"restricted": False},
        },
        "role_of": {device_id: "boat" for device_id in device_ids},
        "qos_default": {},
        "qos_device": {},
    }
    peer_policy.validate_document(doc)
    return doc


# --------------------------------------------------------------------------
# Valid-policy mode
# --------------------------------------------------------------------------

class TestValidMode:
    def test_denies_quarantined_device_from_durable_endpoint(self):
        doc = _quarantine_doc("iris8kv-3")
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.16"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == ["198.51.100.16"]
        assert result.fail_closed is False

    def test_includes_pending_endpoint(self):
        doc = _quarantine_doc("iris8kv-3")
        pending = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.99"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints={}, pending_endpoints=pending,
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == ["198.51.100.99"]

    def test_permitted_device_not_denied(self):
        doc = peer_policy.base_document()  # no assignment -> implicit permit
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.16"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == []

    def test_revoked_principal_derived_denied_regardless_of_policy(self):
        doc = peer_policy.base_document()  # policy would permit
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.16"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals={"device:iris8kv-3"},
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == ["198.51.100.16"]

    def test_protected_seeder_never_blocked(self):
        # Even if the seeder somehow lands in a deny rule, its address is
        # always excluded.
        doc = peer_policy.base_document()
        doc["seeder_assignment"] = "quarantine"
        durable = _endpoints(
            ("service:seeder", "service", "seeder", SEEDER_IP))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert SEEDER_IP not in result.denied_ips

    def test_shared_ip_permit_deny_skips_global_block(self):
        doc = _quarantine_doc("iris8kv-3")  # deny device 3
        # permitted device 4 shares the same IP as denied device 3
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.50"),
            ("device:iris8kv-4", "device", "iris8kv-4", "198.51.100.50"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert "198.51.100.50" not in result.denied_ips
        assert len(result.conflicts) == 1
        c = result.conflicts[0]
        assert c["ipv4"] == "198.51.100.50"
        assert c["reason"] == "shared_permit_deny"
        assert c["global_block_applied"] is False

    def test_valid_empty_policy_applies_empty_list(self):
        doc = peer_policy.base_document()  # nothing denied
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints={}, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == []
        assert result.apply_empty is True   # valid-empty is a real apply

    def test_denied_ips_sorted_and_deduped(self):
        doc = _quarantine_doc("iris8kv-3", "iris8kv-4")
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.60"),
            ("device:iris8kv-4", "device", "iris8kv-4", "198.51.100.20"))
        result = br.derive_denied_set(
            _pr(doc), durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == ["198.51.100.20", "198.51.100.60"]


# --------------------------------------------------------------------------
# Fail-closed / emergency mode
# --------------------------------------------------------------------------

class TestFailClosedMode:
    def test_emergency_denies_every_attributable_non_service(self):
        pr = _pr(peer_policy._fail_closed_document(), degraded=True,
                 fail_closed=True)
        durable = _endpoints(
            ("device:iris8kv-3", "device", "iris8kv-3", "198.51.100.16"),
            ("service:seeder", "service", "seeder", SEEDER_IP))
        result = br.derive_denied_set(
            pr, durable_endpoints=durable, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.fail_closed is True
        assert "198.51.100.16" in result.denied_ips
        # service seeder excluded
        assert SEEDER_IP not in result.denied_ips

    def test_emergency_includes_active_and_pending_non_seeder(self):
        pr = _pr(peer_policy._fail_closed_document(), degraded=True,
                 fail_closed=True)
        pending = _endpoints(
            ("device:iris8kv-9", "device", "iris8kv-9", "198.51.100.40"))
        active = [{"principal_type": "legacy", "principal_id": "x",
                   "ipv4": "198.51.100.77"}]
        result = br.derive_denied_set(
            pr, durable_endpoints={}, pending_endpoints=pending,
            active_participants=active, revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert "198.51.100.40" in result.denied_ips
        assert "198.51.100.77" in result.denied_ips  # legacy included

    def test_emergency_excludes_active_service_seeder(self):
        pr = _pr(peer_policy._fail_closed_document(), degraded=True,
                 fail_closed=True)
        active = [{"principal_type": "service", "principal_id": "seeder",
                   "ipv4": SEEDER_IP}]
        result = br.derive_denied_set(
            pr, durable_endpoints={}, pending_endpoints={},
            active_participants=active, revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert SEEDER_IP not in result.denied_ips

    def test_fail_closed_no_known_address_no_false_success(self):
        pr = _pr(peer_policy._fail_closed_document(), degraded=True,
                 fail_closed=True)
        result = br.derive_denied_set(
            pr, durable_endpoints={}, pending_endpoints={},
            active_participants=[], revoked_principals=set(),
            protected_seeder_ip=SEEDER_IP)
        assert result.denied_ips == []
        # crucially, this must NOT be treated as a valid-empty apply
        assert result.apply_empty is False
        assert result.fail_closed is True


# --------------------------------------------------------------------------
# Apply / acknowledgement
# --------------------------------------------------------------------------

class FakeAria:
    def __init__(self, session="sess-1", raise_on_call=False, revision=5):
        self.session = session
        self.raise_on_call = raise_on_call
        self.revision = revision
        self.calls = []

    def get_session_id(self):
        return self.session

    def set_blocklist(self, ips):
        self.calls.append(list(ips))
        if self.raise_on_call:
            raise RuntimeError("rpc down")
        return {"revision": self.revision, "disconnectedPeers": 1,
                "removedPeers": 0}


class TestCanonicalHash:
    def test_status_error_uses_operation_code(self):
        class Aria(FakeAria):
            def set_blocklist(self, ips):
                raise PermissionError("secret")
        outcome = br.apply_blocklist(Aria(), [], True)
        assert outcome.last_error == "peer_blocklist_apply_failed"

    def test_hash_stable_regardless_of_input_order(self):
        h1 = br.canonical_hash(["10.0.0.2", "10.0.0.1"])
        h2 = br.canonical_hash(["10.0.0.1", "10.0.0.2"])
        assert h1 == h2

    def test_hash_differs_on_different_sets(self):
        assert br.canonical_hash(["10.0.0.1"]) != br.canonical_hash(
            ["10.0.0.2"])


class TestApply:
    def test_valid_empty_startup_applies_empty(self):
        aria = FakeAria()
        outcome = br.apply_blocklist(aria, denied_ips=[], apply_empty=True)
        assert aria.calls == [[]]         # full replace with empty list
        assert outcome.success is True
        assert outcome.aria_session_id == "sess-1"
        assert outcome.desired_hash == br.canonical_hash([])

    def test_full_replace_sends_full_list(self):
        aria = FakeAria()
        outcome = br.apply_blocklist(
            aria, denied_ips=["10.0.0.1", "10.0.0.2"], apply_empty=True)
        assert aria.calls == [["10.0.0.1", "10.0.0.2"]]
        assert outcome.success is True

    def test_success_is_nonerror_plus_session_and_hash(self):
        aria = FakeAria(revision=9)
        outcome = br.apply_blocklist(aria, denied_ips=["10.0.0.1"],
                                     apply_empty=True)
        assert outcome.success is True
        assert outcome.aria_session_id == "sess-1"
        assert outcome.desired_hash == br.canonical_hash(["10.0.0.1"])

    def test_revision_and_effects_are_not_success(self):
        # A returned revision / effect counters are effect signals, not the
        # success authority; success comes from the non-error RPC return.
        aria = FakeAria(revision=0)
        outcome = br.apply_blocklist(aria, denied_ips=["10.0.0.1"],
                                     apply_empty=True)
        assert outcome.success is True
        assert outcome.applied_revision == 0
        assert outcome.last_effect == {"disconnected_peers": 1,
                                       "removed_peers": 0}

    def test_rpc_error_is_not_success(self):
        aria = FakeAria(raise_on_call=True)
        outcome = br.apply_blocklist(aria, denied_ips=["10.0.0.1"],
                                     apply_empty=True)
        assert outcome.success is False
        assert outcome.last_error is not None

    def test_no_apply_when_not_empty_and_no_addresses(self):
        # fail_closed with no known address: nothing to apply, no false claim.
        aria = FakeAria()
        outcome = br.apply_blocklist(aria, denied_ips=[], apply_empty=False)
        assert aria.calls == []          # never called
        assert outcome.success is False
        assert outcome.applied is False

    def test_invalid_ip_rejects_whole_call(self):
        aria = FakeAria()
        with pytest.raises(ValueError):
            br.apply_blocklist(aria, denied_ips=["not-an-ip"],
                               apply_empty=True)
        assert aria.calls == []


# ---------------------------------------------------------------------------
# IRIS-04-005 / IRIS-04-003 helpers: denied retention + denied addresses
# ---------------------------------------------------------------------------

class TestDeniedRetention:
    def _policy(self, quarantined=()):
        doc = peer_policy.base_document()
        for dev in quarantined:
            doc["assignments"][dev] = peer_policy.RESERVED_QUARANTINE
        return peer_policy.PolicyResult(
            document=doc, degraded=False, fail_closed=False)

    def test_keep_names_revoked_and_denied_principals_only(self):
        keep = br.denied_retention(
            self._policy(quarantined=["bad"]), {"device:gone"})
        assert keep("device", "bad", "10.0.0.2") is True
        assert keep("device", "gone", "10.0.0.3") is True
        assert keep("device", "good", "10.0.0.1") is False
        assert keep("service", "seeder", "10.0.0.9") is False

    def test_keep_under_fail_closed_keeps_only_revoked(self):
        pr = peer_policy.PolicyResult(
            document={"_fail_closed": True}, degraded=True, fail_closed=True)
        keep = br.denied_retention(pr, {"device:gone"})
        assert keep("device", "gone", "10.0.0.3") is True
        assert keep("device", "bad", "10.0.0.2") is False

    def test_denied_endpoint_ips_ignores_conflicts_and_non_devices(self):
        durable = {
            "device:bad": {"principal_type": "device", "principal_id": "bad",
                           "endpoints": [{"ipv4": "10.0.0.2"}]},
            "device:good": {"principal_type": "device", "principal_id": "good",
                            "endpoints": [{"ipv4": "10.0.0.2"},   # shared
                                          {"ipv4": "10.0.0.1"}]},
            "device:gone": {"principal_type": "device", "principal_id": "gone",
                            "endpoints": [{"ipv4": "10.0.0.3"}]},
            "service:seeder": {"principal_type": "service",
                               "principal_id": "seeder",
                               "endpoints": [{"ipv4": "10.0.0.9"}]},
        }
        ips = br.denied_endpoint_ips(
            self._policy(quarantined=["bad"]), durable, {"device:gone"})
        # The shared 10.0.0.2 IS denied here (fail closed for the legacy
        # question) even though derive_denied_set would record a conflict.
        assert ips == {"10.0.0.2", "10.0.0.3"}


# ---------------------------------------------------------------------------
# B6 release-one preflight: compute mutual-origin effect without applying it
# ---------------------------------------------------------------------------

class TestMutualOriginPreflight:
    @pytest.mark.parametrize("match_type", ["host", "cidr"])
    def test_unknown_origin_is_not_a_false_address_acl_denial(self, match_type):
        doc = peer_policy.base_document()
        doc["acls"]["address-permit"] = {"rules": [
            {"seq": 10, "action": "permit", "match": {
                "type": match_type,
                "value": "10.9.9.9" if match_type == "host" else "10.0.0.0/8"}},
            {"seq": 20, "action": "permit",
             "match": {"type": "device", "value": "d1"}},
            {"seq": 30, "action": "deny", "match": {"type": "any"}},
        ]}
        doc["assignments"]["d1"] = "address-permit"
        peer_policy.validate_document(doc)
        durable = _endpoints(("device:d1", "device", "d1", "10.0.0.3"))
        known = br.derive_denied_set(_pr(doc), durable, {}, [], set(), "10.9.9.9")
        unknown = br.derive_denied_set(_pr(doc), durable, {}, [], set(), None)
        assert known.denied_ips == unknown.denied_ips == []
        assert known.prospective_denied_ips == []
        assert known.prospective_conflicts == []
        assert known.newly_denied_device_ids == []
        assert unknown.prospective_denied_ips is None
        assert unknown.prospective_conflicts is None
        assert unknown.newly_denied_device_ids is None
        # Actual admission remains fail-closed for an unknown address. Only
        # the optional prospective calculation declines to claim an answer.
        assert peer_policy.mutual_permit(
            doc, SEEDER, None, Principal("device", "d1"), "10.0.0.3") is False

    @pytest.mark.parametrize("address", _UNKNOWN_SEEDER_ADDRESSES)
    def test_unknown_origin_skips_mutual_evaluation_without_changing_apply(
            self, monkeypatch, address):
        doc = _quarantine_doc("isolated", "shared-denied")
        doc["acls"]["deny-address"] = {"rules": [
            {"seq": 10, "action": "deny",
             "match": {"type": "host", "value": "10.0.0.4"}},
            {"seq": 20, "action": "permit", "match": {"type": "any"}},
        ]}
        doc["assignments"]["acl-denied"] = "deny-address"
        durable = _endpoints(
            ("device:acl-denied", "device", "acl-denied", "10.0.0.4"),
            ("device:isolated", "device", "isolated", "10.0.0.5"),
            ("device:revoked", "device", "revoked", "10.0.0.6"),
            ("device:shared-denied", "device", "shared-denied", "10.0.0.7"),
            ("device:shared-permitted", "device", "shared-permitted", "10.0.0.7"))
        revoked = {"device:revoked"}
        known = br.derive_denied_set(_pr(doc), durable, {}, [], revoked, SEEDER_IP)

        def unexpected_mutual(*_args, **_kwargs):
            pytest.fail("unknown protected address must not be preflighted")

        monkeypatch.setattr(peer_policy, "mutual_permit", unexpected_mutual)
        unknown = br.derive_denied_set(_pr(doc), durable, {}, [], revoked, address)
        assert unknown.denied_ips == known.denied_ips == [
            "10.0.0.4", "10.0.0.5", "10.0.0.6"]
        assert unknown.conflicts == known.conflicts
        assert len(unknown.conflicts) == 1
        assert unknown.conflicts[0]["ipv4"] == "10.0.0.7"
        assert unknown.apply_empty is True and unknown.fail_closed is False
        assert unknown.prospective_denied_ips is None
        assert unknown.prospective_conflicts is None
        assert unknown.newly_denied_device_ids is None
        aria = FakeAria()
        assert br.apply_blocklist(
            aria, unknown.denied_ips, unknown.apply_empty).success is True
        assert aria.calls == [known.denied_ips]

    @pytest.mark.parametrize("address", _UNKNOWN_SEEDER_ADDRESSES)
    def test_only_string_ipv4_can_establish_known_origin(self, address):
        assert br.valid_protected_seeder_ipv4(address) is False

    @pytest.mark.parametrize("address", ["10.9.9.9", "192.0.2.10", "0.0.0.0"])
    def test_valid_string_ipv4_establishes_known_origin(self, address):
        assert br.valid_protected_seeder_ipv4(address) is True

    def test_derived_set_without_preflight_defaults_to_unknown(self):
        derived = br.DerivedSet([], [], True, False)
        assert derived.prospective_denied_ips is None
        assert derived.prospective_conflicts is None
        assert derived.newly_denied_device_ids is None

    def test_role_origin_false_is_reported_but_current_apply_stays_empty(self):
        doc = _role_doc()
        result = br.derive_denied_set(
            peer_policy.PolicyResult(
                doc, False, False, peer_policy.compile_roles(doc)),
            _endpoints(("device:boat-1", "device", "boat-1", "10.0.0.2")),
            {}, [], set(), SEEDER_IP)

        assert result.denied_ips == []
        assert result.conflicts == []
        assert result.prospective_denied_ips == ["10.0.0.2"]
        assert result.prospective_conflicts == []
        assert result.newly_denied_device_ids == ["boat-1"]
        # The Task 4 legacy-credential admission helper stays on the current
        # self-evaluation rule throughout the preflight release.
        assert br.denied_endpoint_ips(
            _pr(doc),
            _endpoints(("device:boat-1", "device", "boat-1", "10.0.0.2")),
            set()) == set()

    @pytest.mark.parametrize("deny_side", ["seeder", "device"])
    def test_mutual_deny_in_either_direction_is_preflighted(self, deny_side):
        doc = peer_policy.base_document()
        if deny_side == "seeder":
            doc["acls"]["origin-deny"] = {"rules": [
                {"seq": 10, "action": "deny",
                 "match": {"type": "device", "value": "d1"}},
                {"seq": 20, "action": "permit", "match": {"type": "any"}},
            ]}
            doc["seeder_assignment"] = "origin-deny"
        else:
            doc["acls"]["device-deny"] = {"rules": [
                {"seq": 10, "action": "deny",
                 "match": {"type": "service", "value": "seeder"}},
                {"seq": 20, "action": "permit", "match": {"type": "any"}},
            ]}
            doc["assignments"]["d1"] = "device-deny"
        peer_policy.validate_document(doc)

        result = br.derive_denied_set(
            _pr(doc), _endpoints(("device:d1", "device", "d1", "10.0.0.3")),
            {}, [], set(), SEEDER_IP)

        assert result.denied_ips == []
        assert result.prospective_denied_ips == ["10.0.0.3"]
        assert result.newly_denied_device_ids == ["d1"]

    def test_explicit_open_assignment_shadows_role_origin_deny(self):
        doc = _role_doc()
        doc["acls"]["open"] = {"rules": [
            {"seq": 10, "action": "permit", "match": {"type": "any"}},
        ]}
        doc["assignments"]["boat-1"] = "open"
        peer_policy.validate_document(doc)
        result = br.derive_denied_set(
            _pr(doc),
            _endpoints(("device:boat-1", "device", "boat-1", "10.0.0.4")),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == []
        assert result.prospective_denied_ips == []
        assert result.newly_denied_device_ids == []

    def test_existing_self_deny_is_not_newly_denied(self):
        doc = peer_policy.base_document()
        doc["acls"]["address-deny"] = {"rules": [
            {"seq": 10, "action": "deny",
             "match": {"type": "cidr", "value": "10.0.0.0/24"}},
            {"seq": 20, "action": "permit", "match": {"type": "any"}},
        ]}
        doc["assignments"]["d1"] = "address-deny"
        peer_policy.validate_document(doc)
        result = br.derive_denied_set(
            _pr(doc), _endpoints(("device:d1", "device", "d1", "10.0.0.5")),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == ["10.0.0.5"]
        assert result.prospective_denied_ips == ["10.0.0.5"]
        assert result.newly_denied_device_ids == []

    @pytest.mark.parametrize("current_kind", ["quarantine", "revoked"])
    def test_quarantine_and_revocation_are_not_newly_denied(self, current_kind):
        doc = _role_doc(("d1",))
        revoked = set()
        if current_kind == "quarantine":
            doc["assignments"]["d1"] = peer_policy.RESERVED_QUARANTINE
        else:
            revoked.add("device:d1")
        result = br.derive_denied_set(
            _pr(doc), _endpoints(("device:d1", "device", "d1", "10.0.0.6")),
            {}, [], revoked, SEEDER_IP)
        assert result.denied_ips == ["10.0.0.6"]
        assert result.newly_denied_device_ids == []

    def test_protected_address_is_excluded_from_both_sets_and_count(self):
        doc = _role_doc()
        result = br.derive_denied_set(
            _pr(doc),
            _endpoints(("device:boat-1", "device", "boat-1", SEEDER_IP)),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == []
        assert result.prospective_denied_ips == []
        assert result.newly_denied_device_ids == []

    def test_prospective_only_nat_conflict_does_not_degrade_current_result(self):
        doc = _role_doc(("boat-1",))
        durable = _endpoints(
            ("device:boat-1", "device", "boat-1", "10.0.0.7"),
            ("device:open-1", "device", "open-1", "10.0.0.7"))
        result = br.derive_denied_set(
            _pr(doc), durable, {}, [], set(), SEEDER_IP)

        assert result.denied_ips == []
        assert result.conflicts == []
        assert result.prospective_denied_ips == []
        assert len(result.prospective_conflicts) == 1
        assert result.prospective_conflicts[0]["reason"] == "shared_permit_deny"
        assert result.newly_denied_device_ids == []

    def test_multiple_endpoints_and_pending_duplicate_count_device_once(self):
        doc = _role_doc()
        durable = {
            "device:boat-1": {
                "principal_type": "device", "principal_id": "boat-1",
                "endpoints": [
                    {"ipv4": "10.0.0.8", "port": 1, "observed_at": 1},
                    {"ipv4": "10.0.0.9", "port": 2, "observed_at": 1},
                ],
            },
        }
        pending = _endpoints(
            ("device:boat-1", "device", "boat-1", "10.0.0.8"))
        result = br.derive_denied_set(
            _pr(doc), durable, pending, [], set(), SEEDER_IP)
        assert result.prospective_denied_ips == ["10.0.0.8", "10.0.0.9"]
        assert result.newly_denied_device_ids == ["boat-1"]

    def test_supplied_compiled_index_is_used_by_every_current_helper(
            self, monkeypatch):
        doc = _role_doc()
        compiled = peer_policy.compile_roles(doc)
        policy = peer_policy.PolicyResult(doc, False, False, compiled)

        def unexpected(_doc):
            raise AssertionError("compiled roles must be reused")
        monkeypatch.setattr(peer_policy, "compile_roles", unexpected)

        durable = _endpoints(
            ("device:boat-1", "device", "boat-1", "10.0.0.10"))
        assert br.derive_denied_set(
            policy, durable, {}, [], set(), SEEDER_IP).denied_ips == []
        assert br.denied_retention(policy, set())(
            "device", "boat-1", "10.0.0.10") is False
        assert br.denied_endpoint_ips(policy, durable, set()) == set()

    def test_missing_compiled_index_is_built_once_for_full_derivation(
            self, monkeypatch):
        doc = _role_doc(("boat-1", "boat-2"))
        real = peer_policy.compile_roles
        calls = []

        def counted(value):
            calls.append(value)
            return real(value)
        monkeypatch.setattr(peer_policy, "compile_roles", counted)
        durable = _endpoints(
            ("device:boat-1", "device", "boat-1", "10.0.0.11"),
            ("device:boat-2", "device", "boat-2", "10.0.0.12"))
        result = br.derive_denied_set(
            peer_policy.PolicyResult(doc, False, False),
            durable, {}, [], set(), SEEDER_IP)
        assert result.newly_denied_device_ids == ["boat-1", "boat-2"]
        assert calls == [doc]

    def test_fail_closed_has_no_speculative_mutual_origin_evidence(self):
        policy = peer_policy.PolicyResult(
            peer_policy._fail_closed_document(), True, True)
        result = br.derive_denied_set(
            policy,
            _endpoints(("device:d1", "device", "d1", "10.0.0.13")),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == ["10.0.0.13"]
        assert result.prospective_denied_ips is None
        assert result.prospective_conflicts is None
        assert result.newly_denied_device_ids is None


# ---------------------------------------------------------------------------
# Issue #153: the APPLIED set self-evaluates the device ACL. The pair result
# is computed (prospective_denied_ips) but stays preflight-only until the
# documented, separately authorized activation release.
# ---------------------------------------------------------------------------

# (shape, seq the device's own ACL permits the DEVICE at,
#  owner whose ACL denies the seeder<->device pair, seq it denies at)
_ORIGIN_DENIED_SHAPES = [
    ("device_acl_denies_seeder", 20, "device", 10),
    ("permit_self_deny_any", 10, "device", 30),
    ("role_origin_false", 10, "device", 40),
    ("seeder_assignment_denies_device", None, "service", 10),
]


def _origin_denied_doc(shape):
    """Device d1 whose pair with the origin is denied while d1's own ACL still
    permits d1 itself -- every shape the applied set cannot see."""
    doc = peer_policy.base_document()
    if shape == "device_acl_denies_seeder":
        doc["acls"]["dev-deny"] = {"rules": [
            {"seq": 10, "action": "deny",
             "match": {"type": "service", "value": "seeder"}},
            {"seq": 20, "action": "permit", "match": {"type": "any"}}]}
        doc["assignments"]["d1"] = "dev-deny"
    elif shape == "permit_self_deny_any":
        doc["acls"]["self-only"] = {"rules": [
            {"seq": 10, "action": "permit",
             "match": {"type": "device", "value": "d1"}},
            {"seq": 30, "action": "deny", "match": {"type": "any"}}]}
        doc["assignments"]["d1"] = "self-only"
    elif shape == "role_origin_false":
        doc["roles"] = {
            "defs": {"access": {"restricted": True, "peers": ["access"],
                                "origin": False}},
            "role_of": {"d1": "access"}, "qos_default": {}, "qos_device": {}}
    elif shape == "seeder_assignment_denies_device":
        doc["acls"]["origin-deny"] = {"rules": [
            {"seq": 10, "action": "deny",
             "match": {"type": "device", "value": "d1"}},
            {"seq": 20, "action": "permit", "match": {"type": "any"}}]}
        doc["seeder_assignment"] = "origin-deny"
    peer_policy.validate_document(doc)
    return doc


class TestIssue153AppliedSetSelfEvaluates:
    @pytest.mark.parametrize(
        "shape, self_seq, denying_owner, deny_seq", _ORIGIN_DENIED_SHAPES)
    def test_applied_set_asks_the_device_acl_about_the_device_itself(
            self, shape, self_seq, denying_owner, deny_seq):
        doc = _origin_denied_doc(shape)
        d1 = Principal("device", "d1")
        # What the applied set evaluates: d1's own ACL with d1 as the subject.
        # A ``deny service:seeder`` rule, the trailing ``deny any`` behind a
        # ``permit device:<self>`` / ``permit role:<own>`` rule, and every rule
        # of the seeder_assignment ACL can never match that subject.
        assert peer_policy.evaluate(doc, d1, "10.0.0.3") == ("permit", self_seq)
        # What the origin question actually is: the seeder<->device pair.
        if denying_owner == "device":
            assert peer_policy.evaluate_for(
                doc, d1, SEEDER, SEEDER_IP) == ("deny", deny_seq)
        else:
            assert peer_policy.evaluate_for(
                doc, SEEDER, d1, "10.0.0.3") == ("deny", deny_seq)
        assert peer_policy.mutual_permit(
            doc, SEEDER, SEEDER_IP, d1, "10.0.0.3") is False
        result = br.derive_denied_set(
            _pr(doc), _endpoints(("device:d1", "device", "d1", "10.0.0.3")),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == []                  # handed to aria2
        assert result.prospective_denied_ips == ["10.0.0.3"]  # pair result

    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="issue #153: applied denied_ips self-evaluate the device ACL; "
               "the mutual-origin union is preflight-only until the "
               "separately authorized activation release (security.md)")
    @pytest.mark.parametrize(
        "shape", [row[0] for row in _ORIGIN_DENIED_SHAPES])
    def test_origin_denied_device_lands_in_applied_set(self, shape):
        doc = _origin_denied_doc(shape)
        result = br.derive_denied_set(
            _pr(doc), _endpoints(("device:d1", "device", "d1", "10.0.0.3")),
            {}, [], set(), SEEDER_IP)
        assert result.denied_ips == ["10.0.0.3"]
