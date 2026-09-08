# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""QoS grammar, role lifecycle, blast-radius, and recovery-state tests."""
import contextlib
import copy
import json
import os
import shutil
import threading

import pytest

import peer_endpoints
import peer_policy


_MISSING = object()


def _doc(defs=None, role_of=None, qos_default=None, qos_device=None,
         qos_state_default=_MISSING):
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": defs or {},
        "role_of": role_of or {},
        "qos_default": qos_default or {},
        "qos_device": qos_device or {},
    }
    if qos_state_default is not _MISSING:
        doc["roles"]["qos_state_default"] = qos_state_default
    return doc


def _boat_doc(qos=None, device_qos=None, qos_state=_MISSING,
              qos_state_default=_MISSING):
    boat = {
        "restricted": True,
        "peers": ["boat"],
        "origin": True,
        "qos": qos or {},
    }
    if qos_state is not _MISSING:
        boat["qos_state"] = qos_state
    return _doc(
        defs={
            "boat": boat,
            "fiber": {"restricted": False},
        },
        role_of={"boat-1": "boat", "fiber-1": "fiber"},
        qos_device={"boat-1": device_qos or {}} if device_qos else {},
        qos_state_default=qos_state_default,
    )


def _scoped_state_doc(scope, state_map=_MISSING):
    if scope == "global":
        return _boat_doc(qos_state_default=state_map)
    if scope == "role":
        return _boat_doc(qos_state=state_map)
    raise AssertionError("unknown test scope: %s" % scope)


def _tree_bytes(root):
    result = {}
    for directory, _subdirs, filenames in os.walk(root):
        for filename in filenames:
            path = os.path.join(directory, filename)
            with open(path, "rb") as stream:
                result[os.path.relpath(path, root)] = stream.read()
    return result


@pytest.fixture
def paths(tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.initialize(auth, lkg)
    return auth, lkg


class TestQosDefaultsAndUnits:
    def test_builtin_defaults_do_not_introduce_rate_caps(self):
        qos = peer_policy.compile_qos(peer_policy.base_document(), "device-1")
        assert qos == {
            "max_peers": 10,
            "per_peer_bps": 12_500_000,
            "fanout": 1,
            "seed_up_bps": 0,
            "seed_down_bps": 0,
            "leech_up_bps": 0,
            "leech_down_bps": 0,
            "overall_up_bps": 0,
            "overall_down_bps": 0,
            "max_concurrent": 100,
            "request_peer_speed_limit_bps": 51_200,
            "announce_min_interval_s": 30,
            "numwant": 50,
            "handout_budget": 0,
            "catalog_tick_s": 60,
            "telemetry_every_ticks": 1,
            "telemetry_pause": False,
            "on_stale": "defaults",
            "origin_up_bps": 0,
            "origin_per_torrent_up_bps": 0,
            "origin_max_peers": 55,
        }

    def test_units_are_explicit_for_every_closed_key(self):
        expected = {
            "max_peers": "connections_per_torrent",
            "per_peer_bps": "bytes_per_second",
            "fanout": "multiplier",
            "seed_up_bps": "bytes_per_second",
            "seed_down_bps": "bytes_per_second",
            "leech_up_bps": "bytes_per_second",
            "leech_down_bps": "bytes_per_second",
            "overall_up_bps": "bytes_per_second",
            "overall_down_bps": "bytes_per_second",
            "max_concurrent": "torrents",
            "request_peer_speed_limit_bps": "bytes_per_second",
            "announce_min_interval_s": "seconds",
            "numwant": "peers_per_announce",
            "handout_budget": "handouts_per_window",
            "catalog_tick_s": "seconds",
            "telemetry_every_ticks": "ticks",
            "telemetry_pause": "boolean",
            "on_stale": "enum",
            "origin_up_bps": "bytes_per_second",
            "origin_per_torrent_up_bps": "bytes_per_second",
            "origin_max_peers": "connections_per_torrent",
        }
        assert peer_policy.QOS_UNITS == expected

    def test_restricted_role_defaults_to_keep_on_stale(self):
        assert peer_policy.compile_qos(_boat_doc(), "boat-1")["on_stale"] \
            == "keep"


class TestQosGrammar:
    @pytest.mark.parametrize("key,minimum,maximum", [
        ("max_peers", 1, 1000),
        ("per_peer_bps", 0, 10_000_000_000),
        ("fanout", 1, 1000),
        ("seed_up_bps", 0, 10_000_000_000),
        ("seed_down_bps", 0, 10_000_000_000),
        ("leech_up_bps", 0, 10_000_000_000),
        ("leech_down_bps", 0, 10_000_000_000),
        ("overall_up_bps", 0, 10_000_000_000),
        ("overall_down_bps", 0, 10_000_000_000),
        ("max_concurrent", 1, 1000),
        ("request_peer_speed_limit_bps", 0, 1_000_000_000),
        ("announce_min_interval_s", 10, 300),
        ("numwant", 4, 200),
        ("handout_budget", 0, 1000),
        ("catalog_tick_s", 60, 900),
        ("telemetry_every_ticks", 1, 60),
        ("origin_up_bps", 0, 10_000_000_000),
        ("origin_per_torrent_up_bps", 0, 10_000_000_000),
        ("origin_max_peers", 1, 1000),
    ])
    def test_numeric_bounds(self, key, minimum, maximum):
        for value in (minimum, maximum):
            doc = _doc(qos_default={key: value})
            if key == "fanout":
                doc["roles"]["qos_default"]["max_peers"] = maximum
            peer_policy.validate_document(doc)
        for value in (minimum - 1, maximum + 1):
            doc = _doc(qos_default={key: value})
            with pytest.raises(peer_policy.PolicyError):
                peer_policy.validate_document(doc)

    @pytest.mark.parametrize("key", [
        "per_peer_bps", "seed_up_bps", "seed_down_bps", "leech_up_bps",
        "leech_down_bps", "overall_up_bps", "overall_down_bps",
        "request_peer_speed_limit_bps", "origin_up_bps",
        "origin_per_torrent_up_bps",
    ])
    def test_nonzero_byte_rates_have_an_8192_floor(self, key):
        peer_policy.validate_document(_doc(qos_default={key: 0}))
        with pytest.raises(peer_policy.PolicyError, match="at least 8192"):
            peer_policy.validate_document(_doc(qos_default={key: 8191}))
        peer_policy.validate_document(_doc(qos_default={key: 8192}))

    @pytest.mark.parametrize("value", [True, 1.5, "10", None])
    def test_numeric_values_are_integers_not_bools(self, value):
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(_doc(qos_default={"max_peers": value}))

    @pytest.mark.parametrize("value", [True, False])
    def test_telemetry_pause_is_boolean(self, value):
        peer_policy.validate_document(
            _doc(qos_default={"telemetry_pause": value}))

    @pytest.mark.parametrize("value", [0, 1, "false", None])
    def test_telemetry_pause_rejects_non_boolean(self, value):
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(
                _doc(qos_default={"telemetry_pause": value}))

    @pytest.mark.parametrize("value", ["keep", "defaults"])
    def test_on_stale_enum(self, value):
        peer_policy.validate_document(_doc(qos_default={"on_stale": value}))

    @pytest.mark.parametrize("value", ["permit", "", 1, None])
    def test_on_stale_rejects_unknown_values(self, value):
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(_doc(qos_default={"on_stale": value}))

    @pytest.mark.parametrize("bad_key", [
        "bt-tracker-interval", "dscp", "tos", "cos", "policy-map",
        "class_map", "service-policy", "shaper", "policer",
        "interface_rate_limit", "seed-ratio", "seed-time", "header", "dir",
        "bt-tracker", "bt-tracker-connect-timeout",
        "announce_min_interval_seed_s", "announce_min_interval_leech_s",
    ])
    def test_closed_key_set_rejects_transport_and_device_qos(self, bad_key):
        for location in ("global", "role", "device"):
            doc = _boat_doc()
            if location == "global":
                doc["roles"]["qos_default"][bad_key] = 1
            elif location == "role":
                doc["roles"]["defs"]["boat"]["qos"][bad_key] = 1
            else:
                doc["roles"]["qos_device"]["boat-1"] = {bad_key: 1}
            with pytest.raises(peer_policy.PolicyError):
                peer_policy.validate_document(doc)

    @pytest.mark.parametrize("key", [
        "origin_up_bps", "origin_per_torrent_up_bps", "origin_max_peers",
    ])
    def test_origin_keys_are_global_only(self, key):
        doc = _boat_doc(qos={key: 1})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    @pytest.mark.parametrize("key", [
        "request_peer_speed_limit_bps", "announce_min_interval_s",
        "numwant", "handout_budget", "on_stale",
    ])
    def test_role_only_keys_are_not_device_overrides(self, key):
        value = "keep" if key == "on_stale" else {
            "request_peer_speed_limit_bps": 0,
            "announce_min_interval_s": 30,
            "numwant": 4,
            "handout_budget": 0,
        }[key]
        doc = _boat_doc(device_qos={key: value})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(doc)

    def test_role_on_stale_has_one_canonical_location(self):
        canonical = _boat_doc()
        canonical["roles"]["defs"]["boat"]["on_stale"] = "keep"
        peer_policy.validate_document(canonical)

        noncanonical = _boat_doc(qos={"on_stale": "keep"})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(noncanonical)

    def test_effective_fanout_must_not_exceed_max_peers(self):
        doc = _boat_doc(qos={"max_peers": 4, "fanout": 5})
        with pytest.raises(peer_policy.PolicyError, match="fanout"):
            peer_policy.validate_document(doc)

    @pytest.mark.parametrize("location", ["global", "role", "device"])
    def test_derived_per_torrent_rate_respects_wire_ceiling(self, location):
        at_ceiling = {
            "max_peers": 1000, "fanout": 1000,
            "per_peer_bps": 10_000_000,
        }
        above_ceiling = dict(at_ceiling, per_peer_bps=10_000_001)

        def document(qos):
            if location == "global":
                return _doc(qos_default=qos)
            if location == "role":
                return _boat_doc(qos=qos)
            return _boat_doc(device_qos=qos)

        peer_policy.validate_document(document(at_ceiling))
        with pytest.raises(peer_policy.PolicyError, match="derived.*range"):
            peer_policy.validate_document(document(above_ceiling))

    def test_empty_role_still_validates_effective_qos(self):
        doc = _doc(defs={
            "boat": {"restricted": True, "qos": {
                "max_peers": 4, "fanout": 5}}})
        with pytest.raises(peer_policy.PolicyError, match="fanout"):
            peer_policy.validate_document(doc)

    def test_catalog_tick_is_a_launcher_tick_multiple(self):
        with pytest.raises(peer_policy.PolicyError, match="catalog_tick"):
            peer_policy.validate_document(
                _doc(qos_default={"catalog_tick_s": 61}))

    def test_restricted_catalog_tick_is_bounded_by_endpoint_ttl(self,
                                                                 monkeypatch):
        monkeypatch.setattr(peer_endpoints, "endpoint_ttl", lambda: 600)
        with pytest.raises(peer_policy.PolicyError, match="endpoint TTL"):
            peer_policy.validate_document(
                _boat_doc(qos={"catalog_tick_s": 240}))
        unrestricted = _doc(
            defs={"fiber": {"restricted": False,
                            "qos": {"catalog_tick_s": 900}}},
            role_of={"fiber-1": "fiber"})
        peer_policy.validate_document(unrestricted)


class TestTrackerStateCompatibility:
    def test_base_document_remains_exact_and_state_free(self):
        expected = {
            "schema": 1,
            "revision": 1,
            "acls": {"quarantine": {
                "reserved": True,
                "description": "reserved: fully isolate an assigned device",
                "rules": [{"seq": 10, "action": "deny",
                           "match": {"type": "any"}}]}},
            "assignments": {},
            "seeder_assignment": None,
            "operation_outbox": [],
        }

        assert peer_policy.base_document() == expected
        assert "roles" not in peer_policy.base_document()

    def test_scalar_only_authoritative_load_preserves_deliberate_bytes(
            self, tmp_path):
        document = _boat_doc(
            qos={"announce_min_interval_s": 75, "numwant": 17},
            device_qos={"max_peers": 3})
        peer_policy.validate_document(document)
        payload = (json.dumps(
            document, indent=3, sort_keys=False) + "\n").encode()
        auth = tmp_path / "peer-policy.json"
        auth.write_bytes(payload)

        loaded = peer_policy.load_policy(
            str(auth), str(tmp_path / "peer-policy.lkg.json"))

        assert loaded.document == document
        assert loaded.degraded is False
        assert loaded.fail_closed is False
        assert auth.read_bytes() == payload
        assert not (tmp_path / "peer-policy.lkg.json").exists()


class TestTrackerStateQosGrammar:
    def test_empty_and_partial_state_maps_are_valid(self):
        documents = [
            _doc(qos_state_default={}),
            _doc(qos_state_default={"seeder": {}}),
            _doc(qos_state_default={
                "seeder": {"announce_min_interval_s": 10},
                "leecher": {"numwant": 200}}),
            _boat_doc(qos_state={}),
            _boat_doc(qos_state={"leecher": {}}),
            _boat_doc(qos_state={
                "seeder": {"numwant": 4},
                "leecher": {"announce_min_interval_s": 300}}),
        ]
        for document in documents:
            assert peer_policy.validate_document(document) is document

    def test_state_maps_reject_unknown_names_keys_and_non_objects(self):
        documents = []
        for bad_state in ("complete", "SEEDER", ""):
            for scope in ("global", "role"):
                documents.append(_scoped_state_doc(
                    scope, {bad_state: {"numwant": 10}}))
        for bad_outer in ([], "seeder", 1, True, None):
            for scope in ("global", "role"):
                documents.append(_scoped_state_doc(scope, bad_outer))
        for scope in ("global", "role"):
            for state in ("seeder", "leecher"):
                for bad_value in ([], "values", 1, True, None):
                    documents.append(_scoped_state_doc(
                        scope, {state: bad_value}))
                for bad_key in (
                        "max_peers", "interval", "announce_min_interval"):
                    documents.append(_scoped_state_doc(
                        scope, {state: {bad_key: 10}}))

        for document in documents:
            with pytest.raises(peer_policy.PolicyError):
                peer_policy.validate_document(document)

    def test_state_values_reuse_integer_ranges_and_reject_other_types(self):
        ranges = (
            ("announce_min_interval_s", 10, 300),
            ("numwant", 4, 200),
        )
        for scope in ("global", "role"):
            for state in ("seeder", "leecher"):
                for key, minimum, maximum in ranges:
                    for value in (minimum, maximum):
                        peer_policy.validate_document(_scoped_state_doc(
                            scope, {state: {key: value}}))
                    invalid = (minimum - 1, maximum + 1,
                               True, False, 10.0, "10", None, [], {})
                    for value in invalid:
                        with pytest.raises(peer_policy.PolicyError):
                            peer_policy.validate_document(_scoped_state_doc(
                                scope, {state: {key: value}}))

    def test_state_is_rejected_at_unknown_and_device_scopes(self):
        unknown = _doc()
        unknown["roles"]["qos_state_defaults"] = {}
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(unknown)

        device_state = _doc(qos_device={"d1": {
            "qos_state": {"seeder": {"numwant": 4}}}})
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.validate_document(device_state)

class TestCompileQos:
    def test_global_role_device_precedence_and_absent_inheritance(self):
        doc = _boat_doc(
            qos={"max_peers": 8, "per_peer_bps": 200, "fanout": 3,
                 "leech_down_bps": 7},
            device_qos={"seed_down_bps": 9, "max_concurrent": 4})
        doc["roles"]["qos_default"] = {
            "max_peers": 20, "per_peer_bps": 100, "fanout": 2,
            "overall_up_bps": 2,
        }
        qos = peer_policy.compile_qos(doc, "boat-1")
        assert qos["max_peers"] == 8
        assert qos["per_peer_bps"] == 200
        assert qos["fanout"] == 3
        assert qos["max_concurrent"] == 4
        assert qos["overall_up_bps"] == 2
        assert qos["seed_down_bps"] == 9
        assert qos["leech_down_bps"] == 7
        assert qos["seed_up_bps"] == 600
        assert qos["leech_up_bps"] == 600

    def test_operator_per_peer_derives_four_per_torrent_rates(self):
        doc = _doc(qos_default={"per_peer_bps": 125_000, "fanout": 4,
                                "max_peers": 4})
        qos = peer_policy.compile_qos(doc, "d1")
        assert {qos[key] for key in peer_policy.PER_TORRENT_RATE_KEYS} \
            == {500_000}

    def test_explicit_rate_at_same_layer_wins_over_derivation(self):
        doc = _doc(qos_default={"per_peer_bps": 10_000, "fanout": 2,
                                "seed_up_bps": 25_000})
        qos = peer_policy.compile_qos(doc, "d1")
        assert qos["seed_up_bps"] == 25_000
        assert qos["seed_down_bps"] == 20_000

    def test_more_specific_model_input_replaces_less_specific_explicit_rate(self):
        doc = _boat_doc(qos={"per_peer_bps": 20_000, "fanout": 2})
        doc["roles"]["qos_default"] = {"seed_up_bps": 25_000}
        assert peer_policy.compile_qos(doc, "boat-1")["seed_up_bps"] == 40_000

    def test_compiler_is_pure(self):
        doc = _boat_doc(qos={"max_peers": 4})
        before = copy.deepcopy(doc)
        peer_policy.compile_qos(doc, "boat-1")
        assert doc == before


class TestCompileTrackerQos:
    def test_scalar_only_policy_is_state_independent(self):
        doc = _boat_doc(qos={"announce_min_interval_s": 75,
                             "numwant": 17})
        before = copy.deepcopy(doc)

        for state in ("seeder", "leecher"):
            assert peer_policy.compile_tracker_qos(doc, "boat-1", state) == {
                "announce_min_interval_s": 75,
                "numwant": 17,
            }
            assert peer_policy.explain_tracker_qos(doc, "boat-1", state) == {
                "announce_min_interval_s": {
                    "value": 75, "source": "role:boat"},
                "numwant": {"value": 17, "source": "role:boat"},
            }
        assert doc == before

    def test_state_layers_do_not_enter_scalar_compilation_or_explanation(self):
        state_free = _boat_doc(
            qos={"announce_min_interval_s": 75, "numwant": 17},
            device_qos={"max_peers": 3, "seed_up_bps": 90_000})
        doc = _boat_doc(
            qos={"announce_min_interval_s": 75, "numwant": 17},
            device_qos={"max_peers": 3, "seed_up_bps": 90_000},
            qos_state_default={"seeder": {
                "announce_min_interval_s": 120, "numwant": 10}},
            qos_state={"seeder": {
                "announce_min_interval_s": 180, "numwant": 4}})
        before = copy.deepcopy(doc)

        assert peer_policy.compile_qos(doc, "boat-1") == \
            peer_policy.compile_qos(state_free, "boat-1")
        assert peer_policy.explain_qos(doc, "boat-1") == \
            peer_policy.explain_qos(state_free, "boat-1")
        assert doc == before

    def test_five_layer_precedence_for_both_keys_states_and_exact_sources(self):
        for state in ("seeder", "leecher"):
            for key, builtin in (("announce_min_interval_s", 30),
                                 ("numwant", 50)):
                other_state = "leecher" if state == "seeder" else "seeder"
                values = {
                    "global": builtin + 1,
                    "global-state:%s" % state: builtin + 2,
                    "role:boat": builtin + 3,
                    "role-state:boat:%s" % state: builtin + 4,
                }

                documents = [
                    (peer_policy.base_document(), "d1", builtin, "builtin"),
                    (_doc(qos_default={key: values["global"]}),
                     "d1", values["global"], "global"),
                    (_doc(qos_default={key: values["global"]},
                          qos_state_default={
                              state: {key: values[
                                  "global-state:%s" % state]},
                              other_state: {key: builtin + 10}}),
                     "d1", values["global-state:%s" % state],
                     "global-state:%s" % state),
                    (_boat_doc(
                        qos={key: values["role:boat"]},
                        qos_state_default={state: {key: values[
                            "global-state:%s" % state]}}),
                     "boat-1", values["role:boat"], "role:boat"),
                    (_boat_doc(
                        qos={key: values["role:boat"]},
                        qos_state_default={state: {key: values[
                            "global-state:%s" % state]}},
                        qos_state={
                            state: {key: values[
                                "role-state:boat:%s" % state]},
                            other_state: {key: builtin + 11}}),
                     "boat-1", values["role-state:boat:%s" % state],
                     "role-state:boat:%s" % state),
                ]

                for doc, device_id, expected, source in documents:
                    compiled = peer_policy.compile_tracker_qos(
                        doc, device_id, state)
                    explained = peer_policy.explain_tracker_qos(
                        doc, device_id, state)
                    assert compiled[key] == expected
                    assert explained[key] == {
                        "value": expected, "source": source}

    def test_partial_state_override_inherits_each_key_independently(self):
        keys = ("announce_min_interval_s", "numwant")
        role_values = {"announce_min_interval_s": 80, "numwant": 30}
        state_values = {"announce_min_interval_s": 180, "numwant": 8}
        for state in ("seeder", "leecher"):
            other_state = "leecher" if state == "seeder" else "seeder"
            for overridden in keys:
                doc = _boat_doc(
                    qos=role_values,
                    qos_state_default={state: {
                        "announce_min_interval_s": 120, "numwant": 20}},
                    qos_state={
                        state: {overridden: state_values[overridden]},
                        other_state: {
                            "announce_min_interval_s": 200,
                            "numwant": 6}})
                before = copy.deepcopy(doc)
                expected = dict(role_values)
                expected[overridden] = state_values[overridden]
                explanation = {
                    key: {
                        "value": expected[key],
                        "source": ("role-state:boat:%s" % state
                                   if key == overridden else "role:boat"),
                    }
                    for key in keys
                }

                assert peer_policy.compile_tracker_qos(
                    doc, "boat-1", state) == expected
                assert peer_policy.explain_tracker_qos(
                    doc, "boat-1", state) == explanation
                assert doc == before

    def test_tracker_compilers_reject_every_state_outside_closed_enum(self):
        for state in ("", "seed", "SEEDER", "complete", None, 0, True):
            with pytest.raises(peer_policy.PolicyError):
                peer_policy.compile_tracker_qos(peer_policy.base_document(),
                                                "d1", state)
            with pytest.raises(peer_policy.PolicyError):
                peer_policy.explain_tracker_qos(peer_policy.base_document(),
                                                "d1", state)


class TestCompiledRoleMembershipIndex:
    def test_reverse_membership_is_precompiled_and_immutable(self):
        compiled = peer_policy.compile_roles(_boat_doc())
        assert compiled.members_by_role["boat"] == frozenset(["boat-1"])
        assert compiled.members_by_role["fiber"] == frozenset(["fiber-1"])
        with pytest.raises(TypeError):
            compiled.members_by_role["boat"] = frozenset()
        with pytest.raises(AttributeError):
            compiled.members_by_role["boat"].add("boat-2")

    def test_four_argument_construction_remains_compatible(self):
        compiled = peer_policy.CompiledRoles({}, {}, frozenset(), {})
        assert compiled.members_by_role is None


class TestRoleGraphValidationAndWarnings:
    def test_public_role_name_validator_returns_the_validated_name(self):
        assert peer_policy.validate_role_name("boat-1") == "boat-1"

    @pytest.mark.parametrize("name", sorted(peer_policy.RESERVED_ROLE_NAMES))
    def test_reserved_role_names_are_rejected_in_raw_documents(self, name):
        with pytest.raises(peer_policy.PolicyError) as exc:
            peer_policy.validate_document(
                _doc(defs={name: {"restricted": False}}))
        assert exc.value.code == "role_reserved_name"
        assert exc.value.details == {"role": name}

    @pytest.mark.parametrize("name", sorted(peer_policy.RESERVED_ROLE_NAMES))
    def test_reserved_role_names_are_rejected_by_lifecycle(self, paths, name):
        auth, lkg = paths
        with pytest.raises(peer_policy.PolicyError) as exc:
            peer_policy.define_role(
                auth, lkg, name, {"restricted": False}, "operator", 1.0)
        assert exc.value.code == "role_reserved_name"
        assert exc.value.details == {"role": name}
        assert peer_policy.load_policy(auth, lkg).document == \
            peer_policy.base_document()

    def test_explicit_peers_must_include_self(self):
        doc = _boat_doc()
        doc["roles"]["defs"]["boat"]["peers"] = ["fiber"]
        with pytest.raises(peer_policy.PolicyError) as exc:
            peer_policy.validate_document(doc)
        assert exc.value.code == "role_isolated"
        assert exc.value.details == {"role": "boat"}

    def test_two_restricted_roles_must_be_symmetric(self):
        doc = _doc(defs={
            "a": {"restricted": True, "peers": ["a", "b"]},
            "b": {"restricted": True, "peers": ["b"]},
        })
        with pytest.raises(peer_policy.PolicyError) as exc:
            peer_policy.validate_document(doc)
        assert exc.value.code == "asymmetric_peers"
        assert exc.value.details == {"role": "a", "peer": "b"}

    def test_origin_defaults_true_and_dead_end_is_a_structured_warning(self):
        doc = _boat_doc()
        assert peer_policy.role_origin_enabled(doc, "boat") is True
        doc["roles"]["defs"]["boat"]["origin"] = False
        warnings = []
        peer_policy.validate_document(doc, warning_sink=warnings)
        assert warnings == [{"code": "origin_unreachable", "role": "boat"}]

    def test_origin_warning_clears_when_a_peer_can_reach_origin(self):
        doc = _doc(defs={
            "a": {"restricted": True, "peers": ["a", "b"],
                  "origin": False},
            "b": {"restricted": True, "peers": ["a", "b"],
                  "origin": True},
        })
        warnings = []
        peer_policy.validate_document(doc, warning_sink=warnings)
        assert warnings == []

    def test_origin_warning_traverses_mutually_reachable_roles(self):
        doc = _doc(defs={
            "a": {"restricted": True, "peers": ["a", "b"],
                  "origin": False},
            "b": {"restricted": True, "peers": ["a", "b", "c"],
                  "origin": False},
            "c": {"restricted": True, "peers": ["b", "c"],
                  "origin": True},
            "d": {"restricted": True, "peers": ["d"],
                  "origin": False},
        })
        warnings = []

        peer_policy.validate_document(doc, warning_sink=warnings)

        assert warnings == [{"code": "origin_unreachable", "role": "d"}]


class TestRoleLifecycle:
    def test_define_role_normalizes_undirected_peers(self, paths):
        auth, lkg = paths
        peer_policy.define_role(
            auth, lkg, "fiber", {"restricted": False}, "operator", 1.0)
        doc = peer_policy.define_role(
            auth, lkg, "boat",
            {"restricted": True, "peers": ["boat", "fiber"]},
            "operator", 2.0)
        assert doc["roles"]["defs"]["boat"]["peers"] == ["boat", "fiber"]
        assert doc["roles"]["defs"]["fiber"]["peers"] == ["fiber", "boat"]
        peer_policy.validate_document(doc)

    def test_bulk_assignment_is_one_revision_and_one_outbox_event(self, paths):
        auth, lkg = paths
        before = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        doc = peer_policy.set_roles_bulk(
            auth, lkg, "boat", ["boat-1", "boat-2", "boat-3"],
            "operator", 2.0)
        assert doc["revision"] == before["revision"] + 1
        assert len(doc["operation_outbox"]) == \
            len(before["operation_outbox"]) + 1
        assert doc["operation_outbox"][-1]["target"] == "role:boat"
        assert doc["roles"]["role_of"] == {
            "boat-1": "boat", "boat-2": "boat", "boat-3": "boat"}

    def test_bulk_clear_is_one_revision_and_one_outbox_event(self, paths):
        auth, lkg = paths
        peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        before = peer_policy.set_roles_bulk(
            auth, lkg, "boat", ["boat-1", "boat-2", "boat-3"],
            "operator", 2.0)
        doc = peer_policy.set_roles_bulk(
            auth, lkg, None, ["boat-1", "boat-3"], "operator", 3.0)
        assert doc["revision"] == before["revision"] + 1
        assert len(doc["operation_outbox"]) == \
            len(before["operation_outbox"]) + 1
        assert doc["operation_outbox"][-1]["action"] == "set_roles_bulk"
        assert doc["operation_outbox"][-1]["target"] == "role:"
        assert doc["roles"]["role_of"] == {"boat-2": "boat"}

    def test_qos_updates_each_commit_one_revision_and_one_event(self, paths):
        auth, lkg = paths
        prior = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        global_doc = peer_policy.set_qos(
            auth, lkg, {"max_peers": 20}, "operator", 2.0)
        role_doc = peer_policy.set_qos(
            auth, lkg, {"max_peers": 4}, "operator", 3.0, role="boat")
        device_doc = peer_policy.set_qos(
            auth, lkg, {"max_peers": 2}, "operator", 4.0,
            device_id="boat-1")

        assert device_doc["revision"] == prior["revision"] + 3
        assert len(device_doc["operation_outbox"]) == \
            len(prior["operation_outbox"]) + 3
        assert [entry["target"] for entry in
                device_doc["operation_outbox"][-3:]] == [
                    "qos:global", "role:boat", "boat-1"]
        assert global_doc["roles"]["qos_default"] == {"max_peers": 20}
        assert role_doc["roles"]["defs"]["boat"]["qos"] == {
            "max_peers": 4}
        assert peer_policy.compile_qos(device_doc, "boat-1")["max_peers"] == 2

    def test_delete_in_use_reports_members_and_referring_roles(self, paths):
        auth, lkg = paths
        peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        peer_policy.define_role(
            auth, lkg, "fiber",
            {"restricted": True, "peers": ["fiber", "boat"]},
            "operator", 2.0)
        peer_policy.set_role(
            auth, lkg, "boat-1", "boat", "operator", 3.0)
        with pytest.raises(peer_policy.RoleInUse) as exc:
            peer_policy.delete_role(
                auth, lkg, "boat", "operator", 4.0)
        assert exc.value.code == "role_in_use"
        assert exc.value.member_count == 1
        assert exc.value.referring_roles == ("fiber",)

    def test_role_write_sets_marker_and_durable_watermark(self, paths):
        auth, lkg = paths
        doc = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        assert doc["roles_present"] is True
        assert peer_policy.roles_ever_configured(auth)
        assert os.path.exists(peer_policy.roles_watermark_path(auth))

    def test_watermark_failure_prevents_first_role_commit(self, paths,
                                                           monkeypatch):
        auth, lkg = paths

        def fail_watermark(_auth_path):
            raise OSError("watermark disk full")

        monkeypatch.setattr(
            peer_policy, "_write_roles_watermark", fail_watermark)
        with pytest.raises(OSError, match="watermark"):
            peer_policy.define_role(
                auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        with open(auth) as f:
            persisted = json.load(f)
        assert persisted == peer_policy.base_document()
        with open(lkg) as f:
            persisted_lkg = json.load(f)
        assert persisted_lkg == peer_policy.base_document()
        assert peer_policy.lkg_ring_revisions(lkg) == []

    def test_marker_is_an_ignorable_top_level_extension(self):
        doc = peer_policy.base_document()
        doc["roles_present"] = True
        assert peer_policy.validate_document(doc) is doc

    def test_watermark_distinguishes_lost_state_from_fresh_install(self,
                                                                   tmp_path):
        fresh_auth = str(tmp_path / "fresh" / "peer-policy.json")
        fresh_lkg = str(tmp_path / "fresh" / "peer-policy.lkg.json")
        fresh = peer_policy.load_policy(fresh_auth, fresh_lkg)
        assert fresh.degraded is False

        auth = str(tmp_path / "lost" / "peer-policy.json")
        lkg = str(tmp_path / "lost" / "peer-policy.lkg.json")
        peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        os.remove(auth)
        os.remove(lkg)
        shutil.rmtree(peer_policy.lkg_ring_path(lkg))
        restored = peer_policy.load_policy(auth, lkg)
        assert restored.degraded is True
        assert restored.fail_closed is False
        assert "roles" not in restored.document

    def test_first_load_does_not_overwrite_a_concurrent_first_commit(
            self, tmp_path, monkeypatch):
        auth = str(tmp_path / "race" / "peer-policy.json")
        lkg = str(tmp_path / "race" / "peer-policy.lkg.json")
        loader_waiting = threading.Event()
        release_loader = threading.Event()
        real_lock = peer_policy._umbrella_lock

        @contextlib.contextmanager
        def controlled_lock(path):
            if threading.current_thread().name == "policy-loader":
                loader_waiting.set()
                assert release_loader.wait(timeout=5)
            with real_lock(path):
                yield

        monkeypatch.setattr(peer_policy, "_umbrella_lock", controlled_lock)
        outcome = {}

        def load():
            try:
                outcome["result"] = peer_policy.load_policy(auth, lkg)
            except BaseException as exc:  # preserve a thread failure to assert
                outcome["error"] = exc

        loader = threading.Thread(target=load, name="policy-loader")
        loader.start()
        try:
            assert loader_waiting.wait(timeout=5)
            committed = peer_policy.commit_mutation(
                auth, lkg, "assign", "device-1", "operator", 1.0,
                lambda doc: doc["assignments"].update(
                    {"device-1": "quarantine"}))
        finally:
            release_loader.set()
            loader.join(timeout=5)

        assert not loader.is_alive()
        assert "error" not in outcome
        assert outcome["result"].document == committed
        assert committed["revision"] == 2
        with open(auth) as f:
            assert json.load(f) == committed

class TestTrackerStateQosMutation:
    def test_unrelated_role_mutation_does_not_materialize_state(self, paths):
        auth, lkg = paths
        assert "roles" not in peer_policy.base_document()
        doc = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)

        assert "qos_state_default" not in doc["roles"]
        assert "qos_state" not in doc["roles"]["defs"]["boat"]

    def test_global_omission_preserves_and_empty_state_clears_only_state(
            self, paths):
        auth, lkg = paths
        scalar = {"announce_min_interval_s": 60, "numwant": 25}
        state_qos = {"seeder": {"announce_min_interval_s": 120,
                                 "numwant": 8}}
        prior = peer_policy.set_qos(
            auth, lkg, scalar, "operator", 1.0)
        with_state = peer_policy.set_qos(
            auth, lkg, None, "operator", 2.0,
            qos_state=state_qos, expected_revision=prior["revision"])

        assert with_state["roles"]["qos_default"] == scalar
        assert with_state["roles"]["qos_state_default"] == state_qos
        assert with_state["revision"] == prior["revision"] + 1
        assert with_state["operation_outbox"][-1]["target"] == "qos:global"

        scalar_empty = peer_policy.set_qos(
            auth, lkg, {}, "operator", 3.0, qos_state=None,
            expected_revision=with_state["revision"])
        assert scalar_empty["roles"]["qos_default"] == {}
        assert scalar_empty["roles"]["qos_state_default"] == state_qos

        cleared = peer_policy.set_qos(
            auth, lkg, None, "operator", 4.0, qos_state={},
            expected_revision=scalar_empty["revision"])
        assert "qos_state_default" not in cleared["roles"]
        assert cleared["roles"]["qos_default"] == {}

    def test_role_scalar_and_state_replacements_are_atomic_and_independent(
            self, paths):
        auth, lkg = paths
        prior = peer_policy.define_role(
            auth, lkg, "boat", {
                "restricted": True,
                "qos": {"announce_min_interval_s": 70},
                "qos_state": {"leecher": {"numwant": 18}},
            }, "operator", 1.0)

        state_only = peer_policy.set_qos(
            auth, lkg, None, "operator", 2.0, role="boat",
            qos_state={"seeder": {"numwant": 6}},
            expected_revision=prior["revision"])
        definition = state_only["roles"]["defs"]["boat"]
        assert definition["qos"] == {"announce_min_interval_s": 70}
        assert definition["qos_state"] == {"seeder": {"numwant": 6}}

        scalar_only = peer_policy.set_qos(
            auth, lkg, {"announce_min_interval_s": 90}, "operator", 3.0,
            role="boat", qos_state=None,
            expected_revision=state_only["revision"])
        definition = scalar_only["roles"]["defs"]["boat"]
        assert definition["qos"] == {"announce_min_interval_s": 90}
        assert definition["qos_state"] == {"seeder": {"numwant": 6}}

        both = peer_policy.set_qos(
            auth, lkg, {"announce_min_interval_s": 100}, "operator", 4.0,
            role="boat", qos_state={"leecher": {"numwant": 12}},
            expected_revision=scalar_only["revision"])
        definition = both["roles"]["defs"]["boat"]
        assert definition["qos"] == {"announce_min_interval_s": 100}
        assert definition["qos_state"] == {"leecher": {"numwant": 12}}
        assert both["revision"] == scalar_only["revision"] + 1
        assert len(both["operation_outbox"]) == \
            len(scalar_only["operation_outbox"]) + 1

        state_cleared = peer_policy.set_qos(
            auth, lkg, None, "operator", 5.0, role="boat", qos_state={},
            expected_revision=both["revision"])
        definition = state_cleared["roles"]["defs"]["boat"]
        assert "qos_state" not in definition
        assert definition["qos"] == {"announce_min_interval_s": 100}

    def test_state_mutation_requires_a_component_and_rejects_device_scope(
            self, paths):
        auth, lkg = paths
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.set_qos(
                auth, lkg, None, "operator", 1.0, qos_state=None)
        with pytest.raises(peer_policy.PolicyError):
            peer_policy.set_qos(
                auth, lkg, None, "operator", 1.0, device_id="d1",
                qos_state={"seeder": {"numwant": 4}})

    def test_state_only_dry_run_changes_no_store_bytes(self, paths):
        auth, lkg = paths
        root = os.path.dirname(auth)
        before = _tree_bytes(root)
        candidate = peer_policy.set_qos(
            auth, lkg, None, "operator", 1.0,
            qos_state={"seeder": {"announce_min_interval_s": 120}},
            dry_run=True)

        assert candidate["roles"]["qos_state_default"] == {
            "seeder": {"announce_min_interval_s": 120}}
        assert _tree_bytes(root) == before


class TestTrackerStatePersistenceBoundaries:
    def test_state_bearing_authority_and_lkg_load_without_rewriting(
            self, tmp_path):
        valid = _boat_doc(
            qos_state_default={
                "seeder": {"announce_min_interval_s": 120},
                "leecher": {"numwant": 25}},
            qos_state={
                "seeder": {"numwant": 8},
                "leecher": {"announce_min_interval_s": 45}})
        valid["revision"] = 9
        invalid = copy.deepcopy(valid)
        invalid["roles"]["defs"]["boat"]["qos_state"]["leecher"] = []
        auth = tmp_path / "peer-policy.json"
        lkg = tmp_path / "peer-policy.lkg.json"

        auth_payload = (json.dumps(valid, indent=2) + "\n").encode()
        lkg_payload = json.dumps(peer_policy.base_document()).encode()
        auth.write_bytes(auth_payload)
        lkg.write_bytes(lkg_payload)
        result = peer_policy.load_policy(str(auth), str(lkg))
        assert result.document == valid
        assert result.degraded is False
        assert auth.read_bytes() == auth_payload
        assert lkg.read_bytes() == lkg_payload

        invalid_payload = json.dumps(invalid).encode()
        lkg_payload = (json.dumps(valid, indent=4) + "\n").encode()
        auth.write_bytes(invalid_payload)
        lkg.write_bytes(lkg_payload)
        result = peer_policy.load_policy(str(auth), str(lkg))
        assert result.document == valid
        assert result.degraded is True
        assert result.fail_closed is False
        assert auth.read_bytes() == invalid_payload
        assert lkg.read_bytes() == lkg_payload

        auth_payload = b"{ invalid authoritative"
        lkg_payload = invalid_payload
        auth.write_bytes(auth_payload)
        lkg.write_bytes(lkg_payload)
        result = peer_policy.load_policy(str(auth), str(lkg))
        assert result.degraded is True
        assert result.fail_closed is True
        assert auth.read_bytes() == auth_payload
        assert lkg.read_bytes() == lkg_payload

    def test_state_bearing_retained_revision_restores_as_one_new_commit(
            self, paths):
        auth, lkg = paths
        role_state = {"seeder": {"numwant": 8}}
        global_state = {"leecher": {"announce_min_interval_s": 45}}
        role_doc = peer_policy.define_role(
            auth, lkg, "boat", {
                "restricted": True, "qos_state": role_state},
            "operator", 1.0)
        state_doc = peer_policy.set_qos(
            auth, lkg, None, "operator", 2.0,
            qos_state=global_state,
            expected_revision=role_doc["revision"])
        current = peer_policy.set_qos(
            auth, lkg, {"numwant": 20}, "operator", 3.0,
            expected_revision=state_doc["revision"])

        restored = peer_policy.restore_lkg_revision(
            auth, lkg, state_doc["revision"], actor="operator", now=4.0,
            expected_revision=current["revision"])

        assert restored["revision"] == current["revision"] + 1
        assert restored["roles"]["qos_state_default"] == global_state
        assert restored["roles"]["defs"]["boat"]["qos_state"] == role_state
        assert len(restored["operation_outbox"]) == \
            len(current["operation_outbox"]) + 1
        assert restored["operation_outbox"][-1]["action"] == "restore"

    def test_malformed_state_retained_revision_is_not_restored(self, paths):
        auth, lkg = paths
        current = peer_policy.set_qos(
            auth, lkg, {"numwant": 20}, "operator", 1.0)
        retained_path = peer_policy.lkg_revision_path(lkg, 1)
        malformed = _boat_doc(qos_state={
            "seeder": {"announce_min_interval_s": "120"}})
        malformed["revision"] = 1
        with open(retained_path, "w") as stream:
            json.dump(malformed, stream)
        root = os.path.dirname(auth)
        before = _tree_bytes(root)

        with pytest.raises(peer_policy.PolicyError):
            peer_policy.restore_lkg_revision(
                auth, lkg, 1, actor="operator", now=2.0,
                expected_revision=current["revision"])

        assert _tree_bytes(root) == before

    def test_invalid_combined_scalar_state_dry_run_and_commit_write_nothing(
            self, paths):
        auth, lkg = paths
        current = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        root = os.path.dirname(auth)
        before = _tree_bytes(root)
        invalid_pairs = (
            ({"numwant": 3}, {"seeder": {"numwant": 8}}),
            ({"numwant": 20}, {"seeder": {"numwant": 3}}),
        )

        for scope in ("global", "role"):
            scoped = {"role": "boat"} if scope == "role" else {}
            for qos, qos_state in invalid_pairs:
                for dry_run in (True, False):
                    with pytest.raises(peer_policy.PolicyError):
                        peer_policy.set_qos(
                            auth, lkg, qos, "operator", 2.0,
                            qos_state=qos_state, dry_run=dry_run,
                            expected_revision=current["revision"], **scoped)
                    assert _tree_bytes(root) == before


class TestBlastRadius:
    @staticmethod
    def documents():
        prior = _doc(
            defs={
                "a": {"restricted": True, "peers": ["a", "b"],
                      "origin": True},
                "b": {"restricted": True, "peers": ["a", "b"],
                      "origin": True},
                "c": {"restricted": False},
            },
            role_of={"a1": "a", "a2": "a", "b1": "b", "c1": "c"})
        candidate = copy.deepcopy(prior)
        candidate["roles"]["role_of"]["a2"] = "b"
        candidate["roles"]["defs"]["a"].update(
            {"peers": ["a"], "origin": False})
        candidate["roles"]["defs"]["b"].update(
            {"peers": ["b"], "origin": False})
        return prior, candidate

    def test_four_counts_and_deterministic_confirm_token(self):
        prior, candidate = self.documents()
        prior_before = copy.deepcopy(prior)
        candidate_before = copy.deepcopy(candidate)
        preview = peer_policy.blast_radius(prior, candidate, threshold=0)
        assert preview.member_delta == 1
        assert preview.origin_access_lost == 3
        assert preview.empty_permitted_sets == 1
        assert preview.role_pairs_stopped == 1
        assert preview.qos_changed is False
        assert preview.requires_confirmation is True
        assert len(preview.confirm_token) == 64
        assert preview == peer_policy.blast_radius(prior, candidate, threshold=0)
        assert peer_policy.confirm_blast_radius(
            prior, candidate, threshold=0, token=preview.confirm_token)
        assert prior == prior_before
        assert candidate == candidate_before

    def test_threshold_boundary_is_strictly_above(self):
        prior, candidate = self.documents()
        at_boundary = peer_policy.blast_radius(prior, candidate, threshold=3)
        assert at_boundary.requires_confirmation is False
        assert at_boundary.confirm_token is None
        above = peer_policy.blast_radius(prior, candidate, threshold=2)
        assert above.requires_confirmation is True
        assert not peer_policy.confirm_blast_radius(
            prior, candidate, threshold=2, token="0" * 64)

    def test_shadowed_member_is_not_counted_as_losing_origin(self):
        prior, candidate = self.documents()
        prior["assignments"]["a1"] = "quarantine"
        candidate["assignments"]["a1"] = "quarantine"
        preview = peer_policy.blast_radius(prior, candidate, threshold=10)
        assert preview.origin_access_lost == 2
        assert preview.empty_permitted_sets == 0

    def test_roleless_device_cannot_assume_restricted_members_permit_it(self):
        prior = _doc(
            defs={"a": {"restricted": True, "peers": ["a"],
                        "origin": False}},
            role_of={"d1": "a", "d2": "a", "d3": "a"})
        prior["acls"]["no-origin"] = {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}},
        ]}
        prior["seeder_assignment"] = "no-origin"
        candidate = copy.deepcopy(prior)
        candidate["roles"]["role_of"].pop("d1")

        preview = peer_policy.blast_radius(prior, candidate, threshold=10)

        assert preview.empty_permitted_sets == 1

    def test_removing_a_shadow_assignment_counts_effective_access_loss(self):
        prior = _doc(
            defs={
                "a": {"restricted": True, "peers": ["a"],
                      "origin": False},
                "b": {"restricted": False},
            },
            role_of={"d1": "a", "d2": "b"})
        prior["acls"]["peer-only"] = {"rules": [
            {"seq": 10, "action": "deny",
             "match": {"type": "service", "value": "seeder"}},
            {"seq": 20, "action": "permit",
             "match": {"type": "device", "value": "d2"}},
            {"seq": 30, "action": "deny", "match": {"type": "any"}},
        ]}
        prior["assignments"]["d1"] = "peer-only"
        candidate = copy.deepcopy(prior)
        candidate["assignments"].pop("d1")

        preview = peer_policy.blast_radius(prior, candidate, threshold=0)

        assert preview[:4] == (0, 0, 1, 0)
        assert preview.qos_changed is False
        assert preview.requires_confirmation is True

    def test_role_creation_does_not_invent_a_prior_pair(self):
        before_create = _doc(defs={"open": {"restricted": False}})
        after_create = copy.deepcopy(before_create)
        after_create["roles"]["defs"]["closed"] = {
            "restricted": True, "peers": ["closed"], "origin": False}

        created = peer_policy.blast_radius(
            before_create, after_create, threshold=0)

        assert created.role_pairs_stopped == 0
        assert created.requires_confirmation is False

    def test_role_deletion_counts_prior_conceptual_edges(self):
        prior = _doc(defs={
            "open": {"restricted": False},
            "spare": {"restricted": False},
        })
        candidate = copy.deepcopy(prior)
        candidate["roles"]["defs"].pop("spare")

        preview = peer_policy.blast_radius(prior, candidate, threshold=0)

        assert preview.role_pairs_stopped == 2
        assert preview.requires_confirmation is True

    def test_restricting_a_role_stops_its_implicit_default_pair(self):
        prior = _doc(
            defs={"boat": {"restricted": False}},
            role_of={"boat-1": "boat"})
        candidate = copy.deepcopy(prior)
        candidate["roles"]["defs"]["boat"] = {
            "restricted": True, "peers": ["boat"], "origin": True}

        stopped = (peer_policy._mutual_role_edges(prior) -
                   peer_policy._mutual_role_edges(candidate))
        preview = peer_policy.blast_radius(prior, candidate, threshold=0)

        assert stopped == {("boat", "default")}
        assert preview[:4] == (0, 0, 0, 1)
        assert preview.requires_confirmation is True

    def test_permitted_set_work_is_grouped_for_a_ten_thousand_device_fleet(
            self, monkeypatch):
        role_of = {"d-%05d" % index: "a" for index in range(10_000)}
        prior = _doc(
            defs={"a": {"restricted": False}}, role_of=role_of)
        prior["acls"]["deny-all"] = {"rules": [
            {"seq": 10, "action": "deny", "match": {"type": "any"}},
        ]}
        device_ids = sorted(role_of)
        for acl_index in range(40):
            first = acl_index * 250
            prior["acls"]["named-%02d" % acl_index] = {"rules": [
                {"seq": offset + 1, "action": "deny",
                 "match": {"type": "device", "value": device_id}}
                for offset, device_id in enumerate(
                    device_ids[first:first + 250])
            ]}
        prior["assignments"] = {
            device_id: "deny-all" for device_id in role_of}
        candidate = copy.deepcopy(prior)
        real_mutual_permit = peer_policy.mutual_permit
        calls = {"count": 0}

        def counted_mutual_permit(*args, **kwargs):
            calls["count"] += 1
            return real_mutual_permit(*args, **kwargs)

        monkeypatch.setattr(
            peer_policy, "mutual_permit", counted_mutual_permit)

        preview = peer_policy.blast_radius(prior, candidate, threshold=0)

        assert preview.empty_permitted_sets == 0
        # All 10,000 ids occur in valid ACL device rules. Peer access still
        # uses ACL bitmasks; only the two linear, address-blind origin walks
        # call the scalar evaluator. Host/CIDR outcomes require endpoint input.
        assert calls["count"] == 20_000

    def test_origin_loss_uses_the_seeders_stored_acl_role_rules(self):
        prior = _doc(
            defs={"a": {"restricted": False},
                  "b": {"restricted": False}},
            role_of={"d1": "a"})
        prior["acls"]["origin-a"] = {"rules": [
            {"seq": 10, "action": "permit",
             "match": {"type": "role", "value": "a"}},
            {"seq": 20, "action": "deny", "match": {"type": "any"}},
        ]}
        prior["seeder_assignment"] = "origin-a"
        candidate = copy.deepcopy(prior)
        candidate["roles"]["role_of"]["d1"] = "b"
        preview = peer_policy.blast_radius(prior, candidate, threshold=10)
        assert preview.origin_access_lost == 1

    def test_qos_change_requires_confirmation_at_exported_threshold(self,
                                                                    paths):
        auth, lkg = paths
        prior = peer_policy.define_role(
            auth, lkg, "boat", {"restricted": True}, "operator", 1.0)
        candidate = peer_policy.set_qos(
            auth, lkg, {"max_peers": 4}, "operator", 2.0,
            expected_revision=prior["revision"], dry_run=True)
        assert peer_policy.load_policy(auth, lkg).document == prior
        assert peer_policy.lkg_ring_revisions(lkg) == [1]

        preview = peer_policy.blast_radius(
            prior, candidate,
            threshold=peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
        assert preview[:4] == (0, 0, 0, 0)
        assert preview.qos_changed is True
        assert preview.requires_confirmation is True

        checked = []

        def confirm_under_lock(live, real_candidate):
            checked.append((live, real_candidate))
            if not peer_policy.confirm_blast_radius(
                    live, real_candidate,
                    peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
                    preview.confirm_token):
                raise peer_policy.PolicyError("confirmation failed")

        committed = peer_policy.set_qos(
            auth, lkg, {"max_peers": 4}, "operator", 2.0,
            expected_revision=prior["revision"],
            precommit=confirm_under_lock)
        assert checked
        assert committed == peer_policy.load_policy(auth, lkg).document

        metadata_only = copy.deepcopy(candidate)
        metadata_only["revision"] += 99
        metadata_only["operation_outbox"] = []
        assert peer_policy.confirm_blast_radius(
            prior, metadata_only,
            peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
            preview.confirm_token)
        different_prior = copy.deepcopy(prior)
        different_prior["revision"] += 1
        assert not peer_policy.confirm_blast_radius(
            different_prior, metadata_only,
            peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
            preview.confirm_token)

        drifted = copy.deepcopy(candidate)
        drifted["roles"]["qos_default"]["max_peers"] = 5
        assert not peer_policy.confirm_blast_radius(
            prior, drifted, peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
            preview.confirm_token)

    def test_global_and_role_state_add_change_remove_have_bound_tokens(self):
        threshold = peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD
        for scope in ("global", "role"):
            absent = _scoped_state_doc(scope)
            explicit_empty = _scoped_state_doc(scope, {})
            initial = _scoped_state_doc(
                scope, {"seeder": {"numwant": 8}})
            changed = _scoped_state_doc(
                scope, {"seeder": {"numwant": 9}})
            transitions = (
                (absent, explicit_empty),
                (explicit_empty, absent),
                (absent, initial),
                (initial, changed),
                (initial, absent),
            )
            for prior, candidate in transitions:
                preview = peer_policy.blast_radius(
                    prior, candidate, threshold=threshold)
                assert preview[:4] == (0, 0, 0, 0)
                assert preview.qos_changed is True
                assert preview.requires_confirmation is True
                assert len(preview.confirm_token) == 64
                assert peer_policy.confirm_blast_radius(
                    prior, candidate, threshold, preview.confirm_token)

            add_token = peer_policy.blast_radius(
                absent, initial, threshold=threshold).confirm_token
            token_mismatches = (
                _scoped_state_doc(
                    scope, {"seeder": {"numwant": 10}}),
                _scoped_state_doc(
                    scope, {"seeder": {"announce_min_interval_s": 120}}),
                _scoped_state_doc(
                    scope, {"leecher": {"numwant": 8}}),
            )
            for mismatch in token_mismatches:
                assert not peer_policy.confirm_blast_radius(
                    absent, mismatch, threshold, add_token)

    def test_precommit_refusal_leaves_policy_and_ring_unchanged(self, paths):
        auth, lkg = paths
        before = peer_policy.load_policy(auth, lkg).document

        def reject(_prior, _candidate):
            raise peer_policy.PolicyError("confirmation failed")

        with pytest.raises(peer_policy.PolicyError, match="confirmation"):
            peer_policy.set_qos(
                auth, lkg, {"max_peers": 4}, "operator", 1.0,
                expected_revision=before["revision"], precommit=reject)

        assert peer_policy.load_policy(auth, lkg).document == before
        assert peer_policy.lkg_ring_revisions(lkg) == []


def test_qos_explanation_shares_derivation_and_source_precedence():
    doc = _boat_doc(qos={"fanout": 3}, device_qos={"seed_up_bps": 90000})
    doc["roles"]["qos_default"] = {"per_peer_bps": 20000}
    before = copy.deepcopy(doc)
    explanation = peer_policy.explain_qos(doc, "boat-1")
    assert {key: row["value"] for key, row in explanation.items()} == \
        peer_policy.compile_qos(doc, "boat-1")
    assert explanation["leech_down_bps"] == {
        "value": 60000, "source": "role:boat", "derived_from": {
            "per_peer_bps": {"value": 20000, "source": "global"},
            "fanout": {"value": 3, "source": "role:boat"}}}
    assert explanation["seed_up_bps"] == {
        "value": 90000, "source": "device:boat-1"}
    assert explanation["on_stale"] == {"value": "keep", "source": "role:boat"}
    assert doc == before
