# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Role CSV preserves tracker timing overrides and validates imported units."""
import pytest

import peer_policy
import role_csv


def test_role_csv_round_trip_keeps_all_tracker_state_fields():
    definition = {"restricted": True, "peers": ["boat"], "origin": False,
                  "qos": {"numwant": 20}, "qos_state": {
                      "seeder": {"numwant": 8, "announce_min_interval_s": 60},
                      "leecher": {"numwant": 12, "announce_min_interval_s": 30}}}
    text = role_csv.export_roles_csv({"roles": {"defs": {"boat": definition}}})
    assert role_csv.parse_roles_csv(text) == {"boat": definition}
    assert "seeder_numwant" in text and "leecher_announce_min_interval_s" in text


@pytest.mark.parametrize("field,value", [
    ("seeder_numwant", "3"), ("leecher_numwant", "201"),
    ("seeder_announce_min_interval_s", "9"),
    ("leecher_announce_min_interval_s", "301"),
    ("seeder_numwant", "true"), ("leecher_numwant", "4.0"),
])
def test_role_csv_invalid_tracker_state_values_are_rejected(field, value):
    with pytest.raises((role_csv.RolesCsvError, peer_policy.PolicyError)):
        role_csv.parse_roles_csv(f"role,{field}\nboat,{value}\n")


def test_role_csv_omitted_and_blank_state_fields_inherit():
    assert "qos_state" not in role_csv.parse_roles_csv("role\nboat\n")["boat"]
    assert "qos_state" not in role_csv.parse_roles_csv(
        "role,seeder_numwant,leecher_numwant\nboat,,\n")["boat"]
