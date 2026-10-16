# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Count-only approval, exact preconditions and separate application proof."""

import copy

import pytest
from openapi_schema_validator import OAS32Validator

import openapi_contract
import origin_enforcement


@pytest.fixture(params=("/api/v1", "/internal/v1"))
def operations(request):
    return openapi_contract.build_document()["paths"][
        request.param + "/peer-policy/origin-enforcement"]


def test_control_request_is_closed_bounded_and_requires_exact_commit_token(operations):
    operation = operations["put"]
    headers = {row["name"]: row for row in operation["parameters"] if row["in"] == "header"}
    assert headers["If-Match"]["required"] is True
    assert headers["If-Match"]["example"] == '"origin-enforcement-0"'
    media = operation["requestBody"]["content"]["application/json"]
    schema, example = media["schema"], media["example"]
    validator = OAS32Validator(schema)
    validator.validate(example)
    committed = dict(example, dry_run=False, confirm_token="a" * 64)
    validator.validate(committed)
    validator.validate(dict(example, if_policy_revision=0))
    for patch in ({"max_new_ips": -1}, {"max_new_devices": 1001},
                  {"max_new_ips": True}, {"mode": "auto"}, {"dry_run": False},
                  {"confirm_token": None}, {"confirm_token": "unbound"},
                  {"if_policy_revision": -1}, {"if_policy_revision": "7"},
                  {"addresses": ["192.0.2.1"]}):
        assert list(validator.iter_errors(dict(example, **patch))), patch
    for field in ("mode", "max_new_ips", "max_new_devices", "if_policy_revision", "dry_run"):
        absent = copy.deepcopy(example)
        absent.pop(field)
        assert list(validator.iter_errors(absent)), field
    assert {"409", "412", "422", "428", "503"} <= set(operation["responses"])


def test_control_get_separates_requested_mode_from_actual_application(operations):
    media = operations["get"]["responses"]["200"]["content"]["application/json"]
    schema, example = media["schema"], media["example"]
    validator = OAS32Validator(schema)
    validator.validate(example)
    assert set(schema["properties"]["state"]["enum"]) == origin_enforcement.STATES
    assert set(schema["properties"]["reason"]["enum"]) == origin_enforcement.REASONS | {None}
    applied = dict(example, mode="enforce", state="enforced", applied_ip_count=2,
                   applied_device_count=3, last_verified_at=1791532800)
    validator.validate(applied)
    for patch in ({"mode": "preflight"}, {"applied_ip_count": None},
                  {"applied_device_count": None}, {"last_verified_at": None},
                  {"last_verified_at": 0}, {"reason": "session_changed"},
                  {"blockers": ["shared_address"]}):
        assert list(validator.iter_errors(dict(applied, **patch))), patch
    for patch in ({"addresses": []}, {"bindings": []}, {"session_id": "private"},
                  {"new_ip_count": -1}, {"reason": "invented"},
                  {"state": "healthy"}):
        assert list(validator.iter_errors(dict(example, **patch))), patch


def test_control_put_accepted_is_pending_not_applied(operations):
    media = operations["put"]["responses"]["200"]["content"]["application/json"]
    validator = OAS32Validator(media["schema"])
    for row in media["examples"].values():
        validator.validate(row["value"])
    accepted = media["examples"]["accepted"]["value"]
    for patch in ({"state": "enforced"}, {"applied_ip_count": 2},
                  {"last_verified_at": 1791532800}, {"confirm_token": "a" * 64},
                  {"requires_confirmation": True}):
        assert list(validator.iter_errors(dict(accepted, **patch))), patch
