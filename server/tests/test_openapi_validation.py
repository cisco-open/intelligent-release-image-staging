# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Standards validation of the generated API document, including streaming."""

import copy
import json
import socket
from pathlib import Path

import pytest
from jsonschema.exceptions import SchemaError, ValidationError
from openapi_schema_validator import OAS32Validator
from openapi_spec_validator import OpenAPIV32SpecValidator


SPEC = Path(__file__).resolve().parents[2] / "docs" / "zensical" / "openapi.yaml"


def _load():
    return json.loads(SPEC.read_text(encoding="utf-8"))


def _schemas(node):
    """Find Schema Objects without interpreting payload examples as schemas.

    Explicitly include request bodies and itemSchema: the document validator
    does not fully traverse these in its 0.9 release. Checking each Schema
    Object validates its nested properties/items/compositions as well.
    """
    if isinstance(node, dict):
        for name, value in node.items():
            if name in ("example", "examples") or name.startswith("x-"):
                continue
            if name in ("schema", "itemSchema"):
                yield value
            elif name == "schemas":
                yield from value.values()
            else:
                yield from _schemas(value)
    elif isinstance(node, list):
        for value in node:
            yield from _schemas(value)


def _check_schema_references(schema, document):
    if isinstance(schema, dict):
        for name, value in schema.items():
            if name in ("$ref", "$dynamicRef"):
                # IRIS ships a self-contained document. Resolve JSON Pointers
                # locally so a broken request/item reference also fails CI.
                assert value.startswith("#/"), value
                target = document
                for part in value[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]
            elif name not in ("example", "examples"):
                _check_schema_references(value, document)
    elif isinstance(schema, list):
        for value in schema:
            _check_schema_references(value, document)


def _validate_schemas(document):
    for schema in _schemas(document):
        OAS32Validator.check_schema(schema)
        _check_schema_references(schema, document)


def _media_examples(media):
    if "example" in media:
        return [media["example"]]
    return [entry["value"] for entry in media.get("examples", {}).values()
            if "value" in entry]


def _local_schema(schema, document):
    """Copy a schema while resolving this self-contained document's refs."""
    def resolve(node, active=()):
        if isinstance(node, dict):
            reference = node.get("$ref")
            if isinstance(reference, str) and reference.startswith("#/"):
                assert reference not in active, reference
                target = document
                for part in reference[2:].split("/"):
                    target = target[
                        part.replace("~1", "/").replace("~0", "~")]
                resolved = resolve(copy.deepcopy(target),
                                   active + (reference,))
                siblings = {key: copy.deepcopy(value)
                            for key, value in node.items() if key != "$ref"}
                if siblings:
                    return {"allOf": [resolved, resolve(siblings, active)]}
                return resolved
            return {key: resolve(value, active)
                    for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(value, active) for value in node]
        return node

    return resolve(schema)


def test_complete_document_and_all_schema_objects_validate_offline(monkeypatch):
    def deny_network(*args, **kwargs):
        raise AssertionError("OpenAPI validation must not use the network")

    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    document = _load()
    OpenAPIV32SpecValidator(document).validate()
    _validate_schemas(document)


@pytest.mark.parametrize("location", ["request", "response", "stream", "component"])
def test_schema_checks_reject_invalid_types_in_every_body_position(location):
    document = _load()
    if location == "request":
        schema = document["paths"]["/api/v1/login"]["post"][
            "requestBody"]["content"]["application/json"]["schema"]
    elif location == "response":
        schema = document["paths"]["/healthz"]["get"][
            "responses"]["200"]["content"]["application/json"]["schema"]
    elif location == "stream":
        schema = _stream_media(document)["itemSchema"]
    else:
        schema = next(iter(document["components"]["schemas"].values()))
    schema["type"] = "not-a-json-schema-type"
    with pytest.raises(SchemaError):
        _validate_schemas(document)


def test_schema_checks_reject_a_dangling_request_reference():
    document = _load()
    document["paths"]["/api/v1/login"]["post"]["requestBody"][
        "content"]["application/json"]["schema"] = {
            "$ref": "#/components/schemas/MissingRequest"}
    with pytest.raises(KeyError, match="MissingRequest"):
        _validate_schemas(document)


def _stream_media(document, prefix="/api/v1"):
    return document["paths"][prefix + "/onboard/jobs/{job_id}/stream"][
        "get"]["responses"]["200"]["content"]["text/event-stream"]


@pytest.mark.parametrize("prefix", ["/api/v1", "/internal/v1"])
def test_sse_contract_validates_each_parsed_event(prefix):
    media = _stream_media(_load(), prefix)
    assert "schema" not in media  # Streams are not complete string documents.
    validator = OAS32Validator(media["itemSchema"])
    validator.validate({"data": "onboard complete: 192.0.2.10"})
    validator.validate({"event": "message", "data": "waiting for device"})
    for state in ("done", "error", "cancelled", "idle", "unknown"):
        validator.validate({"event": "end", "data": state})
    for invalid in ({"event": "end", "data": "running"},
                    {"event": "end"}, {"data": {"state": "done"}},
                    {"event": "unrecognized", "data": "done"}):
        with pytest.raises(ValidationError):
            validator.validate(invalid)
    assert "serializedValue" in media["examples"]["completed"]


def test_binary_payloads_do_not_claim_json_string_encoding():
    document = _load()
    raw_media = {"application/octet-stream", "application/x-bittorrent"}
    for item in document["paths"].values():
        for operation in item.values():
            if not isinstance(operation, dict) or "responses" not in operation:
                continue
            bodies = [operation.get("requestBody", {})]
            bodies.extend(operation["responses"].values())
            for body in bodies:
                for content_type, media in body.get("content", {}).items():
                    if content_type in raw_media or (
                            operation.get("x-iris-service") == "tracker"
                            and content_type == "text/plain"):
                        schema = media["schema"]
                        assert "type" not in schema
                        assert "format" not in schema
                        assert "contentEncoding" not in schema
                    elif content_type in ("text/csv", "application/x-pem-file"):
                        assert media["schema"]["type"] == "string"
                        assert "format" not in media["schema"]


def test_instruction_operations_validate_offline_with_local_examples():
    document = _load()
    paths = (
        "/v1/devices/{device_id}/instructions",
        "/v1/devices/{device_id}/instruction-keylist",
    )
    for path in paths:
        operation = document["paths"][path]["get"]
        _check_schema_references(operation, document)
        for response in operation["responses"].values():
            for content_type, media in response.get("content", {}).items():
                schema = media["schema"]
                if content_type == "application/octet-stream":
                    assert all(key not in schema for key in
                               ("type", "format", "contentEncoding"))
                    continue
                validator = OAS32Validator(_local_schema(schema, document))
                for example in _media_examples(media):
                    validator.validate(example)
                    if content_type == "application/problem+json":
                        for missing in ("type", "title", "status", "code"):
                            invalid = dict(example)
                            del invalid[missing]
                            assert list(validator.iter_errors(invalid)), (
                                path, response, missing)
                        invalid = dict(example, detail="must stay closed")
                        assert list(validator.iter_errors(invalid)), path
                        invalid = dict(example, status=example["status"] + 1)
                        assert list(validator.iter_errors(invalid)), path
                        invalid = dict(example, code="wrong-problem-code")
                        assert list(validator.iter_errors(invalid)), path
                        invalid = dict(example, title="Wrong problem title")
                        assert list(validator.iter_errors(invalid)), path
        assert "content" not in operation["responses"]["304"]

    for path, method, body_name in (
            ("/v1/devices/{device_id}/policy", "get", "responses"),
            ("/v1/devices/{device_id}/heartbeat", "post", "responses")):
        media = document["paths"][path][method][body_name]["200"][
            "content"]["application/json"]
        _check_schema_references(media["schema"], document)
        validator = OAS32Validator(media["schema"])
        for example in _media_examples(media):
            validator.validate(example)

    heartbeat_request = document["paths"][
        "/v1/devices/{device_id}/heartbeat"]["post"]["requestBody"][
            "content"]["application/json"]
    _check_schema_references(heartbeat_request["schema"], document)
    validator = OAS32Validator(heartbeat_request["schema"])
    for example in _media_examples(heartbeat_request):
        validator.validate(example)


def test_instruction_attestation_dependencies_and_bounds_reject_invalid_input():
    document = _load()
    schema = document["paths"]["/v1/devices/{device_id}/heartbeat"]["post"][
        "requestBody"]["content"]["application/json"]["schema"]
    validator = OAS32Validator(schema)
    applied = {
        "bt_max_peers": 4,
        "max_upload_limit": 8192,
        "max_download_limit": 16384,
        "overall_up": 32768,
        "overall_down": 65536,
        "request_peer_speed_limit": 4096,
        "max_concurrent": 3,
    }
    valid = (
        {"applied": applied},
        {"instr_state": "key_rejected", "instr_reason": "unknown_key"},
        {"blocklist_rules": 2, "blocklist_revision": 7},
        {"qos_drift": {"options": [{
            "option": "overall_up", "expected": 32768,
            "observed": 16384}]}},
        {"qos_drift": {"options": [], "blocklist_revision": {
            "expected": 7, "observed": 6}}},
    )
    for body in valid:
        validator.validate(body)

    row = {"option": "bt_max_peers", "expected": 4, "observed": 3}
    invalid = (
        {"applied": dict(applied, overall_up=True)},
        {"applied": {key: value for key, value in applied.items()
                     if key != "max_concurrent"}},
        {"applied": dict(applied, gid="opaque")},
        {"instr_state": "key_rejected"},
        {"instr_state": "applied", "instr_reason": "bad_mac"},
        {"instr_reason": "unknown_key"},
        {"instr_state": "invented"},
        {"blocklist_rules": 2},
        {"blocklist_revision": 7},
        {"qos_drift": {"options": []}},
        {"qos_drift": {"options": [row] * 48}},
        {"qos_drift": {"options": [dict(row, gid="opaque")]}},
        {"qos_drift": {"options": [dict(row, option="unknown")]}},
    )
    for body in invalid:
        assert list(validator.iter_errors(body)), body


def test_role_qos_response_schemas_accept_empty_maps_null_acl_and_explicit_rates():
    document = _load()
    def response(suffix):
        return document["paths"]["/api/v1" + suffix]["get"]["responses"]["200"]["content"]["application/json"]
    media = response("/peer-policy/explain")
    example = json.loads(json.dumps(media["example"]))
    for side in ("a", "b"):
        example[side].update(role=None, acl_name=None, acl_source="none", matched_seq=None)
    OAS32Validator(media["schema"]).validate(example)
    media = response("/peer-policy/roles")
    example = dict(media["example"], roles={})
    OAS32Validator(media["schema"]).validate(example)
    media = response("/devices/{device_id}/effective-qos")
    example = json.loads(json.dumps(media["example"]))
    for value in example["qos"].values():
        value.pop("derived_from", None)
    OAS32Validator(media["schema"]).validate(example)


def test_final_repair_shared_prefix_digit_bound():
    import peer_policy
    import openapi_contract
    import sys
    schema = openapi_contract._role_definition_schema()["properties"]["nets"]["items"]
    bound = peer_policy.ROLE_NET_MAX_PREFIX_DIGITS
    original = sys.get_int_max_str_digits()
    try:
        for interpreter_limit in (0, 640):
            sys.set_int_max_str_digits(interpreter_limit)
            for suffix in ("00", "032", "00024", "0" * bound,
                           "255.255.255.0", "0.0.0.255"):
                value = "192.0.2.17/" + suffix
                assert peer_policy.validate_role_net(value)
                OAS32Validator(schema).validate(value)
            for suffix in ("0" * (bound + 1), "0" * 4301, "33"):
                value = "192.0.2.17/" + suffix
                with pytest.raises(peer_policy.PolicyError):
                    peer_policy.validate_role_net(value)
                assert list(OAS32Validator(schema).iter_errors(value))
    finally:
        sys.set_int_max_str_digits(original)


def test_policy_preflight_schema_distinguishes_unknown_and_zero_without_ids():
    import openapi_contract
    spec = openapi_contract.build_document()
    for prefix in ("/api/v1", "/internal/v1"):
        response = spec["paths"][prefix + "/peer-policy"]["get"]["responses"]["200"]
        schema = response["content"]["application/json"]["schema"]["properties"][
            "enforcement"]["properties"]["mutual_origin"]
        validator = OAS32Validator(schema)
        for count in (None, 0, 2):
            validator.validate({"mode": "preflight", "newly_denied_device_count": count})
        for bad in (
                {"mode": "preflight"},
                {"mode": "enforced", "newly_denied_device_count": 0},
                {"mode": "preflight", "newly_denied_device_count": 0,
                 "newly_denied_device_ids": []},
                *[{"mode": "preflight", "newly_denied_device_count": value}
                  for value in (-1, 1.5, False, "0")]):
            assert list(validator.iter_errors(bad)), bad


def test_policy_contract_qos_subsets_ranges_and_complete_role_definition():
    import openapi_contract
    spec = openapi_contract.build_document()
    qos = spec["paths"]["/api/v1/peer-policy/qos"]["put"]["requestBody"]["content"]["application/json"]["schema"]
    for body in ({"qos": {}}, {"qos": {"max_peers": 4}}, {"qos": {"telemetry_pause": True}}):
        OAS32Validator(qos).validate(body)
    for body in ({}, {"qos": {"typo": 5}}, {"qos": {"max_peers": 0}},
                 {"qos": {"telemetry_pause": 1}}, {"qos": {"seed_up_bps": 1}}):
        assert list(OAS32Validator(qos).iter_errors(body)), body
    schema = spec["paths"]["/api/v1/peer-policy/roles"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    definition = {"restricted": True, "peers": ["boat"], "origin": True,
                  "nets": ["192.0.2.0/24"], "on_stale": "keep", "qos": {"max_peers": 4}}
    valid = {"revision": 2, "degraded": False, "fail_closed": False, "roles": {"boat": definition}}
    OAS32Validator(schema).validate(valid)
    peers = schema["properties"]["roles"]["additionalProperties"]["properties"]["peers"]
    assert peers["uniqueItems"] is True
    assert peers["x-iris-selfPeerRequired"] is True
    assert "{name}" in peers["description"]
    for net in ("192.0.2.1", "192.0.2.1/0", "192.0.2.1/32", "192.0.2.1/255.255.255.0", "192.0.2.1/0.0.0.255"):
        OAS32Validator(schema).validate(dict(valid, roles={"boat": dict(definition, nets=[net])}))
    for bad in (dict(definition, peers=["boat", "boat"]), *[
            dict(definition, nets=[net]) for net in ("not-a-network", "256.1.2.3", "192.00.2.1", "192.0.2.1/33", "192.0.2.1/255.0.255.0")]):
        assert list(OAS32Validator(schema).iter_errors(dict(valid, roles={"boat": bad})))
    for bad in ({"bogus": True}, dict(definition, on_stale="whatever"),
                dict(definition, restricted="true"), dict(definition, qos={"origin_up_bps": 8192})):
        assert list(OAS32Validator(schema).iter_errors(dict(valid, roles={"boat": bad})))


def test_tracker_state_schemas_validate_mutations_presence_pairs_and_published_examples():
    import re
    document = _load()
    state_examples = []
    source_pattern = re.compile(
        r"^(?:builtin|global|global-state:(?:seeder|leecher)|"
        r"role:[a-z0-9][a-z0-9._-]{0,31}|"
        r"role-state:[a-z0-9][a-z0-9._-]{0,31}:(?:seeder|leecher))$")
    for prefix in ("/api/v1", "/internal/v1"):
        paths = document["paths"]
        put_media = paths[prefix + "/peer-policy/qos"]["put"]["requestBody"]["content"]["application/json"]
        role_media = paths[prefix + "/peer-policy/roles/{name}"]["put"]["requestBody"]["content"]["application/json"]
        roles_media = paths[prefix + "/peer-policy/roles"]["get"]["responses"]["200"]["content"]["application/json"]
        effective_media = paths[prefix + "/devices/{device_id}/effective-qos"]["get"]["responses"]["200"]["content"]["application/json"]
        put = OAS32Validator(_local_schema(put_media["schema"], document))
        role = OAS32Validator(_local_schema(role_media["schema"], document))
        roles = OAS32Validator(_local_schema(roles_media["schema"], document))
        effective = OAS32Validator(_local_schema(effective_media["schema"], document))

        def stored(state):
            return {"revision": 4, "degraded": False, "fail_closed": False,
                    "qos_state_default": state,
                    "roles": {"boat": {"restricted": False, "qos_state": state}}}

        valid_maps = ({}, {"seeder": {}}, {"leecher": {}}, {
            "seeder": {"announce_min_interval_s": 10, "numwant": 4},
            "leecher": {"announce_min_interval_s": 300, "numwant": 200}}, {
            "seeder": {"announce_min_interval_s": 300, "numwant": 200},
            "leecher": {"announce_min_interval_s": 10, "numwant": 4}})
        for state in valid_maps:
            for scope in ({}, {"role": None}, {"role": "boat"}):
                put.validate(dict(scope, qos_state=state))
                put.validate(dict(scope, qos={}, qos_state=state))
            role.validate({"restricted": False, "qos_state": state})
            roles.validate(stored(state))
        put.validate({"qos": {}})
        for body in ({}, {"role": "boat"}, {"confirm_token": "token"},
                     {"qos": None}, {"qos": None, "qos_state": {}},
                     {"qos": {}, "qos_state": None}, {"qos_state": {}, "device_id": "d1"}):
            assert list(put.iter_errors(body)), body
        invalid_maps = [None, [], False, "seeder", 4, {"unknown": {}}]
        for state in ("seeder", "leecher"):
            invalid_maps.extend([{state: value} for value in (None, [], False, "bad", 4)])
            invalid_maps.append({state: {"max_peers": 10}})
            for key, low, high in (("announce_min_interval_s", 10, 300), ("numwant", 4, 200)):
                for value in (low - 1, high + 1, True, low + 0.5, str(low), None):
                    invalid_maps.append({state: {key: value}})
        for state in invalid_maps:
            assert list(put.iter_errors({"qos_state": state})), state
            assert list(role.iter_errors({"restricted": False, "qos_state": state})), state
            # Exercise each stored location independently; one invalid sibling
            # must not conceal an accidentally permissive other container.
            global_only = stored({})
            global_only["qos_state_default"] = state
            assert list(roles.iter_errors(global_only)), state
            role_only = stored({})
            role_only["roles"]["boat"]["qos_state"] = state
            assert list(roles.iter_errors(role_only)), state

        legacy = copy.deepcopy(_media_examples(effective_media)[0])
        legacy.pop("tracker_state", None)
        legacy.pop("tracker_qos", None)
        effective.validate(legacy)
        seeder = dict(legacy, tracker_state="seeder", tracker_qos={
            "announce_min_interval_s": {"value": 120, "source": "role-state:boat:seeder"},
            "numwant": {"value": 4, "source": "global-state:seeder",
                        "effective_ceiling": 4, "runtime_request_zero": "disabled",
                        "constraint_source": "pinned-aria2-client"}})
        leecher = dict(legacy, tracker_state="leecher", tracker_qos={
            "announce_min_interval_s": {"value": 45, "source": "role-state:boat:leecher",
                                       "peerless_leecher_floor_s": 120,
                                       "constraint_source": "pinned-aria2-client"},
            "numwant": {"value": 150, "source": "global-state:leecher",
                        "effective_ceiling": 50, "runtime_request_zero": "disabled",
                        "constraint_source": "pinned-aria2-client"}})
        effective.validate(seeder)
        effective.validate(leecher)
        for body in (dict(legacy, tracker_state="seeder"),
                     dict(legacy, tracker_qos=seeder["tracker_qos"]),
                     dict(seeder, tracker_state="unknown"),
                     dict(seeder, tracker_qos={}),
                     dict(seeder, tracker_qos=dict(seeder["tracker_qos"], unexpected={})),
                     dict(seeder, tracker_qos={"numwant": seeder["tracker_qos"]["numwant"]})):
            assert list(effective.iter_errors(body)), body

        for media, validator in ((put_media, put), (role_media, role),
                                 (roles_media, roles), (effective_media, effective)):
            for example in _media_examples(media):
                validator.validate(example)
                if "tracker_state" in example:
                    state_examples.append(example)
        mutation_examples = _media_examples(put_media) + _media_examples(role_media)
        assert any("qos_state" in example for example in mutation_examples)
        operation = paths[prefix + "/peer-policy/qos"]["put"]

        def schema_descriptions(schema):
            descriptions = [schema.get("description", "")]
            for part in schema.get("allOf", []):
                descriptions.extend(schema_descriptions(part))
            return descriptions

        descriptions = [operation.get("description", ""),
                        operation["requestBody"].get("description", "")]
        descriptions += schema_descriptions(_local_schema(put_media["schema"], document))
        text = " ".join(" ".join(descriptions).lower().replace("`", "").split())
        assert "global qos_state is stored at roles.qos_state_default" in text
        assert "role qos_state is stored at roles.defs.<role>.qos_state" in text
        published = [example for example in _media_examples(effective_media)
                     if "tracker_state" in example]
        assert any(
            example["tracker_qos"]["announce_min_interval_s"]["source"] ==
            "role-state:boat:" + example["tracker_state"] and
            example["tracker_qos"]["numwant"]["source"] ==
            "global-state:" + example["tracker_state"]
            for example in published), "publish the role-state/global-state explanation"
    assert state_examples, "publish a queried effective-QoS example"
    for example in state_examples:
        state = example["tracker_state"]
        assert state in ("seeder", "leecher")
        rows = example["tracker_qos"]
        for row in rows.values():
            assert source_pattern.fullmatch(row["source"])
            if "-state:" in row["source"]:
                assert row["source"].endswith(":" + state)
        interval, numwant = rows["announce_min_interval_s"], rows["numwant"]
        assert numwant["effective_ceiling"] == min(numwant["value"], 50)
        assert numwant["runtime_request_zero"] == "disabled"
        assert numwant["constraint_source"] == "pinned-aria2-client"
        assert set(numwant) == {"value", "source", "effective_ceiling",
                                "runtime_request_zero", "constraint_source"}
        if state == "leecher":
            assert interval["peerless_leecher_floor_s"] == 120
            assert interval["constraint_source"] == "pinned-aria2-client"
            assert set(interval) == {"value", "source", "peerless_leecher_floor_s",
                                     "constraint_source"}
        else:
            assert set(interval) == {"value", "source"}


def test_onboard_and_undeploy_log_opt_in_is_an_optional_boolean():
    document = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        for action in ("onboard", "undeploy"):
            media = document["paths"][prefix + "/devices/{device_id}/" + action][
                "post"]["requestBody"]["content"]["application/json"]
            schema = _local_schema(media["schema"], document)
            assert schema["properties"]["log"]["default"] is False
            validator = OAS32Validator(schema)
            for body in ({}, {"log": False}, {"log": True}):
                validator.validate(body)
            for invalid in (None, 0, 1, "on", "false", [], {}):
                with pytest.raises(ValidationError):
                    validator.validate({"log": invalid})


def test_schedule_closed_schemas_cover_stage_only_defaults_and_patch_replacement():
    document = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        paths = document["paths"]
        def validator(suffix, method):
            media = paths[prefix + suffix][method]["requestBody"]["content"]["application/json"]
            return OAS32Validator(_local_schema(media["schema"], document))
        create = validator("/schedules", "post")
        put = validator("/schedules/{id}", "put")
        patch = validator("/schedules/{id}", "patch")
        reaffirm = validator("/schedules/{id}/reaffirm", "post")
        definition = {"kind": "assign", "target": {}, "payload": {"image_ids": ["image-a"]},
                      "when": {"kind": "once", "at": 1788883200, "window_seconds": 3600}}
        create.validate(dict(definition, id="s-boat"))
        put.validate(definition)
        onboard = dict(definition, kind="onboard", payload={"max_devices": 20000}, when={
            "kind": "recurring", "weekday": 6, "hour": 2, "minute": 30,
            "tz": "Australia/Lord_Howe", "window_seconds": 604800})
        put.validate(onboard)
        after = {"schedule_id": "s-earlier", "condition": "min_staged_ratio",
                 "min_staged_ratio": 0.95, "max_errored_ratio": 0, "max_missing_ratio": 0.05,
                 "deadline_seconds": 604800}
        put.validate(dict(definition, after=after))
        patch.validate({"after": after})
        for value in ({}, {"state": "paused"}, {"after": None},
                      {"payload": {"max_devices": 1}}, {"target": {}}):
            patch.validate(value)
        reaffirm.validate({})
        for key in ("id", "generation", "rev", "created_by", "created_at",
                    "preview", "etag", "creator_exists", "next_fire"):
            assert list(put.iter_errors(dict(definition, **{key: "forged"}))), key
            assert list(patch.iter_errors({key: "forged"})), key
        for bad in (dict(definition, kind="install"), dict(definition, kind="activate"),
                    dict(definition, kind="reload"), dict(definition, payload={"image_ids": []}),
                    dict(definition, payload={"image_ids": ["image-a"], "reload": True}),
                    dict(definition, payload={"max_devices": 1}),
                    dict(onboard, payload={"max_devices": 0}),
                    dict(onboard, payload={"max_devices": 1, "mode": "replace"}),
                    dict(definition, target={"filters": {"unknown": "value"}}),
                    dict(definition, target={"device_ids": ["seeder"]}),
                    dict(definition, target={"device_ids": ["edge-1", "edge-1"]}),
                    dict(definition, when=dict(definition["when"], weekday=0)),
                    dict(onboard, when=dict(onboard["when"], weekday=7)),
                    dict(definition, after=None),
                    dict(definition, after=dict(after, min_staged_ratio=1.01)),
                    dict(definition, after=dict(after, reload=True))):
            assert list(put.iter_errors(bad)), bad
        for bad in ({"payload": {"mode": "replace"}}, {"when": {"minute": 5}},
                    {"after": {"schedule_id": "s-other"}}, {"target": {"bind": "unknown"}}):
            assert list(patch.iter_errors(bad)), bad
        assert list(reaffirm.iter_errors({"created_by": "console:forged"}))
        for path, methods in paths.items():
            if not path.startswith(prefix + "/schedules"):
                continue
            for operation in methods.values():
                for body in [operation.get("requestBody", {})] + list(operation["responses"].values()):
                    for media in body.get("content", {}).values():
                        schema = OAS32Validator(_local_schema(media["schema"], document))
                        for example in _media_examples(media):
                            schema.validate(example)


def test_schedule_response_views_history_and_receipts_are_closed_and_bounded():
    document = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        paths = document["paths"]
        media = paths[prefix + "/schedules/{id}"]["get"]["responses"]["200"]["content"]["application/json"]
        schema = OAS32Validator(_local_schema(media["schema"], document))
        example = copy.deepcopy(_media_examples(media)[0])
        schema.validate(example)
        for field in ("etag", "creator_exists", "next_fire", "generation",
                      "rev", "preview"):
            broken = copy.deepcopy(example)
            broken["schedule"].pop(field)
            assert list(schema.iter_errors(broken)), field
        broken = copy.deepcopy(example)
        broken["schedule"]["extra"] = True
        assert list(schema.iter_errors(broken))
        receipts = paths[prefix + "/schedules/{id}/receipts"]["get"]
        page_media = receipts["responses"]["200"]["content"]["application/json"]
        page_schema = OAS32Validator(_local_schema(page_media["schema"], document))
        page = copy.deepcopy(_media_examples(page_media)[0])
        page_schema.validate(page)
        for field in ("schedule_id", "occurrence_id", "scheduled_at", "window_end",
                      "occurrence_state", "schedule_rev", "attempt", "predecessors"):
            broken = copy.deepcopy(page)
            broken["receipts"][0].pop(field)
            assert list(page_schema.iter_errors(broken)), field
        broken = copy.deepcopy(page)
        broken["receipts"][0]["status"] = "installed"
        assert list(page_schema.iter_errors(broken))
        broken = copy.deepcopy(page)
        broken["receipts"] *= 1001
        assert list(page_schema.iter_errors(broken))
        params = {p["name"]: p for p in receipts["parameters"]}
        assert params["limit"]["schema"]["maximum"] == 1000
        assert params["limit"]["schema"]["default"] == 1000
        assert params["offset"]["schema"]["minimum"] == 0
        occurrences = paths[prefix + "/schedules/{id}/occurrences"]["get"]
        occurrence_media = occurrences["responses"]["200"]["content"][
            "application/json"]
        occurrence_schema = OAS32Validator(_local_schema(
            occurrence_media["schema"], document))
        occurrence_page = copy.deepcopy(_media_examples(occurrence_media)[0])
        occurrence_schema.validate(occurrence_page)
        bound_page = copy.deepcopy(occurrence_page)
        bound_snapshot = bound_page["occurrences"][0]["target_snapshot"]
        bound_snapshot["registration_ids"] = {
            device_id: "a" * 32 for device_id in bound_snapshot["device_ids"]}
        occurrence_schema.validate(bound_page)
        absent_page = copy.deepcopy(bound_page)
        absent_bindings = absent_page["occurrences"][0]["target_snapshot"]["registration_ids"]
        absent_bindings[next(iter(absent_bindings))] = None
        occurrence_schema.validate(absent_page)
        for invalid_registration in ("", "a" * 31, "g" * 32, "a" * 32 + "\n"):
            broken = copy.deepcopy(bound_page)
            bindings = broken["occurrences"][0]["target_snapshot"]["registration_ids"]
            bindings[next(iter(bindings))] = invalid_registration
            assert list(occurrence_schema.iter_errors(broken))
        occurrence = occurrence_page["occurrences"][0]
        for field in ("schedule", "slot", "preview", "schedule_generation",
                      "schedule_rev", "state", "created_at", "updated_at"):
            broken = copy.deepcopy(occurrence_page)
            broken["occurrences"][0].pop(field)
            assert list(occurrence_schema.iter_errors(broken)), field
        broken = copy.deepcopy(occurrence_page)
        broken["occurrences"][0]["unexpected"] = True
        assert list(occurrence_schema.iter_errors(broken))
        missed = copy.deepcopy(occurrence_page)
        missed["occurrences"][0]["state"] = "missed"
        missed["occurrences"][0]["slot"]["status"] = "missed"
        missed["occurrences"][0].pop("target_snapshot")
        missed["occurrences"][0].pop("delta")
        occurrence_schema.validate(missed)
        occurrence_params = {p["name"]: p for p in occurrences["parameters"]}
        assert occurrence_params["limit"]["schema"]["maximum"] == 100
        assert occurrence_params["limit"]["schema"]["default"] == 100
        assert occurrence_params["offset"]["schema"]["minimum"] == 0
        for method, nullable in (("post", False), ("put", False), ("patch", True)):
            suffix = "/schedules" if method == "post" else "/schedules/{id}"
            status = "201" if method == "post" else "200"
            media = paths[prefix + suffix][method]["responses"][status]["content"]["application/json"]
            schema = OAS32Validator(_local_schema(media["schema"], document))
            example = copy.deepcopy(_media_examples(media)[0])
            assert set(example) == {"schedule", "target_facts"}
            assert list(schema.iter_errors({"schedule": example["schedule"]}))
            null_facts = dict(example, target_facts=None)
            assert bool(list(schema.iter_errors(null_facts))) is not nullable


def test_schedule_examples_match_store_rows_and_if_match_rejects_invalid_tags():
    import schedules
    document = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        paths = document["paths"]
        for method, suffix in (("put", "/schedules/{id}"), ("patch", "/schedules/{id}"),
                               ("delete", "/schedules/{id}"), ("post", "/schedules/{id}/reaffirm")):
            parameter = next(p for p in paths[prefix + suffix][method]["parameters"]
                             if p["name"] == "If-Match")
            validator = OAS32Validator(parameter["schema"])
            for value in ('"iris-schedule-s-boat-1"', '*',
                          '"iris-schedule-s-boat-9223372036854775807"'):
                validator.validate(value)
            for value in ('W/"iris-schedule-s-boat-1"', '"iris-schedule-s-boat-1", "other"',
                          '*, "iris-schedule-s-boat-1"', '"iris-schedule-s-boat-0"',
                          '"iris-schedule-s-boat-01"', '"iris-schedule-s-boat-9223372036854775808"',
                          '"iris-schedule-s-boat-1"\n', ''):
                assert list(validator.iter_errors(value)), value
        for suffix, methods in paths.items():
            if not suffix.startswith(prefix + "/schedules"):
                continue
            for operation in methods.values():
                for response in operation["responses"].values():
                    media = response.get("content", {}).get("application/json", {})
                    for example in _media_examples(media):
                        rows = [example["schedule"]] if "schedule" in example else example.get("schedules", [])
                        for view in rows:
                            stored = {key: value for key, value in view.items()
                                      if key not in ("etag", "creator_exists",
                                                     "next_fire")}
                            schedules.validate_schedule(stored["id"], stored)
                            assert schedules.schedule_etag(stored) == view["etag"]
                        for receipt in example.get("receipts", []):
                            stored = {key: value for key, value in receipt.items() if key not in (
                                "schedule_id", "scheduled_at", "window_end", "occurrence_state", "schedule_rev")}
                            schedules._validate_receipt(stored["device_id"], stored)
                        for occurrence in example.get("occurrences", []):
                            schedules._validate_occurrence(
                                occurrence["id"], occurrence)
