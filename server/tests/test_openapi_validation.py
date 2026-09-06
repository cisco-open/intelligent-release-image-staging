# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Standards validation of the generated API document, including streaming."""

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
