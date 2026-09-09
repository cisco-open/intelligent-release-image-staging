# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OpenAPI/runtime bidirectional drift and API-wide security invariants."""

import json
from pathlib import Path
import re

import api_problem
import api_routes
import openapi_contract


SPEC = Path(__file__).resolve().parents[2] / "docs" / "zensical" / "openapi.yaml"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

INSTRUCTION_RESOURCES = (
    "/v1/devices/{device_id}/instructions",
    "/v1/devices/{device_id}/instruction-keylist",
)


def _media_examples(media):
    if "example" in media:
        return [media["example"]]
    return [entry["value"] for entry in media["examples"].values()]


def _assert_i63_schema(schema, minimum=0):
    assert schema["type"] == "integer"
    assert schema["minimum"] == minimum
    assert schema["maximum"] == (1 << 63) - 1


def _load():
    # The checked-in .yaml is emitted as JSON, a strict YAML subset, so this
    # contract test needs no optional YAML parser in production/test images.
    return json.loads(SPEC.read_text(encoding="utf-8"))


def _specified_keys(doc):
    keys = set()
    for path, item in doc["paths"].items():
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            services = operation.get(
                "x-iris-services", [operation["x-iris-service"]])
            keys.update((service, method.upper(), path) for service in services)
    return keys


def test_openapi_is_generated_from_exact_runtime_route_registry():
    doc = _load()
    assert doc["openapi"] == "3.2.0"
    assert _specified_keys(doc) == api_routes.keys()
    # This second equality catches semantic drift beyond the route triples:
    # auth, examples, status contracts and compatibility declarations.
    assert doc == openapi_contract.build_document()


def test_instruction_resources_are_exact_registered_device_routes():
    routes = [route for route in api_routes.ROUTES
              if "instruction" in route.path]
    assert {(route.service, route.method, route.path, route.security)
            for route in routes} == {
        ("catalog", "GET", path, "deviceBearer")
        for path in INSTRUCTION_RESOURCES
    }
    assert all(api_routes.match("catalog", "GET", path.replace(
        "{device_id}", "edge-01")) is not None
        for path in INSTRUCTION_RESOURCES)
    for alias in ("/v1/instructions", "/v1/instruction-keylist",
                  "/v1/keylist", "/v1/krl", "/krl",
                  "/v1/devices/edge-01/krl",
                  "/v1/devices/edge-01/role",
                  "/v1/devices/edge-01/instruction-keylist/extra"):
        assert api_routes.match("catalog", "GET", alias) is None

    document = _load()
    documented = {path for path in document["paths"]
                  if "instruction" in path}
    assert documented == set(INSTRUCTION_RESOURCES)
    for path in INSTRUCTION_RESOURCES:
        operation = document["paths"][path]["get"]
        assert operation["x-iris-service"] == "catalog"
        assert operation["x-iris-security"] == "deviceBearer"
        assert operation["security"] == [{"deviceBearer": []}]


def test_anonymous_routes_are_probes_or_exact_guest_shell_static_compatibility():
    anonymous = {(r.service, r.method, r.path) for r in api_routes.ROUTES
                 if openapi_contract._security(r) == []}
    probes = {
        ("console", "GET", "/healthz"),
        ("console", "GET", "/readyz"),
        ("telemetry", "GET", "/healthz"),
        ("telemetry", "GET", "/readyz"),
    }
    guest_shell_static = {
        ("artifact", method, path)
        for method in ("GET", "HEAD")
        for path in ("/bootstrap.sh", "/iris-agent.tgz",
                     "/iris-agent-arm.tgz", "/iris-catalog.pem",
                     "/iris-signers.pem")}
    guest_shell_capabilities = {
        ("artifact", method, "/staging/{legacy_artifact}")
        for method in ("GET", "HEAD")}
    assert anonymous == probes | guest_shell_static | guest_shell_capabilities
    assert all(r.security == "none" for r in api_routes.ROUTES
               if (r.service, r.method, r.path) in probes)
    assert all(r.security == "guestShellAnonymousStatic"
               for r in api_routes.ROUTES
               if (r.service, r.method, r.path) in guest_shell_static)
    assert all(r.security == "legacyGuestShell"
               for r in api_routes.ROUTES
               if (r.service, r.method, r.path) in
               guest_shell_capabilities)
    assert next(r for r in api_routes.ROUTES
                if r.path == "/api/v1/login").security == "consolePassword"
    assert next(r for r in api_routes.ROUTES
                if r.path == "/api/v1/setup").security == "setupGrant"

    capability = _load()["paths"]["/staging/{legacy_artifact}"]["get"]
    patterns = [item["pattern"] for item in capability["parameters"][0][
        "schema"]["oneOf"]]
    assert patterns == [
        r"^iris-agent-[A-Za-z0-9._:-]+-[0-9A-Fa-f]{32}\.conf$",
        r"^rpc-secret-[0-9A-Fa-f]{32}$",
        r"^iris-instructions-[A-Za-z0-9._:-]+-[0-9a-f]{32}\.envelope$",
        r"^bundle-sha256-[0-9a-f]{32}$",
    ]


def test_every_operation_has_auth_schemas_statuses_and_examples():
    doc = _load()
    for path, item in doc["paths"].items():
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            assert "x-iris-security" in operation, (method, path)
            assert "security" in operation, (method, path)
            assert operation["responses"], (method, path)
            assert "default" not in operation["responses"], (method, path)
            for status, response in operation["responses"].items():
                assert status.isdigit(), (method, path, status)
                if status in ("429", "503"):
                    assert "Retry-After" in response.get("headers", {}), (
                        method, path, status)
                for media in response.get("content", {}).values():
                    assert "schema" in media or "itemSchema" in media, (method, path)
                    assert "example" in media or "examples" in media, (
                        method, path)
                    assert media.get("schema", media.get("itemSchema")) != {
                        "$ref": "#/components/schemas/JsonObject"}, (
                            method, path)
            for media in operation.get("requestBody", {}).get(
                    "content", {}).values():
                assert "schema" in media, (method, path)
                assert "example" in media or "examples" in media, (
                    method, path)
                assert media["schema"] != {
                    "$ref": "#/components/schemas/JsonObject"}, (
                        method, path)


def test_login_contract_enumerates_both_successes_and_runtime_failures():
    doc = _load()
    for path in ("/api/v1/login", "/internal/v1/login"):
        op = doc["paths"][path]["post"]
        assert "oneOf" in op["responses"]["200"]["content"][
            "application/json"]["schema"]
        assert {"400", "401", "413", "429", "503"}.issubset(
            op["responses"])


def test_catalog_torrent_media_and_cache_vary_are_explicit():
    response = _load()["paths"]["/v1/torrents/{image_id}"]["get"][
        "responses"]["200"]
    assert set(response["content"]) == {"application/x-bittorrent"}
    assert response["headers"]["Cache-Control"]["schema"]["const"] == \
        "private, no-store"
    assert response["headers"]["Vary"]["schema"]["const"] == \
        "Authorization, X-IRIS-Tracker-Auth"


def test_instruction_binary_success_and_conditional_contracts_are_exact():
    document = _load()
    expected_headers = {
        "Cache-Control", "Vary", "ETag", "Date",
        "X-Content-Type-Options",
    }
    for path in INSTRUCTION_RESOURCES:
        operation = document["paths"][path]["get"]
        parameters = {(item["name"], item["in"]): item
                      for item in operation["parameters"]}
        conditional = parameters[("If-None-Match", "header")]
        assert conditional["required"] is False
        assert conditional["schema"]["type"] == "string"
        description = conditional["description"].lower()
        assert all(term in description for term in
                   ("weak", "list", "wildcard"))

        success = operation["responses"]["200"]
        assert set(success["content"]) == {"application/octet-stream"}
        media = success["content"]["application/octet-stream"]
        assert all(key not in media["schema"]
                   for key in ("type", "format", "contentEncoding"))
        assert set(success["headers"]) == expected_headers
        assert success["headers"]["Cache-Control"]["schema"]["const"] == \
            "private, no-store"
        assert success["headers"]["Vary"]["schema"]["const"] == \
            "Authorization"
        assert success["headers"]["X-Content-Type-Options"]["schema"][
            "const"] == "nosniff"
        etag = success["headers"]["ETag"]
        assert re.fullmatch(r'"sha256-[0-9a-f]{64}"', etag["example"])
        assert success["headers"]["Date"]["schema"]["type"] == "string"

        unchanged = operation["responses"]["304"]
        assert "content" not in unchanged
        assert set(unchanged["headers"]) == expected_headers
        assert all(name not in unchanged["headers"]
                   for name in ("Content-Type", "Content-Length"))
        assert unchanged["headers"]["Cache-Control"]["schema"]["const"] == \
            "private, no-store"
        assert unchanged["headers"]["Vary"]["schema"]["const"] == \
            "Authorization"
        assert unchanged["headers"]["X-Content-Type-Options"]["schema"][
            "const"] == "nosniff"


def test_instruction_problem_matrix_titles_and_headers_are_exact():
    document = _load()
    expected = {
        INSTRUCTION_RESOURCES[0]: {
            "401": [("catalog-authentication-required",
                     "Catalog authentication required")],
            "403": [("instruction-device-forbidden",
                     "Instruction access forbidden")],
            "404": [("instruction-stamp-missing",
                     "Instruction stamp missing")],
            "409": [("stale_pointer", "Stale instruction pointer")],
            "429": [("instruction-rate-limit-exceeded",
                     "Instruction request rate limit exceeded")],
            "503": [("credential-store-unavailable",
                     "Credential store unavailable"),
                    ("instruction-state-unavailable",
                     "Instruction state unavailable")],
        },
        INSTRUCTION_RESOURCES[1]: {
            "401": [("catalog-authentication-required",
                     "Catalog authentication required")],
            "403": [("instruction-device-forbidden",
                     "Instruction access forbidden")],
            "404": [("instruction-keylist-missing",
                     "Instruction keylist missing")],
            "429": [("instruction-rate-limit-exceeded",
                     "Instruction request rate limit exceeded")],
            "503": [("credential-store-unavailable",
                     "Credential store unavailable"),
                    ("instruction-keylist-unavailable",
                     "Instruction keylist unavailable")],
        },
    }
    common_headers = {
        "Cache-Control", "Vary", "Date", "X-Content-Type-Options"}
    observed = set()
    for path, statuses in expected.items():
        responses = document["paths"][path]["get"]["responses"]
        assert set(responses) == {"200", "304", *statuses}
        for status, variants in statuses.items():
            response = responses[status]
            assert len(response["x-iris-problem-codes"]) == len(variants)
            assert set(response["x-iris-problem-codes"]) == {
                code for code, _title in variants}
            media = response["content"]["application/problem+json"]
            examples = _media_examples(media)
            assert len(examples) == len(variants)
            assert {(item["code"], item["title"])
                    for item in examples} == set(variants)
            for item in examples:
                assert set(item) == {"type", "title", "status", "code"}
                assert item["status"] == int(status)
                assert item["type"] == api_problem.TYPE_BASE + item["code"]
                observed.add((int(status), item["code"], item["title"]))

            header_names = set(response["headers"])
            expected_names = set(common_headers)
            if status == "401":
                expected_names.add("WWW-Authenticate")
            if status in ("409", "429", "503"):
                expected_names.add("Retry-After")
            assert header_names == expected_names
            assert response["headers"]["Cache-Control"]["schema"][
                "const"] == "no-store"
            assert response["headers"]["Vary"]["schema"]["const"] == \
                "Authorization"
            assert response["headers"]["X-Content-Type-Options"]["schema"][
                "const"] == "nosniff"
            if status == "401":
                assert response["headers"]["WWW-Authenticate"][
                    "example"] == "Bearer"
            if status in ("409", "503"):
                assert response["headers"]["Retry-After"]["example"] == 10
            elif status == "429":
                assert response["headers"]["Retry-After"]["schema"][
                    "minimum"] == 1

    assert observed == {
        (503, "credential-store-unavailable", "Credential store unavailable"),
        (401, "catalog-authentication-required",
         "Catalog authentication required"),
        (403, "instruction-device-forbidden", "Instruction access forbidden"),
        (404, "instruction-stamp-missing", "Instruction stamp missing"),
        (404, "instruction-keylist-missing", "Instruction keylist missing"),
        (409, "stale_pointer", "Stale instruction pointer"),
        (429, "instruction-rate-limit-exceeded",
         "Instruction request rate limit exceeded"),
        (503, "instruction-state-unavailable",
         "Instruction state unavailable"),
        (503, "instruction-keylist-unavailable",
         "Instruction keylist unavailable"),
    }


def test_instruction_policy_and_heartbeat_response_contracts_are_bounded():
    document = _load()
    paths = (
        "/v1/devices/{device_id}/policy",
        "/v1/devices/{device_id}/heartbeat",
    )
    for path in paths:
        method = "get" if path.endswith("/policy") else "post"
        media = document["paths"][path][method]["responses"]["200"][
            "content"]["application/json"]
        properties = media["schema"]["properties"]
        pointer = properties["instr_rev"]
        assert len(pointer["required"]) == 2
        assert set(pointer["required"]) == {"epoch", "instr_serial"}
        assert pointer["additionalProperties"] is False
        for name in pointer["required"]:
            _assert_i63_schema(pointer["properties"][name])
        _assert_i63_schema(properties["keylist_seq"], minimum=1)
        examples = _media_examples(media)
        assert any(set(example.get("instr_rev", {})) == {
            "epoch", "instr_serial"} and "keylist_seq" in example
            for example in examples)

    heartbeat = document["paths"][paths[1]]["post"]["responses"]["200"][
        "content"]["application/json"]
    cadence = heartbeat["schema"]["properties"]
    assert cadence["stream_every"]["type"] == "integer"
    assert cadence["stream_every"]["minimum"] == 1
    assert cadence["stream_every"]["maximum"] == 60
    assert cadence["stream_pause"]["type"] == "boolean"
    assert any("instr_rev" not in example and
               {"stream_every", "stream_pause"} <= set(example)
               for example in _media_examples(heartbeat))


def test_instruction_heartbeat_attestation_schema_and_examples_are_complete():
    document = _load()
    media = document["paths"]["/v1/devices/{device_id}/heartbeat"]["post"][
        "requestBody"]["content"]["application/json"]
    schema = media["schema"]
    properties = schema["properties"]
    applied_names = [
        "bt_max_peers", "max_upload_limit", "max_download_limit",
        "overall_up", "overall_down", "request_peer_speed_limit",
        "max_concurrent",
    ]
    applied = properties["applied"]
    assert len(applied["required"]) == len(applied_names)
    assert set(applied["required"]) == set(applied_names)
    assert applied["additionalProperties"] is False
    for name in applied_names:
        _assert_i63_schema(applied["properties"][name])

    expected_states = {
        "none", "applied", "lkg", "stale_expired", "allowlist_expired",
        "rollback_rejected", "floor_reset", "audience_mismatch",
        "key_rejected", "tamper_rejected", "verifier_missing",
        "lkg_rejected", "lkg_unreadable", "oversize", "reasserted",
        "instr_unavailable", "instr_pending", "instr_forbidden",
        "tracker-only",
    }
    assert len(properties["instr_state"]["enum"]) == len(expected_states)
    assert set(properties["instr_state"]["enum"]) == expected_states
    assert len(properties["instr_reason"]["enum"]) == 2
    assert set(properties["instr_reason"]["enum"]) == {
        "unknown_key", "bad_mac"}
    _assert_i63_schema(properties["instr_serial"])
    assert len(properties["verify_level"]["enum"]) == 2
    assert set(properties["verify_level"]["enum"]) == {"sig", "none"}
    for name in ("blocklist_rules", "blocklist_revision"):
        _assert_i63_schema(properties[name])

    drift = properties["qos_drift"]
    assert len(drift["required"]) == 1
    assert set(drift["required"]) == {"options"}
    assert drift["additionalProperties"] is False
    options = drift["properties"]["options"]
    assert options["maxItems"] == 47
    assert len(options["items"]["required"]) == 3
    assert set(options["items"]["required"]) == {
        "option", "expected", "observed"}
    assert options["items"]["additionalProperties"] is False
    option_names = options["items"]["properties"]["option"]["enum"]
    assert len(option_names) == len(applied_names)
    assert set(option_names) == set(applied_names)
    _assert_i63_schema(options["items"]["properties"]["expected"])
    _assert_i63_schema(options["items"]["properties"]["observed"])
    for name in ("blocklist_rules", "blocklist_revision"):
        pair = drift["properties"][name]
        assert len(pair["required"]) == 2
        assert set(pair["required"]) == {"expected", "observed"}
        assert pair["additionalProperties"] is False
        _assert_i63_schema(pair["properties"]["expected"])
        _assert_i63_schema(pair["properties"]["observed"])

    examples = _media_examples(media)
    assert any("applied" in example for example in examples)
    assert any(example.get("instr_state") == "key_rejected" and
               example.get("instr_reason") in ("unknown_key", "bad_mac")
               for example in examples)
    instruction_fields = {
        "applied", "instr_state", "instr_reason", "instr_serial",
        "verify_level", "blocklist_rules", "blocklist_revision", "qos_drift",
    }
    assert any(not instruction_fields.intersection(example)
               for example in examples)


def test_task19_heartbeat_capability_identity_and_pointer_contract_is_bounded():
    from jsonschema import Draft202012Validator

    document = _load()
    media = document["paths"]["/v1/devices/{device_id}/heartbeat"]["post"][
        "requestBody"]["content"]["application/json"]
    schema = media["schema"]
    properties = schema["properties"]

    assert properties["instr_protocol"]["type"] == ["integer", "null"]
    assert properties["instr_protocol"]["enum"] == [1, None]
    for name in ("instr_epoch", "instr_serial", "instr_policy_revision"):
        _assert_i63_schema(properties[name])
    assert properties["pointer_skew"] == {"type": ["boolean", "null"]}
    assert schema["dependentRequired"]["instr_epoch"] == [
        "instr_serial", "instr_policy_revision"]
    assert schema["dependentRequired"]["instr_policy_revision"] == [
        "instr_epoch", "instr_serial"]
    assert "instr_serial" not in schema["dependentRequired"]

    current = media["examples"]["applied"]["value"]
    assert {name: current[name] for name in (
        "instr_epoch", "instr_serial", "instr_policy_revision")} == {
            "instr_epoch": 11, "instr_serial": 7,
            "instr_policy_revision": 3}
    assert current["pointer_skew"] is False
    rejected = media["examples"]["keyRejected"]["value"]
    assert rejected["instr_protocol"] == 1
    assert rejected["pointer_skew"] is False
    assert media["examples"]["unknownCapability"]["value"][
        "instr_protocol"] is None
    legacy = media["examples"]["legacy"]["value"]
    assert not {"instr_epoch", "instr_policy_revision", "pointer_skew"}.intersection(
        legacy)
    validator = Draft202012Validator(schema)
    for example in _media_examples(media):
        assert not list(validator.iter_errors(example)), example
    for valid in (
            {"instr_serial": 7},
            {"instr_protocol": None},
            {"instr_protocol": 1, "instr_epoch": 11, "instr_serial": 7,
             "instr_policy_revision": 3, "pointer_skew": False}):
        assert not list(validator.iter_errors(valid)), valid
    for invalid in (
            {"instr_protocol": 2}, {"instr_protocol": True},
            {"pointer_skew": 1},
            {"instr_epoch": 11, "instr_serial": 7},
            {"instr_policy_revision": 3, "instr_serial": 7}):
        assert list(validator.iter_errors(invalid)), invalid


def test_task19_device_instruction_projection_contract_is_exact_and_bounded():
    from jsonschema import Draft202012Validator

    document = _load()
    states = {
        "applied", "lkg", "stale", "rejected", "tracker-only",
        "pre-instructions", "unknown", "unavailable", "pending",
        "forbidden", "floor_reset", "none", "revoked",
    }
    fields = {
        "display_state", "label", "evidence", "underlying_state",
        "underlying_label", "underlying_evidence", "reason",
        "reported_instr_serial", "accepted_identity", "verify_level",
        "pointer_skew", "qos_drift_count", "report_age_seconds",
        "report_stale", "revoked", "revocation_evidence",
    }
    raw_states = set(openapi_contract.instructions.INSTR_STATES)

    for prefix in ("/api/v1", "/internal/v1"):
        media = document["paths"][prefix + "/devices"]["get"]["responses"][
            "200"]["content"]["application/json"]
        row = media["schema"]["properties"]["devices"]["items"]
        assert "instruction" in row["required"]
        instruction = row["properties"]["instruction"]
        assert instruction["additionalProperties"] is False
        assert set(instruction["required"]) == fields
        assert set(instruction["properties"]) == fields
        props = instruction["properties"]
        assert set(props["display_state"]["enum"]) == states
        for name in ("label", "underlying_label"):
            assert props[name]["type"] == "string"
            assert props[name]["minLength"] == 1
            assert props[name]["maxLength"] == 96
        assert props["evidence"]["type"] == "string"
        assert set(props["evidence"]["enum"]) == {
            "agent-asserted", "server-observed"}
        assert props["underlying_evidence"] == {
            "type": "string", "const": "agent-asserted"}
        assert props["revocation_evidence"] == {
            "type": "string", "const": "server-observed"}
        assert set(props["underlying_state"]["enum"]) == raw_states | {None}
        assert set(props["reason"]["enum"]) == {
            "unknown_key", "bad_mac", None}
        for name in ("reported_instr_serial", "report_age_seconds"):
            assert props[name]["type"] == ["integer", "null"]
            assert props[name]["minimum"] == 0
            assert props[name]["maximum"] == (1 << 63) - 1
        assert props["qos_drift_count"] == {
            "type": ["integer", "null"], "minimum": 0, "maximum": 49}
        for name in ("pointer_skew", "report_stale", "revoked"):
            assert props[name] == {"type": ["boolean", "null"]}
        assert set(props["verify_level"]["enum"]) == {"sig", "none", None}

        identity = props["accepted_identity"]
        assert identity["oneOf"][1] == {"type": "null"}
        accepted = identity["oneOf"][0]
        assert accepted["additionalProperties"] is False
        assert set(accepted["required"]) == {
            "epoch", "instr_serial", "policy_revision"}
        for value in accepted["properties"].values():
            _assert_i63_schema(value)

        example = media["example"]["devices"][0]["instruction"]
        assert set(example) == fields
        assert example["label"] == "applied r9223372036854775807"
        assert example["accepted_identity"]["instr_serial"] == (1 << 63) - 1
        validator = Draft202012Validator(instruction)
        assert not list(validator.iter_errors(example))
        assert not list(Draft202012Validator(media["schema"]).iter_errors(
            media["example"]))
        invalid = dict(example, private="must-not-cross-projection")
        assert list(validator.iter_errors(invalid))
        invalid = dict(example, accepted_identity={
            "epoch": 11, "instr_serial": 7})
        assert list(validator.iter_errors(invalid))
        for field, value in (
                ("evidence", None),
                ("evidence", "device-authored"),
                ("underlying_evidence", "server-observed"),
                ("revocation_evidence", "agent-asserted")):
            assert list(validator.iter_errors(dict(example, **{field: value})))


def test_task19_effective_qos_deprecates_legacy_delivery_state_and_requires_instruction():
    from jsonschema import Draft202012Validator

    document = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        device_media = document["paths"][prefix + "/devices"]["get"][
            "responses"]["200"]["content"]["application/json"]
        canonical = device_media["schema"]["properties"]["devices"][
            "items"]["properties"]["instruction"]
        media = document["paths"][
            prefix + "/devices/{device_id}/effective-qos"]["get"][
                "responses"]["200"]["content"]["application/json"]
        schema = media["schema"]
        assert "instruction" in schema["required"]
        assert schema["properties"]["instruction"] == canonical
        legacy = schema["properties"]["delivery_state"]
        assert legacy["type"] == "string"
        assert legacy["const"] == "pre-instructions"
        assert legacy["deprecated"] is True
        assert "legacy" in legacy["description"].lower()
        assert "instruction" in legacy["description"].lower()
        example = media["example"]
        assert example["delivery_state"] == "pre-instructions"
        assert example["instruction"] == device_media["example"][
            "devices"][0]["instruction"]
        assert not list(Draft202012Validator(schema).iter_errors(example))


def test_task19_peer_policy_rollup_status_and_custody_are_exact_and_bounded():
    from jsonschema import Draft202012Validator

    document = _load()
    states = {
        "applied", "lkg", "stale", "rejected", "tracker-only",
        "pre-instructions", "unknown", "unavailable", "pending",
        "forbidden", "floor_reset", "none", "revoked",
    }
    custody_fields = {
        "schema", "enabled", "state", "certificate_days_to_expiry",
        "certificate_renewal_due", "signing_refused", "keylist_seq",
        "keylist_age_days", "keylist_resign_due", "roots_configured",
        "roots_attested_180d", "root_ceremony_overdue",
        "root_quorum_degraded", "updated_at",
    }
    for prefix in ("/api/v1", "/internal/v1"):
        media = document["paths"][prefix + "/peer-policy"]["get"][
            "responses"]["200"]["content"]["application/json"]
        schema = media["schema"]
        assert {"fleet_rollup", "instruction_status", "instruction_keys"} <= set(
            schema["required"])

        rollup = schema["properties"]["fleet_rollup"]
        assert rollup["additionalProperties"] is False
        assert set(rollup["required"]) == {
            "issued_revision", "applied", "states"}
        issued = rollup["properties"]["issued_revision"]
        assert issued == {"type": ["integer", "null"], "minimum": 0,
                          "maximum": (1 << 63) - 1}
        applied = rollup["properties"]["applied"]
        assert applied["propertyNames"]["pattern"] == \
            openapi_contract._DECIMAL_I63_PATTERN
        _assert_i63_schema(applied["additionalProperties"])
        decimal_pattern = re.compile(applied["propertyNames"]["pattern"])
        assert decimal_pattern.fullmatch(str((1 << 63) - 1))
        assert decimal_pattern.fullmatch(str(1 << 63)) is None
        applied_validator = Draft202012Validator(applied)
        assert not list(applied_validator.iter_errors({
            str((1 << 63) - 1): 1}))
        assert list(applied_validator.iter_errors({str(1 << 63): 1}))
        for newline_key in ("7\n", str((1 << 63) - 1) + "\n"):
            assert list(applied_validator.iter_errors({newline_key: 1}))
        state_map = rollup["properties"]["states"]
        assert state_map["additionalProperties"] is False
        assert set(state_map["properties"]) == states
        assert not state_map.get("required")
        for count in state_map["properties"].values():
            _assert_i63_schema(count)

        status = schema["properties"]["instruction_status"]
        assert status["additionalProperties"] is False
        assert set(status["required"]) == {
            "observed_at", "instr_stamp_missing", "pointer_skew",
            "issued_revision_label"}
        assert status["properties"]["observed_at"] == {
            "type": "number", "minimum": 0, "maximum": (1 << 63) - 1}
        for name in ("instr_stamp_missing", "pointer_skew"):
            count = status["properties"][name]
            assert count["type"] == ["integer", "null"]
            assert count["minimum"] == 0
            assert count["maximum"] == (1 << 63) - 1
        label_schema = status["properties"]["issued_revision_label"]
        assert label_schema == {
            "type": ["string", "null"], "maxLength": 20,
            "pattern": "^r" + openapi_contract._DECIMAL_I63_PATTERN[1:]}
        label_pattern = re.compile(label_schema["pattern"])
        assert label_pattern.fullmatch("r%d" % ((1 << 63) - 1))
        assert label_pattern.fullmatch("r%d" % (1 << 63)) is None
        label_validator = Draft202012Validator(label_schema)
        assert not list(label_validator.iter_errors(
            "r%d" % ((1 << 63) - 1)))
        assert list(label_validator.iter_errors("r%d" % (1 << 63)))
        for newline_label in ("r7\n", "r%d\n" % ((1 << 63) - 1)):
            assert list(label_validator.iter_errors(newline_label))

        custody = schema["properties"]["instruction_keys"]
        assert custody["oneOf"][1] == {"type": "null"}
        custody = custody["oneOf"][0]
        assert custody["additionalProperties"] is False
        assert set(custody["required"]) == custody_fields
        assert set(custody["properties"]) == custody_fields
        assert set(custody["properties"]["state"]["enum"]) == {
            "phase0", "ready", "renewal_due", "signing_refused",
            "keylist_missing", "invalid", "error"}
        assert set(custody["properties"]["root_ceremony_overdue"]["enum"]) == {
            "unknown", "ok", "warn", "critical"}
        assert custody["properties"]["certificate_days_to_expiry"]["minimum"] == \
            -((1 << 63) - 1)

        example = media["example"]
        assert example["instruction_status"]["issued_revision_label"] == "r12"
        assert example["fleet_rollup"] == {
            "issued_revision": 12, "applied": {"7": 1},
            "states": {"applied": 1}}
        assert set(example["instruction_keys"]) == custody_fields
        assert example["instruction_keys"]["updated_at"] <= \
            example["instruction_status"]["observed_at"]
        assert not list(Draft202012Validator(schema).iter_errors(example))
        assert not list(Draft202012Validator(rollup).iter_errors(
            example["fleet_rollup"]))
        assert not list(Draft202012Validator(status).iter_errors(
            example["instruction_status"]))
        custody_validator = Draft202012Validator(
            schema["properties"]["instruction_keys"])
        assert not list(custody_validator.iter_errors(example["instruction_keys"]))
        expired = dict(example["instruction_keys"],
                       certificate_days_to_expiry=-2)
        assert not list(custody_validator.iter_errors(expired))
        assert not list(custody_validator.iter_errors(None))
        assert list(custody_validator.iter_errors(
            dict(example["instruction_keys"], private="must-not-cross")))


def test_problem_types_use_stable_anchors_on_the_documented_page():
    assert api_problem.TYPE_BASE.endswith("/docs/problems/#")
    sample = api_problem.document(400, "invalid-request", "Invalid request")
    assert sample["type"] == api_problem.TYPE_BASE + "invalid-request"
    assert sample["code"] == "invalid-request"
    doc = _load()
    for path, item in doc["paths"].items():
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            for status, response in operation["responses"].items():
                media = response.get("content", {}).get(
                    "application/problem+json")
                if media is None:
                    continue
                examples = ([media["example"]] if "example" in media else
                            [entry["value"] for entry in
                             media["examples"].values()])
                assert examples
                for example in examples:
                    assert example["type"] == (
                        api_problem.TYPE_BASE + example["code"])
                    assert example["status"] == int(status)
                    assert example["title"]


def test_problem_examples_use_service_specific_authentication_codes():
    doc = _load()
    cases = {
        "/v1/devices/{device_id}/artifacts/{artifact_path}":
            "artifact-authentication-required",
        "/v1/images": "catalog-authentication-required",
        "/metrics": "observability-authentication-required",
        "/status": "management-authentication-required",
    }
    for path, code in cases.items():
        media = doc["paths"][path]["get"]["responses"]["401"]["content"][
            "application/problem+json"]
        values = ([media["example"]] if "example" in media else
                  [entry["value"] for entry in media["examples"].values()])
        assert code in {value["code"] for value in values}

    assert doc["paths"]["/v1/devices/{device_id}/artifacts/{artifact_path}"][
        "get"]["responses"]["401"]["headers"][
            "WWW-Authenticate"]["example"].startswith("Basic ")
    for path in ("/v1/images", "/status",
                 "/internal/v1/console-certificate"):
        assert doc["paths"][path]["get"]["responses"]["401"][
            "headers"]["WWW-Authenticate"]["example"] == "Bearer"
    assert "WWW-Authenticate" not in doc["paths"]["/api/v1/images"][
        "get"]["responses"]["401"].get("headers", {})


def test_special_problem_codes_match_pre_dispatch_runtime_errors():
    doc = _load()
    assert doc["paths"]["/internal/v1/console-certificate"]["get"][
        "responses"]["503"]["x-iris-problem-codes"] == [
            "console-certificate-unavailable"]
    assert doc["paths"]["/internal/v1/authorizations"]["post"][
        "responses"]["400"]["x-iris-problem-codes"] == [
            "invalid-authorization-request"]
    artifact_codes = doc["paths"][
        "/v1/devices/{device_id}/artifacts/{artifact_path}"]["get"][
            "responses"]["500"]["x-iris-problem-codes"]
    assert artifact_codes == ["artifact-request-failed"]
    assert api_problem.STATUS_DEFAULTS[405][0] == "method-not-allowed"


def test_console_read_query_contract_matches_runtime_filters_and_limits():
    doc = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        devices = {p["name"]: p for p in
                   doc["paths"][prefix + "/devices"]["get"]["parameters"]
                   if p["in"] == "query"}
        assert set(devices) == {
            "limit", "offset", "q", "management_type", "platform", "cred",
            "telemetry", "peer", "status"}
        assert devices["limit"]["schema"]["maximum"] == 1000
        assert "__none" in devices["platform"]["schema"]["enum"]
        expected = {
            "/audit": {"limit", "before_ts", "after_ts", "category"},
            "/audit/histogram": {
                "category", "buckets", "window", "since_ts", "until_ts"},
            "/install-options": {"model"},
            "/swarm": {"limit", "offset"},
            "/deploy-logs": {"device_id", "after_ts", "before_ts"},
            "/deploy-logs/histogram": {
                "device_id", "buckets", "window", "since_ts", "until_ts"},
        }
        for suffix, names in expected.items():
            actual = {p["name"] for p in
                      doc["paths"][prefix + suffix]["get"]["parameters"]
                      if p["in"] == "query"}
            assert actual == names, (prefix + suffix, actual)


def test_tracker_documents_preferred_bearer_and_guest_shell_query_fallback():
    doc = _load()
    for path in ("/announce", "/scrape"):
        op = doc["paths"][path]["get"]
        assert op["servers"] == [{
            "url": "https://iris.example:6969",
            "description": "TLS BEP tracker v1 listener",
        }]
        assert op["x-iris-security"] == "announceBearerOrLegacyQuery"
        assert op["security"][0] == {"announceBearer": []}
        query = {p["name"]: p for p in op["parameters"]
                 if p["in"] == "query"}
        assert query["announce_token"]["deprecated"] is True
        assert query["key"]["deprecated"] is True
        assert "token" not in query
        assert query["info_hash"]["required"] is True
        assert query["info_hash"]["schema"]["x-iris-decodedLength"] == 20
    announce = {p["name"]: p for p in
                doc["paths"]["/announce"]["get"]["parameters"]}
    assert announce["peer_id"]["required"] is False
    assert announce["port"]["required"] is False
    assert "uploaded" not in announce
    assert "downloaded" not in announce
    assert "403" in doc["paths"]["/announce"]["get"]["responses"]
    assert "HTTPS-only" in doc["x-iris-retained-v1-exceptions"][
        "trackerTransport"]


def test_settings_and_optional_success_shapes_match_runtime():
    doc = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        verification = doc["paths"][
            prefix + "/settings/image-verification"]
        request = verification["post"]["requestBody"]["content"][
            "application/json"]
        assert request["example"]["mode"] == "daily"
        assert request["schema"]["required"] == ["mode"]
        assert request["schema"]["properties"]["mode"]["enum"] == [
            "off", "daily", "weekly"]
        success = verification["get"]["responses"]["200"]["content"][
            "application/json"]
        assert set(success["example"]["last_run"]) == {
            "at", "source", "outcome", "matched", "mismatched",
            "not_in_feed"}
        assert success["schema"]["properties"]["last_run"]["properties"][
            "matched"]["type"] == ["integer", "null"]

        destination = doc["paths"][
            prefix + "/settings/telemetry-destination"]["post"]
        dest_request = destination["requestBody"]["content"][
            "application/json"]
        assert dest_request["example"] == {"endpoint": None, "enabled": None}
        assert dest_request["schema"]["required"] == []
        dest_success = destination["responses"]["200"]["content"][
            "application/json"]
        assert dest_success["example"]["endpoint"] is None
        assert dest_success["example"]["enabled"] is None

        ca_request = doc["paths"][prefix + "/settings/ca-trust"]["post"][
            "requestBody"]["content"]["application/json"]
        assert ca_request["example"]["url"] is None
        assert ca_request["schema"]["required"] == []
        cert_success = doc["paths"][prefix + "/settings/gui-cert"]["post"][
            "responses"]["200"]["content"]["application/json"]
        assert cert_success["example"]["applied"] is True
        assert cert_success["example"]["note"] is None
        assert set(cert_success["example"]["gui_cert"]) == {
            "source", "subject", "issuer", "not_after",
            "fingerprint_sha256"}
        deleted_cert = doc["paths"][prefix + "/settings/gui-cert"][
            "delete"]["responses"]["200"]["content"][
                "application/json"]["example"]["gui_cert"]
        assert set(deleted_cert) == {
            "source", "subject", "issuer", "not_after",
            "fingerprint_sha256"}

        setup = doc["paths"][
            prefix + "/settings/setup-status"]["get"]["responses"]["200"][
                "content"]["application/json"]
        fingerprint = setup["schema"]["properties"]["packages"][
            "properties"]["reference_fingerprint"]
        assert fingerprint["type"] == ["string", "null"]
        package_item = setup["schema"]["properties"]["packages"][
            "properties"]["items"]["items"]
        assert package_item["properties"]["state"]["enum"] == [
            "ok", "absent", "unknown", "stale"]
        assert set(package_item["required"]) == {
            "name", "state", "fingerprint", "built_at", "remedy",
            "provenance"}
        assert package_item["properties"]["built_at"]["type"] == [
            "integer", "null"]
        assert package_item["properties"]["reason"]["type"] == "string"
        assert package_item["properties"]["provenance"]["type"] == [
            "object", "null"]
        assert setup["example"]["packages"]["items"][0]["remedy"] == \
            "tools/provision-iox-packages.sh"

        for suffix in ("/images/{image_id}/release-quarantine",
                       "/telemetry/stream", "/settings/ca-trust",
                       "/settings/telemetry-destination"):
            assert doc["paths"][prefix + suffix]["post"][
                "requestBody"]["required"] is False

    assert "411" in doc["paths"]["/api/v1/login"]["post"]["responses"]
    assert "411" not in doc["paths"]["/internal/v1/login"]["post"][
        "responses"]
    assert "411" in doc["paths"]["/api/v1/setup"]["post"]["responses"]
    assert "411" not in doc["paths"]["/internal/v1/setup"]["post"][
        "responses"]


def test_swarm_contract_uses_real_source_grouped_snapshot_shapes():
    import telemetry
    import management_api
    import auth
    import peer_policy
    from peer_registry import PeerRegistry
    from openapi_schema_validator import OAS32Validator
    registry = PeerRegistry()
    for index, kind in enumerate(("device", "service", "legacy")):
        registry.announce("abc", "peer" + str(index), "192.0.2." + str(index + 1),
                          6881, left=10,
                          principal=auth.Principal(kind, "d1" if kind == "device" else "seeder"))
    policy_doc = peer_policy.base_document()
    policy_doc["assignments"]["d1"] = "quarantine"
    policy = peer_policy.PolicyResult(policy_doc, True, True, peer_policy.compile_roles(policy_doc))
    snapshot = telemetry.Telemetry(registry, policy_info=lambda: policy).swarm_snapshot()
    device = next(row for row in snapshot["images"][0]["peers"] if row["device_id"] == "d1")
    assert device["peer_policy"]["decision"] == "deny"
    assert device["peer_policy"]["assignment"] is None
    assert device["peer_policy"]["quarantined"] is True
    service = next(row for row in registry.snapshot()["abc"] if row["principal_type"] == "service")
    service_row = telemetry._peer_row(service, None, {}, {}, {}, {}, None, None, set(), set(), 10)
    OAS32Validator(openapi_contract._swarm_peer_schema()).validate(service_row)
    doc = _load()
    for path in ("/api/v1/swarm", "/internal/v1/swarm", "/swarm"):
        media = doc["paths"][path]["get"]["responses"]["200"][
            "content"]["application/json"]
        whole = media["examples"]["whole"]["value"]
        OAS32Validator(media["schema"]).validate(snapshot)
        assert whole["images"][0]["peers"][0]["tracker"]["principal_type"] == "device"
        if path != "/swarm":
            page = management_api._swarm_page(json.dumps(snapshot), 1, 0)
            assert page["peers_total"] == 2 and page["peers_limit"] == 1
            assert len(page["images"][0]["peers"]) == 1
            OAS32Validator(media["schema"]).validate(page)
        assert set(whole) == {"now", "server", "images"}
        assert set(whole["server"]) == {"host", "server_observation"}
        assert set(whole["images"][0]) == {
            "image", "info_hash", "total_bytes", "seeders", "leechers",
            "peers"}
        # Root response schemas are closed so the whole and paged variants do
        # not both match the same document.
        assert media["schema"]["oneOf"][0]["additionalProperties"] is False


def test_collection_and_catalog_success_examples_match_live_wire_shapes():
    doc = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        def success(suffix):
            return doc["paths"][prefix + suffix]["get"]["responses"]["200"][
                "content"]["application/json"]

        assert success("/devices")["example"]["limit"] is None
        options = success("/install-options")
        assert options["example"] == {"options": ["guestshell", "iox"]}
        assert options["schema"]["properties"]["options"]["type"] == [
            "array", "null"]
        deployment = success("/devices/{device_id}/deployment")
        assert deployment["example"] == {"record": None, "total": 0}
        assert "oneOf" in deployment["schema"]["properties"]["record"]
        assert set(success("/overview")["example"]) == {
            "images", "devices", "assigned", "staged", "staging_now",
            "awaiting_heartbeat", "rollout", "swarm_map_url"}
        assert set(success("/deploy-logs")["example"]["logs"][0]) == {
            "file", "device_id", "action", "state", "rc", "finished_at",
            "size"}

    policy = doc["paths"]["/v1/devices/{device_id}/policy"]["get"][
        "responses"]["200"]["content"]["application/json"]
    legacy_policy = next(example for example in _media_examples(policy)
                         if not {"instr_rev", "keylist_seq"}.intersection(example))
    assert set(legacy_policy) == {
        "approved_image_id", "approved_image_ids", "plans"}
    refresh = doc["paths"]["/v1/devices/{device_id}/token-refresh"]["post"][
        "responses"]["200"]["content"]["application/json"]
    assert set(refresh["schema"]["required"]) == {
        "catalog_token", "expires_at"}
    assert {"announce_token", "rpc_secret"}.issubset(
        refresh["schema"]["properties"])


def test_artifact_conditional_and_error_statuses_match_simple_handler():
    doc = _load()
    versioned = doc["paths"][
        "/v1/devices/{device_id}/artifacts/{artifact_path}"]["get"]
    assert "304" in versioned["responses"]
    assert "416" not in versioned["responses"]
    staging = doc["paths"]["/staging/{legacy_artifact}"]["get"]
    assert staging["security"] == []
    assert staging["x-iris-path-capability"]["entropyBits"] == 128
    assert "guestShellCapability" not in doc["components"]["securitySchemes"]
    assert "304" in staging["responses"]
    assert "403" in staging["responses"]
    assert "416" not in staging["responses"]


def test_compatibility_request_and_response_shapes_are_operation_specific():
    doc = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        assignment_body = doc["paths"][
            prefix + "/devices/{device_id}/assign"]["post"]["requestBody"]
        assignment = assignment_body["content"]["application/json"]
        assert assignment_body["required"] is False
        assert assignment["schema"]["required"] == []
        assert {"image_ids", "image_id", "expect_image_ids"}.issubset(
            assignment["schema"]["properties"])
        assert set(assignment["examples"]) == {
            "orderedSet", "singularCompatibility", "unassign"}
        assignment_operation = doc["paths"][
            prefix + "/devices/{device_id}/assign"]["post"]
        assert "422" in assignment_operation["responses"]
        assignment_result = assignment_operation["responses"]["200"][
            "content"]["application/json"]
        assert set(assignment_result["schema"]["required"]) == {
            "ok", "assigned_image_ids", "removed_image_ids"}
        fleet_operation = doc["paths"][prefix + "/devices"]["post"]
        fleet_schema = fleet_operation["requestBody"]["content"][
            "application/json"]["schema"]
        assert fleet_schema["additionalProperties"] is False
        assert "os_family" not in fleet_schema["properties"]
        assert "registered_at" not in fleet_schema["properties"]
        assert {"iris_vlan", "app_ip", "role", "credential_profile_id"}.issubset(
            fleet_schema["properties"])
        assert "422" in fleet_operation["responses"]
        release = doc["paths"][
            prefix + "/images/{image_id}/release-quarantine"]["post"]
        assert release["requestBody"]["content"]["application/json"][
            "schema"]["required"] == []
        assert set(release["responses"]["200"]["content"][
            "application/json"]["example"]) == {
                "released", "override", "state", "seeding_resumed"}
        for suffix in ("/image-verification/offline",
                       "/image-verification/refresh"):
            result = doc["paths"][prefix + suffix]["post"]["responses"][
                "200"]["content"]["application/json"]["example"]
            assert "source" not in result
        reports = doc["paths"][
            prefix + "/devices/{device_id}/reports"]["get"]["responses"][
                "200"]["content"]["application/json"]["example"]["reports"]
        assert reports[0]["stage_state"] == "ready"
        assert "state" not in reports[0]
        report_schema = doc["paths"][
            prefix + "/devices/{device_id}/reports"]["get"]["responses"][
                "200"]["content"]["application/json"]["schema"]
        variants = report_schema["properties"]["reports"]["items"]["oneOf"]
        assert {variant["properties"]["schema"]["const"]
                for variant in variants} == {"v1", "v2"}

    policy = doc["paths"]["/v1/devices/{device_id}/policy"]["get"][
        "responses"]["200"]["content"]["application/json"]["schema"]
    plans = policy["properties"]["plans"]
    assert "image-01" not in plans.get("properties", {})
    assert "additionalProperties" in plans
    direct_swarm = doc["paths"]["/swarm"]["get"]["responses"]["200"][
        "content"]["application/json"]
    assert direct_swarm["examples"]["serializationFallback"]["value"] == {}
    assert direct_swarm["schema"]["oneOf"][-1] == {
        "type": "object", "maxProperties": 0}


def test_external_and_internal_console_routes_are_paired():
    for route in api_routes.ROUTES:
        if route.service != "console" or not route.path.startswith("/api/v1/"):
            continue
        target = api_routes.console_to_management(route.method, route.path)
        assert target is not None
        assert api_routes.match("management", route.method, target) is not None


def test_image_publish_job_contract_covers_every_runtime_phase_shape():
    doc = _load()
    for prefix in ("/api/v1", "/internal/v1"):
        media = doc["paths"][prefix + "/images/jobs/{job_id}"]["get"][
            "responses"]["200"]["content"]["application/json"]
        examples = {name: wrapped["value"]
                    for name, wrapped in media["examples"].items()}
        assert set(examples) == {
            "publishing", "verifying", "verified", "verificationFailed",
            "publishFailed"}
        assert examples["publishing"]["verification"] is None
        assert examples["publishing"]["finished_at"] is None
        assert examples["verifying"]["verification"] == {
            "outcome": "running", "image_state": None}
        assert examples["verified"]["verification"] == {
            "outcome": "ok", "image_state": "verified", "matched": 1,
            "mismatched": 0, "not_in_feed": 0}
        assert examples["verificationFailed"]["verification"] == {
            "outcome": "fail", "image_state": None,
            "detail": "feed unavailable"}
        assert examples["publishFailed"]["state"] == "error"
        assert examples["publishFailed"]["verification"] is None

        variants = media["schema"]["oneOf"]
        by_state = {variant["properties"]["state"]["const"]: variant
                    for variant in variants}
        assert set(by_state) == {"publishing", "verifying", "done", "error"}
        required = {"id", "state", "filename", "message", "image_id",
                    "started_at", "finished_at", "verification"}
        assert all(set(variant["required"]) == required
                   for variant in variants)
        assert by_state["publishing"]["properties"]["verification"] == {
            "type": "null"}
        running = by_state["verifying"]["properties"]["verification"]
        assert set(running["required"]) == {"outcome", "image_state"}
        assert "matched" not in running["properties"]
        terminal = by_state["done"]["properties"]["verification"]["oneOf"]
        ok = next(value for value in terminal
                  if value.get("properties", {}).get("outcome", {}).get(
                      "const") == "ok")
        failed = next(value for value in terminal
                      if value.get("properties", {}).get("outcome", {}).get(
                          "enum") == ["fail", "already_running"])
        assert set(ok["required"]) == {
            "outcome", "image_state", "matched", "mismatched",
            "not_in_feed"}
        assert set(failed["required"]) == {
            "outcome", "image_state", "detail"}
        assert "matched" not in failed["properties"]


def test_openapi_role_qos_mutations_require_cas_and_preview():
    spec = openapi_contract.build_document()
    for suffix, method in (("/peer-policy/roles/{name}", "put"),
                           ("/peer-policy/roles/{name}", "delete"),
                           ("/peer-policy/qos", "put"),
                           ("/devices/{device_id}/role", "post"),
                           ("/devices/bulk-role", "post")):
        for prefix in ("/api/v1", "/internal/v1"):
            operation = spec["paths"][prefix + suffix][method]
            assert {"409", "412", "422", "428"} <= set(operation["responses"])
            parameters = {p["name"]: p for p in operation["parameters"]}
            assert parameters["If-Match"]["required"] is True
            assert "dry_run" in parameters
    assert "/api/v1/devices/{device_id}/qos" not in spec["paths"]


def test_policy_contract_exact_business_unions_compose_tier_failures():
    spec = openapi_contract.build_document()
    for prefix in ("/api/v1", "/internal/v1"):
        def codes(suffix, method, status):
            return set(spec["paths"][prefix + suffix][method]["responses"][str(status)]["x-iris-problem-codes"])
        operations = set(openapi_contract.POLICY_MUTATIONS) | {
            ("GET", "/peer-policy"), ("GET", "/peer-policy/roles"),
            ("GET", "/peer-policy/explain"), ("GET", "/devices/{device_id}/effective-qos")}
        for method, suffix in operations:
            assert codes(suffix, method.lower(), 401) == {"console-session-required", "management-authentication-required"}
        assert codes("/peer-policy/roles/{name}", "put", 422) == {"invalid_policy", "invalid_policy_request"}
        assert codes("/peer-policy/roles/{name}", "put", 409) == {"role_isolated", "role_reserved_name", "revision_conflict", "operation_backlog_full"}
        assert codes("/peer-policy/qos", "put", 404) == {"route-not-found", "role_not_found"}
        assert codes("/devices/{device_id}/effective-qos", "get", 404) == {"route-not-found", "device_not_found"}
        assert codes("/peer-policy/explain", "get", 422) == {"principal_unresolvable"}
        assert codes("/peer-policy/qos", "put", 409) == {"revision_conflict", "operation_backlog_full", "role_reserved_name"}
        assert "fleet_write_failed" not in codes("/peer-policy/explain", "get", 503)
        if prefix == "/api/v1":
            assert "management-api-unavailable" in codes("/peer-policy/qos", "put", 503)
        schema = spec["paths"][prefix + "/peer-policy"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema["properties"]["roles_supported"] == {"type": "boolean", "const": True}


def test_tracker_state_openapi_contract_is_closed_reusable_and_exactly_generated():
    document = _load()
    generated = openapi_contract.build_document()
    assert document["openapi"] == "3.2.0"
    assert SPEC.read_bytes() == (json.dumps(generated, indent=2,
                                           sort_keys=False) + "\n").encode("utf-8")
    assert _specified_keys(document) == api_routes.keys()

    def resolve(schema):
        while "$ref" in schema:
            reference = schema["$ref"]
            assert reference.startswith("#/components/schemas/")
            schema = document["components"]["schemas"][reference.rsplit("/", 1)[-1]]
        return schema

    def state_map(schema):
        map_ref = schema.get("$ref")
        assert map_ref, "one reusable tracker-state map"
        schema = resolve(schema)
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        assert set(schema["properties"]) == {"seeder", "leecher"}
        assert not schema.get("required")
        refs = [schema["properties"][state].get("$ref") for state in ("seeder", "leecher")]
        assert refs[0] and refs[0] == refs[1], "one reusable tracker-state object"
        row = resolve(schema["properties"]["seeder"])
        assert row["type"] == "object" and row["additionalProperties"] is False
        assert set(row["properties"]) == {"announce_min_interval_s", "numwant"}
        assert not row.get("required")
        for key, lower, upper in (("announce_min_interval_s", 10, 300), ("numwant", 4, 200)):
            value = resolve(row["properties"][key])
            assert (value["type"], value["minimum"], value["maximum"]) == ("integer", lower, upper)
        return map_ref, refs[0]

    state_refs = []
    for prefix in ("/api/v1", "/internal/v1"):
        put = document["paths"][prefix + "/peer-policy/qos"]["put"]
        body = resolve(put["requestBody"]["content"]["application/json"]["schema"])
        assert body["additionalProperties"] is False
        assert set(body["properties"]) == {"qos", "qos_state", "role", "confirm_token"}
        state_refs.append(state_map(body["properties"]["qos_state"]))
        assert set(put["responses"]["422"]["x-iris-problem-codes"]) == {
            "invalid_policy", "invalid_policy_request"}
        definition = resolve(document["paths"][prefix + "/peer-policy/roles/{name}"]["put"][
            "requestBody"]["content"]["application/json"]["schema"])
        state_refs.append(state_map(definition["properties"]["qos_state"]))
        roles = resolve(document["paths"][prefix + "/peer-policy/roles"]["get"][
            "responses"]["200"]["content"]["application/json"]["schema"])
        assert "qos_state_default" not in roles["required"]
        state_refs.append(state_map(roles["properties"]["qos_state_default"]))
        stored_role = resolve(roles["properties"]["roles"]["additionalProperties"])
        state_refs.append(state_map(stored_role["properties"]["qos_state"]))
        effective = document["paths"][prefix + "/devices/{device_id}/effective-qos"]["get"]
        query = [parameter for parameter in effective["parameters"] if parameter["in"] == "query"]
        assert len(query) == 1 and query[0]["name"] == "tracker_state"
        assert query[0].get("required", False) is False
        assert resolve(query[0]["schema"])["type"] == "string"
        assert set(resolve(query[0]["schema"])["enum"]) == {"seeder", "leecher"}
        assert set(effective["responses"]["422"]["x-iris-problem-codes"]) == {"invalid_policy_request"}
        assert set(effective["responses"]["404"]["x-iris-problem-codes"]) == {
            "route-not-found", "device_not_found"}
        response = resolve(effective["responses"]["200"]["content"]["application/json"]["schema"])
        assert {"tracker_state", "tracker_qos"} <= set(response["properties"])
    assert len(set(state_refs)) == 1
