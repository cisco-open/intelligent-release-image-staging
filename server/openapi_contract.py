# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Build the checked-in OpenAPI 3.2 contract from the runtime route registry.

The generated document is intentionally JSON (which is valid YAML). Keeping
the verbose path inventory mechanical makes review focus on semantics, while
the contract test compares both directions so neither runtime-only nor
spec-only operations can drift in unnoticed.
"""

import json
import re

import api_problem
import api_routes
import instructions
import peer_policy


ERROR_STATUSES = (400, 401, 403, 404, 405, 408, 409, 411, 412, 413, 415,
                  416, 422, 428, 429, 500, 502, 503)
MUTATIONS = {"POST", "PUT", "PATCH", "DELETE"}
POLICY_MUTATIONS = {
    ("PUT", "/peer-policy/roles/{name}"),
    ("DELETE", "/peer-policy/roles/{name}"),
    ("PUT", "/peer-policy/qos"),
    ("POST", "/devices/{device_id}/role"),
    ("POST", "/devices/bulk-role"),
}

INSTRUCTION_RESOURCES = (
    "/v1/devices/{device_id}/instructions",
    "/v1/devices/{device_id}/instruction-keylist",
)


def _instruction_resource(route):
    return (route.service == "catalog" and route.method == "GET"
            and route.path in INSTRUCTION_RESOURCES)


def _instruction_headers(success=True):
    headers = {
        "Cache-Control": {"schema": {"type": "string", "const":
            "private, no-store" if success else "no-store"}},
        "Vary": {"schema": {"type": "string", "const": "Authorization"}},
        "Date": {"schema": {"type": "string"},
                 "description": "Current RFC 9110 HTTP-date; independent of immutable envelope server_time and ETag",
                 "example": "Mon, 07 Sep 2026 12:00:00 GMT"},
        "X-Content-Type-Options": {
            "schema": {"type": "string", "const": "nosniff"}},
    }
    if success:
        headers["ETag"] = {
            "schema": {"type": "string", "pattern": '^"sha256-[0-9a-f]{64}"$'},
            "description": "Strong SHA-256 digest of the exact selected response bytes",
            "example": '"sha256-' + "0" * 64 + '"',
        }
    return headers


def _instruction_problem_variants(route, status):
    keylist = route.path == INSTRUCTION_RESOURCES[1]
    return {
        401: (("catalog-authentication-required", "Catalog authentication required"),),
        403: (("instruction-device-forbidden", "Instruction access forbidden"),),
        404: (("instruction-keylist-missing", "Instruction keylist missing"),)
             if keylist else (("instruction-stamp-missing", "Instruction stamp missing"),),
        409: (("stale_pointer", "Stale instruction pointer"),),
        429: (("instruction-rate-limit-exceeded", "Instruction request rate limit exceeded"),),
        503: (("credential-store-unavailable", "Credential store unavailable"),
              ("instruction-keylist-unavailable", "Instruction keylist unavailable")
              if keylist else ("instruction-state-unavailable", "Instruction state unavailable")),
    }[status]


def _instruction_integer(minimum=0):
    return {"type": "integer", "minimum": minimum, "maximum": instructions.MAX_I63}


def _instruction_pair_schema():
    return {
        "type": "object", "required": ["expected", "observed"],
        "additionalProperties": False,
        "properties": {name: _instruction_integer() for name in ("expected", "observed")},
        "description": "Non-Boolean integers; expected and observed must differ. Equality is rejected by the runtime sanitizer.",
    }


def _instruction_attestation_request(schema, legacy):
    """Document the authoritative vocabulary and complete omission units."""
    applied_names = list(instructions.APPLIED_FIELDS)
    pair = _instruction_pair_schema()
    option = _instruction_pair_schema()
    option["required"] = ["option", "expected", "observed"]
    option["properties"]["option"] = {"type": "string", "enum": applied_names}
    properties = schema["properties"]
    properties.update({
        "applied": {
            "type": "object", "required": applied_names,
            "additionalProperties": False,
            "properties": {name: _instruction_integer() for name in applied_names},
            "description": "Seven complete global/default aria2 observations, not per-GID claims. Omitted until successful assertion; retained for known LKG/fallback settings. Invalid objects are omitted as a whole.",
        },
        "instr_state": {"type": "string", "enum": sorted(instructions.INSTR_STATES)},
        "instr_reason": {"type": "string", "enum": sorted(instructions.INSTR_REASONS)},
        "instr_serial": _instruction_integer(),
        "verify_level": {"type": "string", "enum": ["sig", "none"]},
        "blocklist_rules": _instruction_integer(),
        "blocklist_revision": _instruction_integer(),
        "qos_drift": {
            "type": "object", "required": ["options"], "additionalProperties": False,
            "properties": {
                "options": {"type": "array", "maxItems": instructions.QOS_DRIFT_MAX_ROWS,
                            "items": option},
                "blocklist_revision": pair, "blocklist_rules": pair,
            },
            "anyOf": [
                {"properties": {"options": {"minItems": 1}}},
                {"required": ["blocklist_revision"]},
                {"required": ["blocklist_rules"]},
            ],
            "description": "One bounded fact; preserves option order and duplicate observations. At most seven global/default plus four options for each of ten active GIDs. GIDs, scopes, indexes, addresses and arbitrary option names are never transmitted. Active GIDs contribute only bt_max_peers, max_upload_limit, max_download_limit or request_peer_speed_limit. Any invalid row or pair omits the whole fact.",
        },
    })
    schema["dependentRequired"] = {
        "blocklist_rules": ["blocklist_revision"],
        "blocklist_revision": ["blocklist_rules"],
    }
    schema["allOf"] = [{
        "if": {"required": ["instr_state"],
               "properties": {"instr_state": {"const": "key_rejected"}}},
        "then": {"required": ["instr_reason"]},
        "else": {"not": {"required": ["instr_reason"]}},
    }]
    schema["description"] = (
        "Instruction fields are optional device assertions, not verified compliance. "
        "The server omits invalid state/reason and blocklist pairs as units; legacy "
        "agents omit all instruction fields. Integers exclude Boolean values and "
        "fractional or floating-point input. Device role/platform, keys, signatures, "
        "peer lists and opaque aria2 option dictionaries are never accepted as attestation.")
    applied = dict(legacy, instr_state="applied", instr_serial=7, verify_level="sig",
                   applied={name: index for index, name in enumerate(applied_names)},
                   blocklist_rules=12, blocklist_revision=3,
                   qos_drift={"options": [{"option": "max_upload_limit",
                                          "expected": 8192, "observed": 16384}]})
    return {"schema": schema, "examples": {
        "applied": {"value": applied},
        "keyRejected": {"value": dict(legacy, instr_state="key_rejected",
                                      instr_reason="unknown_key")},
        "legacy": {"value": legacy},
    }}


def _policy_mutation(route):
    return (route.method, _resource_suffix(route)) in POLICY_MUTATIONS


def _policy_business_errors(route):
    """Business refusals by the exact handler branch, excluding tier guards."""
    key = (route.method, _resource_suffix(route))
    specific = {
        ("GET", "/peer-policy"): {},
        ("GET", "/peer-policy/roles"): {503: ("policy_unavailable",)},
        ("GET", "/peer-policy/explain"): {
            422: ("principal_unresolvable",), 503: ("policy_unavailable",)},
        ("GET", "/devices/{device_id}/effective-qos"): {
            404: ("device_not_found",), 503: ("policy_unavailable",)},
        ("PUT", "/peer-policy/roles/{name}"): {
            409: ("role_reserved_name", "role_isolated"),
            413: ("payload-too-large",),
            422: ("invalid_policy",)},
        ("DELETE", "/peer-policy/roles/{name}"): {
            404: ("role_not_found",), 409: ("role_reserved_name", "role_in_use"),
            413: ("payload-too-large",), 422: ("invalid_policy",)},
        ("PUT", "/peer-policy/qos"): {
            404: ("role_not_found",), 409: ("role_reserved_name",),
            413: ("payload-too-large",), 422: ("invalid_policy",)},
        ("POST", "/devices/{device_id}/role"): {
            404: ("device_not_found", "role_not_found"),
            409: ("role_reserved_name", "role_shadowed_by_assignment"),
            422: ("bad_role", "invalid_policy", "incomparable_role_change"),
            503: ("fleet_write_failed",)},
        ("POST", "/devices/bulk-role"): {
            404: ("role_not_found",),
            409: ("role_reserved_name", "role_shadowed_by_assignment"),
            422: ("bad_role", "invalid_policy", "incomparable_role_change", "mixed_role_direction"),
            503: ("fleet_write_failed",)},
    }.get(key)
    if specific is None or route.service not in ("console", "management"):
        return None
    result = dict(specific)
    if _policy_mutation(route):
        for status, codes in {
                409: ("revision_conflict", "operation_backlog_full"),
                412: ("precondition_failed",), 422: ("invalid_policy_request",),
                428: ("precondition_required", "confirmation_required"),
                503: ("policy_unavailable",)}.items():
            result[status] = result.get(status, ()) + codes
    return result


def _policy_errors(route):
    business = _policy_business_errors(route)
    if business is None:
        return None
    errors = {status: set(codes) for status, codes in business.items()}
    common = {401: {"console-session-required"},
              404: {"route-not-found"}, 503: {"service-unavailable"}}
    # The proxy can forward a rejected mounted tier credential as well.
    common[401].add("management-authentication-required")
    if route.method in MUTATIONS:
        common[403] = {"csrf-validation-failed"}
    if route.method == "POST":
        common[400] = {"invalid-request"}  # body length / unsupported idempotency
        common[413] = {"payload-too-large"}
    if route.service == "console":
        common.setdefault(400, set()).add("invalid-content-length")
        if route.method == "GET":
            common[400].add("request-body-not-supported")
        common[411] = {"content-length-required"}
        common[413] = {"payload-too-large"}
        common[503].add("management-api-unavailable")
    for status, codes in common.items():
        errors.setdefault(status, set()).update(codes)
    return {status: tuple(sorted(codes)) for status, codes in errors.items()}


def _qos_schema(scope):
    """Use the policy validator's closed grammar; every layer key is optional."""
    properties = {}
    for key, scopes in peer_policy._QOS_SCOPES.items():
        if scope not in scopes:
            continue
        if key == "telemetry_pause":
            value = {"type": "boolean"}
        elif key == "on_stale":
            value = {"type": "string", "enum": ["keep", "defaults"]}
        else:
            minimum, maximum = peer_policy._QOS_RANGES[key]
            value = {"type": "integer", "minimum": minimum, "maximum": maximum}
            if key in peer_policy._RATE_KEYS:
                value["anyOf"] = [{"const": 0}, {"minimum": peer_policy._MIN_RATE_BPS}]
            if key == "catalog_tick_s":
                value["multipleOf"] = 60
        properties[key] = value
    return {"type": "object", "properties": properties,
            "additionalProperties": False,
            "description": "Replace this layer with any supported subset; an empty object clears it. Cross-field and restricted-role semantics are validated by the policy transaction."}


def _role_name_schema():
    return {"type": "string", "pattern": peer_policy._ROLE_NAME_RE.pattern,
            "not": {"enum": sorted(peer_policy.RESERVED_ROLE_NAMES)}}


def _role_definition_schema():
    return {"type": "object", "additionalProperties": False, "properties": {
        "restricted": {"type": "boolean"}, "origin": {"type": "boolean"},
        "peers": {"type": "array", "items": _role_name_schema(),
                  "minItems": 1, "maxItems": peer_policy.MAX_ROLE_PEERS,
                  "uniqueItems": True, "x-iris-selfPeerRequired": True,
                  "description": "Must contain the role's {name} path value; missing self returns 409 role_isolated."},
        "nets": {"type": "array", "items": {"type": "string",
            "pattern": peer_policy.ROLE_NET_PATTERN,
            "description": "IPv4 address, CIDR or dotted netmask/hostmask. A decimal prefix allows at most %d digits, including leading zeroes; valid spelling is preserved." % peer_policy.ROLE_NET_MAX_PREFIX_DIGITS}},
        "on_stale": {"type": "string", "enum": ["keep", "defaults"]},
        "qos": _qos_schema("role")}}


def _swarm_peer_schema():
    """Explicit source-grouped tracker identity variants from telemetry._peer_row."""
    variants = []
    for kind in ("device", "service", "legacy"):
        tracker = {"type": "object", "additionalProperties": False,
            "required": ["principal_type", "role", "left", "last_seen", "progress"],
            "properties": {
                "principal_type": {"const": kind},
                "role": {"enum": ["seeder", "leecher"]},
                "left": {"type": ["integer", "null"]},
                "last_seen": {"type": ["number", "null"]},
                "progress": {"type": ["number", "null"], "minimum": 0, "maximum": 1}}}
        properties = {"ip": {"type": "string"}, "port": {"type": "integer"},
                      "tracker": tracker}
        required = ["ip", "port", "tracker"]
        if kind == "legacy":
            tracker["properties"]["participant_class"] = {"type": "string"}
            properties.update(device_id={"type": "null"},
                warning={"const": "legacy_unattributed"}, quarantine_available={"const": False})
        else:
            tracker["properties"]["principal_id"] = {"type": "string"}
            tracker["required"].append("principal_id")
            for name in ("device_observation", "server_observation", "latest_report",
                         "peer_policy", "peer_enforcement"):
                properties[name] = {"type": "object"}
            if kind == "device":
                required.append("device_id")
                properties["device_id"] = {"type": "string"}
                for name in ("model", "current_image_id", "stage_state"):
                    properties[name] = {"type": "string"}
                for name in ("staged_image_ids", "errored_image_ids"):
                    properties[name] = {"type": "array", "items": {"type": "string"}}
        variants.append({"type": "object", "additionalProperties": False,
                         "required": required, "properties": properties})
    return {"oneOf": variants}


def _blast_example():
    return {"member_delta": 1, "origin_access_lost": 0,
            "empty_permitted_sets": 0, "role_pairs_stopped": 0,
            "qos_changed": False, "requires_confirmation": True,
            "confirm_token": "candidate-bound-sha256"}


def _policy_write_example():
    return {"ok": True, "revision": 5, "candidate_revision": 5,
            "dry_run": True, **_blast_example()}


def _qos_example():
    # Representative final/derived values include each key in the shared grammar.
    import peer_policy
    doc = peer_policy.base_document()
    doc["roles"] = {"qos_default": {"per_peer_bps": 20000}}
    qos = peer_policy.explain_qos(doc, "edge-01")
    qos["numwant"].update(effective_ceiling=50, runtime_request_zero="disabled",
                         constraint_source="pinned-aria2-client")
    qos["announce_min_interval_s"].update(peerless_leecher_floor_s=120,
                                         constraint_source="pinned-aria2-client")
    qos["catalog_tick_s"].update(offline_horizon_s=600, heartbeat_always=True)
    return qos


def _explain_side(device_id):
    return {"principal": {"type": "device", "id": device_id}, "role": "boat",
            "acl_source": "role:boat", "acl_name": "role:boat",
            "decision": "permit", "matched_seq": 10,
            "role_unknown": False, "role_shadowed_by": None}


def _ref(name):
    return {"$ref": "#/components/schemas/" + name}


def _media(schema, example):
    return {"schema": schema, "example": example}


def _operation_name(route, suffix):
    words = re.sub(r"[^a-zA-Z0-9]+", " ", suffix).title().replace(" ", "")
    return route.service.title() + words


def _schema_for_example(example, title, required=None, field="",
                        credential_input=False):
    """Return a concrete JSON Schema for one documented wire example.

    This intentionally emits an inline, operation-named schema rather than a
    catch-all object.  Mature console values have a few forward-compatible
    extension fields, so response objects remain open while the fields that
    are guaranteed by the example are required.
    """
    if isinstance(example, bool):
        return {"type": "boolean"}
    if isinstance(example, int):
        return {"type": "integer"}
    if isinstance(example, float):
        return {"type": "number"}
    if example is None:
        if field in ("enabled",):
            return {"type": ["boolean", "null"]}
        if field in ("record",):
            return {"type": ["object", "null"]}
        if field == "last_reconciled_at":
            return {"type": ["number", "null"]}
        if field in ("limit", "certs", "at", "matched", "mismatched",
                     "not_in_feed", "finished_at", "rc", "issued_revision",
                     "matched_seq", "applied_revision"):
            return {"type": ["integer", "null"]}
        return {"type": ["string", "null"]}
    if isinstance(example, str):
        schema = {"type": "string"}
        lowered = field.lower()
        if lowered in ("password", "current", "new", "confirm",
                       "device_pass", "enable_secret", "key_passphrase"):
            schema["format"] = "password"
            if credential_input:
                schema["writeOnly"] = True
        elif credential_input and any(
                part in lowered for part in ("token", "secret", "grant")):
            schema["writeOnly"] = True
        elif lowered in ("url", "docs_url", "endpoint"):
            schema["format"] = "uri"
        return schema
    if isinstance(example, list):
        item = example[0] if example else "value"
        return {"type": "array",
                "items": _schema_for_example(
                    item, title + "Item", field=field.rstrip("s"),
                    credential_input=credential_input)}
    if isinstance(example, dict):
        required_fields = list(example) if required is None else list(required)
        return {
            "title": title,
            "type": "object",
            "properties": {
                key: _schema_for_example(
                    value, title + key.title(), field=key,
                    credential_input=credential_input)
                for key, value in example.items()
            },
            "required": required_fields,
            "additionalProperties": True,
        }
    raise TypeError("unsupported OpenAPI example value: %r" % (example,))


def _problem_variants(route, status):
    """Stable Problem codes this operation can actually emit at *status*.

    Authentication gates use service-specific codes so callers can distinguish
    a missing browser session from an unavailable tier/device credential. The
    mature handler still supplies the status-level code for business errors.
    """
    if _instruction_resource(route):
        return _instruction_problem_variants(route, status)
    suffix = _resource_suffix(route)
    if route.service == "artifact":
        if status == 403 and route.security == "legacyGuestShell":
            return (("artifact-forbidden", "Artifact forbidden"),)
        return {
            401: (("artifact-authentication-required",
                   "Artifact authentication required"),),
            403: (("artifact-resource-forbidden",
                   "Artifact resource forbidden"),
                  ("artifact-forbidden", "Artifact forbidden")),
            404: (("artifact-not-found", "Artifact not found"),),
            500: (("artifact-request-failed", "Artifact request failed"),),
            503: (("credential-store-unavailable",
                   "Credential store unavailable"),),
        }.get(status, (api_problem.STATUS_DEFAULTS[status],))
    if route.service == "catalog":
        direct = {
            401: (("catalog-authentication-required",
                   "Catalog authentication required"),),
            411: (("content-length-required", "Content-Length required"),),
            413: (("payload-too-large", "Payload too large"),),
            503: (("credential-store-unavailable",
                   "Credential store unavailable"),),
        }
        if status == 400:
            values = [("invalid-request", "Invalid request")]
            if suffix == "/v1/torrents/{image_id}":
                values.insert(0, ("invalid-tracker-auth-selector",
                                  "Invalid tracker authentication selector"))
            elif route.method != "GET":
                values[:0] = [
                    ("invalid-content-length", "Invalid Content-Length"),
                    ("invalid-request-body", "Invalid request body")]
            return tuple(values)
        return direct.get(status, (api_problem.STATUS_DEFAULTS[status],))
    if route.service == "telemetry":
        if status == 401:
            return (("observability-authentication-required",
                     "Observability authentication required"),) \
                if suffix == "/metrics" else (
                    ("management-authentication-required",
                     "Management authentication required"),)
        if status == 404:
            return (("route-not-found", "Route not found"),)
        if status == 503 and suffix == "/status":
            return (("telemetry-status-unavailable",
                     "Telemetry status unavailable"),)
    policy_errors = _policy_errors(route)
    if policy_errors is not None:
        return tuple((code, code.replace("_", " ").replace("-", " ").capitalize())
                     for code in policy_errors[status])
    if route.service in ("console", "management"):
        if status == 503 and route.path == \
                "/internal/v1/console-certificate":
            return (("console-certificate-unavailable",
                     "Console certificate unavailable"),)
        if status == 400 and route.path == \
                "/internal/v1/authorizations":
            return (("invalid-authorization-request",
                     "Invalid authorization request"),)
        if status == 401:
            values = []
            if route.service == "management":
                values.append(("management-authentication-required",
                               "Management authentication required"))
            if suffix == "/login":
                values.append(("authentication-required",
                               "Authentication required"))
            elif suffix != "/setup" and route.path != \
                    "/internal/v1/console-certificate":
                values.append(("console-session-required",
                               "Console session required"))
            return tuple(values) or (api_problem.STATUS_DEFAULTS[status],)
        if status == 403 and route.method in MUTATIONS and \
                suffix not in ("/login", "/setup"):
            return (("csrf-validation-failed", "CSRF validation failed"),
                    api_problem.STATUS_DEFAULTS[status])
        if status == 400 and route.service == "console":
            return (("invalid-content-length", "Invalid Content-Length"),
                    ("request-body-not-supported",
                     "Request body not supported"),
                    api_problem.STATUS_DEFAULTS[status])
        if status == 503 and route.service == "console":
            return (("management-api-unavailable",
                     "Management API unavailable"),
                    api_problem.STATUS_DEFAULTS[status])
        if status == 404:
            return (("resource-not-found", "Resource not found"),
                    ("route-not-found", "Route not found"))
    return (api_problem.STATUS_DEFAULTS[status],)


def _problem_response(route, status):
    variants = _problem_variants(route, status)
    documents = [
        api_problem.document(status, code, title)
        for code, title in variants
    ]
    media = {"schema": _ref("Problem")}
    if len(documents) == 1:
        media["example"] = documents[0]
    else:
        media["examples"] = {
            doc["code"]: {"value": doc} for doc in documents}
    response = {
        "description": " or ".join(title for _code, title in variants),
        "x-iris-problem-codes": [code for code, _title in variants],
        "content": {"application/problem+json": media},
    }
    if _instruction_resource(route):
        schemas = [{
            "type": "object", "required": ["type", "title", "status", "code"],
            "additionalProperties": False,
            "properties": {name: {"const": value} for name, value in doc.items()},
        } for doc in documents]
        media["schema"] = schemas[0] if len(schemas) == 1 else {"oneOf": schemas}
        response["headers"] = _instruction_headers(success=False)
        if status == 401:
            response["headers"]["WWW-Authenticate"] = {
                "schema": {"type": "string", "const": "Bearer"}, "example": "Bearer"}
        if status in (409, 429, 503):
            response["headers"]["Retry-After"] = {
                "schema": {"type": "integer", "minimum": 1},
                "example": 1 if status == 429 else 10,
                "description": "Computed seconds until one limiter token is available"
                               if status == 429 else "Retry after ten seconds",
            }
            if status != 429:
                response["headers"]["Retry-After"]["schema"]["const"] = 10
        return response
    if status in (429, 503):
        response["headers"] = {
            "Retry-After": {"description": "Seconds before a retry when known",
                            "schema": {"type": "integer", "minimum": 1}}}
    if status == 401 and route.service in (
            "artifact", "catalog", "telemetry", "management"):
        challenge = ('Basic realm="iris-artifacts", charset="UTF-8"'
                     if route.service == "artifact" else "Bearer")
        response.setdefault("headers", {})["WWW-Authenticate"] = {
            "description": "Authentication challenge for this service boundary",
            "schema": {"type": "string"},
            "example": challenge,
        }
    business_errors = _policy_business_errors(route)
    if business_errors is not None and status in business_errors:
        response.setdefault("headers", {})["ETag"] = {"schema": {"type": "string"}}
    return response


def _path_parameters(path):
    params = []
    for name in re.findall(r"\{([^}]+)\}", path):
        params.append({
            "name": name, "in": "path", "required": True,
            "description": ("Slash-separated path below the authenticated device artifact root"
                            if name == "artifact_path" else
                            "High-entropy, time-bounded Guest Shell enrollment filename"
                            if name == "legacy_artifact" else
                            "Opaque resource identifier"),
            "schema": ({
                "type": "string",
                "oneOf": [
                    {"pattern": r"^iris-agent-[A-Za-z0-9._:-]+-[0-9A-Fa-f]{32}\.conf$"},
                    {"pattern": r"^rpc-secret-[0-9A-Fa-f]{32}$"},
                ],
            } if name == "legacy_artifact" else
                {"type": "string", "minLength": 1}),
            "example": ("iris-agent.tgz" if name == "artifact_path" else
                        "iris-agent-edge-01-0123456789abcdef0123456789abcdef.conf"
                        if name == "legacy_artifact" else
                        "edge-01" if name == "device_id" else "example-id"),
        })
    return params


def _query_parameters(route):
    path = route.path
    suffix = _resource_suffix(route)
    params = []
    if _policy_mutation(route):
        params.append({"name": "dry_run", "in": "query", "required": False,
            "description": "1 previews the locked candidate without persistence; 0 commits after required confirmation.",
            "schema": {"type": "integer", "enum": [0, 1]}, "example": 1})
    if suffix == "/peer-policy/explain":
        params.extend({"name": key, "in": "query", "required": True,
            "description": "Bare device ID, device:<id>, or service:seeder. Requires one fresh, unambiguous durable IPv4 attribution; no inventory-IP fallback.",
            "schema": {"type": "string"}, "example": value}
            for key, value in (("a", "edge-01"), ("b", "service:seeder")))

    if route.service in ("console", "management") and suffix == "/devices":
        params.extend([
            {"name": "limit", "in": "query", "required": False,
             "description": "Page size; omit for the v1 whole-fleet compatibility response",
             "schema": {"type": "integer", "minimum": 1, "maximum": 1000},
             "example": 100},
            {"name": "offset", "in": "query", "required": False,
             "description": "Zero-based offset; paged results sort by device_id",
             "schema": {"type": "integer", "minimum": 0}, "example": 0},
            {"name": "q", "in": "query", "required": False,
             "description": "Case-insensitive device search", "schema": {"type": "string"},
             "example": "edge"},
        ])
        filter_specs = {
            "management_type": ({"type": "string", "enum": [
                "routed", "inband", "router-routed", "router-nat",
                "xr-host", "legacy"]}, "inband"),
            "platform": ({"type": "string", "enum": [
                "guestshell", "iox", "router", "xr-appmgr", "__none"]},
                "iox"),
            "cred": ({"type": "string"}, "default"),
            "telemetry": ({"type": "string", "enum": [
                "on", "off", "unknown"]}, "on"),
            "peer": ({"type": "string", "enum": [
                "quarantined", "not-quarantined"]}, "not-quarantined"),
            "status": ({"type": "string", "enum": [
                "onboarding", "undeploying", "waiting-heartbeat", "waiting-staging",
                "onboard-failed", "undeploy-failed", "deployed",
                "placement-failed", "image-failed", "copying", "staging",
                "unassigned", "enrolled", "not-enrolled", "offline",
                "__attention"]}, "deployed"),
        }
        for name, (schema, example) in filter_specs.items():
            params.append({
                "name": name, "in": "query", "required": False,
                "description": "Exact server-side device table filter",
                "schema": schema, "example": example})
    elif route.service in ("console", "management") and suffix == "/audit":
        params.extend([
            {"name": "limit", "in": "query", "required": False,
             "schema": {"type": "integer", "minimum": 1, "maximum": 500},
             "example": 200},
            {"name": "before_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788470400},
            {"name": "after_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788384000},
            {"name": "category", "in": "query", "required": False,
             "description": "Audit event category",
             "schema": {"type": "string"}, "example": "auth"},
        ])
    elif route.service in ("console", "management") and \
            suffix == "/audit/histogram":
        params.extend([
            {"name": "category", "in": "query", "required": False,
             "schema": {"type": "string"}, "example": "auth"},
            {"name": "buckets", "in": "query", "required": False,
             "schema": {"type": "integer", "minimum": 1, "maximum": 200},
             "example": 30},
            {"name": "window", "in": "query", "required": False,
             "description": "Seconds ending at server now; ignored when both bounds are present",
             "schema": {"type": "number", "exclusiveMinimum": 0},
             "example": 604800},
            {"name": "since_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788384000},
            {"name": "until_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788470400},
        ])
    elif route.service in ("console", "management") and \
            suffix == "/install-options":
        params.append({"name": "model", "in": "query", "required": False,
                       "description": "Device model used to derive supported install methods",
                       "schema": {"type": "string"}, "example": "IE-3400"})
    elif route.service in ("console", "management") and suffix == "/swarm":
        params.extend([
            {"name": "limit", "in": "query", "required": False,
             "description": "Peer page size; omit for the complete compatibility response",
             "schema": {"type": "integer", "minimum": 1, "maximum": 1000},
             "example": 100},
            {"name": "offset", "in": "query", "required": False,
             "schema": {"type": "integer", "minimum": 0}, "example": 0},
        ])
    elif route.service in ("console", "management") and suffix == "/deploy-logs":
        params.extend([
            {"name": "device_id", "in": "query", "required": False,
             "schema": {"type": "string"}, "example": "edge-01"},
            {"name": "after_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788384000},
            {"name": "before_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788470400},
        ])
    elif route.service in ("console", "management") and \
            suffix == "/deploy-logs/histogram":
        params.extend([
            {"name": "device_id", "in": "query", "required": False,
             "schema": {"type": "string"}, "example": "edge-01"},
            {"name": "buckets", "in": "query", "required": False,
             "schema": {"type": "integer", "minimum": 1, "maximum": 200},
             "example": 30},
            {"name": "window", "in": "query", "required": False,
             "schema": {"type": "number", "minimum": 60},
             "example": 604800},
            {"name": "since_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788384000},
            {"name": "until_ts", "in": "query", "required": False,
             "schema": {"type": "number"}, "example": 1788470400},
        ])
    elif route.service == "tracker":
        hash_parameter = {
            "name": "info_hash", "in": "query", "required": True,
            "description": "Percent-encoded binary SHA-1 info hash; exactly 20 bytes after URL decoding",
            "schema": {"type": "string", "x-iris-decodedLength": 20},
            "example": "01234567890123456789"}
        params.append(hash_parameter)
        if path == "/announce":
            params.extend([
                {"name": "peer_id", "in": "query", "required": False,
                 "description": "Percent-encoded peer id; absent becomes the empty compatibility id",
                 "schema": {"type": "string"},
                 "example": "-IR0001-012345678901"},
                {"name": "port", "in": "query", "required": False,
                 "description": "Listening peer port; absent defaults to 6881. An invalid port suppresses registration.",
                 "schema": {"type": "integer", "minimum": 1,
                            "maximum": 65535, "default": 6881},
                 "example": 6881},
                {"name": "left", "in": "query", "required": False,
                 "description": "Bytes remaining",
                 "schema": {"type": "integer", "minimum": 0},
                 "example": 1024},
                {"name": "event", "in": "query", "required": False,
                 "schema": {"type": "string", "enum": [
                     "started", "completed", "stopped"]},
                 "example": "started"},
                {"name": "numwant", "in": "query", "required": False,
                 "schema": {"type": "integer", "minimum": 0,
                            "default": 50}, "example": 50},
                {"name": "compact", "in": "query", "required": False,
                 "schema": {"type": "integer", "enum": [0, 1],
                            "default": 0}, "example": 1},
                {"name": "ip", "in": "query", "required": False,
                 "description": "Private/CGNAT IPv4 override honored only for an authenticated service principal; devices always use the socket source address",
                 "schema": {"type": "string", "format": "ipv4"},
                 "example": "10.0.0.10"},
            ])
        params.extend([
            {"name": "announce_token", "in": "query", "required": False,
             "deprecated": True,
             "description": "Guest Shell-only credential fallback. Bearer Authorization takes precedence and disables query fallback.",
             "schema": {"type": "string", "writeOnly": True}},
            {"name": "key", "in": "query", "required": False,
             "deprecated": True,
             "description": "Query credential accepted only when Authorization is absent.",
             "schema": {"type": "string", "writeOnly": True}},
        ])
    if route.service == "catalog" and path.startswith("/v1/torrents/"):
        params.append({
            "name": "X-IRIS-Tracker-Auth", "in": "header", "required": False,
            "description": "Set exactly to bearer by unified IOx/XR agents for a token-free announce URL. Omit for Guest Shell query-auth torrents.",
            "schema": {"type": "string", "const": "bearer"},
            "example": "bearer",
        })
    if _instruction_resource(route):
        params.append({
            "name": "If-None-Match", "in": "header", "required": False,
            "schema": {"type": "string"},
            "description": "RFC 9110 weak comparison for GET: accepts a weak or strong tag, a comma-separated list, or wildcard *. Multiple field lines form one list. Invalid syntax and nonmatches return the ordinary response. Authentication, limiter admission and current state/key validation precede matching.",
            "example": 'W/"sha256-' + "0" * 64 + '"',
        })
    return params


def _security(route):
    name = route.security
    mapping = {
        "none": [],
        # These custom HTTP scheme tokens classify authentication for generated
        # clients; x-iris-in and the request schemas state that their values
        # are carried in the JSON body rather than Authorization.
        "consolePassword": [{"consolePassword": []}],
        "setupGrant": [{"setupGrant": []}],
        "consoleSession": [{"consoleSession": []}],
        "managementBearer": [{"managementBearer": []}],
        "managementBearer+consolePassword": [
            {"managementBearer": [], "consolePassword": []}],
        "managementBearer+setupGrant": [
            {"managementBearer": [], "setupGrant": []}],
        "managementBearer+consoleSession": [
            {"managementBearer": [], "consoleSession": []}],
        "deviceBearer": [{"deviceBearer": []}],
        "announceBearer": [{"announceBearer": []}],
        "announceBearerOrLegacyQuery": [
            {"announceBearer": []}, {"legacyAnnounceToken": []},
            {"legacyTrackerKey": []}],
        "observabilityBearer": [{"observabilityBearer": []}],
        "artifactBasic": [{"artifactBasic": []}],
        "guestShellAnonymousStatic": [],
        # The credential is part of the required high-entropy path segment,
        # not an HTTP authentication scheme representable by OpenAPI.
        "legacyGuestShell": [],
    }
    result = mapping[name]
    if route.method in MUTATIONS and "consoleSession" in name:
        result = [dict(result[0], csrfHeader=[])]
    return result


def _resource_suffix(route):
    for prefix in ("/api/v1", "/internal/v1"):
        if route.path.startswith(prefix):
            return route.path[len(prefix):] or "/"
    return route.path


# Every JSON mutation has an explicit body example and a list of fields the
# handler actually requires.  ``required_body`` is false only for operations
# whose established v1 wire form permits an empty body.
_JSON_REQUESTS = {
    "/peer-policy/roles/{name}": ({"restricted": True, "peers": ["boat"],
        "origin": True, "nets": [], "on_stale": "keep", "qos": {},
        "confirm_token": "candidate-bound-sha256"}, (), True),
    "/peer-policy/qos": ({"qos": {"numwant": 25}, "role": "boat",
        "confirm_token": "candidate-bound-sha256"}, ("qos",), True),
    "/devices/{device_id}/role": ({"role": "boat",
        "confirm_token": "candidate-bound-sha256"}, ("role",), True),
    "/devices/bulk-role": ({"device_ids": ["edge-01", "edge-02"], "role": "boat",
        "confirm_token": "candidate-bound-sha256"}, ("device_ids", "role"), True),
    "/peer-policy/quarantine/{device_id}": (
        {"quarantined": True, "if_revision": 4},
        ("quarantined", "if_revision"), True),
    "/login": ({"username": "admin", "password": "operator-entered-password"},
               ("username", "password"), True),
    "/setup": ({"username": "admin", "password": "new-administrator-password",
                "setup_grant": "short-lived-one-time-grant"},
               ("username", "password", "setup_grant"), True),
    "/logout": ({}, (), False),
    "/images/import": ({"path": "/srv/images/ios-xe/example.bin"},
                       ("path",), True),
    "/images/{image_id}/release-quarantine": (
        {"override": False, "confirm_text": ""}, (), False),
    "/image-verification/refresh": ({}, (), False),
    "/devices": ({"device_id": "edge-01", "device_ip": "192.0.2.10",
                  "management_type": "inband", "model": "C9300-48P",
                  "credential_profile_id": "default"},
                 ("device_id", "device_ip", "management_type"), True),
    "/devices/bulk-credential": (
        {"device_ids": ["edge-01"], "credential_profile_id": "default"},
        ("device_ids", "credential_profile_id"), True),
    "/devices/{device_id}/assign": (
        {"image_ids": ["image-01"], "expect_image_ids": []},
        (), False),
    "/devices/{device_id}/credential": (
        {"credential_profile_id": "default"},
        ("credential_profile_id",), True),
    "/devices/{device_id}/platform": ({"platform": "iox"},
                                      ("platform",), True),
    "/devices/{device_id}/forget-host-key": ({}, (), False),
    "/devices/{device_id}/request-report": ({}, (), False),
    "/devices/{device_id}/adopt": ({"acknowledge_adopt": True},
                                   ("acknowledge_adopt",), True),
    "/devices/{device_id}/onboard": (
        {"telemetry": True, "telemetry_stream": False}, (), False),
    "/devices/{device_id}/undeploy": ({"force": False}, (), False),
    "/credentials": (
        {"id": "default", "name": "Default devices",
         "device_user": "operator", "device_pass": "device-password",
         "enable_secret": "enable-password"},
        ("id", "name", "device_user", "device_pass"), True),
    "/onboard/jobs/{job_id}/abort": ({}, (), False),
    "/onboard/cancel-queued": ({"job_ids": ["job-01"]}, (), False),
    "/telemetry/stream": ({"every": 4, "pause": False}, (), False),
    "/settings/password": (
        {"current": "current-password", "new": "new-password",
         "confirm": "new-password"}, ("current", "new", "confirm"), True),
    "/settings/sessions/revoke-others": ({}, (), False),
    "/settings/image-verification": ({"mode": "daily", "hour_utc": 3},
                                     ("mode",), True),
    "/settings/audit-export": (
        {"host": "audit.example", "port": 22, "user": "iris",
         "path": "/archive/iris", "age_recipient": "age1example",
         "auto": True, "password": "transport-password"},
        ("host", "user", "path", "age_recipient"), True),
    "/settings/audit-export/run": ({}, (), False),
    "/settings/ca-trust": ({"url": None, "auto": True}, (), False),
    "/settings/ca-trust/refresh": ({}, (), False),
    "/settings/telemetry-destination": (
        {"endpoint": None, "enabled": None}, (), False),
    "/settings/gui-cert": (
        {"cert_pem": "-----BEGIN CERTIFICATE-----\n...",
         "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
         "key_passphrase": "optional-passphrase"},
        ("cert_pem", "key_pem"), True),
    "/settings/trust": ({"pem": "-----BEGIN CERTIFICATE-----\n..."},
                        ("pem",), True),
    "/internal/v1/authorizations": (
        {"method": "POST", "path": "/internal/v1/devices"},
        ("method", "path"), True),
    "/v1/devices/{device_id}/heartbeat": (
        {"agent_version": "2026.09.04", "telemetry_enabled": True,
         "telemetry_stream_enabled": True}, (), True),
    "/v1/devices/{device_id}/telemetry": (
        {"schema": "v2", "image_id": "image-01", "state": "complete",
         "timestamp": 1788470400}, ("schema", "image_id"), True),
    "/v1/devices/{device_id}/token-refresh": ({}, (), False),
}


def _request_body(route):
    if route.method == "DELETE" and _policy_mutation(route):
        return {"required": False, "content": {"application/json": _media(
            {"type": "object", "properties": {"confirm_token": {"type": ["string", "null"]}},
             "additionalProperties": False}, {"confirm_token": "candidate-bound-sha256"})}}
    if route.method not in ("POST", "PUT", "PATCH"):
        return None
    path = route.path
    suffix = _resource_suffix(route)
    if "/images/upload/" in path or suffix == "/image-verification/offline":
        return {"required": True, "content": {
            "application/octet-stream": _media(
                {}, "<binary payload>")}}
    if suffix == "/devices/import-csv":
        return {"required": True, "content": {"text/csv": _media(
            {"type": "string"},
            "device_id,device_ip\nedge-01,192.0.2.10\n")}}
    lookup = path if route.service == "catalog" else suffix
    if path == "/internal/v1/authorizations":
        lookup = path
    try:
        example, required, required_body = _JSON_REQUESTS[lookup]
    except KeyError as exc:
        raise AssertionError("missing request contract for %s %s" %
                             (route.method, route.path)) from exc
    title = _operation_name(route, suffix) + "Request"
    schema = _schema_for_example(
        example, title, required=required, credential_input=True)
    if route.service == "catalog" and path.endswith("/heartbeat"):
        return {"required": required_body, "content": {
            "application/json": _instruction_attestation_request(schema, example)}}
    if suffix == "/settings/image-verification":
        schema["properties"]["mode"].update(
            {"enum": ["off", "daily", "weekly"]})
        schema["properties"]["hour_utc"].update(
            {"minimum": 0, "maximum": 23})
    elif suffix == "/settings/telemetry-destination" and \
            "endpoint" in schema["properties"]:
        schema["properties"]["endpoint"]["format"] = "uri"
    elif suffix == "/settings/ca-trust":
        schema["properties"]["url"]["format"] = "uri"
    elif suffix == "/devices/{device_id}/assign":
        singular = {"image_id": "image-01", "expect_image_ids": []}
        schema["properties"]["image_id"] = {"type": ["string", "null"]}
        schema["description"] = (
            "image_ids is the preferred ordered set and wins when both forms "
            "are present. image_id is the singular v1 compatibility form. "
            "An empty object, empty image_ids, or null image_id unassigns.")
        return {"required": required_body,
                "content": {"application/json": {
            "schema": schema,
            "examples": {
                "orderedSet": {"value": example},
                "singularCompatibility": {"value": singular},
                "unassign": {"value": {}},
            }}}}
    # Credential-bearing request objects are closed: misspellings must not be
    # silently accepted as alternate credentials.
    if suffix in ("/login", "/setup") or path.endswith("/authorizations"):
        schema["additionalProperties"] = False
    if _policy_mutation(route):
        schema["additionalProperties"] = False
        schema["properties"]["confirm_token"]["type"] = ["string", "null"]
        if suffix == "/peer-policy/roles/{name}":
            schema["properties"].update(_role_definition_schema()["properties"])
        if suffix == "/peer-policy/qos":
            schema["properties"]["qos"] = _qos_schema("global")
            schema["allOf"] = [{"if": {"required": ["role"], "properties": {
                "role": {"type": "string"}}}, "then": {"properties": {"qos": _qos_schema("role")}}}]
        if "role" in schema["properties"]:
            schema["properties"]["role"]["type"] = ["string", "null"]
        if "device_ids" in schema["properties"]:
            schema["properties"]["device_ids"].update(minItems=1, maxItems=10000)
    return {"required": required_body,
            "content": {"application/json": _media(schema, example)}}


def _json_success_example(route):
    """Return the actual stable fields for a JSON success response."""
    suffix = _resource_suffix(route)

    exact = {
        "/peer-policy/roles": {"revision": 4, "degraded": False, "fail_closed": False,
            "roles": {"boat": {"restricted": True, "peers": ["boat"], "origin": True}}},
        "/peer-policy/roles/{name}": _policy_write_example(),
        "/peer-policy/qos": _policy_write_example(),
        "/devices/{device_id}/role": {**_policy_write_example(), "partial": False,
            "applied": 1, "failed": {}, "direction": "tighten",
            "role_drift": {"count": 0, "device_ids": [], "truncated": False}},
        "/devices/bulk-role": {**_policy_write_example(), "partial": False,
            "applied": 2, "failed": {}, "direction": "tighten",
            "role_drift": {"count": 0, "device_ids": [], "truncated": False}},
        "/devices/{device_id}/effective-qos": {"revision": 4, "degraded": False,
            "fail_closed": False, "device_id": "edge-01",
            "delivery_state": "pre-instructions", "qos": _qos_example()},
        "/peer-policy/explain": {"revision": 4, "degraded": False,
            "fail_closed": False, "a": _explain_side("edge-01"),
            "b": _explain_side("edge-02"), "mutual": True},
        "/peer-policy": {
            "schema": 1, "revision": 4, "degraded": False,
            "fail_closed": False,
            "quarantine": {"reserved": True,
                           "description": "reserved policy value"},
            "quarantine_assignments": ["edge-02"],
            "roles_supported": True, "roles_present": True,
            "roles": {"defined": 1, "restricted": 1, "members": {"boat": 2}},
            "role_drift": {"count": 0, "device_ids": [], "truncated": False},
            "outbox": {"unacknowledged": 1, "capacity": 256},
            "origin_qos": {"state": None, "global_option_count": 0,
                "target_download_count": 0, "applied_download_count": 0,
                "last_reconciled_at": None, "last_error": None},
            "fleet_rollup": {"issued_revision": None, "applied": {},
                "states": {"pre-instructions": 2}},
            "enforcement": {"state": None, "stale": False,
                            "desired_ip_count": 1, "conflict_count": 0}},
        "/peer-policy/quarantine/{device_id}": {
            "ok": True, "revision": 5, "quarantined": True},
        "/audit": {"events": [{"ts": 1788470400, "event": "login",
                                  "category": "auth", "result": "ok"}]},
        "/audit/histogram": {"buckets": [{"start": 1788470400, "count": 1}],
                              "now": 1788474000, "bucket_seconds": 120},
        "/session": {"username": "admin", "csrf": "session-csrf-token"},
        "/setup": {"ok": True},
        "/logout": {"ok": True},
        "/images": {"images": [{"id": "image-01", "filename": "image.bin",
                                   "size": 1048576, "sha256": "00" * 32}]},
        "/images/importable": {
            "importable": [{"path": "/srv/images/ios-xe/image.bin",
                             "filename": "image.bin", "size": 1048576}],
            "skipped": []},
        "/images/import": {"job_id": "job-01"},
        "/images/upload/{filename}": {"job_id": "job-01"},
        "/images/jobs/{job_id}": {"id": "job-01", "state": "done",
                                        "filename": "image.bin",
                                        "image_id": "image-01",
                                        "message": "",
                                        "finished_at": 1788470412,
                                        "verification": {
                                            "outcome": "ok",
                                            "image_state": "verified",
                                            "matched": 1,
                                            "mismatched": 0,
                                            "not_in_feed": 0}},
        "/images/{image_id}": {"deleted": True, "warnings": []},
        "/images/{image_id}/release-quarantine": {
            "released": True, "override": False, "state": "verified",
            "seeding_resumed": True},
        "/image-verification/offline": {
            "outcome": "ok", "matched": 1,
            "mismatched": 0, "not_in_feed": 0},
        "/image-verification/refresh": {
            "outcome": "ok", "matched": 1,
            "mismatched": 0, "not_in_feed": 0},
        "/devices/import-csv": {"imported": 1, "new": 1,
                                 "updated": 0, "skipped": 0},
        "/devices/bulk-credential": {"ok": True, "applied": 1,
                                      "failed": {}},
        "/devices/{device_id}/plan": {
            "plan": {"plan_hash": "sha256:example",
                     "resolved": {"platform": "iox",
                                  "management_type": "inband"}}},
        "/devices/{device_id}/reports": {
            "reports": [{
                "v": 2, "schema": "v2",
                "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
                "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
                "report_request_id": None, "report_created_at": 1788470300,
                "received_at": 1788470400,
                "image_id": "image-01", "event": "staging-complete",
                "stage_state": "ready",
                "content_sha256": {"state": "verified", "algo": "sha256"},
                "ios_copy_verify": {"state": "ok"},
                "sampling": {"sampling_class": "good"},
                "peers": [], "peers_total": 0, "peers_rows_dropped": 0,
                "peers_truncated": False, "peers_saturated": False}, {
                "schema": "v1", "event": "seeding-only",
                "image_id": "image-01", "peers": [], "peers_total": 0,
                "peers_rows_dropped": 0,
                "received_at": 1788470400,
                "_event_id": "0123456789abcdef0123456789abcdef"}]},
        "/devices/{device_id}/deployment": {
            "record": None, "total": 0},
        "/devices/{device_id}/assign": {"ok": True},
        "/devices/{device_id}/credential": {"ok": True},
        "/devices/{device_id}/platform": {"ok": True},
        "/devices/{device_id}/forget-host-key": {
            "ok": True, "peer": "192.0.2.10"},
        "/devices/{device_id}/request-report": {
            "ok": True, "expires_at": 1788474000},
        "/devices/{device_id}/adopt": {"record_id": "record-01"},
        "/devices/{device_id}/onboard": {"job_id": "job-01"},
        "/devices/{device_id}/undeploy": {"job_id": "job-01"},
        "/install-options": {"options": ["guestshell", "iox"]},
        "/credentials": {"profiles": [{"id": "default",
                                          "name": "Default devices",
                                          "device_user": "operator"}]},
        "/credentials/{credential_id}": {"deleted": True},
        "/onboard/jobs": {"jobs": [{"id": "job-01", "state": "running"}],
                            "max_concurrent": 4, "now": 1788470400},
        "/onboard/jobs/{job_id}": {"id": "job-01", "state": "running",
                                         "device_id": "edge-01"},
        "/onboard/jobs/{job_id}/abort": {"aborted": True},
        "/onboard/cancel-queued": {"cancelled": 1},
        "/deploy-logs": {"logs": [{
            "file": "1788470400-edge-01-onboard-job-01.log",
            "device_id": "edge-01", "action": "onboard",
            "state": "done", "rc": 0, "finished_at": 1788470400,
            "size": 1024}]},
        "/deploy-logs/histogram": {
            "buckets": [{"start": 1788470400, "count": 1}],
            "now": 1788474000},
        "/overview": {
            "images": 1, "devices": 1, "assigned": 1, "staged": 1,
            "staging_now": 0, "awaiting_heartbeat": 0,
            "rollout": [{"image_id": "image-01", "filename": "image.bin",
                         "assigned": 1, "staged": 1}],
            "swarm_map_url": "/swarmmap"},
        "/swarm": {
            "now": 1788470400.0,
            "server": {
                "host": "192.0.2.1",
                "server_observation": {
                    "observed_at": 1788470400, "rpc_up": True,
                    "unavailable": False, "aria_session_id": "session-01"}},
            "images": [{
                "image": "image.bin", "info_hash": "00" * 20,
                "total_bytes": 1048576, "seeders": 1, "leechers": 0,
                "peers": [{"device_id": "edge-01", "ip": "192.0.2.10", "port": 6881,
                           "tracker": {"principal_type": "device", "principal_id": "edge-01",
                                       "role": "seeder", "left": 0, "last_seen": 1788470400.0,
                                       "progress": 1.0}}]}]},
        "/telemetry/health": {
            "ok": True,
            "otlp_export": {"state": "healthy", "signals": {}}},
        "/telemetry/stream": {"ok": True, "stream_every": 4,
                               "stream_pause": False},
        "/settings": {"admin_username": "admin", "trust": [],
                        "host_ip": "192.0.2.10",
                        "console_url": "https://console.example.com:8080",
                        "gui_cert": {
                            "source": "built-in", "subject": "CN=console.example.com",
                            "issuer": "CN=IRIS CA",
                            "not_after": "Sep 4 00:00:00 2027 GMT",
                            "fingerprint_sha256": "00" * 32},
                        "telemetry_destination": {
                            "endpoint": None, "enabled": None,
                            "source": "env",
                            "effective_endpoint":
                                "https://collector.example:4318",
                            "effective_enabled": True}},
        "/settings/password": {"ok": True},
        "/settings/sessions/revoke-others": {"revoked": 2},
        "/settings/setup-status": {
            "admin": {"state": "ok", "username": "admin"},
            "telemetry": {"state": "ok", "endpoint":
                          "https://collector.example:4318"},
            "packages": {"state": "ok",
                         "reference_fingerprint": "00:" * 31 + "00",
                         "items": [{"name": "iris-amd64.tar",
                                    "state": "ok",
                                    "fingerprint": None,
                                    "built_at": 1788470400,
                                    "detail": "Package bytes match build provenance",
                                    "remedy": "tools/provision-iox-packages.sh",
                                    "provenance": {
                                        "canonical_index_digest":
                                            "sha256:" + "00" * 32,
                                        "canonical_archive_sha256":
                                            "11" * 32,
                                        "canonical_source_sha256":
                                            "22" * 32}}],
                         "remedy": "tools/provision-iox-packages.sh"},
            "image_verification": {"state": "ok"}},
        "/settings/image-verification": {
            "mode": "daily", "hour_utc": 3,
            "last_run": {"at": None, "source": None, "outcome": None,
                         "matched": None, "mismatched": None,
                         "not_in_feed": None}},
        "/settings/audit-export": {"ok": True},
        "/settings/audit-export/run": {"job_id": "job-01"},
        "/settings/audit-export/run/{job_id}": {
            "state": "running", "detail": ""},
        "/settings/ca-trust": {
            "ok": True, "ca_trust": {
                "url": "https://example.invalid/ca.pem", "auto": True}},
        "/settings/ca-trust/refresh": {"job": "job-01"},
        "/settings/ca-trust/refresh/{job_id}": {
            "state": "running", "detail": "", "certs": None},
        "/settings/telemetry-destination": {
            "ok": True, "endpoint": None, "enabled": None},
        "/settings/gui-cert": {
            "gui_cert": {
                "source": "custom", "subject": "CN=iris.example",
                "issuer": "CN=IRIS CA", "not_after": "Sep 4 00:00:00 2027 GMT",
                "fingerprint_sha256": "00" * 32},
            "applied": True, "note": None},
        "/settings/trust": {
            "entry": {"name": "ca-example.pem", "subject": "CN=Example CA",
                      "fingerprint_sha256": "00" * 32}},
        "/settings/trust/{name}": {"deleted": True},
        "/help": {"version": "2026.09.04", "deployment_id": "deployment-01",
                  "docs_url": "https://cisco-open.github.io/intelligent-release-image-staging/docs/",
                  "guides": {"device": "/help-device.html",
                             "server": "/help-server.html"}},
        "/v1/images": {"images": [{"id": "image-01",
                                      "filename": "image.bin",
                                      "size": 1048576,
                                      "sha256": "00" * 32}]},
        "/v1/images/{image_id}": {"id": "image-01", "filename": "image.bin",
                                          "size": 1048576,
                                          "sha256": "00" * 32},
        "/v1/devices/{device_id}/policy": {
            "approved_image_id": None, "approved_image_ids": ["image-01"],
            "plans": {"image-01": {
                "plan_id": "0123456789abcdef0123456789abcdef",
                "transfer_id": "fedcba9876543210fedcba9876543210"}}},
        "/v1/devices/{device_id}/heartbeat": {
            "ok": True, "stream_every": 4, "stream_pause": False},
        "/v1/devices/{device_id}/telemetry": {"ok": True},
        "/v1/devices/{device_id}/token-refresh": {
            "catalog_token": "replacement-catalog-token",
            "expires_at": 1788556800},
        "/status": {"ok": True,
                    "otlp_export": {"state": "healthy", "signals": {}}},
    }
    if suffix == "/login":
        # The two success shapes are intentionally handled by _success(): a
        # configured login establishes a session, while first-run auth returns
        # only a short-lived one-use setup grant.
        return None
    if suffix == "/devices" and route.method == "GET":
        return {"devices": [{"device_id": "edge-01",
                              "device_ip": "192.0.2.10"}],
                "total": 1, "offset": 0, "limit": None,
                "revision": 7, "now": 1788470400}
    if suffix == "/devices" and route.method == "POST":
        return {"device": {"device_id": "edge-01",
                            "device_ip": "192.0.2.10",
                            "management_type": "inband"}}
    if suffix == "/devices/{device_id}" and route.method == "DELETE":
        return {"deleted": True, "degraded": []}
    if suffix == "/credentials" and route.method == "POST":
        return {"profile": {"id": "default", "name": "Default devices",
                            "device_user": "operator"}}
    if suffix in ("/settings/audit-export",
                  "/settings/telemetry-destination") and route.method == "DELETE":
        return {"deleted": True}
    if suffix == "/settings/gui-cert" and route.method == "DELETE":
        return {"deleted": True,
                **({"applied": True, "note": None}
                   if route.service == "console" else {}),
                "gui_cert": {
                    "source": "built-in", "subject": "CN=iris.example",
                    "issuer": "CN=IRIS CA",
                    "not_after": "Sep 4 00:00:00 2027 GMT",
                    "fingerprint_sha256": "00" * 32}}
    try:
        return exact[suffix]
    except KeyError as exc:
        raise AssertionError("missing success contract for %s %s" %
                             (route.method, route.path)) from exc


def _success(route):
    path = route.path
    suffix = _resource_suffix(route)
    if _instruction_resource(route):
        artifact = "IRIS-KEYLIST/1" if path == INSTRUCTION_RESOURCES[1] else "IRIS-INSTR/1"
        return "200", {
            "description": "Exact " + artifact + " framed bytes",
            "headers": _instruction_headers(),
            "content": {"application/octet-stream": _media({}, "<" + artifact + " bytes>")},
        }
    if path.endswith("/authorizations"):
        return "204", {"description": "Headers authorized; no response body"}
    if path.endswith("/console-certificate"):
        return "200", {
            "description": "Active custom console identity; 204 selects the separately mounted default",
            "headers": {"X-IRIS-Certificate-Source": {
                "schema": {"type": "string", "enum": ["custom", "built-in"]}}},
            "content": {"application/x-pem-file": _media(
                {"type": "string"}, "<certificate and private key PEM>")}}
    if route.service == "tracker":
        return "200", {"description": "BEP 3 bencoded tracker response",
                       "content": {"text/plain": _media(
                           {},
                           "d8:intervali30ee")}}
    if route.service == "artifact":
        headers = ({"Deprecation": {
            "schema": {"type": "boolean", "const": True},
            "description": "Present on the Guest Shell compatibility surface"}}
            if route.security in ("legacyGuestShell",
                                  "guestShellAnonymousStatic") else {})
        if route.path.startswith("/staging/") or "{artifact_path}" in route.path:
            headers["Cache-Control"] = {
                "schema": {"type": "string", "const": "private, no-store"},
                "description": "Present whenever the resolved artifact is under staging"}
        response = {
            "description": "Artifact metadata" if route.method == "HEAD"
                           else "Artifact bytes",
            "headers": headers,
        }
        if route.method != "HEAD":
            response["content"] = {"application/octet-stream": _media(
                {}, "<artifact bytes>")}
        return "200", response
    if route.service == "catalog" and path.startswith("/v1/torrents/"):
        return "200", {
            "description": "Device-personalized BitTorrent metainfo",
            "headers": {
                "Cache-Control": {"schema": {"type": "string",
                                               "const": "private, no-store"}},
                "Vary": {"schema": {"type": "string",
                                      "const": "Authorization, X-IRIS-Tracker-Auth"}}},
            "content": {"application/x-bittorrent": _media(
                {}, "<bencoded torrent>")}}
    if path.endswith("/metrics"):
        return "200", {"description": "Prometheus text exposition",
                       "content": {"text/plain": _media(
                           {"type": "string"}, "iris_tracker_peers 2\n")}}
    if path.endswith("/swarmmap"):
        return "200", {"description": "Authenticated HTML application",
                       "content": {"text/html": _media(
                           {"type": "string"}, "<!doctype html>...")}}
    if path.endswith("/stream") and "/jobs/" in path:
        return "200", {"description": (
            "Job log lines as unnamed text data events, with keepalive comments. "
            "An end event carries done, error, cancelled, idle, or unknown. "
            "Each connection replays the retained lines from the start; "
            "Last-Event-ID is not supported."),
                       "content": {"text/event-stream": {
                           # OpenAPI 3.2 validates parsed events individually;
                           # keepalive comments are not dispatched events.
                           "itemSchema": {
                               "type": "object", "required": ["data"],
                               "properties": {
                                   "data": {"type": "string"},
                                   "event": {"enum": ["message", "end"]},
                               },
                               "if": {"required": ["event"], "properties": {
                                   "event": {"const": "end"}}},
                               "then": {"properties": {"data": {
                                   "enum": ["done", "error", "cancelled",
                                            "idle", "unknown"]}}},
                           },
                           "examples": {"completed": {
                               "summary": "A log line followed by completion",
                               "serializedValue": (
                                   "data: onboard complete: 192.0.2.10\n\n"
                                   "event: end\ndata: done\n\n"),
                           }},
                       }}}
    if path.endswith("/deploy-logs/{filename}"):
        return "200", {"description": "Deployment log text",
                       "content": {"text/plain": _media(
                           {"type": "string"}, "onboard started\n")}}
    if path.endswith("export-csv") or path.endswith("example-csv"):
        return "200", {"description": "CSV document",
                       "content": {"text/csv": _media(
                           {"type": "string"}, "device_id,device_ip\n")}}
    if path.endswith("/healthz") or path.endswith("/readyz"):
        return "200", {"description": "Non-disclosing probe result",
                       "content": {"application/json": _media(
                           _ref("Health"), {"ok": True})}}
    if suffix == "/login":
        configured = {"username": "admin", "csrf": "session-csrf-token"}
        initial = {"setup": True,
                   "setup_grant": "short-lived-one-time-grant"}
        configured_schema = _schema_for_example(
            configured, _operation_name(route, suffix) + "Session")
        initial_schema = _schema_for_example(
            initial, _operation_name(route, suffix) + "SetupGrant")
        configured_schema["additionalProperties"] = False
        initial_schema["additionalProperties"] = False
        return "200", {
            "description": "Session credentials, or a one-use setup grant before the first administrator exists",
            "headers": {"Set-Cookie": {
                "description": "Present only for a configured administrator login",
                "schema": {"type": "string"}}},
            "content": {"application/json": {
                "schema": {"oneOf": [configured_schema, initial_schema]},
                "examples": {
                    "configured": {"value": configured},
                    "firstRun": {"value": initial}}}}}
    if suffix == "/images/jobs/{job_id}":
        # Publish jobs deliberately expose the durable publish and the
        # follow-on Cisco hash reconciliation as separate phases.  A schema
        # inferred from only the terminal success example is too narrow: the
        # same polling endpoint also returns nullable fields while publishing,
        # a compact running-verification object, and terminal publish or
        # verification failures.  Keep those wire shapes explicit here.
        title = _operation_name(route, suffix) + "Response"
        image_state = {
            "type": ["string", "null"],
            "enum": ["verified", "mismatch", "not_in_feed", None],
        }
        verification_ok = {
            "title": title + "VerificationSuccess",
            "type": "object",
            "properties": {
                "outcome": {"type": "string", "const": "ok"},
                "image_state": image_state,
                "matched": {"type": ["integer", "null"], "minimum": 0},
                "mismatched": {"type": ["integer", "null"], "minimum": 0},
                "not_in_feed": {"type": ["integer", "null"], "minimum": 0},
            },
            "required": ["outcome", "image_state", "matched",
                         "mismatched", "not_in_feed"],
            "additionalProperties": False,
        }
        verification_failure = {
            "title": title + "VerificationFailure",
            "type": "object",
            "properties": {
                "outcome": {"type": "string",
                            "enum": ["fail", "already_running"]},
                "image_state": image_state,
                "detail": {"type": "string"},
            },
            "required": ["outcome", "image_state", "detail"],
            "additionalProperties": False,
        }
        verification_running = {
            "title": title + "VerificationRunning",
            "type": "object",
            "properties": {
                "outcome": {"type": "string", "const": "running"},
                "image_state": image_state,
            },
            "required": ["outcome", "image_state"],
            "additionalProperties": False,
        }
        common = {
            "id": {"type": "string"},
            "filename": {"type": "string"},
            "message": {"type": "string"},
            "started_at": {"type": "integer"},
        }
        required = ["id", "state", "filename", "message", "image_id",
                    "started_at", "finished_at", "verification"]

        def phase_schema(name, state, image_id, finished_at, verification):
            properties = dict(common)
            properties.update({
                "state": {"type": "string", "const": state},
                "image_id": image_id,
                "finished_at": finished_at,
                "verification": verification,
            })
            return {
                "title": title + name,
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": True,
            }

        nullable_string = {"type": ["string", "null"]}
        null_only = {"type": "null"}
        publishing_schema = phase_schema(
            "Publishing", "publishing", null_only, null_only, null_only)
        verifying_schema = phase_schema(
            "Verifying", "verifying", {"type": "string"}, null_only,
            verification_running)
        done_schema = phase_schema(
            "Done", "done", {"type": "string"}, {"type": "integer"},
            {"oneOf": [verification_ok, verification_failure, null_only]})
        error_schema = phase_schema(
            "Error", "error", nullable_string, {"type": "integer"},
            null_only)

        publishing = {
            "id": "job-01", "state": "publishing", "filename": "image.bin",
            "message": "", "image_id": None, "started_at": 1788470400,
            "finished_at": None, "verification": None,
        }
        verifying = dict(
            publishing, state="verifying", image_id="image-01",
            verification={"outcome": "running", "image_state": None})
        verified = dict(
            verifying, state="done", finished_at=1788470412,
            verification={"outcome": "ok", "image_state": "verified",
                          "matched": 1, "mismatched": 0,
                          "not_in_feed": 0})
        verification_failed = dict(
            verified,
            message="published, but Cisco hash verification did not complete",
            verification={"outcome": "fail", "image_state": None,
                          "detail": "feed unavailable"})
        publish_failed = dict(
            publishing, state="error", message="publish failed",
            finished_at=1788470401)
        return "200", {
            "description": (
                "Current publish phase and, after the durable publish, the "
                "Cisco Bulk Hash reconciliation result"),
            "content": {"application/json": {
                "schema": {"oneOf": [publishing_schema, verifying_schema,
                                     done_schema, error_schema]},
                "examples": {
                    "publishing": {"value": publishing},
                    "verifying": {"value": verifying},
                    "verified": {"value": verified},
                    "verificationFailed": {"value": verification_failed},
                    "publishFailed": {"value": publish_failed},
                },
            }},
        }
    if suffix == "/swarm":
        normal = _json_success_example(route)
        paged = dict(normal, peers_total=1, peers_offset=0, peers_limit=100)
        unavailable = {"peers": [], "error": "swarm data unavailable"}
        title = _operation_name(route, suffix)
        normal_schema = _schema_for_example(
            normal, title + "WholeResponse")
        normal_schema["additionalProperties"] = False
        normal_schema["properties"]["server"]["properties"][
            "server_observation"]["properties"]["observed_at"] = {
                "type": ["number", "null"]}
        normal_schema["properties"]["server"]["properties"][
            "server_observation"]["properties"]["aria_session_id"] = {
                "type": ["string", "null"]}
        normal_schema["properties"]["images"]["items"]["properties"][
            "total_bytes"] = {"type": ["integer", "null"]}
        normal_schema["properties"]["images"]["items"]["properties"]["peers"]["items"] = _swarm_peer_schema()
        empty_schema = {"type": "object", "maxProperties": 0}
        if route.service == "telemetry":
            variants = [normal_schema, empty_schema]
            examples = {
                "whole": {"value": normal},
                "serializationFallback": {"value": {}},
            }
            description = "Whole swarm or an empty serialization fallback"
        else:
            paged_schema = _schema_for_example(
                paged, title + "PageResponse")
            paged_schema["additionalProperties"] = False
            paged_schema["properties"]["server"]["properties"][
                "server_observation"]["properties"]["observed_at"] = {
                    "type": ["number", "null"]}
            paged_schema["properties"]["server"]["properties"][
                "server_observation"]["properties"]["aria_session_id"] = {
                    "type": ["string", "null"]}
            paged_schema["properties"]["images"]["items"]["properties"][
                "total_bytes"] = {"type": ["integer", "null"]}
            paged_schema["properties"]["images"]["items"]["properties"]["peers"]["items"] = _swarm_peer_schema()
            paged_schema["properties"]["peers_limit"] = {
                "type": ["integer", "null"]}
            unavailable_schema = _schema_for_example(
                unavailable, title + "UnavailableResponse")
            unavailable_schema["additionalProperties"] = False
            variants = [normal_schema, paged_schema, unavailable_schema]
            examples = {
                "whole": {"value": normal},
                "page": {"value": paged},
                "unavailable": {"value": unavailable},
            }
            description = "Whole swarm, an opt-in peer page, or an availability fallback"
        return "200", {
            "description": description,
            "content": {"application/json": {
                "schema": {"oneOf": variants},
                "examples": examples}}}
    if suffix == "/telemetry/health":
        healthy = _json_success_example(route)
        unavailable = {"ok": False, "error": "unavailable"}
        title = _operation_name(route, suffix)
        healthy_schema = _schema_for_example(healthy, title + "Response")
        unavailable_schema = _schema_for_example(
            unavailable, title + "UnavailableResponse")
        healthy_schema["additionalProperties"] = False
        unavailable_schema["additionalProperties"] = False
        return "200", {
            "description": "Detailed exporter status or a non-secret availability fallback",
            "content": {"application/json": {
                "schema": {"oneOf": [healthy_schema,
                                       unavailable_schema]},
                "examples": {"healthy": {"value": healthy},
                             "unavailable": {"value": unavailable}}}}}
    example = _json_success_example(route)
    title = _operation_name(route, suffix) + "Response"
    schema = _schema_for_example(example, title)
    if suffix == "/install-options":
        schema["properties"]["options"] = {
            "type": ["array", "null"], "items": {"type": "string"}}
    elif suffix == "/devices/{device_id}/reports":
        v2_example, v1_example = example["reports"]
        v2_schema = _schema_for_example(v2_example, title + "V2Report")
        v1_schema = _schema_for_example(v1_example, title + "V1Report")
        v2_schema["properties"]["schema"] = {
            "type": "string", "const": "v2"}
        v1_schema["properties"]["schema"] = {
            "type": "string", "const": "v1"}
        schema["properties"]["reports"]["items"] = {
            "oneOf": [v2_schema, v1_schema]}
    elif suffix == "/devices/{device_id}/deployment":
        schema["properties"]["record"] = {
            "oneOf": [
                _schema_for_example(
                    {"record_id": "record-01", "state": "active"},
                    title + "Record"),
                {"type": "null"},
            ]}
    elif suffix == "/settings/image-verification":
        schema["properties"]["mode"]["enum"] = [
            "off", "daily", "weekly"]
        schema["properties"]["hour_utc"].update(
            {"minimum": 0, "maximum": 23})
    elif suffix == "/settings/setup-status":
        packages = schema["properties"]["packages"]
        packages["properties"]["reference_fingerprint"] = {
            "type": ["string", "null"]}
        packages["properties"]["state"]["enum"] = [
            "ok", "absent", "unknown", "stale"]
        packages["properties"]["reason"] = {
            "type": "string", "enum": [
                "served-cert-unavailable", "distributed-cert-unavailable",
                "served-vs-distributed-mismatch"]}
        item = packages["properties"]["items"]["items"]
        item["properties"]["state"]["enum"] = [
            "ok", "absent", "unknown", "stale"]
        item["properties"]["built_at"]["type"] = ["integer", "null"]
        item["properties"]["built_at"]["description"] = (
            "Artifact file modification time as Unix seconds; the "
            "field name does not attest the original package build time.")
        item["properties"]["fingerprint"]["description"] = (
            "Null for deployment-neutral packages; runtime "
            "trust is reported by packages.reference_fingerprint.")
        item["properties"]["provenance"]["type"] = ["object", "null"]
        item["properties"]["reason"] = {"type": "string"}
        item["required"] = [
            "name", "state", "fingerprint", "built_at", "remedy",
            "provenance"]
        item["additionalProperties"] = False
    elif suffix == "/settings/telemetry-destination" and \
            "endpoint" in schema["properties"]:
        schema["properties"]["endpoint"]["format"] = "uri"
    elif route.service == "catalog" and \
            suffix == "/v1/devices/{device_id}/token-refresh":
        # These two credentials are sent only when provisioned for the device;
        # absence must not overwrite an agent's still-live local value.
        schema["properties"].update({
            "announce_token": {"type": "string"},
            "rpc_secret": {"type": "string"},
        })
    elif route.service == "catalog" and \
            suffix == "/v1/devices/{device_id}/policy":
        schema["properties"]["plans"] = {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "plan_id": {"type": "string",
                                "pattern": "^[0-9a-f]{32}$"},
                    "transfer_id": {"type": "string",
                                    "pattern": "^[0-9a-f]{32}$"},
                },
                "required": ["plan_id", "transfer_id"],
                "additionalProperties": False,
            },
        }
    elif suffix == "/audit":
        event = schema["properties"]["events"]["items"]
        event["required"] = [name for name in event["required"]
                             if name != "category"]
    if suffix == "/peer-policy/explain":
        for side in ("a", "b"):
            properties = schema["properties"][side]["properties"]
            for key in ("role", "acl_name", "role_shadowed_by"):
                properties[key]["type"] = ["string", "null"]
            properties["matched_seq"]["type"] = ["integer", "null"]
            properties["principal"]["properties"]["type"]["enum"] = ["device", "service"]
    if suffix == "/peer-policy/roles":
        schema["properties"]["roles"] = {"type": "object",
            "propertyNames": _role_name_schema(), "additionalProperties": _role_definition_schema()}
    if suffix == "/peer-policy":
        schema["properties"]["roles_supported"]["const"] = True
        schema["properties"]["roles"]["properties"]["members"] = {
            "type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}
        schema["properties"]["fleet_rollup"]["properties"]["issued_revision"] = {"type": "null"}
    if suffix == "/devices/{device_id}/effective-qos":
        for row in schema["properties"]["qos"]["properties"].values():
            row["required"] = [key for key in row["required"] if key != "derived_from"]
    if suffix in ("/devices/{device_id}/role", "/devices/bulk-role"):
        optional = {"candidate_revision", *_blast_example()}
        schema["required"] = [key for key in schema["required"] if key not in optional]
    if _policy_mutation(route) and route.method != "POST":
        example["member_delta"] = 0
        if suffix == "/peer-policy/qos":
            example["qos_changed"] = True
        else:
            example["role_pairs_stopped"] = 1
    if _policy_mutation(route):
        schema["properties"]["confirm_token"]["type"] = ["string", "null"]
    response = {"description": route.summary + " response",
                "content": {"application/json": _media(
                    schema, example)}}
    if _policy_mutation(route):
        no_confirmation = dict(example, confirm_token=None, requires_confirmation=False,
            member_delta=0, origin_access_lost=0, empty_permitted_sets=0,
            role_pairs_stopped=0, qos_changed=False)
        media = response["content"]["application/json"]
        media.pop("example")
        media["examples"] = {
            "confirmationRequired": {"value": example},
            "noConfirmation": {"value": no_confirmation}}
        if route.method == "POST":
            noop = {key: value for key, value in no_confirmation.items()
                    if key not in {"candidate_revision", *_blast_example()}}
            noop.update(dry_run=False, direction="neutral")
            media["examples"]["unchangedMembership"] = {"value": noop}
    if suffix == "/devices" and route.method == "GET":
        response["headers"] = {"ETag": {
            "schema": {"type": "string"}, "example": '"iris-fleet-7"'}}
    if suffix in ("/peer-policy", "/peer-policy/roles", "/peer-policy/explain",
                  "/devices/{device_id}/effective-qos") or _policy_mutation(route):
        response["headers"] = {"ETag": {
            "schema": {"type": "string"},
            "example": '"iris-peer-policy-4"'}}
    if suffix == "/peer-policy/quarantine/{device_id}":
        response["headers"] = {"ETag": {
            "schema": {"type": "string"},
            "example": '"iris-peer-policy-5"'}}
    if route.service == "catalog" and suffix in (
            "/v1/devices/{device_id}/policy", "/v1/devices/{device_id}/heartbeat"):
        media = response["content"]["application/json"]
        properties = media["schema"]["properties"]
        properties["instr_rev"] = {
            "type": "object", "required": ["epoch", "instr_serial"],
            "additionalProperties": False,
            "properties": {name: _instruction_integer() for name in ("epoch", "instr_serial")},
            "description": "Pointer from the complete stored stamp only; absent before stamping. Role/cadence failure does not remove a valid pointer.",
        }
        properties["keylist_seq"] = dict(_instruction_integer(1), description=(
            "Monotonic sequence parsed from the installed signed artifact; omitted "
            "when uninitialized or unavailable without failing policy/heartbeat."))
        legacy = media.pop("example")
        current = dict(legacy, instr_rev={"epoch": 1788782400, "instr_serial": 7},
                       keylist_seq=8)
        media["examples"] = {"instructionsAvailable": {"value": current},
                             "legacyOrUnavailable": {"value": legacy}}
        if suffix.endswith("/heartbeat"):
            properties["stream_every"] = {
                "type": "integer", "minimum": 1, "maximum": 60,
                "description": "The one server-resolved telemetry cadence reused for observation validation, retention and response; global settings supply the fallback."}
            properties["stream_pause"] = {"type": "boolean"}
            media["examples"]["fallbackCadence"] = {
                "value": {"ok": True, "stream_every": 4, "stream_pause": False}}
    return "200", response


def _operation(route):
    operation_id = (route.service + "_" + route.method.lower() + "_" +
                    re.sub(r"[^a-zA-Z0-9]+", "_", route.path).strip("_"))
    op = {
        "operationId": operation_id,
        "summary": route.summary,
        "description": _description(route),
        "tags": [route.service],
        "x-iris-service": route.service,
        "x-iris-security": route.security,
        "servers": [_service_server(route.service)],
        "security": _security(route),
        "parameters": _path_parameters(route.path) + _query_parameters(route),
        "responses": {},
    }
    if route.method in MUTATIONS and "consoleSession" in route.security:
        op["parameters"].append({
            "name": "X-CSRF-Token", "in": "header", "required": True,
            "description": "Constant-time validated token from the console session",
            "schema": {"type": "string"}, "example": "session-csrf-token"})
    if route.method == "POST" and _idempotency_supported(route.path):
        op["parameters"].append({
            "name": "Idempotency-Key", "in": "header", "required": False,
            "description": "8-128 safe characters; replays the same successful response for 24 hours within one management process",
            "schema": {"type": "string", "minLength": 8, "maxLength": 128},
            "example": "onboard-edge-01-0001"})
        op["x-iris-idempotency"] = "process-local-24h-success-replay"
    if route.security == "legacyGuestShell":
        op["x-iris-path-capability"] = {
            "parameter": "legacy_artifact",
            "entropyBits": 128,
            "timeBounded": True,
            "compatibility": "Guest Shell copy HTTPS",
        }
    path_exception = _resource_path_exception(route)
    if path_exception is not None:
        op["x-iris-v1-resource-path-exception"] = path_exception
    if _policy_mutation(route):
        op["parameters"].append({"name": "If-Match", "in": "header", "required": True,
            "description": "One exact strong policy ETag. Missing: 428; stale: 412; race under the policy lock: 409. Confirmation is candidate-bound at threshold zero, including every changed QoS document.",
            "schema": {"type": "string"}, "example": '\"iris-peer-policy-4\"'})
    if route.path.endswith("/peer-policy/quarantine/{device_id}"):
        op["parameters"].append({
            "name": "If-Match", "in": "header", "required": False,
            "description": "Strong ETag from GET peer-policy. Body if_revision remains until the advertised Sunset for v1 clients.",
            "schema": {"type": "string"}, "example": '"iris-peer-policy-4"'})
        op["x-iris-compatibility"] = "Body if_revision is retained through 2027-09-04; omission emits Deprecation and Sunset."
    body = _request_body(route)
    if body is not None:
        op["requestBody"] = body
    success_status, success = _success(route)
    op["responses"][success_status] = success
    if _instruction_resource(route):
        op["responses"]["304"] = {
            "description": "Selected representation matches If-None-Match after current authorization, limiter and state checks; no body, Content-Type or Content-Length",
            "headers": _instruction_headers(),
        }
    if route.method == "DELETE" and _policy_mutation(route):
        op["responses"]["200"]["description"] = "Dry-run candidate and confirmation preview"
        op["responses"]["204"] = {"description": "Role deleted; no body",
            "headers": {"ETag": {"schema": {"type": "string"}}}}
    if route.service == "artifact":
        op["responses"]["304"] = {
            "description": "Artifact has not changed since If-Modified-Since"}
    if route.path.endswith("/console-certificate"):
        op["responses"]["204"] = {
            "description": "Use independently mounted default; no private key crosses tiers",
            "headers": {"X-IRIS-Certificate-Source": {
                "schema": {"type": "string", "const": "default"}}}}
    if _resource_suffix(route) == "/devices/{device_id}" \
            and route.method == "DELETE":
        partial = _json_success_example(route)
        op["responses"]["207"] = {
            "description": "Device retired but one or more non-authorizing cleanup steps degraded",
            "content": {"application/json": _media(
                _schema_for_example(
                    partial, _operation_name(route, _resource_suffix(route)) +
                    "PartialResponse"), partial)}}
    if route.path.endswith("/readyz"):
        op["responses"]["503"] = {
            "description": "Not ready; probe documents deliberately use the minimal health schema",
            "headers": {"Retry-After": {
                "description": "Seconds before another readiness check",
                "schema": {"type": "integer", "minimum": 1},
                "example": 1}},
            "content": {"application/json": _media(
                _ref("Health"), {"ok": False})}}
    else:
        for status in _error_statuses(route):
            op["responses"][str(status)] = (
                _tracker_error(status) if route.service == "tracker"
                else _problem_response(route, status))
    return op


def _error_statuses(route):
    """Enumerate the bounded response-code envelope for a registered route.

    Console operations include the state-free proxy's framing/availability
    errors in addition to the corresponding management handler. Mature route
    families share some guards, so a conditional operation can expose only a
    subset of its family's declared codes. This remains explicit rather than
    an unbounded OpenAPI ``default`` response.
    """
    if _instruction_resource(route):
        return ((401, 403, 404, 429, 503) if route.path == INSTRUCTION_RESOURCES[1]
                else (401, 403, 404, 409, 429, 503))
    suffix = _resource_suffix(route)
    policy_errors = _policy_errors(route)
    if policy_errors is not None:
        return tuple(sorted(policy_errors))
    if suffix == "/healthz":
        return ()
    if suffix == "/readyz":
        return ()  # the non-Problem 503 is emitted directly in _operation
    if route.service == "tracker":
        return (400, 401, 403, 404, 503)
    if route.service == "artifact":
        if route.security == "guestShellAnonymousStatic":
            return (404, 500)
        if route.security == "legacyGuestShell":
            return ((403, 404, 500) if route.path.startswith("/staging/")
                    else (404, 500))
        return (401, 403, 404, 500, 503)
    if route.service == "telemetry":
        if suffix == "/status":
            return (401, 404, 503)
        return (401, 404)
    if route.service == "catalog":
        if route.method == "GET":
            return (400, 401, 404, 500, 503)
        statuses = [400, 401, 404, 411, 413, 500, 503]
        if suffix.endswith("/token-refresh"):
            statuses.append(409)
        return tuple(sorted(statuses))

    # Body-authenticated first-run endpoints precede a browser session and
    # therefore have their own smaller, auditable error unions.
    if suffix == "/login":
        statuses = {400, 401, 413, 429, 503}
        if route.service == "console":
            statuses.add(411)  # BFF rejects unsupported chunked framing
        return tuple(sorted(statuses))
    if suffix == "/setup":
        statuses = {400, 403, 409, 413, 415, 503}
        if route.service == "console":
            statuses.add(411)  # BFF rejects unsupported chunked framing
        if route.service == "management":
            statuses.add(401)  # tier credential
        return tuple(sorted(statuses))
    if route.path == "/internal/v1/console-certificate":
        return (401, 503)
    if route.path == "/internal/v1/authorizations":
        return (400, 401, 403, 404, 413)

    # Cross-cutting state/session/framing errors, narrowed below for reads.
    if route.method == "GET":
        statuses = {401, 404, 503}
        if route.service == "console":
            statuses.update((400, 411, 413))
        if suffix in ("/audit", "/audit/histogram", "/devices", "/swarm",
                      "/deploy-logs/histogram"):
            statuses.add(400)
        if suffix == "/devices/{device_id}/plan":
            statuses.add(409)
        if suffix == "/devices/{device_id}/reports":
            statuses.update((400, 422))
        return tuple(sorted(statuses))

    statuses = {400, 401, 403, 404, 413, 503}
    if route.service == "console":
        statuses.add(411)
    if suffix == "/images/upload/{filename}":
        statuses.add(408)
    if suffix in ("/image-verification/offline",):
        statuses.update((408, 409, 502))
    if suffix in ("/image-verification/refresh",):
        statuses.update((409, 502))
    if _policy_mutation(route):
        statuses.update((409, 412, 422, 428))
    if suffix in ("/peer-policy/explain", "/devices/{device_id}/effective-qos"):
        statuses.add(422)
    if suffix in ("/peer-policy/quarantine/{device_id}",):
        statuses.update((409, 412, 422))
    if suffix in ("/images/import", "/images/{image_id}",
                  "/images/{image_id}/release-quarantine",
                  "/devices/{device_id}/assign",
                  "/devices/{device_id}/adopt",
                  "/devices/{device_id}/onboard",
                  "/devices/{device_id}/undeploy",
                  "/onboard/jobs/{job_id}/abort",
                  "/settings/audit-export/run"):
        statuses.add(409)
    if suffix == "/devices/{device_id}/request-report":
        statuses.update((422, 429))
    if suffix in ("/settings/audit-export", "/settings/ca-trust",
                  "/settings/telemetry-destination", "/settings/gui-cert",
                  "/settings/trust", "/devices/{device_id}"):
        statuses.add(500)
    return tuple(sorted(statuses))


def _service_server(service):
    return {
        "console": {"url": "https://iris.example:8080", "description": "Operator Console; replace with the configured public origin"},
        "management": {"url": "https://iris-server:9443", "description": "Internal management API"},
        "catalog": {"url": "https://iris.example:8443", "description": "Device catalog"},
        "tracker": {"url": "https://iris.example:6969", "description": "TLS BEP tracker v1 listener"},
        "artifact": {"url": "https://iris.example:8000", "description": "Artifact service"},
        "telemetry": {"url": "https://iris.example:9101", "description": "TLS telemetry listener"},
    }[service]


def _tracker_error(status):
    reasons = {
        400: "invalid tracker request",
        401: "authentication required",
        403: "authentication required",
        404: "torrent not found",
        503: "credential store unavailable",
    }
    reason = reasons[status]
    response = {
        "description": "BEP-compatible bencoded failure; deliberate RFC 9457 exception",
        "content": {"text/plain": _media(
            {},
            "d14:failure reason%d:%se" % (len(reason), reason))}}
    if status == 503:
        response["headers"] = {"Retry-After": {
            "description": "Seconds before retrying an unavailable credential store",
            "schema": {"type": "integer", "minimum": 1}, "example": 1}}
    if status == 401:
        response["headers"] = {"WWW-Authenticate": {
            "description": "Bearer challenge for the preferred header transport",
            "schema": {"type": "string", "const": "Bearer"},
            "example": "Bearer"}}
    return response


def _idempotency_supported(path):
    suffix = path
    for prefix in ("/api/v1", "/internal/v1"):
        if suffix.startswith(prefix):
            suffix = "/api" + suffix[len(prefix):]
            break
    if suffix in ("/api/devices", "/api/images/import",
                  "/api/image-verification/refresh",
                  "/api/settings/audit-export/run",
                  "/api/settings/ca-trust/refresh"):
        return True
    return bool(re.fullmatch(
        r"/api/devices/\{device_id\}/(?:request-report|adopt|onboard|undeploy)",
        suffix))


def _resource_path_exception(route):
    """Describe retained action paths in the newly namespaced v1 contract.

    The stateful handler and shipped console used these suffixes before the
    explicit version boundary existed.  Renaming them in-place would require
    parallel aliases through two authentication tiers and would broaden the
    security-critical dispatch surface.  They therefore remain stable in v1;
    any normalized replacements belong to a new major base path.
    """
    suffix = _resource_suffix(route)
    families = (
        (r"^/images/(?:import|\{image_id\}/release-quarantine)$",
         "image lifecycle action"),
        (r"^/image-verification/(?:offline|refresh)$",
         "verification job action"),
        (r"^/devices/(?:import-csv|bulk-credential|bulk-role)$",
         "fleet batch action"),
        (r"^/devices/\{device_id\}/(?:role|effective-qos|assign|credential|platform|forget-host-key|request-report|adopt|onboard|undeploy)$",
         "device workflow action"),
        (r"^/onboard/(?:jobs/\{job_id\}/abort|cancel-queued)$",
         "onboarding job control"),
        (r"^/telemetry/stream$", "telemetry stream control"),
        (r"^/settings/(?:password|sessions/revoke-others|audit-export/run(?:/\{job_id\})?|ca-trust/refresh(?:/\{job_id\})?)$",
         "settings command"),
    )
    for pattern, family in families:
        if re.fullmatch(pattern, suffix):
            return (family + ": retained for the shipped console and the "
                    "one-to-one BFF/management dispatch boundary; a rename "
                    "would be breaking and is reserved for a future major API")
    return None


def _description(route):
    notes = [route.summary + "."]
    if _instruction_resource(route):
        notes.extend([
            "Only the current same-device catalog Bearer is accepted. Previous catalog tokens are limited to token-refresh. Missing/malformed Bearer returns 401 before any store access; usable Bearer meets strict credential-store validation before dispatch (503 on unavailable state). A valid credential naming another device returns 403 without revealing target existence.",
            "Both instruction routes share one process-local per-device token bucket: burst 2, refill one token per 10 seconds, 20,000 device bound, and 20-second idle pruning. Body, 304 and later resource-error requests all consume a token; authentication/authorization failures do not. Retry-After on 429 is max(1, ceil((1 - tokens) * 10)). Restart resets the limiter; multiple processes or replicas multiply the allowance. The supported deployment uses one catalog process/replica.",
            "No instruction-key material, role artifacts, signatures or trust roots have separate delivery aliases. IRIS stages images only.",
        ])
        if route.path == INSTRUCTION_RESOURCES[0]:
            notes.append("Reconstructs at most 256 KiB from one stored stamp and its validated immutable role artifact. The exact stamped non-revoked current key remains eligible regardless of rotation-trigger expiry; a non-revoked previous key is eligible only before its overlap deadline. Every response, including cache hits and 304, rechecks complete state and key eligibility. Missing stamp/named file returns counted 404; an unavailable stamped key returns stale_pointer 409. server_time equals stored issued_at; current HTTP Date does not change envelope bytes. The process-memory ciphertext cache is bounded at 256 entries and 16 MiB; per-device ciphertext is never persisted.")
        else:
            notes.append("Serves at most 128 KiB of the exact installed root-signed keylist, including a KRL of at most 80 KiB. Both artifact and metadata absent means uninitialized 404; established artifact loss or contradictory/corrupt state means 503. An artifact ahead of its metadata remains authoritative and serveable. No signature verification, root discovery or repair occurs on GET.")
        return " ".join(notes)
    if route.service == "console":
        notes.append("Browser-facing BFF route; session/CSRF decisions are repeated by the state owner before request-body forwarding.")
    elif route.service == "management":
        notes.append("Internal HTTPS route; requires the scoped current or previous file-mounted tier credential.")
    elif route.service == "catalog":
        notes.append("The device bearer is resource-bound. Image collections, items and torrents expose only that device's current assignment.")
    elif route.service == "artifact":
        if route.security == "guestShellAnonymousStatic":
            notes.append("Guest Shell can fetch an exact static allowlist containing no credentials anonymously; arbitrary files are unreachable.")
        elif route.security == "legacyGuestShell":
            notes.append("Guest Shell uses IOS copy HTTPS with staging filenames that are 128-bit time-bounded capabilities. Explicit artifact API clients use resource-bound Basic authentication.")
        else:
            notes.append("HTTP Basic username is device_id and password is that same device's current/overlap catalog token; authentication precedes path translation and existence checks.")
    elif route.service == "tracker":
        notes.append("The tracker is HTTPS-only and uses the same certificate pinned by device agents. Bearer Authorization is preferred and disables fallback. Guest Shell aria2 uses query credentials protected by TLS; BEP-compatible bencoded errors are the sole response-format exception.")
        if route.path == "/scrape":
            notes.append("A device principal may scrape only an info hash in its current catalog assignment; unknown and cross-assignment hashes return the same result. The seeder service and authenticated unattributed principals can scrape all torrents.")
    suffix = _resource_suffix(route)
    if suffix == "/install-options":
        notes.append("The model only restricts installer choices; null means no model-based restriction. The Console also restricts installers by management type, which alone controls network-field visibility. A saved free-text model does not confirm hardware support.")
    elif suffix == "/devices" and route.method == "GET":
        notes.append("Status filter keys remain stable: deployed displays as Staged, placement-failed as Staging failed, and waiting-staging means an assigned device has not reported work on the current set. Current per-image errors take precedence over earlier staged flags.")
    elif suffix == "/swarm":
        notes.append("Image rows include image_id when the torrent hash maps to one catalog image. Observations and reports carry image_id when known; match it before attributing measurements. Tracker seeder role does not establish device staging completion, and ambiguous peer rates remain unavailable.")
    elif suffix == "/settings":
        notes.append("host_ip identifies the device-facing server; console_url is the configured browser origin and may use another host.")
        if route.service == "console":
            notes.append("gui_cert describes the certificate loaded by this Console, including an independently mounted deployment default.")
    elif suffix == "/settings/gui-cert" and route.service == "console":
        notes.append("Successful changes persist on the server and reload this Console before replying. applied reports the Console reload result; gui_cert describes the identity currently loaded. If applied is false, restart the Console to load the saved configuration.")
    path_exception = _resource_path_exception(route)
    if path_exception is not None:
        notes.append(path_exception + ".")
    if route.method == "GET" and route.path.endswith(("/images", "/credentials", "/onboard/jobs")):
        notes.append("This bounded v1 collection has no pagination parameter; adding one without a stable compatibility shape is deferred to the next major version.")
    return " ".join(notes)


def build_document():
    paths = {}
    for route in api_routes.ROUTES:
        item = paths.setdefault(route.path, {})
        method = route.method.lower()
        if method in item:
            # /healthz and /readyz intentionally exist on both independently
            # deployed listeners. OpenAPI keys paths by URL path rather than
            # server, so represent the one wire operation once and retain the
            # complete service ownership list for bidirectional drift checks.
            item[method].setdefault(
                "x-iris-services", [item[method]["x-iris-service"]]).append(
                    route.service)
            item[method]["x-iris-service-responses"] = {
                "console": {"ok": True},
                "telemetry": {"ok": True},
            }
            item[method]["servers"].append(_service_server(route.service))
        else:
            item[method] = _operation(route)
    return {
        "openapi": "3.2.0",
        "info": {
            "title": "IRIS HTTP API",
            "version": "1",
            "description": "Canonical contract for the browser console BFF, internal management tier, device catalog, tracker, telemetry and artifact services. Guest Shell static files and staging path capabilities have dedicated access rules; other anonymous routes are limited to /healthz and /readyz.",
        },
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "tags": [{"name": name} for name in
                 ("console", "management", "catalog", "tracker", "telemetry", "artifact")],
        "x-iris-version-policy": {
            "current": "v1",
            "breakingChanges": "require a new major base path",
            "retirement": "announce for at least two dated releases; deprecated compatibility responses carry Deprecation and a dated Sunset",
        },
        "x-iris-retained-v1-exceptions": {
            "trackerErrors": "BEP clients require bencoded failures, so tracker errors are not RFC 9457.",
            "probeErrors": "readyz 503 remains a deliberately non-disclosing {ok:false} health document.",
            "trackerTransport": "Port 6969 is HTTPS-only and uses the certificate pinned by device agents. IOx/XR agents use Bearer Authorization; Guest Shell uses query credentials. TLS protects both forms, and credentials are never logged.",
            "guestShellArtifacts": "IOS Guest Shell copy HTTPS uses four static files and two high-entropy staging filename forms. Staging files expire automatically. Explicit artifact API clients use resource-bound Basic authentication at /v1/devices/{device_id}/artifacts/{artifact_path}.",
            "resourcePaths": "Use the operation paths defined in this contract, including verb-based action paths.",
            "pagination": "Devices and audit expose the documented paging shapes. Other collections are bounded by assignment or returned whole; they do not claim pagination.",
            "compareAndSet": "Peer policy exposes ETag/If-Match while accepting body if_revision through its Sunset. Device assignment uses expect_image_ids to compare the assigned set and returns the conflicting set when it differs.",
            "statusCodes": "Upsert and job operations return 200 with the documented response body. Operations declare a bounded set of error responses; conditional branches may use a subset.",
            "idempotency": "Only operations explicitly declaring Idempotency-Key have process-local 24-hour successful-response replay. Restart clears that replay ledger and in-memory jobs; inspect catalog state, deployment records, and persisted deployment logs before retrying.",
        },
        "paths": paths,
        "components": {
            "securitySchemes": {
                "consoleSession": {"type": "apiKey", "in": "cookie", "name": "iris_sid",
                                   "description": "HttpOnly Secure browser session"},
                "consolePassword": {
                    "type": "http", "scheme": "iris-json-password",
                    "description": "Username/password authentication carried by the documented JSON request body, not an HTTP Authorization header",
                    "x-iris-in": "requestBody"},
                "setupGrant": {
                    "type": "http", "scheme": "iris-json-setup-grant",
                    "description": "Short-lived one-use setup grant carried by the documented JSON request body",
                    "x-iris-in": "requestBody"},
                "csrfHeader": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token",
                               "description": "Required with a console session on mutations"},
                "managementBearer": {"type": "http", "scheme": "bearer",
                                     "bearerFormat": "scoped opaque token"},
                "deviceBearer": {"type": "http", "scheme": "bearer",
                                 "bearerFormat": "device catalog token"},
                "announceBearer": {"type": "http", "scheme": "bearer",
                                   "bearerFormat": "device announce token"},
                "legacyAnnounceToken": {"type": "apiKey", "in": "query",
                                         "name": "announce_token",
                                         "description": "Guest Shell announce query credential"},
                "legacyTrackerKey": {"type": "apiKey", "in": "query",
                                      "name": "key",
                                      "description": "Alternate query credential accepted when Authorization is absent"},
                "observabilityBearer": {"type": "http", "scheme": "bearer",
                                        "bearerFormat": "scoped observability token"},
                "artifactBasic": {"type": "http", "scheme": "basic",
                                  "description": "device_id plus resource-bound catalog token"},
            },
            "schemas": {
                "Problem": {"type": "object", "required": ["type", "title", "status", "code"],
                            "properties": {"type": {"type": "string", "format": "uri"},
                                           "title": {"type": "string"},
                                           "status": {"type": "integer", "minimum": 400, "maximum": 599},
                                           "code": {"type": "string"},
                                           "error": {"type": "string", "deprecated": True}},
                            "additionalProperties": True},
                "Health": {"type": "object", "required": ["ok"],
                           "properties": {
                               "ok": {"type": "boolean"},
                           },
                           "additionalProperties": False},
            },
        },
    }


def main():
    print(json.dumps(build_document(), indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
