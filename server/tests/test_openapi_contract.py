# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OpenAPI/runtime bidirectional drift and API-wide security invariants."""

import json
from pathlib import Path

import api_problem
import api_routes
import openapi_contract


SPEC = Path(__file__).resolve().parents[2] / "docs" / "zensical" / "openapi.yaml"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


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
    assert doc["openapi"] == "3.1.0"
    assert _specified_keys(doc) == api_routes.keys()
    # This second equality catches semantic drift beyond the route triples:
    # auth, examples, status contracts and compatibility declarations.
    assert doc == openapi_contract.build_document()


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
                     "/iris-agent-arm.tgz", "/iris-catalog.pem")}
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
                    assert "schema" in media, (method, path)
                    assert "example" in media or "examples" in media, (
                        method, path)
                    assert media["schema"] != {
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
    doc = _load()
    for path in ("/api/v1/swarm", "/internal/v1/swarm", "/swarm"):
        media = doc["paths"][path]["get"]["responses"]["200"][
            "content"]["application/json"]
        whole = media["examples"]["whole"]["value"]
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
    assert set(policy["example"]) == {
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
