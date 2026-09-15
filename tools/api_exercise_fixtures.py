# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Safe, repeatable Console API fixtures for live-route smoke/load tests.

This module deliberately does not create devices or images.  The caller owns a
synthetic device (normally one of a larger pre-created fleet) and supplies a
client whose ``call(method, path, body=None, expected=(200,))`` method handles
the normal Console session, CSRF, and conditional-write headers.  No request
is made at import time.
"""

from __future__ import annotations

import time
from urllib.parse import quote


def _segment(value):
    """Quote one path segment without permitting a caller-created path."""
    return quote(str(value), safe=".-_~")


def _id(prefix, suffix):
    return "%s-%s" % (prefix.strip("-"), suffix)


def _result(checks, name, fn):
    try:
        status, body = fn()
        checks.append({"name": name, "ok": True, "status": status})
        return status, body
    except Exception as exc:  # clients commonly raise for unexpected status
        checks.append({"name": name, "ok": False, "error": str(exc)})
        return None, None


def exercise(client, device_id, prefix):
    """Exercise safe policy, credential, schedule, and assignment routes.

    ``device_id`` must already exist in the Console fleet.  ``prefix`` should
    be unique to this run (and contain no slash); all created role, schedule,
    and credential IDs are derived from it.  The returned report contains
    ``checks`` plus ``fixture_routes`` (IDs useful to a GET-route driver).

    The function never installs, activates, reloads, onboards, starts a job,
    exports data, changes trust/security settings, or creates an image/device.
    A nonexistent image assignment is intentionally attempted only to verify
    rejection, and an empty assignment is restored in cleanup.
    """
    if not isinstance(device_id, str) or not device_id.strip() or "/" in device_id:
        raise ValueError("device_id must be a non-empty existing ID")
    if not isinstance(prefix, str) or not prefix.strip() or "/" in prefix:
        raise ValueError("prefix must be a unique non-empty ID prefix")

    checks = []
    routes = {}
    did = _segment(device_id)
    role = _id(prefix, "role")
    cred = _id(prefix, "credential")
    schedule = _id(prefix, "schedule")
    routes.update(role=role, credential=cred, schedule=schedule,
                  device=device_id)
    original_role = None
    original_credential = None

    def policy_write(method, path, body):
        """Refresh policy CAS immediately before each policy mutation."""
        _, current = client.call("GET", "/api/v1/peer-policy", expected=(200,))
        etag = client.response_header("ETag")
        if not etag:
            raise RuntimeError("peer-policy response did not include ETag")
        if path.startswith("/api/v1/peer-policy/quarantine/"):
            body = dict(body, if_revision=current["revision"])
        status, result = client.call(method, path, body, expected=(200, 204, 428),
                                     headers={"If-Match": etag})
        if status == 428 and result.get("code") == "confirmation_required" and result.get("confirm_token"):
            # This helper only mutates its new isolated role/synthetic device.
            return client.call(method, path, dict(body or {}, confirm_token=result["confirm_token"]),
                               expected=(200, 204), headers={"If-Match": etag})
        if status not in (200, 204):
            raise RuntimeError("policy confirmation unavailable: " + str(result.get("code")))
        return status, result

    # Capture defaults before mutation when the list route is available.
    _, devices = _result(checks, "read-device-defaults", lambda: client.call(
        "GET", "/api/v1/devices", expected=(200,)))
    if isinstance(devices, dict):
        rows = devices.get("devices", devices.get("items", []))
        if isinstance(rows, list):
            row = next((x for x in rows if isinstance(x, dict) and
                        x.get("device_id") == device_id), None)
            if row:
                original_role = row.get("role")
                original_credential = row.get("credential_profile_id") or ""

    try:
        # Policy reads are intentionally broad and role-scoped QoS is the only
        # QoS mutation made here; global QoS is never touched.
        _, policy = _result(checks, "read-peer-policy", lambda: client.call(
            "GET", "/api/v1/peer-policy", expected=(200,)))
        _result(checks, "read-role-definitions", lambda: client.call(
            "GET", "/api/v1/peer-policy/roles", expected=(200,)))
        _result(checks, "create-role", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/roles/" + _segment(role),
            {"restricted": True, "peers": [role], "origin": False,
            "nets": [], "on_stale": "keep", "qos": {}}))
        _result(checks, "update-role", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/roles/" + _segment(role),
            {"restricted": True, "peers": [role], "origin": False,
            "nets": [], "on_stale": "keep", "qos": {"numwant": 4}}))
        _result(checks, "assign-device-role", lambda: policy_write(
            "POST", "/api/v1/devices/" + did + "/role", {"role": role}))
        _result(checks, "read-effective-qos", lambda: client.call(
            "GET", "/api/v1/devices/" + did + "/effective-qos", expected=(200,)))
        _result(checks, "set-role-qos", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/qos",
            {"role": role, "qos": {"numwant": 5}}))
        _result(checks, "quarantine-on", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/quarantine/" + did,
            {"quarantined": True}))
        _result(checks, "quarantine-off", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/quarantine/" + did,
            {"quarantined": False}))

        # Credential CRUD is a profile only; assigning it to the synthetic
        # device is reversible and the profile contains fixture-only values.
        _result(checks, "create-credential", lambda: client.call(
            "POST", "/api/v1/credentials", {"id": cred, "name": cred,
            "device_user": "fixture-user", "device_pass": "fixture-pass"},
            expected=(200,)))
        _result(checks, "assign-credential", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/credential",
            {"credential_profile_id": cred}, expected=(200,)))
        _result(checks, "unassign-credential", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/credential",
            {"credential_profile_id": ""}, expected=(200,)))
        _result(checks, "bulk-credential", lambda: client.call(
            "POST", "/api/v1/devices/bulk-credential",
            {"device_ids": [device_id], "credential_profile_id": ""}))
        _result(checks, "bulk-role", lambda: policy_write(
            "POST", "/api/v1/devices/bulk-role", {"device_ids": [device_id], "role": role}))
        _result(checks, "set-platform", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/platform", {"platform": "guestshell"}))
        _result(checks, "clear-platform", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/platform", {"platform": ""}))

        definition = {"kind": "onboard", "state": "paused",
                      "target": {"device_ids": [device_id], "filters": {}, "bind": "late"},
                      "payload": {"max_devices": 1, "mode": "new-only",
                                  "telemetry": False, "telemetry_stream": False},
                      "when": {"kind": "once", "at": int(time.time()) + 86400,
                               "tz": "UTC", "window_seconds": 60}}
        _, created = _result(checks, "create-paused-schedule", lambda: client.call(
            "POST", "/api/v1/schedules", dict(definition, id=schedule), expected=(201,)))
        if created is not None:
            if created.get("schedule", {}).get("state") != "paused":
                raise RuntimeError("schedule did not remain paused")
            def schedule_write(method, body, suffix=""):
                client.call("GET", "/api/v1/schedules/" + schedule)
                return client.call(method, "/api/v1/schedules/" + schedule + suffix,
                                   body, headers={"If-Match": client.response_header("ETag")})
            _result(checks, "patch-paused-schedule", lambda: schedule_write("PATCH", {"state": "paused"}))
            _result(checks, "replace-paused-schedule", lambda: schedule_write("PUT", definition))
            _result(checks, "reaffirm-paused-schedule", lambda: schedule_write("POST", {}, "/reaffirm"))
            for suffix in ("", "/occurrences", "/receipts"):
                _result(checks, "read-schedule" + suffix, lambda suffix=suffix: client.call(
                    "GET", "/api/v1/schedules/" + schedule + suffix))

        # Empty is the only assignment mutation.  A made-up image verifies a
        # safe rejection path and can never stage anything.
        _result(checks, "reject-nonexistent-image", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/assign",
            {"image_ids": [_id(prefix, "no-such-image")]}, expected=(400, 404, 422)))
        _result(checks, "restore-empty-assignment", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/assign", {"image_ids": []},
            expected=(200,)))
    finally:
        # Cleanup is best-effort per route, but always attempted.  Role and
        # credential IDs are owned by this prefix; no pre-existing fixture is
        # deleted accidentally.
        def delete_schedule():
            status, _ = client.call("GET", "/api/v1/schedules/" + schedule, expected=(200, 404))
            if status == 404:
                return status, {}
            return client.call("DELETE", "/api/v1/schedules/" + schedule, expected=(204,),
                               headers={"If-Match": client.response_header("ETag")})
        _result(checks, "delete-schedule", delete_schedule)
        # Re-read the revision after all policy writes: quarantine's CAS body
        # revision is not necessarily the value captured before role/QoS CRUD.
        _, final_policy = _result(checks, "read-policy-for-cleanup",
                                  lambda: client.call("GET", "/api/v1/peer-policy",
                                                       expected=(200,)))
        _result(checks, "ensure-quarantine-off", lambda: policy_write(
            "PUT", "/api/v1/peer-policy/quarantine/" + did,
            {"quarantined": False}))
        _result(checks, "restore-device-role", lambda: policy_write(
            "POST", "/api/v1/devices/" + did + "/role", {"role": original_role}))
        _result(checks, "clear-device-credential", lambda: client.call(
            "POST", "/api/v1/devices/" + did + "/credential",
            {"credential_profile_id": original_credential or ""}, expected=(200,)))
        _result(checks, "delete-credential", lambda: client.call(
            "DELETE", "/api/v1/credentials/" + _segment(cred), expected=(200, 404)))
        def delete_role():
            return policy_write("DELETE", "/api/v1/peer-policy/roles/" + _segment(role), None)
        _result(checks, "delete-role", delete_role)

    return {"device_id": device_id, "prefix": prefix, "checks": checks,
            "fixture_routes": routes}
