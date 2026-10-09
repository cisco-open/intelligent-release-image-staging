# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped browser model consumes real authenticated two-tier responses."""
import json
import os
from pathlib import Path
import subprocess
import time

import pytest
from openapi_schema_validator import OAS32Validator

import auth
import openapi_contract
import origin_enforcement as oe
import peer_endpoints
import peer_policy
from test_api_split import policy_tiers
from test_blocklist_reconciler import _role_doc


def check_browser_model(replies):
    operations = openapi_contract.build_document()["paths"][
        "/api/v1/peer-policy/origin-enforcement"]
    for item in replies:
        method = "get" if item["kind"] == "status" else "put"
        schema = operations[method]["responses"]["200"]["content"]["application/json"]["schema"]
        OAS32Validator(schema).validate(item["reply"][2])
    model = (Path(__file__).resolve().parents[1] /
             "console-ui/src/origin-enforcement-model.mjs").as_uri()
    script = """
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkedOrigin, checkedOriginPreview, originWriteResult} from MODULE;
for (const item of JSON.parse(readFileSync(0, 'utf8'))) {
  const [status, headers, body] = item.reply;
  assert.equal(status, 200);
  if (item.kind === 'status') {
    assert.deepEqual(checkedOrigin(body, headers.ETag), body);
  } else if (item.kind === 'preview') {
    assert.deepEqual(checkedOriginPreview(body, headers.ETag, item.request, item.revision), body);
  } else {
    const response = {status, ok: true, headers: new Headers(headers)};
    assert.equal(originWriteResult(response, body, item.request, item.revision), 'saved');
    assert.equal(body.state, 'pending');
    assert.equal(body.applied_ip_count, null);
  }
}
""".replace("MODULE", json.dumps(model))
    result = subprocess.run(["node", "--input-type=module", "-e", script],
                            input=json.dumps(replies), text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("tier", ["console", "management"])
def test_origin_review_over_both_tiers_matches_shipped_browser(policy_tiers, monkeypatch, tier):
    call, _, catalog = policy_tiers
    monkeypatch.setenv("IRIS_HOST_IP", "192.0.2.10")
    for name in ("peer-policy.json", "peer-policy.lkg.json"):
        peer_policy._atomic_write_json(os.path.join(catalog.state_dir, name), _role_doc(("d1",)))
    endpoint_path = os.path.join(catalog.state_dir, "peer-endpoints.json")
    for principal, address in ((auth.Principal("service", "seeder"), "192.0.2.10"),
                               (auth.Principal("device", "d1"), "198.51.100.20")):
        peer_endpoints.record_endpoint(endpoint_path, principal, address, 6881, time.time())
    endpoint = "/peer-policy/origin-enforcement"
    assert call(tier, "GET", endpoint, authorized=False)[0] == 401
    replies = [{"kind": "status", "reply": call(tier, "GET", endpoint)}]
    for revision, mode in enumerate(("enforce", "preflight")):
        if mode == "preflight":
            # A missing observation must not prevent a reviewed disable. Its
            # target counts are exact zeroes, not an unrenderable null preview.
            peer_endpoints.clear_principal(endpoint_path, auth.Principal("service", "seeder"))
        request = dict(mode=mode, max_new_ips=10, max_new_devices=10,
                       if_policy_revision=1, dry_run=True)
        assert call(tier, "PUT", endpoint, request, match=False)[0] == 428
        preview = call(tier, "PUT", endpoint, request, match=oe.etag(revision))
        assert preview[0] == 200 and preview[2]["blockers"] == []
        if mode == "preflight":
            assert preview[2]["proposed_ip_count"] == 0
            assert preview[2]["proposed_device_count"] == 0
        replies.append(dict(kind="preview", reply=preview, request=request, revision=revision))
        commit = dict(request, dry_run=False, confirm_token=preview[2]["confirm_token"])
        saved = call(tier, "PUT", endpoint, commit, match=oe.etag(revision))
        assert saved[0] == 200
        replies.append(dict(kind="saved", reply=saved, request=request, revision=revision))
        assert call(tier, "PUT", endpoint, commit, match=oe.etag(revision))[0] == 412
        replies.append({"kind": "status", "reply": call(tier, "GET", endpoint)})
    check_browser_model(replies)
