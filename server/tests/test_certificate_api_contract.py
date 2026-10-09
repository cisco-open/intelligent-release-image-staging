# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real versioned certificate APIs agree with OpenAPI and shipped UI models."""

import base64
import json
from pathlib import Path
import subprocess
import uuid

import pytest
from openapi_schema_validator import OAS32Validator

import certificate_lifecycle
import instruction_keys
import instruction_rotation
import openapi_contract
from test_api_split import policy_tiers
from test_instruction_keys import NOW, _issue, _root_sign
from test_instruction_rotation import custody


def _check_browser_contract(replies):
    model = (Path(__file__).resolve().parents[1] /
             "console-ui/src/certificates-model.mjs").as_uri()
    program = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkedInventory, checkedRenewalRequest, checkedRenewal, checkedSigner,
        checkedSignerResult, retirementPayload} from MODULE;
for (const {kind, body, request, before} of JSON.parse(readFileSync(0, 'utf8'))) {
  const check = {inventory: checkedInventory, renewalRequest: checkedRenewalRequest,
                 renewal: checkedRenewal, signer: checkedSigner}[kind];
  if (check) assert.equal(check(body), true, kind);
  else if (kind === 'retirement') {
    const bytes = retirementPayload(body, request);
    assert.equal(Buffer.from(bytes).toString('base64'), body.payload);
  } else {
    assert.equal(kind, 'signerResult');
    assert.equal(checkedSignerResult(request.action, request, before, body), true,
                 request.action);
  }
}
""".replace("MODULE", json.dumps(model))
    result = subprocess.run(["node", "--input-type=module", "-e", program],
                            input=json.dumps(replies), capture_output=True,
                            text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("tier", ["console", "management"])
def test_native_certificate_lifecycle_matches_openapi_and_browser(
        custody, policy_tiers, tmp_path, monkeypatch, tier):
    paths, roots = custody
    call, _, _ = policy_tiers
    # Keep actual filesystem, age/OpenSSH and both HTTP servers. Only supply
    # the disposable custody paths and deterministic crypto-operation clock.
    inventory = certificate_lifecycle.inventory
    renewal = certificate_lifecycle.renew
    rotation = instruction_rotation.operate
    monkeypatch.setattr(certificate_lifecycle, "inventory",
                        lambda: inventory(paths=paths, now=NOW))
    monkeypatch.setattr(certificate_lifecycle, "renew",
                        lambda body: renewal(body, paths=paths, now=NOW))
    monkeypatch.setattr(instruction_rotation, "operate",
                        lambda body: rotation(body, paths=paths, now=NOW))
    before_authority = {path: path.read_bytes() for path in (
        Path(paths.epoch), Path(paths.instructions_dir) / "replay.fixture")}
    spec = openapi_contract.build_document()
    prefix = "/api/v1" if tier == "console" else "/internal/v1"
    base = "/settings/certificates"
    signer = base + "/instruction/rotation"
    replies = []

    def request(method, endpoint, body=None, *, kind, before=None):
        operation = spec["paths"][prefix + endpoint][method.lower()]
        if body is not None:
            OAS32Validator(operation["requestBody"]["content"]
                           ["application/json"]["schema"]).validate(body)
        status, headers, result = call(tier, method, endpoint, body, match=False)
        assert status == 200, (tier, endpoint, result)
        assert "no-store" in headers["Cache-Control"]
        assert headers["Content-Type"].startswith("application/json")
        OAS32Validator(operation["responses"]["200"]["content"]
                       ["application/json"]["schema"]).validate(result)
        assert "PRIVATE KEY" not in json.dumps(result)
        replies.append(dict(kind=kind, body=result, request=body, before=before))
        return result

    assert call(tier, "GET", base, authorized=False, match=False)[0] == 401
    request("GET", base, kind="inventory")
    initial = request("GET", signer, kind="signer")
    assert initial["state"] == "idle"
    renew_request = request("POST", base + "/instruction/request", {},
                            kind="renewalRequest")
    certificate = _issue(roots["root-a"], Path(paths.public_key), NOW,
                         NOW + 30 * 86400).read_text()
    renewed = request("POST", base + "/instruction/renew", {
        "public_key_sha256": renew_request["public_key_sha256"],
        "certificate_sha256": renew_request["certificate_sha256"],
        "certificate": certificate}, kind="renewal")
    assert renewed["applied"] is True
    assert Path(paths.public_key).read_text() == renew_request["public_key"]
    request("GET", base, kind="inventory")

    identity = str(uuid.uuid4())
    prepared = request("POST", signer, {"action": "prepare", "request_id": identity},
                       kind="signerResult", before=initial)
    assert prepared["previous_public_key"] == renew_request["public_key"]
    assert request("GET", signer, kind="signer") == prepared
    public = tmp_path / "approved-replacement.pub"
    public.write_text(prepared["public_key"])
    approved = _issue(roots["root-a"], public, NOW, NOW + 30 * 86400).read_text()
    active = request("POST", signer, {
        "action": "activate", "request_id": identity,
        "certificate": approved, "confirm": True},
        kind="signerResult", before=prepared)
    assert request("GET", signer, kind="signer") == active
    retirement = request("POST", signer, {
        "action": "retirement-request", "request_id": identity, "root_id": "root-a"},
        kind="retirement")
    payload = base64.b64decode(retirement["payload"], validate=True)
    artifact = instruction_keys.assemble_keylist_artifact(
        payload, _root_sign(payload, roots["root-a"]))
    completed = request("POST", signer, {
        "action": "retire", "request_id": identity, "confirm": True,
        "artifact": base64.b64encode(artifact).decode()},
        kind="signerResult", before=active)
    assert completed["state"] == "completed"
    assert completed["retired_keylist_seq"] == 1
    assert request("GET", signer, kind="signer") == completed
    request("GET", base, kind="inventory")
    _check_browser_contract(replies)
    for path, original in before_authority.items():
        assert path.read_bytes() == original
