# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped Policies controller against an authenticated temporary HTTP API.

Real stores and routes; this does not qualify live devices, proxying or TLS.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

import gui_fleet

from test_schedule_api import schedule_api, _request


def test_partial_role_recovery_requires_a_fresh_revision_and_preview(
        schedule_api, monkeypatch):
    """Real HTTP/store regression; the one write failure is deliberately injected."""
    server, _app, auth = schedule_api
    path = "/api/devices/edge-1/role"
    # This fixture starts with declared roles but no compiled memberships.
    # Establish agreement first, so clearing edge-1 really is a relaxation.
    for device_id, role in (("edge-1", "boat"), ("edge-2", "fiber")):
        status, _, raw = _request(server, "GET", "/api/peer-policy/roles", headers=auth)
        assert status == 200
        revision = json.loads(raw)["revision"]
        headers = {**auth, "If-Match": f'"iris-peer-policy-{revision}"'}
        member_path = f"/api/devices/{device_id}/role"
        status, _, raw = _request(server, "POST", member_path + "?dry_run=1",
                                  {"role": role}, headers)
        assert status == 200
        commit = {"role": role, "confirm_token": json.loads(raw)["confirm_token"]}
        status, _, raw = _request(server, "POST", member_path, commit, headers)
        assert status == 200
        assert json.loads(raw)["applied"] == 1
    status, _, raw = _request(server, "GET", "/api/peer-policy/roles", headers=auth)
    assert status == 200
    original_revision = json.loads(raw)["revision"]
    original_headers = {**auth, "If-Match": f'"iris-peer-policy-{original_revision}"'}
    status, _, raw = _request(server, "POST", path + "?dry_run=1",
                              {"role": None}, original_headers)
    assert status == 200
    original_commit = {"role": None, "confirm_token": json.loads(raw)["confirm_token"]}
    write = gui_fleet.FleetStore.bulk_upsert
    attempts = []

    def fail_first_fleet_write(fleet, device_ids, fields):
        attempts.append((device_ids, fields))
        if len(attempts) == 1:
            raise gui_fleet.FleetStateError("injected fleet write failure")
        return write(fleet, device_ids, fields)

    monkeypatch.setattr(gui_fleet.FleetStore, "bulk_upsert", fail_first_fleet_write)
    status, _, raw = _request(server, "POST", path, original_commit, original_headers)
    assert status == 503
    partial = json.loads(raw)
    assert partial["partial"] is True
    assert partial["revision"] > original_revision
    assert partial["role_drift"]["device_ids"] == ["edge-1"]

    # Policy committed first, so blindly replaying the earlier request is stale.
    status, _, _ = _request(server, "POST", path, original_commit, original_headers)
    assert status == 412
    assert len(attempts) == 1
    status, _, raw = _request(server, "GET", "/api/peer-policy/roles", headers=auth)
    assert status == 200
    current_revision = json.loads(raw)["revision"]
    assert current_revision == partial["revision"]
    current_headers = {**auth, "If-Match": f'"iris-peer-policy-{current_revision}"'}
    status, _, raw = _request(server, "POST", path + "?dry_run=1",
                              {"role": None}, current_headers)
    assert status == 200
    reviewed = {"role": None, "confirm_token": json.loads(raw)["confirm_token"]}
    status, _, raw = _request(server, "POST", path, reviewed, current_headers)
    assert status == 200
    recovered = json.loads(raw)
    assert recovered["ok"] is True and recovered["partial"] is False
    assert recovered["role_drift"]["count"] == 0
    assert recovered["revision"] == current_revision
    assert len(attempts) == 2


def test_policies_editor_csv_delete_and_conflict_against_real_stores(schedule_api):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped Policies controller")
    server, _app, auth = schedule_api
    source = Path(__file__).resolve().parents[1] / "console-ui/src"
    script = r'''
import assert from 'node:assert/strict';
import {PoliciesController} from CONTROLLER;
import {InventoryController} from INVENTORY;
const c = new PoliciesController(), inventory = new InventoryController(), calls = [], downloads = [], prompts = [];
const base = BASE, auth = AUTH;
let ticket = 0;
async function transport(path, options = {}) {
  const response = await fetch(base + path.replace('/api/v1/', '/api/'), {...options, headers: {...auth, ...options.headers}});
  calls.push({path, options, status: response.status}); return response;
}
c.connect({fetch: transport, headers: extra => ({...extra, 'X-CSRF-Token': auth['X-CSRF-Token']}), isVisible: () => true,
  beginPolicyRead: () => ++ticket, publishPolicy(policy, valid, mine) {if (mine !== ticket) return false; c.policy(valid ? policy : c.state.policy, valid); return true;},
  invalidatePolicyReads() {ticket++; inventory.invalidate();},
  claimBulk() {if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; inventory.update({bulkBusy: true}); return true;},
  releaseBulk() {inventory.update({bulkBusy: false});}, confirm(message) {prompts.push(message); return true;}, saveCsv: (...args) => downloads.push(args)});
inventory.subscribe(() => c.prerequisites(inventory.state));
assert.equal(await c.refresh(), true, c.state.readError);
c.open(); c.field('name', 'new-role'); c.field('restricted', true); c.field('origin', false); c.field('numwant', '12', true);
const baseRevision = c.state.editor.revision;
await c.save(); assert.ok(c.state.preview, c.state.formMessage); await c.save();
assert.equal(c.state.dialog, null, c.state.formMessage); assert.equal(c.state.failed, false, c.state.message);
assert.deepEqual(c.state.definitions['new-role'], {restricted: true, origin: false, peers: ['new-role'], qos: {numwant: 12}});
const writes = () => calls.filter(call => call.options.method);
assert.equal(writes().length, 2);
assert.equal(writes()[0].options.headers['If-Match'], `"iris-peer-policy-${baseRevision}"`);
assert.equal(writes()[1].options.headers['If-Match'], writes()[0].options.headers['If-Match']);
// A server-side overlay is retained exactly when the UI edits other fields.
let definition = {...c.state.definitions['new-role'], qos_state: {seeder: {numwant: 8}, leecher: {announce_min_interval_s: 30}}};
const externalHeaders = {'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${c.state.policy.revision}"`};
let response = await transport('/api/v1/peer-policy/roles/new-role?dry_run=1', {method: 'PUT', headers: externalHeaders, body: JSON.stringify(definition)});
assert.equal(response.status, 200); const preview = await response.json();
response = await transport('/api/v1/peer-policy/roles/new-role', {method: 'PUT', headers: externalHeaders, body: JSON.stringify({...definition, confirm_token: preview.confirm_token})});
assert.equal(response.status, 200); await c.refresh(true); c.open('new-role'); c.field('origin', true); await c.save(); await c.save();
assert.deepEqual(c.state.definitions['new-role'].qos_state, definition.qos_state); assert.equal(c.state.definitions['new-role'].origin, true);
// Another administrator advances policy after the reviewed preview.
c.open('new-role'); c.field('numwant', '24', true); await c.save(); assert.ok(c.state.preview, c.state.formMessage);
response = await transport('/api/v1/peer-policy/quarantine/edge-1', {method: 'PUT', headers: {'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${c.state.policy.revision}"`}, body: JSON.stringify({quarantined: true, if_revision: c.state.policy.revision})});
assert.equal(response.status, 200); await c.save(); assert.equal(writes().at(-1).status, 412);
assert.equal(c.state.editor.stale, true); assert.equal(c.state.form.qos.numwant, '24');
await c.reloadEditor(); assert.equal(c.state.editor.stale, false); assert.equal(c.state.form.qos.numwant, '12'); c.close();
await c.exportCsv(); assert.equal(downloads.length, 1); assert.equal(downloads[0][1], 'roles.csv');
const csv = downloads[0][0]; await c.importFile({name: 'roles.csv', size: Buffer.byteLength(csv), text: async () => csv});
assert.match(c.state.message, /Imported 3 role definition/); assert.match(prompts.at(-1), /Roles missing from the file are removed/);
assert.deepEqual(c.state.definitions['new-role'].qos_state, definition.qos_state);
const before = writes().length; await c.delete('boat'); assert.equal(writes().length, before + 1);
assert.match(c.state.message, /role in use.*edge-1/); assert.equal(writes().at(-1).status, 409);
await c.delete('new-role'); assert.equal(writes().at(-1).status, 204); assert.match(c.state.message, /deleted at policy revision/);
assert.equal(c.state.reviewRequired, false); assert.equal(Object.hasOwn(c.state.definitions, 'new-role'), false);
assert.equal(inventory.state.bulkBusy, false);
'''.replace("CONTROLLER", json.dumps((source / "policies-controller.mjs").as_uri())).replace(
        "INVENTORY", json.dumps((source / "inventory-controller.mjs").as_uri())).replace(
        "BASE", json.dumps("http://127.0.0.1:%d" % server.server_address[1])).replace(
        "AUTH", json.dumps(auth))
    result = subprocess.run([node, "--input-type=module", "-"], input=script,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    status, _, raw = _request(server, "GET", "/api/peer-policy/roles", headers=auth)
    assert status == 200
    assert sorted(json.loads(raw)["roles"]) == ["boat", "fiber"]
