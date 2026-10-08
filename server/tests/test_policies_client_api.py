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

from test_schedule_api import schedule_api, _request


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
