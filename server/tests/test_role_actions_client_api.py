# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped role controller against authenticated temporary API and real stores.

HTTP fixture only: no live devices, Console proxy or TLS qualification.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from test_schedule_api import schedule_api, _request


def test_role_actions_capture_targets_report_partial_and_keep_cas(schedule_api):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped role controller")
    server, _app, auth = schedule_api
    source = Path(__file__).resolve().parents[1] / "console-ui/src"
    script = r'''
      import assert from 'node:assert/strict';
      import {RoleActionsController} from CONTROLLER;
      import {InventoryController} from INVENTORY;
      const base = BASE, auth = AUTH, c = new RoleActionsController(), inventory = new InventoryController(), calls = [], reports = [];
      async function transport(path, options = {}) {
        const response = await fetch(base + path.replace('/api/v1/', '/api/'), {...options, headers: {...auth, ...options.headers}});
        calls.push({path, options, status: response.status}); return response;
      }
      async function refresh() {
        const response = await transport('/api/v1/peer-policy'); assert.equal(response.status, 200);
        inventory.update({policy: await response.json(), policyOk: true}); return true;
      }
      c.connect({fetch: transport, headers: extra => ({...extra, 'X-CSRF-Token': auth['X-CSRF-Token']}),
        warning: () => '', policyWriteBusy: () => false, isVisible: () => true, confirm: () => true,
        claimBulk() {if (inventory.state.bulkBusy) return false; inventory.update({bulkBusy: true}); return true;},
        releaseBulk() {inventory.update({bulkBusy: false});}, invalidatePolicyReads() {},
        report: (...args) => reports.push(args), refreshInventory: refresh});
      inventory.subscribe(() => c.prerequisites(inventory.state)); await refresh();
      inventory.changeSelection(new Set(['edge-1', 'edge-2', 'missing'])); c.open(inventory.selectedIds()); c.choice('boat');
      inventory.changeSelection(new Set(['edge-2'])); const baseRevision = inventory.state.policy.revision;
      await c.apply(); assert.ok(c.state.preview, c.state.message); assert.equal(c.state.preview.body.applied, 2);
      assert.equal(c.state.preview.body.failed.missing, 'no such device');
      await c.apply(); assert.match(c.state.message, /2\/3.*missing.*role drift: 0/); assert.equal(c.state.failed, true);
      let writes = calls.filter(call => call.options.method);
      assert.equal(writes.length, 2); assert.deepEqual(JSON.parse(writes[1].options.body).device_ids, ['edge-1', 'edge-2', 'missing']);
      assert.equal(writes[0].options.headers['If-Match'], `"iris-peer-policy-${baseRevision}"`);
      assert.equal(writes[1].options.headers['If-Match'], writes[0].options.headers['If-Match']);
      c.close(); c.open(['edge-1', 'edge-2']); c.choice('__none'); await c.apply(); await c.apply();
      assert.equal(c.state.open, false, c.state.message); assert.equal(reports.at(-1)[1], false);
      assert.deepEqual(inventory.state.policy.roles.members, {boat: 0, fiber: 0});
      assert.equal(inventory.state.policy.role_drift.count, 0);
      c.open(['edge-1', 'edge-2']); c.choice('fiber'); await c.apply(); assert.ok(c.state.preview, c.state.message);
      const reviewed = c.state.preview.revision;
      // Another administrator changes policy after preview, through the real API.
      const changed = await transport('/api/v1/peer-policy/quarantine/edge-1', {method: 'PUT',
        headers: {'Content-Type': 'application/json', 'If-Match': `"iris-peer-policy-${reviewed}"`},
        body: JSON.stringify({quarantined: true, if_revision: reviewed})}); assert.equal(changed.status, 200);
      await c.apply(); assert.match(c.state.message, /Peer policy changed/); assert.equal(c.state.preview, null);
      writes = calls.filter(call => call.options.method); assert.equal(writes.at(-1).status, 412);
      c.close(); await c.quarantine(['edge-1', 'edge-2'], false);
      assert.deepEqual(c.state.results.map(row => row.result), ['saved', 'saved']);
      assert.deepEqual(inventory.state.policy.quarantine_assignments, []);
      // Send a confirmed stale revision: the client must consume one 412, read,
      // and retry exactly once with the new revision before continuing.
      const current = inventory.state.policy.revision;
      inventory.update({policy: {...inventory.state.policy, revision: current - 1}});
      const before = calls.length; await c.quarantine(['edge-1', 'edge-2'], true);
      const attempts = calls.slice(before).filter(call => call.options.method);
      assert.deepEqual(attempts.map(call => call.status), [412, 200, 200]);
      assert.deepEqual(c.state.results.map(row => row.result), ['saved', 'saved']);
      assert.deepEqual([...inventory.state.policy.quarantine_assignments].sort(), ['edge-1', 'edge-2']);
      assert.equal(inventory.state.bulkBusy, false);
    '''.replace("CONTROLLER", json.dumps((source / "role-actions-controller.mjs").as_uri())).replace(
        "INVENTORY", json.dumps((source / "inventory-controller.mjs").as_uri())).replace(
        "BASE", json.dumps("http://127.0.0.1:%d" % server.server_address[1])).replace(
        "AUTH", json.dumps(auth))
    result = subprocess.run([node, "--input-type=module", "-"], input=script,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    status, _, raw = _request(server, "GET", "/api/peer-policy", headers=auth)
    assert status == 200
    assert sorted(json.loads(raw)["quarantine_assignments"]) == ["edge-1", "edge-2"]
