# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped schedule controller against real temporary management API/stores.

No live devices, Console proxy or TLS qualification. No schedule runner starts.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from test_schedule_api import schedule_api, _request


def test_schedule_client_create_history_and_reaffirm_cas(schedule_api):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped schedule controller")
    server, app, auth = schedule_api
    root = Path(__file__).resolve().parents[1] / "console-ui/src"
    setup = r'''
      import assert from 'node:assert/strict';
      import {SchedulesController} from CONTROLLER;
      import {InventoryController} from INVENTORY;
      const base = BASE, auth = AUTH, c = new SchedulesController(), inventory = new InventoryController(), writes = [];
      async function transport(path, options = {}) {
        if (options.method) writes.push({path, ...options});
        return fetch(base + path.replace('/api/v1/', '/api/'), {...options, headers: {...auth, ...options.headers}});
      }
      c.connect({fetch: transport, post: (path, body) => transport(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}),
        headers: extra => ({...extra, 'X-CSRF-Token': auth['X-CSRF-Token']}), claimBulk: () => true, releaseBulk: () => {},
        isVisible: () => true, report: () => {}, refreshInventory: async () => {}, publishSchedules: patch => inventory.update(patch)});
    '''.replace("CONTROLLER", json.dumps((root / "schedules-controller.mjs").as_uri())).replace(
        "INVENTORY", json.dumps((root / "inventory-controller.mjs").as_uri())).replace(
        "BASE", json.dumps("http://127.0.0.1:%d" % server.server_address[1]))

    def run(script, headers):
        result = subprocess.run([node, "--input-type=module", "-"],
                                input=setup.replace("AUTH", json.dumps(headers)) + script,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr

    run(r'''
      inventory.update({selected: new Set(['edge-1']), readOk: true, matchQuery: '', total: 2, images: [{id: 'image-a'}], imagesOk: true});
      c.prerequisites(inventory.state); c.open(inventory.state);
      c.update({form: {...c.state.form, id: 'client-window', scope: 'selection', kind: 'assign', imageIds: ['image-a'], at: '2027-01-01T00:00', tz: 'UTC'}});
      inventory.changeSelection(new Set(['edge-2']));
      await c.create(); assert.equal(c.state.failed, false, c.state.message); assert.equal(writes.length, 1);
      assert.deepEqual(JSON.parse(writes[0].body).target.device_ids, ['edge-1']);
      assert.equal(c.state.rows[0].id, 'client-window'); assert.equal(c.state.history.get('client-window'), null);
      assert.equal(c.state.rows[0].created_by, 'console:alice');
    ''', auth)
    status, _, raw = _request(server, "GET", "/api/schedules/client-window", headers=auth)
    assert status == 200
    assert json.loads(raw)["schedule"]["preview"]["device_ids"] == ["edge-1"]

    app.set_admin("bob", "new-password")
    status, headers, body = _request(server, "POST", "/api/login", {"username": "bob", "password": "new-password"})
    assert status == 200
    bob = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": json.loads(body)["csrf"]}
    run(r'''
      await c.togglePanel(); assert.equal(c.state.rows[0].creator_exists, false);
      const old = c.state.rows[0];
      const edited = await transport('/api/v1/schedules/client-window', {method: 'PATCH',
        headers: {'Content-Type': 'application/json', 'If-Match': old.etag}, body: JSON.stringify({state: 'paused'})});
      assert.equal(edited.status, 200);
      await c.reaffirm('client-window'); assert.match(c.state.message, /changed elsewhere/);
      assert.equal(writes[1].headers['If-Match'], old.etag);
      assert.equal(c.state.rows[0].rev, old.rev + 1);
      await c.reaffirm('client-window'); assert.match(c.state.message, /now owned/);
      assert.equal(c.state.rows[0].created_by, 'console:bob'); assert.equal(c.state.rows[0].creator_exists, true);
      assert.equal(writes.length, 3); assert.equal(writes[2].headers['If-Match'], '"iris-schedule-client-window-2"');
    ''', bob)
