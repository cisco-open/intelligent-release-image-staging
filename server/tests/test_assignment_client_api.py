# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the shipped controller against a local authenticated state owner.

Temporary stores and inventory-only writes. No live devices or TLS claim.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from test_gui_server import _auth, _serve_full


def test_assignment_controller_real_api_conflict_and_bulk_partial(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped assignment controller")
    host, port, deps, stop = _serve_full(tmp_path)
    _, fleet, creds, catalog = deps
    try:
        cookie, csrf = _auth(host, port)
        for index, device_id in enumerate(("one", "two")):
            fleet.upsert({"device_id": device_id, "device_ip": "192.0.2.%d" % (index + 1)})
        catalog.save_image({"id": "img2", "filename": "image-two.bin", "sha256": "fixture", "published_at": 2})
        catalog.set_policy("one", approved_image_ids=["img1", "img2"])
        catalog.set_policy("two", approved_image_ids=["img1"])
        creds.set_profile("__none", {"name": "Literal profile", "device_user": "admin", "device_pass": "fixture-only"})
        module = (Path(__file__).resolve().parents[1] / "console-ui/src/assignments-controller.mjs").as_uri()
        source = """
          import assert from 'node:assert/strict';
          import {AssignmentsController} from MODULE;
          const base = BASE, headers = HEADERS, writes = [], reports = [];
          let confirms = 0, locked = false;
          async function transport(path, options = {}) {
            assert.ok(path.startsWith('/api/v1/'));
            return fetch(base + path.replace('/api/v1/', '/api/'), {...options, headers});
          }
          async function post(path, body) {
            writes.push({path, body});
            return transport(path, {method: 'POST', body: JSON.stringify(body)});
          }
          const c = new AssignmentsController();
          c.connect({fetch: transport, post, confirm: () => { confirms++; return true; },
            report: (...args) => reports.push(args), refreshInventory: async () => {},
            claimBulk: () => { if (locked) return false; locked = true; return true; }, releaseBulk: () => { locked = false; },
            claimRow: () => { if (locked) return false; locked = true; return true; }, releaseRow: () => { locked = false; }});
          c.acceptImages({ok: true, body: await (await transport('/api/v1/images')).json()}, c.beginImageRead());
          c.prerequisites({credentials: (await (await transport('/api/v1/credentials')).json()).profiles,
            credentialsOk: true, bulkBusy: false, rowBusy: new Set()});
          await c.openImages(['one', 'two']); assert.equal(c.state.ready, true, c.state.message);
          assert.deepEqual(c.state.chosen, ['img1']); c.toggleImage('img2'); await c.applyImages();
          assert.equal(c.state.open, false); assert.equal(locked, false); assert.equal(confirms, 0);
          assert.deepEqual(writes.map(row => row.body.expect_image_ids), [['img1', 'img2'], ['img1']]);
          await c.openImages(['one'], true);
          const other = await post('/api/v1/devices/one/assign', {image_ids: ['img2'], expect_image_ids: ['img1', 'img2']});
          assert.equal(other.status, 200); const before = writes.length;
          await c.applyImages(); assert.equal(c.state.results[0].kind, 'conflict');
          await c.applyImages(); assert.equal(writes.length, before + 1, 'Conflict is never automatically replayed');
          await c.review(); assert.deepEqual(c.state.chosen, ['img2']); assert.equal(writes.length, before + 1);
          c.close(); c.openCredentials(['one', 'missing']); c.chooseCredential('profile:__none');
          await c.applyCredential(); assert.match(c.state.message, /1\\/2.*missing/); assert.equal(locked, false);
          assert.equal(confirms, 0, 'Literal __none profile is not a clear');
          c.close(); c.openCredentials(['two']); c.chooseCredential('clear'); await c.applyCredential();
          assert.equal(c.state.open, false); assert.equal(confirms, 1); assert.equal(locked, false);
          assert.ok(reports.some(([message]) => message.includes('conflict')));
          console.log('Real API: exact ordered CAS, additive bulk, conflict review, literal profile and partial/clear outcomes passed.');
        """.replace("MODULE", json.dumps(module)).replace("BASE", json.dumps("http://%s:%d" % (host, port))).replace(
            "HEADERS", json.dumps({"Cookie": cookie, "X-CSRF-Token": csrf, "Content-Type": "application/json"}))
        result = subprocess.run([node, "--input-type=module", "-e", source],
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert catalog.get_policy("one")["approved_image_ids"] == ["img2"]
        assert catalog.get_policy("two")["approved_image_ids"] == ["img1", "img2"]
        assert fleet.get_device("one")["credential_profile_id"] == "__none"
        assert fleet.get_device("two")["credential_profile_id"] == ""
    finally:
        stop()
