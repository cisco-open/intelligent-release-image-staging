# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped action controller against temporary authenticated API and real stores.

No live devices, no Console proxy or TLS qualification.
"""
import json
import csv
import io
from pathlib import Path
import shutil
import subprocess

import pytest
import deployment_records
import gui_fleet

from test_gui_server import _auth, _serve_full


def test_csv_and_retirement_controller_real_api_partial_cleanup(tmp_path, monkeypatch):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the shipped action controller")
    records = deployment_records.DeploymentRecordStore(str(tmp_path / "state"))
    retire = records.retire_device

    def partial(device_id, *args, **kwargs):
        if device_id == "partial":
            raise OSError("fixture record cleanup failure")
        return retire(device_id, *args, **kwargs)

    monkeypatch.setattr(records, "retire_device", partial)
    host, port, (_, fleet, _, _), stop = _serve_full(tmp_path, record_store=records)
    try:
        cookie, csrf = _auth(host, port)
        module = (Path(__file__).resolve().parents[1] / "console-ui/src/inventory-actions-controller.mjs").as_uri()
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=gui_fleet.CSV_V2_COLS)
        writer.writeheader()
        for index, device_id in enumerate(("one", "partial")):
            writer.writerow({"device_id": device_id, "device_ip": "192.0.2.%d" % (index + 1),
                             "management_type": "xr-host", "model": "XR8000", "platform": "xr-appmgr"})
        script = r'''
          import assert from 'node:assert/strict';
          import {InventoryActionsController} from MODULE;
          const base = BASE, headers = HEADERS, c = new InventoryActionsController();
          const calls = [], reports = [], files = [], selection = new Set(['one', 'partial', 'missing']);
          let busy = false;
          async function transport(path, options = {}) {
            calls.push({path, options});
            return fetch(base + path.replace('/api/v1/', '/api/'), {...options, headers: {...headers, ...options.headers}});
          }
          c.connect({fetch: transport, post: (path, body) => transport(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}),
            headers: extra => ({...extra, 'X-CSRF-Token': headers['X-CSRF-Token']}),
            claimBulk: () => { if (busy) return false; busy = true; return true; }, releaseBulk: () => {busy = false;},
            csvBusy: () => {}, confirm: () => true, refreshInventory: async () => {}, report: (...args) => reports.push(args),
            saveCsv: (...args) => files.push(args), removeSelection: ids => ids.forEach(id => selection.delete(id))});
          const text = CSV_TEXT;
          await c.importFile({size: Buffer.byteLength(text), text: async () => text});
          assert.equal(c.state.csvFailed, false, c.state.csvMessage); assert.match(c.state.csvMessage, /Imported 2/); assert.equal(busy, false);
          await c.download('/api/v1/devices/export-csv', 'devices.csv');
          assert.equal(files[0][1], 'devices.csv'); assert.match(files[0][0], /one,192.0.2.1/);
          await c.download('/api/v1/devices/example-csv', 'devices-example.csv'); assert.equal(files[1][1], 'devices-example.csv');
          await c.act('delete', ['one', 'partial', 'missing']);
          assert.deepEqual([...selection], ['partial']); assert.match(reports.at(-1)[0], /2\/3.*partial.*records.*Already absent/s);
          assert.equal(reports.at(-1)[1], true); assert.equal(busy, false);
          const before = calls.length; await c.act('adopt', ['missing']);
          assert.equal(calls.length, before + 1); assert.match(reports.at(-1)[0], /0\/1.*refused/);
          console.log('Actual API CSV import/download and retirement: complete, absent, degraded207 and adoption refusal passed.');
        '''.replace("CSV_TEXT", json.dumps(stream.getvalue())).replace("MODULE", json.dumps(module)).replace("BASE", json.dumps("http://%s:%d" % (host, port))).replace(
            "HEADERS", json.dumps({"Cookie": cookie, "X-CSRF-Token": csrf}))
        result = subprocess.run([node, "--input-type=module", "-"], input=script, text=True,
                                capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert fleet.get_device("one") is None
        assert fleet.get_device("partial") is None
    finally:
        stop()
