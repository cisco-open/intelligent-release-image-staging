# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped Swarm controller against authenticated temporary API and stores.

The swarm producer is real; reports enter its temporary catalog directly.
No device, Console TLS proxy, signed device application or live transfer runs.
"""
import json
from pathlib import Path
import subprocess
import time

import auth
import telemetry

from test_gui_server import (
    _define_device_role, _loaded_peer_policy, _policy_device, _serve_full,
    gui_server,
)


def test_swarm_controller_native_interval_and_report_identity(tmp_path, monkeypatch):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    _policy_device(fleet)
    _define_device_role(cat)
    cat.record_heartbeat("d1", {"peer_telemetry_v": 1,
                               "peer_telemetry_interval_s": 60})
    hub = telemetry.Telemetry(device_info=lambda: cat.device_status())
    hub.registry.announce("a" * 40, "fixture-peer", "192.0.2.1", 6881,
                          left=100, now=time.time(),
                          principal=auth.Principal("device", "d1"))
    monkeypatch.setattr(gui_server, "_default_swarm_fetch", lambda: json.dumps(
        hub.swarm_snapshot(now=time.time())).encode())
    source = Path(__file__).parents[1] / "console-ui/src"
    setup = r'''
import assert from 'node:assert/strict';
import {SwarmMapController} from CONTROLLER;
import {participantRows, peerKey} from MODEL;
const origin = ORIGIN;
const login = await fetch(origin + '/api/login', {method: 'POST',
  headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], calls = [], confirmations = [];
const transport = (path, options = {}) => {
  calls.push({path, options});
  return fetch(origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
};
const c = new SwarmMapController({swarmUrl: '/api/v1/swarm', pull: true}, {
  fetch: transport, now: Date.now, confirm: text => {confirmations.push(text); return true;},
  setTimeout: () => 1, clearTimeout: () => {}, embedded: false, documentHidden: false,
});
await c.start(); assert.equal(c.state.sessionReady, true); assert.equal(c.state.loadFailed, false);
const row = participantRows(c.state.data).find(p => p.device_id === 'd1'); assert.ok(row);
await c.select(peerKey(row));
'''.replace("CONTROLLER", json.dumps((source / "swarm-map-controller.mjs").as_uri())).replace(
        "MODEL", json.dumps((source / "swarm-map-model.mjs").as_uri())).replace(
        "ORIGIN", json.dumps(f"http://{host}:{port}"))

    def run(script):
        result = subprocess.run(["node", "--input-type=module"], input=setup + script,
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    try:
        directive = json.loads(run(r'''
c.setIntervalDraft('10'); await c.saveInterval();
assert.match(c.actionsFor('d1').interval.message, /^Saved\. Waiting for the device/);
assert.equal(c.actionsFor('d1').interval.unknown, false);
assert.equal(confirmations.length, 1); assert.match(confirmations[0], /d1.*10 seconds/);
await c.reviewInterval(); assert.equal(c.actionsFor('d1').interval.draft, '10');
assert.match(c.actionsFor('d1').interval.message, /Current requested interval: 10/);
const missingCsrf = await transport('/api/v1/devices/d1/request-report', {method: 'POST'});
assert.equal(missingCsrf.status, 403);
await c.requestPull(); assert.equal(c.actionsFor('d1').pull.unknown, false);
const accepted = c.actionsFor('d1').pull.request; assert.match(accepted.request_id, /^[a-f0-9]{32}$/);
assert.equal(c.canPull(), false); const count = calls.length;
await c.requestPull(); assert.equal(calls.length, count, 'Pending pull never replays');
console.log(JSON.stringify(accepted)); c.stop();
'''))
        assert cat.pending_request("d1", time.time()) == directive
        assert _loaded_peer_policy(cat).document["roles"]["qos_device"]["d1"][
            "peer_telemetry_interval_s"] == 10
        cat.record_telemetry("d1", {"schema": "v2", "event": "pull",
                                   "report_id": "b" * 32,
                                   "report_request_id": "c" * 32,
                                   "peers": []})
        run(r'''
assert.equal(c.actionsFor('d1').pull.request.request_id, REQUEST_ID);
await c.reviewPull(); assert.equal(c.actionsFor('d1').pull.request.request_id, REQUEST_ID);
assert.doesNotMatch(c.actionsFor('d1').pull.message, /Matching report received/);
c.stop();
'''.replace("REQUEST_ID", json.dumps(directive["request_id"])))
        cat.record_telemetry("d1", {"schema": "v2", "event": "pull",
                                   "report_id": "d" * 32,
                                   "report_request_id": directive["request_id"],
                                   "peers": []})
        assert cat.pending_request("d1", time.time()) is None
        newer = cat.request_report_details("d1", time.time())
        run(r'''
c.action('d1', 'pull', {request: ORIGINAL, unknown: true});
await c.reviewPull(); assert.equal(c.actionsFor('d1').pull.unknown, false);
assert.match(c.actionsFor('d1').pull.message, /Matching report received/);
assert.equal(c.actionsFor('d1').pull.request.request_id, NEWER_ID);
assert.equal(c.canPull(), false, 'Matching A must not erase pending B');
c.stop();
'''.replace("ORIGINAL", json.dumps(directive)).replace("NEWER_ID", json.dumps(newer["request_id"])))
    finally:
        stop()
