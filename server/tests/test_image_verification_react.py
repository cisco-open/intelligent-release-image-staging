# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped verification controller against authenticated HTTP and signed feeds."""
import io
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess
import tarfile
import threading

import bulkhash_refresh
from test_gui_server_bulkhash import _entry, _serve, _throwaway_keypair


def test_shipped_verification_controller_with_native_schedule_signature_and_quarantine(tmp_path, monkeypatch):
    certificate, key = _throwaway_keypair(tmp_path, "react-feed")
    csv = ("FILE_NAME,MD5_CHECKSUM,SHA512_CHECKSUM,PUBLISH_DATE,DEFERRAL_STATUS,IMAGE_SIZE\r\n"
           "match.bin," + "ab" * 16 + "," + "aa" * 64 + ",August 03 2016 00:00:00 PDT-0700,,5\r\n"
           "mismatch.bin," + "ab" * 16 + "," + "bb" * 64 + ",August 03 2016 00:00:00 PDT-0700,,5\r\n").encode()
    signature = subprocess.check_output(["openssl", "dgst", "-sha512", "-sign", key], input=csv)

    def archive(name, signed):
        path = tmp_path / name
        with tarfile.open(path, "w:gz") as bundle:
            members = [("feed.csv", csv)] + ([("feed.csv.signature", signature)] if signed else [])
            for member, data in members:
                info = tarfile.TarInfo(member)
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
        return path

    signed = archive("signed.tar", True)
    unsigned = archive("unsigned.tar", False)

    class Feed(BaseHTTPRequestHandler):
        def do_GET(self):
            body = signed.read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    feed = HTTPServer(("127.0.0.1", 0), Feed)
    thread = threading.Thread(target=feed.serve_forever, daemon=True)
    thread.start()
    native_refresh = bulkhash_refresh.run_refresh

    def local_refresh(source, state_dir, catalog, **kwargs):
        # Keep the real fetch/verify/parse/reconcile/persist pipeline. Only its
        # external trust fixture and URL change; no unsigned verification seam.
        return native_refresh(source, state_dir, catalog, cert_path=certificate,
                              feed_url=f"http://127.0.0.1:{feed.server_port}/feed.tar", **kwargs)

    monkeypatch.setattr(bulkhash_refresh, "run_refresh", local_refresh)
    host, port, (_, _, _, catalog), state, _, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state)
    for identifier in ("match", "mismatch", "absent"):
        catalog.save_image(_entry(identifier, identifier + ".bin"))
    server = Path(__file__).parents[1]
    program = r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {ImageVerificationController} from MODULE;
const config = CONFIG, writes = [], c = new ImageVerificationController();
const login = await fetch(config.origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
const request = (path, options = {}) => fetch(config.origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
let consumers = 0;
c.connect({visible: () => true, confirm: () => true, formatDate: String,
  headers: extra => ({...extra, 'X-CSRF-Token': csrf}), catalogChanged: async () => {consumers++;},
  fetch: async (path, options = {}) => {if (options.method) writes.push({path, body: JSON.parse(options.body)}); return request(path, options);},
  xhr: () => ({headers: {}, upload: {}, open(method, path) {this.method = method; this.path = path;},
    setRequestHeader(name, value) {this.headers[name] = value;},
    async send(file) {
      writes.push({path: this.path, name: file.name});
      try {
        const response = await request(this.path, {method: this.method, headers: this.headers, body: file.bytes});
        this.status = response.status; this.responseText = await response.text(); this.onload();
      } catch {this.onerror();}
    }})});
c.select('settings-pane-bulkhash'); await c.refresh(); assert.equal(c.state.valid, true);
assert.equal(c.state.data.last_run.at, null);
c.field('mode', 'weekly'); c.field('hour', '8'); await c.perform('schedule');
assert.equal(c.state.messages.schedule.kind, 'success', c.state.messages.schedule.text);
assert.deepEqual([c.state.data.mode, c.state.data.hour_utc], ['weekly', 8]);
await c.perform('refresh'); assert.equal(c.state.messages.refresh.kind, 'success', c.state.messages.refresh.text);
assert.match(c.state.messages.refresh.text, /1 matched, 1 mismatched, 1 not in feed/);
assert.equal(c.state.data.last_run.source, 'manual'); assert.equal(c.state.data.last_run.outcome, 'ok');
const images = async () => (await (await request('/api/v1/images')).json()).images;
const before = await images();
assert.equal(before.find(row => row.id === 'match').hash_verification.state, 'verified');
assert.equal(before.find(row => row.id === 'mismatch').quarantined, true);
assert.equal(before.find(row => row.id === 'absent').hash_verification.state, 'not_in_feed');
const upload = async name => {const bytes = fs.readFileSync(config[name]); await c.perform('offline', {name: name + '.tar', size: bytes.length, bytes});};
await upload('signed'); assert.equal(c.state.messages.offline.kind, 'success', c.state.messages.offline.text);
assert.equal(c.state.data.last_run.source, 'offline'); const verified = await images();
await upload('unsigned'); assert.equal(c.state.messages.offline.kind, 'error', c.state.messages.offline.text);
assert.match(c.state.messages.offline.text, /^Check failed:/); assert.match(c.state.data.last_run.outcome, /^fail: /);
assert.equal(c.state.data.last_run.matched, null);
assert.deepEqual(await images(), verified, 'Unsigned upload must not change previous verdicts or quarantine');
assert.equal(c.state.unknown, false); assert.equal(consumers, 3); assert.equal(writes.length, 4);
assert.deepEqual(writes[0].body, {mode: 'weekly', hour_utc: 8});
console.log('Native signed feed, failed signature, exact counts, schedule and quarantine passed.');
'''.replace("MODULE", json.dumps((server / "console-ui/src/image-verification-controller.mjs").as_uri())).replace("CONFIG", json.dumps({
        "origin": f"http://{host}:{port}", "signed": str(signed), "unsigned": str(unsigned)}))
    try:
        result = subprocess.run(["node", "--input-type=module"], input=program,
                                text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "schedule and quarantine passed" in result.stdout
        assert (Path(state) / bulkhash_refresh.OFFLINE_CACHE).read_bytes() == signed.read_bytes()
    finally:
        stop()
        feed.shutdown()
        feed.server_close()
        thread.join(5)
