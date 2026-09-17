# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Run the real CSV controller with local file/API doubles; no fleet writes."""
from pathlib import Path
import subprocess

APP = Path(__file__).resolve().parents[1] / "webroot/app.js"


def run(scenario):
    source = APP.read_text().split("// ---- Device CSV import ----", 1)[1].split(
        "// ---- End device CSV import ----", 1)[0]
    harness = r'''
const assert = require('node:assert/strict');
const elements = new Map();
function el(id) {
  if (!elements.has(id)) elements.set(id, {value:'', disabled:false, hidden:true,
    textContent:'', listeners:{}, addEventListener(k,f) {this.listeners[k]=f;}, click() {}});
  return elements.get(id);
}
const document = {getElementById: el};
const csrfHdr = headers => ({...headers, 'X-CSRF-Token':'test-csrf'});
let calls = [], replies = [], refreshes = 0;
async function fetch(url, options) {
  calls.push({url, options});
  const reply = replies.shift();
  if (reply instanceof Error) throw reply;
  return {status:reply.status, ok:reply.status<400,
    text:async () => typeof reply.body==='string' ? reply.body : JSON.stringify(reply.body)};
}
async function refreshDevices() {refreshes++; el('dev-status').textContent='poll replaced inventory status';}
async function select(file = {size:10, text:async ()=>'device_id\nexample'}) {
  const input = el('csv-file'); input.value='same.csv'; input.files=[file];
  await input.listeners.change({target:input});
  assert.equal(input.value, '', 'Same file must be selectable again');
  assert.equal(el('import-csv').disabled, false);
}
''' + source + '\n(async () => {\n' + scenario + r'''
})().catch(error => {console.error(error); process.exitCode=1;});
'''
    result = subprocess.run(["node", "-"], input=harness, text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


def test_csv_refusal_preserves_context_across_poll_and_same_file_retry():
    run(r'''
for (let i=0;i<2;i++) {
  replies.push({status:422, body:{error:'role_not_found', detail:'unknown role',
    role:'edge<script>', device_id:'edge-1'}});
  await select();
  const message=el('csv-import-status').textContent;
  assert.match(message, /unknown role.*role: edge<script>.*device_id: edge-1/);
  assert.match(message, /Define the role in Policies/);
  assert.equal(el('csv-import-status').className, 'err');
  await refreshDevices();
  assert.equal(el('csv-import-status').textContent, message);
}
assert.equal(calls.length, 2);
assert.equal(calls[0].options.headers['X-CSRF-Token'], 'test-csrf');
''')


def test_csv_bad_bodies_and_network_failure_never_look_successful_or_retry():
    run(r'''
for (const response of [
  {status:413, body:'<html>private proxy diagnostic</html>'},
  {status:502, body:''}, {status:200, body:'not JSON'}, new Error('network failed')
]) {
  const count=calls.length; replies.push(response); await select();
  assert.equal(calls.length,count+1);
  assert.equal(el('csv-import-status').className,'err');
  assert.doesNotMatch(el('csv-import-status').textContent,/private proxy diagnostic/);
}
assert.equal(refreshes,0);
assert.match(el('csv-import-status').textContent,/may have completed/);
''')


def test_csv_local_failure_never_posts_and_success_keeps_its_summary():
    run(r'''
await select({size:9*1024*1024, text:async()=>{throw Error('must not read');}});
assert.match(el('csv-import-status').textContent,/exceeds 8 MiB/);
await select({size:10, text:async()=>{throw Error('read failed');}});
assert.equal(calls.length,0);
assert.match(el('csv-import-status').textContent,/No import request sent/);
replies.push({status:200,body:{imported:2}}); await select();
assert.equal(refreshes,1);
assert.equal(el('csv-import-status').textContent,'Imported 2 device(s).');
''')
