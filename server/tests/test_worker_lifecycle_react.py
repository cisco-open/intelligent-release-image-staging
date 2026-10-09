# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped worker UI contracts against authenticated APIs and real approvals."""
import json
import os
from pathlib import Path
import subprocess
import time
import threading

import pytest

import gui_server
import instruction_keys as keys
import trust_rotation
from test_api_split import policy_tiers
from test_gui_server import _serve_full
from test_instruction_keys import _issue, _root_sign
from test_trust_rotation import environment, setup_roots
from test_lifecycle_worker import worker, worker_module


def test_shipped_worker_controller_with_authenticated_native_trust_and_scheduler(environment):
    paths, new, record = setup_roots(environment)
    now = int(time.time())
    certificate = _issue(new['root-a'], Path(paths.public_key), now - 60, now - 60 + 30 * 86400).read_text()
    payload = record['keylist_payload'].encode()
    artifact = keys.assemble_keylist_artifact(payload, _root_sign(payload, new['root-a'])).decode()
    host, port, _, stop = _serve_full(environment)
    server = Path(__file__).parents[1]
    config = dict(origin=f'http://{host}:{port}', directory=str(environment), certificate=certificate, keylist=artifact)
    program = r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {WorkerLifecycleController} from MODULE;
const config = CONFIG, c = new WorkerLifecycleController(), downloads = {}, writes = [];
const login = await fetch(config.origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
c.connect({visible: () => true, uuid: randomUUID, now: Date.now, confirm: () => true, formatDate: String,
  headers: extra => ({...extra, 'X-CSRF-Token': csrf}), download: (name, bytes) => {downloads[name] = bytes;},
  fetch: async (path, options = {}) => {
    if (options.method) writes.push(JSON.parse(options.body));
    const response = await fetch(config.origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
    if (options.method && response.status !== 200) console.error('Native fixture refusal:', await response.clone().json());
    return response;
  }});
const file = text => ({size: Buffer.byteLength(text), text: async () => text});
await c.select('certificates');
for (const name of ['trust', 'rotation', 'maintenance', 'backups']) assert.equal(c.state.valid[name], true, name + ': ' + JSON.stringify(c.state.messages));
c.field('family', 'instruction-roots'); assert.equal(c.item().state, 'awaiting-approval');
c.file('certificate', file(config.certificate)); c.file('keylist', file(config.keylist));
await c.performTrust('approve'); assert.equal(c.item().state, 'approved', c.state.messages.deployment.text);
assert.match(c.state.messages.deployment.text, /Public approval validated/);
await c.performTrust('cancel'); assert.equal(c.item().state, 'cancelled', c.state.messages.deployment.text);
// Native cancellation exposes configured roots, never the discarded candidates.
assert.equal(c.item().roots['root-a'], fs.readFileSync(config.directory + '/old-root-a.pub', 'utf8').split(' ').slice(0, 2).join(' ').trim() + '\n');
c.field('family', 'device-tls'); c.field('names', 'distribution.example,127.0.0.1'); c.field('mode', 'self-signed');
await c.performTrust('prepare'); assert.equal(c.item().state, 'approved', c.state.messages.deployment.text);
await c.performTrust('cancel'); assert.equal(c.item().state, 'cancelled');
c.field('mode', 'ca'); await c.performTrust('prepare'); assert.equal(c.item().state, 'awaiting-approval');
c.downloadTrust(); fs.writeFileSync(config.directory + '/request.csr', downloads['iris-device.csr']);
execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=Fixture CA', '-keyout', config.directory + '/ca.key', '-out', config.directory + '/ca.crt', '-days', '365'], {stdio: 'pipe'});
const leaf = execFileSync('openssl', ['x509', '-req', '-in', config.directory + '/request.csr', '-CA', config.directory + '/ca.crt', '-CAkey', config.directory + '/ca.key', '-set_serial', '17', '-days', '90', '-copy_extensions', 'copyall'], {encoding: 'utf8', stdio: 'pipe'});
c.file('certificate', file(leaf + fs.readFileSync(config.directory + '/ca.crt', 'utf8')));
await c.performTrust('approve'); assert.equal(c.item().state, 'approved', c.state.messages.deployment.text);
await c.performTrust('cancel'); assert.equal(c.item().state, 'cancelled');
c.field('family', 'peer-ca'); await c.performTrust('prepare'); assert.equal(c.item().state, 'approved', c.state.messages.deployment.text);
await c.performTrust('cancel'); assert.equal(c.item().state, 'cancelled');
c.field('family', 'instruction-roots');
for (const name of ['root-a', 'root-b']) {
  c.field('attestRoot', name); await c.performTrust('attestation-request');
  const attestationRequest = c.state.attestation;
  assert.equal(attestationRequest.root_id, name);
  assert.equal(c.item().attestation_request_id, attestationRequest.request_id);
  assert.equal(c.state.messages.deployment.text, 'Public root confirmation request downloaded for ' + name + '. Its holder approves it with that root key, then returns the signed public list.');
  const payload = downloads['keylist-payload.json'];
  const signature = execFileSync('ssh-keygen', ['-Y', 'sign', '-f', config.directory + '/old-' + name, '-n', 'iris-keylist-v1'], {input: payload, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe']});
  c.file('attestation-keylist', file(payload + Buffer.from(signature).toString('base64') + '\n'));
  await c.performTrust('attestation-apply');
  assert.equal(c.state.messages.deployment.text, 'Signed root confirmation applied for ' + name + ', request ' + attestationRequest.request_id + '. Confirm the other root separately.');
  assert.equal(c.item().attestation_request_id, attestationRequest.request_id);
  assert.equal(c.item().attestation_root_id, name);
  assert.ok(c.item().attested_root_ids.includes(name));
  assert.equal(c.item().attestation_applied, undefined, 'GET public status never repeats the POST confirmation');
}
c.scheduleField('family', 'browser-tls'); c.scheduleField('enabled', true);
await c.schedule(); assert.equal(c.state.draftRevision, 1, c.state.messages.maintenance.text);
assert.equal(c.state.maintenance.policies.length, 1); const policyId = c.state.schedule.selected;
c.scheduleField('enabled', false); await c.schedule(); assert.equal(c.state.draftRevision, 2);
assert.equal(c.state.schedule.selected, policyId); assert.equal(c.state.maintenance.policies[0].enabled, false);
assert.ok(writes.every(body => !JSON.stringify(body).includes('PRIVATE KEY')));
assert.equal(writes.length, 15);
console.log('Real public root/TLS approvals, independent attestations and durable schedule revision checks passed.');
'''.replace('MODULE', json.dumps((server / 'console-ui/src/worker-lifecycle-controller.mjs').as_uri())).replace('CONFIG', json.dumps(config))
    try:
        result = subprocess.run(['node', '--input-type=module'], input=program, text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'durable schedule revision checks passed' in result.stdout
    finally:
        stop()


@pytest.mark.parametrize('tier', ['console', 'management'])
def test_trust_approval_transport_cap_is_scoped_authenticated_and_bounded(policy_tiers, monkeypatch, tier):
    request, _, _ = policy_tiers
    calls = []
    monkeypatch.setattr(trust_rotation, 'operate', lambda body: calls.append(body) or {'transport_probe': True})
    endpoint = '/settings/trust-rotation'
    body = {'action': 'approve', 'certificate': 'a\n' * 32760, 'keylist': 'b' * 131072}
    assert request(tier, 'POST', endpoint, body, authorized=False, match=False)[0] == 401
    assert not calls
    status, _, result = request(tier, 'POST', endpoint, body, match=False)
    assert status == 200 and result['transport_probe'] and calls == [body]
    assert request(tier, 'POST', endpoint, declared_length=256 * 1024 + 1, match=False)[0] == 413
    for suffix in ['deployment-rotation', 'key-maintenance', 'backups']:
        assert request(tier, 'POST', '/settings/' + suffix, declared_length=64 * 1024 + 1, match=False)[0] == 413
    assert len(calls) == 1


def test_worker_lifecycle_single_owner_and_scoped_limits():
    server = Path(__file__).parents[1]
    html, app = ((server / 'webroot' / name).read_text() for name in ['index.html', 'app.js'])
    component = (server / 'console-ui/src/worker-lifecycle.jsx').read_text()
    for name in ['worker-lifecycle-root', 'worker-deployment', 'worker-maintenance', 'worker-backups']:
        assert f'id="iris-{name}"' in html
    for name in ['deployment-rotation-family', 'maintenance-save', 'backup-create']:
        assert f'id="{name}"' not in html and f'id="{name}"' in component
        assert f"getElementById('{name}')" not in app
    for name in ['deploymentAction', 'sendMaintenance', 'requestBackupAction']:
        assert f'function {name}' not in app
    assert 'workerLifecycle.select(sub)' in app and 'workerLifecycle.hide()' in app
    assert gui_server._body_limit('/internal/v1/settings/trust-rotation') == 256 * 1024
    assert gui_server._body_limit('/internal/v1/settings/key-maintenance') == 64 * 1024


def test_shipped_worker_controller_regressions():
    suite = Path(__file__).parents[1] / 'console-ui/tests/worker-lifecycle.test.mjs'
    result = subprocess.run(['node', '--test', str(suite)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shipped_backup_controller_with_real_unix_worker_admission(worker, tmp_path, monkeypatch):
    endpoint = tmp_path / 'maintenance.sock'
    monkeypatch.setenv('IRIS_LIFECYCLE_SOCKET', str(endpoint))
    monkeypatch.setenv('IRIS_STATE', str(worker.state_dir))
    calls = []
    # Exercise real admission/journaling/transport, not a deployment cutover.
    monkeypatch.setattr(worker_module.backup, 'create', lambda args: calls.append(args) or 0)
    listener = worker_module.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    console = tmp_path / 'console'
    console.mkdir()
    host, port, _, stop = _serve_full(console)
    module = Path(__file__).parents[1] / 'console-ui/src/worker-lifecycle-controller.mjs'
    program = r'''
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {WorkerLifecycleController} from MODULE;
const origin = ORIGIN;
const login = await fetch(origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
const c = new WorkerLifecycleController(), writes = [];
const transport = async (path, options = {}) => fetch(origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
c.connect({visible: () => true, uuid: randomUUID, now: Date.now, confirm: () => true, formatDate: String,
  headers: extra => ({...extra, 'X-CSRF-Token': csrf}), fetch: async (path, options = {}) => {
    if (options.method) writes.push(JSON.parse(options.body)); return transport(path, options);
  }});
await c.select('backups'); assert.equal(c.state.valid.backups, true); assert.equal(c.state.valid.rotation, true);
assert.equal(c.canBackup('backup'), true); await c.backup('backup');
assert.match(c.state.messages.backups.text, /Accepted operation/, c.state.messages.backups.text);
for (let i = 0; i < 50 && c.state.backups.jobs[0]?.state !== 'captured'; ++i) {
  await new Promise(resolve => setTimeout(resolve, 20)); await c.refreshAll();
}
assert.equal(c.state.backups.jobs.length, 1); const row = c.state.backups.jobs[0];
assert.equal(row.state, 'captured'); assert.equal(row.id, writes[0].request_id); assert.match(row.backup_id, /^[0-9a-f-]{36}$/);
c.field('backupSelected', row.backup_id); assert.equal(c.canBackup('verify'), false, 'Unprovisioned recovery access must not be invented');
const duplicate = await transport('/api/v1/settings/backups', {method: 'POST', headers: c.services.headers({'Content-Type': 'application/json'}), body: JSON.stringify(writes[0])});
assert.equal(duplicate.status, 200); assert.equal((await duplicate.json()).job_id, row.id);
await c.review('backups'); assert.equal(c.state.backups.jobs.length, 1); assert.equal(writes.length, 1);
'''.replace('MODULE', json.dumps(module.as_uri())).replace('ORIGIN', json.dumps(f'http://{host}:{port}'))
    try:
        result = subprocess.run(['node', '--input-type=module'], input=program, text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert len(calls) == 1
    finally:
        stop()
        listener.shutdown()
        listener.server_close()
        thread.join(2)
