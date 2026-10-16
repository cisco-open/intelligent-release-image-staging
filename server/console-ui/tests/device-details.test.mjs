// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {DeviceDetailsController} from '../src/device-details-controller.mjs';
import {boundarySteps, hardwareRows, imageRows, recordRows, validRecordResponse} from '../src/device-details-model.mjs';

const response = (data, status = 200) => ({ok: status === 200, status, json: async () => data, text: async () => data});
const pending = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; };
const log = file => ({file, finished_at: 1000, action: 'onboard', state: 'done', size: 42, rc: 0});
const data = {device: {model_family: 'XR8000', model: '8201'}, status: {key: 'deployed'}};

function fixture(t) {
  const controller = new DeviceDetailsController(), calls = [], writes = [], confirmations = [];
  const services = {
    fetch: async (url, options) => {
      calls.push([url, options]);
      return response(url.includes('/deployment') ? {record: {record_id: 'new'}, total: 1}
        : url.includes('?device_id=') ? {logs: [log('a.log'), log('b.log')]} : 'new text');
    },
    post: async (url, body) => { writes.push([url, body]); return response({ok: true, peer: 'peer'}); },
    confirm: async text => { confirmations.push(text); return true; },
  };
  controller.connect(services); t.after(() => controller.dispose());
  return {controller, services, calls, writes, confirmations};
}

test('hardware evidence prefers preflight, rejects series aliases and leaves plain text for React', () => {
  assert.deepEqual(hardwareRows({model_family: 'C8xxx', model: 'C8xxx'}, {preflight: {detected_model: 'C8000V'}}),
    [{label: 'Series', value: 'Catalyst Routers'}, {label: 'Chassis model', value: 'C8000V', note: 'last preflight'}]);
  assert.equal(hardwareRows({model: 'NCS'})[1].value, 'Not detected');
  assert.equal(hardwareRows({model: 'NCS', heartbeat_model: '<script>'})[1].value, '<script>');
  assert.equal(hardwareRows({model_family: 'constructor'})[0].value, '—');
  assert.equal(hardwareRows({model: 'inventory'}, {resolved: {model: 'record'}})[1].note, 'deployment record');
});

test('XR host omits non-applicable addressing; router VPG zero and malformed scalars render safely', () => {
  const rows = recordRows({resolved: {management_type: 'xr-host', platform: 'xr-appmgr'}, state: 'active', adopted: true}, 2);
  assert.equal(rows.find(row => row.label === 'Management type').value, 'XR host');
  assert.equal(rows.find(row => row.label === 'Agent install').value, 'XR appmgr container');
  assert.equal(rows.find(row => row.label === 'State').note, 'adopted');
  for (const label of ['Management VLAN / VPG', 'SVI', 'App IP', 'NAT interface']) assert.ok(!rows.some(row => row.label === label));
  const router = recordRows({resolved: {management_type: 'router-nat', vpg_number: 0, platform: 'constructor', app_ip: {}}, timestamps: {planned_at: {}}, state: 'constructor'});
  assert.equal(router.find(row => row.label === 'Management VLAN / VPG').value, 'VPG0');
  assert.equal(router.find(row => row.label === 'App IP').value, '—');
  assert.equal(router[0].badge, 'badge-queued');
  for (const platform of ['router', 'guestshell']) assert.equal(recordRows({resolved: {platform}})
    .find(row => row.label === 'Agent install').value, 'Guest Shell');
  for (const body of [null, {}, {record: []}, {record: {resolved: []}}, {record: null, total: -1}]) assert.equal(validRecordResponse(body), false);
  assert.equal(validRecordResponse({record: null}), true);
});

test('image errors override staged membership and set-wide errors are never assigned to the identity pointer', () => {
  const device = {assigned_image_ids: ['a', 'b', 'c', 'd'], staged_image_ids: ['a', 'b', 'parked'],
    errored_image_ids: ['b'], current_image_id: 'a', stage_state: 'error', stage_error: 'bad hash', last_seen: 1000};
  const rows = imageRows(device, {a: 'a.bin', b: 'b'});
  assert.deepEqual(rows.map(row => row.state), ['ready', 'error', 'staging', 'staging', 'bad hash']);
  assert.equal(rows[0].label, 'a — a.bin'); assert.equal(rows[1].label, 'b');
  assert.equal(rows.at(-1).label, 'Last reported error');
  assert.deepEqual(imageRows({...device, assigned_image_ids: [], assigned_image_id: null}), []);
  assert.equal(imageRows({assigned_image_id: 'new', current_image_id: 'old', stage_state: 'error', last_seen: 1})[0].state, 'pending');
  assert.equal(imageRows({assigned_image_id: 'a', stage_state: 'error', stage_error: 'failure', last_seen: 1})[0].state, 'error — failure');
  assert.equal(imageRows({assigned_image_id: 'constructor'})[0].label, 'constructor');
});

test('boundary uses shared staging status, never onboarding failure or inferred verification', () => {
  assert.deepEqual(boundarySteps({}, {key: 'deployed'}), ['na', 'na', 'upcoming', 'na', 'na', 'na']);
  const device = {assigned_image_ids: ['a']};
  assert.deepEqual(boundarySteps(device, {key: 'deployed'}), ['done', 'na', 'done', 'done', 'na', 'done']);
  for (const key of ['onboard-failed', 'undeploy-failed']) assert.equal(boundarySteps(device, {key})[3], 'na');
  assert.equal(boundarySteps(device, {key: 'placement-failed'})[3].level, 'negative');
  for (const [ratio, level] of [[.25, 'warning'], [.5, 'severe']]) assert.equal(boundarySteps(device, {key: 'image-failed'}, ratio)[3].level, level);
  assert.equal(boundarySteps(device, {key: 'staging'}, 0, {a: true})[1].label, '1 image quarantined');
  assert.equal(boundarySteps({assigned_image_ids: ['constructor']}, {})[1], 'na');
});

test('record and logs start together and fail independently; 404 and no record stay distinct', async t => {
  const {controller, services, calls} = fixture(t), held = pending(), original = services.fetch;
  services.fetch = (url, options) => url.includes('/deployment') ? held.promise : original(url, options);
  const opening = controller.open('x / y', data);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(controller.snapshot().logs.length, 2); assert.equal(controller.snapshot().note, 'Loading…');
  assert.equal(calls[0][0], '/api/v1/deploy-logs?device_id=x%20%2F%20y');
  held.resolve(response({record: []})); await opening;
  assert.match(controller.snapshot().note, /unavailable/);
  services.fetch = async url => response(url.includes('/deployment') ? {record: null} : {logs: null});
  await controller.open('x', data);
  assert.match(controller.snapshot().note, /^No deployment record/);
  assert.match(controller.snapshot().logNote, /unavailable/);
  services.fetch = async () => response({}, 404); await controller.open('x', data);
  assert.match(controller.snapshot().note, /unavailable on this server/);
});

test('an undated saved log remains available in device history', async t => {
  const {controller, services} = fixture(t);
  services.fetch = async url => response(url.includes('/deployment') ? {record: null}
    : {logs: [{...log('undated.log'), finished_at: null, state: null, previous_registration: false}]});
  await controller.open('a', data);
  assert.equal(controller.snapshot().logs.length, 1);
  assert.equal(controller.snapshot().logNote, '');
});

for (const delay of ['headers', 'body']) test(`reopened same device rejects late ${delay} even if abort is ignored`, async t => {
  const {controller, services, calls} = fixture(t), held = pending(), original = services.fetch;
  services.fetch = async (url, options) => {
    calls.push([url, options]);
    return delay === 'headers' ? held.promise : {ok: true, json: () => held.promise};
  };
  const old = controller.open('a', data);
  await Promise.resolve(); await Promise.resolve();
  services.fetch = original;
  await controller.open('b', data); await controller.open('a', data);
  assert.equal(calls[0][1].signal.aborted, true);
  const stale = {record: {record_id: 'old'}, logs: [log('old.log')]};
  held.resolve(delay === 'headers' ? response(stale) : stale); await old;
  assert.equal(controller.snapshot().record.record_id, 'new');
  assert.equal(controller.snapshot().logs[0].file, 'a.log');
});

test('close and disposal invalidate pending reads without reviving the drawer', async t => {
  const {controller, services} = fixture(t), held = pending();
  services.fetch = () => held.promise;
  const old = controller.open('a', data); controller.close(); controller.dispose();
  held.resolve(response({record: null, logs: []})); await old;
  assert.equal(controller.snapshot(), null);
});

test('latest log wins; a late body cannot populate a new device or a reopened same device', async t => {
  const {controller, services} = fixture(t); await controller.open('a', data);
  const held = pending(), original = services.fetch;
  services.fetch = async url => url.endsWith('/a.log') ? {ok: true, text: () => held.promise} : response('new text');
  const old = controller.openFile('a.log'); await controller.openFile('b.log');
  held.resolve('old text'); await old;
  assert.equal(controller.snapshot().file.text, 'new text');
  const other = pending(); services.fetch = () => other.promise;
  const older = controller.openFile('a.log'); services.fetch = original;
  await controller.open('b', data); await controller.open('a', data);
  other.resolve(response('wrong device')); await older;
  assert.equal(controller.snapshot().file, null);
  services.fetch = () => assert.fail('unlisted files must not be fetched');
  await controller.openFile('unlisted');
});

test('host-key action is confirmed, encoded, and cannot be duplicated even after reopening', async t => {
  const {controller, services, writes, confirmations} = fixture(t); await controller.open('a / b', data);
  services.confirm = () => false; await controller.forgetHostKey(); assert.equal(writes.length, 0);
  services.confirm = text => { confirmations.push(text); return true; };
  const held = pending(); services.post = (url, body) => { writes.push([url, body]); return held.promise; };
  const first = controller.forgetHostKey(); await Promise.resolve();
  await controller.forgetHostKey(); await controller.open('a / b', data); await controller.forgetHostKey();
  assert.equal(controller.snapshot().forgetBusy, true); assert.equal(writes.length, 1);
  assert.deepEqual(writes[0], ['/api/v1/devices/a%20%2F%20b/forget-host-key', {}]);
  assert.match(confirmations[0], /First verify.*trust and save any key/);
  held.resolve(response({ok: true, peer: 'peer'})); await first;
  assert.equal(controller.snapshot().forgetBusy, false);
  assert.match(controller.snapshot().forgetStatus, /Earlier host-key request ended/);
});

test('host-key success, rejection, ambiguous outcome and delayed body stay distinct without replay', async t => {
  const {controller, services, writes} = fixture(t); await controller.open('a', data);
  await controller.forgetHostKey(); assert.equal(writes.length, 1);
  assert.match(controller.snapshot().forgetStatus, /Host key forgotten for peer/);
  services.post = async () => response({error: 'rejected'}, 400); await controller.forgetHostKey();
  assert.match(controller.snapshot().forgetStatus, /failed: rejected/);
  for (const post of [async () => { throw new Error('lost response'); }, async () => response({}),
    async () => response({error: 'unavailable'}, 503), async () => ({ok: true, json: async () => { throw new Error('bad json'); }})]) {
    let count = 0; services.post = (...args) => { count++; return post(...args); };
    await controller.forgetHostKey(); assert.equal(count, 1);
    assert.match(controller.snapshot().forgetStatus, /outcome is unknown/);
    assert.equal(controller.snapshot().forgetBusy, false);
  }
  const held = pending(); services.post = async () => ({ok: true, json: () => held.promise});
  const old = controller.forgetHostKey(); await Promise.resolve(); await Promise.resolve();
  await controller.open('b', data); held.resolve({ok: true, peer: 'old peer'}); await old;
  assert.equal(controller.snapshot().forgetStatus, '');
});

test('navigation while confirmation is pending sends no write', async t => {
  const {controller, services, writes} = fixture(t), held = pending();
  await controller.open('a', data); services.confirm = () => held.promise;
  const old = controller.forgetHostKey(); await controller.open('b', data);
  held.resolve(true); await old; assert.equal(writes.length, 0);
});
