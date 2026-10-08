// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {InventoryActionsController} from '../src/inventory-actions-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {ActivityController} from '../src/activity-controller.mjs';
import {CSV_LIMIT, initialOptions, jobOptions, deviceActionResult} from '../src/inventory-actions-model.mjs';
const reply = (body, status = 200, type = 'text/csv; charset=utf-8') => ({ok: status >= 200 && status < 300, status,
  headers: new Headers({'Content-Type': type}), json: async () => body, text: async () => body});
const gate = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
function fixture() {
  const c = new InventoryActionsController(), inventory = new InventoryController(), requests = [], messages = [], saved = [], confirms = [];
  let visible = true, refreshes = 0;
  c.connect({fetch: async (path, options) => { requests.push({path, options}); return reply(path.includes('import-csv') ? {imported: 2} : {deleted: true, degraded: []}); },
    post: async (path, body) => { requests.push({path, body}); return reply({record_id: 'record'}); }, headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}),
    confirm: message => { confirms.push(message); return true; }, report: (...message) => messages.push(message),
    claimBulk: () => { if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; inventory.update({bulkBusy: true}); return true; },
    releaseBulk: () => inventory.update({bulkBusy: false}), csvBusy: csvBusy => inventory.update({csvBusy}),
    removeSelection: ids => inventory.removeSelection(ids), startJobs: async (...args) => requests.push(args),
    refreshInventory: async () => { refreshes++; }, isVisible: () => visible, saveCsv: (...args) => saved.push(args)});
  inventory.subscribe(() => c.prerequisites(inventory.state));
  return {c, inventory, requests, messages, saved, confirms, refreshes: () => refreshes, hide: () => { visible = false; c.hide(); }};
}
test('job options have independent defaults and omit force unless explicitly set', () => {
  assert.deepEqual(jobOptions('onboard'), {telemetry: true, telemetry_stream: false, log: false});
  assert.deepEqual(jobOptions('undeploy'), {log: false});
  assert.deepEqual(jobOptions('onboard', {...initialOptions(), force: true, undeployLog: true}), jobOptions('onboard'));
  assert.throws(() => jobOptions('reload'));
});
for (const telemetry of [false, true]) for (const telemetry_stream of [false, true]) for (const log of [false, true]) {
  test(`real Activity submission captures options and targets: ${telemetry}/${telemetry_stream}/${log}`, async () => {
    const {c, requests, inventory} = fixture();
    const activity = new ActivityController({setTimer: () => 1, clearTimer() {}}); activity.visible = true;
    activity.connect({fetch: async () => reply({jobs: []}), confirm: () => true,
      post: async (path, body) => { requests.push({path, body}); c.option('telemetry', !telemetry); return reply({job_id: path}); }});
    c.services.startJobs = (...args) => activity.start(...args);
    const ids = ['a/b', 'two']; c.open('onboard', ids); ids.push('unreviewed');
    c.option('telemetry', telemetry); c.option('telemetry_stream', telemetry_stream); c.option('onboardLog', log);
    await c.start(); assert.equal(inventory.state.bulkBusy, false); assert.equal(c.state.dialog, null);
    assert.deepEqual(requests, ['a%2Fb', 'two'].map(id => ({path: '/api/v1/devices/' + id + '/onboard', body: {telemetry, telemetry_stream, log}})));
    activity.dispose();
  });
}
test('job dialog options persist, captured IDs survive selection changes, cancel never submits', async () => {
  const {c, requests} = fixture(); c.open('undeploy', ['one']); c.option('force', true); c.option('undeployLog', true); c.close();
  await c.start(); assert.deepEqual(requests, []); c.open('undeploy', ['two']); await c.start();
  assert.deepEqual(requests, [['undeploy', ['two'], {force: true, log: true}]]);
});
test('pending job locks survive close/reopen and unexpected bridge failure is unknown', async () => {
  const {c, inventory, messages} = fixture(), pending = gate(); c.services.startJobs = () => pending.promise;
  c.open('onboard', ['one']); const job = c.start(); c.open('undeploy', ['two']); await c.start();
  assert.equal(c.state.dialog, null); assert.equal(inventory.state.bulkBusy, true);
  pending.reject(Error('lost')); await job; assert.equal(inventory.state.bulkBusy, false); assert.match(messages.at(-1)[0], /unknown.*Activity/);
});
test('active row and bulk operations refuse new writes without releasing their locks', async () => {
  const {c, inventory, requests} = fixture(); c.open('onboard', ['one']); inventory.claimRow('other'); await c.start();
  await c.act('delete', ['one']); await c.importFile({size: 5, text: async () => 'hello'});
  assert.deepEqual(requests, []); assert.equal(inventory.state.rowBusy.has('other'), true);
  inventory.releaseRow('other'); inventory.update({bulkBusy: true}); await c.start(); assert.equal(inventory.state.bulkBusy, true);
});
test('delete/adopt require named acknowledgement; cancel and invalid targets send nothing', async () => {
  const {c, requests, confirms} = fixture(); c.services.confirm = message => { confirms.push(message); return false; };
  await c.act('delete', ['one']); await c.act('adopt', ['two']); await c.act('delete', ['one', 'one']);
  assert.deepEqual(requests, []); assert.match(confirms[0], /one.*does NOT undeploy.*cannot be undone/s);
  assert.match(confirms[1], /two.*IRIS-owned.*Routers cannot be adopted/s);
});
test('retirement validates partial, absent, refused and unknown bodies; retains incomplete selections', async () => {
  const {c, inventory, messages, requests} = fixture(); inventory.changeSelection(new Set(['removed', 'partial', 'absent', 'lost', 'malformed', 'refused', 'elsewhere']));
  c.services.fetch = async (path, options) => { requests.push({path, options}); const id = path.split('/').at(-1);
    if (id === 'lost') throw Error('lost');
    return reply(id === 'malformed' ? {} : id === 'refused' ? {error: 'busy'} : {deleted: id !== 'absent', degraded: id === 'partial' ? ['records'] : []},
      id === 'partial' ? 207 : id === 'refused' ? 409 : 200); };
  await c.act('delete', ['removed', 'partial', 'absent', 'lost', 'malformed', 'refused']);
  assert.deepEqual([...inventory.state.selected], ['partial', 'lost', 'malformed', 'refused', 'elsewhere']);
  assert.match(messages.at(-1)[0], /2\/6.*partial.*records.*Already absent.*unknown.*refused/s); assert.equal(messages.at(-1)[1], true);
  assert.ok(requests.every(row => row.options.method === 'DELETE' && row.options.headers['X-CSRF-Token'] === 'fixture'));
});
test('adoption checks record identity, explicit payload and does not change selection', async () => {
  const {c, inventory, messages, requests} = fixture(); inventory.changeSelection(new Set(['one', 'two']));
  c.services.post = async (path, body) => { requests.push({path, body}); return reply(path.includes('/one/') ? {record_id: 'saved'} : {}); };
  await c.act('adopt', ['one', 'two']); assert.equal(inventory.state.selected.size, 2);
  assert.deepEqual(requests.map(row => row.body), [{acknowledge_adopt: true}, {acknowledge_adopt: true}]); assert.match(messages.at(-1)[0], /1\/2.*two: unknown/);
});
for (const body of [{}, {deleted: 'true', degraded: []}, {deleted: true}, {deleted: true, degraded: [3]}]) {
  test('malformed retirement is unknown: ' + JSON.stringify(body), () => assert.equal(deviceActionResult('delete', reply(body), body).kind, 'unknown'));
}
test('500 write errors and malformed 207 are never complete; 4xx is explicit refusal', () => {
  assert.equal(deviceActionResult('delete', reply({}, 500), {}).kind, 'unknown');
  assert.equal(deviceActionResult('delete', reply({}, 403), {}).kind, 'refused');
  assert.equal(deviceActionResult('delete', reply({}, 207), {deleted: true, degraded: []}).kind, 'unknown');
});
test('destructive batch bounds requests and survives hiding without hidden refresh', async () => {
  const {c, hide, refreshes, inventory} = fixture(), waiting = [], ids = Array.from({length: 7}, (_, i) => String(i));
  c.services.fetch = () => { const pending = gate(); waiting.push(pending); return pending.promise; };
  const job = c.act('delete', ids); assert.equal(waiting.length, 4); hide(); await c.act('delete', ids); assert.equal(waiting.length, 4);
  for (let i = 0; i < ids.length; i++) { waiting[i].resolve(reply({deleted: true, degraded: []})); await new Promise(resolve => setImmediate(resolve)); }
  await job; assert.equal(refreshes(), 0); assert.equal(inventory.state.bulkBusy, false);
});
test('CSV import keeps dedicated feedback and exact text/CSRF, with shared lock through file read', async () => {
  const {c, inventory, requests, refreshes} = fixture(), waiting = gate();
  const job = c.importFile({size: 20, text: () => waiting.promise});
  assert.equal(inventory.state.csvBusy, true); assert.equal(inventory.state.bulkBusy, true);
  await c.importFile({size: 1, text: async () => 'ignored'}); waiting.resolve('device_id\none'); await job;
  assert.deepEqual(requests, [{path: '/api/v1/devices/import-csv', options: {method: 'POST', headers: {'Content-Type': 'text/csv', 'X-CSRF-Token': 'fixture'}, body: 'device_id\none'}}]);
  assert.equal(c.state.csvMessage, 'Imported 2 device(s).'); assert.equal(refreshes(), 1); assert.equal(inventory.state.bulkBusy, false); assert.equal(inventory.state.csvBusy, false);
  inventory.update({message: 'poll'}); assert.equal(c.state.csvMessage, 'Imported 2 device(s).');
});
test('CSV preflight and local read failures never POST', async () => {
  const {c, requests} = fixture();
  for (const size of [CSV_LIMIT + 1, -1, NaN]) await c.importFile({size, text: async () => { throw Error('must not read'); }});
  await c.importFile({size: 0, text: async () => { throw Error('cannot read'); }}); assert.match(c.state.csvMessage, /Cannot read/);
  await c.importFile({size: 1, text: async () => 'x'.repeat(CSV_LIMIT + 1)}); assert.match(c.state.csvMessage, /exceeds/); assert.deepEqual(requests, []);
});
for (const mode of ['refused', 'html', 'network', 'invalid', 'server']) test(`CSV ${mode} cannot look successful or replay`, async () => {
  const {c, requests, inventory} = fixture();
  c.services.fetch = async () => { requests.push(1); if (mode === 'network') throw Error('lost');
    if (mode === 'html') return {ok: false, status: 502, json: async () => { throw Error('<private proxy>'); }};
    return reply(mode === 'refused' ? {error: 'role_not_found', detail: 'unknown role', role: 'edge<script>', device_id: 'one'} : {},
      mode === 'refused' ? 422 : mode === 'server' ? 503 : 200); };
  await c.importFile({size: 1, text: async () => 'x'}); assert.equal(requests.length, 1); assert.equal(c.state.csvFailed, true);
  assert.doesNotMatch(c.state.csvMessage, /private proxy|Imported/); assert.equal(inventory.state.bulkBusy, false);
  if (mode === 'refused') assert.match(c.state.csvMessage, /edge<script>.*one.*Define the role/s);
});
test('submitted import survives hide but successful completion starts no hidden read', async () => {
  const {c, hide, refreshes} = fixture(), waiting = gate(); c.services.fetch = () => waiting.promise;
  const job = c.importFile({size: 1, text: async () => 'x'}); await Promise.resolve(); hide(); waiting.resolve(reply({imported: 1})); await job;
  assert.equal(c.state.csvMessage, 'Imported 1 device(s).'); assert.equal(refreshes(), 0);
});
test('downloads require CSV content, retain exact filename and reject unexpected paths', async () => {
  const {c, saved, requests} = fixture(); c.services.fetch = async (path, options) => { requests.push({path, options}); return reply('device_id\none'); };
  await c.download('/api/v1/devices/export-csv', 'devices.csv'); assert.deepEqual(saved, [['device_id\none', 'devices.csv']]);
  await c.download('/api/v1/devices/export-csv', 'unexpected.html'); await c.download('/other', 'devices.csv'); assert.equal(requests.length, 1);
  c.services.fetch = async () => reply('<private proxy>', 200, 'text/html'); await c.download('/api/v1/devices/example-csv', 'devices-example.csv');
  assert.equal(saved.length, 1); assert.equal(c.state.downloadFailed, true); assert.doesNotMatch(c.state.downloadMessage, /private proxy/);
});
test('closed/reopened download rejects late body/failure and does not cancel a newer request', async () => {
  const {c, saved} = fixture(), waiting = gate(); let signal;
  c.services.fetch = async (path, options) => { signal = options.signal; return {...reply(''), text: () => waiting.promise}; };
  const old = c.download('/api/v1/devices/export-csv', 'devices.csv'); await Promise.resolve(); c.hide(); assert.equal(signal.aborted, true);
  c.services.fetch = async () => reply('new'); await c.download('/api/v1/devices/export-csv', 'devices.csv'); waiting.resolve('old'); await old;
  assert.deepEqual(saved, [['new', 'devices.csv']]); assert.match(c.state.downloadMessage, /Downloaded/);
});
test('parallel downloads both arrive but an older failure cannot replace newer status', async () => {
  const {c, saved} = fixture(), waiting = gate(); c.services.fetch = path => path.includes('example') ? Promise.resolve(reply('example')) : waiting.promise;
  const old = c.download('/api/v1/devices/export-csv', 'devices.csv'); await c.download('/api/v1/devices/example-csv', 'devices-example.csv');
  waiting.reject(Error('lost')); await old; assert.deepEqual(saved, [['example', 'devices-example.csv']]); assert.equal(c.state.downloadMessage, 'Downloaded devices-example.csv.');
});
