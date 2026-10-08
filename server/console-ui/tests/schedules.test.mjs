// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {SchedulesController} from '../src/schedules-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {initialForm, checkedSchedules, formDefinition, scheduleWriteResult, historyText} from '../src/schedules-model.mjs';

const reply = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const gate = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
const tick = () => new Promise(resolve => setImmediate(resolve));
const row = (id = 'nightly', rev = 1) => ({id, rev, etag: `"iris-schedule-${id}-${rev}"`, kind: 'assign', state: 'pending',
  target: {filters: {}, device_ids: ['one'], bind: 'late'}, preview: {device_ids: ['one']}, created_by: 'console:operator', creator_exists: true,
  next_fire: {local_time: '2027-01-01T02:30', tz: 'Europe/Stockholm', status: 'future'}});
const list = rows => ({schedules: rows, total: rows.length});
const occurrence = id => ({schedule_id: id, state: 'completed', delta: {added: 1, removed: 0}});
function fixture() {
  const c = new SchedulesController(), inventory = new InventoryController(), calls = [], reports = [];
  let visible = true, refreshes = 0;
  const fetch = async (path, options = {}) => {
    calls.push({path, options});
    if (path === '/api/v1/schedules') return reply(list([row()]));
    const id = path.split('/')[4];
    if (path.endsWith('/reaffirm')) return reply({schedule: row(id, 2)});
    return reply({total: 1, offset: 0, occurrences: [occurrence(id)]});
  };
  c.connect({fetch, post: async (path, body) => {calls.push({path, body}); return reply({schedule: row(body.id)}, 201);},
    headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), isVisible: () => visible,
    claimBulk() {if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; inventory.update({bulkBusy: true}); return true;},
    releaseBulk() {inventory.update({bulkBusy: false});}, publishSchedules: patch => inventory.update(patch),
    report: (...args) => reports.push(args), refreshInventory: async () => {refreshes++;}});
  inventory.subscribe(() => c.prerequisites(inventory.state));
  inventory.update({selected: new Set(['one', 'two']), total: 2, readOk: true, matchQuery: '', images: [{id: 'image-a'}], imagesOk: true});
  const open = () => {c.open(inventory.state); c.update({form: {...c.state.form, id: 'nightly', at: '2027-01-01T00:00', tz: 'UTC', imageIds: ['image-a']}});};
  return {c, inventory, calls, reports, open, hide() {visible = false; c.hide();}, refreshes: () => refreshes};
}
test('create captures reviewed selection and exact once fields, never new live targets', async () => {
  const {c, inventory, calls, open} = fixture(); open(); c.field('scope', 'selection');
  inventory.changeSelection(new Set(['not-reviewed'])); await c.create();
  assert.deepEqual(calls[0], {path: '/api/v1/schedules', body: {id: 'nightly', kind: 'assign',
    target: {filters: {}, device_ids: ['one', 'two'], bind: 'late'}, payload: {image_ids: ['image-a'], mode: 'merge'},
    when: {kind: 'once', at: Math.floor(new Date('2027-01-01T00:00').getTime() / 1000), tz: 'UTC', window_seconds: 3600}}});
  assert.equal(c.state.dialog, null); assert.equal(c.state.panelOpen, true); assert.equal(inventory.state.bulkBusy, false);
});
test('reviewed filter, all wire names, recurring onboard defaults and server next slot survive later edits', async () => {
  const {c, inventory, calls, open} = fixture();
  const filters = {q: 'edge', managementType: 'xr-host', platform: 'xr-appmgr', cred: 'named', telemetry: 'on', peer: 'online', role: 'core', modelFamily: 'XR8000', osFamily: 'xr', status: 'deployed'};
  const {filterQuery} = await import('../src/inventory-model.mjs'); inventory.update({filters, matchQuery: filterQuery(filters)}); open();
  c.field('kind', 'onboard'); c.field('when', 'recurring'); c.field('tz', 'Europe/Stockholm');
  inventory.update({filters: {...filters, role: 'different'}}); await c.create();
  assert.deepEqual(calls[0].body.target, {filters: {q: 'edge', management_type: 'xr-host', platform: 'xr-appmgr', cred: 'named', telemetry: 'on', peer: 'online', role: 'core', model_family: 'XR8000', os_family: 'xr', status: 'deployed'}, device_ids: [], bind: 'late'});
  assert.deepEqual(calls[0].body.payload, {telemetry: true, telemetry_stream: false, mode: 'new-only', max_devices: 20});
  assert.deepEqual(calls[0].body.when, {kind: 'recurring', weekday: 6, hour: 2, minute: 30, tz: 'Europe/Stockholm', window_seconds: 3600});
  assert.match(c.state.message, /2027-01-01T02:30 Europe\/Stockholm/);
});
test('unconfirmed filter cannot silently target the fleet; explicit selection remains available', async () => {
  const {c, inventory, calls, open} = fixture(); inventory.update({readOk: false}); open();
  assert.equal(c.state.form.scope, 'selection'); c.field('scope', 'filter'); await c.create();
  assert.equal(calls.length, 0); assert.match(c.state.formMessage, /preview unavailable/);
});
test('close sends nothing and keeps form choices but reopening captures new targets', () => {
  const {c, inventory, calls, open} = fixture(); open(); c.field('mode', 'replace'); c.close(); inventory.changeSelection(new Set(['three'])); c.open(inventory.state);
  assert.deepEqual(c.state.dialog.ids, ['three']); assert.equal(c.state.form.mode, 'replace'); assert.equal(calls.length, 0);
});
for (const [field, value] of [['id', '../bad'], ['when', 'bad'], ['scope', 'bad'], ['kind', 'bad'], ['at', ''], ['windowMinutes', ''], ['windowMinutes', '10081'], ['windowMinutes', '0.001'], ['imageIds', []], ['imageIds', ['image-a', 'image-a']], ['mode', 'bad']]) {
  test(`invalid ${field} ${JSON.stringify(value)} sends no request`, async () => {
    const {c, calls, open} = fixture(); open(); c.field(field, value); await c.create(); assert.equal(calls.length, 0); assert.ok(c.state.formMessage);
  });
}
test('recurring time, onboard cap, timezone and changed/quarantined catalog fail closed', () => {
  const dialog = {ids: ['one'], filters: {}, filterReady: true}, form = {...initialForm(), id: 'nightly', tz: 'UTC', when: 'recurring', kind: 'onboard'};
  for (const patch of [{time: '25:00'}, {time: ''}, {weekday: '7'}, {tz: ''}, {maxDevices: '1.5'}, {maxDevices: '0'}, {maxDevices: '20001'}]) assert.throws(() => formDefinition({...form, ...patch}, dialog, [], false));
  for (const [images, ok] of [[[], false], [[], true], [[{id: 'image-a', quarantined: true}], true]]) assert.throws(() => formDefinition({...form, kind: 'assign', imageIds: ['image-a']}, dialog, images, ok));
  assert.equal(formDefinition({...form, imageIds: Array.from({length: 11}, (_, i) => 'unused-' + i)}, dialog, [], false).payload.max_devices, 20);
});
for (const mode of ['lost', 'malformed', 'wrong-id', 'server']) test(`creation ${mode} is unknown, locks until response, blocks retry until explicit review`, async () => {
  const {c, inventory, calls, open} = fixture(), pending = gate(); open(); c.services.post = (path, body) => {calls.push({path, body}); return pending.promise;};
  const request = c.create(); assert.equal(inventory.state.bulkBusy, true); c.field('id', 'changed'); c.open(inventory.state); await c.create();
  assert.equal(calls.length, 1); assert.equal(c.state.form.id, 'nightly');
  if (mode === 'lost') pending.reject(Error('lost')); else pending.resolve(reply(mode === 'wrong-id' ? {schedule: row('wrong')} : {}, mode === 'server' ? 503 : 201));
  await request; assert.equal(inventory.state.bulkBusy, false); assert.match(c.state.formMessage, /may have been created.*Refresh/); assert.equal(c.state.reviewRequired, true);
  await c.create(); assert.equal(calls.length, 1); c.update({panelOpen: true}); await c.refresh(true); assert.equal(c.state.reviewRequired, false);
});
test('refused creation is distinct from unknown; HTML or lost error body remains unknown', async () => {
  const {c, open} = fixture(); open(); c.services.post = async () => reply({code: 'schedule_conflict'}, 409); await c.create(); assert.match(c.state.formMessage, /not created.*schedule_conflict/);
  assert.equal(c.state.reviewRequired, false);
});
test('busy device row or external bulk operation prevents writes without releasing its lock', async () => {
  const {c, inventory, calls, open} = fixture(); open(); inventory.claimRow('one'); await c.create();
  assert.equal(calls.length, 0); assert.equal(inventory.state.rowBusy.has('one'), true);
  inventory.releaseRow('one'); inventory.update({bulkBusy: true}); await c.create(); assert.equal(calls.length, 0); assert.equal(inventory.state.bulkBusy, true);
});
test('submitted write survives close/hide, does not reopen or issue hidden reads', async () => {
  const {c, open, hide, refreshes, calls} = fixture(), pending = gate(); open(); c.services.post = () => pending.promise;
  const request = c.create(); hide(); pending.resolve(reply({schedule: row()}, 201)); await request;
  assert.equal(c.state.dialog, null); assert.equal(c.state.panelOpen, false); assert.equal(refreshes(), 0); assert.equal(calls.length, 0); assert.match(c.state.message, /created/);
});
test('list keeps all 26 rows, bounds latest history to 25 and uses last ascending page', async () => {
  const {c, inventory, calls} = fixture(); const rows = Array.from({length: 26}, (_, i) => row(i === 25 ? 'constructor' : 's' + i));
  c.services.fetch = async (path, options) => {calls.push({path, options}); const id = path.split('/')[4];
    return reply(path === '/api/v1/schedules' ? list(rows) : {total: 101, offset: path.includes('offset=') ? 100 : 0, occurrences: [occurrence(id)]});};
  await c.togglePanel(); assert.equal(c.state.rows.length, 26); assert.equal(inventory.state.schedules.length, 26);
  assert.equal(calls.length, 51); assert.equal(calls.filter(call => call.path.includes('offset=100')).length, 25);
  assert.equal(c.state.history.size, 25); assert.equal(historyText(c.state.history.get('constructor')), 'run history unavailable');
});
for (const mode of ['network', 'probe', 'page', 'missing-row', 'wrong-schedule', 'invalid-total', 'empty']) test(`history ${mode} is distinguished from confirmed zero`, async () => {
  const {c} = fixture(); c.services.fetch = async path => {
    if (path === '/api/v1/schedules') return reply(list([row()])); if (mode === 'network') throw Error('offline');
    const page = path.includes('offset=');
    if ((mode === 'probe' && !page) || (mode === 'page' && page)) return reply({}, 503);
    return reply({total: mode === 'empty' ? 0 : mode === 'invalid-total' ? -1 : 1, offset: 0,
      occurrences: mode === 'empty' || (mode === 'missing-row' && page) ? [] : [occurrence(mode === 'wrong-schedule' ? 'other' : 'nightly')]});};
  await c.togglePanel(); assert.equal(historyText(c.state.history.get('nightly')), mode === 'empty' ? 'no run yet' : 'run history unavailable');
});
test('failed/malformed list keeps previous evidence but disables reaffirm', async () => {
  const {c, calls} = fixture(); const ticket = c.beginScheduleRead(); c.acceptSchedules({ok: true, body: list([{...row(), creator_exists: false}])}, ticket);
  c.services.fetch = async () => reply({schedules: []}); await c.togglePanel(); await c.reaffirm('nightly');
  assert.equal(c.state.listOk, false); assert.equal(c.state.rows.length, 1); assert.equal(calls.length, 0);
});
test('panel close/reopen refuses late bodies and failure callbacks', async () => {
  const {c} = fixture(), old = gate(); c.services.fetch = async () => ({ok: true, json: () => old.promise}); const first = c.togglePanel(); await tick(); c.closePanel();
  c.services.fetch = async path => reply(path === '/api/v1/schedules' ? list([row('new')]) : {total: 0, offset: 0, occurrences: []}); await c.togglePanel();
  old.resolve(list([row('old')])); await first; assert.equal(c.state.rows[0].id, 'new'); assert.equal(c.state.loading, false);
});
test('shared tickets prevent older Inventory/panel results replacing newer evidence in either order', async () => {
  const {c, inventory} = fixture(), old = gate();
  const invTicket = c.beginScheduleRead(); await c.togglePanel(); c.acceptSchedules({ok: true, body: list([row('old')])}, invTicket); assert.equal(c.state.rows[0].id, 'nightly');
  c.services.fetch = async () => ({ok: true, json: () => old.promise}); const request = c.refresh(); await tick();
  const latest = c.beginScheduleRead(); inventory.update(c.acceptSchedules({ok: true, body: list([row('new')])}, latest));
  old.resolve(list([row('stale-panel')])); await request; assert.equal(c.state.rows[0].id, 'new'); assert.equal(inventory.state.schedules[0].id, 'new');
});
test('history has at most four requests in flight and starts no more after hiding', async () => {
  const {c, hide} = fixture(), waits = []; c.services.fetch = path => {
    if (path === '/api/v1/schedules') return reply(list(Array.from({length: 10}, (_, i) => row('s' + i))));
    const pending = gate(); waits.push(pending); return pending.promise;};
  const request = c.togglePanel(); await tick(); assert.equal(waits.length, 4); hide();
  waits.forEach(wait => wait.resolve(reply({total: 0, offset: 0, occurrences: []}))); await request; assert.equal(waits.length, 4);
});
for (const mode of ['saved', 'conflict', 'refused', 'malformed', 'lost']) test(`reaffirm ${mode}: exact CSRF/revision, one request and honest outcome`, async () => {
  const {c, calls} = fixture(); c.acceptSchedules({ok: true, body: list([{...row(), creator_exists: false}])}, c.beginScheduleRead());
  c.services.fetch = async (path, options) => {calls.push({path, options}); if (mode === 'lost') throw Error('lost');
    return reply(mode === 'saved' ? {schedule: row('nightly', 2)} : {}, mode === 'conflict' ? 412 : mode === 'refused' ? 403 : 200);};
  await c.reaffirm('nightly'); assert.deepEqual(calls, [{path: '/api/v1/schedules/nightly/reaffirm', options: {method: 'POST',
    headers: {'Content-Type': 'application/json', 'If-Match': '"iris-schedule-nightly-1"', 'X-CSRF-Token': 'fixture'}, body: '{}'}}]);
  assert.match(c.state.message, mode === 'saved' ? /now owned/ : mode === 'conflict' ? /changed elsewhere/ : mode === 'refused' ? /refused/ : /unknown outcome/);
});
test('poll started during a write cannot restore its old row after write completion', async () => {
  const {c, open} = fixture(), pending = gate(); open(); c.services.post = () => pending.promise; const request = c.create();
  const during = c.beginScheduleRead(); c.acceptSchedules({ok: true, body: list([row('during')])}, during); assert.equal(c.state.rows.length, 0);
  pending.resolve(reply({schedule: row()}, 201)); await request; c.acceptSchedules({ok: true, body: list([row('late')])}, during); assert.equal(c.state.rows[0].id, 'nightly');
});
test('response checks reject duplicate rows, false etags and non-advanced revisions', () => {
  assert.throws(() => checkedSchedules(list([row(), row()]))); assert.throws(() => checkedSchedules(list([{...row(), etag: '*'}])));
  assert.equal(scheduleWriteResult(reply({}), {schedule: row()}, 'nightly', 1), 'unknown');
  assert.equal(scheduleWriteResult(reply({}, 503), {schedule: row()}, 'nightly'), 'unknown');
});
test('malformed optional history evidence never renders invented counts', () => {
  assert.match(historyText({state: 'running', delta: {}, annotations: {wave: {gate: 'held'}}}), /target change unavailable.*wave evidence unavailable/);
  assert.doesNotMatch(historyText({state: 'running', delta: {added: -1, removed: 0}}), /undefined|\+-1/);
});
test('real Inventory refresh shares schedule tickets with the panel in both directions', async () => {
  const {c, inventory} = fixture(); const oldInventory = gate(), oldPanel = gate(); let mode = 'old-inventory';
  const original = c.services.fetch;
  const fetch = async (path, options) => {
    if (path === '/api/v1/schedules') {
      if (mode === 'old-inventory') return {ok: true, json: () => oldInventory.promise};
      if (mode === 'old-panel') return {ok: true, json: () => oldPanel.promise};
      return reply(list([row(mode)]));
    }
    if (path.includes('/occurrences')) return original(path, options);
    if (path.startsWith('/api/v1/devices?')) return reply({devices: [{device_id: 'one'}], total: 1, offset: 0, revision: 1, now: 2000000000});
    return reply(path.endsWith('/images') ? {images: []} : path.endsWith('/credentials') ? {profiles: []} : path.endsWith('/jobs') ? {jobs: []} : {revision: 1, quarantine_assignments: []});
  };
  c.services.fetch = fetch; inventory.connect({fetch, beginScheduleRead: () => c.beginScheduleRead(), acceptSchedules: (result, ticket) => c.acceptSchedules(result, ticket)});
  const first = inventory.refresh(); await tick(); mode = 'new-panel'; await c.togglePanel();
  oldInventory.resolve(list([row('stale-inventory')])); await first;
  assert.equal(inventory.state.schedules[0].id, 'new-panel'); assert.equal(c.state.rows[0].id, 'new-panel');
  mode = 'old-panel'; const second = c.refresh(); await tick(); mode = 'new-inventory'; await inventory.refresh();
  oldPanel.resolve(list([row('stale-panel')])); await second;
  assert.equal(c.state.rows[0].id, 'new-inventory'); assert.equal(inventory.state.schedules[0].id, 'new-inventory');
});
