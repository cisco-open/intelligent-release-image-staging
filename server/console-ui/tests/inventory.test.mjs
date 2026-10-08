// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {InventoryController} from '../src/inventory-controller.mjs';
import {checkedPage, emptyFilters, enforcementBadge, filterQuery, instructionBadge, managementLabel,
  pageQuery, selectionScope, telemetryBadge, tlsBadge} from '../src/inventory-model.mjs';

const pending = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; };
const response = (body, status = 200) => ({ok: status === 200, status, json: async () => body});
const turn = () => new Promise(resolve => setImmediate(resolve));
const page = (ids, total = ids.length, offset = 0, revision = 1) =>
  ({devices: ids.map(device_id => ({device_id})), total, offset, revision, now: 1000});

async function fixture(t) {
  const timers = new Map(), calls = [], writes = [], published = [], outcomes = [], confirmations = [];
  let next = 0;
  const controller = new InventoryController({later: (fn, delay) => {
    assert.equal(delay, 250); timers.set(++next, fn); return next;
  }, cancel: id => timers.delete(id)});
  const bodies = {'/api/v1/devices': page(['a', 'b']), '/api/v1/images': {images: [{id: 'image', filename: 'image.bin'}]},
    '/api/v1/credentials': {profiles: [{id: 'operator'}]}, '/api/v1/peer-policy': {revision: 1, quarantine_assignments: [], enforcement: {state: 'enforced'}},
    '/api/v1/onboard/jobs': {jobs: [{id: 'job', device_id: 'a', state: 'running'}]}, '/api/v1/schedules': {schedules: [{id: 'window'}]}};
  const services = {fetch: async (url, options) => {
    calls.push([url, options]); return response(bodies[url.split('?')[0]]);
  }, publish: state => published.push(state), report: (...args) => outcomes.push(args),
  post: async (url, body) => { writes.push([url, body]); return response({ok: true}); },
  confirm: message => { confirmations.push(message); return true; }, headers: extra => ({'X-CSRF-Token': 'fixture-only', ...extra})};
  controller.connect(services); t.after(() => controller.dispose()); await controller.refresh();
  return {controller, services, bodies, timers, calls, writes, published, outcomes, confirmations};
}

test('filters preserve exact API names, normalization and encoded operator data', () => {
  const filters = {...emptyFilters(), q: ' EDGE & TEST ', managementType: 'xr-host', platform: 'iox', cred: 'ops/admin',
    telemetry: 'unknown', peer: 'quarantined', role: 'constructor', modelFamily: 'XR8000', osFamily: 'xr', status: '__attention'};
  assert.equal(filterQuery(filters), 'q=edge%20%26%20test&management_type=xr-host&platform=iox&cred=ops%2Fadmin&telemetry=unknown&peer=quarantined&role=constructor&model_family=XR8000&os_family=xr&status=__attention');
  assert.equal(pageQuery({}, 200), 'limit=200&offset=200');
});

test('device observations retain telemetry tri-state, XR/VPG labels and server-clock TLS freshness', () => {
  assert.equal(managementLabel({management_type: 'xr-host', iris_vlan: 99}), 'XR host');
  assert.equal(managementLabel({management_type: 'router-nat', vpg_number: 0}), 'router-nat / VPG0');
  assert.equal(managementLabel({management_type: 'legacy_routed'}), 'Inventory only — management type not chosen');
  for (const [device, label] of [[{}, '—'], [{telemetry_enabled: false, telemetry_stream_enabled: true}, 'off'],
    [{telemetry_enabled: true}, 'reports'], [{telemetry_stream_enabled: false}, 'reports'], [{telemetry_stream_enabled: true}, 'streaming']]) {
    assert.equal(telemetryBadge(device).label, label);
  }
  const device = {last_seen: 900, peer_tls: {runtime_source: 'aria2_rpc', runtime_mode: 'required', configured_mode: 'disabled'}};
  assert.equal(tlsBadge(device, 1000).label, 'TLS required', 'Local browser clock is deliberately unrelated');
  assert.equal(tlsBadge(device, 1500).label, 'TLS required (stale)');
  assert.equal(tlsBadge({...device, peer_tls: {configured_mode: 'required'}}, 1000).label, 'TLS unknown');
  assert.match(tlsBadge(device, 1000).title, /Configured: off.*not a negotiated connection/);
});

test('instruction and enforcement evidence never promote stale or unavailable observations to healthy', () => {
  assert.equal(instructionBadge({}).label, 'unknown');
  const i = instructionBadge({instruction: {display_state: 'rejected', label: '<rejected>', evidence: 'signature', underlying_state: 'pending',
    reason: 'revoked', report_age_seconds: 0, pointer_skew: true, qos_drift_count: 1}});
  assert.equal(i.cls, 'badge-fail'); assert.equal(i.label, '<rejected>');
  assert.match(i.detail, /signature.*agent-asserted.*reason: revoked.*report 0s old.*pointer skew.*1 QoS drift violation$/);
  assert.equal(instructionBadge({instruction: {display_state: 'applied'}}).cls, 'badge-ok');
  assert.match(instructionBadge({instruction: {}}).detail, /report age unavailable.*QoS drift unavailable/);
  assert.equal(enforcementBadge({enforcement: {state: 'enforced'}}, false).label, 'unavailable');
  assert.equal(enforcementBadge({enforcement: {state: 'enforced', stale: true}}, true).cls, 'badge-fail');
  assert.equal(enforcementBadge({enforcement: {state: 'fail_closed'}}, true).cls, 'badge-fail');
});

test('page validation rejects malformed counts, duplicate IDs and wrong revision/offset', () => {
  for (const bad of [null, {}, {...page(['a']), offset: 1}, {...page(['a']), revision: '1'}, {...page(['a']), total: -1},
    page(['a', 'a']), page(['']), page([null]), page(['a', 'b'], 1), {...page(['a']), devices: [null]}]) {
    assert.throws(() => checkedPage(bad, 0, 200));
  }
  assert.equal(checkedPage(page([], 1, 200), 200, 200).offset, 200, 'Off-end page is recoverable');
});

test('filter debounce cancels the previous timer and selection coverage immediately', async t => {
  const {controller, timers, calls} = await fixture(t); controller.toggle('a');
  controller.setFilter('q', 'old'); controller.setFilter('q', 'new');
  assert.equal(timers.size, 1); assert.equal(controller.snapshot().matchQuery, null);
  assert.match(selectionScope(controller.snapshot()).text, /unconfirmed/);
  const before = calls.length; controller.hide(); assert.equal(timers.size, 0);
  assert.equal(calls.length, before, 'Hidden view does not start a debounce read');
});

for (const route of ['devices', 'images', 'credentials', 'peer-policy', 'onboard/jobs', 'schedules']) {
  for (const delay of ['headers', 'body']) test(`a stale ${route} ${delay} cannot replace any part of a newer snapshot`, async t => {
    const {controller, services, bodies, published} = await fixture(t), original = services.fetch, held = pending();
    services.fetch = async (url, options) => url.split('?')[0] === '/api/v1/' + route
      ? delay === 'headers' ? held.promise : {ok: true, json: () => held.promise} : original(url, options);
    const old = controller.refresh(); await turn();
    services.fetch = original;
    bodies['/api/v1/devices'] = page(['new']); bodies['/api/v1/images'] = {images: [{id: 'new-image'}]};
    bodies['/api/v1/credentials'] = {profiles: [{id: 'new-credential'}]};
    bodies['/api/v1/peer-policy'] = {revision: 2, quarantine_assignments: []}; bodies['/api/v1/onboard/jobs'] = {jobs: []}; bodies['/api/v1/schedules'] = {schedules: []};
    await controller.refresh(); const fresh = controller.snapshot(), count = published.length;
    assert.equal(fresh.policy.revision, 2); assert.equal(fresh.policyOk, true);
    held.resolve(delay === 'headers' ? response({devices: [], images: [], profiles: [], revision: 0, jobs: [], schedules: []})
      : {devices: [], images: [], profiles: [], revision: 0, jobs: [], schedules: []}); await old;
    assert.equal(controller.snapshot(), fresh); assert.equal(published.length, count);
  });
}

test('unavailable companions retain evidence but disable writes; device failure clears unconfirmed rows only', async t => {
  const f = await fixture(t), {controller, services, bodies} = f; controller.toggle('a');
  services.fetch = async url => url.startsWith('/api/v1/devices?') ? response(bodies['/api/v1/devices']) : response({}, 503);
  await controller.refresh();
  const state = controller.snapshot(); assert.equal(state.rows.length, 2); assert.equal(state.imagesOk, false); assert.equal(state.credentialsOk, false);
  assert.equal(state.policyOk, false); assert.equal(state.images[0].id, 'image'); assert.equal(state.credentials[0].id, 'operator');
  assert.equal(state.jobs[0].id, 'job'); assert.equal(state.schedules[0].id, 'window');
  await controller.edit('a', 'credential', 'other'); await controller.edit('a', 'quarantine', true);
  assert.equal(f.writes.length, 0); assert.equal(f.confirmations.length, 0);
  services.fetch = async () => response({}, 401); await controller.refresh();
  assert.equal(controller.snapshot().readOk, false); assert.deepEqual(controller.snapshot().rows, []);
  assert.match(controller.snapshot().error, /401/); assert.deepEqual(controller.selectedIds(), ['a']);
  assert.match(selectionScope(controller.snapshot()).text, /unconfirmed/);
});

test('malformed companions cannot enable controls or erase last known evidence', async t => {
  const {controller, bodies} = await fixture(t);
  bodies['/api/v1/images'] = {images: [null]}; bodies['/api/v1/credentials'] = {profiles: [{id: 'a'}, {id: 'a'}]};
  bodies['/api/v1/peer-policy'] = {revision: 3}; bodies['/api/v1/onboard/jobs'] = {jobs: [null]};
  bodies['/api/v1/schedules'] = {schedules: [null]}; await controller.refresh();
  const state = controller.snapshot(); assert.equal(state.readOk, true);
  assert.equal(state.imagesOk, false); assert.equal(state.credentialsOk, false); assert.equal(state.policyOk, false);
  assert.equal(state.jobs[0].id, 'job'); assert.equal(state.schedules[0].id, 'window');
  assert.equal(state.policy.revision, 1);
});

test('paging is bounded, filters reset to page one and an empty off-end page recovers once', async t => {
  const {controller, services, calls} = await fixture(t);
  controller.update({total: 201});
  const original = services.fetch;
  services.fetch = async (url, options) => url.startsWith('/api/v1/devices?')
    ? response(url.endsWith('offset=200') ? page([], 1, 200) : page(['only'])) : original(url, options);
  await controller.page(1);
  assert.equal(controller.snapshot().offset, 0); assert.equal(controller.snapshot().rows[0].device_id, 'only');
  assert.equal(calls.filter(([url]) => url.includes('/devices?')).length, 1, 'The original stub is not called for replacement pages');
  await controller.page(-1); await controller.page(1); assert.equal(controller.snapshot().offset, 0);
  controller.update({offset: 200}); await controller.setFilter('q', 'only', false); assert.equal(controller.snapshot().offset, 0);
});

test('page selection updates immediately, survives paging, and treats prototype names as data', async t => {
  const {controller} = await fixture(t); controller.toggle('__proto__');
  assert.equal(selectionScope(controller.snapshot()).pageLabel, 'Select page');
  controller.toggle('a'); assert.equal(selectionScope(controller.snapshot()).pageLabel, 'Select page');
  controller.toggle('b'); assert.equal(selectionScope(controller.snapshot()).pageLabel, 'Clear page selection');
  controller.togglePage(); assert.deepEqual(controller.selectedIds(), ['__proto__']);
  controller.togglePage(); assert.deepEqual(controller.selectedIds(), ['__proto__', 'a', 'b']);
  controller.removeSelection(['a']); assert.deepEqual(controller.selectedIds(), ['__proto__', 'b']);
  controller.clearSelection(); assert.equal(controller.selectedIds().length, 0);
});

test('equal or larger selection counts cannot claim different matching IDs', async t => {
  const {controller} = await fixture(t);
  controller.update({rows: [{device_id: 'b'}], total: 1, matchIds: ['b'], selected: new Set(['a', 'c'])});
  let scope = selectionScope(controller.snapshot()); assert.equal(scope.offerAll, true); assert.match(scope.text, /2 selected outside this filter/);
  controller.toggle('b'); scope = selectionScope(controller.snapshot());
  assert.equal(scope.text, '· All 1 matching devices selected; 2 selected outside this filter'); assert.equal(scope.offerAll, false);
  controller.update({matchIds: null}); assert.equal(selectionScope(controller.snapshot()).offerAll, true);
});

test('all-pages selection is atomic, additive and guarded against duplicate requests', async t => {
  const {controller, services, calls, outcomes} = await fixture(t), held = pending();
  const first = Array.from({length: 1000}, (_, i) => 'd' + i);
  controller.toggle('a'); controller.update({total: 1001, matchIds: null});
  let reads = 0; services.fetch = async url => { reads++; assert.match(url, /limit=1000/); return url.endsWith('offset=0') ? response(page(first, 1001)) : held.promise; };
  const read = controller.selectAll(); await turn();
  assert.deepEqual(controller.selectedIds(), ['a']); assert.equal(controller.snapshot().selectionBusy, true);
  await controller.selectAll(); assert.equal(reads, 2);
  held.resolve(response(page(['constructor'], 1001, 1000))); await read;
  assert.equal(controller.selectedIds().length, 1002); assert.equal(controller.snapshot().selected.has('constructor'), true);
  assert.equal(selectionScope(controller.snapshot()).text, '· All 1001 matching devices selected; 1 selected outside this filter');
  assert.equal(outcomes.at(-1)[1], false); assert.ok(calls.every(([, options]) => !options.method));
});

for (const failure of ['http', 'network', 'json', 'total', 'revision', 'invalid-revision', 'duplicate', 'empty', 'offset', 'invalid-id']) {
  test(`a ${failure} on a later selection page leaves the original selection unchanged`, async t => {
    const {controller, services, outcomes} = await fixture(t), first = Array.from({length: 1000}, (_, i) => 'd' + i);
    controller.toggle('a'); controller.update({total: 1001, matchIds: null});
    services.fetch = async url => {
      if (url.endsWith('offset=0')) return response(page(first, 1001));
      if (failure === 'http') return response({}, 503);
      if (failure === 'network') throw new Error('offline');
      if (failure === 'json') return {ok: true, json: async () => { throw new Error('unreadable'); }};
      const body = page(['last'], 1001, 1000);
      if (failure === 'total') body.total++;
      if (failure === 'revision') body.revision++;
      if (failure === 'invalid-revision') body.revision = '1';
      if (failure === 'duplicate') body.devices = [{device_id: 'd0'}];
      if (failure === 'empty') body.devices = [];
      if (failure === 'offset') body.offset = 0;
      if (failure === 'invalid-id') body.devices = [{device_id: null}];
      return response(body);
    };
    await controller.selectAll();
    assert.deepEqual(controller.selectedIds(), ['a']); assert.equal(controller.snapshot().matchIds, null);
    assert.equal(controller.snapshot().selectionBusy, false); assert.match(outcomes.at(-1)[0], /selection is unchanged/);
    assert.equal(outcomes.at(-1)[1], true);
  });
}

for (const delay of ['headers', 'body']) test(`a cancelled selection ${delay} cannot unlock a newer walk`, async t => {
  const {controller, services} = await fixture(t), held = pending(), fresh = pending();
  controller.toggle('a');
  services.fetch = async () => delay === 'headers' ? held.promise : {ok: true, json: () => held.promise};
  const old = controller.selectAll(); await turn(); controller.cancelSelection();
  services.fetch = () => fresh.promise; const newest = controller.selectAll();
  held.resolve(delay === 'headers' ? response(page(['stale'])) : page(['stale'])); await old;
  assert.equal(controller.snapshot().selectionBusy, true); assert.deepEqual(controller.selectedIds(), ['a']);
  fresh.resolve(response(page(['new']))); await newest; assert.deepEqual(controller.selectedIds(), ['a', 'new']);
});

for (const action of ['row', 'clear', 'hide', 'dispose', 'filter']) test(`${action} cancels a pending selection expansion`, async t => {
  const {controller, services} = await fixture(t), held = pending(); let signal;
  controller.toggle('a'); services.fetch = async (url, options) => { signal = options.signal; return held.promise; };
  const read = controller.selectAll(); await turn();
  if (action === 'row') controller.toggle('b');
  if (action === 'clear') controller.clearSelection();
  if (action === 'hide') controller.hide();
  if (action === 'dispose') controller.dispose();
  if (action === 'filter') controller.setFilter('q', 'new');
  assert.equal(signal.aborted, true); const ids = controller.selectedIds();
  held.resolve(response(page(['stale']))); await read; assert.deepEqual(controller.selectedIds(), ids);
});

test('a changed filter independently rejects a delayed selection body', async t => {
  const {controller, services} = await fixture(t), held = pending();
  controller.toggle('a'); services.fetch = async () => ({ok: true, json: () => held.promise});
  const read = controller.selectAll(); await turn(); controller.update({filters: {...emptyFilters(), q: 'other'}});
  held.resolve(page(['stale'])); await read; assert.deepEqual(controller.selectedIds(), ['a']);
  assert.equal(selectionScope(controller.snapshot()).offerAll, false); assert.equal(controller.snapshot().selectionBusy, false);
});

for (const kind of ['credential', 'platform']) test(`${kind} writes use the correct API, lock the row and read back without replay`, async t => {
  const {controller, services, writes, calls} = await fixture(t), held = pending();
  services.post = async (url, body) => { writes.push([url, body]); return held.promise; };
  const writing = controller.edit('edge &/1', kind, 'value');
  assert.equal(controller.snapshot().rowBusy.has('edge &/1'), true);
  await controller.edit('edge &/1', kind, 'duplicate'); assert.equal(writes.length, 1);
  assert.equal(writes[0][0], '/api/v1/devices/edge%20%26%2F1/' + kind);
  assert.deepEqual(writes[0][1], kind === 'credential' ? {credential_profile_id: 'value'} : {platform: 'value'});
  const n = calls.length; held.resolve(response({ok: true})); await writing;
  assert.equal(controller.snapshot().rowBusy.size, 0); assert.equal(calls.length, n + 6); assert.equal(writes.length, 1);
});

test('quarantine uses a reviewed confirmation, CSRF and exact current revision precondition', async t => {
  const {controller, services, confirmations, outcomes} = await fixture(t), writes = [], original = services.fetch;
  services.fetch = async (url, options) => {
    if (options.method !== 'PUT') return original(url, options);
    writes.push([url, options]); return response({ok: true, revision: 2, quarantined: true});
  };
  await controller.edit('constructor', 'quarantine', true);
  assert.equal(writes.length, 1); assert.equal(writes[0][0], '/api/v1/peer-policy/quarantine/constructor');
  assert.deepEqual(writes[0][1].headers, {'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-only', 'If-Match': '"iris-peer-policy-1"'});
  assert.deepEqual(JSON.parse(writes[0][1].body), {quarantined: true, if_revision: 1});
  assert.match(confirmations[0], /Quarantine constructor\?.*Changes peer/s); assert.match(outcomes.at(-1)[0], /intent saved/);
  services.confirm = () => false; await controller.edit('constructor', 'quarantine', false); assert.equal(writes.length, 1);
});

for (const outcome of ['lost', 'malformed', 'refused']) test(`an inline ${outcome} result never retries or claims success`, async t => {
  const {controller, services, outcomes} = await fixture(t); let writes = 0;
  services.post = async () => { writes++; if (outcome === 'lost') throw new Error('lost'); return response(outcome === 'refused' ? {error: 'not allowed'} : {}, outcome === 'refused' ? 409 : 200); };
  await controller.edit('a', 'platform', 'iox'); assert.equal(writes, 1);
  assert.equal(outcomes.at(-1)[1], true); assert.match(outcomes.at(-1)[0], outcome === 'refused' ? /refused.*not allowed/ : /outcome is unknown/);
});

test('navigation during a write records the result without starting a hidden-route policy read', async t => {
  const {controller, services, calls, outcomes} = await fixture(t), held = pending();
  services.post = () => held.promise; const writing = controller.edit('a', 'platform', 'iox');
  controller.hide(); services.isVisible = () => false; const reads = calls.length;
  held.resolve(response({ok: true})); await writing;
  assert.equal(calls.length, reads); assert.match(outcomes.at(-1)[0], /updated/); assert.equal(controller.snapshot().rowBusy.size, 0);
});

test('action adapter locks duplicate dialog reads but allows Activity during a bulk write', async t => {
  const {controller} = await fixture(t), held = pending(), opener = {}; let opened = 0;
  controller.onAction('assign-images-selected', function () { assert.equal(this, opener); opened++; return held.promise; });
  const first = controller.action('assign-images-selected', {currentTarget: opener});
  await controller.action('assign-images-selected', {currentTarget: opener}); assert.equal(opened, 1);
  held.resolve(); await first; assert.equal(controller.snapshot().actionBusy.size, 0);
  controller.update({bulkBusy: true});
  controller.onAction('dev-activity', () => opened++); await controller.action('dev-activity', {currentTarget: opener}); assert.equal(opened, 2);
  await controller.action('assign-images-selected', {currentTarget: opener}); assert.equal(opened, 2);
  controller.update({bulkBusy: false, rowBusy: new Set(['a'])});
  await controller.action('assign-images-selected', {currentTarget: opener}); assert.equal(opened, 2);
});

test('legacy assignment and CSV adapters share state locks without touching React controls', async t => {
  const {controller, writes} = await fixture(t);
  assert.equal(controller.claimRow('a'), true); assert.equal(controller.claimRow('a'), false);
  await controller.edit('a', 'credential', 'other'); assert.equal(writes.length, 0);
  controller.releaseRow('a'); await controller.edit('a', 'credential', 'other'); assert.equal(writes.length, 1);
  controller.update({bulkBusy: true}); assert.equal(controller.claimRow('a'), false);
  let opens = 0; controller.onAction('import-csv', () => opens++);
  controller.update({csvBusy: true}); await controller.action('import-csv', {currentTarget: {}}); assert.equal(opens, 0);
  controller.update({csvBusy: false}); await controller.action('import-csv', {currentTarget: {}}); assert.equal(opens, 1);
});
