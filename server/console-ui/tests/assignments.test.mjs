// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {AssignmentsController} from '../src/assignments-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {assignedIds, assignmentPreview, pickerRows, removalConfirmation, assignmentResult, bulkCredentialResult} from '../src/assignments-model.mjs';

const reply = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const wait = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {resolve, reject, promise}; };
const record = (id, images = ['A']) => ({device_id: id, assigned_image_ids: images});
const page = (devices, total = devices.length, offset = 0, revision = 1) => ({devices, total, offset, revision, now: 1});
function fixture() {
  const c = new AssignmentsController(), writes = [], reads = [], reports = [], confirmations = [], locks = [];
  const inventory = new InventoryController();
  const images = [{id: 'A', filename: 'image-A.bin'}, {id: 'B', filename: 'B'}, {id: 'bad', quarantined: true}];
  let devices = [record('one', ['A', 'B']), record('two', ['A'])], visible = true;
  c.connect({fetch: async (path, options) => { reads.push({path, options}); return reply(path.includes('/images') ? {images} : page(devices)); },
    post: async (path, body) => { writes.push({path, body}); return reply(path.endsWith('/assign')
      ? {ok: true, assigned_image_ids: body.image_ids, removed_image_ids: []} : {ok: true, applied: body.device_ids.length, failed: {}}); },
    confirm: message => { confirmations.push(message); return true; }, report: (...args) => reports.push(args), isVisible: () => visible,
    claimRow: id => { locks.push(['row', id]); return inventory.claimRow(id); }, releaseRow: id => { locks.push(['release-row', id]); inventory.releaseRow(id); },
    claimBulk: ids => { if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; locks.push(['bulk', ids]); inventory.update({bulkBusy: true}); return true; },
    releaseBulk: () => { locks.push(['release-bulk']); inventory.update({bulkBusy: false}); }, refreshInventory: async () => reads.push({path: 'refresh'})});
  c.acceptImages({ok: true, body: {images}}, c.beginImageRead());
  c.prerequisites({credentials: [{id: 'operator'}, {id: '__none'}], credentialsOk: true, rowBusy: new Set(), bulkBusy: false});
  return {c, inventory, images, writes, reads, reports, locks, confirmations, setDevices: value => { devices = value; }, hide: () => { visible = false; c.hide(); }};
}
test('preview uses intersection and ordered equality without inventing missing assignments', () => {
  const rows = new Map([['one', record('one', ['A', 'B'])], ['two', record('two', ['B', 'A'])]]);
  assert.deepEqual(assignmentPreview(['one', 'two'], rows).chosen, ['A', 'B']);
  assert.equal(assignmentPreview(['one', 'two'], rows).different, true);
  rows.set('two', record('two', ['A'])); assert.deepEqual(assignmentPreview(['one', 'two'], rows).chosen, ['A']);
  assert.throws(() => assignmentPreview(['one', 'missing'], rows), /not found/);
  assert.deepEqual(assignedIds({assigned_image_ids: [], assigned_image_id: 'stale'}), []);
  assert.deepEqual(assignedIds({assigned_image_ids: null, assigned_image_id: 'legacy'}), ['legacy']);
  for (const value of [null, undefined, '']) assert.deepEqual(assignedIds({assigned_image_id: value}), []);
  for (const value of [false, 0, [], {}]) assert.throws(() => assignedIds({assigned_image_id: value}));
  for (const value of [['A', 'A'], [5], 'A']) assert.throws(() => assignedIds({assigned_image_ids: value}));
});
test('row and bulk use one picker, captured targets and ordered compare-and-set bodies', async () => {
  for (const row of [true, false]) {
    const {c, writes, confirmations} = fixture(); await c.openImages(row ? ['one'] : ['one', 'two'], row);
    c.services.selectedIds = () => ['unreviewed']; // old handler retargeted at Apply
    c.toggleImage('B'); await c.applyImages();
    assert.deepEqual(writes.map(row => row.path), row ? ['/api/v1/devices/one/assign'] : ['/api/v1/devices/one/assign', '/api/v1/devices/two/assign']);
    assert.deepEqual(writes[0].body.expect_image_ids, ['A', 'B']);
    if (!row) assert.deepEqual(writes[1].body.expect_image_ids, ['A']);
    assert.deepEqual(writes[0].body.image_ids, row ? ['A'] : ['A', 'B']);
    assert.equal(confirmations.length, 0, 'Additive bulk / nonempty row changes do not claim destructive bulk removal');
    assert.equal(c.state.open, false);
  }
});
test('identical sets and empty sets do not show differing assignments', async () => {
  const {c, setDevices} = fixture();
  for (const set of [[], ['A', 'B']]) { setDevices([record('one', set), record('two', set)]); await c.openImages(['one', 'two']); assert.equal(c.state.different, false); }
});
test('actual removal and empty results confirm, cancellation sends nothing and holds no locks', async () => {
  const {c, confirmations, locks, writes} = fixture(); await c.openImages(['one', 'two']);
  c.services.confirm = message => { confirmations.push(message); return false; };
  await c.applyImages(); assert.match(confirmations[0], /Existing assignments.*removed/);
  c.toggleImage('A'); await c.applyImages(); assert.match(confirmations[1], /Unassign all.*2 device/);
  assert.deepEqual(locks, []); assert.deepEqual(writes, []);
  c.close(); await c.openImages(['one'], true); c.toggleImage('A'); c.toggleImage('B');
  assert.match(removalConfirmation(c.state), /Unassign all images from one/);
});
test('missing catalog images are retained checked and immutable, unsafe new quarantine cannot be checked', async () => {
  const {c, setDevices} = fixture(); setDevices([record('one', ['gone', 'bad'])]); await c.openImages(['one'], true);
  assert.deepEqual(c.state.order, ['gone', 'bad', 'A', 'B']);
  assert.equal(pickerRows(c.state)[0].disabled, true); assert.equal(pickerRows(c.state)[0].retained, true);
  c.toggleImage('gone'); assert.equal(c.state.chosen.includes('gone'), true);
  c.toggleImage('bad'); assert.equal(pickerRows(c.state).find(row => row.id === 'bad').disabled, true);
  c.toggleImage('bad'); assert.equal(c.state.chosen.includes('bad'), false);
});
test('ten-image cap permits unchecking and retains checked-first order', async () => {
  const {c, images, setDevices} = fixture(); images.splice(0, images.length, ...Array.from({length: 12}, (_, i) => ({id: String(i)})));
  setDevices([record('one', ['2', '1'])]); await c.openImages(['one'], true);
  for (const id of c.state.order) c.toggleImage(id);
  assert.equal(c.state.chosen.length, 10); assert.deepEqual(c.state.chosen, ['0', '3', '4', '5', '6', '7', '8', '9', '10', '11']);
  assert.equal(pickerRows(c.state).find(row => row.id === '2').disabled, true);
  c.toggleImage('0'); c.toggleImage('2'); assert.equal(c.state.chosen[0], '2');
});
test('catalog labels show filename once and late disappearance lets a new choice be removed', async () => {
  const {c} = fixture(); await c.openImages(['two'], true); c.toggleImage('B');
  assert.equal(pickerRows(c.state).find(row => row.id === 'A').label, 'A — image-A.bin');
  assert.equal(pickerRows(c.state).find(row => row.id === 'B').label, 'B');
  c.acceptImages({ok: true, body: {images: [{id: 'A'}]}}, c.beginImageRead());
  assert.equal(pickerRows(c.state).find(row => row.id === 'B').disabled, false); c.toggleImage('B');
  assert.equal(pickerRows(c.state).find(row => row.id === 'B').disabled, true);
});
test('unavailable catalog refuses opening and later failure blocks Apply without dropping draft', async () => {
  const {c, writes} = fixture(); c.acceptImages({ok: false}, c.beginImageRead());
  await c.openImages(['one'], true); assert.equal(c.state.open, false);
  c.acceptImages({ok: true, body: {images: [{id: 'A'}, {id: 'B'}]}}, c.beginImageRead());
  await c.openImages(['one'], true); c.acceptImages({ok: false}, c.beginImageRead());
  await c.applyImages(); assert.deepEqual(writes, []); assert.deepEqual(c.state.chosen, ['A', 'B']);
});
for (const fault of ['http', 'body', 'missing', 'duplicate', 'offset', 'revision', 'total', 'empty-page']) test(`off-page ${fault} fails closed, no fabricated empty expectation`, async () => {
  const {c, writes, images} = fixture(); let requests = 0;
  c.services.fetch = async path => {
    if (path.includes('/images')) return reply({images}); requests++;
    if (requests === 1) return reply(page([record('one')], 2));
    if (fault === 'http') return reply({}, 503);
    if (fault === 'body') return {ok: true, json: async () => { throw Error('Invalid JSON'); }};
    return reply(page(fault === 'empty-page' ? [] : [record(fault === 'duplicate' ? 'one' : fault === 'missing' ? 'different' : 'two')],
      fault === 'total' ? 3 : 2, fault === 'offset' ? 0 : 1, fault === 'revision' ? 2 : 1));
  };
  await c.openImages(['one', 'two']); assert.equal(c.state.ready, false); assert.equal(c.state.failed, true);
  await c.applyImages(); assert.deepEqual(writes, []);
});
test('paged preview resolves off-filter IDs at one fleet revision and stops when all found', async () => {
  const {c, images} = fixture(); const requests = [];
  c.services.fetch = async path => { requests.push(path); return reply(path.includes('/images') ? {images}
    : path.endsWith('offset=0') ? page([record('elsewhere'), record('one', ['B'])], 5)
      : page([record('two', ['B', 'A'])], 5, 2)); };
  await c.openImages(['one', 'two']); assert.deepEqual(c.state.chosen, ['B']);
  assert.deepEqual(c.state.expect.get('two'), ['B', 'A']);
  assert.deepEqual(requests.filter(path => path.includes('/devices?')), ['/api/v1/devices?limit=1000&offset=0', '/api/v1/devices?limit=1000&offset=2']);
});
test('failed catalog cancels unfinished device page walk, including an ignored abort signal', async () => {
  const {c} = fixture(), gate = wait(); let requests = 0, signal;
  c.services.fetch = async (path, options) => {
    if (path.includes('/images')) return reply({}, 503);
    requests++; signal = options.signal; return {ok: true, json: () => gate.promise};
  };
  await c.openImages(['one', 'two']); assert.equal(signal.aborted, true); assert.equal(c.state.ready, false);
  gate.resolve(page([record('one')], 2)); await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests, 1, 'No second page after another prerequisite failed');
});
for (const late of ['resolve', 'reject']) test(`closed/reopened preview ignores late ${late} body`, async () => {
  const {c, images} = fixture(), gate = wait(); let signal;
  c.services.fetch = async (path, options) => { if (path.includes('/images')) return reply({images}); signal = options.signal; return {ok: true, json: () => gate.promise}; };
  const old = c.openImages(['one'], true); await Promise.resolve(); c.close(); assert.equal(signal.aborted, true);
  c.services.fetch = async path => reply(path.includes('/images') ? {images} : page([record('two', ['B'])]));
  await c.openImages(['two'], true); late === 'resolve' ? gate.resolve(page([record('one', ['A'])])) : gate.reject(Error('old'));
  await old; assert.deepEqual(c.state.ids, ['two']); assert.deepEqual(c.state.chosen, ['B']); assert.equal(c.state.failed, false);
});
test('new catalog read wins over earlier Inventory poll without resetting the picked order', async () => {
  const {c} = fixture(); await c.openImages(['one'], true);
  const old = c.beginImageRead(), next = c.beginImageRead();
  c.acceptImages({ok: true, body: {images: [{id: 'A', quarantined: true}, {id: 'B'}]}}, next);
  const late = c.acceptImages({ok: true, body: {images: [{id: 'A', quarantined: false}]}}, old);
  assert.equal(late.images[0].quarantined, true); assert.deepEqual(c.state.chosen, ['A', 'B']);
  c.toggleImage('A'); c.toggleImage('A'); assert.deepEqual(c.state.chosen, ['B']);
});
test('actual Inventory read cannot replace newer picker catalog evidence', async () => {
  const {c} = fixture(), inventory = new InventoryController(), gate = wait();
  inventory.connect({beginImageRead: () => c.beginImageRead(), acceptImages: (r, t) => c.acceptImages(r, t),
    fetch: async path => path.endsWith('/images') ? {ok: true, json: () => gate.promise}
      : reply(path.includes('/devices?') ? page([]) : path.endsWith('credentials') ? {profiles: []}
        : path.endsWith('peer-policy') ? {revision: 1, quarantine_assignments: []} : path.endsWith('jobs') ? {jobs: []} : {schedules: []})});
  const old = inventory.refresh(); await Promise.resolve();
  c.acceptImages({ok: true, body: {images: [{id: 'new', quarantined: true}]}}, c.beginImageRead());
  gate.resolve({images: [{id: 'old'}]}); await old; assert.equal(inventory.state.images[0].id, 'new');
});
for (const mode of ['lost', 'malformed', 'wrong-order', 'server', 'refused', 'conflict']) test(`assignment ${mode} is explicit and never replayed`, async () => {
  const {c, writes, reports} = fixture(); await c.openImages(['one'], true);
  c.services.post = async (path, body) => { writes.push({path, body});
    if (mode === 'lost') throw Error('lost');
    return reply(mode === 'wrong-order' ? {ok: true, assigned_image_ids: ['B', 'A']}
      : {error: mode === 'conflict' ? 'assignment_conflict' : 'refused'}, mode === 'server' ? 503 : mode === 'refused' ? 400 : mode === 'conflict' ? 409 : 200); };
  await c.applyImages(); await c.applyImages(); assert.equal(writes.length, 1);
  assert.equal(c.state.ready, false); assert.equal(c.state.open, true);
  assert.match(reports.at(-1)[0], mode === 'refused' ? /refused/ : mode === 'conflict' ? /conflict/ : /unknown/);
  assert.equal(c.state.busy, false);
});
test('conflict review refreshes expectations but does not submit; no stale retry can overwrite a newer set', async () => {
  const {c, writes, setDevices} = fixture(); await c.openImages(['one'], true);
  c.services.post = async (path, body) => { writes.push({path, body}); return reply({error: 'assignment_conflict', assigned_image_ids: ['B']}, 409); };
  await c.applyImages(); setDevices([record('one', ['B'])]); await c.review(); assert.equal(writes.length, 1);
  assert.deepEqual(c.state.chosen, ['B']); assert.deepEqual(c.state.expect.get('one'), ['B']);
});
test('bulk assignment has four workers, stable result order, partial success and close does not abort writes', async () => {
  const {c, setDevices, reports, locks, hide} = fixture(), gates = [], ids = Array.from({length: 9}, (_, i) => String(i));
  setDevices(ids.map(id => record(id))); await c.openImages(ids);
  c.services.post = async (path, body) => { const gate = wait(); gates.push({gate, path, body}); return gate.promise; };
  const job = c.applyImages(); assert.equal(gates.length, 4); c.close(); await c.openImages(['one'], true);
  assert.equal(c.state.open, false); assert.equal(c.operation, true);
  for (let i = 0; i < ids.length; i++) {
    assert.equal(gates[i].body.expect_image_ids[0], 'A'); gates[i].gate.resolve(reply(i === 3 ? {error: 'refused'} : {ok: true, assigned_image_ids: ['A']}, i === 3 ? 422 : 200));
    await new Promise(resolve => setImmediate(resolve));
  }
  hide(); await job; assert.match(reports.at(-1)[0], /8\/9.*3: refused/); assert.equal(c.operation, false);
  assert.equal(locks.filter(row => row[0] === 'release-bulk').length, 1);
});
test('row assignment never releases another bulk lock; refused claim sends nothing', async () => {
  const {c, inventory, locks, writes} = fixture(); await c.openImages(['one'], true);
  inventory.update({bulkBusy: true}); await c.applyImages(); assert.deepEqual(writes, []); assert.equal(inventory.state.bulkBusy, true);
  inventory.update({bulkBusy: false}); await c.applyImages(); assert.equal(locks.some(row => row[0] === 'release-bulk'), false);
  assert.equal(inventory.state.rowBusy.size, 0);
});
test('bulk credential untouched is a no-op and __none profile never collides with explicit clear', async () => {
  const {c, writes, confirmations} = fixture(); c.openCredentials(['one']); await c.applyCredential(); assert.equal(writes.length, 0);
  c.chooseCredential('profile:__none'); await c.applyCredential(); assert.deepEqual(writes[0].body, {device_ids: ['one'], credential_profile_id: '__none'});
  assert.equal(confirmations.length, 0); c.openCredentials(['one', 'two']); c.chooseCredential('clear'); await c.applyCredential();
  assert.match(confirmations[0], /2 reviewed.*Onboard and undeploy/s); assert.equal(writes[1].body.credential_profile_id, '');
});
test('bulk credential clear cancellation and unavailable/missing selected profile prevent writes', async () => {
  const {c, writes, locks} = fixture(); c.openCredentials(['one']); c.chooseCredential('clear'); c.services.confirm = () => false;
  await c.applyCredential(); assert.deepEqual(locks, []);
  c.chooseCredential('profile:operator'); c.prerequisites({credentials: [], credentialsOk: true, rowBusy: new Set(), bulkBusy: false});
  await c.applyCredential(); assert.equal(writes.length, 0);
  c.prerequisites({credentials: [{id: 'operator'}], credentialsOk: false, rowBusy: new Set(), bulkBusy: false});
  await c.applyCredential(); assert.equal(writes.length, 0); assert.equal(c.state.choice, 'profile:operator');
});
test('bulk credentials use captured explicit ids, one POST, strict partial counts and shared lock', async () => {
  const {c, writes, locks, reports} = fixture(); c.openCredentials(['one', 'two']); c.chooseCredential('profile:operator');
  c.services.selectedIds = () => ['unreviewed'];
  c.services.post = async (path, body) => { writes.push({path, body}); return reply({ok: true, applied: 1, failed: {two: 'not found'}}); };
  await c.applyCredential(); await c.applyCredential(); assert.equal(writes.length, 1);
  assert.deepEqual(writes[0], {path: '/api/v1/devices/bulk-credential', body: {device_ids: ['one', 'two'], credential_profile_id: 'operator'}});
  assert.match(reports[0][0], /1\/2.*two \(not found\)/); assert.equal(locks.at(-1)[0], 'release-bulk');
});
for (const body of [{}, {ok: true, applied: 2, failed: {}}, {ok: true, applied: 1, failed: {other: 'bad'}},
  {ok: true, applied: -1, failed: {}}, {ok: true, applied: 0, failed: []}, {ok: true, applied: 0, failed: {one: {}}}]) {
  test(`malformed bulk result is unknown: ${JSON.stringify(body)}`, () => assert.equal(bulkCredentialResult(reply(body), body, ['one']).unknown, true));
}
test('credential unknown writes stay locked through close/reopen and never repeat after hidden completion', async () => {
  const {c, locks, reads, hide} = fixture(), gate = wait(); let count = 0;
  c.openCredentials(['one']); c.chooseCredential('profile:operator'); c.services.post = () => { count++; return gate.promise; };
  const job = c.applyCredential(); c.close(); c.openCredentials(['two']); await c.applyCredential(); assert.equal(count, 1);
  hide(); gate.reject(Error('lost')); await job;
  assert.equal(locks.at(-1)[0], 'release-bulk'); assert.equal(reads.some(row => row.path === 'refresh'), false);
});
test('five-hundred write replies are unknown, four-hundred refusals remain explicit', () => {
  assert.equal(assignmentResult(reply({}, 500), {}, []).kind, 'unknown');
  assert.equal(assignmentResult(reply({}, 403), {}, []).kind, 'refused');
  assert.equal(bulkCredentialResult(reply({}, 500), {}, ['one']).unknown, true);
  assert.equal(bulkCredentialResult(reply({}, 403), {}, ['one']).failed.length, 1);
});
