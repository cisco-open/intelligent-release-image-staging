// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {PoliciesController} from '../src/policies-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {definitionForm, definitionPayload, checkedDefinitions, checkedDefinitionPreview, definitionWriteResult,
  definitionProblem, definitionPreviewText, policyEtagRevision, policyBody, rateHint, roleQosFields, expiryChoices} from '../src/policy-definitions-model.mjs';
import {instructionDiagnostics, instructionMapRows, policyDiagnostics, roleCapabilityMessage} from '../src/policy-model.mjs';

const reply = (body, status = 200, headers = {}) => ({ok: status >= 200 && status < 300, status, body,
  json: async () => body, text: async () => body, headers: {get: key => headers[key] || null}});
const gate = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
const tick = () => new Promise(resolve => setImmediate(resolve));
const preview = (extra = {}) => ({ok: true, dry_run: true, revision: 8, candidate_revision: 8,
  member_delta: 0, origin_access_lost: 2, empty_permitted_sets: 0, role_pairs_stopped: 1,
  qos_changed: true, requires_confirmation: true, confirm_token: 'preview-token', ...extra});
const saved = (extra = {}) => ({ok: true, dry_run: false, revision: 8, ...extra});
test('expiry labels preserve API values and explain built-in fallback and inheritance', () => {
  assert.deepEqual(expiryChoices.map(choice => choice.value), ['', 'keep', 'defaults']);
  assert.equal(expiryChoices[0].label, 'Follow the server setting');
  assert.match(expiryChoices[0].help, /roles with sharing limits keep.*Server-wide overrides can change this/);
  assert.match(expiryChoices[1].help, /verified transfer limits and check-in timing/);
  assert.match(expiryChoices[2].help, /no upload or download speed limit/);
  assert.match(expiryChoices[2].help, /not your current role or server defaults/);
  for (const choice of expiryChoices) {
    const form = definitionForm('branch'); form.onStale = choice.value;
    const {definition} = definitionPayload(form, {name: null, original: {}});
    assert.equal(definition.on_stale, choice.value || undefined);
  }
});
test('role preview describes exact impact counts without claiming live blocking', () => {
  const text = definitionPreviewText('Edit branch', preview({member_delta: 2, origin_access_lost: 3, empty_permitted_sets: 1, role_pairs_stopped: 4}));
  for (const line of ['Membership changes: 2', 'Devices losing distribution permission: 3', 'Devices losing all permitted peers: 1',
    'Role-to-role links removed: 4', 'Speed or agent settings changed: yes', 'existing device-to-device sessions may continue']) assert.ok(text.includes(line), line);
  assert.doesNotMatch(text, /Devices blocked|Blocks confirmed/);
});
async function fixture() {
  const c = new PoliciesController(), inventory = new InventoryController(), calls = [], replies = [], prompts = [], downloads = [];
  const data = {revision: 7, roles: {boat: {restricted: true, peers: ['boat', 'fiber'], origin: false, qos: {seed_up_bps: 12500000}, qos_state: {seeder: {numwant: 4}}},
    fiber: {restricted: true, peers: ['fiber', 'boat'], origin: true}}};
  let visible = true, ticket = 0;
  const fetch = async (path, options = {}) => {
    calls.push({path, options, body: options.body ? JSON.parse(options.body) : undefined});
    if (options.method) {
      const value = replies.shift(); if (value instanceof Error) throw value;
      const result = await value;
      if (result.body?.dry_run === false) data.revision = result.body.revision;
      if (result.status === 204) data.revision = policyEtagRevision(result.headers.get('ETag')) || data.revision;
      return result;
    }
    if (path.endsWith('/export-csv')) return reply('role,restricted\nboat,true\n', 200, {'Content-Type': 'text/csv; charset=utf-8'});
    if (path.endsWith('/roles')) return reply({revision: data.revision, roles: data.roles});
    return reply({revision: data.revision, roles_supported: true, quarantine_assignments: [], roles: {defined: 2, members: {boat: 2, fiber: 1}}});
  };
  c.connect({fetch, headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), isVisible: () => visible,
    beginPolicyRead: () => ++ticket, publishPolicy: (policy, valid, mine) => {if (mine !== ticket) return false; c.policy(valid ? policy : c.state.policy, valid); return true;},
    invalidatePolicyReads() {ticket++; inventory.invalidate();},
    claimBulk() {if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; inventory.update({bulkBusy: true}); return true;},
    releaseBulk() {inventory.update({bulkBusy: false});}, confirm(message) {prompts.push(message); return true;}, saveCsv: (...args) => downloads.push(args)});
  inventory.subscribe(() => c.prerequisites(inventory.state)); await c.refresh();
  const open = (name = null) => {c.open(name); if (!name) c.field('name', 'new-role');};
  return {c, inventory, calls, replies, prompts, downloads, data, open, hide() {visible = false; c.hide();}, tabHide() {visible = false; c.pause();}, show() {visible = true;},
    supersede(policy) {ticket++; if (policy) c.policy(policy, true);}, writes: () => calls.filter(call => call.options.method)};
}
test('definition create previews and commits one captured body, token, CSRF and original CAS', async () => {
  const f = await fixture(); f.open(); f.c.field('restricted', true); f.c.field('peers', 'boat'); f.c.field('nets', '192.0.2.0/24');
  f.replies.push(reply(preview())); await f.c.save(); assert.ok(f.c.state.preview); assert.equal(f.inventory.state.bulkBusy, true);
  f.c.policy({...f.c.state.policy, revision: 99}, true); f.replies.push(reply(saved())); await f.c.save();
  const writes = f.writes(); assert.equal(writes.length, 2); assert.match(writes[0].path, /new-role\?dry_run=1$/);
  assert.deepEqual(writes[0].body, {restricted: true, peers: ['new-role', 'boat'], origin: true, nets: ['192.0.2.0/24']});
  assert.deepEqual(writes[1].body, {...writes[0].body, confirm_token: 'preview-token'});
  for (const call of writes) {assert.equal(call.options.headers['If-Match'], '"iris-peer-policy-7"'); assert.equal(call.options.headers['X-CSRF-Token'], 'fixture');}
  assert.equal(f.c.state.dialog, null); assert.match(f.c.state.message, /saved at policy revision 8/); assert.equal(f.inventory.state.bulkBusy, false);
});
test('existing editor holds original definition revision and deep-cloned non-editable overlay', async () => {
  const f = await fixture(); f.open('boat'); f.c.state.definitions.boat.qos_state.seeder.numwant = 9;
  f.data.roles.boat = {...f.data.roles.boat, qos_state: {seeder: {numwant: 12}}, origin: true}; f.data.revision = 8; await f.c.refresh();
  f.replies.push(reply({code: 'revision_conflict'}, 412)); await f.c.save();
  assert.equal(f.writes()[0].options.headers['If-Match'], '"iris-peer-policy-7"'); assert.deepEqual(f.writes()[0].body.qos_state, {seeder: {numwant: 4}});
  assert.equal(f.writes()[0].body.origin, false); assert.equal(f.c.state.editor.stale, true); assert.match(f.c.state.formMessage, /reopen/);
  f.replies.push(reply(preview())); await f.c.save(); assert.equal(f.writes().length, 1);
  await f.c.reloadEditor(); assert.equal(f.c.state.editor.revision, 8); assert.equal(f.c.state.form.origin, true);
  assert.deepEqual(f.c.state.editor.original.qos_state, {seeder: {numwant: 12}});
});
for (const field of ['nets', 'restricted']) test(`editing ${field} during pending preview invalidates its approval`, async () => {
  const f = await fixture(), pending = gate(); f.open(); f.replies.push(pending.promise); const request = f.c.save();
  f.c.field(field, field === 'nets' ? '198.51.100.0/24' : true); pending.resolve(reply(preview())); await request;
  assert.equal(f.c.state.preview, null); assert.equal(f.inventory.state.bulkBusy, false); assert.match(f.c.state.formMessage, /Preview again/);
  f.replies.push(reply(preview())); await f.c.save(); assert.equal(f.writes().length, 2);
  if (field === 'nets') assert.deepEqual(f.writes()[1].body.nets, ['198.51.100.0/24']);
  else assert.equal(f.writes()[1].body.restricted, true);
});
test('editing after preview cancels its token and releases only its own lease', async () => {
  const f = await fixture(); f.open(); f.replies.push(reply(preview())); await f.c.save(); f.c.field('origin', false);
  assert.equal(f.c.state.preview, null); assert.equal(f.inventory.state.bulkBusy, false); f.inventory.update({bulkBusy: true}); f.c.close(); assert.equal(f.inventory.state.bulkBusy, true);
});
test('tab pause preserves the open role draft and exact reviewed preview without another read', async () => {
  const f = await fixture(); f.open('boat'); f.c.field('nets', '192.0.2.0/24');
  f.replies.push(reply(preview())); await f.c.save();
  const {form, editor, preview: approved} = f.c.state, calls = f.calls.length;
  f.c.pause();
  assert.equal(f.c.state.dialog, 'editor'); assert.equal(f.c.state.form, form);
  assert.equal(f.c.state.editor, editor); assert.equal(f.c.state.preview, approved);
  assert.equal(f.calls.length, calls); assert.equal(f.inventory.state.bulkBusy, true);
  f.c.hide(); assert.equal(f.c.state.dialog, null); assert.equal(f.inventory.state.bulkBusy, false);
});
test('tab pause rejects a late policy read while preserving typed role fields', async () => {
  const f = await fixture(); f.open('boat'); f.c.field('nets', '192.0.2.0/24');
  const pending = gate(); f.c.services.fetch = () => pending.promise;
  const read = f.c.refresh(); f.tabHide(); f.show();
  pending.resolve(reply({revision: 88, roles_supported: true, quarantine_assignments: [], roles: {}}));
  await read; assert.equal(f.c.state.loading, false); assert.equal(f.c.state.policy.revision, 7);
  assert.equal(f.c.state.form.nets, '192.0.2.0/24'); assert.equal(f.c.state.dialog, 'editor');
});
test('preview started before tab hide cannot be adopted after returning', async () => {
  const f = await fixture(), pending = gate(); f.open('boat');
  f.replies.push(pending.promise); const action = f.c.save(); f.tabHide(); f.show();
  pending.resolve(reply(preview())); await action;
  assert.equal(f.c.state.preview, null); assert.equal(f.c.state.dialog, 'editor');
  assert.match(f.c.state.formMessage, /Preview interrupted/); assert.equal(f.inventory.state.bulkBusy, false);
  assert.equal(f.writes().length, 1);
});
for (const result of ['saved', 'unknown']) test('tab hide/return retains committed role result ' + result, async () => {
  const f = await fixture(), pending = gate(); f.open('boat'); f.replies.push(reply(preview())); await f.c.save();
  f.replies.push(pending.promise); const action = f.c.save(); f.tabHide(); f.show();
  pending.resolve(reply(result === 'saved' ? saved() : {})); await action;
  assert.equal(f.c.state.reviewRequired, result === 'unknown'); assert.equal(f.writes().length, 2);
  assert.match(f.c.state.message, result === 'saved' ? /saved at policy revision/ : /may have been saved/);
});
for (const close of ['close', 'hide']) test(`${close} during preview blocks reopening until the request finishes`, async () => {
  const f = await fixture(), pending = gate(); f.open(); f.replies.push(pending.promise); const request = f.c.save();
  if (close === 'hide') f.hide(); else f.c.close(); f.open('boat'); assert.equal(f.c.state.dialog, null); assert.equal(f.inventory.state.bulkBusy, true);
  pending.resolve(reply(preview())); await request; assert.equal(f.c.state.dialog, null); assert.equal(f.c.state.preview, null); assert.equal(f.inventory.state.bulkBusy, false);
});
for (const mode of ['empty', 'html', 'lost', 'server', 'preview', 'wrong-revision']) test(`definition commit ${mode} cannot be mistaken for saved or replayed`, async () => {
  const f = await fixture(); f.open(); f.replies.push(reply(preview())); await f.c.save();
  f.replies.push(mode === 'lost' ? Error('offline') : mode === 'html' ? {...reply({}), json: async () => {throw Error('HTML');}}
    : reply(mode === 'preview' ? preview() : mode === 'wrong-revision' ? saved({revision: 6}) : {}, mode === 'server' ? 503 : 200));
  await f.c.save(); assert.equal(f.c.state.reviewRequired, true); assert.match(f.c.state.message, /may have been saved/); assert.equal(f.c.state.dialog, 'editor');
  await f.c.save(); assert.equal(f.writes().length, 2); f.c.close(); f.open(); await f.c.save(); assert.equal(f.writes().length, 2);
  f.c.services.fetch = async () => {throw Error('offline');}; await f.c.refresh(true); assert.equal(f.c.state.reviewRequired, true);
});
test('pending hidden commit retains uncertainty and lease, never reopens or refreshes hidden', async () => {
  const f = await fixture(), pending = gate(); f.open(); f.replies.push(reply(preview())); await f.c.save(); f.replies.push(pending.promise);
  const request = f.c.save(); f.c.field('name', 'changed'); assert.equal(f.c.state.form.name, 'new-role'); f.hide(); const count = f.calls.length;
  assert.equal(f.inventory.state.bulkBusy, true); pending.resolve(reply({})); await request;
  assert.equal(f.calls.length, count); assert.equal(f.c.state.reviewRequired, true); assert.equal(f.c.state.dialog, null); assert.equal(f.inventory.state.bulkBusy, false);
});
for (const [status, code] of [[412, 'precondition_failed'], [428, 'confirmation_required'], [409, 'operation_backlog_full'], [409, 'role_in_use'], [401, 'session_expired']]) {
  test(`definition refusal ${status} ${code} resets preview without replay`, async () => {
    const f = await fixture(); f.open(); f.replies.push(reply(preview()), reply({code}, status)); await f.c.save(); await f.c.save();
    assert.equal(f.writes().length, 2); assert.equal(f.c.state.reviewRequired, false); assert.equal(f.c.state.preview, null); assert.equal(f.c.state.failed, true);
  });
}
test('delete uses a checked dry run, named confirmation, original CAS and native204 ETag', async () => {
  const f = await fixture(); f.replies.push(reply(preview()), reply(null, 204, {ETag: '"iris-peer-policy-9"'}));
  await f.c.delete('boat'); assert.equal(f.writes().length, 2); assert.match(f.prompts[0], /Delete role boat.*Membership changes/s);
  assert.match(f.c.state.message, /Role boat deleted at policy revision 9/);
  assert.deepEqual(f.writes()[1].body, {confirm_token: 'preview-token'}); assert.equal(f.writes()[1].options.headers['If-Match'], '"iris-peer-policy-7"');
});
for (const [status, etag] of [[200, '"iris-peer-policy-8"'], [204, null], [204, 'W/"iris-peer-policy-8"'], [204, '"iris-peer-policy-6"']]) {
  test(`delete status ${status} etag ${etag} is unknown without the real completion contract`, async () => {
    const f = await fixture(); f.replies.push(reply(preview()), reply({}, status, {ETag: etag})); await f.c.delete('boat');
    assert.equal(f.c.state.reviewRequired, true); assert.match(f.c.state.message, /may have changed/); assert.equal(f.writes().length, 2);
  });
}
test('delete cancellation, all-failed preview and navigation never commit', async () => {
  const f = await fixture(); f.c.services.confirm = () => false; f.replies.push(reply(preview())); await f.c.delete('boat');
  assert.equal(f.writes().length, 1); assert.match(f.c.state.message, /cancelled; nothing changed/);
  f.replies.push(reply({code: 'role_in_use', member_count: 2, device_ids: ['one', 'two'], referring_schedules: ['nightly']}, 409)); await f.c.delete('boat');
  assert.match(f.c.state.message, /2 device.*one, two.*nightly/);
  const pending = gate(); f.replies.push(pending.promise); const request = f.c.delete('boat'); f.hide(); pending.resolve(reply(preview())); await request;
  assert.equal(f.writes().length, 3);
});
test('CSV import previews exact captured bytes, confirms whole replacement and validates returned role count', async () => {
  const f = await fixture(), csv = 'role,restricted\nboat,true\nfiber,true\n';
  f.replies.push(reply(preview({roles: 2})), reply(saved({roles: 2}))); await f.c.importFile({name: 'roles.csv', size: csv.length, text: async () => csv});
  assert.equal(f.writes().length, 2); assert.equal(f.writes()[0].body.csv, csv); assert.equal(f.writes()[1].body.csv, csv);
  assert.match(f.prompts[0], /Replace every role definition.*2 role.*Roles missing from the file are removed/s);
  assert.match(f.c.state.message, /Imported 2 role definition\(s\) from roles.csv at policy revision 8/);
});
test('CSV incomplete success is unknown; a malformed preview sends no commit', async () => {
  const f = await fixture(), file = {name: 'roles.csv', size: 5, text: async () => 'role\n'};
  f.replies.push(reply({})); await f.c.importFile(file); assert.equal(f.writes().length, 1); assert.match(f.c.state.message, /No commit was sent/);
  f.replies.push(reply(preview({roles: 2})), reply(saved({roles: 1}))); await f.c.importFile(file);
  assert.equal(f.c.state.reviewRequired, true); assert.match(f.c.state.message, /may have changed/);
  await f.c.importFile(file); assert.equal(f.writes().length, 3);
});
test('CSV file failures, encoded-body limits and hidden late reads send no request and release the lock', async () => {
  const f = await fixture();
  for (const file of [{size: 8388609}, {size: 4, text: async () => {throw Error('file unreadable');}}, {size: 4, text: async () => 'é'.repeat(4194304)}]) {
    await f.c.importFile({name: 'roles.csv', ...file}); assert.equal(f.writes().length, 0); assert.equal(f.inventory.state.bulkBusy, false);
  }
  const pending = gate(); const request = f.c.importFile({name: 'late.csv', size: 4, text: () => pending.promise}); f.hide(); pending.resolve('role\n'); await request;
  assert.equal(f.writes().length, 0); assert.equal(f.inventory.state.bulkBusy, false);
});
test('CSV permits bodies above ordinary policy limit but checks token-bearing encoded import size', async () => {
  const f = await fixture(), csv = 'role\n' + 'boat\n'.repeat(20000);
  f.replies.push(reply(preview({roles: 1})), reply(saved({roles: 1})));
  await f.c.importFile({name: 'large.csv', size: csv.length, text: async () => csv});
  assert.equal(f.writes().length, 2); assert.equal(f.writes()[1].body.csv, csv);
  const exact = 'a'.repeat(8388608 - JSON.stringify({csv: ''}).length);
  f.replies.push(reply(preview({revision: 9, roles: 1})));
  await f.c.importFile({name: 'limit.csv', size: exact.length, text: async () => exact});
  assert.equal(f.writes().length, 3); assert.match(f.c.state.message, /8 MiB.*No commit was sent/);
  assert.equal(f.c.state.reviewRequired, false); assert.equal(f.inventory.state.bulkBusy, false);
});
test('role exports verify CSV content, save exact text, and reject late downloads on hide', async () => {
  const f = await fixture(); await f.c.exportCsv(); assert.deepEqual(f.downloads, [['role,restricted\nboat,true\n', 'roles.csv']]);
  f.c.services.fetch = async () => reply('<html>', 200, {'Content-Type': 'text/html'}); await f.c.exportCsv(); assert.equal(f.downloads.length, 1); assert.match(f.c.state.downloadMessage, /unavailable/);
  const pending = gate(); f.c.services.fetch = async () => ({...reply('', 200, {'Content-Type': 'text/csv'}), text: () => pending.promise});
  const request = f.c.exportCsv(); await tick(); f.hide(); pending.resolve('late'); await request; assert.equal(f.downloads.length, 1);
});
test('capability, degraded policy, unavailable definitions and shared row/bulk locks prevent writes', async () => {
  const f = await fixture(); f.open(); f.inventory.claimRow('one'); await f.c.save(); assert.equal(f.writes().length, 0); assert.equal(f.inventory.state.rowBusy.size, 1);
  f.inventory.releaseRow('one'); f.inventory.update({bulkBusy: true}); await f.c.save(); f.c.close(); assert.equal(f.inventory.state.bulkBusy, true);
  f.inventory.update({bulkBusy: false}); f.c.policy({...f.c.state.policy, degraded: true}, true); f.open(); assert.equal(f.c.state.dialog, null); assert.match(f.c.state.message, /degraded/);
  f.c.policy({...f.c.state.policy, degraded: false, roles_supported: false}, true); await f.c.delete('boat'); assert.equal(f.writes().length, 0);
  f.c.update({definitionsRevision: null}); f.c.policy({...f.c.state.policy, roles_supported: true}, true); f.open('boat'); assert.equal(f.c.state.dialog, null);
});
test('policy reads are latest-only across late bodies, failed reads, hide and external Inventory tickets', async () => {
  const f = await fixture(), pending = gate(), fetch = f.c.services.fetch;
  f.c.services.fetch = async path => path.endsWith('/roles') ? {...reply({}), json: () => pending.promise} : fetch(path);
  const old = f.c.refresh(true); await tick(); f.hide(); pending.resolve({revision: 1, roles: {stale: {}}}); await old;
  assert.equal(f.c.state.definitionsRevision, 7); assert.equal(f.c.state.loading, false); f.show();
  const policy = gate(); f.c.services.fetch = () => policy.promise; const another = f.c.refresh(); f.supersede({...f.c.state.policy, revision: 12});
  policy.resolve(reply({revision: 8, quarantine_assignments: []})); await another; assert.equal(f.c.state.policy.revision, 12);
  f.c.services.fetch = async () => {throw Error('offline');}; await f.c.refresh(); assert.equal(f.c.state.policyOk, false); assert.equal(f.c.state.policy.revision, 12);
});
test('mismatched policy/definition revisions cannot enable editing or release unknown-result gate', async () => {
  const f = await fixture(); f.c.update({reviewRequired: true});
  f.c.services.fetch = async path => reply(path.endsWith('/roles') ? {revision: 8, roles: f.data.roles} : {revision: 9, roles_supported: true, quarantine_assignments: []});
  assert.equal(await f.c.refresh(true), false); assert.equal(f.c.current(), false); assert.equal(f.c.state.reviewRequired, true); f.open('boat'); assert.equal(f.c.state.dialog, null);
});
test('model validates role/QoS fields, preserves overlay, and counts encoded bytes without precision loss', () => {
  const editor = {name: 'boat', original: {qos_state: {leecher: {numwant: 5}}}}, form = definitionForm('boat', {restricted: true});
  for (const [key, value] of [['max_peers', '0'], ['fanout', '1001'], ['catalog_tick_s', '61'], ['numwant', '3'], ['telemetry_pause', 'maybe'], ['seed_up_bps', '1'], ['seed_up_bps', '9007199254740993']]) {
    assert.throws(() => definitionPayload({...form, qos: {...form.qos, [key]: value}}, editor));
  }
  const all = {...form, qos: Object.fromEntries(roleQosFields.map(([key, , kind, min]) => [key, kind === 'bool' ? 'false' : String(min)]))};
  all.qos.max_peers = '5'; all.qos.fanout = '5'; assert.equal(Object.keys(definitionPayload(all, editor).definition.qos).length, roleQosFields.length);
  assert.deepEqual(definitionPayload(form, editor).definition.qos_state, editor.original.qos_state);
  assert.throws(() => definitionPayload({...form, name: 'renamed'}, editor)); assert.throws(() => policyBody({csv: 'é'.repeat(40000)}));
  assert.equal(rateHint('0'), 'unlimited'); assert.equal(rateHint('12500000'), '≈ 100.0 Mbit/s'); assert.match(rateHint('1'), /too low/);
});
test('definition response checks reject incomplete bodies, unsafe revisions and weak or malformed ETags', () => {
  for (const key of ['restricted', 'origin', 'peers', 'nets', 'on_stale', 'qos', 'qos_state']) assert.throws(() => checkedDefinitions({revision: 7, roles: {boat: {[key]: null}}}));
  for (const qos_state of [{seeder: null}, {unknown: {}}, {seeder: {numwant: 3}}, {leecher: {max_peers: 10}}]) assert.throws(() => checkedDefinitions({revision: 7, roles: {boat: {qos_state}}}));
  for (const body of [{}, {revision: 7, roles: []}, {revision: 7, roles: {boat: {peers: 'boat'}}}, {revision: 7, roles: {boat: {qos: {origin_up_bps: 10}}}}]) assert.throws(() => checkedDefinitions(body));
  for (const patch of [{dry_run: false}, {revision: 6}, {confirm_token: null}, {member_delta: '0'}, {qos_changed: null}]) assert.throws(() => checkedDefinitionPreview(preview(patch), 7));
  assert.throws(() => checkedDefinitionPreview(preview({roles: undefined}), 7, true));
  for (const value of ['iris-peer-policy-8', 'W/"iris-peer-policy-8"', '"iris-peer-policy-9007199254740993"', '"iris-peer-policy-8" extra']) assert.equal(policyEtagRevision(value), null);
  assert.equal(definitionWriteResult(reply(saved(), 200, {ETag: '"iris-peer-policy-9"'}), saved(), 7).kind, 'unknown');
  assert.equal(definitionWriteResult(reply(saved(), 200, {ETag: 'bad'}), saved(), 7).kind, 'unknown');
  assert.match(definitionProblem(409, {code: 'role_in_use', roles: ['boat'], referring_roles: ['fiber']}, 'Import'), /missing from the file: boat.*referred to by fiber/);
});
test('preflight diagnostics distinguish unknown, zero, missing and stale evidence', () => {
  const p = {enforcement: {stale: true, mutual_origin: {mode: 'preflight'}}};
  for (const value of [null, undefined, false, '0', -1, NaN]) {
    p.enforcement.mutual_origin.newly_denied_device_count = value;
    const text = policyDiagnostics(p, true, String).mutual;
    assert.match(text, /preflight count unavailable/i); assert.doesNotMatch(text, /newly denied devices/);
    assert.match(text, /restriction is not active/); assert.match(text, /Tracker status is stale/);
  }
  p.enforcement.mutual_origin.newly_denied_device_count = 0;
  assert.match(policyDiagnostics(p, true, String).mutual, /0 newly denied devices/);
  delete p.enforcement.mutual_origin;
  assert.match(policyDiagnostics(p, true, String).mutual, /status unavailable/);
});
test('capability warnings retain downgrade containment and fail-closed guidance', () => {
  for (const p of [{roles_supported: false}, {}]) {
    const warning = roleCapabilityMessage(p, true);
    assert.match(warning, /cannot confirm.*role support/);
    assert.match(warning, /Independent peer quarantine is not enforced by older servers/);
    assert.match(warning, /containment and compatibility procedure before downgrading/);
    assert.doesNotMatch(warning, /quarantine restricted devices before/);
  }
  assert.match(roleCapabilityMessage({roles_supported: true, degraded: true}, true), /degraded/);
  assert.match(roleCapabilityMessage({roles_supported: true, fail_closed: true}, true), /fail-closed/);
  assert.match(roleCapabilityMessage({}, false), /unavailable/);
});
test('unknown write requires successful explicit review and reload before another captured preview', async () => {
  const f = await fixture(); f.open('boat'); f.replies.push(reply(preview()), reply({})); await f.c.save(); await f.c.save();
  assert.equal(f.c.state.reviewRequired, true); await f.c.refresh(); assert.equal(f.c.state.reviewRequired, true);
  await f.c.refresh(true); assert.equal(f.c.state.reviewRequired, false); assert.equal(f.c.state.editor.stale, true);
  await f.c.save(); assert.equal(f.writes().length, 2); await f.c.reloadEditor(); assert.equal(f.c.state.editor.stale, false);
  f.replies.push(reply(preview())); await f.c.save(); assert.equal(f.writes().length, 3);
});
test('actual Policies bridge shares Inventory read ordering and mutation locks in both directions', async () => {
  const inventory = new InventoryController(), policies = new PoliciesController();
  let peerPolicy = {}, peerPolicyReadOk = false, peerPolicyReadGeneration = 0, bulkBusy = false, held = null;
  let revision = 7;
  const document = {hidden: false, getElementById: () => ({hidden: false})};
  const csrfHdr = extra => extra, fmtDate = String, confirm = () => true, inventoryActions = {saveCsv() {}};
  const cancelSelectAllMatching = () => inventory.cancelSelection();
  const setBulkBusy = value => {bulkBusy = value; inventory.update({bulkBusy: value});};
  const fetch = async path => {
    if (path === '/api/v1/peer-policy' && held) {const pending = held; held = null; return pending.promise;}
    const fixtures = {'/api/v1/peer-policy': {revision, roles_supported: true, quarantine_assignments: []},
      '/api/v1/peer-policy/roles': {revision, roles: {boat: {restricted: true}}}, '/api/v1/images': {images: []},
      '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
    return reply(fixtures[path] || {devices: [], total: 0, offset: 0, revision: 1, now: 100});
  };
  // Run the shipped adapters, including the publication guard, not a copy.
  const legacy = fs.readFileSync(new URL('../../webroot/app.js', import.meta.url), 'utf8');
  let LAST_DEVICES, LAST_DEV_NOW, devTotal, imageListOk, imageIds, imageFilenames, imageQuarantined, credListOk, credOpts, LAST_JOBS_BY_DEVICE;
  const lastJobStep = {}, bestJobForDevice = () => ({});
  const publishSource = legacy.split('    publish: function (state, policyTicket) {')[1].split('    selectionChanged: updateSelBar,')[0];
  const bridgeSource = legacy.slice(legacy.indexOf('  function roleCapabilityMessage()'), legacy.indexOf('  // React owns captured role targets'));
  const bridge = eval('(() => {' + bridgeSource + '\nreturn {renderPeerPolicyPanel};})()');
  const renderPeerPolicyPanel = bridge.renderPeerPolicyPanel;
  const publish = eval('(function(state, policyTicket) {' + publishSource.slice(0, publishSource.lastIndexOf('},')) + '})');
  inventory.connect({fetch, beginPolicyRead: () => ++peerPolicyReadGeneration, publish});
  await policies.refresh(); assert.equal(policies.state.policy.revision, 7);
  let pending = gate(); held = pending; const oldInventory = inventory.refresh();
  revision = 8; await policies.refresh(); pending.resolve(reply({revision: 7, roles_supported: true, quarantine_assignments: []})); await oldInventory;
  assert.equal(policies.state.policy.revision, 8); assert.equal(inventory.state.policy.revision, 8);
  pending = gate(); held = pending; const oldPolicy = policies.refresh(); revision = 9; await inventory.refresh();
  pending.resolve(reply({revision: 8, roles_supported: true, quarantine_assignments: []})); await oldPolicy;
  assert.equal(policies.state.policy.revision, 9); await policies.refresh(); assert.equal(policies.current(), true);
  inventory.claimRow('one'); assert.equal(policies.state.externalBusy, true); policies.open('boat'); assert.equal(policies.state.dialog, null);
  inventory.releaseRow('one'); policies.open('boat'); assert.equal(policies.claim(), true); assert.equal(inventory.state.bulkBusy, true);
  policies.close(); assert.equal(inventory.state.bulkBusy, false);
});
test('diagnostics keep exact revisions and explain signing status without inventing evidence', () => {
  const p = {fleet_rollup: {issued_revision: 12, applied: {'7': 2, '9223372036854775807': 1}, states: {applied: 3}},
    instruction_status: {observed_at: 456, instr_stamp_missing: 0, pointer_skew: 1},
    instruction_keys: {enabled: true, state: 'signing_refused', certificate_days_to_expiry: -2, keylist_age_days: 136,
      root_ceremony_overdue: 'critical', root_quorum_degraded: true, roots_attested_180d: 1, roots_configured: 2,
      certificate_renewal_due: true, signing_refused: true, keylist_resign_due: false}};
  const diag = instructionDiagnostics(p, time => 'time:' + time);
  assert.deepEqual(diag.applied, [{label: 'r7', count: 2}, {label: 'r9223372036854775807', count: 1}]);
  assert.equal(diag.cells['policy-instr-stamp-missing'], '0 devices'); assert.equal(diag.cells['instruction-cert-days'], '-2 days');
  assert.equal(diag.cells['policy-instruction-observed'], 'time:456'); assert.match(diag.cells['instruction-root-quorum'], /Confirmation needed.*1 of 2 roots confirmed within 180 days/);
  assert.equal(diag.cells['instruction-key-state'], 'Signing stopped');
  assert.equal(diag.cells['instruction-root-ceremony'], 'Review overdue');
  assert.equal(diag.cells['instruction-key-actions'], 'Renew signing certificate · Signing is stopped');
  const missing = instructionDiagnostics({}, String); assert.equal(missing.cells['instruction-key-actions'], 'Unavailable'); assert.deepEqual(missing.applied, [{label: 'unavailable'}]);
  const disabled = instructionDiagnostics({instruction_keys: {enabled: false}}, String); assert.equal(disabled.cells['instruction-root-quorum'], 'Not enabled'); assert.equal(disabled.cells['instruction-key-actions'], 'Not enabled');
  const hidden = policyDiagnostics({...p, roles: {members: {boat: 2}, nets: ['192.0.2.1']}, role_drift: {count: 1, device_ids: ['192.0.2.2']}}, true, String);
  assert.doesNotMatch(JSON.stringify(hidden), /192\.0\.2/);
  assert.deepEqual(instructionMapRows({}, false, 'none'), [{label: 'none'}]); assert.deepEqual(instructionMapRows({bad: -1}, false, 'none'), [{label: 'unavailable'}]);
  assert.match(roleCapabilityMessage({roles_supported: false}, true), /Independent peer quarantine is not enforced by older servers/);
});
test('signing diagnostics translate only recognized public status codes', () => {
  for (const [state, label] of [['phase0', 'Not enabled'], ['invalid', 'Check signing files'], ['ready', 'Ready'],
    ['signing_refused', 'Signing stopped'], ['keylist_missing', 'Revocation list missing'], ['renewal_due', 'Certificate renewal due'],
    ['constructor', 'Unavailable'], ['__proto__', 'Unavailable'], ['unknown-future-state', 'Unavailable'], [null, 'Unavailable']]) {
    const result = instructionDiagnostics({instruction_keys: {state, root_ceremony_overdue: state}}, String);
    assert.equal(result.cells['instruction-key-state'], label);
    assert.equal(result.cells['instruction-root-ceremony'], 'Unavailable');
  }
  for (const [status, label] of [['ok', 'Current'], ['warn', 'Review due'], ['critical', 'Review overdue'], ['unknown', 'Unavailable']]) {
    assert.equal(instructionDiagnostics({instruction_keys: {root_ceremony_overdue: status}}, String).cells['instruction-root-ceremony'], label);
  }
});
