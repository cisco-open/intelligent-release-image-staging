// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {RoleActionsController} from '../src/role-actions-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {checkedRolePreview, roleCommitResult, rolePreviewText, quarantineResult, quarantineConflict} from '../src/role-actions-model.mjs';

const reply = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const gate = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
const preview = (extra = {}) => ({ok: true, applied: 2, failed: {}, dry_run: true, revision: 8,
  member_delta: 2, origin_access_lost: 1, empty_permitted_sets: 0, role_pairs_stopped: 1,
  qos_changed: true, requires_confirmation: true, confirm_token: 'preview-token', ...extra});
const saved = (extra = {}) => ({ok: true, applied: 2, failed: {}, partial: false, dry_run: false, revision: 8, role_drift: {count: 0}, ...extra});
function fixture() {
  const c = new RoleActionsController(), inventory = new InventoryController(), calls = [], reports = [], prompts = [], replies = [];
  let visible = true, refreshes = 0, invalidations = 0;
  c.connect({fetch: async (path, options = {}) => {
    calls.push({path, options, body: options.body ? JSON.parse(options.body) : undefined});
    const next = replies.shift(); if (next instanceof Error) throw next;
    return await next;
  }, headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}),
  warning: () => '', policyWriteBusy: () => false, isVisible: () => visible,
  confirm: message => {prompts.push(message); return true;},
  claimBulk() {if (inventory.state.bulkBusy || inventory.state.rowBusy.size) return false; inventory.update({bulkBusy: true}); return true;},
  releaseBulk() {inventory.update({bulkBusy: false});}, invalidatePolicyReads() {invalidations++;},
  report: (...args) => reports.push(args), refreshInventory: async () => {refreshes++; return true;}});
  inventory.subscribe(() => c.prerequisites(inventory.state));
  inventory.update({selected: new Set(['on-page', 'off-page']), policyOk: true,
    policy: {revision: 7, roles_supported: true, roles: {members: {boat: 2}}, quarantine_assignments: []}});
  const open = () => {c.open(inventory.selectedIds()); c.choice('boat');};
  return {c, inventory, calls, reports, prompts, replies, open,
    hide() {visible = false; c.hide();}, refreshes: () => refreshes, invalidations: () => invalidations};
}
test('role preview captures reviewed IDs and commits once with original CAS and confirmation', async () => {
  const {c, inventory, calls, replies, reports} = fixture(); c.open(inventory.selectedIds()); await c.apply();
  assert.equal(calls.length, 0); c.choice('boat'); inventory.changeSelection(new Set(['unreviewed']));
  replies.push(reply(preview())); await c.apply();
  assert.deepEqual(calls[0].body, {device_ids: ['on-page', 'off-page'], role: 'boat'});
  assert.equal(calls[0].path, '/api/v1/devices/bulk-role?dry_run=1');
  assert.equal(calls[0].options.headers['If-Match'], '"iris-peer-policy-7"');
  assert.equal(calls[0].options.headers['X-CSRF-Token'], 'fixture');
  assert.equal(inventory.state.bulkBusy, true); assert.equal(c.state.externalBusy, false);
  assert.match(c.state.preview.text, /origin access: 1/); assert.match(c.state.preview.text, /QoS policy changed: yes/);
  inventory.update({policy: {...inventory.state.policy, revision: 99}});
  replies.push(reply(saved())); await c.apply();
  assert.equal(calls.length, 2); assert.equal(calls[1].path, '/api/v1/devices/bulk-role');
  assert.deepEqual(calls[1].body, {...calls[0].body, confirm_token: 'preview-token'});
  assert.equal(calls[1].options.headers['If-Match'], '"iris-peer-policy-7"');
  assert.equal(c.state.open, false); assert.equal(inventory.state.bulkBusy, false); assert.match(reports[0][0], /2\/2/);
});
test('clear role is explicit null; changing choice discards preview and releases only its own lock', async () => {
  const {c, inventory, replies, calls, open} = fixture(); open(); replies.push(reply(preview())); await c.apply();
  c.choice('__none'); assert.equal(c.state.preview, null); assert.equal(inventory.state.bulkBusy, false);
  replies.push(reply(preview({requires_confirmation: false, confirm_token: null, qos_changed: false}))); await c.apply();
  assert.equal(calls[1].body.role, null); assert.match(c.state.preview.text, /QoS policy changed: no/);
  c.close(); assert.equal(calls.length, 2); inventory.update({bulkBusy: true}); c.close(); assert.equal(inventory.state.bulkBusy, true);
});
for (const [status, code] of [[412, 'precondition_failed'], [428, 'confirmation_required'], [409, 'operation_backlog_full'], [503, 'policy_unavailable']]) {
  test(`role commit ${status} discards preview without replay`, async () => {
    const {c, inventory, calls, replies, open} = fixture(); open(); replies.push(reply(preview())); await c.apply();
    replies.push(reply({error: code, unacknowledged: 256, capacity: 256}, status)); await c.apply();
    assert.equal(calls.length, 2); assert.equal(c.state.open, true); assert.equal(c.state.preview, null);
    assert.equal(inventory.state.bulkBusy, false); assert.ok(c.state.message.length > 20);
    assert.equal(c.state.reviewRequired, status === 503);
  });
}
test('role partial preview names failures; explicit 503 partial reports accounting and drift', async () => {
  const {c, replies, reports, open} = fixture(); open();
  replies.push(reply(preview({applied: 1, failed: {'off-page': 'role_shadowed_by_assignment'}}))); await c.apply();
  assert.match(c.state.preview.text, /off-page \(explicit ACL assignment shadows the role\)/);
  replies.push(reply({error: 'fleet_write_failed', partial: true, revision: 8, applied: 1, failed: {'off-page': 'write_failed'}, role_drift: {count: 1}}, 503));
  await c.apply(); assert.match(reports[0][0], /1\/2.*off-page.*drift: 1/); assert.equal(reports[0][1], true);
  assert.equal(c.state.open, true); assert.equal(c.state.preview, null); assert.equal(c.state.reviewRequired, false);
});
test('role all-failed preview cannot commit and explains every refusal', async () => {
  const {c, inventory, replies, calls, open} = fixture(); open();
  replies.push(reply({ok: false, applied: 0, failed: {'on-page': 'not_found', 'off-page': 'role_shadowed_by_assignment'}, revision: 7, dry_run: true}));
  await c.apply(); assert.equal(calls.length, 1); assert.equal(c.state.preview, null); assert.equal(inventory.state.bulkBusy, false);
  assert.match(c.state.message, /explicit ACL assignment shadows the role/);
});
for (const closing of ['close', 'hide']) test(`pending ${closing} cannot release another batch early or resurrect preview`, async () => {
  const f = fixture(), pending = gate(); f.open(); f.replies.push(pending.promise);
  const request = f.c.apply(); await f.c.apply(); f.c.choice('__none'); assert.equal(f.c.state.choice, 'boat');
  if (closing === 'hide') f.hide(); else f.c.close();
  assert.equal(f.inventory.state.bulkBusy, true); f.c.open(['new']); assert.equal(f.c.state.open, false);
  pending.resolve(reply(preview())); await request;
  assert.equal(f.calls.length, 1); assert.equal(f.inventory.state.bulkBusy, false); assert.equal(f.c.state.preview, null); assert.equal(f.c.state.open, false);
  assert.equal(f.refreshes(), closing === 'hide' ? 0 : 1);
});
for (const mode of ['lost', 'empty', 'html', 'server', 'bad-accounting', 'drift-missing']) test(`role commit ${mode} is unknown and needs successful explicit review`, async () => {
  const {c, replies, calls, open} = fixture(); open(); replies.push(reply(preview())); await c.apply();
  replies.push(mode === 'lost' ? Error('offline') : mode === 'html' ? {ok: true, status: 200, json: async () => {throw Error('HTML');}}
    : reply(mode === 'bad-accounting' ? saved({applied: 1}) : mode === 'drift-missing' ? saved({role_drift: {}}) : {}, mode === 'server' ? 500 : 200));
  await c.apply(); assert.equal(c.state.reviewRequired, true); assert.match(c.state.message, /may have been saved/);
  await c.apply(); assert.equal(calls.length, 2);
  c.services.refreshInventory = async () => {throw Error('offline');}; await c.review(); assert.equal(c.state.reviewRequired, true);
  c.services.refreshInventory = async () => false; await c.review(); assert.equal(c.state.reviewRequired, true);
  c.services.refreshInventory = async () => true; await c.review(); assert.equal(c.state.reviewRequired, false);
});
test('submitted role write finishes while hidden, reports once without refreshing or reopening', async () => {
  const f = fixture(), pending = gate(); f.open(); f.replies.push(reply(preview())); await f.c.apply(); f.replies.push(pending.promise);
  const request = f.c.apply(); f.hide(); assert.equal(f.inventory.state.bulkBusy, true);
  pending.resolve(reply(saved())); await request; assert.equal(f.c.state.open, false); assert.equal(f.reports.length, 1); assert.equal(f.refreshes(), 0);
  assert.equal(f.invalidations(), 2); assert.equal(f.inventory.state.bulkBusy, false);
});
test('closing or hiding a pending commit cannot bypass unknown-result review on reopen', async () => {
  for (const mode of ['empty', 'lost']) {
    const f = fixture(), pending = gate(); f.open(); f.replies.push(reply(preview())); await f.c.apply(); f.replies.push(pending.promise);
    const request = f.c.apply(); f.hide();
    if (mode === 'lost') pending.reject(Error('offline')); else pending.resolve(reply({}));
    await request; assert.equal(f.c.state.reviewRequired, true);
    f.c.services.isVisible = () => true; f.open(); await f.c.apply();
    assert.equal(f.calls.length, 2); assert.match(f.c.state.message, /previous role result is uncertain/);
    await f.c.review(); assert.equal(f.c.state.reviewRequired, false);
  }
});
test('role availability, removed role, row lock and external bulk lock all prevent writes', async () => {
  const {c, inventory, calls, open} = fixture(); open(); c.services.warning = () => 'Not supported'; await c.apply(); assert.match(c.state.message, /Not supported/);
  c.services.warning = () => ''; c.choice('removed'); await c.apply(); assert.match(c.state.message, /unavailable/);
  c.choice('boat'); inventory.claimRow('on-page'); await c.apply(); assert.equal(inventory.state.rowBusy.size, 1);
  inventory.releaseRow('on-page'); inventory.update({bulkBusy: true}); await c.apply(); c.close(); assert.equal(inventory.state.bulkBusy, true);
  inventory.update({bulkBusy: false}); c.services.policyWriteBusy = () => true; c.open(['on-page']); assert.equal(c.state.open, false);
  assert.equal(calls.length, 0);
});
test('role preview validates effects, total accounting, revision and confirmation before offering commit', () => {
  for (const patch of [{applied: 1}, {failed: {unknown: 'bad'}}, {revision: 6}, {revision: true}, {dry_run: false}, {member_delta: null},
    {origin_access_lost: -1}, {qos_changed: null}, {requires_confirmation: null}, {confirm_token: null}, {confirm_token: ''}]) {
    assert.throws(() => checkedRolePreview(preview(patch), ['on-page', 'off-page'], 7));
  }
  const body = preview(); const copy = checkedRolePreview(body, ['on-page', 'off-page'], 7); body.member_delta = 999; assert.equal(copy.member_delta, 2);
  assert.match(rolePreviewText(copy, 'boat', 2), /existing device-to-device sessions may continue/);
  assert.equal(roleCommitResult(reply({}, 200), saved({role_drift: {count: 1}}), ['on-page', 'off-page'], 7), 'partial');
  for (const status of [200, 503]) assert.equal(roleCommitResult(reply({}, status), saved({partial: true, dry_run: true}), ['on-page', 'off-page'], 7), 'unknown');
  assert.equal(roleCommitResult(reply({}), saved({partial: undefined}), ['on-page', 'off-page'], 7), 'unknown');
});
test('quarantine confirms captured names and advances its own revision serially despite polling', async () => {
  const {c, inventory, replies, calls, prompts, reports} = fixture(), pending = gate();
  replies.push(pending.promise, reply({ok: true, revision: 9, quarantined: true}));
  const request = c.quarantine(inventory.selectedIds(), true); inventory.changeSelection(new Set(['unreviewed']));
  inventory.update({policy: {...inventory.state.policy, revision: 999}});
  assert.equal(calls.length, 1); pending.resolve(reply({ok: true, revision: 8, quarantined: true})); await request;
  assert.match(prompts[0], /on-page, off-page/); assert.equal(calls[1].path, '/api/v1/peer-policy/quarantine/off-page');
  assert.deepEqual(calls.map(call => call.body), [{quarantined: true, if_revision: 7}, {quarantined: true, if_revision: 8}]);
  assert.equal(calls[1].options.headers['If-Match'], '"iris-peer-policy-8"'); assert.equal(calls[1].options.headers['X-CSRF-Token'], 'fixture');
  assert.match(reports[0][0], /2\/2/); assert.equal(reports[0][1], false); assert.equal(inventory.state.bulkBusy, false);
});
for (const [status, error] of [[412, 'precondition failed'], [409, 'revision_conflict']]) test(`quarantine confirmed CAS ${status} re-reads and retries once`, async () => {
  const {c, replies, calls} = fixture(); replies.push(reply({error}, status), reply({revision: 10}), reply({ok: true, revision: 11, quarantined: false}));
  await c.quarantine(['on-page'], false); assert.equal(calls.length, 3); assert.equal(calls[1].path, '/api/v1/peer-policy');
  assert.equal(calls[2].body.if_revision, 10); assert.equal(c.state.results[0].result, 'saved');
});
test('quarantine second CAS refusal is not retried a third time', async () => {
  const {c, replies, calls} = fixture(); replies.push(reply({error: 'revision_conflict'}, 409), reply({revision: 10}), reply({error: 'revision_conflict'}, 409));
  await c.quarantine(['on-page'], true); assert.equal(calls.length, 3); assert.equal(c.state.results[0].result, 'refused');
});
for (const [status, body] of [[409, {error: 'operation_backlog_full'}], [412, {}], [403, {error: 'denied'}], [422, {error: 'invalid'}]]) {
  test(`quarantine explicit refusal ${status} ${JSON.stringify(body)} does not retry`, async () => {
    const {c, replies, calls} = fixture(); replies.push(reply(body, status)); await c.quarantine(['on-page'], true);
    assert.equal(calls.length, 1); assert.equal(c.state.results[0].result, 'refused');
  });
}
for (const result of [reply({}), reply({ok: true, quarantined: false, revision: 8}), reply({ok: true, quarantined: true, revision: 6}), reply({}, 503), Error('lost')]) {
  test(`quarantine uncertain result stops remaining devices: ${JSON.stringify(result)}`, async () => {
    const {c, replies, calls, reports, inventory} = fixture(); replies.push(result); await c.quarantine(['on-page', 'off-page'], true);
    assert.equal(calls.length, 1); assert.deepEqual(c.state.results, [{id: 'on-page', result: 'unknown'}, {id: 'off-page', result: 'not attempted'}]);
    assert.match(reports[0][0], /0\/2.*on-page: unknown.*off-page: not attempted.*Refresh/); assert.equal(reports[0][1], true);
    assert.equal(inventory.state.bulkBusy, false);
  });
}
test('quarantine unavailable conflict refresh stops the remainder', async () => {
  const {c, replies, calls} = fixture(); replies.push(reply({error: 'revision_conflict'}, 409), reply({revision: 10, fail_closed: true}));
  await c.quarantine(['on-page', 'off-page'], false); assert.equal(calls.length, 2);
  assert.match(c.state.results[0].result, /current policy unavailable/); assert.equal(c.state.results[1].result, 'not attempted');
});
test('quarantine capability, lock and cancellation gates send nothing', async () => {
  const {c, inventory, calls, open, replies} = fixture(); inventory.update({policyOk: false}); await c.quarantine(['on-page'], true);
  inventory.update({policyOk: true}); inventory.claimRow('on-page'); await c.quarantine(['on-page'], true); inventory.releaseRow('on-page');
  c.services.confirm = () => false; await c.quarantine(['on-page'], true); assert.equal(calls.length, 0);
  c.services.confirm = () => true; open(); replies.push(reply(preview())); await c.apply(); await c.quarantine(['on-page'], true);
  assert.equal(calls.length, 1); assert.equal(inventory.state.bulkBusy, true); c.close();
  assert.equal(quarantineResult(reply({}), {ok: true, revision: 7, quarantined: false}, false, 7), 'saved');
  assert.equal(quarantineConflict(reply({}, 500), {error: 'revision_conflict'}), false);
});

test('real bridge only unlocks unknown-role review after an accepted current Inventory policy read', async () => {
  const inventory = new InventoryController(), roleActions = new RoleActionsController();
  let peerPolicyReadGeneration = 0, peerPolicyReadOk = true, roleDefBusy = false, bulkBusy = false;
  let held = null, superseded = false, unavailable = false;
  const policy = {revision: 7, quarantine_assignments: [], roles_supported: true, roles: {members: {boat: 2}}};
  const fetch = async path => {
    if (held) return await held.promise;
    const fixtures = {'/api/v1/peer-policy': policy, '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []},
      '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
    return reply(fixtures[path] || {devices: [], total: 0, offset: 0, revision: 1, now: 100}, unavailable ? 503 : 200);
  };
  const document = {hidden: false, getElementById: () => ({hidden: false})};
  const csrfHdr = extra => extra, roleCapabilityMessage = () => '', confirm = () => true;
  const refreshDevices = () => inventory.refresh(), cancelSelectAllMatching = () => inventory.cancelSelection();
  const setBulkBusy = value => {bulkBusy = value; inventory.update({bulkBusy: value});};
  inventory.connect({fetch, beginPolicyRead: () => ++peerPolicyReadGeneration, publish: (state, ticket) => {
    if (superseded) peerPolicyReadGeneration++;
    if (ticket === peerPolicyReadGeneration) peerPolicyReadOk = state.policyOk;
  }});
  const legacy = fs.readFileSync(new URL('../../webroot/app.js', import.meta.url), 'utf8');
  eval(legacy.slice(legacy.indexOf('  roleActions.connect({'), legacy.indexOf("  onInventoryAction('set-role-selected'")));
  await refreshDevices(); roleActions.open(['on-page']); roleActions.update({reviewRequired: true});
  // The request can be invalidated or superseded without throwing. Neither is
  // proof that current policy was reread, even if previous policyOk stayed true.
  held = gate(); let request = roleActions.review(); inventory.invalidate(); held.resolve(reply({})); await request; held = null;
  assert.equal(roleActions.state.reviewRequired, true);
  superseded = true; await roleActions.review(); assert.equal(roleActions.state.reviewRequired, true);
  superseded = false; unavailable = true; await roleActions.review(); assert.equal(roleActions.state.reviewRequired, true);
  unavailable = false; await roleActions.review(); assert.equal(roleActions.state.reviewRequired, false);
});
