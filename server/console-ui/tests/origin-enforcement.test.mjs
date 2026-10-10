// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {OriginEnforcementController} from '../src/origin-enforcement-controller.mjs';
import {checkedOrigin, checkedOriginPreview, originApplicationConfirmed, originEtag, originForm, originModeLabel, originNextAction, originPayload, originStates, originWriteResult} from '../src/origin-enforcement-model.mjs';

export const originFixture = (extra = {}) => ({revision: 0, policy_revision: 7, mode: 'preflight', max_new_ips: 10, max_new_devices: 10,
  approved_ip_count: 0, approved_device_count: 0, new_ip_count: 2, new_device_count: 3, retained_ip_count: 0,
  proposed_ip_count: 2, proposed_device_count: 3, shared_conflict_count: 0, protected_conflict_count: 0,
  state: 'preflight', reason: null, applied_ip_count: null, applied_device_count: null, last_verified_at: null, blockers: [], ...extra});
const token = 'a'.repeat(64);
const preview = (extra = {}) => originFixture({mode: 'enforce', dry_run: true, requires_confirmation: true, confirm_token: token, ...extra});
const saved = (extra = {}) => preview({revision: 1, dry_run: false, requires_confirmation: false, confirm_token: null, state: 'pending', ...extra});
test('operator copy separates saved mode, confirmed effect and next action', () => {
  assert.equal(originModeLabel('preflight'), 'Preview only');
  assert.equal(originModeLabel('enforce'), 'Enforce reviewed blocks');
  assert.equal(originModeLabel('unknown'), 'Unavailable');
  assert.equal(originStates.pending, 'Waiting for confirmation');
  assert.equal(originStates.enforced, 'Blocks confirmed');
  assert.match(originNextAction(originFixture(), true, false), /Enforce reviewed blocks, then Preview change/);
  assert.match(originNextAction(saved(), true, false), /Wait for the transfer service.*choose Refresh status/);
  assert.doesNotMatch(originNextAction(saved(), true, false), /every five seconds|automatically/);
  assert.match(originNextAction(originFixture({state: 'review_required'}), true, false), /changed policy or addresses/);
  assert.match(originNextAction(originFixture({state: 'degraded'}), true, false), /Resolve the reported problem/);
  assert.match(originNextAction(originFixture({state: 'unavailable'}), true, false), /check the distribution service/);
  assert.match(originNextAction(originFixture({state: 'enforced'}), false, false), /^Choose Refresh status/);
  assert.match(originNextAction(originFixture({state: 'enforced'}), true, true), /review the saved settings before trying/);
});
test('blocking counts are confirmed only with coherent current application proof', () => {
  const proof = originFixture({mode: 'enforce', state: 'enforced', applied_device_count: 3, applied_ip_count: 2, last_verified_at: 100});
  assert.equal(originApplicationConfirmed(proof), true);
  assert.equal(originApplicationConfirmed(originFixture()), false);
  assert.equal(originApplicationConfirmed(null), false);
  for (const patch of [{state: 'pending'}, {state: 'review_required'}, {state: 'degraded'}, {state: 'unavailable'},
    {state: 'preflight'}, {mode: 'preflight'}, {last_verified_at: null}, {last_verified_at: 0},
    {last_verified_at: Infinity}, {applied_device_count: null}, {applied_ip_count: null},
    {applied_ip_count: '2'}, {reason: 'session_changed'}, {blockers: ['shared_address']}]) {
    assert.equal(originApplicationConfirmed({...proof, ...patch}), false, JSON.stringify(patch));
  }
  assert.equal(originApplicationConfirmed({...proof, mode: 'preflight', state: 'preflight', applied_device_count: 0, applied_ip_count: 0}), true);
});
const reply = (body, status = 200, etag = originEtag(body?.revision)) => ({status, ok: status >= 200 && status < 300,
  headers: {get: key => key === 'ETag' ? etag : null}, json: async () => body});
const gate = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
async function fixture() {
  const c = new OriginEnforcementController(), writes = [], replies = [], reads = [];
  const env = {visible: true, revision: 7, warning: '', lock: false, value: originFixture(), readReply: null, accept: true, confirmations: []};
  c.connect({isVisible: () => env.visible, policyRevision: () => env.revision, warning: () => env.warning,
    confirm(message) {env.confirmations.push(message); return env.accept;},
    headers: headers => ({...headers, 'X-CSRF-Token': 'fixture-csrf'}),
    claimBulk() {if (env.lock) return false; env.lock = true; c.prerequisites({bulkBusy: true, rowBusy: new Set()}); return true;},
    releaseBulk() {env.lock = false; c.prerequisites({bulkBusy: false, rowBusy: new Set()});},
    async fetch(path, options = {}) {
      if (!options.method) {reads.push(path); return env.readReply || reply(env.value);}
      writes.push({path, ...options, body: JSON.parse(options.body)});
      const next = replies.shift(); if (next instanceof Error) throw next; return next;
    }});
  c.policy(env.revision); await c.refresh(); c.field('mode', 'enforce');
  return {c, env, writes, replies, reads, hide() {env.visible = false; c.hide();}, async preview(body = preview()) {replies.push(reply(body)); await c.save();}};
}

test('origin preview and commit preserve exact reviewed body, control CAS, policy revision, token and CSRF', async () => {
  const f = await fixture(); await f.preview(); assert.equal(f.env.lock, true);
  f.env.value = saved(); f.replies.push(reply(saved())); await f.c.save();
  assert.equal(f.writes.length, 2);
  assert.deepEqual(f.writes[0].body, {mode: 'enforce', if_policy_revision: 7, max_new_ips: 10, max_new_devices: 10, dry_run: true});
  assert.deepEqual(f.writes[1].body, {...f.writes[0].body, dry_run: false, confirm_token: token});
  for (const write of f.writes) {assert.equal(write.method, 'PUT'); assert.equal(write.path, '/api/v1/peer-policy/origin-enforcement');
    assert.equal(write.headers['If-Match'], '"origin-enforcement-0"'); assert.equal(write.headers['X-CSRF-Token'], 'fixture-csrf');}
  assert.match(f.c.state.message, /Waiting.*confirm/); assert.equal(f.c.state.value.state, 'pending'); assert.equal(f.env.lock, false);
});
test('disabling uses the same reviewed confirmation protocol, not a direct bypass', async () => {
  const f = await fixture(); f.c.field('mode', 'preflight'); await f.preview(preview({mode: 'preflight'}));
  f.replies.push(reply(saved({mode: 'preflight'}))); await f.c.save();
  assert.deepEqual(f.writes.map(w => w.body.mode), ['preflight', 'preflight']); assert.equal(f.writes[1].body.confirm_token, token);
});
for (const action of ['field', 'hide', 'cancel', 'policy']) test(`${action} invalidates a pending preview and releases only after its response`, async () => {
  const f = await fixture(), pending = gate(); f.replies.push(pending.promise); const request = f.c.save(); assert.equal(f.env.lock, true);
  if (action === 'field') f.c.field('max_new_ips', '2');
  else if (action === 'hide') f.hide();
  else if (action === 'policy') {f.env.revision = 8; f.c.policy(8);}
  else f.c.cancel();
  assert.equal(f.env.lock, true); pending.resolve(reply(preview())); await request;
  assert.equal(f.c.state.preview, null); assert.equal(f.env.lock, false); assert.equal(f.writes.length, 1);
});
for (const action of ['field', 'hide', 'cancel', 'policy']) test(`${action} invalidates an already received approval`, async () => {
  const f = await fixture(); await f.preview();
  if (action === 'field') f.c.field('max_new_devices', '12');
  else if (action === 'hide') f.hide();
  else if (action === 'policy') {f.env.revision = 8; f.c.policy(8);}
  else f.c.cancel();
  assert.equal(f.c.state.preview, null); assert.equal(f.env.lock, false);
});
for (const mode of ['empty', 'lost', 'server', 'wrong-mode', 'wrong-revision', 'weak-etag', 'claimed-enforced', 'preview']) {
  test(`unknown ${mode} commit is never replayed or called applied; only explicit good review clears the gate`, async () => {
    const f = await fixture(); await f.preview();
    f.replies.push(mode === 'lost' ? Error('network') : mode === 'empty' ? reply({}) : mode === 'server' ? reply({}, 503)
      : mode === 'wrong-mode' ? reply(saved({mode: 'preflight'})) : mode === 'wrong-revision' ? reply(saved({revision: 3}))
        : mode === 'weak-etag' ? reply(saved(), 200, 'W/"origin-enforcement-1"')
          : mode === 'claimed-enforced' ? reply(saved({state: 'enforced', applied_ip_count: 2, applied_device_count: 3, last_verified_at: 100})) : reply(preview()));
    await f.c.save(); assert.equal(f.c.state.reviewRequired, true); assert.match(f.c.state.message, /may have been saved/);
    await f.c.save(); assert.equal(f.writes.length, 2); await f.c.refresh(); assert.equal(f.c.state.reviewRequired, true);
    f.env.readReply = reply({}, 503); await f.c.refresh(true); assert.equal(f.c.state.reviewRequired, true);
    f.env.readReply = null; await f.c.refresh(true); assert.equal(f.c.state.reviewRequired, false);
  });
}
test('hidden pending commit keeps its mutation lease, ignores field edits and records uncertainty without a hidden read', async () => {
  const f = await fixture(); await f.preview(); const pending = gate(); f.replies.push(pending.promise); const request = f.c.save();
  f.c.field('mode', 'preflight'); assert.equal(f.c.state.form.mode, 'enforce'); f.hide(); const reads = f.reads.length;
  assert.equal(f.env.lock, true); pending.resolve(reply({})); await request;
  assert.equal(f.c.state.reviewRequired, true); assert.equal(f.c.state.preview, null); assert.equal(f.env.lock, false); assert.equal(f.reads.length, reads);
});
for (const status of [401, 403, 409, 412, 422, 428]) test(`HTTP ${status} refuses without retry and invalidates the token`, async () => {
  const f = await fixture(); await f.preview(); f.replies.push(reply({code: 'refused'}, status)); await f.c.save();
  assert.equal(f.c.state.preview, null); assert.equal(f.writes.length, 2); assert.equal(f.c.state.reviewRequired, false);
});
test('blocked previews show checks but cannot commit, and release the mutation lease', async () => {
  const f = await fixture(); await f.preview(preview({blockers: ['shared_address'], confirm_token: null}));
  assert.deepEqual(f.c.state.preview.body.blockers, ['shared_address']); assert.equal(f.env.lock, false);
  await f.c.save(); assert.equal(f.writes.length, 1);
});
test('competing policy/device mutations and unsupported capability prevent even previews', async () => {
  const f = await fixture(); f.env.warning = 'Unsupported server'; await f.c.save(); assert.equal(f.writes.length, 0);
  f.env.warning = ''; f.env.lock = true; await f.c.save(); assert.equal(f.writes.length, 0); assert.equal(f.env.lock, true);
  f.env.lock = false; f.c.prerequisites({bulkBusy: false, rowBusy: new Set(['device'])}); await f.c.save(); assert.equal(f.writes.length, 0);
});
test('latest-only status and policy mismatch cannot enable stale controls', async () => {
  const f = await fixture(), slow = gate(); f.env.readReply = slow.promise; const pending = f.c.refresh();
  f.env.readReply = reply(originFixture({revision: 2})); await f.c.refresh(); slow.resolve(reply(originFixture({revision: 1}))); await pending;
  assert.equal(f.c.state.value.revision, 2);
  f.env.readReply = reply(originFixture({policy_revision: 8})); await f.c.refresh(true); assert.equal(f.c.state.ready, false);
  f.env.readReply = slow.promise; f.hide(); await f.c.refresh(); assert.equal(f.c.state.ready, false);
});
test('status readback preserves edited limits but confirmed review reloads current values', async () => {
  const f = await fixture(); f.c.field('max_new_devices', '4'); await f.c.refresh(); assert.equal(f.c.state.form.max_new_devices, '4');
  await f.c.review(); assert.equal(f.c.state.form.max_new_devices, '10'); assert.equal(f.c.state.form.mode, 'preflight');
  assert.match(f.env.confirmations[0], /Unsaved changes and the current preview will be discarded/);
});
test('canceling draft discard keeps values, preview, lock and uncertainty without a read', async () => {
  const f = await fixture(); f.c.field('max_new_devices', '4'); await f.preview(preview({max_new_devices: 4}));
  f.c.update({reviewRequired: true}); const before = f.c.state, reads = f.reads.length;
  f.env.accept = false; assert.equal(await f.c.review(), false);
  assert.equal(f.c.state, before); assert.equal(f.reads.length, reads); assert.equal(f.env.lock, true);
  assert.equal(f.writes.length, 1);
});
test('tab pause preserves the distribution draft and reviewed preview, route departure still cancels', async () => {
  const f = await fixture(); await f.preview();
  const {form, preview: approved} = f.c.state, reads = f.reads.length;
  f.c.pause(); assert.equal(f.c.state.form, form); assert.equal(f.c.state.preview, approved);
  assert.equal(f.reads.length, reads); assert.equal(f.env.lock, true);
  f.hide(); assert.equal(f.c.state.preview, null); assert.equal(f.env.lock, false);
});
test('distribution read started before tab hide cannot replace the snapshot after returning', async () => {
  const f = await fixture(), pending = gate(), previous = f.c.state.value;
  f.c.field('max_new_devices', '4'); f.env.readReply = pending.promise;
  const action = f.c.refresh(); f.env.visible = false; f.c.pause(); f.env.visible = true;
  pending.resolve(reply(originFixture({revision: 2}))); await action;
  assert.equal(f.c.state.value, previous); assert.equal(f.c.state.form.max_new_devices, '4');
  assert.equal(f.c.state.loading, false);
});
test('distribution preview started before tab hide cannot be adopted after returning', async () => {
  const f = await fixture(), pending = gate(); f.replies.push(pending.promise); const action = f.c.save();
  f.env.visible = false; f.c.pause(); f.env.visible = true;
  pending.resolve(reply(preview())); await action;
  assert.equal(f.c.state.preview, null); assert.equal(f.env.lock, false); assert.equal(f.writes.length, 1);
  assert.match(f.c.state.message, /Preview interrupted/);
});
for (const result of ['saved', 'unknown']) test('tab hide/return retains committed distribution result ' + result, async () => {
  const f = await fixture(), pending = gate(); await f.preview();
  f.replies.push(pending.promise); const action = f.c.save();
  f.env.visible = false; f.c.pause(); f.env.visible = true;
  f.env.value = saved(); pending.resolve(reply(result === 'saved' ? saved() : {})); await action;
  assert.equal(f.c.state.reviewRequired, result === 'unknown'); assert.equal(f.writes.length, 2);
  assert.match(f.c.state.message, result === 'saved' ? /Review saved/ : /may have been saved/);
});
test('clean explicit review needs no discard prompt and still refuses a failed read', async () => {
  const f = await fixture(); f.c.update({dirty: false, reviewRequired: true});
  f.env.readReply = reply({}, 503); await f.c.review();
  assert.equal(f.env.confirmations.length, 0); assert.equal(f.c.state.ready, false);
  assert.equal(f.c.state.reviewRequired, true);
});
test('status rejects malformed counts, revisions, modes, ETags, timestamps and unverified healthy claims', () => {
  const valid = originFixture(); assert.deepEqual(checkedOrigin(valid, originEtag(0)), valid);
  for (const patch of [{revision: -1}, {policy_revision: 1e20}, {max_new_ips: true}, {max_new_devices: 1001},
    {state: 'success'}, {mode: 'automatic'}, {new_ip_count: -1}, {applied_ip_count: '2'}, {approved_ip_count: null},
    {blockers: ['invented']}, {reason: 'invented'}, {last_verified_at: Infinity}, {state: 'enforced'},
    {state: ['enforced']}, {reason: ['shared_address']}, {blockers: [['shared_address']]}]) {
    const body = {...valid, ...patch}; assert.throws(() => checkedOrigin(body, originEtag(body.revision)), JSON.stringify(patch));
  }
  for (const etag of [null, '*', 'W/"origin-enforcement-0"', '"iris-peer-policy-7"']) assert.throws(() => checkedOrigin(valid, etag));
  const enforced = originFixture({mode: 'enforce', state: 'enforced', applied_ip_count: 2, applied_device_count: 3, last_verified_at: 100});
  assert.equal(checkedOrigin(enforced, originEtag(0)).state, 'enforced');
});
test('preview must echo the exact request, explicit token and all proposal counts', () => {
  const request = originPayload({...originForm(), mode: 'enforce'}, 7);
  assert.equal(checkedOriginPreview(preview(), originEtag(0), request, 0).confirm_token, token);
  for (const patch of [{dry_run: false}, {requires_confirmation: false}, {confirm_token: null}, {confirm_token: 'token'},
    {mode: 'preflight'}, {max_new_ips: 11}, {policy_revision: 8}, {revision: 1}, {new_device_count: null},
    {confirm_token: [token]}]) {
    const body = preview(patch); assert.throws(() => checkedOriginPreview(body, originEtag(body.revision), request, 0));
  }
  assert.equal(originWriteResult(reply(saved()), saved(), request, 0), 'saved');
});
test('review limits remain bounded, integer and exact', () => {
  for (const raw of ['', '-1', '1.5', '1001', '1e2', ' 10', '01', true]) assert.throws(() => originPayload({...originForm(), max_new_ips: raw}, 7));
  for (const raw of ['0', '10', '1000']) assert.equal(originPayload({...originForm(), max_new_devices: raw}, 7).max_new_devices, Number(raw));
  assert.equal(originPayload(originForm(), 0).if_policy_revision, 0);
  assert.throws(() => originPayload(originForm(), null));
});
