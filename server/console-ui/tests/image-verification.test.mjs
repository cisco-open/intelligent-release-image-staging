// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {ImageVerificationController} from '../src/image-verification-controller.mjs';
import {AssignmentsController} from '../src/assignments-controller.mjs';
import {verificationSettings, verificationPaths, OFFLINE_FEED_LIMIT, checkedVerificationResult, scheduleRequest,
  validOfflineFile, lastRunSummary} from '../src/image-verification-model.mjs';

const settings = () => ({mode: 'off', hour_utc: 0, last_run: {at: null, source: null, outcome: null, matched: null, mismatched: null, not_in_feed: null}});
const counts = {matched: 3, mismatched: 1, not_in_feed: 2};
const success = () => ({outcome: 'ok', ...counts});
const failed = () => ({outcome: 'fail', detail: 'signature rejected', matched: null, mismatched: null, not_in_feed: null});
const last = () => ({at: 2000000000, source: 'manual', ...success()});
const reply = (body, status = 200) => ({status, ok: status >= 200 && status < 300, json: async () => body});
const gate = () => {let resolve; const promise = new Promise(yes => {resolve = yes;}); return {promise, resolve};};
const tick = () => new Promise(resolve => setImmediate(resolve));
const file = (size = 4, name = 'feed.tar') => ({name, size});
async function fixture() {
  const c = new ImageVerificationController(), calls = [], replies = [], reads = [], uploads = [], annotations = [], prompts = [];
  let visible = true, confirm = true, catalog = 0;
  const cfg = settings();
  c.connect({visible: () => visible, headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), formatDate: value => String(value),
    annotation: value => annotations.push(value), catalogChanged: async () => {catalog++;},
    confirm: text => {prompts.push(text); return confirm;},
    fetch: async (url, options = {}) => {
      calls.push({url, options}); if (options.method) return await (replies.shift() || reply(success()));
      return await (reads.shift() || reply(structuredClone(cfg)));
    }, xhr: () => {
      const xhr = {headers: {}, upload: {}, open(method, path) {this.method = method; this.path = path;},
        setRequestHeader(name, value) {this.headers[name] = value;}, send(body) {this.body = body;},
        finish(body, status = 200) {this.status = status; this.responseText = typeof body === 'string' ? body : JSON.stringify(body); this.onload();}};
      uploads.push(xhr); return xhr;
    }});
  c.select('settings-pane-bulkhash'); await c.refresh();
  return {c, cfg, calls, replies, reads, uploads, annotations, prompts, writes: () => calls.filter(row => row.options.method),
    catalog: () => catalog, hide() {visible = false; c.hide();}, async show() {visible = true; await c.refresh();}, cancel() {confirm = false;}};
}

test('settings validates native empty/success/failure records and strips unknown fields', () => {
  assert.deepEqual(verificationSettings({...settings(), injected: 'private'}), settings());
  const value = settings(); value.last_run = last(); assert.deepEqual(verificationSettings(value), value);
  value.last_run = {...last(), matched: null, mismatched: null, not_in_feed: null, outcome: 'fail: signature rejected'}; assert.deepEqual(verificationSettings(value), value);
  for (const mutation of [value => {value.mode = 'sometimes';}, value => {value.hour_utc = '0';}, value => {value.last_run = null;},
    value => {value.last_run.outcome = 'future-state';}, value => {value.last_run.at = -1;}, value => {value.last_run.source = 'unknown';},
    value => {value.last_run.matched = true;}, value => {value.last_run.not_in_feed = -1;}, value => {value.last_run.at = Infinity;}]) {
    const invalid = settings(); invalid.last_run = last(); mutation(invalid); assert.equal(verificationSettings(invalid), null);
  }
  const invalid = settings(); invalid.last_run.matched = 0; assert.equal(verificationSettings(invalid), null);
});
test('run status never labels an unrecognized outcome successful and epoch zero is not never-run', () => {
  assert.match(lastRunSummary(settings().last_run, String), /Never run/);
  assert.match(lastRunSummary({...last(), at: 0}, String), /^0 · manual · 3 matched/);
  assert.match(lastRunSummary({...last(), outcome: 'fail: bad signature'}, String), /Failed: bad signature/);
});
test('schedule payload sends only validated native mode and whole UTC hour', () => {
  assert.deepEqual(scheduleRequest('weekly', '23'), {mode: 'weekly', hour_utc: 23});
  for (const value of ['01', '1.5', '', '24', '-1', '1x', true, NaN]) assert.throws(() => scheduleRequest('daily', value));
  assert.throws(() => scheduleRequest('hourly', '0'));
});
test('schedule success requires exact persisted mode/hour and complete response', () => {
  const payload = {mode: 'daily', hour_utc: 8}, body = {...settings(), ...payload};
  assert.equal(checkedVerificationResult('schedule', reply(body), body, payload), 'saved');
  for (const malformed of [{}, settings(), {...body, hour_utc: 7}, {...body, last_run: null}]) {
    assert.equal(checkedVerificationResult('schedule', reply(malformed), malformed, payload), 'unknown');
  }
  assert.equal(checkedVerificationResult('schedule', reply(body, 202), body, payload), 'unknown');
});
for (const action of ['refresh', 'offline']) test(action + ' requires exact status/outcome/counts and does not trust a count-only or contradictory response', () => {
  assert.equal(checkedVerificationResult(action, reply(success()), success()), 'complete');
  for (const body of [counts, {...success(), outcome: 'fail'}, {...success(), matched: -1}, {...success(), matched: true}, {...success(), matched: 1.5}]) {
    assert.equal(checkedVerificationResult(action, reply(body), body), 'unknown');
  }
  assert.equal(checkedVerificationResult(action, reply(success(), 202), success()), 'unknown');
  assert.equal(checkedVerificationResult(action, reply({outcome: 'already_running'}, 409), {outcome: 'already_running'}), 'running');
  assert.equal(checkedVerificationResult(action, reply({}, 409), {}), 'unknown');
  assert.equal(checkedVerificationResult(action, reply(failed(), 502), failed()), 'failed');
  const problem = {outcome: 'fail', detail: 'signature rejected', status: 502, code: 'upstream-operation-failed'};
  assert.equal(checkedVerificationResult(action, reply(problem, 502), problem), 'failed', 'Problem Details omits null count extensions');
  assert.equal(checkedVerificationResult(action, reply({error: 'proxy'}, 502), {error: 'proxy'}), 'unknown');
});
test('offline archive size is checked before dispatch, inclusive of 256 MiB', () => {
  assert.equal(validOfflineFile(file(OFFLINE_FEED_LIMIT)), true);
  for (const value of [file(0), file(-1), file(OFFLINE_FEED_LIMIT + 1), file(1.5), file(4, 'feed.zip')]) assert.equal(validOfflineFile(value), false);
});
test('controller saves checked schedule and emits CSRF with only native payload', async () => {
  const f = await fixture(); f.c.field('mode', 'weekly'); f.c.field('hour', '7');
  Object.assign(f.cfg, {mode: 'weekly', hour_utc: 7}); f.replies.push(reply(f.cfg)); await f.c.perform('schedule');
  assert.deepEqual(JSON.parse(f.writes()[0].options.body), {mode: 'weekly', hour_utc: 7});
  assert.equal(f.writes()[0].options.headers['X-CSRF-Token'], 'fixture'); assert.equal(f.c.state.messages.schedule.kind, 'success');
  assert.equal(f.c.state.dirty, false); assert.equal(f.catalog(), 0);
  f.c.field('hour', '8'); assert.equal(f.c.state.messages.schedule.text, 'Unsaved schedule changes.');
});
test('initial and failed reads disable writes without changing the dirty schedule', async () => {
  const f = await fixture(); f.c.field('mode', 'daily'); f.c.field('hour', '9');
  f.reads.push(reply({}, 503)); await f.c.refresh(); await f.c.perform('refresh');
  assert.equal(f.writes().length, 0); assert.equal(f.c.state.valid, false); assert.equal(f.c.state.hour, '9');
  assert.equal(f.annotations.at(-1), null);
  await f.c.refresh(); assert.equal(f.c.state.mode, 'daily'); assert.equal(f.c.state.hour, '9');
});
test('a stale or hidden GET cannot restore write permission or overwrite newer status', async () => {
  const f = await fixture(), pending = gate(); f.reads.push({...reply({}), json: () => pending.promise});
  const old = f.c.refresh(); await tick(); Object.assign(f.cfg, {mode: 'weekly', hour_utc: 3}); await f.c.refresh();
  pending.resolve(settings()); await old; assert.equal(f.c.state.mode, 'weekly');
  const hidden = gate(); f.reads.push(hidden.promise); const read = f.c.refresh(); f.hide(); hidden.resolve(reply(settings())); await read;
  assert.equal(f.c.state.valid, false);
});
test('one lock covers save, refresh and upload, including navigation while POST is pending', async () => {
  const f = await fixture(), pending = gate(); f.replies.push(pending.promise); const write = f.c.perform('refresh'); await tick();
  await f.c.perform('schedule'); await f.c.perform('offline', file()); f.hide(); await f.show(); await f.c.perform('refresh');
  assert.equal(f.writes().length, 1); assert.equal(f.uploads.length, 0); assert.equal(f.c.state.busy, 'refresh');
  pending.resolve(reply(success())); await write; assert.equal(f.c.state.busy, null); assert.equal(f.catalog(), 1);
});
for (const action of ['schedule', 'refresh']) test(action + ' unknown outcome blocks replay until explicit latest status review', async () => {
  const f = await fixture(); f.c.field('mode', 'daily'); f.replies.push(reply({})); await f.c.perform(action);
  assert.equal(f.c.state.unknown, true); await f.c.refresh(); await f.c.perform(action); assert.equal(f.writes().length, 1);
  await f.c.review(); assert.equal(f.c.state.unknown, false); assert.equal(f.c.state.mode, 'off');
  assert.match(f.c.state.messages.review.text, /does not prove/); assert.equal(f.c.state.messages[action], undefined);
  assert.equal(f.writes().length, 1);
});
test('network failure and HTML proxy responses remain unknown, not refused', async () => {
  for (const response of [Promise.reject(Error('network')), {...reply({}), json: async () => {throw Error('HTML');}}]) {
    const f = await fixture(); f.replies.push(response); await f.c.perform('refresh'); assert.equal(f.c.state.unknown, true);
    assert.match(f.c.state.messages.refresh.text, /may have started/); assert.equal(f.catalog(), 1);
  }
});
test('known single-flight conflict does not auto-retry and requires current status review', async () => {
  const f = await fixture(); f.replies.push(reply({outcome: 'already_running'}, 409)); await f.c.perform('refresh');
  assert.equal(f.c.state.unknown, true); assert.match(f.c.state.messages.refresh.text, /already in progress/);
  await f.c.perform('refresh'); assert.equal(f.writes().length, 1);
});
test('verified failure is shown without claiming completion and refreshes quarantine consumers', async () => {
  const f = await fixture(); f.replies.push(reply(failed(), 502)); await f.c.perform('refresh');
  assert.equal(f.c.state.unknown, false); assert.equal(f.c.state.messages.refresh.text, 'Check failed: signature rejected'); assert.equal(f.catalog(), 1);
});
for (const status of [400, 401, 403, 404, 413]) test('explicit HTTP ' + status + ' refusal does not echo arbitrary error material', async () => {
  const f = await fixture(); f.replies.push(reply({error: 'secret-ish raw proxy text'}, status)); await f.c.perform('refresh');
  assert.equal(f.c.state.unknown, false); assert.doesNotMatch(f.c.state.messages.refresh.text, /secret-ish/); assert.equal(f.c.state.messages.refresh.kind, 'error');
});
test('review cancellation or failed GET keeps unresolved outcome and never posts', async () => {
  const f = await fixture(); f.replies.push(reply({})); await f.c.perform('refresh');
  f.reads.push(reply({}, 503)); await f.c.review(); assert.equal(f.c.state.unknown, true);
  f.cancel(); await f.c.review(); assert.equal(f.c.state.unknown, true); assert.equal(f.writes().length, 1);
});
for (const event of ['new-read', 'edit', 'hide']) test('status review cannot clear unknown after ' + event, async () => {
  const f = await fixture(); f.replies.push(reply({})); await f.c.perform('refresh');
  const pending = gate(); f.reads.push(pending.promise); const review = f.c.review();
  if (event === 'new-read') await f.c.refresh(); else if (event === 'edit') f.c.field('hour', '4'); else f.hide();
  pending.resolve(reply(settings())); await review; assert.equal(f.c.state.unknown, true);
});
test('offline upload is raw bytes with CSRF; 100 percent is still busy until server outcome', async () => {
  const f = await fixture(), archive = file(); const write = f.c.perform('offline', archive), xhr = f.uploads[0];
  assert.equal(xhr.method, 'POST'); assert.equal(xhr.path, verificationPaths.offline); assert.equal(xhr.body, archive);
  assert.deepEqual(xhr.headers, {'X-CSRF-Token': 'fixture'});
  xhr.upload.onprogress({lengthComputable: true, loaded: 4, total: 4}); assert.equal(f.c.state.progress, 100);
  assert.equal(f.c.state.busy, 'offline'); assert.equal(f.c.state.messages.offline.kind, 'info');
  await f.c.perform('refresh'); assert.equal(f.writes().length, 0);
  xhr.finish(success()); await write; assert.equal(f.c.state.messages.offline.kind, 'success'); assert.equal(f.catalog(), 1);
});
test('oversized offline archive and invalid draft never allocate a transport', async () => {
  const f = await fixture(); await f.c.perform('offline', file(OFFLINE_FEED_LIMIT + 1)); assert.equal(f.uploads.length, 0);
  f.c.field('hour', '25'); await f.c.perform('schedule'); assert.equal(f.writes().length, 0);
});
for (const event of ['onerror', 'onabort', 'ontimeout', 'bad-json', 'bad-response']) test('offline ' + event + ' requires review and never re-sends the archive', async () => {
  const f = await fixture(), write = f.c.perform('offline', file()), xhr = f.uploads[0];
  if (event === 'bad-json') xhr.finish('<html>bad</html>'); else if (event === 'bad-response') xhr.finish(counts); else xhr[event]();
  await write; assert.equal(f.c.state.unknown, true); await f.c.perform('offline', file()); assert.equal(f.uploads.length, 1);
  await f.c.review(); assert.equal(f.uploads.length, 1); assert.equal(f.c.state.unknown, false);
});
test('offline progress is bounded and hiding does not cancel or unlock the request', async () => {
  const f = await fixture(), write = f.c.perform('offline', file()), xhr = f.uploads[0];
  xhr.upload.onprogress({lengthComputable: true, loaded: 10, total: 4}); assert.equal(f.c.state.progress, 100);
  xhr.upload.onprogress({lengthComputable: true, loaded: -1, total: 4}); assert.equal(f.c.state.progress, 0);
  xhr.upload.onprogress({lengthComputable: true, loaded: NaN, total: 4}); assert.equal(f.c.state.progress, 0);
  f.hide(); assert.equal(f.c.state.busy, 'offline'); xhr.finish(success()); await write;
  assert.equal(f.c.state.valid, false); assert.equal(f.catalog(), 1);
});
test('moving the shared workflow preserves draft and unknown state with only one controller', async () => {
  const f = await fixture(); f.c.field('mode', 'weekly'); f.c.field('hour', '11'); f.replies.push(reply({})); await f.c.perform('refresh');
  f.c.select('wz-iv-mount'); await f.c.refresh(); assert.equal(f.c.state.mode, 'weekly'); assert.equal(f.c.state.hour, '11');
  assert.equal(f.c.state.unknown, true); await f.c.perform('refresh'); assert.equal(f.writes().length, 1);
});
test('post-check invalidation retires pending assignment catalog reads until a fresh quarantine read', () => {
  const assignments = new AssignmentsController(), before = {images: [{id: 'image', quarantined: false}]};
  assignments.acceptImages({ok: true, body: before}, assignments.beginImageRead());
  assert.equal(assignments.state.imagesOk, true); const pending = assignments.beginImageRead();
  assignments.acceptImages({ok: false}, assignments.beginImageRead());
  assert.equal(assignments.state.imagesOk, false);
  assignments.acceptImages({ok: true, body: before}, pending); assert.equal(assignments.state.imagesOk, false);
  assignments.acceptImages({ok: true, body: {images: [{id: 'image', quarantined: true}]}}, assignments.beginImageRead());
  assert.equal(assignments.state.imagesOk, true); assert.equal(assignments.state.images[0].quarantined, true);
});
