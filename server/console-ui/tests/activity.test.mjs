// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {ActivityController} from '../src/activity-controller.mjs';
import {actionLabel, activityRows, appendLines, MAX_CHARS, MAX_LINES, MAX_LOGS, summary, validListing} from '../src/activity-model.mjs';

const pending = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; };
const response = (body, status = 200) => ({ok: status === 200, status, json: async () => body});
const job = (id, state = 'running', action = 'onboard') => ({id, device_id: 'device-' + id, state, action, started_at: 900, queued_at: 850});
const turn = () => new Promise(resolve => setImmediate(resolve));

async function fixture(t, jobs = []) {
  const timers = new Map(), streams = [], calls = [], writes = [], confirmations = [], outcomes = [], counts = [];
  let timerId = 0, deviceRefreshes = 0;
  const controller = new ActivityController({setTimer: (fn, delay) => { assert.equal(delay, 2000); timers.set(++timerId, fn); return timerId; },
    clearTimer: id => timers.delete(id), queuePaint: queueMicrotask});
  const listing = {jobs, now: 1000};
  const services = {
    fetch: async (...args) => { calls.push(args); return response(listing); },
    post: async (url, payload) => {
      writes.push([url, payload]);
      return response(url.endsWith('/cancel-queued') ? {cancelled: payload.job_ids.length}
        : url.endsWith('/abort') ? {aborted: true} : {job_id: url.split('/').at(-2)});
    },
    confirm: message => { confirmations.push(message); return true; },
    eventSource: url => {
      const stream = {url, listeners: {}, closed: false, addEventListener(name, listener) { this.listeners[name] = listener; },
        close() { this.closed = true; }};
      streams.push(stream); return stream;
    },
    outcome: (...args) => outcomes.push(args), reportCount: (...args) => counts.push(args), refreshDevices: () => deviceRefreshes++,
  };
  controller.connect(services); t.after(() => controller.dispose()); await controller.setVisible(true);
  return {controller, services, listing, timers, streams, calls, writes, confirmations, outcomes, counts,
    refreshes: () => deviceRefreshes,
    tick: async () => { const [id, fn] = timers.entries().next().value; timers.delete(id); fn(); await turn(); }};
}

test('job projection uses server time and global queue positions, including scoped batches', () => {
  const state = {now: 1000, jobs: [job('other', 'queued'), job('a', 'queued'), job('b'), {...job('c'), finished_at: 920}], scope: ['a', 'b', 'c']};
  assert.deepEqual(activityRows(state).map(row => row.duration), ['#2 in line', '1m40s', '20s']);
  assert.equal(activityRows({...state, now: null})[1].duration, '', 'unknown server time is never replaced by browser time');
  assert.equal(summary([], true), 'No confirmed jobs in this batch.');
  assert.equal(summary([{state: 'constructor'}, {state: null}]), '1 constructor · 1 unknown');
  assert.equal(actionLabel('constructor'), 'Device action'); assert.equal(actionLabel('iox-recover'), 'Recover');
  assert.equal(validListing({jobs: [job('a')]}), true);
  for (const data of [null, {}, {jobs: [null]}, {jobs: [{}]}, {jobs: [job('a'), job('a')]},
    {jobs: [{...job('a'), last_line: {}}]}, {jobs: [], now: 'bad'}]) assert.equal(validListing(data), false);
});

test('buffers bound both line count and characters and explicitly record truncation', () => {
  const entry = {lines: []};
  appendLines(entry, Array.from({length: 900}, (_, i) => String(i)).join('\n'));
  assert.equal(entry.lines.length, MAX_LINES); assert.equal(entry.lines[0], '400'); assert.equal(entry.truncated, true);
  appendLines(entry, 'a'.repeat(MAX_CHARS * 2));
  assert.ok(entry.lines.join('\n').length <= MAX_CHARS);
  appendLines(entry, 'end'); assert.equal(entry.lines.at(-1), 'end');
});

test('one background timer tracks active jobs; closed drawer never cancels them, hidden view stops reads', async t => {
  const f = await fixture(t, [job('a')]); const {controller, timers, calls, writes} = f;
  assert.equal(timers.size, 1); await controller.open(); assert.equal(timers.size, 1);
  await f.tick(); assert.equal(calls.at(-1)[2], true);
  controller.close(); assert.equal(timers.size, 1); assert.equal(writes.length, 0);
  await controller.setVisible(false); assert.equal(timers.size, 0);
  const n = calls.length; await controller.refresh(); assert.equal(calls.length, n);
  await controller.setVisible(true); assert.equal(calls.length, n + 1);
  f.listing.jobs = [job('a', 'done')]; await f.tick(); await turn();
  assert.equal(timers.size, 0); assert.equal(f.refreshes(), 1);
});

for (const delay of ['headers', 'body']) test(`old Activity ${delay} cannot replace a reopened view or a new batch`, async t => {
  const f = await fixture(t), held = pending(), original = f.services.fetch;
  f.services.fetch = async () => delay === 'headers' ? held.promise : {ok: true, json: () => held.promise};
  const old = f.controller.open(); await turn(); f.controller.close();
  f.services.fetch = original; f.listing.jobs = [job('new')]; await f.controller.open();
  const stale = {jobs: [job('old')], now: 1}; held.resolve(delay === 'headers' ? response(stale) : stale); await old;
  assert.equal(f.controller.snapshot().jobs[0].id, 'new');
  assert.equal(f.controller.snapshot().open, true);
});

test('read failure retains evidence, malformed data is explicit and session expiry stops the timer/streams', async t => {
  const {controller, services, timers, streams} = await fixture(t, [job('a')]); await controller.open(); controller.openLog('a');
  for (const data of [{jobs: null}, {jobs: [null]}, {jobs: [job('a')], now: {}}, null]) {
    services.fetch = async () => response(data); await controller.refresh();
    assert.equal(controller.snapshot().jobs[0].id, 'a'); assert.match(controller.snapshot().error, /unavailable/);
    assert.equal(timers.size, 1);
  }
  services.fetch = async () => response({}, 401); await controller.refresh();
  assert.match(controller.snapshot().error, /Session expired/); assert.equal(timers.size, 0);
  assert.ok(streams.every(stream => stream.closed));
});

test('streams have independent output, bounded cache and explicit reconnect; close rejects late callbacks', async t => {
  const jobs = Array.from({length: 8}, (_, i) => job(String(i))), f = await fixture(t, jobs);
  const {controller, streams, writes} = f; await controller.open(); controller.openLog('0');
  const first = streams[0]; first.onmessage({data: 'first job'}); await turn();
  controller.openLog('1'); streams[1].onmessage({data: '<script>second job</script>'}); await turn();
  assert.equal(controller.snapshot().logs[0].text, 'first job');
  assert.equal(controller.snapshot().logs[1].text, '<script>second job</script>');
  controller.openLog('0'); assert.equal(streams.length, 2, 'live cached stream reused');
  first.listeners.end({data: 'idle'}); controller.openLog('0'); const reopened = streams.at(-1);
  reopened.onmessage({data: 'reconnected'}); first.onmessage({data: 'STALE'}); first.listeners.end({data: 'done'}); await turn();
  assert.equal(controller.snapshot().logs.find(entry => entry.id === '0').text, 'reconnected');
  for (let i = 2; i < 8; i++) controller.openLog(String(i));
  assert.equal(controller.snapshot().logs.length, MAX_LOGS);
  assert.ok(first.closed && reopened.closed);
  const last = streams.at(-1); controller.close();
  last.onmessage({data: 'late'}); last.listeners.end({data: 'done'}); last.onerror(); await turn();
  assert.deepEqual(controller.snapshot().logs, []); assert.equal(writes.length, 0);
  assert.ok(streams.every(stream => stream.closed));
});

test('tab suspension preserves the viewer but closes streams until explicit reconnect', async t => {
  const {controller, streams, timers} = await fixture(t, [job('a')]); await controller.open(); controller.openLog('a');
  await controller.setVisible(false);
  assert.equal(controller.snapshot().open, true); assert.equal(streams[0].closed, true); assert.equal(timers.size, 0);
  assert.match(controller.snapshot().logs[0].text, /view was hidden/);
  await controller.setVisible(true); assert.equal(streams.length, 1);
  controller.openLog('a'); assert.equal(streams.length, 2);
});

test('terminal stream outcomes preserve action labels and avoid duplicate completion lines', async t => {
  const {controller, streams, listing} = await fixture(t, [job('a', 'running', 'undeploy')]);
  await controller.open(); controller.openLog('a'); const stream = streams[0];
  stream.onmessage({data: 'Undeploy completed.'}); listing.jobs = [job('a', 'done', 'undeploy')];
  stream.listeners.end({data: 'done'}); await turn();
  assert.equal(controller.snapshot().logs[0].text, 'Undeploy completed.');
  assert.equal(controller.snapshot().logs[0].terminal, true); assert.equal(stream.closed, true);
});

test('queued cancellation is confirmed and explicitly scoped; no unscoped cancel or running abort', async t => {
  const f = await fixture(t, [job('other', 'queued'), job('a', 'queued'), job('b')]); const {controller, services, writes, confirmations} = f;
  await controller.open(); controller.patch({scope: ['a', 'b']});
  services.confirm = () => false; await controller.cancelQueued(); assert.deepEqual(writes, []);
  services.confirm = message => { confirmations.push(message); return true; };
  await controller.cancelQueued();
  assert.deepEqual(writes, [['/api/v1/onboard/cancel-queued', {job_ids: ['a']}]]);
  assert.match(confirmations[0], /Cancel 1 queued job.*Running jobs continue/);
});

test('queued Abort switches to a running abort only after a valid cancelled:0 response', async t => {
  const f = await fixture(t, [job('a / b', 'queued')]); const {controller, services, writes} = f;
  await controller.open(); controller.openLog('a / b');
  services.post = async (url, payload) => { writes.push([url, payload]); return response(url.endsWith('/cancel-queued') ? {cancelled: 0} : {aborted: true}); };
  await controller.abort('a / b');
  assert.deepEqual(writes, [['/api/v1/onboard/cancel-queued', {job_ids: ['a / b']}], ['/api/v1/onboard/jobs/a%20%2F%20b/abort', {}]]);
  assert.match(controller.snapshot().logs[0].text, /abort requested/);
});

test('unknown queued cancellation outcome never falls through to an abort or retries', async t => {
  const {controller, services, writes} = await fixture(t, [job('a', 'queued')]); await controller.open(); controller.openLog('a');
  for (const result of [{}, {cancelled: '0'}, {cancelled: 2}, {error: 'unavailable'}]) {
    writes.length = 0; services.post = async (url, payload) => { writes.push([url, payload]); return response(result); };
    await controller.abort('a'); assert.equal(writes.length, 1);
    assert.match(controller.snapshot().logs[0].text, /outcome is unknown/);
  }
  services.post = async () => { writes.push('lost'); throw new Error('lost response'); };
  writes.length = 0; await controller.abort('a'); assert.equal(writes.length, 1);
});

test('per-job mutation lock survives close/reopen and stale responses cannot append to a new log', async t => {
  const {controller, services, writes} = await fixture(t, [job('a')]); await controller.open(); controller.openLog('a');
  const held = pending(); services.post = (url, payload) => { writes.push([url, payload]); return held.promise; };
  const first = controller.abort('a'); await turn(); controller.close(); await controller.open(); controller.openLog('a');
  await controller.abort('a'); assert.equal(writes.length, 1); assert.deepEqual(controller.snapshot().busyJobs, ['a']);
  held.resolve(response({aborted: true})); await first;
  assert.equal(controller.snapshot().logs[0].text, ''); assert.deepEqual(controller.snapshot().busyJobs, []);
});

test('closing while confirmation is pending sends no cancellation', async t => {
  const {controller, services, writes} = await fixture(t, [job('a', 'queued')]); await controller.open();
  const held = pending(); services.confirm = () => held.promise;
  const action = controller.cancelQueued(); controller.close(); held.resolve(true); await action;
  assert.equal(writes.length, 0);
});

test('batch submits each device once, passes options unchanged and separates rejections from unknown outcomes', async t => {
  const {controller, services, writes, outcomes} = await fixture(t);
  services.post = async (url, payload) => {
    writes.push([url, payload]);
    return url.includes('/accepted/') ? response({job_id: 'accepted-job'})
      : url.includes('/refused/') ? response({error: 'no credential'}, 400) : response({});
  };
  const options = {telemetry: true, telemetry_stream: false, log: true};
  await controller.start('onboard', ['accepted', 'accepted', 'refused', 'unknown'], options);
  assert.equal(writes.length, 3); assert.ok(writes.every(([, body]) => body === options));
  assert.deepEqual(controller.snapshot().scope, ['accepted-job']);
  assert.match(outcomes[0][0], /Started onboard for 1 device.*refused: refused: no credential.*outcome unknown: unknown/);
  assert.equal(outcomes[0][1], true); assert.equal(controller.snapshot().starting, false);
});

test('late read cannot reset an in-flight batch; closing does not cancel accepted submissions', async t => {
  const {controller, services, writes, listing} = await fixture(t, [job('old')]); const heldRead = pending(), heldPost = pending(), original = services.fetch;
  services.fetch = () => heldRead.promise; const oldRead = controller.open();
  services.post = (url, payload) => { writes.push([url, payload]); return heldPost.promise; };
  const starting = controller.start('onboard', ['a'], {log: true}); await turn();
  await controller.start('onboard', ['b'], {}); assert.equal(writes.length, 1);
  controller.close(); await controller.setVisible(false);
  heldRead.resolve(response({jobs: [job('stale')], now: 1})); await oldRead;
  assert.deepEqual(controller.snapshot().scope, []);
  heldPost.resolve(response({job_id: 'new'})); await starting;
  assert.deepEqual(controller.snapshot().scope, ['new']); assert.equal(controller.snapshot().open, false);
  services.fetch = original; listing.jobs = [job('new')]; await controller.setVisible(true);
  assert.equal(activityRows(controller.snapshot())[0].id, 'new');
});

test('undeploy cancellation and confirmation errors release the start guard without sending a write', async t => {
  const {controller, services, writes, confirmations} = await fixture(t);
  services.confirm = message => { confirmations.push(message); return false; };
  await controller.start('undeploy', ['a'], {force: true}); assert.equal(writes.length, 0);
  assert.match(confirmations[0], /skips record and device identity checks.*[\s\S]*Keeps staged images/);
  services.confirm = () => { throw new Error('no confirmation'); };
  await assert.rejects(controller.start('undeploy', ['a'], {}));
  services.confirm = () => true; await controller.start('undeploy', ['a'], {log: true});
  assert.equal(writes.length, 1); assert.equal(controller.snapshot().starting, false);
});
