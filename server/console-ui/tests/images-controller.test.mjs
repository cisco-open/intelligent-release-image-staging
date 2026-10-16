// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {ImagesController} from '../src/images-controller.mjs';
import {imageVerdicts, publishedJobText} from '../src/image-model.mjs';

const response = (data, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => data});
const pending = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };
const settle = () => new Promise(resolve => setImmediate(resolve));

test('injected browser timers are called without the controller as receiver', () => {
  const calls = [];
  const controller = new ImagesController({
    later: function (callback, delay) { assert.equal(this, undefined); calls.push(delay); return 42; },
    cancel: function (timer) { assert.equal(this, undefined); calls.push(timer); },
  });
  controller.schedule(() => {}, 1000);
  controller.dispose();
  assert.deepEqual(calls, [1000, 42]);
});

function fixture(t) {
  const calls = [], timers = new Map(), alerts = [];
  let timer = 0, deviceRefreshes = 0;
  const controller = new ImagesController({later: (callback, delay) => { timers.set(++timer, {callback, delay}); return timer; }, cancel: id => timers.delete(id)});
  const services = {
    headers: () => ({'X-CSRF-Token': 'fixture-only'}), confirm: () => true, alert: text => alerts.push(text),
    refreshDevices: async () => { deviceRefreshes++; },
    fetch: async (url, options = {}) => {
      calls.push([url, options]);
      return response(url.endsWith('/importable') ? {importable: [], skipped: []} : {images: []});
    },
    post: async (url, body) => { calls.push([url, body]); return response({}); },
  };
  controller.connect(services);
  t.after(() => controller.dispose());
  const fire = async delay => {
    for (const [id, entry] of [...timers]) if (entry.delay === delay) { timers.delete(id); entry.callback(); }
    await settle();
  };
  return {controller, services, calls, alerts, timers, fire, deviceRefreshes: () => deviceRefreshes};
}

test('verification never confuses released mismatch, unknown, or deferral with verified', () => {
  for (const [state, quarantined, label, level] of [[undefined, false, 'Not checked', 'inactive'], ['verified', false, 'Verified', 'positive'],
    ['mismatch', true, 'Mismatch — quarantined', 'negative'], ['mismatch', false, 'Mismatch — released', 'negative'],
    ['not_in_feed', false, "Not in Cisco's feed", 'inactive'], ['future-state', false, 'Unknown verification state', 'inactive']]) {
    assert.deepEqual(imageVerdicts({state, deferral: true}, quarantined), [{label, level}, {level: 'warning', label: 'Deferred by Cisco'}]);
  }
});

test('publish text preserves automatic verification results for imports and uploads', () => {
  for (const [verification, expected] of [[undefined, 'Published image-a ✓'], [{outcome: 'failed', detail: 'unavailable'}, 'verification incomplete: unavailable'],
    [{outcome: 'ok', image_state: 'verified'}, 'verified against Cisco Bulk Hash'], [{outcome: 'ok', image_state: 'mismatch'}, 'mismatch — quarantined'],
    [{outcome: 'ok', image_state: 'not_in_feed'}, 'not found in Cisco Bulk Hash'], [{outcome: 'ok'}, 'verdict unavailable']]) {
    assert.ok(publishedJobText({image_id: 'image-a', verification}).includes(expected));
  }
});

test('newer catalog wins even when the old server ignores abort', async t => {
  const {controller, services} = fixture(t), old = pending();
  const signals = [];
  services.fetch = (url, options) => { signals.push(options.signal); return signals.length === 1 ? old.promise : Promise.resolve(response({images: [{id: 'new'}]})); };
  const first = controller.refresh();
  await controller.refresh();
  assert.equal(signals[0].aborted, true);
  old.resolve(response({images: [{id: 'old'}]}));
  await first;
  assert.equal(controller.snapshot().images[0].id, 'new');
});

test('failed or malformed reads retain known catalog and hide failed import inventory', async t => {
  const {controller, services, calls} = fixture(t);
  assert.equal(controller.snapshot().catalogLoaded, false);
  controller.update({images: [{id: 'known'}], importAvailable: true});
  controller.setAttention(true);
  assert.deepEqual(calls, [], 'Filtering is local');
  for (const data of [{images: [null]}, {images: [{id: {unsafe: true}}]}, {images: [{id: 'bad', filename: {}}]}]) {
    services.fetch = async () => response(data);
    await controller.refresh();
    assert.equal(controller.snapshot().images[0].id, 'known');
    assert.match(controller.snapshot().catalogError, /could not be refreshed/);
  }
  services.fetch = async () => response({}, 503);
  await controller.refresh('importable');
  assert.equal(controller.snapshot().importAvailable, false);
  services.fetch = async () => response({images: []});
  await controller.refresh();
  assert.equal(controller.snapshot().catalogError, '');
  assert.equal(controller.snapshot().catalogLoaded, true);
  assert.equal(controller.snapshot().attentionOnly, true);
});

test('delete requires confirmation, preserves CSRF, and shows assignment refusal', async t => {
  const {controller, services, calls, alerts} = fixture(t);
  services.confirm = () => false;
  await controller.remove('a/b');
  assert.deepEqual(calls, []);
  services.confirm = () => true;
  const request = pending();
  services.fetch = (url, options) => { calls.push([url, options]); return request.promise; };
  const deleting = controller.remove('a/b');
  await controller.remove('a/b');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ['/api/v1/images/a%2Fb', {method: 'DELETE', headers: {'X-CSRF-Token': 'fixture-only'}}]);
  request.resolve(response({assigned: ['router-a']}, 409));
  await deleting;
  assert.match(alerts[0], /router-a.*Reassign/);
  assert.deepEqual(controller.snapshot().deleting, []);
});

test('quarantine override requires server refusal and exact operator-entered filename', async t => {
  const {controller, services, calls, deviceRefreshes} = fixture(t);
  controller.update({images: [{id: 'image/a', filename: 'firmware.bin', quarantined: true}]});
  controller.openDetails('image/a');
  assert.equal(controller.snapshot().details.confirmText, '');
  await controller.release(true);
  assert.deepEqual(calls, []);
  services.post = async (url, body) => { calls.push([url, body]); return body.override ? response({}) : response({error: 'quarantine_still_mismatched'}, 409); };
  await controller.release(false);
  assert.equal(controller.snapshot().details.override, true);
  controller.editConfirmation('wrong.bin');
  await controller.release(true);
  assert.equal(calls.length, 1);
  controller.editConfirmation('firmware.bin');
  await controller.release(true);
  assert.deepEqual(calls[1], ['/api/v1/images/image%2Fa/release-quarantine', {override: true, confirm_text: 'firmware.bin'}]);
  assert.equal(controller.snapshot().details, null);
  assert.equal(deviceRefreshes(), 1);
});

test('late release cannot close another image drawer and network failure unlocks controls', async t => {
  const {controller, services, deviceRefreshes} = fixture(t), held = pending();
  controller.update({images: [{id: 'a', quarantined: true}, {id: 'b', quarantined: true}]});
  controller.openDetails('a');
  services.post = () => held.promise;
  const release = controller.release(false);
  assert.equal(controller.snapshot().details.busy, true);
  controller.openDetails('b');
  held.resolve(response({}));
  await release;
  assert.equal(controller.snapshot().details.image.id, 'b');
  assert.equal(deviceRefreshes(), 1);
  services.post = async () => { throw new Error('fixture disconnect'); };
  await controller.release(false);
  assert.equal(controller.snapshot().details.busy, false);
  assert.match(controller.snapshot().details.error, /response unavailable/);
});

test('release API errors stay readable and cannot become invalid React children', async t => {
  const {controller, services} = fixture(t);
  controller.update({images: [{id: 'a', quarantined: true}]});
  controller.openDetails('a');
  for (const body of [null, {error: {detail: 'unexpected shape'}}]) {
    services.post = async () => response(body, 503);
    await controller.release(false);
    assert.equal(controller.snapshot().details.error, 'Release failed (503).');
    assert.equal(controller.snapshot().details.busy, false);
    assert.equal(controller.snapshot().details.override, false);
  }
  services.post = async () => response({error: 'fixture refusal'}, 403);
  await controller.release(false);
  assert.equal(controller.snapshot().details.error, 'fixture refusal');
});

test('parallel uploads track progress and publish verdicts independently, with terminal 404', async t => {
  const {controller, services, fire} = fixture(t);
  services.upload = async (file, progress) => { progress(50); return {job_id: file.name}; };
  services.fetch = async url => url.includes('/jobs/a') ? response({state: 'done', image_id: 'a', verification: {outcome: 'ok', image_state: 'verified'}})
    : url.includes('/jobs/b') ? response({}, 404) : response(url.endsWith('/importable') ? {importable: []} : {images: []});
  await Promise.all([controller.upload({name: 'a.bin', size: 10}), controller.upload({name: 'b.bin', size: 10})]);
  await settle();
  assert.match(controller.snapshot().uploads[0].text, /verified against Cisco Bulk Hash/);
  assert.equal(controller.snapshot().uploads[0].error, false);
  assert.match(controller.snapshot().uploads[1].text, /404/);
  assert.equal(controller.snapshot().uploads[1].error, true);
  await fire(8000);
  assert.deepEqual(controller.snapshot().uploads.map(row => row.name), ['b.bin']);
});

test('oversize upload never calls transport; malformed successful response is not success', async t => {
  const {controller, services} = fixture(t);
  services.upload = async () => { throw new Error('must not upload'); };
  await controller.upload({name: 'large.bin', size: 4 * 1024 ** 3 + 1});
  assert.match(controller.snapshot().uploads[0].text, /not uploaded/);
  services.upload = async () => ({});
  await controller.upload({name: 'small.bin', size: 10});
  assert.match(controller.snapshot().uploads[1].text, /did not identify a job/);
});

test('disk imports preserve exact path and maintain separate jobs without duplicate submissions', async t => {
  const {controller, services, calls, fire} = fixture(t);
  let finished = false;
  services.post = async (url, body) => { calls.push([url, body]); return response({job_id: body.path}); };
  services.fetch = async url => url.includes('/jobs/') ? response(finished ? {state: 'done', image_id: 'imported'} : {state: 'verifying'})
    : response(url.endsWith('/importable') ? {importable: []} : {images: []});
  const first = '/opt/images/one/a.bin', second = '/opt/images/two/a.bin';
  await Promise.all([controller.importFile(first), controller.importFile(first), controller.importFile(second)]);
  await settle();
  assert.deepEqual(calls, [['/api/v1/images/import', {path: first}], ['/api/v1/images/import', {path: second}]]);
  assert.deepEqual(controller.snapshot().importing, [first, second]);
  assert.match(controller.snapshot().status, /checking Cisco Bulk Hash/);
  finished = true;
  await fire(1000);
  assert.deepEqual(controller.snapshot().importing, []);
});

test('disposing while a job request fails leaves no retries or state updates', async t => {
  const {controller, services, timers} = fixture(t), held = pending();
  services.fetch = () => held.promise;
  controller.pollJob('a', {progress: () => {}, done: () => {}, failed: () => {}});
  const snapshot = controller.snapshot();
  controller.dispose();
  held.reject(new Error('page gone'));
  await settle();
  assert.equal(timers.size, 0);
  assert.equal(controller.snapshot(), snapshot);
});
