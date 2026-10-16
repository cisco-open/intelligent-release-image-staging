// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {SetupPackagesController} from '../src/setup-packages-controller.mjs';
import {setupFixture, verificationFixture, response, deferred} from './setup-packages-fixtures.mjs';

function fixture() {
  const c = new SetupPackagesController(), requests = [], navigations = []; let visible = true;
  c.connect({fetch: async (url, options) => {requests.push({url, options}); return response(url.endsWith('setup-status') ? setupFixture() : verificationFixture('daily'));}, visible: () => visible,
    navigate: hash => navigations.push(hash), storage: {getItem: () => null, setItem() {}}});
  return {c, requests, navigations, hide: () => {visible = false;}};
}
test('read-only setup has one authoritative projection and configured annotation', async () => {
  const {c, requests} = fixture(); await c.select('setup'); assert.equal(c.state.status.packages.state, 'ok'); assert.equal(c.state.configured, true); assert.equal(requests.length, 2); requests.forEach(row => assert.equal(row.options.method, undefined));
});
test('package view does not fetch unrelated verification settings', async () => {
  const {c, requests} = fixture(); await c.select('packages'); assert.equal(requests.length, 1); assert.equal(c.state.status.packages.items.length, 4);
});
for (const name of ['http error', 'wrong success status', 'malformed payload', 'network failure', 'json failure']) test(name + ' clears all previously healthy evidence', async () => {
  const {c} = fixture(); await c.select('setup'); assert.ok(c.state.status);
  c.services.fetch = async () => {if (name === 'network failure') throw Error('offline'); if (name === 'json failure') return {status: 200, json: async () => {throw Error('json');}}; return response(name === 'malformed payload' ? {} : setupFixture(), name === 'http error' ? 500 : name === 'wrong success status' ? 202 : 200);};
  await c.refresh(); assert.equal(c.state.status, null); assert.equal(c.state.configured, null); assert.match(c.state.message, /cannot be determined/);
});
test('starting a read immediately removes previously healthy chips', async () => {
  const {c} = fixture(); await c.select('packages'); const held = deferred(); c.services.fetch = () => held.promise;
  const pending = c.refresh(); assert.equal(c.state.status, null); assert.equal(c.state.loading, true); held.resolve(response(setupFixture())); await pending; assert.ok(c.state.status);
});
test('aborted older reads cannot erase or replace newer evidence', async () => {
  const {c} = fixture(); await c.select('packages'); const old = deferred(); let signal;
  c.services.fetch = (_url, options) => {signal = options.signal; return old.promise;}; const pending = c.refresh();
  c.services.fetch = async () => response(setupFixture()); await c.refresh(); assert.equal(signal.aborted, true);
  old.resolve(response({})); await pending; assert.equal(c.state.status.packages.state, 'ok');
});
test('hidden completion is ignored and returning performs only GETs', async () => {
  const {c, requests} = fixture(); await c.select('packages'); const old = deferred(); c.services.fetch = () => old.promise;
  const pending = c.refresh(); c.hide(); old.resolve(response(setupFixture())); await pending; assert.equal(c.state.status, null); assert.equal(c.state.loading, false);
  c.services.fetch = async () => response(setupFixture()); await c.refresh(); assert.ok(c.state.status); assert.equal(requests.some(row => row.options.method === 'POST'), false);
});
test('new wizard entry starts at step one even with absent packages, and every step is accessible', async () => {
  const {c} = fixture(); const raw = setupFixture(); raw.packages.state = 'absent'; Object.assign(raw.packages.items[0], {state: 'absent', built_at: null, provenance: null, reason: 'absent'});
  c.services.fetch = async url => response(url.endsWith('setup-status') ? raw : verificationFixture()); await c.select('wizard'); assert.equal(c.state.step, 0);
  c.chooseStep(0); assert.equal(c.state.step, 0); c.chooseStep(2); assert.equal(c.state.step, 2); c.chooseStep(4); assert.equal(c.state.step, 2);
});
test('healthy, unknown and failed initial reads stay on step one', async () => {
  for (const raw of [setupFixture(), {}, null]) {
    const {c} = fixture();
    c.services.fetch = async url => response(url.endsWith('setup-status') ? raw : verificationFixture());
    await c.select('wizard'); assert.equal(c.state.step, 0);
  }
});
test('refresh preserves the current step, while leaving and returning starts at step one', async () => {
  const {c} = fixture(); await c.select('wizard'); c.chooseStep(2);
  await c.refresh(); assert.equal(c.state.step, 2);
  c.hide(); await c.refresh(); assert.equal(c.state.step, 2);
  await c.select('packages'); await c.select('wizard'); assert.equal(c.state.step, 0);
});
test('initial wizard response cannot override an explicit step selection', async () => {
  const {c} = fixture(); const held = deferred(); c.services.fetch = url => url.endsWith('setup-status') ? held.promise : Promise.resolve(response(verificationFixture()));
  const pending = c.select('wizard'); c.chooseStep(1); held.resolve(response(setupFixture())); await pending; assert.equal(c.state.step, 1);
});
test('Next does not navigate after leaving the wizard during its refresh', async () => {
  const {c, navigations} = fixture(); await c.select('wizard'); const held = deferred(); c.services.fetch = () => held.promise;
  const pending = c.next(); assert.equal(c.state.navigating, true); c.select(null); held.resolve(response(setupFixture())); await pending; assert.deepEqual(navigations, []); assert.equal(c.state.mode, null);
});
test('direct step selection wins over a pending Next and does not advance twice', async () => {
  const {c} = fixture(); await c.select('wizard'); c.chooseStep(0); const held = deferred(); c.services.fetch = url => url.endsWith('setup-status') ? held.promise : Promise.resolve(response(verificationFixture()));
  const pending = c.next(); c.chooseStep(1); held.resolve(response(setupFixture())); await pending; assert.equal(c.state.step, 1); assert.equal(c.state.navigating, false);
});
test('Continue follows the three steps and Open dashboard never submits form changes', async () => {
  const {c, navigations, requests} = fixture(); await c.select('wizard');
  await c.next(); assert.equal(c.state.step, 1); assert.deepEqual(navigations, []);
  await c.next(); assert.equal(c.state.step, 2); assert.deepEqual(navigations, []);
  await c.next(); assert.deepEqual(navigations, ['#overview']);
  assert.equal(requests.some(row => row.options.method === 'POST'), false);
});
for (const step of [0, 1, 2]) test('failed status refresh cannot advance or complete step ' + (step + 1), async () => {
  const {c, navigations} = fixture(); await c.select('wizard'); c.chooseStep(step);
  c.services.fetch = async () => response({}, 503);
  await c.next(); assert.equal(c.state.step, step); assert.equal(c.state.navigating, false);
  assert.equal(c.state.status, null); assert.match(c.state.message, /cannot be determined/); assert.deepEqual(navigations, []);
  // An explicit skip is navigation, not evidence that this step succeeded.
  c.skip(); assert.equal(c.state.status, null);
  assert.equal(c.state.step, step === 2 ? 2 : step + 1);
  assert.deepEqual(navigations, step === 2 ? ['#overview'] : []);
});
test('a newer verified schedule annotation survives an older pending setup read', async () => {
  const {c} = fixture(); await c.select('setup'); const held = deferred(); c.services.fetch = url => url.endsWith('setup-status') ? Promise.resolve(response(setupFixture())) : held.promise;
  const pending = c.refresh(); c.annotation(true); held.resolve(response(verificationFixture('off'))); await pending; assert.equal(c.state.configured, true);
});
test('blocked session storage cannot crash setup or prevent dismissal', () => {
  const c = new SetupPackagesController(); c.connect({storage: {getItem() {throw Error('denied');}, setItem() {throw Error('denied');}}}); c.dismiss(); assert.equal(c.state.dismissed, true);
});
