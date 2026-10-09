// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {SwarmMapController} from '../src/swarm-map-controller.mjs';
import {participantRows, peerKey} from '../src/swarm-map-model.mjs';

const flush = async () => {for (let i = 0; i < 30; i++) await Promise.resolve();};
const deferred = () => {let resolve; const promise = new Promise(done => {resolve = done;}); return {promise, resolve};};
const response = (status, body) => ({status, json: async () => body});
const data = {now: 100, images: [{info_hash: 'a'.repeat(40), peers: [
  {device_id: 'router-a', tracker: {principal_type: 'device', principal_id: 'router-a', role: 'leecher'}},
]}]};

function fixture(options = {}) {
  const calls = [], timers = new Map(); let serial = 0, review;
  const controller = new SwarmMapController({pull: true, swarmUrl: '/api/v1/swarm'}, {
    embedded: false, documentHidden: false, now: () => 100000,
    setTimeout: (callback, delay) => {timers.set(++serial, {callback, delay}); return serial;},
    clearTimeout: id => timers.delete(id),
    fetch: async (url, init = {}) => {
      calls.push({url, init});
      assert.ok(!init.method || init.method === 'GET', 'Lifetime review must not submit a mutation');
      if (url === '/api/v1/session') return response(200, {csrf: 'current-session-fixture'});
      if (url === '/api/v1/swarm') return response(200, data);
      if (url.endsWith('/reports')) return response(200, {device_id: 'router-a', observed_at: 100, pending_request: null, reports: []});
      if (url.endsWith('/effective-qos')) return review.promise;
      throw Error('Unexpected request: ' + url);
    }, ...options,
  });
  return {controller, calls, timers, holdReview() {review = deferred(); return review;},
    async open() {await controller.start(); await controller.select(peerKey(participantRows(data)[0]));}};
}

for (const family of ['host', 'document', 'manual']) {
  test(`an obsolete interval review 401 after ${family} pause/resume cannot invalidate the resumed session`, async () => {
    const f = fixture(), c = f.controller;
    await f.open();
    const held = f.holdReview(), pending = c.reviewInterval();
    assert.equal(c.actionsFor('router-a').interval.busy, true);
    if (family === 'host') {c.setHostPaused(true); c.setHostPaused(false);}
    if (family === 'document') {c.setDocumentHidden(true); c.setDocumentHidden(false);}
    if (family === 'manual') {c.togglePause(); c.togglePause();}
    await flush();
    assert.equal(c.state.sessionReady, true);
    held.resolve(response(401, {code: 'authentication-required'})); await pending;
    assert.equal(c.state.sessionReady, true);
    assert.equal(c.state.sessionError, false);
    assert.equal(c.csrf, 'current-session-fixture');
    assert.equal(c.canInterval(), true);
    c.stop(); assert.equal(f.timers.size, 0);
  });
}

test('a current interval review 401 still invalidates the session and disables controls', async () => {
  const f = fixture(), c = f.controller;
  await f.open();
  const held = f.holdReview(), pending = c.reviewInterval();
  held.resolve(response(401, {code: 'authentication-required'})); await pending;
  assert.equal(c.state.sessionReady, false);
  assert.equal(c.state.sessionError, true);
  assert.equal(c.csrf, null);
  assert.equal(c.canInterval(), false);
  assert.equal(c.canPull(), false);
  c.stop(); assert.equal(f.timers.size, 0);
});

test('a read started before a newer session generation cannot revoke the refreshed session', async () => {
  const f = fixture(), c = f.controller;
  await f.open();
  const held = f.holdReview(), pending = c.reviewInterval();
  c.update({sessionReady: false}); await c.ensureSession();
  assert.equal(f.calls.filter(call => call.url === '/api/v1/session').length, 2);
  held.resolve(response(401, {code: 'authentication-required'})); await pending;
  assert.equal(c.state.sessionReady, true);
  assert.equal(c.state.sessionError, false);
  assert.equal(c.csrf, 'current-session-fixture');
  c.stop();
});

test('embedded hidden bootstrap performs no session or snapshot reads until both visibility gates open', async () => {
  const f = fixture({embedded: true, documentHidden: true}), c = f.controller;
  await c.start(); assert.deepEqual(f.calls, []); assert.equal(f.timers.size, 0);
  c.setHostPaused(false); await flush(); assert.deepEqual(f.calls, []);
  c.setDocumentHidden(false); await flush();
  assert.deepEqual(f.calls.map(call => call.url).sort(), ['/api/v1/session', '/api/v1/swarm']);
  assert.equal(c.state.sessionReady, true);
  c.stop(); assert.equal(f.timers.size, 0);
});

test('the first host resume cannot reverse a manual pause set while embedded', async () => {
  const f = fixture({embedded: true}), c = f.controller;
  await c.start(); c.togglePause(); c.setHostPaused(false); await flush();
  assert.equal(c.state.paused, true); assert.deepEqual(f.calls, []);
  c.togglePause(); await flush();
  assert.equal(c.state.paused, false);
  assert.deepEqual(f.calls.map(call => call.url).sort(), ['/api/v1/session', '/api/v1/swarm']);
  c.stop(); assert.equal(f.timers.size, 0);
});
