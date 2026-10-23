// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {swarmSummary} from '../src/swarm-view-model.mjs';
import {SwarmViewController} from '../src/swarm-view-controller.mjs';

const peer = (type = 'device') => ({ip: '192.0.2.1', port: 6881, tracker: {
  principal_type: type, ...(type === 'legacy' ? {participant_class: 'legacy_unattributed'} : {principal_id: 'router-a'}),
  role: 'leecher', left: 4, last_seen: 2000000000, progress: .5}});
const snapshot = (peers = []) => ({now: 2000000000.25, images: [{info_hash: 'a'.repeat(40), peers}]});
const response = data => ({status: 200, json: async () => data});
const deferred = () => {let resolve; const promise = new Promise(done => {resolve = done;}); return {resolve, promise};};

test('summarizes image-peer entries without inventing unique-device or IP attribution', () => {
  const data = snapshot([peer(), peer('legacy')]);
  data.images.push({info_hash: 'b'.repeat(40), peers: [peer()]});
  assert.deepEqual(swarmSummary(data), {entries: 3, legacy: 1, seederUnavailable: false});
});
test('accepts a native empty snapshot and distinguishes unavailable seeder observations', () => {
  assert.deepEqual(swarmSummary({now: 2000000000, images: []}), {entries: 0, legacy: 0, seederUnavailable: false});
  const data = snapshot(); data.server = {server_observation: {unavailable: true, rpc_up: false}};
  assert.equal(swarmSummary(data).seederUnavailable, true);
});
for (const [name, value] of Object.entries({missing: {}, error: {...snapshot(), error: 'private internals'},
  noTime: {images: []}, peersOnly: {peers: []}, nullImage: {now: 1, images: [null]},
  badHash: {now: 1, images: [{info_hash: '<svg>', peers: []}]}, absentPeers: {now: 1, images: [{info_hash: 'a'.repeat(40)}]},
  badPeer: snapshot([null]), noPrincipal: snapshot([{tracker: {principal_type: 'device'}}]),
  unknownPrincipal: snapshot([peer('guess')]), partial: {...snapshot(), peers_total: 4, peers_offset: 0},
  offset: {...snapshot(), peers_total: 0, peers_offset: 2},
  duplicate: {now: 1, images: [...snapshot().images, ...snapshot().images]}})) {
  test(`rejects ${name} instead of displaying a reassuring zero`, () => assert.equal(swarmSummary(value), null));
}
function fixture() {
  const c = new SwarmViewController(), messages = [], requests = [];
  let visible = true, next = response(snapshot([peer('legacy')]));
  c.connect({visible: () => visible, origin: 'https://iris.test', fetch: (url, options) => {
    requests.push({url, options}); return next;
  }});
  c.attachFrame({contentWindow: {postMessage: (...args) => messages.push(args)}});
  return {c, messages, requests, visible: value => {visible = value;}, next: value => {next = value;}};
}
test('read errors clear previous counts and attribution warnings', async () => {
  const {c, next} = fixture(); await c.refresh(); assert.equal(c.state.summary.legacy, 1);
  next(response({})); await c.refresh(); assert.equal(c.state.summary, null); assert.equal(c.state.error, true);
});
test('latest snapshot wins even when the old transport ignores abort', async () => {
  const {c, next, requests} = fixture(), old = deferred(); next(old.promise); const pending = c.refresh();
  next(response(snapshot())); await c.refresh(); old.resolve(response(snapshot([peer()]))); await pending;
  assert.equal(requests[0].options.signal.aborted, true); assert.equal(c.state.summary.entries, 0);
});
test('hidden reads stop and late frame load receives host pause', async () => {
  const {c, next, requests, visible, messages} = fixture(), old = deferred(); next(old.promise); const pending = c.refresh();
  visible(false); c.syncVisibility(); old.resolve(response(snapshot([peer()]))); await pending;
  c.syncVisibility(); await c.refresh();
  assert.equal(requests.length, 1); assert.equal(requests[0].options.signal.aborted, true);
  assert.equal(c.state.summary, null); assert.equal(c.state.started, true);
  assert.deepEqual(messages.at(-1), ['MAP_PAUSE', 'https://iris.test']);
});
test('polling never sends resume and only uses the fixed same-origin swarm route', async () => {
  const {c, messages, requests} = fixture(); c.syncVisibility(); await c.refresh(); await c.refresh();
  assert.deepEqual(messages, [['MAP_RESUME', 'https://iris.test']]);
  assert.ok(requests.every(row => row.url === '/api/v1/swarm' && row.options.cache === 'no-store'));
});
test('a late map-ready handshake restores current visibility only for the attached frame', () => {
  const {c, messages, visible} = fixture();
  const ready = {data: 'MAP_READY', origin: 'https://iris.test', source: c.frame.contentWindow};
  c.frameReady({...ready, origin: 'https://other.test'});
  c.frameReady({...ready, source: {}});
  assert.deepEqual(messages, []);
  c.frameReady(ready);
  assert.deepEqual(messages.at(-1), ['MAP_RESUME', 'https://iris.test']);
  visible(false); c.frameReady(ready);
  assert.deepEqual(messages.at(-1), ['MAP_PAUSE', 'https://iris.test']);
});
