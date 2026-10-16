// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Independent port of the former Python/inline-script map regressions. These
// imports exercise the same native-contract model/controller bundled for users.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as model from '../src/swarm-map-model.mjs';
import {SwarmMapController} from '../src/swarm-map-controller.mjs';

const hash = 'a'.repeat(40);
const peer = (id = 'd1', state = 'staging') => ({device_id: id, ip: '192.0.2.1', port: 6881,
  tracker: {principal_type: 'device', principal_id: id, role: state === 'ready' ? 'seeder' : 'leecher',
    left: state === 'ready' ? 0 : 50, progress: state === 'ready' ? 1 : .5},
  device_observation: {image_id: 'os', obs_state: 'observed', stale: false},
  current_image_id: 'os', stage_state: state, staged_image_ids: state === 'ready' ? ['os'] : [], errored_image_ids: [],
  peer_telemetry: {supported: true, requested_interval_s: 60, effective_interval_s: 60}});
const snapshot = (peers = [peer()]) => ({now: 100, images: [{image: 'os.iso', image_id: 'os', info_hash: hash, peers}]});
const attached = p => model.participantRows(snapshot([p]))[0];
const response = (body, status = 200) => ({status, ok: status >= 200 && status < 300, json: async () => body});
const deferred = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
const flush = async () => {for (let n = 0; n < 40; n++) await Promise.resolve();};
const directive = (id = 'a') => ({request_id: id.repeat(32), requested_at: 100, expires_at: 700});
const intervalReply = (dry, overrides = {}) => ({ok: true, device_id: 'd1', requested_interval_s: 10,
  revision: 8, candidate_revision: 8, dry_run: dry, requires_confirmation: false, confirm_token: null, ...overrides});

async function fixture(options = {}) {
  const calls = [], timers = new Map(); let tick = 100000, serial = 0;
  let data = snapshot(), handler = null, confirm = () => true, hidden = false;
  const c = new SwarmMapController({swarmUrl: '/api/v1/swarm', pull: true}, {
    now: () => tick, embedded: false, documentHidden: false,
    confirm: message => confirm(message),
    setTimeout: (callback, delay) => {const id = ++serial; timers.set(id, {callback, at: tick + delay}); return id;},
    clearTimeout: id => timers.delete(id),
    fetch: async (url, init = {}) => {
      calls.push({url, init});
      if (handler) {const result = handler(url, init); if (result !== undefined) return result;}
      if (url === '/api/v1/session') return response({csrf: 'fixture-only'});
      if (url === '/api/v1/swarm') return response(data);
      if (url.endsWith('/peer-policy')) return response({revision: 7});
      if (url.endsWith('/effective-qos')) return response({revision: 8, device_id: 'd1', degraded: false,
        fail_closed: false, qos: {peer_telemetry_interval_s: {value: 10}}});
      if (url.endsWith('/reports')) return response({device_id: 'd1', observed_at: 102, pending_request: null, reports: []});
      if (url.endsWith('/request-report')) return response({ok: true, device_id: 'd1', ...directive()});
      if (url.includes('/peer-telemetry')) return response(intervalReply(url.includes('?')));
      throw Error('Unexpected test request: ' + url);
    }, ...options,
  });
  c.start(); await flush(); c.select(model.peerKey(attached(peer()))); await flush(); c.setIntervalDraft('10');
  return {c, calls, data: value => {data = value;}, handler: value => {handler = value;},
    confirm: value => {confirm = value;}, hidden: value => {hidden = value; c.setDocumentHidden(value);},
    refresh: async () => {void c.poll(); await flush();},
    advance: async milliseconds => {
      tick += milliseconds;
      for (const [id, timer] of [...timers]) if (timer.at <= tick) {timers.delete(id); timer.callback();}
      await flush();
    }, writes: () => calls.filter(row => row.init.method === 'POST'),
  };
}

for (const state of ['staging', 'verifying', 'transferring_to_ios', 'flash_full']) {
  test(`tracker completion never claims device staging complete: ${state}`, () => {
    const p = attached(peer('d1', state)); p.tracker.left = 0; p.tracker.progress = 1;
    p.device_observation = {obs_state: 'not_due', stale: true};
    assert.doesNotMatch(model.peerStatus(p, 100), /staging complete|^ready/);
    assert.match(model.imageState(p, 'os'), new RegExp(state));
  });
}
test('image-specific staging, error precedence and independent peers are preserved', () => {
  const one = attached(peer('one', 'ready')), two = attached(peer('two'));
  assert.match(model.peerStatus(one, 100), /ready/); assert.doesNotMatch(model.peerStatus(two, 100), /ready/);
  two.staged_image_ids = ['os']; two.errored_image_ids = ['os'];
  assert.equal(model.imageState(two, 'os'), 'error'); assert.match(model.peerStatus(two, 100), /error/);
  one._image_id = 'other'; assert.match(model.peerStatus(one, 100), /pending/);
  assert.doesNotMatch(model.peerStatus(one, 100), /ready/);
});
for (const state of ['error', 'copy_failed', 'transferring_to_ios', 'ready']) {
  test(`single-image agent retains exact reported state: ${state}`, () => {
    const p = attached(peer()); delete p.staged_image_ids; delete p.errored_image_ids; p.stage_state = state;
    assert.equal(model.imageState(p, 'os'), state);
  });
}
test('other-image observations retain explicit provenance', () => {
  const p = attached(peer()); p.device_observation = {image_id: 'other', obs_state: 'observed', valid: true};
  assert.equal(model.otherImage(p, p.device_observation), true);
  assert.match(model.peerStatus(p, 100), /another image/);
});
test('typed identities use reported model and secondary IP without legacy attribution', () => {
  const xr = attached(peer('192.0.2.1')); xr.model = '8000';
  const xe = attached(peer('router-b')); xe.model = 'C8000V';
  const legacy = {...attached(peer()), device_id: null, model: 'must not leak',
    tracker: {principal_type: 'legacy', participant_class: 'legacy_unattributed'}};
  assert.equal(model.peerCaption(xr), '192.0.2.1 (8000)'); assert.equal(model.peerRowLabel(xr), '192.0.2.1');
  assert.equal(model.peerCaption(xe), 'router-b (C8000V)'); assert.equal(model.peerRowLabel(xe), 'router-b — 192.0.2.1');
  assert.equal(model.peerName(legacy), 'Legacy unattributed peer'); assert.equal(model.peerModel(legacy), '');
  assert.equal(model.peerCaption(legacy), 'Legacy unattributed peer');
});
test('catalog filenames and image identity survive flattening and filtering', () => {
  const data = snapshot(); data.images[0].image = '8000-x64.iso'; data.images[0].image_id = '8000-x64.iso';
  data.images.push({image: 'cat9k_iosxe.SPA.bin', image_id: 'cat9k_iosxe', info_hash: 'b'.repeat(40), peers: [peer('xe')]});
  assert.deepEqual(model.participantRows(data).map(p => p._img), ['8000-x64.iso', 'cat9k_iosxe.SPA.bin']);
  assert.deepEqual(model.filteredPeers(data, {imageHash: hash, query: '', attention: ''}, 100).map(p => p.device_id), ['d1']);
  assert.deepEqual(model.filteredPeers(data, {imageHash: 'all', query: 'xe', attention: ''}, 100).map(p => p.device_id), ['xe']);
});
test('measured peer arrows retain direction, provenance, scope and cached expiry', () => {
  const data = snapshot([peer('one'), peer('two')]);
  data.images[0].peer_edges = [{source_device_id: 'one', target_device_id: 'two', reporter_device_id: 'two',
    rate_field: 'receive_bps', identity_basis: 'unique_tracker_address', bytes_per_second: 123, received_at: 95, valid_for_s: 120}];
  const edges = model.freshPeerEdges(data, 100); assert.equal(edges.length, 1);
  assert.equal(edges[0]._hash, hash); assert.match(model.edgeLabel(edges[0], 100), /one → two/);
  assert.match(model.edgeLabel(edges[0], 100), /by two/);
  assert.equal(model.freshPeerEdges(data, 100, 'b'.repeat(40)).length, 0);
  assert.equal(model.freshPeerEdges(data, 216).length, 0);
});
for (const value of [['120'], '120', true, -1, NaN, Infinity, {}]) {
  test(`malformed measured edge lifetime is omitted: ${String(value)}`, () => {
    const data = snapshot([peer('one'), peer('two')]);
    data.images[0].peer_edges = [{source_device_id: 'one', target_device_id: 'two', reporter_device_id: 'two',
      bytes_per_second: 123, received_at: 95, valid_for_s: value}];
    assert.deepEqual(model.freshPeerEdges(data, 100), []);
  });
}
test('server measured rate uses native observation time fallback and expires', () => {
  const data = snapshot(), p = attached(peer()); data.server = {server_observation: {observed_at: 99}};
  p.server_observation = {peer: {send_bps: 123}};
  assert.equal(model.freshServerPeer(p, data, 100).observed_at, 99);
  assert.equal(model.freshServerPeer(p, data, 220), null);
  p.server_observation.peer.observed_at = 98; assert.equal(model.freshServerPeer(p, data, 100).observed_at, 98);
  p.server_observation.peer.send_bps = 0; assert.equal(model.freshServerPeer(p, data, 100), null);
});
test('repeated older snapshots cannot indefinitely renew measured observation freshness', async () => {
  const f = await fixture(); const data = snapshot();
  data.images[0].peer_edges = [{source_device_id: 'one', target_device_id: 'two', reporter_device_id: 'two',
    bytes_per_second: 123, received_at: 100, valid_for_s: 120}];
  f.data(data); await f.refresh();
  for (let n = 0; n < 26; n++) await f.advance(5000);
  assert.equal(model.freshPeerEdges(f.c.state.data, f.c.state.now).length, 0,
    'Repeated older server timestamps must not reset elapsed local aging');
  f.c.stop();
});

for (const [name, body] of Object.entries({missing: {}, imageObject: {now: 100, images: {}}, nullImage: {now: 100, images: [null]},
  nullTime: {...snapshot(), now: null}, noPrincipal: snapshot([{}]), unknownPrincipal: snapshot([{tracker: {principal_type: 'unknown'}}]),
  invalidStaged: snapshot([{...peer(), staged_image_ids: {}}]), invalidObservation: snapshot([{...peer(), device_observation: {obs_state: 7}}]),
  invalidRole: snapshot([{...peer(), tracker: {...peer().tracker, role: {unsafe: true}}}]),
  partialOffset: {...snapshot(), peers_offset: 1}})) {
  test(`malformed ${name} snapshot is unavailable and recovers`, async () => {
    assert.equal(model.validSnapshot(body), false);
    const f = await fixture(); f.data(body); await f.refresh();
    assert.equal(f.c.state.data, null); assert.equal(f.c.state.loadFailed, true);
    f.data(snapshot()); await f.refresh(); assert.equal(f.c.state.data.images[0].peers[0].device_id, 'd1'); f.c.stop();
  });
}
test('selected exact participant survives reorder, disappears safely and recovers', async () => {
  const f = await fixture(), key = f.c.state.selected;
  f.data(snapshot([peer('other'), peer('d1', 'ready')])); await f.refresh();
  assert.equal(f.c.state.selected, key); assert.equal(f.c.selectedPeer().device_id, 'd1');
  assert.equal(model.imageState(f.c.selectedPeer(), 'os'), 'ready');
  f.data(snapshot([peer('other')])); await f.refresh(); assert.equal(f.c.selectedPeer(), null);
  assert.equal(f.c.state.selected, key); assert.equal(f.c.canPull(), false);
  f.data(snapshot()); await f.refresh(); assert.equal(f.c.selectedPeer().device_id, 'd1');
  f.c.select('hub'); assert.equal(f.c.selectedPeer(), null); f.c.close(); assert.equal(f.c.state.selected, null); f.c.stop();
});
test('late failed read cannot clear a newer successful snapshot', async () => {
  const f = await fixture(), old = deferred(); let hold = true;
  f.handler(url => url === '/api/v1/swarm' && hold ? old.promise : undefined);
  await f.refresh(); hold = false; f.data(snapshot([peer('new')])); await f.refresh();
  old.reject(Error('old read failed')); await flush();
  assert.equal(f.c.state.data.images[0].peers[0].device_id, 'new'); f.c.stop();
});

for (const [name, bad] of Object.entries({device: {device_id: 'other'}, interval: {requested_interval_s: 60},
  revision: {revision: 7}, dryRun: {dry_run: false}, success: {ok: false}})) {
  test(`mismatched ${name} interval preview never commits`, async () => {
    const f = await fixture(); f.handler(url => url.includes('/peer-telemetry') ? response(intervalReply(true, bad)) : undefined);
    await f.c.saveInterval(); assert.equal(f.writes().length, 1);
    assert.equal(f.c.actionsFor('d1').interval.unknown, true); assert.doesNotMatch(f.c.actionsFor('d1').interval.message, /^Saved/); f.c.stop();
  });
}
for (const [name, bad] of Object.entries({device: {device_id: 'other'}, interval: {requested_interval_s: 60},
  revision: {revision: 7}, dryRun: {dry_run: true}, success: {ok: false}})) {
  test(`mismatched ${name} interval commit requires review without replay`, async () => {
    const f = await fixture(); f.handler(url => url.endsWith('/peer-telemetry') ? response(intervalReply(false, bad)) : undefined);
    await f.c.saveInterval(); await f.c.saveInterval(); assert.equal(f.writes().length, 2);
    assert.equal(f.c.actionsFor('d1').interval.unknown, true);
    await f.c.reviewInterval(); assert.equal(f.c.actionsFor('d1').interval.unknown, false);
    assert.match(f.c.actionsFor('d1').interval.message, /Current requested interval: 10/); f.c.stop();
  });
}
for (const [name, change] of Object.entries({document: f => f.hidden(true), host: f => f.c.setHostPaused(true),
  manual: f => f.c.togglePause(), drawer: f => {f.c.close(); f.c.select(model.peerKey(attached(peer())));}})) {
  test(`${name} change during interval preflight never commits`, async () => {
    const f = await fixture(), held = deferred(); f.handler(url => url.includes('?dry_run=1') ? held.promise : undefined);
    const pending = f.c.saveInterval(); await flush(); change(f); held.resolve(response(intervalReply(true))); await pending;
    assert.equal(f.writes().length, 1); assert.equal(f.c.actionsFor('d1').interval.busy, false); f.c.stop();
  });
}
for (const accept of [true, false]) {
  test(`required interval confirmation is exact and ${accept ? 'accepted once' : 'cancellable'}`, async () => {
    const f = await fixture(), prompts = [];
    f.confirm(message => {prompts.push(message); return accept;});
    f.handler(url => url.includes('/peer-telemetry') ? response(intervalReply(url.includes('?'),
      {requires_confirmation: true, confirm_token: 'intent-bound-test-token'})) : undefined);
    await f.c.saveInterval(); assert.equal(prompts.length, 1); assert.match(prompts[0], /d1 to 10 seconds/);
    assert.match(prompts[0], /revision 7 will become 8/); assert.equal(f.writes().length, accept ? 2 : 1);
    assert.equal(f.c.actionsFor('d1').interval.unknown, false); assert.equal(f.c.actionsFor('d1').interval.busy, false);
    if (accept) {const commit = f.writes()[1]; assert.equal(commit.init.headers['X-CSRF-Token'], 'fixture-only');
      assert.equal(commit.init.headers['If-Match'], '"iris-peer-policy-7"');
      assert.equal(JSON.parse(commit.init.body).confirm_token, 'intent-bound-test-token');}
    else assert.match(f.c.actionsFor('d1').interval.message, /cancelled/);
    f.c.stop();
  });
}
for (const [name, change] of Object.entries({host: f => f.c.setHostPaused(true), document: f => f.hidden(true),
  drawer: f => f.c.close()})) {
  test(`confirmation rechecks ${name} context before committing`, async () => {
    const f = await fixture(); f.confirm(() => {change(f); return true;});
    f.handler(url => url.includes('/peer-telemetry') ? response(intervalReply(true,
      {requires_confirmation: true, confirm_token: 'intent-bound-test-token'})) : undefined);
    await f.c.saveInterval(); assert.equal(f.writes().length, 1); f.c.stop();
  });
}
test('inflight write remains locked across same-device drawer reopen', async () => {
  const f = await fixture(), held = deferred(); f.handler(url => url.endsWith('/peer-telemetry') ? held.promise : undefined);
  const pending = f.c.saveInterval(); await flush(); f.c.close(); f.c.select(model.peerKey(attached(peer())));
  await f.c.saveInterval(); assert.equal(f.writes().length, 2);
  held.resolve(response(intervalReply(false))); await pending;
  assert.equal(f.c.actionsFor('d1').interval.busy, false); assert.match(f.c.actionsFor('d1').interval.message, /^Saved/); f.c.stop();
});
test('participant disappearing during interval preflight cannot commit', async () => {
  const f = await fixture(), held = deferred(); f.handler(url => url.includes('?dry_run=1') ? held.promise : undefined);
  const pending = f.c.saveInterval(); await flush(); f.data(snapshot([])); await f.refresh();
  held.resolve(response(intervalReply(true))); await pending;
  assert.equal(f.writes().length, 1); assert.equal(f.c.actionsFor('d1').interval.busy, false); f.c.stop();
});
test('native directive IDs cannot be regex-coerced', () => {
  assert.equal(model.validDirective({...directive(), request_id: ['a'.repeat(32)]}), false);
  assert.equal(model.validDirective(directive()), true);
});
for (const [name, body] of Object.entries({falseSuccess: {ok: false}, wrongDevice: {ok: true, device_id: 'other', ...directive()},
  invalidId: {ok: true, device_id: 'd1', ...directive(), request_id: 'bad'}})) {
  test(`${name} report acceptance remains unknown without replay until review`, async () => {
    const f = await fixture(); f.handler(url => url.endsWith('/request-report') ? response(body) : undefined);
    await f.c.requestPull(); await f.c.requestPull(); assert.equal(f.writes().length, 1);
    assert.equal(f.c.actionsFor('d1').pull.unknown, true); await f.c.reviewPull();
    assert.equal(f.c.actionsFor('d1').pull.unknown, false);
    assert.doesNotMatch(f.c.actionsFor('d1').pull.message, /Matching report received/); f.c.stop();
  });
}
test('pull requires exact request identity and preserves a newer pending directive', async () => {
  const f = await fixture(); let pending = directive(), reports = [];
  f.handler(url => url.endsWith('/reports') ? response({device_id: 'd1', observed_at: 103, pending_request: pending, reports}) : undefined);
  const request = f.c.requestPull(); await flush();
  assert.equal(f.c.actionsFor('d1').pull.request.request_id, directive().request_id);
  reports = [{schema: 'v2', event: 'staging-complete', report_id: 'b'.repeat(32), report_request_id: null, received_at: 9999999999}];
  await f.advance(2500); assert.doesNotMatch(f.c.actionsFor('d1').pull.message, /Matching report received/);
  reports.push({schema: 'v2', event: 'pull', report_id: 'c'.repeat(32), report_request_id: 'd'.repeat(32)});
  await f.advance(2500); assert.doesNotMatch(f.c.actionsFor('d1').pull.message, /Matching report received/);
  reports.push({schema: 'v2', event: 'pull', report_id: ['e'.repeat(32)], report_request_id: directive().request_id});
  await f.advance(2500); assert.doesNotMatch(f.c.actionsFor('d1').pull.message, /Matching report received/);
  assert.equal(f.c.state.reportMessage, 'Historical participation unavailable.');
  reports.pop(); // Reject the malformed envelope; a subsequent valid read recovers.
  reports.push({schema: 'v2', event: 'pull', report_id: 'f'.repeat(32), report_request_id: directive().request_id}); pending = directive('b');
  await f.advance(2500); await request;
  assert.match(f.c.actionsFor('d1').pull.message, /Matching report received/);
  assert.equal(f.c.actionsFor('d1').pull.request.request_id, pending.request_id); assert.equal(f.c.canPull(), false); f.c.stop();
});
test('old historical read cannot overwrite newer explicit review', async () => {
  const f = await fixture(), held = deferred(); let first = true;
  f.handler(url => {if (!url.endsWith('/reports')) return undefined;
    if (first) {first = false; return held.promise;}
    return response({device_id: 'd1', observed_at: 103, pending_request: null, reports: [{image_id: 'new', peers: []}]});});
  f.c.close(); f.c.select(model.peerKey(attached(peer()))); await flush();
  await f.c.reviewPull(); held.resolve(response({device_id: 'd1', reports: [{image_id: 'old', peers: []}]})); await flush();
  assert.equal(f.c.state.reports.at(-1).image_id, 'new'); f.c.stop();
});
test('embedded map waits for host handshake and host resume preserves manual pause', async () => {
  const f = await fixture({embedded: true}); assert.equal(f.calls.length, 0);
  f.c.setHostPaused(false); await flush(); assert.ok(f.calls.some(row => row.url === '/api/v1/swarm'));
  f.c.togglePause(); const count = f.calls.length; f.c.setHostPaused(true); f.c.setHostPaused(false); await f.advance(10000);
  assert.equal(f.c.state.paused, true); assert.equal(f.calls.length, count); f.c.stop();
});
test('service participants cannot invoke device controls even with a device-shaped field', async () => {
  const f = await fixture(); const service = {...peer(), tracker: {principal_type: 'service', principal_id: 'seeder'}};
  f.data(snapshot([service])); await f.refresh(); f.c.select(model.peerKey(attached(service))); await flush();
  assert.equal(f.c.canInterval(), false); assert.equal(f.c.canPull(), false);
  assert.equal(f.c.canReviewInterval(), false); assert.equal(f.c.canReviewPull(), false);
  await f.c.saveInterval(); await f.c.requestPull(); assert.equal(f.writes().length, 0); f.c.stop();
});
