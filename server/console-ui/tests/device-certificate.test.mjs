// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {DeviceCertificateController} from '../src/device-certificate-controller.mjs';
import {certificateStatus, revocationConfirmation, reenrollmentConfirmation, runtimeObservation} from '../src/device-certificate-model.mjs';

const identity = 'a'.repeat(64), uuid = '172a1100-abcd-4000-8000-000000000001';
const status = (id = 'edge', extra = {}) => ({device_id: id, identity_sha256: identity, revision: 2,
  state: 'active', revoked_at: null, request_id: null, recovery_request_id: null,
  peer_tls_required: true, enforcement: 'not-applicable', ...extra});
const revoked = (id = 'edge', extra = {}) => status(id, {revision: 3, state: 'revoked', revoked_at: 2000000000,
  request_id: uuid, enforcement: 'pending', ...extra});
const recovery = (id = 'edge', extra = {}) => revoked(id, {revision: 4, state: 'reenrollment-required', recovery_request_id: uuid, ...extra});
const recovered = (id = 'edge', extra = {}) => status(id, {revision: 5, identity_sha256: 'b'.repeat(64), recovery_request_id: uuid, ...extra});
const response = (body, code = 200) => ({ok: code >= 200 && code < 300, status: code, json: async () => body});
const gate = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
function fixture(t) {
  const views = [], requests = [], confirms = [], controller = new DeviceCertificateController(view => views.push(view));
  const current = new Map();
  const services = {uuid: () => uuid, confirm: text => { confirms.push(text); return true; },
    fetch: async (url, options) => { requests.push({url, options}); const id = decodeURIComponent(url.split('/').at(-2));
      return response(current.get(id) || status(id)); },
    post: async (url, body) => { requests.push({url, body}); const id = decodeURIComponent(url.split('/').at(-3));
      const next = url.endsWith('/reenroll') ? recovery(id, {recovery_request_id: body.request_id}) : revoked(id);
      current.set(id, next); return response({...next, applied: true}); }};
  controller.connect(services); t.after(() => controller.close());
  return {controller, services, requests, confirms, views, current};
}

test('status requires exact public identity, revision, mode and matching revocation fields', () => {
  assert.equal(certificateStatus(status(), 'edge'), true);
  assert.equal(certificateStatus(revoked(), 'edge'), true);
  assert.equal(certificateStatus(recovery(), 'edge'), true);
  assert.equal(certificateStatus(recovered(), 'edge'), true);
  for (const value of [null, [], {}, status('other'), status('edge', {identity_sha256: '<script>'}),
    status('edge', {revision: -1}), status('edge', {revision: Number.MAX_SAFE_INTEGER + 1}),
    status('edge', {peer_tls_required: 'true'}), status('edge', {enforcement: 'enforced'}),
    status('edge', {request_id: uuid}), revoked('edge', {revoked_at: null}), revoked('edge', {request_id: null}),
    recovery('edge', {recovery_request_id: null}), status('edge', {recovery_request_id: 'invalid'}),
    revoked('edge', {revoked_at: Number.MAX_SAFE_INTEGER}), status('edge', {identity_sha256: identity + '\n'}),
    revoked('edge', {request_id: uuid + '\n'}), recovery('edge', {recovery_request_id: uuid + '\n'})]) {
    assert.equal(certificateStatus(value, 'edge'), false, JSON.stringify(value));
  }
});

test('confirmation identifies the reviewed device and limits without promising immediate isolation', () => {
  assert.match(revocationConfirmation('edge <one>'), /^Revoke device certificate for edge <one>\?/);
  assert.match(revocationConfirmation('edge'), /every IRIS peer certificate.*cannot be undone.*Updated peers.*five minutes.*Clients without this support.*Staged images stay/s);
});

test('revocation pins device identity and revision with a fresh request ID, then reads status', async t => {
  const {controller: c, requests, confirms} = fixture(t);
  await c.open('a / b'); assert.equal(c.canRevoke(), true);
  await c.revoke();
  assert.equal(requests.length, 3);
  assert.deepEqual(requests[1], {url: '/api/v1/devices/a%20%2F%20b/certificate/revoke',
    body: {expected_revision: 2, expected_identity_sha256: identity, request_id: uuid}});
  assert.equal(requests[0].options.cache, 'no-store');
  assert.match(confirms[0], /for a \/ b\?/);
  assert.equal(c.state.status.state, 'revoked'); assert.equal(c.canRevoke(), false);
  assert.match(c.state.message, /Revocation saved.*not yet confirmed/);
});

test('cancel, disabled peer TLS, revoked and unavailable status send no mutation', async t => {
  const {controller: c, services, requests} = fixture(t);
  await c.open('edge'); services.confirm = () => false; await c.revoke();
  assert.equal(c.canRevoke(), true); assert.equal(c.state.message, '');
  for (const value of [status('edge', {peer_tls_required: false}), revoked(), {}]) {
    services.fetch = async () => response(value); await c.refresh(); await c.revoke();
    assert.equal(c.canRevoke(), false);
  }
  assert.equal(requests.filter(item => item.body).length, 0);
});

test('read failures clear stale status and manual status checks never send a write', async t => {
  const {controller: c, services, requests} = fixture(t); await c.open('edge');
  for (const fetch of [async () => response({}, 503), async () => { throw Error('private proxy response'); },
    async () => ({ok: true, json: async () => { throw Error('invalid'); }})]) {
    services.fetch = fetch; await c.refresh();
    assert.equal(c.state.status, null); assert.equal(c.canRevoke(), false);
    assert.match(c.state.message, /status is unavailable/); assert.doesNotMatch(c.state.message, /private proxy/);
  }
  assert.equal(requests.filter(item => item.body).length, 0);
});

test('duplicate actions cannot pass a delayed confirmation or a pending POST', async t => {
  const {controller: c, services, requests} = fixture(t), confirm = gate(), write = gate();
  await c.open('edge'); services.confirm = () => confirm.promise;
  const first = c.revoke(); await c.revoke(); assert.equal(c.state.busy, true);
  services.post = (url, body) => { requests.push({url, body}); return write.promise; };
  confirm.resolve(true); await Promise.resolve(); await c.revoke();
  assert.equal(requests.filter(item => item.body).length, 1);
  write.resolve(response(revoked())); await first;
});

test('unknown outcomes remain blocked across close/reopen and active reads cannot release them', async t => {
  const {controller: c, services, requests} = fixture(t);
  await c.open('edge'); services.post = async (url, body) => { requests.push({url, body}); throw Error('lost'); };
  await c.revoke(); assert.equal(c.state.blocked, true); assert.match(c.state.message, /unknown/);
  c.close(); await c.open('other'); assert.equal(c.canRevoke(), true);
  await c.open('edge'); assert.equal(c.state.status.state, 'active'); assert.equal(c.canRevoke(), false);
  await c.revoke(); await c.refresh(); assert.equal(c.canRevoke(), false);
  assert.equal(requests.filter(item => item.body).length, 1);
  services.fetch = async () => response(revoked()); await c.refresh();
  assert.equal(c.state.blocked, false); assert.equal(c.pending.size, 0); assert.equal(c.canRevoke(), false);
  assert.match(c.state.message, /Revocation saved/);
});

for (const kind of ['500', 'malformed', 'wrong device', 'wrong identity', 'wrong request', 'stale revision', 'invalid JSON']) {
  test(`ambiguous ${kind} cannot be reported as successful or replayed`, async t => {
    const {controller: c, services} = fixture(t); let writes = 0;
    await c.open('edge'); services.post = async () => { writes++;
      if (kind === 'invalid JSON') return {ok: true, status: 200, json: async () => { throw Error('private contents'); }};
      const values = {'500': revoked(), malformed: {}, 'wrong device': revoked('other'),
        'wrong identity': revoked('edge', {identity_sha256: 'b'.repeat(64)}),
        'wrong request': revoked('edge', {request_id: '172a1100-abcd-4000-8000-000000000002'}),
        'stale revision': revoked('edge', {revision: 2})};
      return response(values[kind], kind === '500' ? 500 : 200);
    };
    await c.revoke(); await c.revoke(); assert.equal(writes, 1); assert.equal(c.state.blocked, true);
    assert.match(c.state.message, /unknown/); assert.doesNotMatch(c.state.message, /private contents/);
  });
}

test('an unrelated revoked identity cannot reconcile an uncertain write', async t => {
  const {controller: c, services} = fixture(t); await c.open('edge');
  services.post = async () => { throw Error('lost'); }; await c.revoke();
  services.fetch = async () => response(revoked('edge', {identity_sha256: 'b'.repeat(64)})); await c.refresh();
  assert.equal(c.state.blocked, true); assert.equal(c.canRevoke(), false);
});

test('an older active status cannot undo an observed revocation or enable another write', async t => {
  const {controller: c, services} = fixture(t); await c.open('edge');
  services.post = async () => response(revoked());
  await c.revoke();
  assert.equal(c.state.status, null); assert.equal(c.canRevoke(), false);
  c.close(); await c.open('edge'); assert.equal(c.canRevoke(), false);
  services.fetch = async () => response(status('edge', {revision: 4})); await c.refresh();
  assert.equal(c.state.status, null); assert.equal(c.canRevoke(), false);
});

for (const code of [400, 401, 403, 404, 409, 412]) test(`explicit ${code} rejection needs a fresh review`, async t => {
  const {controller: c, services} = fixture(t); await c.open('edge');
  services.post = async () => response({error: 'arbitrary private error'}, code); await c.revoke();
  assert.equal(c.state.blocked, false); assert.equal(c.canRevoke(), false); assert.equal(c.state.status, null);
  assert.doesNotMatch(c.state.message, /arbitrary private error/); await c.refresh(); assert.equal(c.canRevoke(), true);
});

test('a pending write survives navigation and updates only its own reopened device', async t => {
  const {controller: c, services, current} = fixture(t), write = gate();
  await c.open('edge'); services.post = () => write.promise;
  const action = c.revoke(); await Promise.resolve(); c.close(); await c.open('edge');
  assert.equal(c.state.busy, true); assert.equal(c.canRevoke(), false);
  current.set('edge', revoked()); write.resolve(response(revoked())); await action;
  assert.equal(c.state.busy, false); assert.equal(c.state.status.state, 'revoked');
  await c.open('other'); assert.equal(c.state.status.state, 'active'); assert.equal(c.canRevoke(), true);
});

test('leaving while confirmation is open sends no write or stale status to another device', async t => {
  const {controller: c, services, requests} = fixture(t), confirm = gate();
  await c.open('edge'); services.confirm = () => confirm.promise; const action = c.revoke();
  await c.open('other'); confirm.resolve(true); await action;
  assert.equal(requests.filter(item => item.body).length, 0); assert.equal(c.state.status.device_id, 'other');
});

test('stale status headers and bodies cannot populate a reopened drawer', async t => {
  const {controller: c, services} = fixture(t), read = gate();
  let signal; services.fetch = async (url, options) => { signal = options.signal; return {ok: true, json: () => read.promise}; };
  const first = c.open('edge'); await Promise.resolve(); c.close();
  assert.equal(signal.aborted, true); services.fetch = async () => response(status('other')); await c.open('other');
  read.resolve(revoked()); await first; assert.equal(c.state.status.device_id, 'other');
});

test('request identity failure does not send a write or lock future safe actions', async t => {
  const {controller: c, services, requests} = fixture(t); await c.open('edge'); services.uuid = () => 'bad';
  await c.revoke(); assert.equal(requests.filter(item => item.body).length, 0); assert.equal(c.state.blocked, false);
  assert.match(c.state.message, /Could not confirm/);
});

test('fresh onboarding confirmation preserves the old revocation and names the next action', () => {
  assert.match(reenrollmentConfirmation('edge'), /^Allow fresh onboarding for edge\?/);
  assert.match(reenrollmentConfirmation('edge'), /same inventory device.*permanently revoked.*does not change the device yet.*Run Onboard.*device you trust/s);
});

test('fresh onboarding approval pins old identity and does not start an onboarding job', async t => {
  const {controller: c, current, requests} = fixture(t); current.set('edge', revoked());
  await c.open('edge'); assert.equal(c.canReenroll(), true); assert.equal(c.canRevoke(), false);
  await c.reenroll();
  assert.deepEqual(requests[1], {url: '/api/v1/devices/edge/certificate/reenroll',
    body: {expected_revision: 3, expected_identity_sha256: identity, request_id: uuid}});
  assert.equal(c.state.status.state, 'reenrollment-required');
  assert.equal(c.state.status.identity_sha256, identity); assert.equal(c.canReenroll(), false);
  assert.equal(c.canRevoke(), false); assert.match(c.state.message, /Fresh onboarding approved.*old certificates remain revoked/);
  assert.equal(requests.filter(item => item.body).length, 1);
});

test('active, pending, non-TLS and unavailable devices cannot approve fresh onboarding', async t => {
  const {controller: c, services, requests} = fixture(t);
  for (const value of [status(), recovery(), revoked('edge', {peer_tls_required: false}), {}]) {
    services.fetch = async () => response(value); await c.open('edge'); await c.reenroll();
    assert.equal(c.canReenroll(), false);
  }
  assert.equal(requests.filter(item => item.body).length, 0);
});

test('cancelled fresh onboarding approval leaves the revoked device unchanged', async t => {
  const {controller: c, services, current, requests} = fixture(t); current.set('edge', revoked());
  await c.open('edge'); services.confirm = () => false; await c.reenroll();
  assert.equal(c.canReenroll(), true); assert.equal(c.state.status.state, 'revoked');
  assert.equal(requests.filter(item => item.body).length, 0);
});

test('unknown approval stays blocked after reopening and unchanged revoked state cannot reconcile it', async t => {
  const {controller: c, services, current, requests} = fixture(t); current.set('edge', revoked());
  await c.open('edge'); services.post = async (url, body) => { requests.push({url, body}); throw Error('lost'); };
  await c.reenroll(); assert.match(c.state.message, /fresh onboarding approval result is unknown/);
  c.close(); await c.open('edge'); assert.equal(c.canReenroll(), false);
  await c.reenroll(); assert.equal(requests.filter(item => item.body).length, 1);
  current.set('edge', recovery()); await c.refresh();
  assert.equal(c.pending.size, 0); assert.equal(c.state.blocked, false);
  assert.equal(c.state.status.state, 'reenrollment-required');
});

for (const variant of ['wrong request', 'wrong pending identity', 'same activated identity', 'stale revision']) {
  test(`approval reconciliation rejects ${variant}`, async t => {
    const {controller: c, services, current} = fixture(t); current.set('edge', revoked()); await c.open('edge');
    services.post = async () => { throw Error('lost'); }; await c.reenroll();
    const values = {'wrong request': recovery('edge', {recovery_request_id: '172a1100-abcd-4000-8000-000000000002'}),
      'wrong pending identity': recovery('edge', {identity_sha256: 'b'.repeat(64)}),
      'same activated identity': recovered('edge', {identity_sha256: identity}),
      'stale revision': recovery('edge', {revision: 3})};
    current.set('edge', values[variant]); await c.refresh();
    assert.equal(c.state.blocked, true); assert.equal(c.canReenroll(), false); assert.equal(c.canRevoke(), false);
  });
}

test('matching approval that already activated reconciles only a different certificate identity', async t => {
  const {controller: c, services, current} = fixture(t); current.set('edge', revoked()); await c.open('edge');
  services.post = async () => { throw Error('lost'); }; await c.reenroll();
  current.set('edge', recovered()); await c.refresh();
  assert.equal(c.pending.size, 0); assert.equal(c.state.blocked, false); assert.equal(c.canRevoke(), true);
  assert.match(c.state.message, /New device identity.*Activity.*previous certificates remain revoked/);
});

test('pending and newly active identities cannot regress to an earlier approval or revocation', async t => {
  const {controller: c, current} = fixture(t); current.set('edge', revoked()); await c.open('edge');
  await c.reenroll(); current.set('edge', recovered()); await c.refresh();
  assert.equal(c.canRevoke(), true);
  current.set('edge', recovery()); await c.refresh(); assert.equal(c.state.status, null); assert.equal(c.canRevoke(), false);
  current.set('edge', revoked()); await c.refresh(); assert.equal(c.canReenroll(), false);
});

test('pending fresh onboarding survives navigation without releasing the duplicate action lock', async t => {
  const {controller: c, services, current, requests} = fixture(t), waiting = gate();
  current.set('edge', revoked()); await c.open('edge');
  services.post = async (url, body) => { requests.push({url, body}); return waiting.promise; };
  const action = c.reenroll(); await Promise.resolve(); c.close(); await c.open('edge');
  assert.equal(c.state.busy, true); await c.reenroll(); assert.equal(requests.filter(item => item.body).length, 1);
  current.set('edge', recovery()); waiting.resolve(response(recovery())); await action;
  assert.equal(c.state.busy, false); assert.equal(c.state.status.state, 'reenrollment-required');
});

test('approval refusal invalidates the reviewed state without clearing its old revocation', async t => {
  const {controller: c, services, current} = fixture(t); current.set('edge', revoked()); await c.open('edge');
  services.post = async () => response({error: 'active jobs'}, 409); await c.reenroll();
  assert.equal(c.state.status, null); assert.equal(c.canReenroll(), false); assert.equal(c.state.blocked, false);
  await c.refresh(); assert.equal(c.state.status.state, 'revoked'); assert.equal(c.canReenroll(), true);
});

test('active-job approval refusal gives exact safe Activity guidance, not arbitrary upstream text', async t => {
  const {controller: c, services, current} = fixture(t); current.set('edge', revoked()); await c.open('edge');
  services.post = async () => response({error: 'Finish or cancel this device\'s current job before approving fresh onboarding'}, 409);
  await c.reenroll(); assert.match(c.state.message, /Finish or cancel.*Activity.*check certificate status/);
  await c.refresh(); services.post = async () => response({error: '<private unrelated error>'}, 409);
  await c.reenroll(); assert.doesNotMatch(c.state.message, /private|Activity/);
});

for (const action of ['revoke', 'reenroll']) test(`unknown ${action} can be superseded by a newer identity without claiming success`, async t => {
  const {controller: c, services, current, requests} = fixture(t);
  if (action === 'reenroll') current.set('edge', revoked());
  await c.open('edge'); services.post = async (url, body) => { requests.push({url, body}); throw Error('lost'); };
  await c.act(action);
  const next = recovered('edge', {recovery_request_id: '172a1100-abcd-4000-8000-000000000002'});
  current.set('edge', next); await c.refresh();
  assert.equal(c.state.blocked, false); assert.equal(c.pending.size, 0); assert.equal(c.canRevoke(), true);
  assert.match(c.state.message, /different certificate identity.*earlier request is no longer current/);
  assert.doesNotMatch(c.state.message, /saved|approved/);
  assert.equal(requests.filter(item => item.body).length, 1);
  // A stale GET or a delayed old-body resolution cannot put the old identity
  // back into a reviewed action after the newer identity has been observed.
  const stale = gate(); services.fetch = () => stale.promise;
  const oldRead = c.refresh(); c.close(); services.fetch = async () => response(next); await c.open('edge');
  stale.resolve(response(revoked())); await oldRead;
  assert.equal(c.state.status.identity_sha256, 'b'.repeat(64));
  current.set('edge', status()); services.fetch = async () => response(status()); await c.refresh();
  assert.equal(c.state.status, null); assert.equal(c.canRevoke(), false);
  services.fetch = async () => response(next); await c.refresh();
  services.confirm = () => false; await c.revoke(); assert.equal(requests.filter(item => item.body).length, 1);
});

const observation = extra => ({supported: true, mode: 'required', state: 'valid', authority: 'c'.repeat(64),
  revision: 2, issued_at: 1999999990, expires_at: 2000000290, own_revoked: false, observed_at: 2000000000, ...extra});
test('native observation is bounded device-reported evidence, never fleet-wide confirmation', () => {
  const value = runtimeObservation(observation(), 2000000000, 2000000000);
  assert.equal(value.label, 'Reported current'); assert.match(value.detail, /device reports/);
  assert.equal(value.values.revision, 2); assert.equal(value.values.authority, 'c'.repeat(64));
  assert.match(runtimeObservation(observation({own_revoked: true}), 2000000000, 2000000000).detail, /own certificate is revoked/);
});

for (const extra of [{supported: false}, {mode: 'unexpected'}, {authority: '<script>'}, {authority: 'c'.repeat(64) + '\n'}, {revision: -1},
  {revision: Number.MAX_SAFE_INTEGER + 1}, {expires_at: 2000000300}, {observed_at: Infinity},
  {observed_at: 9007199254740991}, {extra: 'unbounded'}, {own_revoked: 'true'},
  {state: 'valid', authority: null, revision: null, issued_at: null, expires_at: null}]) {
  test('invalid native observation is not rendered: ' + JSON.stringify(extra), () => {
    const value = runtimeObservation(observation(extra), 2000000000, 2000000000);
    assert.equal(value.label, 'Not confirmed'); assert.equal(value.values, null);
  });
}

test('stale, expired, future and disabled native reports are explicitly not confirmed', () => {
  for (const [value, now, seen] of [[observation(), 2000000300, 2000000300],
    [observation(), 2000000000, 1999999600], [observation({observed_at: 2000000040}), 2000000000, 2000000000],
    [observation({state: 'expired'}), 2000000000, 2000000000],
    [observation({mode: 'disabled', state: 'unavailable'}), 2000000000, 2000000000],
    [observation({state: 'unavailable', authority: null, revision: null, issued_at: null, expires_at: null}), 2000000000, 2000000000]]) {
    assert.equal(runtimeObservation(value, now, seen).label, 'Not confirmed');
  }
});
