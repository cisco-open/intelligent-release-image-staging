// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {CertificatesController} from '../src/certificates-controller.mjs';
import {checkedInventory, checkedSigner, checkedRenewalRequest, checkedRenewal, retirementPayload, approvalBody,
  APPROVAL_BODY_LIMIT, publicApproval, checkedSignerResult, refusedCertificateMessage} from '../src/certificates-model.mjs';
const id = '11111111-1111-4111-8111-111111111111', otherId = '22222222-2222-4222-8222-222222222222';
const publicKey = 'ssh-ed25519 AAAA public fixture\n', oldKey = 'ssh-ed25519 BBBB public fixture\n';
const certificate = 'ssh-ed25519-cert-v01@openssh.com AAAA public approval\n';
const idle = () => ({state: 'idle', request_id: null, previous_public_key: null, public_key: null, previous_sha256: null,
  replacement_sha256: null, created_at: null, activated_at: null, retired_keylist_seq: null, root_ids: ['root-a', 'root-b']});
const signer = (state = 'awaiting-approval', request_id = id) => ({...idle(), state, request_id, previous_public_key: oldKey, public_key: publicKey,
  previous_sha256: 'aa'.repeat(32), replacement_sha256: 'bb'.repeat(32), created_at: 100,
  activated_at: ['committing', 'retirement-pending', 'retiring', 'completed'].includes(state) ? 200 : null,
  retired_keylist_seq: state === 'completed' ? 8 : null});
const inventory = () => ({scope: 'server-certificate-files', observed_at: 100, custody: null, items: [
  {id: 'online-key', label: 'Online public key', kind: 'public-key', source: 'server-file', state: 'public-key-present', fingerprint_sha256: 'SHA256:fixture',
    valid_from: null, renew_at: null, expires_at: null, refuse_at: null, impact: 'Public key does not expire.'}]});
const renewalRequest = () => ({public_key: publicKey, public_key_sha256: 'ab'.repeat(32), certificate_sha256: 'cd'.repeat(32)});
const renewed = () => ({applied: true, expires_at: 2592100, refuse_at: 1987300, status_refreshed: true});
const file = raw => ({size: Buffer.byteLength(raw), text: async () => raw});
const reply = (data, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => structuredClone(data)});
const deferred = () => {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};};
const retirement = root => 'IRIS-KEYLIST/1\n' + btoa(JSON.stringify({v: 1, keylist_seq: 8, issued_at: 200, signer_root_id: root, krl_sha256: 'ab'.repeat(32)})) + '\n' + btoa('SSHKRL\n\x00fixture') + '\n';
function setup(initial = idle()) {
  const c = new CertificatesController(), f = {visible: true, status: initial, inventory: inventory(), writes: [], downloads: [], confirms: [], read: null, post: null, accept: true};
  c.connect({visible: () => f.visible, uuid: () => id, formatDate: String, confirm: text => {f.confirms.push(text); return f.accept;},
    headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), download: (name, bytes) => f.downloads.push({name, bytes}),
    fetch: async (path, options = {}) => {
      if (!options.method) return f.read ? f.read(path, options) : reply(path.endsWith('/rotation') ? f.status : f.inventory);
      assert.equal(options.headers['X-CSRF-Token'], 'fixture'); const body = JSON.parse(options.body); f.writes.push({path, body});
      if (f.post) return f.post(path, body);
      if (path.endsWith('/request')) return reply(renewalRequest());
      if (path.endsWith('/renew')) return reply(renewed());
      if (body.action === 'retirement-request') return reply({request_id: body.request_id, root_id: body.root_id, payload: btoa(retirement(body.root_id))});
      f.status = signer({prepare: 'awaiting-approval', activate: 'retirement-pending', cancel: 'cancelled', retire: 'completed'}[body.action], body.request_id);
      return reply(f.status);
    }});
  return {c, f};
}
test('native observation schema preserves unknown custody and public keys without invented expiry', () => {
  assert.ok(checkedInventory(inventory()));
  assert.equal(checkedInventory({...inventory(), items: []}), false);
  for (const change of [row => {row.items[0].expires_at = 100;}, row => {row.items.push(row.items[0]);}, row => {row.observed_at = '100';}, row => {row.scope = 'listener';}, row => {row.items[0].state = 'trusted';}]) {
    const row = inventory(); change(row); assert.equal(checkedInventory(row), false);
  }
});
for (const state of ['idle', 'awaiting-approval', 'committing', 'retirement-pending', 'retiring', 'completed', 'cancelled']) test('native signer schema: ' + state, () => {
  assert.equal(checkedSigner(state === 'idle' ? idle() : signer(state)), true);
});
for (const [key, value] of [['request_id', 'short'], ['public_key', 'PRIVATE KEY'], ['previous_sha256', null], ['replacement_sha256', 'aa'.repeat(32)],
  ['created_at', '100'], ['root_ids', ['root-a', 'root-a']], ['activated_at', 1], ['retired_keylist_seq', 8]]) test('reject malformed signer ' + key, () => {
  assert.equal(checkedSigner({...signer(), [key]: value}), false);
});
test('renewal responses need real booleans, dates and guards', () => {
  assert.equal(checkedRenewalRequest(renewalRequest()), true); assert.equal(checkedRenewal(renewed()), true);
  assert.equal(checkedRenewal({...renewed(), applied: 'false'}), false);
  assert.equal(checkedRenewal({...renewed(), expires_at: 'soon'}), false);
  assert.equal(checkedRenewal({...renewed(), refuse_at: 1}), false);
  assert.equal(checkedRenewal({...renewed(), status_refreshed: 'yes'}), false);
  assert.equal(checkedRenewalRequest({...renewalRequest(), public_key: 'ssh-ed25519 PRIVATE KEY'}), false);
});
test('known approval refusals give next steps without echoing arbitrary server text', () => {
  assert.match(refusedCertificateMessage(409, {error: 'online certificate changed; prepare renewal again'}), /certificate changed/);
  assert.match(refusedCertificateMessage(409, {error: 'keylist changed; prepare retirement again'}), /Download and approve a fresh retirement/);
  assert.match(refusedCertificateMessage(403, {}), /Sign in again/);
  assert.doesNotMatch(refusedCertificateMessage(409, {error: 'PRIVATE KEY sentinel'}), /sentinel|PRIVATE/);
  assert.equal(typeof refusedCertificateMessage(409, {error: 'constructor'}), 'string');
});
test('public approval rejects multiline/private/unicode content before networking', () => {
  assert.equal(publicApproval(certificate, 'renew'), certificate);
  for (const raw of [certificate + certificate, 'PRIVATE KEY', certificate + 'é', certificate + '\u0000']) assert.throws(() => publicApproval(raw, 'activate'));
  assert.throws(() => publicApproval('IRIS-KEYLIST/1\nPRIVATE KEY', 'retire'));
});
test('192 KiB encoded bound allows native 128 KiB envelopes but rejects oversized JSON', () => {
  const header = 'IRIS-KEYLIST/1\n', raw = header + 'a'.repeat(128 * 1024 - header.length);
  const body = approvalBody({action: 'retire', request_id: id, confirm: true, artifact: publicApproval(raw, 'retire')});
  assert.ok(body.length > 64 * 1024 && body.length <= APPROVAL_BODY_LIMIT);
  assert.throws(() => approvalBody({value: 'x'.repeat(APPROVAL_BODY_LIMIT)}));
});
test('retirement download binds ID/root/metadata and public framing', () => {
  const payload = {request_id: id, root_id: 'root-a'}, data = {...payload, payload: btoa(retirement('root-a'))};
  assert.equal(Buffer.from(retirementPayload(data, payload)).toString(), retirement('root-a'));
  for (const bad of [{...data, request_id: otherId}, {...data, root_id: 'root-b'}, {...data, payload: btoa(retirement('root-b'))}, {...data, payload: btoa('garbage')}, {...data, payload: data.payload + '\n'}]) assert.throws(() => retirementPayload(bad, payload));
});
test('complete public rotation preserves original request and explicit approvals', async () => {
  const {c, f} = setup(); await c.refreshAll();
  await c.perform('prepare'); assert.equal(c.state.signer.state, 'awaiting-approval'); c.downloadSigner();
  assert.equal(f.downloads[0].name, 'iris-replacement.pub');
  c.file('activate', file(certificate)); await c.perform('activate'); assert.equal(c.state.signer.state, 'retirement-pending');
  c.root('root-b'); await c.perform('retirement-request'); assert.equal(f.downloads[1].name, 'keylist.payload');
  c.file('retire', file('IRIS-KEYLIST/1\npublic approval')); await c.perform('retire');
  assert.equal(c.state.signer.state, 'completed'); assert.match(c.state.messages.signer.text, /Verify fleet acceptance/);
  assert.ok(f.writes.every(row => row.body.request_id === id)); assert.equal(f.writes[1].body.confirm, true); assert.equal(f.writes[3].body.confirm, true);
  assert.equal(f.confirms.length, 3); assert.deepEqual(c.state.files, {});
});
for (const action of ['prepare', 'activate', 'retire', 'cancel']) test(action + ' rejects valid but wrong state or request identity', async () => {
  const start = action === 'prepare' ? idle() : signer(action === 'retire' ? 'retirement-pending' : 'awaiting-approval');
  const payload = {request_id: id};
  assert.equal(checkedSignerResult(action, payload, start, start), false);
  const end = signer({prepare: 'awaiting-approval', activate: 'retirement-pending', retire: 'completed', cancel: 'cancelled'}[action], otherId);
  assert.equal(checkedSignerResult(action, payload, start, end), false);
});
test('success with different signer bytes is not accepted even with same request ID', () => {
  assert.equal(checkedSignerResult('activate', {request_id: id}, signer(), {...signer('retirement-pending'), public_key: oldKey}), false);
});
test('HTTP accepted is not a synchronous signer completion, even with a plausible body', async () => {
  const {c, f} = setup(signer()); await c.refreshAll();
  f.post = async () => reply(signer('retirement-pending'), 202); c.file('activate', file(certificate)); await c.perform('activate');
  assert.equal(c.state.unknown.signer, true); assert.match(c.state.messages.signer.text, /Outcome unknown/);
});
for (const failure of ['network', 'html', 'empty', 'wrong-state', 'wrong-id', '503', '409']) test('uncertain activation requires explicit read: ' + failure, async () => {
  const {c, f} = setup(signer()); await c.refreshAll(); c.file('activate', file(certificate));
  f.post = async () => {
    if (failure === 'network') throw Error('PRIVATE KEY sentinel');
    if (failure === 'html') return {ok: false, status: 502, json: async () => {throw Error();}};
    return reply(failure === 'empty' ? {} : failure === 'wrong-state' ? signer() : failure === 'wrong-id' ? signer('retirement-pending', otherId) : {error: 'PRIVATE KEY sentinel'}, Number(failure) || 200);
  };
  await c.perform('activate'); assert.equal(c.state.unknown.signer, true); assert.doesNotMatch(c.state.messages.signer.text, /Replacement signer active|PRIVATE KEY|sentinel/);
  await c.refreshAll(); c.hide(); await c.refreshAll(); c.file('activate', file(certificate)); await c.perform('activate'); assert.equal(f.writes.length, 1);
  await c.refresh('signer', true); assert.equal(c.state.unknown.signer, false); assert.deepEqual(c.state.files, {});
  f.post = null; c.file('activate', file(certificate)); await c.perform('activate'); assert.equal(f.writes.length, 2); assert.equal(c.state.signer.state, 'retirement-pending');
});
test('lost prepare reuses its ID after explicit idle review, never automatically posts', async () => {
  const {c, f} = setup(); await c.refreshAll(); let generated = 0;
  c.services.uuid = () => {generated++; return id;}; f.post = async () => {throw Error();};
  await c.perform('prepare'); await c.refreshAll(); assert.equal(f.writes.length, 1);
  await c.refresh('signer', true); f.post = null; await c.perform('prepare'); assert.equal(generated, 1);
  assert.equal(f.writes[0].body.request_id, f.writes[1].body.request_id);
});
test('lost prepare found on server resumes approval without preparing another key', async () => {
  const {c, f} = setup(); await c.refreshAll(); f.post = async () => {f.status = signer(); throw Error();};
  await c.perform('prepare'); await c.refresh('signer', true); await c.perform('prepare');
  assert.equal(f.writes.length, 1); assert.equal(c.state.signer.state, 'awaiting-approval'); assert.equal(c.pendingId, null);
});
test('double click cannot overlap asynchronous file validation', async () => {
  const {c, f} = setup(signer()), pending = deferred(); await c.refreshAll();
  c.file('activate', {size: 100, text: () => pending.promise}); const first = c.perform('activate');
  await c.perform('activate'); await c.perform('cancel'); c.file('activate', file('PRIVATE KEY'));
  assert.equal(c.state.busy, true); pending.resolve(certificate); await first; assert.equal(f.writes.length, 1);
});
test('navigation while reading approval cancels unsent action and clears file', async () => {
  const {c, f} = setup(signer()), pending = deferred(); await c.refreshAll();
  c.file('activate', {size: 100, text: () => pending.promise}); const work = c.perform('activate');
  c.hide(); f.visible = false; pending.resolve(certificate); await work;
  assert.equal(f.writes.length, 0); assert.deepEqual(c.state.files, {}); assert.equal(c.state.busy, false);
  assert.match(c.state.messages.signer.text, /not submitted/);
});
test('navigation after submission never cancels write or allows another mutation', async () => {
  const {c, f} = setup(signer()), pending = deferred(); await c.refreshAll();
  f.post = () => pending.promise; c.file('activate', file(certificate)); const work = c.perform('activate');
  await new Promise(resolve => setImmediate(resolve)); c.hide(); f.visible = false;
  assert.equal(c.state.busy, true); f.status = signer('retirement-pending'); pending.resolve(reply(f.status)); await work;
  assert.equal(f.writes.length, 1); assert.match(c.state.messages.signer.text, /Replacement signer active/); assert.equal(c.state.valid.signer, undefined);
  f.visible = true; await c.refreshAll(); assert.equal(c.state.signer.state, 'retirement-pending');
});
test('hidden public request completion neither downloads nor restores renewal approval', async () => {
  const {c, f} = setup(), pending = deferred(); f.post = () => pending.promise;
  const work = c.renewalRequest(); c.hide(); f.visible = false; pending.resolve(reply(renewalRequest())); await work;
  assert.equal(c.state.request, null); assert.equal(f.downloads.length, 0);
  assert.match(c.state.messages.renew.text, /Download a fresh request/);
});
test('hidden retirement request completion does not trigger file download', async () => {
  const {c, f} = setup(signer('retirement-pending')), pending = deferred(); await c.refreshAll();
  f.post = () => pending.promise; const work = c.perform('retirement-request'); c.hide(); f.visible = false;
  pending.resolve(reply({request_id: id, root_id: 'root-a', payload: btoa(retirement('root-a'))})); await work;
  assert.equal(f.downloads.length, 0); assert.match(c.state.messages.signer.text, /Download it again/);
});
test('superseded explicit review cannot clear unknown-write gate', async () => {
  const {c, f} = setup(signer()), pending = deferred(); await c.refreshAll(); c.update({unknown: {signer: true}});
  f.read = () => pending.promise; const old = c.refresh('signer', true); f.read = null;
  await c.refresh('signer'); pending.resolve(reply(signer())); await old; assert.equal(c.state.unknown.signer, true);
});
test('pre-write status reply cannot replace completed action state', async () => {
  const {c, f} = setup(), pending = deferred(); await c.refreshAll();
  // A late inventory read is invalidated along with signer reads at submission.
  f.read = path => path.endsWith('/rotation') ? reply(f.status) : pending.promise;
  const old = c.refresh('inventory'); f.read = null; await c.perform('prepare'); pending.resolve(reply({})); await old;
  assert.equal(c.state.signer.state, 'awaiting-approval'); assert.equal(c.state.valid.inventory, true);
});
test('status unavailable removes stale authority and rejects mutation', async () => {
  const {c, f} = setup(signer()); await c.refreshAll(); f.read = async () => reply({}, 503); await c.refreshAll();
  assert.equal(c.state.inventory, null); assert.equal(c.state.signer, null); await c.perform('cancel'); assert.equal(f.writes.length, 0);
  f.read = null; await c.refreshAll(); assert.equal(c.state.messages.signer, null, 'Recovered read clears its old error');
});
test('a failed follow-up read cannot erase the confirmed or unknown mutation result', async () => {
  const {c, f} = setup(); await c.refreshAll(); f.read = async () => reply({}, 503);
  await c.perform('prepare'); assert.match(c.state.messages.signer.text, /Replacement prepared/); assert.equal(c.state.valid.signer, false);
  f.read = null; await c.refreshAll(); c.file('activate', file(certificate)); f.post = async () => reply({});
  f.read = async () => reply({}, 503); await c.perform('activate'); assert.match(c.state.messages.signer.text, /Outcome unknown/);
  f.read = null; await c.refreshAll(); assert.match(c.state.messages.signer.text, /Outcome unknown/); assert.equal(c.state.unknown.signer, true);
});
test('same-key renewal sends original guards and strictly reports confirmed deadline', async () => {
  const {c, f} = setup(); await c.renewalRequest(); assert.equal(f.downloads[0].name, 'iris-online.pub');
  c.file('renew', file(certificate)); await c.perform('renew');
  assert.deepEqual(f.writes[1].body, {certificate, public_key_sha256: 'ab'.repeat(32), certificate_sha256: 'cd'.repeat(32)});
  assert.match(c.state.messages.renew.text, /Renewal applied/); assert.equal(c.state.request, null);
});
test('uncertain renewal blocks stale approval and requires new public guards', async () => {
  const {c, f} = setup(); await c.renewalRequest(); c.file('renew', file(certificate)); f.post = async () => reply({...renewed(), applied: 'true'});
  await c.perform('renew'); assert.equal(c.state.unknown.renew, true); assert.equal(c.state.request, null);
  await c.refreshAll(); await c.perform('renew'); assert.equal(f.writes.length, 2);
  f.post = null; await c.renewalRequest(); assert.equal(c.state.unknown.renew, false); c.file('renew', file(certificate)); await c.perform('renew');
  assert.match(c.state.messages.renew.text, /Renewal applied/);
});
test('declined confirmation preserves approval without any write', async () => {
  const {c, f} = setup(signer()); await c.refreshAll(); const approval = file(certificate); c.file('activate', approval); f.accept = false;
  await c.perform('activate'); assert.equal(f.writes.length, 0); assert.equal(c.state.files.activate, approval);
});
test('oversized or unreadable files do not POST and leave controller usable', async () => {
  const {c, f} = setup(signer()); await c.refreshAll();
  for (const approval of [{size: 65537}, {size: 50, text: async () => 'a'.repeat(65537)}, {size: 50, text: async () => {throw Error('File unavailable');}}]) {
    c.file('activate', approval); await c.perform('activate'); assert.equal(c.state.busy, false);
  }
  assert.equal(f.writes.length, 0);
});
test('public download failure does not masquerade as a failed committed rotation', async () => {
  const {c, f} = setup(signer('retirement-pending')); await c.refreshAll(); c.services.download = () => {throw Error();};
  await c.perform('retirement-request'); assert.equal(f.writes.length, 1); assert.match(c.state.messages.signer.text, /Download unavailable/); assert.equal(c.state.unknown.signer, undefined);
});
