// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {SecurityLifecycleController} from '../src/security-lifecycle-controller.mjs';
import {normalizeNames, publicPem, browserStatus, checkedTlsResult, collectorEndpoint, collectorHeaders, metricsToken,
  credentialStatus, checkedCredentialResult, lifecycleBody, TLS_BODY_LIMIT} from '../src/security-lifecycle-model.mjs';
const id = '11111111-1111-4111-8111-111111111111', another = '22222222-2222-4222-8222-222222222222';
const csr = '-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n';
const certificate = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
const changedCertificate = '-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n';
const hash = 'ab'.repeat(32), token = 'fixture-secret-value'.repeat(3);
const idle = () => ({state: 'idle', request_id: null, names: [], mode: null, csr: null, certificate: null, created_at: null, fingerprint_sha256: null});
const tls = (state = 'approved', mode = 'ca') => ({...idle(), state, request_id: id, names: ['console.example'], mode, csr, created_at: 100,
  certificate: state === 'awaiting-approval' ? null : certificate, fingerprint_sha256: state === 'awaiting-approval' ? null : hash});
const credentials = () => ({items: ['metrics-token', 'collector-headers'].map(family => ({family, request_id: null, state: 'deployment-managed', previous_retained: false, started_at: null, observed_at: null, endpoint: null}))});
const active = (family = 'metrics-token', state = 'awaiting-verification') => ({family, state, request_id: id, started_at: 100, observed_at: null,
  previous_retained: state === 'awaiting-verification', endpoint: family === 'collector-headers' && state !== 'reverted' ? 'https://collector.example' : null});
const file = text => ({size: Buffer.byteLength(text), text: async () => text});
const response = (body, status = 200) => ({status, ok: status >= 200 && status < 300, json: async () => structuredClone(body)});
const deferred = () => {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};};
function setup(initial = idle(), initialCredentials = credentials()) {
  const c = new SecurityLifecycleController(), f = {tls: initial, credentials: initialCredentials, visible: true, writes: [], downloads: [], read: null, post: null, accept: true};
  c.connect({visible: () => f.visible, uuid: () => id, hostname: 'console.example', randomToken: () => 'ab'.repeat(32), formatDate: String,
    confirm: () => f.accept, headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), download: (name, bytes) => f.downloads.push({name, bytes}),
    fetch: async (path, options = {}) => {
      if (!options.method) return f.read ? f.read(path, options) : response(path.endsWith('/rotation') ? f.tls : f.credentials);
      assert.equal(options.headers['X-CSRF-Token'], 'fixture'); const body = JSON.parse(options.body); f.writes.push({path, body});
      if (f.post) return f.post(path, body);
      if (path.endsWith('/rotation')) {
        if (body.action === 'prepare') f.tls = {...tls(body.mode === 'ca' ? 'awaiting-approval' : 'approved', body.mode), request_id: body.request_id, names: body.names};
        if (body.action === 'approve') f.tls = {...f.tls, state: 'approved', certificate: body.certificate, fingerprint_sha256: hash};
        if (body.action === 'cancel') f.tls = {...f.tls, state: 'cancelled'};
        if (body.action === 'apply') {f.tls = {...f.tls, state: 'published'}; return response({...f.tls, applied: true, gui_cert: {source: 'custom', fingerprint_sha256: hash}});}
        return response(f.tls);
      }
      const item = f.credentials.items.find(row => row.family === body.family);
      if (body.action === 'replace') Object.assign(item, active(body.family), {request_id: body.request_id, endpoint: body.endpoint || null});
      else Object.assign(item, {state: body.action === 'revert' ? 'reverted' : 'completed', previous_retained: false,
        ...(body.action === 'revert' ? {endpoint: null, observed_at: null} : {})});
      return response(f.credentials);
    }});
  return {c, f};
}
test('names canonicalize DNS and IPv6, sort and reject duplicate or injected identities', () => {
  assert.deepEqual(normalizeNames('Console.Example, 2001:0DB8:0:0::1, 192.0.2.1'), ['192.0.2.1', '2001:db8::1', 'console.example']);
  for (const names of ['', 'a,A', '*.example', 'https://host', 'host..example', 'fe80::1%eth0', '[::1]', ['a\nx=1'], Array(17).fill('a')]) assert.throws(() => normalizeNames(names));
});
test('public PEM is bounded, public only, normalized, with at most eight certificates', () => {
  assert.equal(publicPem(certificate.replaceAll('\n', '\r\n')), certificate);
  assert.equal(publicPem(csr, 'CERTIFICATE REQUEST'), csr);
  for (const input of [certificate + 'PRIVATE KEY', certificate + 'junk', csr, certificate.repeat(9), '-----BEGIN CERTIFICATE-----\nno closing', 'x'.repeat(65537)]) assert.throws(() => publicPem(input));
});
test('PEM normalization checks the stored limit, including its final newline', () => {
  const prefix = '-----BEGIN CERTIFICATE-----\n', suffix = '\n-----END CERTIFICATE-----';
  const bytes = 65536 - prefix.length - suffix.length;
  assert.throws(() => publicPem(prefix + 'A'.repeat(bytes) + suffix), /normalized.*size limit/);
  assert.equal(publicPem(prefix + 'A'.repeat(bytes - 1) + suffix).length, 65536);
});
test('TLS schema accepts all native states and strips nonpublic response fields', () => {
  assert.deepEqual(browserStatus(idle()), idle());
  for (const state of ['awaiting-approval', 'approved', 'committing', 'published', 'cancelled']) assert.ok(browserStatus(tls(state)));
  assert.equal(browserStatus({...tls(), ciphertext: 'private-placeholder'}).ciphertext, undefined);
});
for (const [field, value] of [['request_id', null], ['csr', certificate], ['certificate', null], ['created_at', '100'], ['names', ['Console.Example']], ['fingerprint_sha256', 'bad']]) test('TLS rejects malformed ' + field, () => {
  assert.equal(browserStatus({...tls(), [field]: value}), null);
});
test('TLS result binds request, name set, CSR, approval bytes and listener fingerprint', () => {
  const payload = {action: 'apply', request_id: id}, good = {...tls('published'), applied: true, gui_cert: {source: 'custom', fingerprint_sha256: hash}};
  assert.equal(checkedTlsResult(payload, tls(), good).reloaded, true);
  assert.equal(checkedTlsResult(payload, tls(), {...good, applied: false}).reloaded, false);
  for (const bad of [{...good, request_id: another}, {...good, state: 'approved'}, {...good, names: ['other.example']}, {...good, csr: csr.replace('AAAA', 'BBBB')},
    {...good, certificate: changedCertificate}, {...good, applied: 'true'}, {...good, gui_cert: null}, {...good, gui_cert: {source: 'custom', fingerprint_sha256: 'cd'.repeat(32)}}]) assert.equal(checkedTlsResult(payload, tls(), bad), null);
  assert.equal(checkedTlsResult({action: 'approve', request_id: id, certificate: changedCertificate}, tls('awaiting-approval'), tls()), null);
});
test('credential schema requires unique families and request-bound proof dates without secret readback', () => {
  assert.ok(credentialStatus(credentials()));
  const state = credentials(); state.items[0] = {...active(), token}; assert.equal(credentialStatus(state).items[0].token, undefined);
  assert.equal(credentialStatus({items: [active(), active()]}), null);
  assert.equal(credentialStatus({items: [{...active(), observed_at: 99}, state.items[1]]}), null);
  assert.equal(credentialStatus({items: [{...active('metrics-token', 'completed'), previous_retained: true}, state.items[1]]}), null);
});
test('service result cannot confirm unchanged deployment-managed, wrong ID, family or destination', () => {
  const before = credentials().items[0], payload = {action: 'replace', family: 'metrics-token', request_id: id, token};
  assert.equal(checkedCredentialResult(payload, before, credentials()), null);
  const state = credentials(); state.items[0] = active(); assert.ok(checkedCredentialResult(payload, before, state));
  state.items[0].request_id = another; assert.equal(checkedCredentialResult(payload, before, state), null);
  state.items[0] = active(); state.items[1] = active('collector-headers');
  assert.equal(checkedCredentialResult({...payload, family: 'collector-headers', endpoint: 'https://other.example'}, before, state), null);
});
test('collector credentials validate destination, header names, printable values and aggregate bounds', () => {
  assert.equal(collectorEndpoint('https://collector.example:4318/'), 'https://collector.example:4318');
  for (const endpoint of ['http://collector.example', 'https:collector.example', 'https://name:secret@collector.example', 'https://collector.example?token=secret', 'https://collector.example/#fragment', 'https://collector.example:99999']) assert.throws(() => collectorEndpoint(endpoint));
  assert.deepEqual({...collectorHeaders([{name: 'Authorization', value: 'Bearer fixture'}])}, {authorization: 'Bearer fixture'});
  for (const rows of [[{name: 'Host', value: 'host'}], [{name: 'Authorization', value: 'bad\nvalue'}], [{name: 'X-Test', value: 'a'}, {name: 'x-test', value: 'b'}], Array.from({length: 5}, (_, i) => ({name: 'x-' + i, value: 'a'.repeat(4096)}))]) assert.throws(() => collectorHeaders(rows));
  assert.equal(metricsToken(token), true); assert.equal(metricsToken(token + '\n'), false);
});
test('PEM JSON allowance is scoped and covers escaped newlines without widening credential requests', () => {
  const body = lifecycleBody({certificate: 'a\n'.repeat(32740)}, 'tls'); assert.ok(body.length > 65536 && body.length < TLS_BODY_LIMIT);
  assert.throws(() => lifecycleBody({value: 'a'.repeat(65536)}, 'credentials'));
});
test('complete CA approval/publication workflow uses public requests and distinct local listener evidence', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('names', 'CONSOLE.EXAMPLE'); await c.perform('tls', 'prepare');
  assert.equal(c.state.tls.state, 'awaiting-approval'); c.download('csr'); assert.equal(f.downloads[0].name, 'iris-console.csr');
  c.file(file(certificate)); await c.perform('tls', 'approve'); assert.equal(c.state.tls.state, 'approved'); c.download('certificate');
  await c.perform('tls', 'apply'); assert.equal(c.state.tls.state, 'published'); assert.match(c.state.messages.tls.text, /listener reloaded/);
  assert.ok(f.writes.every(row => row.body.request_id === id)); assert.equal(c.state.tls.gui_cert, undefined);
});
test('self-signed preparation requires explicit confirmation and can cancel before publication', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('mode', 'self-signed'); f.accept = false; await c.perform('tls', 'prepare'); assert.equal(f.writes.length, 0);
  f.accept = true; await c.perform('tls', 'prepare'); assert.equal(c.state.tls.state, 'approved'); assert.equal(c.canTls('approve'), false);
  await c.perform('tls', 'cancel'); assert.equal(c.state.tls.state, 'cancelled');
});
for (const state of ['approved', 'committing', 'published']) test('publication/recovery/reload is explicit for ' + state, async () => {
  const {c, f} = setup(tls(state)); await c.refreshAll();
  f.post = async () => {f.tls = tls('published'); return response({...f.tls, applied: false});};
  await c.perform('tls', 'apply'); assert.match(c.state.messages.tls.text, /has not confirmed reload/); assert.equal(f.writes.length, 1);
  await c.refreshAll(); assert.equal(f.writes.length, 1);
});
for (const fault of ['wrong-state', 'wrong-id', 'empty', 'network', '202', '409', '503']) test('TLS unknown/refused write requires explicit latest evidence: ' + fault, async () => {
  const {c, f} = setup(tls()); await c.refreshAll();
  f.post = async () => {
    if (fault === 'network') throw Error('private-placeholder');
    const good = {...tls('published'), applied: false};
    return response(fault === 'wrong-state' ? {...tls(), applied: true} : fault === 'wrong-id' ? {...good, request_id: another} : fault === 'empty' ? {} : good, Number(fault) || 200);
  };
  await c.perform('tls', 'apply'); assert.equal(c.state.unknown.tls, true); assert.doesNotMatch(c.state.messages.tls.text, /published|private-placeholder/);
  c.hide(); await c.refreshAll(); await c.perform('tls', 'apply'); assert.equal(f.writes.length, 1);
  await c.refresh('tls', true); assert.equal(c.state.unknown.tls, false); f.post = null; await c.perform('tls', 'apply'); assert.equal(f.writes.length, 2);
});
test('lost TLS prepare reuses public parameters and request ID after explicit idle evidence', async () => {
  const {c, f} = setup(); await c.refreshAll(); let count = 0; c.services.uuid = () => {count++; return id;};
  f.post = async () => {throw Error();}; await c.perform('tls', 'prepare'); await c.refreshAll(); await c.perform('tls', 'prepare'); assert.equal(f.writes.length, 1);
  await c.refresh('tls', true); f.post = null; await c.perform('tls', 'prepare'); assert.equal(count, 1); assert.equal(f.writes[1].body.request_id, id);
});
test('double file submission is serialized before file.text and navigation discards unsent approval', async () => {
  const {c, f} = setup(tls('awaiting-approval')), pending = deferred(); await c.refreshAll();
  c.file({size: 50, text: () => pending.promise}); const work = c.perform('tls', 'approve'); await c.perform('tls', 'approve');
  c.hide(); f.visible = false; pending.resolve(certificate); await work; assert.equal(f.writes.length, 0); assert.equal(c.state.file, null);
  assert.match(c.state.messages.tls.text, /not submitted/);
});
test('a submitted TLS write survives hiding and does not replay on return', async () => {
  const {c, f} = setup(tls()), pending = deferred(); await c.refreshAll(); f.post = () => pending.promise;
  const work = c.perform('tls', 'apply'); c.hide(); f.visible = false; assert.equal(c.state.busy, true);
  f.tls = tls('published'); pending.resolve(response({...f.tls, applied: false})); await work;
  f.visible = true; await c.refreshAll(); assert.equal(f.writes.length, 1); assert.match(c.state.messages.tls.text, /has not confirmed reload/);
});
test('metrics replacement clears secrets at dispatch and retirement requires observed use', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.generateToken(); c.download('token'); assert.equal(f.downloads[0].name, 'iris-metrics-token');
  c.field('token', token); const pending = deferred(); f.post = () => pending.promise; const work = c.perform('credentials', 'replace');
  assert.equal(c.state.token, ''); assert.doesNotMatch(JSON.stringify(c.pending) + JSON.stringify(c.state), new RegExp(token));
  f.credentials.items[0] = active(); pending.resolve(response(f.credentials)); await work; assert.equal(c.canCredential('retire'), false);
  f.credentials.items[0].observed_at = 101; await c.refresh('credentials', true); assert.equal(c.canCredential('retire'), true);
  f.post = null; await c.perform('credentials', 'retire'); assert.equal(c.item().state, 'completed'); assert.match(c.state.messages['metrics-token'].text, /every scraper/);
});
test('collector credentials are bound to destination and lowercase headers, then can restore previous setting', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.family('collector-headers'); c.field('endpoint', 'https://collector.example/');
  c.header(c.state.headers[0].id, 'value', 'Bearer fixture'); await c.perform('credentials', 'replace');
  assert.equal(f.writes[0].body.endpoint, 'https://collector.example'); assert.deepEqual(f.writes[0].body.headers, {authorization: 'Bearer fixture'});
  assert.equal(c.state.headers[0].value, ''); assert.equal(c.canCredential('retire'), false);
  await c.perform('credentials', 'revert'); assert.equal(c.item().state, 'reverted'); assert.match(c.state.messages['collector-headers'].text, /external consumers/);
});
test('unknown service result cannot claim saved and stores only an ID, never credential payload', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('token', token); f.post = async () => response(credentials());
  await c.perform('credentials', 'replace'); assert.equal(c.state.unknown['metrics-token'], true);
  assert.doesNotMatch(c.state.messages['metrics-token'].text, /Replacement saved/); assert.doesNotMatch(JSON.stringify(c.pending) + JSON.stringify(c.state), new RegExp(token));
  c.hide(); await c.refreshAll(); await c.perform('credentials', 'replace'); assert.equal(f.writes.length, 1);
  await c.refresh('credentials', true); c.field('token', token); f.post = null; await c.perform('credentials', 'replace');
  assert.equal(f.writes[1].body.request_id, f.writes[0].body.request_id);
});
test('secret fields and pending input clear on family change and hide without sending', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('token', token); c.family('collector-headers'); assert.equal(c.state.token, '');
  c.header(c.state.headers[0].id, 'value', token); c.field('endpoint', 'https://user:secret@collector.example'); c.hide();
  assert.equal(c.state.headers[0].value, ''); assert.equal(c.state.endpoint, ''); assert.equal(f.writes.length, 0);
});
test('header row identities remain stable when editing, adding and removing other rows', async () => {
  const {c} = setup(); await c.refreshAll(); c.family('collector-headers'); const first = c.state.headers[0].id;
  c.addHeader(); const second = c.state.headers[1].id; c.header(second, 'name', 'X-Token'); c.removeHeader(first);
  assert.equal(c.state.headers[0].id, second); assert.equal(c.state.headers[0].name, 'X-Token');
});
test('latest explicit read alone clears uncertainty and changing family prevents implicit acknowledgement', async () => {
  const {c, f} = setup(), pending = deferred(); await c.refreshAll(); c.update({unknown: {'metrics-token': true}});
  f.read = () => pending.promise; const work = c.refresh('credentials', true); c.family('collector-headers');
  pending.resolve(response(credentials())); await work; assert.equal(c.state.unknown['metrics-token'], true);
  c.family('metrics-token'); f.read = null; await c.refresh('credentials', true); assert.equal(c.state.unknown['metrics-token'], false);
});
test('superseded TLS review and failed follow-up reads never erase a write outcome', async () => {
  const {c, f} = setup(tls()), pending = deferred(); await c.refreshAll(); c.update({unknown: {tls: true}});
  f.read = () => pending.promise; const review = c.refresh('tls', true); f.read = null; await c.refresh('tls'); pending.resolve(response(tls())); await review;
  assert.equal(c.state.unknown.tls, true); await c.refresh('tls', true);
  f.read = async () => response({}, 503); await c.perform('tls', 'apply'); assert.equal(c.state.valid.tls, false); assert.match(c.state.messages.tls.text, /listener reloaded/);
  f.read = null; await c.refreshAll(); assert.match(c.state.messages.tls.text, /listener reloaded/);
});
test('public draft survives unrelated status reads, private download failures do not POST', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('names', 'future.example'); await c.refreshAll(); assert.equal(c.state.names, 'future.example');
  c.generateToken(); c.services.download = () => {throw Error();}; c.download('token'); assert.equal(f.writes.length, 0);
  assert.match(c.state.messages['metrics-token'].text, /download unavailable/);
});

test('success from a previous operation is not attributed to a newly observed request', async () => {
  const {c, f} = setup(tls()); await c.refreshAll(); await c.perform('tls', 'apply');
  assert.match(c.state.messages.tls.text, /listener reloaded/);
  f.tls = {...tls('published'), request_id: another}; await c.refreshAll();
  assert.doesNotMatch(c.state.messages.tls.text, /listener reloaded/); assert.match(c.state.messages.tls.text, /operation changed/);
  c.field('token', token); await c.perform('credentials', 'replace');
  assert.match(c.state.messages['metrics-token'].text, /Replacement saved/);
  f.credentials.items[0].request_id = another; await c.refreshAll();
  assert.match(c.state.messages['metrics-token'].text, /operation changed/);
});

test('known public refusal guidance is shown, arbitrary error content is never echoed', async () => {
  const {c, f} = setup(tls('awaiting-approval')); await c.refreshAll();
  c.file(file(certificate)); f.post = async () => response({error: 'Approved certificate names must exactly match the request'}, 409);
  await c.perform('tls', 'approve'); assert.match(c.state.messages.tls.text, /names must exactly match/);
  await c.refresh('tls', true); c.file(file(certificate));
  f.post = async () => response({error: 'private-input-echo'}, 409); await c.perform('tls', 'approve');
  assert.doesNotMatch(JSON.stringify(c.state), /private-input-echo/); assert.equal(c.state.unknown.tls, true);
});

test('shipped adapter supplies unbracketed IPv6 default certificate names', () => {
  const app = readFileSync(new URL('../../webroot/app.js', import.meta.url), 'utf8');
  const expression = app.match(/download: rotationDownload, hostname: ([^\n]+),\n/)[1];
  const hostname = Function('location', 'return ' + expression);
  assert.deepEqual(normalizeNames(hostname({hostname: '[2001:db8::1]'})), ['2001:db8::1']);
  assert.deepEqual(normalizeNames(hostname({hostname: 'console.example'})), ['console.example']);
});
