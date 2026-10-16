// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {SettingsController} from '../src/settings-controller.mjs';
import {CISCO_CA, MOZILLA_CA, SETTINGS_LIMIT, initialForms, settingsValidity, checkedPeer,
  pemFileFields, settingsBody, settingsRequest, checkedSettingsResult, successMessage} from '../src/settings-model.mjs';

const reply = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const gate = () => {let resolve; const promise = new Promise(yes => {resolve = yes;}); return {promise, resolve};};
const tick = () => new Promise(resolve => setImmediate(resolve));
const cert = '-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----';
const key = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nfixture\n-----END ENCRYPTED PRIVATE KEY-----';
const file = (name, text, extra = {}) => ({name, size: Buffer.byteLength(text), text: async () => text, ...extra});
const entry = {name: 'fixture.pem', source: 'manual', cert_count: 1};
const certificateInfo = {source: 'custom', subject: 'CN=fixture', not_after: '2036-10-08T00:00:00Z', fingerprint_sha256: 'ab'.repeat(32)};
const data = () => ({version: 'fixture', admin_username: 'operator', host_ip: '192.0.2.1',
  ports: {tracker: 6969, catalog: 8443, artifacts: 8000, swarm: 8080, console: 8082}, sessions: {active: 2, idle_ttl_minutes: 30},
  gui_cert: {source: 'built-in'}, trust: [entry], ca_trust: {url: CISCO_CA, auto: false},
  telemetry_destination: {source: 'env', effective_endpoint: '', effective_enabled: false},
  audit_export: {host: '', user: '', port: 22, path: '', age_recipient: '', auto: false, password_set: false}});
const peer = () => ({mode: 'disabled', can_change: true, active_devices: 0, active_jobs: 0, origin: {state: 'running', active_mode: 'disabled'}});
async function fixture(pane = 'tls') {
  const c = new SettingsController(), calls = [], replies = [], reads = [], peerReads = [], jobReads = [], timers = new Map(), prompts = [];
  let visible = true, accept = true, timerId = 0;
  const settings = data(), transport = peer();
  c.connect({headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), visible: () => visible, formatDate: String,
    confirm: message => {prompts.push(message); return accept;}, setTimeout: (fn, delay) => {timers.set(++timerId, {fn, delay}); return timerId;}, clearTimeout: id => timers.delete(id),
    fetch: async (path, options = {}) => {
      calls.push({path, options, body: options.body ? JSON.parse(options.body) : undefined});
      const queue = options.method ? replies : path === '/api/v1/settings' ? reads : path.endsWith('/peer-tls') ? peerReads : jobReads;
      const value = queue.length ? queue.shift() : reply(path === '/api/v1/settings' ? structuredClone(settings) : path.endsWith('/peer-tls') ? structuredClone(transport) : {state: 'running'});
      if (value instanceof Error) throw value;
      return await value;
    }});
  c.select(pane); await c.refresh();
  return {c, calls, replies, reads, peerReads, jobReads, settings, transport, timers, prompts,
    hide() {visible = false; c.hide();}, async show(next = pane) {visible = true; c.select(next); await c.refresh();},
    cancel() {accept = false;}, writes: () => calls.filter(call => call.options.method)};
}
function fill(c, group) {
  const values = {pw: {current: 'current-secret', next: 'next-secret', confirm: 'next-secret'}, cert: {pem: cert, key, passphrase: 'key-secret'},
    trust: {pem: cert}, td: {endpoint: 'https://collector.example/', enabled: true},
    ae: {host: 'archive.example', user: 'operator', port: '22', path: '/archive', recipient: 'age1fixture', password: 'ssh-secret', auto: true},
    ca: {source: 'mozilla', auto: true}, peer: {required: true}}[group] || {};
  for (const [name, value] of Object.entries(values)) c.field(group, name, value);
}
const actions = {pw: ['general', 'pw', {ok: true}], revoke: ['general', 'revoke', {revoked: 1}],
  cert: ['tls', 'cert', {applied: true, gui_cert: certificateInfo}], certDefault: ['tls', 'cert', {applied: true, deleted: true, gui_cert: {...certificateInfo, source: 'built-in'}}],
  trust: ['tls', 'trust', {entry}], trustDelete: ['tls', 'trust', {deleted: true}], ca: ['tls', 'ca', {ok: true, ca_trust: {url: MOZILLA_CA, auto: true}}],
  td: ['telemetry', 'td', {ok: true, endpoint: 'https://collector.example', enabled: true}], tdDefault: ['telemetry', 'td', {deleted: true}],
  ae: ['audit', 'ae', {ok: true}], aeClear: ['audit', 'ae', {deleted: true}],
  peer: ['tls', 'peer', {...peer(), mode: 'required', applied: true}],
  caRun: ['tls', 'ca', {job: 'ca-1'}], aeRun: ['audit', 'ae', {job_id: 'ae-1'}]};
for (const [action, [pane, group, body]] of Object.entries(actions)) {
  test(action + ' confirms only its endpoint contract with CSRF, no duplicate submit', async () => {
    const f = await fixture(pane); fill(f.c, group); const pending = gate(); f.replies.push(pending.promise);
    const writing = f.c.perform(action, 'fixture.pem'); await f.c.perform(action, 'fixture.pem');
    assert.equal(f.writes().length, 1); assert.equal(f.c.state.busy, true);
    assert.equal(f.writes()[0].options.headers['X-CSRF-Token'], 'fixture');
    pending.resolve(reply(body)); await writing; assert.equal(f.c.state.busy, false); assert.equal(f.c.state.messages[group].kind, 'success');
  });
  test(action + ' empty 200 is unknown and never replayed, including navigation', async () => {
    const f = await fixture(pane); fill(f.c, group); f.replies.push(reply({})); await f.c.perform(action, 'fixture.pem');
    assert.equal(f.c.state.unknown[group], true); assert.notEqual(f.c.state.messages[group].kind, 'success');
    await f.c.perform(action, 'fixture.pem'); f.hide(); await f.show(); fill(f.c, group); await f.c.perform(action, 'fixture.pem');
    assert.equal(f.writes().length, 1); await f.c.review(group);
    assert.equal(!!f.c.state.unknown[group], group === 'pw', 'Password recovery requires a new sign-in');
  });
}
test('response validation rejects malformed bodies, invalid metadata and wrong echoes', () => {
  for (const value of [null, [], {}, {trust: []}]) assert.ok(!Object.values(settingsValidity(value)).some(Boolean));
  assert.equal(checkedPeer({...peer(), active_devices: -1}), false);
  assert.equal(settingsValidity({...data(), trust: [{...entry, name: '../ca.pem'}]}).tls, false);
  const state = {forms: initialForms(), data: data()}; state.forms.td = {endpoint: 'https://example.test', enabled: true};
  const r = settingsRequest('td', state);
  for (const body of [{}, [], {ok: true, endpoint: 'https://wrong.test', enabled: true}, {ok: true, endpoint: 'https://example.test', enabled: 1}]) assert.equal(checkedSettingsResult(r, reply(body), body), 'unknown');
  assert.equal(checkedSettingsResult(r, reply({ok: true}, 503), {ok: true}), 'unknown');
});
test('payloads enforce encoded byte limit, strict ports, public-only PEM and URL policy', () => {
  const state = {forms: initialForms(), data: data()}; assert.throws(() => settingsBody({pem: 'é'.repeat(SETTINGS_LIMIT / 2)}), /64 KiB/);
  for (const url of ['ftp://example.test', 'https://user:pass@example.test', 'https://example.test?q=secret', 'https://example.test/#fragment']) {
    state.forms.td.endpoint = url; assert.throws(() => settingsRequest('td', state), /URL/);
  }
  state.forms.cert = {pem: cert + key, key, passphrase: 'secret'}; assert.throws(() => settingsRequest('cert', state), /only in the Private/);
  state.forms.trust.pem = cert + key; assert.throws(() => settingsRequest('trust', state), /public CA/);
  state.forms.ca.source = 'custom'; state.forms.ca.url = 'http://example.test'; assert.throws(() => settingsRequest('ca', state), /HTTPS/);
  state.forms.ae = {host: 'h', user: 'u', path: '/p', recipient: 'age1fixture', port: '2e1'}; assert.throws(() => settingsRequest('ae', state), /Port/);
  state.forms.ae.port = ''; const request = settingsRequest('ae', state); assert.equal(request.payload.port, 22); assert.equal('password' in request.payload, false);
});
for (const mode of ['network', 'html', 'server', 'refused', 'conflict']) test(mode + ' reply clears submitted secrets, preserves unrelated drafts and never reflects secrets', async () => {
  const f = await fixture(); fill(f.c, 'cert'); fill(f.c, 'ca');
  f.replies.push(mode === 'network' ? Error('key-secret') : mode === 'html' ? {...reply({}), json: async () => {throw Error('key-secret');}} : reply({error: 'key-secret'}, {server: 503, refused: 400, conflict: 409}[mode]));
  await f.c.perform('cert'); assert.deepEqual(f.c.state.forms.cert, initialForms().cert);
  assert.equal(f.c.state.forms.ca.source, 'mozilla'); assert.doesNotMatch(f.c.state.messages.cert.text, /key-secret/);
  assert.equal(!!f.c.state.unknown.cert, mode !== 'refused');
});
test('hide clears every secret while retaining non-secret drafts, and stale reads cannot restore them', async () => {
  const f = await fixture('audit'); fill(f.c, 'ae'); fill(f.c, 'cert'); fill(f.c, 'pw'); fill(f.c, 'td');
  const pending = gate(); f.reads.push(pending.promise); const read = f.c.refresh(); f.hide();
  pending.resolve(reply(data())); await read;
  assert.deepEqual(f.c.state.forms.cert, initialForms().cert); assert.equal(f.c.state.forms.pw.current, '');
  assert.equal(f.c.state.forms.ae.password, ''); assert.equal(f.c.state.forms.ae.host, 'archive.example');
  assert.equal(f.c.state.forms.td.endpoint, 'https://collector.example/'); assert.equal(f.c.available('ae'), false);
});
test('read body completion is latest-wins; failed refresh disables writes without erasing a draft', async () => {
  const f = await fixture('telemetry'), pending = gate(); fill(f.c, 'td');
  f.reads.push({...reply({}), json: () => pending.promise}); const old = f.c.refresh(); await tick();
  f.settings.telemetry_destination = {source: 'override', effective_endpoint: 'https://new.example', effective_enabled: false};
  await f.c.refresh(); pending.resolve(data()); await old;
  assert.equal(f.c.state.data.telemetry_destination.effective_endpoint, 'https://new.example');
  assert.equal(f.c.state.forms.td.endpoint, 'https://collector.example/');
  f.reads.push(reply({}, 503)); await f.c.refresh(); await f.c.perform('td'); assert.equal(f.writes().length, 0);
  assert.equal(f.c.state.forms.td.endpoint, 'https://collector.example/');
  await f.c.review('td'); assert.equal(f.c.state.forms.td.endpoint, 'https://new.example');
});
test('peer poll preserves original CAS and operator draft; conflict needs explicit reload', async () => {
  const f = await fixture(); fill(f.c, 'peer'); f.transport.mode = 'required'; f.transport.origin.active_mode = 'required'; await f.c.refreshPeer();
  assert.equal(f.c.state.peerBase, 'disabled'); assert.equal(f.c.state.forms.peer.required, true);
  f.replies.push(reply({error: 'conflict'}, 409)); await f.c.perform('peer'); assert.deepEqual(f.writes()[0].body, {mode: 'required', expected_mode: 'disabled'});
  await f.c.review('peer'); assert.equal(f.c.state.peerBase, 'required'); assert.equal(f.c.state.unknown.peer, false);
});
test('confirmation cancellation sends nothing and keeps drafts; unapplied certificate is only saved', async () => {
  const f = await fixture(); fill(f.c, 'cert'); f.cancel(); await f.c.perform('certDefault'); assert.equal(f.writes().length, 0);
  assert.equal(f.c.state.forms.cert.key, key);
  assert.match(successMessage('cert', {applied: false}), /saved; restart/); assert.doesNotMatch(successMessage('cert', {applied: false}), /use it now/);
});
test('combined PEM file separates private material, clears passphrase and rejects multiple keys', async () => {
  const f = await fixture(); fill(f.c, 'cert'); await f.c.certificateFiles([file('combined.pem', cert + '\n' + key)]);
  assert.equal(f.c.state.forms.cert.pem, cert + '\n'); assert.equal(f.c.state.forms.cert.key, key); assert.equal(f.c.state.forms.cert.passphrase, '');
  assert.throws(() => pemFileFields(key + key), /only one private/);
  await f.c.certificateFiles([file('large.pem', cert, {size: SETTINGS_LIMIT + 1})]); assert.match(f.c.state.messages.cert.text, /64 KiB/);
});
for (const change of ['edit', 'hide', 'new-file']) test('late file result cannot undo ' + change, async () => {
  const f = await fixture(), pending = gate(); const reading = f.c.certificateFiles([file('late.pem', cert, {text: () => pending.promise})]);
  if (change === 'edit') f.c.field('cert', 'pem', 'edited');
  else if (change === 'hide') f.hide();
  else await f.c.certificateFiles([file('new.pem', cert.replace('fixture', 'new'))]);
  pending.resolve(cert); await reading;
  assert.equal(f.c.state.forms.cert.pem, change === 'edit' ? 'edited' : change === 'hide' ? '' : cert.replace('fixture', 'new') + '\n');
  assert.equal(f.c.state.fileBusy, false);
});
test('trust batch stops after unknown, bounds request bytes, and never uploads private keys', async () => {
  const f = await fixture(); f.replies.push(reply({entry}), reply({}));
  await f.c.trustFiles([file('private.pem', cert + key), file('large.pem', cert + 'é'.repeat(SETTINGS_LIMIT)), file('one.pem', cert), file('two.pem', cert), file('three.pem', cert)]);
  assert.equal(f.writes().length, 2); assert.equal(f.c.state.unknown.trust, true);
  assert.match(f.c.state.messages.trust.text, /private.pem: skipped.*large.pem: unreadable or too large.*one.pem: added.*two.pem: unknown.*three.pem: not attempted/);
});
test('trust batch navigation leaves submitted request running but never starts unread files', async () => {
  const f = await fixture(), pending = gate(); f.replies.push(pending.promise);
  const batch = f.c.trustFiles([file('one.pem', cert), file('two.pem', cert)]); await tick(); f.hide();
  assert.equal(f.c.state.busy, true); pending.resolve(reply({entry})); await batch;
  assert.equal(f.writes().length, 1); assert.match(f.c.state.messages.trust.text, /two.pem: not attempted/);
});
for (const [group, pane, action, start, done] of [['ca', 'tls', 'caRun', {job: 'ca-1'}, {state: 'done', certs: 7}], ['ae', 'audit', 'aeRun', {job_id: 'ae-1'}, {state: 'done', detail: '7 events'}]]) {
  test(group + ' job pauses on hide, resumes same handle and completes without another POST', async () => {
    const f = await fixture(pane); f.replies.push(reply(start)); await f.c.perform(action); await tick();
    assert.ok(f.c.state.jobs[group]); assert.ok(f.timers.size); f.hide(); assert.equal(f.timers.size, 0);
    f.jobReads.push(reply(done)); await f.show(); await tick(); assert.equal(f.c.state.jobs[group], null); assert.equal(f.writes().length, 1);
    assert.equal(f.c.state.messages[group].kind, 'success');
  });
  test(group + ' missing job and stale body cannot falsely complete or replay', async () => {
    const f = await fixture(pane), pending = gate(); f.replies.push(reply(start)); f.jobReads.push({...reply({}), json: () => pending.promise});
    await f.c.perform(action); f.hide(); pending.resolve(done); await tick(); assert.ok(f.c.state.jobs[group]);
    f.jobReads.push({...reply({}, 404), json: async () => {throw Error('HTML');}}); await f.show(); await tick();
    assert.equal(f.c.state.jobs[group], null); assert.equal(f.c.state.unknown[group], true); assert.notEqual(f.c.state.messages[group].kind, 'success');
    await f.c.perform(action); assert.equal(f.writes().length, 1);
  });
}
test('malformed terminal job keeps its handle for observation and blocks duplicate starts', async () => {
  const f = await fixture(); f.replies.push(reply({job: 'ca-1'})); f.jobReads.push(reply({state: 'done', certs: '7'}));
  await f.c.perform('caRun'); await tick(); assert.ok(f.c.state.jobs.ca); assert.match(f.c.state.messages.ca.text, /status unavailable/);
  await f.c.perform('caRun'); assert.equal(f.writes().length, 1);
});

test('applied certificate needs identity evidence, while saved-only may have no active TLS details', () => {
  for (const body of [{applied: true, gui_cert: {}}, {applied: true, gui_cert: {...certificateInfo, fingerprint_sha256: ''}},
    {applied: true, gui_cert: {...certificateInfo, source: 'built-in'}}]) {
    assert.equal(checkedSettingsResult({action: 'cert'}, reply(body), body), 'unknown');
  }
  const body = {applied: false, gui_cert: {}};
  assert.equal(checkedSettingsResult({action: 'cert'}, reply(body), body), 'saved');
});
test('latest peer read cannot be replaced by an older body or restore permission after hide', async () => {
  const f = await fixture(), pending = gate(); f.peerReads.push({...reply({}), json: () => pending.promise});
  const old = f.c.refreshPeer(); await tick(); f.transport.can_change = false; await f.c.refreshPeer();
  pending.resolve(peer()); await old; assert.equal(f.c.state.peer.can_change, false);
  const hidden = gate(); f.peerReads.push(hidden.promise); const read = f.c.refreshPeer(); f.hide(); hidden.resolve(reply(peer())); await read;
  assert.equal(f.c.state.peerOk, false); assert.equal(f.timers.size, 0);
});
test('explicit review cannot discard later input after a superseding read or navigation', async () => {
  const f = await fixture('telemetry'), pending = gate(); fill(f.c, 'td');
  f.reads.push(pending.promise); const review = f.c.review('td'); await f.c.refresh(); pending.resolve(reply(data())); await review;
  assert.equal(f.c.state.forms.td.endpoint, 'https://collector.example/');
  const hidden = gate(); f.reads.push(hidden.promise); const second = f.c.review('td'); f.hide(); hidden.resolve(reply(data())); await second;
  assert.equal(f.c.state.forms.td.endpoint, 'https://collector.example/');
});
test('navigation never unlocks a pending mutation or accepts another action before its response', async () => {
  const f = await fixture(), pending = gate(); fill(f.c, 'cert'); f.replies.push(pending.promise);
  const write = f.c.perform('cert'); f.hide(); await f.show('general'); fill(f.c, 'pw'); await f.c.perform('pw');
  assert.equal(f.c.state.busy, true); assert.equal(f.writes().length, 1);
  pending.resolve(reply({applied: true, gui_cert: certificateInfo})); await write; assert.equal(f.c.state.busy, false);
});
for (const status of [401, 503]) test('job status HTTP ' + status + ' retains handle without false completion', async () => {
  const f = await fixture(); f.replies.push(reply({job: 'ca-1'})); f.jobReads.push(reply({}, status));
  await f.c.perform('caRun'); await tick(); assert.ok(f.c.state.jobs.ca); assert.notEqual(f.c.state.messages.ca.kind, 'success');
  assert.equal(f.writes().length, 1);
});
test('failed CA and audit jobs clear the handle and report failure rather than successful completion', async () => {
  for (const [pane, group, action, response, state] of [['tls', 'ca', 'caRun', {job: 'c'}, 'failed'], ['audit', 'ae', 'aeRun', {job_id: 'a'}, 'error']]) {
    const f = await fixture(pane); f.replies.push(reply(response)); f.jobReads.push(reply({state, detail: 'arbitrary-secret-error'}));
    await f.c.perform(action); await tick(); assert.equal(f.c.state.jobs[group], null);
    assert.equal(f.c.state.messages[group].kind, 'error'); assert.doesNotMatch(f.c.state.messages[group].text, /arbitrary-secret/);
  }
});

test('editing during an explicit review keeps newer input and the uncertain-result gate', async () => {
  const f = await fixture('telemetry'), pending = gate(); fill(f.c, 'td');
  f.c.update({unknown: {td: true}}); f.reads.push(pending.promise); const review = f.c.review('td');
  f.c.field('td', 'endpoint', 'https://newer.example'); pending.resolve(reply(data())); await review;
  assert.equal(f.c.state.forms.td.endpoint, 'https://newer.example'); assert.equal(f.c.state.unknown.td, true);
  assert.match(f.c.state.messages.td.text, /newer edits are kept/);
});
test('starting and completing jobs preserve unsaved CA and audit destination drafts', async () => {
  for (const [pane, group, action, start, done] of [['tls', 'ca', 'caRun', {job: 'c'}, {state: 'done', certs: 2}],
    ['audit', 'ae', 'aeRun', {job_id: 'a'}, {state: 'done', detail: '2 events'}]]) {
    const f = await fixture(pane); fill(f.c, group); const before = {...f.c.state.forms[group]};
    f.replies.push(reply(start)); f.jobReads.push(reply(done)); await f.c.perform(action); await tick();
    assert.deepEqual(f.c.state.forms[group], group === 'ae' ? {...before, password: ''} : before);
    assert.equal(f.c.state.dirty[group], true);
  }
});

test('known refused password and disabled audit export give safe recovery instructions', async () => {
  const f = await fixture('general'); fill(f.c, 'pw'); f.replies.push(reply({error: 'current password is incorrect'}, 400));
  await f.c.perform('pw'); assert.match(f.c.state.messages.pw.text, /Current password is incorrect/);
  await f.show('audit'); fill(f.c, 'ae'); f.replies.push(reply({error: 'settings save failed',
    detail: 'settings save failed; audit export is disabled. Reload settings, re-enter the destination and password, then save again'}, 500));
  await f.c.perform('ae'); assert.match(f.c.state.messages.ae.text, /Audit export was disabled.*destination and password/);
  assert.equal(f.c.state.unknown.ae, true);
});
