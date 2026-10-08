// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {DeviceFormsController} from '../src/device-forms-controller.mjs';
import {InventoryController} from '../src/inventory-controller.mjs';
import {emptyDevice, emptyCredential, managementInstallOptions, networkFields, deviceBody, credentialBody, credentialProfiles} from '../src/device-forms-model.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };
const response = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const profile = {id: 'operator', name: 'Operators', device_user: 'admin'};
function fixture() {
  const controller = new DeviceFormsController(), writes = [], reports = [], publications = [];
  let refreshes = 0;
  controller.connect({fetch: async path => response(path.includes('install-options') ? {options: null} : {profiles: [profile]}),
    post: async (path, body) => { writes.push({path, body}); return response(path.endsWith('/devices') ? {device: {device_id: body.device_id}} : {profile: {id: body.id}}); },
    headers: () => ({'X-CSRF-Token': 'fixture'}), confirm: () => true, report: (...args) => reports.push(args),
    publishCredentials: state => publications.push(state), refreshInventory: async () => { refreshes++; }});
  return {controller, writes, reports, publications, refreshes: () => refreshes};
}
async function device(controller, management = 'xr-host') {
  await controller.toggleDevice(); controller.setDevice('id', ' edge '); controller.setDevice('ip', ' 192.0.2.1 ');
  await controller.setDevice('management', management); await controller.setDevice('model', 'XR8000');
}
async function credential(controller) {
  await controller.toggleCredentials();
  for (const [key, value] of Object.entries({id: ' operator ', name: ' Operators ', user: ' admin ', password: ' secret ', confirm: ' secret ', enable: ' enable '})) controller.setCredential(key, value);
}

for (const [management, fields, options] of [
  ['', [], []], ['xr-host', [], ['xr-appmgr']],
  ['routed', ['vlan', 'svi', 'guest', 'mask', 'gateway'], ['guestshell', 'iox']],
  ['inband', ['vlan', 'guest', 'mask', 'gateway'], ['guestshell', 'iox']],
  ['router-routed', ['vpg', 'guest', 'mask', 'gateway'], ['router', 'iox']],
  ['router-nat', ['vpg', 'nat', 'guest', 'mask', 'gateway'], ['router', 'iox']],
]) test(`only management ${management || '(blank)'} determines fields and allowed installers`, async () => {
  const {controller: c} = fixture(); await c.toggleDevice(); await c.setDevice('management', management);
  assert.deepEqual(networkFields(c.state.device.management), fields); assert.deepEqual(managementInstallOptions(management), options);
  for (const model of ['', '8', '8000', 'C9300', 'unknown']) {
    c.services.fetch = async () => response({options: model === '8000' ? ['xr-appmgr'] : null});
    await c.setDevice('model', model); assert.equal(c.state.device.management, management);
    assert.deepEqual(networkFields(c.state.device.management), fields);
  }
});
for (const management of ['routed', 'inband', 'router-routed', 'router-nat', 'xr-host']) test(`wire addressing for ${management}`, () => {
  const form = {...emptyDevice(), id: ' edge ', ip: ' 192.0.2.1 ', model: 'C8xxx', management,
    platform: managementInstallOptions(management)[0], credential: 'operator', vlan: ' 100 ', svi: ' 192.0.2.2 ',
    mask: ' 255.255.255.0 ', vpg: ' 0 ', nat: ' GigabitEthernet1 ', guest: ' 192.0.2.3 ', gateway: ' 192.0.2.4 '};
  const base = {device_id: 'edge', device_ip: '192.0.2.1', management_type: management, model: 'C8xxx', platform: form.platform, credential_profile_id: 'operator'};
  const network = {app_ip: '192.0.2.3', app_mask: '255.255.255.0', app_gateway: '192.0.2.4'};
  const extra = management === 'routed' ? {iris_vlan: '100', svi_ip: '192.0.2.2', svi_mask: '255.255.255.0'}
    : management === 'inband' ? {inband_vlan: '100'} : management === 'router-nat' ? {vpg_number: '0', nat_interface: 'GigabitEthernet1'} : {vpg_number: '0'};
  assert.deepEqual(deviceBody(form), management === 'xr-host' ? base : {...base, ...network, ...extra});
  assert.equal(deviceBody({...form, ip: ''}).device_ip, 'edge');
});
test('device validation stops each incomplete choice', () => {
  const form = emptyDevice();
  for (const [message, patch] of [['Device ID', {id: 'edge'}], ['model series', {model: 'C9xxx'}],
    ['management type', {management: 'routed'}], ['agent install', {platform: 'iox'}]]) {
    assert.throws(() => deviceBody(form), new RegExp(message)); Object.assign(form, patch);
  }
  assert.equal(deviceBody(form).platform, 'iox');
});
test('known conflict is empty, XR explicit choice auto-selects, routers retain either installer', async () => {
  const {controller: c} = fixture(); await device(c, 'routed');
  c.services.fetch = async () => response({options: ['xr-appmgr']}); await c.refreshOptions();
  assert.deepEqual(c.state.options, []); assert.equal(c.state.device.platform, ''); assert.match(c.state.optionHint, /management type/);
  await c.saveDevice(); assert.equal(c.state.deviceFailed, true);
  await c.setDevice('management', 'xr-host'); assert.equal(c.state.device.platform, 'xr-appmgr');
  c.services.fetch = async () => response({options: ['router', 'iox']});
  for (const management of ['router-routed', 'router-nat']) {
    await c.setDevice('management', management); assert.deepEqual(c.state.options, ['router', 'iox']);
    for (const value of ['router', 'iox']) { c.setDevice('platform', value); await c.refreshOptions(); assert.equal(c.state.device.platform, value); }
  }
});
for (const result of ['http', 'network', 'json', 'malformed']) test(`model lookup ${result} retains explicit management and installer`, async () => {
  const {controller: c} = fixture(); await device(c);
  c.services.fetch = async () => { if (result === 'network') throw Error('offline');
    if (result === 'json') return {ok: true, json: async () => { throw Error('JSON'); }};
    return response({options: 'not array'}, result === 'http' ? 503 : 200); };
  await c.refreshOptions(); assert.equal(c.state.device.management, 'xr-host'); assert.equal(c.state.device.platform, 'xr-appmgr');
  assert.match(c.state.optionHint, /validated when saved/);
});
for (const fail of [false, true]) test(`late model body ${fail ? 'failure' : 'success'} cannot replace new form choice`, async () => {
  const {controller: c} = fixture(); await device(c); const gate = deferred();
  c.services.fetch = async () => ({ok: true, json: () => gate.promise}); const old = c.refreshOptions(); await Promise.resolve();
  c.services.fetch = async () => response({options: ['guestshell', 'iox']}); await c.setDevice('management', 'routed'); c.setDevice('platform', 'iox');
  fail ? gate.reject(Error('old')) : gate.resolve({options: ['xr-appmgr']}); await old;
  assert.equal(c.state.device.management, 'routed'); assert.equal(c.state.device.platform, 'iox');
  assert.deepEqual(c.state.options, ['guestshell', 'iox']);
});
test('closing cancels late model response even for same-device reopen', async () => {
  const {controller: c} = fixture(); await device(c); const gate = deferred(); let signal;
  c.services.fetch = async (path, options) => { signal = options.signal; return {ok: true, json: () => gate.promise}; };
  const old = c.refreshOptions(); await Promise.resolve(); c.closeDevice(); assert.equal(signal.aborted, true);
  c.services.fetch = async () => response({options: null}); await c.toggleDevice();
  gate.resolve({options: []}); await old; assert.equal(c.state.device.platform, 'xr-appmgr');
});
test('device save exact body and single lock survive close/reopen, hide avoids inventory read', async () => {
  const {controller: c, reports, refreshes} = fixture(); await device(c); const gate = deferred(), writes = [];
  c.services.post = async (path, body) => { writes.push({path, body}); return gate.promise; };
  const save = c.saveDevice(); await c.saveDevice(); c.closeDevice(); await c.toggleDevice(); await c.saveDevice();
  assert.equal(writes.length, 1); assert.deepEqual(writes[0], {path: '/api/v1/devices', body: {
    device_id: 'edge', device_ip: '192.0.2.1', model: 'XR8000', management_type: 'xr-host', platform: 'xr-appmgr', credential_profile_id: ''}});
  c.services.isVisible = () => false; c.hide(); gate.resolve(response({device: {device_id: 'edge'}})); await save;
  assert.equal(c.state.deviceOpen, true); assert.equal(c.state.device.id, ' edge '); assert.equal(c.state.deviceBusy, false);
  assert.equal(refreshes(), 0); assert.match(reports[0][0], /saved/);
});
for (const mode of ['refused', 'lost', 'malformed', 'wrong-id']) test(`device save ${mode} keeps draft and never retries`, async () => {
  const {controller: c} = fixture(); await device(c); let calls = 0;
  c.services.post = async () => { calls++; if (mode === 'lost') throw Error('gone');
    return response(mode === 'refused' ? {error: 'review model'} : mode === 'wrong-id' ? {device: {device_id: 'other'}} : {}, mode === 'refused' ? 422 : 200); };
  await c.saveDevice(); assert.equal(calls, 1); assert.equal(c.state.deviceOpen, true); assert.equal(c.state.deviceFailed, true);
  assert.match(c.state.deviceMessage, mode === 'refused' ? /refused.*review model/ : /outcome is unknown/);
});
test('unavailable or deleted chosen credential cannot silently save as no credential', async () => {
  const {controller: c, writes} = fixture(); await device(c); c.setDevice('credential', 'operator');
  await c.saveDevice(); assert.equal(writes.length, 0); assert.match(c.state.deviceMessage, /Credential unavailable/);
  await c.refreshCredentials(); await c.saveDevice(); assert.equal(writes[0].body.credential_profile_id, 'operator');
});
test('device save shares Inventory row/bulk lock and releases only its own claim', async () => {
  const {controller: c, writes} = fixture(), inventory = new InventoryController(); await device(c);
  c.services.claimDevice = id => inventory.claimRow(id); c.services.releaseDevice = id => inventory.releaseRow(id);
  inventory.update({bulkBusy: true}); await c.saveDevice(); assert.equal(writes.length, 0); assert.match(c.state.deviceMessage, /Another device action/);
  inventory.update({bulkBusy: false}); inventory.claimRow('edge'); await c.saveDevice(); assert.equal(inventory.state.rowBusy.has('edge'), true);
  inventory.releaseRow('edge'); const gate = deferred(); c.services.post = () => gate.promise;
  const save = c.saveDevice(); assert.equal(inventory.state.rowBusy.has('edge'), true);
  gate.reject(Error('lost')); await save; assert.equal(inventory.state.rowBusy.has('edge'), false);
});
test('profiles projection rejects malformed/duplicate ids and discards any secret fields', () => {
  for (const profiles of [null, [null], [{id: ''}], [profile, profile], [{id: 'x', name: 7}]]) assert.throws(() => credentialProfiles({profiles}));
  assert.deepEqual(credentialProfiles({profiles: [{...profile, password: 'never store', device_pass: 'never store'}]}), [profile]);
});
test('credential validation preserves password whitespace and strips no secrets', () => {
  const form = emptyCredential(); assert.throws(() => credentialBody(form), /Profile id/);
  form.id = ' x '; assert.throws(() => credentialBody(form), /Password is required/);
  form.password = ' p '; assert.throws(() => credentialBody(form), /Passwords do not match/);
  form.confirm = ' p '; form.enable = ' e ';
  assert.deepEqual(credentialBody(form), {id: 'x', name: 'x', device_user: 'admin', device_pass: ' p ', enable_secret: ' e '});
  assert.throws(() => credentialBody({...form, user: ' '}), /Device username is required/);
  assert.throws(() => credentialBody({...form, password: ' ', confirm: ' '}), /Password is required/);
});
test('failed credential read retains last projection but disables actions and preserves draft', async () => {
  const {controller: c} = fixture(); await credential(c); c.services.fetch = async () => response({}, 503);
  await c.refreshCredentials(); assert.deepEqual(c.state.profiles, [profile]); assert.equal(c.state.credentialsOk, false);
  assert.equal(c.state.credential.password, ' secret '); assert.equal(c.state.credentialsLoading, false);
  let confirms = 0; c.services.confirm = () => { confirms++; return true; }; await c.deleteCredential(profile.id);
  c.editCredential(profile.id); assert.equal(confirms, 0); assert.equal(c.state.editing, false);
});
test('credential draft and focus identity are independent of list polling; edit locks id and clears secrets', async () => {
  const {controller: c} = fixture(); await credential(c); const form = c.state.credential;
  await c.refreshCredentials(); assert.equal(c.state.credential, form);
  c.editCredential('operator'); assert.equal(c.state.editing, true); assert.equal(c.state.credential.password, '');
  c.setCredential('id', 'different'); assert.equal(c.state.credential.id, 'operator');
  c.newCredential(); assert.equal(c.state.editing, false); assert.equal(c.state.credential.id, '');
});
test('save credentials verifies identity, clears secrets and refreshes choices and Inventory', async () => {
  const {controller: c, writes, refreshes} = fixture(); await credential(c); await c.saveCredential();
  assert.deepEqual(writes[0], {path: '/api/v1/credentials', body: {id: 'operator', name: 'Operators', device_user: 'admin', device_pass: ' secret ', enable_secret: ' enable '}});
  assert.deepEqual(c.state.credential, emptyCredential()); assert.equal(c.state.credentialsOk, true); assert.equal(refreshes(), 1);
  assert.match(c.state.credentialMessage, /saved/);
});
for (const mode of ['refused', 'lost', 'malformed', 'wrong-id']) test(`credential save ${mode}: never replay or echo secrets`, async () => {
  const {controller: c, reports} = fixture(); await credential(c); let writes = 0;
  c.services.post = async () => { writes++; if (mode === 'lost') throw Error(' secret ');
    return response(mode === 'refused' ? {error: ' secret ', detail: ' enable '} : mode === 'wrong-id' ? {profile: {id: 'wrong'}} : {}, mode === 'refused' ? 422 : 200); };
  await c.saveCredential(); assert.equal(writes, 1); assert.equal(c.state.credentialFailed, true);
  assert.doesNotMatch(c.state.credentialMessage + JSON.stringify(reports), / secret | enable /);
  assert.equal(c.state.credential.password, mode === 'refused' ? ' secret ' : '');
  assert.match(c.state.credentialMessage, mode === 'refused' ? /refused.*422/ : /outcome is unknown/);
});
for (const result of [true, false, 'refused', 'lost', 'malformed']) test(`credential delete result ${result}`, async () => {
  const {controller: c, reports} = fixture(); await credential(c); let confirmed = false; const writes = [];
  c.services.confirm = () => confirmed; await c.deleteCredential('operator'); assert.equal(writes.length, 0);
  confirmed = true;
  c.services.fetch = async (path, options) => {
    if (options?.method !== 'DELETE') return response({profiles: [profile]});
    writes.push({path, options}); if (result === 'lost') throw Error('gone');
    return response(typeof result === 'boolean' ? {deleted: result} : {}, result === 'refused' ? 409 : 200);
  };
  await c.deleteCredential('operator'); assert.equal(writes.length, 1);
  assert.equal(writes[0].path, '/api/v1/credentials/operator'); assert.deepEqual(writes[0].options.headers, {'X-CSRF-Token': 'fixture'});
  assert.match(reports.at(-1)[0], result === true ? /deleted/ : result === false ? /already absent/ : result === 'refused' ? /refused/ : /unknown/);
});
test('close/hide wipe secrets; write lock survives reopen and completion cannot erase a new form', async () => {
  const {controller: c, refreshes} = fixture(); await credential(c); const gate = deferred(); let calls = 0;
  c.services.post = async () => { calls++; return gate.promise; }; const save = c.saveCredential();
  c.closeCredentials(); assert.equal(c.state.credential.password, ''); assert.equal(c.state.credential.enable, '');
  await c.toggleCredentials(); await c.saveCredential(); await c.deleteCredential('operator'); c.newCredential();
  assert.equal(calls, 1); assert.equal(c.state.credentialBusy, true);
  c.services.isVisible = () => false; c.hide(); gate.resolve(response({profile: {id: 'operator'}})); await save;
  assert.equal(c.state.credentialsOpen, false); assert.equal(c.state.credential.id, ' operator '); assert.equal(c.state.credential.password, '');
  assert.equal(c.state.credentialBusy, false); assert.equal(refreshes(), 0);
});
test('credential list tickets order Inventory and panel, including failed latest read', async () => {
  const {controller: c} = fixture(); await c.refreshCredentials();
  const old = c.beginCredentialRead(), next = c.beginCredentialRead();
  c.acceptCredentials({ok: true, body: {profiles: [{id: 'new'}]}}, next);
  c.acceptCredentials({ok: true, body: {profiles: [profile]}}, old);
  assert.equal(c.state.profiles[0].id, 'new');
  const fail = c.beginCredentialRead(); c.acceptCredentials({ok: false}, fail);
  c.acceptCredentials({ok: true, body: {profiles: [profile]}}, next);
  assert.equal(c.state.credentialsOk, false); assert.equal(c.state.profiles[0].id, 'new');
});
test('late credential bodies cannot replace post-write refresh or leave spinner stuck', async () => {
  const {controller: c} = fixture(); await credential(c); const gate = deferred();
  c.services.fetch = async () => ({ok: true, json: () => gate.promise}); const old = c.refreshCredentials(); await Promise.resolve();
  c.services.fetch = async () => response({profiles: []}); await c.saveCredential();
  gate.resolve({profiles: [profile]}); await old; assert.deepEqual(c.state.profiles, []); assert.equal(c.state.credentialsLoading, false);
  const held = deferred(); c.services.fetch = async () => ({ok: true, json: () => held.promise});
  const panel = c.refreshCredentials(); await Promise.resolve(); c.beginCredentialRead(); held.resolve({profiles: [profile]}); await panel;
  assert.equal(c.state.credentialsLoading, false, 'Superseded panel read still releases its own spinner');
});
test('read started during write cannot restore old profiles after write completes', async () => {
  const {controller: c} = fixture(); await credential(c); const gate = deferred(); c.services.post = async () => gate.promise;
  const save = c.saveCredential(), midWrite = c.beginCredentialRead();
  c.acceptCredentials({ok: true, body: {profiles: [profile]}}, midWrite); assert.equal(c.state.credentialsOk, false);
  c.services.fetch = async () => response({profiles: []}); gate.resolve(response({profile: {id: 'operator'}})); await save;
  c.acceptCredentials({ok: true, body: {profiles: [profile]}}, midWrite); assert.deepEqual(c.state.profiles, []);
});
test('actual Inventory controller cannot publish an older credentials body over panel evidence', async () => {
  const {controller: c} = fixture(), inventory = new InventoryController(), gate = deferred();
  inventory.connect({fetch: async path => path.includes('/credentials') ? {ok: true, json: () => gate.promise}
    : response(path.includes('/devices?') ? {devices: [], offset: 0, total: 0, revision: 1, now: 1}
      : path.endsWith('images') ? {images: []} : path.endsWith('peer-policy') ? {revision: 1, quarantine_assignments: []}
      : path.endsWith('jobs') ? {jobs: []} : {schedules: []}), beginCredentialRead: () => c.beginCredentialRead(),
    acceptCredentials: (result, ticket) => c.acceptCredentials(result, ticket)});
  const old = inventory.refresh(); await Promise.resolve(); await c.refreshCredentials();
  gate.resolve({profiles: [{id: 'obsolete'}]}); await old;
  assert.deepEqual(inventory.state.credentials, [profile]); assert.equal(inventory.state.credentialsOk, true);
});
