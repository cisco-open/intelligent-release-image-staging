// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {WorkerLifecycleController} from '../src/worker-lifecycle-controller.mjs';
import {urls, workerStatus, acceptedJob, matchingJob, workerBody, workerRefusalHint} from '../src/worker-lifecycle-model.mjs';
import {rootPublic, rootsPublic, keylistPayload, signedKeylist, trustItem, trustStatus, checkedTrust} from '../src/deployment-trust-model.mjs';
import {maintenanceStatus, checkedMaintenance, validPolicy, schedulePayload, scheduleDraft} from '../src/key-maintenance-model.mjs';
import {id, other, now, hash, csr, certificate, roots, root, keylist, signed, idle, trust, prepared, rotation, backups, maintenance, policy, job, maintenanceJob, response, file, deferred} from './worker-fixtures.mjs';
function setup(pane = 'certificates') {
  const c = new WorkerLifecycleController(), f = {rotation: rotation(), trust: trust(), maintenance: maintenance(), backups: backups(), visible: true, accept: true, writes: [], downloads: [], read: null, post: null};
  c.connect({visible: () => f.visible, uuid: () => id, now: () => now * 1000, formatDate: String,
    headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), confirm: () => f.accept, download: (name, bytes) => f.downloads.push({name, bytes}),
    fetch: async (path, options = {}) => {
      const kind = Object.keys(urls).find(key => urls[key] === path); assert.ok(kind);
      if (!options.method) return f.read ? f.read(kind, options) : response(f[kind]);
      assert.equal(options.headers['X-CSRF-Token'], 'fixture'); const payload = JSON.parse(options.body); f.writes.push({kind, payload});
      if (f.post) return f.post(kind, payload);
      if (kind === 'trust') {
        const old = f.trust.items.find(row => row.family === payload.family); let next;
        if (payload.action === 'prepare') next = {...prepared(payload.family, payload.family === 'peer-ca' || payload.mode === 'self-signed' ? 'approved' : 'awaiting-approval', payload.mode), request_id: payload.request_id, names: payload.names || []};
        else next = {...old, state: payload.action === 'cancel' ? 'cancelled' : 'approved', ...(payload.certificate ? {certificate: payload.certificate, fingerprint_sha256: hash} : {})};
        f.trust.items = f.trust.items.map(row => row.family === payload.family ? next : row); return response(next);
      }
      if (kind === 'maintenance') {f.maintenance = {...f.maintenance, revision: payload.revision + 1, policies: [payload.policy]}; return response(f.maintenance);}
      return response({job_id: payload.request_id});
    }});
  c.pane = pane; return {c, f};
}
test('native public status shapes validate and remove private journal fields', () => {
  for (const kind of ['rotation', 'backups']) {const value = kind === 'rotation' ? rotation() : backups(); assert.ok(workerStatus(value, kind)); assert.equal(workerStatus({...value, private_identity: 'not-public'}, kind).private_identity, undefined);}
  assert.ok(trustStatus(trust())); assert.ok(maintenanceStatus(maintenance()));
  for (const family of ['device-tls', 'peer-ca', 'instruction-roots']) assert.ok(trustItem(prepared(family)), family);
  assert.ok(trustItem({...idle('instruction-roots'), roots}));
});
test('root files normalize comments and reject private, duplicate or malformed keys', () => {
  assert.equal(rootPublic(roots['root-a'].trim() + ' comment\n'), roots['root-a']);
  assert.deepEqual(rootsPublic(roots), roots);
  for (const value of ['PRIVATE KEY', 'ssh-ed25519 AAAA\n', root('a') + root('b')]) assert.throws(() => rootPublic(value));
  assert.throws(() => rootsPublic({'root-a': root('a'), 'root-b': root('a')}));
});
test('raw public keylist binds framing, canonical metadata, root and prepared payload', () => {
  assert.equal(keylistPayload(keylist(), 'root-a'), keylist()); assert.equal(signedKeylist(signed(), 'root-a', keylist()), signed());
  for (const value of [btoa(signed()), signed('root-b'), signed().replace('IRIS-KEYLIST/1', 'IRIS-KEYLIST/2'), signed().replace(/\n$/, '')]) assert.throws(() => signedKeylist(value, 'root-a', keylist()));
});
test('trust approval rejects unrelated ID, unchanged state, changed request and approval bytes', () => {
  const before = prepared('device-tls', 'awaiting-approval'), payload = {family: 'device-tls', action: 'approve', request_id: id, certificate};
  assert.ok(checkedTrust(payload, before, prepared()));
  for (const next of [before, {...prepared(), request_id: other}, {...prepared(), csr: csr.replace('AAAA', 'BBBB')}, {...prepared(), certificate: certificate.replace('AAAA', 'BBBB')}, {...prepared(), names: ['other.example']}]) assert.equal(checkedTrust(payload, before, next), null);
});
test('current-root attestation needs a POST confirmation and exact ceremony and root', () => {
  const before = {...idle('instruction-roots'), roots, attestation_request_id: id, attestation_root_id: 'root-a'};
  const next = {...before, attested_root_ids: ['root-a'], attestation_applied: true}, payload = {family: 'instruction-roots', action: 'attestation-apply', request_id: id, root_id: 'root-a'};
  assert.ok(checkedTrust(payload, before, next));
  for (const change of [{attestation_applied: false}, {attestation_request_id: other}, {attestation_root_id: 'root-b'}, {attested_root_ids: []}, {roots: {...roots, 'root-b': root('c')}}]) assert.equal(checkedTrust(payload, before, {...next, ...change}), null);
});
test('cancelled root replacement shows active roots instead of discarded candidates', () => {
  const before = prepared('instruction-roots', 'awaiting-approval'), next = {...before, state: 'cancelled', roots: {'root-a': root('x'), 'root-b': root('y')}};
  assert.ok(checkedTrust({family: before.family, action: 'cancel', request_id: id}, before, next));
});
test('worker acceptance and recovery require the exact durable job identity and intent', () => {
  const payload = {action: 'recover-rotation', request_id: id, family: 'management-tls'};
  assert.equal(acceptedJob({job_id: other}, payload), false); assert.equal(acceptedJob({job_id: id}, payload), true);
  assert.equal(matchingJob(job(), payload), true); assert.equal(matchingJob({...job(), family: 'peer-ca'}, payload), false);
  assert.equal(matchingJob(job('restore'), {action: 'recover-restore', request_id: id, backup_id: other}), false);
});
test('public worker states distinguish backup verification, extraction and actual restore', () => {
  for (const [action, state] of [['backup', 'captured'], ['verify', 'verified-files'], ['extract', 'verified-isolated-files'], ['restore', 'restored']]) {
    assert.ok(workerStatus({...backups(), jobs: [job(action, state)]}, 'backups'));
    assert.equal(workerStatus({...backups(), jobs: [job(action, 'rotated')]}, 'backups'), null);
  }
  assert.equal(workerStatus({...rotation(), jobs: [job(), job()]}, 'rotation'), null);
});
test('only public trust approvals receive the larger scoped transport budget', () => {
  const payload = {certificate: 'a'.repeat(65536), keylist: 'b'.repeat(131072)};
  assert.ok(workerBody(payload, 'trust')); assert.throws(() => workerBody(payload, 'maintenance'));
  assert.throws(() => workerBody({keylist: 'x'.repeat(262144)}, 'trust'));
});
test('scheduler save requires the submitted policy and exactly the next revision', () => {
  const before = maintenance(), payload = {action: 'save-policy', revision: 0, policy: policy()}, after = {...before, revision: 1, policies: [policy()]};
  assert.ok(checkedMaintenance(payload, before, after));
  for (const bad of [before, {...after, revision: 2}, {...after, policies: [{...policy(), enabled: true}]}]) assert.equal(checkedMaintenance(payload, before, bad), null);
});
test('scheduled job actions bind operation identity, family, due window and resulting state', () => {
  const before = {...maintenance(), policies: [policy()], jobs: [maintenanceJob()]}, payload = {action: 'reviewed', job_id: other};
  const after = {...before, jobs: [{...maintenanceJob(), state: 'reviewed'}]}; assert.ok(checkedMaintenance(payload, before, after));
  for (const change of [{id}, {family: 'device-tls'}, {due_at: now + 1}, {state: 'completed'}, {updated_at: now - 1}]) assert.equal(checkedMaintenance(payload, before, {...after, jobs: [{...after.jobs[0], ...change}]}), null);
});
test('device policy restrictions and UTC calendar parsing match native rules', () => {
  const draft = scheduleDraft(policy(), now * 1000); assert.deepEqual(schedulePayload(draft, 0, id).policy, policy());
  for (const next of ['2026-02-30T12:00', '2026-10-09', '2026-10-09T25:00', '2026-10-09T12:00+02:00']) assert.throws(() => schedulePayload({...draft, next}, 0, id));
  for (const target of ['seeder', '../device', 'a'.repeat(65)]) assert.equal(validPolicy({...policy(), family: 'device-instruction', target}), false);
  for (const interval_days of [7, 22]) assert.equal(validPolicy({...policy(), family: 'device-instruction', target: 'router-1', interval_days}), false);
});
for (const kind of ['rotation', 'backups', 'trust', 'maintenance']) test('malformed ' + kind + ' reads fail closed', async () => {
  const {c, f} = setup(); f[kind] = {}; await c.refreshAll(); assert.equal(c.state.valid[kind], false);
});
test('all normal trust and scheduled save actions retain explicit request identity', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('family', 'device-tls'); c.field('names', 'distribution.example');
  await c.performTrust('prepare'); assert.equal(c.item().state, 'awaiting-approval', c.state.messages.deployment.text);
  c.file('certificate', file(certificate)); await c.performTrust('approve'); assert.equal(c.item().state, 'approved', c.state.messages.deployment.text);
  await c.performTrust('cancel'); assert.equal(c.item().state, 'cancelled'); assert.deepEqual(c.state.files, {});
  c.scheduleField('family', 'browser-tls'); await c.schedule(); assert.equal(c.state.draftRevision, 1); assert.equal(c.state.schedule.selected, id);
  assert.equal(f.writes.length, 4);
});
for (const failure of ['wrong-id', 'wrong-state', 'network', 'http-202', 'http-409']) test('trust ' + failure + ' requires an explicit review and never replays on navigation', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.field('family', 'peer-ca');
  f.post = async () => {if (failure === 'network') throw Error('lost'); return response({...prepared('peer-ca'), ...(failure === 'wrong-id' ? {request_id: other} : failure === 'wrong-state' ? {state: 'cancelled'} : {})}, failure === 'http-202' ? 202 : failure === 'http-409' ? 409 : 200);};
  await c.performTrust('prepare'); assert.equal(c.state.unknown.deployment, true); assert.equal(c.canTrust('prepare'), false);
  await c.select('backups'); await c.select('certificates'); assert.equal(f.writes.length, 1); assert.equal(c.canTrust('prepare'), false);
  await c.review('deployment'); assert.equal(c.canTrust('prepare'), true); assert.equal(f.writes.length, 1);
});
test('unknown backup acceptance retains its id until matching history is explicitly reviewed', async () => {
  const {c, f} = setup('backups'); await c.refreshAll(); f.post = () => response({job_id: other});
  await c.backup('backup'); assert.equal(c.state.unknown.backups, true); assert.equal(c.pending['backup:backup'].id, id);
  f.backups.jobs = [job('backup', 'captured')]; await c.refreshAll(); assert.equal(c.state.unknown.backups, true);
  await c.review('backups'); assert.equal(c.state.unknown.backups, false); assert.equal(c.pending['backup:backup'], undefined);
  assert.equal(f.writes.length, 1);
});
test('dirty schedules preserve the reviewed revision after concurrent changes', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.scheduleField('family', 'browser-tls');
  f.maintenance.revision = 1; await c.refresh('maintenance'); assert.equal(c.state.draftRevision, 0); assert.equal(c.canSchedule(), false);
  await c.schedule(); assert.equal(f.writes.length, 0); c.chooseSchedule('', true); assert.equal(c.state.draftRevision, 1); assert.equal(c.canSchedule(), true);
});
test('lost policy-save response reconciles the same saved policy without creating another', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.scheduleField('family', 'browser-tls');
  f.post = (kind, payload) => {f.maintenance = {...f.maintenance, revision: 1, policies: [payload.policy]}; throw Error('lost');};
  await c.schedule(); assert.equal(c.state.unknown.maintenance, true); assert.equal(c.state.draftRevision, 0);
  await c.review('maintenance'); assert.equal(c.state.schedule.selected, id); assert.equal(c.state.draftRevision, 1); assert.equal(c.state.draftDirty, false); assert.equal(f.writes.length, 1);
});
test('rotation and backup history jointly block conflicting new worker operations', async () => {
  const {c, f} = setup(); f.backups.jobs = [job('restore', 'recovery-required')]; await c.refreshAll();
  assert.equal(c.canRotate(), false); c.field('family', 'peer-ca'); assert.equal(c.canTrust('prepare'), false);
  await c.select('backups'); assert.equal(c.canBackup('backup'), false); assert.equal(c.canBackup('recover-restore', id), true);
  f.rotation.jobs = [{...job(), id: other}]; await c.refresh('rotation'); assert.equal(c.canBackup('recover-restore', id), false);
});
test('explicit recovery targets the original operation, not the currently selected backup', async () => {
  const {c, f} = setup('backups'); f.backups.jobs = [job('restore', 'recovery-required')]; await c.refreshAll(); c.field('backupSelected', other);
  await c.backup('recover-restore', id); assert.deepEqual(f.writes[0].payload, {action: 'recover-restore', request_id: id, backup_id: id, allow_downtime: true, confirm_restore: true});
  assert.match(c.state.messages.backups.text, /Accepted operation/);
});
function recoveryRetention(action, identifier = id) {
  return {schema: 1, revision: hash, busy: true, recoverable_job_id: identifier,
    capacity: {history_used: 1, history_limit: 100, backup_used: 0, backup_limit: 20},
    jobs: [{id: identifier, action, state: 'recovery-required', backup_id: id, family: action === 'rotate' ? 'management-tls' : null,
      finished_at: now, retire_allowed: false, retire_reason: 'This operation needs recovery.'}], backups: [], operation: null};
}
for (const action of ['backup', 'restore', 'rotate']) test('actual busy retention permits only the original interrupted ' + action, async () => {
  const {c, f} = setup(action === 'rotate' ? 'certificates' : 'backups');
  f.backups.can_recover_backup = true;
  f[action === 'rotate' ? 'rotation' : 'backups'].jobs = [job(action, 'recovery-required')];
  f.backups.retention = recoveryRetention(action);
  await c.refreshAll();
  assert.equal(c.workerIdle(), false);
  assert.equal(action === 'rotate' ? c.canRotate(id) : c.canBackup('recover-' + action, id), true);
  f.backups.retention.recoverable_job_id = null; await c.refresh('backups');
  assert.equal(action === 'rotate' ? c.canRotate(id) : c.canBackup('recover-' + action, id), false);
});
test('backup recovery uses original IDs without requiring decryption or restoring files', async () => {
  const {c, f} = setup('backups');
  f.backups = {...f.backups, can_recover_backup: true, can_verify: false, can_restore: false,
    jobs: [job('backup', 'recovery-required')], retention: recoveryRetention('backup')};
  await c.refreshAll(); c.field('backupSelected', other);
  assert.equal(c.canBackup('backup'), false); assert.equal(c.canBackup('recover-backup', other), false);
  f.accept = false; await c.backup('recover-backup', id); assert.equal(f.writes.length, 0);
  f.accept = true; await c.backup('recover-backup', id);
  assert.deepEqual(f.writes[0].payload, {action: 'recover-backup', request_id: id, backup_id: id, allow_downtime: true});
  assert.equal(matchingJob(job('backup'), f.writes[0].payload), true);
  assert.equal(matchingJob({...job('backup'), backup_id: other}, f.writes[0].payload), false);
});
test('unsupported workers cannot advertise backup recovery through a history row alone', async () => {
  const {c, f} = setup('backups'); f.backups.jobs = [job('backup', 'recovery-required')];
  f.backups.retention = recoveryRetention('backup'); await c.refreshAll();
  assert.equal(c.canBackup('recover-backup', id), false);
  for (const invalid of ['true', 1, {}]) assert.equal(workerStatus({...f.backups, can_recover_backup: invalid}, 'backups'), null);
});
test('lost backup recovery response is reviewed without replay on navigation', async () => {
  const {c, f} = setup('backups'); f.backups.can_recover_backup = true;
  f.backups.jobs = [job('backup', 'recovery-required')]; f.backups.retention = recoveryRetention('backup');
  await c.refreshAll(); f.post = () => {throw Error('response lost');};
  await c.backup('recover-backup', id); assert.equal(c.state.unknown.backups, true);
  await c.select('certificates'); await c.select('backups'); assert.equal(f.writes.length, 1);
  await c.review('backups'); assert.equal(c.state.unknown.backups, false); assert.equal(f.writes.length, 1);
});
test('pre-dispatch file read locks actions and leaving the pane cancels unsent work', async () => {
  const {c, f} = setup(); f.trust.items[0] = prepared('device-tls', 'awaiting-approval'); await c.refreshAll(); c.field('family', 'device-tls');
  const pending = deferred(); c.file('certificate', {size: certificate.length, text: () => pending.promise});
  const work = c.performTrust('approve'); assert.equal(c.state.busy, true); await c.performTrust('approve'); await c.select('backups');
  pending.resolve(certificate); await work; assert.equal(f.writes.length, 0); assert.deepEqual(c.state.files, {});
});
test('leaving after dispatch preserves an uncertain outcome and never cancels or replays the job', async () => {
  const {c, f} = setup('backups'); await c.refreshAll(); const pending = deferred(); f.post = () => pending.promise;
  const work = c.backup('backup'); await Promise.resolve(); assert.equal(f.writes.length, 1); await c.select(null);
  pending.resolve(response({job_id: other})); await work; assert.equal(c.state.unknown.backups, true);
  await c.select('backups'); assert.equal(c.canBackup('backup'), false); assert.equal(f.writes.length, 1);
});
test('stale read cannot replace newer evidence or acknowledge an uncertain action', async () => {
  const {c, f} = setup(); await c.refreshAll(); c.state.unknown.deployment = true;
  const held = deferred(); f.read = kind => kind === 'trust' ? held.promise : response(f[kind]);
  const review = c.review('deployment'); await Promise.resolve(); f.read = null; await c.refresh('rotation');
  held.resolve(response(f.trust)); await review; assert.equal(c.state.unknown.deployment, true);
});
test('declined confirmation and private-file rejection send no requests', async () => {
  const {c, f} = setup(); await c.refreshAll(); f.accept = false; await c.rotate(); assert.equal(f.writes.length, 0);
  f.accept = true; f.trust.items[0] = prepared('device-tls', 'awaiting-approval'); await c.refresh('trust'); c.field('family', 'device-tls');
  c.file('certificate', file('-----BEGIN PRIVATE KEY-----')); await c.performTrust('approve'); assert.equal(f.writes.length, 0); assert.match(c.state.messages.deployment.text, /public approvals only/);
});
test('public refusal guidance is allowlisted and never echoes private exception text', () => {
  assert.match(workerRefusalHint(409, {error: 'certificate does not have a 30-day validity'}), /30-day/);
  assert.equal(workerRefusalHint(409, {error: 'PRIVATE KEY file /protected/key missing'}), '');
  assert.match(workerRefusalHint(401, {}), /Sign in again/);
});
for (const [family, beforeState, action, afterState] of [
  ['online-signer', 'intervention-required', 'retry', 'approval-required'],
  ['online-signer', 'intervention-required', 'retry', 'intervention-required'],
  ['device-instruction', 'intervention-required', 'retry', 'completed'],
  ['management-token', 'intervention-required', 'reconcile-management', 'verification-required'],
  ['management-token', 'intervention-required', 'reconcile-management', 'cancelled'],
  ['management-token', 'verification-required', 'retire-management', 'completed'],
]) test('scheduled ' + family + ' ' + action + ' verifies ' + afterState, () => {
  const target = family === 'device-instruction' ? 'edge-01' : 'deployment';
  const row = {...maintenanceJob(family, beforeState), target, before: 'ab'.repeat(32), after: 'cd'.repeat(32)};
  const before = {...maintenance(), policies: [{...policy(), family, target}], jobs: [row]}, payload = {action, job_id: row.id};
  const after = {...before, jobs: [{...row, state: afterState}]};
  assert.ok(checkedMaintenance(payload, before, after));
  assert.equal(checkedMaintenance(payload, before, {...after, jobs: [{...row, state: 'running'}]}), null);
  if (action === 'retire-management') assert.equal(checkedMaintenance(payload, before, {...after, jobs: [{...after.jobs[0], after: hash}]}), null);
});
test('rotation recovery keeps the history family and ID despite a different selected family', async () => {
  const {c, f} = setup(); f.rotation.jobs = [job('rotate', 'recovery-required')]; await c.refreshAll(); c.field('family', 'age-identity');
  assert.equal(c.canRotate(), false); assert.equal(c.canRotate(id), true); await c.rotate(id);
  assert.deepEqual(f.writes[0].payload, {action: 'recover-rotation', family: 'management-tls', allow_downtime: true, request_id: id});
});
