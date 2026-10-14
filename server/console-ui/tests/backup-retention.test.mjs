// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {retentionStatus, retentionOperation, matchingRetention} from '../src/backup-retention-model.mjs';
import {WorkerLifecycleController} from '../src/worker-lifecycle-controller.mjs';
import {urls, workerStatus} from '../src/worker-lifecycle-model.mjs';
import {id, other, hash, now, rotation, backups, job, response} from './worker-fixtures.mjs';

const third = '33333333-3333-4333-8333-333333333333';
const row = () => ({id: other, action: 'verify', state: 'failed', backup_id: id, family: null,
  finished_at: now, retire_allowed: true, retire_reason: ''});
const retained = () => ({schema: 1, revision: hash, busy: false,
  capacity: {history_used: 1, history_limit: 100, backup_used: 1, backup_limit: 20}, jobs: [row()],
  backups: [{backup_id: id, created_at: now, delete_allowed: true, delete_reason: ''}], operation: null});
const operation = (action = 'retire-history', state = 'completed') => ({request_id: third, action, state,
  retired_count: action === 'retire-history' ? 1 : 0, backup_id: action === 'retire-history' ? null : id});
async function setup() {
  const c = new WorkerLifecycleController(), f = {visible: true, accept: true, reads: [], writes: [],
    rotation: rotation(), backups: {...backups(), jobs: [job('backup', 'captured')], retention: retained()}, post: null};
  c.connect({visible: () => f.visible, uuid: () => third, confirm: () => f.accept, now: () => now * 1000,
    headers: extra => ({...extra, 'X-CSRF-Token': 'fixture'}), fetch: async (path, options = {}) => {
      const address = new URL(path, 'https://fixture.test'), kind = Object.keys(urls).find(key => urls[key] === address.pathname);
      assert.ok(kind);
      if (!options.method) {f.reads.push(address); return response(f[kind]);}
      assert.equal(options.headers['X-CSRF-Token'], 'fixture'); const payload = JSON.parse(options.body); f.writes.push(payload);
      return f.post ? f.post(payload) : response({retention_operation: operation(payload.action)});
    }});
  c.pane = 'backups'; await c.refreshAll(); c.field('backupSelected', id); c.field('backupDeleteSelected', id); return {c, f};
}

test('old workers stay supported without enabling unadvertised cleanup', async () => {
  assert.equal(workerStatus(backups(), 'backups').retention, null);
  const {c, f} = await setup(); delete f.backups.retention; await c.refresh('backups');
  for (const action of ['retire-history', 'delete-backup', 'resume-delete']) assert.equal(c.canRetire(action), false);
  assert.equal(c.canBackup('backup'), true);
});
test('retention status validates limits, exact fields, unique IDs and protected history', () => {
  assert.deepEqual(retentionStatus(retained()), retained());
  const unknown = retained(); unknown.backups[0] = {...unknown.backups[0], created_at: null, delete_allowed: false, delete_reason: 'Ownership not established'};
  assert.ok(retentionStatus(unknown));
  for (const mutate of [value => {value.schema = 2;}, value => {value.revision = 'stale';},
    value => {value.capacity.history_used = 0;}, value => {value.capacity.backup_limit = 30;},
    value => {value.jobs[0].state = 'running';}, value => {value.jobs[0].state = 'recovery-required';},
    value => {value.jobs[0].state = 'captured';}, value => {value.jobs[0].secret = 'private';},
    value => {value.jobs.push(row()); value.capacity.history_used++;},
    value => {value.backups[0].backup_id = '../foreign';}, value => {value.backups[0].delete_allowed = 1;},
    value => {value.operation = {};}, value => {value.busy = 'false';}]) {
    const value = retained(); mutate(value); assert.equal(retentionStatus(value), null);
    assert.equal(workerStatus({...backups(), retention: value}, 'backups'), null);
  }
});
test('same-job recovery hint requires one exact interrupted row and a busy worker', () => {
  const value = retained(); value.busy = true; value.recoverable_job_id = other;
  value.jobs[0] = {...value.jobs[0], state: 'recovery-required', retire_allowed: false};
  assert.ok(retentionStatus(value));
  for (const patch of [{recoverable_job_id: id}, {recoverable_job_id: 'bad'}, {busy: false}]) {
    assert.equal(retentionStatus({...value, ...patch}), null);
  }
  value.jobs[0].state = 'running'; assert.equal(retentionStatus(value), null);
  value.recoverable_job_id = null; assert.ok(retentionStatus(value));
});
test('operation acknowledgements bind exact request, action, count and backup', () => {
  const payload = {action: 'retire-history', request_id: third, job_ids: [other]};
  assert.ok(matchingRetention(operation(), payload));
  for (const patch of [{request_id: other}, {retired_count: 0}, {backup_id: id}, {state: 'failed'}, {extra: true}]) {
    assert.equal(matchingRetention({...operation(), ...patch}, payload), false);
  }
  assert.ok(retentionOperation(operation('delete-backup', 'running')));
  assert.ok(matchingRetention(operation('delete-backup'), {action: 'resume-delete', request_id: third, backup_id: id}));
  assert.equal(matchingRetention(operation('delete-backup'), {action: 'delete-backup', request_id: third, backup_id: other}), false);
});
test('protected upgrade archives are optional, exact and separately counted', () => {
  const value = retained();
  value.protected_upgrade_backups = [{operation_id: third, attempt: 1, phase: 'upgraded', deployment_archive: true, recovery_archive: true}];
  value.capacity.protected_upgrade_used = 1;
  assert.deepEqual(retentionStatus(value), value);
  const partial = structuredClone(value); partial.protected_upgrade_backups[0].recovery_archive = false;
  assert.ok(retentionStatus(partial));
  for (const mutate of [v => {delete v.capacity.protected_upgrade_used;}, v => {delete v.protected_upgrade_backups;},
    v => {v.capacity.protected_upgrade_used = 0;}, v => {v.capacity.protected_upgrade_used = true;},
    v => {v.protected_upgrade_backups[0].attempt = 0;}, v => {v.protected_upgrade_backups[0].attempt = 4;},
    v => {v.protected_upgrade_backups[0].phase = 'unknown';}, v => {v.protected_upgrade_backups[0].operation_id = '../foreign';},
    v => {v.protected_upgrade_backups[0].deployment_archive = false; v.protected_upgrade_backups[0].recovery_archive = false;},
    v => {v.protected_upgrade_backups[0].delete_allowed = true;},
    v => {v.protected_upgrade_backups.push({...v.protected_upgrade_backups[0]}); v.capacity.protected_upgrade_used++;}]) {
    const bad = structuredClone(value); mutate(bad); assert.equal(retentionStatus(bad), null);
  }
});
test('protected upgrade backups never become selectable deletion or restore targets', async () => {
  const {c, f} = await setup();
  f.backups.retention.protected_upgrade_backups = [{operation_id: third, attempt: 2,
    phase: 'upgraded', deployment_archive: true, recovery_archive: false}];
  f.backups.retention.capacity.protected_upgrade_used = 1; await c.refresh('backups');
  assert.equal(c.state.valid.backups, true); assert.equal(c.canBackup('backup'), true);
  c.field('backupDeleteSelected', third); assert.equal(c.canRetire('delete-backup'), false);
  c.field('backupSelected', third); assert.equal(c.canBackup('restore'), false);
});
test('clear history uses a reviewed revision and bounded exact finished IDs', async () => {
  const {c, f} = await setup(); await c.retire('retire-history');
  assert.deepEqual(f.writes, [{action: 'retire-history', request_id: third, expected_revision: hash, job_ids: [other]}]);
  assert.match(c.state.messages.backups.text, /Cleared 1 finished history record\./);
  assert.equal(c.state.retentionAttempt, null); assert.equal(c.state.retentionUncertain, false);
});
test('history selection is capped at 25 and excludes protected rows', async () => {
  const {c, f} = await setup(); const rows = Array.from({length: 30}, (_, index) => ({...row(),
    id: '44444444-4444-4444-8444-' + String(index).padStart(12, '0')}));
  rows[0].retire_allowed = false; rows[0].retire_reason = 'Needed for recovery';
  f.backups.retention.jobs = rows; f.backups.retention.capacity.history_used = rows.length;
  await c.refresh('backups'); f.post = payload => response({retention_operation: {...operation(), retired_count: payload.job_ids.length}});
  await c.retire('retire-history'); assert.equal(f.writes[0].job_ids.length, 25); assert.equal(f.writes[0].job_ids.includes(rows[0].id), false);
});
test('existing backups above the limit stay visible for cleanup but block new captures', async () => {
  const {c, f} = await setup();
  f.backups.retention.backups = Array.from({length: 21}, (_, index) => ({...retained().backups[0],
    backup_id: index ? '55555555-5555-4555-8555-' + String(index).padStart(12, '0') : id}));
  f.backups.retention.capacity.backup_used = 21; await c.refresh('backups');
  assert.equal(c.state.valid.backups, true); assert.equal(c.canBackup('backup'), false);
  assert.equal(c.canRetire('delete-backup'), true); assert.equal(c.canBackup('verify'), true);
  await c.select('certificates'); assert.equal(c.canRotate(), false);
});
test('full recent history permits clearing records without admitting new jobs', async () => {
  const {c, f} = await setup(); f.backups.retention.jobs = Array.from({length: 100}, (_, index) => ({...row(),
    id: '66666666-6666-4666-8666-' + String(index).padStart(12, '0')}));
  f.backups.retention.capacity.history_used = 100; await c.refresh('backups');
  assert.equal(c.canBackup('backup'), false); assert.equal(c.canBackup('verify'), false);
  assert.equal(c.canRetire('retire-history'), true); assert.equal(c.canRetire('delete-backup'), true);
  await c.select('certificates'); assert.equal(c.canRotate(), false);
});
test('delete requires exact selected backup and separate confirmation', async () => {
  const {c, f} = await setup(); f.accept = false; await c.retire('delete-backup');
  assert.equal(f.writes.length, 0); assert.equal(c.state.retentionAttempt, null);
  f.accept = true; c.field('backupDeleteSelected', other); await c.retire('delete-backup'); assert.equal(f.writes.length, 0);
  c.field('backupDeleteSelected', id); c.field('backupSelected', other); await c.retire('delete-backup');
  assert.deepEqual(f.writes[0], {action: 'delete-backup', request_id: third, expected_revision: hash, backup_id: id, confirm_delete: true});
  assert.match(c.state.messages.backups.text, /deployment and recovery archives/);
});
for (const status of [400, 401, 403, 409]) test('definite cleanup refusal ' + status + ' does not strand an unknown request', async () => {
  const {c, f} = await setup(); f.post = () => response({error: 'not echoed private error'}, status);
  await c.retire('delete-backup'); assert.equal(c.state.retentionUncertain, false); assert.equal(c.state.retentionAttempt, null);
  assert.equal(!!c.state.unknown.backups, false); assert.match(c.state.messages.backups.text, /Cleanup request refused/);
  assert.doesNotMatch(c.state.messages.backups.text, /private error/); assert.equal(f.writes.length, 1);
});
for (const failure of ['network', 'wrong-id', '503']) test('uncertain cleanup ' + failure + ' requires exact read evidence without replay', async () => {
  const {c, f} = await setup();
  f.post = () => {if (failure === 'network') throw Error(); return response({retention_operation: {...operation(), request_id: id}}, failure === '503' ? 503 : 200);};
  await c.retire('retire-history'); assert.equal(c.state.retentionUncertain, true); assert.equal(c.canBackup('backup'), false);
  const original = structuredClone(c.state.retentionAttempt);
  assert.equal(f.reads.at(-1).searchParams.get('retention_request_id'), third);
  await c.select(null); await c.select('backups'); await c.review('backups');
  assert.equal(c.state.unknown.backups, true); assert.deepEqual(c.state.retentionAttempt, original); assert.equal(f.writes.length, 1);
  f.backups.retention.operation = {...operation(), request_id: id}; await c.review('backups'); assert.equal(c.state.unknown.backups, true);
  f.backups.retention.operation = operation(); await c.review('backups');
  assert.equal(c.state.unknown.backups, false); assert.equal(c.state.retentionUncertain, false); assert.equal(c.state.retentionAttempt, null);
  assert.equal(f.writes.length, 1);
});
test('a later uncertain backup is not confused with a completed history cleanup', async () => {
  const {c, f} = await setup(); await c.retire('retire-history');
  f.post = () => response({job_id: other}); await c.backup('backup'); assert.equal(c.state.unknown.backups, true);
  f.backups.jobs.push({...job('backup', 'captured'), id: third, backup_id: third});
  await c.review('backups'); assert.equal(c.state.unknown.backups, false); assert.equal(c.state.retentionUncertain, false);
});
test('unfinished cleanup blocks other maintenance but permits exact deletion recovery', async () => {
  const {c, f} = await setup(); f.backups.retention.busy = true;
  f.backups.retention.operation = operation('delete-backup', 'recovery-required'); await c.refresh('backups');
  assert.equal(c.canBackup('backup'), false); assert.equal(c.canRetire('retire-history'), false); assert.equal(c.canRetire('delete-backup'), false);
  c.field('backupDeleteSelected', other); assert.equal(c.canRetire('resume-delete'), true);
  f.post = () => response({retention_operation: operation('delete-backup', 'running')}); await c.retire('resume-delete');
  assert.deepEqual(f.writes[0], {action: 'resume-delete', request_id: third, expected_revision: hash, backup_id: id, confirm_delete: true});
  await c.select('certificates'); assert.equal(c.canRotate(), false);
  await c.select('backups'); f.rotation.jobs = [job()]; await c.refresh('rotation'); assert.equal(c.canRetire('resume-delete'), false);
});
