// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId} from './certificates-model.mjs';
import {stamp, digest, boundedText, unique, pick} from './worker-lifecycle-model.mjs';
export const maintenanceFamilies = {'online-signer': 'prepare', 'device-instruction': 'rotate', 'management-token': 'rotate',
  'browser-tls': 'review', 'management-tls': 'review', 'device-tls': 'review', 'peer-ca': 'review', 'offline-roots': 'review',
  'age-identity': 'review', 'seeder-token': 'review', 'metrics-token': 'review', 'collector-headers': 'review'};
export const activeMaintenance = ['running', 'approval-required', 'verification-required', 'review-required', 'intervention-required'];
const policyFields = ['id', 'family', 'target', 'enabled', 'next_at', 'interval_days', 'window_minutes'];
export const equalPolicy = (a, b) => !!a && !!b && policyFields.every(key => a[key] === b[key]);
export function validPolicy(policy) {
  return !!policy && requestId(policy.id) && Object.hasOwn(maintenanceFamilies, policy.family) && typeof policy.enabled === 'boolean' && stamp(policy.next_at) &&
    Number.isInteger(policy.interval_days) && policy.interval_days >= (policy.family === 'device-instruction' ? 8 : 1) && policy.interval_days <= (policy.family === 'device-instruction' ? 21 : 365) &&
    Number.isInteger(policy.window_minutes) && policy.window_minutes >= 5 && policy.window_minutes <= 1440 &&
    (policy.family === 'device-instruction' ? typeof policy.target === 'string' && /^(?!seeder$)[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(policy.target) : policy.target === 'deployment');
}
export function maintenanceStatus(data) {
  if (!data || data.schema !== 1 || !Number.isSafeInteger(data.revision) || data.revision < 0 ||
      !['not-observed', 'clock-error', 'stale', 'observed'].includes(data.worker) || data.observed_at !== null && !stamp(data.observed_at) ||
      !Array.isArray(data.families) || data.families.length !== Object.keys(maintenanceFamilies).length || !unique(data.families.map(row => row?.id)) ||
      !data.families.every(row => row && Object.hasOwn(maintenanceFamilies, row.id) && row.action === maintenanceFamilies[row.id] && boundedText(row.label, 256) && boundedText(row.requirement, 512)) ||
      !Array.isArray(data.policies) || data.policies.length > 32 || !data.policies.every(validPolicy) || !unique(data.policies.map(row => row.id)) ||
      !unique(data.policies.map(row => row.family + ':' + row.target)) || !Array.isArray(data.jobs) || data.jobs.length > 256 || !unique(data.jobs.map(row => row?.id))) return null;
  const jobs = [];
  for (const row of data.jobs) {
    if (!row || !requestId(row.id) || !requestId(row.policy_id) || !data.policies.some(policy => policy.id === row.policy_id) ||
        !validPolicy({id: row.policy_id, family: row.family, target: row.target, enabled: false, next_at: 0, interval_days: 14, window_minutes: 30}) ||
        ![...activeMaintenance, 'completed', 'reviewed', 'missed', 'cancelled'].includes(row.state) || !stamp(row.due_at) || !stamp(row.updated_at) ||
        !boundedText(row.detail, 300) || !['before', 'after'].every(key => row[key] === null || digest(row[key]))) return null;
    jobs.push(pick(row, ['id', 'policy_id', 'family', 'target', 'state', 'due_at', 'updated_at', 'detail', 'before', 'after']));
  }
  return {...pick(data, ['schema', 'revision', 'worker', 'observed_at']), policies: data.policies.map(row => pick(row, policyFields)), jobs,
    families: data.families.map(row => pick(row, ['id', 'label', 'action', 'requirement']))};
}
export function maintenanceAction(job) {
  if (!job) return null;
  if (job.state === 'review-required') return 'reviewed';
  if (job.state === 'verification-required' && job.family === 'management-token') return 'retire-management';
  if (job.state === 'intervention-required') return job.family === 'management-token' ? 'reconcile-management'
    : ['online-signer', 'device-instruction'].includes(job.family) ? 'retry' : null;
  return null;
}
export function checkedMaintenance(payload, before, data) {
  const state = maintenanceStatus(data); if (!state) return null;
  if (payload.action === 'save-policy') {
    if (state.revision !== payload.revision + 1 || !equalPolicy(payload.policy, state.policies.find(row => row.id === payload.policy.id))) return null;
    return state;
  }
  const old = before.jobs.find(row => row.id === payload.job_id), current = state.jobs.find(row => row.id === payload.job_id);
  if (!old || !current || ['policy_id', 'family', 'target', 'due_at'].some(key => current[key] !== old[key]) || current.updated_at < old.updated_at) return null;
  const expected = {'reviewed': ['reviewed'], 'retire-management': ['completed'], 'reconcile-management': ['verification-required', 'cancelled'],
    retry: old.family === 'online-signer' ? ['approval-required', 'intervention-required'] : ['completed', 'intervention-required']};
  if (!expected[payload.action]?.includes(current.state)) return null;
  if (payload.action === 'retire-management' && (!old.after || current.after !== old.after || current.before !== old.before)) return null;
  return state;
}
export function utcInput(seconds) {return new Date(seconds * 1000).toISOString().slice(0, 19);}
export function scheduleDraft(policy, now) {
  return {selected: policy?.id || '', family: policy?.family || 'online-signer', target: policy?.family === 'device-instruction' ? policy.target : '',
    next: utcInput(policy?.next_at ?? Math.floor(now / 1000) + 3600), interval: String(policy?.interval_days ?? 14), window: String(policy?.window_minutes ?? 30), enabled: policy?.enabled ?? false};
}
export function schedulePayload(draft, revision, id) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(draft.next)) throw Error('Choose a valid UTC start time.');
  const next = Date.parse(draft.next + 'Z');
  if (!Number.isFinite(next) || utcInput(next / 1000) !== (draft.next.length === 16 ? draft.next + ':00' : draft.next)) throw Error('Choose a valid UTC start time.');
  if (!/^\d+$/.test(draft.interval) || !/^\d+$/.test(draft.window)) throw Error('Use whole numbers for the interval and window length.');
  const policy = {id, family: draft.family, target: draft.family === 'device-instruction' ? draft.target.trim() : 'deployment', enabled: draft.enabled,
    next_at: next / 1000, interval_days: Number(draft.interval), window_minutes: Number(draft.window)};
  if (!validPolicy(policy) || !Number.isSafeInteger(revision) || revision < 0) throw Error('Check the device ID, UTC window and allowed interval.');
  return {action: 'save-policy', revision, policy};
}
