// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {epoch, requestId} from './certificates-model.mjs';
import {refusalHint} from './security-lifecycle-model.mjs';
import {retentionStatus} from './backup-retention-model.mjs';
export const urls = {rotation: '/api/v1/settings/deployment-rotation', trust: '/api/v1/settings/trust-rotation',
  maintenance: '/api/v1/settings/key-maintenance', backups: '/api/v1/settings/backups'};
export const rotationFamilies = ['management-tls', 'device-tls', 'peer-ca', 'instruction-roots', 'age-identity', 'age-recovery', 'seeder-announce'];
export const familyLabels = {'management-tls': 'Console-to-server certificate', 'device-tls': 'Device connection certificate',
  'peer-ca': 'Private swarm certificate authority', 'instruction-roots': 'Root signing keys', 'age-identity': 'Server encryption key',
  'age-recovery': 'Backup recovery recipient', 'seeder-announce': 'Seeder announce credential'};
export const topologyLabels = {'single-docker': 'Docker on one host', 'split-docker': 'Docker on separate hosts', kubernetes: 'Kubernetes', unavailable: 'Unavailable'};
export const stamp = value => epoch(value) && value >= 0;
export const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const boundedText = (value, limit = 1024) => typeof value === 'string' && value.length <= limit;
export const unique = list => new Set(list).size === list.length;
export const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const pick = (value, keys) => Object.fromEntries(keys.map(key => [key, value[key]]));
export function publicProof(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) throw Error('Worker evidence is invalid.');
  let nodes = 0;
  const valid = (item, depth = 0) => {
    if (++nodes > 4096 || depth > 8) return false;
    if (item === null || typeof item === 'boolean' || typeof item === 'number' && Number.isFinite(item)) return true;
    if (typeof item === 'string') return boundedText(item, 4096);
    if (Array.isArray(item)) return item.length <= 1024 && item.every(entry => valid(entry, depth + 1));
    return typeof item === 'object' && Object.entries(item).every(([key, entry]) => boundedText(key, 128) && valid(entry, depth + 1));
  };
  if (!valid(value) || JSON.stringify(value).length > 65536) throw Error('Worker evidence is oversized.');
  return structuredClone(value);
}
function job(row, kind) {
  if (!row || !requestId(row.id) || !stamp(row.started_at) || !boundedText(row.detail, 2048) ||
      row.finished_at !== undefined && (!stamp(row.finished_at) || row.finished_at < row.started_at)) return null;
  const states = kind === 'rotation' ? {rotate: ['running', 'rotated', 'failed', 'recovery-required']}
    : {backup: ['running', 'captured', 'failed', 'recovery-required'], verify: ['running', 'verified-files', 'failed', 'recovery-required'],
      extract: ['running', 'verified-isolated-files', 'failed', 'recovery-required'], restore: ['running', 'restored', 'failed', 'recovery-required']};
  if (!states[row.action]?.includes(row.state) || (kind === 'rotation' ? !rotationFamilies.includes(row.family) : !requestId(row.backup_id))) return null;
  try {return {...pick(row, ['id', 'action', 'state', 'started_at', 'detail']), ...(kind === 'rotation' ? {family: row.family} : {backup_id: row.backup_id}),
    finished_at: row.finished_at ?? null, proof: publicProof(row.proof)};} catch {return null;}
}
export function workerStatus(data, kind) {
  if (!['rotation', 'backups'].includes(kind) || !data || typeof data.available !== 'boolean' || !Object.hasOwn(topologyLabels, data.target) ||
      !boundedText(data.note, 4096) || !Array.isArray(data.jobs) || data.jobs.length > 100 || !unique(data.jobs.map(row => row?.id))) return null;
  if (data.available !== (data.target !== 'unavailable')) return null;
  const jobs = data.jobs.map(row => job(row, kind)); if (jobs.some(row => !row)) return null;
  const result = {...pick(data, ['available', 'target', 'note']), jobs};
  if (kind === 'rotation') {
    if (typeof data.can_rotate !== 'boolean' || !Array.isArray(data.families) || !unique(data.families) || !data.families.every(family => rotationFamilies.includes(family))) return null;
    if (!data.available && (data.can_rotate || jobs.length || data.families.length)) return null;
    return {...result, can_rotate: data.can_rotate, families: [...data.families]};
  }
  if (!['can_verify', 'can_extract', 'can_restore'].every(key => typeof data[key] === 'boolean') || !boundedText(data.storage, 256)) return null;
  if (!data.available && (jobs.length || data.can_verify || data.can_extract || data.can_restore)) return null;
  if (data.available && data.restore_scope !== 'same-deployment-same-security-generation') return null;
  if (data.can_recover_backup !== undefined && typeof data.can_recover_backup !== 'boolean') return null;
  if (!data.available && data.can_recover_backup === true) return null;
  const retention = data.retention === undefined ? null : retentionStatus(data.retention);
  if (data.retention !== undefined && !retention) return null;
  return {...result, ...pick(data, ['can_verify', 'can_extract', 'can_restore', 'storage']), can_recover_backup: data.can_recover_backup === true, restore_scope: data.restore_scope ?? null, retention};
}
export const activeJobs = state => [...(state.rotation?.jobs || []), ...(state.backups?.jobs || [])].filter(row => ['running', 'recovery-required'].includes(row.state));
export function acceptedJob(data, payload) {return !!data && data.job_id === payload.request_id && requestId(data.job_id);}
export function matchingJob(row, payload) {
  return !!row && row.id === payload.request_id && row.action === ({'recover-rotation': 'rotate', 'recover-restore': 'restore', 'recover-backup': 'backup'}[payload.action] || payload.action) &&
    (payload.family ? row.family === payload.family : payload.action === 'backup' || row.backup_id === payload.backup_id);
}
export function workerBody(payload, kind) {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > (kind === 'trust' ? 256 * 1024 : 64 * 1024)) throw Error('The maintenance request exceeds its size limit.');
  return body;
}
export function workerRefusalHint(status, data) {
  const base = refusalHint(status, data); if (base) return base;
  const allowed = new Set([
    'Finish or cancel the pending trust rotation',
    'Finish online signer replacement and retirement before changing offline roots',
    'Keep the existing two root IDs when replacing their public keys',
    'Replacement roots must change at least one public key',
    'certificate does not have a 30-day validity',
    'Keylist must approve this exact preserved-revocation request',
    'Approval does not match this independent root attestation request',
    'Trust request changed; refresh before continuing',
    'Maintenance policies changed; refresh before saving',
    'Choose a future UTC start time',
    'Resolve this policy’s active operation before changing it',
    'Use the replacement credential and verify all Console copies before retirement',
    'Credential files do not prove this operation; restore custody before reconciliation',
  ]);
  return status === 409 && allowed.has(data?.error) ? data.error + '. ' : '';
}
