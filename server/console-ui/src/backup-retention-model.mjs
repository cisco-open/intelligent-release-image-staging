// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId} from './certificates-model.mjs';

const object = value => value && typeof value === 'object' && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).sort().join(',') === fields.split(' ').sort().join(',');
const count = (value, limit) => Number.isSafeInteger(value) && value >= 0 && value <= limit;
const stamp = value => Number.isSafeInteger(value) && value >= 0;
const text = value => typeof value === 'string' && value.length <= 1024;
const unique = values => new Set(values).size === values.length;
const actions = ['backup', 'verify', 'extract', 'restore', 'rotate', 'renew-transport'];
const states = ['running', 'recovery-required', 'failed', 'captured', 'verified-files', 'verified-isolated-files', 'restored', 'rotated', 'renewed'];
export const upgradeArchivePhases = Object.freeze({
  building: 'Historical preparation', prepared: 'Historical operation prepared', fencing: 'Stopping new work',
  'backing-up': 'Saving recovery archives', stopped: 'Services stopped', publishing: 'Updating files',
  published: 'Updated files ready', starting: 'Starting services', verifying: 'Checking deployment',
  worker: 'Updating maintenance worker', finishing: 'Completing recorded operation', upgraded: 'Recorded operation complete',
  cancelled: 'Recorded operation cancelled', 'recovery-required': 'Needs recovery',
});

function protectedUpgradeBackups(value) {
  if (!Array.isArray(value) || !unique(value.map(row => row?.operation_id + ':' + row?.attempt))) return false;
  return value.every(row => exact(row, 'operation_id attempt phase deployment_archive recovery_archive') &&
    requestId(row.operation_id) && count(row.attempt, 3) && row.attempt > 0 && Object.hasOwn(upgradeArchivePhases, row.phase) &&
    typeof row.deployment_archive === 'boolean' && typeof row.recovery_archive === 'boolean' &&
    (row.deployment_archive || row.recovery_archive));
}

export function retentionOperation(value) {
  if (!exact(value, 'request_id action state retired_count backup_id') || !requestId(value.request_id) ||
      !['retire-history', 'delete-backup'].includes(value.action) ||
      !['running', 'completed', 'recovery-required'].includes(value.state) || !count(value.retired_count, 100) ||
      (value.action === 'retire-history' ? value.backup_id !== null : !requestId(value.backup_id))) return null;
  return structuredClone(value);
}

export function retentionStatus(value) {
  const upgraded = object(value) && Object.hasOwn(value, 'protected_upgrade_backups');
  const recoverable = object(value) && Object.hasOwn(value, 'recoverable_job_id');
  const inventory = object(value) && Object.hasOwn(value, 'inventory_available');
  const unavailable = inventory && value.inventory_available === false;
  if (!exact(value, 'schema revision busy capacity jobs backups operation' + (upgraded ? ' protected_upgrade_backups' : '') +
      (recoverable ? ' recoverable_job_id' : '') + (inventory ? ' inventory_available storage_problem' : '')) || value.schema !== 1 ||
      (inventory && (typeof value.inventory_available !== 'boolean' || (unavailable ?
        !upgraded || !text(value.storage_problem) || !value.storage_problem : value.storage_problem !== null))) ||
      typeof value.revision !== 'string' || !/^[a-f0-9]{64}$/.test(value.revision) || typeof value.busy !== 'boolean' ||
      !exact(value.capacity, 'history_used history_limit backup_used backup_limit' + (upgraded ? ' protected_upgrade_used' : '')) ||
      (upgraded && (!protectedUpgradeBackups(value.protected_upgrade_backups) ||
        (unavailable ? value.capacity.protected_upgrade_used !== null || value.protected_upgrade_backups.length !== 0 :
          value.capacity.protected_upgrade_used !== value.protected_upgrade_backups.length))) ||
      value.capacity.history_limit !== 100 || value.capacity.backup_limit !== 20 ||
      !count(value.capacity.history_used, 100) || (unavailable ? value.capacity.backup_used !== null :
        !count(value.capacity.backup_used, Number.MAX_SAFE_INTEGER)) ||
      !Array.isArray(value.jobs) || value.jobs.length !== value.capacity.history_used || !unique(value.jobs.map(row => row?.id)) ||
      !value.jobs.every(row => exact(row, 'id action state backup_id family finished_at retire_allowed retire_reason') &&
        requestId(row.id) && actions.includes(row.action) && states.includes(row.state) &&
        (row.backup_id === null || requestId(row.backup_id)) && (row.family === null || text(row.family)) &&
        (row.finished_at === null || stamp(row.finished_at)) && typeof row.retire_allowed === 'boolean' && text(row.retire_reason) &&
        (!row.retire_allowed || !unavailable && !['running', 'recovery-required', 'captured'].includes(row.state))) ||
      !Array.isArray(value.backups) || value.backups.length !== (unavailable ? 0 : value.capacity.backup_used) ||
      !unique(value.backups.map(row => row?.backup_id)) ||
      !value.backups.every(row => exact(row, 'backup_id created_at delete_allowed delete_reason') && requestId(row.backup_id) &&
        (row.created_at === null || stamp(row.created_at)) && typeof row.delete_allowed === 'boolean' && text(row.delete_reason)) ||
      (value.operation !== null && !retentionOperation(value.operation))) return null;
  if (recoverable && value.recoverable_job_id !== null) {
    const active = value.jobs.filter(row => ['running', 'recovery-required'].includes(row.state));
    if (!requestId(value.recoverable_job_id) || !value.busy || active.length !== 1 ||
        active[0].id !== value.recoverable_job_id || active[0].state !== 'recovery-required') return null;
  }
  return structuredClone(value);
}

export function matchingRetention(operation, payload) {
  return !!retentionOperation(operation) && !!payload && operation.request_id === payload.request_id &&
    operation.action === (payload.action === 'resume-delete' ? 'delete-backup' : payload.action) &&
    (operation.action === 'delete-backup' ? operation.backup_id === payload.backup_id :
      Array.isArray(payload.job_ids) && (operation.state !== 'completed' || operation.retired_count === payload.job_ids.length));
}
