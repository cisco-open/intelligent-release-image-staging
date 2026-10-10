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

export function retentionOperation(value) {
  if (!exact(value, 'request_id action state retired_count backup_id') || !requestId(value.request_id) ||
      !['retire-history', 'delete-backup'].includes(value.action) ||
      !['running', 'completed', 'recovery-required'].includes(value.state) || !count(value.retired_count, 100) ||
      (value.action === 'retire-history' ? value.backup_id !== null : !requestId(value.backup_id))) return null;
  return structuredClone(value);
}

export function retentionStatus(value) {
  if (!exact(value, 'schema revision busy capacity jobs backups operation') || value.schema !== 1 ||
      typeof value.revision !== 'string' || !/^[a-f0-9]{64}$/.test(value.revision) || typeof value.busy !== 'boolean' ||
      !exact(value.capacity, 'history_used history_limit backup_used backup_limit') ||
      value.capacity.history_limit !== 100 || value.capacity.backup_limit !== 20 ||
      !count(value.capacity.history_used, 100) || !count(value.capacity.backup_used, Number.MAX_SAFE_INTEGER) ||
      !Array.isArray(value.jobs) || value.jobs.length !== value.capacity.history_used || !unique(value.jobs.map(row => row?.id)) ||
      !value.jobs.every(row => exact(row, 'id action state backup_id family finished_at retire_allowed retire_reason') &&
        requestId(row.id) && actions.includes(row.action) && states.includes(row.state) &&
        (row.backup_id === null || requestId(row.backup_id)) && (row.family === null || text(row.family)) &&
        (row.finished_at === null || stamp(row.finished_at)) && typeof row.retire_allowed === 'boolean' && text(row.retire_reason) &&
        (!row.retire_allowed || !['running', 'recovery-required', 'captured'].includes(row.state))) ||
      !Array.isArray(value.backups) || value.backups.length !== value.capacity.backup_used ||
      !unique(value.backups.map(row => row?.backup_id)) ||
      !value.backups.every(row => exact(row, 'backup_id created_at delete_allowed delete_reason') && requestId(row.backup_id) &&
        (row.created_at === null || stamp(row.created_at)) && typeof row.delete_allowed === 'boolean' && text(row.delete_reason)) ||
      (value.operation !== null && !retentionOperation(value.operation))) return null;
  return structuredClone(value);
}

export function matchingRetention(operation, payload) {
  return !!retentionOperation(operation) && !!payload && operation.request_id === payload.request_id &&
    operation.action === (payload.action === 'resume-delete' ? 'delete-backup' : payload.action) &&
    (operation.action === 'delete-backup' ? operation.backup_id === payload.backup_id :
      Array.isArray(payload.job_ids) && (operation.state !== 'completed' || operation.retired_count === payload.job_ids.length));
}
