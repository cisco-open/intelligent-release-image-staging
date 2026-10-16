// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const revisionOk = value => Number.isSafeInteger(value) && value >= 1;
const count = value => Number.isSafeInteger(value) && value >= 0;
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
export function roleFailureText(failed = {}) {
  const ids = Object.keys(failed);
  return !ids.length ? '' : '; failed: ' + ids.slice(0, 10).map(id => `${id} (${failed[id] === 'role_shadowed_by_assignment'
    ? 'explicit ACL assignment shadows the role' : failed[id]})`).join(', ') + (ids.length > 10 ? `; and ${ids.length - 10} more` : '');
}
export function roleAccounting(body, ids) {
  return object(body) && count(body.applied) && object(body.failed)
    && Object.entries(body.failed).every(([id, reason]) => ids.includes(id) && typeof reason === 'string' && reason)
    && body.applied + Object.keys(body.failed).length === ids.length;
}
export function checkedRolePreview(body, ids, revision) {
  if (!roleAccounting(body, ids) || typeof body.ok !== 'boolean' || body.dry_run !== true
    || !revisionOk(body.revision) || body.revision < revision) throw new Error('Preview response incomplete. No commit was sent; refresh and preview again.');
  if (!body.ok || !body.applied) return null;
  if (['member_delta', 'origin_access_lost', 'empty_permitted_sets', 'role_pairs_stopped'].some(key => !count(body[key]))
    || typeof body.qos_changed !== 'boolean' || typeof body.requires_confirmation !== 'boolean'
    || (body.confirm_token !== null && (typeof body.confirm_token !== 'string' || !body.confirm_token))
    || (body.requires_confirmation && !body.confirm_token)) throw new Error('Preview effects or confirmation are incomplete. No commit was sent; preview again.');
  return structuredClone(body);
}
export function rolePreviewText(body, role, total) {
  return `Set role to ${role || 'no role'} for ${body.applied}/${total} device(s)` + roleFailureText(body.failed) + '.\n'
    + `Membership changes: ${body.member_delta}\nDevices losing origin access: ${body.origin_access_lost}`
    + `\nEmpty permitted peer sets: ${body.empty_permitted_sets}\nRole pairings stopped: ${body.role_pairs_stopped}`
    + `\nQoS policy changed: ${body.qos_changed ? 'yes' : 'no'}`
    + '\nChanges affect new pairings; existing device-to-device sessions may continue.'
    + (body.requires_confirmation ? '\nThis exceeds the confirmation threshold. Set role confirms these effects.' : '');
}
export function roleProblem(status, body = {}) {
  const code = body?.error || body?.code;
  if (status === 412 || code === 'revision_conflict') return 'Peer policy changed. Refresh, then preview the change again before saving.';
  if (status === 428) return 'A fresh preview and confirmation are required. Preview the change again.';
  if (code === 'operation_backlog_full') return `The operation backlog is full (${count(body.unacknowledged) ? body.unacknowledged : 'unknown'}/${count(body.capacity) ? body.capacity : 'unknown'}). Wait for tracker acknowledgement, then preview again.`;
  return 'Set role was refused' + (typeof code === 'string' ? ': ' + code : ` (HTTP ${status})`) + '. Refresh and preview again.';
}
export function roleCommitResult(response, body, ids, revision) {
  const accounted = roleAccounting(body, ids) && count(body.role_drift?.count);
  // A failed cross-store write can still confirm partial work, but an HTTP
  // success must carry the ordinary commit contract, never preview evidence.
  if (response.status === 503 && body?.partial === true && accounted && revisionOk(body.revision)
    && body.revision >= revision && (body.dry_run === undefined || body.dry_run === false)) return 'partial';
  if (response.status >= 500) return 'unknown';
  if (!response.ok) return 'refused';
  if (!accounted || typeof body.ok !== 'boolean' || typeof body.partial !== 'boolean' || body.dry_run !== false
    || !revisionOk(body.revision) || body.revision < revision) return 'unknown';
  return body.ok && !body.partial && !Object.keys(body.failed).length && body.role_drift.count === 0 ? 'saved' : 'partial';
}
export function quarantineResult(response, body, value, revision) {
  if (response.status >= 500) return 'unknown';
  if (!response.ok) return 'refused';
  return body?.ok === true && body.quarantined === value && revisionOk(body.revision) && body.revision >= revision ? 'saved' : 'unknown';
}
export function quarantineConflict(response, body) {
  return (response.status === 412 && ['precondition failed', 'precondition_failed'].includes(body?.error || body?.code))
    || (response.status === 409 && (body?.error || body?.code) === 'revision_conflict');
}
