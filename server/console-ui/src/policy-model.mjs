// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Role intent only: quarantine and explicit device/server ACLs can further
// restrict a real pair. This is not a device compliance claim.
export function roleAllows(definitions, from, to) {
  if (!Object.hasOwn(definitions, from) || !Object.hasOwn(definitions, to)) return false;
  const role = definitions[from];
  return role.restricted !== true || from === to || (role.peers || []).includes(to);
}

export function roleConnections(definitions, name) {
  return Object.keys(definitions).sort().filter(peer =>
    roleAllows(definitions, name, peer) && roleAllows(definitions, peer, name));
}

export function distributionAllowed(role) {
  // An unrestricted role has no virtual ACL, so origin=false is ignored.
  return role.restricted !== true || role.origin !== false;
}

export function enforcementLabel(policy, ready) {
  if (!ready || !policy.enforcement) return 'Unavailable';
  if (policy.enforcement.stale !== false) return 'Not current';
  return {enforced: 'Enforced', degraded: 'Partly enforced', pending: 'Pending',
    rpc_unavailable: 'Transfer service unavailable', fail_closed: 'Fail closed'}[policy.enforcement.state] || 'Unavailable';
}

export function roleCapabilityMessage(policy, ready) {
  if (!ready) return 'Peer policy unavailable. Role changes are disabled; refresh to read current policy.';
  if (policy.roles_supported !== true) return 'This Console cannot confirm backend role support. '
    + (policy.roles_present ? 'The backend declares role state. ' : '')
    + 'Role changes are disabled. Use a compatible server. Independent peer quarantine is not enforced by older servers. '
    + 'Use a reviewed containment and compatibility procedure before downgrading. A fully downgraded Console and server cannot show this warning.';
  if (policy.fail_closed) return 'Peer policy is fail-closed. Peer discovery is denied and role changes are disabled. Restore a valid policy.';
  if (policy.degraded) return 'Peer policy is degraded. The server may be using a last-known-good policy or have lost role state. '
    + 'Role changes are disabled; check server startup logs and restore authoritative policy state.';
  return '';
}

const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const count = value => Number.isSafeInteger(value) && value >= 0;
export const policyCount = value => count(value) ? value : '—';
export function checkedPolicy(body) {
  return object(body) && Number.isSafeInteger(body.revision) && body.revision >= 1
    && Array.isArray(body.quarantine_assignments) && body.quarantine_assignments.every(id => typeof id === 'string' && id);
}
export function instructionMapRows(values, revisions, empty) {
  if (!object(values) || Object.values(values).some(value => !count(value))) return [{label: 'unavailable'}];
  // Revision keys are decimal strings, never Numbers: policy revisions can
  // exceed JavaScript's safe integer range in the instruction rollup.
  const keys = Object.keys(values).sort(revisions ? (a, b) => a.length - b.length || (a < b ? -1 : a > b ? 1 : 0) : undefined);
  return keys.length ? keys.map(key => ({label: revisions ? 'r' + key : key, count: values[key]})) : [{label: empty}];
}
export function instructionDiagnostics(policy, formatDate) {
  const rollup = object(policy.fleet_rollup) ? policy.fleet_rollup : null;
  const status = policy.instruction_status || {}, custody = object(policy.instruction_keys) ? policy.instruction_keys : null;
  const devices = value => count(value) ? `${value} device${value === 1 ? '' : 's'}` : 'unavailable';
  const days = value => Number.isSafeInteger(value) ? `${value} days` : 'unavailable';
  const cells = {
    'policy-issued-revision': typeof status.issued_revision_label === 'string' ? status.issued_revision_label
      : count(rollup?.issued_revision) ? 'r' + rollup.issued_revision : 'unavailable',
    'policy-instr-stamp-missing': devices(status.instr_stamp_missing), 'policy-pointer-skew': devices(status.pointer_skew),
    'policy-instruction-observed': Number.isFinite(status.observed_at) && status.observed_at >= 0 ? formatDate(status.observed_at) : 'unavailable',
    'instruction-key-state': typeof custody?.state === 'string' ? custody.state : 'unavailable',
    'instruction-cert-days': days(custody?.certificate_days_to_expiry), 'instruction-keylist-age': days(custody?.keylist_age_days),
    'instruction-root-ceremony': ['ok', 'warn', 'critical', 'unknown'].includes(custody?.root_ceremony_overdue) ? custody.root_ceremony_overdue : 'unknown',
    'instruction-root-quorum': 'unknown', 'instruction-key-actions': 'unavailable',
  };
  if (custody) {
    const roots = count(custody.roots_attested_180d) && count(custody.roots_configured)
      ? ` · ${custody.roots_attested_180d}/${custody.roots_configured} roots attested in 180 days` : '';
    cells['instruction-root-quorum'] = custody.enabled === false ? 'not enabled' : custody.enabled !== true ? 'unknown'
      : custody.root_quorum_degraded === true ? 'degraded' + roots : custody.root_quorum_degraded === false ? 'healthy' + roots : 'unknown';
    const flags = [['certificate_renewal_due', 'certificate renewal due'], ['signing_refused', 'signing refused'], ['keylist_resign_due', 'key list re-sign due']];
    cells['instruction-key-actions'] = custody.enabled === false ? 'not enabled' : custody.enabled !== true || flags.some(([key]) => typeof custody[key] !== 'boolean')
      ? 'unavailable' : flags.filter(([key]) => custody[key]).map(([, text]) => text).join(' · ') || 'none';
  }
  return {cells,
    applied: instructionMapRows(count(status.pointer_skew) && rollup ? rollup.applied : null, true, 'No accepted identity reported.'),
    states: instructionMapRows(rollup?.states, false, 'No inventory devices.')};
}
export function policyDiagnostics(policy, ready, formatDate) {
  const p = ready ? policy : {}, roles = p.roles || {}, origin = p.origin_qos || {}, enforcement = p.enforcement || {}, mutual = enforcement.mutual_origin || {};
  const outbox = policyCount(p.outbox?.unacknowledged) + '/' + policyCount(p.outbox?.capacity);
  const originState = {enforced: 'enforced', degraded: 'degraded', rpc_unavailable: 'RPC unavailable'}[origin.state] || 'unavailable';
  const reconciled = origin.last_reconciled_at === 0 ? 'never' : Number.isFinite(origin.last_reconciled_at) && origin.last_reconciled_at > 0
    ? formatDate(origin.last_reconciled_at) : 'unavailable';
  return {cells: {'policy-roles-defined': policyCount(roles.defined), 'policy-roles-restricted': policyCount(roles.restricted),
    'policy-role-drift': policyCount(p.role_drift?.count), 'policy-outbox': outbox},
    summary: ready ? `${policyCount(roles.defined)} roles · ${policyCount(roles.restricted)} restricted · ${policyCount(p.role_drift?.count)} drift · outbox ${outbox}` : 'Policy counts unavailable',
    members: instructionMapRows(roles.members, false, ready && roles.defined === 0 ? 'No roles defined.' : 'Role member counts unavailable.'),
    origin: `Last origin QoS state: ${originState} · ${policyCount(origin.applied_download_count)}/${policyCount(origin.target_download_count)} downloads applied · last reconciled: ${reconciled}. Origin limits apply globally or per torrent, not per role.`,
    mutual: mutual.mode === 'preflight' ? (count(mutual.newly_denied_device_count) ? `Mutual-origin preflight only: ${mutual.newly_denied_device_count} newly denied devices.`
      : 'Mutual-origin preflight count unavailable.') + ' This additional origin restriction is not active.' + (enforcement.stale ? ' Tracker status is stale; check the tracker process.' : '')
      : mutual.mode === 'enforce' ? 'Reviewed origin restrictions requested. Distribution access shows the separately verified application status.' : 'Mutual-origin preflight status unavailable.',
    instruction: instructionDiagnostics(p, formatDate)};
}
