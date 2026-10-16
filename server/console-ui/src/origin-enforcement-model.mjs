// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const count = value => Number.isSafeInteger(value) && value >= 0;
const nullableCount = value => value === null || count(value);
export const originStates = {
  preflight: 'Preview only', pending: 'Waiting for confirmation', enforced: 'Blocks confirmed',
  review_required: 'Review needed', degraded: 'Needs attention', unavailable: 'Status unavailable',
};
export const originModeLabel = mode => ({preflight: 'Preview only', enforce: 'Enforce reviewed blocks'}[mode] || 'Unavailable');
export function originApplicationConfirmed(value) {
  return !!value && ((value.state === 'enforced' && value.mode === 'enforce') || (value.state === 'preflight' && value.mode === 'preflight'))
    && value.reason === null && Array.isArray(value.blockers) && value.blockers.length === 0
    && count(value.applied_device_count) && count(value.applied_ip_count)
    && Number.isFinite(value.last_verified_at) && value.last_verified_at > 0;
}
export function originNextAction(value, ready, reviewRequired) {
  if (reviewRequired) return 'Choose Refresh status and review the saved settings before trying another change.';
  if (!ready) return 'Choose Refresh status to read the saved settings and current effect.';
  return {
    preflight: 'To block distribution transfers denied by the policy, choose Enforce reviewed blocks, then Preview change.',
    pending: 'Wait for the transfer service to apply the saved change, then choose Refresh status to check for confirmation.',
    enforced: 'The last check confirmed the reviewed blocks. Refresh status for current confirmation, or preview a change to update or release them.',
    review_required: 'Review the changed policy or addresses, then choose Preview change to check the current set.',
    degraded: 'Resolve the reported problem, then choose Refresh status before previewing again.',
    unavailable: 'Choose Refresh status. If status stays unavailable, check the distribution service.',
  }[value?.state] || 'Choose Refresh status to read the current effect.';
}
export const originReasons = {
  origin_unknown: 'Set a valid distribution address before enabling restrictions.',
  origin_unobserved: 'The tracker has not observed the distribution service yet.',
  origin_mismatch: 'The observed distribution address does not match its configuration.',
  policy_unavailable: 'Restore a valid peer policy before reviewing this change.',
  endpoint_state_unavailable: 'Current peer addresses are unavailable. Check the tracker.',
  control_state_unavailable: 'The saved distribution-access settings cannot be read.',
  application_state_unavailable: 'The last application record cannot be verified.',
  policy_changed: 'Peer policy changed. Review its current effects again.',
  endpoint_set_changed: 'Peer addresses changed. Review the affected devices again.',
  shared_address: 'Allowed and denied devices share an address. Use separate addresses before enforcing these restrictions.',
  protected_address: 'A proposed block includes a protected distribution address.',
  ip_budget_exceeded: 'The new address count exceeds your review limit.',
  device_budget_exceeded: 'The new device count exceeds your review limit.',
  retention_capacity_exceeded: 'The retained approval set is full. Review existing restrictions before adding more.',
  application_pending: 'The transfer service has not confirmed this change yet.',
  aria_unavailable: 'The transfer service is unavailable.',
  apply_failed: 'The transfer service could not apply this change.',
  session_changed: 'The transfer service restarted. Waiting for a new application check.',
};
const counts = ['new_ip_count', 'new_device_count', 'retained_ip_count', 'proposed_ip_count',
  'proposed_device_count', 'shared_conflict_count', 'protected_conflict_count', 'applied_ip_count', 'applied_device_count'];
export const originEtag = revision => `"origin-enforcement-${revision}"`;
export function checkedOrigin(body, etag, preview = false) {
  if (!object(body) || !count(body.revision) || !count(body.policy_revision)
    || etag !== originEtag(body.revision) || !['preflight', 'enforce'].includes(body.mode)
    || typeof body.state !== 'string' || !Object.hasOwn(originStates, body.state)
    || ['max_new_ips', 'max_new_devices'].some(key => !count(body[key]) || body[key] > 1000)
    || ['approved_ip_count', 'approved_device_count'].some(key => !count(body[key]))
    || counts.some(key => !nullableCount(body[key]))
    || (body.last_verified_at !== null && (!Number.isFinite(body.last_verified_at) || body.last_verified_at <= 0))
    || (body.reason !== null && (typeof body.reason !== 'string' || !Object.hasOwn(originReasons, body.reason)))
    || !Array.isArray(body.blockers) || body.blockers.length > Object.keys(originReasons).length
    || body.blockers.some(code => typeof code !== 'string' || !Object.hasOwn(originReasons, code))) throw Error('Distribution-access status is incomplete. Refresh before changing it.');
  if (!preview && body.state === 'enforced' && (body.mode !== 'enforce' || body.reason !== null || body.blockers.length
    || body.applied_ip_count === null || body.applied_device_count === null || body.last_verified_at === null)) {
    throw Error('Application has not been verified. Refresh the distribution-access status.');
  }
  return structuredClone(body);
}
export function originForm(value) {
  return {mode: value?.mode || 'preflight', max_new_ips: String(value?.max_new_ips ?? 10), max_new_devices: String(value?.max_new_devices ?? 10)};
}
export function originPayload(form, policyRevision) {
  if (!['preflight', 'enforce'].includes(form.mode) || !count(policyRevision)) throw Error('Read current peer policy before previewing.');
  const body = {mode: form.mode, if_policy_revision: policyRevision};
  for (const key of ['max_new_ips', 'max_new_devices']) {
    if (typeof form[key] !== 'string' || !/^(0|[1-9][0-9]{0,3})$/.test(form[key]) || Number(form[key]) > 1000) {
      throw Error('Each review limit must be a whole number from 0 to 1000.');
    }
    body[key] = Number(form[key]);
  }
  return body;
}
export function checkedOriginPreview(body, etag, request, revision) {
  const result = checkedOrigin(body, etag, true);
  if (result.dry_run !== true || result.requires_confirmation !== true || result.revision !== revision
    || result.policy_revision !== request.if_policy_revision
    || ['mode', 'max_new_ips', 'max_new_devices'].some(key => result[key] !== request[key])
    || (result.blockers.length ? result.confirm_token !== null : typeof result.confirm_token !== 'string' || !/^[0-9a-f]{64}$/.test(result.confirm_token)
      || ['new_ip_count', 'new_device_count', 'retained_ip_count', 'proposed_ip_count', 'proposed_device_count', 'shared_conflict_count', 'protected_conflict_count'].some(key => result[key] === null))) {
    throw Error('Preview does not match this change. No commit was sent; refresh and preview again.');
  }
  return result;
}
export function originWriteResult(response, body, request, revision) {
  if (response.status >= 500) return 'unknown';
  if (!response.ok) return 'refused';
  try {
    checkedOrigin(body, response.headers.get('ETag'));
    if (body.dry_run !== false || body.requires_confirmation !== false || body.confirm_token !== null
      || body.revision !== revision + 1 || body.policy_revision !== request.if_policy_revision
      || ['mode', 'max_new_ips', 'max_new_devices'].some(key => body[key] !== request[key])
      || body.state !== 'pending' || body.applied_ip_count !== null || body.applied_device_count !== null || body.last_verified_at !== null) return 'unknown';
    return 'saved';
  } catch {return 'unknown';}
}
export function originProblem(status, body) {
  if (status === 401) return 'Your session expired. Log in again, then refresh.';
  if (status === 403) return 'This account cannot change distribution access.';
  if ([409, 412, 428].includes(status)) return 'The review is no longer current. Refresh and preview again before applying.';
  if (status === 422) return 'The server refused these settings. Check the mode and review limits.';
  return 'Distribution access is unavailable. Refresh before trying again.';
}
