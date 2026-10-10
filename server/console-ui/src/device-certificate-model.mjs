// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId} from './certificates-model.mjs';

export const certificateUrl = id => `/api/v1/devices/${encodeURIComponent(id)}/certificate`;
export const uncertainRevocation = 'The revocation result is unknown. Check status before taking another action.';
export const uncertainReenrollment = 'The fresh onboarding approval result is unknown. Check status before taking another action.';
export const enforcementDelay = 'Updated peers refresh the revocation list or stop encrypted peer connections when it expires, within five minutes. '
  + 'Clients without this support can still accept the old certificate; block network access when immediate isolation is needed.';
const digest = value => typeof value === 'string' && value.length === 64 && /^[0-9a-f]{64}$/.test(value);
const uuid = value => typeof value === 'string' && value.length === 36 && requestId(value);

export function certificateStatus(value, id) {
  return !!value && value.device_id === id && digest(value.identity_sha256)
    && Number.isSafeInteger(value.revision) && value.revision >= 0
    && ['active', 'revoked', 'reenrollment-required'].includes(value.state) && typeof value.peer_tls_required === 'boolean'
    && (value.recovery_request_id === null || uuid(value.recovery_request_id))
    && (value.state !== 'reenrollment-required' || uuid(value.recovery_request_id))
    && value.enforcement === (value.state === 'active' ? 'not-applicable' : 'pending')
    && (value.state === 'active' ? value.revoked_at === null && value.request_id === null
      : Number.isSafeInteger(value.revoked_at) && value.revoked_at >= 0 && value.revoked_at <= 8640000000000 && uuid(value.request_id));
}

export function revocationConfirmed(value, pending) {
  return ['revoked', 'reenrollment-required'].includes(value.state) && value.identity_sha256 === pending.identity
    && value.revision > pending.revision;
}

export function reenrollmentConfirmed(value, pending) {
  return value.revision > pending.revision && value.recovery_request_id === pending.request
    && (value.state === 'reenrollment-required' && value.identity_sha256 === pending.identity
      || value.state === 'active' && value.identity_sha256 !== pending.identity);
}

export function certificateActionSuperseded(value, pending) {
  return value.identity_sha256 !== pending.identity && value.revision > pending.revision
    && uuid(value.recovery_request_id)
    && !(value.state === 'reenrollment-required' && value.recovery_request_id === pending.request);
}

export function certificateMessage(value) {
  if (value.state === 'reenrollment-required') return 'Fresh onboarding approved. The old certificates remain revoked.';
  if (value.state === 'revoked') return 'Revocation saved. Enforcement by every peer is not yet confirmed.';
  if (value.recovery_request_id) return 'New device identity created. Check Activity for the onboarding result. Its previous certificates remain revoked.';
  return '';
}

export function revocationConfirmation(id) {
  return `Revoke device certificate for ${id}?\n\n`
    + 'Withdraws every IRIS peer certificate issued for this device identity and blocks new certificates. '
    + 'This cannot be undone.\n\n'
    + enforcementDelay + '\n\nStaged images stay on the device.';
}

export function reenrollmentConfirmation(id) {
  return `Allow fresh onboarding for ${id}?\n\n`
    + 'Approve a new certificate identity for the same inventory device. Its old certificates remain permanently revoked.\n\n'
    + 'This does not change the device yet. Run Onboard from Inventory after approval. '
    + 'Only approve a device you trust and have secured.';
}

export function revocationRefusal(status, action = 'revoke', body = null) {
  const name = action === 'reenroll' ? 'Fresh onboarding approval' : 'Revocation';
  const busy = 'Finish or cancel this device\'s current job before approving fresh onboarding';
  if (status === 409 && action === 'reenroll' && [body?.error, body?.detail].includes(busy)) {
    return 'Finish or cancel the current device job in Activity, then check certificate status again.';
  }
  if (status === 401 || status === 403) return name + ' was not accepted. Sign in again, then check status.';
  if (status === 409 || status === 412) return 'The device certificate state changed. Check status and review it before trying again.';
  if (status === 404) return 'This device is unavailable. Refresh Inventory before continuing.';
  return name + ' was not accepted. Check status and the server configuration before trying again.';
}

export function runtimeObservation(value, now, lastSeen) {
  const unavailable = {label: 'Not confirmed', detail: 'No supported device report is available.', values: null};
  const integer = number => Number.isSafeInteger(number) && number >= 0 && number <= 8640000000000;
  const fields = ['supported', 'mode', 'state', 'authority', 'revision', 'issued_at', 'expires_at', 'own_revoked', 'observed_at'];
  if (!value || Object.keys(value).length !== fields.length || !fields.every(field => Object.hasOwn(value, field))
      || value.supported !== true || !['required', 'disabled'].includes(value.mode)
      || !['valid', 'expired', 'unavailable'].includes(value.state) || typeof value.own_revoked !== 'boolean'
      || !integer(value.observed_at)) return unavailable;
  const absent = value.authority === null && [value.revision, value.issued_at, value.expires_at].every(item => item === null);
  const complete = digest(value.authority) && Number.isSafeInteger(value.revision) && value.revision >= 0
    && integer(value.issued_at) && integer(value.expires_at) && value.expires_at > value.issued_at
    && value.expires_at - value.issued_at <= 300;
  if (!absent && !complete || ['valid', 'expired'].includes(value.state) && (!complete || value.mode !== 'required')) return unavailable;
  const fresh = integer(now) && integer(lastSeen) && lastSeen <= now + 30 && now - lastSeen < 300
    && value.observed_at <= now + 30 && now - value.observed_at < 300;
  const current = fresh && complete && value.mode === 'required' && value.state === 'valid'
    && value.issued_at <= now + 30 && value.expires_at > now;
  return {label: current ? 'Reported current' : 'Not confirmed', detail: current
    ? value.own_revoked ? 'The device reports its own certificate is revoked.' : 'The device reports a current revocation list.'
    : !fresh ? 'The last device report is stale or its time cannot be confirmed.'
      : value.mode !== 'required' ? 'The device reports that peer TLS is disabled.'
        : 'The device has not reported a current revocation list.', values: {...value}};
}
