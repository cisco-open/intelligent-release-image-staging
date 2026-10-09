// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const CERTIFICATE_LIMIT = 64 * 1024;
export const KEYLIST_LIMIT = 128 * 1024;
export const APPROVAL_BODY_LIMIT = 192 * 1024;
export const certificateUrl = '/api/v1/settings/certificates';
export const signerUrl = certificateUrl + '/instruction/rotation';
const states = ['idle', 'awaiting-approval', 'committing', 'retirement-pending', 'retiring', 'completed', 'cancelled'];
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const epoch = value => Number.isSafeInteger(value) && Math.abs(value) <= 8640000000000;
const nullableDate = value => value === null || epoch(value);
const text = value => typeof value === 'string' && value.length > 0;
export const requestId = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value);
const rootId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value);
const ascii = value => typeof value === 'string' && /^[\x09\x0a\x0d\x20-\x7e]*$/.test(value) && !value.includes('PRIVATE KEY');
export function publicKey(value) {
  return ascii(value) && value.length <= 16384 && /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [\x20-\x7e]*)?\r?\n?$/.test(value);
}
export function publicCertificate(value) {
  return ascii(value) && value.length <= CERTIFICATE_LIMIT && /^ssh-ed25519-cert-v01@openssh.com [A-Za-z0-9+/]+={0,2}(?: [\x20-\x7e]*)?\r?\n?$/.test(value);
}
export function checkedInventory(data) {
  const rowStates = ['unknown', 'not-yet-valid', 'expired', 'signing-refused', 'renewal-due', 'within-validity', 'public-key-present'];
  return !!data && data.scope === 'server-certificate-files' && epoch(data.observed_at) && Array.isArray(data.items) && data.items.length > 0 &&
    new Set(data.items.map(row => row?.id)).size === data.items.length && data.items.every(row =>
      row && text(row.id) && text(row.label) && text(row.impact) && row.source === 'server-file' &&
      rowStates.includes(row.state) && ['certificate', 'public-key'].includes(row.kind) &&
      (row.fingerprint_sha256 === null || text(row.fingerprint_sha256)) &&
      ['valid_from', 'expires_at', 'renew_at', 'refuse_at'].every(key => nullableDate(row[key])) &&
      (row.kind === 'public-key' ? ['unknown', 'public-key-present'].includes(row.state) : row.state !== 'public-key-present') &&
      (row.kind !== 'public-key' || ['valid_from', 'expires_at', 'renew_at', 'refuse_at'].every(key => row[key] === null))) &&
    (data.custody === null || (data.custody && text(data.custody.state)));
}
export function checkedRenewalRequest(data) {
  return !!data && publicKey(data.public_key) && digest(data.public_key_sha256) && digest(data.certificate_sha256);
}
export function checkedRenewal(data) {
  return !!data && data.applied === true && epoch(data.expires_at) && epoch(data.refuse_at) &&
    data.expires_at - data.refuse_at === 7 * 86400 && typeof data.status_refreshed === 'boolean';
}
export function checkedSigner(data) {
  if (!data || !states.includes(data.state) || !Array.isArray(data.root_ids) ||
      !data.root_ids.every(rootId) || new Set(data.root_ids).size !== data.root_ids.length) return false;
  const nullable = ['request_id', 'previous_public_key', 'public_key', 'previous_sha256', 'replacement_sha256', 'created_at', 'activated_at', 'retired_keylist_seq'];
  if (data.state === 'idle') return nullable.every(key => data[key] === null);
  if (!requestId(data.request_id) || !publicKey(data.previous_public_key) || !publicKey(data.public_key) ||
      !digest(data.previous_sha256) || !digest(data.replacement_sha256) || data.previous_sha256 === data.replacement_sha256 ||
      !epoch(data.created_at) || data.created_at < 0) return false;
  const approved = ['committing', 'retirement-pending', 'retiring', 'completed'].includes(data.state);
  return (approved ? epoch(data.activated_at) && data.activated_at >= data.created_at : data.activated_at === null) &&
    (data.state === 'completed' ? Number.isSafeInteger(data.retired_keylist_seq) && data.retired_keylist_seq > 0 : data.retired_keylist_seq === null);
}
export function signerAllows(state, action) {
  return ({prepare: ['idle', 'completed', 'cancelled'], activate: ['awaiting-approval'], cancel: ['awaiting-approval'],
    'retirement-request': ['retirement-pending', 'retiring'], retire: ['retirement-pending', 'retiring']})[action]?.includes(state) === true;
}
export function checkedSignerResult(action, payload, before, data) {
  if (!checkedSigner(data) || data.request_id !== payload.request_id) return false;
  if (action !== 'prepare' && ['previous_public_key', 'public_key', 'previous_sha256', 'replacement_sha256', 'created_at'].some(key => before[key] !== data[key])) return false;
  return ({prepare: ['awaiting-approval'], activate: ['retirement-pending', 'retiring', 'completed'], cancel: ['cancelled'], retire: ['completed']})[action]?.includes(data.state) === true;
}
export function decodePublic(value, limit) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(limit / 3) || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error('Public response is incomplete.');
  const raw = atob(value);
  if (raw.length > limit || btoa(raw) !== value) throw Error('Public response is incomplete.');
  return raw;
}
export function retirementPayload(data, payload) {
  if (data?.request_id !== payload.request_id || data?.root_id !== payload.root_id) throw Error('Retirement response does not match this request.');
  const raw = decodePublic(data.payload, 116 * 1024), lines = raw.split('\n');
  if (lines.length !== 4 || lines[0] !== 'IRIS-KEYLIST/1' || lines[3] !== '') throw Error('Retirement response is incomplete.');
  const metadata = JSON.parse(decodePublic(lines[1], 4096));
  if (metadata?.v !== 1 || metadata.signer_root_id !== payload.root_id || !Number.isSafeInteger(metadata.keylist_seq) || metadata.keylist_seq < 1 ||
      !epoch(metadata.issued_at) || !digest(metadata.krl_sha256)) throw Error('Retirement metadata does not match this request.');
  const krl = decodePublic(lines[2], 80 * 1024);
  if (!krl.startsWith('SSHKRL\n\x00')) throw Error('Retirement response has no revocation list.');
  return Uint8Array.from(raw, character => character.charCodeAt(0));
}
export function approvalBody(payload) {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > APPROVAL_BODY_LIMIT) throw Error('Public approval exceeds the request limit.');
  return body;
}
export function publicApproval(raw, action) {
  if (action === 'renew' || action === 'activate') {
    if (!publicCertificate(raw)) throw Error(action === 'renew' ? 'Choose the public certificate returned by your custodian, not a private key.' : 'Upload the public approval, never a private key.');
    return raw;
  }
  if (!ascii(raw) || raw.length > KEYLIST_LIMIT || !raw.startsWith('IRIS-KEYLIST/1\n')) throw Error('Upload the public approval, never a private key.');
  return btoa(raw);
}
export function refusedCertificateMessage(status, data) {
  if (status === 401 || status === 403) return 'Sign in again, then review the current signing state.';
  const guidance = {
    'online key changed; prepare renewal again': 'The online key changed.',
    'online certificate changed; prepare renewal again': 'The online certificate changed.',
    'certificate does not match the online key': 'The certificate belongs to a different online key. Ask the key holder to approve the current public request.',
    'renewed certificate must have more than seven days remaining': 'Ask the key holder for a certificate with more than seven days remaining.',
    'replacement certificate needs more than seven days remaining': 'Ask the key holder for a certificate with more than seven days remaining.',
    'renewed certificate must extend the existing expiry': 'Ask the key holder for a certificate with a later expiry.',
    'current custody changed; cancel and prepare rotation again': 'The signer or trusted roots changed. After refreshing, cancel the pending replacement and prepare another request.',
    'keylist changed; prepare retirement again': 'The revocation list changed. Download and approve a fresh retirement request after refreshing.',
    'approval does not match the retirement request': 'The approval belongs to another retirement request. Download and approve the current request after refreshing.',
  };
  // Never echo arbitrary upstream bodies, even for public-file operations.
  return typeof data?.error === 'string' && Object.hasOwn(guidance, data.error) ? guidance[data.error] : 'Check signing status and the approved public file.';
}
