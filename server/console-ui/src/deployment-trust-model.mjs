// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {requestId, publicKey, publicCertificate, decodePublic} from './certificates-model.mjs';
import {normalizeNames, publicPem} from './security-lifecycle-model.mjs';
import {stamp, digest, boundedText, unique, pick, same} from './worker-lifecycle-model.mjs';
export const trustFamilies = ['device-tls', 'peer-ca', 'instruction-roots'];
export const rootId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value);
const publicFields = ['family', 'request_id', 'state', 'created_at', 'names', 'mode', 'csr', 'certificate', 'fingerprint_sha256', 'roots',
  'online_public_key', 'keylist_payload', 'keylist_signer', 'requires_reonboarding', 'requires_package_rebuild',
  'attested_root_ids', 'attestation_request_id', 'attestation_root_id'];
const ascii = value => typeof value === 'string' && /^[\x09\x0a\x0d\x20-\x7e]*$/.test(value) && !/PRIVATE KEY|AGE-SECRET-KEY/.test(value);
export function rootPublic(value) {
  if (!ascii(value) || value.length > 4096 || !publicKey(value)) throw Error('Choose one public Ed25519 root file, never a private key.');
  const core = value.trim().split(/\s+/)[1].replace(/=+$/, '');
  const raw = decodePublic(core + '='.repeat((4 - core.length % 4) % 4), 128);
  if (raw.length !== 51 || !raw.startsWith('\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20')) throw Error('Choose a valid public Ed25519 root.');
  return 'ssh-ed25519 ' + btoa(raw) + '\n';
}
export function rootsPublic(roots, allowEmpty = false) {
  if (!roots || typeof roots !== 'object' || Array.isArray(roots) || ![...(allowEmpty ? [0] : []), 2].includes(Object.keys(roots).length)) throw Error('Provide exactly two public roots.');
  const result = Object.fromEntries(Object.keys(roots).sort().map(name => {
    if (!rootId(name)) throw Error('Use the existing root names.'); return [name, rootPublic(roots[name])];
  }));
  if (!unique(Object.values(result))) throw Error('The two public roots must be distinct.');
  return result;
}
export function keylistPayload(raw, signer) {
  if (!ascii(raw) || raw.length > 116 * 1024) throw Error('Choose the bounded public revocation request.');
  const lines = raw.split('\n'); if (lines.length !== 4 || lines[0] !== 'IRIS-KEYLIST/1' || lines[3] !== '') throw Error('The public revocation request is incomplete.');
  const metadata = JSON.parse(decodePublic(lines[1], 4096));
  if (!metadata || !same(Object.keys(metadata).sort(), ['issued_at', 'keylist_seq', 'krl_sha256', 'signer_root_id', 'v']) ||
      metadata.v !== 1 || !Number.isSafeInteger(metadata.keylist_seq) || metadata.keylist_seq < 1 || !stamp(metadata.issued_at) ||
      metadata.signer_root_id !== signer || !rootId(signer) || !digest(metadata.krl_sha256)) throw Error('The public revocation request belongs to another root.');
  const canonical = Object.fromEntries(Object.keys(metadata).sort().map(key => [key, metadata[key]]));
  if (btoa(JSON.stringify(canonical)) !== lines[1]) throw Error('The public revocation request is not canonical.');
  const krl = decodePublic(lines[2], 80 * 1024);
  if (krl && !krl.startsWith('SSHKRL\n\x00')) throw Error('The public revocation list is invalid.');
  return raw;
}
export function signedKeylist(raw, signer, expected = null) {
  if (!ascii(raw) || raw.length > 128 * 1024) throw Error('Choose a public signed revocation list within 128 KiB.');
  const lines = raw.split('\n');
  if (lines.length !== 5 || lines[4] !== '') throw Error('The signed public revocation list is incomplete.');
  const payload = keylistPayload(lines.slice(0, 3).join('\n') + '\n', signer);
  if (expected !== null && payload !== expected) throw Error('The approval belongs to another public revocation request.');
  const signature = decodePublic(lines[3], 8192);
  if (!signature.startsWith('-----BEGIN SSH SIGNATURE-----\n') || !signature.trimEnd().endsWith('-----END SSH SIGNATURE-----')) throw Error('The public revocation list has no SSH signature.');
  return raw;
}
export function trustItem(data) {
  if (!data || !trustFamilies.includes(data.family) || !['idle', 'awaiting-approval', 'approved', 'committing', 'published', 'cancelled'].includes(data.state) ||
      data.requires_reonboarding !== true || data.requires_package_rebuild !== (data.family === 'instruction-roots') ||
      !Array.isArray(data.attested_root_ids) || !unique(data.attested_root_ids) || !data.attested_root_ids.every(rootId) ||
      data.attestation_request_id !== null && !requestId(data.attestation_request_id) ||
      data.attestation_root_id !== null && (!rootId(data.attestation_root_id) || !data.attestation_request_id)) return null;
  try {
    const roots = rootsPublic(data.roots, data.family !== 'instruction-roots' || data.state === 'idle');
    if (data.family !== 'instruction-roots' && (Object.keys(roots).length || data.attested_root_ids.length || data.attestation_request_id !== null || data.attestation_root_id !== null)) return null;
    if (data.attested_root_ids.some(root => !Object.hasOwn(roots, root)) || data.attestation_root_id !== null && !Object.hasOwn(roots, data.attestation_root_id)) return null;
    if (data.state === 'idle') {
      if (!['request_id', 'created_at', 'mode', 'csr', 'certificate', 'fingerprint_sha256', 'online_public_key', 'keylist_payload', 'keylist_signer'].every(key => data[key] === null) || !same(data.names, [])) return null;
    } else {
      if (!requestId(data.request_id) || !stamp(data.created_at) || data.fingerprint_sha256 !== null && !digest(data.fingerprint_sha256)) return null;
      if (data.family === 'device-tls') {
        if (!same(normalizeNames(data.names), data.names) || !['ca', 'self-signed'].includes(data.mode) || publicPem(data.csr, 'CERTIFICATE REQUEST') !== data.csr ||
            data.certificate !== null && publicPem(data.certificate) !== data.certificate || data.online_public_key !== null || data.keylist_payload !== null || data.keylist_signer !== null) return null;
      } else {
        if (!same(data.names, []) || data.mode !== null || data.csr !== null) return null;
        if (data.family === 'peer-ca') {
          if (publicPem(data.certificate) !== data.certificate || data.online_public_key !== null || data.keylist_payload !== null || data.keylist_signer !== null) return null;
        } else if (!publicKey(data.online_public_key) || !Object.hasOwn(roots, data.keylist_signer) ||
            keylistPayload(data.keylist_payload, data.keylist_signer) !== data.keylist_payload || data.certificate !== null && !publicCertificate(data.certificate)) return null;
      }
      if (['approved', 'committing', 'published'].includes(data.state) && (!data.certificate || !digest(data.fingerprint_sha256))) return null;
      if ((data.certificate === null) !== (data.fingerprint_sha256 === null)) return null;
    }
    return {...pick(data, publicFields), roots};
  } catch {return null;}
}
export function trustStatus(data) {
  if (!data || !Array.isArray(data.items) || data.items.length !== 3 || !unique(data.items.map(row => row?.family))) return null;
  const items = data.items.map(trustItem), drain = data.drain;
  if (items.some(row => !row) || !drain || typeof drain.ready !== 'boolean' ||
      !['blocked_device_ids', 'removed_device_ids'].every(key => Array.isArray(drain[key]) && unique(drain[key]) && drain[key].every(value => boundedText(value, 256) && value.length))) return null;
  if (drain.ready !== (drain.blocked_device_ids.length === 0)) return null;
  return {items, drain: pick(drain, ['ready', 'blocked_device_ids', 'removed_device_ids'])};
}
export function trustAllows(item, action) {
  if (!item) return false;
  if (action.startsWith('attestation-')) return item.family === 'instruction-roots' && ['idle', 'published', 'cancelled'].includes(item.state) && Object.keys(item.roots).length === 2;
  return ({prepare: ['idle', 'published', 'cancelled'], approve: ['awaiting-approval', 'approved'], cancel: ['awaiting-approval', 'approved']})[action]?.includes(item.state) === true &&
    (action !== 'approve' || item.family !== 'peer-ca' && item.mode !== 'self-signed');
}
export function checkedTrust(payload, before, data) {
  if (payload.action === 'attestation-request') {
    if (data?.request_id !== payload.request_id || data?.root_id !== payload.root_id) return null;
    try {return {request: {request_id: data.request_id, root_id: data.root_id, payload: keylistPayload(data.payload, payload.root_id)}};} catch {return null;}
  }
  const state = trustItem(data); if (!state || state.family !== payload.family) return null;
  if (payload.action === 'attestation-apply') {
    return data.attestation_applied === true && state.attestation_request_id === payload.request_id && state.attestation_root_id === payload.root_id &&
      same(state.roots, before.roots) && state.attested_root_ids.includes(payload.root_id) ? {state} : null;
  }
  if (state.request_id !== payload.request_id) return null;
  if (payload.action === 'prepare') {
    const expected = payload.family === 'peer-ca' || payload.mode === 'self-signed' ? 'approved' : 'awaiting-approval';
    if (state.state !== expected || payload.family === 'device-tls' && (!same(payload.names, state.names) || payload.mode !== state.mode) ||
        payload.family === 'instruction-roots' && (!same(rootsPublic(payload.roots), state.roots) || payload.keylist_signer !== state.keylist_signer)) return null;
  } else {
    const preserved = ['created_at', 'mode', 'names', 'csr', 'online_public_key', 'keylist_payload', 'keylist_signer'];
    // Cancelled root requests show the configured roots, not the discarded candidates.
    if (!(payload.family === 'instruction-roots' && payload.action === 'cancel')) preserved.push('roots');
    if (preserved.some(key => !same(state[key], before[key]))) return null;
    if (payload.action === 'approve') {
      if (state.state !== 'approved' || state.certificate !== payload.certificate) return null;
    } else if (payload.action !== 'cancel' || state.state !== 'cancelled' || state.certificate !== before.certificate || state.fingerprint_sha256 !== before.fingerprint_sha256) return null;
  }
  return {state};
}
