// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {epoch, requestId} from './certificates-model.mjs';

export const TLS_URL = '/api/v1/settings/certificates/browser/rotation';
export const CREDENTIAL_URL = '/api/v1/settings/service-credentials';
export const TLS_BODY_LIMIT = 128 * 1024;
export const JSON_LIMIT = 64 * 1024;
export const FAMILIES = ['metrics-token', 'collector-headers'];
const TLS_FIELDS = ['request_id', 'state', 'names', 'mode', 'csr', 'certificate', 'created_at', 'fingerprint_sha256'];
const CREDENTIAL_FIELDS = ['family', 'request_id', 'state', 'previous_retained', 'started_at', 'observed_at', 'endpoint'];
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const pick = (value, fields) => Object.fromEntries(fields.map(key => [key, value[key]]));
const stamp = value => epoch(value) && value >= 0;

export function normalizeNames(value) {
  const input = typeof value === 'string' ? value.split(',').map(item => item.trim()) : value;
  if (!Array.isArray(input) || input.length < 1 || input.length > 16) throw Error('Provide 1–16 exact DNS names or IP addresses.');
  const result = input.map(item => {
    if (typeof item !== 'string' || item.length < 1 || item.length > 253) throw Error('Provide a valid certificate name.');
    if (item.includes(':')) {
      try {
        const host = new URL('https://[' + item + ']/').hostname;
        if (host.startsWith('[') && host.endsWith(']')) return host.slice(1, -1);
      } catch { /* Fall through to the same exact-name guidance. */ }
      throw Error('Use exact DNS names or IP addresses, without URLs, wildcards or IPv6 zone IDs.');
    }
    const name = item.toLowerCase();
    if (!name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw Error('Use exact DNS names or IP addresses, without wildcards or URLs.');
    return name;
  }).sort();
  if (new Set(result).size !== result.length) throw Error('Certificate names must be distinct.');
  return result;
}
export function publicPem(value, kind = 'CERTIFICATE') {
  const limit = kind === 'CERTIFICATE' ? 65536 : 16384;
  if (typeof value !== 'string' || value.length > limit || !/^[\x09\x0a\x0d\x20-\x7e]*$/.test(value) || value.includes('PRIVATE KEY')) throw Error('Upload the public certificate chain, never a private key.');
  const pattern = new RegExp('-----BEGIN ' + kind + '-----[\\s\\S]*?-----END ' + kind + '-----', 'g');
  const blocks = value.match(pattern) || [];
  if (!blocks.length || blocks.length > (kind === 'CERTIFICATE' ? 8 : 1) || value.replace(pattern, '').trim()) throw Error('Choose a bounded public PEM file without other material.');
  const normalized = blocks.map(block => {
    const lines = block.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (lines.length < 3 || !/^[A-Za-z0-9+/]+={0,2}$/.test(lines.slice(1, -1).join(''))) throw Error('Choose a valid public PEM file.');
    return lines.join('\n');
  }).join('\n') + '\n';
  if (normalized.length > limit) throw Error('The normalized public PEM file exceeds its size limit.');
  return normalized;
}
function pemIdentity(value) {return publicPem(value).replace(/\s/g, '');}
export function browserStatus(data) {
  if (!data || !['idle', 'awaiting-approval', 'approved', 'committing', 'published', 'cancelled'].includes(data.state)) return null;
  if (data.state === 'idle') {
    if (!Array.isArray(data.names) || data.names.length || TLS_FIELDS.filter(key => !['state', 'names'].includes(key)).some(key => data[key] !== null)) return null;
    return pick(data, TLS_FIELDS);
  }
  try {
    if (!requestId(data.request_id) || !['ca', 'self-signed'].includes(data.mode) || !stamp(data.created_at) ||
        !same(normalizeNames(data.names), data.names) || publicPem(data.csr, 'CERTIFICATE REQUEST') !== data.csr) return null;
    if (data.certificate === null ? data.fingerprint_sha256 !== null : !digest(data.fingerprint_sha256) || publicPem(data.certificate) !== data.certificate) return null;
    if (['approved', 'committing', 'published'].includes(data.state) && data.certificate === null) return null;
    if (data.state === 'awaiting-approval' && (data.certificate !== null || data.mode !== 'ca')) return null;
    return pick(data, TLS_FIELDS);
  } catch {return null;}
}
export function tlsAllows(data, action) {
  return !!data && ({prepare: ['idle', 'published', 'cancelled'], approve: ['awaiting-approval', 'approved'],
    apply: ['approved', 'committing', 'published'], cancel: ['awaiting-approval', 'approved']})[action]?.includes(data.state) === true &&
    (action !== 'approve' || data.mode === 'ca');
}
export function checkedTlsResult(payload, before, data) {
  const state = browserStatus(data);
  if (!state || data.request_id !== payload.request_id) return null;
  if (payload.action === 'prepare') {
    if (data.mode !== payload.mode || !same(data.names, payload.names) || data.state !== (payload.mode === 'ca' ? 'awaiting-approval' : 'approved')) return null;
  } else {
    if (['names', 'mode', 'csr', 'created_at'].some(key => !same(data[key], before[key]))) return null;
    if (payload.action === 'approve') {
      try {if (data.state !== 'approved' || pemIdentity(data.certificate) !== pemIdentity(payload.certificate)) return null;} catch {return null;}
    } else if (payload.action === 'cancel') {
      if (data.state !== 'cancelled' || data.certificate !== before.certificate || data.fingerprint_sha256 !== before.fingerprint_sha256) return null;
    } else if (payload.action === 'apply') {
      if (data.state !== 'published' || data.certificate !== before.certificate || data.fingerprint_sha256 !== before.fingerprint_sha256 || typeof data.applied !== 'boolean') return null;
      // A published journal is not proof that this Console loaded the identity.
      if (data.applied && (!data.gui_cert || data.gui_cert.source !== 'custom' || data.gui_cert.fingerprint_sha256 !== data.fingerprint_sha256)) return null;
    } else return null;
  }
  return {state, reloaded: payload.action === 'apply' && data.applied === true};
}
export function collectorEndpoint(value) {
  if (typeof value !== 'string' || !/^https:\/\//i.test(value) || value.length > 2048 || !/^[\x21-\x7e]+$/.test(value)) throw Error('Provide an HTTPS collector base URL.');
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || value.includes('?') || value.includes('#')) throw Error();
  } catch {throw Error('Provide an HTTPS collector base URL without credentials, query parameters or fragments.');}
  return value.replace(/\/+$/, '');
}
export const metricsToken = value => typeof value === 'string' && /^[A-Za-z0-9._~+/-]{32,256}$/.test(value);
export function collectorHeaders(rows) {
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 16) throw Error('Provide 1–16 collector authentication headers.');
  const headers = Object.create(null), prohibited = ['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'accept-encoding'];
  let size = 0;
  for (const row of rows) {
    const name = typeof row.name === 'string' ? row.name.trim().toLowerCase() : '';
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/.test(name) || prohibited.includes(name) || Object.hasOwn(headers, name) ||
        typeof row.value !== 'string' || !/^[\x20-\x7e]{1,4096}$/.test(row.value)) throw Error('Provide distinct authentication header names and nonempty printable values.');
    headers[name] = row.value; size += name.length + row.value.length;
  }
  if (size > 16384) throw Error('Collector headers exceed 16 KiB.');
  return headers;
}
export function credentialStatus(data) {
  if (!data || !Array.isArray(data.items) || data.items.length !== 2 || new Set(data.items.map(item => item?.family)).size !== 2) return null;
  const items = [];
  for (const row of data.items) {
    if (!row || !FAMILIES.includes(row.family) || !['deployment-managed', 'awaiting-verification', 'completed', 'reverted'].includes(row.state) || typeof row.previous_retained !== 'boolean') return null;
    if (row.state === 'deployment-managed') {
      if (row.request_id !== null || row.started_at !== null || row.observed_at !== null || row.endpoint !== null || row.previous_retained) return null;
    } else {
      if (!requestId(row.request_id) || !stamp(row.started_at) || (row.observed_at !== null && (!stamp(row.observed_at) || row.observed_at < row.started_at))) return null;
      if (['completed', 'reverted'].includes(row.state) && row.previous_retained || row.state === 'reverted' && row.observed_at !== null) return null;
      if (row.family === 'metrics-token' ? row.endpoint !== null : row.endpoint === null && row.state !== 'reverted') return null;
      if (row.endpoint !== null) {try {if (collectorEndpoint(row.endpoint) !== row.endpoint) return null;} catch {return null;}}
    }
    items.push(pick(row, CREDENTIAL_FIELDS));
  }
  return {items};
}
export function credentialAllows(item, action) {
  return !!item && (action === 'replace' ? ['deployment-managed', 'completed', 'reverted'].includes(item.state)
    : action === 'revert' ? item.state === 'awaiting-verification' : action === 'retire' && item.state === 'awaiting-verification' && item.observed_at !== null);
}
export function checkedCredentialResult(payload, before, data) {
  const state = credentialStatus(data), row = state?.items.find(item => item.family === payload.family);
  if (!row || row.request_id !== payload.request_id || row.state !== ({replace: 'awaiting-verification', retire: 'completed', revert: 'reverted'})[payload.action]) return null;
  if (payload.action === 'replace') {
    if (row.endpoint !== (payload.family === 'collector-headers' ? payload.endpoint : null)) return null;
  } else if (row.started_at !== before.started_at || payload.action === 'retire' && row.endpoint !== before.endpoint) return null;
  return state;
}
export function lifecycleBody(payload, group) {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > (group === 'tls' ? TLS_BODY_LIMIT : JSON_LIMIT)) throw Error('The request exceeds its size limit.');
  return body;
}

// Exact, public domain errors only. Never display an arbitrary response body:
// proxies and unexpected handlers can echo submitted credential material.
export function refusalHint(status, data) {
  if (status === 401 || status === 403) return 'Sign in again and check owner access. ';
  if (status === 413) return 'Choose a public approval within the file size limit. ';
  const allowed = new Set([
    'Certificate does not match this replacement key',
    'Certificate must be valid now with more than seven days remaining',
    'Approved certificate names must exactly match the request',
    'Certificate must permit TLS server authentication',
    'Import a bounded PEM certificate chain, leaf first',
    'Durable encrypted key storage must be configured',
    'TLS files changed outside this request; do not overwrite them',
    'TLS rotation journal is invalid; preserve it for recovery',
    'Active certificate changed after this publication',
    'Finish or cancel the pending TLS rotation',
    'Durable encrypted credential storage must be configured',
    'Request ID belongs to different credentials',
    'Replacement must differ from the current credential',
    'Retire the deployment-managed scrape overlap before adopting Console management',
    'Verify and retire the previous transition first',
    'No successful use of this replacement has been observed yet',
  ]);
  return status === 409 && allowed.has(data?.error) ? data.error + '. ' : '';
}
