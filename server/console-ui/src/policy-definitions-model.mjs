// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {revisionOk} from './role-actions-model.mjs';

export const ROLE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;
export const POLICY_BODY_LIMIT = 64 * 1024;
export const POLICY_CSV_LIMIT = 8 * 1024 * 1024;
export const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
export const count = value => Number.isSafeInteger(value) && value >= 0;
export const roleQosFields = [
  ['seed_up_bps', 'Upload while seeding', 'rate', 0, 10000000000],
  ['seed_down_bps', 'Download while seeding', 'rate', 0, 10000000000],
  ['leech_up_bps', 'Upload while downloading', 'rate', 0, 10000000000],
  ['leech_down_bps', 'Download while downloading', 'rate', 0, 10000000000],
  ['overall_up_bps', 'Overall upload', 'rate', 0, 10000000000],
  ['overall_down_bps', 'Overall download', 'rate', 0, 10000000000],
  ['per_peer_bps', 'Per-peer modelling rate', 'rate', 0, 10000000000],
  ['request_peer_speed_limit_bps', 'Requested peer speed', 'rate', 0, 1000000000],
  ['max_peers', 'Peers per torrent', '1–1000', 1, 1000],
  ['fanout', 'Fanout multiplier', '1–1000, ≤ peers per torrent', 1, 1000],
  ['max_concurrent', 'Concurrent torrents', '1–1000', 1, 1000],
  ['numwant', 'Peers per announce', '4–200', 4, 200],
  ['announce_min_interval_s', 'Announce interval', 'seconds, 10–300', 10, 300],
  ['handout_budget', 'Handouts per window', '0–1000', 0, 1000],
  ['catalog_tick_s', 'Catalog tick', 'seconds, 60–900, multiple of 60', 60, 900],
  ['telemetry_every_ticks', 'Telemetry every', 'ticks, 1–60', 1, 60],
  ['telemetry_pause', 'Pause telemetry', 'bool'],
];
export function rateHint(raw) {
  if (raw === '') return '';
  if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(Number(raw))) return 'whole number of bytes per second';
  const value = Number(raw), bits = value * 8;
  if (!value) return 'unlimited';
  if (value < 8192) return 'too low: 0 or at least 8192';
  return '≈ ' + (bits >= 1e9 ? (bits / 1e9).toFixed(2) + ' Gbit/s' : bits >= 1e6
    ? (bits / 1e6).toFixed(1) + ' Mbit/s' : (bits / 1e3).toFixed(0) + ' kbit/s');
}
export function checkedDefinitions(body) {
  if (!object(body) || !revisionOk(body.revision) || !object(body.roles) || Object.keys(body.roles).length > 256) throw Error('Role definitions unavailable.');
  for (const [name, definition] of Object.entries(body.roles)) {
    if (!ROLE_NAME_RE.test(name) || !object(definition)
      || Object.keys(definition).some(key => !['restricted', 'origin', 'peers', 'nets', 'on_stale', 'qos', 'qos_state'].includes(key))
      || ['restricted', 'origin'].some(key => Object.hasOwn(definition, key) && typeof definition[key] !== 'boolean')
      || ['peers', 'nets'].some(key => Object.hasOwn(definition, key) && (!Array.isArray(definition[key]) || definition[key].some(value => typeof value !== 'string')))
      || (Object.hasOwn(definition, 'on_stale') && !['keep', 'defaults'].includes(definition.on_stale))
      || (Object.hasOwn(definition, 'qos') && (!object(definition.qos) || Object.entries(definition.qos).some(([key, value]) => {
        const field = roleQosFields.find(field => field[0] === key);
        return !field || (key === 'telemetry_pause' ? typeof value !== 'boolean' : !count(value) || value < field[3] || value > field[4]
          || (field[2] === 'rate' && value !== 0 && value < 8192) || (key === 'catalog_tick_s' && value % 60));
      })))
      || (Object.hasOwn(definition, 'qos_state') && (!object(definition.qos_state) || Object.entries(definition.qos_state).some(([state, values]) =>
        !['seeder', 'leecher'].includes(state) || !object(values) || Object.entries(values).some(([key, value]) =>
          !['numwant', 'announce_min_interval_s'].includes(key) || !count(value)
          || value < (key === 'numwant' ? 4 : 10) || value > (key === 'numwant' ? 200 : 300)))))) throw Error('Role definitions are incomplete or unsupported. Refresh before editing.');
  }
  return {definitions: structuredClone(body.roles), revision: body.revision};
}
export function definitionForm(name = '', definition = {}) {
  return {name, restricted: !!definition.restricted, origin: definition.origin !== false,
    peers: (definition.peers || []).filter(peer => peer !== name).join(', '), nets: (definition.nets || []).join(', '),
    onStale: definition.on_stale || '', qos: Object.fromEntries(roleQosFields.map(([key]) => [key,
      Object.hasOwn(definition.qos || {}, key) ? String(definition.qos[key]) : '']))};
}
export function definitionPayload(form, editor) {
  const name = form.name.trim(), list = value => value.split(/[\s,;]+/).filter(Boolean);
  if (typeof form.restricted !== 'boolean' || typeof form.origin !== 'boolean') throw Error('Choose valid sharing permissions.');
  if (!ROLE_NAME_RE.test(name)) throw Error('Role name must be 1–32 characters of a–z, 0–9, dot, underscore or hyphen, starting with a letter or digit.');
  if (editor.name && editor.name !== name) throw Error('Close this editor to create a different role.');
  const peers = [...new Set([name, ...list(form.peers)])];
  if (peers.some(peer => !ROLE_NAME_RE.test(peer)) || peers.length > 64) throw Error('Choose at most 64 valid peer role names, including this role.');
  const definition = {restricted: form.restricted, peers, origin: form.origin};
  const nets = list(form.nets); if (nets.length) definition.nets = nets;
  if (form.onStale) {
    if (!['keep', 'defaults'].includes(form.onStale)) throw Error('Choose a valid action for expired instructions.');
    definition.on_stale = form.onStale;
  }
  const qos = {};
  for (const [key, label, kind, min, max] of roleQosFields) {
    const raw = form.qos[key].trim(); if (!raw) continue;
    if (kind === 'bool') {
      if (!['true', 'false'].includes(raw)) throw Error(label + ' must be Yes, No or Inherit.');
      qos[key] = raw === 'true'; continue;
    }
    const value = Number(raw);
    if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(value) || value < min || value > max
      || (kind === 'rate' && value !== 0 && value < 8192) || (key === 'catalog_tick_s' && value % 60)) {
      throw Error(label + (kind === 'rate' ? ` must be 0, or a whole number from 8192 to ${max} bytes per second.` : ` must be a whole number: ${kind}.`));
    }
    qos[key] = value;
  }
  if (qos.fanout !== undefined && qos.max_peers !== undefined && qos.fanout > qos.max_peers) throw Error('Fanout cannot exceed peers per torrent.');
  if (Object.keys(qos).length) definition.qos = qos;
  // PUT replaces a definition. Preserve the non-editable, API-owned overlay
  // from this editor's original read, not a newer poll response.
  if (editor.name && Object.hasOwn(editor.original, 'qos_state')) definition.qos_state = structuredClone(editor.original.qos_state);
  return {name, definition};
}
export function policyBody(payload, limit = POLICY_BODY_LIMIT) {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > limit) throw Error(`This policy request exceeds ${limit === POLICY_CSV_LIMIT ? '8 MiB' : '64 KiB'}. Reduce the definition or CSV size before retrying.`);
  return body;
}
export function policyEtagRevision(value) {
  const match = /^"iris-peer-policy-([1-9][0-9]*)"$/.exec(value || '');
  return match && revisionOk(Number(match[1])) ? Number(match[1]) : null;
}
export function checkedDefinitionPreview(body, revision, importing = false) {
  if (!object(body) || body.ok !== true || body.dry_run !== true || !revisionOk(body.revision) || body.revision < revision
    || ['member_delta', 'origin_access_lost', 'empty_permitted_sets', 'role_pairs_stopped'].some(key => !count(body[key]))
    || typeof body.qos_changed !== 'boolean' || typeof body.requires_confirmation !== 'boolean'
    || (body.confirm_token !== null && (typeof body.confirm_token !== 'string' || !body.confirm_token))
    || (body.requires_confirmation && !body.confirm_token) || (importing && (!count(body.roles) || body.roles > 256))) {
    throw Error('Preview response incomplete. No commit was sent; refresh and preview again.');
  }
  return structuredClone(body);
}
export function definitionWriteResult(response, body, revision, deleting = false, roles = null) {
  if (response.status >= 500) return {kind: 'unknown'};
  if (!response.ok) return {kind: 'refused'};
  const header = response.headers.get('ETag'), etag = policyEtagRevision(header);
  if (deleting) return response.status === 204 && revisionOk(etag) && etag >= revision ? {kind: 'saved', revision: etag} : {kind: 'unknown'};
  if (body?.ok !== true || body.dry_run !== false || !revisionOk(body.revision) || body.revision < revision
    || (header !== null && etag !== body.revision) || (roles !== null && body.roles !== roles)) return {kind: 'unknown'};
  return {kind: 'saved', revision: body.revision};
}
export function definitionProblem(status, body, verb) {
  const code = body?.code || body?.error;
  if (status === 412 || code === 'revision_conflict') return 'Peer policy changed. Close this editor, refresh, and reopen the current definition before previewing again.';
  if (status === 428) return 'A fresh preview and confirmation are required. Preview again.';
  if (code === 'role_in_use') {
    const parts = [], names = value => Array.isArray(value) ? value.filter(name => typeof name === 'string').slice(0, 10).join(', ') : '';
    if (count(body.member_count)) parts.push(`${body.member_count} device(s) declare it` + (names(body.device_ids) ? ` (${names(body.device_ids)}${body.truncated ? ', …' : ''})` : ''));
    if (names(body.roles)) parts.push('declared roles missing from the file: ' + names(body.roles));
    if (names(body.referring_roles)) parts.push('referred to by ' + names(body.referring_roles));
    if (names(body.referring_schedules)) parts.push('used by schedule(s) ' + names(body.referring_schedules));
    return verb + ' refused: role in use' + (parts.length ? ' — ' + parts.join('; ') : '') + '.';
  }
  if (code === 'operation_backlog_full') return `The operation backlog is full (${count(body.unacknowledged) ? body.unacknowledged : 'unknown'}/${count(body.capacity) ? body.capacity : 'unknown'}). Wait for tracker acknowledgement, then preview again.`;
  if (status === 401) return 'Your session expired. Log in again, then preview again.';
  const reason = code === 'role_isolated' ? 'a role must permit itself; check the peer roles' : code === 'role_reserved_name'
    ? 'that role name is reserved' : typeof body?.detail === 'string' ? body.detail : typeof code === 'string' ? code : `HTTP ${status}`;
  return verb + ' refused: ' + reason + '.';
}
export function definitionPreviewText(title, body) {
  return title + `.\nMembership changes: ${body.member_delta}\nDevices losing distribution permission: ${body.origin_access_lost}`
    + `\nDevices losing all permitted peers: ${body.empty_permitted_sets}\nRole-to-role links removed: ${body.role_pairs_stopped}`
    + `\nSpeed or agent settings changed: ${body.qos_changed ? 'yes' : 'no'}`
    + '\nChanges affect new pairings; existing device-to-device sessions may continue.'
    + (body.requires_confirmation ? '\nThis exceeds the confirmation threshold; applying confirms these effects.' : '');
}
