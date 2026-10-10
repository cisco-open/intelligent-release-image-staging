// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const ranges = {
  '24h': {window: 86400, buckets: 24, label: 'Last 24 h'},
  '7d': {window: 604800, buckets: 28, label: 'Last 7 d'},
  '30d': {window: 2592000, buckets: 30, label: 'Last 30 d'},
  '90d': {window: 7776000, buckets: 45, label: 'Last 90 d'},
};
export const PAGE_SIZE = 25;
export const width = 600, height = 64, handleWidth = 4;
export const bucketCount = span => Math.min(90, Math.max(1, Math.floor(span / 60)));
export const bounds = (range, now) => ({since: now - ranges[range].window, until: now});

export function clampSelection(a, b, outer) {
  let start = Math.max(outer.since, Math.min(outer.until, Math.min(a, b)));
  let end = Math.max(outer.since, Math.min(outer.until, Math.max(a, b)));
  if (end - start < 60) {
    end = Math.min(outer.until, start + 60);
    start = end - 60;
  }
  return {start, end};
}

export function panSelection(selection, shift, outer) {
  const span = Math.min(selection.end - selection.start, outer.until - outer.since);
  const start = Math.max(outer.since, Math.min(selection.start + shift, outer.until - span));
  return {start, end: start + span};
}

export function queries(kind, state, now, cursor) {
  const prefix = `/api/v1/${kind === 'audit' ? 'audit' : 'deploy-logs'}`;
  const outer = bounds(state.range, now), cfg = ranges[state.range];
  const list = new URLSearchParams(), histogram = new URLSearchParams();
  if (kind === 'audit') list.set('limit', '200');
  list.set('after_ts', state.selection?.start ?? Math.floor(outer.since));
  if (state.selection) list.set('before_ts', state.selection.end);
  if (kind === 'audit' && cursor != null) list.set('cursor', cursor);
  if (state.selection) {
    histogram.set('since_ts', state.selection.start);
    histogram.set('until_ts', state.selection.end);
    histogram.set('buckets', bucketCount(state.selection.end - state.selection.start));
  } else {
    histogram.set('window', cfg.window);
    histogram.set('buckets', cfg.buckets);
  }
  if (kind === 'audit' && state.category) {
    list.set('category', state.category);
    histogram.set('category', state.category);
  }
  return {list: `${prefix}?${list}`, histogram: `${prefix}/histogram?${histogram}`};
}

export function deploymentRows(state) {
  const q = state.query.trim().toLowerCase();
  const rows = state.rows.filter(row => (!state.action || row.action === state.action)
    && (!state.result || (row.state || 'unknown') === state.result)
    && (!q || [row.device_id, row.action, row.state, row.rc == null ? '' : `rc=${row.rc}`]
      .filter(Boolean).join(' ').toLowerCase().includes(q)));
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const page = Math.max(0, Math.min(state.page, pages - 1));
  return {rows: rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), total: rows.length, pages, page};
}

const verbs = {
  login: 'logged in', login_fail: 'failed to log in', setup: 'created the admin account', logout: 'logged out',
  password_change: 'changed the console password', password_change_fail: 'failed to change the console password',
  revoke_other_sessions: 'revoked other console sessions', 'gui-cert-replace': 'replaced the console TLS certificate',
  'gui-cert-revert': 'selected the deployment default certificate', 'trust-add': 'installed a trusted CA certificate',
  'trust-remove': 'removed a trusted CA certificate', 'ca-trust-config': 'changed the CA bundle download settings',
  'ca-trust-refresh': 'refreshed the public CA bundle', 'telemetry-destination-set': 'changed the telemetry destination',
  'telemetry-destination-clear': 'reverted the telemetry destination to the deployment default',
  audit_export: 'exported audit log', audit_export_config: 'changed audit export settings',
  device_csv_import: 'imported devices from CSV', revoke: 'had all secrets revoked', auth_fail: 'failed token authentication',
};
const targetVerbs = {
  device_assign: 'assigned an image to', device_credential_change: 'changed the credential profile of',
  device_platform_change: 'changed the platform of', device_delete: 'deleted device',
  request_report: 'requested a fresh report from', onboard_start: 'started onboarding',
  undeploy_start: 'started undeploying', credential_profile_delete: 'deleted credential profile',
  mint: 'minted a token for', refresh: 'rotated the catalog token of', refresh_fail: 'failed to rotate the token of',
};
const categories = {mint: 'token', refresh: 'token', refresh_fail: 'token', revoke: 'token', auth_fail: 'auth'};

export function auditMessage(event) {
  const target = event.target || event.device_id || '';
  let message = Object.hasOwn(verbs, event.event) ? verbs[event.event] : '';
  if (Object.hasOwn(targetVerbs, event.event)) message = `${targetVerbs[event.event]} ${target}`;
  switch (event.event) {
    case 'device_upsert': message = `${event.action === 'create' ? 'added' : event.action === 'update' ? 'updated' : 'saved'} device ${target}`; break;
    case 'onboard_finished': message = event.result === 'ok' ? `finished onboarding ${target}` : `onboarding of ${target} failed`; break;
    case 'undeploy_finished': message = event.result === 'ok' ? `finished undeploying ${target}` : `undeploy of ${target} failed`; break;
    case 'onboard_cancel': message = 'cancelled queued onboarding jobs'; break;
    case 'credential_profile_set': message = `${event.action === 'create' ? 'created' : 'updated'} credential profile ${target}`; break;
    case 'image_upload': message = `${event.result === 'ok' ? 'uploaded image' : 'rejected upload of'} ${target}`; break;
    case 'image_publish_finished': message = `${event.result === 'ok' ? 'published image' : 'failed to publish image'} ${target}`; break;
    case 'image_delete': message = `${event.result === 'ok' ? 'deleted image' : 'could not delete image'} ${target}`; break;
  }
  const category = event.category || (Object.hasOwn(categories, event.event) ? categories[event.event] : 'system');
  const actor = event.actor || (event.device_id ? `device:${event.device_id}` : 'system');
  return {
    message: message || `${event.event || 'event'}${target ? ` ${target}` : ''}`,
    category, categoryLabel: category === 'onboard' ? 'deployment' : category,
    actor: actor.replace(/^(console:|device:)/, ''),
    actorTitle: actor.startsWith('console:') ? 'console session' : actor.startsWith('device:') ? 'device' : '',
    actorClass: actor.startsWith('device:') ? 'machine' : actor === 'system' ? 'muted' : '',
    detail: event.detail || (event.secret_name ? `${event.secret_name} ${event.old_id || '?'} -> ${event.new_id || '?'}` : ''),
    source: category === 'auth' ? event.src_ip : '',
  };
}

export function formatAgo(ts, now) {
  const seconds = Math.max(0, Math.floor(now - ts));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function validRows(rows, kind, {allowUndated = false} = {}) {
  const text = kind === 'audit'
    ? ['event', 'category', 'actor', 'target', 'device_id', 'detail', 'secret_name', 'old_id', 'new_id', 'src_ip', 'result', 'action']
    : ['file', 'device_id', 'action', 'state'];
  return Array.isArray(rows) && rows.every(row => row && typeof row === 'object'
    && !Array.isArray(row) && text.every(key => row[key] == null || typeof row[key] === 'string')
    && ((kind === 'deploylogs' && allowUndated && row.finished_at == null)
      || Number.isFinite(row[kind === 'audit' ? 'ts' : 'finished_at']))
    && (kind === 'audit' || (typeof row.file === 'string'
      && (row.rc == null || Number.isFinite(row.rc)) && (row.size == null || Number.isFinite(row.size)))));
}

export function deploymentResult(log) {
  const label = log.state || 'unknown';
  const badges = {queued: 'badge-queued', running: 'badge-running', done: 'badge-ok', error: 'badge-fail', cancelled: 'badge-cancelled'};
  return {label, badge: Object.hasOwn(badges, label) ? badges[label] : 'badge-off'};
}
