// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const PAGE_SIZE = 200;
export const FILTER_NAMES = {q: 'q', managementType: 'management_type', platform: 'platform',
  cred: 'cred', telemetry: 'telemetry', peer: 'peer', role: 'role', modelFamily: 'model_family',
  osFamily: 'os_family', status: 'status'};
export const emptyFilters = () => Object.fromEntries(Object.keys(FILTER_NAMES).map(key => [key, '']));
export function filterQuery(filters) {
  return Object.entries(FILTER_NAMES).flatMap(([key, wire]) => {
    const value = key === 'q' ? (filters.q || '').trim().toLowerCase() : filters[key];
    return value ? [wire + '=' + encodeURIComponent(value)] : [];
  }).join('&');
}
export function pageQuery(filters, offset, limit = PAGE_SIZE) {
  const query = filterQuery(filters);
  return (query ? query + '&' : '') + `limit=${limit}&offset=${offset}`;
}
export function checkedPage(body, offset, limit) {
  if (!body || !Array.isArray(body.devices) || !Number.isSafeInteger(body.total) || body.total < 0
    || body.offset !== offset || !Number.isSafeInteger(body.revision) || body.revision < 0
    || body.devices.length > limit || body.devices.some(row => !row || typeof row.device_id !== 'string' || !row.device_id)
    || new Set(body.devices.map(row => row.device_id)).size !== body.devices.length
    || (body.devices.length && offset + body.devices.length > body.total)) throw new Error('Invalid device page');
  return body;
}
export function selectionScope(state) {
  const {selected, rows, total, matchQuery, matchIds, filters} = state;
  const n = selected.size, known = matchQuery !== null && matchQuery === filterQuery(filters);
  const complete = known && matchIds !== null && matchIds.length === total;
  const onPage = rows.filter(row => selected.has(row.device_id)).length;
  const matched = complete ? matchIds.filter(id => selected.has(id)).length : null;
  const all = total > 0 && complete && matched === total;
  const outside = n - (complete ? matched : onPage);
  let text = all ? `· All ${total} matching devices selected` : '';
  if (!known && n) text = '· Selection kept; current matches are unconfirmed';
  else if (outside > 0) text += (text ? '; ' : '· ') + `${outside} selected outside this ${complete ? 'filter' : 'page'}`;
  return {text, offerAll: !all && n > 0 && known && total > 0,
    pageLabel: rows.length && onPage === rows.length ? 'Clear page selection' : 'Select page'};
}
export function managementLabel(device) {
  const type = device.management_type || 'legacy';
  if (type === 'legacy' || type === 'legacy_routed') return 'Inventory only — management type not chosen';
  if (type === 'xr-host') return 'XR host';
  return type + (type.startsWith('router-') ? ` / VPG${device.vpg_number ?? ''}`
    : ` / ${device.inband_vlan || device.iris_vlan || ''}`);
}
export function telemetryBadge(device) {
  if (device.telemetry_enabled === false) return {label: 'off', cls: 'badge-off', title: 'the agent sends no telemetry'};
  if (device.telemetry_stream_enabled === true) return {label: 'streaming', cls: 'badge-ok', title: "live samples ride this device's heartbeats"};
  if (device.telemetry_stream_enabled === false) return {label: 'reports', cls: 'badge-queued', title: 'terminal reports only; re-onboard with Telemetry streaming ticked to enable'};
  if (device.telemetry_enabled === true) return {label: 'reports', cls: 'badge-queued', title: 'agent predates the streaming flag'};
  return {label: '—', cls: '', title: 'no heartbeat yet'};
}
export function tlsBadge(device, now) {
  const tls = device.peer_tls || {}, mode = tls.runtime_source === 'aria2_rpc' ? tls.runtime_mode : 'unknown';
  const known = mode === 'required' || mode === 'disabled';
  const stale = !device.last_seen || now - device.last_seen >= 600;
  const label = known ? (mode === 'required' ? 'required' : 'off') : 'unknown';
  const configured = tls.configured_mode === 'required' ? 'required' : tls.configured_mode === 'disabled' ? 'off' : 'unknown';
  return {label: 'TLS ' + label + (stale && known ? ' (stale)' : ''), cls: known && !stale ? 'badge-queued' : 'badge-off',
    title: 'Torrent transport: daemon policy last reported ' + (device.last_seen ? new Date(device.last_seen * 1000).toLocaleString() : 'never')
      + '. Configured: ' + configured + '. This is not a negotiated connection measurement.'};
}
export function instructionBadge(device) {
  const instruction = device.instruction;
  if (!instruction || typeof instruction !== 'object' || Array.isArray(instruction)) return {label: 'unknown', cls: 'badge-queued', detail: ''};
  const state = typeof instruction.display_state === 'string' ? instruction.display_state : 'unknown';
  const cls = state === 'applied' ? 'badge-ok' : state === 'pending' ? 'badge-running'
    : ['rejected', 'revoked', 'forbidden'].includes(state) ? 'badge-fail'
      : ['pre-instructions', 'none', 'tracker-only'].includes(state) ? 'badge-off' : 'badge-queued';
  const detail = [];
  if (typeof instruction.evidence === 'string') detail.push(instruction.evidence);
  if (instruction.underlying_state && instruction.underlying_state !== state) detail.push('last agent report (agent-asserted): ' + instruction.underlying_state);
  if (typeof instruction.reason === 'string') detail.push('reason: ' + instruction.reason);
  detail.push(Number.isSafeInteger(instruction.report_age_seconds) && instruction.report_age_seconds >= 0
    ? `report ${instruction.report_age_seconds}s old` : 'report age unavailable');
  if (instruction.pointer_skew === true) detail.push('pointer skew');
  detail.push(Number.isSafeInteger(instruction.qos_drift_count) && instruction.qos_drift_count >= 0
    ? `${instruction.qos_drift_count} QoS drift violation${instruction.qos_drift_count === 1 ? '' : 's'}` : 'QoS drift unavailable');
  return {label: typeof instruction.label === 'string' ? instruction.label : 'unknown', cls, detail: detail.join(' · ')};
}
export function enforcementBadge(policy, available) {
  if (!available) return {label: 'unavailable', cls: 'badge-off', title: 'Current sharing policy is unavailable'};
  const e = policy?.enforcement || {};
  const state = ['pending', 'enforced', 'degraded', 'rpc_unavailable', 'fail_closed'].includes(e.state) ? e.state : 'pending';
  let title = `Last tracker enforcement: ${state}; desired peers: ${typeof e.desired_ip_count === 'number' ? e.desired_ip_count : 0}`;
  title += '; last reconciled: ' + (e.last_reconciled_at ? new Date(e.last_reconciled_at * 1000).toLocaleString() : 'never');
  if (e.stale) title += ' (STALE -- enforcement may not reflect current policy; check the tracker process)';
  if (e.last_error) title += '; last error: ' + e.last_error;
  if (e.conflict_count) title += '; conflicts: ' + (e.conflict_types || []).join(', ');
  return {label: state + (e.stale ? ' (stale)' : ''), title,
    cls: e.stale || ['degraded', 'fail_closed'].includes(state) ? 'badge-fail' : state === 'enforced' ? 'badge-ok' : 'badge-queued'};
}
