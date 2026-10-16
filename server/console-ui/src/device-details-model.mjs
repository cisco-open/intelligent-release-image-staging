// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {formatDate} from './image-model.mjs';

const text = value => typeof value === 'string' || Number.isFinite(value) ? String(value) : '';
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const lookup = (map, key, fallback = '') => Object.hasOwn(map, key) ? map[key] : fallback;
const series = {IE3x00: 'IE Switches', IR1x00: 'IR Routers', C8xxx: 'Catalyst Routers',
  C9xxx: 'Catalyst Switches', NCS: 'NCS', XR8000: 'Cisco 8000 Series'};
const platforms = {guestshell: 'Guest Shell', iox: 'IOx', router: 'Guest Shell', 'xr-appmgr': 'XR appmgr container'};
const aliases = [...Object.keys(series), 'ISR/ASR/CSR'];
const strings = value => Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
const assignedIds = device => device.assigned_image_ids?.length ? strings(device.assigned_image_ids)
  : typeof device.assigned_image_id === 'string' && device.assigned_image_id ? [device.assigned_image_id] : [];

export function hardwareRows(device = {}, record = {}) {
  const candidates = [[record?.preflight?.detected_model, 'last preflight'],
    [record?.resolved?.model, 'deployment record'], [device.model, 'inventory'],
    [device.heartbeat_model, 'agent-reported']];
  const chassis = candidates.find(([value]) => typeof value === 'string' && value.trim()
    && !aliases.some(alias => alias.toLowerCase() === value.trim().toLowerCase()));
  return [{label: 'Series', value: lookup(series, device.model_family, '—')},
    {label: 'Chassis model', value: chassis?.[0] || 'Not detected', note: chassis?.[1]}];
}

export function validRecordResponse(body) {
  return object(body) && (body.record === null || (object(body.record)
    && ['resolved', 'preflight', 'timestamps'].every(key => body.record[key] == null || object(body.record[key]))))
    && (body.total == null || (Number.isInteger(body.total) && body.total >= 0));
}

export function recordRows(rec, total = 0) {
  const res = rec.resolved || {}, ts = rec.timestamps || {}, pf = rec.preflight || {};
  const managementType = text(res.management_type), xrHost = managementType === 'xr-host';
  const mgmt = managementType.startsWith('router-')
    ? (res.vpg_number != null && text(res.vpg_number) ? 'VPG' + text(res.vpg_number) : '')
    : (res.inband_vlan || res.iris_vlan ? 'VLAN ' + text(res.inband_vlan || res.iris_vlan) : '');
  const svi = text(res.svi_ip) ? text(res.svi_ip) + (text(res.svi_mask) ? ' / ' + text(res.svi_mask) : '') : '';
  const app = text(res.app_ip) ? text(res.app_ip) + (text(res.app_mask) ? ' / ' + text(res.app_mask) : '')
    + (text(res.app_gateway) ? ' → gw ' + text(res.app_gateway) : '') : '';
  const row = (label, value, extra = {}) => ({label, value: text(value) || '—', ...extra});
  const date = value => Number.isFinite(value) ? formatDate(value) : '';
  const rows = [
    row('State', text(rec.state) || 'unknown', {badge: lookup({active: 'badge-ok', removed: 'badge-queued',
      superseded: 'badge-cancelled', 'needs-reconcile': 'badge-fail'}, rec.state, 'badge-queued'),
    note: rec.adopted === true ? 'adopted' : ''}),
    row('Record', rec.record_id, {machine: true, note: `${total} stored for this device`}),
    row('Planned', date(ts.planned_at), {machine: true}), row('Finished', date(ts.finished_at), {machine: true}),
    row('Preflight', pf.status), row('Management type', xrHost ? 'XR host' : managementType),
  ];
  // The XR appmgr container uses the host network, not an unknown app VLAN.
  if (!xrHost) {
    rows.push(row('Management VLAN / VPG', mgmt), row('SVI', svi, {machine: true}),
      row('App IP', app, {machine: true}), row('NAT interface', res.nat_interface, {machine: true}));
  }
  rows.push(row('Swarm port', res.swarm_port, {machine: true}),
    row('Agent install', lookup(platforms, res.platform, text(res.platform))),
    row('Device identity', res.device_identity, {machine: true}));
  return rows;
}

export function imageRows(device, filenames = {}) {
  const ids = assignedIds(device), errored = strings(device.errored_image_ids), staged = strings(device.staged_image_ids);
  const perImage = device.staged_image_ids != null || device.errored_image_ids != null;
  const rows = ids.map(id => {
    let state;
    // An error overrides retained staged membership. current_image_id is an
    // identity pointer, never an activity pointer for a multi-image heartbeat.
    if (errored.includes(id)) state = 'error';
    else if (device.staged_image_ids != null ? staged.includes(id)
      : device.stage_state === 'ready' && device.current_image_id === id) state = 'ready';
    else if (!device.last_seen || !device.stage_state || ['ready', 'unassigned'].includes(device.stage_state)) state = 'pending';
    else if (!perImage) state = device.current_image_id && device.current_image_id !== id ? 'pending'
      : text(device.stage_state) + (text(device.stage_error) ? ' — ' + text(device.stage_error) : '');
    else state = 'staging';
    const filename = text(lookup(filenames, id));
    return {id, label: filename && filename !== id ? `${id} — ${filename}` : id, state};
  });
  if (ids.length && perImage && text(device.stage_error)) rows.push({label: 'Last reported error', state: text(device.stage_error)});
  return rows;
}

export function boundarySteps(device, status, failedRatio, quarantined = {}) {
  const ids = assignedIds(device);
  if (!ids.length) return ['na', 'na', 'upcoming', 'na', 'na', 'na'];
  const count = ids.filter(id => lookup(quarantined, id, false)).length;
  const source = count ? {state: 'failed', level: 'negative', label: `${count} image${count === 1 ? '' : 's'} quarantined`} : 'na';
  let transfer = 'na', staged = 'na';
  if (status?.key === 'placement-failed') transfer = {state: 'failed', level: 'negative', label: 'staging failed'};
  else if (status?.key === 'image-failed') transfer = {state: 'failed', level: failedRatio >= .5 ? 'severe' : 'warning', label: text(status.label)};
  else if (status?.key === 'deployed') { transfer = 'done'; staged = 'done'; }
  else if (['copying', 'staging'].includes(status?.key)) { transfer = 'current'; staged = 'upcoming'; }
  // Neither source verification nor a distinct on-device verification signal
  // is supplied to this view. Unknown must not be inferred as complete.
  return ['done', source, 'done', transfer, 'na', staged];
}
