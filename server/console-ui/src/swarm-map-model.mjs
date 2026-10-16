// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const POLL_SECONDS = 5;
export const MEASURED_RATE_FRESH_S = 120;
export const DENSE_LABEL_THRESHOLD = 40;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const optionalRecord = value => value === undefined || value === null || object(value);
const optionalText = value => value === undefined || value === null || typeof value === 'string';
export const validRevision = value => Number.isSafeInteger(value) && value >= 0;

export function eventsLink(template, peer) {
  if (typeof template !== 'string' || !/^https?:\/\//i.test(template) || /[\u0000-\u0020\u007f]/.test(template)) return null;
  const values = {ip: peer?.ip, device_id: peer?.device_id};
  try {
    const url = new URL(template.replace(/\{(ip|device_id)\}/g, (_, key) => encodeURIComponent(typeof values[key] === 'string' ? values[key] : '')));
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

export function validSnapshot(data) {
  if (!object(data) || data.error || !Number.isFinite(data.now) || data.now < 0 || !Array.isArray(data.images)
    || !optionalRecord(data.server) || !optionalText(data.server?.host) || !optionalRecord(data.server?.server_observation)) return false;
  const hashes = new Set(); let entries = 0;
  for (const image of data.images) {
    if (!object(image) || typeof image.info_hash !== 'string' || !/^[a-f0-9]{40}$/.test(image.info_hash)
      || hashes.has(image.info_hash) || !Array.isArray(image.peers) || !optionalText(image.image)
      || !optionalText(image.image_id)) return false;
    hashes.add(image.info_hash);
    if (image.peer_edges !== undefined && (!Array.isArray(image.peer_edges) || image.peer_edges.some(edge => !object(edge)))) return false;
    for (const peer of image.peers) {
      if (!object(peer) || !object(peer.tracker)) return false;
      const tracker = peer.tracker;
      if (!optionalText(tracker.role)) return false;
      if (!['device', 'service', 'legacy'].includes(tracker.principal_type)) return false;
      if (tracker.principal_type !== 'legacy' && (typeof tracker.principal_id !== 'string' || !tracker.principal_id)) return false;
      if (tracker.principal_type === 'device' && peer.device_id !== tracker.principal_id) return false;
      if (tracker.principal_type === 'legacy' && peer.device_id != null) return false;
      for (const name of ['staged_image_ids', 'errored_image_ids']) {
        if (peer[name] !== undefined && (!Array.isArray(peer[name]) || peer[name].some(value => typeof value !== 'string'))) return false;
      }
      for (const name of ['device_id', 'ip', 'model', 'current_image_id', 'stage_state']) if (!optionalText(peer[name])) return false;
      for (const name of ['device_observation', 'server_observation', 'latest_report', 'peer_policy', 'peer_enforcement', 'peer_tls', 'peer_telemetry']) {
        if (!optionalRecord(peer[name])) return false;
      }
      if (!optionalText(peer.device_observation?.obs_state)) return false;
      entries++;
    }
  }
  return (!('peers_offset' in data) || data.peers_offset === 0) && (!('peers_total' in data) || data.peers_total === entries);
}

export function validReports(reports) {
  return Array.isArray(reports) && reports.every(report => object(report)
    && ['image_id', 'schema', 'event', 'report_id', 'report_request_id'].every(key => optionalText(report[key]))
    && (report.peers === undefined || Array.isArray(report.peers) && report.peers.every(peer => typeof peer === 'string' || object(peer))));
}
export function validDirective(value) {
  return object(value) && id(value.request_id) && Number.isFinite(value.requested_at) && value.requested_at >= 0
    && Number.isFinite(value.expires_at) && value.expires_at > value.requested_at;
}
export function intervalReply(body, peer, interval, revision, dry) {
  return object(body) && body.ok === true && body.device_id === peer.device_id && body.requested_interval_s === interval
    && validRevision(revision) && validRevision(revision + 1) && body.revision === revision + 1
    && body.candidate_revision === revision + 1 && body.dry_run === dry;
}
export function reportsReply(body, deviceId) {
  return object(body) && body.device_id === deviceId && validReports(body.reports)
    && Number.isFinite(body.observed_at) && body.observed_at >= 0
    && (body.pending_request === null || validDirective(body.pending_request));
}
export function matchingPull(reports, request) {
  return !!request && reports.some(report => (report.schema === 'v2' || report.v === 2) && report.event === 'pull'
    && report.report_request_id === request.request_id && id(report.report_id));
}

export function participantRows(data) {
  return (data?.images || []).flatMap(image => image.peers.map(peer => ({...peer, _img: image.image, _hash: image.info_hash, _image_id: image.image_id})));
}
export function peerKey(peer) {return JSON.stringify([peer._hash, peer.tracker?.principal_type, peer.tracker?.principal_id ?? peer.device_id, peer.ip, peer.port]);}
export function peerName(peer) {return peer.tracker?.principal_type === 'legacy' ? 'Legacy unattributed peer' : peer.device_id || 'Unknown participant';}
export function peerModel(peer) {return peer.tracker?.principal_type === 'legacy' ? '' : String(peer.model ?? '').trim();}
export function peerCaption(peer) {const model = peerModel(peer); return model ? `${peerName(peer)} (${model})` : peerName(peer);}
export function peerRowLabel(peer) {const name = peerName(peer); return name + (peer.ip && peer.ip !== name ? ` — ${peer.ip}` : '');}
export function otherImage(peer, source) {return Boolean(peer._image_id && source?.image_id && peer._image_id !== source.image_id);}
export function imageState(peer, imageId) {
  if ((peer.errored_image_ids || []).includes(imageId)) return 'error';
  if ((peer.staged_image_ids || []).includes(imageId)) return 'ready';
  if (!Array.isArray(peer.staged_image_ids) && !Array.isArray(peer.errored_image_ids)
    && imageId === peer.current_image_id && peer.stage_state) return peer.stage_state;
  if (peer.stage_state && !['ready', 'idle', 'unassigned'].includes(peer.stage_state)) return 'pending — device reports ' + peer.stage_state;
  return 'pending';
}
export function peerTlsLabel(peer, now) {
  const tls = peer.peer_tls || {}, mode = tls.runtime_source === 'aria2_rpc' ? tls.runtime_mode : 'unknown';
  const known = ['required', 'disabled'].includes(mode), stale = !Number.isFinite(tls.reported_at) || now - tls.reported_at >= 600;
  return 'TLS ' + (known ? mode === 'required' ? 'required' : 'off' : 'unknown') + (known && stale ? ' (stale)' : '');
}
export function peerStatus(peer, now) {
  const device = peer.device_observation, enforcement = peer.peer_enforcement, parts = [];
  if (peer._image_id && peer.device_id) parts.push(imageState(peer, peer._image_id));
  if (peer.device_id) parts.push(peerTlsLabel(peer, now));
  if (peer.tracker?.principal_type === 'legacy') parts.push('legacy unattributed');
  if (otherImage(peer, device)) parts.push('device observation is for another image');
  else if (!device) parts.push('device telemetry unavailable');
  else if (device.obs_state && device.obs_state !== 'observed') parts.push('device telemetry ' + device.obs_state.replace(/_/g, ' '));
  else if (device.stale) parts.push('device telemetry stale');
  else parts.push(device.obs_state || 'device telemetry fresh');
  if (peer.peer_policy?.quarantined) parts.push('policy intent: quarantined');
  if (enforcement) {
    parts.push('tracker enforcement: ' + (enforcement.state || 'unknown') + ' (fleet-wide, not this peer)');
    if (enforcement.blocked === true) parts.push('THIS PEER BLOCKED');
  }
  return parts.join(' · ');
}
export function filteredPeers(data, {imageHash = 'all', query = '', attention = ''} = {}, now = data?.now) {
  return participantRows(data).filter(peer => imageHash === 'all' || peer._hash === imageHash)
    .filter(peer => !query || (peerName(peer) + ' ' + (peer.ip || '') + ' ' + (peer.model || '') + peerStatus(peer, now)).toLowerCase().includes(query.toLowerCase()))
    .filter(peer => attention !== 'attention' || /error|failed|stale|unavailable|quarantined|legacy/.test(peerStatus(peer, now)));
}
export function sortedPeers(peers, {column = 'name', direction = 1} = {}, now) {
  const key = peer => column === 'model' ? String(peer.model || '~') : column === 'role' ? String(peer.tracker?.role || '~')
    : column === 'status' ? peerStatus(peer, now) : peerName(peer);
  return [...peers].sort((left, right) => (direction < 0 ? -1 : 1) * key(left).localeCompare(key(right), undefined, {numeric: true}));
}
export function freshServerPeer(peer, data, now) {
  const measured = peer.server_observation?.peer, observed = measured?.observed_at ?? data?.server?.server_observation?.observed_at;
  // Fallback is valid only while the producer emits peer rates with this poll.
  return measured && Number.isFinite(measured.send_bps) && measured.send_bps > 0 && Number.isFinite(observed)
    && now >= observed && now - observed <= MEASURED_RATE_FRESH_S ? {...measured, observed_at: observed} : null;
}
export function freshPeerEdges(data, now, imageHash = 'all') {
  return (data?.images || []).filter(image => imageHash === 'all' || image.info_hash === imageHash).flatMap(image =>
    (image.peer_edges || []).slice(0, 1024).filter(edge => Number.isFinite(edge.bytes_per_second) && edge.bytes_per_second > 0
      && (edge.valid_for_s === undefined || Number.isFinite(edge.valid_for_s) && edge.valid_for_s >= 0)
      && Number.isFinite(edge.received_at) && now >= edge.received_at && now - edge.received_at <= Math.min(120, edge.valid_for_s ?? 120)
      && ['source_device_id', 'target_device_id', 'reporter_device_id'].every(key => typeof edge[key] === 'string' && edge[key]))
      .map(edge => ({...edge, _hash: image.info_hash, _img: image.image})));
}
export const formatBytes = value => value == null || !Number.isFinite(Number(value)) ? '—'
  : Number(value) < 1024 ? Math.round(Number(value)) + ' B' : (Number(value) / 1024 / 1024).toFixed(1) + ' MB';
export const rate = value => value == null ? '—' : formatBytes(value) + '/s';
export const age = (when, now) => !Number.isFinite(when) ? '—' : Math.max(0, Math.round(now - when)) + 's ago';
export const edgeLabel = (edge, now) => `${edge.source_device_id} → ${edge.target_device_id}: ${rate(edge.bytes_per_second)} · reported ${age(edge.received_at, now)} by ${edge.reporter_device_id}`;
