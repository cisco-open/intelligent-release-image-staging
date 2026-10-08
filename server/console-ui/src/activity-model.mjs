// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const MAX_LOGS = 6, MAX_LINES = 500, MAX_CHARS = 262144;
export const active = job => ['queued', 'running'].includes(job?.state);
const actions = {onboard: 'Onboard', undeploy: 'Undeploy', 'iox-recover': 'Recover', 'iox-reconcile-enabled': 'Reconcile'};
export const actionLabel = action => Object.hasOwn(actions, action) ? actions[action] : 'Device action';

export function validListing(body) {
  const textFields = ['device_id', 'action', 'state', 'last_line'];
  return !!body && Array.isArray(body.jobs) && (body.now == null || Number.isFinite(body.now))
    && body.jobs.every(job => job && typeof job.id === 'string' && job.id && typeof job.device_id === 'string' && job.device_id
      && textFields.every(key => job[key] == null || typeof job[key] === 'string')
      && ['started_at', 'finished_at', 'queued_at'].every(key => job[key] == null || Number.isFinite(job[key])))
    && new Set(body.jobs.map(job => job.id)).size === body.jobs.length;
}

export function activityRows(state) {
  const scope = state.scope === null ? null : new Set(state.scope);
  const queued = state.jobs.filter(job => job.state === 'queued');
  return state.jobs.filter(job => !scope || scope.has(job.id)).map(job => {
    let duration = '';
    if (job.state === 'queued') duration = `#${queued.indexOf(job) + 1} in line`;
    else if (job.started_at != null && (job.finished_at != null || state.now != null)) {
      const seconds = Math.max(0, Math.round((job.finished_at ?? state.now) - job.started_at));
      duration = seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m${String(seconds % 60).padStart(2, '0')}s`;
    }
    return {...job, duration};
  });
}

export function summary(rows, scoped) {
  if (!rows.length) return scoped ? 'No confirmed jobs in this batch.' : 'No recent device activity.';
  const counts = new Map();
  for (const row of rows) counts.set(row.state || 'unknown', (counts.get(row.state || 'unknown') || 0) + 1);
  return [...counts].map(([state, count]) => `${count} ${state === 'error' ? 'failed' : state}`).join(' · ');
}

export function appendLines(entry, value) {
  const text = String(value), fresh = text.slice(-MAX_CHARS).split('\n');
  if (text.length > MAX_CHARS || entry.lines.length + fresh.length > MAX_LINES) entry.truncated = true;
  entry.lines = [...entry.lines, ...fresh].slice(-MAX_LINES);
  let size = entry.lines.reduce((sum, line) => sum + line.length + 1, 0);
  while (size > MAX_CHARS && entry.lines.length > 1) {
    size -= entry.lines.shift().length + 1; entry.truncated = true;
  }
}

export function submissionMessage(action, accepted, refused, unknown) {
  let message = `Started ${action} for ${accepted} device(s)`;
  if (refused.length) message += '; refused: ' + refused.join(', ');
  if (unknown.length) message += '; outcome unknown: ' + unknown.join(', ')
    + '. Close and reopen Activity to check before trying again.';
  return message;
}
