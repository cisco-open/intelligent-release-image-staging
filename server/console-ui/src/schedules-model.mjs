// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {checkedIds} from './assignments-model.mjs';

export function scheduleTargetSummary(row) {
  var target = (row && row.target) || {};
  var filters = target.filters || {};
  var parts = Object.keys(filters).sort().filter(function (key) {
    return filters[key] !== '' && filters[key] != null;
  }).map(function (key) { return key + '=' + filters[key]; });
  var named = (target.device_ids || []).length;
  if (named) parts.push(named + ' named device(s)');
  return (parts.length ? parts.join(', ') : 'whole fleet') + ' · ' +
    (target.bind === 'early'
      ? 'bound at creation' : 'resolved at each run');
}

// The slot the SERVER computed (see _schedule_views): local weekly time
// across a DST boundary is the runner's arithmetic, never the browser's.
export function scheduleNextFireText(row) {
  var slot = row && row.next_fire;
  // A paused or completed schedule reports its own state; anything else
  // with no slot has simply run out of them. An unreadable row says the
  // latter rather than rendering "undefined" at an operator.
  if (!slot) {
    var state = row && row.state;
    return state && state !== 'pending' ? state : 'no further run';
  }
  return slot.local_time + ' ' + slot.tz + ' (' + slot.status + ')';
}

// What the target actually resolved to at fire time, against the preview
// the operator approved. A late-bound target is meant to move; this is how
// much it moved.
export function scheduleDeltaText(occurrence) {
  var delta = occurrence && occurrence.delta;
  if (!delta) return '';
  if (![delta.added, delta.removed].every(value => Number.isSafeInteger(value) && value >= 0)) return 'target change unavailable';
  return '+' + delta.added + ' / \u2212' + delta.removed + ' since preview';
}

// Missing is reported apart from errored on purpose: a dark device is not
// a failed one, and an operator deciding whether to wait needs to see which
// of the two is holding the wave.
export function scheduleWaveText(occurrence) {
  var wave = occurrence && occurrence.annotations &&
    occurrence.annotations.wave;
  if (!wave) return '';
  if (!['open', 'held'].includes(wave.gate) || ![wave.staged, wave.errored, wave.missing, wave.total].every(value => Number.isSafeInteger(value) && value >= 0)
    || wave.staged + wave.errored + wave.missing > wave.total) return 'wave evidence unavailable';
  return 'wave ' + wave.gate + ' · ' + wave.staged + ' staged / ' +
    wave.errored + ' errored / ' + wave.missing + ' missing of ' +
    wave.total;
}

export function scheduleCreatorText(row) {
  return row.created_by + (row.creator_exists ? ''
    : ' (actor no longer exists)');
}

// The Devices filter IS the schedule's target: it is re-resolved at each
// run, which is the reason to schedule against it rather than against the
// rows that happen to be checked now. Naming devices instead is the
// explicit second choice, and it says so in the modal.
export function scheduleTargetFromFilters(state, ids, scope) {
  if (scope === 'selection') {
    return { filters: {}, device_ids: (ids || []).slice(), bind: 'late' };
  }
  var names = { q: 'q', managementType: 'management_type',
                platform: 'platform', cred: 'cred', telemetry: 'telemetry',
                peer: 'peer', role: 'role', modelFamily: 'model_family',
                osFamily: 'os_family', status: 'status' };
  var filters = {};
  Object.keys(names).forEach(function (key) {
    if (state[key]) filters[names[key]] = state[key];
  });
  return { filters: filters, device_ids: [], bind: 'late' };
}

export function scheduleDefinitionFromForm(values) {
  var when = values.recurring
    ? { kind: 'recurring', weekday: values.weekday, hour: values.hour,
        minute: values.minute, tz: values.tz,
        window_seconds: values.windowSeconds }
    : { kind: 'once', at: values.at, tz: values.tz,
        window_seconds: values.windowSeconds };
  var payload = values.kind === 'assign'
    ? { image_ids: (values.imageIds || []).slice(), mode: values.mode }
    : { telemetry: !!values.telemetry,
        telemetry_stream: !!values.telemetryStream,
        mode: 'new-only', max_devices: values.maxDevices };
  return { id: values.id, kind: values.kind, target: values.target,
           payload: payload, when: when };
}

// A schedule already aimed at this device, shown on the row itself so a
// manual assignment is not made in ignorance of one. It reads the stored
// preview: a late-bound target is re-resolved at fire time, so this is the
// last approved answer, not a promise about the next one.
export function pendingScheduleText(deviceId, rows) {
  var names = (rows || []).filter(function (row) {
    return row.state === 'pending' &&
      ((row.preview && row.preview.device_ids) || []).indexOf(deviceId) > -1;
  }).map(function (row) { return row.id; });
  return names.length ? 'Scheduled: ' + names.join(', ') : '';
}

export const initialForm = () => ({id: '', scope: 'filter', kind: 'assign', imageIds: [], mode: 'merge',
  maxDevices: '20', when: 'once', at: '', weekday: '6', time: '02:30', tz: '', windowMinutes: '60'});
export function checkedSchedules(body) {
  if (!Array.isArray(body?.schedules) || body.total !== body.schedules.length) throw new Error('Incomplete schedule list');
  checkedIds(body.schedules.map(row => row?.id), Number.MAX_SAFE_INTEGER);
  for (const row of body.schedules) {
    if (!['assign', 'onboard'].includes(row.kind) || !['pending', 'paused', 'completed'].includes(row.state)
      || typeof row.created_by !== 'string' || typeof row.creator_exists !== 'boolean'
      || !Number.isSafeInteger(row.rev) || row.rev < 1 || row.etag !== `"iris-schedule-${row.id}-${row.rev}"`
      || !row.target || !row.target.filters || typeof row.target.filters !== 'object' || Array.isArray(row.target.filters)
      || !['early', 'late'].includes(row.target.bind)
      || Object.values(row.target.filters).some(value => typeof value !== 'string')) throw new Error('Invalid schedule');
    checkedIds(row.target.device_ids, 20000); checkedIds(row.preview?.device_ids, 20000);
    if (row.next_fire !== null && (!row.next_fire || ['local_time', 'tz', 'status'].some(key => typeof row.next_fire[key] !== 'string'))) throw new Error('Invalid next run');
  }
  return body.schedules;
}
export function formDefinition(form, dialog, images, imagesOk) {
  const id = form.id.trim(), tz = form.tz.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) throw new Error('Use 1–64 letters, numbers, dots, underscores or hyphens for the schedule id. Start with a letter or number.');
  if (!['filter', 'selection'].includes(form.scope)) throw new Error('Choose a target.');
  if (form.scope === 'filter' && !dialog.filterReady) throw new Error('Filter preview unavailable. Close and refresh Inventory first.');
  if (!['assign', 'onboard'].includes(form.kind)) throw new Error('Choose an action.');
  if (!['once', 'recurring'].includes(form.when)) throw new Error('Choose when to run.');
  if (!tz) throw new Error('Enter the schedule time zone.');
  const windowSeconds = Number(form.windowMinutes) * 60;
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 604800) throw new Error('Use a window between one second and seven days.');
  const recurring = form.when === 'recurring', at = Math.floor(new Date(form.at).getTime() / 1000);
  const weekday = Number(form.weekday), time = /^(\d{2}):(\d{2})$/.exec(form.time), hour = Number(time?.[1]), minute = Number(time?.[2]);
  if (!recurring && (!Number.isSafeInteger(at) || at <= 0)) throw new Error('Choose when this window starts.');
  if (recurring && (!Number.isInteger(weekday) || weekday < 0 || weekday > 6 || !time || hour > 23 || minute > 59)) throw new Error('Choose a valid weekday and time.');
  const maxDevices = Number(form.maxDevices); let imageIds = [];
  if (form.kind === 'assign') {
    try { imageIds = checkedIds(form.imageIds, 10); } catch { throw new Error('Choose at most ten different images.'); }
    if (!['merge', 'replace'].includes(form.mode)) throw new Error('Choose an assignment mode.');
    if (!imagesOk) throw new Error('Image catalog unavailable. Refresh Inventory before creating this schedule.');
    if (!imageIds.length) throw new Error('Choose at least one image to assign.');
    if (imageIds.some(id => !images.some(row => row.id === id && !row.quarantined))) throw new Error('A chosen image is unavailable or quarantined. Review the images.');
  } else if (!Number.isSafeInteger(maxDevices) || maxDevices < 1 || maxDevices > 20000) throw new Error('Maximum devices must be a whole number from 1 to 20000.');
  return scheduleDefinitionFromForm({id, kind: form.kind, target: scheduleTargetFromFilters(dialog.filters, dialog.ids, form.scope),
    imageIds, mode: form.mode, maxDevices, telemetry: true, telemetryStream: false,
    recurring, at, weekday, hour, minute, tz, windowSeconds});
}
export function scheduleWriteResult(response, body, id, previousRev = null) {
  if (response.status >= 500) return 'unknown';
  if (response.status === 412) return 'conflict';
  if (!response.ok) return 'refused';
  try {
    const [row] = checkedSchedules({schedules: [body?.schedule], total: 1});
    if (row.id !== id || !row.creator_exists || (previousRev !== null && row.rev <= previousRev)) return 'unknown';
    return 'saved';
  } catch { return 'unknown'; }
}
export function historyText(occurrence) {
  if (occurrence === null) return 'no run yet';
  if (!occurrence) return 'run history unavailable';
  return [occurrence.state, scheduleDeltaText(occurrence), scheduleWaveText(occurrence)].filter(Boolean).join(' · ');
}
