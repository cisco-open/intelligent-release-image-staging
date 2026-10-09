// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const OFFLINE_FEED_LIMIT = 256 * 1024 * 1024;
export const verificationPaths = {settings: '/api/v1/settings/image-verification',
  refresh: '/api/v1/image-verification/refresh', offline: '/api/v1/image-verification/offline'};
const counts = ['matched', 'mismatched', 'not_in_feed'];
const count = value => Number.isSafeInteger(value) && value >= 0;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const modes = ['off', 'daily', 'weekly'];
const validHour = value => Number.isInteger(value) && value >= 0 && value <= 23;

export function verificationSettings(value) {
  if (!record(value) || !modes.includes(value.mode) || !validHour(value.hour_utc) || !record(value.last_run)) return null;
  const run = value.last_run, never = run.at === null;
  if (never) {if (['source', 'outcome', ...counts].some(key => run[key] !== null)) return null;}
  else {
    if (!count(run.at) || run.at > 8640000000000 || !['manual', 'scheduled', 'offline'].includes(run.source)) return null;
    if (run.outcome === 'ok') {if (!counts.every(key => count(run[key]))) return null;}
    else if (typeof run.outcome === 'string' && run.outcome.startsWith('fail: ') && run.outcome.length <= 206) {
      if (!counts.every(key => run[key] === null)) return null;
    } else return null;
  }
  return {mode: value.mode, hour_utc: value.hour_utc,
    last_run: Object.fromEntries(['at', 'source', 'outcome', ...counts].map(key => [key, run[key]]))};
}

export function scheduleRequest(mode, hour) {
  if (!modes.includes(mode) || !/^(?:[0-9]|1[0-9]|2[0-3])$/.test(String(hour))) throw Error('Choose a frequency and an hour from 00:00 to 23:00 UTC.');
  return {mode, hour_utc: Number(hour)};
}

export function checkedVerificationResult(action, response, body, payload) {
  if (!record(body)) return 'unknown';
  if (action === 'schedule') {
    const checked = verificationSettings(body);
    if (response.status === 200 && checked?.mode === payload.mode && checked?.hour_utc === payload.hour_utc) return 'saved';
  } else {
    if (response.status === 200 && body.outcome === 'ok' && counts.every(key => count(body[key]))) return 'complete';
    if (response.status === 409 && body.outcome === 'already_running') return 'running';
    if (response.status === 502 && body.outcome === 'fail' && typeof body.detail === 'string' && body.detail.length <= 200
      && counts.every(key => body[key] === null || body[key] === undefined)) return 'failed';
  }
  // Only a bounded, explicit client rejection proves this request was refused.
  // A proxy 5xx or malformed successful body cannot establish the outcome.
  if ([400, 401, 403, 404, 413].includes(response.status) && typeof body.error === 'string' && body.error.length <= 500) return 'refused';
  return 'unknown';
}

export function countSummary(run) {
  return `${run.matched} matched, ${run.mismatched} mismatched, ${run.not_in_feed} not in feed`;
}

export function lastRunSummary(run, formatDate) {
  if (!run || run.at === null) return 'Never run.';
  const prefix = `${formatDate(run.at)} · ${run.source}`;
  return run.outcome === 'ok' ? `${prefix} · ${countSummary(run)}.`
    : `${prefix} · Failed: ${run.outcome.slice(6)}`;
}

export function validOfflineFile(file) {
  return file && Number.isSafeInteger(file.size) && file.size > 0 && file.size <= OFFLINE_FEED_LIMIT
    && typeof file.name === 'string' && /\.tar$/i.test(file.name);
}
