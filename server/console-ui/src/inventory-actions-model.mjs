// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const CSV_LIMIT = 8 * 1024 * 1024;
export const initialOptions = () => ({telemetry: true, telemetry_stream: false, onboardLog: false, undeployLog: false, force: false});
export function jobOptions(action, options = initialOptions()) {
  if (action === 'onboard') return {telemetry: options.telemetry !== false, telemetry_stream: !!options.telemetry_stream, log: !!options.onboardLog};
  if (action === 'undeploy') return {...(options.force ? {force: true} : {}), log: !!options.undeployLog};
  throw new Error('Unknown job action');
}
export function csvProblem(body, status) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'HTTP ' + status;
  let detail = [body.detail, body.message, body.error].find(value => typeof value === 'string' && value.trim()) || ('HTTP ' + status);
  for (const key of ['role', 'device_id']) if (typeof body[key] === 'string') detail += ` · ${key}: ${body[key]}`;
  if (body.error === 'role_not_found') detail += '. Define the role in Policies before importing.';
  return detail.slice(0, 1200);
}
export function actionConfirmation(action, ids) {
  if (action === 'delete') return `Delete ${ids.length} device(s) from the inventory?\n\n${ids.join(', ')}\n\n`
    + 'This does NOT undeploy the agent or remove staged images. Undeploy first if you want to remove IRIS from the device.\n\n'
    + 'Old deployment records can no longer be used for cleanup. Re-adding a device starts fresh. This cannot be undone.';
  if (action === 'adopt') return `Adopt ${ids.length} device(s)?\n\n${ids.join(', ')}\n\n`
    + 'Marks existing resources as IRIS-owned: undeploy may then remove them, even if IRIS did not create them. '
    + 'Verify the inventory matches the device. Onboarding again is safer. Routers cannot be adopted.';
  throw new Error('Unknown device action');
}
export function deviceActionResult(action, response, body) {
  const unknown = {kind: 'unknown', reason: 'Response unavailable or incomplete; review before trying again'};
  if (response.status >= 500) return unknown;
  if (!response.ok) return {kind: 'refused', reason: typeof body?.error === 'string' ? body.error : `HTTP ${response.status}`};
  if (action === 'adopt') return typeof body?.record_id === 'string' && body.record_id
    ? {kind: 'done', reason: ''} : unknown;
  if (typeof body?.deleted !== 'boolean' || !Array.isArray(body.degraded)
    || body.degraded.some(value => typeof value !== 'string' || !value)) return unknown;
  if (body.degraded.length) return {kind: 'partial', reason: 'Cleanup incomplete: ' + body.degraded.join(', ')};
  if (response.status === 207) return unknown;
  return {kind: 'done', reason: body.deleted ? '' : 'Already absent'};
}
export const downloads = Object.freeze({
  '/api/v1/devices/export-csv': 'devices.csv', '/api/v1/devices/example-csv': 'devices-example.csv',
  '/api/v1/peer-policy/roles/export-csv': 'roles.csv',
});
