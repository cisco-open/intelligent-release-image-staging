// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const setupURL = '/api/v1/settings/setup-status';
export const verificationURL = '/api/v1/settings/image-verification';
export const setupSteps = [
  {id: 'telemetry', key: 'telemetry', label: 'Telemetry destination', next: 'Continue to device packages', skip: 'Skip telemetry'},
  {id: 'packages', key: 'packages', label: 'Device packages', next: 'Continue to image verification', skip: 'Skip package review'},
  {id: 'imageverification', key: 'image_verification', label: 'Image verification', next: 'Open dashboard', skip: 'Skip image verification'},
];
const packageNames = ['iris-amd64.tar', 'iris-arm64.tar', 'iris-xr.rpm', 'iris-agent.tgz'];
const rank = {ok: 0, absent: 1, unknown: 2, stale: 3};
const sha = value => typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value);
const fingerprint = value => value === null || typeof value === 'string' && /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 4096) => typeof value === 'string' && value.length <= max;
const timestamp = value => value === null || Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000;
function wrapperProvenance(value) {
  if (!object(value) || typeof value.canonical_index_digest !== 'string' || value.canonical_index_digest.length !== 71 || !/^sha256:[a-f0-9]{64}$/.test(value.canonical_index_digest) || !sha(value.canonical_archive_sha256)) return null;
  const fields = ['canonical_index_digest', 'canonical_archive_sha256'];
  if (value.format === 'iris-device-wrapper-v2') {
    if (!sha(value.canonical_neutral_source_sha256) || !sha(value.canonical_finalization_sha256)) return null;
    fields.push('format', 'canonical_neutral_source_sha256', 'canonical_finalization_sha256');
  } else {
    if (Object.hasOwn(value, 'format') || !sha(value.canonical_source_sha256)) return null;
    fields.push('canonical_source_sha256');
  }
  if (Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) return null;
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}
export const packageReasons = {
  'served-vs-distributed-mismatch': "The certificate served by this server differs from the copy sent during onboarding. Fix the certificate copies before onboarding; rebuilding packages alone will not resolve this.",
  'distributed-cert-unavailable': 'The certificate copy sent during onboarding could not be read. Onboarding readiness cannot be confirmed.',
  'served-cert-unavailable': 'The certificate served by this server could not be read. Onboarding readiness cannot be confirmed.',
};
function packageItem(row) {
  if (!object(row) || !packageNames.includes(row.name) || !Object.hasOwn(rank, row.state) || row.fingerprint !== null || !timestamp(row.built_at) || !text(row.remedy, 1024) || !row.remedy || !(row.reason === undefined || text(row.reason, 128)) || !(row.detail === undefined || text(row.detail))) return null;
  let provenance = null;
  if (row.provenance !== null) {
    provenance = wrapperProvenance(row.provenance);
    if (!provenance) return null;
  }
  if (row.state === 'ok' && (row.built_at === null || !row.detail || (row.name === 'iris-agent.tgz' ? provenance !== null || row.reason !== 'ready' : !provenance))) return null;
  if (row.state !== 'ok' && provenance !== null) return null;
  return {name: row.name, state: row.state, fingerprint: null, built_at: row.built_at, remedy: row.remedy, provenance, reason: row.reason || '', detail: row.detail || ''};
}
export function setupStatus(value) {
  if (!object(value)) return null;
  const {admin, telemetry, packages, image_verification: verification} = value;
  if (!object(admin) || !['ok', 'unknown'].includes(admin.state) || !text(admin.username, 256) || (admin.state === 'ok') !== Boolean(admin.username)) return null;
  if (!object(telemetry) || !['ok', 'unset'].includes(telemetry.state) || !['env', 'override'].includes(telemetry.source) || typeof telemetry.enabled !== 'boolean' || !text(telemetry.endpoint) || (telemetry.state === 'ok') !== (telemetry.enabled && Boolean(telemetry.endpoint))) return null;
  if (!object(verification) || !['ok', 'unset'].includes(verification.state)) return null;
  if (!object(packages) || !Object.hasOwn(rank, packages.state) || !fingerprint(packages.reference_fingerprint) || !text(packages.remedy, 1024) || !Array.isArray(packages.items) || packages.items.length !== 4 || !(packages.reason === undefined || Object.hasOwn(packageReasons, packages.reason))) return null;
  const items = packages.items.map(packageItem);
  if (items.some(row => !row) || new Set(items.map(row => row.name)).size !== items.length || packageNames.some(name => !items.some(row => row.name === name))) return null;
  const worst = items.reduce((state, row) => rank[row.state] > rank[state] ? row.state : state, 'ok');
  const expected = packages.reason === 'served-vs-distributed-mismatch' ? 'unknown' : packages.reason ? (rank[worst] < rank.unknown ? 'unknown' : worst) : worst;
  if (packages.state !== expected || (!packages.reason && packages.reference_fingerprint === null) || (packages.reason === 'served-cert-unavailable' && packages.reference_fingerprint !== null) || (packages.reason && packages.reason !== 'served-cert-unavailable' && packages.reference_fingerprint === null)) return null;
  return {admin: {state: admin.state, username: admin.username}, telemetry: {state: telemetry.state, source: telemetry.source, endpoint: telemetry.endpoint, enabled: telemetry.enabled},
    packages: {state: packages.state, reference_fingerprint: packages.reference_fingerprint, remedy: packages.remedy, reason: packages.reason || '', items}, image_verification: {state: verification.state}};
}
export function setupChip(key, state = 'unknown', configured = null) {
  if (key === 'image_verification' && state === 'unset' && configured === true) return {label: 'Configured — no successful run yet', level: 'warning'};
  const labels = {ok: 'Done', unset: 'Not configured', stale: 'Needs rebuild', absent: 'Not built', unknown: 'Cannot determine'};
  const levels = {ok: 'positive', unset: 'warning', stale: 'warning', absent: 'inactive', unknown: 'inactive'};
  const level = state === 'unset' && ['telemetry', 'image_verification'].includes(key) ? 'info' : levels[state] || 'inactive';
  return {label: labels[state] || labels.unknown, level};
}
export function packageRemedy(pkg) {
  if (!pkg || pkg.state === 'ok') return '';
  const parts = packageReasons[pkg.reason] ? [packageReasons[pkg.reason]] : [];
  if (pkg.reason !== 'served-vs-distributed-mismatch') {
    const remedies = [...new Set(pkg.items.filter(row => row.state !== 'ok').map(row => row.remedy))];
    if (remedies.length) parts.push('On the build host, repair or rebuild the affected packages, then re-check: ' + remedies.join('; '));
  }
  return parts.join(' ');
}
export function telemetryNote(item) {
  if (!item) return '';
  const scope = item.source === 'override' ? 'console override' : 'deployment default';
  return item.state === 'ok' ? `Exporting to ${item.endpoint} (${scope}).` : !item.enabled ? `Export is disabled (${scope}).` : `No endpoint is set (${scope}).`;
}
export function incompleteCount(status) {
  if (!status) return 0;
  // Optional telemetry/verification remain visible in their cards; a nudge
  // must not call an intentionally disabled export an unfinished install.
  return ['unknown', 'stale'].includes(status.packages.state) ? 1 : 0;
}
