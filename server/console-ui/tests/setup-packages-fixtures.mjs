// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const digest = 'ab'.repeat(32);
export const reference = Array(32).fill('AB').join(':');
export function setupFixture() {
  return {admin: {state: 'ok', username: 'operator'}, telemetry: {state: 'unset', source: 'env', endpoint: '', enabled: false},
    packages: {state: 'ok', reference_fingerprint: reference, remedy: 'tools/provision-iox-packages.sh', items: ['iris-amd64.tar', 'iris-arm64.tar', 'iris-xr.rpm'].map(name => ({name, state: 'ok', fingerprint: null, built_at: 1790000000,
      detail: 'Readable package bytes match the adjacent build-provenance manifest; package contents and native signatures are not inspected, and the sidecar is not authenticated here.',
      remedy: name.endsWith('.rpm') ? 'tools/build-xr-package.sh --out artifacts/' : 'tools/provision-iox-packages.sh',
      provenance: {canonical_index_digest: 'sha256:' + digest, canonical_archive_sha256: digest, canonical_source_sha256: digest}})).concat([
        {name: 'iris-agent.tgz', state: 'ok', fingerprint: null, built_at: 1790000000, provenance: null, reason: 'ready', detail: 'The served bundle, raw digest, bootstrap and device instruction trust match the latest successful provisioning from a checksum- and architecture-verified aria2c.', remedy: 'Rebuild the server image and restart after correcting the provisioning error.'}])}, image_verification: {state: 'unset'}};
}
export function verificationFixture(mode = 'off') {
  return {mode, hour_utc: 0, last_run: {at: null, source: null, outcome: null, matched: null, mismatched: null, not_in_feed: null}};
}
export const response = (value, status = 200) => ({status, ok: status >= 200 && status < 300, json: async () => structuredClone(value)});
export const deferred = () => {let resolve, reject; const promise = new Promise((yes, no) => {resolve = yes; reject = no;}); return {promise, resolve, reject};};
