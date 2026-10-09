// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {rotationFamilies} from '../src/worker-lifecycle-model.mjs';
import {maintenanceFamilies} from '../src/key-maintenance-model.mjs';
export const id = '11111111-1111-4111-8111-111111111111', other = '22222222-2222-4222-8222-222222222222';
export const now = 1790160000, hash = 'ab'.repeat(32);
export const csr = '-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n';
export const certificate = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
export const root = value => 'ssh-ed25519 ' + btoa('\0\0\0\x0bssh-ed25519\0\0\0\x20' + value.repeat(32)) + '\n';
export const roots = {'root-a': root('a'), 'root-b': root('b')};
export const keylist = (signer = 'root-a') => 'IRIS-KEYLIST/1\n' + btoa(JSON.stringify({issued_at: now, keylist_seq: 1, krl_sha256: hash, signer_root_id: signer, v: 1})) + '\n\n';
export const signed = (signer = 'root-a') => keylist(signer) + btoa('-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n') + '\n';
export const idle = family => ({family, state: 'idle', request_id: null, created_at: null, names: [], mode: null, csr: null,
  certificate: null, fingerprint_sha256: null, roots: {}, online_public_key: null, keylist_payload: null, keylist_signer: null,
  requires_reonboarding: true, requires_package_rebuild: family === 'instruction-roots', attested_root_ids: [], attestation_request_id: null, attestation_root_id: null});
export const trust = () => ({items: ['device-tls', 'peer-ca', 'instruction-roots'].map(idle), drain: {ready: true, blocked_device_ids: [], removed_device_ids: []}});
export const prepared = (family = 'device-tls', state = 'approved', mode = 'ca') => ({...idle(family), request_id: id, created_at: now, state,
  names: family === 'device-tls' ? ['distribution.example'] : [], mode: family === 'device-tls' ? mode : null, csr: family === 'device-tls' ? csr : null,
  certificate: state === 'awaiting-approval' ? null : family === 'instruction-roots' ? 'ssh-ed25519-cert-v01@openssh.com AAAA\n' : certificate,
  fingerprint_sha256: state === 'awaiting-approval' ? null : hash,
  ...(family === 'instruction-roots' ? {roots, online_public_key: root('c'), keylist_payload: keylist(), keylist_signer: 'root-a'} : {})});
export const rotation = () => ({available: true, target: 'single-docker', can_rotate: true, families: [...rotationFamilies], jobs: [], note: 'Independent recovery access ready.'});
export const backups = () => ({available: true, target: 'single-docker', storage: 'operator-configured-host-directories', can_verify: true, can_extract: true,
  can_restore: true, restore_scope: 'same-deployment-same-security-generation', jobs: [], note: 'Keep encrypted copies off this host.'});
export const maintenance = () => ({schema: 1, revision: 0, observed_at: null, worker: 'not-observed', policies: [], jobs: [],
  families: Object.entries(maintenanceFamilies).map(([id, action]) => ({id, action, label: id === 'browser-tls' ? 'Console browser TLS' : id,
    requirement: action === 'review' ? 'Operator certificate approval' : 'Offline approval or device verification'}))});
export const policy = () => ({id, family: 'browser-tls', target: 'deployment', enabled: false, next_at: now + 3600, interval_days: 14, window_minutes: 30});
export const job = (action = 'rotate', state = 'running') => ({id, action, state, started_at: now, detail: 'Fixture operation', proof: null,
  ...(action === 'rotate' ? {family: 'management-tls'} : {backup_id: id})});
export const maintenanceJob = (family = 'browser-tls', state = 'review-required') => ({id: other, policy_id: id, family, target: 'deployment', state,
  due_at: now, updated_at: now, detail: 'Fixture scheduled operation', before: null, after: null});
export const response = (body, status = 200) => ({status, json: async () => structuredClone(body)});
export const file = text => ({size: Buffer.byteLength(text), text: async () => text});
export const deferred = () => {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};};
