// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {certificateGuidance, certificateState, signingHealth, signerGuidance, browserGuidance, deploymentGuidance, trustState} from '../src/certificate-guidance.mjs';
import {familyLabels} from '../src/worker-lifecycle-model.mjs';

test('certificate purposes distinguish browser-independent connection and approval boundaries', () => {
  const guidance = id => certificateGuidance({id, label: id, impact: 'Native public impact'});
  assert.match(guidance('device-tls').next, /Remove IRIS deployments.*onboard/);
  assert.match(guidance('management-tls').purpose, /private connection between the Console and IRIS server/);
  assert.match(guidance('peer-ca').next, /Devices renew their own peer certificates/);
  assert.match(guidance('instruction-signer').next, /keep the current key.*holder must approve/);
  assert.match(guidance('online-key').next, /routine expiry.*key itself/);
  assert.match(guidance('root-root-a').next, /signed confirmation.*new packages.*re-onboarding/);
  assert.equal(guidance('unknown-identity').purpose, 'Native public impact');
  assert.match(guidance('__proto__').next, /Review this identity/);
});
test('file validity does not claim live service trust or private key readiness', () => {
  for (const state of ['unknown', 'not-yet-valid', 'expired', 'signing-refused', 'renewal-due', 'within-validity', 'public-key-present']) {
    assert.equal(typeof certificateState(state), 'string');
    assert.doesNotMatch(certificateState(state), /trusted|healthy|ready/i);
  }
  assert.equal(certificateState('within-validity'), 'Within validity dates');
  assert.equal(certificateState('public-key-present'), 'Public key found');
  assert.match(signingHealth('ready'), /recorded checks/);
  assert.match(signingHealth('signing_refused'), /stopped.*Renew/);
  assert.match(signingHealth('keylist_missing'), /holder.*approve/);
  assert.match(signingHealth('phase0'), /not initialized/);
});
test('root signing labels name the root without assuming private key storage', () => {
  const row = {id: 'root-root-a', label: 'Offline root root-a', impact: 'Public trust only.'};
  assert.equal(certificateGuidance(row).title, 'Root signing key: root-a');
  assert.equal(row.label, 'Offline root root-a', 'The native inventory is unchanged');
  const untrusted = {id: 'root-<img src=x onerror=alert(1)>', label: 'Offline root ignored'};
  assert.equal(certificateGuidance(untrusted).title, 'Root signing key: <img src=x onerror=alert(1)>');
});
test('each signing state gives an action without claiming fleet adoption', () => {
  for (const state of ['idle', 'awaiting-approval', 'committing', 'retirement-pending', 'retiring', 'completed', 'cancelled']) {
    const guide = signerGuidance(state);
    assert.equal(guide.length, 2); assert.ok(guide.every(value => typeof value === 'string' && value.length > 15));
  }
  assert.match(signerGuidance('awaiting-approval')[1], /current key remains active/);
  assert.match(signerGuidance('committing')[1], /Refresh.*diagnostics/);
  assert.match(signerGuidance('retirement-pending')[1], /holder must approve/);
  assert.match(signerGuidance('completed')[1], /Verify.*on your devices/);
  assert.doesNotMatch(signerGuidance('completed').join(' '), /devices.*accepted|fleet.*complete/i);
});
test('browser guidance separates approval, saved files and live connection verification', () => {
  for (const state of ['idle', 'awaiting-approval', 'approved', 'committing', 'published', 'cancelled']) assert.equal(browserGuidance(state).length, 2);
  assert.match(browserGuidance('awaiting-approval')[1], /certificate authority/);
  assert.match(browserGuidance('approved')[1], /current browser certificate is still active/);
  assert.match(browserGuidance('committing')[1], /Recover.*trusted browser connection/);
  assert.match(browserGuidance('published')[1], /every Console.*alone do not prove/);
});
test('deployment choices explain every offered family and preserve maintenance requirements', () => {
  assert.deepEqual(Object.keys(deploymentGuidance).sort(), Object.keys(familyLabels).filter(id => id !== 'age-recovery').sort());
  for (const id of ['device-tls', 'peer-ca', 'instruction-roots']) assert.match(deploymentGuidance[id][1], /Remove.*deployments/);
  assert.match(deploymentGuidance['instruction-roots'][1], /holders.*public keys.*worker rebuilds packages/);
  assert.match(deploymentGuidance['age-identity'][1], /older backups.*original keys/);
  assert.match(trustState('published'), /verify device adoption/);
});
test('unrecognized and inherited states never become successful display states', () => {
  for (const state of [null, undefined, '', 'future', '__proto__', 'constructor', 'toString']) {
    assert.match(certificateState(state), /unavailable/);
    assert.match(signingHealth(state), /unavailable/);
    assert.match(signerGuidance(state)[0], /unavailable/);
    assert.match(browserGuidance(state)[0], /unavailable/);
    assert.match(trustState(state), /unavailable/);
  }
});
