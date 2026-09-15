// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {distributionAllowed, enforcementLabel, roleConnections} from '../src/policy-model.mjs';

test('role sharing requires both sides, with implicit same-role access', () => {
  const roles = {
    branch: {restricted: true, peers: ['hub']},
    hub: {restricted: true, peers: ['branch', 'isolated']},
    isolated: {restricted: true, peers: []},
    open: {restricted: false, peers: []},
    other: {restricted: false, peers: []},
  };
  assert.deepEqual(roleConnections(roles, 'branch'), ['branch', 'hub']);
  assert.deepEqual(roleConnections(roles, 'hub'), ['branch', 'hub']);
  assert.deepEqual(roleConnections(roles, 'isolated'), ['isolated']);
  assert.deepEqual(roleConnections(roles, 'open'), ['open', 'other']);
  assert.deepEqual(roleConnections(roles, 'missing'), []);
});

test('unrestricted role ignores origin false exactly as the server does', () => {
  assert.equal(distributionAllowed({restricted: false, origin: false}), true);
  assert.equal(distributionAllowed({restricted: true, origin: false}), false);
  assert.equal(distributionAllowed({restricted: true}), true);
});

test('unavailable and stale enforcement never look enforced', () => {
  assert.equal(enforcementLabel({}, true), 'Unavailable');
  assert.equal(enforcementLabel({enforcement: {state: 'enforced', stale: false}}, false), 'Unavailable');
  assert.equal(enforcementLabel({enforcement: {state: 'enforced', stale: true}}, true), 'Not current');
  assert.equal(enforcementLabel({enforcement: {state: 'enforced'}}, true), 'Not current');
  assert.equal(enforcementLabel({enforcement: {state: 'enforced', stale: false}}, true), 'Enforced');
  assert.equal(enforcementLabel({enforcement: {state: 'degraded', stale: false}}, true), 'Partly enforced');
});
