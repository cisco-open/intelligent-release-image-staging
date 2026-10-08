// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {attentionCards, fleetCards, rolloutPercent} from '../src/overview-model.mjs';

test('fleet totals name their denominators and preserve singular/plural', () => {
  const cards = fleetCards({images: 2, devices: 5, assigned: 3, staged: 1, staging_now: 2, awaiting_heartbeat: 1});
  assert.deepEqual(cards.map(card => [card.label, card.number, card.sub]), [
    ['Images', 2, undefined], ['Devices', 5, undefined], ['Assigned', 3, 'of 5 devices'],
    ['Staged', 1, 'of 3 assigned'], ['Staging now', 2, 'of 3 assigned'], ['Waiting for heartbeat', 1, 'of 5 devices'],
  ]);
  assert.equal(fleetCards({devices: 1})[2].sub, 'of 1 device');
  assert.equal(fleetCards({devices: 1})[5].number, 0);
});

test('unavailable is neutral and never all-clear, even alongside a known problem', () => {
  for (const devices of [{count: 0, level: null}, {count: 2, level: 'severe'}]) {
    const cards = attentionCards({devices, images: {count: 0}, unavailable: true});
    assert.ok(cards.every(card => card.level !== 'positive'));
    assert.deepEqual(cards.at(-1), {kind: 'unavailable', level: 'inactive', label: 'Fleet status unavailable',
      hint: 'Device or image data could not be loaded; retrying.'});
    assert.equal(cards.length, devices.count ? 2 : 1);
  }
});

test('confirmed clean and both actionable attention groups remain distinct', () => {
  assert.equal(attentionCards({devices: {count: 0}, images: {count: 0}, unavailable: false})[0].kind, 'clear');
  assert.deepEqual(attentionCards({devices: {count: 1, level: 'warning'}, images: {count: 3, level: 'negative'}, unavailable: false}), [
    {kind: 'devices', count: 1, level: 'warning', label: 'device needs attention', hint: 'View filtered devices'},
    {kind: 'images', count: 3, level: 'negative', label: 'images quarantined', hint: 'View filtered images'},
  ]);
});

test('rollout percentage stays within the progressbar accessibility bounds', () => {
  for (const [assigned, staged, expected] of [[0, 0, 0], [3, 1, 33], [3, 3, 100], [3, 4, 100], [3, -1, 0], [3, NaN, 0]]) {
    assert.equal(rolloutPercent({assigned, staged}), expected);
  }
});
