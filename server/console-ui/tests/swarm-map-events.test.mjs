// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {eventsLink} from '../src/swarm-map-model.mjs';
import {SwarmMapController} from '../src/swarm-map-controller.mjs';

test('Events templates encode every device and address substitution as data', () => {
  assert.equal(eventsLink('https://events.example/device/{device_id}?ip={ip}&device={device_id}',
    {device_id: 'edge/$&?#<tag>', ip: '2001:db8::1'}),
  'https://events.example/device/edge%2F%24%26%3F%23%3Ctag%3E?ip=2001%3Adb8%3A%3A1&device=edge%2F%24%26%3F%23%3Ctag%3E');
  assert.equal(eventsLink('http://events.example/?ip={ip}&device={device_id}', {ip: '192.0.2.1'}),
    'http://events.example/?ip=192.0.2.1&device=');
});

test('Events links reject absent, malformed, credential-bearing and non-HTTP(S) templates', () => {
  for (const value of [null, {}, '', 'javascript:alert(1)', 'data:text/html,hello', '//events.example/', '/events',
    'https://', 'https://operator:password@events.example/', 'https://events.example/\n{ip}', ' https://events.example/']) {
    assert.equal(eventsLink(value, {device_id: 'edge'}), null, String(value));
  }
  assert.equal(eventsLink('HTTPS://events.example/', {}), 'https://events.example/');
});

test('controller retains only a string Events template in the consumed config', () => {
  assert.equal(new SwarmMapController({eventsUrlTemplate: 'https://events.example/{ip}'}).config.eventsUrlTemplate, 'https://events.example/{ip}');
  assert.equal(new SwarmMapController({eventsUrlTemplate: {url: 'https://events.example/'}}).config.eventsUrlTemplate, '');
});
