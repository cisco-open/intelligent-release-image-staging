// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export function fleetCards(ov) {
  const devicesWord = ov.devices === 1 ? 'device' : 'devices';
  return [
    {label: 'Images', number: ov.images},
    {label: 'Devices', number: ov.devices},
    {label: 'Assigned', number: ov.assigned, sub: `of ${ov.devices} ${devicesWord}`},
    {label: 'Staged', number: ov.staged, sub: `of ${ov.assigned} assigned`},
    {label: 'Staging now', number: ov.staging_now, sub: `of ${ov.assigned} assigned`},
    {label: 'Waiting for heartbeat', number: ov.awaiting_heartbeat || 0, sub: `of ${ov.devices} ${devicesWord}`},
  ];
}

export function attentionCards({devices, images, unavailable}) {
  const cards = [];
  if (devices.count) cards.push({kind: 'devices', level: devices.level, count: devices.count,
    label: devices.count === 1 ? 'device needs attention' : 'devices need attention', hint: 'View filtered devices'});
  if (images.count) cards.push({kind: 'images', level: images.level, count: images.count,
    label: images.count === 1 ? 'image quarantined' : 'images quarantined', hint: 'View filtered images'});
  if (unavailable) cards.push({kind: 'unavailable', level: 'inactive', label: 'Fleet status unavailable',
    hint: 'Device or image data could not be loaded; retrying.'});
  else if (!cards.length) cards.push({kind: 'clear', level: 'positive', label: 'All clear',
    hint: 'No devices or images need attention.'});
  return cards;
}

export function rolloutPercent(row) {
  const value = row.assigned ? Math.round(row.staged / row.assigned * 100) : 0;
  return Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
}
