// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// These are image-peer entries, not a count of unique devices. Attribution
// comes from authenticated tracker principals, never from device_ip matches.
export function swarmSummary(value) {
  if (!object(value) || value.error || !Array.isArray(value.images)
    || !Number.isFinite(value.now) || value.now < 0) return null;
  let entries = 0, legacy = 0;
  const hashes = new Set();
  for (const image of value.images) {
    if (!object(image) || typeof image.info_hash !== 'string' || !/^[0-9a-f]{40}$/.test(image.info_hash)
      || hashes.has(image.info_hash) || !Array.isArray(image.peers)) return null;
    hashes.add(image.info_hash);
    for (const peer of image.peers) {
      if (!object(peer) || !object(peer.tracker)) return null;
      const tracker = peer.tracker;
      if (!['device', 'service', 'legacy'].includes(tracker.principal_type)) return null;
      if (tracker.principal_type !== 'legacy' && (typeof tracker.principal_id !== 'string' || !tracker.principal_id)) return null;
      if (tracker.principal_type === 'legacy') legacy++;
      entries++;
    }
  }
  // The Console requests the complete snapshot. Never describe a partial page
  // as the full swarm, even if a proxy accidentally returns a paginated body.
  if ('peers_offset' in value && value.peers_offset !== 0) return null;
  if ('peers_total' in value && value.peers_total !== entries) return null;
  const seederUnavailable = value.server?.server_observation?.unavailable === true;
  return {entries, legacy, seederUnavailable};
}
