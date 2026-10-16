// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export function imageVerdicts(verification, quarantined) {
  const state = verification?.state;
  let verdict;
  if (!state) verdict = {level: 'inactive', label: 'Not checked'};
  else if (state === 'verified') verdict = {level: 'positive', label: 'Verified'};
  else if (state === 'mismatch') verdict = {level: 'negative', label: quarantined ? 'Mismatch — quarantined' : 'Mismatch — released'};
  else if (state === 'not_in_feed') verdict = {level: 'inactive', label: "Not in Cisco's feed"};
  else verdict = {level: 'inactive', label: 'Unknown verification state'};
  return verification?.deferral ? [verdict, {level: 'warning', label: 'Deferred by Cisco'}] : [verdict];
}

export function formatSize(value) {
  if (value === null || value === undefined) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let number = Number(value), unit = 0;
  while (number >= 1024 && unit < units.length - 1) { number /= 1024; unit++; }
  return `${number.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export const formatDate = value => value ? new Date(value * 1000).toLocaleString() : '';

export function verificationDetail(verification) {
  if (!verification?.checked_at) return 'Never checked against the Cisco Bulk Hash feed.';
  return `Checked ${formatDate(verification.checked_at)} (source: ${verification.source || 'unknown'})`
    + (verification.feed_published_at ? `; feed published ${formatDate(verification.feed_published_at)}` : '');
}

export function publishedJobText(job) {
  const text = `Published ${job.image_id || ''}`;
  const verification = job.verification;
  if (!verification) return `${text} ✓`;
  if (verification.outcome !== 'ok') return `${text}; Cisco hash verification incomplete: ${verification.detail || 'unknown failure'}`;
  if (verification.image_state === 'verified') return `${text} · verified against Cisco Bulk Hash ✓`;
  if (verification.image_state === 'mismatch') return `${text} · Cisco hash mismatch — quarantined`;
  if (verification.image_state === 'not_in_feed') return `${text} · not found in Cisco Bulk Hash feed`;
  return `${text} · Cisco hash verdict unavailable`;
}
