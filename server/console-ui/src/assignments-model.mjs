// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export function checkedIds(ids, limit = 10000) {
  if (!Array.isArray(ids) || ids.length > limit || ids.some(id => typeof id !== 'string' || !id)
    || new Set(ids).size !== ids.length) throw new Error('Invalid ID list');
  return ids.slice();
}
export function assignedIds(row) {
  if (row.assigned_image_ids != null) return checkedIds(row.assigned_image_ids, 10);
  return row.assigned_image_id == null || row.assigned_image_id === '' ? [] : checkedIds([row.assigned_image_id], 10);
}
export const sameIds = (a, b) => a.length === b.length && a.every((id, index) => id === b[index]);
export function assignmentPreview(ids, records) {
  const expect = new Map(ids.map(id => {
    if (!records.has(id)) throw new Error(`Device ${id} was not found. Refresh Inventory and review the selection.`);
    return [id, assignedIds(records.get(id))];
  }));
  const sets = [...expect.values()];
  const chosen = sets.reduce((a, b) => a.filter(id => b.includes(id)));
  return {expect, chosen, different: sets.some(set => !sameIds(set, sets[0]))};
}
export function checkedCatalog(body) {
  if (!Array.isArray(body?.images)) throw new Error('Image catalog unavailable.');
  checkedIds(body.images.map(row => row?.id));
  if (body.images.some(row => row.filename != null && typeof row.filename !== 'string')) throw new Error('Invalid image catalog.');
  return body.images.map(row => ({id: row.id, filename: row.filename || '', quarantined: !!row.quarantined}));
}
export const imageLabel = row => row.filename && row.filename !== row.id ? `${row.id} — ${row.filename}` : row.id;
export function pickerRows(state) {
  const catalog = new Map(state.images.map(row => [row.id, row]));
  return state.order.map(id => {
    const image = catalog.get(id), checked = state.chosen.includes(id), unknown = !image;
    const retained = unknown && state.original?.includes(id);
    return {id, label: imageLabel(image || {id}), checked, unknown, retained, quarantined: !!image?.quarantined,
      disabled: state.busy || !state.ready || !state.imagesOk || retained || (!checked && (unknown || image?.quarantined || state.chosen.length >= 10))};
  });
}
export function removalConfirmation(state) {
  if (!state.chosen.length) return `Unassign all images from ${state.ids.length === 1 ? state.ids[0] : state.ids.length + ' device(s)'}?`;
  if (!state.row && [...state.expect.values()].some(set => set.some(id => !state.chosen.includes(id)))) {
    return 'Replace image assignments?\n\nAll reviewed devices will use these ' + state.chosen.length
      + ' images. Existing assignments not selected here will be removed.';
  }
  return '';
}
export function assignmentResult(response, body, chosen) {
  if (response.status >= 500) return {kind: 'unknown', reason: `HTTP ${response.status}; review before trying again`};
  if (!response.ok) return {kind: response.status === 409 && body?.error === 'assignment_conflict' ? 'conflict' : 'refused',
    reason: typeof body?.error === 'string' ? body.error : `HTTP ${response.status}`};
  try {
    if (body?.ok !== true || !sameIds(checkedIds(body.assigned_image_ids, 10), chosen)) throw new Error('Unknown');
    return {kind: 'saved', reason: ''};
  } catch { return {kind: 'unknown', reason: 'Response incomplete; review before trying again'}; }
}
export function bulkCredentialResult(response, body, ids) {
  if (response.status >= 500) return {applied: null, failed: [], unknown: true};
  if (!response.ok) return {applied: 0, failed: ids.map(id => [id, typeof body?.error === 'string' ? body.error : `HTTP ${response.status}`]), unknown: false};
  const failed = body?.failed;
  if (body?.ok !== true || !Number.isSafeInteger(body.applied) || body.applied < 0 || !failed || typeof failed !== 'object' || Array.isArray(failed)
    || Object.keys(failed).some(id => !ids.includes(id) || typeof failed[id] !== 'string' || !failed[id])
    || body.applied + Object.keys(failed).length !== ids.length) return {applied: null, failed: [], unknown: true};
  return {applied: body.applied, failed: Object.entries(failed), unknown: false};
}
