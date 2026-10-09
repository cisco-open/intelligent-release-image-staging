// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Geometry only. React owns the graph nodes and semantic interaction state;
// this module cannot fetch, select a device or change a reporting policy.
export const graphCenter = {x: 500, y: 300};
export function position(index, center = graphCenter) {
  const ring = Math.floor(Math.sqrt(index / 8)), start = ring * ring * 8;
  const slots = Math.max(8, (ring * 2 + 1) * 8), angle = -Math.PI / 2 + (index - start) * 2 * Math.PI / slots, radius = 150 + ring * 95;
  return {x: center.x + radius * Math.cos(angle), y: center.y + radius * Math.sin(angle)};
}
export function transferPath(source, target) {
  const dx = target.x - source.x, dy = target.y - source.y, length = Math.hypot(dx, dy);
  if (!Number.isFinite(length) || length < 60) return null;
  const ux = dx / length, uy = dy / length, sx = source.x + ux * 28, sy = source.y + uy * 28, tx = target.x - ux * 29, ty = target.y - uy * 29;
  return `M${sx},${sy} Q${(sx + tx) / 2 - uy * 28},${(sy + ty) / 2 + ux * 28} ${tx},${ty}`;
}
export function spokeLine(target, source = graphCenter) {
  const dx = target.x - source.x, dy = target.y - source.y, length = Math.hypot(dx, dy);
  if (!Number.isFinite(length) || length < 66) return null;
  const ux = dx / length, uy = dy / length;
  return {x1: source.x + ux * 36, y1: source.y + uy * 36, x2: target.x - ux * 29, y2: target.y - uy * 29};
}
export const initialView = () => ({zoom: 1, panX: 0, panY: 0});
export function zoomView(view, requested, origin = null) {
  if (!Number.isFinite(requested)) return view;
  const zoom = Math.min(4, Math.max(.4, requested));
  return {zoom, panX: origin ? origin.x - (origin.x - view.panX) * zoom / view.zoom : view.panX,
    panY: origin ? origin.y - (origin.y - view.panY) * zoom / view.zoom : view.panY};
}
export function panView(view, offset, size) {
  if (![offset.x, offset.y, size.width, size.height].every(Number.isFinite) || size.width <= 0 || size.height <= 0) return view;
  return {...view, panX: view.panX + offset.x / size.width * 1000, panY: view.panY + offset.y / size.height * 650};
}
export const viewTransform = view => `translate(${view.panX} ${view.panY}) scale(${view.zoom})`;
