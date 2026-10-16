// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {position, transferPath, spokeLine, initialView, zoomView, panView, viewTransform} from '../src/swarm-map-graph.mjs';

test('first participant keeps the established origin-relative location', () => {assert.deepEqual(position(0), {x: 500, y: 150});});
test('radial layout is deterministic and separates rings', () => {
  const first = position(0), next = position(8); assert.deepEqual(position(8), next);
  assert.ok(Math.hypot(next.x - 500, next.y - 300) > Math.hypot(first.x - 500, first.y - 300));
});
test('independent two-way paths bend in opposite directions', () => {
  assert.equal(transferPath({x: 0, y: 0}, {x: 100, y: 0}), 'M28,0 Q49.5,28 71,0');
  assert.equal(transferPath({x: 100, y: 0}, {x: 0, y: 0}), 'M72,0 Q50.5,-28 29,0');
});
test('self and too-close connections never draw an arrow through a node', () => {
  assert.equal(transferPath({x: 1, y: 1}, {x: 1, y: 1}), null);
  assert.equal(transferPath({x: 0, y: 0}, {x: 59, y: 0}), null);
  assert.equal(transferPath({x: NaN, y: 0}, {x: 100, y: 0}), null);
});
test('measured origin arrows end outside the participant circle, so the arrowhead is visible', () => {
  assert.deepEqual(spokeLine({x: 500, y: 150}), {x1: 500, y1: 264, x2: 500, y2: 179});
  assert.equal(spokeLine({x: 500, y: 300}), null);
});
test('zoom bounds prevent disappearance and extreme expansion', () => {
  assert.equal(zoomView(initialView(), 0).zoom, .4); assert.equal(zoomView(initialView(), 10).zoom, 4);
  const view = initialView(); assert.equal(zoomView(view, NaN), view);
});
test('zoom about a coordinate retains its local scene point', () => {
  const view = {zoom: 2, panX: 10, panY: -10}, origin = {x: 200, y: 300}, next = zoomView(view, 3, origin);
  assert.equal((origin.x - next.panX) / next.zoom, (origin.x - view.panX) / view.zoom);
  assert.equal((origin.y - next.panY) / next.zoom, (origin.y - view.panY) / view.zoom);
});
test('screen-space pan is converted to the established SVG viewBox', () => {
  const start = {zoom: 2, panX: 7, panY: 9};
  assert.deepEqual(panView(start, {x: 50, y: 25}, {width: 500, height: 325}), {zoom: 2, panX: 107, panY: 59});
  assert.deepEqual(start, {zoom: 2, panX: 7, panY: 9}, 'No mutation of React view state');
});
test('hidden or unmeasurable graph cannot create invalid pan coordinates', () => {
  const view = initialView(); assert.equal(panView(view, {x: 1, y: 1}, {width: 0, height: 0}), view);
  assert.equal(panView(view, {x: Infinity, y: 1}, {width: 100, height: 100}), view);
});
test('fit uses a fresh stable transform without changing an older view', () => {
  const view = zoomView(initialView(), 3); assert.equal(viewTransform(initialView()), 'translate(0 0) scale(1)'); assert.equal(view.zoom, 3);
});
