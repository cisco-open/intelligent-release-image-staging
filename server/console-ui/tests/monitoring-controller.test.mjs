// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import {MonitoringController} from '../src/monitoring-controller.mjs';
import {auditMessage, bounds, bucketCount, clampSelection, deploymentRows, panSelection,
  queries, validRows} from '../src/monitoring-model.mjs';

const response = (data, status = 200) => ({ok: status === 200, status, json: async () => data, text: async () => data});
const pending = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; };
const event = (ts, detail = '') => ({ts, event: 'login', category: 'auth', actor: 'console:operator', result: 'ok', detail});
const histogram = {now: 1000000, bucket_seconds: 3600, buckets: [{start: 996400, count: 1}]};

function fixture(t) {
  const controller = new MonitoringController({now: () => 1000000}), calls = [];
  const services = {fetch: async (url, options) => {
    calls.push([url, options]);
    return response(url.includes('/histogram?') ? histogram
      : url.includes('/deploy-logs') ? {logs: []} : {events: [event(999990)]});
  }};
  controller.connect(services);
  t.after(() => controller.dispose());
  return {controller, services, calls};
}

test('selection clamps both directions and panning retains width at boundaries', () => {
  const outer = {since: 1000, until: 2000};
  assert.deepEqual(clampSelection(1900, 1300, outer), {start: 1300, end: 1900});
  assert.deepEqual(clampSelection(3000, 4000, outer), {start: 1940, end: 2000});
  assert.deepEqual(clampSelection(0, 10, outer), {start: 1000, end: 1060});
  assert.deepEqual(panSelection({start: 1300, end: 1700}, 800, outer), {start: 1600, end: 2000});
  assert.deepEqual(panSelection({start: 1300, end: 1700}, -800, outer), {start: 1000, end: 1400});
  assert.deepEqual([bucketCount(60), bucketCount(3600), bucketCount(86400)], [1, 60, 90]);
  assert.deepEqual(bounds('all', 10000000), {since: 2224000, until: 10000000});
});

test('table, histogram and older-page requests keep identical time/category bounds', () => {
  const state = {range: '24h', selection: {start: 100, end: 3700}, category: 'onboard'};
  const urls = queries('audit', state, 9999);
  assert.equal(urls.list, '/api/v1/audit?limit=200&after_ts=100&before_ts=3700&category=onboard');
  assert.equal(urls.histogram, '/api/v1/audit/histogram?since_ts=100&until_ts=3700&buckets=60&category=onboard');
  assert.equal(queries('audit', state, 9999, 1000).list,
    '/api/v1/audit?limit=200&after_ts=100&before_ts=1000&category=onboard');
  assert.equal(queries('deploylogs', {...state, selection: null}, 1000000).list,
    '/api/v1/deploy-logs?after_ts=913600');
});

test('audit messages retain broker fallbacks, plain text and unknown event names', () => {
  const record = auditMessage({event: 'refresh', device_id: '<device>', secret_name: 'catalog', old_id: 'old', new_id: 'new'});
  assert.equal(record.category, 'token');
  assert.equal(record.actor, '<device>');
  assert.equal(record.message, 'rotated the catalog token of <device>');
  assert.equal(record.detail, 'catalog old -> new');
  assert.equal(auditMessage({event: 'undeploy_finished', result: 'ok', target: 'router', category: 'onboard'}).categoryLabel, 'deployment');
  assert.equal(auditMessage({event: 'constructor', target: '<script>'}).message, 'constructor <script>');
  assert.equal(validRows([{ts: 1, event: {unsafe: true}}], 'audit'), false);
  assert.equal(validRows([{finished_at: 1, file: 'x', rc: {unsafe: true}}], 'deploylogs'), false);
});

test('deployment filters cover action, result, device and zero return code, paging stays bounded', () => {
  const rows = Array.from({length: 61}, (_, index) => ({file: `${index}.log`, device_id: `router-${index}`, action: 'onboard', state: 'done', rc: 0}));
  const state = {rows, page: 2, query: '', action: '', result: ''};
  assert.equal(deploymentRows(state).rows.length, 11);
  assert.equal(deploymentRows({...state, query: 'rc=0'}).total, 61);
  assert.equal(deploymentRows({...state, query: 'ROUTER-60'}).page, 0);
  assert.equal(deploymentRows({...state, action: 'undeploy'}).total, 0);
  assert.equal(deploymentRows({...state, result: 'error'}).pages, 1);
});

test('newer query owns both rows and histogram even when an old transport ignores abort', async t => {
  const {controller, services, calls} = fixture(t), old = pending();
  const original = services.fetch;
  services.fetch = async (url, options) => {
    if (!url.includes('category=')) { calls.push([url, options]); return old.promise; }
    return original(url, options);
  };
  const first = controller.refresh();
  await controller.setCategory('device');
  assert.equal(calls[0][1].signal.aborted, true);
  old.resolve(response({events: [event(1)], ...histogram}));
  await first;
  assert.equal(controller.snapshot().audit.category, 'device');
  assert.equal(controller.snapshot().audit.rows[0].ts, 999990);
});

test('failed or malformed reads retain known evidence with an explicit error; new query does not relabel old rows', async t => {
  const {controller, services} = fixture(t);
  await controller.refresh();
  for (const data of [{events: [null]}, {events: [{ts: 1, event: {}}]}, {buckets: null}, null]) {
    services.fetch = async () => response(data);
    await controller.refresh();
    assert.equal(controller.snapshot().audit.rows[0].ts, 999990);
    assert.match(controller.snapshot().audit.error, /could not be refreshed/);
  }
  await controller.setRange('audit', '7d');
  assert.equal(controller.snapshot().audit.loaded, false);
  assert.deepEqual(controller.snapshot().audit.rows, []);
  assert.equal(controller.snapshot().audit.range, '7d');
});

test('older audit requests cannot duplicate a page and polling retains appended rows', async t => {
  const {controller, services, calls} = fixture(t);
  await controller.refresh();
  const old = pending(), original = services.fetch;
  services.fetch = (url, options) => url.includes('before_ts=') ? old.promise : original(url, options);
  const first = controller.older();
  await controller.older();
  await controller.refresh('audit', true);
  assert.equal(calls.length, 2, 'poll does not invalidate the in-flight older page');
  old.resolve(response({events: [event(999000)]}));
  await first;
  assert.deepEqual(controller.snapshot().audit.rows.map(row => row.ts), [999990, 999000]);
  calls.length = 0;
  await controller.refresh('audit', true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0][0].includes('/histogram?'));
  assert.equal(controller.snapshot().audit.rows.length, 2);
  await controller.refresh();
  assert.equal(controller.snapshot().audit.rows.length, 1, 'manual refresh returns to the first page');
});

test('older audit failure keeps rows and cursor, empty older page stops further reads', async t => {
  const {controller, services} = fixture(t);
  await controller.refresh();
  services.fetch = async () => response({}, 503);
  await controller.older();
  assert.equal(controller.snapshot().audit.rows.length, 1);
  assert.equal(controller.snapshot().audit.exhausted, false);
  assert.match(controller.snapshot().audit.error, /Older audit events/);
  services.fetch = async () => response({events: []});
  await controller.older();
  assert.equal(controller.snapshot().audit.exhausted, true);
  services.fetch = () => assert.fail('no more reads');
  await controller.older();
});

test('route switch and pointer interaction invalidate pending results without starting another timer', async t => {
  const {controller, services} = fixture(t), wait = pending();
  services.fetch = () => wait.promise;
  const first = controller.refresh();
  controller.setInteracting('audit', true);
  await controller.refresh('audit', true);
  wait.resolve(response({...histogram, events: [event(1)]}));
  await first;
  assert.equal(controller.snapshot().audit.loaded, false);
  controller.select('deploylogs');
  assert.equal(controller.snapshot().audit.interacting, false);
  assert.equal(controller.snapshot().active, 'deploylogs');
  assert.equal(controller.snapshot().audit.busy, false);
});

test('newest file wins after delayed response body and closing cannot reopen the drawer', async t => {
  const {controller, services} = fixture(t), text = pending();
  services.fetch = async url => ({ok: true, text: () => url.endsWith('/a.log') ? text.promise : Promise.resolve('new content')});
  const first = controller.openDetail('a.log');
  await controller.openDetail('b.log');
  text.resolve('old content');
  await first;
  assert.equal(controller.snapshot().detail.file, 'b.log');
  assert.equal(controller.snapshot().detail.text, 'new content');
  const waiting = pending();
  services.fetch = () => waiting.promise;
  const last = controller.openDetail('c.log');
  controller.closeDetail();
  waiting.resolve(response('late content'));
  await last;
  assert.equal(controller.snapshot().detail, null);
});

test('deployment filters are local and preserve selection, refresh keeps a valid page', async t => {
  const {controller, calls} = fixture(t);
  controller.patch('deploylogs', {rows: Array.from({length: 51}, (_, i) => ({file: `${i}.log`, device_id: 'router'}))});
  controller.page(1);
  controller.page(1);
  assert.equal(controller.snapshot().deploylogs.page, 2);
  controller.filter({query: 'router'});
  assert.equal(controller.snapshot().deploylogs.page, 0);
  assert.deepEqual(calls, []);
});

test('a late older page cannot append after the category changes', async t => {
  const {controller, services} = fixture(t), older = pending(), original = services.fetch;
  await controller.refresh();
  services.fetch = (url, options) => url.includes('before_ts=') ? older.promise : original(url, options);
  const first = controller.older();
  await controller.setCategory('device');
  older.resolve(response({events: [event(999000, 'stale older event')]}));
  await first;
  assert.equal(controller.snapshot().audit.category, 'device');
  assert.equal(controller.snapshot().audit.rows.length, 1);
  assert.equal(controller.snapshot().audit.olderPages, 0);
  assert.equal(controller.snapshot().audit.olderBusy, false);
});

test('leaving Monitoring invalidates both pane reads and a pending file', async t => {
  const {controller, services} = fixture(t), waiting = pending();
  services.fetch = () => waiting.promise;
  const audit = controller.refresh('audit'), logs = controller.refresh('deploylogs'), detail = controller.openDetail('a.log');
  controller.hide();
  waiting.resolve(response({...histogram, events: [event(1)], logs: []}));
  await Promise.all([audit, logs, detail]);
  assert.equal(controller.snapshot().audit.loaded, false);
  assert.equal(controller.snapshot().deploylogs.loaded, false);
  assert.equal(controller.snapshot().audit.busy, false);
  assert.equal(controller.snapshot().deploylogs.busy, false);
  assert.equal(controller.snapshot().detail, null);
});

test('invalid histogram data cannot replace a valid table with a mismatched interval', async t => {
  const {controller, services} = fixture(t);
  await controller.refresh();
  for (const invalid of [{...histogram, bucket_seconds: 0}, {...histogram, now: 'bad'},
    {...histogram, buckets: [{start: 1, count: Infinity}]}, {...histogram, buckets: Array(201).fill({start: 1, count: 1})}]) {
    services.fetch = async url => response(url.includes('/histogram?') ? invalid : {events: [event(1)]});
    await controller.refresh();
    assert.equal(controller.snapshot().audit.rows[0].ts, 999990);
    assert.match(controller.snapshot().audit.error, /could not be refreshed/);
  }
});
