// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated browser fixtures: never contacts a deployment or a device.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  const errors = [], writes = [], failures = new Map();
  let holdTelemetry = false, heldTelemetry = null;
  const devices = {devices: [{device_id: 'router-a', device_ip: '192.0.2.10', model: 'C8000V',
    model_family: 'C8xxx', management_type: 'iox', assigned_images: [], stage_state: 'error'}], total: 1};
  const images = {images: [{id: 'image-a', filename: '<img src=x onerror=alert(1)>', quarantined: true}]};
  const fixtures = {
    '/api/v1/session': {username: 'Overview fixture', csrf: 'test-only'},
    '/api/v1/help': {version: 'test', deployment_id: 'fixture-only'},
    '/api/v1/overview': {images: 1, devices: 5, assigned: 3, staged: 1, staging_now: 2, awaiting_heartbeat: 1,
      rollout: [{image_id: '<svg onload=alert(1)>', assigned: 3, staged: 1}]},
    '/api/v1/devices': devices, '/api/v1/images': images,
    '/api/v1/onboard/jobs': {jobs: [], max_concurrent: 25},
    '/api/v1/credentials': {profiles: []},
    '/api/v1/deployment': {layout: 'single-container', components: [{role: 'server', kind: 'container',
      name: 'iris', host: 'fixture-host', state: 'running', os: 'Debian', architecture: 'arm64'}]},
    '/api/v1/telemetry/health': {otlp_export: {state: 'ok', signals: {logs: {state: 'ok', queued: 2}, metrics: {state: 'ok'}}}},
  };
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
  });
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (route.request().method() !== 'GET') writes.push(url.pathname);
      if (holdTelemetry && url.pathname === '/api/v1/telemetry/health') { heldTelemetry = route; return; }
      const failure = failures.get(url.pathname);
      if (failure === 'network') return route.abort('failed');
      if (failure === 'http') return route.fulfill({status: 503, json: {error: 'fixture failure'}});
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'Fixture unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname))
      : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {
      return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript',
        '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
        headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});
    } catch { return route.fulfill({status: 404, body: ''}); }
  });
  const refresh = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.goto('http://iris.test/#overview');
  await page.locator('#ov-attention [data-attn="devices"]').waitFor();
  assert.match(await page.locator('#ov-attention').innerText(), /1\s+device needs attention/);
  assert.match(await page.locator('#ov-cards').innerText(), /Staged\s+1\s+of 3 assigned/i);
  assert.match(await page.locator('#ov-cards').innerText(), /Waiting for heartbeat\s+1\s+of 5 devices/i);
  assert.equal(await page.locator('#ov-rows svg').count(), 0, 'Image IDs must be text, never markup');
  assert.equal(await page.getByRole('progressbar').getAttribute('aria-valuenow'), '33');
  assert.equal(await page.locator('#ov-rows .pbar > span').evaluate(node => node.style.width), '33%');
  await page.locator('#telemetry-health').getByText('Telemetry export: ok', {exact: true}).waitFor();
  assert.match(await page.locator('#telemetry-health').getAttribute('title'), /queued 2/);

  // Reconciliation must keep the focused action across refreshes.
  await page.locator('#ov-attention [data-attn="devices"]').focus();
  fixtures['/api/v1/overview'].staged = 2;
  await refresh();
  await page.waitForFunction(() => document.querySelector('#ov-cards').textContent.includes('Staged2of 3 assigned'));
  assert.equal(await page.evaluate(() => document.activeElement.dataset.attn), 'devices');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => location.hash === '#devices' && document.querySelector('#dev-filter-status').value === '__attention');
  await page.goto('http://iris.test/#overview');
  await page.locator('#ov-attention [data-attn="images"]').click();
  await page.waitForFunction(() => location.hash === '#images' && document.querySelector('#images-filter-attention').checked);
  assert.equal(await page.locator('#rows img').count(), 0);
  await page.goto('http://iris.test/#overview');

  // Both HTTP and network failures keep valid totals and the other attention group.
  for (const failure of ['http', 'network']) {
    failures.set('/api/v1/devices', failure);
    await refresh();
    await page.locator('#ov-attention').getByText('Fleet status unavailable', {exact: true}).waitFor();
    assert.equal(await page.locator('#ov-attention [data-attn="images"]').count(), 1);
    assert.equal(await page.locator('#ov-attention .is-positive').count(), 0);
    assert.equal(await page.locator('#ov-cards .card').count(), 6);
    failures.set('/api/v1/images', failure);
    await refresh();
    await page.waitForFunction(() => document.querySelectorAll('#ov-attention [data-attn]').length === 0);
    assert.equal(await page.locator('#ov-attention .is-positive').count(), 0);
    failures.clear();
    await refresh();
    await page.locator('#ov-attention [data-attn="devices"]').waitFor();
  }
  devices.devices[0].stage_state = 'unassigned';
  images.images[0].quarantined = false;
  await refresh();
  await page.locator('#ov-attention').getByText('All clear', {exact: true}).waitFor();

  // Malformed deployment content fails closed without crashing the React root.
  const deployment = fixtures['/api/v1/deployment'];
  for (const components of [[null], [{name: {bad: 'value'}}], Array(65).fill({name: 'too many'})]) {
    fixtures['/api/v1/deployment'] = {...deployment, components};
    await refresh();
    await page.locator('#deployment-layout').getByText('Unavailable', {exact: true}).waitFor();
    assert.equal(await page.locator('#deployment-table').isVisible(), false);
    fixtures['/api/v1/deployment'] = deployment;
    await refresh();
    await page.locator('#deployment-layout').getByText('Single container', {exact: true}).waitFor();
  }

  // Late health data cannot overwrite the result of a newer refresh.
  holdTelemetry = true;
  await refresh();
  const deadline = Date.now() + 5000;
  while (!heldTelemetry && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(heldTelemetry, 'Old health response was captured');
  holdTelemetry = false;
  fixtures['/api/v1/telemetry/health'] = {otlp_export: {state: 'degraded'}};
  await refresh();
  await page.locator('#telemetry-health').getByText('Telemetry export: degraded', {exact: true}).waitFor();
  const oldResponse = page.waitForResponse(response => response.url().endsWith('/api/v1/telemetry/health'));
  await heldTelemetry.fulfill({json: {otlp_export: {state: 'off'}}});
  await oldResponse;
  // Wait two render frames after the old response has been processed.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.locator('#telemetry-health').innerText(), 'Telemetry export: degraded');
  assert.equal(await page.locator('#telemetry-health').getAttribute('title'), '');

  for (const [width, name] of [[1440, 'desktop'], [390, 'mobile']]) {
    await page.setViewportSize({width, height: 1000});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    if (process.env.IRIS_UI_SCREENSHOTS) {
      await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, `overview-react-${name}.png`), fullPage: true});
    }
  }
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  assert.deepEqual(writes, [], 'Viewing and filtering must not issue writes');
  assert.deepEqual(errors, []);
  console.log('Overview rendering, failures, keyboard actions, focus retention, stale health and CSP passed.');
} finally { await browser.close(); }
