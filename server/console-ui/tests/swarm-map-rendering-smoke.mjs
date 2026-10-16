// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Generated, self-contained map under production-style nonce CSP. Every API
// is intercepted; this is rendering qualification, not live transfer evidence.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), now = Math.floor(Date.now() / 1000);
const hash = 'a'.repeat(40), otherHash = 'b'.repeat(40);
const peer = (id, model = 'Cisco 8000 series') => ({device_id: id, ip: id === 'XR-A' ? '192.0.2.10' : '192.0.2.11', port: 6881, model,
  tracker: {principal_type: 'device', principal_id: id, role: 'seeder', last_seen: now},
  current_image_id: 'image-c', stage_state: 'copying', staged_image_ids: ['image-a'], errored_image_ids: ['image-b'],
  device_observation: {image_id: 'image-b', obs_state: 'observed', valid: true, age_s: 0, receive_bps: 1048576},
  peer_tls: {runtime_source: 'aria2_rpc', runtime_mode: 'required', configured_mode: 'required', reported_at: now},
  peer_policy: {decision: 'allowed', quarantined: false, fail_closed: false},
  peer_enforcement: {state: 'observed', blocked: false, conflict: {reason: 'shared address', global_block_applied: false}},
  peer_telemetry: {supported: true, requested_interval_s: 60, effective_interval_s: 60},
  server_observation: {peer: {send_bps: 2097152, observed_at: now}},
  latest_report: {image_id: 'image-a', schema: 'v2', event: 'stage', content_sha256_state: 'ok', ios_copy_verify_state: 'ok', report_id: 'c'.repeat(32), received_at: now}});
let data = {now, server: {host: 'Distribution', server_observation: {rpc_up: true, observed_at: now, global: {send_bps: 2097152, receive_bps: 0, connections: 2}}}, images: [
  {image: 'Image A', image_id: 'image-a', info_hash: hash, peers: [peer('XR-A'), peer('XE-B', 'C8000V')], peer_edges: [{source_device_id: 'XR-A', target_device_id: 'XE-B', bytes_per_second: 1048576, reporter_device_id: 'XE-B', identity_basis: 'tracker_endpoint', received_at: now, valid_for_s: 120}], peer_edges_truncated: true, unattributed_peer_connections: 1},
  {image: 'Image B', image_id: 'image-b', info_hash: otherHash, peers: [peer('XR-A')], peer_edges: []},
]};
let html = await fs.readFile(path.join(root, 'dist/swarmmap.html'), 'utf8');
html = html.replace('<script>', '<script nonce="test">').replace('<style>', '<style nonce="test">');
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}, reducedMotion: 'reduce'}); page.setDefaultTimeout(10000);
  const errors = [], writes = []; let unavailable = false;
  let eventsTemplate = 'https://events.example/device/{device_id}?ip={ip}';
  await page.clock.install();
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname === '/swarmmap') return route.fulfill({body: html.replace('window.IRIS_MAP_CFG = null;', 'window.IRIS_MAP_CFG = ' + JSON.stringify({pull: false, swarmUrl: '/swarm', eventsUrlTemplate: eventsTemplate}) + ';'), contentType: 'text/html', headers: {'Content-Security-Policy': "default-src 'self'; script-src 'nonce-test'; style-src 'nonce-test'; connect-src 'self'; img-src 'self'; font-src 'self'"}});
    if (request.method() !== 'GET') {writes.push(url.pathname); throw Error('Read-only map attempted a write');}
    if (url.pathname === '/swarm') return route.fulfill({status: unavailable ? 503 : 200, json: unavailable ? {error: 'unavailable'} : data});
    if (url.pathname.startsWith('/fonts/')) return route.fulfill({body: await fs.readFile(path.join(root, '../webroot', url.pathname)), contentType: 'font/woff2'});
    throw Error('Unexpected request: ' + url.pathname);
  });
  await page.goto('http://iris.test/swarmmap'); await page.locator('#peertable tbody tr').nth(2).waitFor();
  assert.equal(await page.locator('#peertable tbody tr').count(), 3);
  assert.equal(await page.locator('#svg .peer-transfer').count(), 1);
  assert.equal(await page.locator('#svg .edge.measured').first().evaluate(node => getComputedStyle(node).animationName), 'none');
  await page.locator('#imgsel').selectOption(hash); assert.equal(await page.locator('#peertable tbody tr').count(), 2);
  await page.locator('#peerfind').fill('C8000V'); assert.equal(await page.locator('#peertable tbody tr').count(), 1);
  await page.locator('#peerfind').fill(''); await page.locator('[data-sort=name]').click();
  assert.equal(await page.locator('#peertable th[aria-sort]').getAttribute('aria-sort'), 'descending');
  await page.locator('#zoom-in').click(); assert.match(await page.locator('#scene').getAttribute('transform'), /scale\(1.25\)/);
  await page.locator('#fit').click(); assert.equal(await page.locator('#scene').getAttribute('transform'), 'translate(0 0) scale(1)');
  const xr = page.locator('#svg [aria-label="Open XR-A (Cisco 8000 series) details"]');
  await xr.focus(); await page.keyboard.press('Enter'); await page.locator('#drawer').waitFor({state: 'visible'});
  assert.equal(await page.locator('#close').evaluate(node => node === document.activeElement), true);
  assert.equal(await page.locator('#wrap').getAttribute('inert'), '');
  assert.equal(await page.locator('header').getAttribute('inert'), '');
  assert.equal(await page.locator('#pullbtn').count(), 0, 'Public map never renders mutation controls');
  assert.match(await page.locator('#peer-details').innerText(), /Latest device observation is for another image/);
  assert.match(await page.locator('#peer-details').innerText(), /negotiated connection encryption is not measured/);
  assert.match(await page.locator('#peer-details').innerText(), /Some peer observations were truncated/);
  const stateRows = await page.locator('#peer-details section').filter({has: page.getByRole('heading', {name: 'Image staging', exact: true})}).innerText();
  assert.match(stateRows, /image-a\nready/); assert.match(stateRows, /image-b\nerror/); assert.match(stateRows, /image-c\npending/);
  const events = page.getByRole('link', {name: 'Events', exact: true});
  assert.equal(await events.getAttribute('href'), 'https://events.example/device/XR-A?ip=192.0.2.10');
  assert.equal(await events.getAttribute('target'), '_blank'); assert.equal(await events.getAttribute('rel'), 'noopener noreferrer');
  await page.keyboard.press('Shift+Tab'); assert.equal(await events.evaluate(node => node === document.activeElement), true, 'Drawer traps focus through its Events link');
  await page.keyboard.press('Tab'); assert.equal(await page.locator('#close').evaluate(node => node === document.activeElement), true);
  data.images[0].peers[0].model = '<img src=x onerror=alert(1)>';
  await page.clock.fastForward(5100); await page.locator('#peer-details').getByText('Model: <img src=x onerror=alert(1)>', {exact: true}).waitFor();
  assert.equal(await page.locator('#drawer img').count(), 0);
  await page.keyboard.press('Escape'); assert.equal(await page.locator('#drawer').isVisible(), false);
  assert.match(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), /Open XR-A/);
  assert.equal(await page.locator('#imgsel').inputValue(), hash, 'Selected image is preserved across refresh');
  unavailable = true; await page.clock.fastForward(5100); await page.locator('#state').getByText(/Unavailable/).waitFor();
  assert.equal(await page.locator('#peertable tbody tr').count(), 0); assert.equal(await page.locator('#imgsel').inputValue(), hash, 'A failed read does not reset the operator filter');
  unavailable = false; await page.clock.fastForward(10100); await page.locator('#peertable tbody tr').nth(1).waitFor();
  await page.locator('#pause').click(); assert.equal(await page.locator('#pause').innerText(), 'Resume');
  await page.clock.fastForward(121000); assert.equal(await page.locator('#svg .peer-transfer').count(), 0); assert.equal(await page.locator('#svg .edge.measured').count(), 0, 'Paused snapshots cannot keep rates fresh');
  const renewed = await page.evaluate(() => Math.floor(Date.now() / 1000)); data.now = renewed;
  data.server.server_observation.observed_at = renewed;
  for (const image of data.images) {
    for (const row of image.peers) {row.model = row.device_id === 'XR-A' ? 'Cisco 8000 series' : 'C8000V'; row.server_observation.peer.observed_at = renewed; row.peer_tls.reported_at = renewed;}
    for (const edge of image.peer_edges) edge.received_at = renewed;
  }
  await page.locator('#pause').click(); await page.locator('#svg .peer-transfer').waitFor();
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height}); await page.evaluate(() => window.scrollTo(0, 0)); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Map fits ' + width);
    if (process.env.IRIS_UI_SCREENSHOTS) {await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'swarm-map-' + width + '.png')});}
    await page.locator('#peertable tbody button').first().click(); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Drawer fits ' + width);
    if (process.env.IRIS_UI_SCREENSHOTS) await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'swarm-map-drawer-' + width + '.png')});
    await page.locator('#close').click();
  }
  for (const template of ['', 'javascript:alert(1)', 'data:text/html,hello', '//events.example/']) {
    eventsTemplate = template; await page.reload(); await page.locator('#peertable tbody button').first().click();
    assert.equal(await page.getByRole('link', {name: 'Events', exact: true}).count(), 0, 'Unsafe or unset template has no Events link');
    await page.locator('#close').click();
  }
  assert.deepEqual(writes, []); assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Standalone Swarm rendering passed: sourced details, filters, graph, keyboard/focus, stale arrows, CSP and responsive layouts.');
} finally {await browser.close();}
