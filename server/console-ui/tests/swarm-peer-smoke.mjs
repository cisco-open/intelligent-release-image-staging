// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
// Isolated map/API fixtures. Never contacts the lab or opens an owner session.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const now = Math.floor(Date.now() / 1000);
const peer = (id, supported = true) => ({device_id: id, ip: id === 'XR-A' ? '192.0.2.1' : '192.0.2.2',
  port: 6881, model: id === 'XR-A' ? '8000' : 'C8000V',
  tracker: {principal_type: 'device', principal_id: id, role: 'seeder', last_seen: now},
  peer_telemetry: {supported, requested_interval_s: 60, effective_interval_s: 60}});
const data = {now, server: {host: 'Distribution'}, images: [{image: 'Release image',
  image_id: 'release', info_hash: 'a'.repeat(40), peers: [peer('XR-A'), peer('XE-B')],
  peer_edges: [{source_device_id: 'XR-A', target_device_id: 'XE-B',
    bytes_per_second: 1048576, reporter_device_id: 'XE-B', rate_field: 'receive_bps',
    identity_basis: 'unique_tracker_address', received_at: now, valid_for_s: 120}]}]};
let html = await fs.readFile(new URL('../../swarmmap.html', import.meta.url), 'utf8');
html = html.replace('window.IRIS_MAP_CFG = null;',
  'window.IRIS_MAP_CFG = {swarmUrl:"/api/v1/swarm",pull:true};')
  .replace('<script>', '<script nonce="test">').replace('<style>', '<style nonce="test">');
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}, reducedMotion: 'reduce'});
  await page.clock.install();
  const errors = [], writes = [];
  let refused = false;
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, 'http://iris.test');
    if (url.pathname === '/swarmmap') return route.fulfill({contentType: 'text/html', body: html,
      headers: {'Content-Security-Policy': "default-src 'self'; script-src 'nonce-test'; style-src 'nonce-test'; connect-src 'self'; img-src 'self'"}});
    if (url.pathname === '/api/v1/swarm') return route.fulfill({json: data});
    if (url.pathname === '/api/v1/session') return route.fulfill({json: {csrf: 'test-only'}});
    if (url.pathname === '/api/v1/peer-policy') return route.fulfill({json: {revision: 7}});
    if (url.pathname.endsWith('/reports')) return route.fulfill({json: {reports: []}});
    if (url.pathname.endsWith('/peer-telemetry')) {
      assert.equal(route.request().method(), 'POST');
      assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
      assert.equal(route.request().headers()['if-match'], '"iris-peer-policy-7"');
      const body = route.request().postDataJSON();
      writes.push({preview: url.searchParams.get('dry_run') === '1', body});
      if (refused) return route.fulfill({status: 412, json: {code: 'policy_changed'}});
      if (!url.search) assert.equal(body.confirm_token, 'preview-only-fixture');
      return route.fulfill({json: url.search ? {confirm_token: 'preview-only-fixture'} : {ok: true}});
    }
    if (url.pathname.startsWith('/fonts/')) return route.fulfill({body:
      await fs.readFile(new URL('../../webroot' + url.pathname, import.meta.url))});
    throw new Error('Unexpected request: ' + url.pathname);
  });
  await page.goto('http://iris.test/swarmmap');
  const arrow = page.locator('.peer-transfer');
  await arrow.waitFor();
  assert.equal(await arrow.count(), 1);
  assert.match(await arrow.getAttribute('aria-label'), /^XR-A → XE-B: 1.0 MB\/s/);
  assert.equal(await arrow.evaluate(node => getComputedStyle(node).animationName), 'none');
  await arrow.focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#drawer h2').textContent(), 'XE-B');
  await page.locator('#peer-interval').selectOption('10');
  await page.locator('#save-peer-interval').click();
  await page.getByText(/Saved. Waiting for the device/).waitFor();
  assert.deepEqual(writes, [{preview: true, body: {interval_s: 10}},
    {preview: false, body: {interval_s: 10, confirm_token: 'preview-only-fixture'}}]);
  // A saved request must not be presented as already effective on the device.
  assert.match(await page.locator('#peer-details').textContent(), /Reported interval60s/);
  refused = true;
  await page.locator('#peer-interval').selectOption('60');
  await page.locator('#save-peer-interval').click();
  await page.getByText('Policy changed. Try again.').waitFor();
  assert.equal(writes.length, 3, 'A failed preview must never commit');
  await page.keyboard.press('Escape');
  await page.locator('#peerfind').fill('XR-A');
  assert.equal(await arrow.count(), 0, 'No arrows to hidden endpoints');
  await page.locator('#peerfind').fill('');
  await arrow.waitFor();
  // Pointer input must open the same receiver without starting a pan.
  await arrow.dispatchEvent('pointerdown', {pointerId: 1, clientX: 20, clientY: 20});
  assert.equal(await page.locator('#svg.panning').count(), 0);
  await arrow.dispatchEvent('click');
  assert.equal(await page.locator('#drawer h2').textContent(), 'XE-B');
  await page.keyboard.press('Escape');
  if (process.env.SWARM_SCREENSHOT) await page.screenshot({path: process.env.SWARM_SCREENSHOT, fullPage: true});
  await page.locator('#pause').click();
  await page.clock.fastForward(121000);
  assert.equal(await arrow.count(), 0, 'Paused snapshots must expire measured arrows');
  data.images[0].peers[1].peer_telemetry.supported = false;
  await page.reload();
  await page.getByRole('button', {name: 'Open XE-B (C8000V) details', exact: true}).click();
  assert.equal(await page.locator('#peer-interval option[value="10"]').isDisabled(), true);
  assert.deepEqual(errors, []);
  console.log('Swarm peer arrows, keyboard/pointer access, expiry and signed interval UI passed.');
} finally { await browser.close(); }
