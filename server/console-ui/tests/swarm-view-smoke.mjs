// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated Console wrapper fixtures; no deployment or device is contacted.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}), errors = [], writes = [];
  const peer = type => ({ip: '192.0.2.2', port: 6881, tracker: {principal_type: type,
    ...(type === 'legacy' ? {participant_class: 'legacy_unattributed'} : {principal_id: 'router-a'}), role: 'leecher'}});
  let data = {now: 2000000000, images: [{info_hash: 'a'.repeat(40), peers: [peer('device'), peer('legacy')]},
    {info_hash: 'b'.repeat(40), peers: [peer('device')]}]};
  let heldFrame, frameLoads = 0, holdRead = false, heldRead, readCount = 0;
  const fixtures = {'/api/v1/session': {username: 'Swarm fixture', csrf: 'fixture-only'},
    '/api/v1/help': {version: 'test'}, '/api/v1/overview': {images: 0, devices: 0, rollout: [], swarm_map_url: 'https://unexpected.test/'},
    '/api/v1/devices': {devices: [], total: 0, offset: 0, revision: 1}, '/api/v1/images': {images: []},
    '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: [], max_concurrent: 25}};
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const url = new URL(route.request().url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname === '/swarmmap') {frameLoads++; heldFrame = route; return;}
    if (url.pathname.startsWith('/api/')) {
      if (route.request().method() !== 'GET') writes.push(url.pathname);
      if (url.pathname === '/api/v1/swarm') {
        readCount++; if (holdRead) {heldRead = route; return;}
        return route.fulfill({json: data});
      }
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'Fixture unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname))
      : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)],
      headers: {'Content-Security-Policy': "default-src 'self'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const refresh = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  const until = async fn => {const end = Date.now() + 5000; while (!fn() && Date.now() < end) await new Promise(resolve => setTimeout(resolve, 10)); assert.ok(fn());};
  await page.goto('http://iris.test/#overview');
  assert.equal(frameLoads, 0, 'The map is lazy-loaded');
  await page.locator('a[href="#swarm"]').click();
  await page.locator('#swarm-summary').getByText('3 image-peer entries.', {exact: false}).waitFor();
  assert.match(await page.locator('#legacy-peer-warning').innerText(), /1 unattributed/);
  assert.equal(await page.locator('#swarm-open').getAttribute('href'), '/swarmmap');
  await until(() => heldFrame);
  await page.locator('a[href="#overview"]').first().click();
  // A frame that finishes after navigation must receive the current host pause.
  await heldFrame.fulfill({contentType: 'text/html', body: '<!doctype html><title>Isolated map fixture</title><script nonce="fixture">window.messages=[];addEventListener("message",e=>window.messages.push(e.data));</script>',
    headers: {'Content-Security-Policy': "default-src 'self'; script-src 'nonce-fixture'"}});
  const map = page.frameLocator('#swarm-frame');
  await map.locator('body').waitFor({state: 'attached'});
  const frame = page.frames().find(row => row.url().endsWith('/swarmmap'));
  await frame.waitForFunction(() => window.messages?.at(-1) === 'MAP_PAUSE');
  await page.locator('a[href="#swarm"]').click();
  await frame.waitForFunction(() => window.messages.at(-1) === 'MAP_RESUME');
  assert.equal(frameLoads, 1, 'Navigation retains the loaded frame');
  // A listener that becomes ready after iframe load asks for visibility again.
  await frame.evaluate(() => {window.messages = []; parent.postMessage('MAP_READY', location.origin);});
  await frame.waitForFunction(() => window.messages.at(-1) === 'MAP_RESUME');
  const messages = await frame.evaluate(() => window.messages.length);
  await page.evaluate(() => window.irisSwarmView.refresh());
  assert.equal(await frame.evaluate(() => window.messages.length), messages, 'Summary polling must not resume a manual pause');
  data = {}; await refresh();
  await page.locator('#swarm-summary').getByText('Swarm data unavailable.', {exact: true}).waitFor();
  assert.equal(await page.locator('#legacy-peer-warning').isVisible(), false);
  data = {now: 2000000001, images: []}; await refresh();
  await page.locator('#swarm-summary').getByText('0 image-peer entries.', {exact: false}).waitFor();
  holdRead = true; await refresh(); await until(() => heldRead);
  holdRead = false; data = {now: 2000000002, images: [{info_hash: 'a'.repeat(40), peers: [peer('device')]}]};
  await refresh(); await page.locator('#swarm-summary').getByText('1 image-peer entries.', {exact: false}).waitFor();
  await heldRead.fulfill({json: {now: 2000000000, images: []}}).catch(() => {});
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.match(await page.locator('#swarm-summary').innerText(), /^1 image-peer entries/);
  const reads = readCount;
  await page.evaluate(() => {Object.defineProperty(document, 'hidden', {configurable: true, value: true}); document.dispatchEvent(new Event('visibilitychange'));});
  await frame.waitForFunction(() => window.messages.at(-1) === 'MAP_PAUSE');
  await page.evaluate(() => window.irisSwarmView.refresh()); assert.equal(readCount, reads);
  await page.evaluate(() => {delete document.hidden; document.dispatchEvent(new Event('visibilitychange'));});
  await frame.waitForFunction(() => window.messages.at(-1) === 'MAP_RESUME');
  for (const width of [390, 320]) {
    await page.setViewportSize({width, height: 900});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No narrow-screen page overflow');
  }
  assert.deepEqual(writes, []); assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Swarm Console wrapper: lazy/late frame visibility, exact counts, malformed/stale reads, CSP and mobile PASS');
} finally {await browser.close();}
