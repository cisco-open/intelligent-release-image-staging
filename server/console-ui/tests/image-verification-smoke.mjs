// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built Console with intercepted APIs only; no lab uploads or live feed fetches.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], reads = [];
  const cfg = {mode: 'off', hour_utc: 0, last_run: {at: null, source: null, outcome: null, matched: null, mismatched: null, not_in_feed: null}};
  const setup = {admin: {state: 'ok', username: 'operator'}, telemetry: {state: 'unset', enabled: false, endpoint: '', source: 'env'},
    packages: {state: 'absent', reference_fingerprint: 'AA:'.repeat(31) + 'AA', remedy: 'Rebuild packages', items:
      ['iris-amd64.tar', 'iris-arm64.tar', 'iris-xr.rpm'].map(name => ({name, state: 'absent', fingerprint: null, built_at: null, provenance: null, remedy: 'Rebuild packages'}))},
    image_verification: {state: 'unset'}};
  const success = {outcome: 'ok', matched: 2, mismatched: 1, not_in_feed: 0};
  let behavior = '', pending, reached, badRead = false;
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        writes.push({path: url.pathname, body: url.pathname.endsWith('/offline') ? request.postDataBuffer() : request.postDataJSON()});
        if (behavior === 'hold') {pending = route; reached(); return;}
        if (behavior === 'bad') return route.fulfill({json: {matched: 2, mismatched: 0, not_in_feed: 0}});
        if (url.pathname.endsWith('/settings/image-verification')) {
          const body = request.postDataJSON(); if (behavior !== 'wrong-schedule') Object.assign(cfg, body);
          return route.fulfill({json: cfg});
        }
        if (behavior === 'running') return route.fulfill({status: 409, json: {outcome: 'already_running', code: 'resource-conflict'}});
        cfg.last_run = {at: 2000000000, source: url.pathname.endsWith('/offline') ? 'offline' : 'manual', ...success};
        setup.image_verification.state = 'ok'; return route.fulfill({json: success});
      }
      reads.push(url.pathname);
      if (url.pathname.endsWith('/settings/image-verification')) return route.fulfill({status: badRead ? 503 : 200, json: badRead ? {error: 'unavailable'} : cfg});
      const fixtures = {'/api/v1/session': {username: 'Verification fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/settings/setup-status': setup, '/api/v1/devices': {devices: [], total: 0, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const idle = () => page.waitForFunction(() => window.irisImageVerification && !window.irisImageVerification.state.busy && !window.irisImageVerification.state.loading);
  const review = async () => {await page.locator('#iv-review').click(); await idle();};
  const navigate = async (wait = true) => {await page.evaluate(() => {location.hash = '#settings/bulkhash';}); await page.locator('#settings-pane-bulkhash #iv-content').waitFor(); if (wait) await idle();};
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png')});}};
  await page.goto('http://iris.test/#settings/bulkhash'); await page.waitForFunction(() => window.irisImageVerification?.state.valid); await idle();
  assert.equal(await page.locator('#iv-content').count(), 1); assert.equal(await page.locator('#iv-hour option').count(), 24);
  assert.match(await page.locator('#iv-last-run').innerText(), /Never run/);
  await page.locator('#iv-mode').selectOption('weekly'); await page.locator('#iv-hour').selectOption('8');
  await page.evaluate(() => window.irisImageVerification.refresh()); assert.equal(await page.locator('#iv-mode').inputValue(), 'weekly');
  behavior = 'wrong-schedule'; await page.locator('#iv-schedule-form button').click(); await idle();
  assert.match(await page.locator('#iv-schedule-msg').innerText(), /may have changed/); assert.equal(await page.locator('#iv-refresh').isDisabled(), true);
  await review(); assert.equal(await page.locator('#iv-mode').inputValue(), 'off');
  behavior = ''; await page.locator('#iv-mode').selectOption('weekly'); await page.locator('#iv-hour').selectOption('8'); await page.locator('#iv-schedule-form button').click(); await idle();
  assert.equal(await page.locator('#iv-schedule-msg').innerText(), 'Schedule saved.');
  behavior = 'bad'; await page.locator('#iv-refresh').click(); await idle();
  assert.match(await page.locator('#iv-refresh-msg').innerText(), /Response unavailable/);
  assert.equal(await page.locator('#iv-refresh').isDisabled(), true); assert.equal(await page.locator('#iv-offline-dropzone').getAttribute('aria-disabled'), 'true');
  await review(); behavior = 'hold'; const waiting = new Promise(resolve => {reached = resolve;});
  await page.locator('#iv-refresh').click(); await waiting;
  assert.equal(await page.locator('#iv-schedule-form button').isDisabled(), true);
  assert.equal(await page.locator('#iv-refresh-msg').evaluate(node => node === document.activeElement), true);
  const count = writes.length;
  await page.evaluate(() => {location.hash = '#settings/general';}); await navigate(false);
  assert.equal(await page.locator('#iv-refresh').isDisabled(), true); assert.equal(writes.length, count);
  await pending.fulfill({json: success}); await idle(); behavior = '';
  assert.match(await page.locator('#iv-refresh-msg').innerText(), /2 matched, 1 mismatched/);
  await page.evaluate(() => {
    const assignments = window.irisAssignments;
    assignments.services.publishImages(assignments.acceptImages({ok: true, body: {images: [{id: 'before-check', quarantined: false}]}}, assignments.beginImageRead()));
    window.staleImageTicket = assignments.beginImageRead();
  });
  assert.equal(await page.evaluate(() => window.irisAssignments.state.imagesOk), true);
  const beforeReads = reads.length;
  await page.locator('#iv-offline-dropzone').focus(); const chooser = page.waitForEvent('filechooser'); await page.keyboard.press('Enter');
  await (await chooser).setFiles({name: 'Cisco_BulkHash_CSV.tar', mimeType: 'application/octet-stream', buffer: Buffer.from('raw-fixture-tar')}); await idle();
  assert.match(await page.locator('#iv-offline-msg').innerText(), /Offline check complete/);
  assert.equal(writes.at(-1).body.toString(), 'raw-fixture-tar');
  assert.ok(reads.slice(beforeReads).includes('/api/v1/images'));
  assert.equal(await page.evaluate(() => window.irisAssignments.state.imagesOk), false, 'Quarantine change invalidates hidden picker prerequisites');
  await page.evaluate(() => {
    const assignments = window.irisAssignments;
    assignments.services.publishImages(assignments.acceptImages({ok: true, body: {images: [{id: 'before-check', quarantined: false}]}}, window.staleImageTicket));
  });
  assert.equal(await page.evaluate(() => window.irisAssignments.state.imagesOk), false, 'Earlier read cannot reinstate stale picker prerequisites');
  assert.match(await page.locator('#iv-last-run').innerText(), /offline/);
  behavior = 'running'; await page.locator('#iv-refresh').click(); await idle();
  assert.match(await page.locator('#iv-refresh-msg').innerText(), /already in progress/); assert.equal(await page.locator('#iv-refresh').isDisabled(), true);
  await review(); behavior = ''; badRead = true; await page.evaluate(() => window.irisImageVerification.refresh()); await idle();
  assert.match(await page.locator('#iv-last-run').innerText(), /Could not load/); assert.equal(await page.locator('#iv-refresh').isDisabled(), true);
  badRead = false; await review();
  await page.locator('#iv-hour').selectOption('11');
  await page.evaluate(() => {location.hash = '#setup';}); await page.locator('.wz-steplist-item').filter({hasText: 'Image verification'}).click();
  await page.locator('#wz-iv-mount #iv-content').waitFor(); await idle();
  assert.equal(await page.locator('#iv-hour').inputValue(), '11'); assert.equal(await page.locator('#iv-content').count(), 1);
  await navigate(); assert.equal(await page.locator('#iv-hour').inputValue(), '11'); assert.equal(await page.locator('#wz-iv-mount #iv-content').count(), 0);
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Fits width ' + width);
    assert.equal(await page.locator('#iv-content select').evaluateAll(nodes => nodes.every(node => node.labels.length)), true);
    assert.equal(await page.locator('#iv-content h3').evaluateAll(nodes => nodes.every(node => !!node.closest('.card'))), true);
    await snapshot('image-verification-' + width);
  }
  await page.evaluate(() => {Object.defineProperty(document, 'hidden', {configurable: true, value: true}); document.dispatchEvent(new Event('visibilitychange'));});
  assert.equal(await page.evaluate(() => window.irisImageVerification.state.valid), false);
  await page.evaluate(() => {delete document.hidden; document.dispatchEvent(new Event('visibilitychange'));}); await page.waitForFunction(() => window.irisImageVerification.state.valid); await idle();
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Image verification browser passed: exact results, lock/review, raw upload, shared wizard, focus, CSP and 1440/390/320px.');
} finally {await browser.close();}
