// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Exercise shipped assets and exact review semantics without live policy writes.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], token = 'a'.repeat(64);
  const policy = {revision: 7, quarantine_assignments: [], roles_supported: true, roles: {defined: 0, members: {}}};
  let value = {revision: 0, policy_revision: 7, mode: 'preflight', max_new_ips: 10, max_new_devices: 10,
    approved_ip_count: 0, approved_device_count: 0, new_ip_count: 2, new_device_count: 3, retained_ip_count: 0,
    proposed_ip_count: 2, proposed_device_count: 3, shared_conflict_count: 0, protected_conflict_count: 0,
    state: 'preflight', reason: null, applied_ip_count: null, applied_device_count: null, last_verified_at: null, blockers: []};
  let mode = 'ok', held, reached;
  const response = body => ({json: body, headers: {ETag: `"origin-enforcement-${body.revision}"`}});
  const preview = body => ({...value, mode: body.mode, max_new_ips: body.max_new_ips, max_new_devices: body.max_new_devices,
    dry_run: true, requires_confirmation: true, confirm_token: token});
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname === '/api/v1/peer-policy/origin-enforcement') {
      if (request.method() === 'GET') return route.fulfill(response(value));
      const body = request.postDataJSON(); writes.push({body, headers: request.headers()});
      assert.equal(request.method(), 'PUT'); assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
      assert.equal(request.headers()['if-match'], `"origin-enforcement-${value.revision}"`);
      assert.equal(body.if_policy_revision, policy.revision);
      if (body.dry_run) {
        if (mode === 'hold') {held = route; reached(); return;}
        return route.fulfill(response(mode === 'blocked' ? {...preview(body), blockers: ['shared_address'], confirm_token: null} : preview(body)));
      }
      assert.equal(body.confirm_token, token);
      if (mode === 'empty') return route.fulfill({json: {}});
      value = {...value, revision: value.revision + 1, mode: body.mode, max_new_ips: body.max_new_ips, max_new_devices: body.max_new_devices,
        state: 'pending', reason: 'application_pending', approved_ip_count: 2, approved_device_count: 3};
      return route.fulfill(response({...value, dry_run: false, requires_confirmation: false, confirm_token: null}));
    }
    if (url.pathname.startsWith('/api/')) {
      assert.equal(request.method(), 'GET', 'No unreviewed policy or device writes');
      const fixtures = {'/api/v1/session': {username: 'Policy fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/peer-policy': policy, '/api/v1/peer-policy/roles': {revision: policy.revision, roles: {}},
        '/api/v1/devices': {devices: [], total: 0, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const idle = () => page.waitForFunction(() => !window.irisPolicies.origin.state.busy && !window.irisPolicies.origin.state.loading);
  const apply = async () => {await page.locator('#origin-apply').click(); await idle();};
  const refresh = async () => {await page.locator('#origin-refresh').click(); await idle();};
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {
    await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true});
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png'), fullPage: true});
  }};
  await page.goto('http://iris.test/#policies'); await page.waitForFunction(() => window.irisPolicies?.origin.state.ready);
  assert.equal(await page.locator('#origin-application-state').innerText(), 'Preview only');
  assert.equal(await page.locator('#origin-saved-mode').innerText(), 'Preview only');
  assert.equal(await page.locator('#origin-approved-counts').innerText(), '0 devices · 0 addresses');
  assert.equal(await page.locator('#origin-confirmed-counts').innerText(), 'Not confirmed');
  await snapshot('distribution-preview-only');
  await page.locator('#origin-mode').selectOption('enforce'); await page.locator('#origin-max_new_ips').fill('1001'); await apply();
  assert.equal(writes.length, 0); assert.match(await page.locator('#origin-message').innerText(), /0 to 1000/);
  await page.locator('#origin-max_new_ips').fill('10'); await apply();
  assert.equal(writes.length, 1); assert.equal(await page.locator('#origin-apply').innerText(), 'Apply reviewed change');
  assert.equal(await page.locator('#origin-apply').evaluate(node => document.activeElement === node), true);
  assert.match(await page.locator('#origin-preview').innerText(), /New devices to block\s+3/);
  assert.equal(await page.locator('#origin-saved-mode').innerText(), 'Preview only', 'A requested draft does not replace saved settings');
  assert.equal(await page.locator('#origin-application-state').innerText(), 'Preview only');
  assert.equal(await page.locator('#origin-confirmed-counts').innerText(), 'Not confirmed');
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height}); await page.locator('#origin-apply').scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const box = await page.locator('#origin-apply').boundingBox(); assert.ok(box.x >= 0 && box.x + box.width <= width);
    await snapshot('origin-preview-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000});
  await page.getByRole('button', {name: 'Cancel review', exact: true}).click(); assert.equal(writes.length, 1);
  assert.equal(await page.evaluate(() => window.irisInventory.state.bulkBusy), false);
  mode = 'blocked'; await apply(); assert.match(await page.locator('#origin-preview').innerText(), /Allowed and denied devices share an address/);
  assert.equal(await page.locator('#origin-apply').isDisabled(), true); assert.equal(await page.evaluate(() => window.irisInventory.state.bulkBusy), false);
  mode = 'ok'; await refresh(); await page.locator('#origin-mode').selectOption('enforce'); await apply();
  mode = 'empty'; await apply(); assert.match(await page.locator('#origin-message').innerText(), /may have been saved/);
  assert.equal(await page.locator('#origin-apply').isDisabled(), true);
  await page.evaluate(() => window.irisPolicies.origin.refresh()); assert.equal(await page.locator('#origin-apply').isDisabled(), true);
  await refresh(); mode = 'ok'; await page.locator('#origin-mode').selectOption('enforce'); await apply(); await apply();
  assert.equal(await page.locator('#origin-application-state').innerText(), 'Waiting for confirmation');
  assert.equal(await page.locator('#origin-saved-mode').innerText(), 'Enforce reviewed blocks');
  assert.equal(await page.locator('#origin-approved-counts').innerText(), '3 devices · 2 addresses');
  assert.equal(await page.locator('#origin-confirmed-counts').innerText(), 'Not confirmed');
  await snapshot('distribution-waiting');
  value = {...value, state: 'enforced', reason: null, applied_ip_count: 2, applied_device_count: 3, last_verified_at: 2000000000};
  await refresh(); assert.equal(await page.locator('#origin-application-state').innerText(), 'Blocks confirmed');
  assert.equal(await page.locator('#origin-confirmed-counts').innerText(), '3 devices · 2 addresses');
  await snapshot('distribution-confirmed');
  value = {...value, state: 'pending', reason: 'session_changed', applied_ip_count: null, applied_device_count: null, last_verified_at: null};
  await refresh(); assert.equal(await page.locator('#origin-confirmed-counts').innerText(), 'Not confirmed');
  assert.equal(await page.locator('#origin-application-state').innerText(), 'Waiting for confirmation', 'Restarted transfer service needs current-session proof');
  // Keyboard operation reaches the same review button; no mouse-only confirmation.
  await page.locator('#origin-max_new_devices').focus(); await page.keyboard.press('Tab');
  assert.equal(await page.locator('#origin-apply').evaluate(node => document.activeElement === node), true);
  mode = 'hold'; const arrived = new Promise(resolve => {reached = resolve;});
  await page.keyboard.press('Enter'); await arrived;
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Inventory', exact: true}).click();
  await held.fulfill(response(preview(writes.at(-1).body))); await idle();
  assert.equal(await page.evaluate(() => window.irisPolicies.origin.state.preview), null);
  assert.equal(await page.evaluate(() => window.irisInventory.state.bulkBusy), false);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Distribution access: exact review/CAS, cancellation, shared-address refusal, unknown-write recovery, pending/application distinction, keyboard, mobile and CSP passed.');
} finally {await browser.close();}
