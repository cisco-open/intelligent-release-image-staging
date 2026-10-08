// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Shipped assets, mocked endpoints. No live policy or device is changed.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], prompts = [], devices = ['one', 'two', 'three'].map((device_id, i) => ({device_id, device_ip: '192.0.2.' + (i + 1), model: 'C8xxx', platform: 'iox', management_type: 'router-nat'}));
  let previewMode = 'ok', commitMode = 'ok', quarantineMode = 'empty', held, reached, reads = 0;
  const policy = {revision: 7, quarantine_assignments: [], roles_supported: true, roles: {defined: 2, restricted: 1, members: {boat: 2, '<script>role</script>': 0}},
    enforcement: {state: 'preflight-only'}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
  const preview = () => ({ok: true, applied: 2, failed: {}, dry_run: true, revision: policy.revision + 1, member_delta: 2,
    origin_access_lost: 1, empty_permitted_sets: 0, role_pairs_stopped: 1, qos_changed: true, requires_confirmation: true, confirm_token: 'checked-preview'});
  page.on('pageerror', error => errors.push(error.message)); page.on('dialog', async dialog => {prompts.push(dialog.message()); await dialog.accept();});
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const body = request.postDataJSON(); writes.push({path: url.pathname + url.search, body, headers: request.headers()});
        if (url.pathname === '/api/v1/devices/bulk-role') {
          if (url.searchParams.get('dry_run') === '1') {
            if (previewMode === 'hold') {held = route; reached(); return;}
            return route.fulfill({json: preview()});
          }
          if (commitMode === 'empty') return route.fulfill({json: {}});
          return route.fulfill({json: {ok: commitMode === 'ok', applied: commitMode === 'ok' ? 2 : 1,
            failed: commitMode === 'ok' ? {} : {two: '<script>refused</script>'}, partial: commitMode !== 'ok', dry_run: false,
            revision: ++policy.revision, role_drift: {count: commitMode === 'ok' ? 0 : 1}}});
        }
        assert.ok(url.pathname.startsWith('/api/v1/peer-policy/quarantine/'));
        return route.fulfill({json: quarantineMode === 'empty' ? {} : {ok: true, quarantined: body.quarantined, revision: ++policy.revision}});
      }
      if (url.pathname === '/api/v1/peer-policy') reads++;
      const fixtures = {'/api/v1/session': {username: 'Role fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/devices': {devices, total: devices.length, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []}, '/api/v1/peer-policy': policy,
        '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const select = ids => page.evaluate(ids => window.irisInventory.changeSelection(new Set(ids)), ids);
  const action = async id => {await page.locator('#more-menu-btn').click(); await page.locator('#' + id).click();};
  const open = () => action('set-role-selected');
  const focus = selector => page.locator(selector).evaluate(el => el === document.activeElement);
  const idle = () => page.waitForFunction(() => !window.irisRoleActions.state.busy && !window.irisInventory.state.loading);
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png')});}};
  await page.goto('http://iris.test/#devices'); await page.waitForFunction(() => window.irisInventory?.state.readOk);
  await select(['one', 'two']); await open(); assert.equal(await focus('#role-selected'), true);
  await page.locator('#apply-role-selected').focus(); await page.keyboard.press('Tab'); assert.equal(await focus('#role-modal-x'), true);
  await page.keyboard.press('Escape'); assert.equal(await focus('#more-menu-btn'), true); assert.equal(writes.length, 0);
  await open(); await page.locator('#role-selected').selectOption('boat'); await select(['three']);
  policy.degraded = true; await page.locator('#apply-role-selected').focus(); await page.evaluate(() => window.irisInventory.refresh());
  assert.equal(await page.locator('#apply-role-selected').isDisabled(), true);
  assert.match(await page.locator('#inventory-role-capability-banner').innerText(), /degraded/);
  assert.equal(await focus('#role-modal-x'), true);
  policy.degraded = false; await page.evaluate(() => window.irisInventory.refresh());
  await page.locator('#role-modal summary').click(); assert.match(await page.locator('#role-modal details').innerText(), /one.*two/s);
  assert.equal(await page.locator('#role-modal-count').innerText(), '2 reviewed');
  await page.locator('#role-selected').focus(); await page.evaluate(() => window.irisInventory.refresh()); assert.equal(await focus('#role-selected'), true);
  await page.locator('#apply-role-selected').click(); await page.waitForFunction(() => !!window.irisRoleActions.state.preview && !window.irisRoleActions.state.busy);
  assert.equal(await focus('#apply-role-selected'), true); assert.match(await page.locator('#role-preview').innerText(), /Membership changes: 2.*QoS policy changed: yes/s);
  assert.equal(await page.locator('#dev-rows .cred').first().isDisabled(), true); assert.equal(await page.locator('#role-modal script').count(), 0);
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    for (const selector of ['#role-modal .modal', '#role-modal-x', '#apply-role-selected', '#role-modal-cancel']) {
      const box = await page.locator(selector).boundingBox(); assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= width && box.y + box.height <= height, selector);
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await snapshot('role-preview-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000}); policy.revision = 99; await page.evaluate(() => window.irisInventory.refresh());
  await page.locator('#apply-role-selected').click(); await idle(); assert.equal(await page.locator('#role-modal').isHidden(), true);
  assert.deepEqual(writes.slice(0, 2).map(row => row.body.device_ids), [['one', 'two'], ['one', 'two']]);
  assert.deepEqual(writes.slice(0, 2).map(row => row.headers['if-match']), ['"iris-peer-policy-7"', '"iris-peer-policy-7"']);
  assert.equal(writes[1].body.confirm_token, 'checked-preview'); await page.locator('#dev-status').getByText(/2\/2/).waitFor();
  await select(['one', 'two']); await open(); await page.locator('#role-selected').selectOption('__none');
  await page.locator('#apply-role-selected').click(); await idle(); commitMode = 'partial'; await page.locator('#apply-role-selected').click(); await idle();
  assert.match(await page.locator('#role-modal-msg').innerText(), /1\/2.*two.*<script>refused<\/script>.*drift: 1/);
  assert.equal(await page.locator('#role-modal script').count(), 0); assert.equal(writes[3].body.role, null);
  commitMode = 'empty'; await page.locator('#apply-role-selected').click(); await idle(); await page.locator('#apply-role-selected').click(); await idle();
  assert.equal(await page.locator('#apply-role-selected').isDisabled(), true); assert.match(await page.locator('#role-modal-msg').innerText(), /may have been saved/);
  const count = writes.length; await page.getByRole('button', {name: 'Refresh policy before retrying'}).click();
  await page.waitForFunction(() => !window.irisRoleActions.state.reviewRequired); assert.equal(writes.length, count);
  await page.locator('#role-modal-cancel').click(); await action('quarantine-selected'); await idle();
  assert.match(prompts[0], /one, two/); assert.match(await page.locator('#dev-status').innerText(), /0\/2.*one: unknown.*two: not attempted/);
  assert.equal(writes.length, count + 1);
  quarantineMode = 'ok'; await action('release-selected'); await idle(); assert.match(await page.locator('#dev-status').innerText(), /Release intent saved for 2\/2/);
  assert.equal(writes.at(-1).body.if_revision, writes.at(-2).body.if_revision + 1);
  await open(); await page.locator('#role-selected').selectOption('boat');
  const arrived = new Promise(resolve => {reached = resolve;}); previewMode = 'hold'; await page.locator('#apply-role-selected').click(); await arrived;
  assert.equal(await focus('#role-modal-x'), true); await page.locator('#role-modal-x').click();
  assert.equal(await page.locator('#dev-rows .cred').first().isDisabled(), true);
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  // Policies has its own read; wait for it before measuring late Inventory work.
  await page.waitForFunction(() => !document.getElementById('view-policies').hidden); await page.waitForTimeout(100);
  const before = reads; await held.fulfill({json: preview()}); await idle(); assert.equal(reads, before); assert.equal(await page.locator('#role-modal').isHidden(), true);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Role actions: captured targets, CSRF/CAS/confirmation, partial/unknown results, serial quarantine, locks, focus, mobile and CSP passed.');
} finally {await browser.close();}
