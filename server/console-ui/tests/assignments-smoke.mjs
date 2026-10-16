// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated API fixtures, never real device actions.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], reads = [], devices = ['one', 'two', 'three'].map((device_id, i) => ({device_id, device_ip: `192.0.2.${i + 1}`,
    platform: 'iox', model: 'C8xxx', management_type: 'router-nat', assigned_image_ids: i === 0 ? ['A', 'B'] : i === 1 ? ['A'] : ['gone', 'bad']}));
  const images = [{id: 'A', filename: '<img onerror=alert(1)>.bin'}, {id: 'B', filename: 'B'}, {id: 'bad', quarantined: true},
    ...Array.from({length: 10}, (_, i) => ({id: 'extra-' + i}))];
  const policy = {revision: 1, roles_supported: true, quarantine_assignments: [], roles: {defined: 0, restricted: 0, members: {}},
    enforcement: {state: 'preflight-only'}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
  let mode = 'ok', held, arrived, profilesOk = true;
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective)); });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const body = request.postDataJSON(); writes.push({url: url.pathname, body, method: request.method()});
        if (mode === 'hold') { held = route; arrived(); return; }
        if (mode === 'lost') return route.abort('failed');
        if (mode === 'malformed') return route.fulfill({json: {}});
        if (url.pathname.endsWith('/assign')) {
          const device = devices.find(row => row.device_id === decodeURIComponent(url.pathname.split('/').at(-2)));
          if (JSON.stringify(body.expect_image_ids) !== JSON.stringify(device.assigned_image_ids)) return route.fulfill({status: 409,
            json: {error: 'assignment_conflict', assigned_image_ids: device.assigned_image_ids}});
          device.assigned_image_ids = body.image_ids;
          return route.fulfill({json: {ok: true, assigned_image_ids: body.image_ids, removed_image_ids: []}});
        }
        assert.equal(url.pathname, '/api/v1/devices/bulk-credential');
        return route.fulfill({json: {ok: true, applied: body.device_ids.length - (mode === 'partial' ? 1 : 0), failed: mode === 'partial' ? {two: '<not found>'} : {}}});
      }
      reads.push(url.pathname);
      if (!profilesOk && url.pathname === '/api/v1/credentials') return route.fulfill({status: 503, json: {error: 'unavailable'}});
      const fixtures = {
        '/api/v1/session': {username: 'Assignment fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/devices': {devices, total: 3, offset: 0, revision: 1, now: 2000000000}, '/api/v1/images': {images},
        '/api/v1/credentials': {profiles: [{id: 'operator'}, {id: '__none'}]}, '/api/v1/peer-policy': policy,
        '/api/v1/onboard/jobs': {jobs: [], now: 2000000000}, '/api/v1/schedules': {schedules: []},
      };
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try { return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}}); }
    catch { return route.fulfill({status: 404, body: ''}); }
  });
  const selection = ids => page.evaluate(ids => window.irisInventory.changeSelection(new Set(ids)), ids);
  const openRow = async id => { await page.locator(`#dev-rows tr[data-id="${id}"] .assign-btn`).click(); await page.waitForFunction(() => window.irisAssignments.snapshot().ready); };
  const check = id => page.locator(`#img-picker-rows input[value="${id}"]`);
  const close = () => page.locator('#img-picker-cancel').click();
  const waitMessage = expression => page.waitForFunction(source => new RegExp(source).test(document.getElementById('dev-status').textContent), expression.source);
  const openCredentials = async () => { await page.locator('#more-menu-btn').click(); await page.locator('#set-cred-selected').click(); await page.locator('#cred-modal').waitFor(); };
  await page.goto('http://iris.test/#devices'); await page.waitForFunction(() => window.irisInventory?.snapshot().readOk);
  await openRow('one'); assert.equal(await page.locator('#img-picker-cancel').evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#img-picker img').count(), 0); assert.match(await page.locator('#img-picker-rows').innerText(), /<img onerror=alert\(1\)>/);
  assert.deepEqual(await page.locator('#img-picker-rows input:checked').evaluateAll(rows => rows.map(row => row.value)), ['A', 'B']);
  for (let i = 0; i < 8; i++) await check('extra-' + i).check();
  assert.equal(await page.locator('#img-picker-count').innerText(), '10/10'); assert.equal(await check('extra-8').isDisabled(), true);
  await check('extra-0').uncheck(); assert.equal(await check('extra-8').isEnabled(), true);
  await page.locator('#img-picker-apply').focus(); await page.keyboard.press('Tab');
  assert.equal(await page.locator('#img-picker-x').evaluate(el => el === document.activeElement), true, 'Forward Tab stays inside dialog');
  await page.keyboard.press('Shift+Tab'); assert.equal(await page.locator('#img-picker-apply').evaluate(el => el === document.activeElement), true);
  await page.keyboard.press('Escape'); await page.locator('#img-picker').waitFor({state: 'hidden'});
  assert.equal(await page.locator('#dev-rows tr[data-id="one"] .assign-btn').evaluate(el => el === document.activeElement), true);
  assert.equal(writes.length, 0);
  await openRow('three'); assert.equal(await check('gone').isChecked(), true); assert.equal(await check('gone').isDisabled(), true);
  await check('bad').uncheck(); assert.equal(await check('bad').isDisabled(), true); await close();
  await selection(['one', 'two']); await page.locator('#assign-images-selected').click(); await page.waitForFunction(() => window.irisAssignments.snapshot().ready);
  await page.locator('#img-picker-note').waitFor(); await page.locator('#img-picker .assignment-targets summary').click();
  await selection(['three']); assert.match(await page.locator('#img-picker .assignment-targets').innerText(), /2 reviewed devices.*one.*two/s);
  for (const [width, height] of [[1440, 1000], [390, 1000], [320, 1000], [320, 568]]) {
    await page.setViewportSize({width, height}); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    for (const selector of ['#img-picker .modal', '#img-picker-x', '#img-picker-cancel', '#img-picker-review', '#img-picker-apply']) {
      const box = await page.locator(selector).boundingBox();
      assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= width && box.y + box.height <= height, selector + ' stays reachable');
    }
    if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) { await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, `assignments-${width}${height < 1000 ? '-short' : ''}.png`)}); }
  }
  await page.setViewportSize({width: 1440, height: 1000});
  page.once('dialog', dialog => { assert.match(dialog.message(), /removed/); dialog.dismiss(); });
  await page.locator('#img-picker-apply').click(); assert.equal(writes.length, 0); assert.equal(await page.locator('#img-picker').isVisible(), true);
  page.once('dialog', dialog => dialog.accept()); await page.locator('#img-picker-apply').click(); await page.locator('#img-picker').waitFor({state: 'hidden'});
  assert.deepEqual(writes.map(write => write.url).sort(), ['/api/v1/devices/one/assign', '/api/v1/devices/two/assign']);
  assert.deepEqual(writes.find(write => write.url.endsWith('one/assign')).body, {image_ids: ['A'], expect_image_ids: ['A', 'B']});
  assert.deepEqual(writes.find(write => write.url.endsWith('two/assign')).body, {image_ids: ['A'], expect_image_ids: ['A']});
  await waitMessage(/2\/2/);
  await openRow('one'); devices[0].assigned_image_ids = ['B']; await page.locator('#img-picker-apply').click(); await waitMessage(/one: conflict/);
  assert.equal(await page.locator('#img-picker-apply').isDisabled(), true); const beforeReview = writes.length;
  await page.locator('#img-picker-review').click(); await page.waitForFunction(() => window.irisAssignments.snapshot().ready);
  assert.equal(await check('B').isChecked(), true); assert.equal(await check('A').isChecked(), false); assert.equal(writes.length, beforeReview);
  mode = 'malformed'; await page.locator('#img-picker-apply').click(); await waitMessage(/one: unknown/); assert.equal(writes.length, beforeReview + 1);
  assert.equal(await page.locator('#img-picker-apply').isDisabled(), true); await close();
  await selection(['one', 'two']); mode = 'partial'; await openCredentials();
  assert.equal(await page.locator('#cred-selected').evaluate(el => el === document.activeElement), true);
  await page.locator('#apply-cred-selected').click(); await page.getByText('Choose a credential profile, or no credential to clear.', {exact: true}).waitFor();
  const count = writes.length; await page.locator('#cred-selected').selectOption('profile:__none'); await selection(['three']);
  profilesOk = false; await page.evaluate(() => window.irisInventory.refresh()); assert.equal(await page.locator('#apply-cred-selected').isDisabled(), true);
  assert.equal(await page.locator('#cred-selected').inputValue(), 'profile:__none');
  profilesOk = true; await page.evaluate(() => window.irisInventory.refresh());
  await page.locator('#apply-cred-selected').click(); await waitMessage(/1\/2.*two \(<not found>\)/);
  assert.equal(writes.length, count + 1); assert.deepEqual(writes.at(-1), {url: '/api/v1/devices/bulk-credential', method: 'POST', body: {device_ids: ['one', 'two'], credential_profile_id: '__none'}});
  assert.equal(await page.locator('#cred-modal-msg').getAttribute('class'), 'err');
  await page.locator('#cred-modal-cancel').click(); assert.equal(await page.locator('#more-menu-btn').evaluate(el => el === document.activeElement), true);
  await openCredentials(); await page.locator('#cred-selected').selectOption('clear');
  page.once('dialog', dialog => { assert.match(dialog.message(), /1 reviewed device/); dialog.dismiss(); }); await page.locator('#apply-cred-selected').click();
  assert.equal(writes.length, count + 1); await page.locator('#cred-modal-cancel').click();
  await openRow('one'); mode = 'hold'; const reached = new Promise(resolve => { arrived = resolve; }); await page.locator('#img-picker-apply').click(); await reached;
  assert.equal(await page.locator('#onboard-selected').isDisabled(), true); assert.equal(await page.locator('#img-picker-apply').isDisabled(), true);
  assert.equal(await page.locator('#img-picker-cancel').evaluate(el => el === document.activeElement), true, 'Pending write retains dialog focus');
  await page.locator('#img-picker-cancel').press('Tab');
  assert.equal(await page.locator('#img-picker-x').evaluate(el => el === document.activeElement), true);
  await close(); await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('view-devices').hidden); const readCount = reads.filter(path => path === '/api/v1/devices').length;
  await held.fulfill({json: {ok: true, assigned_image_ids: ['B'], removed_image_ids: []}}); await page.waitForFunction(() => !window.irisAssignments.operation);
  assert.equal(reads.filter(path => path === '/api/v1/devices').length, readCount);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Assignments: captured targets, exact CSRF/CAS, mixed/empty confirmation, quarantine/cap, conflicts/unknowns, bulk credential outcomes, locks, keyboard focus, mobile and CSP passed.');
} finally { await browser.close(); }
