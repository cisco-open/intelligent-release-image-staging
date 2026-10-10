// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated browser fixtures. Never contact live devices or deployments.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], requests = [], devices = ['one', 'two', 'three'].map((device_id, index) => ({device_id, device_ip: '192.0.2.' + (index + 1), model: 'C8xxx', platform: 'iox', management_type: 'router-nat'}));
  let mode = 'ok', held, reached, csvMode = 'refused';
  const jobs = [], policy = {revision: 1, quarantine_assignments: [], roles_supported: true, roles: {defined: 0, restricted: 0, members: {}}, enforcement: {state: 'preflight-only'}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective)); });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const csv = url.pathname.endsWith('/import-csv'), body = csv ? request.postData() : request.method() === 'DELETE' ? null : request.postDataJSON();
        requests.push({url: url.pathname, method: request.method(), body});
        if (csv) {
          assert.equal(request.headers()['content-type'], 'text/csv');
          if (csvMode === 'refused') return route.fulfill({status: 422, json: {error: 'role_not_found', role: '<script>edge</script>', device_id: 'one'}});
          if (csvMode === 'hold') { held = route; reached(); return; }
          return route.fulfill({json: {imported: 2}});
        }
        if (url.pathname.endsWith('/onboard') || url.pathname.endsWith('/undeploy')) {
          const action = url.pathname.split('/').at(-1), device_id = url.pathname.split('/').at(-2), job_id = 'job-' + requests.length;
          jobs.push({id: job_id, device_id, action, state: 'done', started_at: 1, finished_at: 2});
          return route.fulfill({json: {job_id}});
        }
        if (mode === 'hold') { held = route; reached(); return; }
        if (mode === 'malformed') return route.fulfill({json: {}});
        if (request.method() === 'DELETE') return route.fulfill({status: url.pathname.endsWith('/two') ? 207 : 200,
          json: {deleted: true, degraded: url.pathname.endsWith('/two') ? ['records'] : []}});
        assert.ok(url.pathname.endsWith('/adopt')); return route.fulfill({json: {record_id: 'saved'}});
      }
      if (url.pathname.endsWith('/export-csv') || url.pathname.endsWith('/example-csv')) return route.fulfill({contentType: 'text/csv', body: 'device_id,device_ip\none,192.0.2.1\n'});
      const fixtures = {'/api/v1/session': {username: 'Action fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/devices': {devices, total: devices.length, offset: 0, revision: 1, now: 2000000000}, '/api/v1/images': {images: []},
        '/api/v1/credentials': {profiles: []}, '/api/v1/peer-policy': policy, '/api/v1/onboard/jobs': {jobs, now: 2000000000}, '/api/v1/schedules': {schedules: []}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try { return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}}); }
    catch { return route.fulfill({status: 404, body: ''}); }
  });
  const select = ids => page.evaluate(ids => window.irisInventory.changeSelection(new Set(ids)), ids);
  const more = async id => { await page.locator('#more-menu-btn').click(); await page.locator('#' + id).click(); };
  const message = pattern => page.waitForFunction(source => new RegExp(source).test(document.getElementById('dev-status').textContent), pattern.source);
  await page.goto('http://iris.test/#devices'); await page.waitForFunction(() => window.irisInventory?.state.readOk);
  await select(['one', 'two']); await page.locator('#onboard-selected').click();
  assert.equal(await page.locator('#onboard-telemetry').isChecked(), true); assert.equal(await page.locator('#onboard-telemetry-stream').isChecked(), false);
  assert.equal(await page.locator('#onboard-log').isChecked(), false); assert.equal(await page.locator('#onboard-telemetry').evaluate(el => el === document.activeElement), true);
  await page.locator('#onboard-confirm').focus(); await page.keyboard.press('Tab'); assert.equal(await page.locator('#onboard-modal-x').evaluate(el => el === document.activeElement), true);
  await page.keyboard.press('Escape'); assert.equal(await page.locator('#onboard-selected').evaluate(el => el === document.activeElement), true); assert.equal(requests.length, 0);
  await page.locator('#onboard-selected').click(); await page.locator('#onboard-telemetry').uncheck(); await page.locator('#onboard-telemetry-stream').check(); await page.locator('#onboard-log').check();
  await select(['three']); await page.locator('#onboard-modal details summary').click(); assert.match(await page.locator('#onboard-modal details').innerText(), /one.*two/s);
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    for (const selector of ['#onboard-modal .modal', '#onboard-modal-x', '#onboard-confirm']) {
      const box = await page.locator(selector).boundingBox(); assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= width && box.y + box.height <= height);
    }
    if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) { await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, 'inventory-actions-' + width + '.png')}); }
  }
  await page.setViewportSize({width: 1440, height: 1000}); await page.locator('#onboard-confirm').click(); await message(/Started onboard for 2/);
  assert.deepEqual(requests.map(row => row.url).sort(), ['/api/v1/devices/one/onboard', '/api/v1/devices/two/onboard']);
  assert.ok(requests.every(row => JSON.stringify(row.body) === JSON.stringify({telemetry: false, telemetry_stream: true, log: true})));
  await page.locator('#batch-close').click(); await page.locator('#undeploy-selected').click();
  assert.equal(await page.locator('#undeploy-force').isChecked(), false); assert.equal(await page.locator('#undeploy-log').isChecked(), false);
  await page.setViewportSize({width: 320, height: 568});
  for (const selector of ['#undeploy-modal .modal', '#undeploy-modal-x', '#undeploy-confirm']) {
    const box = await page.locator(selector).boundingBox(); assert.ok(box && box.y >= 0 && box.y + box.height <= 568);
  }
  if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, 'inventory-actions-undeploy-320.png')});
  await page.setViewportSize({width: 1440, height: 1000});
  await page.locator('#undeploy-force').check(); await page.locator('#undeploy-log').check();
  assert.match(await page.locator('#undeploy-force-help').innerText(), /IRIS-marked VirtualPortGroups and related NAT settings on routers\. Keeps unrelated networking/);
  page.once('dialog', dialog => { assert.match(dialog.message(), /1 device.*Force cleanup.*IRIS-marked VirtualPortGroups.*Keeps unrelated networking/s); dialog.dismiss(); });
  await page.locator('#undeploy-confirm').click(); assert.equal(requests.length, 2);
  await page.locator('#undeploy-selected').click(); page.once('dialog', dialog => dialog.accept()); await page.locator('#undeploy-confirm').click(); await message(/Started undeploy for 1/);
  assert.deepEqual(requests.at(-1).body, {force: true, log: true}); await page.locator('#batch-close').click();
  await select(['one', 'two']); page.once('dialog', dialog => { assert.match(dialog.message(), /one, two.*does NOT undeploy/s); dialog.accept(); }); await more('delete-selected'); await message(/Delete completed for 1\/2.*two: partial.*records/);
  assert.deepEqual(await page.evaluate(() => window.irisInventory.selectedIds()), ['two']);
  mode = 'malformed'; page.once('dialog', dialog => dialog.accept()); await more('adopt-selected'); await message(/Adopt completed for 0\/1.*unknown/);
  assert.deepEqual(requests.at(-1).body, {acknowledge_adopt: true});
  const csvFile = {name: 'devices.csv', mimeType: 'text/csv', buffer: Buffer.from('device_id\none\n')};
  await page.locator('#csv-file').setInputFiles(csvFile); await page.waitForFunction(() => window.irisInventoryActions.state.csvFailed);
  assert.match(await page.locator('#csv-import-status').innerText(), /<script>edge<\/script>.*Define the role/); assert.equal(await page.locator('#csv-import-status script').count(), 0);
  await page.evaluate(() => window.irisInventory.refresh()); assert.match(await page.locator('#csv-import-status').innerText(), /Define the role/);
  csvMode = 'ok'; await page.locator('#csv-file').setInputFiles(csvFile); await page.getByText('Imported 2 device(s).', {exact: true}).waitFor();
  assert.equal(await page.locator('#csv-file').inputValue(), '');
  await page.locator('#csv-menu-btn').click(); const download = page.waitForEvent('download'); await page.locator('#export-csv').click();
  const exported = await download; assert.equal(exported.suggestedFilename(), 'devices.csv'); assert.equal(await exported.failure(), null);
  assert.equal(await fs.readFile(await exported.path(), 'utf8'), 'device_id,device_ip\none,192.0.2.1\n');
  const arrived = new Promise(resolve => { reached = resolve; }); csvMode = 'hold'; await page.locator('#csv-file').setInputFiles(csvFile); await arrived;
  assert.equal(await page.locator('#onboard-selected').isDisabled(), true); assert.equal(await page.locator('#dev-rows .cred').first().isDisabled(), true);
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  await held.fulfill({json: {imported: 2}}); await page.waitForFunction(() => !window.irisInventoryActions.state.busy);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Inventory actions: captured job options/targets, retirement partial/unknown, CSV feedback/locks/download, keyboard/mobile and CSP passed.');
} finally { await browser.close(); }
