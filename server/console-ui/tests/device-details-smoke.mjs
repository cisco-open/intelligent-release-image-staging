// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated browser fixtures. No deployment, credential or device is contacted.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  page.setDefaultTimeout(10000);
  const errors = [], writes = [], failures = new Set();
  let held = null, hold = false, writeMode = 'ok';
  const devices = [
    {device_id: 'edge-01', device_ip: '192.0.2.10', model: '8201', model_family: 'XR8000', platform: 'xr-appmgr',
      management_type: 'xr-host', assigned_image_ids: ['a', 'b'], staged_image_ids: ['a', 'b'], errored_image_ids: ['b'],
      current_image_id: 'a', last_seen: 2000000000, stage_state: 'error', stage_error: '<script>bad hash</script>'},
    {device_id: 'edge-02', device_ip: '192.0.2.11', model: 'C8xxx', model_family: 'C8xxx', platform: 'iox', assigned_image_ids: []},
  ];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    Date.now = () => 2000000000000;
    window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
  });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        writes.push([request.method(), url.pathname, request.headers()['x-csrf-token'], request.postDataJSON()]);
        assert.ok(url.pathname.endsWith('/forget-host-key'));
        if (writeMode === 'lost') return route.abort('failed');
        if (writeMode === 'reject') return route.fulfill({status: 400, json: {error: 'fixture rejected'}});
        return route.fulfill({json: {ok: true, peer: '192.0.2.10'}});
      }
      if (failures.has(url.pathname)) return route.fulfill({status: 503, json: {error: 'fixture unavailable'}});
      if (url.pathname.endsWith('/deployment') && url.pathname.includes('/devices/')) {
        const xr = url.pathname.includes('edge-01');
        return route.fulfill({json: {total: 1, record: {record_id: 'record-' + (xr ? 'xr' : 'xe'), state: 'active',
          timestamps: {planned_at: 1999999900, finished_at: 1999999990}, preflight: {status: 'ok', detected_model: xr ? '8201' : '<img src=x onerror=alert(1)>'},
          resolved: {management_type: xr ? 'xr-host' : 'router-nat', vpg_number: 0, platform: xr ? 'xr-appmgr' : 'iox',
            swarm_port: 6881, device_identity: 'device-' + (xr ? 'xr' : 'xe')}}}});
      }
      if (url.pathname === '/api/v1/deploy-logs') return route.fulfill({json: {logs: [{file: `${url.searchParams.get('device_id')}.log`,
        finished_at: 1999999900, action: 'onboard', state: 'done', rc: 0, size: 4096, previous_registration: true},
      {file: `${url.searchParams.get('device_id')}-undated.log`, finished_at: null, action: 'onboard', state: null,
        rc: null, size: 100, previous_registration: false}]}});
      if (url.pathname.startsWith('/api/v1/deploy-logs/')) {
        if (hold) { held = route; return; }
        return route.fulfill({body: url.pathname + '\n<script>hostile log</script>', contentType: 'text/plain'});
      }
      const fixtures = {
        '/api/v1/session': {username: 'Details fixture', csrf: 'fixture-only'},
        '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/devices': {devices, total: devices.length, offset: 0, now: 2000000000},
        '/api/v1/images': {images: [{id: 'a', filename: 'a.bin'}, {id: 'b', filename: 'b.bin', quarantined: true}]},
        '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: [], max_concurrent: 25},
        '/api/v1/peer-policy': {revision: 1, roles_supported: true, roles: {defined: 0, restricted: 0, members: {}},
          enforcement: {state: 'enforced', stale: false}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}},
      };
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
  const open = async id => {
    await page.locator(`#dev-rows tr[data-id="${id}"] button.dinfo`).first().click();
    await page.waitForFunction(id => document.getElementById('di-dev').textContent === id, id);
    await page.locator('#di-log-rows .dlog-view').first().waitFor();
  };
  const screenshot = async name => {
    const directory = process.env.IRIS_BROWSER_SCREENSHOT_DIR;
    if (directory) { await fs.mkdir(directory, {recursive: true}); await page.screenshot({path: path.join(directory, name + '.png'), fullPage: true}); }
  };
  await page.goto('http://iris.test/#devices');
  await open('edge-01');
  await page.locator('#di-rows').getByText('XR host', {exact: true}).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'di-close');
  assert.equal(await page.locator('#deploy-info-panel').getAttribute('aria-modal'), null);
  assert.match(await page.locator('#di-rows').innerText(), /8201.*last preflight/);
  assert.doesNotMatch(await page.locator('#di-rows').innerText(), /Management VLAN|App IP|NAT interface/);
  const images = await page.locator('#di-img-rows').innerText();
  assert.match(images, /a — a.bin\s+ready/); assert.match(images, /b — b.bin\s+error/);
  assert.match(images, /Last reported error\s+<script>bad hash<\/script>/);
  assert.match(await page.locator('#di-log-rows').innerText(), /previous device/);
  const undated = page.locator('#di-log-rows tr').last();
  assert.match(await undated.locator('td').first().innerText(), /Unknown/);
  assert.equal(await undated.locator('.badge-off').textContent(), 'unknown');
  assert.equal(await undated.locator('.badge-ok').count(), 0);
  assert.match(await page.locator('#di-boundary').innerText(), /1 image quarantined/);
  assert.equal(await page.locator('#di-boundary .boundary-step').nth(4).getAttribute('class'), 'boundary-step is-na');
  await screenshot('details-desktop');

  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#di-forget-host-key').click();
  assert.equal(writes.length, 0);
  assert.equal(await page.locator('#di-forget-host-key-status').innerText(), '');
  page.once('dialog', dialog => { assert.match(dialog.message(), /First verify.*trust and save any key/); return dialog.accept(); });
  await page.locator('#di-forget-host-key').click();
  await page.locator('#di-forget-host-key-status').getByText('Host key forgotten', {exact: false}).waitFor();
  assert.deepEqual(writes, [['POST', '/api/v1/devices/edge-01/forget-host-key', 'fixture-only', {}]]);
  writeMode = 'reject'; page.once('dialog', dialog => dialog.accept()); await page.locator('#di-forget-host-key').click();
  await page.locator('#di-forget-host-key-status').getByText('failed: fixture rejected', {exact: false}).waitFor();
  writeMode = 'lost'; page.once('dialog', dialog => dialog.accept()); await page.locator('#di-forget-host-key').click();
  await page.locator('#di-forget-host-key-status').getByText('outcome is unknown', {exact: false}).waitFor();
  assert.equal(writes.length, 3, 'lost mutation is not replayed');

  await page.locator('#di-log-rows .dlog-view').first().click();
  await page.locator('#di-log-text').getByText('<script>hostile log</script>', {exact: false}).waitFor();
  assert.equal(await page.locator('#deploy-info-panel script, #deploy-info-panel img').count(), 0);
  hold = true; await page.locator('#di-log-rows .dlog-view').first().click();
  await page.waitForFunction(() => document.getElementById('di-log-text').textContent.startsWith('Loading'));
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#deploy-info-panel').isVisible(), false);
  assert.equal(await page.evaluate(() => document.activeElement.matches('#dev-rows tr[data-id="edge-01"] button.dinfo')), true);
  await open('edge-02');
  await page.locator('#di-rows').getByText('VPG0', {exact: true}).waitFor();
  assert.match(await page.locator('#di-rows').innerText(), /<img src=x onerror=alert\(1\)>/);
  assert.equal(await page.locator('#deploy-info-panel img').count(), 0);
  hold = false; assert.ok(held); await held.fulfill({body: 'wrong device log'}).catch(() => {});
  assert.equal(await page.locator('#di-log-text').isVisible(), false);
  // Non-modal means keyboard focus can leave for the table behind the drawer.
  await page.locator('#di-log-rows .dlog-view').last().focus(); await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => !!document.activeElement.closest('#deploy-info-panel')), false);

  for (const width of [390, 320]) {
    await page.setViewportSize({width, height: 844});
    await page.locator('#deploy-info-panel .drawer-body').evaluate(node => { node.scrollTop = 0; });
    await page.locator('#di-close').focus();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const box = await page.locator('#di-close').boundingBox();
    assert.ok(box.x >= 0 && box.x + box.width <= width && box.y >= 56);
    const title = await page.locator('#deploy-info-panel .drawer-head > span').boundingBox();
    assert.ok(title.x + title.width <= box.x, 'the device title stays clear of Close');
    assert.ok(await page.locator('#deploy-info-panel .drawer-head > span').evaluate(node => node.scrollWidth <= node.clientWidth + 1),
      'the device title wraps inside its header');
    await screenshot(`details-mobile-${width}`);
  }
  await page.locator('#di-close').click(); await page.setViewportSize({width: 1440, height: 1000});
  failures.add('/api/v1/devices/edge-01/deployment'); await open('edge-01');
  await page.locator('#di-note').getByText('Deployment details unavailable', {exact: false}).waitFor();
  assert.equal(await page.locator('#di-log-rows .dlog-view').count(), 2, 'logs survive record failure');
  await page.evaluate(() => {
    window.originalDetailsOpener = document.querySelector('#dev-rows tr[data-id="edge-01"] button.dinfo');
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.waitForFunction(() => !window.originalDetailsOpener.isConnected);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.matches('#dev-rows tr[data-id="edge-01"] button.dinfo')), true,
    'closing after a table refresh focuses the replacement opener');
  await open('edge-01');
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Images', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('deploy-info-panel').hidden);
  assert.equal(writes.length, 3);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Device details: XR/XE evidence, image errors, confirmed CSRF writes, stale logs, failures, focus, mobile and CSP passed.');
} finally { await browser.close(); }
