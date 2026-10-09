// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built Console, real React and browser CSP. APIs are intercepted; this is not
// live platform or native package-signature acceptance qualification.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {setupFixture, verificationFixture} from './setup-packages-fixtures.mjs';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], reads = []; let setup = setupFixture(), failure = '', held, reached;
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {writes.push(url.pathname); return route.fulfill({status: 500, json: {error: 'No writes in this fixture'}});}
      reads.push(url.pathname);
      if (url.pathname.endsWith('/settings/setup-status')) {
        if (failure === 'hold') {held = route; reached(); return;}
        if (failure === 'malformed') return route.fulfill({json: {packages: {state: 'ok', items: []}}});
        if (failure === 'http') return route.fulfill({status: 503, json: {error: 'unavailable'}});
        return route.fulfill({json: setup});
      }
      const fixtures = {'/api/v1/session': {username: 'Setup fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/settings/image-verification': verificationFixture('daily'),
        '/api/v1/settings': {version: 'fixture', admin_username: 'operator', host_ip: '192.0.2.1', ports: {tracker: 6969, catalog: 8443, artifacts: 8000, swarm: 8080, console: 8082}, sessions: {active: 1, idle_ttl_minutes: 30}, gui_cert: {source: 'built-in'}, trust: [], ca_trust: {url: '', auto: false}, telemetry_destination: {source: 'env', effective_endpoint: '', effective_enabled: false}, audit_export: {host: '', user: '', port: 22, path: '', age_recipient: '', auto: false, password_set: false}}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream', headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const idle = () => page.waitForFunction(() => window.irisSetupPackages && !window.irisSetupPackages.state.loading);
  const visit = async route => {await page.evaluate(route => {location.hash = route;}, route); await page.waitForFunction(route => location.hash === route && window.irisSetupPackages.state.mode === (route === '#setup' ? 'wizard' : route.endsWith('/packages') ? 'packages' : 'setup'), route); await idle();};
  await page.goto('http://iris.test/#settings/packages'); await idle();
  assert.equal(await page.locator('#device-packages-table tbody tr').count(), 4);
  assert.match(await page.locator('#settings-pane-packages').innerText(), /does not authenticate that manifest or verify native package signatures/);
  assert.equal(reads.includes('/api/v1/settings/image-verification'), false, 'Package-only review has no unrelated verification read');
  for (const mode of ['malformed', 'http']) {
    failure = mode; await page.locator('#device-packages-recheck').click(); await idle();
    assert.match(await page.locator('#device-packages-chip').innerText(), /Cannot determine/);
    assert.equal(await page.locator('#device-packages-table tbody tr').count(), 0);
    assert.match(await page.locator('#device-packages-msg').innerText(), /cannot be determined/);
    failure = ''; await page.locator('#device-packages-recheck').click(); await idle();
  }
  setup.packages.state = 'unknown'; setup.packages.reason = 'served-vs-distributed-mismatch';
  await page.locator('#device-packages-recheck').click(); await idle();
  assert.match(await page.locator('#device-packages-remedy').innerText(), /Fix the certificate copies/);
  assert.doesNotMatch(await page.locator('#device-packages-remedy').innerText(), /tools\//);
  await page.locator('#setup-nudge').waitFor({state: 'visible'}); await page.locator('#setup-nudge-dismiss').click();
  assert.equal(await page.locator('#setup-nudge').isVisible(), false);
  setup = setupFixture(); setup.packages.items[0].detail = '<img src=x onerror=alert(1)>';
  await visit('#settings/setup'); assert.equal(await page.locator('#setup-pkg-table img').count(), 0);
  assert.match(await page.locator('#setup-pkg-table').innerText(), /<img src=x onerror=alert\(1\)>/);
  assert.match(await page.locator('#setup-iv-chip').innerText(), /Configured.*no successful run yet/);
  await visit('#setup'); assert.equal(await page.locator('.wz-steplist-item').count(), 3);
  assert.equal(await page.locator('.wz-steplist-item[aria-current=step]').getAttribute('data-step'), '2');
  await page.locator('.wz-steplist-item').filter({hasText: 'Telemetry'}).click();
  await page.locator('#wz-td-mount #td-form').waitFor();
  await page.locator('.wz-steplist-item').filter({hasText: 'Device packages'}).focus(); await page.keyboard.press('Enter');
  assert.equal(await page.locator('#wz-step-packages h3').evaluate(node => node === document.activeElement), true);
  assert.equal(await page.locator('#wz-pkg-table tbody tr').count(), 4);
  await page.locator('.wz-steplist-item').filter({hasText: 'Image verification'}).click(); await page.locator('#wz-iv-mount #iv-mode').waitFor();
  for (const route of ['#settings/setup', '#settings/packages', '#setup']) {
    await visit(route);
    if (route === '#setup') await page.locator('.wz-steplist-item').filter({hasText: 'Device packages'}).click();
    for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
      await page.setViewportSize({width, height});
      const overflow = await page.evaluate(() => [...document.querySelectorAll('body *')].filter(node => {const rect = node.getBoundingClientRect(); return rect.width && rect.right > innerWidth + 1 && getComputedStyle(node).position !== 'fixed' && !node.closest('.table-scroll');}).map(node => node.id || node.className).slice(-12));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, route + ' fits ' + width + ': ' + overflow.join(', '));
      if (process.env.IRIS_UI_SCREENSHOTS) {await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'setup-' + route.replace(/[#/]/g, '-') + '-' + width + '.png')});}
    }
  }
  await page.setViewportSize({width: 1440, height: 1000}); await visit('#settings/packages');
  failure = 'hold'; const pending = new Promise(resolve => {reached = resolve;}); await page.locator('#device-packages-recheck').click(); await pending;
  assert.match(await page.locator('#device-packages-chip').innerText(), /Cannot determine/);
  await page.evaluate(() => {location.hash = '#overview';}); await page.locator('#view-overview').waitFor({state: 'visible'});
  await held.fulfill({json: setup}).catch(() => {}); failure = ''; await visit('#settings/packages');
  assert.equal(await page.locator('#device-packages-table tbody tr').count(), 4);
  assert.deepEqual(writes, []); assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Setup/packages: native-shaped readiness, fail-closed reads, navigation, shared forms, keyboard, responsive and CSP checks passed.');
} finally {await browser.close();}
