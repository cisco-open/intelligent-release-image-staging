// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built Console with intercepted APIs: no lab services or external destinations.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], jobReads = [];
  let failure = '', jobState = 'running', hold, reached, accept = true;
  const settings = {version: 'fixture', admin_username: 'operator', host_ip: '192.0.2.1',
    ports: {tracker: 6969, catalog: 8443, artifacts: 8000, swarm: 8080, console: 8082}, sessions: {active: 2, idle_ttl_minutes: 30},
    gui_cert: {source: 'built-in', subject: 'CN=fixture', not_after: '2036-10-08T00:00:00Z', fingerprint_sha256: 'ab'.repeat(32)},
    trust: [{name: 'fixture.pem', source: 'manual', cert_count: 1, subject: '<img src=x onerror=alert(1)>', fingerprint_sha256: 'cd'.repeat(32)}],
    ca_trust: {url: 'https://www.cisco.com/security/pki/trs/ios.p7b', auto: false},
    telemetry_destination: {source: 'env', effective_endpoint: '', effective_enabled: false},
    audit_export: {host: '', user: '', port: 22, path: '', age_recipient: '', auto: false, password_set: false}};
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', dialog => accept ? dialog.accept() : dialog.dismiss());
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const r = route.request(), url = new URL(r.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (r.method() !== 'GET') {
        assert.equal(r.headers()['x-csrf-token'], 'fixture-only');
        writes.push({path: url.pathname, method: r.method(), body: r.postData() ? r.postDataJSON() : null});
        if (failure === 'hold') {hold = route; reached(); return;}
        if (failure === 'empty') return route.fulfill({json: {}});
        if (url.pathname.endsWith('/ca-trust/refresh')) return route.fulfill({json: {job: 'confirmed-ca-job'}});
        if (url.pathname.endsWith('/audit-export/run')) return route.fulfill({json: {job_id: 'confirmed-audit-job'}});
        if (url.pathname.endsWith('/trust')) return route.fulfill({json: {entry: settings.trust[0]}});
        if (url.pathname.endsWith('/gui-cert')) return route.fulfill({json: {gui_cert: settings.gui_cert, applied: false, deleted: true}});
        return route.fulfill({json: {ok: true, revoked: 1, deleted: true}});
      }
      if (/\/(ca-trust\/refresh|audit-export\/run)\//.test(url.pathname)) {
        jobReads.push(url.pathname); return route.fulfill({json: {state: jobState, certs: 3, detail: '4 events'}});
      }
      const fixtures = {'/api/v1/session': {username: 'Settings fixture', csrf: 'fixture-only'},
        '/api/v1/help': {version: 'fixture'}, '/api/v1/settings': settings,
        '/api/v1/settings/peer-tls': {mode: 'disabled', can_change: true, active_devices: 0, active_jobs: 0, origin: {state: 'running', active_mode: 'disabled'}},
        '/api/v1/settings/setup-status': {admin: {state: 'ok'}, telemetry: {state: 'unset', enabled: false, source: 'env'},
          packages: {state: 'absent', items: []}, image_verification: {state: 'unset'}},
        '/api/v1/devices': {devices: [], total: 0, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []},
        '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const idle = () => page.waitForFunction(() => !window.irisSettings.state.busy && !window.irisSettings.state.loading);
  const select = async pane => {await page.evaluate(pane => {location.hash = '#settings/' + pane;}, pane); await page.waitForFunction(pane => window.irisSettings.state.pane === pane && window.irisSettings.state.valid[pane], pane); await idle();};
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png')});}};
  await page.goto('http://iris.test/#settings/general'); await page.waitForFunction(() => window.irisSettings?.state.valid.general); await idle();
  for (const [id, text] of [['pw-cur', 'current-secret'], ['pw-new', 'next-secret'], ['pw-confirm', 'next-secret']]) await page.locator('#' + id).fill(text);
  failure = 'empty'; await page.locator('#pw-form button[type=submit]').click(); await idle();
  assert.match(await page.locator('#pw-msg').innerText(), /Sign in again/); assert.equal(await page.locator('#pw-new').inputValue(), '');
  assert.equal(await page.locator('#pw-form button[type=submit]').isDisabled(), true);
  await page.locator('#settings-review-pw').click(); assert.equal(writes.length, 1);
  failure = ''; await select('tls');
  assert.equal(await page.locator('#trust-rows img').count(), 0);
  assert.match(await page.locator('#trust-rows').innerText(), /<img src=x onerror=alert\(1\)>/);
  const cert = '-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----';
  const key = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nfixture\n-----END ENCRYPTED PRIVATE KEY-----';
  await page.locator('#cert-dropzone').focus();
  const choosing = page.waitForEvent('filechooser'); await page.keyboard.press('Enter');
  await (await choosing).setFiles({name: 'combined.pem', mimeType: 'text/plain', buffer: Buffer.from(cert + '\n' + key)});
  await page.locator('#cert-passphrase').waitFor(); assert.equal(await page.locator('#cert-pem').inputValue(), cert + '\n');
  await page.locator('#cert-passphrase').fill('key-secret');
  await page.locator('#ca-source').selectOption('custom'); await page.locator('#ca-url').fill('https://draft.example/roots.pem');
  await page.evaluate(() => window.irisSettings.refresh()); assert.equal(await page.locator('#ca-url').inputValue(), 'https://draft.example/roots.pem');
  failure = 'hold'; const pending = new Promise(resolve => {reached = resolve;});
  await page.locator('#cert-form button[type=submit]').click(); await pending;
  assert.equal(await page.locator('#cert-key').inputValue(), '');
  assert.equal(await page.locator('#cert-msg').evaluate(node => node === document.activeElement), true, 'Disabled action transfers focus to outcome');
  await hold.fulfill({json: {applied: false, gui_cert: settings.gui_cert}}); await idle(); failure = '';
  assert.match(await page.locator('#cert-msg').innerText(), /saved; restart/);
  assert.equal(await page.locator('#ca-url').inputValue(), 'https://draft.example/roots.pem', 'Unrelated save preserves draft');
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    for (const pane of ['general', 'tls', 'telemetry', 'audit']) {
      await select(pane);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, pane + ' fits ' + width);
      assert.equal(await page.locator('#settings-pane-' + pane + ' h3').evaluateAll(nodes => nodes.every(node => !!node.closest('.card'))), true);
      const controls = page.locator('#settings-pane-' + pane + ' input:not([hidden]):not([type=checkbox]), #settings-pane-' + pane + ' textarea, #settings-pane-' + pane + ' select');
      assert.equal(await controls.evaluateAll(nodes => nodes.every(node => node.labels.length > 0)), true, 'Persistent labels');
      await snapshot('settings-' + pane + '-' + width);
    }
  }
  await page.setViewportSize({width: 1440, height: 1000}); await select('tls');
  await page.locator('#ca-refresh').click(); await idle(); assert.equal(await page.locator('#ca-refresh').isDisabled(), true);
  assert.equal(writes.filter(row => row.path.endsWith('/ca-trust/refresh')).length, 1);
  await select('general'); const paused = jobReads.length; await page.waitForTimeout(1100); assert.equal(jobReads.length, paused);
  jobState = 'done'; await select('tls'); await page.locator('#ca-msg').getByText('Downloaded 3 certificate(s).', {exact: true}).waitFor();
  assert.equal(writes.filter(row => row.path.endsWith('/ca-trust/refresh')).length, 1);
  jobState = 'running'; await select('audit'); await page.locator('#ae-run').click(); await idle();
  await page.evaluate(() => {Object.defineProperty(document, 'hidden', {configurable: true, value: true}); document.dispatchEvent(new Event('visibilitychange'));});
  const hiddenReads = jobReads.length; await page.waitForTimeout(1100); assert.equal(jobReads.length, hiddenReads);
  jobState = 'done'; await page.evaluate(() => {delete document.hidden; document.dispatchEvent(new Event('visibilitychange'));});
  await page.locator('#ae-msg').getByText('Exported: 4 events', {exact: true}).waitFor();
  await select('telemetry'); await page.locator('#td-endpoint').fill('https://draft.example:4318');
  await page.evaluate(() => {location.hash = '#setup';}); await page.locator('.wz-steplist-item').filter({hasText: 'Telemetry'}).click();
  await page.locator('#wz-td-mount #td-form').waitFor(); await idle();
  assert.equal(await page.locator('#td-form').count(), 1); assert.equal(await page.locator('#td-endpoint').inputValue(), 'https://draft.example:4318');
  await select('telemetry'); assert.equal(await page.locator('#td-mount #td-form').count(), 1); assert.equal(await page.locator('#wz-td-mount #td-form').count(), 0);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Settings browser passed: checked writes, secrets, shared telemetry, jobs, focus, CSP, desktop/390px/320px.');
} finally {await browser.close();}
