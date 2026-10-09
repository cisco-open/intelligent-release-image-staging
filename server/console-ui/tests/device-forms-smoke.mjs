// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Shipped forms with isolated APIs; no device connections or real credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1050}});
  page.setDefaultTimeout(10000);
  const errors = [], writes = [], reads = [];
  let profiles = [{id: 'operator', name: '<img src=x onerror=alert(1)>', device_user: '<script>evil()</script>'}],
    unavailable = false, mode = 'ok', held, heldResolve, device, holdCredentialRead = false, credentialRead, credentialReadResolve;
  const policy = {revision: 1, roles_supported: true, quarantine_assignments: [], roles: {defined: 0, restricted: 0, members: {}},
    enforcement: {state: 'preflight-only', stale: false}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
  });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const body = request.method() === 'DELETE' ? null : request.postDataJSON();
        writes.push({url: url.pathname, method: request.method(), body});
        if (mode === 'hold') { held = route; heldResolve(); return; }
        if (mode === 'refused') return route.fulfill({status: 409, json: {error: 'fixture-only-password', detail: 'Do not echo this secret'}});
        if (mode === 'unavailable') return route.fulfill({status: 503, json: {code: 'management-api-unavailable'}});
        if (mode === 'lost') return route.abort('failed');
        if (mode === 'malformed') return route.fulfill({json: {}});
        if (url.pathname === '/api/v1/devices') { device = {...body, assigned_image_ids: []}; return route.fulfill({json: {device}}); }
        if (url.pathname === '/api/v1/credentials') {
          const profile = {id: body.id, name: body.name, device_user: body.device_user};
          profiles = [...profiles.filter(item => item.id !== profile.id), profile]; return route.fulfill({json: {profile}});
        }
        if (url.pathname.startsWith('/api/v1/credentials/') && request.method() === 'DELETE') {
          profiles = profiles.filter(item => item.id !== decodeURIComponent(url.pathname.split('/').at(-1)));
          return route.fulfill({json: {deleted: true}});
        }
        throw Error('Unexpected write ' + url.pathname);
      }
      reads.push(url.pathname);
      if (holdCredentialRead && url.pathname === '/api/v1/credentials' && !request.headers()['x-iris-poll']) {
        holdCredentialRead = false; credentialRead = route; credentialReadResolve(); return;
      }
      if (unavailable && url.pathname === '/api/v1/credentials') return route.fulfill({status: 503, json: {error: 'Unavailable'}});
      if (url.pathname === '/api/v1/install-options') return route.fulfill({json: {options: {C9xxx: ['guestshell', 'iox'], C8xxx: ['router', 'iox'], XR8000: ['xr-appmgr']}[url.searchParams.get('model')] || null}});
      const fixtures = {
        '/api/v1/session': {username: 'Device forms fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/devices': {devices: device ? [device] : [], total: device ? 1 : 0, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles}, '/api/v1/onboard/jobs': {jobs: [], now: 2000000000},
        '/api/v1/schedules': {schedules: []}, '/api/v1/peer-policy': policy,
      };
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'Fixture unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname))
      : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try { return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}}); }
    catch { return route.fulfill({status: 404, body: ''}); }
  });
  const refresh = () => page.evaluate(() => window.irisInventory.refresh());
  const credentialSave = () => page.locator('#cred-form').getByRole('button', {name: 'Save profile', exact: true}).click();
  const deviceSave = () => page.locator('#dev-form').getByRole('button', {name: 'Save device', exact: true}).click();
  const fillPasswords = async () => { await page.locator('#cf-pass').fill('fixture-only-password'); await page.locator('#cf-pass2').fill('fixture-only-password'); };
  const outcome = (id, expression) => page.waitForFunction(({id, source}) => new RegExp(source).test(document.getElementById(id).textContent), {id, source: expression.source});
  await page.goto('http://iris.test/#devices'); await page.waitForFunction(() => window.irisInventory?.snapshot().readOk);
  await page.locator('#add-dev').click(); await page.locator('#df-id').waitFor();
  assert.equal(await page.locator('#df-id').evaluate(el => el === document.activeElement), true);
  await page.locator('#df-id').fill('new-device'); await page.locator('#df-ip').fill('192.0.2.10');
  for (const [management, visible] of [['routed', ['df-vlan', 'df-svi', 'df-guest', 'df-mask', 'df-gateway']],
    ['inband', ['df-vlan', 'df-guest', 'df-mask', 'df-gateway']], ['router-routed', ['df-vpg', 'df-guest', 'df-mask', 'df-gateway']],
    ['router-nat', ['df-vpg', 'df-nat-interface', 'df-guest', 'df-mask', 'df-gateway']], ['xr-host', []]]) {
    await page.locator('#df-management-type').selectOption(management);
    for (const id of ['df-vlan', 'df-svi', 'df-vpg', 'df-nat-interface', 'df-guest', 'df-mask', 'df-gateway']) {
      assert.equal(await page.locator(`label[for="${id}"]`).isVisible(), visible.includes(id), 'Whole label/control is management-specific');
    }
  }
  await page.locator('#df-model').selectOption('XR8000'); await outcome('df-platform-hint', /^$/);
  assert.equal(await page.locator('#df-platform').inputValue(), 'xr-appmgr');
  await page.locator('#df-cred').selectOption('operator'); await page.locator('#df-ip').focus(); const inputHandle = await page.locator('#df-ip').elementHandle();
  await refresh(); assert.equal(await inputHandle.evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#df-ip').inputValue(), '192.0.2.10');
  unavailable = true; await refresh(); await deviceSave(); await outcome('df-err', /Credential unavailable/); assert.equal(writes.length, 0);
  unavailable = false; await refresh();
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({width, height: 1050});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `device form ${width}`);
    if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) { await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, `device-form-${width}.png`), fullPage: true}); }
  }
  await page.setViewportSize({width: 1440, height: 1050});
  mode = 'lost'; await deviceSave(); await outcome('df-err', /outcome is unknown/); assert.equal(writes.length, 1);
  assert.equal(await page.locator('#df-id').inputValue(), 'new-device');
  mode = 'ok'; await deviceSave(); await page.locator('#dev-form').waitFor({state: 'hidden'}); await outcome('dev-status', /new-device saved/);
  assert.equal(await page.locator('#add-dev').evaluate(el => el === document.activeElement), true, 'Successful save restores focus');
  assert.deepEqual(writes.at(-1), {method: 'POST', url: '/api/v1/devices', body: {device_id: 'new-device', device_ip: '192.0.2.10',
    model: 'XR8000', management_type: 'xr-host', platform: 'xr-appmgr', credential_profile_id: 'operator'}});
  await page.waitForFunction(() => !window.irisInventory.snapshot().loading);
  holdCredentialRead = true; const waitingRead = new Promise(resolve => { credentialReadResolve = resolve; });
  await page.locator('#manage-creds').click(); await waitingRead;
  assert.equal(await page.locator('#manage-creds').isEnabled(), true, 'Slow read does not lock the form trigger');
  await page.locator('#cf-close').click(); await page.locator('#manage-creds').click();
  await page.waitForFunction(() => !window.irisDeviceForms.snapshot().credentialsLoading);
  await credentialRead.fulfill({json: {profiles: [{id: 'stale-profile'}]}});
  await page.getByRole('button', {name: 'Edit operator', exact: true}).waitFor();
  assert.equal(await page.getByRole('button', {name: 'Edit stale-profile', exact: true}).count(), 0);
  assert.equal(await page.locator('#cf-id').evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#cred-rows img,#cred-rows script').count(), 0);
  assert.match(await page.locator('#cred-rows').innerText(), /<img src=x onerror=alert\(1\)>/);
  await page.getByRole('button', {name: 'Edit operator', exact: true}).click();
  assert.equal(await page.locator('#cf-pass').evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#cf-id').getAttribute('readonly'), '');
  await fillPasswords(); await page.locator('#cf-name').fill('Operators updated');
  const password = await page.locator('#cf-pass').elementHandle(); await page.locator('#cf-pass').focus(); await refresh();
  assert.equal(await password.evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#cf-pass').inputValue(), 'fixture-only-password');
  mode = 'refused'; await credentialSave(); await outcome('cf-err', /refused.*409/);
  assert.doesNotMatch(await page.locator('#cf-err').innerText(), /fixture-only-password|Do not echo/);
  mode = 'malformed'; await credentialSave(); await outcome('cf-err', /outcome is unknown/);
  assert.equal(await page.locator('#cf-pass').inputValue(), ''); assert.equal(await page.locator('#cf-name').inputValue(), 'Operators updated');
  await page.waitForFunction(() => !window.irisDeviceForms.state.credentialsLoading);
  assert.equal(await page.locator('#cred-form button[type="submit"]').isDisabled(), true);
  assert.equal(await page.locator('#cf-refresh').evaluate(el => el === document.activeElement), true);
  const unknownCount = writes.length;
  await page.locator('#cf-close').click(); await page.locator('#manage-creds').click();
  await page.waitForFunction(() => !window.irisDeviceForms.state.credentialsLoading);
  assert.equal(await page.locator('#cred-form button[type="submit"]').isDisabled(), true);
  unavailable = true; await page.locator('#cf-refresh').click();
  await page.waitForFunction(() => !window.irisDeviceForms.state.credentialsLoading);
  assert.equal(await page.locator('#cred-form button[type="submit"]').isDisabled(), true);
  assert.equal(writes.length, unknownCount);
  unavailable = false; await page.locator('#cf-refresh').click();
  await page.waitForFunction(() => !window.irisDeviceForms.state.credentialReviewRequired);
  await fillPasswords(); await page.locator('#cf-en').fill('fixture-only-enable');
  mode = 'unavailable'; await credentialSave(); await outcome('cf-err', /outcome is unknown/);
  await page.waitForFunction(() => !window.irisDeviceForms.state.credentialsLoading);
  for (const id of ['cf-pass', 'cf-pass2', 'cf-en']) assert.equal(await page.locator('#' + id).inputValue(), '');
  assert.equal(await page.locator('#cred-form button[type="submit"]').isDisabled(), true);
  assert.equal(await page.getByRole('button', {name: 'Delete operator', exact: true}).isDisabled(), true);
  await page.locator('#cf-refresh').click(); await page.waitForFunction(() => !window.irisDeviceForms.state.credentialReviewRequired);
  await fillPasswords(); mode = 'ok'; await credentialSave(); await outcome('cf-err', /Profile operator saved/);
  assert.equal(await page.locator('#cf-pass').inputValue(), ''); assert.equal(await page.locator('#cf-id').inputValue(), '');
  assert.deepEqual(writes.at(-1).body, {id: 'operator', name: 'Operators updated', device_user: '<script>evil()</script>', device_pass: 'fixture-only-password', enable_secret: ''});
  unavailable = true; await page.locator('#cf-refresh').click();
  await page.getByText('Credential profiles unavailable. Showing the last successful read.', {exact: true}).waitFor();
  assert.equal(await page.getByRole('button', {name: 'Delete operator', exact: true}).isDisabled(), true);
  assert.match(await page.locator('#cred-rows').innerText(), /Operators updated/);
  unavailable = false; await page.locator('#cf-refresh').click(); await page.waitForFunction(() => window.irisDeviceForms.snapshot().credentialsOk);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({width, height: 1050});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `credential form ${width}`);
    if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, `credential-form-${width}.png`), fullPage: true});
  }
  await page.setViewportSize({width: 1440, height: 1050});
  mode = 'refused'; page.once('dialog', dialog => dialog.accept()); await page.getByRole('button', {name: 'Delete operator', exact: true}).click();
  await outcome('cf-err', /delete refused/); assert.equal(profiles.length, 1);
  mode = 'ok'; page.once('dialog', dialog => dialog.accept()); await page.getByRole('button', {name: 'Delete operator', exact: true}).click();
  await outcome('cf-err', /Profile operator deleted/); await page.getByText('No credential profiles yet.', {exact: true}).waitFor();
  unavailable = true; await page.locator('#cf-refresh').click(); await page.getByText('Credential profiles unavailable.', {exact: true}).waitFor();
  assert.equal(await page.getByText('No credential profiles yet.', {exact: true}).count(), 0);
  unavailable = false; await page.locator('#cf-refresh').click(); await page.getByText('No credential profiles yet.', {exact: true}).waitFor();
  await fillPasswords(); await page.locator('#cf-en').fill('fixture-only-enable');
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', {configurable: true, value: true}); document.dispatchEvent(new Event('visibilitychange')); });
  await page.locator('#cred-panel').waitFor({state: 'hidden'}); assert.equal(await page.locator('#cf-pass').inputValue(), '');
  assert.equal(await page.locator('#cf-en').inputValue(), '');
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', {configurable: true, value: false}); document.dispatchEvent(new Event('visibilitychange')); });
  await page.locator('#manage-creds').click(); await page.locator('#cf-user').focus(); await page.keyboard.press('Escape');
  await page.locator('#cred-panel').waitFor({state: 'hidden'}); assert.equal(await page.locator('#manage-creds').evaluate(el => el === document.activeElement), true);
  await page.locator('#manage-creds').click();
  await page.locator('#cf-id').fill('new-profile'); await fillPasswords(); await page.locator('#cf-en').fill('fixture-only-enable');
  mode = 'hold'; const arrived = new Promise(resolve => { heldResolve = resolve; }); const count = writes.length;
  await credentialSave(); await arrived;
  assert.equal(await page.locator('#cf-pass').isDisabled(), true); await page.locator('#cf-close').click();
  assert.equal(await page.locator('#manage-creds').evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#cf-pass').inputValue(), ''); assert.equal(await page.locator('#cf-en').inputValue(), '');
  await page.locator('#manage-creds').click(); assert.equal(await page.locator('#cred-form button[type="submit"]').isDisabled(), true);
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('view-devices').hidden);
  const before = reads.length; await held.fulfill({json: {profile: {id: 'new-profile'}}});
  await page.waitForFunction(() => !window.irisDeviceForms.snapshot().credentialBusy);
  assert.equal(reads.slice(before).filter(url => url === '/api/v1/devices' || url === '/api/v1/credentials').length, 0);
  assert.equal(writes.length, count + 1, 'Closing and reopening never repeats write');
  assert.equal(await page.locator('#cf-pass').inputValue(), '');
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Device and credential forms: explicit networking, exact CSRF writes, unavailable/refused/unknown states, lock lifetime, secret clearing, polling focus, mobile and CSP passed.');
} finally { await browser.close(); }
