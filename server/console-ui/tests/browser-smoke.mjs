// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Run after npm run build. Supply PLAYWRIGHT_MODULE when Playwright is installed
// outside this package. This test uses mocked APIs and never contacts a device.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  const writes = [];
  const jobOptions = [];
  const deviceQueries = [];
  let settingsReads = 0;
  let logoutResult = 'http-error';
  const settingsWrites = [];
  const defaultCA = 'https://www.cisco.com/security/pki/trs/ios.p7b';
  const settingsState = {ca_trust: {url: defaultCA, auto: false}, trust: [],
    telemetry_destination: {source: 'environment', effective_endpoint: '', effective_enabled: false}};
  let settingsFailure = '';
  await page.addInitScript(() => {
    window.addEventListener('iris:policy-state', event => { window.testPolicyState = event.detail; });
    window.testStreams = [];
    window.EventSource = class {
      constructor(url) { this.url = url; this.listeners = {}; window.testStreams.push(this); }
      addEventListener(name, listener) { this.listeners[name] = listener; }
      close() { this.closed = true; }
    };
  });
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests allowed');
    if (url.pathname.startsWith('/api/')) {
      if (url.pathname === '/api/v1/settings') settingsReads++;
      if (url.pathname === '/api/v1/logout') {
        assert.equal(route.request().method(), 'POST');
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        if (logoutResult === 'network-error') return route.abort('failed');
        return route.fulfill({status: logoutResult === 'success' ? 204 : 503, body: ''});
      }
      if (url.pathname.startsWith('/api/v1/settings/') && route.request().method() !== 'GET') {
        const method = route.request().method();
        const body = method === 'DELETE' ? null : route.request().postDataJSON();
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        settingsWrites.push({path: url.pathname, method, body});
        if (settingsFailure === 'network') return route.abort('failed');
        if (settingsFailure === 'html') return route.fulfill({status: 503, body: '<h1>Unavailable</h1>', contentType: 'text/html'});
        if (settingsFailure === 'invalid-success') return route.fulfill({status: 200, json: {}});
        if (url.pathname === '/api/v1/settings/ca-trust') settingsState.ca_trust = {url: body.url || defaultCA, auto: body.auto};
        if (url.pathname === '/api/v1/settings/telemetry-destination') settingsState.telemetry_destination = method === 'DELETE'
          ? {source: 'environment', effective_endpoint: '', effective_enabled: false}
          : {source: 'override', effective_endpoint: body.endpoint, effective_enabled: body.enabled};
        if (url.pathname === '/api/v1/settings/trust') settingsState.trust = [{name: 'fixture.pem', source: 'manual', subject: 'Fixture CA', cert_count: 1}];
        if (url.pathname === '/api/v1/settings/trust/fixture.pem') settingsState.trust = [];
        return route.fulfill({json: {applied: true, revoked: 2}});
      }
      if (url.pathname === '/api/v1/devices') deviceQueries.push(url.searchParams.toString());
      if (route.request().method() !== 'GET') writes.push(route.request().method() + ' ' + url.pathname);
      if (url.pathname === '/api/v1/peer-policy/roles/branch' && route.request().method() === 'PUT') {
        const body = route.request().postDataJSON();
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        assert.equal(route.request().headers()['if-match'], '"iris-peer-policy-1"');
        assert.equal(body.qos.overall_up_bps, 4096);
        assert.equal(body.restricted, true);
        assert.equal(body.origin, false);
        assert.deepEqual(body.peers, ['branch', 'staging']);
        if (url.searchParams.get('dry_run') === '1') return route.fulfill({json: {confirm_token: 'fixture-preview', revision: 1}});
        assert.equal(body.confirm_token, 'fixture-preview');
        return route.fulfill({status: 412, json: {code: 'revision_conflict'}});
      }
      if (url.pathname === '/api/v1/install-options') {
        const options = { IE3x00: ['iox'], IR1x00: ['iox'], C8xxx: ['router','iox'],
          C9xxx: ['guestshell','iox'], NCS: ['xr-appmgr'], XR8000: ['xr-appmgr'] };
        return route.fulfill({ json: { options: options[url.searchParams.get('model')] || null } });
      }
      if (url.pathname === '/api/v1/devices/import-csv') {
        return route.fulfill({status: 422, json: {error: 'role_not_found',
          detail: 'unknown role', role: 'missing-role', device_id: 'csv-test'}});
      }
      if (/^\/api\/v1\/devices\/[^/]+\/(onboard|undeploy)$/.test(url.pathname) && route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        assert.equal(typeof body.log, 'boolean');
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        jobOptions.push([url.pathname.split('/').at(-1), body.log]);
        return route.fulfill({status: 409, json: {error: 'Fixture: device actions are not executed'}});
      }
      if (url.pathname === '/api/v1/devices' && route.request().method() === 'POST') {
        assert.deepEqual(route.request().postDataJSON(), {
          device_id: 'series-ui-test', device_ip: '192.0.2.99',
          model: 'XR8000', management_type: 'xr-host', platform: 'xr-appmgr', credential_profile_id: '',
        });
        return route.fulfill({ status: 201, json: { device_id: 'series-ui-test' } });
      }
      const fixtures = {
        '/api/v1/session': { username: 'UI test', csrf: 'test-only' },
        '/api/v1/overview': { images: 0, devices: 0, assigned: 0, staged: 0, staging_now: 0, rollout: [] },
        '/api/v1/devices': { devices: [
          { device_id: 'edge-01', device_ip: '192.0.2.10', model: '8201', model_family: 'XR8000', management_type: 'xr-host', assigned_images: [] },
          { device_id: 'edge-02', device_ip: '192.0.2.11', model: 'NCS-540', model_family: 'NCS', management_type: 'xr-host', assigned_images: [] },
        ], total: 2, offset: 0 },
        '/api/v1/onboard/jobs': { jobs: [
          { id: 'job-1', device_id: 'edge-01', state: 'done', action: 'onboard', last_line: 'onboard complete' },
          { id: 'job-2', device_id: 'edge-02', state: 'done', action: 'onboard', last_line: 'onboard complete' },
        ], max_concurrent: 25 },
        '/api/v1/images': { images: [] },
        '/api/v1/credentials': { profiles: [] },
        '/api/v1/settings': { version: 'UI test build', admin_username: 'UI test', host_ip: '192.0.2.1',
          ports: { tracker: 6969, catalog: 8443, artifacts: 8000, swarm: 8080, console: 8082 },
          sessions: { active: 1, idle_ttl_minutes: 30 }, ...settingsState },
        '/api/v1/help': { version: 'UI test build', deployment_id: 'fixture-deployment' },
        '/api/v1/peer-policy': { revision: 1, roles_supported: true, roles: { defined: 3, restricted: 2, members: { staging: 2, branch: 5, isolated: 1 } },
          enforcement: {state: 'enforced', stale: false, mutual_origin: {mode: 'preflight', newly_denied_device_count: 1}},
          role_drift: { count: 0 }, outbox: { unacknowledged: 0, capacity: 256 } },
        '/api/v1/peer-policy/roles': { revision: 1, roles: {
          staging: { peers: ['staging'], origin: true, restricted: false },
          branch: { peers: ['branch', 'staging'], origin: false, restricted: true, qos: {overall_up_bps: 8192} },
          isolated: { peers: ['isolated'], origin: false, restricted: true },
        } },
      };
      if (url.pathname === '/api/v1/devices') {
        const family = url.searchParams.get('model_family');
        const q = url.searchParams.get('q');
        fixtures[url.pathname].devices = fixtures[url.pathname].devices.filter(d =>
          (!family || d.model_family === family) && (!q || d.device_id.includes(q)));
        fixtures[url.pathname].total = fixtures[url.pathname].devices.length;
      }
      return route.fulfill({ status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || { error: 'Not included in this fixture' } });
    }
    const file = url.pathname.startsWith('/assets/')
      ? path.join(root, 'dist', path.basename(url.pathname))
      : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {
      const contentType = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' }[path.extname(file)];
      return route.fulfill({ body: await fs.readFile(file), contentType: contentType || 'application/octet-stream',
        headers: { 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'" } });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.goto('http://iris.test/');
  await page.getByText('UI test', { exact: true }).waitFor();
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Settings', exact: true }).click();
  assert.equal(new URL(page.url()).hash, '#settings/general');
  const settings = page.getByRole('navigation', { name: 'Settings sections' });
  await settings.waitFor();
  const settingsTab = async name => {
    const response = page.waitForResponse(r => r.url().endsWith('/api/v1/settings') && r.request().method() === 'GET');
    await settings.getByRole('link', {name, exact: true}).click();
    await (await response).finished();
    await page.waitForLoadState('networkidle');
  };
  await page.locator('#settings-info').getByText('UI test build', {exact: true}).waitFor();
  assert.equal(settingsReads, 1, 'Entering Settings performs one settings read, not duplicate form refreshes');
  await page.locator('#pw-new').fill('example-passphrase');
  for (const [name, pane] of [['TLS & trust', 'tls'], ['Telemetry', 'telemetry'], ['Image verification', 'bulkhash'],
    ['Device packages', 'packages'], ['Audit export', 'audit'], ['Setup checklist', 'setup'], ['General', 'general']]) {
    await settings.getByRole('link', { name, exact: true }).click();
    await page.locator(`#settings-pane-${pane}`).waitFor({ state: 'visible' });
    assert.equal(await settings.getByRole('link', { name, exact: true }).getAttribute('aria-current'), 'page');
  }
  assert.equal(await page.locator('#pw-new').inputValue(), 'example-passphrase', 'Navigation must not remount edited fields');
  await page.locator('#pw-new').fill('');
  // Settings controls exercise only intercepted requests, including failures.
  await page.locator('#pw-cur').fill('fixture-current');
  await page.locator('#pw-new').fill('fixture-new-password');
  await page.locator('#pw-confirm').fill('fixture-new-password');
  await page.locator('#pw-form button[type="submit"]').click();
  await page.locator('#pw-msg').getByText('Password changed. Other sessions signed out.', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {current: 'fixture-current', new: 'fixture-new-password', confirm: 'fixture-new-password'});
  assert.equal(await page.locator('#pw-cur').inputValue(), '');
  await page.locator('#revoke-others').click();
  await page.locator('#revoke-msg').getByText('Signed out 2 other session(s).', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {});
  await settingsTab('TLS & trust');
  await page.waitForFunction(() => document.getElementById('ca-source').value === 'cisco');
  assert.equal(await page.locator('#ca-url').isVisible(), false, 'Built-in Cisco URL is not a custom source');
  await page.locator('#ca-auto').check();
  await page.locator('#ca-form button[type="submit"]').click();
  await page.locator('#ca-msg').getByText('CA download settings saved.', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {url: null, auto: true}, 'Daily refresh supports the server default URL');
  await page.waitForFunction(() => document.getElementById('ca-auto').checked);
  await page.locator('#ca-source').selectOption('mozilla');
  await page.locator('#ca-form button[type="submit"]').click();
  await page.waitForFunction(() => document.getElementById('ca-url').value === 'https://curl.se/ca/cacert.pem');
  assert.deepEqual(settingsWrites.at(-1).body, {url: 'https://curl.se/ca/cacert.pem', auto: true});
  await page.locator('#ca-source').selectOption('custom');
  await page.locator('#ca-url').fill('');
  const beforeEmptyCA = settingsWrites.length;
  await page.locator('#ca-form button[type="submit"]').click();
  await page.locator('#ca-msg').getByText('Enter a custom HTTPS bundle URL.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforeEmptyCA);
  const certPEM = '-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----';
  const keyPEM = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nfixture-only\n-----END ENCRYPTED PRIVATE KEY-----';
  await page.locator('#cert-pem').fill(certPEM);
  await page.locator('#cert-key').fill(keyPEM);
  await page.locator('#cert-passphrase').fill('fixture-passphrase');
  settingsFailure = 'html';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.locator('#cert-msg').getByText('Request failed (503).', {exact: true}).waitFor();
  assert.equal(await page.locator('#cert-key').inputValue(), keyPEM, 'Failed upload preserves the draft for correction');
  settingsFailure = 'invalid-success';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.locator('#cert-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  assert.equal(await page.locator('#cert-key').inputValue(), keyPEM, 'Invalid success response cannot claim a certificate replacement');
  settingsFailure = '';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.waitForFunction(() => document.getElementById('cert-key').value === '');
  assert.deepEqual(settingsWrites.at(-1).body, {cert_pem: certPEM, key_pem: keyPEM, key_passphrase: 'fixture-passphrase'});
  assert.equal(await page.locator('#cert-passphrase-row').isVisible(), false);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#cert-revert').click();
  await page.locator('#cert-msg').getByText('Reverted to the deployment default certificate.', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).method, 'DELETE');
  await page.locator('#trust-pem').fill(certPEM);
  await page.locator('#trust-form button[type="submit"]').click();
  await page.locator('#trust-rows .trust-del').waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {pem: certPEM});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#trust-rows .trust-del').click();
  await page.locator('#trust-rows .trust-del').waitFor({state: 'detached'});
  assert.equal(settingsWrites.at(-1).path, '/api/v1/settings/trust/fixture.pem');
  await settingsTab('Telemetry');
  await page.locator('#td-endpoint').fill('https://collector.example:4318/');
  await page.locator('#td-enabled').check();
  settingsFailure = 'network';
  await page.locator('#td-form button[type="submit"]').click();
  await page.locator('#td-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  settingsFailure = '';
  await page.locator('#td-form button[type="submit"]').click();
  await page.locator('#td-revert').waitFor({state: 'visible'});
  assert.deepEqual(settingsWrites.at(-1).body, {endpoint: 'https://collector.example:4318', enabled: true});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#td-revert').click();
  await page.locator('#td-revert').waitFor({state: 'hidden'});
  assert.equal(await page.locator('#td-endpoint').inputValue(), '');
  assert.equal(await page.locator('#td-enabled').isChecked(), false);
  assert.equal(settingsWrites.at(-1).method, 'DELETE');
  await settingsTab('Audit export');
  await page.locator('#ae-host').fill('archive.example');
  await page.locator('#ae-user').fill('fixture');
  await page.locator('#ae-path').fill('/exports');
  await page.locator('#ae-recipient').fill('age1fixture');
  settingsFailure = 'html';
  await page.locator('#ae-form button[type="submit"]').click();
  await page.locator('#ae-msg').getByText('Request failed (503).', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.port, 22);
  assert.equal(Object.hasOwn(settingsWrites.at(-1).body, 'password'), false, 'An empty password preserves the saved credential');
  await settingsTab('Image verification');
  settingsFailure = 'network';
  await page.locator('#iv-schedule-form button[type="submit"]').click();
  await page.locator('#iv-schedule-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  settingsFailure = '';
  await settingsTab('General');
  const screenshots = process.env.IRIS_UI_SCREENSHOTS;
  if (screenshots) { await fs.mkdir(screenshots, { recursive: true }); await page.screenshot({ path: path.join(screenshots, 'settings-desktop.png') }); }
  await page.getByRole('link', { name: 'Skip to content' }).focus();
  await page.keyboard.press('Enter');
  assert.equal(new URL(page.url()).hash, '#settings/general');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'iris-main-content');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Toggle navigation' }).click();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.body.classList.contains('iris-nav-open')), false);
  await page.setViewportSize({ width: 320, height: 720 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'settings-mobile.png') });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Inventory', exact: true }).click();
  await page.locator('#dev-rows tr[data-id]').first().waitFor();
  assert.equal(await page.locator('#devices input[type="checkbox"]').count(), 0, 'No device selection checkboxes');
  assert.equal(await page.getByText('Distribute. Verify. Stage.', { exact: true }).count(), 0);
  const rows = page.locator('#dev-rows tr[data-id]');
  assert.equal(await rows.count(), 2);
  await rows.first().locator('td').nth(2).click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#sel-count').innerText(), '1 selected');
  // Clicking an embedded dropdown must not alter row selection or write data.
  await rows.first().locator('select.platform').click();
  await page.keyboard.press('Escape');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  await page.locator('#mark-all').click();
  assert.equal(await rows.evaluateAll(nodes => nodes.every(node => node.getAttribute('aria-selected') === 'true')), true);
  await rows.first().focus();
  await page.keyboard.press('Space');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false');
  await page.keyboard.press('Enter');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-row-selection.png') });
  await page.locator('#mark-all').click();
  assert.equal(await page.locator('#sel-bar').isVisible(), false);
  await rows.first().locator('td').nth(2).click();
  await rows.first().locator('td').nth(2).click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false', 'Second row click deselects');
  await rows.first().locator('.dev-id .dinfo').click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false', 'Details button does not select');
  assert.match(await page.locator('#di-rows').innerText(), /Series\s+Cisco 8000 Series/);
  assert.match(await page.locator('#di-rows').innerText(), /Chassis model\s+8201.*inventory/);
  await page.locator('#di-close').click();
  assert.equal(await rows.first().locator('td').nth(3).innerText(), 'Cisco 8000 Series');
  assert.equal(await rows.first().locator('td').nth(3).getAttribute('title'), '8201');
  await page.locator('#add-dev').click();
  const addSeries = page.locator('#df-model');
  assert.equal(await addSeries.evaluate(node => node.tagName), 'SELECT');
  assert.deepEqual(await addSeries.locator('option').allTextContents(), [
    'Choose a series…', 'IE Switches', 'IR Routers', 'Catalyst Routers',
    'Catalyst Switches', 'NCS', 'Cisco 8000 Series',
  ]);
  for (const [value, management, install] of [
    ['IE3x00', 'inband', 'iox'], ['IR1x00', 'inband', 'iox'],
    ['C9xxx', 'inband', 'guestshell'], ['C8xxx', 'router-routed', 'router'],
    ['C8xxx', 'router-routed', 'iox'], ['C8xxx', 'router-nat', 'router'],
    ['C8xxx', 'router-nat', 'iox'],
    ['NCS', 'xr-host', 'xr-appmgr'], ['XR8000', 'xr-host', 'xr-appmgr'],
  ]) {
    await page.locator('#df-management-type').selectOption(management);
    const response = page.waitForResponse(r => r.url().includes('/install-options?model=' + value));
    await addSeries.selectOption(value);
    await response;
    await page.waitForFunction(expected => Array.from(document.querySelector('#df-platform').options)
      .some(option => option.value === expected), install);
    await page.locator('#df-platform').selectOption(install);
    assert.equal(await page.locator('#df-management-type').inputValue(), management);
  }
  await page.locator('#df-id').fill('series-ui-test');
  await page.locator('#df-ip').fill('192.0.2.99');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'add-device-series.png') });
  await page.locator('#dev-form').getByRole('button', { name: 'Save device', exact: true }).click();
  await page.locator('#dev-form').waitFor({ state: 'hidden' });
  assert.deepEqual(writes.splice(0), ['POST /api/v1/devices'], 'Only the explicit synthetic form submission writes');
  await page.locator('#more-filters-summary').click();
  const series = page.locator('#dev-filter-model-family');
  assert.deepEqual(await series.locator('option').allTextContents(), [
    'Device series: any', 'IE Switches', 'IR Routers', 'Catalyst Routers',
    'Catalyst Switches', 'NCS', 'Cisco 8000 Series', 'ISR/ASR/CSR', 'Unknown series',
  ]);
  await series.selectOption('NCS');
  await page.getByRole('button', { name: 'Remove filter: NCS', exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 1);
  assert.match(deviceQueries.at(-1), /model_family=NCS/);
  assert.match(await page.locator('#dev-rows').innerText(), /edge-02/);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-filters.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  const filterBox = await series.boundingBox();
  assert.ok(filterBox.x >= 0 && filterBox.x + filterBox.width <= 390, 'Filter stays in viewport');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-filters-mobile.png') });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Remove filter: NCS', exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 2);
  await page.locator('#dev-filter-q').fill('edge-01');
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 1);
  await page.locator('#dev-filter-clear').click();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 2);
  await page.locator('#more-filters-summary').click();
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-desktop.png') });
  await page.locator('#dev-activity').click();
  await page.locator('#batch-rows .blog').first().click();
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'FIRST JOB ONLY' }));
  await page.locator('#onboard-logs').getByText('FIRST JOB ONLY', { exact: true }).waitFor();
  await page.locator('#batch-rows .blog').nth(1).click();
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'SECOND JOB ONLY' }));
  await page.locator('#onboard-logs').getByText('SECOND JOB ONLY', { exact: true }).waitFor();
  assert.equal(await page.locator('#onboard-logs .job-log-panel:visible').count(), 1);
  assert.equal(await page.locator('#activity-panel').getByRole('button', { name: /Close/ }).count(), 1);
  assert.equal(await page.locator('#onboard-logs').getByText('FIRST JOB ONLY', { exact: true }).isVisible(), false);
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'Undeploy completed.' }));
  await page.waitForFunction(() => document.querySelector('#onboard-logs .job-log-panel:not([hidden]) .log').textContent.includes('Undeploy completed.'));
  const fonts = await page.evaluate(() => ['body', '.page-title', '#onboard-logs .job-log-panel:not([hidden]) .log', '.machine', 'button', 'code']
    .map(selector => document.querySelector(selector)).filter(Boolean)
    .map(element => getComputedStyle(element).fontFamily));
  assert.equal(new Set(fonts).size, 1, 'Headings, controls, data and completion logs share one font family');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-activity.png') });
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#activity-panel').isVisible(), false);
  assert.equal(await page.evaluate(() => window.testStreams.every(s => s.closed)), true);
  await page.locator('#dev-activity').click();
  await page.locator('#batch-rows .blog').first().click();
  assert.equal(await page.evaluate(() => window.testStreams.length), 3, 'Reopening reconnects');
  await page.locator('#batch-close').click();
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Policies', exact: true }).click();
  const sharing = page.getByRole('table', {name: 'Who can share images', exact: true});
  await sharing.getByRole('rowheader').filter({hasText: 'staging'}).waitFor();
  assert.equal(await page.locator('#policy-advanced-modal').isVisible(), false);
  const branchRow = sharing.getByRole('row').filter({has: page.getByRole('rowheader').filter({hasText: 'branch'})});
  assert.match(await branchRow.innerText(), /staging/);
  assert.match(await branchRow.innerText(), /Not allowed by role/);
  assert.doesNotMatch(await branchRow.innerText(), /isolated/);
  assert.match(await page.locator('#iris-policies-root').innerText(), /Preview only — not enforced at the distribution server/);
  await page.getByRole('button', {name: 'Edit role branch', exact: true}).click();
  assert.equal(await page.locator('#role-editor-advanced').getAttribute('open'), null);
  await page.locator('#role-editor-advanced > summary').click();
  assert.equal(await page.locator('[data-qos="overall_up_bps"]').inputValue(), '8192');
  await page.locator('[data-qos="overall_up_bps"]').fill('4096');
  await page.locator('#role-def-save').click();
  await page.locator('#role-def-save').getByText('Save role', {exact: true}).waitFor();
  await page.locator('#role-def-save').click();
  await page.locator('#role-def-msg').getByText('Peer policy changed. Close this editor, refresh, and reopen the current definition before previewing again.', {exact: true}).waitFor();
  assert.equal(await page.locator('#role-def-preview').isVisible(), false, 'A conflict invalidates the preview instead of silently committing');
  assert.deepEqual(writes.splice(0), ['PUT /api/v1/peer-policy/roles/branch', 'PUT /api/v1/peer-policy/roles/branch']);
  await page.locator('#role-def-cancel').click();
  await page.getByRole('button', {name: 'Advanced…', exact: true}).click();
  await page.locator('#policy-advanced-modal').waitFor({state: 'visible'});
  assert.equal(await page.locator('#role-def-export').isVisible(), true);
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('button', {name: 'Advanced…', exact: true}).evaluate(el => el === document.activeElement), true);
  await page.getByRole('button', {name: 'New role', exact: true}).click();
  await page.locator('#role-def-modal').waitFor({ state: 'visible' });
  await page.locator('#rd-name').fill('test-role');
  assert.equal(await page.locator('#rd-origin').isDisabled(), true);
  await page.locator('#rd-restricted').check();
  assert.equal(await page.locator('#rd-origin').isDisabled(), false);
  await page.locator('#role-def-cancel').click();
  await page.locator('#role-def-modal').waitFor({ state: 'hidden' });
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'policies-desktop.png') });
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'policies-mobile.png') });
  await page.setViewportSize({width: 1440, height: 1000});
  const policyState = await page.evaluate(() => window.testPolicyState);
  await page.evaluate(state => window.dispatchEvent(new CustomEvent('iris:policy-state', {detail: {...state, ready: false, disabled: true}})), policyState);
  await sharing.getByText('Role permissions unavailable. Refresh or check Advanced.').waitFor();
  assert.equal(await page.getByRole('button', {name: 'New role', exact: true}).isDisabled(), true);
  await page.evaluate(state => window.dispatchEvent(new CustomEvent('iris:policy-state', {detail: state})), policyState);
  await sharing.getByRole('rowheader').filter({hasText: 'staging'}).waitFor();
  assert.deepEqual(writes, [], 'Navigation, selection and cancelling an editor must not mutate server state');
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Inventory', exact: true }).click();
  const csv = {name: 'same.csv', mimeType: 'text/csv', buffer: Buffer.from('device_id,role\ncsv-test,missing-role\n')};
  for (let attempt = 0; attempt < 2; attempt++) {
    const imported = page.waitForResponse(r => r.url().endsWith('/api/v1/devices/import-csv'));
    await page.locator('#csv-file').setInputFiles(csv);
    await imported;
    await page.waitForFunction(() => !document.getElementById('import-csv').disabled);
    await page.waitForFunction(() => document.getElementById('csv-import-status').textContent.includes('role: missing-role'));
    assert.equal(await page.locator('#csv-file').inputValue(), '');
    assert.match(await page.locator('#csv-import-status').innerText(), /device_id: csv-test.*Define the role in Policies/);
  }
  assert.deepEqual(writes.splice(0), ['POST /api/v1/devices/import-csv', 'POST /api/v1/devices/import-csv']);
  if (await page.locator('#sel-clear').isVisible()) await page.locator('#sel-clear').click();
  await page.locator('#dev-rows tr[data-id]').first().locator('td').nth(2).click();
  for (const action of ['onboard', 'undeploy']) {
    for (const detail of [false, true]) {
      await page.locator('#' + action + '-selected').click();
      await page.locator('#' + action + '-log').setChecked(detail);
      if (action === 'undeploy') {
        const copy = await page.locator('#undeploy-modal .modal-body').innerText();
        assert.ok(copy.split(/\s+/).length < 90, 'Undeploy popup stays concise');
        assert.match(copy, /Skips record and device identity checks/);
        assert.equal(await page.locator('#undeploy-force-help').evaluate(el => getComputedStyle(el).fontFamily), fonts[0]);
        // Exercise both normal and Force confirmation warnings without a real job.
        await page.locator('#undeploy-force').setChecked(detail);
        if (screenshots) await page.screenshot({ path: path.join(screenshots, 'undeploy-popup.png') });
        page.once('dialog', async dialog => {
          assert.match(dialog.message(), /Keeps staged images in device storage/);
          assert.match(dialog.message(), /Does not stop running jobs/);
          if (detail) assert.match(dialog.message(), /skips record and device identity checks/);
          assert.ok(dialog.message().split(/\s+/).length < 65);
          await dialog.accept();
        });
      }
      const submitted = page.waitForResponse(r => r.url().endsWith('/' + action) && r.request().method() === 'POST');
      await page.locator('#' + action + '-confirm').click();
      await submitted;
      await page.waitForFunction(() => !document.getElementById('onboard-selected').disabled);
      await page.locator('#batch-close').click();
    }
  }
  assert.deepEqual(jobOptions, [['onboard', false], ['onboard', true], ['undeploy', false], ['undeploy', true]]);
  assert.equal(writes.length, 4);
  await page.getByRole('button', {name: 'Help', exact: false}).click();
  for (const failure of ['http-error', 'network-error']) {
    logoutResult = failure;
    await page.getByRole('button', {name: 'Sign out', exact: true}).click();
    await page.getByRole('alert').filter({hasText: 'Your session may still be active'}).waitFor();
    assert.equal(new URL(page.url()).pathname, '/', 'Failed logout must not imply that the session was revoked');
    assert.equal(await page.getByRole('button', {name: 'Sign out', exact: true}).isEnabled(), true);
  }
  logoutResult = 'success';
  await page.getByRole('button', {name: 'Sign out', exact: true}).click();
  await page.waitForURL('http://iris.test/login.html');
  assert.deepEqual(errors, []);
  console.log('React UI browser smoke passed (mock APIs: settings, selection, series/search/reset, isolated activity streams, desktop + mobile).');
} finally { await browser.close(); }
