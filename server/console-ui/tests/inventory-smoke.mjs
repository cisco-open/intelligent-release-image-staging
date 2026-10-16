// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated API fixtures exercise shipped controls. No live device actions.
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
  const errors = [], writes = [], reads = [];
  let credentialFailure = false, policyFailure = false, writeMode = 'ok', held, hold;
  const device = {device_id: 'constructor', device_ip: '192.0.2.10', model_family: 'C8xxx', model: '<img src=x onerror=alert(1)>',
    platform: 'iox', management_type: 'router-nat', vpg_number: 0, credential_profile_id: 'operator', assigned_image_ids: [],
    last_seen: 1999999900, telemetry_enabled: true, telemetry_stream_enabled: true,
    peer_tls: {runtime_source: 'aria2_rpc', runtime_mode: 'required', configured_mode: 'required'},
    install_options: ['iox', 'router'], instruction: {display_state: 'rejected', label: '<rejected>', reason: '<script>evil()</script>', report_age_seconds: 1, qos_drift_count: 0}};
  const policy = {revision: 1, roles_supported: true, quarantine_assignments: [], roles: {defined: 0, restricted: 0, members: {}},
    enforcement: {state: 'enforced', stale: false}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
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
        const body = request.postDataJSON(); writes.push({url: url.pathname, method: request.method(), body, headers: request.headers()});
        if (writeMode === 'hold') { held = route; hold(); return; }
        if (writeMode === 'refused') return route.fulfill({status: 409, json: {error: 'review current policy'}});
        if (writeMode === 'lost') return route.abort('failed');
        if (writeMode === 'malformed') return route.fulfill({body: '{}', contentType: 'application/json'});
        if (url.pathname.endsWith('/credential')) device.credential_profile_id = body.credential_profile_id;
        else if (url.pathname.endsWith('/platform')) device.platform = body.platform;
        else if (url.pathname.includes('/quarantine/')) {
          policy.revision++; policy.quarantine_assignments = body.quarantined ? [device.device_id] : [];
          return route.fulfill({json: {ok: true, revision: policy.revision, quarantined: body.quarantined}});
        } else throw new Error('Unexpected write: ' + url.pathname);
        return route.fulfill({json: {ok: true}});
      }
      reads.push(url.pathname);
      if ((credentialFailure && url.pathname === '/api/v1/credentials') || (policyFailure && url.pathname === '/api/v1/peer-policy')) {
        return route.fulfill({status: 503, json: {error: 'Fixture unavailable'}});
      }
      const fixtures = {
        '/api/v1/session': {username: 'Inventory fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/devices': {devices: [device], total: 1, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: [{id: 'operator'}, {id: 'other'}]},
        '/api/v1/onboard/jobs': {jobs: [], now: 2000000000}, '/api/v1/schedules': {schedules: []}, '/api/v1/peer-policy': policy,
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
  const refresh = () => page.evaluate(() => window.irisInventory.refresh());
  const row = page.locator('#dev-rows tr[data-id="constructor"]');
  const status = text => page.locator('#dev-status').getByText(text, {exact: false}).waitFor();
  await page.goto('http://iris.test/#devices'); await row.waitFor();
  const feedback = page.locator('#dev-status'), capability = page.locator('#inventory-role-capability-banner');
  assert.equal(await page.locator('#iris-inventory-status-root > #dev-status').count(), 1);
  assert.equal(await page.locator('#iris-inventory-capability-root > #inventory-role-capability-banner').count(), 1);
  for (const region of [feedback, capability]) {
    assert.equal(await region.getAttribute('role'), 'status'); assert.equal(await region.getAttribute('aria-live'), 'polite');
  }
  assert.equal(await capability.isHidden(), true);
  assert.equal(await page.evaluate(() => {
    const roots = [...document.getElementById('view-devices').children].map(node => node.id);
    return roots.indexOf('iris-inventory-capability-root') < roots.indexOf('iris-inventory-root')
      && roots.indexOf('iris-inventory-status-root') === roots.indexOf('iris-inventory-root') + 1
      && roots.indexOf('iris-inventory-status-root') < roots.indexOf('iris-inventory-selection-root');
  }), true, 'Capability warning and action feedback retain their established positions');
  await page.evaluate(() => window.irisInventory.report('edge-1: <img src=x onerror=alert(1)> unreachable', true));
  await status('edge-1: <img src=x onerror=alert(1)> unreachable');
  assert.equal(await feedback.locator('img').count(), 0); assert.match(await feedback.getAttribute('class'), /\berr\b/);
  await refresh(); assert.match(await feedback.innerText(), /edge-1: <img/);
  assert.equal(await row.locator('script,img').count(), 0);
  assert.match(await row.innerText(), /<rejected>.*<script>evil\(\)<\/script>/s);
  assert.match(await row.innerText(), /TLS required/); assert.doesNotMatch(await row.innerText(), /TLS required \(stale\)/);
  assert.equal(await row.locator('.platform option[value="guestshell"]').isDisabled(), true);
  assert.equal(await row.locator('.platform option[value="router"]').isEnabled(), true);
  await row.focus(); await page.keyboard.press('Space');
  assert.equal(await row.getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#mark-all').innerText(), 'Clear page selection');
  const rowHandle = await row.elementHandle(); await refresh();
  assert.equal(await rowHandle.evaluate(el => el === document.activeElement), true, 'Polling preserves the exact keyed focused row');
  await row.locator('.cred').focus(); await refresh();
  assert.equal(await row.locator('.cred').evaluate(el => el === document.activeElement), true, 'Polling preserves select focus');
  await row.locator('.cred').selectOption('other'); await status('Credential updated');
  assert.match(await feedback.getAttribute('class'), /\bmuted\b/); assert.doesNotMatch(await feedback.getAttribute('class'), /\berr\b/);
  assert.deepEqual(writes.at(-1).body, {credential_profile_id: 'other'});
  await page.waitForFunction(() => document.querySelector('#dev-rows .cred').value === 'other');
  assert.equal(await row.getAttribute('aria-selected'), 'true', 'Inline controls do not toggle row selection');
  writeMode = 'refused'; await row.locator('.platform').selectOption('router'); await status('update refused');
  assert.match(await feedback.getAttribute('class'), /\berr\b/); assert.doesNotMatch(await feedback.getAttribute('class'), /\bmuted\b/);
  await page.waitForFunction(() => !document.querySelector('#dev-rows .platform').disabled);
  assert.equal(await row.locator('.platform').inputValue(), 'iox');
  for (const mode of ['lost', 'malformed']) {
    writeMode = mode; const count = writes.length;
    await row.locator('.platform').selectOption('router'); await status('outcome is unknown');
    await page.waitForFunction(() => !document.querySelector('#dev-rows .platform').disabled);
    assert.equal(writes.length, count + 1, 'Unknown outcome is never retried');
    assert.equal(await row.locator('.platform').inputValue(), 'iox');
  }
  writeMode = 'ok'; page.once('dialog', dialog => dialog.accept());
  await row.locator('.peer-quarantine').click(); await status('intent saved');
  assert.equal(writes.at(-1).method, 'PUT'); assert.equal(writes.at(-1).headers['if-match'], '"iris-peer-policy-1"');
  assert.deepEqual(writes.at(-1).body, {quarantined: true, if_revision: 1});
  await row.locator('.peer-intent').getByText('Quarantined intent', {exact: true}).waitFor();
  assert.equal(await row.locator('.peer-quarantine').getAttribute('aria-label'), 'Release constructor');
  credentialFailure = true; policyFailure = true; await refresh();
  await capability.waitFor({state: 'visible'}); assert.match(await capability.innerText(), /unavailable/i);
  assert.equal(await page.locator('#set-role-selected').isDisabled(), true);
  assert.equal(await row.locator('.cred').isDisabled(), true); assert.equal(await row.locator('.cred').inputValue(), 'other');
  assert.equal(await row.locator('.peer-quarantine').isDisabled(), true); assert.match(await row.innerText(), /Policy unavailable/);
  credentialFailure = false; policyFailure = false; await refresh();
  await capability.waitFor({state: 'hidden'}); assert.equal(await page.locator('#set-role-selected').isEnabled(), true);
  policy.roles_supported = false; await refresh(); await capability.waitFor({state: 'visible'});
  assert.equal(await page.locator('#set-role-selected').isDisabled(), true);
  policy.roles_supported = true; await refresh(); await capability.waitFor({state: 'hidden'});
  await page.locator('#csv-menu-btn').click(); await page.keyboard.press('Escape');
  assert.equal(await page.locator('#csv-menu').isVisible(), false);
  assert.equal(await page.locator('#csv-menu-btn').evaluate(el => el === document.activeElement), true);
  // Force Escape before the native details toggle event updates React state.
  const filterEscape = await page.evaluate(async () => {
    const details = document.querySelector('#more-filters'), summary = document.querySelector('#more-filters-summary');
    const toggled = new Promise(resolve => details.addEventListener('toggle', resolve, {once: true}));
    const snapshot = () => ({open: details.open, state: window.irisInventory.snapshot().filtersOpen,
      summaryFocused: document.activeElement === summary});
    summary.click();
    const opened = {open: details.open, state: window.irisInventory.snapshot().filtersOpen};
    const role = document.querySelector('#dev-filter-role'); role.focus();
    role.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
    const immediate = snapshot();
    await toggled;
    return {opened, immediate, settled: snapshot()};
  });
  assert.deepEqual(filterEscape.opened, {open: true, state: false}, 'Native toggle delivery is still pending');
  const closedFilters = {open: false, state: false, summaryFocused: true};
  assert.deepEqual(filterEscape.immediate, closedFilters, 'Escape closes the native panel before toggle delivery');
  assert.deepEqual(filterEscape.settled, closedFilters, 'The queued toggle cannot reopen the panel');
  await page.locator('#more-filters-summary').click(); await page.locator('#dev-filter-role').focus(); await page.keyboard.press('Escape');
  await page.locator('#more-filters:not([open])').waitFor({state: 'attached'});
  assert.equal(await page.locator('#more-filters').getAttribute('open'), null);
  assert.equal(await page.locator('#more-filters-summary').evaluate(el => el === document.activeElement), true);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({width, height: 1000});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const directory = process.env.IRIS_BROWSER_SCREENSHOT_DIR;
    if (directory) {
      await fs.mkdir(directory, {recursive: true}); await page.screenshot({path: path.join(directory, `inventory-${width}.png`)});
      await page.getByRole('region', {name: 'Device inventory'}).evaluate(el => { el.scrollLeft = el.scrollWidth; });
      await page.screenshot({path: path.join(directory, `inventory-status-${width}.png`)});
      await page.getByRole('region', {name: 'Device inventory'}).evaluate(el => { el.scrollLeft = 0; });
    }
  }
  await page.setViewportSize({width: 1440, height: 1000});
  writeMode = 'hold'; const arrived = new Promise(resolve => { hold = resolve; });
  await row.locator('.platform').selectOption('router'); await arrived;
  assert.equal(await row.locator('.cred').isDisabled(), true); assert.equal(await page.locator('#onboard-selected').isDisabled(), true);
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('view-devices').hidden);
  const before = reads.filter(url => url === '/api/v1/devices').length;
  await held.fulfill({json: {ok: true}}); await page.waitForFunction(() => !window.irisInventory.snapshot().rowBusy.size);
  assert.equal(reads.filter(url => url === '/api/v1/devices').length, before, 'Finishing a hidden write does not refresh Inventory');
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Inventory row edits: exact CSRF/preconditions, refused/unknown writes, locks, navigation, freshness, keyboard focus, plain text, mobile and CSP passed.');
} finally { await browser.close(); }
