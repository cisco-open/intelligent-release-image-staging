// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Real Console controls over isolated, paged API fixtures. No device actions.
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
  const errors = [], writes = [];
  let failure = false, previewFailure = false, holdSecond = false, revisionChange = false, held, ready;
  const devices = Array.from({length: 1001}, (_, i) => ({device_id: `edge-${String(i).padStart(4, '0')}`,
    device_ip: '192.0.2.10', model_family: 'C8xxx', model: 'C8xxx', platform: 'iox', management_type: 'router-nat', assigned_image_ids: []}));
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
        assert.equal(request.method(), 'POST'); assert.ok(url.pathname.endsWith('/onboard'));
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        writes.push(url.pathname);
        return route.fulfill({status: 409, json: {error: 'Fixture actions are not executed'}});
      }
      if (url.pathname === '/api/v1/devices') {
        if (previewFailure) return route.fulfill({status: 503, json: {error: 'Fixture unavailable'}});
        const limit = Number(url.searchParams.get('limit') || 200), offset = Number(url.searchParams.get('offset') || 0);
        const q = (url.searchParams.get('q') || '').toLowerCase();
        const matching = devices.filter(device => device.device_id.includes(q));
        if (limit === 1000 && offset === 1000) {
          if (holdSecond) { held = route; ready(); return; }
          if (failure) return route.fulfill({status: 503, json: {error: 'Fixture second page unavailable'}});
        }
        return route.fulfill({json: {devices: matching.slice(offset, offset + limit), total: matching.length, offset,
          revision: revisionChange && offset === 1000 ? 2 : 1, now: 2000000000}});
      }
      const fixtures = {
        '/api/v1/session': {username: 'Selection fixture', csrf: 'fixture-only'},
        '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []},
        '/api/v1/onboard/jobs': {jobs: [], now: 2000000000},
        '/api/v1/peer-policy': {revision: 1, quarantine_assignments: [], roles_supported: true, roles: {defined: 0, restricted: 0, members: {}},
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
  const count = n => page.locator('#sel-count').getByText(`${n} selected`, {exact: true}).waitFor();
  const filter = async q => {
    await page.locator('#dev-filter-q').fill(q);
    await page.waitForFunction(q => {
      const rows = [...document.querySelectorAll('#dev-rows tr[data-id]')];
      return rows.length === (q ? 1 : 200) && rows.every(row => row.dataset.id.includes(q));
    }, q);
    await page.locator('#dev-count').getByText(q ? '1 result' : '200 of 1001 results', {exact: true}).waitFor();
  };
  const row = id => page.locator(`#dev-rows tr[data-id="${id}"]`);
  const startHeld = async () => {
    holdSecond = true;
    const arrived = new Promise(resolve => { ready = resolve; });
    await page.locator('#sel-scope-all').click(); await arrived;
    assert.equal(await page.locator('#sel-scope-all').isDisabled(), true);
  };
  const releaseHeld = async () => {
    holdSecond = false;
    await held.fulfill({json: {devices: [devices[1000]], total: 1001, offset: 1000, revision: 1, now: 2000000000}}).catch(() => {});
  };
  await page.goto('http://iris.test/#devices');
  await row('edge-0000').locator('td').nth(2).click(); await count(1);
  await filter('edge-0001');
  assert.equal(await row('edge-0001').getAttribute('aria-selected'), 'false');
  assert.equal(await page.locator('#sel-scope-text').textContent(), '· 1 selected outside this filter');
  assert.equal(await page.locator('#sel-scope-all').isVisible(), true, 'Same count, different IDs still offers matching selection');
  await page.locator('#sel-scope-all').click(); await count(2);
  assert.equal(await row('edge-0001').getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#sel-scope-text').textContent(), '· All 1 matching devices selected; 1 selected outside this filter');
  // Bulk target is the explicit selected ID set, including the disclosed extra.
  await page.locator('#onboard-selected').click(); await page.locator('#onboard-confirm').click();
  await page.locator('#dev-status').getByText('Started onboard for 0 device(s)', {exact: false}).waitFor();
  assert.deepEqual(writes.sort(), ['/api/v1/devices/edge-0000/onboard', '/api/v1/devices/edge-0001/onboard']);
  await page.locator('#batch-close').click();
  await filter('edge-0002');
  assert.equal(await page.locator('#sel-scope-all').isVisible(), true, 'Larger selection does not hide matching selection');
  assert.match(await page.locator('#sel-scope-text').textContent(), /2 selected outside this filter/);
  await page.locator('#sel-clear').click(); await filter('');

  await page.locator('#mark-all').click(); await count(200);
  await startHeld(); await count(200);
  const abortedFilter = page.waitForEvent('requestfailed', request => request === held.request());
  await filter('edge-0002'); await abortedFilter; await releaseHeld(); await count(200);
  assert.equal(await page.locator('#sel-scope-text').textContent(), '· All 1 matching devices selected; 199 selected outside this filter');
  await filter('');
  await startHeld();
  const abortedClear = page.waitForEvent('requestfailed', request => request === held.request());
  await page.locator('#sel-clear').click(); await abortedClear; await releaseHeld();
  await page.locator('#sel-bar').waitFor({state: 'hidden'});
  assert.equal(await page.locator('#dev-rows tr[aria-selected="true"]').count(), 0, 'Late page does not restore a cleared selection');

  await page.locator('#mark-all').click(); await count(200);
  failure = true; await page.locator('#sel-scope-all').click();
  await page.locator('#dev-status').getByText('Your selection is unchanged.', {exact: false}).waitFor();
  assert.match(await page.locator('#dev-status').getAttribute('class'), /err/);
  await count(200); assert.equal(await page.locator('#sel-scope-all').isEnabled(), true);
  failure = false; revisionChange = true; await page.locator('#sel-scope-all').click();
  await page.waitForFunction(() => !document.getElementById('sel-scope-all').disabled);
  await count(200); assert.match(await page.locator('#dev-status').innerText(), /selection is unchanged/);
  revisionChange = false; await page.locator('#sel-scope-all').click(); await count(1001);
  assert.doesNotMatch(await page.locator('#dev-status').getAttribute('class'), /err/);
  await page.locator('#sel-scope-text').getByText('· All 1001 matching devices selected', {exact: true}).waitFor();
  await page.locator('#dev-page-next').click();
  await row('edge-0200').waitFor();
  assert.equal(await row('edge-0200').getAttribute('aria-selected'), 'true', 'IDs remain selected on another page');
  assert.doesNotMatch(await page.locator('#sel-scope-text').textContent(), /All .*matching/,
    'A new partial read cannot prove the complete matching set is unchanged');
  await page.locator('#dev-page-next').click(); await row('edge-0400').waitFor();
  await page.locator('#mark-all').click(); await count(801);
  assert.equal(await row('edge-0400').getAttribute('aria-selected'), 'false');
  assert.equal(await page.locator('#sel-scope-all').isVisible(), true);

  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({width, height: 1000});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const directory = process.env.IRIS_BROWSER_SCREENSHOT_DIR;
    if (directory) {
      await fs.mkdir(directory, {recursive: true});
      await page.screenshot({path: path.join(directory, `selection-${width}.png`)});
    }
  }
  previewFailure = true;
  await page.locator('#dev-filter-q').fill('unavailable');
  await page.locator('#dev-count').getByText('Results unavailable', {exact: true}).waitFor();
  await count(801);
  assert.equal(await page.locator('#sel-scope-all').isVisible(), false);
  assert.match(await page.locator('#sel-scope-text').textContent(), /matches are unconfirmed/);
  assert.equal(writes.length, 2, 'Selection and failed reads perform no device actions');
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Inventory selection: ID membership, off-filter targets, atomic paging, cancellation, failures, retained pages, mobile and CSP passed.');
} finally { await browser.close(); }
