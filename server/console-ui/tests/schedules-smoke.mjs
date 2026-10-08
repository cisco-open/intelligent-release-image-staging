// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Shipped browser assets; all endpoints mocked, never a live deployment.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}, timezoneId: 'UTC'}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], devices = ['one', 'two', 'three'].map((device_id, i) => ({device_id, device_ip: '192.0.2.' + (i + 1), model: 'C8xxx', platform: 'iox', management_type: 'router-nat'}));
  const makeRow = (id, rev = 1) => ({id, rev, etag: `"iris-schedule-${id}-${rev}"`, kind: 'assign', state: 'pending',
    target: {filters: {role: 'edge'}, device_ids: [], bind: 'late'}, preview: {device_ids: ['one']}, created_by: 'console:departed', creator_exists: false,
    next_fire: {local_time: '2027-01-01T02:30', tz: 'Europe/Stockholm', status: 'future'}});
  let rows = [makeRow('orphan')], createMode = 'ok', reaffirmMode = 'conflict', held, reached, reads = 0, listMode = 'ok';
  const policy = {revision: 1, quarantine_assignments: [], roles_supported: true, roles: {defined: 0, restricted: 0, members: {}}, enforcement: {state: 'preflight-only'}, role_drift: {count: 0}, outbox: {unacknowledged: 0, capacity: 256}};
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const body = request.postDataJSON(); writes.push({path: url.pathname, body, headers: request.headers()});
        if (url.pathname.endsWith('/reaffirm')) {
          assert.equal(request.headers()['if-match'], rows[0].etag); assert.deepEqual(body, {});
          rows[0] = {...rows[0], rev: rows[0].rev + 1, etag: `"iris-schedule-orphan-${rows[0].rev + 1}"`};
          if (reaffirmMode === 'conflict') return route.fulfill({status: 412, json: {code: 'precondition_failed'}});
          rows[0] = {...rows[0], creator_exists: true, created_by: 'console:operator'};
          return route.fulfill({json: {schedule: rows[0]}});
        }
        assert.equal(url.pathname, '/api/v1/schedules');
        if (createMode === 'hold') {held = route; reached(); return;}
        if (createMode === 'unknown') return route.fulfill({status: 503, json: {}});
        const schedule = {...makeRow(body.id), ...body, creator_exists: true, created_by: 'console:operator'}; rows.push(schedule);
        return route.fulfill({status: 201, json: {schedule}});
      }
      if (url.pathname === '/api/v1/schedules') {
        reads++; if (listMode === 'bad') return route.fulfill({status: 503, json: {error: 'unavailable'}});
        return route.fulfill({json: {schedules: rows, total: rows.length}});
      }
      if (url.pathname.endsWith('/occurrences')) return route.fulfill({json: {total: 101, offset: Number(url.searchParams.get('offset') || 0),
        occurrences: [{schedule_id: url.pathname.split('/')[4], state: 'completed', delta: {added: 2, removed: 1},
          annotations: {wave: {gate: 'held', staged: 7, errored: 1, missing: 2, total: 10}}}]}});
      const fixtures = {'/api/v1/session': {username: 'Schedule fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/devices': {devices, total: devices.length, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: [{id: 'image-a', filename: '<script>image</script>'}, {id: 'quarantined', quarantined: true}]},
        '/api/v1/credentials': {profiles: []}, '/api/v1/peer-policy': policy, '/api/v1/onboard/jobs': {jobs: []}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try { return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}}); }
    catch {return route.fulfill({status: 404, body: ''});}
  });
  const select = ids => page.evaluate(ids => window.irisInventory.changeSelection(new Set(ids)), ids);
  const open = async () => {await page.locator('#more-menu-btn').click(); await page.locator('#schedule-selected').click();};
  const focus = selector => page.locator(selector).evaluate(el => el === document.activeElement);
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png')});}};
  await page.goto('http://iris.test/#devices'); await page.waitForFunction(() => window.irisInventory?.state.readOk);
  await select(['one', 'two']); await open(); assert.equal(await focus('#sched-modal-id'), true);
  assert.equal(await page.locator('#sched-modal-count').innerText(), '3 filter matches');
  await page.locator('#create-schedule').focus(); await page.keyboard.press('Tab'); assert.equal(await focus('#sched-modal-x'), true);
  await page.keyboard.press('Escape'); assert.equal(await focus('#more-menu-btn'), true); assert.equal(writes.length, 0); await open();
  await page.locator('#sched-modal-id').fill('reviewed'); await page.locator('#sched-modal-scope').selectOption('selection');
  assert.equal(await page.locator('#sched-modal-count').innerText(), '2 reviewed');
  await page.locator('#sched-modal-images').selectOption('image-a'); await page.locator('#sched-modal-at').fill('2027-01-01T00:00'); await page.locator('#sched-modal-tz').fill('UTC');
  assert.equal(await page.locator('#sched-modal-images option[value="quarantined"]').evaluate(el => el.disabled), true,
    JSON.stringify(await page.evaluate(() => window.irisSchedules.state.images)));
  assert.ok((await page.locator('#sched-modal-images').boundingBox()).height >= 96);
  assert.equal(await page.locator('#sched-modal script').count(), 0);
  await select(['three']); await page.locator('#sched-modal details summary').click();
  assert.match(await page.locator('#sched-modal details').innerText(), /one.*two/s); assert.doesNotMatch(await page.locator('#sched-modal details').innerText(), /three/);
  await page.locator('#sched-modal-id').focus(); await page.evaluate(() => window.irisInventory.refresh()); assert.equal(await focus('#sched-modal-id'), true); assert.equal(await page.locator('#sched-modal-id').inputValue(), 'reviewed');
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    for (const selector of ['#sched-modal .modal', '#sched-modal-x', '#create-schedule', '#sched-modal-cancel']) {
      const box = await page.locator(selector).boundingBox(); assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= width && box.y + box.height <= height, selector);
    }
    await snapshot('schedules-modal-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000}); await page.locator('#create-schedule').click();
  await page.waitForFunction(() => window.irisSchedules.state.message.includes('reviewed created') && !window.irisSchedules.state.busy);
  assert.deepEqual(writes[0].body.target, {filters: {}, device_ids: ['one', 'two'], bind: 'late'});
  assert.deepEqual(writes[0].body.payload, {image_ids: ['image-a'], mode: 'merge'});
  assert.deepEqual(writes[0].body.when, {kind: 'once', at: 1798761600, tz: 'UTC', window_seconds: 3600});
  await page.locator('#sched-rows tr').first().getByText(/7 staged.*2 missing/).waitFor();
  await page.locator('#sched-rows .sched-reaffirm').focus(); await page.evaluate(() => window.irisInventory.refresh()); assert.equal(await focus('#sched-rows .sched-reaffirm'), true);
  await page.locator('#sched-rows .sched-reaffirm').click(); await page.getByText(/changed elsewhere; nothing was re-affirmed/, {exact: false}).first().waitFor();
  await page.waitForFunction(() => !window.irisSchedules.state.busy); reaffirmMode = 'ok'; await page.locator('#sched-rows .sched-reaffirm').click();
  await page.waitForFunction(() => window.irisSchedules.state.message.includes('now owned') && !window.irisSchedules.state.busy);
  assert.equal(writes[1].headers['if-match'], '"iris-schedule-orphan-1"'); assert.equal(writes[2].headers['if-match'], '"iris-schedule-orphan-2"');
  assert.equal(await page.locator('#sched-rows .sched-reaffirm').count(), 0);
  await snapshot('schedules-table-1440');
  await page.setViewportSize({width: 320, height: 568});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.locator('#sched-panel').scrollIntoViewIfNeeded();
  assert.equal(await page.locator('#sched-panel .table-scroll').evaluate(el => el.scrollWidth > el.clientWidth && el.tabIndex === 0), true);
  await snapshot('schedules-table-320');
  await page.setViewportSize({width: 1440, height: 1000});
  listMode = 'bad'; await page.locator('#sched-refresh').click(); await page.getByText(/Showing the last known schedules/).waitFor(); assert.equal(await page.locator('#sched-rows tr').count(), 2); listMode = 'ok';
  await open(); await page.locator('#sched-modal-id').fill('weekly'); await page.locator('#sched-modal-kind').selectOption('onboard'); await page.locator('#sched-modal-when').selectOption('recurring');
  await page.locator('#sched-modal-scope').selectOption('filter'); await page.locator('#sched-modal-tz').fill('Europe/Stockholm'); createMode = 'unknown';
  await page.locator('#create-schedule').click(); await page.getByText(/weekly may have been created/).first().waitFor();
  assert.equal(await page.locator('#create-schedule').isDisabled(), true); assert.equal(writes.length, 4);
  assert.deepEqual(writes[3].body.payload, {telemetry: true, telemetry_stream: false, mode: 'new-only', max_devices: 20});
  assert.deepEqual(writes[3].body.when, {kind: 'recurring', weekday: 6, hour: 2, minute: 30, tz: 'Europe/Stockholm', window_seconds: 3600});
  await page.getByRole('button', {name: 'Refresh schedules before retrying'}).click(); await page.waitForFunction(() => !window.irisSchedules.state.reviewRequired);
  assert.equal(writes.length, 4);
  const arrived = new Promise(resolve => {reached = resolve;}); createMode = 'hold'; await page.locator('#create-schedule').click(); await arrived;
  assert.equal(await page.locator('#dev-rows .cred').first().isDisabled(), true);
  assert.equal(await focus('#sched-modal-x'), true, JSON.stringify(await page.evaluate(() => ({active: document.activeElement.id || document.activeElement.tagName, busy: window.irisSchedules.state.busy}))));
  await page.locator('#sched-modal-x').click(); await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Policies', exact: true}).click();
  const before = reads; await held.fulfill({status: 201, json: {schedule: {...makeRow('weekly'), creator_exists: true}}});
  await page.waitForFunction(() => !window.irisSchedules.state.busy); assert.equal(reads, before);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Schedules: reviewed targets/time fields, CSRF/CAS, history, failures, write locks, focus, narrow screens and CSP passed.');
} finally {await browser.close();}
