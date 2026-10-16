// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated fixtures: no deployment or device is contacted.
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
  let reads = 0, readMode = 'ok', writeMode = 'ok';
  let jobs = [
    {id: 'one', device_id: 'edge-01', action: 'onboard', state: 'running', started_at: 1999999900,
      last_line: '<script>plain output</script>'},
    {id: 'two', device_id: 'edge-02', action: 'undeploy', state: 'queued', queued_at: 1999999990},
    {id: 'three', device_id: 'edge-03', action: 'onboard', state: 'queued', queued_at: 1999999995},
  ];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    Date.now = () => 2100000000000; // A wrong browser clock must not affect job durations.
    window.testStreams = []; window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
    window.EventSource = class {
      constructor(url) { this.url = url; this.listeners = {}; window.testStreams.push(this); }
      addEventListener(name, listener) { this.listeners[name] = listener; }
      close() { this.closed = true; }
    };
  });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        const body = request.postDataJSON();
        writes.push([url.pathname, request.headers()['x-csrf-token'], body]);
        assert.equal(request.method(), 'POST');
        if (writeMode === 'lost') return route.abort('failed');
        if (url.pathname === '/api/v1/onboard/cancel-queued') {
          const selected = jobs.filter(job => body.job_ids.includes(job.id) && job.state === 'queued');
          for (const job of selected) job.state = 'cancelled';
          return route.fulfill({json: {cancelled: selected.length}});
        }
        if (url.pathname.endsWith('/abort')) return route.fulfill({json: {aborted: true}});
        if (url.pathname.endsWith('/onboard')) return route.fulfill({status: 409, json: {error: 'fixture device busy'}});
        assert.fail('Unexpected write: ' + url.pathname);
      }
      if (url.pathname === '/api/v1/onboard/jobs') {
        reads++;
        if (readMode === 'invalid') return route.fulfill({json: {jobs: [{id: 'broken'}]}});
        return route.fulfill({json: {jobs, now: 2000000000, max_concurrent: 25}});
      }
      const fixtures = {
        '/api/v1/session': {username: 'Activity fixture', csrf: 'fixture-only'},
        '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/devices': {devices: [{device_id: 'edge-01', device_ip: '192.0.2.10', model_family: 'C8xxx',
          platform: 'iox', management_type: 'router-nat', assigned_image_ids: []}], total: 1, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []},
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
  const row = id => page.locator(`#batch-rows tr[data-job="${id}"]`);
  const log = () => page.locator('#onboard-logs .job-log-panel:visible');
  const emit = async (index, text, kind = 'message') => page.evaluate(({index, text, kind}) => {
    const stream = window.testStreams[index];
    if (kind === 'message') stream.onmessage({data: text});
    else if (kind === 'error') stream.onerror();
    else stream.listeners.end({data: text});
  }, {index, text, kind});
  const screenshot = async name => {
    const directory = process.env.IRIS_BROWSER_SCREENSHOT_DIR;
    if (directory) { await fs.mkdir(directory, {recursive: true}); await page.screenshot({path: path.join(directory, name + '.png'), fullPage: true}); }
  };
  await page.goto('http://iris.test/#devices');
  await page.locator('#dev-activity').click();
  await row('one').waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'batch-close');
  assert.equal(await page.locator('#activity-panel').getAttribute('aria-modal'), null);
  assert.match(await row('one').innerText(), /1m40s/);
  assert.match(await row('three').innerText(), /#2 in line/);
  assert.equal(await page.locator('#activity-panel script').count(), 0);
  const initialReads = reads;
  await page.waitForResponse(response => response.url().endsWith('/api/v1/onboard/jobs'));
  assert.ok(reads > initialReads, 'active jobs poll without reopening the drawer');

  await row('one').getByRole('button', {name: 'View onboard log for edge-01'}).click();
  await emit(0, 'first job\n<script>plain log</script>');
  await log().getByText('<script>plain log</script>', {exact: false}).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.dataset.job), 'one');
  await row('two').getByRole('button', {name: 'View undeploy log for edge-02'}).click();
  await emit(1, 'second job');
  await log().getByText('second job', {exact: false}).waitFor();
  await emit(0, 'first job later');
  assert.doesNotMatch(await log().innerText(), /first job/);
  await emit(1, '', 'error');
  await log().getByRole('button', {name: 'Reconnect log'}).click();
  await emit(2, 'reconnected job');
  await emit(1, 'stale connection');
  await log().getByText('reconnected job', {exact: false}).waitFor();
  assert.doesNotMatch(await log().innerText(), /stale connection/);
  await emit(2, 'done', 'end');
  await log().getByText('Undeploy completed.', {exact: false}).waitFor();
  assert.equal(await log().getByRole('button', {name: 'Abort', exact: true}).isVisible(), false);
  await screenshot('activity-desktop');

  // Cancel only the queued IDs visible in this listing, never a global queue.
  page.once('dialog', dialog => dialog.dismiss()); await page.locator('#batch-cancel').click();
  assert.equal(writes.length, 0);
  page.once('dialog', dialog => { assert.match(dialog.message(), /2 queued.*Running jobs continue/); return dialog.accept(); });
  await page.locator('#batch-cancel').click();
  await page.locator('#activity-panel').getByText('Cancelled 2 queued job(s).', {exact: true}).waitFor();
  assert.deepEqual(writes, [['/api/v1/onboard/cancel-queued', 'fixture-only', {job_ids: ['two', 'three']}]]);
  await row('one').getByRole('button', {name: 'View onboard log for edge-01'}).click();
  page.once('dialog', dialog => { assert.match(dialog.message(), /partially configured/); return dialog.accept(); });
  await log().getByRole('button', {name: 'Abort', exact: true}).click();
  await log().getByText('[abort requested]', {exact: false}).waitFor();
  assert.deepEqual(writes.at(-1), ['/api/v1/onboard/jobs/one/abort', 'fixture-only', {}]);
  writeMode = 'lost'; page.once('dialog', dialog => dialog.accept());
  await log().getByRole('button', {name: 'Abort', exact: true}).click();
  await log().getByText('Request outcome is unknown.', {exact: false}).waitFor();
  assert.equal(writes.length, 3, 'lost mutation is not replayed');

  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'dev-activity');
  assert.equal(await page.evaluate(() => window.testStreams.every(stream => stream.closed)), true);
  await emit(0, 'stale after close');
  assert.equal(await page.locator('#onboard-logs .job-log-panel').count(), 0);
  assert.equal(writes.length, 3, 'close does not cancel jobs');
  await page.locator('#dev-activity').click();
  readMode = 'invalid'; await page.locator('#batch-refresh').click();
  await page.locator('#activity-panel').getByText('Activity unavailable. Showing the last known jobs; retrying.', {exact: true}).waitFor();
  assert.equal(await row('one').count(), 1);
  readMode = 'ok'; await page.locator('#batch-refresh').click();
  await page.waitForFunction(() => document.querySelector('#activity-panel .err').hidden);
  await row('one').getByRole('button', {name: 'View onboard log for edge-01'}).click();
  await emit(3, Array.from({length: 600}, (_, i) => `output ${i}`).join('\n'));
  await log().getByText('Showing recent output, up to 500 lines.', {exact: false}).waitFor();
  assert.equal((await log().locator('pre').innerText()).split('\n').length, 500);
  assert.match(await log().locator('pre').innerText(), /^output 100\n/);
  await log().locator('pre').evaluate(node => { node.scrollTop = 0; node.dispatchEvent(new Event('scroll')); });
  await emit(3, 'new output while reading earlier lines');
  await page.waitForFunction(() => document.querySelector('#onboard-logs .job-log-panel:not([hidden]) pre')
    .textContent.endsWith('new output while reading earlier lines'));
  assert.equal(await log().locator('pre').evaluate(node => node.scrollTop), 0, 'new output does not move a reader back to the tail');
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable: true, value: true});
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await log().getByRole('button', {name: 'Reconnect log'}).waitFor();
  assert.equal(await page.evaluate(() => window.testStreams[3].closed), true);
  await emit(3, 'stale while hidden');
  assert.doesNotMatch(await log().innerText(), /stale while hidden/);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable: true, value: false});
    document.dispatchEvent(new Event('visibilitychange'));
  });

  for (const width of [390, 320]) {
    await page.setViewportSize({width, height: 844});
    await page.locator('#activity-panel .drawer-body').evaluate(node => { node.scrollTop = 0; });
    await page.locator('#batch-close').focus();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const box = await page.locator('#batch-close').boundingBox();
    assert.ok(box.x >= 0 && box.x + box.width <= width && box.y >= 56);
    const title = await page.locator('#activity-title').boundingBox();
    assert.ok(title.x + title.width <= box.x, 'title and Close do not overlap');
    const logTitle = await log().locator('h3').boundingBox();
    const abort = await log().getByRole('button', {name: 'Abort', exact: true}).boundingBox();
    assert.ok(logTitle.y + logTitle.height <= abort.y, 'narrow log heading has its own line');
    await page.getByRole('region', {name: 'Device jobs'}).focus();
    await page.keyboard.press('ArrowRight');
    await screenshot(`activity-mobile-${width}`);
  }
  await page.locator('#batch-close').click(); await page.setViewportSize({width: 1440, height: 1000});
  writeMode = 'ok'; jobs = [];
  await page.locator('#dev-rows tr[data-id="edge-01"] td').nth(2).click();
  await page.locator('#onboard-selected').click();
  await page.locator('#onboard-confirm').click();
  await page.locator('#dev-status').getByText('edge-01: fixture device busy', {exact: false}).waitFor();
  assert.match(await page.locator('#dev-status').getAttribute('class'), /err/);
  assert.equal(writes.at(-1)[0], '/api/v1/devices/edge-01/onboard');
  assert.equal(writes.at(-1)[1], 'fixture-only');
  await page.locator('#batch-summary').getByText('No confirmed jobs in this batch.', {exact: true}).waitFor();
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Images', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('activity-panel').hidden);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  console.log('Activity: scoped CSRF writes, unknown outcomes, polling, stream isolation, reconnect, bounds, focus, mobile and CSP passed.');
} finally { await browser.close(); }
