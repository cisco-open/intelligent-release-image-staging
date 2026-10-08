// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Isolated read-only browser fixtures; no deployment or device is contacted.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
const now = 2000000000;
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1100}});
  const errors = [], writes = [], calls = [], failures = new Set();
  let heldFile = null, holdFile = '', expire = false;
  const first = [
    {ts: now - 20, event: 'login', actor: 'console:operator', category: 'auth', result: 'ok', detail: '<img src=x onerror=alert(1)>'},
    {ts: now - 30, event: 'undeploy_finished', actor: 'system', target: 'router-a', category: 'onboard', result: 'ok'},
  ];
  const older = [{ts: now - 60, event: 'refresh', device_id: 'router-a', secret_name: 'catalog', old_id: 'old', new_id: 'new'}];
  const logs = Array.from({length: 31}, (_, index) => ({file: `log-${index}.txt`, device_id: `router-${index}`,
    finished_at: now - index * 60, action: index % 2 ? 'undeploy' : 'onboard', state: index % 3 ? 'done' : 'error', rc: index % 3 ? 0 : 1, size: 1234}));
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(value => {
    Date.now = () => value * 1000;
    window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
  }, now);
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      calls.push(url.pathname + url.search);
      if (request.method() !== 'GET') writes.push([request.method(), url.pathname]);
      if (expire && url.pathname === '/api/v1/audit') return route.fulfill({status: 401, json: {error: 'fixture expired'}});
      if (failures.has(url.pathname)) return route.fulfill({status: 503, json: {error: 'fixture unavailable'}});
      if (url.pathname.endsWith('/histogram')) {
        const since = Number(url.searchParams.get('since_ts') ?? now - Number(url.searchParams.get('window')));
        const until = Number(url.searchParams.get('until_ts') ?? now), count = Number(url.searchParams.get('buckets'));
        const seconds = (until - since) / count;
        return route.fulfill({json: {now, bucket_seconds: seconds,
          buckets: Array.from({length: count}, (_, index) => ({start: since + index * seconds, count: index % 4 + 1}))}});
      }
      if (url.pathname === '/api/v1/audit') {
        const before = Number(url.searchParams.get('before_ts') ?? now + 1);
        const rows = before === first.at(-1).ts ? older : before <= older.at(-1).ts ? [] : first;
        return route.fulfill({json: {events: rows.filter(event => event.ts > Number(url.searchParams.get('after_ts') || 0)
          && event.ts < before && (!url.searchParams.get('category') || event.category === url.searchParams.get('category')))}});
      }
      if (url.pathname === '/api/v1/deploy-logs') return route.fulfill({json: {logs: logs.filter(log =>
        log.finished_at > Number(url.searchParams.get('after_ts') || 0)
        && log.finished_at < Number(url.searchParams.get('before_ts') || now + 1))}});
      if (url.pathname.startsWith('/api/v1/deploy-logs/')) {
        if (url.pathname.endsWith('/' + holdFile)) { heldFile = route; return; }
        return route.fulfill({body: 'read-only log ' + url.pathname + '\n<script>unsafe()</script>', contentType: 'text/plain'});
      }
      const fixtures = {
        '/api/v1/session': {username: 'Monitoring fixture', csrf: 'fixture-only'},
        '/api/v1/help': {version: 'fixture', deployment_id: 'fixture-only'},
        '/api/v1/overview': {images: 0, devices: 0, assigned: 0, staged: 0, rollout: []},
        '/api/v1/images': {images: []}, '/api/v1/devices': {devices: []},
        '/api/v1/deployment': {layout: 'single-container', components: []},
        '/api/v1/telemetry/health': {otlp_export: {state: 'off'}},
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
  const command = action => page.evaluate(action => new Promise((resolve, reject) => {
    window.dispatchEvent(new CustomEvent('iris:monitoring-command', {detail: {action, resolve, reject}}));
  }), action);
  const screenshot = async name => {
    const directory = process.env.IRIS_BROWSER_SCREENSHOT_DIR;
    if (directory) { await fs.mkdir(directory, {recursive: true}); await page.screenshot({path: path.join(directory, name + '.png'), fullPage: true}); }
  };
  await page.goto('http://iris.test/#monitoring/audit');
  await page.locator('#audit-rows').getByText('operator', {exact: true}).waitFor();
  assert.match(await page.locator('#audit-rows').innerText(), /deployment\s+finished undeploying router-a/i);
  assert.equal(await page.locator('#audit-rows img').count(), 0);
  assert.equal(await page.locator('#audit-scope-tag').innerText(), 'Last 24 h');
  assert.equal(await page.locator('#audit-bars rect').count(), 24);
  assert.equal(calls.some(url => url.startsWith('/api/v1/deploy-logs')), false, 'hidden pane is not fetched');
  await screenshot('audit-desktop');

  await page.locator('#audit-load-older').click();
  await page.locator('#audit-rows').getByText('catalog old -> new', {exact: false}).waitFor();
  assert.equal(await page.locator('#audit-rows tr').count(), 3);
  calls.length = 0;
  await command('poll');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].startsWith('/api/v1/audit/histogram?'));
  assert.equal(await page.locator('#audit-rows tr').count(), 3);
  await page.locator('#audit-load-older').click();
  await page.waitForFunction(() => document.getElementById('audit-load-older').disabled);
  await page.locator('#audit-refresh').click();
  await page.waitForFunction(() => document.querySelectorAll('#audit-rows tr').length === 2);

  await page.locator('#audit-category').selectOption('onboard');
  await page.waitForFunction(() => document.querySelectorAll('#audit-rows tr').length === 1
    && document.getElementById('audit-rows').textContent.includes('finished undeploying'));
  assert.ok(calls.at(-1).includes('category=onboard'));
  await page.locator('#audit-category').focus();
  await command('poll');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'audit-category');
  await page.locator('#audit-category').selectOption('');
  await command('refresh');

  // Freeze the timeline domain while captured; only release commits a query.
  let rect = await page.locator('#audit-histogram').boundingBox();
  calls.length = 0;
  await page.mouse.move(rect.x + rect.width * .2, rect.y + 25);
  await page.mouse.down();
  await page.mouse.move(rect.x + rect.width * .7, rect.y + 25, {steps: 4});
  assert.equal(await page.locator('#audit-brush .brush-handle').count(), 2);
  await command('poll');
  assert.equal(calls.length, 0);
  await page.mouse.up();
  await page.waitForFunction(() => !document.getElementById('audit-clear-selection').hidden);
  await command('poll');
  const selected = calls.map(url => new URL(url, 'http://iris.test'));
  const hist = selected.find(url => url.pathname.endsWith('/histogram'));
  const list = selected.find(url => url.pathname === '/api/v1/audit');
  assert.equal(hist.searchParams.get('since_ts'), list.searchParams.get('after_ts'));
  assert.equal(hist.searchParams.get('until_ts'), list.searchParams.get('before_ts'));
  assert.ok(Number(hist.searchParams.get('buckets')) <= 90);
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => document.getElementById('audit-clear-selection').hidden);
  await command('refresh');

  rect = await page.locator('#audit-histogram').boundingBox();
  await page.mouse.click(rect.x + rect.width / 2, rect.y + 25);
  await page.waitForFunction(() => !document.getElementById('audit-clear-selection').hidden);
  await command('refresh');
  const beforeCancel = await page.locator('#audit-window-label').innerText();
  await page.mouse.move(rect.x + rect.width / 3, rect.y + 25);
  await page.mouse.down();
  await page.mouse.move(rect.x + rect.width / 2, rect.y + 25);
  await page.locator('#audit-histogram').dispatchEvent('pointercancel');
  await page.mouse.up();
  assert.equal(await page.locator('#audit-window-label').innerText(), beforeCancel);
  await page.locator('#audit-clear-selection').click();
  await command('refresh');
  await page.locator('#audit-histogram').focus();
  await page.keyboard.press('ArrowRight');
  await page.waitForFunction(() => !document.getElementById('audit-clear-selection').hidden);
  await page.locator('#audit-range-chips [data-range="7d"]').click();
  await command('refresh');
  assert.equal(await page.locator('#audit-scope-tag').innerText(), 'Last 7 d');
  assert.equal(await page.locator('#audit-clear-selection').isHidden(), true);

  failures.add('/api/v1/audit');
  await command('refresh');
  await page.getByText('Audit trail could not be refreshed. Try Refresh.', {exact: true}).waitFor();
  assert.equal(await page.locator('#audit-rows tr').count(), 2, 'refresh failure retains known evidence');
  await page.locator('#audit-category').selectOption('image');
  await page.locator('#audit-rows').getByText('Unavailable.', {exact: true}).waitFor();
  failures.clear();

  await page.goto('http://iris.test/#monitoring/deploylogs');
  await page.waitForFunction(() => document.querySelectorAll('#dl-rows tr').length === 25);
  assert.equal(await page.locator('#dl-page').innerText(), 'page 1 of 2');
  await page.locator('#dl-next').click();
  assert.equal(await page.locator('#dl-rows tr').count(), 6);
  await command('poll');
  assert.equal(await page.locator('#dl-page').innerText(), 'page 2 of 2');
  calls.length = 0;
  await page.locator('#dl-search').fill('ROUTER-30');
  assert.equal(await page.locator('#dl-rows tr').count(), 1);
  assert.equal(await page.locator('#dl-count').innerText(), '1 log of 31');
  assert.equal(calls.length, 0, 'typing searches locally');
  await page.locator('#dl-search').fill('');
  await page.locator('#dl-action').selectOption('undeploy');
  assert.equal(await page.locator('#dl-count').innerText(), '15 logs of 31');
  await page.locator('#dl-result').selectOption('error');
  assert.equal(await page.locator('#dl-count').innerText(), '5 logs of 31');
  await page.locator('#dl-action').selectOption('');
  await page.locator('#dl-result').selectOption('');
  await screenshot('deployment-desktop');

  holdFile = 'log-0.txt';
  await page.locator('#dl-rows .dlog-view').first().click();
  await page.locator('#dl-text').getByText('Loading log-0.txt…', {exact: true}).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'dl-drawer-close');
  assert.equal(await page.locator('#dl-drawer').getAttribute('aria-modal'), null);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.className), 'linkish dlog-view');
  await page.locator('#dl-rows .dlog-view').nth(1).click();
  await page.locator('#dl-text').getByText('read-only log', {exact: false}).waitFor();
  assert.ok(heldFile);
  await heldFile.fulfill({body: 'old log must not replace selected file', contentType: 'text/plain'});
  await page.evaluate(() => new Promise(requestAnimationFrame));
  assert.equal(await page.locator('#dl-drawer-title').innerText(), 'log-1.txt');
  assert.match(await page.locator('#dl-text').innerText(), /log-1\.txt/);
  assert.equal(await page.locator('#dl-text script').count(), 0);
  assert.ok(await page.locator('#dl-drawer-close').evaluate(node => node.getBoundingClientRect().top >= 56), 'close control stays below the fixed header');
  assert.ok(await page.locator('#dl-text').evaluate(node => Math.abs(node.getBoundingClientRect().bottom - innerHeight) <= 2), 'log text fills the drawer');
  await screenshot('deployment-log-drawer');
  await page.locator('#dl-drawer-close').click();

  await page.locator('#dl-histogram').focus();
  await page.keyboard.press('ArrowRight');
  await command('refresh');
  assert.equal(await page.locator('#dl-brush .brush-sel').evaluate(node => getComputedStyle(node).fill), 'rgba(39, 116, 217, 0.14)');
  rect = await page.locator('#dl-histogram').boundingBox();
  await page.mouse.click(rect.x + rect.width / 2, rect.y + 25);
  await command('refresh');
  assert.equal(await page.locator('#dl-clear-selection').isHidden(), true, 'deployment click clears its selection');
  failures.add('/api/v1/deploy-logs');
  await command('refresh');
  await page.getByText('Deployment logs could not be refreshed. Try Refresh.', {exact: true}).waitFor();
  assert.equal(await page.locator('#dl-rows tr').count(), 25);
  failures.clear();
  await command('refresh');

  await page.setViewportSize({width: 390, height: 844});
  await screenshot('deployment-mobile');
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'mobile page must not overflow');
  assert.equal(await page.locator('#dl-histogram').evaluate(node => getComputedStyle(node).touchAction), 'none');
  logs[0].file = 'device-' + 'a'.repeat(64) + '.log';
  await command('refresh');
  await page.locator('#dl-rows .dlog-view').first().click();
  await page.locator('#dl-text').getByText('read-only log', {exact: false}).waitFor();
  assert.ok(await page.locator('#dl-drawer-close').evaluate(node => node.getBoundingClientRect().right <= innerWidth), 'long filenames cannot push Close off screen');
  await screenshot('deployment-mobile-long-file');
  await page.locator('#dl-drawer-close').click();
  await page.goto('http://iris.test/#monitoring/audit');
  await command('refresh');
  await screenshot('audit-mobile');
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.deepEqual(writes, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  expire = true;
  await page.locator('#audit-refresh').click();
  await page.waitForURL('http://iris.test/login.html');
  console.log('Monitoring timelines, pagination, filters, failures, plain-text logs, focus, session expiry and CSP passed.');
} finally { await browser.close(); }
