// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built UI and CSP; intercepted APIs are not live-deployment qualification.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {id, other, certificate, prepared, trust, rotation, backups, maintenance, job} from './worker-fixtures.mjs';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], fixtures = {trust: trust(), rotation: rotation(), backups: backups(), maintenance: maintenance()};
  fixtures.trust.items[0] = prepared('device-tls', 'awaiting-approval');
  let mode = 'wrong-id', held, reached;
  const endpoints = {'trust-rotation': 'trust', 'deployment-rotation': 'rotation', 'backups': 'backups', 'key-maintenance': 'maintenance'};
  page.on('pageerror', error => errors.push(error.message)); page.on('dialog', dialog => dialog.accept());
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      const kind = endpoints[url.pathname.split('/').at(-1)];
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only'); const body = request.postDataJSON(); writes.push(body);
        if (mode === 'hold') {held = route; reached(); return;}
        if (kind === 'trust') {
          const row = {...prepared(body.family), request_id: mode === 'wrong-id' ? other : body.request_id, state: mode === 'wrong-state' ? 'awaiting-approval' : 'approved'};
          if (mode === 'success') fixtures.trust.items[0] = row;
          return route.fulfill({json: row});
        }
        if (kind === 'maintenance') {
          if (mode === 'success') fixtures.maintenance = {...fixtures.maintenance, revision: body.revision + 1, policies: [body.policy]};
          return route.fulfill({json: fixtures.maintenance});
        }
        if (mode === 'success') fixtures[kind].jobs = [{...job(body.action === 'recover-restore' ? 'restore' : body.action), id: body.request_id, backup_id: body.backup_id || body.request_id}];
        return route.fulfill({json: {job_id: mode === 'wrong-id' ? other : body.request_id}});
      }
      if (kind) return route.fulfill({json: fixtures[kind]});
      const otherFixtures = {'/api/v1/session': {username: 'Worker fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/settings/setup-status': {admin: {state: 'ok'}, telemetry: {state: 'unset', enabled: false, source: 'env'}, packages: {state: 'absent', items: []}, image_verification: {state: 'unset'}}};
      return route.fulfill({status: otherFixtures[url.pathname] ? 200 : 503, json: otherFixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const idle = () => page.waitForFunction(() => window.irisWorkerLifecycle && !window.irisWorkerLifecycle.state.busy && !Object.values(window.irisWorkerLifecycle.state.loading).some(Boolean));
  const tab = async name => {await page.evaluate(name => {location.hash = '#settings/' + name;}, name); await page.locator('#settings-pane-' + name).waitFor({state: 'visible'}); await idle();};
  await page.goto('http://iris.test/#settings/certificates'); await idle();
  await page.locator('#deployment-rotation-family').selectOption('peer-ca');
  await page.getByRole('link', {name: 'Open devices to remove IRIS deployments'}).click();
  await page.locator('#view-devices').waitFor({state: 'visible'}); await tab('certificates');
  await page.locator('#deployment-rotation-family').selectOption('device-tls');
  for (const failure of ['wrong-id', 'wrong-state']) {
    mode = failure;
    await page.locator('#deployment-rotation-certificate').setInputFiles({name: 'approved.pem', mimeType: 'text/plain', buffer: Buffer.from(certificate)});
    await page.locator('#deployment-rotation-approve').click(); await idle();
    assert.match(await page.locator('#deployment-rotation-result').innerText(), /Outcome unknown/);
    assert.equal(await page.locator('#deployment-rotation-approve').isDisabled(), true);
    assert.equal(await page.locator('#deployment-rotation-result').evaluate(node => node === document.activeElement), true);
    assert.equal(await page.locator('#deployment-rotation-certificate').evaluate(node => node.files.length), 0);
    const count = writes.length; await tab('backups'); await tab('certificates');
    assert.equal(writes.length, count); assert.equal(await page.locator('#deployment-rotation-approve').isDisabled(), true);
    await page.locator('#deployment-rotation-refresh').click(); await idle();
    assert.equal(await page.locator('#deployment-rotation-approve').isDisabled(), false);
  }
  mode = 'wrong-revision'; await page.locator('#maintenance-family').selectOption('browser-tls');
  await page.locator('#maintenance-save').click(); await idle();
  assert.match(await page.locator('#maintenance-result').innerText(), /Outcome unknown/);
  assert.equal(await page.locator('#maintenance-save').isDisabled(), true);
  await page.locator('#maintenance-refresh').click(); await idle(); mode = 'success';
  await page.locator('#maintenance-save').click(); await idle();
  assert.match(await page.locator('#maintenance-result').innerText(), /Schedule saved at revision 1/);
  await page.locator('#maintenance-window').fill('45'); fixtures.maintenance.revision = 2;
  await page.locator('#maintenance-refresh').click(); await idle();
  assert.equal(await page.locator('#maintenance-window').inputValue(), '45'); assert.equal(await page.locator('#maintenance-save').isDisabled(), true);
  await page.locator('#maintenance-reload').click(); assert.equal(await page.locator('#maintenance-window').inputValue(), '30');
  await tab('backups'); mode = 'wrong-id'; await page.locator('#backup-create').click(); await idle();
  assert.match(await page.locator('#backup-operation-result').innerText(), /Outcome unknown/);
  assert.equal(await page.locator('#backup-create').isDisabled(), true);
  const accepted = writes.at(-1).request_id;
  await tab('certificates');
  await page.locator('#deployment-rotation-workflow').getByRole('link', {name: 'Backup & restore'}).waitFor();
  assert.equal(await page.locator('#deployment-rotation-apply').isDisabled(), true); await tab('backups');
  fixtures.backups.jobs = [{...job('backup', 'captured'), id: accepted, backup_id: accepted}];
  await page.locator('#backup-refresh').click(); await idle();
  assert.equal(await page.locator('#backup-create').isDisabled(), false); await page.locator('#backup-selected').selectOption(accepted);
  mode = 'success'; await page.locator('#backup-restore').click(); await idle();
  assert.match(await page.locator('#backup-operation-result').innerText(), /Accepted operation.*Refresh history/);
  assert.equal(await page.locator('#backup-create').isDisabled(), true);
  const restore = writes.at(-1); fixtures.backups.jobs[0].state = 'recovery-required';
  await page.locator('#backup-refresh').click(); await idle(); await page.locator('#backup-recover').click(); await idle();
  assert.equal(writes.at(-1).action, 'recover-restore'); assert.equal(writes.at(-1).request_id, restore.request_id); assert.equal(writes.at(-1).backup_id, accepted);
  fixtures.backups.jobs[0].state = 'restored';
  for (const pane of ['certificates', 'backups']) {
    await tab(pane);
    for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
      await page.setViewportSize({width, height});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, pane + ' fits ' + width);
      assert.equal(await page.locator('[data-worker-group] input, [data-worker-group] select').evaluateAll(nodes => nodes.every(node => node.labels.length > 0)), true);
      assert.equal(await page.locator('.worker-actions').evaluateAll(nodes => nodes.every(node => {
        const buttons = [...node.querySelectorAll('button')].map(button => button.getBoundingClientRect());
        return buttons.every((a, i) => buttons.slice(i + 1).every(b => a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top));
      })), true, 'Actions do not overlap');
      if (process.env.IRIS_UI_SCREENSHOTS) {
        await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
        for (const target of pane === 'certificates' ? ['iris-worker-deployment', 'iris-worker-maintenance'] : ['iris-worker-backups']) {
          await page.locator('#' + target).evaluate(node => window.scrollTo(0, window.scrollY + node.getBoundingClientRect().top - 72));
          await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, target + '-' + width + '.png')});
        }
      }
    }
  }
  await page.setViewportSize({width: 1440, height: 1000}); mode = 'hold'; const pending = new Promise(resolve => {reached = resolve;});
  await page.locator('#backup-create').click(); await pending; assert.equal(await page.locator('#backup-refresh').isDisabled(), true);
  await page.evaluate(() => {location.hash = '#settings/general';}); await page.locator('#settings-pane-general').waitFor({state: 'visible'}); const count = writes.length;
  await held.fulfill({json: {job_id: other}}); await idle(); await tab('backups');
  assert.equal(writes.length, count); assert.equal(await page.locator('#backup-create').isDisabled(), true);
  assert.deepEqual(await page.evaluate(() => window.csp), []); assert.deepEqual(errors, []);
  console.log('Worker lifecycle smoke passed: exact approvals/revisions/jobs, uncertainty, recovery, labels, focus, responsive layout and CSP.');
} finally {await browser.close();}
