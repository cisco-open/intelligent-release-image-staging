// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built UI with intercepted APIs, not live-device qualification.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [];
  const id = '11111111-1111-4111-8111-111111111111';
  let rotation = {state: 'awaiting-approval', request_id: id, previous_public_key: 'ssh-ed25519 AAAA old\n', public_key: 'ssh-ed25519 BBBB new\n',
    previous_sha256: 'aa'.repeat(32), replacement_sha256: 'bb'.repeat(32), created_at: 1790160000, activated_at: null,
    retired_keylist_seq: null, root_ids: ['root-a', 'root-b']};
  let mode = 'wrong-state', hold, reached, inventoryAvailable = true;
  page.on('pageerror', error => errors.push(error.message)); page.on('dialog', dialog => dialog.accept());
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only'); writes.push(request.postDataJSON());
        if (mode === 'hold') {hold = route; reached(); return;}
        if (mode === 'wrong-id') return route.fulfill({json: {...rotation, state: 'retirement-pending', activated_at: 1790160001, request_id: '22222222-2222-4222-8222-222222222222'}});
        return route.fulfill({json: rotation}); // A valid status, but not the requested transition.
      }
      const inventory = {scope: 'server-certificate-files', observed_at: 1790160000, custody: null, items: [
        {id: 'root-a', label: '<img src=x onerror=alert(1)>', kind: 'public-key', source: 'server-file', state: 'public-key-present',
          fingerprint_sha256: 'SHA256:fixture', valid_from: null, expires_at: null, renew_at: null, refuse_at: null, impact: 'Confirm the public root with its holder.'}]};
      const fixtures = {'/api/v1/session': {username: 'Certificate fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/settings/certificates/instruction/rotation': rotation,
        '/api/v1/settings/certificates': inventoryAvailable ? inventory : null,
        '/api/v1/settings/setup-status': {admin: {state: 'ok'}, telemetry: {state: 'unset', enabled: false, source: 'env'}, packages: {state: 'absent', items: []}, image_verification: {state: 'unset'}}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  await page.goto('http://iris.test/#settings/certificates');
  const idle = () => page.waitForFunction(() => window.irisCertificates && !window.irisCertificates.state.busy && !Object.values(window.irisCertificates.state.loading).some(Boolean));
  await page.locator('#rotation-state').getByText('Rotation: awaiting approval.', {exact: true}).waitFor(); await idle();
  assert.equal(await page.locator('#certificate-rows img').count(), 0);
  assert.match(await page.locator('#certificate-rows').innerText(), /<img src=x/); assert.match(await page.locator('#certificate-observed').innerText(), /unknown/);
  const choose = () => page.locator('#rotation-certificate').setInputFiles({name: 'approved.pub', mimeType: 'text/plain', buffer: Buffer.from('ssh-ed25519-cert-v01@openssh.com AAAA fixture\n')});
  await choose(); await page.locator('#rotation-activate').click(); await idle();
  assert.match(await page.locator('#rotation-result').innerText(), /Outcome unknown/); assert.equal(await page.locator('#rotation-activate').isDisabled(), true);
  assert.equal(await page.locator('#rotation-result').evaluate(node => node === document.activeElement), true, 'Disabled action moves focus to its outcome');
  await page.evaluate(() => {location.hash = '#settings/general';}); await page.locator('#settings-pane-general').waitFor({state: 'visible'});
  await page.evaluate(() => {location.hash = '#settings/certificates';}); await idle();
  assert.equal(writes.length, 1); assert.equal(await page.locator('#rotation-activate').isDisabled(), true, 'Navigation is not explicit recovery');
  await page.locator('#rotation-refresh').click(); await idle(); assert.equal(await page.locator('#rotation-activate').isDisabled(), false);
  mode = 'wrong-id'; await choose(); await page.locator('#rotation-activate').click(); await idle();
  assert.match(await page.locator('#rotation-result').innerText(), /Outcome unknown/); assert.equal(writes.length, 2);
  await page.locator('#rotation-refresh').click(); await idle();
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Fits ' + width);
    assert.equal(await page.locator('[data-certificate-group] input, [data-certificate-group] select').evaluateAll(nodes => nodes.every(node => node.labels.length > 0)), true);
    if (process.env.IRIS_UI_SCREENSHOTS) {
      await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
      for (const [id, name] of [['signer-rotation', 'signer'], ['iris-certificates-renewal', 'renewal']]) {
        await page.locator('#' + id).evaluate(node => window.scrollTo(0, window.scrollY + node.getBoundingClientRect().top - 72));
        await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'certificates-' + name + '-' + width + '.png')});
      }
      await page.locator('#rotation-approval').evaluate(node => window.scrollTo(0, window.scrollY + node.getBoundingClientRect().top - 72));
      await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'certificates-approval-' + width + '.png')});
    }
    assert.equal(await page.locator('#rotation-approval .certificate-actions').evaluate(node => {
      const buttons = [...node.querySelectorAll('button')].map(button => button.getBoundingClientRect());
      return buttons.every((a, i) => buttons.slice(i + 1).every(b => a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top));
    }), true, 'Approval actions do not overlap at ' + width);
  }
  // Leaving after dispatch must not cancel or replay a write. Public file
  // selection is discarded; the outcome remains visible on return.
  mode = 'hold'; const pending = new Promise(resolve => {reached = resolve;}); await choose();
  await page.locator('#rotation-activate').click(); await pending;
  assert.equal(await page.locator('#rotation-certificate').inputValue(), '');
  await page.evaluate(() => {location.hash = '#settings/general';}); await page.locator('#settings-pane-general').waitFor({state: 'visible'});
  rotation = {...rotation, state: 'retirement-pending', activated_at: 1790160001}; await hold.fulfill({json: rotation}); await idle();
  await page.evaluate(() => {location.hash = '#settings/certificates';});
  await page.locator('#rotation-state').getByText('Rotation: retirement pending.', {exact: true}).waitFor();
  assert.equal(writes.length, 3); assert.match(await page.locator('#rotation-result').innerText(), /Replacement signer active/);
  inventoryAvailable = false; await page.locator('#certificate-refresh').click(); await idle();
  assert.equal(await page.locator('#certificate-rows tr').count(), 0); assert.match(await page.locator('#certificate-observed').innerText(), /unavailable/);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Certificate browser checks passed: exact outcomes, explicit recovery, pending navigation, labels, focus, mobile and CSP.');
} finally {await browser.close();}
