// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Built UI and CSP with intercepted APIs, not live-deployment qualification.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], id = '11111111-1111-4111-8111-111111111111', other = '22222222-2222-4222-8222-222222222222';
  const certificate = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
  let tls = {state: 'approved', request_id: id, names: ['console.example'], mode: 'ca', created_at: 1790160000,
    csr: '-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n', certificate, fingerprint_sha256: 'ab'.repeat(32)};
  let credentials = {items: ['metrics-token', 'collector-headers'].map(family => ({family, request_id: null, state: 'deployment-managed', previous_retained: false, started_at: null, observed_at: null, endpoint: null}))};
  let mode = 'wrong-state', hold, reached, available = true;
  page.on('pageerror', error => errors.push(error.message)); page.on('dialog', dialog => dialog.accept());
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only'); const body = request.postDataJSON(); writes.push(body);
        if (mode === 'hold') {hold = route; reached(); return;}
        if (url.pathname.endsWith('/browser/rotation')) {
          if (mode === 'wrong-id') return route.fulfill({json: {...tls, state: 'published', request_id: other, applied: true, gui_cert: {source: 'custom', fingerprint_sha256: tls.fingerprint_sha256}}});
          if (mode === 'reload-pending') {tls = {...tls, state: 'published'}; return route.fulfill({json: {...tls, applied: false}});}
          if (mode === 'success') {tls = {...tls, state: 'published'}; return route.fulfill({json: {...tls, applied: true, gui_cert: {source: 'custom', fingerprint_sha256: tls.fingerprint_sha256}}});}
          return route.fulfill({json: tls});
        }
        return route.fulfill({json: credentials}); // Valid public status, no requested replacement.
      }
      const fixtures = {'/api/v1/session': {username: 'Lifecycle fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/settings/certificates/browser/rotation': available ? tls : null,
        '/api/v1/settings/service-credentials': available ? credentials : null,
        '/api/v1/settings/setup-status': {admin: {state: 'ok'}, telemetry: {state: 'unset', enabled: false, source: 'env'}, packages: {state: 'absent', items: []}, image_verification: {state: 'unset'}}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  await page.goto('http://iris.test/#settings/certificates');
  const idle = () => page.waitForFunction(() => window.irisSecurityLifecycle && !window.irisSecurityLifecycle.state.busy && !Object.values(window.irisSecurityLifecycle.state.loading).some(Boolean));
  const tab = async name => {await page.evaluate(name => {location.hash = '#settings/' + name;}, name); await page.locator('#settings-pane-' + name).waitFor({state: 'visible'}); await idle();};
  await page.locator('#browser-tls-state').getByText('Approved certificate ready to apply.', {exact: true}).waitFor(); await idle();
  assert.match(await page.locator('#browser-tls-next-step').innerText(), /current browser certificate is still active/);
  assert.match(await page.locator('[data-security-group=tls]').innerText(), /browser to the Console/);
  await page.locator('#browser-tls-workflow summary').click();
  assert.match(await page.locator('#browser-tls-identity').innerText(), new RegExp('ab'.repeat(32)));
  await page.locator('#browser-tls-workflow summary').click();
  for (const failure of ['wrong-state', 'wrong-id']) {
    mode = failure; await page.locator('#browser-tls-apply').click(); await idle();
    assert.match(await page.locator('#browser-tls-result').innerText(), /Outcome unknown/);
    assert.equal(await page.locator('#browser-tls-apply').isDisabled(), true);
    assert.equal(await page.locator('#browser-tls-result').evaluate(node => node === document.activeElement), true);
    const count = writes.length; await tab('general'); await tab('certificates');
    assert.equal(writes.length, count); assert.equal(await page.locator('#browser-tls-apply').isDisabled(), true, 'Navigation does not acknowledge uncertain outcomes');
    await page.locator('#browser-tls-refresh').click(); await idle();
    assert.equal(await page.locator('#browser-tls-apply').isDisabled(), false);
  }
  mode = 'reload-pending'; await page.locator('#browser-tls-apply').click(); await idle();
  assert.match(await page.locator('#browser-tls-result').innerText(), /has not confirmed reload/);
  assert.match(await page.locator('#browser-tls-state').innerText(), /saved; verify browser access/);
  assert.match(await page.locator('#browser-tls-next-step').innerText(), /every Console.*alone do not prove/);
  assert.match(await page.locator('#browser-tls-apply').innerText(), /Retry Console certificate reload/);
  mode = 'success'; await page.locator('#browser-tls-apply').click(); await idle();
  assert.match(await page.locator('#browser-tls-result').innerText(), /this Console listener reloaded/);
  mode = 'wrong-state'; await page.locator('#service-credential-token').fill('browser-only-secret'.repeat(3));
  await page.locator('#service-credential-replace').click(); await idle();
  assert.match(await page.locator('#service-credential-result').innerText(), /Outcome unknown/);
  assert.equal(await page.locator('#service-credential-token').inputValue(), '');
  assert.equal(await page.locator('#service-credential-replace').isDisabled(), true);
  assert.equal(await page.evaluate(() => JSON.stringify(window.irisSecurityLifecycle.pending).includes('browser-only-secret')), false);
  await page.locator('#service-credential-family').selectOption('collector-headers');
  await page.locator('#service-credential-endpoint').fill('https://collector.example:4318');
  await page.locator('#service-credential-headers [data-field=value]').fill('collector-local-secret');
  await page.locator('#service-credential-add-header').click();
  await page.locator('#service-credential-headers [data-field=name]').last().fill('X-Account');
  await page.locator('#service-credential-headers [data-field=value]').last().fill('local-account');
  await page.locator('#service-credential-headers button').last().click();
  assert.equal(await page.locator('#service-credential-add-header').evaluate(node => node === document.activeElement), true, 'Removed row returns focus to Add header');
  assert.equal(await page.locator('#service-credential-headers [data-field=value]').inputValue(), 'collector-local-secret', 'Removing another row preserves this row');
  await page.locator('#service-credential-family').selectOption('metrics-token');
  assert.equal(await page.locator('#service-credential-replace').isDisabled(), true, 'Other-family navigation never acknowledges metrics uncertainty');
  await page.locator('#service-credential-refresh').click(); await idle();
  await page.locator('#service-credential-family').selectOption('collector-headers');
  assert.equal(await page.locator('#service-credential-headers [data-field=value]').inputValue(), '');
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Fits ' + width);
    assert.equal(await page.locator('[data-security-group] input, [data-security-group] select').evaluateAll(nodes => nodes.every(node => node.labels.length > 0)), true);
    assert.equal(await page.locator('.security-field > input, .security-field > select').evaluateAll(nodes => nodes.filter(node => node.getClientRects().length).every(node => {
      const field = node.getBoundingClientRect(), label = node.parentElement.getBoundingClientRect();
      return field.left >= label.left && field.right <= label.right;
    })), true, 'Fields stay inside their labelled column at ' + width);
    assert.equal(await page.locator('.security-actions').evaluateAll(nodes => nodes.every(node => {
      const buttons = [...node.querySelectorAll('button')].map(button => button.getBoundingClientRect());
      return buttons.every((a, i) => buttons.slice(i + 1).every(b => a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top));
    })), true, 'Actions do not overlap at ' + width);
    if (process.env.IRIS_UI_SCREENSHOTS) {
      await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
      for (const [id, name] of [['iris-browser-tls', 'browser-tls'], ['iris-service-credentials', 'credentials']]) {
        await page.locator('#' + id).evaluate(node => window.scrollTo(0, window.scrollY + node.getBoundingClientRect().top - 72));
        await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'security-' + name + '-' + width + '.png')});
      }
    }
  }
  await page.locator('#service-credential-headers [data-field=value]').fill('unsent-private-value');
  await tab('general'); await tab('certificates');
  assert.equal(await page.locator('#service-credential-headers [data-field=value]').inputValue(), '');
  await page.locator('#service-credential-family').selectOption('metrics-token');
  await page.locator('#service-credential-token').fill('pending-fixture-token'.repeat(3));
  mode = 'hold'; const pending = new Promise(resolve => {reached = resolve;});
  await page.locator('#service-credential-replace').click(); await pending;
  assert.equal(await page.locator('#service-credential-token').inputValue(), '', 'Clear before response, not after success');
  assert.equal(await page.locator('#service-credential-family').isDisabled(), true);
  await page.evaluate(() => {location.hash = '#settings/general';}); await page.locator('#settings-pane-general').waitFor({state: 'visible'});
  const body = writes.at(-1), item = credentials.items[0];
  Object.assign(item, {request_id: body.request_id, state: 'awaiting-verification', started_at: 1790160000});
  await hold.fulfill({json: credentials}); await idle(); await tab('certificates');
  assert.match(await page.locator('#service-credential-result').innerText(), /Replacement saved/);
  assert.equal(await page.locator('#service-credential-retire').isDisabled(), true);
  assert.equal(writes.length, 6, 'Submitted operation completes once across navigation');
  available = false; await page.locator('#service-credential-refresh').click(); await idle();
  assert.match(await page.locator('#service-credential-state').innerText(), /unavailable/);
  assert.match(await page.locator('#service-credential-result').innerText(), /Replacement saved/, 'Failed read does not erase completed write');
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Security lifecycle browser checks passed: exact results, reload distinction, secret clearing, pending writes, focus, labels, mobile and CSP.');
} finally {await browser.close();}
