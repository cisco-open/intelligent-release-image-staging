// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Shipped assets with intercepted endpoints; no live policy or device writes.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url)), browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}}); page.setDefaultTimeout(10000);
  const errors = [], writes = [], prompts = [], policyReads = [];
  let mode = 'ok', held, reached, accept = true;
  const policy = {revision: 7, quarantine_assignments: [], roles_supported: true, roles: {defined: 2, restricted: 1, members: {boat: 2, fiber: 1}},
    enforcement: {state: 'enforced', stale: false, mutual_origin: {mode: 'preflight', newly_denied_device_count: 0}},
    fleet_rollup: {applied: {'9223372036854775807': 2}, states: {'<img src=x onerror=alert(1)>': 2}},
    instruction_status: {issued_revision_label: 'r9223372036854775807', pointer_skew: 0},
    instruction_keys: {enabled: true, state: 'ready', root_quorum_degraded: false, roots_attested_180d: 2, roots_configured: 2,
      certificate_renewal_due: false, signing_refused: false, keylist_resign_due: false}};
  let roles = {boat: {restricted: true, peers: ['boat', 'fiber'], origin: false, qos: {numwant: 10}, qos_state: {seeder: {numwant: 8}}},
    fiber: {restricted: false, peers: ['fiber', 'boat'], origin: false}};
  const preview = (extra = {}) => ({ok: true, dry_run: true, revision: policy.revision + 1, member_delta: 0, origin_access_lost: 1,
    empty_permitted_sets: 0, role_pairs_stopped: 1, qos_changed: true, requires_confirmation: true, confirm_token: 'reviewed-token', ...extra});
  page.on('pageerror', error => errors.push(error.message)); page.on('dialog', async dialog => {prompts.push(dialog.message()); await (accept ? dialog.accept() : dialog.dismiss());});
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation', event => window.csp.push(event.violatedDirective));});
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()); assert.equal(url.origin, 'http://iris.test');
    if (url.pathname.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'fixture-only');
        const body = request.postDataJSON(); writes.push({path: url.pathname + url.search, body, headers: request.headers()});
        assert.ok(url.pathname.startsWith('/api/v1/peer-policy/roles/'));
        if (url.searchParams.get('dry_run') === '1') {
          if (mode === 'hold') {held = route; reached(); return;}
          return route.fulfill({json: preview(url.pathname.endsWith('/import-csv') ? {roles: 2} : {})});
        }
        if (mode === 'empty') return route.fulfill({json: {}});
        policy.revision++;
        if (request.method() === 'DELETE') {delete roles[url.pathname.split('/').at(-1)]; return route.fulfill({status: 204, headers: {ETag: `"iris-peer-policy-${policy.revision}"`}});}
        if (request.method() === 'PUT') {const {confirm_token, ...definition} = body; roles[url.pathname.split('/').at(-1)] = definition;}
        return route.fulfill({json: {ok: true, dry_run: false, revision: policy.revision, ...(request.method() === 'POST' ? {roles: 2} : {})}});
      }
      if (url.pathname.startsWith('/api/v1/peer-policy')) policyReads.push(url.pathname);
      if (url.pathname.endsWith('/roles/export-csv')) return route.fulfill({body: 'role,restricted\nboat,true\nfiber,true\n', contentType: 'text/csv'});
      const fixtures = {'/api/v1/session': {username: 'Policy fixture', csrf: 'fixture-only'}, '/api/v1/help': {version: 'fixture'},
        '/api/v1/peer-policy': policy, '/api/v1/peer-policy/roles': {revision: policy.revision, roles}, '/api/v1/devices': {devices: [], total: 0, offset: 0, revision: 1, now: 2000000000},
        '/api/v1/images': {images: []}, '/api/v1/credentials': {profiles: []}, '/api/v1/onboard/jobs': {jobs: []}, '/api/v1/schedules': {schedules: [], total: 0}};
      return route.fulfill({status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || {error: 'unavailable'}});
    }
    const file = url.pathname.startsWith('/assets/') ? path.join(root, 'dist', path.basename(url.pathname)) : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
      headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});} catch {return route.fulfill({status: 404, body: ''});}
  });
  const focus = selector => page.locator(selector).evaluate(node => node === document.activeElement);
  const idle = () => page.waitForFunction(() => !window.irisPolicies.state.busy && !window.irisPolicies.state.loading);
  const save = async () => {await page.locator('#role-def-save').click(); await idle();};
  const edit = () => page.getByRole('button', {name: 'Edit role boat', exact: true}).click();
  const tabAwayAndBack = () => page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {configurable: true, value: true}); document.dispatchEvent(new Event('visibilitychange'));
    Object.defineProperty(document, 'hidden', {configurable: true, value: false}); document.dispatchEvent(new Event('visibilitychange'));
    delete document.hidden;
  });
  const snapshot = async name => {if (process.env.IRIS_BROWSER_SCREENSHOT_DIR) {await fs.mkdir(process.env.IRIS_BROWSER_SCREENSHOT_DIR, {recursive: true}); await page.screenshot({path: path.join(process.env.IRIS_BROWSER_SCREENSHOT_DIR, name + '.png')});}};
  await page.clock.install();
  await page.goto('http://iris.test/#policies'); await page.waitForFunction(() => window.irisPolicies?.current()); await idle();
  assert.equal(await page.getByRole('heading', {name: 'Device-to-device sharing', exact: true}).count(), 1);
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await snapshot('policies-overview-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000});
  await page.getByRole('button', {name: 'Edit role fiber', exact: true}).click();
  assert.equal(await page.locator('#rd-origin').isChecked(), true, 'Unrestricted role permits distribution even with a stored false field');
  assert.equal(await page.locator('#rd-origin').isDisabled(), true);
  await page.locator('#rd-restricted').check();
  assert.equal(await page.locator('#rd-origin').isChecked(), false, 'Enabling a limit preserves the stored draft permission');
  await page.locator('#role-def-cancel').click(); assert.equal(writes.length, 0);
  await edit(); assert.equal(await focus('#rd-restricted'), true); assert.equal(await page.locator('#rd-name').isDisabled(), true);
  await snapshot('policy-sharing-editor');
  await page.locator('#role-def-save').focus(); await page.keyboard.press('Tab'); assert.equal(await focus('#role-def-modal-x'), true);
  await page.keyboard.press('Escape'); assert.equal(await page.getByRole('button', {name: 'Edit role boat', exact: true}).evaluate(node => node === document.activeElement), true);
  await edit(); await page.locator('#role-editor-advanced summary').click(); assert.equal(await page.locator('[data-qos]').count(), 17);
  await page.locator('#rd-qos-numwant').fill('24'); await page.locator('#rd-qos-numwant').evaluate(node => node.setSelectionRange(0, 1));
  const beforeIdleReads = policyReads.length, beforeScroll = await page.locator('#role-def-modal .modal-body').evaluate(node => node.scrollTop);
  await page.clock.fastForward(16000); await tabAwayAndBack();
  assert.equal(policyReads.length, beforeIdleReads, 'No five- or ten-second policy reads, including tab return');
  assert.equal(await page.locator('#rd-qos-numwant').inputValue(), '24'); assert.equal(await focus('#rd-qos-numwant'), true);
  assert.deepEqual(await page.locator('#rd-qos-numwant').evaluate(node => [node.selectionStart, node.selectionEnd]), [0, 1]);
  assert.equal(await page.locator('#role-def-modal .modal-body').evaluate(node => node.scrollTop), beforeScroll);
  assert.equal(await page.locator('#role-def-modal').isVisible(), true);
  await page.locator('#rd-on-stale').selectOption('defaults');
  assert.match(await page.locator('#role-expiry-choice').innerText(), /no upload or download speed limit/);
  assert.match(await page.locator('#role-expiry-scope').innerText(), /Transfers can continue.*does not extend expired peer permissions/);
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height}); await page.locator('#role-expiry-help').scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await snapshot('policy-expiry-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000}); await page.locator('#rd-on-stale').selectOption('');
  await page.evaluate(() => window.irisPolicies.refresh()); assert.equal(await page.locator('#rd-qos-numwant').inputValue(), '24');
  await page.locator('#rd-qos-overall_up_bps').fill('4096'); await save(); assert.equal(writes.length, 0); assert.match(await page.locator('#role-def-msg').innerText(), /8192/);
  await page.locator('#rd-qos-overall_up_bps').fill('16384'); await save(); assert.equal(await focus('#role-def-save'), true);
  assert.deepEqual(writes[0].body.qos_state, {seeder: {numwant: 8}});
  assert.match(await page.locator('#role-def-preview').innerText(), /Membership changes: 0.*Speed or agent settings changed: yes/s);
  const reviewedText = await page.locator('#role-def-preview').innerText(), reviewedReads = policyReads.length;
  await page.clock.fastForward(16000); await tabAwayAndBack();
  assert.equal(policyReads.length, reviewedReads); assert.equal(await page.locator('#role-def-preview').innerText(), reviewedText);
  assert.equal(await page.locator('#role-def-save').innerText(), 'Save role');
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    await page.locator('#role-def-preview').scrollIntoViewIfNeeded();
    for (const selector of ['#role-def-modal .modal', '#role-def-modal-x', '#role-def-save', '#role-def-cancel']) {
      const box = await page.locator(selector).boundingBox(); assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= width && box.y + box.height <= height, selector);
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true); await snapshot('policy-preview-' + width);
  }
  await page.setViewportSize({width: 1440, height: 1000}); mode = 'empty'; await save();
  assert.equal(await page.locator('#role-def-save').isDisabled(), true); assert.match(await page.locator('#role-def-msg').innerText(), /may have been saved/);
  assert.deepEqual(writes.slice(0, 2).map(row => row.headers['if-match']), ['"iris-peer-policy-7"', '"iris-peer-policy-7"']);
  assert.equal(writes[1].body.confirm_token, 'reviewed-token');
  await page.locator('#role-def-cancel').click(); await edit(); assert.equal(await page.locator('#role-def-save').isDisabled(), true);
  await page.getByRole('button', {name: 'Reload current definition', exact: true}).click(); await idle();
  assert.equal(await page.locator('#role-def-save').isDisabled(), false); assert.equal(await page.locator('#rd-qos-numwant').inputValue(), '10');
  mode = 'ok'; await save(); await save(); assert.equal(await page.locator('#role-def-modal').isHidden(), true);
  await page.locator('#policy-advanced-open').click(); assert.equal(await focus('#policy-advanced-close'), true);
  const unrestricted = page.locator('#role-def-rows tr').filter({has: page.getByRole('cell', {name: 'fiber', exact: true})});
  assert.match(await unrestricted.innerText(), /No role limit.*All roles, if the other role permits sharing.*Allowed by role/s);
  await page.locator('.policy-diagnostics summary').filter({hasText: 'Instruction delivery and signing keys'}).click();
  assert.equal(await page.getByRole('heading', {name: 'Signing key status', exact: true}).count(), 1);
  assert.doesNotMatch(await page.locator('#policy-advanced-modal .policy-diagnostics').innerText(), /key custody|Root ceremony|Root quorum/);
  assert.match(await page.locator('#policy-applied-revisions').innerText(), /r9223372036854775807: 2/);
  assert.equal(await page.locator('#policy-issued-revision').innerText(), 'r9223372036854775807');
  assert.match(await page.locator('#policy-instruction-states').innerText(), /<img src=x onerror=alert\(1\)>/);
  assert.equal(await page.locator('#policy-instruction-states img').count(), 0);
  assert.equal(await page.locator('#instruction-key-actions').innerText(), 'None');
  assert.match(await page.locator('#policy-mutual-origin').innerText(), /0 newly denied devices.*not active/);
  const download = page.waitForEvent('download'); await page.locator('#role-def-export').click(); assert.equal((await download).suggestedFilename(), 'roles.csv');
  const csv = 'role,restricted\nboat,true\nfiber,true\n';
  await page.locator('#role-def-file').setInputFiles({name: 'roles.csv', mimeType: 'text/csv', buffer: Buffer.from(csv)}); await idle();
  assert.match(prompts.at(-1), /Replace every role definition.*2 role.*Roles missing from the file are removed/s);
  assert.equal(writes.at(-1).body.csv, csv); assert.match(await page.locator('#role-def-status').innerText(), /Imported 2/);
  accept = false; const before = writes.length; await page.locator('.role-def-delete[data-role="fiber"]').click(); await idle();
  assert.equal(writes.length, before + 1); assert.match(await page.locator('#role-def-status').innerText(), /cancelled; nothing changed/);
  accept = true; await page.locator('.role-def-delete[data-role="fiber"]').click(); await idle(); assert.match(await page.locator('#role-def-status').innerText(), /deleted at policy revision/);
  await snapshot('policy-diagnostics');
  await page.locator('#policy-advanced-close').click(); assert.equal(await focus('#policy-advanced-open'), true);
  // An explicit refresh changing capability moves focus off the disabled edit button.
  await page.getByRole('button', {name: 'Edit role boat', exact: true}).focus(); policy.degraded = true;
  await page.evaluate(() => window.irisPolicies.refresh()); assert.equal(await focus('#policy-advanced-open'), true);
  assert.match(await page.locator('#role-capability-banner').innerText(), /degraded/); policy.degraded = false; await page.evaluate(() => window.irisPolicies.refresh());
  await edit(); mode = 'hold'; const arrived = new Promise(resolve => {reached = resolve;});
  await page.locator('#role-def-save').click(); await arrived; assert.equal(await focus('#role-def-modal-x'), true);
  await page.locator('#role-def-modal-x').click(); assert.equal(await page.getByRole('button', {name: 'Edit role boat', exact: true}).isDisabled(), true);
  await page.getByRole('navigation', {name: 'Primary', exact: true}).getByRole('link', {name: 'Inventory', exact: true}).click();
  await held.fulfill({json: preview()}); await idle(); assert.equal(await page.locator('#role-def-modal').isHidden(), true);
  assert.equal(await page.evaluate(() => window.irisInventory.state.bulkBusy), false);
  assert.deepEqual(errors, []); assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Policies: editing, exact preview/CAS, unknown-save recovery, CSV, native204 deletion, diagnostics, focus, mobile and CSP passed.');
} finally {await browser.close();}
