// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
// Isolated map/API fixtures. Never contacts the lab or opens an owner session.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const now = Math.floor(Date.now() / 1000);
const peer = (id, supported = true) => ({device_id: id, ip: id === 'XR-A' ? '192.0.2.1' : '192.0.2.2',
  port: 6881, model: id === 'XR-A' ? '8000' : 'C8000V',
  tracker: {principal_type: 'device', principal_id: id, role: 'seeder', last_seen: now},
  current_image_id: 'release', stage_state: 'staging', staged_image_ids: [], errored_image_ids: [],
  device_observation: {image_id: 'release', obs_state: 'observed', stale: false, valid: true},
  peer_telemetry: {supported, requested_interval_s: 60, effective_interval_s: 60}});
const data = {now, server: {host: 'Distribution'}, images: [{image: 'Release image',
  image_id: 'release', info_hash: 'a'.repeat(40), peers: [peer('XR-A'), peer('XE-B')],
  peer_edges: [{source_device_id: 'XR-A', target_device_id: 'XE-B',
    bytes_per_second: 1048576, reporter_device_id: 'XE-B', rate_field: 'receive_bps',
    identity_basis: 'unique_tracker_address', received_at: now, valid_for_s: 120}]}]};
let html = await fs.readFile(new URL('../dist/swarmmap.html', import.meta.url), 'utf8');
assert.match(html, /swarm-map/, 'Exercise the generated React map, not the retired inline renderer');
html = html.replace('window.IRIS_MAP_CFG = null;',
  'window.IRIS_MAP_CFG = {swarmUrl:"/api/v1/swarm",pull:true};')
  .replace('<script>', '<script nonce="test">').replace('<style>', '<style nonce="test">');
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}, reducedMotion: 'reduce'});
  await page.clock.install();
  const errors = [], writes = [], confirmations = [];
  await page.addInitScript(() => {window.csp = []; window.addEventListener('securitypolicyviolation',
    event => window.csp.push(event.violatedDirective));});
  let acceptConfirmation = true;
  page.on('dialog', async dialog => { confirmations.push(dialog.message());
    if (acceptConfirmation) await dialog.accept(); else await dialog.dismiss(); });
  let refused = false, wrongCommit = false, holdPolicy = false, heldPolicy = null, swarmReads = 0, sessionReads = 0;
  const directive = {request_id: 'a'.repeat(32), requested_at: now, expires_at: now + 600};
  let reports = [], pending = null, pulls = 0;
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, 'http://iris.test');
    if (url.pathname === '/embedded-host') return route.fulfill({contentType: 'text/html',
      body: '<!doctype html><html><body><iframe id="embedded" src="/swarmmap" width="1400" height="900" hidden title="Swarm"></iframe></body></html>'});
    if (url.pathname === '/swarmmap') return route.fulfill({contentType: 'text/html', body: html,
      headers: {'Content-Security-Policy': "default-src 'self'; script-src 'nonce-test'; style-src 'nonce-test'; connect-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'"}});
    if (url.pathname.startsWith('/assets/')) {
      const file = path.join(root, 'dist', path.basename(url.pathname));
      return route.fulfill({body: await fs.readFile(file), contentType:
        {'.js': 'text/javascript', '.css': 'text/css'}[path.extname(file)] || 'application/octet-stream'});
    }
    if (url.pathname === '/api/v1/swarm') { swarmReads++; return route.fulfill({json: data}); }
    if (url.pathname === '/api/v1/session') {sessionReads++; return route.fulfill({json: {csrf: 'test-only'}});}
    if (url.pathname === '/api/v1/peer-policy') {
      if (holdPolicy) { heldPolicy = route; return; }
      return route.fulfill({json: {revision: 7}});
    }
    if (url.pathname.endsWith('/effective-qos')) return route.fulfill({json: {
      device_id: 'XE-B', revision: 8, degraded: false, fail_closed: false,
      qos: {peer_telemetry_interval_s: {value: 60}}}});
    if (url.pathname.endsWith('/reports')) return route.fulfill({json: {
      device_id: 'XE-B', observed_at: now + 5, pending_request: pending, reports}});
    if (url.pathname.endsWith('/request-report')) { pulls++; pending = directive;
      return route.fulfill({json: {ok: true, device_id: 'XE-B', ...directive}}); }
    if (url.pathname.endsWith('/peer-telemetry')) {
      assert.equal(route.request().method(), 'POST');
      assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
      assert.equal(route.request().headers()['if-match'], '"iris-peer-policy-7"');
      const body = route.request().postDataJSON();
      writes.push({preview: url.searchParams.get('dry_run') === '1', body});
      if (refused) return route.fulfill({status: 412, json: {code: 'policy_changed'}});
      if (!url.search) assert.equal(body.confirm_token, 'preview-only-fixture');
      return route.fulfill({json: {ok: true, device_id: wrongCommit && !url.search ? 'OTHER' : 'XE-B',
        requested_interval_s: body.interval_s, revision: 8, candidate_revision: 8,
        dry_run: !!url.search, requires_confirmation: true, confirm_token: 'preview-only-fixture'}});
    }
    if (url.pathname.startsWith('/fonts/')) return route.fulfill({body:
      await fs.readFile(new URL('../../webroot' + url.pathname, import.meta.url))});
    throw new Error('Unexpected request: ' + url.pathname);
  });
  await page.goto('http://iris.test/swarmmap');
  const arrow = page.locator('.peer-transfer');
  await arrow.waitFor();
  assert.equal(await arrow.count(), 1);
  assert.match(await arrow.getAttribute('aria-label'), /^XR-A → XE-B: 1.0 MB\/s/);
  assert.equal(await arrow.evaluate(node => getComputedStyle(node).animationName), 'none');
  await arrow.focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#drawer h2').textContent(), 'XE-B');
  assert.equal(await page.locator('#close').evaluate(node => node === document.activeElement), true);
  await page.locator('#peer-interval').focus();
  // A new participant before the selected row must not steal identity, focus,
  // or the currently edited interval as the same drawer refreshes.
  data.images[0].peers.unshift(peer('NEW-C'));
  data.images[0].peers.find(p => p.device_id === 'XE-B').staged_image_ids = ['release'];
  await page.clock.fastForward(5100);
  await page.waitForFunction(() => document.querySelector('#peer-details')?.textContent.includes('ready'));
  assert.equal(await page.locator('#drawer h2').textContent(), 'XE-B');
  assert.equal(await page.locator('#peer-interval').evaluate(node => node === document.activeElement), true);
  await page.keyboard.press('Escape');
  assert.equal(await arrow.evaluate(node => node === document.activeElement), true, 'Closing restores the opening graph control');
  await arrow.press('Enter');
  await page.locator('#peer-interval').selectOption('10');
  await page.locator('#save-peer-interval').click();
  await page.getByText(/Saved. Waiting for the device/).waitFor();
  assert.deepEqual(writes, [{preview: true, body: {interval_s: 10}},
    {preview: false, body: {interval_s: 10, confirm_token: 'preview-only-fixture'}}]);
  assert.equal(confirmations.length, 1);
  assert.match(confirmations[0], /XE-B to 10 seconds/);
  assert.match(confirmations[0], /revision 7 will become 8/);
  // A saved request must not be presented as already effective on the device.
  assert.match(await page.locator('#peer-details').textContent(), /Reported interval60s/);
  // Cancelling the reviewed policy change never sends the mutation.
  acceptConfirmation = false;
  await page.locator('#peer-interval').selectOption('60');
  await page.locator('#save-peer-interval').click();
  await page.getByText('Interval change cancelled. No update was sent.').waitFor();
  assert.equal(writes.length, 3); assert.equal(writes.at(-1).preview, true);
  assert.match(confirmations.at(-1), /XE-B to 60 seconds/);
  acceptConfirmation = true;
  refused = true;
  await page.locator('#peer-interval').selectOption('60');
  await page.locator('#save-peer-interval').click();
  await page.getByText('Policy changed. Review the current interval before trying again.').waitFor();
  assert.equal(writes.length, 4, 'A failed preview must never commit');
  await page.keyboard.press('Escape');
  await page.locator('#peerfind').fill('XR-A');
  assert.equal(await arrow.count(), 0, 'No arrows to hidden endpoints');
  assert.equal(await page.locator('#peertable tbody tr').count(), 1);
  await page.locator('#peerfind').fill('NO-SUCH-DEVICE');
  await page.getByText('No participants match the current filter.').waitFor();
  assert.equal(await page.locator('#peertable tbody tr').count(), 0);
  await page.locator('#peerfind').fill('');
  await arrow.waitFor();
  // Pointer input must open the same receiver without starting a pan.
  await arrow.dispatchEvent('pointerdown', {pointerId: 1, clientX: 20, clientY: 20});
  assert.equal(await page.locator('#svg.panning').count(), 0);
  await arrow.dispatchEvent('click');
  assert.equal(await page.locator('#drawer h2').textContent(), 'XE-B');
  await page.keyboard.press('Escape');
  if (process.env.SWARM_SCREENSHOT) await page.screenshot({path: process.env.SWARM_SCREENSHOT, fullPage: true});
  for (const [width, height] of [[390, 844], [320, 568]]) {
    await page.setViewportSize({width, height});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'Map fits ' + width + 'px; table overflow stays within its scroll container');
    await page.getByRole('button', {name: 'Open XE-B (C8000V) details', exact: true}).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'Drawer fits ' + width + 'px');
    await page.locator('#close').focus(); await page.keyboard.press('Shift+Tab');
    assert.equal(await page.locator('#review-pull').evaluate(node => node === document.activeElement), true,
      'Dialog traps reverse keyboard traversal');
    await page.keyboard.press('Tab');
    assert.equal(await page.locator('#close').evaluate(node => node === document.activeElement), true,
      'Dialog traps forward keyboard traversal');
    await page.keyboard.press('Escape');
  }
  await page.setViewportSize({width: 1440, height: 1000});
  await page.locator('#pause').click();
  await page.clock.fastForward(121000);
  assert.equal(await arrow.count(), 0, 'Paused snapshots must expire measured arrows');
  data.images[0].peers.find(p => p.device_id === 'XE-B').peer_telemetry.supported = false;
  await page.reload();
  await page.getByRole('button', {name: 'Open XE-B (C8000V) details', exact: true}).click();
  await page.locator('#drawer').waitFor({state: 'visible'});
  assert.equal(await page.locator('#peer-interval option[value="10"]').evaluate(option => option.disabled), true);
  refused = false;
  // Wrong target replies never produce success, and re-opening cannot replay.
  wrongCommit = true;
  await page.locator('#save-peer-interval').click();
  await page.getByText('Save outcome is not confirmed. Review the current interval before trying again.').waitFor();
  assert.equal(await page.locator('#save-peer-interval').isDisabled(), true);
  await page.keyboard.press('Escape');
  await page.getByRole('button', {name: 'Open XE-B (C8000V) details', exact: true}).click();
  assert.equal(await page.locator('#save-peer-interval').isDisabled(), true);
  wrongCommit = false;
  await page.locator('#review-peer-interval').click();
  await page.getByText(/Current requested interval: 60 seconds/).waitFor();
  // A host-hidden preflight cannot commit, even if it completes afterward.
  holdPolicy = true; const priorWrites = writes.length;
  await page.locator('#save-peer-interval').click();
  while (!heldPolicy) await new Promise(resolve => setTimeout(resolve, 5));
  await page.evaluate(() => window.postMessage('MAP_PAUSE', location.origin));
  await page.getByText(/^Paused\./).waitFor();
  await heldPolicy.fulfill({json: {revision: 7}}); holdPolicy = false;
  await page.waitForTimeout(30);
  assert.equal(writes.length, priorWrites);
  await page.evaluate(() => window.postMessage('MAP_RESUME', location.origin));
  await page.getByText(/^Live\./).waitFor();
  // A fresh unrelated completion does not satisfy the exact pull request.
  reports = [{schema: 'v2', event: 'staging-complete', report_id: 'b'.repeat(32),
    report_request_id: null, received_at: now + 999}];
  await page.locator('#pullbtn').click();
  await page.getByText(/accepted. Waiting for its matching report/).waitFor();
  await page.clock.fastForward(2500);
  assert.doesNotMatch(await page.locator('#pullstatus').textContent(), /Matching report received/);
  reports.push({schema: 'v2', event: 'pull', report_id: 'c'.repeat(32),
    report_request_id: directive.request_id, received_at: now}); pending = null;
  await page.clock.fastForward(2500);
  await page.getByText(/Matching report received for request/).waitFor();
  assert.equal(pulls, 1);
  // Parent resume must not undo the operator's manual pause.
  await page.keyboard.press('Escape'); await page.locator('#pause').click();
  const readsBeforePause = swarmReads;
  await page.evaluate(() => { window.postMessage('MAP_PAUSE', location.origin); window.postMessage('MAP_RESUME', location.origin); });
  await page.waitForTimeout(30); await page.clock.fastForward(10000);
  assert.equal(await page.locator('#pause').textContent(), 'Resume');
  assert.equal(swarmReads, readsBeforePause);
  // A late embedded load starts inert until the verified same-origin parent
  // resumes it. Neither a foreign origin nor self-posted child message counts.
  const beforeEmbedded = {swarmReads, sessionReads};
  data.images[0].peers.push({device_id: null, ip: '192.0.2.200', port: 6881, model: 'MUST-NOT-ATTRIBUTE',
    tracker: {principal_type: 'legacy', participant_class: 'legacy_unattributed', role: 'leecher'}});
  await page.goto('http://iris.test/embedded-host');
  const embedded = page.frames().find(frame => frame.url().endsWith('/swarmmap'));
  assert.ok(embedded, 'Generated map loaded as an iframe');
  await embedded.waitForFunction(() => window.irisSwarmMap && document.querySelector('#state')?.textContent.startsWith('Paused.'));
  await embedded.evaluate(() => {
    window.dispatchEvent(new MessageEvent('message', {origin: 'https://other.invalid', source: parent, data: 'MAP_RESUME'}));
    window.postMessage('MAP_RESUME', location.origin);
  });
  await page.clock.fastForward(10000);
  assert.deepEqual({swarmReads, sessionReads}, beforeEmbedded, 'No hidden session or map polling before parent handshake');
  await page.evaluate(() => {const frame = document.getElementById('embedded'); frame.hidden = false; frame.contentWindow.postMessage('MAP_RESUME', location.origin);});
  await embedded.waitForFunction(() => document.querySelector('#state')?.textContent.startsWith('Live.'));
  assert.equal(swarmReads, beforeEmbedded.swarmReads + 1); assert.equal(sessionReads, beforeEmbedded.sessionReads + 1);
  assert.equal(await embedded.getByText('MUST-NOT-ATTRIBUTE', {exact: false}).count(), 0,
    'An unattributed participant does not inherit a device model in the graph or table');
  await embedded.getByRole('button', {name: 'Open Legacy unattributed peer details', exact: true}).click();
  await embedded.getByText('No device identity; fresh report pull is unavailable.', {exact: true}).waitFor();
  assert.equal(await embedded.locator('#pullbtn').count(), 0);
  assert.equal(await embedded.locator('#save-peer-interval').count(), 0);
  await embedded.locator('#close').click();
  await embedded.locator('#pause').click(); const embeddedPausedReads = swarmReads;
  await page.evaluate(() => {const target = document.getElementById('embedded').contentWindow; target.postMessage('MAP_PAUSE', location.origin); target.postMessage('MAP_RESUME', location.origin);});
  await page.clock.fastForward(10000);
  assert.equal(await embedded.locator('#pause').textContent(), 'Resume'); assert.equal(swarmReads, embeddedPausedReads);
  assert.deepEqual(await embedded.evaluate(() => window.csp), []);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => window.csp), []);
  console.log('Swarm peer arrows, keyboard/pointer access, expiry and signed interval UI passed.');
} finally { await browser.close(); }
