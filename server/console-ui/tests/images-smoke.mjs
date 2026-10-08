// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Full Images workflows on isolated browser fixtures, never lab data or devices.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1100}});
  const errors = [], writes = [], dialogs = [], jobs = new Map(), reads = new Map();
  const uploaded = new Map([['one.bin', 'first image'], ['two.bin', 'second image'], ['drop.bin', 'dropped image'], ['expired.bin', 'expired session']]);
  let failCatalog = false, failImports = false, allowDelete = false, acceptDelete = false, expireUpload = false;
  let holdRelease = false, heldRelease;
  const images = {images: [
    {id: 'image/a', filename: 'bad.bin', quarantined: true, hash_verification: {state: 'mismatch'}},
    {id: 'image-b', filename: 'other.bin', quarantined: true, hash_verification: {state: 'mismatch'}},
    {id: 'verified', filename: 'router.bin', hash_verification: {state: 'verified', deferral: true, checked_at: 1790000000, source: 'offline'}},
    {id: 'released', filename: 'released.bin', hash_verification: {state: 'mismatch'}},
    {id: 'unknown', filename: '<img src=x onerror=alert(1)>', hash_verification: {state: 'future-state'}},
  ].map((row, index) => ({size: 1048576, sha256: '0123456789abcdef'.repeat(4), published_at: 1790000000 - index, ...row}))};
  const candidates = ['/opt/images/one/same.bin', '/opt/images/two/same.bin'];
  const importable = {importable: candidates.map(value => ({path: value, filename: 'same.bin', size: 123})),
    skipped: [{path: '/opt/images/blocked.bin', filename: 'blocked.bin', size: 456, reason: 'Unreadable'}]};
  const fixtures = {
    '/api/v1/session': {username: 'Images fixture', csrf: 'test-only'},
    '/api/v1/help': {version: 'test', deployment_id: 'fixture-only'},
    '/api/v1/devices': {devices: [], total: 0},
    '/api/v1/images': images, '/api/v1/images/importable': importable,
    '/api/v1/onboard/jobs': {jobs: [], max_concurrent: 25}, '/api/v1/credentials': {profiles: []},
  };
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', async dialog => {
    dialogs.push({type: dialog.type(), message: dialog.message()});
    if (dialog.type() === 'confirm' && !acceptDelete) await dialog.dismiss(); else await dialog.accept();
  });
  await page.addInitScript(() => {
    window.testCspViolations = [];
    window.addEventListener('securitypolicyviolation', event => window.testCspViolations.push(event.violatedDirective));
  });
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), endpoint = url.pathname;
    assert.equal(url.origin, 'http://iris.test', 'No external requests');
    if (endpoint.startsWith('/api/')) {
      if (request.method() !== 'GET') {
        assert.equal(request.headers()['x-csrf-token'], 'test-only', endpoint);
        writes.push({endpoint, method: request.method(), body: request.method() === 'PUT' ? request.postDataBuffer()?.toString() : request.postDataJSON()});
        if (endpoint.endsWith('/release-quarantine')) {
          if (holdRelease) { heldRelease = route; return; }
          const body = request.postDataJSON();
          if (!body.override) return route.fulfill({status: 409, json: {error: 'quarantine_still_mismatched'}});
          assert.deepEqual(body, {override: true, confirm_text: 'bad.bin'});
          images.images[0].quarantined = false;
          return route.fulfill({json: {ok: true}});
        }
        if (request.method() === 'DELETE') {
          if (!allowDelete) return route.fulfill({status: 409, json: {assigned: ['router-a']}});
          images.images = images.images.filter(row => row.id !== 'released');
          return route.fulfill({json: {ok: true}});
        }
        if (endpoint.startsWith('/api/v1/images/upload/')) {
          const name = decodeURIComponent(endpoint.split('/').at(-1));
          assert.equal(request.postDataBuffer().toString(), uploaded.get(name));
          if (expireUpload) return route.fulfill({status: 401, json: {error: 'unauthorized'}});
          jobs.set(name, {state: 'verifying'});
          return route.fulfill({json: {job_id: name}});
        }
        if (endpoint === '/api/v1/images/import') {
          const value = request.postDataJSON().path;
          assert.ok(candidates.includes(value));
          jobs.set(value, {state: 'verifying'});
          return route.fulfill({json: {job_id: value}});
        }
        throw new Error(`Unexpected write ${request.method()} ${endpoint}`);
      }
      reads.set(endpoint, (reads.get(endpoint) || 0) + 1);
      if (endpoint.startsWith('/api/v1/images/jobs/')) {
        const job = jobs.get(decodeURIComponent(endpoint.slice('/api/v1/images/jobs/'.length)));
        return route.fulfill({status: job ? 200 : 404, json: job || {error: 'not found'}});
      }
      if ((failCatalog && endpoint === '/api/v1/images') || (failImports && endpoint === '/api/v1/images/importable')) {
        return route.fulfill({status: 503, json: {error: 'fixture failure'}});
      }
      return route.fulfill({status: fixtures[endpoint] ? 200 : 503, json: fixtures[endpoint] || {error: 'Fixture unavailable'}});
    }
    const file = endpoint.startsWith('/assets/') ? path.join(root, 'dist', path.basename(endpoint))
      : path.join(root, '../webroot', endpoint === '/' ? 'index.html' : endpoint);
    try {
      return route.fulfill({body: await fs.readFile(file), contentType: {'.html': 'text/html', '.js': 'text/javascript',
        '.css': 'text/css', '.woff2': 'font/woff2'}[path.extname(file)] || 'application/octet-stream',
        headers: {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}});
    } catch { return route.fulfill({status: 404, body: ''}); }
  });
  const refresh = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  const row = id => page.locator(`#rows tr[data-id="${id}"]`);
  const waitRows = count => page.waitForFunction(value => document.querySelectorAll('#rows tr[data-id]').length === value, count);
  await page.goto('http://iris.test/#images');
  await waitRows(5);
  await page.locator('#import-rows .do-import').first().waitFor();
  assert.equal(await page.locator('#file').getAttribute('accept'), '.bin,.iso,.tar,.rpm');
  assert.deepEqual((await page.locator('#images th').allTextContents()).slice(0, 3), ['File', 'Verification', 'Image ID']);
  assert.equal(await page.locator('#rows img').count(), 0, 'Filenames render as text');
  assert.match(await row('unknown').innerText(), /<img src=x onerror=alert\(1\)>/);
  assert.match(await row('unknown').innerText(), /Unknown verification state/);
  assert.equal(await row('released').locator('.is-positive').count(), 0);
  assert.equal(await row('verified').locator('.is-positive').innerText(), 'Verified');
  assert.equal(await row('verified').locator('.is-warning').innerText(), 'Deferred by Cisco');
  assert.match(await page.locator('#import-rows').innerText(), /Unreadable/);
  assert.equal(await page.locator('#import-rows .do-import').count(), 2);
  const beforeFilter = reads.get('/api/v1/images');
  await page.locator('#images-filter-attention').check();
  await waitRows(2);
  assert.equal(await page.locator('#images-count').innerText(), '2 of 5 images');
  await page.locator('#images-filter-attention').uncheck();
  await waitRows(5);
  assert.equal(reads.get('/api/v1/images'), beforeFilter, 'Filtering does not fetch');
  assert.deepEqual(writes, [], 'Viewing and filtering do not mutate');

  // Polling retains focused rows; the nonmodal drawer restores focus on Escape.
  await row('verified').locator('.img-info').focus();
  images.images[2].size = 2097152;
  await refresh();
  await row('verified').getByText('2.0 MB', {exact: true}).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Image details for verified');
  await page.keyboard.press('Enter');
  await page.locator('#img-info-panel').waitFor();
  assert.equal(await page.locator('#img-info-panel').getAttribute('aria-modal'), null);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'ii-close');
  assert.equal(await page.locator('#ii-release-block').isVisible(), false);
  assert.match(await page.locator('#ii-operator-attestation').innerText(), /Not attested/);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Image details for verified');

  // A hidden Images drawer must not steal focus from a different workflow.
  await row('verified').locator('.img-info').click();
  await page.evaluate(() => { location.hash = '#devices'; });
  await page.locator('#dev-filter-q').focus();
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'dev-filter-q');
  await page.evaluate(() => { location.hash = '#images'; });
  await page.locator('#img-info-panel').waitFor();
  await page.keyboard.press('Escape');

  // Override is offered only after a server refusal, never prefilled or implied.
  await page.locator('#images-filter-attention').check();
  await row('image/a').locator('.img-info').click();
  assert.equal(await page.locator('#ii-override-block').isVisible(), false);
  await page.locator('#ii-release').click();
  await page.locator('#ii-override-block').waitFor();
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
    await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'images-react-quarantine.png'), fullPage: true});
  }
  assert.equal(await page.locator('#ii-confirm-text').inputValue(), '');
  await page.locator('#ii-confirm-text').fill('wrong.bin');
  assert.equal(await page.locator('#ii-release-override').isDisabled(), true);
  assert.equal(writes.length, 1);
  await page.locator('#ii-confirm-text').fill('bad.bin');
  const deviceReads = reads.get('/api/v1/devices') || 0;
  await page.locator('#ii-release-override').click();
  await page.locator('#img-info-panel').waitFor({state: 'hidden'});
  assert.equal(await page.evaluate(() => document.activeElement.id), 'images-filter-attention');
  await page.locator('#images-filter-attention').uncheck();
  await row('image/a').getByText('Mismatch — released', {exact: true}).waitFor();
  assert.ok((reads.get('/api/v1/devices') || 0) > deviceReads, 'Release refreshes device eligibility');
  assert.equal(writes[0].endpoint, '/api/v1/images/image%2Fa/release-quarantine');
  assert.deepEqual(writes[0].body, {override: false, confirm_text: ''});
  assert.equal(await row('image/a').locator('.is-positive').count(), 0);

  // Switching drawers while release is pending must not let its response close the new one.
  holdRelease = true;
  await row('image-b').locator('.img-info').click();
  const pendingRelease = page.waitForRequest(request => request.url().endsWith('/image-b/release-quarantine'));
  await page.locator('#ii-release').click();
  await pendingRelease;
  await page.keyboard.press('Escape');
  await row('verified').locator('.img-info').click();
  const untilHeld = Date.now() + 5000;
  while (!heldRelease && Date.now() < untilHeld) await new Promise(resolve => setTimeout(resolve, 10));
  assert.ok(heldRelease);
  images.images[1].quarantined = false;
  holdRelease = false;
  await heldRelease.fulfill({json: {ok: true}});
  await row('image-b').getByText('Mismatch — released', {exact: true}).waitFor();
  assert.equal(await page.locator('#ii-id').innerText(), 'verified');
  assert.equal(await page.locator('#img-info-panel').isVisible(), true);
  await page.keyboard.press('Escape');

  // Cancel never writes; assigned-image refusal preserves the row. Success refreshes both lists.
  const beforeCancel = writes.length;
  await row('released').locator('.del-img').click();
  assert.equal(writes.length, beforeCancel);
  acceptDelete = true;
  await row('released').locator('.del-img').click();
  await page.waitForFunction(() => !document.querySelector('#rows tr[data-id="released"] .del-img').disabled);
  assert.match(dialogs.at(-1).message, /router-a.*Reassign/);
  assert.equal(await row('released').count(), 1);
  allowDelete = true;
  const beforeImportReads = reads.get('/api/v1/images/importable');
  await row('released').locator('.del-img').click();
  await row('released').waitFor({state: 'detached'});
  assert.ok(reads.get('/api/v1/images/importable') > beforeImportReads);

  // Uploads use real XHR, distinct jobs, accessible progress and independent outcomes.
  await page.locator('#file').setInputFiles(['one.bin', 'two.bin'].map(name => ({name, mimeType: 'application/octet-stream', buffer: Buffer.from(uploaded.get(name))})));
  await page.waitForFunction(() => [...document.querySelectorAll('.up-state')].filter(node => node.textContent === 'checking Cisco Bulk Hash…').length === 2).catch(async error => {
    console.error({uploadRows: await page.locator('#uploads').innerText(), writes, errors});
    throw error;
  });
  for (const value of await page.locator('#uploads [role="progressbar"]').evaluateAll(nodes => nodes.map(node => node.getAttribute('aria-valuenow')))) assert.equal(value, '100');
  jobs.set('one.bin', {state: 'done', image_id: 'upload-one', verification: {outcome: 'ok', image_state: 'verified'}});
  jobs.set('two.bin', {state: 'error', message: 'fixture publish failure'});
  await page.locator('#uploads').getByText('Published upload-one · verified against Cisco Bulk Hash ✓', {exact: true}).waitFor();
  await page.locator('#uploads').getByText('Publish failed: fixture publish failure', {exact: true}).waitFor();
  await page.getByRole('button', {name: 'Dismiss two.bin', exact: true}).click();
  assert.equal(await page.locator('#uploads').getByText('two.bin', {exact: true}).count(), 0);
  await page.locator('#drop').evaluate(node => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['dropped image'], 'drop.bin', {type: 'application/octet-stream'}));
    node.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: transfer}));
  });
  await page.locator('#uploads').getByText('drop.bin', {exact: true}).waitFor();
  // A lost job terminates visibly rather than reporting publication or polling forever.
  const waitDrop = Date.now() + 5000;
  while (!jobs.has('drop.bin') && Date.now() < waitDrop) await new Promise(resolve => setTimeout(resolve, 10));
  jobs.delete('drop.bin');
  await page.locator('#uploads').getByText('Publish status unavailable (404). Refresh before trying again.', {exact: true}).waitFor();

  // Same basename in different roots: independent imports echo the exact discovered paths.
  for (const value of candidates) await page.locator(`.do-import[data-path="${value}"]`).click();
  await page.getByText('2 import job(s) in progress.', {exact: true}).waitFor();
  for (const value of candidates) assert.equal(await page.locator(`.do-import[data-path="${value}"]`).isDisabled(), true);
  assert.deepEqual(writes.filter(write => write.endpoint === '/api/v1/images/import').map(write => write.body), candidates.map(value => ({path: value})));
  jobs.set(candidates[0], {state: 'done', image_id: 'disk-one', verification: {outcome: 'ok', image_state: 'not_in_feed'}});
  await page.getByText('1 import job(s) in progress.', {exact: true}).waitFor();
  assert.equal(await page.locator(`.do-import[data-path="${candidates[1]}"]`).isDisabled(), true);
  jobs.set(candidates[1], {state: 'done', image_id: 'disk-two', verification: {outcome: 'ok', image_state: 'mismatch'}});
  await page.locator('#status').getByText('Published disk-two · Cisco hash mismatch — quarantined', {exact: true}).waitFor();
  assert.equal(await page.getByText(/import job\(s\) in progress/).count(), 0);

  // Failed reads retain known catalog with an explicit warning, not a fabricated empty result.
  failCatalog = true; failImports = true;
  await refresh();
  await page.getByText('Catalog could not be refreshed. Retrying automatically.', {exact: true}).waitFor();
  assert.equal(await page.locator('#rows tr[data-id]').count(), 4);
  await page.locator('#import-panel').waitFor({state: 'hidden'});
  failCatalog = false; failImports = false;
  await refresh();
  await page.getByText('Catalog could not be refreshed. Retrying automatically.', {exact: true}).waitFor({state: 'hidden'});
  await page.locator('#import-panel').waitFor();

  for (const [width, name] of [[1440, 'desktop'], [390, 'mobile']]) {
    await page.setViewportSize({width, height: 1100});
    const geometry = await page.evaluate(() => ({viewport: innerWidth, width: document.documentElement.scrollWidth,
      outside: [...document.querySelectorAll('body *')].filter(node => node.getBoundingClientRect().right > innerWidth && !node.closest('.table-scroll'))
        .map(node => ({tag: node.tagName, id: node.id, classes: node.className, right: node.getBoundingClientRect().right})).slice(0, 20)}));
    for (const id of ['images', 'importable']) {
      assert.equal(await page.locator(`#${id}`).evaluate(node => node.closest('.table-scroll').getAttribute('role')), 'region');
    }
    for (const bar of await page.locator('#uploads [role="progressbar"]').all()) {
      assert.ok((await bar.boundingBox()).width >= 64, 'Long verdicts must not collapse the progress bar');
    }
    if (process.env.IRIS_UI_SCREENSHOTS) {
      await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, `images-react-${name}.png`), fullPage: true});
    }
    assert.ok(geometry.width <= geometry.viewport, `No page-level horizontal overflow: ${JSON.stringify(geometry)}`);
  }
  assert.deepEqual(await page.evaluate(() => window.testCspViolations), []);
  assert.deepEqual(errors, []);

  // An initial failed read is unavailable, not proof of an empty catalog.
  failCatalog = true;
  await page.reload();
  await page.locator('#images-count').getByText('Unavailable', {exact: true}).waitFor();
  assert.equal(await page.locator('#rows').innerText(), 'Catalog unavailable.');
  failCatalog = false;
  await refresh();
  await page.locator('#images-count').getByText('4 images', {exact: true}).waitFor();

  // Upload bypasses fetch: its XHR must still honor session expiry and return to sign-in.
  expireUpload = true;
  await page.locator('#file').setInputFiles({name: 'expired.bin', mimeType: 'application/octet-stream', buffer: Buffer.from(uploaded.get('expired.bin'))});
  await page.waitForURL('http://iris.test/login.html');
  assert.deepEqual(errors, []);
  console.log('Images catalog, quarantine, delete, concurrent upload/import, failures, focus, session expiry and CSP passed.');
} finally { await browser.close(); }
