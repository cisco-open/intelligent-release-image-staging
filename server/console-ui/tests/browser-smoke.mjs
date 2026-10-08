// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Run after npm run build. Supply PLAYWRIGHT_MODULE when Playwright is installed
// outside this package. This test uses mocked APIs and never contacts a device.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  const writes = [];
  const jobOptions = [];
  const deviceQueries = [];
  let settingsReads = 0;
  const deploymentBase = {layout: 'docker', source: 'managed-worker', observed_at: 1790160000,
    instance: 'iris', namespace: null, note: null, components: [
      {role: 'server', kind: 'container', name: 'iris-server', host: 'staging-host',
        image: 'iris-server:2026.09.29', state: 'running / healthy', os: 'Debian GNU/Linux 12', architecture: 'x86_64', kernel: '6.8.0'},
      {role: 'console', kind: 'container', name: 'iris-console', host: 'staging-host',
        image: 'iris-console:2026.09.29', state: 'running / healthy', os: 'Debian GNU/Linux 12', architecture: 'x86_64', kernel: '6.8.0'},
    ]};
  let deploymentSummary = deploymentBase, deploymentUnavailable = false, deploymentStall = false;
  let logoutResult = 'http-error';
  const settingsWrites = [];
  const defaultCA = 'https://www.cisco.com/security/pki/trs/ios.p7b';
  const settingsState = {gui_cert: {source: 'built-in', subject: 'CN=iris.example.test', not_after: 'Sep 18 12:00:00 2036 GMT', fingerprint_sha256: 'ab'.repeat(32)}, ca_trust: {url: defaultCA, auto: false}, trust: [],
    telemetry_destination: {source: 'environment', effective_endpoint: '', effective_enabled: false}};
  let peerTlsState = {mode: 'disabled', origin: {active_mode: 'disabled', state: 'running'}, active_devices: 0, active_jobs: 0, can_change: true};
  let settingsFailure = '';
  let certificateAvailable = true, renewalAccepted = false;
  let rotationFixture = {state: 'idle', request_id: null, root_ids: ['root-a', 'root-b']};
  let browserTlsFixture = {state: 'idle', request_id: null, names: [], mode: null, csr: null, certificate: null, fingerprint_sha256: null};
  let serviceCredentialFixture = {items: ['metrics-token', 'collector-headers'].map(family => ({family, request_id: null, state: 'deployment-managed', observed_at: null}))};
  let maintenanceFixture = {schema: 1, revision: 0, observed_at: null, worker: 'not-observed', policies: [], jobs: [], families: [
    {id: 'online-signer', label: 'Online instruction signer', action: 'prepare', requirement: 'Offline approval'},
    {id: 'device-instruction', label: 'Device instruction encryption key', action: 'rotate', requirement: 'Verify device acceptance'},
    {id: 'browser-tls', label: 'Console browser TLS', action: 'review', requirement: 'Operator certificate approval'}]};
  let backupFixture = {available: false, target: 'unavailable', can_verify: false, can_extract: false,
    jobs: [], note: 'Configure the lifecycle worker on the installer host.'};
  let deploymentFixture = {available: false, target: 'unavailable', can_rotate: false, families: [], jobs: [], note: 'Configure independent recovery access.'};
  let trustFixture = {items: ['device-tls', 'peer-ca', 'instruction-roots'].map(family => ({family, state: 'idle', request_id: null})),
    drain: {ready: true, blocked_device_ids: [], removed_device_ids: []}};
  const backupId = '11111111-1111-1111-1111-111111111111';
  await page.addInitScript(() => {
    window.addEventListener('iris:policy-state', event => { window.testPolicyState = event.detail; });
    window.testStreams = [];
    window.EventSource = class {
      constructor(url) { this.url = url; this.listeners = {}; window.testStreams.push(this); }
      addEventListener(name, listener) { this.listeners[name] = listener; }
      close() { this.closed = true; }
    };
  });
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests allowed');
    if (url.pathname.startsWith('/api/')) {
      if (url.pathname === '/api/v1/deployment') {
        if (deploymentStall) return; // Deliberately leave this request pending until the UI timeout.
        return route.fulfill({status: deploymentUnavailable ? 503 : 200, json: deploymentSummary});
      }
      if (url.pathname === '/api/v1/settings') settingsReads++;
      if (url.pathname === '/api/v1/settings/certificates/browser/rotation' && route.request().method() === 'GET') return route.fulfill({json: browserTlsFixture});
      if (url.pathname === '/api/v1/settings/service-credentials' && route.request().method() === 'GET') return route.fulfill({json: serviceCredentialFixture});
      if (url.pathname === '/api/v1/settings/deployment-rotation' && route.request().method() === 'GET') return route.fulfill({json: deploymentFixture});
      if (url.pathname === '/api/v1/settings/trust-rotation' && route.request().method() === 'GET') return route.fulfill({json: trustFixture});
      if (url.pathname === '/api/v1/settings/key-maintenance' && route.request().method() === 'GET') return route.fulfill({json: maintenanceFixture});
      if (url.pathname === '/api/v1/settings/certificates/instruction/rotation' && route.request().method() === 'GET') return route.fulfill({json: rotationFixture});
      if (url.pathname === '/api/v1/settings/certificates') return route.fulfill({
        status: certificateAvailable ? 200 : 503,
        json: certificateAvailable ? {observed_at: 1790160000, custody: {state: 'renewal_due'}, items: [
          {id: 'instruction-signer', kind: 'certificate', label: 'Instruction signing certificate', state: 'renewal-due',
            fingerprint_sha256: 'ab'.repeat(32), renew_at: 1790060000, expires_at: 1791360000,
            refuse_at: 1790755200, impact: 'Renew with the existing key and offline root approval.'},
          {id: 'management-tls', kind: 'certificate', label: 'Console-to-server TLS', state: 'unknown',
            impact: 'Coordinate server identity and Console trust before restart.'},
          {id: 'root-a', kind: 'public-key', label: 'Offline root A', state: 'public-key-present',
            fingerprint_sha256: 'SHA256:fixturePublicOnly', impact: 'Confirm private custody with the holder.'},
        ]} : {error: 'unavailable'}});
      if (url.pathname === '/api/v1/settings/backups' && route.request().method() === 'GET') return route.fulfill({json: backupFixture});
      if (url.pathname === '/api/v1/settings/peer-tls' && route.request().method() === 'GET') return route.fulfill({json: peerTlsState});
      if (url.pathname === '/api/v1/logout') {
        assert.equal(route.request().method(), 'POST');
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        if (logoutResult === 'network-error') return route.abort('failed');
        return route.fulfill({status: logoutResult === 'success' ? 204 : 503, body: ''});
      }
      if (url.pathname.startsWith('/api/v1/settings/') && route.request().method() !== 'GET') {
        const method = route.request().method();
        const body = method === 'DELETE' ? null : route.request().postDataJSON();
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        settingsWrites.push({path: url.pathname, method, body});
        if (settingsFailure === 'network') return route.abort('failed');
        if (settingsFailure === 'html') return route.fulfill({status: 503, body: '<h1>Unavailable</h1>', contentType: 'text/html'});
        if (settingsFailure === 'invalid-success') return route.fulfill({status: 200, json: {}});
        if (url.pathname === '/api/v1/settings/certificates/browser/rotation') {
          if (body.action === 'prepare') browserTlsFixture = {...browserTlsFixture, request_id: body.request_id,
            names: body.names, mode: body.mode, state: 'awaiting-approval', csr: 'PUBLIC CSR FIXTURE'};
          if (body.action === 'approve') browserTlsFixture = {...browserTlsFixture, state: 'approved', certificate: body.certificate, fingerprint_sha256: 'ab'.repeat(32)};
          if (body.action === 'apply') browserTlsFixture = {...browserTlsFixture, state: 'published', applied: true};
          if (body.action === 'cancel') browserTlsFixture = {...browserTlsFixture, state: 'cancelled'};
          return route.fulfill({json: browserTlsFixture});
        }
        if (url.pathname === '/api/v1/settings/service-credentials') {
          assert.equal(body.confirm, true);
          const row = serviceCredentialFixture.items.find(item => item.family === body.family);
          row.request_id = body.request_id;
          row.state = body.action === 'replace' ? 'awaiting-verification' : body.action === 'revert' ? 'reverted' : 'completed';
          return route.fulfill({json: serviceCredentialFixture});
        }
        if (url.pathname === '/api/v1/settings/trust-rotation') {
          assert.equal(body.family, 'peer-ca');
          assert.equal(body.action, 'prepare');
          const item = trustFixture.items.find(item => item.family === body.family);
          Object.assign(item, {request_id: body.request_id, state: 'approved', certificate: 'PUBLIC CERTIFICATE', fingerprint_sha256: 'cd'.repeat(32)});
          return route.fulfill({json: item});
        }
        if (url.pathname === '/api/v1/settings/deployment-rotation') {
          assert.equal(body.action, 'rotate');
          assert.equal(body.allow_downtime, true);
          deploymentFixture.jobs.push({id: body.request_id, family: body.family, state: 'running', detail: 'Preparing verified backup', proof: null});
          return route.fulfill({json: {job_id: body.request_id}});
        }
        if (url.pathname === '/api/v1/settings/key-maintenance') {
          assert.equal(body.action, 'save-policy');
          assert.equal(body.revision, maintenanceFixture.revision);
          assert.match(body.policy.id, /^[0-9a-f-]{36}$/);
          maintenanceFixture = {...maintenanceFixture, revision: body.revision + 1, policies: [body.policy]};
          return route.fulfill({json: maintenanceFixture});
        }
        if (url.pathname === '/api/v1/settings/certificates/instruction/rotation') {
          assert.match(body.request_id, /^[0-9a-f-]{36}$/);
          if (body.action === 'retirement-request') return route.fulfill({json: {
            request_id: body.request_id, root_id: body.root_id, payload: Buffer.from('public fixture').toString('base64')}});
          if (body.action === 'activate' || body.action === 'retire') assert.equal(body.confirm, true);
          rotationFixture = {...rotationFixture, request_id: body.request_id,
            state: {prepare: 'awaiting-approval', activate: 'retirement-pending', retire: 'completed', cancel: 'cancelled'}[body.action],
            previous_sha256: 'aa'.repeat(32), replacement_sha256: 'bb'.repeat(32),
            public_key: 'ssh-ed25519 fixture-public-only\n', retired_keylist_seq: body.action === 'retire' ? 8 : null};
          return route.fulfill({json: rotationFixture});
        }
        if (url.pathname === '/api/v1/settings/certificates/instruction/request') return route.fulfill({json: {
          public_key: 'ssh-ed25519 fixture-public-only\n', public_key_sha256: 'ab'.repeat(32), certificate_sha256: 'cd'.repeat(32)}});
        if (url.pathname === '/api/v1/settings/certificates/instruction/renew') return route.fulfill({
          status: renewalAccepted ? 200 : 409,
          json: renewalAccepted ? {applied: true, expires_at: 1793360000, refuse_at: 1792755200, status_refreshed: true}
            : {error: 'online certificate changed; prepare renewal again'}});
        if (url.pathname === '/api/v1/settings/backups') {
          backupFixture = {...backupFixture, jobs: [{id: 'job-fixture', action: body.action,
            backup_id: backupId, started_at: 1790160000, state: 'running', detail: ''}]};
          return route.fulfill({json: {job_id: 'job-fixture'}});
        }
        if (url.pathname === '/api/v1/settings/peer-tls') {
          assert.equal(body.expected_mode, peerTlsState.mode);
          peerTlsState = {...peerTlsState, mode: body.mode, origin: {active_mode: body.mode, state: 'running'}};
          return route.fulfill({json: {...peerTlsState, applied: true}});
        }
        if (url.pathname === '/api/v1/settings/ca-trust') settingsState.ca_trust = {url: body.url || defaultCA, auto: body.auto};
        if (url.pathname === '/api/v1/settings/telemetry-destination') settingsState.telemetry_destination = method === 'DELETE'
          ? {source: 'environment', effective_endpoint: '', effective_enabled: false}
          : {source: 'override', effective_endpoint: body.endpoint, effective_enabled: body.enabled};
        if (url.pathname === '/api/v1/settings/trust') settingsState.trust = [{name: 'fixture.pem', source: 'manual', subject: 'Fixture CA', cert_count: 1}];
        if (url.pathname === '/api/v1/settings/trust/fixture.pem') settingsState.trust = [];
        return route.fulfill({json: {applied: true, revoked: 2}});
      }
      if (url.pathname === '/api/v1/devices') deviceQueries.push(url.searchParams.toString());
      if (route.request().method() !== 'GET') writes.push(route.request().method() + ' ' + url.pathname);
      if (url.pathname === '/api/v1/peer-policy/roles/branch' && route.request().method() === 'PUT') {
        const body = route.request().postDataJSON();
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        assert.equal(route.request().headers()['if-match'], '"iris-peer-policy-1"');
        assert.equal(body.qos.overall_up_bps, 4096);
        assert.equal(body.restricted, true);
        assert.equal(body.origin, false);
        assert.deepEqual(body.peers, ['branch', 'staging']);
        if (url.searchParams.get('dry_run') === '1') return route.fulfill({json: {confirm_token: 'fixture-preview', revision: 1}});
        assert.equal(body.confirm_token, 'fixture-preview');
        return route.fulfill({status: 412, json: {code: 'revision_conflict'}});
      }
      if (url.pathname === '/api/v1/install-options') {
        const options = { IE3x00: ['iox'], IR1x00: ['iox'], C8xxx: ['router','iox'],
          C9xxx: ['guestshell','iox'], NCS: ['xr-appmgr'], XR8000: ['xr-appmgr'] };
        return route.fulfill({ json: { options: options[url.searchParams.get('model')] || null } });
      }
      if (url.pathname === '/api/v1/devices/import-csv') {
        return route.fulfill({status: 422, json: {error: 'role_not_found',
          detail: 'unknown role', role: 'missing-role', device_id: 'csv-test'}});
      }
      if (/^\/api\/v1\/devices\/[^/]+\/(onboard|undeploy)$/.test(url.pathname) && route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        assert.equal(typeof body.log, 'boolean');
        assert.equal(route.request().headers()['x-csrf-token'], 'test-only');
        jobOptions.push([url.pathname.split('/').at(-1), body.log]);
        return route.fulfill({status: 409, json: {error: 'Fixture: device actions are not executed'}});
      }
      if (url.pathname === '/api/v1/devices' && route.request().method() === 'POST') {
        assert.deepEqual(route.request().postDataJSON(), {
          device_id: 'series-ui-test', device_ip: '192.0.2.99',
          model: 'XR8000', management_type: 'xr-host', platform: 'xr-appmgr', credential_profile_id: '',
        });
        return route.fulfill({ status: 201, json: { device_id: 'series-ui-test' } });
      }
      const fixtures = {
        '/api/v1/session': { username: 'UI test', csrf: 'test-only' },
        '/api/v1/overview': { images: 0, devices: 0, assigned: 0, staged: 0, staging_now: 0, rollout: [] },
        '/api/v1/devices': { devices: [
          { device_id: 'edge-01', device_ip: '192.0.2.10', model: '8201', model_family: 'XR8000', management_type: 'xr-host', assigned_images: [] },
          { device_id: 'edge-02', device_ip: '192.0.2.11', model: 'NCS-540', model_family: 'NCS', management_type: 'xr-host', assigned_images: [] },
        ], total: 2, offset: 0 },
        '/api/v1/onboard/jobs': { jobs: [
          { id: 'job-1', device_id: 'edge-01', state: 'done', action: 'onboard', last_line: 'onboard complete' },
          { id: 'job-2', device_id: 'edge-02', state: 'done', action: 'onboard', last_line: 'onboard complete' },
        ], max_concurrent: 25 },
        '/api/v1/images': { images: [] },
        '/api/v1/credentials': { profiles: [] },
        '/api/v1/settings': { version: 'UI test build', admin_username: 'UI test', host_ip: '192.0.2.1',
          ports: { tracker: 6969, catalog: 8443, artifacts: 8000, swarm: 8080, console: 8082 },
          sessions: { active: 1, idle_ttl_minutes: 30 }, ...settingsState },
        '/api/v1/help': { version: 'UI test build', deployment_id: 'fixture-deployment' },
        '/api/v1/peer-policy': { revision: 1, roles_supported: true, roles: { defined: 3, restricted: 2, members: { staging: 2, branch: 5, isolated: 1 } },
          enforcement: {state: 'enforced', stale: false, mutual_origin: {mode: 'preflight', newly_denied_device_count: 1}},
          role_drift: { count: 0 }, outbox: { unacknowledged: 0, capacity: 256 } },
        '/api/v1/peer-policy/roles': { revision: 1, roles: {
          staging: { peers: ['staging'], origin: true, restricted: false },
          branch: { peers: ['branch', 'staging'], origin: false, restricted: true, qos: {overall_up_bps: 8192} },
          isolated: { peers: ['isolated'], origin: false, restricted: true },
        } },
      };
      if (url.pathname === '/api/v1/devices') {
        const family = url.searchParams.get('model_family');
        const q = url.searchParams.get('q');
        fixtures[url.pathname].devices = fixtures[url.pathname].devices.filter(d =>
          (!family || d.model_family === family) && (!q || d.device_id.includes(q)));
        fixtures[url.pathname].total = fixtures[url.pathname].devices.length;
      }
      return route.fulfill({ status: fixtures[url.pathname] ? 200 : 503, json: fixtures[url.pathname] || { error: 'Not included in this fixture' } });
    }
    const file = url.pathname.startsWith('/assets/')
      ? path.join(root, 'dist', path.basename(url.pathname))
      : path.join(root, '../webroot', url.pathname === '/' ? 'index.html' : url.pathname);
    try {
      const contentType = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' }[path.extname(file)];
      return route.fulfill({ body: await fs.readFile(file), contentType: contentType || 'application/octet-stream',
        headers: { 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'" } });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.goto('http://iris.test/');
  await page.getByText('UI test', { exact: true }).waitFor();
  const showDeployment = async () => {
    await page.goto('http://iris.test/#overview');
    await page.locator('#deployment-layout').getByText(
      deploymentUnavailable ? 'Unavailable' : deploymentSummary.layout === 'kubernetes' ? 'Kubernetes' :
        deploymentSummary.layout === 'docker-split' ? 'Docker · separate hosts' : 'Docker · one host', {exact: true}).waitFor();
  };
  await showDeployment();
  assert.equal(await page.locator('#deployment-rows tr').count(), 2);
  assert.match(await page.locator('#deployment-rows').innerText(), /Tracker \/ distribution/);
  assert.match(await page.locator('#deployment-rows').innerText(), /Debian GNU\/Linux/);
  deploymentSummary = {...deploymentBase, layout: 'docker-split', components: [deploymentBase.components[0],
    {...deploymentBase.components[1], host: '192.0.2.20'}]};
  await showDeployment();
  assert.match(await page.locator('#deployment-rows').innerText(), /192\.0\.2\.20/);
  deploymentSummary = {...deploymentBase, layout: 'kubernetes', namespace: 'iris-production', components: [
    {...deploymentBase.components[0], kind: 'pod', name: 'iris-seed-server-a', host: 'node-a', address: '192.0.2.10'},
    {...deploymentBase.components[1], kind: 'pod', name: 'iris-console-a', host: 'node-b'},
    {...deploymentBase.components[1], kind: 'pod', name: '<img src=x onerror=alert(1)>', host: 'node-c', state: 'Running / not ready'},
  ]};
  await showDeployment();
  assert.equal(await page.locator('#deployment-rows tr').count(), 3);
  assert.equal(await page.locator('#deployment-rows img').count(), 0, 'Runtime labels must be text, never HTML');
  assert.match(await page.locator('#deployment-context').innerText(), /iris-production/);
  deploymentSummary.components[2].name = 'iris-console-b';
  await showDeployment();
  for (const [width, name] of [[1440, 'desktop'], [390, 'mobile']]) {
    await page.setViewportSize({width, height: 1000});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Deployment table must not overflow the page');
    if (process.env.IRIS_UI_SCREENSHOTS) {
      await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
      await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'deployment-kubernetes-' + name + '.png')});
    }
  }
  deploymentSummary = {...deploymentBase, source: 'runtime', note: 'Full deployment inventory is unavailable.'};
  await showDeployment();
  assert.equal(await page.locator('#deployment-note').innerText(), deploymentSummary.note);
  deploymentUnavailable = true;
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.locator('#deployment-layout').getByText('Unavailable', {exact: true}).waitFor();
  assert.equal(await page.locator('#deployment-table').isVisible(), false, 'Failed refresh must hide previous runtime state');
  assert.match(await page.locator('#deployment-note').innerText(), /Retrying automatically/);
  deploymentSummary = deploymentBase; deploymentUnavailable = false;
  await page.setViewportSize({width: 1440, height: 1000});
  await showDeployment();
  if (process.env.IRIS_UI_SCREENSHOTS) await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'deployment-docker-desktop.png')});
  deploymentStall = true;
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.locator('#deployment-layout').getByText('Unavailable', {exact: true}).waitFor({timeout: 12000});
  assert.equal(await page.locator('#deployment-table').isVisible(), false, 'A stalled endpoint must not leave old state visible');
  deploymentStall = false;
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Settings', exact: true }).click();
  assert.equal(new URL(page.url()).hash, '#settings/general');
  const settings = page.getByRole('navigation', { name: 'Settings sections' });
  await settings.waitFor();
  const settingsTab = async name => {
    const response = page.waitForResponse(r => r.url().endsWith('/api/v1/settings') && r.request().method() === 'GET');
    await settings.getByRole('link', {name, exact: true}).click();
    await (await response).finished();
    await page.waitForLoadState('networkidle');
  };
  await page.locator('#settings-info').getByText('UI test build', {exact: true}).waitFor();
  assert.equal(settingsReads, 1, 'Entering Settings performs one settings read, not duplicate form refreshes');
  await page.locator('#pw-new').fill('example-passphrase');
  for (const [name, pane] of [['TLS & trust', 'tls'], ['Telemetry', 'telemetry'], ['Image verification', 'bulkhash'],
    ['Device packages', 'packages'], ['Audit export', 'audit'], ['Setup checklist', 'setup'], ['General', 'general']]) {
    await settings.getByRole('link', { name, exact: true }).click();
    await page.locator(`#settings-pane-${pane}`).waitFor({ state: 'visible' });
    assert.equal(await settings.getByRole('link', { name, exact: true }).getAttribute('aria-current'), 'page');
  }
  assert.equal(await page.locator('#pw-new').inputValue(), 'example-passphrase', 'Navigation must not remount edited fields');
  await page.locator('#pw-new').fill('');
  // Settings controls exercise only intercepted requests, including failures.
  await page.locator('#pw-cur').fill('fixture-current');
  await page.locator('#pw-new').fill('fixture-new-password');
  await page.locator('#pw-confirm').fill('fixture-new-password');
  await page.locator('#pw-form button[type="submit"]').click();
  await page.locator('#pw-msg').getByText('Password changed. Other sessions signed out.', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {current: 'fixture-current', new: 'fixture-new-password', confirm: 'fixture-new-password'});
  assert.equal(await page.locator('#pw-cur').inputValue(), '');
  await page.locator('#revoke-others').click();
  await page.locator('#revoke-msg').getByText('Signed out 2 other session(s).', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {});
  await settingsTab('TLS & trust');
  await page.locator('#cert-status').getByText('CN=iris.example.test', {exact: true}).waitFor();
  assert.equal(await page.locator('#cert-status .tls-fingerprint dd').textContent(), 'ab'.repeat(32));
  assert.equal(await page.locator('#cert-pem').isVisible(), false);
  assert.equal(await page.locator('#peer-tls-toggle').isChecked(), false);
  await page.locator('#peer-tls-toggle').check();
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#peer-tls-save').click();
  await page.locator('#peer-tls-status').getByText('Origin seeder: TLS required · running', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {mode: 'required', expected_mode: 'disabled'});
  await page.locator('#peer-tls-toggle').uncheck();
  page.once('dialog', dialog => dialog.dismiss());
  const beforeCancelTls = settingsWrites.length;
  await page.locator('#peer-tls-save').click();
  assert.equal(settingsWrites.length, beforeCancelTls);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#peer-tls-save').click();
  await page.locator('#peer-tls-status').getByText('Origin seeder: TLS off · running', {exact: true}).waitFor();
  peerTlsState = {...peerTlsState, active_devices: 1, can_change: false};
  await settingsTab('General'); await settingsTab('TLS & trust');
  await page.waitForFunction(() => document.getElementById('peer-tls-toggle').disabled);
  assert.match(await page.locator('#peer-tls-status').textContent(), /1 device/);
  peerTlsState = {...peerTlsState, active_devices: 0, can_change: true};
  await settingsTab('General'); await settingsTab('TLS & trust');
  await page.locator('#cert-form summary').click();
  assert.equal(await page.locator('#cert-pem').isVisible(), true);
  await page.waitForFunction(() => document.getElementById('ca-source').value === 'cisco');
  assert.equal(await page.locator('#ca-url').isVisible(), false, 'Built-in Cisco URL is not a custom source');
  await page.locator('#ca-auto').check();
  await page.locator('#ca-form button[type="submit"]').click();
  await page.locator('#ca-msg').getByText('CA download settings saved.', {exact: true}).waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {url: null, auto: true}, 'Daily refresh supports the server default URL');
  await page.waitForFunction(() => document.getElementById('ca-auto').checked);
  await page.locator('#ca-source').selectOption('mozilla');
  await page.locator('#ca-form button[type="submit"]').click();
  await page.waitForFunction(() => document.getElementById('ca-url').value === 'https://curl.se/ca/cacert.pem');
  assert.deepEqual(settingsWrites.at(-1).body, {url: 'https://curl.se/ca/cacert.pem', auto: true});
  await page.locator('#ca-source').selectOption('custom');
  await page.locator('#ca-url').fill('');
  const beforeEmptyCA = settingsWrites.length;
  await page.locator('#ca-form button[type="submit"]').click();
  await page.locator('#ca-msg').getByText('Enter a custom HTTPS bundle URL.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforeEmptyCA);
  const certPEM = '-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----';
  const keyPEM = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nfixture-only\n-----END ENCRYPTED PRIVATE KEY-----';
  await page.locator('#cert-pem').fill(certPEM);
  await page.locator('#cert-key').fill(keyPEM);
  await page.locator('#cert-passphrase').fill('fixture-passphrase');
  settingsFailure = 'html';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.locator('#cert-msg').getByText('Request failed (503).', {exact: true}).waitFor();
  assert.equal(await page.locator('#cert-key').inputValue(), keyPEM, 'Failed upload preserves the draft for correction');
  settingsFailure = 'invalid-success';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.locator('#cert-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  assert.equal(await page.locator('#cert-key').inputValue(), keyPEM, 'Invalid success response cannot claim a certificate replacement');
  settingsFailure = '';
  await page.locator('#cert-form button[type="submit"]').click();
  await page.waitForFunction(() => document.getElementById('cert-key').value === '');
  assert.deepEqual(settingsWrites.at(-1).body, {cert_pem: certPEM, key_pem: keyPEM, key_passphrase: 'fixture-passphrase'});
  assert.equal(await page.locator('#cert-passphrase-row').isVisible(), false);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#cert-revert').click();
  await page.locator('#cert-msg').getByText('Reverted to the deployment default certificate.', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).method, 'DELETE');
  await page.locator('#trust-form summary').click();
  await page.locator('#trust-pem').fill(certPEM);
  await page.locator('#trust-form button[type="submit"]').click();
  await page.locator('#trust-rows .trust-del').waitFor();
  assert.deepEqual(settingsWrites.at(-1).body, {pem: certPEM});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#trust-rows .trust-del').click();
  await page.locator('#trust-rows .trust-del').waitFor({state: 'detached'});
  assert.equal(settingsWrites.at(-1).path, '/api/v1/settings/trust/fixture.pem');
  await settingsTab('Telemetry');
  await page.locator('#td-endpoint').fill('https://collector.example:4318/');
  await page.locator('#td-enabled').check();
  settingsFailure = 'network';
  await page.locator('#td-form button[type="submit"]').click();
  await page.locator('#td-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  settingsFailure = '';
  await page.locator('#td-form button[type="submit"]').click();
  await page.locator('#td-revert').waitFor({state: 'visible'});
  assert.deepEqual(settingsWrites.at(-1).body, {endpoint: 'https://collector.example:4318', enabled: true});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#td-revert').click();
  await page.locator('#td-revert').waitFor({state: 'hidden'});
  assert.equal(await page.locator('#td-endpoint').inputValue(), '');
  assert.equal(await page.locator('#td-enabled').isChecked(), false);
  assert.equal(settingsWrites.at(-1).method, 'DELETE');
  await settingsTab('Audit export');
  await page.locator('#ae-host').fill('archive.example');
  await page.locator('#ae-user').fill('fixture');
  await page.locator('#ae-path').fill('/exports');
  await page.locator('#ae-recipient').fill('age1fixture');
  settingsFailure = 'html';
  await page.locator('#ae-form button[type="submit"]').click();
  await page.locator('#ae-msg').getByText('Request failed (503).', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.port, 22);
  assert.equal(Object.hasOwn(settingsWrites.at(-1).body, 'password'), false, 'An empty password preserves the saved credential');
  await settingsTab('Image verification');
  settingsFailure = 'network';
  await page.locator('#iv-schedule-form button[type="submit"]').click();
  await page.locator('#iv-schedule-msg').getByText('Response unavailable. Settings may have changed; reload to check before retrying.', {exact: true}).waitFor();
  settingsFailure = '';
  await settingsTab('Certificates & keys');
  await page.locator('#browser-tls-state').getByText('Browser certificate: idle.', {exact: true}).waitFor();
  await page.locator('#browser-tls-names').fill('console.example.com, 192.0.2.10');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#browser-tls-prepare').click();
  await page.locator('#browser-tls-state').getByText('Browser certificate: awaiting approval.', {exact: true}).waitFor();
  const csrDownload = page.waitForEvent('download');
  await page.locator('#browser-tls-csr').click();
  assert.equal((await csrDownload).suggestedFilename(), 'iris-console.csr');
  const beforeTlsPrivate = settingsWrites.length;
  await page.locator('#browser-tls-approved').setInputFiles({name: 'bad.pem', mimeType: 'text/plain', buffer: Buffer.from('-----BEGIN PRIVATE KEY-----')});
  await page.locator('#browser-tls-approve').click();
  await page.locator('#browser-tls-result').getByText('Upload the public certificate chain, never a private key.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforeTlsPrivate);
  await page.locator('#browser-tls-approved').setInputFiles({name: 'cert.pem', mimeType: 'text/plain', buffer: Buffer.from('-----BEGIN CERTIFICATE-----\npublic fixture')});
  await page.locator('#browser-tls-approve').click();
  await page.locator('#browser-tls-state').getByText('Browser certificate: approved.', {exact: true}).waitFor();
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#browser-tls-apply').click();
  await page.locator('#browser-tls-result').getByText(/this Console listener reloaded/).waitFor();
  await page.locator('#service-credential-generate').click();
  const token = await page.locator('#service-credential-token').inputValue();
  assert.match(token, /^[0-9a-f]{64}$/);
  const tokenDownload = page.waitForEvent('download');
  await page.locator('#service-credential-download').click();
  assert.equal((await tokenDownload).suggestedFilename(), 'iris-metrics-token');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#service-credential-replace').click();
  await page.locator('#service-credential-state').getByText(/awaiting verification/).waitFor();
  assert.equal(await page.locator('#service-credential-token').inputValue(), '', 'Clear the browser secret after successful publication');
  assert.equal(await page.locator('#service-credential-retire').isDisabled(), true, 'No proof, no retirement');
  serviceCredentialFixture.items[0].observed_at = 1790230000;
  await page.locator('#service-credential-refresh').click();
  await page.waitForFunction(() => !document.getElementById('service-credential-retire').disabled);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#service-credential-retire').click();
  await page.locator('#service-credential-result').getByText(/Previous scrape token retired/).waitFor();
  await page.locator('#service-credential-family').selectOption('collector-headers');
  await page.locator('#service-credential-endpoint').fill('https://collector.example:4318');
  await page.locator('#service-credential-headers [data-field=value]').fill('Bearer isolated-ui-fixture');
  await page.locator('#service-credential-add-header').click();
  await page.locator('#service-credential-headers [data-field=name]').last().fill('authorization');
  await page.locator('#service-credential-headers [data-field=value]').last().fill('duplicate');
  const beforeDuplicate = settingsWrites.length;
  await page.locator('#service-credential-replace').click();
  await page.locator('#service-credential-result').getByText('Provide distinct authentication header names.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforeDuplicate);
  await page.locator('#service-credential-headers button').last().click();
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#service-credential-replace').click();
  await page.locator('#service-credential-state').getByText(/awaiting verification/).waitFor();
  assert.equal(settingsWrites.at(-1).body.endpoint, 'https://collector.example:4318');
  assert.equal(await page.locator('#service-credential-headers [data-field=value]').inputValue(), '');
  assert.equal(await page.locator('#service-credential-retire').isDisabled(), true);
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
      await page.setViewportSize({width, height});
      for (const id of ['browser-tls-workflow', 'service-credential-workflow']) {
        await page.locator('#' + id).screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, id + '-' + name + '.png')});
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    }
    await page.setViewportSize({width: 1440, height: 1000});
  }
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#service-credential-revert').click();
  await page.locator('#service-credential-result').getByText(/Previous IRIS setting restored/).waitFor();
  assert.equal(await page.locator('#deployment-rotation-apply').isDisabled(), true);
  deploymentFixture = {...deploymentFixture, available: true, can_rotate: true, target: 'single-docker',
    families: ['management-tls', 'device-tls', 'peer-ca', 'instruction-roots', 'age-identity', 'seeder-announce'], note: 'Verified backup required; downtime expected.'};
  await page.locator('#deployment-rotation-refresh').click();
  await page.waitForFunction(() => !document.getElementById('deployment-rotation-apply').disabled);
  for (const [target, label] of [['split-docker', 'Docker on separate hosts'], ['kubernetes', 'Kubernetes']]) {
    deploymentFixture.target = target;
    await page.locator('#deployment-rotation-refresh').click();
    await page.locator('#deployment-rotation-worker').getByText('Deployment: ' + label + '.', {exact: false}).waitFor();
    await page.waitForFunction(() => !document.getElementById('deployment-rotation-apply').disabled);
  }
  await page.locator('#deployment-rotation-family').selectOption('peer-ca');
  assert.equal(await page.locator('#deployment-rotation-apply').isDisabled(), true);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#deployment-rotation-prepare').click();
  await page.waitForFunction(() => !document.getElementById('deployment-rotation-apply').disabled);
  const trustOperation = settingsWrites.at(-1).body.request_id;
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#deployment-rotation-apply').click();
  await page.locator('#deployment-rotation-result').getByText(/acceptance is not completion/).waitFor();
  assert.equal(settingsWrites.at(-1).body.request_id, trustOperation);
  assert.equal(await page.locator('#deployment-rotation-apply').isDisabled(), true);
  if (process.env.IRIS_UI_SCREENSHOTS) {
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
      await page.setViewportSize({width, height});
      await page.locator('#deployment-rotation-workflow').screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'deployment-rotation-' + name + '.png')});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    }
    await page.setViewportSize({width: 1440, height: 1000});
  }
  await page.locator('#maintenance-worker').getByText('Scheduler: not observed.', {exact: true}).waitFor();
  assert.equal(await page.locator('#maintenance-enabled').isChecked(), false);
  await page.locator('#maintenance-families').getByText('Review reminder', {exact: true}).waitFor();
  await page.locator('#maintenance-family').selectOption('device-instruction');
  assert.equal(await page.locator('#maintenance-target').isEnabled(), true);
  assert.equal(await page.locator('#maintenance-interval').getAttribute('min'), '8');
  await page.locator('#maintenance-family').selectOption('browser-tls');
  assert.equal(await page.locator('#maintenance-target').isDisabled(), true);
  await page.locator('#maintenance-next').fill('2027-01-01T03:00');
  await page.locator('#maintenance-enabled').check();
  const beforeSchedule = settingsWrites.length;
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#maintenance-save').click();
  assert.equal(settingsWrites.length, beforeSchedule, 'Cancelled enable leaves policy unchanged');
  page.once('dialog', dialog => { assert.match(dialog.message(), /review reminders/); dialog.accept(); });
  await page.locator('#maintenance-save').click();
  await page.locator('#maintenance-result').getByText('Schedule saved.', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.policy.next_at, Date.parse('2027-01-01T03:00Z') / 1000);
  assert.equal(settingsWrites.at(-1).body.policy.target, 'deployment');
  settingsFailure = 'invalid-success';
  await page.locator('#maintenance-enabled').uncheck();
  await page.locator('#maintenance-save').click();
  await page.locator('#maintenance-result').getByText(/Refresh maintenance before continuing/).waitFor();
  assert.equal(await page.locator('#maintenance-save').isDisabled(), true);
  settingsFailure = '';
  await page.locator('#maintenance-refresh').click();
  await page.waitForFunction(() => !document.getElementById('maintenance-save').disabled);
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('#key-maintenance').screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'key-maintenance-mobile.png')});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.setViewportSize({width: 1440, height: 1100});
    await page.locator('#key-maintenance').screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'key-maintenance-desktop.png')});
  }
  await page.locator('#certificate-rows').getByText('renewal due', {exact: true}).waitFor();
  await page.locator('#certificate-rows').getByText('No expiry', {exact: true}).waitFor();
  assert.equal(await page.locator('#certificate-renew').isDisabled(), true);
  const download = page.waitForEvent('download');
  await page.locator('#certificate-request').click();
  assert.equal((await download).suggestedFilename(), 'iris-online.pub');
  await page.waitForFunction(() => !document.getElementById('certificate-renew').disabled);
  const beforePrivate = settingsWrites.length;
  await page.locator('#certificate-approved').setInputFiles({name: 'wrong.pub', mimeType: 'text/plain', buffer: Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----')});
  await page.locator('#certificate-renew').click();
  await page.locator('#certificate-renew-result').getByText('Choose the public certificate returned by your custodian, not a private key.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforePrivate, 'Private key must not be uploaded');
  await page.locator('#certificate-approved').setInputFiles({name: 'approved.pub', mimeType: 'text/plain', buffer: Buffer.from('ssh-ed25519-cert-v01@openssh.com fixture')});
  await page.locator('#certificate-renew').click();
  await page.locator('#certificate-renew-result').getByText('online certificate changed; prepare renewal again', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.public_key_sha256, 'ab'.repeat(32));
  renewalAccepted = true;
  await page.locator('#certificate-renew').click();
  await page.locator('#certificate-renew-result').getByText(/Renewal applied/).waitFor();
  assert.equal(await page.locator('#certificate-renew').isDisabled(), true);
  certificateAvailable = false;
  await page.locator('#certificate-refresh').click();
  await page.locator('#certificate-observed').getByText(/Certificate inventory unavailable/).waitFor();
  assert.equal(await page.locator('#certificate-rows tr').count(), 0, 'Missing evidence clears stale dates');
  certificateAvailable = true;
  await page.locator('#certificate-refresh').click();
  await page.locator('#certificate-rows tr').first().waitFor();
  await page.locator('#rotation-state').getByText('Rotation: idle.', {exact: true}).waitFor();
  const beforeRotation = settingsWrites.length;
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#rotation-prepare').click();
  assert.equal(settingsWrites.length, beforeRotation);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#rotation-prepare').click();
  await page.locator('#rotation-state').getByText('Rotation: awaiting approval.', {exact: true}).waitFor();
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false,
    JSON.stringify(await page.evaluate(() => Array.from(document.querySelectorAll('body *'))
      .filter(el => el.getBoundingClientRect().right > innerWidth)
      .map(el => ({tag: el.tagName, id: el.id, class: el.className})).slice(-20))));
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
    await page.locator('#signer-rotation').screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'rotation-approval-mobile.png')});
  }
  await page.setViewportSize({width: 1440, height: 1000});
  const publicDownload = page.waitForEvent('download');
  await page.locator('#rotation-download').click();
  assert.equal((await publicDownload).suggestedFilename(), 'iris-replacement.pub');
  const beforeRotationPrivate = settingsWrites.length;
  await page.locator('#rotation-certificate').setInputFiles({name: 'private', mimeType: 'text/plain', buffer: Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----')});
  await page.locator('#rotation-activate').click();
  await page.locator('#rotation-result').getByText('Upload the public approval, never a private key.', {exact: true}).waitFor();
  assert.equal(settingsWrites.length, beforeRotationPrivate);
  await page.locator('#rotation-refresh').click();
  await page.locator('#rotation-state').getByText('Rotation: awaiting approval.', {exact: true}).waitFor();
  await page.locator('#rotation-certificate').setInputFiles({name: 'approved.pub', mimeType: 'text/plain', buffer: Buffer.from('ssh-ed25519-cert-v01@openssh.com fixture')});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#rotation-activate').click();
  await page.locator('#rotation-state').getByText('Rotation: retirement pending.', {exact: true}).waitFor();
  const retirementDownload = page.waitForEvent('download');
  await page.locator('#rotation-retirement-request').click();
  assert.equal((await retirementDownload).suggestedFilename(), 'keylist.payload');
  await page.locator('#rotation-keylist').setInputFiles({name: 'keylist.envelope', mimeType: 'text/plain', buffer: Buffer.from('IRIS-KEYLIST/1\npublic fixture')});
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#rotation-retire').click();
  await page.locator('#rotation-state').getByText(/Previous key revoked at keylist sequence 8/).waitFor();
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
    await page.locator('#signer-rotation').screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'rotation-mobile.png')});
  }
  await page.setViewportSize({width: 1440, height: 1000});
  if (process.env.IRIS_UI_SCREENSHOTS) {
    await fs.mkdir(process.env.IRIS_UI_SCREENSHOTS, {recursive: true});
    await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'certificates-desktop.png')});
  }
  await settingsTab('Backup & restore');
  assert.equal(await page.locator('#backup-create').isDisabled(), true);
  backupFixture = {...backupFixture, available: true, target: 'single-docker', note: 'Keep encrypted copies off this host.'};
  await page.locator('#backup-refresh').click();
  await page.waitForFunction(() => !document.getElementById('backup-create').disabled);
  const beforeCancelled = settingsWrites.length;
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#backup-create').click();
  assert.equal(settingsWrites.length, beforeCancelled);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#backup-create').click();
  await page.locator('#backup-job-rows').getByText('running', {exact: true}).waitFor();
  assert.match(settingsWrites.at(-1).body.request_id, /^[0-9a-f-]{36}$/);
  assert.equal(settingsWrites.at(-1).body.action, 'backup');
  assert.equal(settingsWrites.at(-1).body.allow_downtime, true);
  assert.equal(await page.locator('#backup-create').isDisabled(), true);
  backupFixture.jobs[0].state = 'captured';
  await page.locator('#backup-refresh').click();
  await page.locator('#backup-job-rows').getByText('captured', {exact: true}).waitFor();
  await page.locator('#backup-selected').selectOption(backupId);
  assert.equal(await page.locator('#backup-verify').isDisabled(), true, 'Recovery access must be provisioned separately');
  backupFixture.can_verify = true;
  await page.locator('#backup-refresh').click();
  await page.waitForFunction(() => !document.getElementById('backup-verify').disabled);
  await page.locator('#backup-verify').click();
  await page.locator('#backup-job-rows').getByText('verify', {exact: true}).waitFor();
  assert.match(settingsWrites.at(-1).body.request_id, /^[0-9a-f-]{36}$/);
  assert.equal(settingsWrites.at(-1).body.action, 'verify');
  assert.equal(settingsWrites.at(-1).body.backup_id, backupId);
  backupFixture = {...backupFixture, can_restore: true, jobs: [{id: backupId, action: 'backup',
    backup_id: backupId, started_at: 1790160000, state: 'captured', detail: ''}]};
  await page.locator('#backup-refresh').click();
  await page.locator('#backup-job-rows').getByText('captured', {exact: true}).waitFor();
  await page.locator('#backup-selected').selectOption(backupId);
  await page.waitForFunction(() => !document.getElementById('backup-restore').disabled);
  const beforeRestoreCancel = settingsWrites.length;
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#backup-restore').click();
  assert.equal(settingsWrites.length, beforeRestoreCancel);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#backup-restore').click();
  await page.locator('#backup-job-rows').getByText('running', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.action, 'restore');
  assert.equal(settingsWrites.at(-1).body.backup_id, backupId);
  assert.equal(settingsWrites.at(-1).body.confirm_restore, true);
  assert.equal(settingsWrites.at(-1).body.allow_downtime, true);
  const restoreId = settingsWrites.at(-1).body.request_id;
  backupFixture.jobs[0].id = restoreId;
  backupFixture.jobs[0].state = 'recovery-required';
  await page.locator('#backup-refresh').click();
  await page.waitForFunction(() => !document.getElementById('backup-recover').disabled);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#backup-recover').click();
  await page.locator('#backup-job-rows').getByText('running', {exact: true}).waitFor();
  assert.equal(settingsWrites.at(-1).body.action, 'recover-restore');
  assert.equal(settingsWrites.at(-1).body.request_id, restoreId);
  assert.equal(settingsWrites.at(-1).body.backup_id, backupId);
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (process.env.IRIS_UI_SCREENSHOTS) await page.screenshot({path: path.join(process.env.IRIS_UI_SCREENSHOTS, 'backups-mobile.png')});
  await page.setViewportSize({width: 1440, height: 1000});
  await settingsTab('General');
  const screenshots = process.env.IRIS_UI_SCREENSHOTS;
  if (screenshots) { await fs.mkdir(screenshots, { recursive: true }); await page.screenshot({ path: path.join(screenshots, 'settings-desktop.png') }); }
  await page.getByRole('link', { name: 'Skip to content' }).focus();
  await page.keyboard.press('Enter');
  assert.equal(new URL(page.url()).hash, '#settings/general');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'iris-main-content');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Toggle navigation' }).click();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.body.classList.contains('iris-nav-open')), false);
  await page.setViewportSize({ width: 320, height: 720 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'settings-mobile.png') });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Inventory', exact: true }).click();
  await page.locator('#dev-rows tr[data-id]').first().waitFor();
  assert.equal(await page.locator('#devices input[type="checkbox"]').count(), 0, 'No device selection checkboxes');
  assert.equal(await page.getByText('Distribute. Verify. Stage.', { exact: true }).count(), 0);
  assert.equal(await page.locator('.iris-header').getByText('Stage only', { exact: true }).count(), 0);
  await page.locator('.iris-header').getByText('Intelligent Release & Image Staging', { exact: true }).waitFor();
  const rows = page.locator('#dev-rows tr[data-id]');
  assert.equal(await rows.count(), 2);
  await rows.first().locator('td').nth(2).click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#sel-count').innerText(), '1 selected');
  // Clicking an embedded dropdown must not alter row selection or write data.
  await rows.first().locator('select.platform').click();
  await page.keyboard.press('Escape');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  await page.locator('#mark-all').click();
  assert.equal(await rows.evaluateAll(nodes => nodes.every(node => node.getAttribute('aria-selected') === 'true')), true);
  await rows.first().focus();
  await page.keyboard.press('Space');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false');
  await page.keyboard.press('Enter');
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-row-selection.png') });
  await page.locator('#mark-all').click();
  assert.equal(await page.locator('#sel-bar').isVisible(), false);
  await rows.first().locator('td').nth(2).click();
  await rows.first().locator('td').nth(2).click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false', 'Second row click deselects');
  await rows.first().locator('.dev-id .dinfo').click();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'false', 'Details button does not select');
  assert.match(await page.locator('#di-rows').innerText(), /Series\s+Cisco 8000 Series/);
  assert.match(await page.locator('#di-rows').innerText(), /Chassis model\s+8201.*inventory/);
  await page.locator('#di-close').click();
  assert.equal(await rows.first().locator('td').nth(3).innerText(), 'Cisco 8000 Series');
  assert.equal(await rows.first().locator('td').nth(3).getAttribute('title'), '8201');
  await page.locator('#add-dev').click();
  const addSeries = page.locator('#df-model');
  assert.equal(await addSeries.evaluate(node => node.tagName), 'SELECT');
  assert.deepEqual(await addSeries.locator('option').allTextContents(), [
    'Choose a series…', 'IE Switches', 'IR Routers', 'Catalyst Routers',
    'Catalyst Switches', 'NCS', 'Cisco 8000 Series',
  ]);
  for (const [value, management, install] of [
    ['IE3x00', 'inband', 'iox'], ['IR1x00', 'inband', 'iox'],
    ['C9xxx', 'inband', 'guestshell'], ['C8xxx', 'router-routed', 'router'],
    ['C8xxx', 'router-routed', 'iox'], ['C8xxx', 'router-nat', 'router'],
    ['C8xxx', 'router-nat', 'iox'],
    ['NCS', 'xr-host', 'xr-appmgr'], ['XR8000', 'xr-host', 'xr-appmgr'],
  ]) {
    await page.locator('#df-management-type').selectOption(management);
    const response = page.waitForResponse(r => r.url().includes('/install-options?model=' + value));
    await addSeries.selectOption(value);
    await response;
    await page.waitForFunction(expected => Array.from(document.querySelector('#df-platform').options)
      .some(option => option.value === expected), install);
    await page.locator('#df-platform').selectOption(install);
    assert.equal(await page.locator('#df-management-type').inputValue(), management);
  }
  await page.locator('#df-id').fill('series-ui-test');
  await page.locator('#df-ip').fill('192.0.2.99');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'add-device-series.png') });
  await page.locator('#dev-form').getByRole('button', { name: 'Save device', exact: true }).click();
  await page.locator('#dev-form').waitFor({ state: 'hidden' });
  assert.deepEqual(writes.splice(0), ['POST /api/v1/devices'], 'Only the explicit synthetic form submission writes');
  await page.locator('#more-filters-summary').click();
  const series = page.locator('#dev-filter-model-family');
  assert.deepEqual(await series.locator('option').allTextContents(), [
    'Device series: any', 'IE Switches', 'IR Routers', 'Catalyst Routers',
    'Catalyst Switches', 'NCS', 'Cisco 8000 Series', 'ISR/ASR/CSR', 'Unknown series',
  ]);
  await series.selectOption('NCS');
  await page.getByRole('button', { name: 'Remove filter: NCS', exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 1);
  assert.match(deviceQueries.at(-1), /model_family=NCS/);
  assert.match(await page.locator('#dev-rows').innerText(), /edge-02/);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-filters.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  const filterBox = await series.boundingBox();
  assert.ok(filterBox.x >= 0 && filterBox.x + filterBox.width <= 390, 'Filter stays in viewport');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-filters-mobile.png') });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Remove filter: NCS', exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 2);
  await page.locator('#dev-filter-q').fill('edge-01');
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 1);
  await page.locator('#dev-filter-clear').click();
  await page.waitForFunction(() => document.querySelectorAll('#dev-rows tr[data-id]').length === 2);
  await page.locator('#more-filters-summary').click();
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-desktop.png') });
  await page.locator('#dev-activity').click();
  await page.locator('#batch-rows .blog').first().click();
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'FIRST JOB ONLY' }));
  await page.locator('#onboard-logs').getByText('FIRST JOB ONLY', { exact: true }).waitFor();
  await page.locator('#batch-rows .blog').nth(1).click();
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'SECOND JOB ONLY' }));
  await page.locator('#onboard-logs').getByText('SECOND JOB ONLY', { exact: true }).waitFor();
  assert.equal(await page.locator('#onboard-logs .job-log-panel:visible').count(), 1);
  assert.equal(await page.locator('#activity-panel').getByRole('button', { name: /Close/ }).count(), 1);
  assert.equal(await page.locator('#onboard-logs').getByText('FIRST JOB ONLY', { exact: true }).isVisible(), false);
  await page.evaluate(() => window.testStreams.at(-1).onmessage({ data: 'Undeploy completed.' }));
  await page.waitForFunction(() => document.querySelector('#onboard-logs .job-log-panel:not([hidden]) .log').textContent.includes('Undeploy completed.'));
  const fonts = await page.evaluate(() => ['body', '.page-title', '#onboard-logs .job-log-panel:not([hidden]) .log', '.machine', 'button', 'code']
    .map(selector => document.querySelector(selector)).filter(Boolean)
    .map(element => getComputedStyle(element).fontFamily));
  assert.equal(new Set(fonts).size, 1, 'Headings, controls, data and completion logs share one font family');
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'inventory-activity.png') });
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#activity-panel').isVisible(), false);
  assert.equal(await page.evaluate(() => window.testStreams.every(s => s.closed)), true);
  await page.locator('#dev-activity').click();
  await page.locator('#batch-rows .blog').first().click();
  assert.equal(await page.evaluate(() => window.testStreams.length), 3, 'Reopening reconnects');
  await page.locator('#batch-close').click();
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Policies', exact: true }).click();
  const sharing = page.getByRole('table', {name: 'Who can share images', exact: true});
  await sharing.getByRole('rowheader').filter({hasText: 'staging'}).waitFor();
  assert.equal(await page.locator('#policy-advanced-modal').isVisible(), false);
  const branchRow = sharing.getByRole('row').filter({has: page.getByRole('rowheader').filter({hasText: 'branch'})});
  assert.match(await branchRow.innerText(), /staging/);
  assert.match(await branchRow.innerText(), /Not allowed by role/);
  assert.doesNotMatch(await branchRow.innerText(), /isolated/);
  assert.match(await page.locator('#iris-policies-root').innerText(), /Preview only — not enforced at the distribution server/);
  await page.getByRole('button', {name: 'Edit role branch', exact: true}).click();
  assert.equal(await page.locator('#role-editor-advanced').getAttribute('open'), null);
  await page.locator('#role-editor-advanced > summary').click();
  assert.equal(await page.locator('[data-qos="overall_up_bps"]').inputValue(), '8192');
  await page.locator('[data-qos="overall_up_bps"]').fill('4096');
  await page.locator('#role-def-save').click();
  await page.locator('#role-def-save').getByText('Save role', {exact: true}).waitFor();
  await page.locator('#role-def-save').click();
  await page.locator('#role-def-msg').getByText('Peer policy changed. Close this editor, refresh, and reopen the current definition before previewing again.', {exact: true}).waitFor();
  assert.equal(await page.locator('#role-def-preview').isVisible(), false, 'A conflict invalidates the preview instead of silently committing');
  assert.deepEqual(writes.splice(0), ['PUT /api/v1/peer-policy/roles/branch', 'PUT /api/v1/peer-policy/roles/branch']);
  await page.locator('#role-def-cancel').click();
  await page.getByRole('button', {name: 'Advanced…', exact: true}).click();
  await page.locator('#policy-advanced-modal').waitFor({state: 'visible'});
  assert.equal(await page.locator('#role-def-export').isVisible(), true);
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('button', {name: 'Advanced…', exact: true}).evaluate(el => el === document.activeElement), true);
  await page.getByRole('button', {name: 'New role', exact: true}).click();
  await page.locator('#role-def-modal').waitFor({ state: 'visible' });
  await page.locator('#rd-name').fill('test-role');
  assert.equal(await page.locator('#rd-origin').isDisabled(), true);
  await page.locator('#rd-restricted').check();
  assert.equal(await page.locator('#rd-origin').isDisabled(), false);
  await page.locator('#role-def-cancel').click();
  await page.locator('#role-def-modal').waitFor({ state: 'hidden' });
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'policies-desktop.png') });
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'policies-mobile.png') });
  await page.setViewportSize({width: 1440, height: 1000});
  const policyState = await page.evaluate(() => window.testPolicyState);
  await page.evaluate(state => window.dispatchEvent(new CustomEvent('iris:policy-state', {detail: {...state, ready: false, disabled: true}})), policyState);
  await sharing.getByText('Role permissions unavailable. Refresh or check Advanced.').waitFor();
  assert.equal(await page.getByRole('button', {name: 'New role', exact: true}).isDisabled(), true);
  await page.evaluate(state => window.dispatchEvent(new CustomEvent('iris:policy-state', {detail: state})), policyState);
  await sharing.getByRole('rowheader').filter({hasText: 'staging'}).waitFor();
  assert.deepEqual(writes, [], 'Navigation, selection and cancelling an editor must not mutate server state');
  await page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Inventory', exact: true }).click();
  const csv = {name: 'same.csv', mimeType: 'text/csv', buffer: Buffer.from('device_id,role\ncsv-test,missing-role\n')};
  for (let attempt = 0; attempt < 2; attempt++) {
    const imported = page.waitForResponse(r => r.url().endsWith('/api/v1/devices/import-csv'));
    await page.locator('#csv-file').setInputFiles(csv);
    await imported;
    await page.waitForFunction(() => !document.getElementById('import-csv').disabled);
    await page.waitForFunction(() => document.getElementById('csv-import-status').textContent.includes('role: missing-role'));
    assert.equal(await page.locator('#csv-file').inputValue(), '');
    assert.match(await page.locator('#csv-import-status').innerText(), /device_id: csv-test.*Define the role in Policies/);
  }
  assert.deepEqual(writes.splice(0), ['POST /api/v1/devices/import-csv', 'POST /api/v1/devices/import-csv']);
  if (await page.locator('#sel-clear').isVisible()) await page.locator('#sel-clear').click();
  await page.locator('#dev-rows tr[data-id]').first().locator('td').nth(2).click();
  for (const action of ['onboard', 'undeploy']) {
    for (const detail of [false, true]) {
      await page.locator('#' + action + '-selected').click();
      await page.locator('#' + action + '-log').setChecked(detail);
      if (action === 'undeploy') {
        const copy = await page.locator('#undeploy-modal .modal-body').innerText();
        assert.ok(copy.split(/\s+/).length < 90, 'Undeploy popup stays concise');
        assert.match(copy, /Skips record and device identity checks/);
        assert.equal(await page.locator('#undeploy-force-help').evaluate(el => getComputedStyle(el).fontFamily), fonts[0]);
        // Exercise both normal and Force confirmation warnings without a real job.
        await page.locator('#undeploy-force').setChecked(detail);
        if (screenshots) await page.screenshot({ path: path.join(screenshots, 'undeploy-popup.png') });
        page.once('dialog', async dialog => {
          assert.match(dialog.message(), /Keeps staged images in device storage/);
          assert.match(dialog.message(), /Does not stop running jobs/);
          if (detail) assert.match(dialog.message(), /skips record and device identity checks/);
          assert.ok(dialog.message().split(/\s+/).length < 65);
          await dialog.accept();
        });
      }
      const submitted = page.waitForResponse(r => r.url().endsWith('/' + action) && r.request().method() === 'POST');
      await page.locator('#' + action + '-confirm').click();
      await submitted;
      await page.waitForFunction(() => !document.getElementById('onboard-selected').disabled);
      await page.locator('#batch-close').click();
    }
  }
  assert.deepEqual(jobOptions, [['onboard', false], ['onboard', true], ['undeploy', false], ['undeploy', true]]);
  assert.equal(writes.length, 4);
  await page.getByRole('button', {name: 'Help', exact: false}).click();
  for (const failure of ['http-error', 'network-error']) {
    logoutResult = failure;
    await page.getByRole('button', {name: 'Sign out', exact: true}).click();
    await page.getByRole('alert').filter({hasText: 'Your session may still be active'}).waitFor();
    assert.equal(new URL(page.url()).pathname, '/', 'Failed logout must not imply that the session was revoked');
    assert.equal(await page.getByRole('button', {name: 'Sign out', exact: true}).isEnabled(), true);
  }
  logoutResult = 'success';
  await page.getByRole('button', {name: 'Sign out', exact: true}).click();
  await page.waitForURL('http://iris.test/login.html');
  assert.deepEqual(errors, []);
  console.log('React UI browser smoke passed (mock APIs: settings, selection, series/search/reset, isolated activity streams, desktop + mobile).');
} finally { await browser.close(); }
