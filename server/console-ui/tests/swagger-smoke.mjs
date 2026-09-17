// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Real vendored Swagger and canonical contract; all HTTP is intercepted locally.
// No build step is required: node tests/swagger-smoke.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const docs = fileURLToPath(new URL('../../../docs/zensical/', import.meta.url));
const contract = await fs.readFile(path.join(docs, 'openapi.yaml'));
const spec = JSON.parse(contract.toString());
const methods = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace', 'query']);
const operations = Object.values(spec.paths).flatMap(item => Object.entries(item)
  .filter(([method]) => methods.has(method)).map(([, operation]) => operation));
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  const errors = [], requests = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    assert.equal(url.origin, 'http://iris.test', 'No external requests');
    assert.equal(request.method(), 'GET', 'Reference never mutates a service');
    assert.equal(request.headers().authorization, undefined, 'No credentials sent');
    requests.push(url.pathname);
    let relative;
    if (url.pathname === '/openapi.yaml') relative = 'openapi.yaml';
    else if (url.pathname === '/swagger/') relative = 'swagger/index.html';
    else if (/^\/swagger\/[a-z0-9.-]+\.(js|css)$/.test(url.pathname)) relative = url.pathname.slice(1);
    else assert.fail(`Unexpected request: ${url.pathname}`);
    const type = relative.endsWith('.js') ? 'application/javascript'
      : relative.endsWith('.css') ? 'text/css' : relative.endsWith('.yaml') ? 'application/yaml' : 'text/html';
    await route.fulfill({body: await fs.readFile(path.join(docs, relative)), contentType: type});
  });
  await page.goto('http://iris.test/swagger/');
  await page.waitForFunction(() => window.ui && document.querySelectorAll('.swagger-ui .opblock').length > 0);
  await page.waitForFunction(() => !document.getElementById('iris-streaming-responses').hidden);
  assert.equal(await page.locator('.swagger-ui .opblock').count(), operations.filter(op => op.tags.includes('console')).length);
  assert.equal(await page.getByRole('button', {name: 'Console API', exact: true}).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.evaluate(() => window.ui.layoutSelectors.currentFilter()), 'console');
  assert.deepEqual(await page.evaluate(() => window.ui.specSelectors.specJson().toJS()), spec, 'Filtering must not rewrite the contract');
  assert.equal(await page.locator('.swagger-ui .auth-wrapper:visible, .swagger-ui .authorization__btn:visible').count(), 0);
  assert.equal(await page.locator('.swagger-ui .filter-container:visible').count(), 0, 'No competing native service-filter field');
  assert.equal(await page.locator('input[type="password"]').count(), 0);
  assert.equal(await page.getByRole('button', {name: /^(Try it out|Execute|Authorize)$/i}).count(), 0);
  const output = process.env.IRIS_SWAGGER_SCREENSHOTS || await fs.mkdtemp('/tmp/iris-swagger-review-');
  await fs.mkdir(output, {recursive: true});
  const checkWidth = async () => {
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth
      ? [`Document width ${document.documentElement.scrollWidth}`, ...[...document.querySelectorAll('body *')]
        .filter(el => el.getBoundingClientRect().right > innerWidth + 1 || el.scrollWidth > el.clientWidth + 1)
        .slice(0, 12).map(el => `${el.tagName}.${el.className}: ${el.getBoundingClientRect().right}, scroll ${el.scrollWidth}`)] : []);
    assert.deepEqual(overflow, [], 'No horizontal page overflow');
  };
  await checkWidth();
  await page.screenshot({path: path.join(output, 'swagger-desktop.png')});
  await page.getByRole('button', {name: 'All services', exact: true}).click();
  await page.waitForFunction(count => document.querySelectorAll('.swagger-ui .opblock').length === count, operations.length);
  assert.equal(await page.evaluate(() => window.ui.layoutSelectors.currentFilter()), '');
  // "Authorize a browser mutation" is a legitimate endpoint summary, not
  // Swagger's Authorize control. Inspect execution/auth controls explicitly.
  assert.equal(await page.locator('.try-out__btn:visible, .execute:visible, .auth-wrapper:visible, .authorization__btn:visible').count(), 0);
  assert.equal(await page.getByRole('button', {name: /^(Try it out|Execute|Authorize)$/i}).count(), 0);
  await page.getByRole('button', {name: 'Console API', exact: true}).click();
  await page.waitForFunction(() => window.ui.layoutSelectors.currentFilter() === 'console');
  // Open a real endpoint to exercise vendor schema/response rendering, without execution controls.
  await page.locator('.swagger-ui .opblock-summary-control').first().click();
  await page.locator('.swagger-ui .opblock-body').first().waitFor();
  assert.equal(await page.getByRole('button', {name: /^(Try it out|Execute|Authorize)$/i}).count(), 0);
  const fonts = await page.evaluate(() => ['body', '.iris-api-header', '.swagger-ui .opblock-summary-path', '.swagger-ui pre']
    .map(selector => document.querySelector(selector)).filter(Boolean).map(el => getComputedStyle(el).fontFamily));
  assert.equal(new Set(fonts).size, 1, 'Headings, paths and examples use the same sans family');
  await page.setViewportSize({width: 390, height: 844});
  await checkWidth();
  await page.screenshot({path: path.join(output, 'swagger-mobile.png')});
  await page.locator('.iris-explorer-summary').click();
  const search = page.getByRole('searchbox', {name: 'Find an endpoint or schema'});
  await search.fill('no-such-endpoint-or-schema');
  await page.getByRole('status').filter({hasText: 'No matching endpoints or schemas'}).waitFor();
  assert.equal(await page.locator('.iris-canonical-list details:visible').count(), 0);
  const schemaName = Object.keys(spec.components.schemas)[0];
  await search.fill(`schemas ${schemaName}`);
  const schema = page.locator('.iris-canonical-list details:visible').filter({hasText: `schemas.${schemaName}`}).first();
  await schema.locator('summary').click();
  await schema.locator('pre').waitFor();
  assert.deepEqual(JSON.parse(await schema.locator('pre').innerText()), spec.components.schemas[schemaName]);
  await search.fill('/api/v1/devices');
  assert.ok(await page.locator('.iris-canonical-list details:visible').count() > 0);
  const first = page.locator('.iris-canonical-list details:visible').first();
  await first.locator('summary').click();
  await first.locator('pre').waitFor();
  assert.ok(JSON.parse(await first.locator('pre').innerText()).operationId);
  await checkWidth();
  await page.screenshot({path: path.join(output, 'swagger-search-mobile.png')});
  const before = await page.locator('.iris-canonical-list details').count();
  await page.evaluate(() => window.renderIrisOpenAPI32(window.ui.specSelectors.specJson().toJS()));
  assert.equal(await page.locator('.iris-canonical-list details').count(), before, 'Repeated completion replaces the explorer');
  assert.equal(await page.getByRole('searchbox', {name: 'Find an endpoint or schema'}).count(), 1);
  // A bookmarked non-Console endpoint must not disappear behind the default scope.
  const catalogOperation = operations.find(operation => operation.tags.includes('catalog'));
  await page.evaluate(id => { location.hash = `#/catalog/${encodeURIComponent(id)}`; }, catalogOperation.operationId);
  await page.waitForFunction(() => document.querySelector('[data-iris-service=""]').getAttribute('aria-pressed') === 'true');
  await page.reload();
  await page.waitForFunction(count => document.querySelectorAll('.swagger-ui .opblock').length === count, operations.length);
  assert.equal(await page.getByRole('button', {name: 'All services', exact: true}).getAttribute('aria-pressed'), 'true');
  await page.locator(`[id="operations-catalog-${catalogOperation.operationId}"] .opblock-body`).waitFor();
  await checkWidth();
  assert.deepEqual(errors, []);
  assert.equal(requests.filter(p => p === '/openapi.yaml').length, 2);
  console.log(`Swagger browser smoke passed: ${operations.length} canonical operations, real vendor rendering, scope/search, read-only boundary, desktop/mobile. Screenshots: ${output}`);
} finally { await browser.close(); }
