// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { assembleMapHtml, configPlaceholder, inlineScript } from '../scripts/build-map.mjs';

const template = readFileSync(new URL('../templates/swarmmap.html', import.meta.url), 'utf8');
const html = readFileSync(new URL('../dist/swarmmap.html', import.meta.url), 'utf8');

test('the generated map is one self-contained React document with one configuration placeholder', () => {
  assert.equal(html.split(configPlaceholder).length, 2);
  assert.equal((html.match(/<script\b/gi) || []).length, 1);
  assert.equal((html.match(/<style\b/gi) || []).length, 1);
  assert.ok(html.includes('<div id="iris-swarm-map-root"></div>'));
  assert.match(html, /Copyright 2026 Cisco Systems/);
  assert.match(html, /SPDX-License-Identifier: Apache-2\.0/);
  const script = html.split('<script>')[1].split('</script>')[0];
  assert.ok(script.length > 10000, 'The map includes the React runtime, not an external module');
  assert.equal(inlineScript(script), script);
  assert.doesNotMatch(script, /\beval\s*\(|\bnew Function\s*\(/);
  assert.doesNotMatch(script, /process\.env\.NODE_ENV|react\.development/);
  assert.doesNotMatch(html, /<script\b[^>]+src=|<link\b[^>]+stylesheet|@@IRIS_MAP_/i);
  assert.doesNotMatch(html.split('<style>')[1].split('</style>')[0], /url\(["']?(?:https?:|data:|\/\/)/i);
  for (const name of ['react', 'react-dom', 'scheduler']) {
    const license = readFileSync(new URL(`../node_modules/${name}/LICENSE`, import.meta.url), 'utf8').trim();
    assert.ok(script.includes(`${name}\n${license}`), `${name}: complete runtime notice missing`);
  }
});

test('inline assembly escapes HTML delimiters without changing cooked string values', () => {
  const source = 'const prefix="é😀"; globalThis.values = ["</script>", "<SCRIPT >", "<!--", `</ScRiPt>`, "$&"];';
  const script = inlineScript(source);
  assert.doesNotMatch(script, /<\/?script\b|<!--/i);
  const before = {}, after = {};
  vm.runInNewContext(source, before);
  vm.runInNewContext(script, after);
  assert.equal(JSON.stringify(after.values), JSON.stringify(before.values));
  const assembled = assembleMapHtml(template, source, 'body::before { content: "$&"; }');
  assert.ok(assembled.includes('body::before { content: "$&"; }'));
  assert.equal((assembled.match(/<script\b/gi) || []).length, 1);
  for (const slashes of [1, 2, 3, 4]) {
    for (const quote of ['"', '`']) {
      const escaped = 'globalThis.value = ' + quote + '\\'.repeat(slashes) + '</script>' + quote + ';';
      const prior = {}, next = {};
      vm.runInNewContext(escaped, prior);
      vm.runInNewContext(inlineScript(escaped), next);
      assert.equal(next.value, prior.value, `Preserve ${slashes} escape characters in ${quote} strings`);
    }
  }
});

test('assembly rejects unsafe HTML syntax instead of changing operators or raw template values', () => {
  for (const source of [
    '/* </script> */ globalThis.value = 1;',
    'globalThis.value = 1</script/.test("script");',
    'globalThis.value = String.raw`</script>`;',
  ]) assert.throws(() => inlineScript(source), /Unsafe HTML delimiter/);
  for (const source of ['import("module");', 'import value from "module";', 'export default 1;']) {
    assert.throws(() => inlineScript(source), /without imports or exports/);
  }
  assert.throws(() => assembleMapHtml(template, 'const x=1;', '/* </style> */'), /stylesheet/);
  assert.throws(() => assembleMapHtml(template.replace(configPlaceholder, ''), 'const x=1;', ''), /marker/);
  assert.throws(() => assembleMapHtml(template + '<script>1</script>', 'const x=1;', ''), /one inline map script/);
});
