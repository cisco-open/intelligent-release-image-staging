// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';

const bundle = readFileSync(new URL('../dist/console.js', import.meta.url), 'utf8');
const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
const internalUiReference = /@(?:harbor|magnetic)(?:\/|\b)|\bhbr[-A-Z]|\bagentinfo\b|boilerplate-web-main/i;

function readSources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = new URL(entry.name + (entry.isDirectory() ? '/' : ''), directory);
    return entry.isDirectory() ? readSources(path) : [[path.pathname, readFileSync(path, 'utf8')]];
  });
}

test('production bundle is self-hosted and compatible with strict script CSP', () => {
  assert.ok(bundle.length > 1000, 'React must be included in the local bundle');
  assert.doesNotMatch(bundle, /(?:import|export)\s[^;]*?from\s*["'](?:https?:|react)/);
  assert.doesNotMatch(bundle, /\beval\s*\(|\bnew Function\s*\(/);
  assert.doesNotMatch(bundle, /process\.env\.NODE_ENV|react\.development/);
});

test('runtime dependencies remain React and its public runtime support', () => {
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), ['react', 'react-dom']);
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  for (const field of ['optionalDependencies', 'peerDependencies']) {
    assert.deepEqual(Object.keys(manifest[field] || {}), [], `unexpected ${field}`);
  }
  const runtimePackages = Object.entries(lock.packages)
    .filter(([name, entry]) => name && !entry.dev)
    .map(([name]) => name).sort();
  assert.deepEqual(runtimePackages, [
    'node_modules/react', 'node_modules/react-dom', 'node_modules/scheduler',
  ]);
});

test('distributed JavaScript carries complete runtime dependency licenses', () => {
  for (const name of ['react', 'react-dom', 'scheduler']) {
    const license = readFileSync(new URL(`../node_modules/${name}/LICENSE`, import.meta.url), 'utf8').trim();
    assert.ok(bundle.includes(`${name}\n${license}`), `${name}: missing copyright or permission notice`);
  }
});

test('package manifests and locked downloads have no internal UI dependency or private registry', () => {
  assert.doesNotMatch(JSON.stringify(manifest), internalUiReference);
  assert.doesNotMatch(JSON.stringify(lock), internalUiReference);
  for (const [name, entry] of Object.entries(lock.packages)) {
    if (!name) continue;
    assert.ok(entry.resolved, `${name}: package must resolve to public npm`);
    const resolved = new URL(entry.resolved);
    assert.equal(resolved.origin, 'https://registry.npmjs.org', name);
    assert.equal(resolved.username, '', name);
    assert.equal(resolved.password, '', name);
  }
});

test('shell sources use independent components and local or React imports', () => {
  for (const [path, source] of readSources(new URL('../src/', import.meta.url))) {
    assert.doesNotMatch(source, internalUiReference, path);
    assert.doesNotMatch(source, /(?:https?:)?\/\/[^\s/'"]*(?:artifactory|registry)[^\s/'"]*/i, path);
    const imports = source.matchAll(/(?:\bfrom\s*|\bimport\s*(?:\(\s*)?|\brequire\s*\(\s*)['"]([^'"]+)['"]/g);
    for (const [, specifier] of imports) {
      assert.match(specifier, /^(?:\.{1,2}\/|react(?:-dom)?(?:\/|$))/, `${path}: ${specifier}`);
    }
  }
});
