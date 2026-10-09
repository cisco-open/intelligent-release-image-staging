// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAst } from 'rolldown/parseAst';
import { build } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
export const configPlaceholder = 'window.IRIS_MAP_CFG = null;';

// HTML parses a classic script before JavaScript does. Escape HTML script
// delimiters only inside cooked string values; changing an operator, regexp,
// comment or a tagged template's raw value would change the program instead.
export function inlineScript(source) {
  const ranges = [];
  function visit(node, tagged = false) {
    if (!node || typeof node !== 'object') return;
    if (['ImportDeclaration', 'ImportExpression', 'ExportNamedDeclaration',
      'ExportDefaultDeclaration', 'ExportAllDeclaration'].includes(node.type)) {
      throw new Error('The map must contain one complete classic script, without imports or exports');
    }
    if (node.type === 'TaggedTemplateExpression') {
      visit(node.tag, tagged);
      visit(node.quasi, true);
      return;
    }
    if (!tagged && ((node.type === 'Literal' && typeof node.value === 'string')
      || node.type === 'TemplateElement')) ranges.push([node.start, node.end]);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(child => visit(child, tagged));
      else if (value && typeof value === 'object') visit(value, tagged);
    }
  }
  visit(parseAst(source));
  let result = '', copied = 0;
  for (const match of source.matchAll(/<\/?script\b|<!--/gi)) {
    const offset = match.index;
    if (!ranges.some(([start, end]) => start <= offset && offset + match[0].length <= end)) {
      throw new Error('Unsafe HTML delimiter outside a JavaScript string in the map bundle');
    }
    let backslashes = 0;
    while (source[offset - backslashes - 1] === '\\') backslashes++;
    // A raw \< has the same cooked value as <. Replace that optional escape
    // too, so inserting our escape cannot turn it into a literal backslash.
    result += source.slice(copied, offset - backslashes % 2) + '\\x3c';
    copied = offset + 1;
  }
  result += source.slice(copied);
  parseAst(result);
  return result;
}

export function assembleMapHtml(template, script, css) {
  if (/<\/style\b|<!--/i.test(css)) throw new Error('Unsafe HTML delimiter in the map stylesheet');
  for (const marker of ['@@IRIS_MAP_CSS@@', '@@IRIS_MAP_SCRIPT@@', configPlaceholder]) {
    if (template.split(marker).length !== 2) throw new Error(`Expected one map marker: ${marker}`);
  }
  const html = template.replace('@@IRIS_MAP_CSS@@', () => css)
    .replace('@@IRIS_MAP_SCRIPT@@', () => inlineScript(script));
  for (const tag of ['script', 'style']) {
    if ((html.match(new RegExp(`<${tag}\\b`, 'gi')) || []).length !== 1
      || (html.match(new RegExp(`</${tag}\\s*>`, 'gi')) || []).length !== 1
      || !html.includes(`<${tag}>`)) throw new Error(`Expected one inline map ${tag}`);
  }
  if (html.split(configPlaceholder).length !== 2) throw new Error('Duplicate map configuration placeholder');
  return html;
}

export async function buildMap() {
  const destination = resolve(root, 'dist/swarmmap.html');
  const temporary = `${destination}.${process.pid}.tmp`;
  // A failed build must not leave an older page looking ready to deploy.
  await rm(destination, { force: true });
  try {
    const built = await build({ root, configFile: resolve(root, 'vite.config.js'),
      mode: 'swarm-map', build: { write: false } });
    const output = (Array.isArray(built) ? built : [built]).flatMap(result => result.output);
    const scripts = output.filter(item => item.type === 'chunk');
    const styles = output.filter(item => item.type === 'asset' && item.fileName === 'swarmmap.css');
    if (scripts.length !== 1 || !scripts[0].isEntry || scripts[0].imports.length
      || scripts[0].dynamicImports.length || styles.length !== 1 || output.length !== 2) {
      throw new Error('The map must build into one script and one stylesheet with no external assets');
    }
    const template = await readFile(resolve(root, 'templates/swarmmap.html'), 'utf8');
    const html = assembleMapHtml(template, scripts[0].code, String(styles[0].source));
    await mkdir(resolve(root, 'dist'), { recursive: true });
    await writeFile(temporary, html, { encoding: 'utf8', mode: 0o644 });
    await rename(temporary, destination);
    console.log(`Built self-contained swarm map: ${destination}`);
  } finally {
    await rm(temporary, { force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await buildMap();
}
