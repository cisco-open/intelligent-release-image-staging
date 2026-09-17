// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

// Node dependencies are absent from the runtime image. Keep their complete
// notices in the delivered bundle, not only in the disposable build stage.
function runtimeLicenseNotices() {
  const notices = ['react', 'react-dom', 'scheduler'].map(name => {
    const license = readFileSync(new URL(`./node_modules/${name}/LICENSE`, import.meta.url), 'utf8');
    if (license.includes('*/')) throw new Error(`Unsafe license comment: ${name}`);
    return `${name}\n${license.trim()}`;
  }).join('\n\n');
  return {
    name: 'iris-runtime-license-notices',
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type === 'chunk' && output.isEntry) {
          output.code = `/*! Bundled third-party notices\n\n${notices}\n*/\n${output.code}`;
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), runtimeLicenseNotices()],
  // The existing Python Console owns HTML, auth and API routing. Bundle React
  // locally as one module; never require CDN imports or inline script/style.
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    target: 'es2022',
    sourcemap: false,
    outDir: 'dist',
    emptyOutDir: true,
    lib: {
      entry: fileURLToPath(new URL('./src/main.jsx', import.meta.url)),
      formats: ['es'],
      fileName: () => 'console.js',
      cssFileName: 'console',
    },
  },
});
