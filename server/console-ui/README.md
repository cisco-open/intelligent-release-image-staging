<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Console React build

This directory builds self-hosted React assets for the existing Python Console.
It does not add a second server, authentication flow, or API implementation.

The shell, operational views and standalone Swarm map use IRIS-owned React
components, visually inspired by Catalyst Center. This is not an official
Magnetic implementation: do not use the internal Magnetic boilerplate, Harbor
components, private registries, or copied vendor assets. The existing JavaScript
adapter supplies shared transport, routing and cross-view state. React owns its
explicit mount roots and portals. Settings links preserve the existing
`#settings/<section>` routes.

```sh
npm ci
npm test
```

CI runs the build checks and Console/Swagger browser checks using locked Playwright.
Locally, install Chromium once with `npx --no-install playwright install chromium`,
then run `npm run test:browser` and `npm run test:swagger` after `npm test`. `PLAYWRIGHT_MODULE` can select
an existing external installation. The checks cover desktop/mobile navigation
and focus under the Console CSP, plus the read-only vendored API reference;
they do not contact a live fleet.

Node 22.12 or later is recommended. Dependencies are pinned in the lockfile.
Tests guard public npm resolutions and the React-only direct runtime dependency
boundary, and reject internal UI imports in source files.
`npm run build` writes `dist/console.js`, `dist/console.css` and the self-contained
`dist/swarmmap.html`. Use `build:console` or `build:map` for one target. Build
output and `node_modules` are not source files. Build before Python serving tests.

The Console Dockerfile builds and copies its assets to `server/webroot/assets/`.
The server Dockerfile separately builds and copies the map; rebuild that image
when changing the map. Both use disposable Node stages. For a Python-only preview,
run the following from the repository root after building:

```sh
mkdir -p server/webroot/assets
cp server/console-ui/dist/console.js server/console-ui/dist/console.css server/webroot/assets/
```

The existing HTML loads `/assets/console.js` as an external module and
`/assets/console.css` as an external stylesheet.
Do not relax the Console Content Security Policy, add runtime CDN imports or
inject inline styles. The map's separate policy uses per-request nonces for its
single script and stylesheet. React owns only its explicit roots and portals.

The Python Console remains responsible for sessions, CSRF, role checks, API
proxying, and static-file security headers. Browser requests continue to use its
same-origin API.

Build approach: [React incremental integration](https://react.dev/learn/add-react-to-an-existing-project)
and [Vite production builds](https://vite.dev/guide/build).
