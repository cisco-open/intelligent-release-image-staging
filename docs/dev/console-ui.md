<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# The React build, mount roots and CSP

This page is for a contributor changing `server/console-ui/`, the Console's
React frontend, or the vendored API explorer it ships next to it. It covers
how the frontend is built, which parts of the Console are React and which are
not yet, and the browser rules the build has to keep. It does not cover the
Console as an operator sees it; see [Find your way around the
Console](../zensical/user-guide/console.md) for that.

## The shell and the legacy app

`server/console-ui/` builds three parts of the Console page with React: the
header, which includes the help and account controls, the primary
navigation, and the Settings section navigation bar. Every other screen,
including the operational views, the working forms, and the dedicated
Policies page, still renders from the older `server/webroot/app.js`. This is
a partial migration, not a full rewrite, and the two parts of the interface
run side by side.

The React entry point mounts before the older application loads. It passes
shell state to that older code through an `iris:shell-state` event, and it
listens for an `iris:logout` event so signing out works the same way from
either part of the page. Settings pages keep their existing
`#settings/<section>` routes, so a link into a specific Settings section
still lands there. Settings itself keeps one navigation-rail link and its own
in-page section bar.

The first-run setup wizard reuses these same components instead of
duplicating them; see [Sign in for the first
time](../zensical/install/first-sign-in.md) for how that flow works.

The shell components are IRIS's own, written to look like Cisco Catalyst
Center's layout, not a copy of an internal Cisco design system. Do not bring
in internal Cisco component libraries, internal design-system boilerplate,
or any vendor asset that does not belong in a public repository. Every
runtime dependency has to come from the public npm registry; the build must
not need a private registry.

## Build and test locally

Building or testing the frontend by itself needs Node 22.12 or later:

```bash
cd server/console-ui
npm ci
npm test
```

The test suite also checks the dependency boundary from the previous
section. React and React DOM are the only direct runtime dependencies the
frontend is allowed to declare, and a test fails if an internal Console UI
import appears where a public one should be.

CI also runs a set of browser checks against a mocked Chromium build, using a
pinned Playwright dependency. To run the same checks locally, install
Chromium once and then run the browser test script from
`server/console-ui/`:

```bash
npx --no-install playwright install chromium
npm run test:browser
```

None of these checks contact a live server or a live device.

## Building the browser assets

The Console's Dockerfile builds the frontend in its own Node build stage,
then copies the two files it produces, `console.js` and `console.css`, into
the Python runtime image's `webroot/assets/`. Node and `node_modules` are not
part of that runtime image. A normal Docker build does this for you.

To preview the built Console from a plain Python run, without Docker, build
the frontend from the repository root and copy the output into place by
hand:

```bash
npm --prefix server/console-ui run build
mkdir -p server/webroot/assets
cp server/console-ui/dist/console.js server/console-ui/dist/console.css server/webroot/assets/
```

The browser then loads `/assets/console.js` and `/assets/console.css`. Both
files are generated and git-ignored; do not commit them.

## Content Security Policy

The Console keeps a strict Content Security Policy: no script loads from a
content delivery network at runtime, no inline script runs, and no style is
injected inline. Assets, the React bundle, and the fonts the next section
describes all have to be served from the Console itself. Keep any change to
the frontend build inside that policy rather than relaxing it. This
migration does not change what the backend itself protects; see
[Security model and trust boundaries](../zensical/architecture/security-model.md).
The public documentation site stays separate from the Console and needs no
external dependency of its own.

## Theme and fonts

The Console self-hosts Inter for headings, body text, IP addresses, and log
text, with the system's own sans-serif fonts as a fallback. Both the React
shell and the older pages share this font stack. The IRIS theme is its own
design, with no proprietary component assets, and it does not need a Cisco
font to render correctly.

An older `IRIS_SHARP_SANS_FONT_HOST` mount still exists for compatibility
with earlier deployments, but it no longer changes how the Console looks.
Licensed font files stay out of Docker builds and release tarballs; see
[Server configuration](../zensical/reference/server-configuration.md) for
that variable.

## The API explorer

`docs/zensical/swagger/iris-openapi32.js` is the explorer the Console and the
documentation site both use on top of the vendored Swagger UI. It reads every
operation and schema directly from the loaded OpenAPI contract and shows each
one as exact JSON, calling out streaming `itemSchema` values and serialized
examples along the way. It never rewrites the contract it reads. See
[Swagger UI provenance record](../zensical/swagger/SOURCE.txt) for where the
rest of the vendored files come from, and [Writing and building the
docs](documentation.md) for the one table that pins the vendored Swagger UI
version.

The OpenAPI document itself leaves `jsonSchemaDialect` unset. That is
deliberate: leaving it unset means the OpenAPI 3.2 default dialect applies,
and the vendored Swagger UI renders the contract with no dialect warning.
Setting the field, even to OpenAPI 3.2's own dialect, makes this version of
Swagger UI compare it against the older 3.1 base instead and warn on every
load. None of the schemas use a keyword that only a declared dialect would
unlock, so setting the field would only add that warning. Leave it out.

## Related

- [Find your way around the Console](../zensical/user-guide/console.md)
- [Console API](../zensical/reference/console-api.md)
- [Writing and building the docs](documentation.md)
- [Repository map and contributor entry point](../../DEVELOPMENT.md)
