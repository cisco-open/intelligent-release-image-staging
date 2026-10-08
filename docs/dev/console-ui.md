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

`server/console-ui/` renders the header, primary navigation, Settings section
navigation, simple Policies overview, full Overview dashboard, Images, Monitoring
and Inventory's table, filters, selection, Add Device and credential forms,
image and bulk credential dialogs, CSV and basic device actions, schedules,
device-details and Activity drawers
with React.
Other operational views and working forms still render from
`server/webroot/app.js`. This is a partial migration, not a full rewrite.

The React entry point mounts before the older application loads. The controller
publishes `iris:shell-state` and listens for React's `iris:logout` action.
Overview uses `iris:overview-state` for rendering and `iris:overview-action`
for attention-card navigation. The controller keeps authenticated requests,
shared device-status calculations and the single visible-view refresh timer;
it never writes into React-owned subtrees. Request generation checks prevent
older responses from replacing newer state.
Settings pages keep their existing
`#settings/<section>` routes, so a link into a specific Settings section
still lands there. Settings itself keeps one navigation-rail link and its own
in-page section bar.

Images owns its catalog, upload and import jobs, and quarantine drawer in
`images-controller.mjs` and `images.jsx`. The `iris:images-command` adapter
supplies the shared authenticated transport and routes refreshes from the
existing timer. Each publish job runs independently. Responses from an older
catalog request or a closed drawer cannot replace newer state. The adapter
keeps CSRF tokens inside transport functions, including the upload XHR.

Monitoring owns both audit and deployment-log queries through
`monitoring-controller.mjs`. Its shared timeline renders bars and selections
in React, freezes coordinates during a drag and cancels stale reads when filters
change. Polling leaves expanded audit pages intact; local deployment-log filters
work over the newest 200 results. The `iris:monitoring-command` adapter supplies
authenticated reads and the existing visible-view timer.

Inventory's table uses `inventory-controller.mjs`, `inventory-model.mjs` and
`inventory.jsx`. React owns filter debounce, paging, selection and row edits.
Three mount roots keep the existing inline forms between the controls and the
table. The `irisInventory` adapter supplies authenticated transport and lets
the remaining dialogs read selected IDs and register actions; it never writes
into those roots. All response bodies are checked before one current-generation
snapshot is published. Hidden views cancel reads, and keyed rows keep keyboard
focus during refreshes. Row locks cover assignments, credentials, agent-install
choices and quarantine; an unknown write result is never retried.

Inventory's device-details workflow uses `device-details-controller.mjs` and
`device-details.jsx`. The `iris:device-details-command` adapter supplies shared
status calculations and authenticated transport. Record and log reads run
independently; closing or reopening the drawer invalidates old responses, even
for the same device. Confirmed host-key writes keep a per-device lock until the
request ends and are never automatically retried.

Activity owns job submissions, listing, cancellation and log streams in
`activity-controller.mjs` and `activity.jsx`. The `iris:activity-command`
adapter supplies authenticated transport and the existing option snapshot.
Active jobs refresh every two seconds while Inventory is visible. Hiding the
view pauses reads and closes streams; closing the drawer leaves jobs running.
Log callbacks are tied to their stream instance. Each of the six cached logs
keeps up to 500 lines with a separate character limit. Cancellation names the displayed
queued IDs, and per-job write locks survive closing and reopening. An unknown
write result is reported without retrying. The Policies role-definition
editor still uses the older controller.

The Add Device and credential forms use `device-forms-controller.mjs`, a shared
model and `device-forms.jsx`. Model lookups only narrow the chosen management
type's install options. Credential list reads share ordering tickets with
Inventory, so older panel or poll responses cannot restore outdated choices.
Writes hold their lock through close and reopen. Failed reads keep the last
list as unavailable, and unknown writes are reported without replaying them.
Closing the credential panel, leaving Inventory or hiding the tab clears entered
secrets. Inventory polling preserves form fields and keyboard focus.

Image and bulk credential dialogs use `assignments-controller.mjs`,
`assignments-model.mjs` and `assignments.jsx`. Opening captures the reviewed
device IDs; later selection changes cannot add targets to Apply. Image review
checks fresh device pages and reads the catalog with ordering tickets shared
with Inventory. Each write includes its captured assignment precondition.
Up to four requests run together, with checked per-device outcomes. Conflicts
or unknown results require an explicit review, never an automatic resend.
Bulk credentials use one checked request and distinguish a named profile from
clearing the assignment. Row and bulk locks survive closing the dialog;
closing stops preview reads but leaves submitted writes running.

CSV import/export, Onboard/Undeploy options, Adopt and Delete use
`inventory-actions-controller.mjs`, its model and `inventory-actions.jsx`.
Job dialogs capture reviewed IDs; Start snapshots the options and hands the
batch to Activity. CSV imports share the device mutation lock. Separate status
lines survive Inventory polling. Downloads check the content type and reject
late bodies after navigation. Adopt/Delete run at most four requests together,
check response bodies and report partial cleanup or unknown results. Only
confirmed complete retirements are removed from the selection.

Schedules use `schedules-controller.mjs`, its model and `schedules.jsx` for the
list, bounded latest-history reads, creation and ownership reaffirmation. The
dialog captures IDs and filters at opening. Shared read tickets order panel
and Inventory results, including reads started during a write. Schedule slots
come from the server; the browser does not recalculate recurring dates.
Writes use the shared device mutation lock and checked results. Reaffirmation
keeps the displayed ETag. Unknown creation requires an explicit list refresh
before another submission. Hidden views stop reads, not submitted writes.

Inventory Set role and bulk quarantine use `role-actions-controller.mjs`, its
model and `role-actions.jsx`. Role targets are captured at opening, and commit
uses the original preview revision and token. Checked accounting distinguishes
complete, partial, refused and unknown results. A successful explicit policy
refresh is required before retrying an uncertain commit. The shared device lock
survives preview review and pending cancellation. Quarantine advances its own
revision serially; only a confirmed conflict gets one reread and retry. Unknown
outcomes stop the remaining devices. The separate Policies definition editor,
imports and diagnostics remain in the older controller.

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

CI also runs browser checks in Chromium against mocked APIs, using a pinned
Playwright dependency. To run the same checks locally, install
Chromium once and then run the browser test script from
`server/console-ui/`:

```bash
npx --no-install playwright install chromium
npm run test:browser
```

None of these checks contact a live server or a live device.
Images checks exercise CSRF-protected writes, typed overrides, refused deletes,
simultaneous uploads and imports, session expiry, keyboard focus and strict CSP.
Monitoring checks cover time bounds, pointer cancellation, keyboard selection,
older pages, local filters, file-response races and plain-text event/log content.
Device-details checks cover XR/XE records, per-image status, confirmed host-key
writes, same-device reopen races, plain-text logs, keyboard focus and mobile use.
Activity checks cover scoped cancellation, aborts, batch option snapshots,
unknown write results, hidden views, independent streams and bounded output.
Inventory selection checks use 1,001 fixture devices to cover complete page
reads, revision changes, retained selections, off-filter counts and cancellation
of stale reads. Select all checks a consistent fleet revision, page totals,
offsets and unique IDs before adding them to the explicit selection. It does
not retain all-matches coverage after a newer partial-page read.
Table checks also cover delayed response bodies, unavailable credentials and
policy, row-write locks, revision preconditions, server-clock TLS freshness,
unknown write results, hidden-view reads and keyboard focus across polling.
Form checks cover every management type's wire fields, model lookup races,
credential read ordering, refused saves and deletes, close/reopen locks,
secret clearing and the absence of secret text in error messages.
Assignment checks cover captured targets, complete previews, shared catalog
read ordering, ordered image sets, quarantine and the ten-image limit,
confirmation, conflicts, unknown responses and pending-write focus.
`server/tests/test_assignment_client_api.py` runs the shipped controller against
a temporary authenticated management server for assignment conflicts and partial
credential updates. This fixture uses HTTP and no live devices; it does not
qualify the Console proxy or TLS.
Inventory action checks cover default and captured job options through Activity,
shared import locks, CSV file and response failures, download cancellation,
partial retirement, retained selections and unknown writes.
`server/tests/test_inventory_actions_api.py` uses the shipped controller with
real temporary stores to check CSV import/export and HTTP 207 retirement.
It deliberately fails record cleanup to verify the remaining work is reported.
Schedule tests cover target snapshots, form defaults, read races, bounded
history, unavailable evidence, revision conflicts and uncertain writes.
`server/tests/test_schedules_client_api.py` exercises the shipped controller
against real temporary stores for creation, history, stale ETags and ownership
transfer. No runner or live device is started by that test.
Role-action tests cover captured targets, preview effects, original revision
and token, partial accounting, drift, cancellation and unknown replies.
`server/tests/test_role_actions_client_api.py` checks the shipped controller
against temporary authenticated stores for aggregate partial results, cleared
membership, stale preview refusal and serial quarantine conflict recovery.
Browser tests also check focus, named confirmation, mobile layout and plain-text
failure messages. These fixtures do not qualify live enforcement or TLS.
`server/tests/test_device_forms_api.py` also runs the shipped serializers through
temporary Console and management servers for all five management types. It
checks sessions, CSRF, saved fields and public credential responses. The Console
verifies management HTTPS with the fixture CA; its local browser hop uses HTTP.

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
