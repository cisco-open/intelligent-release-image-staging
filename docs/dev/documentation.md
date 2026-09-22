<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Writing the IRIS documentation

This page is for anyone who edits the manual under `docs/zensical/`. It holds
the writing standard the pages are held to, the heading ids that must survive
a rename, how to retire a page without breaking a link, the tool versions the
site is built with, and what the documentation tests check.

The manual is the user site: Zensical builds it and CI publishes it. This
folder, `docs/dev/`, is contributor material. It sits outside `docs_dir`, so
it is never built and never published.

## Writing standard

**Who each guide is for.** Installation Guide: a network engineer with a fresh
host who has never seen IRIS; they follow it top to bottom once. Administration
Guide: the person maintaining server state, upgrades, credentials, and recovery.
User Guide: the
person who runs IRIS every day; they arrive with a task and leave when it is
done. Architecture Guide: an architect or reviewer who needs to know how it
works and what it does not do before they approve it. Reference: anyone looking
up one value, route, file format or term.

**Voice.** Plain English. Second person, present tense, active voice: "Start
the server", not "The server is started by the operator". Write "you". Use
"operator" only to contrast with another person: a device administrator, a
contributor, a Cisco engineer. Say what a thing is before you name it: "the
file that lists your devices, the inventory CSV", then "the inventory CSV". One
idea per sentence. Aim for sentences under 25 words and never over 35;
paragraphs under six sentences. No exclamation marks. Do not sound like a
machine: no hollow openers ("It is important to note that"), no hedging
padding, no summaries that repeat the heading.

**Spelling.** American: initialize, synchronization, authorized, organize,
behavior, favor. Alias ids keep whatever spelling they had.

**Acronyms.** Expand an acronym on first use on each page unless it is everyday
network vocabulary (VLAN, VRF, NAT, ACL, SCP, NTP, TLS, CA, SSH, HTTPS). PAE,
KDF, KRL, i63 and LKG never appear on a user page; the glossary carries LKG
only.

**Hyphens.** At most one hyphenated modifier before a noun in a heading or a
first sentence. Prefer a clause: "certificates that are tied to one address",
"the status shows counts, not device names", "rate limits apply per process,
not across replicas".

**Words to avoid, and what to write instead.**

| Avoid | Write |
| --- | --- |
| robust, resilient | say what it survives: "keeps seeding after a restart" |
| seamless, seamlessly | delete it, or "without a restart" |
| leverage, utilize | use |
| comprehensive | complete, full, or delete |
| delve, dive into | explain, look at |
| streamline | shorten, simplify |
| powerful, simply, easily, just | delete |
| ensure | make sure, check |
| functionality | feature, or say what it does |
| via | through, over, with |
| prior to, subsequently | before, then |
| in order to | to |
| mgmt | management |
| canonical | "the one place this is written", "the only copy" |
| custody | do not use; write "who holds the private keys" |
| tier | "the server container", "the Console container" |
| break-glass | "when you are locked out", "when both keys are lost" |
| posture | say what happens: "what happens when the file is missing" |
| PoC, lab, alpha, Phase 0/1, F3, Task N, Issue #N, ticket ids, lab hostnames, dates of lab runs | delete on the site; CHANGELOG or `docs/dev/` if the fact must survive |
| an em-dash | a comma, a colon, or a new sentence |
| "see here", "as described above", "click here" | the target's title: "see Rotate credentials and certificates" |
| "the admonition", "the callout", "the note box" | "the warning under Start the server", or repeat the one sentence |

Product names, consistently: Console (capital C), Guest Shell, IOx, IOS-XR
appmgr, the server, the device agent, the tracker, the seeder, the artifact
server, the catalog, management type, Bulk Hash (as Cisco writes it).

**Terms that need a plain lead-in on every page that uses them.** The first use
on a page gets the wording below, or a link to the glossary entry that carries
it. Define a term in the glossary and at most one page per guide; elsewhere,
link to its definition.

| Term | Approved wording |
| --- | --- |
| staging, to stage | Staging means copying an image to the device's flash and checking its hash, then stopping. The device keeps running its current software until you install the image yourself. |
| instruction | the signed message the server sends a device saying which images to stage and how |
| envelope | the encrypted file that carries an instruction |
| tick | one pass of the agent's check-in loop |
| LKG | the last policy the device accepted (last known good) |
| keyed state | the files the server keeps per device, under that device's id |
| mutual origin | two devices that both hold a full copy of the same image |
| quarantine (image) | an image that failed the Cisco hash check and is held back from devices |
| quarantine (device) | a device told to stop sharing with every peer |
| principal | who a request is from: a device, the server's seeder, or a legacy device |
| peer policy, sharing policy | the rules that say which devices may share pieces with which |
| role | a named group of devices that share with each other |
| management type | how the agent reaches the network: on its own address, on your management VLAN, or through the router |
| wave | a group of devices a schedule releases together |
| scheduled outcome | the record of what a scheduled run did on one device (the API calls it a receipt) |
| origin seeder | the server's own copy of the image, the first source in the swarm |
| park | keep an unassigned image on the device in case it is assigned again |
| verifier_missing | the device would check the signature but the tool to do so is not installed |
| Bulk Hash | the checksum Cisco publishes for an image |
| root key, signing root | one of the two offline keys that sign every instruction key |

The glossary line for "scheduled outcome" is the only place a user page writes
"receipt" outside an API route or field name; every such line needs a narrow
entry in `server/tests/test_terminology.py` `ALLOWLIST`.

**Titles and headings.** Titles say what the reader gets, in sentence case. A
procedure page starts with a verb ("Install on one Docker host", "Rotate
credentials and certificates"). An explanation or lookup page is a noun phrase
("Network ports and flows", "Helper commands"). Never a bare product word
("Server", "Operations"). Tab labels are the guide names, in Title Case because
they are names, like a book title; every other heading is sentence case.
Per-layout variants use the fixed H3 names "On one Docker host", "On separate
Docker hosts", "On Kubernetes"; per-platform variants use "Guest Shell", "IOx",
"IOS-XR", except on `install/device-packages.md`, which keeps its five
test-pinned H3s verbatim.

Three rules decide whether a heading may change:

- A heading that something outside the docs links to keeps its anchor id
  through an alias (see Heading aliases below) and may change its text.
- A heading that only `server/tests/test_docs_map.py` names changes its text
  and the test string in the same pull request.
- A heading that a test slices to execute or parse the text under it keeps its
  text. This is the only true no-rename list, repeated under "Headings that
  must not be renamed" below: "Reading the status"; "Build the packages" and
  its five H3s "Publish to either Docker layout", "Publish to Kubernetes",
  "Docker on one host", "Docker on separate hosts", "Kubernetes"; "Start the
  server host"; "Peer-to-peer evidence"; "Assignment to confirmed seeding";
  the five environment-variable H3s "Required at deploy time", "Optional at
  deploy time", "Container paths", "Image path variables", "Telemetry
  variables"; every `## <code>` on `problems.md`.

**Page templates.**

- Install page: one or two sentences (who it is for, what they will have at the
  end); "Skip this page if ..." when the page is optional; "Before you start";
  the steps as numbered H2s or a numbered list, one command per step with the
  expected result after it; "Verify"; "Next steps" (at most five links; on the
  platform pages the first link is "Stage your first image").
- User Guide task page: what this is for; "In the Console"; "With the API" (if
  any, one or two routes with a link to the Reference); "What you see"; the
  edge cases; "Related" (at most five links).
- Architecture page: a one-paragraph summary; a diagram where a picture shows
  the mechanism; the sections; "Limits"; "Related".
- Reference page: one sentence of intro; tables; each item links the task that
  uses it. Procedures never live in Reference; `user-guide/automation.md` is
  where the API is shown as a procedure.
- Landing page (`index.md` of a guide): what the guide covers, the order to
  read it in (the Installation Guide gives a reading list per layout and
  platform), a common-tasks table where the guide has tasks, and every page in
  the section with one line of scope. At most 60 lines.

**The stage-only rule.** The Overview carries the staging definition and the
"Stage only" warning. Do not repeat this general disclaimer on guide landing
pages or individual pages, including contributor docs. Keep task-specific safety
instructions where they affect the operation being described.

**Version numbers and measurements.** No product version numbers in prose; the
CHANGELOG owns release history. Pinned tool versions (aria2c, ioxclient,
Swagger UI, mermaid, Zensical) live in one table in `docs/dev/documentation.md`
and in `requirements-docs.txt`. Lab measurements (sampling percentages, seconds,
MB/s, requests per second) live only in `docs/dev/validation-records.md`;
`architecture/limitations.md` states the method and the limit in words and
links there. Dated records never appear on the site.

**Code blocks and tables.** Commands are `bash` fences with no prompt
characters and no comments longer than the command; every block parses with
`bash -n` (two tests enforce this on the install pages); placeholders in angle
brackets; paths relative to the checkout; when there is more than one host, say
which one the command runs on ("On the server host:"). Two blocks are executed
by tests and must stay byte-identical: the clone block (`IRIS_DIR=...`) and the
detached aarch64 build block (`setsid nohup ./build.sh aarch64`). Tables for
three or more like items and for every lookup; tables never hold procedures;
symptom tables use the columns Symptom, Likely cause, What to do. Note boxes:
`note`, `warning`, `danger` only. Content tabs only for short command variants
on pages that no test slices by heading. Mermaid for diagrams, with plain
labels. Every page starts with the SPDX header comment. Pages stay at 300
lines or fewer, and landing pages at 60 or fewer. Split by moment of use (set
up once versus use every day), never by component.

**Links.** One fact, one home. When another page needs the fact, write one
sentence and link with the target's title as the link text. Cross-guide links
are relative paths so they work on GitHub and on the site. A link to an aliased
heading uses the alias id (the natural slug does not exist). Never introduce a
code-level name (ETag, i63, KRL, outbox) on any guide page without a plain
sentence first.

## Heading aliases

A heading id is a link target. When something outside `docs/zensical` links to
one, the heading may change its text only if it keeps the old id, with an
`attr_list` attribute:

```markdown
## Build the packages { #build-and-publish-the-arm64-iox-package }
```

Zensical then emits `<h2 id="build-and-publish-the-arm64-iox-package">`. The
alias becomes the heading's only id: the natural slug of the new text does not
exist, so links inside the manual have to use the alias id as well. Add a row
here for every pair you create.

The table below records the retained aliases for the reorganization.

| Alias id | Page and new heading text | Who depends on the id |
| --- | --- | --- |
| `build-and-publish-the-arm64-iox-package` | `install/device-packages.md` "Build the packages" | `test_aiagent_arm_package_docs.py`, in-docs links from two install pages. |
| `embedded-agent-packages` | `install/device-packages.md` "When to rebuild the packages" | `help-server.html:118` (shipped in images). |
| `initialise-instruction-custody` | `install/activate-signing.md` "Start signing instructions" | `test_aiagent_arm_package_docs.py`; in-docs links. The id keeps the old spelling; the text is American. |
| `instruction-root-ceremony-and-recovery` | `admin-guide/instruction-keys.md` "Replace the two root keys"; the pointer section on `admin-guide/recovery.md` | `tools/start-compose-server.sh`, `kubernetes/README.md:426`, older script copies, CHANGELOG. |
| `f3-offline-bootstrap-envelope-redelivery` | `admin-guide/instruction-keys.md` "Deliver the first instruction file by hand" | Four in-docs pages, CHANGELOG. |
| `device-administrator-trust-boundary` | `architecture/security-model.md` "What a device administrator can still change" | The literal link `test_docs_map.py` pins on `architecture/data-path.md`. |
| `device-global-package-verification` | `install/iox.md` "Signature verification is a device-wide setting" | `device/iox/README.md:148-149`, six in-docs pages. |
| `unassigned-image-park` | `user-guide/assignments.md` "What happens to an image you unassign" | `fleet/assignments.csv.example:15`, six in-docs pages. |
| `recover-a-volume-whose-private-modes-were-changed` | `admin-guide/recovery.md` "Repair a volume whose file permissions were changed" | `kubernetes/README.md:352`. |
| `rollback-after-the-shard-migration` | `admin-guide/recovery.md` "Roll back the per-device state split" | Guard files written by older `keyed_state.py` builds, CHANGELOG (two links). |
| `crash-safe-same-name-replacement` | `architecture/data-path.md` "How the agent replaces an image without deleting it first" | `device/iox/README.md:193`, two in-docs pages. |

Two test helpers already understand the attribute. `_section()` in
`server/tests/test_docs_map.py` accepts an optional trailing `{ #id }` on the
heading line, and `RECIPE` in `server/tests/test_aiagent_arm_package_docs.py`
splits on either the old or the new heading.

## Headings that must not be renamed

A test slices each of these sections and executes or parses the text under it,
so the heading text is itself the contract. There is no alias that saves a
rename here:

- "Reading the status".
- "Build the packages" and its five H3s: "Publish to either Docker layout",
  "Publish to Kubernetes", "Docker on one host", "Docker on separate hosts",
  "Kubernetes".
- "Start the server host".
- "Peer-to-peer evidence".
- "Assignment to confirmed seeding".
- The five environment-variable H3s: "Required at deploy time", "Optional at
  deploy time", "Container paths", "Image path variables", "Telemetry
  variables".
- Every `## <code>` heading on `problems.md`.

Every other heading may change its text. If something outside the manual links
to it, give it an alias; if only `server/tests/test_docs_map.py` names it,
change the test string in the same pull request.

## Redirect stubs

A page that moves leaves a stub behind at its old path, so a saved link, or a
link inside a container image that shipped months ago, still reaches the new
page. A stub is a Markdown file holding front matter and nothing else:

```markdown
---
template: redirect.html
location: ../install/one-docker-host/
---
```

The template at `docs/overrides/redirect.html` renders a `<noscript>` meta
refresh and a script that replaces the location, keeping any `?query` and
`#hash` the reader arrived with. A stub can use an `anchors` map when a retained
section moved to a different destination page, as in `aiagent.md`. Each key is
an old fragment without `#`; its value is the new relative page and fragment.
The default `location` remains the fallback for other fragments and readers
without JavaScript. Stubs stay out of the navigation and search.

Three things to get right:

- `location` is copied through untouched. Write it relative to the OLD page's
  output directory, which is `old-name/index.html`, so a sibling page is
  `../new-name/`. Material that leaves the site takes a full URL.
- A hash reaches a section only when the target page carries that id, as kept
  text or as an alias. Use an `anchors` entry if the section moved to another
  page. Unknown fragments use the default page.
- A stub only redirects in a browser. A README on GitHub that links the `.md`
  path shows the front matter instead, so re-point those links in the same
  pull request.

`test_redirect_stubs_resolve_to_existing_pages` checks every stub: the target
resolves to a page that exists, the stub is absent from the nav, `location`
carries no hash, and the file has no body.

## Pinned tool versions

A local build has to match the published one, so these are pinned exactly.
Change any of them deliberately, on its own:

| Pin | Where | Value |
| --- | --- | --- |
| Zensical | `requirements-docs.txt` | `zensical==0.0.51` |
| OpenTelemetry Collector Contrib | `docs/zensical/user-guide/splunk.md` (collector image tag) | `0.160.0` |
| Python | `.github/workflows/docs.yml` (`actions/setup-python`) | `3.12` |
| Mermaid | `docs/zensical/javascripts/mermaid.mjs` | `11.17.2`, with its Subresource Integrity digest |
| Swagger UI | `docs/zensical/swagger/SOURCE.txt`, `tools/vendor-swagger-ui.sh` | `swagger-ui-dist` 5.32.15, with both archive checksums |
| aria2c | `tools/aria2c.sha256` | aria2-next 2.5.6, x86_64 and aarch64 digests |
| ioxclient | `tools/ioxclient.sha256` | `1.18.0.0` |

## Build and preview the site

```bash
python3 -m venv /tmp/iris-docs-venv
/tmp/iris-docs-venv/bin/pip install -r requirements-docs.txt
/tmp/iris-docs-venv/bin/zensical serve
```

`zensical serve` reloads on save. It is how you read a changed guide in order,
in a browser, before you push. Then build it the way CI does:

```bash
/tmp/iris-docs-venv/bin/zensical build --clean --strict
```

It has to report `No issues found`. In strict mode a broken in-page link, or a
`#anchor` with no matching heading, fails the build instead of shipping.
Zensical does not validate nav entries, so a nav target naming a file that
does not exist stays silent here; `test_every_nav_page_exists` catches that
one.

`.github/workflows/docs.yml` runs the same build on a push to `main` that
touches `docs/**`, `requirements-docs.txt` or `zensical.toml`. It publishes
the dependency-free website (`docs/index.html`, `docs/app.js`,
`docs/styles.css`) at the root of the `gh-pages` branch and the generated
manual under `/docs/`. Both `site/` and `deploy/` are build output: they are
git-ignored, and editing them by hand changes nothing. `docs/dev/` is outside
`docs_dir`, so it reaches neither.

The Console's Help menu links two bundled guides that are not part of the
manual: `server/webroot/help-device.html` and `server/webroot/help-server.html`.
Update the matching one whenever you change a troubleshooting or workflow
step on the corresponding manual page. Both ship inside the Console image, so
an update needs a Console image rebuild before a running deployment serves
it.

## Regenerate the OpenAPI contract

The contract comes from `server/api_routes.py` and `server/openapi_contract.py`.
After changing a route, regenerate the document and validate it:

```bash
python3 server/openapi_contract.py > docs/zensical/openapi.yaml
python3 -m pytest server/tests/test_openapi_contract.py server/tests/test_openapi_validation.py -q
```

Those two suites check the document itself, its request and response schemas,
and the runtime route inventory. The validator's schemas ship with the test
dependency, so validation needs no network access.

## How the docs tests work

Three suites guard the documentation. Run them with the rest of the server
tests:

```bash
python3 -m pytest server/tests/test_docs_map.py \
  server/tests/test_public_docs_contract.py \
  server/tests/test_terminology.py -q
```

`server/tests/test_docs_map.py` is both the structural gate and the contract
gate:

- The orphan gate. `_docs_pages()` walks `docs/zensical` recursively, so a
  page at any depth must have a nav entry in `zensical.toml`. A page in a new
  folder fails this test until the nav names it.
- Redirect stubs. `_is_redirect_stub()` recognizes a stub by its front matter
  and `_docs_pages()` leaves stubs out, so a stub needs no nav entry;
  `test_redirect_stubs_resolve_to_existing_pages` then checks each one.
- The writing rules. `test_docs_pages_follow_the_writing_rules` reads every
  page with its fenced code blocks stripped and refuses project labels,
  tracker issue numbers, private or lab addresses, em-dashes and the filler
  words listed above, plus any page over 300 lines and any landing page over
  60 lines. Matching is case sensitive and on word boundaries, which
  keeps "alphabetical" and the alias id
  `f3-offline-bootstrap-envelope-redelivery` legal. There is no exempt set of
  pages: every page `_docs_pages()` returns is checked, which is every real
  page under `docs/zensical` except the redirect stubs the bullet above
  already excludes.
- Page collisions. `test_no_page_collides_with_a_folder_index` catches a
  `name.md` sitting beside a `name/index.md`: both build to the same URL and
  one of them is dropped silently.
- Section landing pages. `test_section_landing_pages_link_every_page` requires
  a guide's `index.md` to link every other page in its nav section.
- `PAGE_MAP` maps an old file name to its new path. `_page()` reads through
  it, so a contract test written against the old file keeps working after the
  page moves, and the dict records where each page went.
- The contract assertions, which are most of the file. Each one pins the
  sentence an operator would act on during an incident, so rewording a
  guarantee into something false fails here rather than shipping.

`server/tests/test_public_docs_contract.py` guards the public website under
`docs/`: the dependency-free HTML, CSS and JavaScript, not the manual.

`server/tests/test_terminology.py` is the vocabulary guard. It scans every
tracked file for retired words and fails on a new use. When a word is really
required, an API field named in a reference table for example, add a narrow
entry to its `ALLOWLIST`, `TERM_FILE_ALLOWLIST` or `TERM_SCOPE_ALLOWLIST`
with the reason, rather than widening the pattern. This page has one of those
entries itself, for the two lines in the term table above that quote a
schedule API field name the manual otherwise avoids.
