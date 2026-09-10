# Changelog

All notable changes to **intelligent-release-image-staging (IRIS)** are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses **Calendar Versioning (CalVer)**: `YYYY.0M.0D` with an optional
`.MICRO` counter for multiple releases on the same day (e.g. `2026.06.11`, then
`2026.06.11.1`). A release tag is `v` plus the exact value in `VERSION`, including
any `.MICRO` suffix. The current version is in the top-level `VERSION` file.

## [Unreleased]

### Added
- Make `tools/start-compose-server.sh` the complete first start. It lists every
  handed-in input a fresh clone is missing — `bin/aria2c`, `ioxclient`, the
  per-architecture `aria2c` deliverables, and the two instruction-root public
  keys — in one report before building anything, installs the public roots
  from `IRIS_INSTRUCTION_ROOTS_DIR` into the config volume so the server
  self-provisions a trust-bound Guest Shell bundle on first start, and builds
  the XR RPM alongside both IOx packages (`IRIS_SKIP_XR=1` to omit). It never
  creates roots; those come from the custody ceremony (issue #204).

### Fixed
- Grant the runtime uid the `artifacts/` directory during the Compose bring-up,
  or refuse with the exact `chown`. An artifacts directory the server cannot
  write let it start, report healthy, and then silently never stage
  `iris-catalog.pem` or provision the Guest Shell bundle — leaving the Console
  reporting every device package absent and unable to fix any of it
  (issue #204).
- Refuse the Compose bring-up with a named remedy when the handed-in `aria2c`
  is missing, instead of letting the image build fail with a BuildKit cache-key
  error. `tools/get-aria2c.sh` now also tells a wrong-architecture deliverable
  apart from a stale one; its fail-closed checksum behaviour is unchanged
  (issue #203).

## [2026.09.10]

### Fixed
- Keep concurrent scheduled assignment receipts bound to their prepared policy
  baseline, preserve that baseline as the replacement conflict check when an
  overlapping merge changes policy, and distinguish device registrations
  created within the same second before applying staged-image assignments.
- Reject unknown, nested, and server-owned fleet fields before any inventory or
  role-policy write; trusted model and OS observations use a bounded internal
  update path, while historical CSV imports remain compatible (issue #171).
- Make Console and CLI image assignment share one fleet-aware transaction and
  audit outcome. The CLI now merges ordered image sets by default, explicit
  `--replace` reports removals, and device retirement cannot race an assignment
  into orphaned catalog state (issues #163 and #172).
- Refuse incomplete legacy inventory before onboarding creates a job, mints a
  credential, or contacts a device; complete historical rows remain usable
  (issue #173).
- Keep each ordinary ACL assignment preserved through peer quarantine and
  release. Legacy rows whose ACL was already overwritten have unrecoverable
  assignment history, and older servers ignore independent quarantine during a
  downgrade.
- Verify the server’s Guest Shell aria2c checksum and architecture before
  publishing its bundle; failed provisioning remains visible in Device packages
  readiness even when an older bundle is retained (issue #178).
- Produce the ARM Guest Shell bundle with `tools/make-agent-bundle.sh --arch arm64 --aria2 PATH`, verifying the architecture and pinned checksum before packing (issue #179).
- Accept incoming peers whose BitTorrent handshake arrives together with
  protocol messages, preserving the buffered messages (issue #174).
- Enforce the per-torrent peer admission cap for stalled downloads and
  pending outbound connections in aria2c (issue #168).

### Security
- Validate seeder credentials before writing aria2 configuration or sending
  tracker headers. Reject malformed credentials without exposing their values.

### Reliability
- Describe the API with OpenAPI 3.2, including individual SSE events and raw
  binary bodies, and validate the contract and schemas during testing.
- Keep catalog and tracker credential lookup independent of fleet size with
  digest-keyed indexes and a constant-time check of the selected credential.
- Persist the previous management credential before replacing the current
  credential so a host crash preserves the Console's rotation overlap.
- Reject aliased management credential paths before rotation or retirement.
- Keep Console requests working when its token update reaches it before the
  server. Try the previous token only after a management-authentication
  rejection, and keep the accepted token through request forwarding.
- Parse the manual torrent helper's announce query and refuse missing or
  ambiguous credentials before creating a torrent.

### Deployment
- Run the Docker server and Console on separate hosts with independent Compose
  files, verified HTTPS, management credentials, and separate browser TLS.
- Report the Console's own URL and serving certificate in Settings. Certificate
  changes report whether the Console loaded them successfully.
- Use configured server paths when onboarding devices, and keep server log
  settings out of device installer options.

### Added
- Schedule stage-only maintenance windows. A schedule runs one of two verbs —
  `assign` or `onboard` — against a device **target**: the Devices filter,
  optionally narrowed by named devices, resolved at fire time or frozen at
  creation. One-time windows name an absolute instant; weekly windows resolve
  local time in an IANA zone and record whether the slot was `normal`, a
  daylight-saving `gap`, or a `fold`. Neither verb installs, activates,
  changes a boot variable, or reloads a device.
- Record durable per-device evidence for every scheduled window: an occurrence
  with the target it actually resolved, its `+N / -M` delta against the
  approved preview, and one outcome per device carrying a stable reason.
  Scheduled work is idempotent per occurrence and device, a restart resumes
  only its own records, and manual work wins a conflict rather than being
  overwritten.
- Gate deployment waves on the preceding window's corroborated staging counts,
  ordering core before distribution before access. The gate counts **missing**
  apart from **errored**, so one powered-off device is not reported as a
  failure and cannot hold a chain open forever; an unmet gate ends its
  occurrence `stalled` at its deadline carrying those counts. It is an
  operational signal about when work is admitted, not a security boundary.
- List schedules in the Console and create one from the Devices filter with
  **Schedule…**, at list-plus-action depth. Rows show the target, the
  server-computed next run, the latest run's delta and wave counts, and an
  orphaned creator with a re-affirm that rewrites `created_by` and bumps
  `rev`. A device row marks a pending schedule aimed at it, so a manual
  assignment is not made in ignorance of one.
- Add Phase 0 server-side peer roles with one declared role per device,
  in-memory virtual ACLs, explicit-ACL shadowing, lifecycle/migration tooling,
  fleet/CSV membership, strong-CAS API mutations, dry-run impact counts,
  candidate-bound confirmation, pair explanations, and effective-QoS
  provenance. The Console adds a declared-role column/filter, aggregate
  selection action, and a count-only policy disclosure.
- Apply role-aware tracker discovery, bounded candidate selection, per-record
  expiry, and configurable 10–300 second announce cadence plus `numwant`
  ceilings. Policy changes stop new peer introductions; they do not sever
  existing aria2 connections or erase retained peer addresses.
- Expose state-aware tracker QoS through the management API with scalar
  compatibility, explicit seeder/leecher cadence layers, and API-only
  `qos_state` configuration; tracker state remains outside device delivery.
- Apply origin-wide and per-torrent upload limits plus an origin peer cap, with
  count-only reconciliation status. Per-role origin
  shaping remains unavailable. Phase 1 adds verified device QoS below; the
  effective-QoS route retains its deprecated `pre-instructions` compatibility
  sentinel and adds the canonical `instruction` object used by Devices, with
  fleet rollups on the policy view. Device-side limits remain cooperative under a privileged administrator.
- Measure issue #153's prospective mutual-origin deny as a preflight count while
  retaining the existing applied origin blocklist. Shared NAT permit/deny
  conflicts stay unblocked and are reported by reason/count. The issue remains
  open through one full release of preflight observation; any later activation
  must separately review the union for all ACLs, including hand-written ACLs.
- Keep agent artifacts, enrollment, and token refresh structurally exempt from
  roles, QoS, cadence, and peer-selection budgets. The six-patch amd64/arm64
  aria2 binaries are now the pinned source inputs for future refreshed Guest
  Shell bundles and signed device packages; this does not cut a release, sign a
  package, or update a deployed device.

### Phase 1 instructions

- Deliver bounded per-device encrypted instruction envelopes and root-signed
  keylists over existing authenticated catalog HTTPS 8443. Verify signatures,
  MACs, audience, expiry and monotonic freshness before applying device QoS and
  peer controls; keep locally encrypted LKG through instruction-key rotations.
- Reassert verified/default QoS every mechanical tick and before new torrents;
  demote plaintext peer/concurrency launch values to upgrade compatibility.
  Signed logical catalog cadence remains separate from heartbeat/reassertion.
- Add server-only encrypted online signing custody, two distinct offline public
  roots, certificate/keylist windows and recovery runbooks. IOx/XR image trust
  depends on enforced native package signatures; Guest Shell remains
  tamper-evident, with runtime verifier probing and tracker-only fallback.
- Preserve owned IOx device-global verification state through unsigned package
  onboarding, interruption and uninstall; prefer signed wrappers without state
  mutation. Verify Guest Shell bundle SHA-256 sidecars and both public-root
  files, retaining the prior runnable bundle on refusal.
- Show server-observed and agent-asserted instruction evidence, exact accepted
  identity, policy-revision rollups, evidence age, drift, pointer skew, missing
  stamps and custody alarms in the Console/API. Unavailable evidence remains
  null/unknown; violation = 0 does not mean compliant.
- Document Compose, split-host and single-replica Kubernetes custody/network
  checks. Five supervised processes and existing ports remain; multi-replica
  server operation is unsupported. The next package build must propagate the
  final shared agent and current pinned aria2c binaries to every device format.
  This Unreleased work is not a signed release or live-device validation.
  Issue #153 stays preflight-only through a full tagged-release dwell and a
  separately authorized activation release with lab/live evidence.

## [2026.09.05]

### Documentation
- Update both Console troubleshooting guides, the homepage, API examples,
  and deployment docs for the shared device agent and separate server and
  Console. Correct network, verification, package rebuild, and recovery steps.
  Describe current behavior without historical installation or schema guidance.
- Add a Splunk setup reference with collector configuration, HTTPS ingestion,
  dashboard searches, and troubleshooting using deployment-neutral examples.

### Console
- Show pending assignments as **Waiting for staging**. Current image errors
  override older ready flags in device rows and rollout counts.
- Refresh open swarm details with the map. Keep torrent role and staging
  status separate, and avoid duplicating rates across images or participants
  that share an IP address.
- Keep the swarm details panel above the toolbar so its title and Close button
  stay visible on desktop and mobile.
- Shorten onboard and undeploy logs across Guest Shell, IOx, router and XR.
  Keep error details and remove the duplicate success footer.
- Let management type control Add Device network fields. Model edits, failed
  lookups and late responses no longer switch form modes. Model remains free
  text and limits installer choices when recognized.
- Align controls and grouped buttons in all nine operational forms, including
  when rows wrap. Put feedback on a separate row.

### Device status
- Report verification failures, catalog lookup failures and aria2 rejections
  on the current agent check. Other images can keep progressing.
- Clearing the last image assignment stops its torrent using the same cleanup
  rules as removing an image from a larger set.

### Security
- **Signed IOx packages cannot be rewritten by the legacy rebake helper
  (#135).** It refuses `package.sign` or `package.cert` in the outer or nested
  package envelopes before producing output, preserving the signed input.
  Source changes require a new build and signature.
- **Private tracker announces use HTTPS on TCP 6969.** The origin seeder,
  IOx/XR container, and Guest Shell aria2 launcher verify the pinned server
  certificate. TLS protects IOx/XR bearer headers and Guest Shell query
  credentials. Aria2 JSON-RPC uses HTTP on loopback and is not published.
- **The browser Console is now isolated from device, catalog, image, and
  credential state.** Compose and Kubernetes run it as a state-free service
  with no server data volume; its `/api/v1` gateway reaches the server's
  internal `/internal/v1` management API over CA-pinned HTTPS using a scoped,
  file-mounted current/previous credential. Missing or wrong tier credentials
  fail before route lookup or request-body buffering, while browser sessions,
  CSRF, `X-IRIS-Poll`, and private/no-store response handling remain enforced.
- **The split Console preserves the existing first-run administrator claim.**
  Before an administrator exists, `iris` / `irisisgreat!` mints a one-use,
  ten-minute setup grant rather than a session; creating the administrator
  permanently ends that special behavior. Because the first caller who can
  reach a fresh Console can claim it, keep the Console on a trusted network
  and complete setup immediately after deployment. The login page does not
  display the default credential; it remains in the operator documentation.
- **The unified IOx/XR agent no longer puts tracker credentials in announce
  URLs, and registered non-probe APIs authenticate before disclosing resource
  existence.** Aria2 supplies its resource-bound announce bearer as a request
  header from local configuration/RPC state rather than argv. Guest Shell
  retains its existing personalized query-token and TLS-protected
  artifact-capability compatibility. JSON API errors use a
  redacted RFC 9457 shape; tracker failures remain bencoded for BitTorrent
  compatibility.
- **`GET /v1/devices/<id>/policy` is now bound to the requesting device.**
  It was a shared route — any enrolled device's catalog token could read any
  other device's policy — and the response now carries a `plans` map with a
  server-minted `plan_id`/`transfer_id` per assigned image, so a device (or
  anyone holding one device's catalog token) could enumerate those ids for
  the whole fleet by walking `/v1/devices` then `/v1/devices/<id>/policy` for
  every id. The route joins heartbeat, token-refresh and telemetry in
  `_guard`'s device-bound set: a device can now read only its own assignment
  and its own plan ids.
- **The catalog and artifact server now fail closed to plaintext, matching
  the console.** Run directly (outside the shipped `docker-entrypoint.sh`,
  which always provisions `IRIS_CERT`) with no usable certificate, `catalog.py`
  and `artifact_server.py` used to silently serve plain HTTP — putting every
  device bearer token, and every capability-bearing enrollment file the
  artifact server serves, on the wire in clear text. Both now refuse to
  start in that state unless `IRIS_CATALOG_ALLOW_PLAINTEXT=1` /
  `IRIS_ARTIFACTS_ALLOW_PLAINTEXT=1` opts in explicitly — the same name
  pattern as the console's `IRIS_GUI_ALLOW_PLAINTEXT`.
- **`HEAD` requests against the artifact server now get the same
  symlink-containment and `staging/` permission checks as `GET`.** `HEAD`
  fell straight through to the stock handler and skipped both: a path
  escaping the artifacts root through a symlink, or a foreign-owned,
  loose-permission `staging/` credential file, answered 200 with headers
  (`Content-Length`, `Last-Modified`, `Content-Type`) for a target a `GET`
  would have refused with 404/403. No body ever crossed either way, but
  existence and metadata did.

### Added
- **Device packages now receive server trust at onboarding (#136).** The
  canonical OCI image, both IOx tars, and the XR RPM contain no deployment
  certificate. Console/API onboarding and the CLI installers deliver the
  current public certificate through IOx application data or the XR harddisk
  bind mount, so certificate rotation requires re-onboarding rather than
  rebuilding or modifying a signed package. Console/API and CLI readiness
  verify wrapper SHA-256 against adjacent provenance manifests and separately
  compare served and distributed certificates; they do not claim current-source
  freshness or native-signature verification.
  IOx copies the certificate after app activation mounts application storage
  and before app start; a failed copy leaves the app unstarted.
- **IOx and IOS-XR appmgr now package one canonical multi-architecture device
  image and run one entrypoint.** `IRIS_DEVICE_PLATFORM=iox|xr-appmgr` is the
  required selector and is persisted for restart/upgrade; missing or unknown
  values stop before filesystem writes. IOx retains live storage selection,
  SSH-to-self, and share/SCP placement, while XR retains its verified
  `harddisk:` bind mount and cannot configure the IOx SSH path. The common
  Alpine image keeps `ps`, `top`, `free`, and `kill` for field diagnosis.
- **The supported deployment topology now has independent server and Console
  services.** Compose and Kubernetes give them separate images, processes,
  health checks, resources, and network surfaces; only the server mounts the
  RWO data volume, and Kubernetes uses a private management Service plus
  NetworkPolicy and immutable image references.
- **Every registered API operation now has a checked-in OpenAPI 3.1 contract.** A
  bidirectional route/spec test catches undocumented implementations and stale
  specification entries; the human reference documents authentication,
  Problem Details, pagination, concurrency, idempotency, retry, and version
  retirement policy.
- **A routed device's SVI can now opt into IS-IS per device, not just
  fleet-wide.** `device/device-install.sh`'s `SVI_IGP=isis` env var (default
  `none`) was the only way to add `ip router isis` to the IRIS SVI, and being
  process-wide it was wrong the moment one server onboards devices into
  different fabrics — the SD-Access lab needed `SVI_IGP=isis` set for every
  device on the server, including ones on fabrics that do not run IS-IS. The
  fleet inventory (CSV column and console/API field, routed devices only)
  now carries an `svi_igp` override that flows through onboarding
  (`gui_fleet.validate_record` → the resolved deployment plan →
  `gui_onboard._build_env`) to that same env var; a device whose record
  leaves it blank still falls back to the server's `SVI_IGP` default,
  unchanged. Validated to the closed `none`/`isis` enum before it is ever
  interpolated into the device's config — the same command-injection
  defense every other value on that path gets. See [Management type →
  Routed](docs/zensical/management-type.md#routed-iris-managed-app-network).
- **Device-side logging is now opt-in, and off by default, to protect flash
  write endurance.** Every platform stages images to `flash:` /
  `bootflash:` / `sdflash:` / `harddisk:`, and flash has a finite number of
  write cycles; `aria2c`'s own log is chatty and continuous for the whole
  life of a transfer, and with `--seed-ratio=0.0` a staged device seeds
  forever, so a log left on never stopped growing. `IRIS_LOG` (default
  `off`, same name and `on`/`1`/`true`/`yes` parsing on Guest Shell, IOx and
  XR) now gates whether aria2c's launch line carries `--log=` at all — off
  is genuinely no recurring flash write, not a smaller file: with no
  `--log=`, aria2c's own daemon mode (Guest Shell) or the container
  supervisor's own stdio redirect (IOx, XR) already sends everything to
  `/dev/null`. Turning it on adds `--log-max-size=50M --log-max-files=1` on
  IOx/XR (neither ships `rotate-logs.sh`) and keeps the existing
  `rotate-logs.sh`/EEM cadence on Guest Shell. Error reporting is
  unaffected either way: IOS syslog / the XR container's
  `%IRIS-6-<MNEMONIC>` stdout and the heartbeat's `stage_error` field keep
  working with logging off. See [Device agents → Device-side logging (flash
  write
  endurance)](docs/zensical/device-agents.md#device-side-logging-flash-write-endurance).
- **`IRIS_LOG` (and `RPC_PORT`/`MAX_PEERS`) can now be set persistently on a
  Guest Shell device without editing the guest user's shell profile or
  reinstalling the agent.** `guestshell-start.sh` only reads its own live
  process environment on each 60s EEM tick, so nothing set outside that tick
  survived the next one, let alone a reload — on Guest Shell there was no
  way at all to turn on device-side aria2c logging that stuck. `bootstrap.sh`
  now reads `iris_log`, `rpc_port` and `max_peers` out of the same persisted,
  reboot-durable `iris-agent.conf` the RPC secret already round-trips
  through, validates each (digits in range for the two ports/counts,
  alphanumeric only for `iris_log`; an invalid value is dropped with a
  warning rather than exported, so aria2c's own built-in default applies),
  and exports them into `guestshell-start.sh`'s environment before every
  launch. An operator sets `iris_log = on` (or `rpc_port` / `max_peers`) in
  the device's `iris-agent.conf` and the next EEM tick picks it up — no
  redeploy. See [Device agents → Device-side logging (flash write
  endurance)](docs/zensical/device-agents.md#device-side-logging-flash-write-endurance).
- **The fleet and swarm console projections can be asked for a page.**
  `GET /api/v1/devices` accepts `limit` (1–1000, clamped), `offset` and `q` — a
  case-insensitive substring over the same four fields the console's own
  search box covers — and `GET /api/v1/swarm` accepts `limit`/`offset` over the
  participant list flattened across images. Paging is opt-in: with no
  parameters both routes return the complete projection they always have, and
  `/api/v1/swarm` still passes the hub's bytes through untouched. Every
  `/api/v1/devices` response now states `total` and the fleet-store `revision`
  behind the same read, so a caller can always tell a page from the fleet and
  can tell a coherent page walk from one that raced a fleet edit; a malformed
  or non-positive `limit`/`offset` is a 400 rather than a quietly different
  page. At 10,000 devices a 200-row page answers in 128 ms and 0.12 MiB
  against 280 ms and 5.99 MiB for the whole fleet, on the same host and run.
  See
  [Reference → Devices](docs/zensical/reference.md).
- **The Devices console now uses that paged projection instead of fetching
  the whole fleet on every 10-second poll.** Two prerequisites had to land
  first, because a truncated table an operator reads as the complete fleet
  is worse than a slow one: `GET /api/v1/devices` now accepts every one of the
  filter bar's six column filters — `management_type`, `platform`, `cred`,
  `telemetry`, `peer` and `status` (plus the existing `q`) — server-side,
  condition-for-condition the same as the console's own client-side
  derivation, so a page can never disagree with what the filter bar
  promises; and bulk-action selection is now tracked by device ID in a set
  that survives paging, filtering and the periodic poll, rather than
  scraped from whichever checkboxes happen to be rendered. The header
  checkbox now only ever selects the page on screen (its label says so); a
  new **Select all N matching devices** control performs a real walk of
  every remaining page under the active filter and states plainly once
  every matching device is selected, rather than ever silently meaning
  "this page." The table itself pages at 200 rows once a filter's match
  count exceeds that, with Previous/Next controls and a "Page X of Y"
  readout; `/api/v1/overview`'s attention rollup keeps fetching the whole,
  unfiltered fleet, since its aggregates are fleet-wide by definition. See
  [Console → Paging and selection at fleet scale](docs/zensical/console.md#paging-and-selection-at-fleet-scale).
- **The transfer-lifecycle store's bounds are now numbers an operator can
  read.** The durable plan store counts every row and record its two bounds
  (`MAX_PLANS`, a week of retention) cost, but nothing read those counters, so
  a fleet past the cap — or a collector outage long enough to age out
  unacknowledged records — looked exactly like a fleet that never seeded:
  lifecycle events for some transfers and silence for others, with nothing
  anywhere saying rows were being discarded. Eight flat, unlabelled figures now
  ride both metric surfaces on every sample pass, as
  `iris.transfer.lifecycle.*` OTLP points and `iris_transfer_lifecycle_*`
  Prometheus families on `:9101`: store occupancy against its cap, plans
  watched seeding with no matching report yet, the unacknowledged export
  backlog, and the four ways a row or a record can be lost. The block is
  omitted whole when the store is absent or unreadable rather than published as
  zeros — a missing store is not an empty one. Names and meanings are in
  [Observability → Metrics names](docs/zensical/observability.md#metrics-names-operator-contract).
- **Device agent ticks are now jittered and back off on failure, instead of
  every device polling on the exact same 60s clock.** A fleet installed or
  restarted together kept every device's tick in lockstep — Guest Shell's EEM
  timer fires on IOS's own fixed clock, and the IOx/XR container supervisors
  slept a flat `IRIS_TICK_SECONDS` — turning an ordinary tick into a
  fleet-wide burst of policy GETs, heartbeats and tracker re-announces.
  the common `device/container/entrypoint.sh` now dithers every
  ordinary tick by ±10% of the tick length (`IRIS_TICK_JITTER_PCT`), spread
  their first tick across the whole tick window once at startup
  (`IRIS_STARTUP_JITTER`), and back off exponentially, capped at
  `IRIS_TICK_BACKOFF_MAX` (default 600s), after the agent process fails
  outright — the same shape an unreachable or overloaded catalog produces.
  `device/bootstrap.sh` (Guest Shell and router) cannot move the EEM timer
  itself, so it sleeps a small bounded jitter (`IRIS_TICK_JITTER_MAX`,
  default 0-7s) before contacting the catalog each tick and, after a failed
  tick, skips catalog contact on a run of future ticks under the same
  exponential/capped backoff — local bundle/aria2c/log upkeep still runs
  every tick regardless. All defaults stay comfortably inside the catalog
  token's multi-day refresh slack, so a run of jittered or backed-off ticks
  never strands a device. See [Device agents → Cadence jitter and overload
  backoff](docs/zensical/device-agents.md#cadence-jitter-and-overload-backoff).
- **The console can now forget a device's stale SSH host key.** First
  contact correctly records a device's SSH host key into a persistent
  `known_hosts` (trust-on-first-use), but a device that is later re-imaged
  or replaced presents a new key and every session then fails with a
  changed-key error — with no way to clear the stale entry short of shell
  access to the state volume. `POST /api/v1/devices/<id>/forget-host-key`
  (console: the deployment-details drawer's **Forget host key** button)
  removes just that device's entry from the persistent `known_hosts`;
  `lab/iris-ssh-policy.sh` gained the underlying `iris_ssh_forget` function.
  It touches only the persistent accept-new file — never an
  `IRIS_SSH_HOST_KEY` pin or an operator-supplied `IRIS_SSH_KNOWN_HOSTS` —
  and the next session re-verifies and pins the device's new key rather than
  disabling verification. Always audited (`device_forget_host_key`, naming
  the device and the actor), success or failure. See
  [Operations → Forgetting a device's SSH host
  key](docs/zensical/operations.md#forgetting-a-devices-ssh-host-key).
- **`device/iox/build.sh`, `tools/build-xr-package.sh` and
  `tools/make-agent-bundle.sh` now warn — or, on request, refuse — when the
  checkout they run from is stale.** All three bake in `device/agent` (and
  their own `device/<platform>`/installer-script tree) exactly as it sits in
  whatever worktree the script happens to run from, with no check against
  `main`. A worktree left behind after `main` moved on then silently shipped
  an older agent, with nothing in the built image/package saying so —
  confirmed still live, and exactly how a stale candidate worktree corrupted
  a size comparison (three worktrees pinned at an older commit while the
  baseline moved on). All three now source the new
  `tools/agent-source-freshness.sh` and warn on stderr, naming the missing
  commits, whenever the checkout is behind `main`/`origin/main` under the
  relevant paths; `IRIS_REQUIRE_FRESH_AGENT=1` turns that into a hard build
  failure, and `IRIS_ALLOW_STALE_AGENT_ACK=1` builds anyway under that
  setting. Best-effort only — silent outside a git checkout or when no
  reference branch resolves, and never blocks a checkout already at or ahead
  of it. See [Development → Embedded agent
  packages](docs/zensical/development.md#embedded-agent-packages).
- **There is now a repeatable mixed-workload capacity harness, so the
  per-device scaling work above has something to catch a regression.**
  `server/tests/test_capacity_harness.py` seeds a synthetic fleet of N
  devices in its own temporary directory and drives a tracker announce, a
  catalog heartbeat, a device policy read, a terminal report, a credential
  resolution, and the console's own fleet projection — calling the real
  production functions (and, for the console, the real `gui_server` HTTP
  handler) against synthetic state, never a reimplementation of the logic
  under test — then reports how each operation's cost moves as the fleet
  grows. A fast pair of sizes (50/500 devices) runs by default with every
  test suite; the full 100/1,000/10,000-device progression this project's
  scale claims are stated at is slow by design and opt-in behind
  `IRIS_TEST_CAPACITY_LARGE=1`, the same convention as
  `IRIS_TEST_HOST_INTEGRATION=1`. Wall-clock numbers it prints are
  informational only — this is a shared, noisy host — and every assertion
  that actually runs checks deterministic counted work instead (which shard
  changed, rows per shard, credential-index builds, response bytes), in the
  style `server/tests/test_keyed_state_scaling.py` already uses. See
  [Validation → Capacity
  harness](docs/zensical/validation.md#capacity-harness) and `TESTING.md`.

### Fixed
- **Console image imports now run Cisco Bulk Hash verification before their
  jobs finish.** The import progress reports the verification phase and its
  resulting verified, mismatch/quarantined, not-in-feed, or unavailable
  verdict. Concurrent imports share one successful refresh only when its
  catalog snapshot covers every waiting image; an image registered after that
  snapshot takes a fresh pass, and a failed refresh is never reused.
- **Device package readiness remains available after first-run setup.** A
  persistent Settings → Device packages view re-checks both IOx tars and the
  IOS-XR RPM, and absent, stale, or unverifiable packages show complete host-side
  build commands. The Console still only inspects artifacts; it never receives
  a Docker socket.
- **The Console now calls the C8000V `router` installation recipe Guest Shell.**
  The wire value remains unchanged, but Agent install fields no longer confuse
  the runtime with the separately selected VirtualPortGroup management type.
- **Bulk image assignment warns only when the proposed result removes an
  existing assignment.** Selecting one common image for devices where some
  already have it and others do not is additive and no longer produces the
  misleading different-images warning.
- **Guest Shell can recover a verified C9300 image stranded by IOS's
  same-name rename behavior.** Before retrying final root placement, the agent
  attests an existing canonical `flash:` or `bootflash:` file by native IOS
  size and a bounded asynchronous SHA-512 check against the catalog, then
  adopts it only on an exact match, while reclaiming only the
  reserved IRIS `.iris-tmp` copy. Unknown or mismatched bytes remain untouched
  and fail closed. Ordinary placement retains its download SHA-256 and IOS
  byte-size checks; no install, activation, reload, or boot-variable change
  is performed.
- **The IOS-XR appmgr container log is now bounded and rotated instead of
  growing without limit.** IOS-XR has no syslog path for `emit()`'s
  `%IRIS-6-<MNEMONIC>` diagnostics — they go only to the container's own
  stdout, which appmgr captures — so `--log-driver=none` (considered and
  conditionally approved for the container, "as long as syslog messages for
  iris are not affected") was rejected for this platform: `none` would have
  discarded every one of those lines, including every pre-heartbeat startup
  failure, with no second channel. `device/xr-install.sh` now sets
  `--log-driver json-file --log-opt max-size=1m --log-opt max-file=3` on the
  appmgr activation instead, capping the previously-unbounded write at 3 MiB
  while retaining roughly 11 days of history at the agent's ~1-line/60s emit
  rate. Find the lines with `show appmgr application name iris logs` — they
  were never in `show logging` and still are not.
- **`IRIS_LOG` (the device-side `aria2c.log` opt-in, off by default) now
  actually reaches IOx and IOS-XR devices.** Neither `device/xr-install.sh`
  nor `device/iox/install.sh` passed it to the container, so an operator's
  opt-in silently resolved to each entrypoint's own default on exactly the
  two platforms that implement it. Both installers now forward it
  (`--env IRIS_LOG=…` in XR's `docker-run-opts`, `run-opts N "-e
  IRIS_LOG=…"` in IOx's app-hosting block), validated with the same
  quoting guard already applied to every other interpolated value on that
  activation line. The default stays off on every platform.
- **`ps`, `top`, `free` and `kill` stay in the device images.** A slimming pass
  had removed `procps`, on the reasoning that the aria2c supervisor owns its
  child by exact PID and never needs `pgrep`/`pkill` — true, but it also took
  away every process tool an operator has when an agent misbehaves on a switch
  they cannot easily reach, and `docker exec … ps` began failing with
  "executable file not found". Restored ahead of the signing freeze, after
  which nothing can be added back. Only the Debian IOx image was affected: the
  Alpine XR image already provides all four through busybox. Costs 313 KB on
  amd64 and 329 KB on arm64 in the delivered package.
- **`lab/device-run.sh` refuses the interactive install-subsystem commands.**
  `install remove inactive` and its siblings wait on a `[y/n]` prompt, and
  this transport feeds stdin ahead of the prompt: the answer lands nowhere,
  the session drops while the operation is still open, and the switch then
  refuses every later install operation until it is reloaded, with nothing in
  `show install log` to explain it. A lab Catalyst sat wedged that way for six
  days. The commands are now refused before the device is dialled, with a
  message naming the EEM-applet idiom that does work — the one IRIS's own
  reclaim path has always used. Read-only `show install ...` is unaffected,
  because diagnosing a wedged switch needs it.
- **The tracker, catalog, console, artifact server and metrics listeners now
  bound how many requests they handle at once.** `ThreadingHTTPServer` spawns
  one OS thread per accepted connection with no cap, so a burst of slow
  clients (or handlers blocked on a shared file lock) could accumulate
  arbitrarily many threads and their stacks — a different failure from the
  accept-backlog fix (`request_queue_size = 128`) already in place on the
  fleet-facing listeners. Each listener now admits at most
  `max_concurrent_requests` connections at a time (256 for the tracker,
  catalog, artifact server and console; 64 for the metrics listener); a
  burst beyond that degrades into queueing in the (already-enlarged) kernel
  backlog rather than unbounded thread growth. Admission itself times out
  (10s) rather than blocking forever, so a listener saturated by long-lived
  connections — the console's onboard-log SSE streams, most notably — cannot
  freeze the accept loop for every other client; see `server/bounded_pool.py`.
- **An expired announce credential is now a counted, operator-visible
  refusal, and `iris_legacy_announce_participants` no longer implies
  migration on its own.** A rotated-out seeder announce token past
  `IRIS_SEEDER_PREV_TTL` was refused with a token-free 403 and no counter
  anywhere, so a fleet that missed the personalisation window read
  identically to a fully migrated one: `iris_legacy_announce_participants`
  requires a credential to still authenticate to be counted at all. The
  tracker now counts every refused `/announce` or `/scrape` in
  `iris_tracker_announces_refused_total`, with a separate
  `iris_tracker_announces_refused_expired_total` bucket for a credential
  that was found and valid-shaped but simply timed out; the legacy-
  participants gauge's HELP text no longer asserts "0 = fully migrated" on
  its own. See [Observability → Reading
  iris_legacy_announce_participants](docs/zensical/observability.md#reading-iris_legacy_announce_participants).
- **The console now surfaces a frozen peer-policy reconciler instead of
  showing its last claim as current.** The tracker reconciler already
  records a degraded pass with its exception type and keeps retrying, but if
  even that write fails — or the tracker process itself is down —
  `peer-enforcement.json` simply stops changing, and a console reading only
  its last recorded `state` (possibly `enforced`) would show it as healthy
  indefinitely. `GET /api/v1/peer-policy` now derives `enforcement.stale` from
  how long it has been since `last_reconciled_at` (never, or more than five
  minutes), and the peer-policy badge shows `<state> (stale)` — regardless
  of what that state is — with the last-reconciled time and `last_error` in
  its tooltip.
- **A pull directive for a device that never returns is no longer stranded
  until the device is purged.** `pending_request()`'s per-device reap (see
  below) only clears the row it was asked about, so a device issued a
  console pull request and then never heartbeating or reporting again used
  to leave one expired row in `pull_requests.d/` indefinitely — bounded and
  harmless, but never reclaimed. `list_devices()` (the console's fleet
  table, already an O(fleet) read) now sweeps expired pull directives as
  part of that same pass, so no per-device path gains a fleet-wide scan.
- **A device's heartbeat, policy poll, terminal report and tracker announce no
  longer rewrite or re-index the whole fleet.** Each of those per-device
  operations held one lock on a whole-fleet JSON document — `devices.json`,
  `policy.json`, `pull_requests.json`, `telemetry.json`, `report_ledger.json`,
  `transfer-attestations.json`, `peer-endpoints.json` — while it re-parsed and
  re-serialised every device in it to touch one row, and every request also
  re-loaded the credential store and rebuilt a fleet-wide reverse index to
  resolve a single token. Cost grew with fleet size on exactly the operations
  a rollout repeats per device, and unrelated devices serialised behind one
  writer. All of that state is now **keyed**: one row per device (or
  principal) in a 256-shard directory (`devices.d/`, `policy.d/`, …), and the
  authorization index comes from one snapshot of the credential store that is
  rebuilt only when the store file itself changes. On this host, at 10,000
  devices, the median cost of one operation drops from 245.9 ms to 1.4 ms
  (tracker announce), 192.1 ms to 1.2 ms (heartbeat), 77.4 ms to 0.15 ms
  (policy GET), 641.7 ms to 3.4 ms (terminal report), and 58.5 ms to 0.004 ms
  (credential resolution, now flat in fleet size). Atomic writes, the
  fail-closed refusal to read or overwrite damaged state, and the retention of
  a quarantined or revoked device's endpoint row past its TTL are all
  unchanged; damage to one shard now costs only the devices in it rather than
  the fleet. Existing whole-fleet documents are migrated into shards on first
  use and left in place renamed `<name>.json.migrated` — no operator step. See
  [Reference → Keyed per-device
  state](docs/zensical/reference.md#keyed-per-device-state).
- **A rollback to a release from before the shard migration above no longer
  starts against a silently empty fleet.** Once a store is migrated, code
  from before it reads the now-absent `devices.json` (and the other six
  whole-fleet documents) as an empty store rather than an error — so a
  rollback would have shown no devices, no policy and no telemetry, with the
  real data intact but undiscoverable one rename away under
  `<name>.json.migrated`. Migration now leaves a deliberately-invalid
  placeholder at each retired legacy path instead of leaving nothing, so that
  same pre-migration code's existing fail-closed handling of a *corrupt*
  state file trips instead, and the placeholder names the exact `.migrated`
  file and command to restore it. See [Operations → Rollback after the shard
  migration](docs/zensical/operations.md#rollback-after-the-shard-migration)
  for the recovery procedure and what it does not restore (writes made by the
  new release since migration).
- **A fleet-wide credential or platform reassignment is no longer O(fleet²).**
  `FleetStore` (the operator inventory backing `fleet.json`) was the one
  per-device store the shard migration above missed: every `upsert()` still
  locked and rewrote the WHOLE fleet document, sitting directly beside
  operations that were just made O(1). The console's own "Select all *N*
  matching devices" bulk action fires one HTTP request per selected device
  against the single-device credential/platform routes, each of which calls
  `upsert()` — so reassigning a credential profile across a full 10,000-device
  fleet meant roughly 10,000 whole-fleet rewrites, serialized behind one lock,
  on the same process that serves device heartbeats and announces, for an
  entirely ordinary operator action. `FleetStore` is now sharded the same way
  as the other six stores (`fleet.d/`, migrated from `fleet.json` on first
  use, with the same rollback-guard placeholder and one-shot migration
  guarantees — see [Reference → Keyed per-device
  state](docs/zensical/reference.md#keyed-per-device-state) and [Operations →
  Rollback after the shard
  migration](docs/zensical/operations.md#rollback-after-the-shard-migration),
  both updated to cover it). A new `POST /api/v1/devices/bulk-credential`
  endpoint additionally collapses the console's *N* per-device requests for a
  bulk credential reassignment into one call (`FleetStore.bulk_upsert`) that
  groups the underlying shard writes, so a shard holding many of the selected
  devices is rewritten once, not once per device landing in it — session,
  CSRF, the credential-profile-exists check, and a single audit record all
  still apply, and a response names exactly which selected devices, if any,
  did not apply and why. On this host, reassigning all 10,000 devices this
  way costs at most 256 shard writes instead of 10,000 — see
  `server/tests/test_capacity_harness.py`'s `_measure_bulk_reassignment`.
- **The tracker's endpoint map no longer evicts a live device at full fleet
  size.** Its capacity was 10,000 — the same number as the supported device
  count — but the map also holds the `service:seeder` principal, so a full
  fleet needed 10,001 slots and every announce past that evicted the
  least-recently-updated principal, churning the LRU on the rollout critical
  path. Capacity is now defined as the supported device count plus headroom
  for service principals, and the bound is applied by the reconciler's
  maintenance pass rather than by each announce.
- **An open Monitoring tab no longer re-reads the whole audit trail every ten
  seconds, or make device token refresh wait behind it.** The activity
  histogram, the event page and the amortized prune each re-parsed every line
  in `audit.jsonl` on every call: at the module's own 50,000-event cap that
  measured 255 ms for a histogram, 232 ms for a deep page, and 260 ms for a
  prune that dropped nothing — and the prune paid it while holding the
  cross-process audit lock that device credential rotation also takes. The
  reader now keeps an in-process, append-incremental index of the file
  (offset, length, timestamp and category per line), so a poll costs only the
  bytes appended since the last one and parses only the rows it actually
  returns: 6.7 ms, 6.0 ms and 5.7 ms for the same three calls, back to back on
  the same host. Building the index costs one full pass (354 ms at the cap),
  paid on the first read after a restart or a prune. The index is a cache, never a second
  definition of a result — it is rebuilt whenever the file is not a strict
  extension of what was indexed (a prune's atomic replace always lands on a
  new inode), and the original streaming scan remains the fallback and the
  reference the tests check every answer against.
- **A transfer that resumes after a crash now re-reads what is already on
  flash.** All three device launchers started `aria2c` without
  `--check-integrity`, so on a resume aria2 trusted the piece map recorded in
  its `.aria2` control file and never re-hashed a piece already on disk. A
  piece corrupted in place — bit-rot, a torn write during a power loss —
  therefore survived the resume: the torrent reported complete and the staged
  image carried the wrong SHA-256. IRIS's whole-image hash still caught it, but
  only after the entire remaining transfer, and the repair was then a full
  re-stage instead of one 1 MiB piece. The read-back costs nothing on the paths
  that are not a resume: with nothing on disk yet every piece is dismissed
  without I/O, and a completed file being re-added to seed is skipped outright
  by `--bt-seed-unverified`, so a device seeding its staged images does not
  re-hash them at launch.
- **A busy `aria2c` is no longer mistaken for a dead one and killed.** The
  supervisor's health check was a single 3-second RPC probe, and any overrun
  read as "dead". An `aria2c` built without c-ares resolves tracker hostnames
  with a blocking `getaddrinfo()` on its event-loop thread, so one announce
  against a slow or unresponsive resolver freezes the whole daemon — RPC
  replies included — for as long as the resolver takes (5 seconds measured).
  That stall got a healthy daemon killed and relaunched, twice in five minutes
  in the measured run, dropping its in-flight download each time. The probe now
  asks the two questions separately: a refused connection means nothing is
  listening and still relaunches at once, while a late answer is only a
  suspicion and is confirmed by a second probe before anything is killed, with
  the wait bounded well above the worst resolver stall rather than below it.
  The Guest Shell launcher's own "already up?" probe, which was unbounded and
  could hang the launcher outright, now follows the same rule.
- **A stuck onboarding job now clears itself on an unattended console.** The
  reaper that escalates an overdue installer (`SIGTERM` -> `SIGKILL` -> mark the
  job failed) only ran when an operator submitted something or when an idle
  worker's queue wait timed out. One wedged job on a pool of one — or a full
  pool of wedged installers — left neither: the escalation stopped after its
  first step, the installer kept running, and the device stayed "busy",
  refusing the opposite action, until somebody clicked. A single daemon thread
  now drives the same reaper on a timer while any job exists, and retires
  itself when none is left.
- **A rotated-out seeder announce token is no longer valid forever.** Rotation
  kept the previous credential "non-expiring until explicit revoke", but no
  shipped command revokes one, so the previous token of every rotation stayed
  usable indefinitely — and every device that ever received a torrent carrying
  it still holds it. A retired token now expires 30 days after the rotation
  that replaced it (`IRIS_SEEDER_PREV_TTL`), enforced by the same validity
  check as any other credential, and the next rotation drops the record instead
  of counting it against the two-previous cap. A store written before this
  release gets the same window applied from its own recorded rotation time.
  Both credentials stay valid throughout the overlap, and a device that missed
  the rotation recovers by re-fetching a personalised torrent from the catalog
  — authorised by its catalog token, never by the announce credential being
  retired.
- **A burst of completions no longer strands a plan at `planned` for good.**
  The proof that a device holds verified content is a terminal report, and the
  tracker used to re-derive that fact by re-reading the per-device report ring
  once per sample pass. That ring keeps five reports per *device*, shared by
  every image assigned to it and every report kind. A device finishing several
  images inside one agent tick — ten are assignable, and a flash-tight device
  posts a `seeding-only` report and then a `staging-complete` upgrade for each
  — pushed the earliest terminal report out before any pass had seen it, and
  the fact was then derivable from nowhere: that plan latched its seeder
  observation, never its checksum, and sat at `planned` with no
  `seeding_started` ever emitted, silently and permanently. The same loss hit
  any report that landed while the tracker was restarting. The attestation is
  now recorded where it is known for certain — at ingest, into
  `<state>/transfer-attestations.json`, one row per transfer rather than per
  report — and the promotion pass reads it alongside the ring, so it survives
  the ring rotating past it. Existing state directories need no migration: the
  ring is still read, and a plan whose report has already been lost promotes as
  soon as the device posts another terminal report for it.
- **`iris.transfer.checksum_verified_at` no longer reads as the moment the
  device verified.** It is, and always was, the instant the *server* took the
  attesting report in. The device reports no verification instant at all, and
  its clock is not the server's, so IRIS does not back-date a guess — instead
  the same value now also ships as `iris.transfer.report_received_at`, the name
  that says what it is, and the report's own device-clock instant ships beside
  it as `iris.device.report_created_at`. The difference between them is the
  report-delivery latency folded into every plan-to-seed duration, and it is
  not marginal: the agent arms its terminal report at completion but defers the
  whole send on a `bad` link tier, backing off to about sixteen minutes, so on
  exactly the constrained devices IRIS exists for a `seconds_to_seed` could be
  inflated by that much with nothing on the record to show it. Both older
  attributes keep shipping unchanged — an exported attribute cannot be
  withdrawn — and the documentation that told operators `timeUnixNano` is
  "never an ingestion time" has been corrected for the `seeding_started` event.
- **A recovered lifecycle replay now says on the record that it is one.** A
  plan row rebuilt from a lost state file takes its promotion instant from the
  two durable facts alone, because the third — this tracker's own sight of the
  device announcing — lives in memory and cannot survive the loss. That much
  already made every replay agree with every other. What it could not do is
  reproduce an *original* instant that came from the announce, so a backend
  keeping first-write could hold two disagreeing values under one `event.id`
  with nothing to attribute the difference to. The pre-loss instant is
  genuinely unrecoverable, so it is marked rather than invented:
  `iris.transfer.recovered_promotion` now rides such a record, saying that its
  `seeding_started_at` is a reproducible lower bound, that the
  `tracker_seeder_at` beside it is a post-loss re-announce rather than the
  original observation, and which of two values is the replay. Absent — never
  `false` — on an ordinary promotion.
- **An agent upgrade no longer makes the whole fleet re-hash its staged
  images.** A device that had already staged its image carried a transfer id it
  minted itself and no plan id, so the first tick after the server started
  minting plans read every image as a new plan: every device in the fleet began
  a full SHA-256 of a ~1.2 GB flash file inside roughly one 60-second window,
  holding the agent lock — and therefore its heartbeats and telemetry — for the
  minutes that takes, on switches whose CPU is forwarding production traffic.
  The same reset also discarded any completion report that was still waiting to
  be delivered. Being named by the server for the first time is now treated as
  what it is — a rename of a transfer already in progress — so the tick records
  the plan and the server's transfer id and changes nothing else: no re-hash, no
  re-download, no lost report. Only a move from one known plan to a different
  one is still a boundary.
- **An image that was already staged when it was assigned now reports that it
  is done.** The device short-circuits on an image it has already staged and
  placed, and a completion report was armed only by the download path — so when
  a newly identified transfer landed on content that was already there, no
  report ever named that transfer and the console showed the assignment stuck
  short of complete while the bytes sat finished on the device. Such an image
  now sends exactly one completion report under its current identity, without
  re-hashing anything. The trigger is a measured change of identity, not a
  schedule: a device whose transfer identity did not change sends nothing
  extra, so this cannot turn into a fleet-wide burst.
- **A report can no longer carry a checksum verdict from a transfer that is
  over.** `content_sha256` is the device's own statement that it hashed the
  staged file and it matched the catalog. That verdict was stored per image
  rather than per transfer, so it outlived the transfer that measured it: after
  an image was unassigned (which deletes the staged copy) and assigned again,
  every report sent while the replacement was still downloading claimed
  `verified` for a transfer that had hashed nothing at all. The verdict is now
  dropped wherever the bytes it describes are — an image leaving the assignment
  set, a staged file that went missing, catalog content that changed underneath
  it — and reports say `not_checked` until the file has actually been hashed
  again. Nothing extra is hashed to say so: a staged file that is still
  complete is re-hashed by the same tick that noticed. A failed verify also
  lowers the image's `done` flag, which used to be left set beside the
  mismatch it contradicts.
- **The first IOx onboard of a new package version no longer fails, and a
  failed one is now retryable.** `device/iox/install.sh` gave the app 90
  seconds to reach `ACTIVATED`. That is shorter than the time an IE-3400 needs
  to load a package's docker layers into the IOx image cache the first time it
  sees them, so onboarding a *new* image version reported failure while the
  activation actually completed a minute or two later — and because the failed
  run left the app-hosting config behind, the console's retry was refused by
  preflight ("the iris app-hosting config already exists") until the operator
  undeployed by hand. The install, activate and start waits now default to 300
  seconds each, matching `device/xr-install.sh`'s `ACTIVATE_TIMEOUT`, and are
  overridable per device (`INSTALL_TIMEOUT`, `ACTIVATE_TIMEOUT`,
  `START_TIMEOUT`, `STATE_POLL`). A wait that does time out now prints the
  device's full, unfiltered reply and the last state it observed instead of
  swallowing them. The console preflight treats an IRIS app that is `DEPLOYED`
  or `ACTIVATED` but never started as a resumable retry — it serves nothing,
  and the installer tears down whatever it finds — while a `RUNNING` app, and
  every IRIS artifact the IOx installer does not re-create itself, still
  refuse.
- **The aria2c build scripts ship in the repository.** IRIS redistributes a
  patched `aria2c`, which is GPLv2, and that licence asks for the source *and*
  the scripts used to control its compilation. The source and patches were
  already here; the scripts were not, and `NOTICE` offered them on request
  instead. `tools/aria2c-build/` now carries the pinned builder `Dockerfile`
  and `build.sh`, the release tarball ships them, and the written offer is
  gone — there is nothing left to request. The patch set is deliberately *not*
  duplicated there: the build reads it from `tools/aria2c-patches/`, which
  stays its only home, and a test asserts no patch copy appears beside the
  scripts.
- **The published aria2c build can be rebuilt again.** Those scripts pinned
  `openssl-dev`/`openssl-libs-static` to `3.5.7-r0`, and Alpine v3.24 has since
  replaced that package with `3.5.8-r0`. An Alpine branch indexes only the
  newest release of each package, so the pin was withdrawn out from under the
  build and `apk add` refused the whole set — corresponding source that cannot
  be built is not corresponding source. Both pins are bumped to `3.5.8-r0`,
  which is the only change: every other pin still resolves, and the base image
  is still pinned by digest. Nothing floats, and a withdrawn pin still fails
  the build rather than drifting. A binary rebuilt on the newer OpenSSL will
  not reproduce the bytes in `tools/aria2c.sha256`, which pins the artifact
  IRIS ships rather than the recipe; the handed-in binary and its fail-closed
  check are unchanged. A test resolves every pin against the live Alpine index
  so the next withdrawal is caught here rather than by a recipient.
- **Every documented image build refreshes its base.** The build scripts
  gained `--pull` earlier in this cycle, but the commands the docs hand an
  operator to paste — in `server/Dockerfile`'s own header and in
  `DEVELOPMENT.md` — still did not, so building the server image the
  documented way reused whatever `python:3.12-slim-trixie` the host had
  cached and silently shipped a base missing Debian security updates. Both
  now pass `--pull`, and a test holds every build script and every documented
  build command to it.
- **Install-mode flash reclaim no longer spends its one attempt on a refusal.**
  A device that already holds the install lock answers `install remove
  inactive` with "cannot start new install operation" and does nothing, and
  `show install summary` does not report that state, so the pre-check could
  not see it. The agent treated the refusal as a successful reclaim and burned
  the per-image once-guard, permanently disabling reclaim for that image on a
  device whose lock would have cleared by itself. The refusal is now
  recognised in the command's own output, reported as a no-op, and retried on
  the next tick. Observed on a Catalyst 9300 running IOS-XE 17.18.3.
- **`tools/check-package-freshness.sh` no longer claims to have verified a
  package that is not there.** An absent IOx tar was reported as `absent` and
  then swept into the "verified: both IOx tars pin the live catalog
  certificate" summary, exiting 0 having inspected nothing. Absent required
  packages are now named in a `NOT READY` block, block the verified verdict,
  and exit non-zero, so the check an operator runs before a rollout cannot be green
  because it found nothing to look at.
- **A lifecycle event that a collector never acknowledged is no longer lost
  silently.** A plan row is retired once its records have been *accepted by the
  export queue*, not once the collector has confirmed them — requiring
  confirmation would hold every row forever whenever a collector is down. The
  consequence is real and unavoidable: an outage longer than the retention
  window retires rows whose records were never acknowledged, and by then the
  bounded in-memory queue no longer holds them. Nothing recorded that. The
  store now counts those records in `events_retired_undelivered` and exports it
  next to the standing backlog, so an outage that has already cost terminal
  records is visible instead of being indistinguishable from a quiet fleet.
  Rows of still-assigned plans are excluded — those are rebuilt and re-queued
  under the same `event.id`, so they are a replay, not a loss.
- **`iris.transfer.tracker_seeder_at` can no longer predate
  `iris.transfer.planned_at`.** A peer registry row belongs to a peer, not to a
  plan. Unassigning and re-assigning an image the device is already seeding
  (both inside one agent tick, so aria2 never stops) leaves a row carrying the
  *previous* transfer's completion instant, and the new plan latched it — the
  tracker reporting it had watched a plan seed over an hour before that plan
  existed. Since the observability guide tells operators to read that attribute
  against `checksum_verified_at` to see which precondition was the laggard, the
  comparison returned nonsense for exactly the re-assignment case. Any candidate
  instant older than the plan is now skipped in favour of the next one, ending
  at the tracker's own observation on the pass. The promotion instant itself is
  unchanged (it was already floored at `planned_at`).
- **`TransferLifecycle.prune()` no longer drops a live plan.** The manual
  retention hook took no live plan set, so it could delete the row of a plan
  that was still assigned — a `seeding` row is terminal while its assignment
  stands — after which the next observation pass rebuilt it with an empty
  marker map and re-emitted both events. Nothing in the tracker calls it today,
  so this was latent, but the signature is what a future caller reads: it now
  takes the live set and skips those rows, the same correctness rule the
  automatic retention and size bound already obey.
- **The test suite is green on a clean checkout, whatever machine runs it.**
  Three tests silently depended on the host. The IOx staging test
  (`device/iox/tests/test_stage_iox_package.bats`) asserted that
  `tools/stage-iox-package.sh` fails fast when no catalog certificate is
  configured, but on a host running the IRIS stack the helper found the live
  `iris` container, copied the certificate out of it and ran a full package
  build instead — so the assertion was never reached and the test failed. Docker
  is now stubbed to "no such container", so the fast-fail path is exercised the
  same way everywhere. The `device/tests/test_device_install.bats` remote-SSH
  test used a real lab address as its "non-local" `STAGE_HOST`, which made the
  build host that owns that address take the local-staging branch; it now uses a
  TEST-NET-1 (RFC 5737) documentation address no machine can own. And
  `device/agent/tests/test_report_v2.py` inherited `IRIS_RUNTIME_MODE` from the
  environment, so it failed whenever the agent suite ran inside the IOx image,
  which sets that variable; the test now clears it.
- **The Compose project name is declared, not derived.**
  `server/docker-compose.yml` now sets `name: server`. Compose used to name the
  project after the compose file's parent directory, which is always `server`,
  so a second checkout of this repository on a host already running IRIS
  resolved to the *same* project and the *same* named volumes as the live
  deployment: `up` adopted the production container, `run --rm iris
  iris-bootstrap` re-bootstrapped production state, and `down -v` deleted the
  state, the encrypted config and the published images. The declared value is
  deliberately the string the directory used to derive, so **an existing
  deployment keeps its `server_`-prefixed volumes and needs no migration**;
  what changes is that the name can no longer move under a directory rename or
  be inherited by a second clone. `container_name` is now
  `${IRIS_CONTAINER:-iris}`, so a second stack can take a container name of its
  own (names are host-global) with the same variable the helpers under `tools/`
  already honour; the default is unchanged, so `docker exec iris …` keeps
  working.
- **`tools/start-compose-server.sh` talks to the container it just started.**
  The health poll and the XR RPM freshness check addressed the literal name
  `iris`, so run from a second checkout beside a live deployment they read the
  *production* container: the script reported the new stack healthy because the
  live one was, and compared the RPM against the live catalog certificate. Both
  now use the container resolved from the script's own Compose project, with
  `IRIS_CONTAINER` as the override the rest of `tools/` accepts, and an
  unresolvable container fails the bring-up instead of reaching across the
  deployment boundary.
- **`server/docker-compose.override.yml` is gitignored.** The box-local Compose
  override carries host IPs, ports and tuning and was documented as untracked,
  but only escaped tracking because nobody had run `git add` on it. It now sits
  next to the existing `server/.env` rule.
- **Twelve Bats guards now actually fail when the thing they guard breaks.** A
  negative assertion written as a bare `! cmd` in the middle of a test body is
  exempt from `set -e`, so it reported `ok` whatever the code did. Each is now
  `run cmd` plus an explicit status check, and each was re-verified by breaking
  the guarded code in a throwaway copy and confirming the test goes red. Three
  covered properties nothing else tests: that the IOS-XR entrypoint carries no
  IOx/Guest Shell staging paths or device-SSH credentials, that the seeder
  never puts the RPC secret on the aria2c command line or picks up a stale
  on-volume one, and that the peer-transfer hook makes no claim to identify the
  origin of a share. All twelve pass against the current code — no regression
  had slipped in behind them.
  secrets ciphertext (`secrets.json.age`, the only copy that outlives a
  container restart) is written with the same `fsync` discipline the device
  agent already uses: the bytes are flushed before the rename and the
  containing directory after it. Previously the write was atomic but not
  durable, so a power loss seconds after a device-token rotation the console
  had already reported complete could come back up with the previous
  ciphertext — and the device would then authenticate with a token the server
  no longer held.
- **`IRIS_AUDIT_MAX_EVENTS` and `IRIS_AUDIT_RETENTION_DAYS` now read the same
  way.** `0` used to disable the entry cap entirely on one knob while
  discarding the whole trail on the other. Both now treat a missing,
  non-integer or non-positive value as "use the default" — the rule
  `IRIS_HTTP_TIMEOUT` and `IRIS_ENDPOINT_TTL` already follow. For an
  effectively unbounded audit trail, set a large number.
- **Undeploy no longer tells you to adopt a device IRIS already owns.** When
  the deployment record store is present but unparseable, the console answers
  `503` naming the unreadable file instead of `409 "no deployment record for
  this device; adopt it first"` — advice that would have written a record
  asserting an unverified deployment on top of a repairable one. A device that
  genuinely has no record still gets the adopt/force guidance.
- **The Python test dependencies are declared.** `requirements-dev.txt`
  (`pytest`, `PyYAML`) is what both `TESTING.md` and CI install, and it ships
  in the release tarball beside `TESTING.md`. The Kubernetes manifest and
  `docker-compose.yml` security tests now import `yaml` directly instead of
  skipping themselves, so a clean machine running the documented command gets
  the same result as CI rather than ten checks quietly fewer.
- **Catalog state files fail closed.** An existing but unreadable or
  unparseable state file under `IRIS_STATE` (for example a hand-edited
  `policy.json` with a trailing comma) is no longer read as empty. Device
  routes answer `503 {"error": "state unavailable"}` and writers refuse
  instead of replacing the file with a single row, so a corrupt `policy.json`
  can no longer read as a fleet-wide unassign or lose every other device's
  assignment and plan ids. A genuinely missing file is still the empty store.
- **Device POST bodies are validated at the door.** The catalog refuses the
  non-standard `NaN`/`Infinity` JSON literals, non-object heartbeat bodies,
  pathologically nested bodies (400 rather than a dropped connection) and
  length-less/chunked POSTs (411). Heartbeat fields are typed and capped
  (strings 64-1024 chars, `free_flash_bytes` a finite non-negative int,
  booleans strict, image-id lists image-id-shaped); a wrong-typed field
  stores as absent. State files and JSON responses are written with
  `allow_nan=False`, so one device can no longer break the console's
  `/api/v1/devices` or swarm JSON for every operator. Report, transfer, request
  and image ids are matched whole (a trailing newline no longer passes).
- **v2 terminal reports may omit `window` and `content`.** An agent that
  measured nothing may leave them out or send `null`; the stored report then
  omits the key rather than inventing zeros. This extends per key: a report
  whose opening edge was never observed (an image adopted in place, or one
  whose start time was lost with a state file) omits `window.start` and is
  stored open-ended, and an empty `content` block reads as "not measured"
  rather than a measured zero. Previously the catalog accepted these blocks
  only whole, so exactly the unmeasured reports were rejected, retried under
  backoff and then dropped, leaving the transfer unconverged with nothing an
  operator could see.
- **`iris-assign` fails closed on an unreadable state file,** matching
  `iris-revoke` and `iris-mint-enrollment`: one line naming the file, exit 1,
  no traceback and nothing written over recoverable content.
- **Device-facing listeners survive a fleet burst.** The catalog and tracker
  servers kept the standard library's accept backlog of five connections, so
  a rollout in which the whole fleet announces or heartbeats at once
  overflowed the queue and the kernel answered with resets — an agent saw a
  connection reset rather than a slow answer. Both now queue 128. The
  catalog also completes its TLS handshake in the worker thread instead of
  on the accept thread, so one client that connects and never speaks can no
  longer stall every other device.
- **HTTP handler socket timeout.** The catalog and tracker handlers close a
  connection that stalls mid-request after `IRIS_HTTP_TIMEOUT` seconds
  (default 30) instead of pinning a thread for the life of the server.
- **Tracker enforcement loop survives a failed pass.** An exception in one
  reconcile pass (a full state volume, a malformed endpoint row) no longer
  ends enforcement silently behind a frozen `enforced` status: the pass is
  recorded as `degraded` with the exception type and the loop retries.
  Malformed rows in `peer-endpoints.json` are store corruption (fail
  closed), and a corrupt store no longer aborts device announces without a
  response — discovery continues while the endpoint waits in the retry queue.
- **Quarantine cannot be escaped with a previous seeder token.** A legacy
  announce from an address a durable endpoint attributes to a quarantined or
  revoked device receives no peers and is handed to nobody.
- **The `ip=` announce override is honoured only for the service seeder.** A
  device's durable endpoint is always its socket source, so a device can no
  longer plant an endpoint on another device's address (which lifted that
  device's seeder block through the shared permit/deny conflict) or have
  arbitrary fleet addresses blocked.
- **Seeder blocks for quarantined/revoked devices no longer lapse on
  `IRIS_ENDPOINT_TTL`.** Their endpoint rows are retained until the device is
  un-quarantined or re-onboarded. Expired rows of other devices are now
  actually pruned from `peer-endpoints.json` by the maintenance pass, and a
  non-positive `IRIS_ENDPOINT_TTL` falls back to the default instead of
  silently emptying the blocklist.
- **Telemetry export.** Sampled per-connection `iris.swarm.peer_rate` /
  `peer_bytes` records are evicted first when the OTLP log queue overflows
  during a multi-torrent wave, so they can no longer push tracker peer,
  policy, lifecycle or device report records out of the queue.
  `iris_telemetry_samples_rejected_total` / `iris.telemetry.samples.rejected`
  no longer drop to 0 while the live snapshot is stale or unreadable (which
  read as a counter reset and a phantom burst of rejections on every
  wake-from-idle). `iris_peer_unattributed_bytes_total` is declared a gauge
  (it steps down when a device is traced late; the name is unchanged).
  `otlp-export-degraded` / `otlp-export-recovered` audit events now carry
  `category: telemetry` and `actor: system`. A scheduled audit export that
  raises is recorded as a failed attempt (status line, audit trail, daily
  retry) instead of being silently retried every hour.

### Added
- **SSH host identity for every server-side device session.** `lab/device-run.sh`,
  `lab/xr-run.sh`, the installers' stage-host push and the XR RPM `scp` now
  share one trust policy (`lab/iris-ssh-policy.sh`): pin a key with
  `IRIS_SSH_HOST_KEY`, verify strictly against `IRIS_SSH_KNOWN_HOSTS`, or (the
  default) record on first contact into a persistent `known_hosts` under
  `$IRIS_STATE/ssh` and refuse a changed key thereafter -- `/dev/null` is never
  used. Legacy SHA-1/ssh-rsa/CBC algorithms are now opt-in (`IRIS_SSH_LEGACY=1`,
  also a compose variable), ssh's diagnostics are forwarded redacted instead of
  discarded, and the enable-escalation marker moved off a predictable `/tmp` name.
- **`EXPECTED_DEVICE_IDENTITY` guard in `device/device-uninstall.sh`.** The
  Guest Shell teardown now opens with a read-only `show version` and, when the
  record supplies a board ID, refuses to touch a device that reports a
  different one (same contract as the router scripts). The first session being
  read-only also lets the transport learn the enable requirement before any
  config write. Its verify is marker-gated and fails closed: a dropped or
  truncated verify session is "could not verify", never "clean".
- **`SVI_IGP` for routed Guest Shell installs.** `ip router isis` on the IRIS
  SVI is now opt-in per record (`SVI_IGP=isis`); the default injects nothing
  into the operator's IGP. Routed mode also trunks the AppGig port additively
  (`allowed vlan add`) and teardown removes only the IRIS VLAN from the list.
- **CI runs the test suites on every pull request.** New
  `.github/workflows/tests.yml` installs `pytest`, `pyyaml`, `bats` and
  `mktorrent` on a stock Ubuntu runner and runs the two documented test
  commands (pytest + bats) on pull requests and pushes to `main`.
- **`tools/get-ioxclient.sh` pins the ioxclient binary.** The extracted
  `ioxclient` executable is verified against a new `tools/ioxclient.sha256`
  (first-seen sha256 per version) and the install is refused on a mismatch or
  an unrecorded version; `IOXCLIENT_SKIP_VERIFY=1` is the explicit one-off
  escape hatch that prints the sha256 to pin.
- **`tools/apply-assignments.sh --dry-run`** validates the whole CSV
  (including every `image_id` against the server's published list) and applies
  nothing.
- **Transfer lifecycle telemetry.** Every assignment now mints a *plan*: the
  server writes a `plan_id`, `transfer_id`, `planned_at` and the image's
  torrent info hash into the device's `policy.json` row, in the same atomic
  write as the assignment itself, and the agent adopts that `transfer_id`
  instead of minting its own — so one transfer carries one identity from the
  moment it is approved to the moment it seeds. The tracker exports two OTLP
  log records per plan under the new event name `iris.transfer.lifecycle`:
  `planned` when the assignment is made, and `seeding_started` only once
  **both** a terminal device report bearing that plan's own `transfer_id` has
  verified the file's sha256 **and** this tracker has seen the device announce
  `left = 0` on that image's torrent under its own authenticated principal.
  Either fact alone would lie: aria2 announces `left = 0` the instant the last
  piece lands, minutes before the agent's sha256 of a ~1.2 GB image runs, and
  the device never talks to the tracker at all. The four timestamp attributes
  are RFC3339 UTC with exactly three fractional digits and a literal `Z`
  (`2026-09-02T14:03:11.482Z`), and each record's OTLP event time is the
  instant it describes rather than the moment it was exported. Purely
  additive: no existing record, attribute, log name, or event time changed and
  `iris.telemetry.schema.version` stays `2`. As everywhere else in IRIS this is
  staging telemetry — nothing is installed, activated, or reloaded. See
  [Transfer lifecycle](docs/zensical/reference.md#transfer-lifecycle) and
  [Observability](docs/zensical/observability.md#log-attributes-operator-contract).
- Each lifecycle event is exported **exactly once**, including across a server
  restart, from durable receipts in the new tracker-owned state file
  `<state>/transfer-lifecycle.json`. That file is derived state — identity
  lives in `policy.json` — so it is safe to delete: the next sample pass
  rebuilds every row with the same ids, and any record re-sent afterwards is
  byte-identical under the same deterministic `event.id`, which a backend
  dedupes rather than double-counting. It is bounded at 4096 plans, prunes
  rows that owe nothing a week after their last write, and reports what it
  dropped instead of dropping it quietly. The facts behind a seeding event are
  latched whether or not telemetry export is switched on, so enabling a
  destination later still publishes the transfers that were in flight while it
  was off.
- A plan is minted when an image **enters** a device's approved set and carried
  forward verbatim while it stays there, so a repeat Apply — including one that
  only touches some other image, and the quarantine auto-unassign rewrite —
  never re-mints and never restarts an in-flight transfer's identity.
  Unassigning and re-assigning the same image mints a genuinely new plan, which
  is what keeps two successive transfers of the same image to the same device
  distinct in the telemetry. When that second plan lands on an image the device
  has already staged, the agent re-hashes the staged file once so the new
  transfer is attested by its own checksum instead of inheriting the previous
  one's; the syslog tags `REPLAN` and `REPLAN-VERIFY` record it on the device.
  `GET /v1/devices/<id>/policy` gains a `plans` map alongside the existing
  approval keys, carrying only `plan_id` and `transfer_id`; an agent that
  predates the key ignores it, and the server's internal `get_policy()`
  contract is unchanged.

### Changed
- **Real-`docker build` tests are opt-in.** The two image-build tests in
  `device/xr/tests/test_xr_image.bats` need a reachable Docker daemon, pull the
  pinned base image and take minutes, which made the default suite depend on the
  machine running it. They are now skipped unless `IRIS_TEST_HOST_INTEGRATION=1`
  is set, so a clean checkout is green and an operator can still run them
  deliberately before a release or after touching
  `device/container/Dockerfile`. See
  [Validation](docs/zensical/validation.md#opt-in-host-integration-tests).
- **A `constrained` link means a slower telemetry cadence, and only that.** The
  agent's tier comment promised a trimmed payload on a constrained link; the
  trimming function it referred to had no caller, so a constrained device
  always sent the full report and stamped `link.trimmed: false` on it. v2
  retired both the trimming and the whole `link` section, so the function and
  the promise are gone rather than re-wired — a constrained link is sampled
  every 4th tick, as [Observability](docs/zensical/observability.md) already
  documented. Three other unreachable helpers were removed with it (a
  superseded live-sample builder in the agent, a peer-policy quarantine
  self-repair that policy validation rejects before it can run, and an unused
  hash helper in the announce-rotation tool) along with the nine tests that
  were the only thing exercising them. No wire field, route or operator
  behaviour changes.
- **The console refuses to serve plain HTTP unless told to.** When no usable
  console certificate exists (`IRIS_GUI_CERT` and `IRIS_CERT` both absent or
  unloadable) `iris-gui` now exits with a clear message instead of silently
  falling back to `http://` — a fallback that accepted the admin password in
  cleartext and then could not keep a session, because browsers discard a
  `Secure` cookie set over plain HTTP. `IRIS_GUI_ALLOW_PLAINTEXT=1` opts into
  plaintext deliberately (loopback or an isolated lab only); the session
  cookie then drops its `Secure` attribute so sign-in works, and a warning is
  logged. `POST /api/v1/settings/gui-cert` reports `applied: false` with a note
  when the listener is not serving TLS. See
  [Security](docs/zensical/security.md#tls-and-certificates).
- **`iris-gui-admin` ends every live console session.** The break-glass reset
  stamps a session floor into the admin record; the running console drops
  any session created at or before it on its next request, so a
  suspected-compromised session dies with the credential. The in-console
  password change keeps its caller's session and revokes the others, as
  before. The floor and each session's creation time keep sub-second
  precision: truncating both to whole seconds had made a login in the same
  second as the reset land exactly on the floor and die on its next request.
- **Background polling no longer keeps a console session alive.** The
  console's periodic refreshers send `X-IRIS-Poll: 1` (GET only); the server
  validates the session for those without refreshing its idle clock, so a
  console left open on Devices, Overview, Swarm or Monitoring reaches the
  idle timeout Settings advertises. Operator input still counts.
- **The bulk *Set credential* modal opens on a disabled placeholder.** Apply
  with nothing chosen is a no-op; clearing the credential is a distinct
  entry that asks for confirmation. A failed `/api/v1/credentials` read now
  keeps the last good profile list, disables the pickers and says so,
  instead of rendering every device as "no credential".
- **Trust-store uploads and downloads are validated as X.509.** A
  `CERTIFICATE` block that is not a certificate is rejected before anything
  is written (previously one such block made OpenSSL reject the whole
  runtime bundle and every private CA silently stopped being trusted);
  `rebuild_bundle` skips and reports a store file that fails to load, and
  `ssl_context()` logs when it degrades to system roots.
- **`tools/make-release.sh` assembles from tracked files only, atomically, with
  a manifest.** The release is built from `git ls-files` under an explicit
  allowlist instead of `cp -R` of the live tree, so gitignored material under
  `server/` and `device/` (`server/.env` with a collector bearer token, private
  keys under `server/certs/`, the licensed console typeface, the Compose
  override, `device/xr/out/iris-xr.rpm`) can no longer ship. It builds under a
  temp dir and only replaces `release/` on success, writes
  `release/iris.tgz.sha256` and a per-member `MANIFEST.txt` (inside the tree
  and beside the tarball), and produces a reproducible archive (sorted
  members, fixed owner and mtime, no gzip timestamp) on GNU tar.
- **`.dockerignore` secret patterns are recursive.** `.env`, `*.env`, `*.pem`,
  `*.key`, `*.crt`, `*.p12`, `*.bin`, `*.torrent`, `*.aria2` and `*.rpm` now
  use `**/` so nested files under `server/` and `device/` stay out of image
  layers; `server/docker-compose.override.yml`, the licensed
  `SharpSans-Bold.woff2`, `device/xr/out/` and `device/xr/tests/` are excluded
  too (the public `server/certs/cisco_bulkhash_verify.pem` is re-included). A
  new `server/tests/test_dockerignore.py` evaluates the file with Docker's
  matching rules against a planted tree. Note: the Sharp Sans typeface is no
  longer baked into the image; a lab host that wants it must bind-mount it.
- **`tools/gen-device-installers.sh` validates the whole CSV before minting.**
  Rows are parsed and checked (format, duplicate `device_id`, column count)
  before any enrollment token is minted; installers are written `0700` into a
  private staging directory and renamed over `fleet/dist/` as a complete set,
  so a bad row leaves no partial output and stale installers do not linger.
  The generator refuses to replace an output directory holding files it did
  not create.
- **`tools/apply-assignments.sh` really is all-or-nothing.** Every row is
  validated (shape, identifier format, duplicates, published image ids) before
  the first assignment is written; an apply-time refusal is reported per row
  with an honest "applied N of M" summary.
- **`tools/make-torrent.sh` requires an announce credential.** The tracker
  rejects a credential-less announce, so the helper now needs
  `ANNOUNCE_TOKEN` (embedded as `/announce?announce_token=...`) or a full
  `ANNOUNCE_URL` and fails with a clear message otherwise. `ANNOUNCE_URL` is
  checked too: it must carry a non-empty `announce_token=` (or legacy `key=`)
  query parameter, so the escape hatch cannot recreate the credential-less
  torrent the default path refuses.
- **`tools/build-xr-package.sh` never deletes `APPMGR_BUILD_DIR`.** The
  xr-appmgr-build clone only goes into a missing or empty directory; an
  existing non-empty one without `./appmgr_build` is refused. The RPM is
  placed in `--out` via a temp name + `mv`, and `device/xr/out/` and `*.rpm`
  are gitignored.
- **The Compose `HEALTHCHECK` probes `/readyz`** (12 s timeout) instead of the
  unconditional `/healthz`, so a container whose catalog or artifact listener
  died no longer reports `healthy`, matching the Kubernetes probes.
- **The documentation workflow's actions are pinned to full commit SHAs.**
  `.github/workflows/docs.yml` publishes to `gh-pages` with `contents: write`,
  so `actions/checkout`, `actions/setup-python` and `peaceiris/actions-gh-pages`
  are now pinned to the commits their `v4`/`v5`/`v4` tags resolved to on
  2026-09-04 rather than to the mutable tags (IRIS-13-015); a moved or
  compromised tag can no longer run with that write token.
- **Kubernetes ConfigMaps are generated from the tracked server and Console env
  files** (kustomize `configMapGenerator`, hash-suffixed names), so an edit
  rolls only the affected Deployment on re-apply; the former hand-written
  `kubernetes/configmap.yaml` is gone. Kustomize also replaces deliberately
  unusable server/Console image placeholders with operator-supplied immutable
  digests and both Deployments use `imagePullPolicy: IfNotPresent`; a mutable
  same-tag rollout is no longer part of the supported manifest contract.
- **The seeder's RPC secret leaves the command line.** `server/seed-launch.sh`
  writes a mode-0600 `seeder.aria2.conf` under `IRIS_RUN` and passes
  `--conf-path`, so the secret is no longer readable in
  `/proc/<pid>/cmdline` by every local user on the Docker host.
- **`tools/stage-iox-package.sh`** places the package atomically in the
  `docker cp` branch too, and checks `/proc/sys/fs/binfmt_misc/qemu-aarch64`
  for arm64 emulation before falling back to pulling a probe image.
- **The unified IOx/XR agent image uses Alpine.**
  `device/container/Dockerfile` builds from
  `python:3.12-alpine3.24`, pinned by index digest. The earlier XR-only
  comparison dropped its wrapper from 51.6 MB to 26.4 MB delivered and from
  145 MB to 71 MB unpacked; the unified image adds the OpenSSH/`sshpass`
  surface IOx requires. Every functional
  gate was run side by side with the Debian image before adoption: pinned
  catalog TLS (success and wrong-certificate rejection with identical
  error text), Python ssl/gzip/hashlib/fcntl/statvfs, DNS on musl, the
  BusyBox-ash entrypoint including secret rotation and crash recovery,
  interrupted-torrent resume, indefinite seeding, the completion hook, and
  the agent's own test suite inside the image. This is a deliberate
  departure from the Debian-trixie lineage the server keeps (issue #13): the
  device image has no `openssl` CLI consumer. Bump the digest when the tag
  moves.
- **Container agents supervise aria2c by exact PID and retain field
  diagnostics.** `device/container/entrypoint.sh` launches aria2c as a tracked
  child of the
  PID-1 shell (stdio on `/dev/null`, exactly what `--daemon` did) and act
  only on that PID plus its `/proc` start time — never on `pgrep -f` /
  `pkill -f` name matching. Two latent supervisor faults go with it: a
  stopped or wedged aria2c that ignored SIGTERM could never be replaced
  (the relaunch failed to bind every tick while the log said "(re)started"),
  and a container stop killed aria2c before it saved its `.aria2` control
  file. The supervisor now sends TERM (and CONT), waits up to 5 s, then
  KILLs and reaps, so an interrupted download keeps its checkpoint and a
  stopped daemon is replaced within a tick. Alpine's BusyBox keeps `ps`,
  `top`, `free`, and `kill` available in the signed image for field diagnosis
  without the separate `procps` package.
- **IOx packages no longer carry the docker build context.**
  `device/iox/build.sh` packages from a directory holding only
  `package.yaml` and `rootfs.tar`; `ioxclient package` had been tarring the
  whole build context — a second copy of aria2c, the agent sources, the
  Dockerfile and the cert — into `artifacts.tar.gz` as ~3.3 MB (5.6%) of
  dead weight in every `iris-*.tar`.
- **Image builds now refresh their base image.** `device/iox/build.sh`,
  `tools/build-xr-package.sh` and `tools/start-compose-server.sh` pass
  `--pull` to `docker build`, so a build starts from the current
  `python:3.12-slim-trixie` tag instead of whatever the build host cached.
  Measured on the lab server on 2026-09-02: a 19-day-old cache had shipped
  every image 12 Debian security updates behind, OpenSSL 3.5.6 where the tag
  already carried 3.5.7 (issue #13). `IRIS_NO_PULL=1` keeps the cached base
  for an A/B build of an unrelated change.
- **Standing assignments made before this release carry no plan until they are
  Applied once more.** Until then their devices keep minting their own transfer
  ids and their plans emit no lifecycle events at all. Re-assign from the
  console, or re-run `tools/apply-assignments.sh` — it is idempotent, and an
  image that already carries a plan keeps it.
- **A shared-agent change ships in three packages.** `device/agent/` changed, so
  a fresh Guest Shell bundle, **both** IOx tars and `iris-xr.rpm` must be built
  and republished before device rollout — `tools/provision-iox-packages.sh` and
  `tools/build-xr-package.sh --out artifacts/` after the server rebuild.
  `tools/check-package-freshness.sh` verifies wrapper/provenance consistency
  and runtime certificate readiness, not current-source freshness, so a green
  result does not waive this. Until a device has the new
  bundle it keeps minting its own transfer id, and its plans emit `planned` and
  never `seeding_started`: there is deliberately no fallback that promotes a
  plan from a report bearing a different transfer's id, because that would mean
  publishing "seeding" on the strength of a checksum computed for some other
  transfer. Silence, not a wrong answer — and the tracker counts those plans in
  `plans_awaiting_report` so the rollout gap is visible rather than inferred.
- **`iris-bootstrap` no longer destroys fleet state by accident.** A new
  `--rekey` (alias `--add-recipient`) mode re-encrypts every existing `.age`
  file — including the console's `gui-key.pem.age` — to the current
  `IRIS_AGE_RECIPIENTS`, verifying each rewritten file round-trips with the
  mounted identity before it replaces the original; no token, key, or the
  pinned `tls/crt.pem` changes. The printed break-glass guidance now names
  `--rekey`: it used to recommend `--force`, which wiped every device catalog
  token and rotated the certificate every device pins. `--force` is now
  disaster recovery only and refuses without an explicit `--yes`, printing what
  it destroys. A volume holding only some of the three `.age` files is refused
  with the missing names instead of being silently regenerated on the next
  bring-up; `--repair <secrets.json|rpc-secret|tls/key.pem>` regenerates
  exactly the one named missing file. An empty or undecryptable `.age` file is
  reported by name rather than as "nothing to do", and a fresh bootstrap whose
  recipient list omits the identity's own public key fails at bootstrap time
  with a message naming `IRIS_AGE_RECIPIENTS` instead of at the next `up` with
  "bad master key?".

### Fixed
- **Console HTTP hardening.** `POST` with a negative `Content-Length` is
  refused before any read (it used to read until EOF with no cap, pre-auth);
  session and CSRF are checked *before* a POST body is buffered, so an
  unauthenticated connection can no longer make the console hold up to
  8 MiB per request; the TLS handshake runs in the per-connection worker
  thread, so one idle TCP connection to port 8080 no longer freezes the
  console for every operator; `/api/v1/*` responses carry
  `Cache-Control: private, no-store` and the static assets revalidate with
  `Last-Modified`/`304`.
- **A corrupt live secrets store is no longer mistaken for an empty one.**
  `secrets_store.load` raises for a present-but-unreadable file (a missing
  file is still the empty store), every writer refuses to persist, and the
  console answers 503 instead of showing the first-run wizard — previously
  any mutation would have re-encrypted the empty skeleton over the only
  durable copy of the fleet's credentials.
- The onboard log stream (SSE) counts a job's queued→running transition as
  progress and ends an idle-expired stream with `event: end` / `data: idle`
  rather than closing silently; a password check that finds both scrypt
  slots busy answers 503 + `Retry-After` instead of "invalid credentials"
  (which penalised the login limiter and audited a failure that never
  happened); credential profiles reject non-string values at save time.
- The artifact server no longer follows a symlink out of its root, redacts
  `/staging/<capability>` paths from its access log, and drops a connection
  that completes the handshake but never sends a request after 120 s.
- Web console: session loss after load (restart, revocation, idle expiry)
  now redirects to sign-in from any view instead of freezing the last data
  on screen; a failed poll shows "live data unavailable since …" in the
  header; the embedded swarm map treats the proxy's `error` answer as a
  failed poll instead of "Live" with an empty swarm; the Monitoring poll no
  longer discards "Load older" audit pages or repaints the brush mid-drag
  and polls only the visible pane; the Telemetry filter gains an
  `unknown` bucket; id-keyed maps are prototype-free (a device or image
  named `constructor` rendered pre-selected); the login page distinguishes
  throttling (with the retry delay) and network errors from a wrong
  password.
- **Forced router-nat undeploy no longer records NAT residue as clean.** The
  force path now unwinds the IRIS static mapping, clears only translations
  inside the IRIS VPG subnet, retries the overload no-form with a settle, then
  removes the ACL and VPG -- each in its own session -- and its verify fails
  closed if any object it chose to reclaim survives.
- **`device/bootstrap.sh` no longer overwrites its own executing file** during
  a bundle upgrade; the new bootstrap is written beside it and renamed into
  place, so the upgrade tick finishes on the old script's logic instead of
  resuming at a stale byte offset inside the new one.
- **`lab/iris-diag.py` / `lab/iris-add.py`** send the `iris` placeholder token
  when the RPC secret file is missing or empty (what the daemon actually runs
  on), exit non-zero on a failed probe or RPC error, and `iris-add.py` follows
  `STAGE_DIR` for the download directory.
- **Device reclaim never deletes the file the `BOOT` variable names.** Bundle-mode
  space reclaim, the failed-placement reclaim and the legacy replaced-root
  cleanup now protect the `show boot` target on the same footing as the
  running image (an operator points `BOOT` at a staged image for a later
  window; a parked image's kept root copy was otherwise fair game). When
  `show boot` cannot be read the agent skips the delete instead of guessing.
  The agent's `Deps` contract drops the never-called arbitrary `ios` exec
  seam; `boot_image` (read-only `show boot`) takes its slot.
- **A same-name image replacement — including one the `BOOT` variable
  currently names — no longer deletes the old file before the new one is
  proven good.** The root-copy path used to `delete /force` the destination
  and then `copy`; a copy failure or a power loss between those two commands
  could leave the device unable to boot if the destination was the `BOOT`
  target, and this path was deliberately left unguarded by the previous fix
  because refusing outright would have blocked the ordinary republish flow.
  It now copies the new bytes to a reserved temp name (`<image>.iris-tmp`),
  verifies presence and exact size there, and only then `rename`s the proven
  copy over the real name — a directory-entry update, not a data transfer,
  so it is the smallest exposure window this driver can make. A `rename` (or
  its confirming applet run) that itself raises is not treated as a failure
  outright: the agent re-checks the real name afterwards and reports
  whichever state it actually finds. That re-check is stricter than a
  presence-and-size look at the real name: it also insists the temp name is
  gone, so a `rename` that silently no-ops onto a same-size file already
  sitting at the image name cannot be reported as "placed" while the new
  bytes are still under the temp name (scrubber #130), and it polls for at
  most 60 seconds — the applet's own `maxrun` — rather than the ~15-minute
  budget sized for the copy itself (#140). The flash-space gate costs no extra
  headroom for a same-name replacement: the pre-existing file at the
  destination stays in place until the new copy is proven, but it was
  already occupying space before this placement began, so the gate's free-space
  reading already excludes it — a same-name replacement needs exactly the
  same room as a fresh filename. (An earlier revision of this change briefly
  added a measured surcharge for the pre-existing file on top of that,
  double-counting its bytes and refusing placements that physically fit —
  see scrubber #138, fixed before release.) On bundle-mode devices, the
  reserved temp name is also covered by the low-space bundle-reclaim sweep,
  so a leftover from an attempt that crashed before its own cleanup ran does
  not sit invisible on an otherwise-full device — install-mode devices don't
  get this: their reclaim runs `install remove inactive`, which does not
  touch a stray `.bin.iris-tmp` at the storage root. (Also fixed before
  release, scrubber #139: the sweep's once-per-image guard is now cleared
  whenever a fresh acquisition cycle starts for that image — a same-id
  content republish, a return from park, or the image's own placement
  succeeding — so a device that already burned the guard on an earlier
  cycle still gets one reclaim attempt for the next one, instead of being
  permanently disqualified.)
- **`device/eem-iris-copyroot.cfg` (the hand-maintained reference EEM applet)
  and `device/iox/README.md`'s on-box staging section now match the
  crash-safe two-phase sequence above.** Both still showed the OLD
  delete-then-copy-directly-onto-the-real-name shape the fix above replaced,
  so an operator reading either as a reference would have validated or
  reproduced the unsafe shape. The reference `.cfg` now shows both applet
  phases (stage-and-prove against the `<img>.iris-tmp` temp name, then a
  single `rename` once the agent reverifies it), with comments calling out
  the verification step and the running-image/reverify conditionals the
  static file cannot itself express. `docs/zensical/device-agents.md`'s
  description of the copy sequence itself, and the copy implementations,
  were already accurate; only these two reference files had drifted.
- **A same-id republish now refreshes the device's `.torrent`.** The agent
  records which catalog torrent identity (`info_hash_hex`, else the sha256)
  the on-disk `<id>.torrent` was fetched for; when the catalog's identity
  moves it discards the stale torrent, control file and partial and fetches
  the current torrent, and a sha mismatch drops the torrent along with the
  bad file. Previously the old torrent was re-added every tick and the
  device could never converge on republished content.
- **One image's un-servable torrent no longer aborts the whole tick.** A torrent
  the catalog refuses (404, 503 behind the deployment gate, 500) is reported
  as that image's `error` (`TORRENT-UNAVAILABLE`, new status
  `torrent-unavailable`); the set heartbeat still goes out and the siblings'
  progress is saved.
- **The C9k share probe rejects IOS's error transcript.** The probe now
  requires a parsed `dir` row of the probe's exact size; the
  `%Error opening .../iris-probe.txt` reply echoed the name and used to pass,
  suppressing the scp fallback behind a multi-GB copy and a 15-minute stall.
- **A short catalog outage no longer blocks every later terminal report.** A
  delivered heartbeat resets the heartbeat failure streak, so the `bad` tier
  clears when the link recovers instead of deferring reports until the
  60-attempt give-up. The outage tiering and the separate report streak are
  unchanged.
- **Terminal reports no longer invent measurements.** When no aria2 stats were
  taken at completion (an adopted image, an RPC hiccup) the v2 report omits
  the content byte fields, and an unrecorded transfer start leaves
  `window.start` absent with `window.complete = false`, instead of a
  measured-looking 0/0 over a zero-length complete window.
- **`rotate-logs.sh` trims `aria2c.log` in place.** The rename-over rotation
  left the running daemon writing to an unlinked inode (invisible, unbounded,
  never trimmed again) while the visible file froze; copy-truncate keeps
  aria2c's open descriptor on the file operators see.
- A `200` token-refresh body without `catalog_token`/`expires_at` is now a
  logged best-effort failure (`TOKEN-REFRESH-FAIL`) instead of a `KeyError`
  that silenced the device every tick; the SSH privilege un-learn matches
  CRLF transcripts, so `IRIS_DEVICE_ENABLE_ALWAYS=1` stops sending `enable`
  once a session proves the login is privileged; `write_conf` no longer
  freezes backfilled defaults into the device conf.
- **A failing `mktorrent` no longer leaks the seeder's announce token.** The
  announce URL is only accepted on `mktorrent`'s command line, and a non-zero
  exit used to surface that whole command line — token included — in the
  console's publish job status, in the exported `image_publish_finished` audit
  detail, and in `iris-publish`'s traceback. `publish.make_torrent` now reports
  only the exit status, the console and audit paths redact any
  `announce_token=` / `key=` value defensively, and `iris-publish` prints a
  one-line redacted error (exit 1) instead of a traceback.
- **A quarantined image stays out of the origin seeder across restarts, and a
  released one is seeded again.** The startup re-seed used to hand every
  `state/torrents/*.torrent` to aria2, so any container restart silently
  resumed seeding an image the Bulk Hash check had quarantined, and nothing
  ever re-applied the stop; it is now catalog-authoritative and skips
  quarantined torrents and torrents with no catalog entry. Releasing a
  quarantine now re-adds the torrent to the seeder from its recorded
  `source_dir` (re-syncing the canonical announce to the current credential
  first, with the info hash unchanged); the response carries
  `seeding_resumed` and a failed re-add is audited as
  `image_quarantine_release_seeding`. Previously a released-then-assigned image
  had no origin until the next restart.
- **`rotate-seeder-announce` names its refusal reason and skips quarantined
  images.** Every preflight refusal used to print `refused (ValueError)`; the
  fixed, credential-free reason is now included. A quarantined image — by
  design not active in the seeder — no longer makes fleet-wide credential
  rotation impossible; it is listed as skipped and re-synced when released.
- **A publish that fails after the torrent is built rolls the `.torrent` back**
  (seeder unreachable, state volume full), so no orphan torrent without a
  catalog entry is left for the restart re-seed.
- **Image delete stops the seeder before unlinking the file, and says when it
  could not.** The stop used to run last and swallow every failure while the
  audit row said `deleted`; the `DELETE /api/v1/images/<id>` response now carries
  `warnings` and the audit detail records a failed stop (class name only).
- **The canonical torrent's announce honours `IRIS_TRACKER_PORT` /
  `IRIS_TRACKER_ANNOUNCE`** the same way per-device personalization and the
  rotation CLI already did, instead of a hard-coded `:6969`; both variables are
  now documented in the reference.
- **Console onboarding's deadline reaper no longer fails queued jobs or
  abandons a running installer.** The 2-hour job deadline is measured from the
  moment a job starts running, never from the time it was queued: the tail of
  a large batch behind the worker pool used to be marked failed by the next
  start() for any device (which itself crashed with no JSON body), and then
  either ran the installer anyway or vanished with its planned record
  orphaned. A running job past the deadline is now stopped like an operator
  abort — SIGTERM to the recipe's process group, SIGKILL after
  `IRIS_ONBOARD_REAP_GRACE` seconds (default 60) — and stays `running` until
  its worker returns, so the device stays busy (an undeploy can no longer
  interleave with the still-running install), abort remains available, the
  pool worker is freed, and the record moves to `needs-reconcile` with the
  real exit status. Only an installer that cannot be signalled at all is
  marked failed outright.
- **Guest Shell and IOx teardowns are bound to the deployment record.** Every
  platform's execution-time preflight evidence (processor board ID, detected
  model) is now persisted onto the planned record before apply — records used
  to say preflight `not-required` for a check that had run — and a recorded
  undeploy renders `DEVICE_IP` and `EXPECTED_DEVICE_IDENTITY` from that record
  for every management type, not just routers. An inventory IP edit after
  deployment can no longer retarget a Guest Shell or IOx teardown at whatever
  answers at the new address. Records adopted before this release carry no
  identity, so their teardown still exports an empty
  `EXPECTED_DEVICE_IDENTITY`.
- **A CSV re-import keeps each device's credential profile.** The
  export → edit → re-import round trip used to drop `credential_profile_id`
  (the only key lost), so every later onboard/undeploy for the re-imported
  fleet failed with "device has no credential profile". A CSV that repeats a
  `device_id` is now rejected as a whole, naming both rows, instead of
  silently keeping the last one and mis-counting the import.
- **The stage-host credential is optional and is no longer handed to
  installers.** Console onboarding always stages per-device material locally
  (`IRIS_STAGE_LOCAL=1`), so no recipe could ever use the stage-host SSH
  password; the setup wizard and the Settings › Setup card no longer report
  it as required or claim onboarding cannot start without it, the
  setup-status API marks it `required: false`, and `HOST_USER`/`HOST_PASS`
  (stored or inherited) are no longer exported into any install/uninstall
  recipe's environment.
- **A corrupt `fleet.json` or `deployment_records.json` is refused, not
  emptied.** A file that is present but unparseable used to read as an empty
  store, and the next write replaced it — one device upsert rewrote the whole
  inventory as a one-device fleet at revision 1; one record transition erased
  every device's teardown authority. Writes now fail with an error naming the
  file (reads still degrade to an empty view); a missing file is still an
  empty store.
- **Activating a deployment record retires stale recoverable siblings.** A
  record left `unknown`, `drifted` or `needs-reconcile` survived a successful
  re-onboard and resurfaced as teardown authority once the newer record was
  removed; it is now `abandoned` with the reason recorded. `POST
  `/api/v1/devices` also ignores a client-supplied `os_family` (machine-determined
  from the device banner) and `registered_at`.
- **Package readiness no longer depends on embedded certificate probes.**
  A packaging change had made freshly built IOx packages report "no pinned
  cert" indefinitely. Deployment-neutral packages now have no embedded
  certificate to inspect: readiness uses each wrapper's adjacent provenance
  manifest, and runtime certificate delivery is checked separately.
- **Builds cannot embed a deployment certificate or private key.** The IOx
  and XR image builders accept no `CATALOG_PEM` input. Onboarding validates
  the runtime public certificate and rejects a file containing a private key
  before touching a device.
- **`device/iox/rebake_iris_tar.py` accepts legacy unsigned Docker archives.**
  It expected the old OCI layout (`index.json`) and raised `KeyError` on
  packages built since 2026-08-20; it now rewrites the
  classic docker-archive layout (`manifest.json` + plain layer tars, with
  the config renamed and `rootfs.diff_ids` recomputed), keeps every other
  member of `artifacts.tar.gz`, and replaces the top-level probe pem
  alongside the baked one.
- **IOx undeploy verifies the device it is about to tear down.** When the
  console passes `EXPECTED_DEVICE_IDENTITY`, `device/iox/uninstall.sh` opens
  with a read-only `show version` and refuses to send any destructive
  command unless the live processor board ID matches the deployment
  record (a session that returns no board ID also aborts), the same guard
  the router uninstaller and the IOx installer already apply. Force
  undeploy is unaffected.
- **IOx onboard validates the values it pastes into `run-opts`.** A
  double quote or newline in the device SSH password, catalog token, URL,
  device id or SSH user used to be silently dropped by IOS, so the app
  started without that variable, died on its entrypoint guard, and the
  installer timed out after tearing down the working app. The installer
  now rejects such values before touching the device, as the XR installer
  already did.
- **The XR container refuses to start without its `harddisk:` bind
  mount.** Activated without `-v /misc/disk1:/hostmount`, the entrypoint
  used to create a container-local `/hostmount` and report images staged
  to `harddisk:` that were never on it; it now checks `/proc/mounts` and
  fails closed with the missing activation option named.
- **Twelve documented environment knobs now actually reach the container.**
  Compose injects only what `server/docker-compose.yml`'s `environment:` block
  names, so `IRIS_METRICS_HOST`, `IRIS_METRICS_PORT`, `IRIS_SWARM_URL`,
  `IRIS_SWARM_PUBLIC`, `IRIS_OTLP_HEADERS`, `IRIS_OTLP_HEADERS_FILE`,
  `IRIS_OTLP_DEVICE_METRICS`, `IRIS_EVENTS_URL_TEMPLATE`,
  `IRIS_REQUIRE_IDENTITY_GATE`, `IRIS_ONBOARD_CONCURRENCY`,
  `IRIS_XR_SESSION_TIMEOUT` and `IRIS_DEVICE_ENABLE_ALWAYS` were silent no-ops
  when set in `server/.env` or the shell — including `IRIS_METRICS_HOST`,
  which the security page names as *the* hard control for the per-device swarm
  surface, and `IRIS_OTLP_HEADERS`, the only way to authenticate to a
  collector. All of them, plus `IRIS_HTTP_TIMEOUT`, `IRIS_TRACKER_PORT`,
  `IRIS_TRACKER_ANNOUNCE`, `IRIS_ENDPOINT_TTL`, `IRIS_GUI_ALLOW_PLAINTEXT`,
  `IRIS_HEALTH_LISTENERS`, `IRIS_AUDIT_RETENTION_DAYS`,
  `IRIS_AUDIT_MAX_EVENTS`, `IRIS_ENROLL_TTL`, `IRIS_ONBOARD_JOB_TIMEOUT`,
  `IRIS_ONBOARD_REAP_GRACE`, `IRIS_SSH_HOST_KEY`, `IRIS_SSH_KNOWN_HOSTS` and
  `SEED_MAX_CONCURRENT`, are
  now passed through. The reference states the mechanism, and a new gate
  (`test_documented_env_vars_reach_the_compose_container`) fails if a
  documented variable is neither passed through nor explicitly classified as
  host-side or one-shot.
- **Documentation: the replaced-image cleanup that no longer happens.** Three
  pages described the agent deleting the previous image's storage-root copy on
  reassignment; the agent deliberately does the opposite (it parks the image,
  keeps the root copy, and lets a later placement's reclaim gate free the
  space). Rewritten as "Unassigned image park" with the storage-planning
  consequence carried into the management-type sizing guidance, so a fleet
  reassigned twice on a 2×-image budget no longer stalls silently.
- **Documentation corrections.** `server.md` no longer places the audit trail
  on the state volume or calls `/etc/iris` wholly encrypted — `audit.jsonl` is
  plaintext there, and the page says so. `reference.md` gains the peer-policy
  routes (including the API's only compare-and-set write and its refusal
  codes), `GET /api/v1/install-options`, and 14 previously undocumented
  environment knobs with their real defaults and parser behaviour.
  `operations.md` drops citations to an untracked internal file and a
  lab-host-specific paragraph. `kubernetes.md`, `containers.md` and
  `kubernetes/README.md` gain `--pull` and the `/readyz` distinction.
  `fleet/README.md`, `images/README.md` and `device/iox/README.md` were
  rewritten against current behaviour.
- **`fleet/*.csv.example` no longer import phantom devices.** Three example
  rows in `devices.csv.example` were uncommented and carried live lab
  addresses, so the documented `cp` + import added three real inventory rows
  pointed at addresses the operator does not own. Every example row in both
  templates is now commented and addressed in the RFC 5737 documentation
  range, matching the console's own generated template; new gates in
  `test_docs_map.py` keep the two from diverging.
- **`fleet/iris-fleet.conf.example` is gone.** Nothing read it — the generator
  takes its inputs from the command line and environment only — yet it
  instructed operators to write an aria2 RPC secret and a host SSH password
  into a plaintext file, and it shipped in every release tarball.
- **Dashboards.** Four Splunk panels filtered device reports with
  `where "iris.image.id"==...`, which compares a string *literal* in eval
  syntax and silently returned zero rows the moment an operator narrowed to a
  single image — the board's whole delivery story went blank and read as "no
  device reported". The Grafana board no longer applies `rate()` to
  `iris_peer_unattributed_bytes_total` (a gauge that steps down, so `rate()`
  rendered a spike exactly when tracing improved), its hidden catalog-id
  picker is visible so narrowing an image narrows both legs rather than
  inflating every derived peer share, and its suffix-strip regex passes
  `.iso`/`.tar`/`.rpm` images through instead of dropping them. Both boards'
  prose no longer teaches `image size × completed devices`, a derivation no
  panel implements and panel 33 forbids. New tests parse both files and
  enforce these rules.
- **Telemetry documentation.** The OTLP log-record table listed four record
  names IRIS never emits and labelled the legacy v1 projection as the terminal
  report; it now lists the seven real names and marks the legacy one.
  `iris_swarm_peers_saturated` is described as the 0/1 cap flag it is rather
  than a peer count, the counter/gauge split is stated where alert rules are
  written from, and the collector chapter documents the Loki leg that eight
  Grafana panels — including all three headline delivery stats — depend on.
- **Attribution and licensing.** `NOTICE` now attributes every third-party
  program the server image installs and invokes, including GPLv2 `sshpass`;
  the SIL OFL 1.1 text ships beside the Inter WOFF2 binaries as
  `server/webroot/fonts/Inter-OFL.txt`, as that licence requires; the
  documentation site's Mermaid import is pinned to an exact version instead of
  a floating `@11` range resolved at request time; and
  `tools/aria2c-patches/README.md` carries the build description NOTICE
  promises, including that a locally built binary cannot reproduce the pinned
  checksums.
- **Public site accessibility.** The landing page's full-viewport particle
  animation and its smooth scrolling now honour `prefers-reduced-motion`
  (WCAG 2.2 SC 2.2.2, Level A), its ARIA tablists gained the panels,
  `aria-controls`, arrow-key navigation and roving `tabindex` the roles
  promised, and the delivery-step descriptions reflow to one column on a phone
  instead of being removed from the DOM below 700px.
- **The terminology guard no longer pins line numbers.**
  `server/tests/test_terminology.py` allowlisted absolute line numbers in 22
  other files, so an unrelated edit anywhere above one failed a *vocabulary*
  test with a stale-entry assertion (one entry had been re-pinned seven times
  by CSS work alone). Entries are now anchored on line content; the guard
  keeps its fail-loud property and an anchor that grows too broad still fails.
- **A partial download stranded by a container restart now resumes instead of
  stalling forever.** `_stage_image` used to re-add a torrent to aria2 only
  when the staged file was ABSENT, so once the IOx/appmgr container — and
  aria2c's in-memory session with it — was recreated (crash restart, redeploy,
  upgrade), a present partial file and its `.aria2` control file kept the
  device logging the same `PROGRESS` percentage forever; nothing ever re-added
  the torrent. The guard is now keyed on whether the running aria2c itself
  still knows about the download (`aria2.getPeers`/`tellStatus`, not file
  presence), and re-adding checks for the `.aria2` control file first: without
  it, aria2's own `--bt-seed-unverified` default would mark a re-added
  TRUNCATED file complete without ever hashing it, so that case is discarded
  and restarted clean instead of resumed. The same fix also clears a
  COMPLETED file's `.aria2` sidecar that survived a SIGKILL before aria2's
  next auto-save. Hardware-reproduced twice, including on a Cisco 8010 router.
- **The peer-transfer hook retries once or twice when the only feeding peer
  was a seeder.** `aria2.getPeers` came back empty (`"result":[]`) whenever a
  download's sole source was already seeding, because the seeder has nothing
  left to exchange with us the instant we finish and can disconnect before our
  own RPC round trip is served — losing the exact per-peer byte measurement
  for exactly the highest-value case, the first device of a wave fed only by
  the origin. `peer-transfer-hook.sh` now re-asks up to twice, a beat apart,
  before giving up; unaffected on the ordinary path (a non-empty first answer
  is unchanged). Hardware-reproduced twice on two different base images.
- **A plan boundary's carried terminal report is no longer destroyed by the
  same tick's replan re-verify.** `adopt_plan` carries an armed-but-undelivered
  terminal report across a genuine plan boundary so the previous transfer's
  only completion evidence is not lost — but when that same tick's replan
  re-verify SUCCEEDS, `_telemetry_tick` armed a fresh report for the new
  transfer and popped the carried body before it was ever sent (the carry only
  survived when the re-hash failed, by accident of control flow).
  `_arm_terminal_report` now refuses to arm over a different transfer's
  still-pending frozen report; the new transfer's own report is deferred by
  one tick — behind the carried report's own send attempt, already due on the
  same tick — rather than destroying evidence that was never delivered.
- **`PARK-DEFERRED` no longer repeats forever for a record the catalog can
  never name again.** A per-image record with no `root_file` (e.g. the bare
  `{'download_started': True}` the `aria_add` call site leaves behind) whose
  catalog entry is later dropped entirely can never be named by any future
  tick either, so the park pass — correctly declining to retire an image whose
  torrent might still be running — emitted `PARK-DEFERRED` on every tick for
  the life of the agent. It now gives up after 10 ticks (`PARK-GIVEUP`),
  retiring the bookkeeping record: nothing was ever named, so nothing was left
  to stop or delete.
- **A replan re-verify mismatch on XR no longer silently deletes an
  operator-adopted root image.** On a `copy_in_place` platform (XR:
  attest-in-place, the stage dir IS the target-FS root), the sha256-mismatch
  branch of the replan re-verify short-circuit deleted the staged/root file
  unconditionally, with only an `ERROR` line that never said the deleted file
  was an operator-adopted placement — unlike every other agent-side delete of
  that same file, which is guarded or announced. It now emits
  `ROOTCOPY-REPLACED` first when the placement was adopted (or its origin is
  unproven), mirroring the RECHECK republish path; the delete itself still
  happens (a genuine content mismatch has no "convergence wins" argument for
  silence), but the operator is told.
- **The bulk "Assign images…" picker now resolves a paged-away selection
  from the server instead of guessing it is unassigned.** Selection is
  id-keyed and outlives paging (device table pagination), but the picker's
  pre-check preview and its `expect_image_ids` compare-and-set both read a
  selected device's current image set from the currently rendered page only
  — a selected device on another page fell back to an empty set, which the
  server correctly refused (409) but for the wrong reason, spuriously
  conflicting on every off-page device in a bulk assignment. The console now
  fetches each selected id's real current row first (a bounded
  `/api/v1/devices` walk keyed by device_id — no request at all when the whole
  selection is already on the rendered page) before opening the picker.
- **The stage-host credential store, its Settings route, and its console
  form are gone.** Console onboarding always stages per-device material
  locally (`gui_onboard._build_env` exports `IRIS_STAGE_LOCAL=1` to every
  recipe), so the stage-host SSH credential the form collected was never
  reachable by any onboarding path — a password field with no consumer.
  Removed: `CredentialStore.set_stage_host`/`get_stage_host`/
  `stage_host_secrets`/`clear_stage_host`, the `POST`/`DELETE`
  `/api/settings/stage-host` routes, the `stage_host` card from
  `GET /api/v1/settings/setup-status` (now four cards, not five) and from
  `GET /api/v1/settings`, and the Settings/first-run-wizard form and template.
  The wizard is now three steps (telemetry, device packages, image
  verification), not four. A remote `STAGE_HOST` for a manual, off-console
  `device/device-install.sh` run is unaffected — that path still reads
  `HOST_USER`/`HOST_PASS` from the environment; only the console's UI for
  setting them is gone, so its comment pointing operators at "Console:
  Settings → Stage host" is corrected to say so.
- **An operator's `iris-publish --signature-verified` attestation no longer
  disappears the next time the Cisco Bulk Hash reconciler runs.** The flag
  used to write `cisco_signature_verified` — the exact field
  `catalog.apply_hash_verification`/`release_quarantine` (the reconciler)
  own and overwrite on every run that covers the image — so the operator's
  mark was silently discarded the first time the reconciler ever touched
  that entry. The attestation now lands on its own `operator_attested_signature`
  field, written once at publish time and never touched by the reconciler;
  `cisco_signature_verified` stays exclusively the reconciler's. Both are
  now guaranteed-present booleans on every `/api/v1/images` row (like
  `quarantined`/`hash_verification`) and both are shown, distinctly, in the
  image-detail drawer. Pre-existing catalog entries are left as they are:
  an already-stored `cisco_signature_verified` cannot be attributed after
  the fact to either the operator's old flag or a genuine past reconciler
  verdict, so nothing is guessed or backfilled into
  `operator_attested_signature` — the next scheduled reconciler run settles
  `cisco_signature_verified` correctly, exactly as it always has.
- **The Cisco-licensed Sharp Sans Bold console typeface is restorable at
  runtime, for deployments that hold the license, without ever re-entering
  the Docker build context.** It stays excluded from the image and the
  release tarball (`.dockerignore` — see `test_dockerignore.py`/
  `test_make_release.bats`), so the console keeps falling back to its
  default font stack by default. `server/docker-compose.yml` now bind-mounts
  it in read-only when `IRIS_SHARP_SANS_FONT_HOST` names the `.woff2` file
  on the Compose host; left unset (the common case), it mounts `/dev/null` —
  a harmless no-op every deployment without the license never has to think
  about.

## [2026.09.01]

### Added
- The console now shows an enrolled device with no image assigned as its own
  "unassigned" status, and the status filter can select them — previously they
  read simply as "enrolled", so there was no way to ask the table which devices
  still need an image. The status filter is now ordered alphabetically by label,
  with "Status: any" first and "Needs attention (any)" last.
- Import from disk now recognizes the explicit Cisco software suffixes `.bin`,
  `.iso`, `.tar`, and `.rpm`. IOS-XR base images, GISOs, and package bundles no
  longer disappear from the import panel solely because they are not `.bin`;
  other extensions and compound archives such as `.tar.gz` remain hidden.
- A device can now stage up to ten images at once: pick them per device or for a
  whole selection in the console, transfers run in parallel, and each image
  reports its own state. Unchecking an image stops its torrent and frees the
  staging copy while leaving the staged file on the boot filesystem, still
  tracked by IRIS. The console now says "Agent install" instead of "platform",
  labels bare inventory honestly, only offers installs the device model can run,
  and refuses an IOS-XE install on an IOS-XR device with the same clear message
  on every path.
- IOS-XR staging, for Cisco 8000 series routers. A device set to the new
  "XR appmgr container" agent install onboards from the console, runs the agent
  as an appmgr Docker application, and downloads its assigned images straight
  onto `harddisk:` through a bind mount — there is no separate copy step, so the
  bytes the device verifies and seeds are the bytes already at their final
  location. As on every other platform IRIS distributes, verifies, and stages:
  nothing is installed, activated, or reloaded, and no boot variable is touched.
  Onboarding refuses a router whose banner does not read IOS-XR, or one that
  still carries a previous IRIS deployment; undeploy removes the application,
  its package source, the staged RPM, and everything inside the agent's working
  directory. The empty directory itself is left in place: XR's CLI has no
  prompt-free way to remove a directory, and undeploy reports the leftover
  plainly rather than pretending it is gone.
  The full lifecycle is lab-validated on Cisco 8201 hardware — see
  [Validation](docs/zensical/validation.md#validated-platforms).
- Catalog images can now be checked against Cisco's published Bulk Hash feed:
  a scheduled run (off/daily/weekly, weekly anchored to Monday UTC), a manual
  "Refresh now" in the console, or an offline upload of the feed tar for
  air-gapped servers all join each image by file name and size — or by file
  name alone when a feed row publishes no size, a real gap seen on Cisco's
  live feed — and compare its sha512. The feed tar's X.509 signature is verified against a
  certificate pinned in-repo before anything in it is parsed, and any fetch,
  signature, or parse failure leaves every prior verdict untouched. A sha512
  mismatch quarantines the image — seeding stops, it is auto-unassigned from
  every device that had it approved, and it cannot be newly assigned — until
  an operator releases it, either because the catalog's own sha512 now agrees
  or by typing the image's filename to override a mismatch that persists.
  See [Image verification](docs/zensical/operations.md#image-verification).
- IOS-XR routers running the agent as an appmgr Docker container now have
  their own management type, `xr-host`, matching the platform's real
  networking: the container runs on the router's own network stack, so there
  is no VLAN, SVI, app IP/mask/gateway, VPG, or NAT interface, and `xr-host`
  and the XR appmgr container agent install are mutually required on any
  fully-classified device. The console auto-selects XR host for a Cisco 8000
  series router model or that agent install and hides every addressing field
  for it; the devices table, its filter, and CSV v2 (no new columns; the
  addressing columns stay empty) carry the same value, and the example CSV
  template documents it. Plans, receipts, and undeploy describe exactly what
  IRIS owns on the router — the appmgr application, its registered package
  source, the staged RPM, and the agent's working directory — and leave
  everything else, including the router's networking configuration, alone.
- Undeploy on IOS-XR routers is now bounded, idempotent, and provenance-aware.
  Every command session to the router runs under a wall-clock bound,
  `IRIS_XR_SESSION_TIMEOUT` (default 150 seconds; 0 disables it), on top of
  SSH keepalives, so a wedged router yields a failed job with a real exit
  code instead of an unbounded run. Teardown composes at most two such
  bounded sessions per run: a read-only session that probes the appmgr
  application table and unconditionally deactivates the application, and a
  second, destructive session (uninstall, file removal, sidecar sweep, and
  final verify) that is only ever composed once the first session's
  deactivate has been adjudicated by pairing it against that same early
  probe, rather than trusted on its own reported exit status; a still-
  running application after a rejected deactivate refuses to continue
  before anything destructive is sent. A teardown interrupted partway
  through converges cleanly on a second run, receipted or forced. The agent now records whether each
  staged image was downloaded by IRIS or adopted from a file an operator
  already staged, and an adopted (or legacy, origin-unknown) file is never
  deleted by teardown or by the agent's own cleanup paths, except when the
  catalog republishes different content under the same image id, which
  replaces the file and logs the replacement. Both `APPID` and
  `SOURCE_NAME` overrides are now escaped before they build the router-table
  and file-listing match patterns those steps use, so a name containing a
  regex metacharacter (for example `iris.x`) can no longer loosen a match
  into an unrelated table row.
- `tools/check-package-freshness.sh` now also covers the XR RPM
  (`iris-xr.rpm`), previously left for an operator to check by hand: it
  cannot unpack the RPM the way it unpacks the two IOx tars' inner archive,
  so it compares the RPM's build time against the moment the live catalog
  certificate came into existence instead of inspecting pinned contents, and
  says so plainly in its output. `tools/start-compose-server.sh` runs the same
  comparison at bring-up and warns when a staged `iris-xr.rpm` predates the
  certificate it just (re)provisioned, so a stale package is visible before
  a router is ever onboarded from it rather than only in a later manual
  check.

### Changed
- Image verification is now the same on every platform: the agent proves integrity by
  sha256 against the catalog's published value, and placement onto the boot filesystem
  is attested by exact byte size. The on-device `copy /verify` step is retired; device
  telemetry reports its state as `not_run`.
- **Terminology rename — management type, deployment record, peer transfer
  record:** renamed `attachment`/`network_attachment` to **management type**
  (`management_type`), deployment `receipt` to **deployment record**
  (`record`/`record_id`), and agent peer `receipt` to **peer transfer record**
  (`peer_transfer_records`) across the API, state files, env vars, UI, and
  docs. Breaking, no backward compatibility, in the same style as the
  device-neutral rename (#25): the server ignores any existing
  `deployment_receipts.json` and starts a fresh, empty
  `deployment_records.json` — operators re-adopt devices that already had a
  deployment record. The fleet.json `network_attachment` read-alias (and the
  matching CSV header alias) is gone; a row or export still carrying only the
  old key reads as unclassified until re-saved or re-exported. The
  `NETWORK_ATTACHMENT` env var is renamed to `MANAGEMENT_TYPE`; all six
  install/uninstall scripts that read it now abort with a clear error if
  `NETWORK_ATTACHMENT` is set but `MANAGEMENT_TYPE` is not, rather than
  silently falling back to the routed default. OTLP names changed
  (`iris.device.peer_receipt` → `iris.device.peer_transfer_record`,
  `iris.receipt.*` → `iris.transfer_record.*`, `iris.transfer.peer_receipts.*`
  → `iris.transfer.peer_records.*`); Splunk dashboards and saved searches
  built on the old names need updating, and the queries documented in
  `docs/zensical/telemetry-export.md`, `docs/zensical/observability.md`, and
  `docs/zensical/dashboards/README.md` already use the new ones. The
  published docs page moves from `/network-attachment/` to
  `/management-type/` with no redirect — a redirect stub is not just declined
  but impossible, because the nav-completeness gate forbids an orphan page
  and the docs workflow publishes with `force_orphan: true`. Device images
  and agent bundles must be rebuilt and republished (the peer-transfer hook
  script filename changed inside the XR RPM and IOx tars); an
  already-deployed agent keeps working against the new server, but the
  server drops its old `peer_receipts` key by allow-list reconstruction
  rather than rejecting it, so per-peer attribution is simply absent until
  that device is redeployed, and the agent's own persisted telemetry state
  carries the old key across its own upgrade too, discarding one in-flight
  transfer's already-measured peer data at that upgrade.
  `plan.resolved.attachment` is now `plan.resolved.management_type`, on both
  the plan/preview endpoint and the deployment-record response — any
  external consumer of `GET`/`POST /api/devices/<id>/plan` or `/deployment`
  breaks. The onboard-job-status routes break the same way: `GET
  /api/onboard/jobs` and `/api/onboard/jobs/<id>` now serve `record_id`
  instead of `receipt_id`, and the installer output streamed over a job's
  SSE log (`/api/onboard/jobs/<id>/stream`) carries the renamed wording
  (e.g. "deployment record" in place of "receipt") — a poller or scraper
  keyed on the old field name or matching the old log text breaks too.
  Audit detail wording changed for two events, adopting a device and
  retiring one (`device_delete`); existing `audit.jsonl` lines keep their
  original wording, so a saved search over audit detail for either event
  should match both the old and the new phrasing until the old entries age
  out.
- **Console facelift — Magnetic design system.** The operator console has a
  new visual design built on Cisco Magnetic tokens: Sharp Sans headings over
  Inter body copy, Roboto Mono reserved for machine-readable values (IPs,
  hashes, filenames, IDs, timestamps) and never for prose, a 4px spacing
  scale, and named elevation tiers in place of the previous dark theme. A
  light product-bar-and-nav-rail shell replaces the old chrome. Every status
  surface — the Devices table, Overview's attention cards, image
  verification, the Cisco Bulk Hash verdict — now renders through one shared
  icon-plus-sentence-case-label pill (`levelPillHTML`/`statusPillHTML`), so
  status is never carried by color alone. The Staging Boundary (Catalogued →
  Source checked → Assigned → Transferring → Verified → Staged, ending at a
  hatched "Operator control" terminus marking where IRIS's own
  responsibility stops — installation, activation, and reload stay with the
  operator) is now a first-class rendered component, shared verbatim by
  Overview and the device/image detail drawers. The device status
  previously labelled `deployed` now displays as **Staged**: the wire key is
  unchanged, only the rendered text moves to match the boundary's own last
  step. Setup is now a guided stepper with inline image verification in
  place of the old flat settings form. Devices-view polling is now owned
  solely by the hash router, removing a second, redundant 10-second
  `/api/devices` polling loop that ran unconditionally for the page's
  lifetime alongside the router's own view-scoped one. All console fonts
  are self-hosted under `server/webroot/fonts/`; Sharp Sans is licensed to
  Cisco and excluded from this source distribution, so the console falls
  back to Inter for headings when it is not staged separately. See
  `NOTICE` for full font/icon attribution.

### Fixed
- A dead tracker, catalog, artifact server, or console no longer leaves the
  server container reporting itself healthy. Those run as separate listeners, so
  `/healthz` — which answers 200 unconditionally, by contract, because container
  and orchestrator probes read the status code — only ever proved the metrics
  server was alive; under Kubernetes a pod whose artifact server had died stayed
  Ready and was never restarted, and devices failed at [5/7] with "cannot
  connect". A new `/readyz` endpoint connects to each expected listener and
  answers 503 naming the ones that are down, and the Kubernetes startup,
  readiness, and liveness probes now use it. Set `IRIS_HEALTH_LISTENERS` to
  `name:port,…` to change what is expected, or to `off` for a deployment that
  runs only some of the services.
- A freshly onboarded device no longer reports a transient rejected aria2 RPC
  token as a staging failure. Before bootstrap has copied the first refreshed
  RPC secret and bounced aria2c, aria2-next returns HTTP 400; IRIS now reports
  that short window as staging with an `ARIA2-AUTH` breadcrumb and no
  `stage_error`, while connection-refused and genuinely unreachable RPC still
  remain errors.
- Artifact downloads no longer serialize their TLS handshakes on the server's
  single accept thread. Handshakes now complete in per-connection workers under
  a 30-second bound, the listen backlog is 128, staging cleanup runs on a timer
  instead of on each GET, and every artifact access logs method, path, status,
  duration, and in-flight count. One stalled client can no longer block a fleet
  wave before worker threads are even created.
- IOS-XE sessions no longer send `enable` and its secret before knowing that the
  device is at user EXEC. On already-privileged devices the secret had been
  executed as a command and resolved as a hostname, adding about 48 seconds per
  session on a segment where that lookup black-holed. IRIS now learns the prompt
  emitted by the device, escalates only when required, and warns when IOS reports
  that any submitted line was resolved as a hostname.
- Persisted onboard and undeploy logs now prefix every captured line with its
  offset from the job start, making the slow phase visible without changing the
  live stream or line-matching contract. Guest Shell readiness polling starts at
  two seconds and ramps to fifteen instead of always overshooting by fifteen;
  first-contact probe budgets were raised to cover a genuinely slow SSH session.
- A device no longer needs manual re-onboarding when a catalog-token refresh
  commits on the server but its response or the device's atomic config rewrite
  is lost. The one previous token may now reissue the already-current secret
  bag on the same device's token-refresh route, without rotating again, until
  that previous token's original expiry. This recovery permission does not
  extend to heartbeat or telemetry, does not extend the short shared-route
  overlap, and is revalidated under the secrets-store lock so revocation and a
  newer rotation still win.
- A tick that refreshes the catalog token no longer ends in a spurious
  `%IRIS-6-HEARTBEAT-FAIL` HTTP 401. The refresh rewrote the conf and the
  local cfg but left the live catalog client on the pre-rotation bearer,
  which the server's heartbeat and telemetry routes reject even inside the
  120-second overlap window — so staging proceeded while the
  tick's closing heartbeat failed, once per refresh, since the first
  release. The refresh now re-points the client at the new bearer the
  moment the server mints it, on both the IOS-XE and IOS-XR builders, and
  it does so even when the conf rewrite then fails, because the server has
  already rotated by that point and the new token is the only one the
  device-bound routes will accept for the rest of the tick.
- The console no longer offers "auto by model" as an agent install. Picking it
  handed the decision to a model guess, which is how an IOS-XR router was sent
  down an install its hardware cannot run. The install is now chosen
  explicitly, and saving a device without one is refused with a clear message
  rather than resolved silently.
- The origin now seeds every published image instead of only the first five.
  A seeding torrent never completes, so each one permanently occupied one of
  aria2's five default concurrent-download slots and any image published after
  that was queued and never served. A device assigned such an image reported
  staging indefinitely with no error recorded anywhere, because aria2 reports a
  held-back torrent as waiting rather than as a failure. The same cap is lifted
  on every device-side launcher, where a device holding five staged images
  would otherwise never start a sixth transfer. Both limits are overridable
  (`SEED_MAX_CONCURRENT` on the origin, `IRIS_MAX_CONCURRENT` /
  `MAX_CONCURRENT` on devices).
- The seeder now reports how many published torrents it is holding back, as
  `queued_torrents` in the swarm observation and as the
  `iris_seeder_queued_torrents` metric. A non-zero value means the origin is
  refusing to serve a published image, which previously had no signal at all.
- IOS-XR undeploy no longer fails against a router it has just cleaned. The
  transport stripped a carriage return only where it sat immediately before a
  newline, but the router also emits one at the *start* of an output line, and
  that leading character defeated the anchored patterns the verify step uses:
  an empty `iris-work` directory was read as still holding artifacts and the
  teardown exited non-zero. Carriage returns are now stripped wherever they
  appear, which also closes the opposite risk of an end-anchored match missing
  a leftover sidecar file.
- XR RPM freshness is judged against the catalog certificate's own creation
  time rather than the modification time of a copy of it. The served
  `iris-catalog.pem` is restaged at every bring-up, so its mtime tracked the
  last staging rather than the certificate, and re-copying it alone was enough
  to report a current `iris-xr.rpm` as needing a rebuild. Both the Console's
  setup card and `tools/check-package-freshness.sh` now compare against the
  certificate's `notBefore`; when that cannot be read, the row reports unknown
  rather than falling back to the mtime.
- A forced router undeploy now reclaims the VirtualPortGroup, NAT ACL, overload
  rule and static mapping that IRIS itself created, identified by the description
  IRIS writes into every VPG it creates and by IRIS's own name on the NAT objects.
  Previously they were left on the device and onboarding refused the router until
  an operator cleared them by hand. Anything not carrying IRIS's mark is untouched.
- Device onboarding now reads the operating-system family from the `show version`
  banner. An IOS-XR device is refused with an explanatory error instead of being
  handed an IOS-XE recipe — previously an ASR 9000 matched the same `^ASR`
  prefix as an IOS-XE ASR 1000 and was onboarded as a Guest Shell device.
- The Devices management-type filter's "Inventory only — management type not
  chosen" option matched zero rows: every server path that creates an
  unclassified device writes the truthy string `management_type:
  "legacy_routed"`, and the filter's `d.management_type || 'legacy'`
  fallback only substituted `'legacy'` when the field was empty, which
  never happened. The comparison now normalizes `legacy_routed` to
  `legacy` before comparing, matching the row label's own equivalence; the
  filter option itself is unchanged.
- A device's status cell now shows its running onboard/undeploy job's
  current step and elapsed time (for example `Staging [2/5] · 4 min`)
  instead of a bare status word, so a long-running job reads as making
  progress instead of looking stuck.
- "Offline (expected during undeploy)" is now gated on the device's own
  undeploy job actually being in the `running` state, not merely on its
  status key reading `undeploying` — previously a device still queued
  behind the onboard concurrency cap could show the same "agent
  deactivated, no heartbeat expected" pill before its job had touched the
  device at all.
- Overview's attention band now shows "Fleet status unavailable" instead of
  a false all-clear "All clear" card when the device or image fetch it
  depends on fails — "no data to report a problem from" and "confirmed no
  problem" no longer render identically.
- A package absent for an architecture a deployment does not build (for
  example `iris-arm64.tar` on an amd64-only site) no longer rolls up to a
  persistent, uncleanable amber Warning in Settings > Setup and the setup
  wizard's package step; `absent` is now treated the same as `unknown` — an
  honest not-applicable, not a claimed gap the operator failed to fill.

## [2026.08.26]

### Added
- **Per-peer byte counts are measured again — by reading a counter, not by
  integrating a rate.** Release 2026.08.20 removed the per-peer `rx_bytes` /
  `tx_bytes` / `avg_bps` row fields because they were fabricated, and that
  ruling stands: under aria2 1.37 the client exposed nothing but an
  *instantaneous* per-peer rate, so the agent had to integrate that rate across
  its sampling interval to get a byte total, and on a transfer that finished
  inside a tick the result degenerated to an even split of the transfer across
  whichever peers happened to be connected. None of that machinery comes back
  here. What changed is the client underneath it: the device now runs
  aria2-next 2.5.6, which keeps a **cumulative per-peer session counter** for
  the life of the download (`peer->getSessionDownloadLength()` /
  `getSessionUploadLength()`, surfaced by `aria2.getPeers` as `downloaded` /
  `uploaded`). What ships is the client's own tally, read once. Per-peer bytes
  are back because the measurement now exists, not because the bar for calling
  something measured was lowered.
- **A completion hook on the device captures those counters at the one instant
  they are complete.** `device/agent/peer-receipt-hook.sh` is registered as
  aria2's `--on-bt-download-complete`, deliberately not the generic
  `--on-download-complete`. The BitTorrent hook fires the moment the last piece
  lands, immediately before aria2 flips the group to seed-only, so the peers
  that just fed the device are all still connected; the generic hook fires from
  the stop path, after seeding has *ended*, when those connections are long
  gone and their counters with them. The hook is POSIX `sh` and `curl` only —
  starting a Python interpreter would widen the race against peers hanging up —
  parses no JSON, embeds the RPC response verbatim into a sidecar next to the
  staged image, and exits 0 silently on every failure, because in daemon mode
  aria2 discards its hooks' output and an absent snapshot is an ordinary
  outcome. The next agent tick folds the sidecar into the terminal report and
  deletes it.
- **The v2 device report carries a `peer_receipts` block.** Each row is one
  peer still connected at completion: `ip`, `port`,
  `session_bytes_from_peer` / `session_bytes_to_peer`, and a
  `has_complete_file` flag (aria2's `isSeeder()` — it means the peer holds the
  whole file, and in a wave every device that finishes early sets it, so it
  identifies complete peers and never the origin). The totals are named
  `bytes_from_all_senders_total` / `_omitted` rather than "from peers" because
  that is what the device can honestly claim: the origin seeder is an ordinary
  BitTorrent peer of every device, it appears in the device's own peer list,
  and its bytes are inside that sum. Rows and bytes discarded at any cap are
  counted and summed into `rows_omitted` / `bytes_from_all_senders_omitted`
  instead of vanishing, and `complete` records whether the capture itself was
  lossy.
- **The server decides which sender was the origin, because only the server
  can.** Every receipt row is classified at ingest against the tracker's
  `service:seeder` principal and the server's device-address map into exactly
  one of `origin`, `device` or `unknown`; an address that matches neither — or
  that somehow matches both — is reported as unknown and is never folded into
  the peer figure. The classified totals ride the report record as
  `iris.transfer.bytes_from_origin_total`,
  `iris.transfer.bytes_from_devices_total` and
  `iris.transfer.bytes_from_unknown_total` alongside the device's own
  `iris.transfer.bytes_from_all_senders_total`. A peer-assist ratio computed
  from the all-senders total would have reported very nearly every rollout as
  100% peer-delivered.
- **The exact measurement now reaches an operator.** A new OTLP log record
  `iris.device.peer_receipt` carries one row per peer per completed transfer,
  with `iris.peer.attribution` (`origin` | `device` | `unknown`, always
  present) and `iris.peer.device.id` when the sender resolves to a known
  device. It is a distinct log name from the origin-side
  `iris.swarm.peer_bytes` on purpose: one is exact and one is sampled, and a
  backend must not be able to sum them into a single series by accident.
- **A durable peer ledger and its aggregate counters on `:9101`.** Tracing a
  byte to the device that received it has to happen *as it is observed*, and be
  persisted, because
  aria2's per-peer counter is per connection and disappears when the connection
  does — a counter nobody read before the peer hung up no longer exists. The
  ledger banks each edge's growth at every poll and exposes three counters and
  two gauges per torrent: `iris_origin_sent_bytes_total`,
  `iris_peer_attributed_bytes_total`, `iris_peer_unattributed_bytes_total`,
  `iris_swarm_peers_attributed` and `iris_swarm_peers_saturated`. The residue
  is kept as its own quantity rather than divided among the peers — measured
  against the origin's own `uploadLength` on a 7-router pull, a 3-second poll
  traced 73.3% of the bytes actually sent to a device and a 2-second poll
  88.1%, and spreading the remainder evenly would be arithmetic presented as
  observation.
  The saturation gauge exists so the residue stays readable once the ledger's
  per-torrent peer cap starts refusing peers.
  All five families are labelled `{image, info_hash}` and nothing finer: a
  per-peer label set would have made the cardinality of the origin's metrics a
  function of the size of the fleet. The three byte families are counters and
  not gauges on purpose — a rollout that finished an hour ago has to keep its
  history, and a board built on `increase()` over a counter still reports what
  a swarm did after the swarm has gone quiet, where a gauge would fall to zero
  the moment the last device stopped and blank every panel that had just
  proved the transfer worked. On a cold four-router pull of a 928 MiB image the
  ledger reconciled exactly: 3,492,982,720 bytes sent by the origin =
  3,227,913,693 traced to named devices (92.4%) + 265,069,027 untraced (7.6%),
  with no third bucket and nothing rounded to make the two sides meet. Operator
  wording throughout the boards and docs is *traced to a device* and *untraced*
  rather than *attributed* / *unattributed*, which said nothing to anyone who
  had not written the code; the metric and attribute names are unchanged, so
  `iris_peer_attributed_bytes_total` is still the traced total and
  `iris_peer_unattributed_bytes_total` still the untraced residue.
- **The dashboards that read these metrics ship with the code that emits
  them.** `docs/dashboards/grafana-iris-swarm.json` and
  `docs/dashboards/splunk-iris-swarm.xml` are reference boards for the swarm
  counters, kept in the repository beside `server/metrics.py` so that renaming a
  family is a change to one commit rather than a discovery an operator makes
  weeks later in front of a panel that has quietly read zero ever since. Both
  are built on the aggregate families alone, so neither depends on per-peer
  cardinality the origin does not publish. Every panel states in its own
  description whether the number behind it is measured, derived or estimated,
  and a panel whose input the server does not emit yet reads *No data* rather
  than falling back to a constant — a fleet total priced at a hardcoded 928 MiB
  is wrong the moment a differently sized image is selected.
- **An image can be assigned to the whole selection.** Assignment was per-row
  only, which does not scale past a handful of devices — and the filter bar
  exists precisely so an operator can act on a subset. An *image for selected*
  picker joins the credential one, drawing on the same catalog the per-row
  dropdowns use and running under the same selected-action lock, so a delete
  cannot fire mid-assignment. Unassigning is its own explicit choice rather
  than what an untouched picker does.
- **Every state the Status column can show can now be filtered for.** The
  filter derived its own status from a three-branch copy of the cell's logic,
  which knew `deployed`, `enrolled` and `not enrolled` and nothing else. The
  cell renders eleven states: a device reading `onboarding…`, `undeploying…`,
  `waiting for heartbeat`, `onboard failed`, `undeploy failed`, `placement
  failed`, `copying to bootflash:` or a raw staging state could not be selected
  at all, and asking for `enrolled` silently swept several of them in — with a
  comment above the copy claiming the two could never disagree. There is now
  one derivation, returning the key, the label and the badge class together,
  and the Status options are generated from the same list, so a state cannot be
  renderable but unfilterable. `offline` stays a separate choice, being a
  modifier on top of the cell rather than one of its branches.
- **Deployment details open in a drawer beside the table, not below it.** The
  ⓘ panel was appended under the devices table, so on a fleet of any size
  opening it put the content off-screen and made the operator scroll away from
  the row they had just clicked to read the answer. It now slides in from the
  right like the deployment-log drawer, closes on Escape or ✕, and honours
  `prefers-reduced-motion`.

### Fixed
- **A device deleted and added back under the same id could be neither
  onboarded nor undeployed.** Deleting a device purges every per-device store
  the console owns — the image assignment, the heartbeat record, the telemetry
  ring, the pending pull directive, the seen-report ledger — and revokes the
  device's credentials. It never touched the deployment receipts, and there was
  no API on the receipt store to touch them with. A receipt is matched to a
  device by `device_id` alone, so the next device registered under that id
  inherited its predecessor's deployment. That is not a cosmetic leak: onboard
  refuses while a recoverable receipt exists (`router already has a
  needs-reconcile deployment receipt; undeploy it before onboarding again`),
  and the undeploy it names refuses the box, because the receipt records the
  board ID of the machine that is gone (`device identity mismatch; refusing to
  modify …`) — a rebuilt VM keeps its id and its address but not its identity.
  Onboard pointed at undeploy, undeploy pointed at hardware that no longer
  existed, and delete cleared neither. Deleting a device now marks its receipts
  `abandoned`, a new terminal state that is deliberately neither `removed`
  (which asserts IRIS tore the deployment down) nor `superseded` (which asserts
  a newer receipt replaced it). The rows are kept, not dropped — a receipt is
  the only list of what IRIS built on that box, the VirtualPortGroup, the NAT
  stanza, the app address, and an operator who deleted a still-configured
  device is exactly the person who needs it — but they no longer authorise a
  teardown or block an onboard. The delete audit line names the outcome the way
  it already named the revoked secrets and the retained endpoints, and the
  console's delete confirmation says so before the fact.
- **A hung onboard job kept its own device busy until the deadline expired.**
  The reaper that fails a job past `IRIS_ONBOARD_JOB_TIMEOUT` ran *after* the
  busy guard in `start()`, past every path that returns or raises — so it could
  only ever fire during a start for some other device, never the one actually
  stuck. The device it was stuck on stayed refused for the full two-hour window
  with no console action able to clear it. The reap now runs first. It also
  goes through the ordinary finish path instead of half-writing the record
  itself: it used to set an `rc` key that no reader looks at (they all read
  `returncode`), leave the installer handle in the process table, write no
  persisted log, and emit no `*_finished` audit event — a job could fail with
  nothing anywhere saying so.
- **Deleting a device left its in-flight jobs running.** A job record is keyed
  on the bare device id, the same way receipts were, so one left behind kept
  the busy guard armed against the *next* device registered under that name:
  the opposite action was refused, and the same action silently joined the dead
  job, which reads as a click that did nothing. Delete now cancels the device's
  queued jobs and signals a running installer, and says how many it stopped in
  the audit line.
- **Deployment logs from a deleted device were shown as its replacement's own
  history.** Persisted logs are keyed on the device id and deliberately outlive
  a delete — they are the record of what actually ran, and dropping them to fix
  an attribution problem would be the wrong trade. A device row now carries
  `registered_at`, stamped once when the id is first registered and carried
  across edits and CSV re-imports, and `GET /api/deploy-logs?device_id=…` flags
  every entry that finished before it. The console labels those runs *previous
  device* rather than hiding them: the run happened, it just happened to a
  different machine. A device registered before the stamp existed has none, and
  nothing is flagged for it — guessing would be worse than saying nothing.
- **A forced undeploy was refused in the one situation it exists for.** `force`
  was consulted in a single expression, `if receipt is None and not force`, so
  it applied only when there was no receipt at all. A device whose receipt no
  longer matched the box — the case above — has a receipt, so the flag was read
  and then dropped, the full receipt-driven teardown ran, and the recipe's
  identity guard refused it. The rescue path was unreachable from the state it
  was built to rescue, and the checkbox that offered it was labelled for the
  other case. `force` is now decided before the receipt is read at all, which
  also makes it the way out of `multiple recoverable receipts for device …` —
  a state that refused onboard, undeploy and adopt alike, that a controller
  restart could create, and that nothing in the product could resolve. Once the
  forced teardown succeeds, every receipt the device still held is abandoned,
  so the next onboard is not refused on the receipt the force was run to get
  past; on failure they are left alone, because failing to reach a device is
  not proof that its receipt is wrong. The checkbox is relabelled *Force (no
  usable deployment receipt)* and its note describes both cases.
- **`device identity mismatch` named no way forward.** Refusing to tear down a
  box that is not the one the receipt was written for is correct. Saying only
  that, to an operator whose onboard had just told them to undeploy, was not.
  The message now reports both board IDs and names the two ways out: undeploy
  again with Force, or delete and re-add the device.
- **Retrying a failed undeploy answered with nothing at all.** The 409 path for
  a receipt that cannot authorise teardown marks that receipt `needs-reconcile`
  on its way out — including when it is already `needs-reconcile`, which is not
  a legal transition. Raised from inside an `except` handler with no blanket
  handler above it, that escaped the request entirely: the first attempt
  explained itself and every attempt after it dropped the connection. Both that
  handler and the matching one on the full-work-queue path are now best-effort.

### Known limitations
- **A peer-receipt total is a floor, not a census.** The hook can only read
  peers aria2 still holds a live connection to, and `DefaultPeerStorage` erases
  a peer from `usedPeers_` the instant it disconnects. A peer that delivered
  several hundred megabytes and then dropped before the final piece landed
  leaves no row and contributes no bytes — its share is silently absent, not
  recorded as zero — so the receipt totals will not reconcile with
  `content.completed_content_bytes`. Bytes lost to a *cap* are reported; bytes lost to a
  disconnect cannot be.
- **Tracing a byte to a device is sampled, and sampling misses bytes.**
  `aria2.getPeers` answers with the connections that are live at the instant it
  is called, so a peer that connected, took its bytes and hung up between two
  polls was never visible to the ledger at all. Measured against the origin's
  own `uploadLength` on a seven-router pull, a 3-second poll traced 73.3% of
  the bytes the origin actually sent and a 2-second poll 88.1%. The untraced
  remainder is published as `iris_peer_unattributed_bytes_total` instead of
  being smoothed away, because it is a real quantity — bytes that certainly
  went to somebody —
  and dividing it among the peers that happen to still be connected would print
  arithmetic where the panel promises an observation. A shorter poll interval
  leaves less untraced; nothing closes the gap.
- **`iris_image_size_bytes` is published from the catalog.** The shipped
  dashboards ask for it by name to turn delivered bytes into a share of the
  image, and it now republishes the catalog entry's own `size` field — exact,
  recorded from the file itself at publish time, never inferred from traffic.
  It was briefly specified-but-unemitted; in that state the boards read *No
  data* deliberately rather than falling back to a textbox default or an `or
  vector(...)` — a confident progress figure computed from a number nobody
  measured is worse than an empty panel. An image with no published catalog
  entry still reads *No data* today, for the same reason.
- **First-run setup is a guided flow, and Settings > Setup keeps reporting the
  same state afterwards.** A stepped wizard at its own top-level view walks
  telemetry destination, stage host and device packages, with the admin
  account shown as already complete because first-run has just created it.
  The forms are hosted in the flow rather than linked to, so completing setup
  no longer bounces the operator between Settings pages; a step list shows
  every step's state and any step can be opened directly, which matters
  because a step already satisfied by the deployment environment (a telemetry
  destination from `IRIS_OTLP_ENDPOINT`) would otherwise be skipped past and
  read as missing. Every step can be skipped and the wizard resumes at the
  first incomplete one — necessarily, since the device-packages step can never
  be completed from the console at all: the container has no Docker socket, so
  it can detect a stale package but not rebuild one, and that step is shaped as
  detect-and-instruct rather than as a form whose submit button would be a lie.
  A banner brings the operator back while anything is unfinished, dismissed for
  the session only, because a package that goes stale later is a silent
  regression and a permanently dismissed banner would hide exactly the failure
  this catches. The telemetry and stage-host forms live in one template cloned
  into whichever surface is showing, so there is a single implementation of
  each. First-run sign-in hands off to the flow. Settings > Setup survives as
  the status panel — four cards, admin included — and its actions now enter the
  flow. The package card catches a certificate-drift
  failure mode with no other symptom: `GET /api/settings/setup-status`
  (session-gated) is backed by `server/setup_status.py`, which fingerprints
  the certificate this server currently serves (`IRIS_CERT`, reading only
  the leading certificate block so the combined cert+key file parses), the
  certificate handed to devices at onboard time (`iris-catalog.pem` in the
  artifacts directory), and the certificate baked into each served IOx
  package (`iris-amd64.tar`, `iris-arm64.tar`) at build time — streaming the
  ~60 MB package's inner archive instead of unpacking it. This matters
  because an IOx package pins the catalog certificate at *build* time: if
  the certificate later changes, a device installed from that package still
  installs, its app still reports RUNNING, and it silently never checks in
  again — the only evidence is a `TOKEN-REFRESH-FAIL` line in the device's
  own syslog, with nothing server-side to distinguish "never onboarded" from
  "onboarded but rejecting our certificate." Guest Shell platforms are
  unaffected, since their artifacts (including the certificate) are
  regenerated at every container start. Each package's state
  (ok/stale/absent/unknown) rolls up worst-of, so a stale package is never
  masked by a merely unknown sibling; the top-level state is separately
  demoted to unknown — without masking a worse stale finding underneath —
  when the served and distributed certificates disagree or the distributed
  copy can't be read, and a mismatch gets its own console guidance rather
  than the rebuild remedy, since rebuilding packages does not fix a
  disagreement between what this server serves and what it told devices to
  trust. A failed or thrown status fetch repaints every chip to "cannot
  determine" instead of leaving a stale "done" on screen.
- **`tools/check-package-freshness.sh` puts the same certificate-drift check
  on the command line.** Read-only: it fingerprints the certificate the
  catalog currently serves, the certificate handed to Guest Shell devices at
  onboard time, and the certificate pinned inside each built IOx package,
  and reports any package whose pinned certificate no longer matches,
  exiting 1 on drift. `--rebuild` re-runs `tools/provision-iox-packages.sh`
  and re-checks. It never touches a device.

### Changed
- **Every platform now runs the same collision preflight.** It used to run for
  routers only: `preflight()` returned "not-required" for anything else, IOx
  resolved a device identity and nothing more, and Guest Shell did no more than
  a reachability ping. The same device still carrying IRIS configuration was
  therefore refused as a router and silently accepted as the other two. The
  IRIS-named collisions — the EEM applets, the IRISQ discriminator and its
  logging bindings, `crypto pki trustpoint IRIS`, `ip http client
  secure-trustpoint IRIS` — move into one shared set that every platform
  checks, and each keeps what is genuinely its own: the router its Catalyst
  8000 gate, VirtualPortGroup collision, app-subnet overlap and NAT interface
  check; Guest Shell the guest-share emptiness check; and each its own
  app-hosting stanza, `guestshell` on one and `iris` on the other. IOx
  consequently probes running-config and the app list alongside `show version`,
  over the single-login marker channel the router already used; what it reports
  about identity is unchanged. On Guest Shell the reachability probe stays
  ahead of the collision check deliberately — an unreachable device is far
  commoner than a collision, and "preflight could not run" tells an operator
  nothing about which of the two to go and look at. Paired with the teardown
  change above, undeploy now clears exactly what preflight refuses.
- **Telemetry export health moved from Monitoring to the Overview dashboard.**
  Monitoring is the audit trail and the deployment logs; a telemetry-export
  badge in its heading described something that page has nothing to do with.
  It refreshes with the Overview, and is deliberately not awaited alongside the
  overview fetch so an unreachable collector cannot hold up the cards.
- **The devices table can be filtered, and bulk actions act on the filter.**
  Every meaningful column gets a filter — free text across device, IP and
  model, plus management type, platform, credential, telemetry, peer policy and
  status — and only matching rows are rendered, so filtering and then "select
  all" is how an operator acts on a subset instead of hand-picking rows out of
  the whole fleet. The filter predicate reuses the same derivations the row
  renderer uses, so a filter can never disagree with the cell being read.
  Quarantine and release join the other bulk actions under the same
  selected-action lock; because the peer-policy API is one device per call and
  carries a revision, they run in sequence carrying it forward, and a losing
  race re-reads the policy once rather than stamping a stale revision over
  someone else's change.
- **The deployment logs get the audit page's time filter, not a picture of
  one.** `GET /api/deploy-logs/histogram` bins logs into buckets over a window,
  mirroring the audit histogram's semantics including the `since_ts`/`until_ts`
  brush window, and `GET /api/deploy-logs` now accepts `after_ts`/`before_ts`
  so a selection narrows the list. The console gains range chips, a
  server-binned histogram and a brush with edge handles, panning and
  click-to-clear; the timeline and the table refresh together, or a selection
  would move the bars while the rows below still showed the old range. Search
  covers device, action and result with action and result pickers, results are
  paged, and a log opens in a right-hand drawer — closed on Escape, its slide
  dropped entirely under `prefers-reduced-motion` — so the list stays where the
  operator left it instead of being pushed off screen.
- **Router preflight for `POST /api/devices/<id>/onboard` now runs once, in
  the bounded worker pool, instead of twice.** It used to run synchronously
  before the HTTP request returned, and then again inside the queued job
  right before minting — necessary because a delayed job can still be
  invalidated by a change made after the first check ran — so a large batch
  submission sat through serial SSH round-trips to every selected router
  before any job ID came back, while the blocking check at submit time
  changed nothing about whether the worker's own check still had to run.
  The route now records the preflight as pending and returns immediately, so
  a batch shows queued progress right away, and a preflight failure is
  reported as that individual job's own error with an actionable log line
  instead of rejecting the request or blocking unrelated routers behind it.
  Preflight itself is also cheaper to run: its four commands (five when NAT
  attachment adds an outside-interface check) now travel in one
  `lab/device-run.sh` session instead of one SSH login per command, using
  IOS XE's own command echo as a marker to split the single response back
  into sections.
- **The read-only pre-check and verify passes in the install/uninstall
  recipes now cost one device login instead of several.** The flash/routing
  /clock pre-checks in `device/device-install.sh`, the `show iox` readiness
  check in `device/iox/install.sh`, and the running-config/app-hosting/
  file-listing verify block in both `device/router-install.sh` and
  `device/router-uninstall.sh` each used to open a separate SSH session per
  command; every command in a group now travels in one session, split back
  into sections on IOS XE's own command echo. A missing section is still
  treated as a hard transport failure, never read as an empty, safe result.
  State-gated polling and retry loops — for example the IOx readiness poll,
  which still re-observes live state on every iteration — are unchanged:
  only the repeated read *within* a single observation was collapsed, never
  the polling itself.

### Fixed
- **The console never refreshed a view on its own.** `setInterval` appeared
  nowhere, and the only live mechanism was a per-job `EventSource`, so a view
  updated on navigation or after an explicit action and at no other time —
  device state that changes server-side (heartbeats, staging progress,
  deployment state) stayed invisible until the operator navigated away and came
  back. `refreshDevices()` had even been written to preserve batch checkbox
  selections "across the periodic re-render" that never existed. Each view now
  names the refresh its poll repeats; Settings is excluded, being a set of
  forms that re-rendering under the cursor would clear, and a hidden tab skips
  its tick and refreshes on return.
- **The setup nudge could never hide.** `.nudge { display:flex }` is a class
  selector and outranks the user-agent stylesheet's `[hidden] { display:none }`,
  so setting `hidden` changed nothing on screen; because the code returns before
  rewriting the text once the outstanding count reaches zero, a fully configured
  server kept displaying a stale "1 setup step still needs attention". `.badge`
  had the same shape, leaving the telemetry-health badge as an empty pill until
  its first refresh. Both are now pinned back to `display:none` when hidden.
- **An audit row read "onboard started undeploying &lt;device&gt;".** The
  category chip labels the subsystem, but it sits immediately before the verb
  phrase, where a sentence's subject goes — and one service runs both onboard
  and undeploy jobs, so the category legitimately is `onboard`. The stored value
  is unchanged, being persisted in the audit trail and driving the category
  filter; only the label an operator reads becomes "deployment", which is true
  of both actions.
- **An outbox ack watermark above the policy document's own revision is now
  treated as impossible and ignored, instead of being honored.**
  `last_operation_exported_revision` is persisted in the enforcement status
  file, separately from the policy document itself, so a document restored
  or reset after a lower-revisioned backup can sit below a watermark that
  was written for an older, higher-revisioned document. Honoring that
  watermark was doubly destructive: `pending_exports` selects
  `revision > acked`, so it suppressed every export outright, and the next
  commit's pruning step then silently discarded every unacknowledged outbox
  entry. `server/peer_policy.py` now sanitizes the watermark against the
  document it is applied to and falls back to 0 — nothing counts as
  acknowledged, and the entries re-export — whenever the watermark exceeds
  the document's own revision, is not a non-negative integer, or the
  document itself carries no usable revision.
- **A live telemetry withdrawal now records the reason the server actually
  has, instead of flattening every cause to `not_active`.** The heartbeat
  handler in `server/catalog.py` called the live table's withdrawal with no
  reason on every policy-driven withdrawal, so the `disabled` and `paused`
  states a device genuinely reports for its own master toggle or a stream
  pause could never appear in a live sample or in `/api/swarm` — every
  withdrawal read as `not_active` regardless of cause. The reason is now
  derived from the server's own flags, in the same precedence the agent
  itself uses (master toggle first, then stream-off or a global pause, then
  `not_active` for a device that lost its assignment), and never from the
  device's own claimed `obs_state` — a device claiming `observed` while the
  server has it disabled is still recorded as `disabled`.
- **A forced undeploy now works at all, on every platform.** It is the only
  exit for a device that cannot be undeployed (no receipt), cannot be adopted
  (routers never are) and cannot be re-onboarded (preflight refuses the live
  agent) — and it had never once run end to end. The flag never left the
  server: `OnboardService.start()` received the console's extra environment
  only for the *onboard* action, while `IRIS_FORCE_AGENT_ONLY` is set only in
  the *undeploy* branch, so no teardown recipe ever saw it. On Guest Shell and
  IOx that was not a failed rescue but a destructive one — the full teardown
  ran, removing `Vlan$VLAN` and the VLAN itself from an inventory row no
  receipt has proven, while the audit trail recorded that the operator's
  network had been left untouched. Undeploy now carries its own environment,
  so the telemetry flags stay onboard-only and the force flag reaches the
  recipe.

  On routers the recipe then refused to run: the processor-board identity
  guard sat outside the force branch and compared a live board ID against the
  empty `EXPECTED_DEVICE_IDENTITY` that force mode deliberately does not
  require, aborting every time before touching the device. Two residue scans
  then failed a teardown that had already succeeded — one flagging the IRISQ
  discriminator and PKI trustpoint that only `config_cleanup` removes, the
  other the NAT rules force preserves, whose ACL pattern collapsed to the bare
  prefix `ip access-list standard IRIS-NAT-` and matched any other group's ACL
  once no receipt supplied a VPG number. Both failed *after* the destructive
  work and *before* `copy running-config startup-config`, leaving a reload to
  undo whatever had succeeded.

- **What a teardown removes is now decided by name, not by mode.** Every
  IRIS-named artifact — the EEM applets, the IRISQ discriminator and its
  logging bindings, `crypto pki trustpoint IRIS`, `ip http client
  secure-trustpoint IRIS`, the app-hosting stanza and the staged files — is
  removed in every mode, including force and inband. Previously those were
  preserved whenever the mode was inband or forced, on the reasoning that a
  receipt cannot prove such globals remain uniquely IRIS-owned; that does not
  survive contact with the names, and it left a "clean" device refusing its
  next onboard on artifacts IRIS had put there itself. What the modes protect
  is the operator's *network* — the VLAN and its SVI, the VirtualPortGroup,
  the NAT rules — which IRIS merely configured and no receipt proves it
  created. That distinction is preserved exactly, and the verify scans follow
  the same rule: what is removed in every mode is checked in every mode.

### Documentation
- The public site's copy now speaks to Cisco images and patches generally
  instead of IOS-XE alone, describes Guest Shell and IOx staging in
  platform-neutral terms ("device storage" rather than naming `flash:` /
  `sdflash:`), renames the platform tabs to "Catalyst 9000" and "Industrial
  Ethernet," adds a "Catalyst 8000" tab for router Guest Shell over a
  VirtualPortGroup, and drops the standalone ports table and its filter
  buttons.

## [2026.08.22]

### Added
- **Every tracker and catalog credential resolves to a typed principal.** An
  identity is a `(type, id)` pair — `device:<id>`, `service:seeder` or
  `legacy` — so a device registered under the name `seeder` and the seeder
  service are distinct identities instead of one colliding key. The swarm
  registry keys peers by `(principal type, principal id, peer_id)` and
  excludes a requester from its own results by that full key; swarm
  snapshots and telemetry events carry `principal_type` /
  `participant_class` alongside the existing peer fields.
- **The tracker takes its credential from a dedicated `announce_token=`
  query parameter, and the existing `key=` value keeps working.** A single
  valid legacy `key=` is still accepted, so devices holding an older torrent
  keep announcing. This upgrade migrates nothing and revokes nothing: old
  and new credentials are both valid, and retiring one is a separate
  operator decision. A rotated-out seeder token announces as an unattributed
  `legacy` participant — it is not recorded as an endpoint and cannot be
  quarantined individually. Two `announce_token=` parameters, or two
  different valid `key=` values, are ambiguous and refused with a 403 whose
  body carries no token, URL or query string.
- **`GET /v1/torrents/<image>.torrent` returns a per-device torrent.** For a
  device principal the catalog builds the response in memory with an outer
  announce carrying only that device's announce token, copies the raw `info`
  byte span verbatim so the info hash does not move, and marks the response
  `Cache-Control: private, no-store` with `Vary: Authorization`. A device
  with no valid announce credential gets a 500 and no torrent — it is not
  handed the shared seeder token as a fallback. Service principals still
  receive the canonical file unmodified.
- **A deployment gate for a first identity-compatible rollout.**
  `IRIS_REQUIRE_IDENTITY_GATE=1` makes the catalog answer 503 to every
  personalized (device-principal) torrent request until the checkpoint file
  `<IRIS_STATE>/identity-compatible-ready` exists — the file a proven seeder
  rotation writes and `--recover` removes. The checkpoint is read per
  request, so opening or closing the gate needs no restart, and the
  canonical (service) torrent path is unaffected. The variable is off by
  default; a deployment that does not set it serves personalized torrents as
  before.
- **Peer policy decides which peers the tracker will introduce to each
  other.** ACLs and per-device assignments live in
  `<IRIS_STATE>/peer-policy.json` with a last-known-good copy beside it. A
  candidate peer is returned only on a mutual permit — each side's assigned
  ACL is evaluated against the other peer's principal and address. With
  neither file present the tracker materializes a validated base document
  and discovery stays open, so an existing deployment behaves as it did
  until an operator assigns something. A corrupt authoritative file falls
  back to the last-known-good copy and reports `degraded`; with both files
  corrupt the tracker fails closed, which here means it returns no candidate
  peers at all.
- **The tracker is the only process that writes the aria2 peer blocklist,
  and its status file carries counts only.** A single serialized reconcile
  loop recomputes the denied set each pass from durable policy, the endpoint
  map (`<IRIS_STATE>/peer-endpoints.json`, written on an authenticated
  announce from an attributable principal, TTL via `IRIS_ENDPOINT_TTL`), the
  live registry and the credential-revocation view, then full-replaces the
  blocklist over aria2 JSON-RPC. Status is written to
  `<IRIS_STATE>/peer-enforcement.json` as a denied-address *count* — the
  addresses themselves are neither stored nor exposed, so this file cannot
  tell you whether one particular peer is blocked. An `enforced` state is
  written only when both a current aria2 session id and a desired-set hash
  are present.
- **Quarantine a device from the console.** The devices table gains a *Peer
  policy* column showing the per-device quarantine intent and the tracker's
  last enforcement state, backed by `GET /api/peer-policy` and
  `PUT /api/peer-policy/quarantine/<device>`. Because enforcement status is
  count-only, the column reports intent plus the tracker's overall state,
  not per-address proof that a given peer is blocked. The mutation is
  optimistic: it carries the policy revision it saw and returns 409 with the
  current revision if policy changed elsewhere, so a concurrent edit is
  reported rather than overwritten. The confirmation dialog states what the
  action does and does not do — it changes peer discovery and the server
  seeder across all torrents, may not tear down sessions already
  established, and installs or reloads nothing on the device. The swarm view
  warns when legacy unattributable participants are present, since those
  cannot be quarantined individually.
- **Policy mutations are recorded in a bounded outbox the tracker drains.**
  Each committed mutation appends a stable outbox entry carrying the revision
  it produced, and the tracker reports how far it has consumed through
  `last_operation_exported_revision` in the enforcement status file; entries
  at or below that watermark are pruned on the next commit. The outbox is
  capped at 256 unacknowledged entries and the cap is checked *before any
  write*, so a stalled consumer blocks new operations with a 503
  `operation_backlog_full` rather than silently discarding them. The same
  route separates its other refusals: 409 `revision_conflict` carrying the
  current revision, 422 `policy_error` for a degraded policy, and 503
  `policy_fail_closed` when policy itself is fail-closed.
- **`rotate-seeder-announce`: one supported command for rotating the seeder
  announce credential.** `server/rotate_seeder_announce.py` ships executable
  in the server image and performs the whole rotation. It takes
  `--maintenance-frozen` (required — it acknowledges a maintenance freeze
  the operator has already put in place; the command never creates one),
  `--state`, `--secrets` and `--manifest`. Preflight reads the catalog,
  binds every published image's canonical torrent to exactly one active
  aria2 GID, and refuses before touching anything if an image has no
  canonical torrent, is not uniquely active, the announce base is not a
  private HTTP URL, durable encrypted-secrets configuration is missing, or a
  recovery manifest from an earlier run is still on disk. The new credential
  is persisted encrypted-at-rest before any torrent byte changes; each
  replacement rewrites only the outer announce and keeps the `info` byte
  span SHA-1 identical, so info hashes do not move. Credential values are
  never accepted on the command line and never printed — a failure reports
  an exception class only. Rotation keeps the previous credential valid and
  does not revoke it; at most two valid previous records are allowed and a
  rotation that would exceed that is refused. Revoking a previous record is
  library-level support in this release — no shipped command performs it.
- **A rotation is reported complete only when the tracker independently
  proves the new identity is serving.** After every canonical torrent has
  been re-added, the command polls the tracker's loopback `/swarm` (up to
  three attempts, 2 s timeout each) and requires the current typed
  `service:seeder` principal to be observed for every expected info hash,
  each with an announce strictly later than the post-add boundary; the
  origin's own observation must show aria2 RPC up with exactly those
  torrents in control state, and no legacy or unattributed seeder row for
  them. A completed device peer does not stand in for that proof. Anything
  else — transport error, timeout, or a document that does not prove it —
  fails closed, which here means serving is not claimed, the maintenance
  freeze stands, the recovery manifest is preserved, the command exits 1,
  and no previous credential is revoked.
- **Byte-safe failure handling with a per-torrent damage report.** Every
  rotation writes a nonsecret recovery manifest before it starts
  (`<state>/seeder-rotation-recovery.json`, with exact pre-rotation torrent
  copies and SHA-256 digests under `<state>/seeder-rotation-recovery/`) and
  updates its phase per torrent. If an add fails, the exact old bytes are
  restored and the old torrent is re-added. If that re-add also fails, or if
  a remove fails and the live state is therefore unknown, the run enters a
  hard no-go: old bytes are restored for every torrent already rotated in
  this run, the remaining torrents are abandoned, maintenance stays frozen,
  and the run does not claim the image is still being served. A hard no-go
  can leave an image not being served and needing manual repair — the result
  lists every disturbed torrent with `restore_readd_ok`, and a `false` there
  means serving repair is still required for that image. Rollback removes
  the live GID aria2 returned for the new torrent, and an add that returns
  no GID counts as a failure rather than a success.
- **`--recover` restores the exact pre-rotation state from the manifest.**
  It rejects a manifest that is not version 2, is already terminal, points
  at backup or canonical paths outside their own directories, carries a
  digest or info hash that does not match its backup bytes, or names an
  image directory that disagrees with the current catalog — all before any
  file or aria2 call. It then clears the identity checkpoint, restores the
  original bytes, force-removes any active GID for that info hash, re-adds
  the original torrent and checks the result through `aria2.tellStatus`.
  Recovery leaves maintenance frozen and keeps the manifest as evidence in
  either outcome; if any step fails the manifest is marked `repair_needed`
  with the unrestored torrents flagged and the command exits 1.
- **Durable, identified device transfer reports.** Every acquisition cycle
  carries a random `transfer_id` and every terminal report a random
  `report_id`. The agent freezes the complete report body in its state file
  and checkpoints it (tmp + fsync + rename) *before* the first POST, so a
  retry after a crash sends the byte-identical report and the server stores
  it once; identity and sequence facts are persisted the same way before a
  heartbeat that carries them, and if that write fails the agent skips only
  that piece of telemetry — the heartbeat still goes out and staging is
  untouched. The report replaces the old `avg_bps` / `sha_ok` fields with
  two independent verification facts recorded at the moment each decision is
  made — `content_sha256` (`verified` | `mismatch` | `not_checked`) and
  `ios_copy_verify` (`ok` | `failed` | `not_run` | `unsupported`) — plus
  content bytes at end of window, split heartbeat/report failure streaks,
  catalog RTT and a bounded participation peer list carrying first seen,
  last seen and observation count per address. Neither verification state is
  inferred from "done" or from absence: an unchecked hash is reported as
  `not_checked`, not as a failure.
- **Live transfer observations carry an explicit state.** The v1 `sample`
  embedded in the heartbeat is superseded by a `telemetry_observation`
  envelope whose `obs_state` is one of `observed`, `not_due`, `paused`,
  `disabled`, `not_active` or `rpc_unavailable`. Only `observed` carries
  aria2 counters, per-connection peer rows and a sampling class; a
  state-only envelope carries no transfer numbers at all, so "we are not
  measuring right now" is distinguishable from "the rate is zero".
  Per-connection rows carry the measured send/receive rate, port, client
  name and progress, and a value aria2 does not report is omitted instead of
  being sent as a measured zero.
- **Pull requests are identified, and repeat reports are recognised.** A
  console-requested report mints a `request_id` that rides in the heartbeat
  response and is echoed by the device; clearing the pending request is
  match-gated, so a stale or superseded report cannot clear a newer request.
  On the server a bounded per-device ledger (`report_ledger.json`, 256 ids
  per device, oldest purged first) backs the five-report ring, so a retry of
  a report that has already aged out of the ring is still recognised as a
  duplicate. The ledger is deleted with the device.
- **New Prometheus and OTLP families.** Per-torrent seeder control state
  (`iris_seeder_torrent_upload_length_bytes` /
  `iris.seeder.torrent.upload_length`), a rollout-progress gauge
  (`iris_legacy_announce_participants`, the number of legacy unattributed
  announcers currently seen), numeric peer-policy and enforcement gauges
  (revision, applied revision, denied-address count and a single health
  gauge), and per-signal export accounting —
  `iris_telemetry_export_failures_total`,
  `iris_telemetry_export_dropped_total` and
  `iris_telemetry_export_last_success_seconds`, each labelled by `signal`.
  None of the new families carry a device, peer or report label.
- **The Images screen says where to put images for server-side import.** A note
  above the import table names the import root — `/opt/images` by default, or
  wherever `IMAGES_ROOT` points — and gives `/opt/images/iosxe/c9300/` as an
  example. It is always visible, because the import table itself is hidden when
  nothing is importable, which is exactly the moment an operator needs to know
  where files belong.

### Changed
- **`/swarm` is now a typed, source-grouped document, and consumers of the
  old flat shape will break.** Every value sits under a named source with
  its own observation time: `server` carries the origin's own observation
  (RPC state, global rates, per-torrent control-state upload gauge and
  current upload rate, aria2 session id, and the tracker's typed view of the
  service seeder with a per-info-hash last seen), and each
  `images[].peers[]` row carries `tracker` (principal type/id, role, left,
  last seen, progress) plus, when known, `device_observation`,
  `latest_report`, a measured `server_observation.peer` send rate,
  `peer_policy` and `peer_enforcement`. Device attribution joins on the
  authenticated device principal id only — never on the announce source IP —
  so a row on a legacy credential is marked `legacy_unattributed`, gets no
  device identity and no per-device quarantine control. The current
  non-legacy service seeder is deduped out of the peer rings and appears
  only as `server`. The former top-level `host` / `seeder` objects and the
  IP-joined peer fields are gone.
- **The live transfer metric families were reworked, and the ambiguous ones
  retired.** `iris_transfer_active`, `iris_transfer_stalled`,
  `iris_transfer_down_bps_sum`, `iris_transfer_up_bps_sum` and
  `iris_transfer_tier` are gone. In their place: `iris_transfer_devices`,
  `iris_transfer_throughput_bytes_per_second` (with a `direction` label),
  `iris_transfer_zero_receive_devices`, `iris_transfer_freshness_age_seconds`
  and `iris_stream_devices` labelled by `sampling_class`;
  `iris_transfer_samples_rejected_total` is now
  `iris_telemetry_samples_rejected_total`. The OTLP metric names move the
  same way. Throughput and progress are **omitted** for an image with no
  currently fresh device rather than published as a zero, and the freshness
  age is exported so the omission is explainable. Dashboards and alerts
  built on the old names need updating.
- **Server and IOx agent images move from Debian bookworm to trixie**
  (`python:3.12-slim-trixie`), taking OpenSSL from the 3.0 branch — upstream
  EOL **2026-09-07** — to **3.5 LTS**, supported upstream to 2030-04 (Debian
  tracks security support for each suite on its own schedule; the point is to
  stop running on an upstream-EOL crypto branch). This is a security boundary
  rather than housekeeping: `server/trust.py` shells out to the base image's
  `openssl` to parse the TLS trust store and verify CMS integrity for
  downloaded CA bundles (PKCS#7/CMS). This is CA-bundle/trust-store processing
  only — IOS image authenticity is enforced device-side by IOS `copy /verify`,
  not by the server. Python stays 3.12.14 and both Dockerfiles are bumped in
  lockstep. Addresses the first action item of the third-party EOL audit
  (#13); the aria2c side of that audit already moved to OpenSSL 3.5.7 LTS
  with the Aria2 Next hand-in in 2026.08.21.
- **The console swarm map was rebuilt on that document.** The graph draws
  the origin hub plus one node per tracker participant, labelled by device
  identity (or "Legacy unattributed peer"), and marks an edge as measured
  only when a measured server-to-peer rate was observed within the last 120
  seconds. Each participant carries a status line — device observation
  fresh, stale or unavailable, quarantine intent, enforcement state and
  whether it is blocked — searchable from a peer table beside the graph and
  filterable to participants needing attention. Graph nodes are keyboard
  operable, and the detail drawer keeps focus and closes on Escape; it shows
  tracker presence, server observation, device observation, latest report,
  policy intent, enforcement and the on-demand report pull, and prints "not
  directly reported" where the document says nothing rather than implying a
  value. Polling pauses when the console leaves the swarm view or the tab is
  hidden, backs off to 30 s while `/swarm` is unreachable, and the header
  states whether the view is live, paused, retrying, or showing tracker
  peers while the origin's RPC is unavailable.
- **Deleting a device revokes its credentials before anything else.**
  `DELETE /api/devices/<id>` durably revokes every secret the device owns
  under the secrets-store lock first; if that write fails the delete is
  aborted with a 500 and no fleet, catalog or policy state is touched. Once
  the revoke is durable, policy assignment and catalog state are cleaned up
  best-effort, and a partial cleanup returns 207 with the failed areas named
  in the response and in the audit entry. Endpoint rows are deliberately
  kept until they age out: a revoked device is denied through its still-fresh
  endpoint regardless of policy, so cleanup order cannot re-permit it.
  `iris-revoke` follows the same order and exits nonzero if the policy
  tidy-up fails while the revoke stands; `iris-mint-enrollment` clears a
  device's old endpoint rows before minting, and aborts without minting if
  that clear fails.
- **Per-peer sent-byte figures are no longer derived from the per-torrent
  counter.** The seeder previously split aria2's exact per-torrent
  `uploadLength` delta across connected peers in proportion to their
  instantaneous upload rate, which is division rather than measurement. The
  server now reports what aria2 actually measures: a current per-peer send
  rate, plus the per-torrent `upload_length_bytes` control-state value
  surfaced as a gauge (it can exceed the image size and it can decrease),
  re-baselined on an aria2 session change or an observed decrease.
- **Freshness is decided by the server's own receipt clock.** A live value
  counts as current only while it is within 120 s of the receipt of the
  `observed` envelope that set it; `not_due` does not extend that window,
  and `paused` / `disabled` / `not_active` / `rpc_unavailable` withdraw the
  value immediately. An out-of-order sample sequence for a known transfer
  cannot replace a newer observation. Rows are retained for display for a
  cadence-scaled interval capped at 900 s.
- **Per-device OTLP gauges are retired; `IRIS_OTLP_DEVICE_METRICS` no longer
  has an effect.** Device- and peer-labelled history now lives only in the
  OTLP log records, where it does not multiply metric cardinality. The
  environment variable is still accepted so existing deployments start, but
  setting it exports nothing extra.
- **OTLP log records use canonical event names and a stable event id.**
  Tracker lifecycle events export as `iris.tracker.peer`, v2 device reports
  as `iris.device.transfer.report`, legacy reports as `iris.device.report`
  with a safe subset only, and peer-policy operations as `iris.peer.policy`.
  Log record timestamps are the server receipt time, with the device's own
  observation time carried as an attribute. Legacy v1 fields are not
  re-labelled as v2 measurements, and each record is tagged with its schema
  version.
- **Export health is tracked per signal.** Logs and metrics are now
  independent signals, each `off` / `ok` / `degraded`, with the aggregate
  taken as the worse of the two — a successful metrics push no longer masks
  failing log delivery. The `/healthz` `otlp_export` block and the console
  badge gain the per-signal breakdown, including queue depth and overflow
  drops for logs. Disabling the destination sets both signals to `off` while
  keeping the historic last-success timestamp, and the degraded/recovered
  audit entry fires once per aggregate transition.
- **Queued log events survive a destination change.** The log queue is owned
  for the process lifetime and only the destination transport is rebuilt
  when the OTLP destination is changed, disabled or re-enabled, so events
  queued under the previous destination are delivered to the new one instead
  of being dropped. The queue stays bounded: when it is full the oldest
  event is dropped and counted.
- **Report export is keyed by report identity instead of a timestamp
  watermark.** Reports sharing a server receipt timestamp are all exported
  rather than shadowing one another, and a hub restart replays the stored
  ring with the same ids so the backend can deduplicate. The in-process set
  of delivered ids is trimmed to the ids currently in the ring, so it does
  not grow without bound on a long-running server.
- **Seeder gauges are published only while the aria2 RPC poll is
  succeeding.** A failed or vanished poll clears the cached control state
  instead of republishing the last-known values, so `iris_seeder_*` and the
  per-torrent upload lengths disappear rather than freezing at a stale
  number. `iris_seeder_rpc_up` still reports the poll outcome.
- **An idle tracker no longer talks to aria2 every two seconds.** The
  reconcile loop still runs on a local wake, an external change to the
  durable policy or endpoint files, outstanding pending writes, an unhealthy
  RPC or session, and a bounded maintenance deadline derived from the
  endpoint TTL. A steady-state poll with none of those conditions performs
  no reconcile pass, no `getSessionInfo` and no blocklist apply.
- **Device report endpoints reject devices that are not in the fleet.**
  `GET /api/devices/<id>/reports` and
  `POST /api/devices/<id>/request-report` now answer 422 `device is not in
  fleet` instead of returning an empty report ring or queueing a pull for an
  id the fleet does not know.

### Fixed
- **Mutual peer ACL evaluation applied each ACL to the wrong side.** Both
  halves of the check looked up the ACL assigned to the peer being judged
  and then judged that same peer with it, so a rule written to control what
  one device may see was evaluated against the other device's own
  assignment. Each side's assigned ACL is now evaluated against the *other*
  peer's principal and address, which is what makes a quarantine assignment
  isolate the assigned device in both directions.
- **A corrupt or unreadable endpoint map is treated as fail-closed instead
  of empty.** A parse failure previously produced an empty map, which
  silently emptied the derived deny set. The reconciler now writes a
  `fail_closed` enforcement status and leaves existing blocks in place. The
  pending-write queue is also locked for cross-thread use, and a retry
  removes only the exact tuple it successfully wrote, so a newer endpoint
  queued during the retry is not dropped.
- **A policy mutation on corrupt state no longer resets policy to the base
  document.** When the authoritative file existed but failed validation, the
  commit path treated it as a fresh install and wrote a new base document
  over it, discarding assignments. It now refuses the mutation and reports a
  degraded policy so the operator can repair the file.
- **Re-enrolling a device with expired or revoked credentials now renews
  them.** `iris-mint-enrollment` minted an announce token or RPC secret only
  when the key was absent, so a device whose records existed but were no
  longer valid was re-enrolled with dead credentials. The check now tests
  the record's shape and validity, not just its presence.
- **A shared-address policy conflict no longer reports a device as
  blocked.** `peer_enforcement.blocked` on a `/swarm` peer row is asserted
  only when it is directly known — the tracker is in its fail-closed state,
  or the device appears in a typed conflict whose global block was actually
  applied. A permit/deny conflict that was surfaced but not globally applied
  is still shown as a conflict, with `blocked` false.
- **A live value no longer sticks after a device is unassigned.** Withdrawal
  driven by policy — telemetry flags off, a global stream pause, or the
  device no longer having an approved image — now runs before the
  approved-image check in the heartbeat route. Previously an observation
  naming the now-removed image was treated as malformed, counted as a
  rejected sample and skipped the withdrawal, leaving the console showing a
  stale rate. A policy withdrawal no longer touches the rejected-sample
  counter; a genuinely malformed observation from a still-assigned device
  still rejects and leaves the prior good data in place. The heartbeat
  itself continues to return 200 in both cases.
- **The origin's observation no longer presents retained values as
  current.** After a failed control-state poll the per-torrent upload gauges
  and per-peer send rates are dropped instead of carried forward,
  `observed_at` reports the last successful poll rather than the moment the
  snapshot was rendered, and a torrent that has vanished from aria2 no
  longer lingers in the map's totals. Consumers gate on that timestamp, so a
  stale sample greys out instead of reading as a fresh zero.
- **v2 reports are strictly re-validated at ingest.** The server
  independently re-checks types, enums, ids, timestamp ordering (window
  start before end, peer first seen before last seen), that completed bytes
  do not exceed total, that peer addresses parse as IP addresses, that a
  checked content hash names `sha256` and an unchecked one names no
  algorithm, and that the stated peer total is not below the rows supplied.
  A report is also rejected unless its `image_id` matches the image the
  server has assigned to that device. Rejection means a 400 and nothing
  stored — the device retries with the same frozen report. Observation
  envelopes are size-bounded (8 KB) and rejected whole rather than partially
  parsed, and peer rows beyond the configured cap (at most 32) are truncated
  rather than causing a rejection.
- **`event.id` now reaches the collector.** It was written as a top-level
  log-record field, which the OTLP JSON schema does not define, so the id
  never arrived as an attribute; it is now emitted as a real attribute
  alongside the record. Delivery accounting was corrected in the same pass:
  events evicted from a full queue while a successful send was in flight
  were counted as drops even though they had been delivered.
- **A crash between storing a report and clearing its pull request no longer
  leaves the request pending.** A repeat of a report that is already stored
  is still a storage no-op, but it now also clears the matching pending
  request, so the retry finishes the job the interrupted delivery started.
  The clear stays match-gated and cannot clear a newer request.
- **Log emission no longer waits on an in-flight export.** A batch stays
  logically queued during the network call, so producers do not block on a
  slow or hanging collector and the queue bound stays enforced; concurrent
  flushes are serialised so delivery order is preserved. A queue configured
  with zero capacity now counts drops instead of raising.
- **Server-side per-peer send rates are keyed by address *and* port.** Two
  connections from the same address are no longer summed into one row, and
  the rate is attached to the swarm view only while the seeder poll behind
  it is recent, with the observation time carried alongside the value.
- **Console refreshes can no longer be overwritten by a slower earlier
  request.** Device, image, credential and peer-policy refreshes are
  superseded and aborted when a newer refresh starts, late responses are
  discarded, and an aborted refresh no longer surfaces to the caller as an
  unhandled error.
- **The console header's help button rendered as a wide pill wedged before the
  username.** A single `?` glyph inherited the standard button padding, so it
  stretched to roughly the width of *Sign out*, and the top bar declared no gap,
  leaving it flush against the username it sat in front of. It is now a round
  icon button, grouped with *Sign out* after the username, and the bar spaces its
  controls.

### Security
- **Duplicate credential ownership fails closed instead of resolving to
  whichever record loaded last.** The announce and catalog authorization
  indexes are built strictly: if two records share a credential value they
  raise a token-free error and every request in that lane is refused — a
  tracker 403 or a catalog auth failure — rather than silently overwriting a
  map key and mis-attributing a principal. No error message carries the
  offending value.
- **A device whose every credential is revoked is denied regardless of
  policy.** The tracker rebuilds this view from the durable secrets store on
  each pass, so a revoke takes effect without a restart, and a read or parse
  failure keeps the last known revoked set rather than shrinking it. A
  device with an expired-but-not-revoked token is not treated as retired, so
  ordinary token expiry does not produce a deny.
- **The device id `seeder` is reserved, and minting will not reissue an
  existing credential value.** Console fleet validation and
  `iris-mint-enrollment` reject the id `seeder`, keeping it in the service
  namespace. Minting checks the candidate value against the current index
  and the rotated-out seeder announce records, retrying and finally erroring
  out rather than issuing a value that already belongs to another record.
- **An aria2 RPC error can no longer surface in enforcement status.** The
  session probe swallows the exception, which may embed the RPC secret,
  instead of recording its message; the reconciler records the exception
  type only. The outbox acknowledgement watermark is also read from one
  place, so a status write cannot move it below an already-acknowledged
  revision.

## [2026.08.21]

### Added
- **Deployment visibility in the console.** Each device row gains a details
  panel backed by `GET /api/devices/<id>/deployment`: the latest deployment
  receipt's resolved network configuration (management type, VLAN/VPG, SVI,
  guest/app addressing, NAT interface), preflight evidence, owned resources,
  and state — the console now answers "what did we actually configure on
  this device".
- **Persistent deployment logs.** Onboard and undeploy job output survives
  the job: logs are written under the server state directory at job finish
  (newest 200 kept) and browsable from a new *Monitoring → Deployment logs*
  sub-page and from each device's details panel.
- **Audit export.** On-demand and daily scheduled export of the audit trail
  to an operator-configured SCP destination, encrypted with `age` to an
  operator-supplied recipient (encryption is mandatory; the destination
  password lives in the encrypted secrets store; a new *Settings → Audit
  export* sub-page configures it).
- **Console help.** A header **?** popover shows the server version, a
  persistent unique deployment id, a link to the official documentation, and
  two local troubleshooting guides (device-side and server-side).
- The IOx entrypoint reconciles `agent_version` from the image's baked
  VERSION file on every start, so telemetry reports the running build even
  when a persistent conf predates a package upgrade.

### Changed
- Monitoring now uses sidebar sub-menus (*Audit trail* | *Deployment logs*),
  matching the Settings pattern.
- Concurrent image uploads each render their own progress row; the shared
  progress bar no longer garbles simultaneous uploads.
- Every onboard/undeploy job gets its own log window with its own live
  stream, per-panel Abort (queue-aware: a still-queued job is cancelled
  through the queue instead of failing) and Close; sequential onboards no
  longer merge into one window.
- The Overview *staging* counter counts devices that are actually staging —
  heartbeating within the last 10 minutes and mid-pipeline — instead of
  inventory rows, so an empty fleet no longer reports phantom staging
  devices.

### Fixed
- **Guest Shell devices no longer stay silent after onboarding with the
  Aria2 Next binary.** The installer bakes the device `rpc-secret` file
  *empty* by design (the agent fetches the real value on its first
  token-refresh), and `aria2c` 1.37 accepted `--rpc-secret=` with an empty
  value. Aria2 Next 2.5.6 rejects it outright ("Empty string is not
  allowed"), so on every freshly onboarded Guest Shell device `aria2c`
  exited before daemonizing, `bootstrap.sh` aborted at the launch step
  **before ever running the agent**, and the device never sent a heartbeat —
  invisible in the console with no log anywhere (the `aria2c` log file is
  only created by a successful launch). `device/guestshell-start.sh` now
  launches with the same `iris` placeholder secret the IOx entrypoint has
  always used when the baked secret is still empty; the existing bootstrap
  secret-sync bounces `aria2c` onto the real secret right after the agent's
  first token-refresh.
- **A device stays visible when its download daemon cannot launch.**
  Bootstrap records a failed `aria2c` launch and still runs the agent, and
  the agent reports an error-state heartbeat when the local RPC is down —
  a future launch regression shows up in the console instead of silence.
- **An operator abort issued before the installer process exists is
  honored** instead of being lost to a race between `abort()` and the
  worker registering the process.
- The audit-export worker turns an unexpected export failure into a
  terminal error with an audit record instead of leaving the job running
  forever; export settings writes serialize against the console's save and
  clear routes; export filenames carry a random suffix so same-second runs
  cannot collide.

### Documentation
- Accuracy sweep across the public site and every reference page: Catalyst
  9000 is documented with both runtimes (Guest Shell to `flash:`, or the
  amd64 IOx app on app-hosting SSD switches to `usbflash1:`), telemetry
  examples lead with Cisco Splunk through the OpenTelemetry pipeline, and a
  code-verified pass corrected backup guidance (age identity vs recipient),
  the `copy /verify` signature gate, router adopt semantics, arm64 build
  digest requirements, VLAN/SVI ownership claims, and stale console UI
  descriptions.

## [2026.08.20]

### Added
- **Transfer streaming (opt-in, ships dark)**: while a transfer is active, a
  device embeds one compact live sample (≤250 B, tier-adaptive cadence) in the
  heartbeat it already sends — no new ports, tokens, or network flows. The
  server keeps an in-memory live table (validated against the policy
  assignment), aggregates per image, and serves new `iris_transfer_*` /
  `iris_stream_devices` Prometheus families on `:9101` plus semconv-compliant
  OTLP metrics (`iris.transfer.*`, `iris.stream.devices`,
  `iris.telemetry.*`) to the configured collector. Enabled per device by the
  fail-closed conf key `telemetry_stream` (default off), delivered by all
  three platform installers and reconciled on IOx redeploy; tuned fleet-wide
  without redeploys via `POST /api/telemetry/stream` (pause / stretch, echoed
  on every heartbeat response, defaults restored within three ticks when
  stale). Telemetry remains an add-on: no telemetry condition affects staging.
- **OTLP export health**: console *Telemetry export* badge, `/healthz`
  converted to JSON with an `otlp_export` block (status code unchanged —
  probes unaffected), and one audit entry per degraded/recovered transition.
- **Collector authentication**: `IRIS_OTLP_HEADERS` / `IRIS_OTLP_HEADERS_FILE`
  attach operator-supplied headers to every OTLP POST; values are never
  logged and the exporters refuse HTTP redirects.
- **Console onboarding telemetry checkboxes** (*Telemetry reports* default on,
  *Telemetry streaming* default off), applied to single and bulk onboards; the
  IOx entrypoint now reconciles both `telemetry` and `telemetry_stream` from
  deploy-time env on redeploy.
- `IRIS_OTLP_DEVICE_METRICS` (per-device OTLP gauges, default off with a
  cardinality warning), `IRIS_METRICS_HOST` (bind host for the `:9101`
  listener, default unchanged), and `IRIS_EVENTS_URL_TEMPLATE` (operator-
  configured swarm-drawer events link, replacing the previously hardcoded
  dashboard link; unset renders no link).
- **Console certificate replacement**: Settings → TLS & trust uploads a
  cert/key PEM pair for the web console only, validated by a real
  `load_cert_chain` (garbage PEM and key/cert mismatch are rejected
  per-field) and hot-applied — no restart, and no change to the certificate
  devices pin for catalog/artifact traffic. Persisted durable-first as
  `tls/gui-crt.pem` + age-encrypted `tls/gui-key.pem.age`; boot rebuilds the
  combined runtime cert (`IRIS_GUI_CERT`, default
  `/run/iris/tls/gui-cert.pem`), and an override that fails to decrypt — or
  whose certificate and key do not form a matching pair — is skipped with a
  warning, so the console always falls back to the built-in certificate — a bad
  upload can never lock the operator out. *Use built-in
  certificate* reverts. New `POST`/`DELETE /api/settings/gui-cert`, audited
  as `gui-cert-replace` / `gui-cert-revert` (never key material).
- **Root-CA trust store**: Settings → TLS & trust installs and removes CA
  PEMs under `IRIS_TRUST_DIR` (default `/etc/iris/tls/trust`, one
  fingerprint-named file per install); every change — and every boot —
  rebuilds the runtime bundle `IRIS_CA_BUNDLE` (default
  `/run/iris/tls/ca-bundle.pem`). Outbound TLS (OTLP export, the CA-bundle
  download) verifies against the system store *plus* this bundle. New
  `POST /api/settings/trust` and `DELETE /api/settings/trust/<name>`,
  audited as `trust-add` / `trust-remove`.
- **Daily public-CA bundle download** (optional): the operator supplies an
  `https://` URL and an auto flag (`POST /api/settings/ca-trust`, stored in
  `$IRIS_STATE/ca-trust-settings.json`); *Download now* runs the job on
  demand (`POST /api/settings/ca-trust/refresh`, polled). Downloads refuse
  redirects, cap at 2 MiB, must parse as PEM certificates — plain PEM, a
  certs-only PKCS#7 bundle, or a CMS-signed wrapper such as Cisco's Trusted
  Root Store (`https://www.cisco.com/security/pki/trs/ios.p7b`, the default
  URL when none is configured; the wrapper's own signer certificates are
  never imported, and a tampered signature rejects the whole bundle) — and
  never overwrite the previous good bundle on failure. Downloaded certs land
  as the distinguished trust entry `downloaded-bundle.pem`. The console
  re-runs the download every 24 h while auto is enabled.
- **Editable telemetry destination**: the console's Observability row is now
  an editable form — endpoint and enabled flag, hot-applied by the telemetry
  hub on its next sample pass, no restart. Stored in
  `$IRIS_STATE/telemetry-destination.json`; each field overrides its
  deployment default (`IRIS_OTLP_ENDPOINT` / `IRIS_OBSERVABILITY`) and
  *Revert to deployment default* deletes the file, restoring exact env
  behavior. Collector auth headers stay env-only
  (`IRIS_OTLP_HEADERS[_FILE]`). New
  `POST`/`DELETE /api/settings/telemetry-destination`, audited as
  `telemetry-destination-set` / `telemetry-destination-clear` (never header
  values).
- **Installer prerequisite checks**: `device/device-install.sh` and
  `device/iox/install.sh` now verify, before touching any config, that
  `ip routing` is enabled on a routed (IRIS-managed SVI) attachment — a
  disabled global routing table lets onboarding "succeed" while the app's
  VLAN traffic silently never reaches the server — and that IE3x00 IOx
  targets have an SD-card IOx partition; both fail closed with a plain
  `PREREQ:` line and the exact remediation command. A wildly stale device
  clock is a `PREREQ WARNING:` (TLS validation risk) that does not block the
  install. Every line is single, grep-able, and streams straight into the
  operator-visible job log.

### Changed
- **Operator tools require the running container.** `tools/apply-assignments.sh`
  and `tools/gen-device-installers.sh` no longer fall back to invoking server
  code directly on the host — that path existed only for the removed
  bare-metal install. Both now fail with an explicit message when the `iris`
  container is not running, and both honor an `IRIS_CONTAINER` override for a
  non-default container name, matching `tools/stage-iox-package.sh`.
- **First-run setup uses a default credential, not a bootstrap token.** Before
  any admin exists, signing in at the console with `iris` / `irisisgreat!`
  does not open a session — it hands the client a one-time, 10-minute setup
  grant and redirects to `/setup` to create the real admin account. This
  removes the `docker exec … cat /run/iris/gui-bootstrap-token` step (and the
  `0600` token file and startup log banner) in favor of a documented,
  hardcoded credential that only ever works pre-setup; once an admin exists
  it is an ordinary failed login, rate-limited and audited like any other.
- **Settings is split into sub-pages** — General (server info, admin
  password, stage host, sessions), TLS & trust (certificate, trusted CAs,
  public CA bundle download), and Telemetry (destination) — replacing the
  single long page. The sub-pages are reached from an indented feature
  sub-menu in the sidebar under Settings and are deep-linkable
  (`#settings/general`, `#settings/tls`, `#settings/telemetry`).
- **Drag and drop on the TLS & trust page**: drop a certificate and key (or
  one combined PEM) onto the Certificate section, or several CA files onto
  Trusted CAs. Files are classified by PEM content rather than extension, and
  pasting still works — the drop zone fills the same fields the Upload button
  already submits.
- **A choice of public CA bundle source**: Cisco Trusted Root Store (the
  existing default), the Mozilla CA bundle from `https://curl.se/ca/cacert.pem`,
  or a custom URL. Both presets go through the same https-only,
  redirect-refusing, size-capped, PEM-validated fetcher. The downloaded bundle
  shows as one row in the trusted-CA table, named for its source, and removing
  that row is how an operator reverts to the system store alone.
- **Unassign from the device table**: the assign dropdown's empty option now
  clears a device's image assignment (audited as `device_assign`
  action=`unassign`); previously the only way to unassign was deleting and
  re-adding the device.
- **Breaking:** `:9101/swarm` now answers only loopback peers by default (it
  was open to any peer that could reach the port). The authenticated console
  is unaffected — it already proxies swarm data over container loopback
  (`GET /api/swarm`). Remote scrapers must set `IRIS_SWARM_PUBLIC=1` (or point
  `IRIS_SWARM_URL` at a listener that sets it) or read the authenticated
  console API instead. The peer-address gate assumes a rootful container
  engine; see the security page for the rootless/host-networking caveat and
  the `IRIS_METRICS_HOST` hard control.
- **Breaking (OTLP logs, dark-by-default surface):** log records now use
  OpenTelemetry semantic-convention attribute names and a top-level
  `eventName` (`device_id` → `device.id`, `image_id` → `iris.image.id`,
  `tier` → `iris.link.tier`, `avg_bps` → `iris.transfer.throughput_avg`,
  `ip`/`port` → `network.peer.address`/`network.peer.port` +
  `network.transport`, `info_hash` → `iris.torrent.info_hash`; the `event`
  attribute is removed in favor of `eventName`). Update backend queries.
  Report records additionally carry heartbeat enrichment
  (`device.model.identifier`, `iris.device.flash.free`, `iris.stage.state`,
  `iris.agent.*`) and the peers observed as the structured attribute
  `iris.transfer.peers`.
- **Breaking (device report + OTLP peers rows):** per-peer rows are now
  participation-only — `{ip}` on the wire, `network.peer.address` +
  resolved `device.id` in the log record. The per-peer `rx_bytes` /
  `tx_bytes` / `avg_bps` fields (`iris.transfer.received` /
  `iris.transfer.sent` / per-row `throughput_avg`) are removed: aria2
  exposes no per-peer byte counters, so those figures were derived from
  instantaneous rates — on fast transfers every multi-peer report
  degenerated to an even split. Reports gain top-level `peers_total`
  (exact distinct peers observed, saturating at the device's 512-IP
  tracking cap; exported as `iris.transfer.peers_total`); the named-row
  cap rises 20 → 64.
  Transfer-level figures (`transfer.total_bytes`, `avg_bps`) are exact
  and unchanged.
- OTLP resource now carries `service.namespace=iris` and `service.version`.
- OTLP exporters verify collector TLS against the system store plus the IRIS
  trust bundle, so an `https://` collector fronted by a private CA works once
  its root is installed from the console — previously such an endpoint failed
  silently (best-effort drop + `otlp-export-degraded`).

### Removed
- **Bare-metal / systemd server install.** `server/install.sh`, the five
  `server/systemd/*.service` units, `server/logrotate.d/iris`, and
  `server/iris-secretfs` are gone, along with their two test files. Docker
  Compose and the Kubernetes manifests (same image) are now the only supported
  server runtimes. The path was undocumented, was never exercised by CI, and
  could not run console-driven onboarding at all — `install.sh` never copied
  `device/` or `lab/` into the install root, so every onboarding action failed
  at subprocess launch.

  Migrating an existing bare-metal server to Compose keeps all state, because
  the same age key decrypts the same `.age` files:

  1. Set `IRIS_AGE_KEY_FILE_HOST` to the existing key path, normally
     `/etc/iris-key/.iris_age_key`.
  2. `sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"`, keeping mode 600.
  3. Copy the existing `/etc/iris` and `/var/lib/iris` contents into the
     `iris-config` and `iris-state` named volumes, then `chown -R 10001:10001`.

  Two behaviors do not carry over. All five services now share one container, so
  a crash in any of them restarts the whole set rather than just that service —
  this already applied to every Compose and Kubernetes deployment. And seeder
  logs go to Docker's `json-file` driver (10 MB × 3) instead of the 14-day
  compressed rotation `logrotate.d/iris` provided.

### Fixed
- **A live-but-unresponsive `aria2c` no longer blocks its own relaunch.**
  `device/bootstrap.sh` decided whether to start the daemon with
  `pgrep aria2c` — process *liveness* — so an `aria2c` that was running but
  not answering RPC was never replaced. The agent then failed on
  `ECONNREFUSED` to `127.0.0.1:6800` on every 60-second tick and crashed
  **before its first heartbeat**, leaving the device permanently invisible in
  the console with no error anywhere; recovery happened only if the stale
  process happened to die. Bootstrap now delegates unconditionally to
  `device/guestshell-start.sh`, which was already idempotent (it probes the
  RPC and exits early when the daemon is healthy), and that script now clears
  a non-serving `aria2c` before relaunching — it still owns the RPC port, and
  `cp -f` over a running binary fails with `ETXTBSY`. Copy and `chmod`
  failures are reported instead of being swallowed by `|| true`.
  `device/iox/entrypoint.sh` carried the identical condition and gained the
  same RPC health probe, covering both the arm64 (IE-3400) and amd64 (C9k)
  packages, which share one entrypoint.
- **`ip routing` detection is semantic, not textual.** The prerequisite check
  added above grepped the running config for a literal `ip routing` line, but
  on platforms where routing is the default (observed on IE3x00) *enabled*
  routing renders no line at all — so the check failed healthy switches and
  no amount of configuration could satisfy it. It now looks for an explicit
  `no ip routing` line or a host-mode route table (`Default gateway ...`), and
  distinguishes a dead device session (`PREREQ: could not verify ip routing`)
  from routing genuinely being off, instead of blaming routing for a
  transport failure.
- **Re-onboarding a router rebuilds its Guest Shell networking.**
  `device/router-install.sh` applied the app-hosting config while a previous
  Guest Shell was still `RUNNING`; the enable step then saw `RUNNING` and
  never re-enabled, so the guest kept its old networking and the agent had no
  egress — silently, since the device still answered pings. The installer now
  destroys a pre-existing Guest Shell before applying config, waiting for it
  to actually disappear.
- **An unreachable device fails loudly at onboard.** A Guest Shell onboard
  probes reachability before running the installer and fails the job with
  `cannot reach device <ip> — ping/SSH probe failed; check the device IP and
  credentials`; submit-time rejections are rendered in the console and
  audited. A mistyped device IP previously produced no job, no error, and no
  audit record.
- **An encrypted private key can be imported from the console.** A
  passphrase-protected key failed TLS replacement with an opaque
  `certificate/key pair rejected (OSError)`. The TLS page now offers a
  passphrase field when the key is encrypted and decrypts it at import
  (passphrase fed to `openssl pkey` over stdin, never argv); the key is still
  stored age-encrypted at rest.
- **The release tarball can install `aria2c` again.** `tools/make-release.sh`
  shipped `tools/get-aria2c.sh` but not `tools/aria2c.sha256`, and the
  fail-closed script exits when the checksum file is missing. It now ships
  both, plus `tools/start-compose-server.sh` — the documented Compose entry
  point, previously omitted. That script now skips IOx staging with a clear
  message when the IOx packaging tools are absent, as they are in a tarball.

### Security
- **Staged device credentials are capability-addressed.** The artifact server
  served `staging/iris-agent-<DEVICE_ID>.conf` — containing a live catalog
  bearer token — with no authentication, and device IDs are guessable. Each
  install now mints a 128-bit capability and stages
  `iris-agent-<DEVICE_ID>-<CAP>.conf` and `rpc-secret-<CAP>`; the capability
  rides the existing installer→device channel, so no new mechanism was
  needed. `rpc-secret` was previously one shared filename for every device
  and is now per-device. Retention stays 600 s. The artifact server serves a
  mode-tight staging file regardless of which uid wrote it, so remote-SSH and
  stage-host-local staging work rather than 403-ing.
- **`aria2c` is handed in, not downloaded.** The server and both IOx packages
  ship Aria2 Next 2.5.6, built from a pinned source with four local security
  patches and verified against `tools/aria2c.sha256`, which fails closed on
  mismatch. Nothing in the repository downloads a prebuilt client any more:
  `device/iox/build.sh` resolved `aria2c` from a third-party release when no
  local bundle was present, which silently shipped an unpatched build —
  including a peer-blocklist use-after-free that crashes the client — into
  IE-3400 images. Its network fallback is removed entirely.

## [2026.07.26]

### Added
- **Import images already on disk**: the Console's Images screen lists image
  files present on the server but not in the catalog and publishes them **in
  place** — nothing is copied, and a read-only image root stays read-only. Two
  roots are scanned recursively: the uploads volume (`IRIS_IMAGES_DIR`) and the
  read-only import root (`IMAGES_ROOT`, default `/opt/images`). Recovers
  orphaned uploads after a catalog reset and gives the documented
  operator-drops-a-file workflow a UI. New `GET /api/images/importable` and
  `POST /api/images/import`, plus an `image_import` audit event. Files that are
  not offered are reported with a reason rather than silently omitted.
- **Bulk device actions**: **Adopt selected** and **Delete selected** join
  Onboard/Undeploy, alongside a picker that assigns one credential profile to
  every checked device — the CSV inventory carries no credentials, so this is
  the batch path after an import. Every selected-action shares one lock, so a
  delete can no longer fire while an onboard batch is starting.
- **Catalog entries record `source_dir`**, the directory an image is seeded
  from. Deletes only unlink inside the uploads volume, and the startup re-seed
  resolves a torrent by recorded directory instead of guessing from a basename.
- **Non-root server runtime**: the image runs as `iris` (uid/gid 10001) with
  `cap_drop: ALL` and `no-new-privileges`; the Kubernetes pod sets
  `runAsNonRoot` with matching uid/gid/fsGroup and the namespace enforces the
  `restricted` Pod Security profile. Existing deployments need a one-time
  volume-ownership migration — see the Server documentation.
- **Optional device SSH host-key pinning** through a `device_ssh_known_hosts`
  agent config key, following the same verify-if-present pattern as the catalog
  CA. The default path is unchanged.

### Fixed
- **Deleted devices came back with their old assignment**: removing a device
  from the console only dropped the fleet row; the catalog kept the image
  assignment, heartbeat record, telemetry history, and any pending pull
  directive, so re-adding the same device id silently restaged the old
  image. Device deletion now purges all catalog-side state — a re-added
  device always comes back unassigned.
- **IOx packages built on modern Docker engines never ran on IE3x00**:
  containerd-store `docker save` (and therefore `ioxclient docker package`)
  emits a nested OCI index with buildx attestation manifests — CAF
  (dockerd 19.03) installs and activates the app but refuses to start it,
  with nothing in syslog — and the buildx `type=docker` export fails
  activation outright ("Image blobs/… cannot be loaded"). `device/iox/
  build.sh` now packages via skopeo's `docker-archive:` transport (the
  classic docker-save layout, lab-verified on IOS-XE 17.15), requires
  skopeo with an actionable message, and fails closed on OCI-index or
  attestation layouts. IOx packaging now needs `skopeo` on the build host.
- **Unassigned devices never registered**: the agent returned before its
  first heartbeat when no image was assigned, so a freshly onboarded device
  stayed invisible to the console (and IOx onboarding without an assignment
  timed out). The agent now heartbeats with `stage_state` `unassigned` (or
  `error` when the assigned image is missing from the catalog) — assignment
  gates staging, not presence.
- **Stored cross-site scripting in the Swarm Map**: a device-supplied
  `link.rtt_ms_median` reached the report drawer unescaped. The field is now
  numerically gated in the browser and coerced server-side when a report is
  sanitized.
- **Replaced-image cleanup on AAA devices**: cleanup now deletes through an
  authorization-bypass EEM applet. A raw exec `delete` is silently discarded on
  a device running AAA command authorization, so the replaced image was never
  freed and the delete was re-queued on every tick.
- **Interrupted deployments are recoverable**: a receipt left `unknown` by a
  controller restart, or marked `drifted`/`needs-reconcile`, can now be torn
  down. Previously such a receipt was a dead end — the device was already
  configured so a re-onboard failed preflight, a router could not be adopted,
  and undeploy had no receipt to authorize it.
- **Router NAT teardown** clears only translations owned by the receipt before
  removing the dynamic mapping. IOS refuses the mapping's no-form while
  translations reference it; teardown now verifies that removal before
  deleting the ACL and never flushes unrelated device-wide NAT state.
- **Pre-apply onboarding failures** retire their planned deployment receipt
  instead of marking it recoverable, so a collision or missing artifact cannot
  authorize teardown of resources that IRIS never created.
- **Identical image roots are scanned once**, so a deployment that points the
  uploads volume and the import root at one directory (as the Kubernetes
  ConfigMap does) can still import.
- Publish no longer overwrites a catalogued image when a filename differs only
  by the `.SPA.bin`/`.bin` suffix, which resolves to the same catalog id.
- `/api/devices` reads device policies once per request instead of once per
  device.
- Panning the Swarm Map updates the scene transform instead of rebuilding the
  graph on every pointer event.
- The device inventory's required-variable guard in `router-uninstall.sh` now
  runs before the value is first used, and `get-aria2c.sh` cleans up its
  temporary directory on every exit path.

### Changed
- The documentation navigation is grouped into **Get started**, **How it
  works**, **Deploy the server**, **Onboard devices**, **Operate**, and
  **Reference and development** instead of one flat page list. Page URLs are
  unchanged.
- `zensical` and the documentation workflow's Python version are pinned.

## [2026.07.25]

### Added
- **Catalyst 8000 router attachment modes**: `router-routed` creates an
  IRIS-owned VirtualPortGroup (VPG) subnet, while `router-nat` additionally
  configures overload NAT and static TCP PAT for swarm port 6881. NAT teardown
  removes `ip nat outside` only when the deployment receipt proves IRIS added
   that marking. Support is designed for the Catalyst 8000 family, lab-tested
  on C8000v. Both modes completed onboarding, verified image staging, and
  receipt-backed undeploy in the lab; Swarm Map and Grafana telemetry were
  also verified.
- **Router inventory fields**: CSV v2 and the Console now support
  `vpg_number` and `nat_interface` for router attachments.
- **Router safety invariants**: preflight repeats at execution time before
  enrollment-token minting; receipts bind management IP and processor-board
  identity. Router adoption is refused (re-onboard instead). Named globals and
  `guest-share` are collision-free and receipt-owned, NAT interfaces are
  canonicalized, and pre-existing `ip nat outside` is preserved.

## [2026.07.24]

The inband-management release adds a second management type and a
durable deployment-receipt lifecycle. IRIS stays stage-only, and inband
additionally never creates, changes, or removes the operator's existing network.

### Added
- **Inband management type**: attach the staging agent to an existing,
  operator-owned management VLAN (static IPv4) instead of a dedicated IRIS
  VLAN/SVI. IRIS never creates, configures, selects, claims, or deletes that
  VLAN, its SVI, gateway, routes, or VRF. The Console Add Device flow has an
  explicit **Management type** choice and onboards inband one-click, exactly
  like routed. Inband works for both **Guest Shell and IOx** (IE-3x00, C9300);
  inband IOx SSHes to the device's management IP (`device_ip`) for its
  `copy /verify` by default, with `ios_ssh_host` as an optional advanced
  override. DHCP is not supported.
- **Durable deployment receipts**: a lock-protected, atomic, non-secret store
  under `IRIS_STATE` records the applied lifecycle of each deployment. Undeploy
  renders exclusively from a device's active receipt, so editing inventory after
  onboarding can no longer retarget cleanup. A controller restart marks
  in-flight receipts `unknown`; missing, drifted, or uncertain receipts stop in
  `needs-reconcile` rather than guessing.
- **Device adoption**: an explicit, audited **Adopt** action records an active
  receipt from a pre-existing deployment's current inventory so it can be
  undeployed, without making any device change.
- **Attachment-aware inventory (CSV v2)**: a named-header interchange format and
  one shared server-side validator across the Console, API, and CSV import.
  Legacy positional CSVs still import but are classified `legacy_routed` and are
  never inferred as inband.
- **Management Type and VLAN Ownership** documentation page plus a
  public-site safety callout, and cross-links from the Console, Fleet, Security,
  Operations, Server, Kubernetes, Containers, Device Agents, Network Ports, and
  Validation pages.

### Changed
- Documentation and Console wording says **network** rather than "fleet"
  (the `fleet/` CSV directory, `fleet.json`, and code identifiers keep their
  names). The README and docs index now map every documentation page, and a
  new test gate fails whenever the site nav, the docs index, and the README
  drift apart.
- **C9300 IOx image transfer no longer uses scp**: onboarding bind-mounts the
  app-hosting SSD share (`usbflash1:iox_host_data_share`) into the container,
  the agent lands its verified scratch at the share root as
  `iris-staged.bin` at disk speed, and IOS places it with an internal
  `copy /verify` onto bootflash under the real image name — the same final
  placement as Guest Shell, with no image bytes on the CoPP-policed
  control-plane punt path (which capped scp at ~1.4 MB/s by default). IRIS
  touches only `iris-` prefixed filenames at the share root (a
  container-created subdirectory becomes inaccessible to the container itself
  on this platform): each attempt sweeps its own orphans, a probe verifies
  IOS can read the share before any multi-GB copy (falling back to the scp
  push otherwise), and undeploy removes the prefixed files. IE-3x00 keeps the
  scp push unchanged.
- Onboarding resolves an immutable plan and records a receipt before any device
  contact; the platform is resolved before the plan hash so a receipt binds the
  exact rendered plan.
- Both the Guest Shell and IOx installers/uninstallers render an inband path that
  structurally preserves the existing network — the inband command stream never
  contains `vlan`, `interface Vlan`, VRF, `ip route`, IS-IS, or DHCP. The one
  inband interface touch is the AppGigabitEthernet app-hosting port: install
  sets it to trunk mode and **adds** the inband VLAN with
  `switchport trunk allowed vlan add` — additive only, so an existing allowed
  list is never replaced, and teardown never removes it. Inband teardown removes
  only the app footprint and leaves shared globals (logging discriminator, PKI
  trustpoint, HTTP-client settings) in place. Routed teardown is unchanged. The
  IOx installer also gains a `--dry-run` mode to preview its rendered
  configuration.
- The legacy `tools/gen-device-installers.sh` generator is routed-only and
  refuses a v2 (`network_attachment`) header, because a self-contained installer
  cannot record a receipt before minting an enrollment token.
- The Console devices table shows each device's management type instead of a
  bare VLAN/SVI value.

### Fixed
- Tracker `/scrape` now parses the raw query like `/announce`, so a real
  binary info_hash works: it previously crashed the connection on non-UTF-8
  bytes and silently corrupted accidentally-valid UTF-8 sequences (only
  all-ASCII test hashes ever matched).
- The Console devices view carries the heartbeat's `target_fs`, so the
  "copying to <fs>" badge names the real filesystem; the swarm map resolves
  peers by the v2 `app_ip` field (it only knew the legacy `guest_ip`); the
  device-create audit line reads `iris_vlan`/`inband_vlan` (it logged "-" for
  every v2 row).
- The agent verifies a replaced image is actually gone before logging CLEANUP
  (AAA nodes silently no-op raw exec deletes); unverified deletes are queued
  and retried every tick. Telemetry now reports the real packaged
  `agent_version` (both Guest Shell conf and the IOx image bake it in).
- Bare-metal systemd deployments gain `iris-artifacts` (:8000) and `iris-gui`
  (:8080) units — previously only 3 of the 5 container services existed as
  units, so device onboarding had nothing to `copy https://…:8000` from — and
  all units read optional operator env (e.g. `IRIS_AGE_RECIPIENTS`) from
  `/etc/iris/iris.env`.
- `tools/gen-device-installers.sh` refuses a CSV v2 header in its current
  `management_type` spelling too (the guard only knew the old
  `network_attachment` name and was silently bypassed).
- Dead code removed: legacy token-set auth shims (`load_tokens`,
  `check_bearer`), `telemetry.load_swarmmap_html`, `publish.sha256_file`,
  `flashcheck.reclaim_plan`, and the unused `lab/gsrun.sh` /
  `lab/device-copy.sh` helpers; the three drifted aria2 RPC iteration copies
  in the agent are consolidated into one helper (the gid lookup now checks
  queued downloads, as its docstring always claimed). Installer step counters
  no longer switch denominators mid-run; `device/test_bootstrap.bats` joined
  the documented test commands.
- Re-onboarding a device no longer accumulates duplicate `active` deployment
  receipts (which made a later undeploy fail to start with no visible reason):
  a receipt reaching `active` — or an adopt — now retires any previous active
  receipt for that device to the new terminal `superseded` state, and server
  startup collapses legacy duplicates by keeping the newest. Receipt
  transitions in the job worker are race-tolerant: a receipt retired by a
  concurrent action mid-job is reported as a job line instead of killing the
  worker thread (which left the job "running" and the device "busy" forever);
  an undeploy whose receipt is no longer active aborts before touching the
  device. The Console surfaces the server's refusal reason when a batch
  action fails to start, and the undeploy confirmation covers both Guest
  Shell and IOx (it previously described only Guest Shell).
- `NOTICE` now lists Cisco `ioxclient` (the proprietary, operator-provided IOx
  package tool used to build `iris-arm64.tar` / `iris-amd64.tar`) among the
  invoked third-party tools.
- `MAINTAINERS.md` uses the public github.com handles instead of the retired
  internal Cisco GitHub Enterprise usernames.
- `server/swarmmap.html` carries the required Apache-2.0 SPDX header.

## [2026.07.23]

### Added
- **Catalyst 9300 IOx Console onboarding**: select IOx per device in the
  Console or fleet CSV to deploy the amd64 IOx app and stage images to
  `usbflash1:`. C9k devices now resolve `iris-amd64.tar`; IE-3x00 and IR devices
  retain the arm64 `iris.tar` path. An explicit IOx override on an unknown model
  now fails before touching the device instead of selecting an unsafe default.
- **IOx package staging helper**: `tools/stage-iox-package.sh` builds and
  places the per-deployment arm64 or amd64 package into the Compose artifacts
  bind mount without touching a device.

### Changed
- `device/iox/build.sh --amd64` produces `iris-amd64.tar` by default, avoiding
  collisions with the arm64 package when both are served.

## [2026.07.10]

The container deployment alpha makes the existing seed-server and Cisco IOx
paths portable beyond the original lab checkout.

### Added
- **Optional Kubernetes seed server**: a Kustomize deployment with one amd64
  replica, a persistent data PVC, idempotent bootstrap init container, age-key
  Secret mount, memory-backed plaintext runtime secrets, health probes, and a
  source-IP-preserving LoadBalancer that keeps aria2 RPC private.
- **Configurable IOx filesystem placement**: `IRIS_TARGET_FS` / installer
  `TARGET_FS` selects a writable IOS disk such as `sdflash:` or `bootflash:`.
  The agent validates it against `show file systems`, safely falls back to
  platform detection, and still delegates the final write to IOS `copy /verify`.
- **IOx image-only build mode**: `device/iox/build.sh --image-only` builds the
  arm64 Docker image without requiring `ioxclient`. Clean clones can fetch a
  pinned aarch64 static `aria2c` with SHA-256 verification.

### Changed
- The amd64 seed-server image now builds from the repository root and contains
  its device installers and onboarding helper, removing runtime checkout bind
  mounts. A root `.dockerignore` excludes credentials, firmware, fleet state,
  and generated artifacts from the build context.
- Server and IOx entrypoints now handle termination cleanly. The server image
  exposes every real service port and provides a `/healthz` Docker health check;
  IOx config creation is atomic and mode `0600` with no baked lab addresses.
- Docker Compose declares runtime secret paths for one-shot `exec` commands and
  supports configurable host image/artifact mount locations.

## [2026.07.04.8]

### Fixed
- **Self-heal for telemetry state poisoned by the pre-.7 pull bug**: the .7
  fix stopped NEW fabrication, but the fabricated multi-GB tx rows live in
  the agent's persisted state (which survives upgrades), so pulls kept
  re-reporting the old poison verbatim. The agent now detects the exact
  contamination signature — a `staging-complete` transfer whose
  `last_sample_ts` postdates `done_ts`, impossible under the fixed agent
  (seeding-only transfers legitimately sample past completion and are left
  alone) — drops the fabricated zero-rx/nonzero-tx rows, clamps the sample
  clock back to completion, and logs `TELEMETRY-HEAL` once. Idempotent, runs
  every tick, no state-schema bump (a bump would force a fleet-wide
  re-copy).

## [2026.07.04.7]

### Fixed
- **Telemetry pulls fabricated absurd per-peer numbers** (hardware-observed:
  a device showed **~12 GB "sent"** on a 1.26 GB image, and its rx split
  turned into a bogus even split). A steady-state pull took one fresh aria2
  sample and rate-integrated that single instantaneous reading across the
  180 s clamp window — compounding on every pull while the device happened to
  be seeding a neighbor's download, and injecting that neighbor into the
  long-finished transfer's peer table. A completed transfer's per-peer table
  is now **frozen**: steady-state pulls re-send it as-is and take no sample.
  Live-transfer sampling (every tick while downloading/seeding-only) is
  unchanged.

## [2026.07.04.6]

### Added
- **Job-aware device status — "waiting for heartbeat"**: after an onboard
  finishes, the agent needs minutes to bootstrap before its first heartbeat;
  the devices table used to show **not enrolled** in that gap, which reads as
  "the onboard did nothing" (and masked a real enrollment failure tonight).
  The devices view now merges each device's latest onboard/undeploy job:
  **onboarding… / undeploying…** while a job is active, **waiting for
  heartbeat** when an onboard succeeded but no heartbeat has arrived since,
  and **onboard/undeploy failed** when the freshest job errored. The
  Overview gains a **Waiting for heartbeat** card
  (`/api/overview.awaiting_heartbeat`).
- **`device/iox/rebake_iris_tar.py`** — replace files inside an already-built
  IOx package (`iris.tar`) offline, recomputing the entire OCI + package
  SHA256 chain (stdlib Python, no ioxclient/arm64 toolchain needed; the
  aarch64 binaries are untouched). Exists because `iris.tar` bakes the
  catalog CA and agent code at build time: after the server was re-keyed, the
  IE-3400 agent pinned a dead cert and could never reach the catalog — the
  onboard reported rc=0 but the device stayed *not enrolled* with nothing
  staged. Lab-validated: rebaked the package with the new cert (+ the
  per-peer telemetry fix the old build predated), re-onboarded the IE-3400,
  agent enrolled and staged. README documents the recipe.

## [2026.07.04.5]

The fresh-deploy release: the server now provisions its own served artifacts,
so a brand-new deployment onboards Guest Shell devices with zero manual
artifact steps (previously every onboard failed on a different missing file —
iris-agent.tgz, then bootstrap.sh on a read-only mount, then a stale
iris-catalog.pem).

### Added
- **Startup self-provisioning** (`server/provision-served.sh`, called by the
  entrypoint before services launch): rebuilds the Guest Shell agent bundle
  `iris-agent.tgz` from the bind-mounted `device/` sources on EVERY start (the
  served bundle can never drift from the deployed agent code), stages
  `bootstrap.sh`, and refreshes `iris-catalog.pem` from the server's public
  cert (a rotated cert propagates automatically). Best-effort by design —
  warns and continues if the artifacts dir isn't writable or the cert isn't
  minted yet, and logs a clear note when `iris.tar` (the IE-3400 IOx package,
  the one artifact that needs an external aarch64 + ioxclient build) is
  absent.
- **One shared bundle packer** (`server/pack-agent-bundle.sh`):
  `tools/make-agent-bundle.sh` and the startup provisioning both delegate to
  it, so the two paths cannot drift.

### Changed
- The `../artifacts` mount is now **read-write** (was read-only with a
  read-write `staging/` sub-bind): the container writes only content it
  derives itself; device integrity never rested on the mount being read-only —
  it rests on the per-device PKI trustpoint (pushed over SSH) and SHA-256 +
  Cisco-signature verification on the box.

## [2026.07.04.4]

### Fixed
- **`docker compose run --rm iris iris-bootstrap` was silently ignored**: the
  fixed `ENTRYPOINT` (`docker-entrypoint.sh`) never dispatched its arguments,
  so a one-shot command like `iris-bootstrap` was dropped and the script fell
  straight into the normal decrypt→supervise path — which fails closed on a
  fresh config volume (`FATAL: encrypted file …/secrets.json.age missing`).
  This broke the documented first-time bootstrap. The entrypoint now
  `exec "$@"` when arguments are present, before the fail-closed checks.
  Normal `docker compose up` is unaffected (the image sets no `CMD` and compose
  no `command`, so startup reaches the entrypoint with zero args and falls
  through to the supervisor as before).

## [2026.07.04.3]

The fleet-wide-undeploy release — undeploy now works on IOx devices too,
plus swarm-map telemetry-direction clarity. Lab-validated end-to-end on the
IE-3400 (undeploy → re-onboard round-trip).

### Added
- **Fleet-wide undeploy**: undeploy now covers **IOx** devices
  (IE-3x00 / IR1101 / IR18xx) as well as Guest Shell — the new
  `device/iox/uninstall.sh` tears down the IOx app (stop → deactivate →
  uninstall), removes the app-hosting appid, its VLAN/SVI, any runtime
  EEM applet, and the PKI trustpoint, and deletes the `iris.tar` package;
  it leaves `iox`, `file prompt quiet`, the AppGig trunk, `ip scp server
  enable`, and the staged image on `sdflash:` in place. `OnboardService`
  routes undeploy to the right teardown script by platform (mirroring the
  install recipes), so the earlier "IOx not supported" refusal is gone.
  Lab-validated on the IE-3400 (192.0.2.99).

### Changed
- **Swarm-map per-peer table is clearer about direction**: columns are now
  **↓ received / ↓ avg speed / ↑ sent** (was the ambiguous "received / avg
  speed / sent"), "avg throughput" → **avg download**, and a legend explains
  that every figure is *this* device's own measurement over its own transfer
  window — so a peer that served this one earlier legitimately shows **0
  sent** in its own report. Addresses the recurring "I received from .1 but
  .1 says it sent nothing" and "up vs down" confusion.

## [2026.07.04.2]

### Fixed
- **Undeployed devices kept showing as "deployed"**: undeploy removed the
  on-box agent but never cleared the device's last stored heartbeat, so the
  devices table kept rendering the stale `stage_state=ready` +
  `current_image_id` as a green **deployed** badge indefinitely. A successful
  undeploy now forgets the device's heartbeat/staging record
  (`CatalogStore.forget_device`, wired into `OnboardService` via an injected
  `clear_state_fn`), so the row falls back to **not enrolled**. The image
  ASSIGNMENT and telemetry history are intentionally kept (a re-onboard
  restages the same image). Lab-validated: 203.0.113.3/.131 flipped from
  "deployed" to "not enrolled" after an (idempotent) re-undeploy.

## [2026.07.04.1]

The console-feedback release — undeploy from the UI, honest deployment
status, and the guest-share bind-ordering fix that made fresh onboards
actually deliver. Lab-validated on 203.0.113.3 + 203.0.113.131 (full
undeploy → re-onboard cycle through the console).

### Added
- **Undeploy from the console**: select devices and hit **Undeploy selected**
  (confirm-gated) — runs the new `device/device-uninstall.sh` through the same
  bounded pool/batch panel as onboarding (`POST /api/devices/<id>/undeploy`,
  audited as `undeploy_start`/`undeploy_finished`). Removes exactly what
  onboarding added (EEM applets first, guestshell, app-hosting config, VLAN/SVI,
  IRISQ discriminator, PKI trustpoint, guest-share); leaves `iox`,
  `file prompt quiet`, the AppGig trunk and any flash-root image in place.
  Guest Shell devices only for now (IOx boxes are refused with a clear error).
  A device busy with the opposite action returns 409 — onboard and undeploy
  can never race each other on one box. Lab-validated on 203.0.113.3/.131.
- **Queue position**: queued batch rows show "#N in line" (global pool order).
- **Deployed indicator**: the devices table now shows a green **deployed**
  badge when the assigned image is staged and verified (`ready` +
  `current == assigned`), the live stage state otherwise, plus an `offline`
  hint when a device hasn't heartbeat for 10+ minutes (server-clock based).

### Fixed
- **Installer: guest-share must pre-date `guestshell enable`** — IOx binds the
  host dir into the guest at deploy time; on a fresh box (or re-onboarding
  after an undeploy) the guestshell got a permanent empty orphan dir, IOS-side
  copies landed invisibly, and bootstrap never saw a file. device-install.sh
  now creates `<fs>guest-share` right before enabling the guestshell.
- **Swarm map: duplicate icons** — peers are deduped by IP (a device
  re-announcing with a fresh key after re-onboard, or carrying several
  images, rendered as multiple nodes).
- **Swarm map: peer rows degrade to bare guest IPs** — per-peer report rows
  now resolve identity through the fleet inventory as well as the live swarm,
  so devices that finished and left the swarm still show their console device
  id + model; the seed host row is labeled "seed server".

## [2026.07.04]

The parallel onboarding release — lab-validated on 203.0.113.3 + 203.0.113.131
(both undeployed to clean state, then re-onboarded concurrently through the
console batch panel).

### Added
- **Parallel console onboarding**: the onboard service now runs up to **25
  installers concurrently** (env `IRIS_ONBOARD_CONCURRENCY`) and queues the
  rest — previously every selected device's installer was fired with no cap
  and no visibility beyond the first log. "Onboard selected" opens a **batch
  panel** with live per-device state (queued / running / done / failed /
  cancelled), duration, and last output line, polled from the new
  `GET /api/onboard/jobs`; a per-row **log** action streams any job live, and
  a page reload re-attaches the panel to whatever is still running.
- **Cancel queued** (`POST /api/onboard/cancel-queued`, audited as
  `onboard_cancel`): flips not-yet-started jobs to `cancelled`; scoped by
  `job_ids` (the console always scopes to its own batch, so concurrent
  sessions' queues survive each other); running installers are never killed
  mid-flight.
- **Per-device job dedup**: a device with a queued/running onboard job never
  gets a second concurrent installer — re-onboarding it returns the active
  job. Unknown device ids are rejected with 404 before a job is created.

### Fixed
- Onboard log SSE streams now use a 10-minute **idle** timeout (reset by new
  output and by queue-wait) with keepalive frames, instead of a hard lifetime
  cap — watching a deep-queued job no longer dies with a blank
  `[stream closed]` before the install starts. Terminal jobs are also never
  TTL-evicted while any job is still queued/running, so a long batch's
  done/failed record can't shrink mid-run.

## [2026.07.03.1]

### Fixed
- Console static assets (`index.html`, `app.js`, `styles.css`) now send
  `Cache-Control: no-cache`, so a redeploy is picked up on the next page load
  instead of being masked by a stale browser cache — which previously hid
  newly deployed UI such as the Monitoring tab until a manual cache clear.

## [2026.07.03]

The telemetry release — closes public issue #13. Devices now tell the server
how staging actually went, politely, and the swarm map moved into the Console.

### Added
- **Device telemetry reports**: after staging (or seeding-only), the agent
  posts transfer totals, link quality (HTTPS RTT median + failure streak), and
  a per-peer `~bytes` breakdown to a new device-bound catalog route
  (`POST /v1/devices/<id>/telemetry`, 64 KiB cap, optional gzip). Adaptive by
  link tier: full report + jitter on healthy links; trimmed + gzipped when
  constrained; exponential backoff (data kept) when lossy. On/off via the
  `telemetry` conf key — **default on**, both variants (Guest Shell + IE-3400
  IOx), incl. already-deployed IOx devices via the code default.
- **Bounded report store**: ring of the last 5 reports per device
  (`telemetry.json`, ~16 KB/report hard cap) + `iris_device_reports_stored`
  gauge; reports also export to Loki as OTLP `device-report` records when
  observability is on.
- **Console swarm map with manual pull**: the map is embedded in the Console
  (session-gated `/swarmmap`, nonce CSP); the drawer shows the latest device
  report and a *Pull fresh data from device* button (CSRF-protected, one
  pending request per device, 10-min TTL) — the flag rides the heartbeat
  response and the device answers on its next poll. Hub drawer gains the
  server's per-device `~sent` table.
- **Swarm map leads with the console device IP**: ring node labels, tooltips,
  and the drawer title now show a peer's console IP (its `device_id`, resolved
  by the heartbeat swarm-IP join) rather than its raw announce/guest IP, which
  rides below as a smaller `peer <ip>` detail; peers with no heartbeat fall
  back to the announce IP. The per-peer report table is now the "who served me
  how much + how fast" view — **peer · received · avg speed** (`rx_bytes` +
  per-peer `avg_bps`), resolving each serving peer to its console device where
  known, with seeding (`tx_bytes`) surfaced inline only when nonzero. The
  detail drawer widened (340 → 440px) so the richer table fits without overflow.
- **Monitoring time-travel timeline**: the audit trail tab gains a clickable
  histogram above the table, with 24h/7d/30d/90d/All range chips. Clicking a
  bar filters the table to that bucket's window; a *clear selection*
  affordance returns to the full range. New `GET /api/audit/histogram`
  (session-gated, category-validated) backs it; `audit.read_events()` gains
  an `after_ts` lower bound and a new `audit.histogram()` helper bins events
  into evenly-spaced, zero-count-inclusive buckets.
- **Tactile console buttons**: `.btn`/`.btn.ghost` gain hover, `:active`
  press, and `:focus-visible` ring states (previously no feedback on click);
  a new `.chip` style backs the timeline's range presets.
- **Monitoring time brush**: the timeline histogram gains a draggable,
  auto-zooming time brush — drag on empty space to select a range, drag
  either edge handle to adjust, drag the middle to pan; the 24h/7d/30d/90d/All
  chips set the outer window, a visible range readout with a clear (×)
  affordance (or Escape) resets it. Selections refetch the histogram at a
  finer bucket count (auto-rezoom lands near minute resolution under ~2h) and
  window the audit table. Backing it, `GET /api/audit/histogram` accepts an
  explicit `since_ts`/`until_ts` epoch window (both required together;
  `until_ts > since_ts` validated, else 400; the `window=<secs>`-ending-now
  behavior is unchanged otherwise) and the response gains `bucket_seconds`.
- **Operator-readable audit log** (public issue #19): every console emission
  now carries a compact human `detail` an operator can read directly —
  uploads log size + publish job id, CSV imports log new/updated/skipped
  counts, assigns name the image (filename + size + previous image),
  credential/profile/stage-host changes log before → after (never secrets),
  deletes record what was removed (and *fail* when nothing existed),
  onboard start/finish correlate through the job id and finish logs
  duration + platform + rc + the first ERROR line. New emissions: async
  `image_publish_finished` (a failed publish previously left no audit
  trace), blocked image deletes (409), and rejected uploads. The Monitoring
  table now composes these into a Message column (actor + verb + target —
  detail) with ok/fail result badges and relative timestamps, and renders
  legacy broker token events first-class instead of `undefined` columns.
- **Model column in the fleet inventory**: `devices.csv` and the Console device
  form gain an optional trailing `model` column (7 cols; older 6-column CSVs and
  exports still import unchanged). Model drives deterministic platform selection
  for onboarding (Guest Shell vs IOx); left blank, the first onboard auto-detects
  it via a live `show version` probe and caches it back onto the device row.
- **Platform-aware Console onboarding**: one-click onboard picks the installer by
  device family — Guest Shell (`device/device-install.sh`) for the Catalyst
  9300/ISR/ASR/CSR/C8000v families, or the IOx Docker installer
  (`device/iox/install.sh`) for the IE-3x00/IR1101/IR18xx families that cannot run
  Guest Shell — by the device's `model`/`platform` or by live auto-detection. IOx
  onboarding fails fast, before touching the device, if `iris.tar` is not yet
  staged in `artifacts/`.
- **Reusable credential profiles + bulk onboard**: define login profiles
  (username + password + optional enable secret) once and attach them to many
  devices; passwords are stored age-encrypted and never returned to the browser.
  Devices can be multi-selected in the Console and onboarded in one bulk action,
  each with its own per-device credential profile.

### Changed
- `:9101/swarmmap` retired — it now serves a pointer to the Console; `/swarm`
  JSON, `/healthz`, and opt-in `/metrics` are unchanged. Firewall guidance
  drops `9101` from the device-inbound list (device reports ride `8443`).
- Heartbeats carry `telemetry_enabled`; heartbeat responses can carry
  `report_requested` (older agents ignore it; older servers drop the field —
  no flag-day).
- Per-peer telemetry is now accurate: instead of shipping the raw
  rate-integration approximation (which read `0` for fast <2-min downloads),
  the agent **attributes the accurate transfer total across peers by observed
  share** and reports a per-peer average receive speed. Each peer row gains
  `avg_bps` and the row `rx_bytes` now sum to the real total exactly; a
  single-peer or no-sample transfer attributes the whole total to its
  peer(s). The completion snapshot takes one final peer sample before marking
  done so at least one real-elapsed window lands. Server ingest whitelists the
  new `avg_bps` int (coerced, 20-row cap unchanged).
- Console-driven bulk onboarding no longer requires stage-host credentials in
  the standard single-container deployment: the Console stages each device's
  agent config directly (it always runs co-located with the artifact server),
  falling back to the ssh-based stage-host path only for genuinely remote
  stage hosts.
- `server/docker-compose.yml` now binds `../artifacts/staging` read-write
  (nested inside the otherwise read-only `../artifacts:/srv/artifacts:ro`
  mount) so the co-located Console can actually write the per-device configs
  the local-staging path above depends on; served content (agent bundle,
  images) stays read-only. `docker-entrypoint.sh` creates the host-side
  `staging/` dir on start.
- `device-install.sh`'s local-staging path no longer re-copies `bootstrap.sh`
  and `iris-catalog.pem` into the artifacts root when they're already present
  (provisioned ahead of time by `tools/make-agent-bundle.sh`), avoiding a
  "Read-only file system" failure at step [2/6] against the now read-only
  served tree; the laptop-operator path (empty, writable artifacts dir) still
  copies them as before.
- **Published Console port is parameterizable**: the Console's published port and
  the `:9101` pointer-page URL are no longer hard-coded — set via
  `server/docker-compose.yml`, so a deployment can move the Console off `8080`
  without editing source; the `:9101` pointer page links to whatever port the
  Console is actually published on.
- **Console leads with the descriptive project name**: the web UI now presents
  "intelligent-release-image-staging" as the product name (acronym shown inline
  once introduced), per the project naming policy.

### Fixed
- **CSV downloads work over self-signed TLS**: Export CSV and the Example CSV
  template button now fetch same-origin and save via a Blob object URL instead of
  a download-attribute anchor, which Chrome silently blocks on connections with
  certificate errors (self-signed labs) — the buttons previously appeared dead.

## [2026.07.02]

The Console release: the tool gains a web GUI. One new stdlib-only HTTPS service, baked into
the existing server image — no new dependencies, no separate deploy — and the
distribution/staging pipeline itself is untouched: existing deployments keep working
unchanged. The Console preserves the hard stage-only invariant: it can assign images but
can never install, activate, or reload a device. Test-driven throughout; full suite:
504 pytest green.

### Added

- **The Console — a web GUI to administer the whole system from a browser.** A
  stdlib-only HTTPS service (`iris-gui`) on `:8080`, baked into the same server image and
  started automatically with the stack; no separate deploy. A single scrypt-hashed admin
  account is created by a first-run browser wizard or the `iris-gui-admin` CLI and stored
  age-encrypted at rest. Screens: **Overview** (fleet totals + per-image rollout),
  **Images** (drag-and-drop upload → publish/seed, plus delete — a full delete that is
  refused while any device is still assigned that image), **Devices** (inline add / CSV
  import-export with a downloadable example-CSV template, reusable age-encrypted
  credential profiles, per-device image assignment, one-click SSH onboarding with a live
  streamed log), **Swarm**, and **Settings** (server & build info; a change-admin-password
  form — a successful change signs out every other session; an active-session count with a
  "sign out other sessions" control; and the stage-host SSH login, below). Preserves the
  hard stage-only invariant end to end — assigning an image only sets the catalog's
  `approved_image_id` (`install_allowed` stays false); the Console can never install,
  activate, or reload a device. Hardening: HttpOnly/Secure/SameSite session cookie,
  double-submit CSRF, `default-src 'self'` CSP, path-traversal guard, 4 GiB upload cap,
  and a clean `400` (never a dropped connection) on a malformed or valid-but-non-object
  JSON body at every JSON endpoint; admin, device-credential, and stage-host passwords
  are never returned to the browser. Adds an `iris-images` Docker volume for
  Console-uploaded images (the device inventory `fleet.json` lives on `iris-state`).
  See the README's "The Console (the web GUI)".
- **Stage-host SSH credentials — one-click onboarding works from Docker.** A Console
  container never owns `IRIS_HOST_IP` (it has its own network namespace), so
  Console-driven onboarding always takes the installer's remote-`STAGE_HOST` branch,
  which SSHes the per-device artifacts to the stage host. That login is now configured
  once under **Settings → Stage host** and stored age-encrypted in the same secrets
  store as the admin account and the device credential profiles; `GET /api/settings`
  reports only configured-plus-username, never the password. Onboarding injects it into
  the installer's environment — the stored value beats an inherited
  `HOST_USER`/`HOST_PASS`, and leaving it unset keeps the plain env passthrough (the
  on-host CLI case needs neither) — and the streamed onboard log echoes no password.
  See the README's "Onboarding from Docker (stage-host credentials)".
- **Release version surfaced in Docker.** The image bakes an optional `IRIS_VERSION`
  build arg (`IRIS_VERSION="$(cat VERSION)" docker compose -f server/docker-compose.yml
  up -d --build`, or set it once in `server/.env`); the Console's Settings page shows
  it — unset, it reads `unknown`.

### Security

- **Installer:** `device-install.sh` now feeds the stage-host password to `sshpass` via
  the environment (`sshpass -e`) instead of `-p <password>` on the command line, so it
  never appears in the process argv (world-readable in `/proc`) while artifacts are
  staged. Applies to every invocation — Console-driven and CLI alike.

### Docs

- The README documents every install- and operations-phase port in a new "Ports &
  network flows" section (source → destination, transport, purpose, plus a firewall
  summary and caveats); the swarm-map, observability, and scaling tables were
  reformatted to read cleanly in raw markdown as well as rendered.

## [2026.06.29]

A security-hardening and robustness pass driven by a full-codebase review (two
independent adversarial review rounds; every change test-driven). Behavior-compatible
with existing deployments — no schema or config-key changes. Validated end-to-end on
hardware: a clean teardown + redeploy staged and signature-verified the assigned image
on all five lab devices (4× Catalyst 9300 on `flash:`, 1× Catalyst IE-3400 on `sdflash:`).

### Security
- **Secrets broker:** token-refresh now re-checks the device's revoked status *under the
  store lock*, closing a revoke-then-refresh race that could hand a just-revoked device a
  fresh, working catalog token. Durable (age-encrypted) secret writes are atomic and roll
  back on a failed rename so a crash can't leave the durable store ahead of live.
- **Concurrency:** shared catalog state and the secret store are serialized with an
  advisory file lock and written via unique-temp `os.replace`, eliminating torn writes,
  lost token rotations, and lost heartbeats under the threaded server. The tracker
  `PeerRegistry` is now lock-guarded across its announce/prune/metrics threads.
- **Swarm map:** all device-supplied fields are HTML-escaped before rendering (fixes a
  stored XSS); the per-peer Loki query value is URL-encoded.
- **Tracker:** client-supplied `ip=`/port overrides are validated; an out-of-range port no
  longer poisons the peer list (the peer is excluded rather than advertised on a wrong port).
- **Artifact server:** directory listing is disabled; per-device staging configs are swept
  on a time bound (retry-safe while keeping credential exposure short).
- **Fail-closed secrets:** the seeder and the lab RPC tools refuse to run with a missing or
  empty aria2 RPC secret; the IOx build verifies the catalog certificate by SHA-256
  fingerprint instead of fetching it unverified.
- **Bare-metal install:** systemd units decrypt age secrets to a tmpfs `RuntimeDirectory`
  before start; the age master key is stored outside the directory holding its ciphertext;
  `ProtectSystem=strict` `ReadWritePaths` corrected so the catalog can write its audit log.

### Fixed
- **Device agent:** a transient catalog/heartbeat error no longer discards completed
  copy-to-root progress (the heartbeat is best-effort and catches all transient errors);
  the catalog `.torrent` is downloaded atomically.
- **Catalyst IE-3x00:** the installer stages to `sdflash:` (matching its dry-run); the IOx
  app run options carry the device's own SSH host/user; the in-container aria2c is restarted
  if it dies between ticks.
- **Publish:** an image is added to the seeder before its catalog entry is committed, so it
  is never advertised before it is seedable.
- **Robustness:** the catalog returns `400` on a malformed `Content-Length` instead of
  crashing; release packaging scrubs all shipped text files; installer generation handles a
  final CSV row without a trailing newline; on-switch `aria2c` logs are rotated.

### Changed
- Test suites hardened to assert real behavior (multi-assertion `bats` tests split into
  independent cases; auth-guarded routes exercised through the guard; escaping and
  concurrency covered). Full suite: 389 pytest + the `bats` suites green.

### Docs
- The README and `device/iox/README.md` were corrected and expanded against the live
  teardown + redeploy: code-sync caveats, the Catalyst IE-3400 IOx-app teardown, the
  IE-image publish environment, `docker compose exec -T` over a non-interactive shell, and
  a note that the catalog `cisco_signature_verified` field is metadata (the authoritative
  check is the on-device `copy /verify`).

---

**Also in this release** — the descriptive-name lead, the Catalyst IE-3400 bring-up, and the
unified swarm map, which had not previously been cut to a tagged release:

Docs: the project now leads with its descriptive name **intelligent-release-image-staging**
in the README and other docs (per Cisco OSS small-project naming guidance, to avoid
brand-infringement risk). **IRIS** is retained as the defined acronym and for executable
names (`iris-agent`, …), `IRIS_*` env vars, metric names, and syslog markers. No code,
config-key, or repo-slug changes.

IE-3400 bring-up (#18): intelligent-release-image-staging now runs on the Catalyst IE-3x00 (which cannot run
Guest Shell) as an aarch64 **IOx Docker app** (`iris.tar`). A runtime-mode seam
in `build_deps` (`cli_ssh.select_cli`) re-binds `cli_execute`/`cli_configure` to
an **SSH-to-self** transport (`device/agent/cli_ssh.py`) in container mode while
leaving the C9300 Guest Shell path byte-identical. `emit()` is now best-effort
(`_emit_impl`) so a transient transport failure never aborts a tick. The build
context + reproducible packaging live in `device/iox/`. Validated on hardware
(`192.0.2.99`): container RUNNING/healthy, token-refresh + heartbeat over the
catalog, model/version/free read over SSH-to-self, image downloaded over the
swarm — the IE-3400 appears on the swarm map as `IE-3400-8T2S`. The agent stages the
image to `sdflash:` (IE3x00 analog of the C9300's `flash:`): a repeatable installer
(`device/iox/install.sh`, mirroring `device-install.sh`'s trustpoint + `:8000` https
transport) deploys the app, and since IOx can't bind-mount `sdflash:`, the agent
**scp-pushes** the downloaded image to `sdflash:guest-share/iris/` (device SCP server)
then `copy /verify`s it to `sdflash:<img>`. Requires the SD partitioned (IOS vfat + IOx
ext4). The final `copy /verify` to `sdflash:<img>` is validated on hardware: the IE-3400
stages and places the assigned image at `sdflash:` root, signature-verified, reaching
`stage_state=ready`.

Swarm map — **unified multi-image view**: the map now shows every device across
every torrent at once (default "All images"; node colour = image, per-image
legend, per-image selector to filter), with the server seeder deduped to the
central hub. Previously it rendered one torrent at a time and defaulted to the
first, hiding devices on other images. `/swarm` now also surfaces `host` (the
seeder IP) so the map can dedupe the server robustly.

Scaling — documented the swarm's scaling model and knobs (device re-seeding as the
load-fan-out mechanism, `max_peers` fan-out cap, tracker announce/prune limits,
multi-image swarms, secondary seeders) plus honest large-scale limits. No
behavioural change; the peer registry already prunes stale peers and caps numwant.

## [2026.06.23]

IE3k `sdflash:` staging (#24): the agent stages and copies on `sdflash:` on
IE-3x00 switches (IOx/guestshell runs from the SD card), de-hardcoding `flash:`
as the staging filesystem. Install/bundle reclaim and the C9300 flow are
unchanged; mode detection applies identically on both platforms.

## [2026.06.22]

Secrets broker (#27): all coordination-server secrets are now encrypted at rest
and devices enroll with short-lived, self-rotating tokens — no plaintext
token/rpc-secret files anywhere. Also ships the device-neutral rename (#25).
Validated end-to-end on a 4-switch Catalyst 9300 lab (including bundle mode).
Image distribution/staging behavior is unchanged.

- **At-rest encryption (#27):** the tracker/catalog/seeder secrets
  (`secrets.json`, `rpc-secret`, TLS key) are age-encrypted on the iris-config
  volume and decrypted to a `/run/iris` tmpfs at start — no plaintext
  `tokens.txt`/`rpc-secret` on disk. New `iris-bootstrap` one-shot mints the
  initial encrypted material; the master age identity is supplied out-of-band (a
  Docker secret) and the container fails closed without it.
- **Short-lived enrollment tokens (#27):** the per-device installer bakes only a
  1-hour enrollment token (no permanent secrets); the agent self-promotes it to a
  rolling 7-day catalog token on its first refresh, which also delivers the
  device's `announce_token` and `rpc_secret`. `iris-mint-enrollment` provisions all
  three; `bootstrap.sh` reconciles aria2c's RPC secret with the fetched value.
- **Audit log (#27):** records only short, non-secret ids — a truncated sha256 of
  a token value, never any prefix of the value itself.
- **Device-neutral terminology (#25):** renamed `switch`→`device` across the API
  (`/v1/devices`, `device_id`), server state (`devices.json`), the on-device agent,
  the `device/` directory (was `switch/`), lab helpers (`device-run.sh`/`device-copy.sh`),
  fleet CSV headers, and `DEVICE_*` env vars. Breaking, no backward compatibility —
  re-provision deployed agents (new `iris-agent.conf` uses `device_id`). `peer_id` (BEP3)
  and syslog mnemonics are unchanged.

## [2026.06.15]

Added server-side telemetry that feeds an external observability stack
(Prometheus + OTLP/Loki). Observational only — no change to how the system
distributes or stages images, and no switch-side changes.

- **Tracker `/metrics` endpoint** (Prometheus text exposition) on `:9101`,
  serving low-cardinality per-image swarm gauges (seeders, leechers, peers,
  bytes-remaining, completed-total) plus seeder throughput sampled from the
  aria2 RPC and tracker counters. Always served; isolated from the token-gated
  `:6969` announce surface.
- **Per-switch lifecycle events** (join/complete/stop/stale) exported as
  OTLP/HTTP-JSON logs to an OpenTelemetry collector (`IRIS_OTLP_ENDPOINT`) →
  Loki, keeping per-switch (high-cardinality) audit out of Prometheus labels.
- New env: `IRIS_METRICS_PORT` (default `9101`), `IRIS_OTLP_ENDPOINT` (export
  disabled when unset), `IRIS_SAMPLE_INTERVAL` (default `15`). `docker-compose`
  publishes `:9101` and passes `IRIS_OTLP_ENDPOINT`.
- Stdlib only; no third-party dependencies. Telemetry is best-effort and never
  on the announce critical path (a failed metrics bind or unreachable collector
  cannot disrupt the tracker).

## [2026.06.12.1]

**End-to-end switch↔server TLS trust.** Transport-security only — the system still
distributes and stages only, never installs, activates, or reloads.

- **Install-time file push moved to verified HTTPS** (issue #2). New HTTPS artifact
  server (`server/artifact_server.py`) mirrors the catalog's TLS, reusing the same
  cert on the same port `:8000` (docker path only; bare-metal unchanged). The
  per-switch installer pushes the server cert into a PKI trustpoint (`IRIS`) over SSH
  first, then `copy https://…:8000/…` delivers the bootstrap, per-switch config, RPC
  secret, agent bundle, and the agent's pinned CA (`iris-catalog.pem`) — so the
  per-switch catalog token and the aria2 RPC secret no longer travel in cleartext.
- **Agent→catalog TLS now verified** (issue #12). The agent verifies the catalog cert
  against a pinned CA (`catalog_ca`), via a verify-if-present seam: an un-pinned legacy
  config keeps working but logs a warning, so an agent-only upgrade never breaks the
  running fleet.
- The on-box image-trust chain (SHA-256 + Cisco `verify`) is independent and unchanged.
  The live on-switch trustpoint import + `copy https:` is a documented deferred
  hardware-validation step (also feeds the Tier-2 spike).
- Docs: the switch decommission / cleanup steps (`README.md`) now also remove the `IRIS`
  PKI trustpoint and `iris-catalog.pem`, so a true clean slate leaves no IRIS state behind.

## [2026.06.12]

Relicensed to Apache-2.0 and added open-source governance. No functional
changes — the system still distributes and stages only, never installs, activates,
or reloads.

- **Relicensed from GPLv2 to Apache-2.0.** Replaced `LICENSE` with the
  Apache-2.0 text and added the Apache-2.0 header to every source file.
- The runtime tools the project drives — `aria2c` and `mktorrent` (GPLv2) and
  `openssl` — are invoked as separate programs (subprocesses), not linked into
  or derived from the project; see [`NOTICE`](NOTICE) for per-tool attribution.
- Added `NOTICE`, `SECURITY.md`, `CODE_OF_CONDUCT.md` (Cisco Open Source Code
  of Conduct), and `CONTRIBUTING.md`.
- Updated `README.md` (added a License section) and release tooling.

## [2026.06.11.1]

Initial alpha release of **intelligent-release-image-staging (IRIS)**.

Peer-to-peer staging of large software images across Cisco devices — validated
end-to-end on real Cisco Catalyst 9300s (IOS-XE 17.18.x, install mode) in an
SD-Access fabric (IS-IS underlay):

- Dockerized **tracker / catalog / seeder** distributes images over a private
  BitTorrent swarm (DHT/PEX/LPD off; token-authenticated tracker; HTTPS catalog).
- **On-switch Guest Shell agent** (native EEM, 60-second timer) downloads over the
  swarm, verifies **SHA-256 + the Cisco digital signature**, and stages the image at
  `flash:` via a native EEM copy-to-root applet.
- **Distributes and stages only — never installs, activates, or reloads.**
- Flash reclaim uses `install remove inactive` non-interactively (a templated
  `IRIS-RECLAIM` EEM applet) and only once per image.
- GPLv2 licensed; CalVer versioning; credentials, switch images, and generated
  artifacts kept out of the repository.

**Tested and supported:** Cisco Catalyst 9300, IOS-XE 17.18.x (install mode).
Support for other Cisco devices/platforms is planned but not yet tested.
