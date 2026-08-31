# Changelog

All notable changes to **intelligent-release-image-staging (IRIS)** are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses **Calendar Versioning (CalVer)**: `YYYY.0M.0D` with an optional
`.MICRO` counter for multiple releases on the same day (e.g. `2026.06.11`, then
`2026.06.11.1`). Releases are tagged `vYYYY.0M.0D`. The current version is in the
top-level `VERSION` file.

## [Unreleased]

### Added
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
  This platform is not lab-validated yet — see
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
  Lab-validated on the IE-3400 (100.90.168.99).

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
  restages the same image). Lab-validated: 100.92.9.3/.131 flipped from
  "deployed" to "not enrolled" after an (idempotent) re-undeploy.

## [2026.07.04.1]

The console-feedback release — undeploy from the UI, honest deployment
status, and the guest-share bind-ordering fix that made fresh onboards
actually deliver. Lab-validated on 100.92.9.3 + 100.92.9.131 (full
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
  can never race each other on one box. Lab-validated on 100.92.9.3/.131.
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

The parallel onboarding release — lab-validated on 100.92.9.3 + 100.92.9.131
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
(`100.90.168.99`): container RUNNING/healthy, token-refresh + heartbeat over the
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
