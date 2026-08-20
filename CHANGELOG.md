# Changelog

All notable changes to **intelligent-release-image-staging (IRIS)** are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses **Calendar Versioning (CalVer)**: `YYYY.0M.0D` with an optional
`.MICRO` counter for multiple releases on the same day (e.g. `2026.06.11`, then
`2026.06.11.1`). Releases are tagged `vYYYY.0M.0D`. The current version is in the
top-level `VERSION` file.

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
