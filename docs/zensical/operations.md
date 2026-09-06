<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Operations

This page collects the actions operators perform after the first deployment.

## Daily commands

| Task | Command |
| --- | --- |
| Start server and Console | `docker compose -f server/docker-compose.yml up -d --build` |
| View server logs | `docker logs iris` |
| View Console logs | `docker logs iris-console` |
| Publish image | `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<path>/<image>.bin` |
| Show images and assignments | `docker compose -f server/docker-compose.yml exec iris iris-assign` |
| Apply assignments | `tools/apply-assignments.sh fleet/assignments.csv` |
| Create or reset admin | `docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin` — a reset also ends every live console session ([Console sessions](security.md#console-sessions)) |

`apply-assignments.sh` and `gen-device-installers.sh`
([Prepare devices](getting-started.md#prepare-devices)) require the running
`iris` container by that name; set `IRIS_CONTAINER=<name>` if yours differs.

The Console is a separate service. It reaches the server through the internal
HTTPS management API on TCP 9443; it does not mount the server's state or image
storage. For [separate Docker hosts](docker-hosts.md), use
`server/docker-compose.server.yml` on the server and
`server/docker-compose.console.yml` on the Console host, with that host's
`--env-file`. For Kubernetes, use the corresponding deployments:

```bash
kubectl -n iris exec deployment/iris-seed-server -c iris -- iris-assign
kubectl -n iris logs deployment/iris-seed-server -c iris
kubectl -n iris logs deployment/iris-console -c console
```

## Recognizing an ownership problem

Every service runs at uid 10001, so a path the server cannot reach at that uid
produces a recognizable symptom rather than a crash: the Images screen lists a
file as `not readable by the server`, a secret store that worked before fails to
decrypt, or onboarding fails while downloading the agent bundle. These are
ownership problems, not corrupt state.

The host age key and artifacts directory must be owned by uid `10001`; see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).
State, configuration, and uploads volumes need the same ownership. Check
restored or manually copied files against [Volume permissions](server.md#volume-permissions).

## Unreachable devices at onboard

A Guest Shell onboard job probes the device before running the installer. An
unreachable device — wrong IP, wrong credentials, no network path — fails the
job immediately with `cannot reach device <ip> — ping/SSH probe failed; check
the device IP and credentials` instead of silently doing nothing. Router and
IOx onboarding also run a live preflight.
Submit-time rejections render in the console and are audited like any other
onboarding failure.

IRIS does not send `enable` and its secret unless the device's own prompt has
shown that the login lands at user EXEC (`>`). Sending that pair to a login
already at privileged EXEC (`#`) executes the secret as a command, which IOS may
try to resolve as a hostname and can delay every session by tens of seconds. A
device that genuinely needs enable fails its first unprivileged session loudly,
is learned from the prompt, and succeeds on retry. Set
`IRIS_DEVICE_ENABLE_ALWAYS=1` only for a known environment that must start
escalated; even then the pair is dropped for the rest of that process as soon
as a session shows a privileged prompt.

## Bulk device actions

Network-wide changes come from the Devices toolbar, which acts on every checked
row instead of one row at a time. Bulk operations report per-device refusals
rather than failing the batch, so a partial result is normal: the status line
counts the successes and names the devices that refused. The controls and their
individual effects are documented in
[Bulk device actions](console.md#bulk-device-actions).

## Onboarding at scale

`POST /api/v1/devices/<id>/onboard` resolves the plan, checks for a conflicting
deployment record, and returns a job id. Router preflight — the read-only
collision, identity, and NAT checks in
[Router preflight and ownership](management-type.md#router-preflight-and-ownership)
— runs in the onboarding worker before it mints an enrollment token or applies
any device configuration. A preflight failure fails that job and appears in
its log; other queued jobs can continue.

`IRIS_ONBOARD_CONCURRENCY` limits the number of running jobs (default 25).
`GET /api/v1/onboard/jobs` reports the limit as `max_concurrent`.

The installers group read-only pre-checks and final verification into one
device session each. State-polling loops make a fresh observation on every
iteration. Guest Shell readiness waits 2, 4, 6, and then up to 15 seconds
between observations.

## Peer-policy operations and their backlog

Every policy mutation — a quarantine assignment from the console, or its removal
— is committed under a single lock and appends a stable entry to an **outbox**
that the tracker drains. The tracker reports how far it has consumed through
`last_operation_exported_revision` in the enforcement status file, and entries at
or below that watermark are pruned on the next commit.

The outbox is capped at **256** unacknowledged entries, and the cap is checked
*before any write*. A mutation that would exceed it is refused with
`503 operation_backlog_full`, so a stalled consumer blocks new operations instead
of silently discarding them. A 503 here means the tracker is not draining — check
that it is running and reconciling before retrying the mutation.

The same route separates its other refusals, and they mean different things:

| Response | Meaning |
| --- | --- |
| `409 revision_conflict` | Policy changed elsewhere; the current revision is returned so the caller can retry against it. |
| `422 policy_error` | Policy is degraded — running on the last-known-good copy. Repair the authoritative file. |
| `503 policy_fail_closed` | Policy is fail-closed; mutations are refused entirely. |
| `503 operation_backlog_full` | 256 operations are unacknowledged. The tracker is not draining. |

## Endpoint writes that fail

An authenticated announce from an attributable principal records the peer's
address in the durable endpoint map under `IRIS_STATE`, aged out by
`IRIS_ENDPOINT_TTL` (seconds; a non-positive or non-numeric value falls back
to the 900 s default rather than disabling enforcement). The address recorded
for a **device** is always the announce's socket source; the BEP3 `ip=`
override is honoured only for the service seeder, whose container source is
loopback. If that durable write fails, the entry is queued in memory and
retried on the following reconcile passes rather than being dropped — the
device keeps participating in the swarm meanwhile, but the reported enforcement
status degrades until the write lands, because the derived deny set is computed
from durable state.

Rows belonging to a quarantined or revoked device are **not** aged out by the
TTL: the seeder block for a device that has stopped announcing stays in place
until the device is un-quarantined or re-onboarded (which clears its rows), not
merely until the TTL lapses.

### How the map is stored

The endpoint map stores one row per principal in `peer-endpoints.d/`, spread
over 256 shard files. An announce locks, parses, and rewrites only its own
principal's shard. Each write is atomic: a temporary file followed by a rename.

The capacity of the map is the supported fleet size **plus** headroom for
service principals, so a full fleet of devices and the `service:seeder`
principal all fit without evicting anything. The capacity bound is applied by
the reconciler's maintenance pass, not by each announce.

A corrupt or unreadable shard — unparseable JSON, a wrong schema, or a
malformed endpoint row — is treated as fail-closed rather than empty: the reconcile pass stops before deriving or applying anything, existing
blocks stay in place, and the recorded state is forced to `fail_closed`. Peer
discovery for device and service principals continues (the announce still
returns its peer list; the endpoint it could not write waits in the retry
queue), while a legacy-token announce gets no peers until the store is readable
again, because the tracker cannot tell whether its address belongs to a
quarantined device.

If a reconcile pass fails for any other reason (for example the state volume is
full when the status file is written), the loop records `degraded` with the
exception type in `last_error` where it can and retries on the next poll; it
never stops.

If even that degraded write fails — or the tracker process itself is
down — `peer-enforcement.json` simply stops changing, and its last recorded
state (possibly `enforced`) would otherwise sit there looking current
indefinitely. The console's peer-policy badge (device inventory, Peer
policy column) does not take a frozen state at face value: `GET
/api/v1/peer-policy` derives `enforcement.stale` from how long it has been
since `last_reconciled_at` (never, or more than five minutes — several
multiples of the reconciler's own 60-second maintenance deadline, to absorb
scheduling jitter without false-flagging a healthy but quiet fleet) and the
badge shows `<state> (stale)` regardless of what that state is, with the
last-reconciled time and `last_error` in its tooltip. A stale badge means
"go check the tracker process," not "policy is misconfigured."

## Retiring a device

Deleting a device revokes its credentials first. The revoke is written durably
under the secrets-store lock before anything else is touched; if that write
fails, the delete is aborted and no fleet, catalog, or policy state changes. Once
the revoke is durable, the remaining cleanup is best-effort and a partial cleanup
is reported rather than hidden.

Endpoint rows are deliberately **retained** until they age out. A revoked device
is denied through its still-fresh retained endpoint regardless of policy, so the
order of cleanup cannot accidentally re-permit it. Re-onboarding clears the
device's old endpoint rows before the fresh credential becomes usable, and aborts
without minting if that clear fails.

## Forgetting a device's SSH host key

Every SSH/scp session IRIS opens itself — device transports, the installers'
stage-host push, the XR RPM scp — verifies the peer per
[Security → Device SSH host keys](security.md#device-ssh-host-keys).
By default that is trust-on-first-use: the first session records the peer's
host key into a persistent `known_hosts` under the IRIS state volume, and
every later session must present the same one.

A device that is re-imaged or replaced presents a **new** host key, and every
session against it then fails with a changed-key error — correct behavior
(the alternative would be silently trusting a possibly-different box), but
with nothing recorded to distinguish "legitimately re-imaged" from "someone
else answering at that address" beyond the operator's own judgment, and the
persistent `known_hosts` file lives inside the state volume, which the
operator does not always have shell access to reach directly.

**Console:** open the device's deployment details drawer and use **Forget
host key**. This is a trust decision, so it asks for confirmation, and it is
audited (`device_forget_host_key`, naming the device and the console user)
either way. See [Reference → Devices](reference.md#devices) for the
underlying route.

**From a shell with access to the state volume:** the hint
`iris_ssh_explain` already prints on a changed-key failure works directly —
`ssh-keygen -R '<device_ip>' -f '<state>/ssh/known_hosts'`.

Either path only clears the stale entry; it does not disable verification.
The very next session re-verifies and pins whatever key the device now
presents, the same trust-on-first-use flow a brand-new device gets. Neither
path touches `IRIS_SSH_HOST_KEY` (a per-device pin) or an operator-supplied
`IRIS_SSH_KNOWN_HOSTS` file — clearing either of those, if set, is the
operator's own decision.

## Backups

Back up the server's `iris-state`, `iris-config`, and `iris-images` volumes,
the host age identity named by `IRIS_AGE_KEY_FILE_HOST`, and image files under
the read-only import root. Keep the matching state, configuration, and age
identity together: a certificate alone cannot restore device credentials,
assignments, or deployment records.

For one-host Compose, preserve the `iris-tier-auth` and `iris-management-ca`
volumes when restoring the Console-to-server identity. With separate Docker
hosts, back up each host's local credential and TLS directories instead; keep
the management private key on the server host and the default browser private
key on the Console host. Treat the tier credential backup as a secret.
Generated device packages and their adjacent
manifests live in the host artifacts directory; retain them if you need to
redeploy the same build.

For Kubernetes, snapshot the `iris-data` PVC and back up the separately managed
age identity, tier-auth Secret, and management TLS Secrets. The Console has no
state PVC; its persistent application state is on the server.

## Audit export

The console can ship the audit trail (`audit.jsonl`) off the box: *Settings →
Audit export* takes an SCP destination (host, port, user, remote path), an
age recipient, and the SCP password. Every export encrypts the trail to that
recipient before it leaves the server — encryption is mandatory, there is no
plaintext export path, and a missing recipient refuses the run rather than
degrading. The password lives in the age-encrypted secrets store, never in
the settings file, and reaches `scp` through the environment, never argv or a
log line.

Exports run on demand (**Export now**) or on the daily schedule (**Export
daily**): the scheduler makes its first pass shortly after server start and
then at most one attempt per day — failed attempts count, so a broken
destination retries daily rather than hourly. Each upload is a fresh
timestamped file (`audit-<utc>-<suffix>.jsonl.age`), so two exports never
overwrite each other at the destination. The sub-page's status line shows the
destination, the schedule mode, and the last run — timestamp plus `ok` with
the uploaded filename or `fail` with the reason — and every run is also
recorded in the audit trail itself as `audit_export`.

The destination's SSH host key is pinned trust-on-first-use: the first export
records it in a known-hosts file under the server state directory
(`audit-export-known-hosts`), and later exports fail if the destination's key
changes. Verify the fingerprint out of band where the destination warrants
it, and remove that file after an intentional host rebuild.

Audit events are append-only. Use the structured action and device fields for
saved searches rather than matching detail text.

## Image verification

*Settings → Image verification* checks the catalog's images against Cisco's
published Bulk Hash feed and quarantines a sha512 mismatch — see [Cisco Bulk
Hash verification](security.md#cisco-bulk-hash-verification) for what the
check does and what a quarantine changes. A locally-rebuilt image that
reuses a Cisco filename mismatches and quarantines on its next verification
run; the check has no way to distinguish that from tampering, which is the
point.

Every Console upload or **Import from disk** publish starts a reconciliation
immediately, independent of the schedule. Its job progresses from `publishing`
to `verifying`, then reports the new image's verdict. Concurrent imports share
a successful refresh when its catalog snapshot covers their images. An image
registered after that snapshot takes a fresh pass, and a failed refresh is
never reused as success. A feed failure is
reported as verification incomplete without falsely claiming the durable
publish failed.

The schedule has three modes: **off** (the default), **daily**, and
**weekly** — both timed modes fire at a configured `hour_utc` (0-23), and
weekly always anchors to Monday UTC; there is no day-of-week setting. A slot
the server was down for is skipped, not made up: the next scheduled slot
runs normally, and nothing catches up for the one that was missed. **Refresh
now** in the same pane runs the check immediately; if a run is already in
progress, the button and the API both answer "already in progress" rather
than starting a second one.

Air-gapped servers can upload the feed tar directly instead of the server
fetching it: the same pane's offline upload takes a raw `.tar` (256 MiB cap)
and runs it through the identical signature-verification-then-parse
pipeline, recorded as `source=offline`. A scheduled run is
`source=scheduled`; **Refresh now** is `source=manual`.

The pane's status line shows the last run's time, source, outcome, and
matched/mismatched/not_in_feed counts. Every run is audited as
`bulkhash-refresh` — scheduled runs record `actor=system`, a manual refresh
or offline upload records the console operator who triggered it; a schedule
change is audited separately as `bulkhash-schedule-config`, and an offline
upload additionally as `bulkhash-offline-upload`.

### Releasing a quarantine

An image quarantined by a sha512 mismatch cannot be newly assigned to a
device — an assignment attempt is refused with the verdict that blocked it.
From the image's detail view, **Release** re-runs the sha512 comparison
against the stored feed verdict: if the catalog's own sha512 now agrees
(the file was replaced with a corrected copy), the quarantine lifts and the
verdict updates to verified. If it still disagrees, the release is refused
unless the operator types the image's own filename to confirm an override,
recorded as a distinct `release_override` audit action rather than a plain
release. An override does not change the recorded verdict back to verified —
it only permits assignment despite the mismatch — and re-running the check
later and getting that same mismatch again does not re-quarantine an
overridden image; a genuinely different mismatch does.

Either kind of release also puts the image back into the origin seeder: the
quarantine had force-removed its torrent from aria2, and a released image with
no origin would otherwise leave every device assigned it waiting at 0% until the
next container restart. The re-add happens from the image's recorded
`source_dir`, after re-syncing the canonical torrent's announce to the current
seeder credential (a quarantine can outlive an announce rotation, which skips
quarantined images); the `info` byte span, and so the info hash, is unchanged.
The response carries `seeding_resumed`, and a re-add that fails — aria2
unreachable, or a `source_dir` that no longer exists (IRIS never guesses a
directory by basename) — is audited as
`image_quarantine_release_seeding` with `result=fail` while the release itself
stays in force. A container restart re-seeds every catalogued, non-quarantined
torrent, so it repairs that case too.

## Scaling notes

Private BitTorrent reduces server load by letting devices exchange pieces after the seeder introduces the content. The server remains important for tracker announces, catalog policy, initial seeding, and telemetry. Watch the seeder data port, tracker health, and device storage pressure during large network waves.

On Catalyst 9300 IOx devices the final agent-to-IOS transfer uses the bind-mounted SSD share and runs at disk speed; Catalyst 9300 Guest Shell writes through the guest-share; Catalyst 8000 routers stage over Guest Shell to `bootflash:`. On IE-3400 (or a Catalyst 9300 that fell back to the scp push) that transfer is capped by the platform's default control-plane policing at roughly 1.4 MB/s; IRIS never modifies CoPP.

### How many torrents are served at once

Both the origin seeder and every device agent raise aria2's concurrency limit well above any realistic catalog, because a *seeding* torrent never finishes and so would otherwise hold one of aria2's five default slots forever. Left at the default, the sixth published image is never served at all and any device assigned it reports staging indefinitely — aria2 treats a held-back torrent as waiting rather than as an error, so nothing is logged. Override with `SEED_MAX_CONCURRENT` (origin, default 1000) or `IRIS_MAX_CONCURRENT` / `MAX_CONCURRENT` (devices, default 100). These are not throughput controls: bandwidth is governed by peer limits and transfer policy, and lowering these only starves images.

`iris_seeder_queued_torrents` is the signal to watch. Any non-zero value means the origin is holding back a published image; alert on it.

## Cleanup

Use `device/device-uninstall.sh` (Guest Shell devices),
`device/router-uninstall.sh` (Catalyst 8000 IOS-XE routers),
`device/iox/uninstall.sh` (IOx), or `device/xr-uninstall.sh` (IOS-XR appmgr).
Cleanup removes only the platform's IRIS-owned agent footprint and staged agent
artifacts. It still does not reload the device or remove a staged software image.

Undeploy is driven by the device's applied **deployment record**, not its editable
inventory row, so a later inventory edit cannot retarget cleanup. An
**inband** device's teardown removes the app footprint and every other
IRIS-named artifact — the EEM applets, the IRISQ discriminator and its logging
bindings, and the IRIS PKI trustpoint and HTTP-client binding — and preserves
the operator-owned VLAN/SVI/routes/VRF. An agent without an active deployment
record must be **adopted** (an explicit, audited, no-change
recording of ownership) before it can be undeployed, or undeployed with
**Force** to strip only the agent footprint when there is no deployment record at all —
see [Bulk device actions](console.md#bulk-device-actions). A Catalyst 8000
router cannot be adopted, and preflight refuses an onboard over a live agent, so
a router with no deployment record has only Force as its path. Force behaves identically on every
platform: it removes every artifact identifiable by name as IRIS — the IRIS EEM
applets, the IRISQ logging discriminator and its buffered/console/monitor
bindings, `crypto pki trustpoint IRIS` and `ip http client secure-trustpoint
IRIS`, the app-hosting stanza, and the staged IRIS files — and leaves only the
operator's network exactly as it is: the VLAN/SVI, the VirtualPortGroup, and the
NAT rules, which no deployment record proves IRIS created. Undeploy therefore clears
exactly what preflight refuses, so a forced teardown leaves the device able to be
onboarded again. A missing, drifted, or uncertain deployment record otherwise stops cleanup
in `needs-reconcile` rather than guessing. See
[Management Type and VLAN Ownership](management-type.md).

### Recovering an interrupted IOS-XR teardown

An IOS-XR undeploy that was interrupted partway through needs no special
recovery: re-run undeploy (record-backed or Force) and it converges, because
each step re-probes the router's own state — including the appmgr
application's — before acting rather than assuming an earlier attempt
succeeded. A step that cannot even trust its own probe — a transport error,
or a truncated read — refuses to continue rather than guess, and a failed
teardown leaves the device's deployment record in `needs-reconcile` (a red badge in
the console); undeploy or Force is legal to run again directly from that
state, and the re-run converges the same way. Every command session to the
router is bounded by `IRIS_XR_SESSION_TIMEOUT` (tracked default 150 seconds
in `lab/xr-run.sh`; a value exported in the server's environment always
takes precedence over that default, `0` disables the bound entirely, and an
invalid value falls back to the default with a logged warning), so a
wedged router fails the job with a real exit code instead of hanging it. The
150-second default sits at the top of a measured 120-150-second band:
every healthy session in the lab runs ~15-20 seconds, so 150s carries
6-10x headroom over that ceiling for both install and teardown alike — the
install Up-poll is 30 short, client-looped sessions rather than one long
one, so it shares the same bound safely without a separate knob. Undeploy
composes at most two bounded sessions per run — a read-only probe and
deactivate session, then a destructive uninstall/remove/sweep/verify
session — so a completely unresponsive router
holds a teardown job for at most 300 seconds (two stalled sessions) at
the default bound. A deployment
with a tighter job-queue deadline can still export a lower
`IRIS_XR_SESSION_TIMEOUT` (e.g. `60`) in the server's environment. XR's CLI
has no prompt-free way to remove a directory, so a completed teardown may
honestly leave an empty `iris-work/` directory behind on harddisk: rather
than failing over it — a later onboarding simply reuses that same directory
(it only ever ensures the directory exists, never requires it be absent).

An `IRIS_XR_SESSION_TIMEOUT` override changes each session's bound, not the
whole job's deadline. For example, 300 seconds allows up to 600 seconds across
the two teardown sessions.

Successful cleanup ends with `undeploy complete: <device-ip>` on every
platform. XR undeploy removes the app, package, agent files, and torrent
sidecars. It leaves image files at `harddisk:` root in place and does not
change assignments. This differs from clearing assignments while the XR
agent is running: the agent can remove files it recorded as downloaded by
IRIS, while retaining adopted files and files of unknown origin. See
[Unassigned image park](device-agents.md#unassigned-image-park).

Deleting an inventory row is not an undeploy — undeploy before deleting anything
still deployed. See [Bulk device actions](console.md#bulk-device-actions).

## Rebuilding the catalog from images already on disk

A catalog reset does not delete image files, and operators often stage images on
the host outside IRIS, so the recovery path after wiping `iris-state` is to
republish from disk rather than re-upload gigabytes. The Images screen's **Import
from disk** panel lists image files that exist under either root — the uploads
volume (`IRIS_IMAGES_DIR`) or the read-only import root (`IMAGES_ROOT`) — and
are not in the catalog.

Publishing from the panel happens **in place**. The seeder seeds from the file's
own directory, so nothing is copied and the read-only root stays read-only; the
`.torrent` is written to the state directory, never next to the image. Import
each file back instead of copying it into the uploads volume first.

Files the panel greys out carry a reason, and the three reasons and their fixes
are listed in [Import skip reasons](reference.md#import-skip-reasons) — an
`ambiguous name in more than one location` needs the duplicate removed or
renamed, and `not readable by the server` is the ownership problem above. Each
import is audited as `image_import`, rejections included, recorded with
`result=fail`.

A later delete of an entry published in place leaves the file on disk: the unlink
decision comes from the entry's recorded directory, not from its filename. See
[Catalog entry fields](reference.md#catalog-entry-fields) for the exact rule,
including how entries with no recorded source directory are handled.

## Artifact-server diagnostics

The artifact server logs one line per GET with the method, path, response
status, duration, and in-flight request count. TLS handshakes happen in the
per-connection worker rather than the accept loop, have a 30-second handshake
bound, and use a listen backlog of 128. During a slow fleet onboard, compare the
persisted deployment-log offsets with lines such as `artifacts GET ... in
0.123s (inflight 20)` to distinguish device-side delay from server-side
concurrency. Expired staging credentials are swept on a five-minute timer, not
on a request path, so one fetch cannot trigger deletion work for another.

## Rotating the Console-to-server credential

The Console reaches server state only through the internal management API on
9443. Both services read the credential from mounted files; never place it in
`server/.env`, a Compose `environment:` value, a URL, or a command argument.
Compose atomically provisions a scoped random value in its `iris-tier-auth`
named volume on first start. Kubernetes operators create the corresponding
Secret before deployment, as documented in [Kubernetes](kubernetes.md).
Separate Docker hosts keep local credential directories; use the
[remote rotation procedure](docker-hosts.md#rotate-the-management-credential)
to transfer the new value before removing the old one.

Rotation uses the current/previous overlap and is intentionally two phase:

1. Preserve the current scoped JSON record as `previous.json`, then atomically
   replace `current.json` with a random value of at least 32 bytes. Compose's
   `iris-management-token rotate` makes the overlap durable before replacement
   and rejects paths that refer to the same file. Kubernetes uses the two
   projected Secret keys.
2. Confirm both tiers have received the new `current` file and make an
   authenticated browser request through `/api/v1/session`. The processes
   reread their files for requests. Kubernetes should roll Console and server
   while the overlap exists and check the mounted values; see its
   [rotation procedure](kubernetes.md#secrets-and-storage).
3. Remove `previous.json` for Docker or empty the Kubernetes `previous` key,
   verify again, and securely retire any out-of-band copy of the old value.
   Keep the Kubernetes key present because both pods project it.

The Console tries the current token first and can use the previous token only
after a management-authentication rejection. It retains the token accepted by
authorization preflight when forwarding a mutation. It never retries a streamed
request body. Readiness or successful API access alone does not prove the new
token has reached both tiers, because the previous token may still work.

The server rereads the pair and compares both in constant time. A missing,
unreadable, too-short, wrongly scoped, or unmatched value returns a redacted
401 before a route is matched or a request body is read. The Console pins the
management CA independently; a token does not enable plaintext fallback.

## TLS rotation and device packages

The canonical device image, both IOx wrappers (`iris-arm64.tar` and
`iris-amd64.tar`), and the IOS-XR wrapper (`iris-xr.rpm`) are
**deployment-neutral**. None contains a server certificate, and none needs
`CATALOG_PEM` at build time. Console and API onboarding invoke the same
platform installers available from the CLI, and every path delivers the
current public certificate beside the package instead:

- IOx copies it into app-hosting application data after activation and before
  app start. The container reads that runtime file from CAF's app data directory.
- IOS-XR copies it to `harddisk:/iris-catalog.pem`, which the appmgr container
  reads through its `/hostmount` harddisk bind mount.
- Guest Shell receives the same current public certificate with its other
  short-lived onboarding artifacts.

Rotating or regenerating the server certificate therefore does **not** make an
IOx tar or XR RPM stale and does not require a package rebuild. It does leave
already-onboarded agents trusting the previous certificate. Re-onboard every
affected device so its runtime trust file is replaced; the same unchanged IOx
or XR package may be reused. Console onboarding requires the normal undeploy,
then onboard sequence because preflight refuses an already-running IRIS agent.

Console **Settings → Device packages** (also linked from the setup flow) keeps
the two readiness questions separate:

- Each package row checks that the wrapper is readable and non-empty, that its
  adjacent `.manifest` has the expected wrapper kind, filename, platform, and
  canonical OCI digests, and that the manifest's wrapper SHA-256 matches the
  served bytes. `ok` proves that byte-to-provenance binding only; it does not
  inspect package contents or validate a native signature. `stale` means the
  wrapper digest disagrees with its manifest. Missing, unreadable, or malformed
  evidence reports `absent` or `unknown`, never success.
- The card separately compares the certificate the live services present with
  the public `iris-catalog.pem` copy onboarding distributes. A missing copy or
  mismatch means new onboarding is not ready. Reconcile that served artifact;
  rebuilding deployment-neutral packages cannot repair certificate drift.

`tools/check-package-freshness.sh` is the scriptable equivalent. Its default
mode is read-only; `--rebuild` rebuilds wrapper families whose package or
provenance evidence is missing or invalid, then rechecks. It will not rebuild
packages to paper over a served-versus-distributed certificate failure.

Package rebuilds remain mandatory after a shared agent or device-image source
change. Rebuild the server to refresh its Guest Shell bundle, then build both
IOx wrappers and the XR wrapper with their adjacent provenance manifests:

```bash
docker compose -f server/docker-compose.yml up -d --build
IRIS_FORCE_DEVICE_IMAGE_BUILD=1 tools/provision-iox-packages.sh
tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

The force flag allows the local canonical archive to be replaced when source
changed without a `VERSION` change. To retain that archive, set
`IRIS_DEVICE_IMAGE_OCI` to a new path for both wrapper commands instead. Both
families must package the same canonical build.

Then redeploy affected devices so they actually run the new agent bytes. A
green package row verifies the served wrapper against its manifest; it does
not compare the package with the current checkout or confirm that an already
deployed device runs those bytes.

## Redeploying agents after an artifact rebuild

Rebuild and publish the Guest Shell bundles, both IOx packages, and the XR
package after changing shared agent source. Redeploy affected devices to run
those bytes. A package rebuild does not change an already-running agent.

The server accepts only report fields and peer identities it can validate.
Unrecognized peer data is omitted from transfer attribution. Check the device's
running agent and its package when a report lacks expected peer details.

## Rotating the seeder announce credential

`rotate-seeder-announce` is the one supported way to rotate the seeder's announce
credential. It requires `--maintenance-frozen`, which acknowledges a freeze the
operator has already put in place — the command never creates one. Preflight
binds every published image's canonical torrent to exactly one active aria2 GID
and refuses before touching anything if an image has no canonical torrent, is not
uniquely active, the announce base is not a usable HTTPS IPv4 endpoint (loopback,
link-local, unspecified and multicast addresses are refused; any routable
address is accepted), durable encrypted secrets are missing, or a recovery
manifest from an earlier run is still on disk. A refusal names its reason on
stderr (`refused (ValueError: canonical torrent is not uniquely active)`); the
reasons are fixed phrases that never carry a URL or credential.

A quarantined image is skipped, not a refusal: its quarantine removed the
torrent from the seeder on purpose, so it cannot be "uniquely active" and must
not block rotating the credential for the rest of the fleet. The command lists
the skipped ids. Their canonical torrents keep the rotated-out announce until
the quarantine is released, which re-syncs the announce to the then-current
credential before re-adding the torrent (see
[Releasing a quarantine](#releasing-a-quarantine)). If every published image is
quarantined there is nothing active to rotate and the command refuses.

Each replacement rewrites only the outer announce and keeps the `info` byte span
identical, so info hashes do not move. Credential values are never accepted on
the command line and never printed.

The rotated-out credential stays valid for a bounded overlap — 30 days from the
rotation, `IRIS_SEEDER_PREV_TTL` — so a device that has not yet received a
re-personalised torrent keeps announcing meanwhile. Nothing has to be retired by
hand: the old token expires on its own, and the next rotation drops the record.
Two still-valid previous records are the cap, and a rotation that would exceed
it is refused, so run no more than two rotations inside one window unless you
have already personalised the fleet's torrents. Expiry cannot lock a device out:
the way it picks up the current credential is a fresh personalised torrent from
the catalog, and that request is authorised by the device's catalog token.

**The rotation is only reported complete when the tracker independently proves
the new identity is serving.** After every canonical torrent is re-added, the
command polls the telemetry listener's authenticated, pinned-TLS `/swarm` and requires the current typed
`service:seeder` principal to be observed for every expected info hash, each with
an announce later than the post-add boundary. A completed device peer does not
stand in for that proof, and there is no registry shortcut or IP-based guess.
Anything else — transport error, timeout, or a document that does not prove it —
fails closed: serving is not claimed, the freeze stands, the recovery manifest is
preserved, and the command exits non-zero.

Every run writes a non-secret recovery manifest with the exact pre-rotation
torrent bytes and their digests before it starts. If an add fails, the old bytes
are restored and the old torrent re-added. If that re-add also fails, or a remove
fails and live state is therefore unknown, the run becomes a **hard no-go**: old
bytes are restored for every torrent already rotated, the remaining torrents are
abandoned, and maintenance stays frozen.

!!! warning "A hard no-go can leave an image not being served"
    The run does not claim the image is still being served, and it may not be.
    The result lists every disturbed torrent — a `false` restore result means
    serving repair is still required for that image before the freeze is lifted.

`--recover` restores the exact pre-rotation state from the manifest. It validates
the manifest — version, terminal state, path containment, digest and info-hash
agreement, and that the named image directory matches the current catalog —
before any file or aria2 call. Recovery leaves maintenance frozen and keeps the
manifest as evidence in either outcome.

## Recovery checklist

1. Confirm both `iris` and `iris-console` are running. In Kubernetes, check
   both deployments.
2. Check server logs for catalog, tracker, seeder, storage, and secret errors.
   Check Console logs for management API connectivity or authentication errors.
3. Confirm the Console can reach the internal server API on HTTPS TCP 9443.
   Do not publish that port for devices or browsers.
4. From the device's agent network, check the catalog on HTTPS TCP 8443 and
   tracker on HTTPS TCP 6969. Check BitTorrent TCP 6881 to the server seeder
   and TCP 6881–6999 between device peers. Guest Shell onboarding also needs
   the artifact server on HTTPS TCP
   8000; server-to-device onboarding uses SSH/SCP on TCP 22. IOx additionally
   needs SSH/SCP from the app to IOS. See [Network ports](network-ports.md).
5. Confirm the published image still exists in its recorded source directory
   under the import root or uploads volume, and uid 10001 can read it.
6. Confirm the server can read its age key, state, and artifacts. Check the
   device clock and runtime certificate if catalog or tracker TLS fails.
7. Read the device's job log, heartbeat, and per-image report. Confirm its
   management type, installer, and addresses before retrying. A running agent
   normally requires undeploy before Console onboarding again.
