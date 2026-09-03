<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Operations

This page collects the actions operators perform after the first deployment.

## Daily commands

| Task | Command |
| --- | --- |
| Start server | `docker compose -f server/docker-compose.yml up -d --build` |
| View logs | `docker logs iris` |
| Publish image | `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<path>/<image>.bin` |
| Show images and assignments | `docker compose -f server/docker-compose.yml exec iris iris-assign` |
| Apply assignments | `tools/apply-assignments.sh fleet/assignments.csv` |
| Create or reset admin | `docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin` — a reset also ends every live console session ([Console sessions](security.md#console-sessions)) |

`apply-assignments.sh` and `gen-device-installers.sh`
([Prepare devices](getting-started.md#prepare-devices)) require the running
`iris` container by that name; set `IRIS_CONTAINER=<name>` if yours differs.

For Kubernetes, the equivalent process and logs are available through the
single deployment:

```bash
kubectl -n iris exec deployment/iris-seed-server -- iris-assign
kubectl -n iris logs deployment/iris-seed-server -c iris
```

## Recognizing an ownership problem

Every service runs at uid 10001, so a path the server cannot reach at that uid
produces a recognizable symptom rather than a crash: the Images screen lists a
file as `not readable by the server`, a secret store that worked before fails to
decrypt, or onboarding fails while downloading the agent bundle. These are
ownership problems, not corrupt state.

Two ownership rules produce them. The host age key and the host artifacts
directory (`IRIS_ARTIFACTS_HOST_DIR`, the repository's `artifacts/`) need their
chown on **every** deploy — see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).
A deployment upgraded from a root-runtime release needs a one-time volume
migration, and because it applies per volume, any reset that removes some
volumes while keeping others needs it again for the kept ones — see
[Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment)
for the command to run.

## Unreachable devices at onboard

A Guest Shell onboard job probes the device before running the installer. An
unreachable device — wrong IP, wrong credentials, no network path — fails the
job immediately with `cannot reach device <ip> — ping/SSH probe failed; check
the device IP and credentials` instead of silently doing nothing. Router and
IOx onboarding already ran a live preflight and failed the same way.
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

A batch onboard no longer blocks its HTTP request on a router's live SSH
session. `POST /api/devices/<id>/onboard` resolves the plan, checks for a
conflicting deployment record, and returns a job id immediately; router
preflight — the read-only collision, identity, and NAT checks in
[Router preflight and ownership](management-type.md#router-preflight-and-ownership)
— runs afterward, in the bounded onboarding worker pool, right before that
job mints its enrollment token. Selecting a large batch of routers therefore
shows queued and running progress at once instead of the page hanging while
each router is probed in turn, and a preflight failure fails only that job,
with its own log, rather than blocking the routers behind it in the batch.
Every ownership, collision, identity, NAT, and Guest Shell reachability check
still completes before any token is minted or any device configuration is
applied — only when it runs moved.

Worker concurrency is bounded and configurable with `IRIS_ONBOARD_CONCURRENCY`
(default 25); `GET /api/onboard/jobs` reports the current limit as
`max_concurrent`.

The generated installers and Console recipes also cut down on device logins:
the read-only pre-checks before an install and the verification checks after
an install or undeploy each now run over a single device session instead of
one login per command. State-gated poll and retry loops still use a new live
observation per iteration; Guest Shell readiness now waits 2, 4, 6, and so on up
to 15 seconds between observations instead of imposing a flat 15-second delay.

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

The map is **keyed** state: `peer-endpoints.d/` holds one row per principal,
spread over 256 shard files, rather than one `peer-endpoints.json` document.
An announce locks, parses and rewrites only the shard its own principal lands
in, so the cost of a device's announce does not grow with the size of the
fleet and unrelated devices no longer serialise behind one writer. Each shard
is written atomically (temp file + rename). An existing `peer-endpoints.json`
from an earlier release is migrated into the shards the first time the tracker
touches the map and is left behind, renamed to `peer-endpoints.json.migrated`,
for reference; nothing has to be done by hand.

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
/api/peer-policy` derives `enforcement.stale` from how long it has been
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

Back up the Docker volumes that hold `/var/lib/iris` and `/etc/iris`, plus the offline age identity (the host key file `IRIS_AGE_KEY_FILE_HOST` points at) required to decrypt secrets, plus the `iris-images` uploads volume — console-uploaded images live there, and a restore without it loses them. Image binaries under the read-only import root and generated artifacts stay in their normal external storage path.

For Kubernetes, snapshot the `iris-data` PVC and back up the age identity stored
outside that PVC. Both are required for recovery.

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

Audit detail wording can change between releases without rewriting entries
already on disk — `audit.jsonl` is append-only, so old lines keep their
original text. The clearest current example is the deployment-record rename:
the `adopt` action's detail text and the device-retirement (`device_delete`)
detail text naming abandoned deployment records both moved to the new
wording. A saved search over audit detail for either event should match both
the old and the new phrasing until the old entries age out.

## Image verification

*Settings → Image verification* checks the catalog's images against Cisco's
published Bulk Hash feed and quarantines a sha512 mismatch — see [Cisco Bulk
Hash verification](security.md#cisco-bulk-hash-verification) for what the
check does and what a quarantine changes. A locally-rebuilt image that
reuses a Cisco filename mismatches and quarantines on its next verification
run; the check has no way to distinguish that from tampering, which is the
point.

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
the operator-owned VLAN/SVI/routes/VRF. A device deployed before deployment records
existed
has no active deployment record and must be **adopted** (an explicit, audited, no-change
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
now holds a teardown job for at most 300 seconds (two stalled sessions) at
the default bound, down from the roughly two-hour worst case the old
six-to-eleven-session, 900-second-default design could reach. A deployment
with a tighter job-queue deadline can still export a lower
`IRIS_XR_SESSION_TIMEOUT` (e.g. `60`) in the server's environment. XR's CLI
has no prompt-free way to remove a directory, so a completed teardown may
honestly leave an empty `iris-work/` directory behind on harddisk: rather
than failing over it — a later onboarding simply reuses that same directory
(it only ever ensures the directory exists, never requires it be absent).

If your deployment carries an `IRIS_XR_SESSION_TIMEOUT` override from an
earlier release — 300 seconds was a common one, set back when the tracked
default was 900 seconds and a teardown ran six to eleven sessions — it is now
redundant, and leaving it is harmless. That override was always a *per-session*
cap, not a total-teardown one: at 300 seconds a stalled teardown's worst case
is 600 seconds across the two sessions the current design uses, against 300
seconds at the tracked default. Removing it tightens the worst case back to
the default; that edit is the operator's to make. Undeploy itself never touches a bare
image filename and reports, in one summary line, that any operator-staged
image was left in place. Undeploy never unassigns an image, so it never
produces the agent's own per-file record on its own: that line — the file
was kept, or replaced, if the catalog had republished different content
under the same image id — only exists for an image the agent actually
unassigned or republished while it was running. A device undeployed with
its images still assigned leaves every image file in place with no such
line at all; undeploy's own summary is the only confirmation there is.

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
including the fallback for entries published before that field existed.

## Artifact-server diagnostics

The artifact server logs one line per GET with the method, path, response
status, duration, and in-flight request count. TLS handshakes happen in the
per-connection worker rather than the accept loop, have a 30-second handshake
bound, and use a listen backlog of 128. During a slow fleet onboard, compare the
persisted deployment-log offsets with lines such as `artifacts GET ... in
0.123s (inflight 20)` to distinguish device-side delay from server-side
concurrency. Expired staging credentials are swept on a five-minute timer, not
on a request path, so one fetch cannot trigger deletion work for another.

## TLS rotation and device packages

Rotating or regenerating the server's TLS certificate invalidates prebuilt
device packages: each `iris-arm64.tar` / `iris-amd64.tar` bakes the catalog's
certificate in at **build** time, and so does `iris-xr.rpm`, the IOS-XR agent
package for Cisco 8000 Series Routers (`tools/build-xr-package.sh`). The
server only refreshes the *served* `iris-catalog.pem` on container start — it
does not rebuild any of the three. A rebuilt server, a fresh volume, or a
deliberate certificate rotation all silently break every package that was
built before the change.

Symptom: the device installs cleanly and its IOx app (or, on IOS-XR, its
appmgr container) reports RUNNING, and its TCP connection to the catalog even
succeeds, but it can never authenticate and so never checks in. The only
evidence is a `TOKEN-REFRESH-FAIL` line in the **device's own syslog** —
nothing on the server distinguishes "never onboarded" from "onboarded but
rejecting our certificate". Guest Shell devices are immune: their served
artifacts, including `iris-catalog.pem`, are regenerated on every container
start, and the installer always fetches whatever is current.

Two ways to catch this before it reaches a device:

- Console **Settings → Setup** carries a *device packages* card showing each
  package's build time and state (`ok`, `stale`, `absent`, `unknown`) against
  the server's live certificate, including the `iris-xr.rpm` row — see
  [Setup](console.md#setup). That row is checked differently from the two
  tars: this module has no RPM/cpio reader, so it can only compare the RPM's
  build time against the live certificate, not pin the certificate baked
  inside it the way it does for the tars.
- `tools/check-package-freshness.sh` is the read-only, scriptable equivalent
  for all three packages. It compares the certificate the catalog actually
  serves, the copy handed to Guest Shell devices, and the certificate pinned
  inside each served IOx package. For `iris-xr.rpm`, it uses the same explicit
  build-time proxy as the Setup card: built before the certificate's
  `notBefore` is stale; built after it is only `OK-BY-MTIME`, never a contents
  inspection:

  ```bash
  tools/check-package-freshness.sh              # report only
  tools/check-package-freshness.sh --rebuild    # report, then rebuild if stale
  ```

  Run it after any catalog certificate change. `--rebuild` rebuilds stale IOx
  tars only; build the XR RPM separately with the command below.

Remedy: re-run `tools/provision-iox-packages.sh`, then re-onboard the affected
IOx devices. For IOS-XR, rebuild the RPM with `tools/build-xr-package.sh
--out artifacts/`, pointing `CATALOG_PEM` at the NEW live certificate
(certificate block only — the same rebuild the fresh-volume reset sequence in
[aiagent.md](aiagent.md) performs for IOS-XR after bring-up), then redeploy
the affected Cisco 8000 Series routers. If instead the certificate the server
currently serves disagrees with the copy already handed to devices,
rebuilding packages alone will not fix it — new onboards are affected too —
so reconcile the certificate first.

## Redeploying agents after an artifact rebuild

Rebuilding an XR RPM, IOx tar, or agent bundle changes what is baked inside
it — including any script or hook filename — so a rebuild must also be
republished, and a device must be redeployed to pick it up. Until then, an
already-deployed agent keeps working against the current server, but any name
it reports that the server no longer recognizes is dropped by the server's
allow-list reconstruction rather than rejected: per-peer transfer attribution
is simply absent from that device's report until it is redeployed, not an
error. The agent's own persisted telemetry state can carry an old key across
its own upgrade too, so the first report after upgrading a running agent can
discard whatever peer data it had already measured for the transfer in
progress — a one-time gap for that transfer, not a recurring one.

## Rotating the seeder announce credential

`rotate-seeder-announce` is the one supported way to rotate the seeder's announce
credential. It requires `--maintenance-frozen`, which acknowledges a freeze the
operator has already put in place — the command never creates one. Preflight
binds every published image's canonical torrent to exactly one active aria2 GID
and refuses before touching anything if an image has no canonical torrent, is not
uniquely active, the announce base is not a usable HTTP IPv4 endpoint (loopback,
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
command polls the tracker's loopback `/swarm` and requires the current typed
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

## Rollback after the shard migration

See [Keyed per-device state](reference.md#keyed-per-device-state) for what
the migration does. This is what to do if you roll the server back to a
release from before it.

Every whole-fleet document under `IRIS_STATE` — `devices.json`,
`policy.json`, `pull_requests.json`, `telemetry.json`, `report_ledger.json`,
`transfer-attestations.json`, `peer-endpoints.json` — is migrated into a
`<name>.d/` shard directory the first time the running server touches that
store, normally on the container's first restart after an upgrade past the
shard migration. Migration is automatic, one-shot per store, and never
deletes anything: the original document is renamed to `<name>.json.migrated`
and left in place next to its shard directory.

**A rollback to a pre-migration release refuses to start rather than run
with an empty fleet.** Code from before the migration reads a *missing*
`devices.json` (and the same for every other store above) as an empty store
— no devices, no policy, no telemetry — and a rename-away is exactly what
that code would have found once migration renamed the document to
`.migrated`. To close that off, migration leaves a placeholder file at each
legacy path instead of leaving nothing: deliberately not valid JSON, so it
trips the same fail-closed check that release already has for a *corrupt*
state file (`state file unreadable: ...` / `state file is not a JSON
object: ...` in the server log, or `EndpointStoreError` for
`peer-endpoints.json`), and the affected requests fail instead of quietly
succeeding against an empty fleet. The placeholder file itself is plain
text — `cat` it — and names the exact `.migrated` file to restore.

To roll back:

1. Stop the server (`docker compose down`, or the equivalent for your
   deployment).
2. List which stores were actually migrated — only a store the new release
   touched has one:
   ```
   ls <state>/*.json.migrated
   ```
3. For each one, restore the original document over the placeholder:
   ```
   mv <state>/devices.json.migrated <state>/devices.json
   mv <state>/policy.json.migrated <state>/policy.json
   mv <state>/pull_requests.json.migrated <state>/pull_requests.json
   mv <state>/telemetry.json.migrated <state>/telemetry.json
   mv <state>/report_ledger.json.migrated <state>/report_ledger.json
   mv <state>/transfer-attestations.json.migrated <state>/transfer-attestations.json
   mv <state>/peer-endpoints.json.migrated <state>/peer-endpoints.json
   ```
4. Start the pre-migration release.

**What this does not recover.** The restored document is a snapshot from the
moment of migration, not from the moment of rollback. Any write the *new*
(sharded) release made in between — a heartbeat, a policy change, a
telemetry report, an endpoint announce — lives only in the `<name>.d/` shard
directory, and migration never folds later shard writes back into
`<name>.json.migrated`. A rollback shortly after the upgrade, before devices
have reported again, loses nothing; a rollback after the fleet has run on
the new release for a while reverts every migrated store to its state at
migration time. The shard directories are left in place by this procedure —
pre-migration code never reads or writes them — so nothing already on disk
is destroyed, but a device's activity between migration and rollback will
not be visible to the older release. If that gap matters for your fleet,
back up `<state>` (see [Backups](#backups)) before rolling back, and keep it
until you have confirmed you will not need to reconcile against it.

## Recovery checklist

1. Confirm `docker ps` shows the `iris` container.
2. Check `docker logs iris` for catalog, tracker, seeder, or secretfs errors.
3. Confirm the device can reach ports 8443, 8000, 6969, and 6881.
4. Confirm the published image exists under one of the two image roots — the read-only import root (`/opt/images`) or the `iris-images` uploads volume.
5. Confirm the age key, the artifacts directory, and every kept volume are owned by uid 10001 — a `not readable by the server` image or a secrets failure after a reset is an ownership problem, not a corrupt store.
6. Check the console audit and latest device report.
7. Re-run the generated installer only after confirming the device inventory row is still correct.
