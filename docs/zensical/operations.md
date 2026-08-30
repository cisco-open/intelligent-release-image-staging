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
| Create or reset admin | `docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin` |

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
conflicting deployment receipt, and returns a job id immediately; router
preflight — the read-only collision, identity, and NAT checks in
[Router preflight and ownership](network-attachment.md#router-preflight-and-ownership)
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
one login per command. State-gated poll and retry loops — waiting for
`guestshell destroy`, IOx readiness, or app-hosting state — are unchanged,
because each iteration has to re-observe live device state.

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
address in `peer-endpoints.json` under `IRIS_STATE`, aged out by
`IRIS_ENDPOINT_TTL`. If that durable write fails, the entry is queued in memory
and retried on the following reconcile passes rather than being dropped — the
device keeps participating in the swarm meanwhile, but the reported enforcement
status degrades until the write lands, because the derived deny set is computed
from durable state.

A corrupt or unreadable `peer-endpoints.json` is treated as fail-closed rather
than empty: the reconcile pass stops before deriving or applying anything,
existing blocks stay in place, and the recorded state is forced to `fail_closed`.
Peer discovery is unaffected — the announce path reads the policy files
independently.

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

## Scaling notes

Private BitTorrent reduces server load by letting devices exchange pieces after the seeder introduces the content. The server remains important for tracker announces, catalog policy, initial seeding, and telemetry. Watch the seeder data port, tracker health, and device storage pressure during large network waves.

On Catalyst 9300 IOx devices the final agent-to-IOS transfer uses the bind-mounted SSD share and runs at disk speed; Catalyst 9300 Guest Shell writes through the guest-share; Catalyst 8000 routers stage over Guest Shell to `bootflash:`. On IE-3400 (or a Catalyst 9300 that fell back to the scp push) that transfer is capped by the platform's default control-plane policing at roughly 1.4 MB/s; IRIS never modifies CoPP.

## Cleanup

Use `device/device-uninstall.sh` (Guest Shell devices), `device/router-uninstall.sh` (Catalyst 8000 routers), or the IOx uninstall path for device cleanup. Cleanup removes IRIS-owned EEM applets, Guest Shell or IOx agent wiring, trustpoint binding, and staged agent artifacts. It still does not reload the device.

Undeploy is driven by the device's applied **receipt**, not its editable
inventory row, so a later inventory edit cannot retarget cleanup. An
**inband** device's teardown removes the app footprint and every other
IRIS-named artifact — the EEM applets, the IRISQ discriminator and its logging
bindings, and the IRIS PKI trustpoint and HTTP-client binding — and preserves
the operator-owned VLAN/SVI/routes/VRF. A device deployed before receipts
existed
has no active receipt and must be **adopted** (an explicit, audited, no-change
recording of ownership) before it can be undeployed, or undeployed with
**Force** to strip only the agent footprint when there is no receipt at all —
see [Bulk device actions](console.md#bulk-device-actions). A Catalyst 8000
router cannot be adopted, and preflight refuses an onboard over a live agent, so
a receipt-less router's only path is Force. Force behaves identically on every
platform: it removes every artifact identifiable by name as IRIS — the IRIS EEM
applets, the IRISQ logging discriminator and its buffered/console/monitor
bindings, `crypto pki trustpoint IRIS` and `ip http client secure-trustpoint
IRIS`, the app-hosting stanza, and the staged IRIS files — and leaves only the
operator's network exactly as it is: the VLAN/SVI, the VirtualPortGroup, and the
NAT rules, which no receipt proves IRIS created. Undeploy therefore clears
exactly what preflight refuses, so a forced teardown leaves the device able to be
onboarded again. A missing, drifted, or uncertain receipt otherwise stops cleanup
in `needs-reconcile` rather than guessing. See
[Management Type and VLAN Ownership](network-attachment.md).

### Recovering an interrupted IOS-XR teardown

An IOS-XR undeploy that was interrupted partway through needs no special
recovery: re-run undeploy (receipted or Force) and it converges, because
each step re-probes the router's own state — including the appmgr
application's — before acting rather than assuming an earlier attempt
succeeded. Every command session to the router is bounded by
`IRIS_XR_SESSION_TIMEOUT` (default 900 seconds), so a wedged router fails
the job with a real exit code instead of hanging it. Undeploy itself never
touches a bare image filename and reports, in one summary line, that any
operator-staged image was left in place; which file was kept — or
replaced, if the catalog had republished different content under the same
image id — is decided and logged by the agent during its own unassign/park
cycle, which runs before step [1/5] deactivates it. Check the agent's own
log for that per-file record; undeploy's output only confirms the blanket
guarantee.

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

## TLS rotation and IOx packages

Rotating or regenerating the server's TLS certificate invalidates IOx packages
that were already built: each `iris-arm64.tar` / `iris-amd64.tar` bakes the
catalog's certificate in at **build** time, and the server only refreshes the
*served* `iris-catalog.pem` on container start — it does not rebuild the
tars. A rebuilt server, a fresh volume, or a deliberate certificate rotation
all silently break every package that was built before the change.

Symptom: the device installs cleanly and its IOx app reports RUNNING, and its
TCP connection to the catalog even succeeds, but it can never authenticate and
so never checks in. The only evidence is a `TOKEN-REFRESH-FAIL` line in the
**device's own syslog** — nothing on the server distinguishes "never
onboarded" from "onboarded but rejecting our certificate". Guest Shell
devices are immune: their served artifacts, including `iris-catalog.pem`, are
regenerated on every container start, and the installer always fetches
whatever is current.

Two ways to catch this before it reaches a device:

- Console **Settings → Setup** carries a *device packages* card showing each
  package's build time and state (`ok`, `stale`, `absent`, `unknown`) against
  the server's live certificate — see [Setup](console.md#setup).
- `tools/check-package-freshness.sh` is the read-only, scriptable equivalent.
  It compares the certificate the catalog actually serves, the copy handed to
  Guest Shell devices, and the certificate pinned inside each served IOx
  package, and exits non-zero if any package is stale:

  ```bash
  tools/check-package-freshness.sh              # report only
  tools/check-package-freshness.sh --rebuild    # report, then rebuild if stale
  ```

  Run it after any catalog certificate change.

Remedy: re-run `tools/provision-iox-packages.sh`, then re-onboard the affected
IOx devices. If instead the certificate the server currently serves disagrees
with the copy already handed to devices, rebuilding packages alone will not
fix it — new onboards are affected too — so reconcile the certificate first.

## Rotating the seeder announce credential

`rotate-seeder-announce` is the one supported way to rotate the seeder's announce
credential. It requires `--maintenance-frozen`, which acknowledges a freeze the
operator has already put in place — the command never creates one. Preflight
binds every published image's canonical torrent to exactly one active aria2 GID
and refuses before touching anything if an image has no canonical torrent, is not
uniquely active, the announce base is not a private HTTP URL, durable encrypted
secrets are missing, or a recovery manifest from an earlier run is still on disk.

Each replacement rewrites only the outer announce and keeps the `info` byte span
identical, so info hashes do not move. Credential values are never accepted on
the command line and never printed.

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

## Recovery checklist

1. Confirm `docker ps` shows the `iris` container.
2. Check `docker logs iris` for catalog, tracker, seeder, or secretfs errors.
3. Confirm the device can reach ports 8443, 8000, 6969, and 6881.
4. Confirm the published image exists under one of the two image roots — the read-only import root (`/opt/images`) or the `iris-images` uploads volume.
5. Confirm the age key, the artifacts directory, and every kept volume are owned by uid 10001 — a `not readable by the server` image or a secrets failure after a reset is an ownership problem, not a corrupt store.
6. Check the console audit and latest device report.
7. Re-run the generated installer only after confirming the device inventory row is still correct.
