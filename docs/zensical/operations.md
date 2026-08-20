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

## Scaling notes

Private BitTorrent reduces server load by letting devices exchange pieces after the seeder introduces the content. The server remains important for tracker announces, catalog policy, initial seeding, and telemetry. Watch the seeder data port, tracker health, and device storage pressure during large network waves.

On Catalyst 9300 IOx devices the final agent-to-IOS transfer uses the bind-mounted SSD share and runs at disk speed; Catalyst 9300 Guest Shell writes through the guest-share; Catalyst 8000 routers stage over Guest Shell to `bootflash:`. On IE-3400 (or a Catalyst 9300 that fell back to the scp push) that transfer is capped by the platform's default control-plane policing at roughly 1.4 MB/s; IRIS never modifies CoPP.

## Cleanup

Use `device/device-uninstall.sh` (Guest Shell devices), `device/router-uninstall.sh` (Catalyst 8000 routers), or the IOx uninstall path for device cleanup. Cleanup removes IRIS-owned EEM applets, Guest Shell or IOx agent wiring, trustpoint binding, and staged agent artifacts. It still does not reload the device.

Undeploy is driven by the device's applied **receipt**, not its editable
inventory row, so a later inventory edit cannot retarget cleanup. An
**inband** device's teardown removes only the app footprint and preserves the
operator-owned VLAN/SVI/routes/VRF. A device deployed before receipts existed
has no active receipt and must be **adopted** (an explicit, audited, no-change
recording of ownership) before it can be undeployed — except a Catalyst 8000
router, which cannot be adopted and must be re-onboarded to record live
ownership evidence. A missing, drifted, or
uncertain receipt stops cleanup in `needs-reconcile` rather than guessing. See
[Management Type and VLAN Ownership](network-attachment.md).

Deleting an inventory row is not an undeploy. It removes the console record only,
and an onboarded device keeps its agent and its staged image with no inventory
entry left to manage it, so undeploy before deleting anything still deployed.

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
catalog CA in at build time, and the server only refreshes the *served*
`iris-catalog.pem` on start — it does not rebuild the tars.

Symptom: the IOx app runs and its TCP connection to the catalog succeeds, but
the device never heartbeats, because the pinned certificate is rejected.

Remedy: re-run `tools/provision-iox-packages.sh`, then re-onboard the affected
IOx devices. Guest Shell devices need no such fix — the installer pushes the
current certificate on every run, so they heal on re-onboard automatically.

## Recovery checklist

1. Confirm `docker ps` shows the `iris` container.
2. Check `docker logs iris` for catalog, tracker, seeder, or secretfs errors.
3. Confirm the device can reach ports 8443, 8000, 6969, and 6881.
4. Confirm the published image exists under one of the two image roots — the read-only import root (`/opt/images`) or the `iris-images` uploads volume.
5. Confirm the age key, the artifacts directory, and every kept volume are owned by uid 10001 — a `not readable by the server` image or a secrets failure after a reset is an ownership problem, not a corrupt store.
6. Check the console audit and latest device report.
7. Re-run the generated installer only after confirming the device inventory row is still correct.
