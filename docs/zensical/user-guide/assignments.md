<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Assign images and check staging status

## What this is for

An assignment is the list of images you want one device to
[stage](../reference/glossary.md). To assign to many devices at once, select
them on the Devices table and use **Assign images**; see
[Work with many devices at once](devices.md).

## In the Console

1. Open **Inventory** and click the device row.
2. Pick the images the device should stage. The picker allows up to ten.
3. Apply the change. The device shows **Waiting for staging** until its agent
   polls, picks up the assignment and reports work.

!!! warning "Assigning replaces the image set"
    The new choice replaces the old one, so include every image you want to
    keep. An empty set unassigns every image.

## With the API

`POST /api/v1/devices/{device_id}/assign` assigns images to one device that is
already in inventory. The ordered `image_ids` list replaces the assignment, so
list every image you still want. Call it once per device.

Read status back with `GET /api/v1/devices/{device_id}/reports`. See
[Console API](../reference/console-api.md) for payloads and conflict checks,
and [Automate with the API](automation.md) for a worked sequence.

## What you see

### The staging status column

| Status | What it means |
| --- | --- |
| **Waiting for staging** | The assignment is in. The agent has not reported work yet. |
| **Staging now** | The device is transferring the image. |
| **Copying to \<filesystem\>** | An IOx app is copying the downloaded image to IOS storage. |
| **Staging failed** | A download, verification or placement error. Read the diagnostic beside the status; for placement failures, the device's `IRIS ROOTCOPY-FAIL` syslog entry has more detail. |

A current image error outranks an older staged flag in Devices and Overview.

### Reading the instruction status column

An instruction is the signed message the server sends a device saying which
images to stage and how. Devices shows an instruction chip with a label,
source evidence and report age. The server measures two of those itself:
whether a key was revoked, and how old the last report is. The rest is the
agent's own claim. A revoked key wins the display, with the agent's last
reported state beneath it. The labels are server-created strings, and the
Console shows each one exactly as the server sends it.

A second panel shows the health of the keys that sign instructions: whether
signing is on, certificate days remaining, keylist age, and root ceremony
status. Thresholds and what to do about each are in
[Replace or recover signing keys](../admin-guide/instruction-keys.md). State names are listed
in [Data formats and states](../reference/state-and-data.md), and what the
server can prove about an instruction is in
[Security model and trust boundaries](../architecture/security-model.md).

### Device reports and their fields

| Field family | Examples |
| --- | --- |
| Identity | Device id, platform, storage target. |
| Assignment | Approved image id and current staged image. |
| Transfer | Download state, progress, peer information, seeder participation. |
| Verification | Hash checks, staged-copy byte-size confirmation, failure reason. |
| Timing | Last poll, last report, and operation duration. |

For multiple images, read `staged_image_ids` and `errored_image_ids`;
`stage_state` covers the whole set. Peer progress and per-image measurements
are in [Monitor transfers and device reports](monitoring.md).

Current assignments and the latest heartbeat can differ until the next agent
poll: the Console shows an assigned image as **Waiting for staging** until the
device reports it. A current error takes precedence over an older staged flag.

### What a finished assignment looks like

The device reports each assigned image id, swarm state shows completed pieces,
and the file matches the catalog SHA-256 and final size. IOS-XE places the
verified file at the storage root; XR checks it in place. If a same-name image
is already there, the agent adopts it once its size and native hash match the
catalog; a mismatch is reported as a staging failure. On Catalyst 9000 series
switches that agent runs in Guest Shell, or in the IOx app on switches with
app-hosting storage. See [How an image reaches a device](../architecture/data-path.md).

## What happens to an image you unassign { #unassigned-image-park }

Removing an image from a device's assignments **parks** it. To park an image is
to keep it on the device in case it is assigned again. At the agent's next
successful policy poll it stops the torrent, removes the staging copy and marks
the image parked. Clearing all assignments parks every image.

| Platform | What stays on the storage root |
| --- | --- |
| IOS-XE | The placed copy stays. Reassigning the image lets the agent check and reuse it. A later assignment that needs room can reclaim it during the storage check. |
| IOS-XR | Files IRIS downloaded are removed. Files adopted from you, or of unknown origin, stay. When several image records name the same root file, every record must prove downloaded ownership before parking deletes it. |

IOS-XE cleanup protects two files: the **running image** (`show version`) and
the file named by the **`BOOT` variable** (`show boot`). When either read
fails, the agent skips deletion, logs `RECLAIM-DEFERRED` or `CLEANUP-PENDING`,
and retries on a later successful due staging tick, one pass of its check-in loop.

!!! warning "Storage capacity"
    Allow room for all resident images plus working space; see
    [What a device needs before onboarding](../install/device-requirements.md).
    Undeploying IRIS also keeps staged IOS-XE images on the storage root.

## Confirm staging and keep the evidence

| Record | What it proves | How to get it |
| --- | --- | --- |
| Device report | What the agent last reported for each assigned image, including hash checks and failure reasons. | The device row in the Console, or `GET /api/v1/devices/{device_id}/reports`. |
| Scheduled outcome | The record of what a scheduled run did on one device, and the reason it ended that way. | `GET /api/v1/schedules/{id}/receipts`. |
| Audit trail | Who asked for the assignment, and when the server accepted it. | **Monitoring → Audit** in the Console, or `GET /api/v1/audit`. |

Keep the device report and the audit trail together to show that an image
reached a device and that someone asked for it. For an off-box copy,
**Settings → Audit export** ships the audit trail to an SCP destination on
demand or daily, encrypted to your age recipient; see
[Routine maintenance tasks](../admin-guide/maintenance.md).

## Edge cases

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The device stays on **Waiting for staging**. | The agent has not polled yet, or it is not running. | Wait one poll interval; see [Device agent configuration](../reference/device-configuration.md) for the default cadence. If the state holds, see [Troubleshoot: symptoms and first steps](troubleshooting.md). |
| An image you unassigned is still on the device. | Platform ownership rules park or protect the file. | Read [What happens to an image you unassign](#unassigned-image-park) before deleting anything by hand. |
| One image reports an error while others finish. | A hash, catalog or agent error for that one image. | Read the diagnostic beside the status. |
| A job's deployment record reads unknown after a server restart. | The onboarding or undeploy job was running at the time. | Reconcile the record before you retry it; see [Recover from an interrupted job or damaged state](../admin-guide/recovery.md). |

## Related

* [Work with many devices at once](devices.md)
* [Publish and verify images](images.md)
* [Monitor transfers and device reports](monitoring.md)
* [Schedule maintenance windows](scheduling.md)
* [Automate with the API](automation.md)
