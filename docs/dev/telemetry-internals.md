<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# aria2 peer sampling, report ring and promotion design

This page is for a contributor changing how IRIS samples aria2 peer data,
stores transfer reports, or decides when a plan counts as seeding. The manual
states the resulting behavior as fact; this page argues for it, so a later
change can tell which parts were a deliberate trade-off and which were an
oversight. It assumes you have read
[What telemetry measures and proves](../zensical/architecture/telemetry-model.md)
and [Telemetry signals](../zensical/reference/telemetry-signals.md) first.

## Building and testing the download-duration metric

`iris.download.duration_seconds` needs a report field that only an updated
device agent sends. An older agent still stages images correctly; it does
not report a download start and end, so the server excludes that device from
the metric rather than reporting a duration for it.

Refresh all three device package types together before you rely on the
number: the Guest Shell bundle, both IOx packages, and the XR RPM. Refreshing
only some of them leaves part of the fleet unreported.

Build only the amd64 packages when you want to test the change without
touching your ARM devices. Set `IRIS_DEVICE_PLATFORMS=linux/amd64` and run
`tools/stage-iox-package.sh --arch amd64` and `tools/build-xr-package.sh
--out artifacts/`. This writes a separate amd64-only OCI (Open Container Initiative) archive. Do not roll
the untouched ARM packages out as if they carried the change; see
[Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md)
for the rest of the build.

## Why the promotion timestamp is latched twice

A plan is promoted to seeding once the server has independently confirmed two
separate facts: the device's own checksum evidence for that transfer, and the
tracker's own sighting of that device seeding it. IRIS latches each fact the
instant it is first observed, rather than waiting for both to be visible in
the same pass.

Neither fact stays available on its own. The tracker drops a peer's row 60
seconds after its last announce, removes it immediately on a stopped
announce, and clears its completed instant outright when a redownload
begins. If the promotion pass only looked at whichever facts still happened
to be visible together, a peer row that disappeared at the wrong moment would
block that promotion forever. Latching each fact independently as soon as it
appears removes that race.

The per-device report ring keeps a device's newest five reports, across every
image it has and every report kind. That window does not guarantee a
checksum report survives until the tracker sighting arrives. IRIS also
writes the checksum evidence to a separate durable store the moment it
ingests it, one row per transfer, in `<state>/transfer-attestations.json`.
The promotion pass reads both the ring and that store, so a report rotating
out of the ring never erases the evidence that a transfer's content already
verified.

## Recovering a promotion after a lost lifecycle row

Recovering a lost lifecycle store can rebuild a plan's record with a
different `seeding_started_at` than the one it originally produced, under the
same `event.id`. See
[What telemetry measures and proves](../zensical/architecture/telemetry-model.md)
for what an operator sees on such a record.

Two of the three inputs to that timestamp are durable outside the lifecycle
store: `planned_at` lives in the policy record, and `checksum_verified_at`
lives in the ingest-time attestation described above. The third,
`tracker_seeder_at`, comes only from the tracker's in-memory peer registry,
so a device that re-announces after a restart stamps a fresh, later instant
there.

IRIS could replay whatever the registry happens to say at recovery time, but
that value drifts further from the original with every reconnection.
Instead, a promotion made on a pass that detects a lost store uses only the
two durable inputs, `max(checksum_verified_at, planned_at)`, and every later
recovery of that same plan reproduces exactly that value. The record also
carries `iris.transfer.recovered_promotion`, so a value that moved is never
mistaken for a bug in the export path.

That flag exists because the recovered value can only ever be a lower bound
on the original instant. It is bounded below by `planned_at`, and it is
still a genuine server observation of that plan, but not necessarily as
early as the device actually finished seeding. A backend that keeps the
first value it saw for a given `event.id` should keep the first one; the
flag says which of two values on file is the replay. The attribute never
appears on a `planned`
record, because that instant comes only from the policy row and always
replays identically.

## What the per-peer byte counters can and cannot show

IRIS captures per-peer bytes from two vantage points, the device and the
origin. Both are estimates for reasons that trace back to how aria2 tracks
peers, not to a gap in how IRIS reads it.

On the device, an `--on-bt-download-complete` hook reads aria2's cumulative
per-peer counters through `aria2.getPeers` the instant the last piece lands,
before aria2 switches the download to seed-only and its connections start to
drain. aria2's `DefaultPeerStorage` erases a peer's counters from its
internal peer set the moment that peer disconnects. A peer that sent the
device a large share of an image and then dropped before the last piece
landed leaves no row and no bytes in the hook's read. Its contribution is
silently missing, not recorded as zero. The exported total is therefore a
floor on what the device actually received, not a full count of every
sender, and it will not always reconcile with the completed image size. IRIS
does account for rows it deliberately drops at a cap, in separate counters.
It also marks a capture incomplete when the read itself lost data, so a
reader can tell a known gap from an unexplained one.

On the origin side, the server polls the same `aria2.getPeers` call on an
interval and adds each connection's growth to a durable ledger. That counter
belongs to the connection and disappears the moment the connection closes. A
shorter poll interval catches more of a connection's growth before
it closes than a longer one does. The remainder that no poll caught is kept
as its own quantity rather than split across the peers that were seen,
because splitting it evenly would present arithmetic as if it were an
observation. [Dated lab evidence](validation-records.md) has the measured
coverage for a given poll interval.

## Redeploying agents changes what the server can attribute

Rebuilding the Guest Shell bundle, an IOx package, or the XR RPM does not
change any device's already-running agent; see
[Upgrade to a new release](../zensical/admin-guide/upgrade.md) to redeploy it.

This matters for telemetry specifically because the server accepts only the
report fields and peer identities it can validate. An agent still running an
older build that does not send a field the server now expects leaves that
data out of the report; the server never guesses a value to fill the gap. If
a device's transfer report is missing peer detail you expect after a change,
check which package built its running agent before you treat the report
itself as evidence of a bug.

## Related

- [What telemetry measures and proves](../zensical/architecture/telemetry-model.md)
- [Telemetry signals](../zensical/reference/telemetry-signals.md)
- [Monitor transfers and device reports](../zensical/user-guide/monitoring.md)
- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md)
- [Dated lab evidence](validation-records.md)
