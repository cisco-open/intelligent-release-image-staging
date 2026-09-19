<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Limits

What IRIS does not promise.

## The server runs on amd64

The server image is built for amd64 (x86_64) hosts. The agent binary in the
Guest Shell bundle is x86_64 as well. See
[Supported devices and platforms](../install/supported-devices.md) for which
platform each device family uses.

## A platform-family row is a delivery path, not a compatibility promise

A device-family row in the delivery-path table names a path, not confirmation
that every model and software release in that family is supported. Check
[Device requirements](../install/device-requirements.md) before you onboard.
Peer-assisted transfer speed depends on connectivity, peer policy, and which
pieces are locally available. It is not a fixed performance guarantee.

## One server writes state

Run one server replica with one read-write volume. Two server containers
writing the same state are not supported, on any layout.

## The certificate is tied to one address

The server certificate carries the server's own IP address, so that address has
to stay the same. To move the server, rotate the certificate and onboard every
deployed device again. You do not rebuild the device packages. The steps are in
[Rotate credentials and certificates](../admin-guide/rotations.md).

## A device administrator can stop the agent

Someone with privileged access to a device can stop the agent, change what it
reads, or work around the rate limits it applies. A report from a device is
evidence the device gave you, not proof. See
[Security model and trust boundaries](security-model.md#device-administrator-trust-boundary).

## Guest Shell may have no signature checker

Guest Shell checks an [instruction](../reference/glossary.md#instruction)'s
signature with a tool that some builds do not carry. Without that tool the
device reports [`verifier_missing`](../reference/glossary.md#verifier_missing).
It then applies no instruction and keeps to the controls the tracker gives it.

## Rate limits apply per process

The request budget the server applies to Console API calls lives inside one
management process. It is not a distributed quota, and it does not replace
upload size bounds, connection limits or network-layer protection. The settings
are listed in [Server configuration](../reference/server-configuration.md).

## The origin cannot shape one role

The origin seeder is the server's own copy of the image, the first source in the swarm. It can shape all of its traffic or the traffic for one [role](../reference/glossary.md#role). Inside one shared swarm, per-role origin shaping is not expressible. The fields you can set are listed in [Roles and sharing-policy API](../reference/peer-policy-api.md).

## An older agent reports less

A device that has not taken the current bundle keeps staging images, but it
does not adopt the plan identity the server sends. Its reports stay at
`planned` and never reach `seeding_started`. Upgrade the device, as described
in [Upgrade to a new release](../admin-guide/upgrade.md). Any change to the agent
needs a fresh build of every device package before rollout. See
[Build and publish the device packages](../install/device-packages.md#embedded-agent-packages).

## Telemetry costs a little on each link

Streaming transfer telemetry adds a small amount of traffic on the wide area
network, a fraction of the heartbeat each device already sends, and it sends
nothing over a link too poor to carry it. The measured figures are in
[the recorded WAN figures](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/validation-records.md).

## Byte counts are close, not exact

Per-peer byte counts come from two places: the origin seeder and the device
itself. The origin polls its live connections on an interval, so bytes moved by
a peer that came and went between two samples are missing, and that gap is
published on its own as `iris_peer_unattributed_bytes_total`. The device's
record covers only the peers it still had a connection to when the last piece
landed, so it is a floor rather than a census.

## What the capacity tests do not prove

The capacity harness measures how the cost of each operation moves as a
synthetic fleet grows. It does not establish production capacity, and neither
do the live API checks against a running server. See
[Manual checks and the test-file map](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/TESTING.md).

## Related

- [How IRIS works](index.md)
- [Security model and trust boundaries](security-model.md)
- [Monitor transfers and device reports](../user-guide/monitoring.md)
- [Supported devices and platforms](../install/supported-devices.md)
- [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md)
