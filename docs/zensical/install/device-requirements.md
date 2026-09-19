<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# What a device needs before onboarding

## Before you start

- The server and the Console are running, and you have signed in.
- Your device is on the list in [Supported devices and platforms](supported-devices.md).
- You picked a [management type](management-types.md) for it.

## 1. Synchronize the device clock

1. Run `show ntp status` on the device.
   Result: synchronized to an external reference, stratum 1 to 15.
2. If it is not, run `show ntp associations`.
   Result: a selected peer shows non-zero reach.

Configure NTP outside IRIS. The server host has its own clock requirement; see [Check the host before you install](check-the-host.md).

!!! warning

    Do not change routing, VRFs or interfaces that other services depend on to make this check pass.

- `time preflight failed`: check the selected VRF, source interface, return route and UDP/123 access.
- Peer selected, status still `unsynchronized`: the clock is measuring drift (`FREQ`), so let it settle and check again.

### If a device cannot reach the approved upstream server

An operator-approved host NTP relay is an option here, not an IRIS feature.
Synchronize that host to the upstream server, allow UDP/123 only from the
intended clients, and verify both hops. Do not configure a local or orphan
clock to make an unsynchronized relay appear healthy. Keep relay addresses
and service configuration outside IRIS templates. See
[Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md#time-synchronization)
for the other clock symptoms.

## 2. Size the storage root

- Allow **2x the image size + 200 MB** of free space per image in flight, about 4.2 GB for a 2 GB image.
- Budget for every image you want resident at once.
- Remove a file whose size and hash do not match the catalog. Guest Shell adopts a matching one.

## 3. Make the device reachable

1. Give the device a management address the server can reach, then assign it a credential profile in the Console.
2. Open the [required ports](open-ports.md) for the catalog, tracker and artifact server.

## 4. Onboard the device

1. Onboard from the Console or the API.
   Result: the server opens an SSH session, runs the installer, and hands the agent its first credential; it then runs `copy running-config startup-config`.
2. If the device still carries IRIS configuration, onboarding is refused. [Undeploy](../user-guide/undeploy.md) it first, then retry.

## Confirm the device is onboarded

1. Open **Devices** in the Console.
   Result: the job reads `Onboard completed.`
2. Check the device's last report.
   Result: a fresh heartbeat means the agent reaches the catalog.
3. Check each assigned image on the device row.
   Result: its own staging status.

The agent checks in about every 60 seconds; a new assignment reads **Waiting for staging** until then. If a device never reports, or an image stays there, see [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md).

## Next steps

- [Prepare Catalyst 9000 series and 8000 series devices for Guest Shell](guest-shell.md)
- [Prepare Industrial Ethernet 3000 series, Catalyst 9000 series and 8000 series devices for the IOx app](iox.md): on Catalyst 9000 series switches, IOx is the alternative to Guest Shell
- [Prepare Cisco 8000 series and NCS routers for IOS-XR appmgr](ios-xr.md)
