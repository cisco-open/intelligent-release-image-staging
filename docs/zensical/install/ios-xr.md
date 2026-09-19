<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Prepare Cisco 8000 and NCS routers for IOS-XR appmgr

Onboard a Cisco 8000 series or NCS router running IOS-XR. The agent runs as
an appmgr application and stages images on `harddisk:`.

Skip this page for Catalyst 9000 series switches (Guest Shell, or IOx on
switches with app-hosting storage) and Catalyst 8000 series routers; see
[Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](iox.md) and
[Supported devices and platforms](supported-devices.md).

## Before you start

- A current `artifacts/iris-xr.rpm` on the server. See
  [Build and publish the device packages](device-packages.md).
- SSH access to the router and a saved credential profile.
- On the router: bash, curl with HTTPS, and SHA-256 tools.
- A route to the artifact server, normally TCP port 8000. See
  [Open the required ports](open-ports.md).
- Free space on `harddisk:` for the package and every image you stage. See
  [What a device needs before onboarding](device-requirements.md).

## Set the management type and platform

Use the `xr-host` management type with the `xr-appmgr` platform. Leave every
address, VLAN, SVI (switch virtual interface), VirtualPortGroup, and NAT field
empty. See [Choose a management type](management-types.md).

## Make sure the router can reach the catalog

Establish a path from the router to the artifact server, the tracker, and the
seeder. See [Network ports and flows](../architecture/network-ports.md).

!!! warning

    A route that reaches the catalog only from another VRF or a different
    source address will not work.

## Onboard the router

1. Add the router to your inventory with the `xr-host` management type, the
   `xr-appmgr` platform, and a credential profile.
2. Start onboarding from the Console, or call
   `POST /api/v1/devices/{device_id}/onboard`. Result: the server installs
   `iris-xr.rpm` on `harddisk:` and starts the `iris` application.
3. Follow the job until it reports that onboarding completed.
4. Wait for a heartbeat before you assign an image.

## What onboarding puts on the router

| On `harddisk:` | What it is |
| --- | --- |
| `iris-xr.rpm` | The appmgr package that carries the device agent. |
| `iris-catalog.pem` | The certificate the agent trusts. |
| `iris-work/` | The agent's own working directory. |
| Staged images and sidecar files | Each assigned image and its transfer files. |

The agent writes only to `harddisk:`. Undeploy removes the application, the
package, and these files. See
[Undeploy, retire and clean up devices](../user-guide/undeploy.md).

## Verify

- The job's last result says onboarding completed.
- A fresh heartbeat confirms the agent reached the catalog.
- On the router, the `iris` application is active and `harddisk:` holds
  `iris-catalog.pem` and `iris-work/`.

## Next steps

- [Stage your first image](../user-guide/first-image.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [What a device needs before onboarding](device-requirements.md)
- [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md)
