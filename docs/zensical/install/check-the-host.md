<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Check the host before you install

Prepare the hosts and addresses for [the Ubuntu .deb installer](managed-package.md).
The installer adds its build tools and missing dependencies, creates the keys,
and prepares the server and device packages.

## Choose the hosts

Use Ubuntu 24.04 amd64 for the installation controller. For separate Docker
hosts, the Console host also needs Ubuntu 24.04 amd64 and the SSH access described
under [Docker on separate hosts](managed-package.md#docker-on-separate-hosts).

For Kubernetes, provide an existing cluster, storage, enforced NetworkPolicy and
LoadBalancer addresses. See [Kubernetes](managed-package.md#kubernetes) for the
controller, registry and cluster requirements.

## Size the host

Start with this server budget, then measure your fleet's check-ins, telemetry,
and image transfers before expanding a rollout.

| Resource | Need |
| --- | --- |
| Server | 2 vCPU, 4 GB RAM |
| Disk | Space for retained images, encrypted state, artifacts, and build output |
| NIC | Start with 1 GbE; size for your image sizes and rollout windows |

These are planning values, not a validated 200-device capacity guarantee. See
[Limits](../architecture/limitations.md) for the validation boundaries.

## Prepare network access

Give the server a stable address that devices can reach. Choose a Console address
on the management network and reserve its HTTPS port. See
[Open the required ports](open-ports.md). Allow network access for package
repositories and builds, and arrange protected storage for independent backups.

Restrict access to the new Console until you have claimed its administrator
account. Setup displays the Console address when it finishes.

## Verify time before deployment

Check time synchronization on the controller, every Docker host and each
Kubernetes node that can run an IRIS pod. Configure your approved NTP service
and confirm its selected peer, for example with `chronyc tracking` and
`chronyc sources -v`. A running service alone does not prove synchronization.

!!! warning
    Containers take their clock from the host. Correct host time rather than
    granting containers `SYS_TIME` or privileged mode.

## Choose image and backup storage

Keep Cisco image files outside source repositories. To use an existing image
folder with Docker, pass `--image-root /opt/images` to setup. The folder must be
readable and traversable by uid `10001`; setup checks access and preserves its
permissions. Otherwise, setup uses `images` inside its state directory.
See [Use an existing image folder](managed-package.md#use-an-existing-image-folder).

Keep an independent copy of the setup key folder and encrypted backups. Choose
backup storage before setup and record it with the installation's addresses.

## Next steps

- [Install IRIS with the Ubuntu .deb package](managed-package.md)
- [Supported devices and platforms](supported-devices.md)
- [What a device needs before onboarding](device-requirements.md)
