<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install IRIS

Use the managed installer on Ubuntu 24.04 amd64. It prepares dependencies,
creates the signing keys, approves the server and builds the device packages.
Choose Docker on one host, separate Docker hosts or Kubernetes during setup.

## Prepare the host

1. [Check the host before you install](check-the-host.md).
2. Check [supported devices and platforms](supported-devices.md).
3. [Open the required ports](open-ports.md).

## Install and sign in { #choose-a-layout }

1. [Download and authenticate the installer](managed-package.md#download-and-authenticate).
2. Run [guided local setup](managed-package.md#guided-local-setup) for your layout:
   [one Docker host](managed-package.md#docker-on-one-host),
   [separate Docker hosts](managed-package.md#docker-on-separate-hosts) or
   [Kubernetes](managed-package.md#kubernetes).
3. [Sign in for the first time](first-sign-in.md) and create your administrator account.
4. Check [certificates and tokens](certificates-and-tokens.md).
5. [Verify the installation](verify.md).

## Prepare your devices

Read [what a device needs before onboarding](device-requirements.md), then
[choose a management type](management-types.md).

| Your devices | Preparation |
| --- | --- |
| Catalyst 9000 series switches and Catalyst 8000 series routers | [Guest Shell](guest-shell.md), or [IOx](iox.md) on switches with app-hosting storage. |
| Industrial Ethernet switches with app hosting | [IOx](iox.md). |
| Cisco 8000 series and NCS routers | [IOS-XR appmgr](ios-xr.md). |

[Add and onboard a device](../user-guide/onboarding.md), then
[stage your first image](../user-guide/first-image.md).
