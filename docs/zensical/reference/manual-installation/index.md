<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Manual installation reference

These procedures describe the individual build, key and deployment commands
for installations you provision yourself. For guided setup, use
[Install IRIS](../../install/index.md).

## Prepare tools and keys

1. [Check the host](check-the-host.md) and
   [open the required ports](../../install/open-ports.md).
2. [Download the tools that build device packages](build-tools.md).
3. [Build the server and Console images](build-images.md).
4. [Create the two offline signing keys](signing-roots.md).
   [Create keys and approve signing requests](offline-approval.md) covers the key helper.

For managed installation with offline signing keys, use
[Install with separate key holders](offline-approval.md#install-with-separate-key-holders).

## Choose a layout

| Layout | Procedure |
| --- | --- |
| Server and Console together | [Install on one Docker host](one-docker-host.md). |
| Console on another host | [Install on separate Docker hosts](separate-docker-hosts.md). |
| Server and Console in a cluster | [Install on Kubernetes](kubernetes.md). |

Keep the selected topology, environment files, project names and server volumes
consistent through maintenance.

## Finish the deployment

1. [Sign in for the first time](../../install/first-sign-in.md).
2. [Turn on instruction signing](activate-signing.md).
3. [Set up certificates and tokens](certificates-and-tokens.md).
4. [Build and publish the device packages](device-packages.md).
5. [Verify the installation](../../install/verify.md).
6. [Prepare your devices](../../install/index.md#prepare-your-devices).
