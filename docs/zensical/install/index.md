<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install IRIS

Read this guide once, in order. At the end you have a running server and Console, device packages the server serves, and one device staging one image.

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot
    variables. See the [Overview](../index.md).

## Choose a layout

| Layout | Where the Console runs | Deployment files |
| --- | --- | --- |
| Docker on one host, the default | In the same stack as the server, calling `https://iris:9443`. | `server/docker-compose.yml`, configured by `server/.env` |
| Docker on separate hosts | On its own Docker host, reaching the server over private HTTPS 9443 with a file-mounted token and verified management TLS. | `server/docker-compose.server.yml` with `server/server.env`; `server/docker-compose.console.yml` with `server/console.env` |
| Kubernetes | In a second Deployment, on an internal 9443 Service that a NetworkPolicy restricts. | `kubernetes/` manifests |

Choose one layout and use its environment files and deployment commands throughout.
On separate Docker hosts, the server publishes private port 9443 for the Console.

## Read these pages in order

1. [Check the host before you install](check-the-host.md)
2. [Supported devices and platforms](supported-devices.md)
3. [Open the required ports](open-ports.md)
4. [Download the tools that build device packages](build-tools.md)
5. [Build the server and Console images](build-images.md)
6. [Create the two offline signing keys](signing-roots.md)
7. Your layout: [Install on one Docker host](one-docker-host.md), [Install on separate Docker hosts](separate-docker-hosts.md), or [Install on Kubernetes](kubernetes.md), which also adds Kubernetes sections to steps 5 and 11
8. [Sign in for the first time](first-sign-in.md)
9. [Turn on instruction signing](activate-signing.md)
10. [Set up certificates and tokens](certificates-and-tokens.md)
11. [Build and publish the device packages](device-packages.md)
12. [Verify the installation](verify.md)
13. [What a device needs before onboarding](device-requirements.md)
14. [Choose a management type](management-types.md)
15. Your devices, from the table below
16. [Stage your first image](../user-guide/first-image.md)

## Which device page you need

| Your devices | What to read at step 15 |
| --- | --- |
| Catalyst 9000 series switches and Catalyst 8000 series routers | The agent runs in Guest Shell: [Prepare Catalyst 9000 and 8000 devices for Guest Shell](guest-shell.md). On devices with app-hosting storage, [the IOx app](iox.md) is the alternative. |
| Industrial Ethernet switches with app hosting | [Prepare Industrial Ethernet switches with app hosting for the IOx app](iox.md). Step 11 builds the ARM64 package for them. |
| Cisco 8000 series and NCS routers | [Prepare Cisco 8000 and NCS routers for IOS-XR appmgr](ios-xr.md). |
| No devices yet, the server alone | Nothing. Steps 1 to 3 and 5 to 12 are enough. |
