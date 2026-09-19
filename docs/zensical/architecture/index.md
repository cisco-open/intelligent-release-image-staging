<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# How IRIS works

IRIS copies a Cisco image to many devices at once. The server holds the images and
decides which device gets which one. The devices do most of the copying.

## Why a private swarm instead of a file server

With a file server, every device pulls the whole image from one place, and a large
fleet fills that server's uplink. With IRIS, the server seeds the image once and the
devices trade pieces with each other. Every device that finishes becomes another
source for the rest.

## What each part does

| Component | Responsibility |
| --- | --- |
| Catalog | Serves image metadata, assignments, token refresh, and device reports. |
| Tracker | Authenticates private BitTorrent announces over pinned HTTPS. |
| Seeder | Provides the initial image pieces through `aria2c`; its JSON-RPC port stays local-only. |
| Artifact server | Serves bootstrap scripts, catalog trust material, and agent bundles over HTTPS. |
| Console | Serves the browser UI and forwards API requests to the server's internal management API. |
| Management API | Runs Console operations against server state, including image publishing and device onboarding. |
| Telemetry service | Reads device reports stored by the catalog and combines them with tracker and seeder data for swarm views, metrics, and exports. |
| Device agent | Downloads pieces, verifies the image, stages it to platform storage, and reports status. |

IRIS builds three images. The server image runs the catalog, the tracker, the seeder,
the artifact server, the telemetry service and the management API, and it holds the
state. The Console image serves the browser application and forwards its API requests
to the management API over authenticated HTTPS. The device agent image runs on IOx and
IOS-XR appmgr; Guest Shell gets the same agent as a bundle instead.

## Where the two containers run

| Layout | What runs where | Install page |
| --- | --- | --- |
| One Docker host | Both containers, one Compose project, management HTTPS unpublished | [Install on one Docker host](../install/one-docker-host.md) |
| Separate Docker hosts | Server on one host, Console on another, each with its own environment file | [Install on separate Docker hosts](../install/separate-docker-hosts.md) |
| Kubernetes | Two Deployments, their Services, a network policy, and a server-only volume claim | [Install on Kubernetes](../install/kubernetes.md) |

Only the management connection crosses from the Console to the server, so a Console
moves without touching server data or onboarding devices again.

## The device agent

One Python agent runs on every device. It reads its assignment, downloads pieces from
the seeder and from its peers, checks the hash, writes the image to device storage and
reports what it did. On Catalyst 9000 series switches the agent runs in Guest Shell,
and the IOx app is the alternative on switches with app-hosting storage. Catalyst 8000
series routers take either path. Industrial Ethernet 3000 series switches and IR 1100
and 1800 series routers run the IOx app. Cisco 8000 series and NCS routers run the
agent under IOS-XR appmgr.

## What is stored where

| Layout | Volumes | State and secrets | Images | Device packages |
| --- | --- | --- | --- | --- |
| One Docker host | Named volumes on the host | State, encrypted configuration and the public management CA | Console uploads volume, plus your read-only import root | Host-bound artifacts directory |
| Separate Docker hosts | The same volumes, all on the server host | Same, on the server host; the Console host keeps only its token, CA and browser certificate | Same, on the server host | Same, on the server host |
| Kubernetes | One read-write-once claim under `/data` | `/data/state` and `/data/config`; runtime secrets in memory | Uploads on the claim | `/data/artifacts` |

Back up the server host; the Console keeps nothing of its own. For the paths and the
file formats, see
[Server configuration](../reference/server-configuration.md) and
[Data formats and states](../reference/state-and-data.md).

!!! warning
    Keep the encrypted signing key, the age identity and the instruction state on the
    server host. Never copy them to the Console host.

## The rest of this guide

| Page | What it covers |
| --- | --- |
| [How an image reaches a device](data-path.md) | The path from a published image to a file on device storage, and what the agent does on each pass. |
| [Security model and trust boundaries](security-model.md) | Who holds which key, how a device trusts a staging order, and which devices may share. |
| [Network ports and flows](network-ports.md) | Every port, who opens it, and which way traffic runs. |
| [Limitations](limitations.md) | The limits to plan for. |
