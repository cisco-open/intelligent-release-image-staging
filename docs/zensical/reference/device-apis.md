<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# APIs the device agent uses

These four listeners serve the device agent itself: Guest Shell, the IOx app,
or IOS-XR appmgr. For your own integration, use the [Console API](console-api.md).

## Device catalog (port 8443)

Every route needs `Authorization: Bearer <token>`. A missing or invalid token
returns 401.

- **Identity-bound** routes (`heartbeat`, `telemetry`, `policy`,
  `instructions`, `instruction-keylist`, `peer-tls`, `token-refresh`) need a
  token for the device id in the path. `token-refresh` also accepts the
  device's previous token.
- **Assignment-bound** routes (`images`, one image, torrents) show only the
  images assigned to that device. See [Security model and trust
  boundaries](../architecture/security-model.md) for how tokens are issued.

| Route | Auth | What it does |
| --- | --- | --- |
| `GET /v1/images` | Assignment-bound | Lists the caller's assigned images. An unassigned device gets an empty list. See [Publish and verify images](../user-guide/images.md). |
| `GET /v1/images/<id>` | Assignment-bound | One assigned image's details. An unassigned or unknown id returns 404. |
| `GET /v1/torrents/<id>` (also `<id>.torrent`) | Assignment-bound | A torrent file for an assigned image. IOx and IOS-XR appmgr send their tracker credential separately; Guest Shell gets a personalized URL. An unassigned or unknown id returns 404. |
| `GET /v1/devices/<id>/policy` | Identity-bound | The device's peer-sharing policy. See [Data formats and states](state-and-data.md). |
| `GET /v1/devices/<id>/instructions` | Identity-bound | The device's instruction, sealed in an envelope, capped at 256 KiB. An unchanged instruction returns 304. See [Security model and trust boundaries](../architecture/security-model.md). |
| `GET /v1/devices/<id>/instruction-keylist` | Identity-bound | The signed key list for checking that instruction, up to 128 KiB, with the same 304 behavior. |
| `POST /v1/devices/<id>/heartbeat` | Identity-bound | Takes the device's heartbeat and returns `{ok, stream_every, stream_pause, ...}`, telling it how often to report next. |
| `POST /v1/devices/<id>/telemetry` | Identity-bound | Takes one telemetry report. See [Telemetry signals](telemetry-signals.md). |
| `POST /v1/devices/<id>/peer-tls` | Identity-bound | Takes a certificate signing request and returns a 24-hour peer certificate. The private key stays on the device. |
| `POST /v1/devices/<id>/token-refresh` | Identity-bound (current or previous token) | Rotates the device's bearer token and any credentials due for rotation. See [Rotate credentials and certificates](../admin-guide/rotations.md). |

The two instruction routes share one request limit: 2 requests per device,
refilling by one every 10 seconds. Every POST needs a `Content-Length`
header; the body cap is 64 KiB after decompression.

## Tracker (port 6969)

The tracker speaks BitTorrent's own announce and scrape protocol, so answers
are bencoded, not JSON. IOx and IOS-XR appmgr send a bearer header; Guest
Shell sends its own personalized token.

| Route | What it does |
| --- | --- |
| `GET /announce` | Registers the caller as a peer for one image and returns peers to share with. `left=0` marks the caller a seeder. `compact=1` asks for a compact peer list (BEP23). |
| `GET /scrape` | Returns swarm counts (complete, incomplete, downloaded) for one image, per BEP48. |

Query parameters follow BitTorrent's own protocol: `info_hash`, `peer_id`,
`port`, `left`, `event`, `numwant`, `compact`. A device's role sets how often
it may announce and how many peers it gets back. See [Roles and
sharing-policy API](peer-policy-api.md).

## Telemetry listener (port 9101)

GET only. Which listeners `/readyz` checks, and whether `/metrics` answers,
are set in [Server configuration](server-configuration.md).

| Route | Auth | What it does |
| --- | --- | --- |
| `GET /healthz` | Anonymous | `{"ok": true}` when the telemetry process is running. |
| `GET /readyz` | Anonymous | Checks the tracker, catalog, artifact server and management API together. Docker Compose and Kubernetes use this to decide when the server is ready. See [Install on Kubernetes](../install/kubernetes.md). |
| `GET /metrics` | Monitoring credential | Prometheus-format metrics, when monitoring is on. See [Telemetry signals](telemetry-signals.md). |
| `GET /swarm` | Management credential | Peer counts for every image, for the Console. |
| `GET /status` | Management credential | Listener and telemetry-export status, for the Console. |

## Artifact server (port 8000)

Hands a device its onboarding files: the IOx package or IOS-XR rpm, the catalog certificate, and its first instruction.

| Route | Auth | What it does |
| --- | --- | --- |
| `GET`/`HEAD /v1/devices/<device-id>/artifacts/<path>` | HTTP Basic: device id as username, current catalog token as password | Serves one file from the device's onboarding folder. See [Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](../install/iox.md) and [Prepare Cisco 8000 and NCS routers for IOS-XR appmgr](../install/ios-xr.md). |

Guest Shell fetches its bootstrap files, bundle and certificate from
separate, short-lived paths that need no HTTP Basic credential. Files are
removed about an hour after they are written. See [Prepare Catalyst 9000 and
8000 devices for Guest Shell](../install/guest-shell.md).

!!! warning
    A path that tries to escape the device's own onboarding folder is refused.
