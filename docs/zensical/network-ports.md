<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Network ports and flows

Every listed port is TCP. Source ports are ephemeral; the table shows the
destination port to permit in a firewall. IRIS uses one device-reachable server
address plus bidirectional device-to-device BitTorrent traffic.

## Onboarding

| Destination port | Transport | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- | --- |
| 22 | TCP | Console/server host -> device IOS | SSH | Drive the installer, configure the trustpoint, and transfer configuration. |
| 22 | TCP | Console/server host -> remote stage host | SSH | Only when the Console and artifact/stage host are different machines. |
| 8000 | TCP | Console/server host -> artifact server | HTTPS | Installer preflight. |
| 8000 | TCP | Device IOS -> artifact server | HTTPS | Download the Guest Shell bundle, bootstrap, certificate, per-device configuration, and IOx package. |

In the standard Compose deployment the Console and artifact server share the
same container, so per-device configuration is staged locally and there is no
Console-to-stage-host SSH hop.

## Steady-state operation

| Destination port | Transport | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- | --- |
| 8443 | TCP | Device agent -> catalog | HTTPS | Image policy, assignment, enrollment-token refresh, heartbeats, and reports. |
| 6969 | TCP | Device or server seeder -> tracker | HTTP | Private BitTorrent announces. |
| 6881 | TCP | Device -> server seeder | BitTorrent | Initial image pieces from the origin seeder. |
| 6881-6999 | TCP | Device <-> device | BitTorrent | Peer-to-peer fetch and reseed traffic. Router NAT uses static TCP PAT for 6881. |
| 8080 | TCP | Operator browser -> Console | HTTPS | Console UI and API. The host port can be changed with `IRIS_GUI_PUBLISH`. |
| 9101 | TCP | Prometheus or operator tooling -> server telemetry | HTTP | `/healthz` and optional `/metrics`. `/swarm` answers only loopback peers unless `IRIS_SWARM_PUBLIC=1`. |
| 22 | TCP | IOx agent -> its own IOS SVI | SSH/SCP | IOx SSH-to-self control; SCP image transfer before IOS `copy /verify` on IE-3400, or on a Catalyst 9300 falling back from the SSD share. |

External telemetry is opt-in, and the 9101 listener runs either way: `/healthz`
and the `/swarmmap` pointer are served regardless, the Prometheus `/metrics`
endpoint and OTLP export are gated on `IRIS_OBSERVABILITY`, and the `/swarm`
JSON answers only loopback peers by default (`IRIS_SWARM_PUBLIC=1` opens it —
per-device swarm data is otherwise reserved for the authenticated console). See
[Telemetry variables](reference.md#telemetry-variables) for which variable does
what.

The Console reads `/swarm` over container loopback (`127.0.0.1:9101`), so 9101
needs **external** reachability only for Prometheus scraping or operator tools.
A deployment with no monitoring stack can leave it closed at the firewall
without affecting the Console.

Every service listens on an unprivileged port, which is what lets the whole
server run as the non-root uid 10001 with all capabilities dropped. See
[Container runtime privileges](security.md#container-runtime-privileges).

## Local-only services

| Port | Transport | Service | Constraint |
| --- | --- | --- | --- |
| 6800 | TCP | aria2 JSON-RPC | Bound to loopback in the device runtime and seed-server container. It is intentionally not published by Docker Compose and must not be opened in a firewall. |
| 9101 (loopback path) | TCP | Console swarm access | The same listener as the external 9101 row above, reached over container loopback rather than the published port — not a second service. Devices report through authenticated catalog traffic on 8443 and never talk to telemetry directly. |

## Firewall rules

Minimum rules for a Compose server:

All ports below are **TCP**.

| Permit | Transport | Destination ports |
| --- | --- | --- |
| Devices -> server | TCP | 6969, 8443, 8000, 6881 |
| Operators -> server | TCP | 8080 |
| Prometheus or operator tooling -> server, when used | TCP | 9101 |
| Server/Console -> devices during onboarding | TCP | 22 |
| Devices <-> devices | TCP | 6881-6999 in both directions |

!!! note "IRIS uses no UDP"
    Every listener above is TCP. The UDP parts of BitTorrent are switched off on
    every launch path — DHT, peer exchange, and local peer discovery are all
    disabled on the server seeder and on both device agents — so there is no DHT
    UDP port to open and UDP can stay closed for IRIS traffic.

When both `IRIS_OBSERVABILITY` and `IRIS_OTLP_ENDPOINT` are set, the server also
needs outbound TCP reachability to that endpoint (commonly OTLP/HTTP port 4318).
The collector is external to IRIS and is not published by the Compose stack.

## Important constraints

- Trust `server/docker-compose.yml` or the Kubernetes Service definition for
  published ports, not a Dockerfile `EXPOSE` declaration.
- The private swarm disables DHT, peer exchange, and local peer discovery. There
  is no UDP tracker or DHT firewall requirement; tracker discovery is TCP 6969.
- The origin seeder is pinned to TCP 6881. Devices choose an available listen
  port in the 6881-6999 range and announce it to peers.
- Catalog (8443), artifacts (8000), and Console (8080) use HTTPS. Tracker
  (6969) and telemetry (9101) use HTTP by design.
- Kubernetes publishes 6969, 8443, 8000, 6881, 8080, and 9101 through its
  LoadBalancer. Preserve source IP as described in [Kubernetes](kubernetes.md).
- For **inband** devices, these flows traverse the existing operator-owned
  management VLAN and its SVI; IRIS adds no VLAN, SVI, gateway, route, or VRF.
  Onboarding preflight is read-only and does not test that path from the device:
  it confirms the device answers SSH from the server, and — as on every other
  platform — refuses the onboard if the device still carries any IRIS-named
  artifact (an IRIS-* EEM applet, the IRISQ logging discriminator or its
  bindings, `crypto pki trustpoint IRIS`, `ip http client secure-trustpoint
  IRIS`, the app-hosting stanza), has Guest Shell already enabled, or has a
  non-empty `bootflash:guest-share`. The installer separately verifies from the
  server host that the artifact server (8000) is serving over trusted HTTPS.
  See [Management Type and VLAN Ownership](network-attachment.md).
- For **router-routed** devices, the operator must route the VPG app subnet to
  the IRIS server and peers. **router-nat** uses the configured outside
  interface; permit inbound TCP 6881 to its outside address for peer reachability.
- The `/swarm` peer-address gate assumes a rootful container engine; on
  rootless Docker/Podman or host networking a source-IP check is meaningless
  (published-port connections can be re-originated inside the namespace) — set
  `IRIS_METRICS_HOST=127.0.0.1` or drop the 9101 publish to keep swarm data
  local there.
