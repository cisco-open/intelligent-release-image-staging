<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Network Ports and Flows

Every listed port is TCP. Source ports are ephemeral; the table shows the
destination port to permit in a firewall. IRIS uses one device-reachable server
address plus bidirectional device-to-device BitTorrent traffic.

## Onboarding

| Destination port | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- |
| 22 | Console/server host -> device IOS | SSH | Drive the installer, configure the trustpoint, and transfer configuration. |
| 22 | Console/server host -> remote stage host | SSH | Only when the Console and artifact/stage host are different machines. |
| 8000 | Console/server host -> artifact server | HTTPS | Installer preflight. |
| 8000 | Device IOS -> artifact server | HTTPS | Download the Guest Shell bundle, bootstrap, certificate, per-device configuration, and IOx package. |

In the standard Compose deployment the Console and artifact server share the
same container, so per-device configuration is staged locally and there is no
Console-to-stage-host SSH hop.

## Steady-State Operation

| Destination port | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- |
| 8443 | Device agent -> catalog | HTTPS | Image policy, assignment, enrollment-token refresh, heartbeats, and reports. |
| 6969 | Device or server seeder -> tracker | HTTP | Private BitTorrent announces. |
| 6881 | Device -> server seeder | BitTorrent | Initial image pieces from the origin seeder. |
| 6881-6999 | Device <-> device | BitTorrent | Peer-to-peer fetch and reseed traffic. Router NAT uses static TCP PAT for 6881. |
| 8080 | Operator browser -> Console | HTTPS | Console UI and API. The host port can be changed with `IRIS_GUI_PUBLISH`. |
| 9101 | Prometheus or operator tooling -> server telemetry | HTTP | `/healthz`, `/swarm`, and optional `/metrics`. |
| 22 | IOx agent -> its own IOS SVI | SSH/SCP | IOx SSH-to-self control and SCP image transfer before IOS `copy /verify`. |

External telemetry is opt-in, and the 9101 listener runs either way: `/healthz`,
the `/swarm` JSON, and the `/swarmmap` pointer are served regardless, while the
Prometheus `/metrics` endpoint and OTLP export are gated. See
[Telemetry variables](reference.md#telemetry-variables) for which variable does
what.

The Console reads `/swarm` over container loopback (`127.0.0.1:9101`), so 9101
needs **external** reachability only for Prometheus scraping or operator tools.
A deployment with no monitoring stack can leave it closed at the firewall
without affecting the Console.

Every service listens on an unprivileged port, which is what lets the whole
server run as the non-root uid 10001 with all capabilities dropped. See
[Container runtime privileges](security.md#container-runtime-privileges).

## Local-Only Services

| Port | Service | Constraint |
| --- | --- | --- |
| 6800 | aria2 JSON-RPC | Bound to loopback in the device runtime and seed-server container. It is intentionally not published by Docker Compose and must not be opened in a firewall. |
| 9101 | Console swarm access | The Console's swarm view uses container loopback, not the published port. Devices report through authenticated catalog traffic on 8443 and never talk to telemetry directly. |

## Firewall Rules

Minimum rules for a Compose server:

| Permit | Destination ports |
| --- | --- |
| Devices -> server | 6969, 8443, 8000, 6881 |
| Operators -> server | 8080 |
| Prometheus or operator tooling -> server, when used | 9101 |
| Server/Console -> devices during onboarding | 22 |
| Devices <-> devices | 6881-6999 in both directions |

When both `IRIS_OBSERVABILITY` and `IRIS_OTLP_ENDPOINT` are set, the server also
needs outbound TCP reachability to that endpoint (commonly OTLP/HTTP port 4318).
The collector is external to IRIS and is not published by the Compose stack.

## Important Constraints

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
  Preflight only confirms that path can reach the catalog, artifact, tracker,
  and seeder ports. See [Management Type and VLAN Ownership](network-attachment.md).
- For **router-routed** devices, the operator must route the VPG app subnet to
  the IRIS server and peers. **router-nat** uses the configured outside
  interface; permit inbound TCP 6881 to its outside address for peer reachability.
