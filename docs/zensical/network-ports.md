<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Network ports and flows

The tables show the default destination ports in the shipped deployment.
Every listed port is TCP; firewall rules should allow any source port. IRIS
uses one device-reachable server address plus bidirectional device-to-device
BitTorrent traffic.

## Container addresses

In Docker Compose, the server and Console each have a private container IP.
Docker publishes their external ports on the host. The Console reaches the
server at `https://iris:9443` using Docker's service name; neither container
needs a separate LAN address. The Console serves the web UI, including
`index.html`; device containers do not serve a UI.

IOx uses the app IP configured during onboarding. IOS-XR appmgr uses the
router's host network, so it shares the router's addresses. Both run the
shared device image; their connectivity differs by platform.

## Onboarding

| Destination port | Transport | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- | --- |
| 22 | TCP | Server tier or manual installer host -> device IOS | SSH/SCP | Drive onboarding. IOx and IOS-XR packages are pushed over SCP; Guest Shell uses SSH to configure IOS. |
| 8000 | TCP | Guest Shell device IOS -> artifact server | HTTPS capability URL | Guest Shell bootstrap, bundle, certificate, and short-lived per-install configuration fetch. |
| 8000 | TCP | Explicit artifact API client -> server tier | Authenticated HTTPS | Optional resource-bound `/v1/devices/.../artifacts/...` GET/HEAD. |

The Console and artifact server are separate. Console onboarding asks the
server-tier management API to stage Guest Shell's per-install files beside the
artifact server; no artifacts or device state are mounted into the Console.
For Guest Shell, the server-side installer sends
verified `copy https:` commands through SSH after installing the catalog
trustpoint. IOx and XR package delivery use authenticated, host-key-checked SCP;
their passwords reach `sshpass` through the environment, never a URL, argument,
or log. A remote stage-host hop exists only for a manual Guest Shell installer
run; the Console has no UI for it.

## Steady-state operation

| Destination port | Transport | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- | --- |
| 8443 | TCP | Device agent -> catalog | HTTPS | Image policy, assignment, enrollment-token refresh, heartbeats, and reports. |
| 6969 | TCP | Device or server seeder -> tracker | Authenticated HTTPS | Private BitTorrent announces. IOx/XR use a bearer header; Guest Shell uses its personalized query credential inside TLS. All agents and the origin seeder pin the server certificate; neither credential form is logged. |
| 6881 | TCP | Device -> server seeder | BitTorrent | Initial image pieces from the origin seeder. |
| 6881-6999 | TCP | Device <-> device | BitTorrent | Peer-to-peer fetch and reseed traffic. Router NAT uses static TCP PAT for 6881. |
| 8080 | TCP | Operator browser -> Console | HTTPS | Console UI and API. Compose publishes it only on `IRIS_HOST_IP`; the host port can be changed with `IRIS_GUI_PUBLISH`. |
| 9101 | TCP | Prometheus or operator tooling -> server telemetry | HTTPS | Anonymous, non-disclosing `/healthz` and `/readyz`; authenticated optional `/metrics`. Swarm data is reserved for the authenticated management API. |
| 9443 | TCP | Console -> server tier | Authenticated HTTPS | Internal management API. Never publish this port on the host or public LoadBalancer. |
| 22 | TCP | IOx agent -> its own IOS SVI | SSH/SCP | IOx SSH-to-self control; SCP image transfer before the final IOS placement copy on IE-3400, or on a Catalyst 9300 falling back from the SSD share. |

External telemetry is opt-in, and the 9101 listener runs either way.
`/healthz` and `/readyz` disclose no state and are the only anonymous registered
API operations. Guest Shell uses short-lived capability paths for installer
files. Prometheus `/metrics` is both observability-gated and authenticated;
swarm JSON is reached by the Console through the authenticated management API.
See
[Telemetry variables](reference.md#telemetry-variables) for which variable does
what.

The server management API reads its local telemetry state, so 9101 needs
**external** reachability only for authenticated Prometheus scraping or
operator tools.
A deployment with no monitoring stack can leave it closed at the firewall
without affecting the Console.

Every service listens on an unprivileged port, which is what lets the whole
server run as the non-root uid 10001 with all capabilities dropped. See
[Container runtime privileges](security.md#container-runtime-privileges).

## Local-only services

| Port | Transport | Service | Constraint |
| --- | --- | --- | --- |
| 6800 | TCP | aria2 JSON-RPC | Bound to loopback in the device runtime and seed-server container. It is intentionally not published by Docker Compose and must not be opened in a firewall. |
| 9443 | TCP | Server management API | Compose-network/Kubernetes-internal only and reachable only from the Console tier. It is intentionally absent from host/public Service mappings. |

## Firewall rules

Minimum rules for a Compose server:

All ports below are **TCP**.

| Permit | Transport | Destination ports |
| --- | --- | --- |
| Devices -> server | TCP | 6969, 8443, 6881; Guest Shell onboarding also needs 8000 |
| Operators -> server | TCP | 8080 |
| Explicit artifact API clients -> server, when used | TCP | 8000 |
| Prometheus or operator tooling -> server, when used | TCP | 9101 |
| Console -> server, internal network only | TCP | 9443 |
| Server tier or manual installer host -> devices during onboarding | TCP | 22 |
| Devices <-> devices | TCP | 6881-6999 in both directions |

Compose's host binding prevents the Console from also appearing on every other
host interface, but it is not an access-control list: restrict TCP 8080 on
`IRIS_HOST_IP` to trusted operator sources, especially until the first admin is
created. Kubernetes operators must apply the equivalent restriction to the
Console LoadBalancer.

!!! note "IRIS uses no UDP"
    Every listener above is TCP. DHT and local peer discovery are disabled,
    as is peer exchange. IRIS needs no UDP firewall rule.

When OTLP export is enabled, the server also needs outbound TCP reachability
to the configured collector (commonly OTLP/HTTP port 4318).
`IRIS_OBSERVABILITY` and `IRIS_OTLP_ENDPOINT` supply the defaults; Console
telemetry settings can override them at runtime. The collector is external
to IRIS and is not published by the Compose stack.

## Important constraints

- Trust `server/docker-compose.yml` or the Kubernetes Service definition for
  published ports, not a Dockerfile `EXPOSE` declaration.
- The private swarm disables DHT, peer exchange, and local peer discovery. There
  is no UDP tracker or DHT firewall requirement; tracker discovery is TCP 6969.
- The origin seeder is pinned to TCP 6881. Devices choose an available listen
  port in the 6881-6999 range and announce it to peers.
- Tracker (6969), catalog (8443), artifacts (8000), Console (8080), telemetry
  (9101), and internal management (9443) use HTTPS. The only HTTP
  listener is aria2 JSON-RPC on loopback inside each container or Guest Shell;
  it is never host-published.
- Kubernetes publishes server ports 6969, 8443, 8000, 6881, and 9101 through
  one LoadBalancer and Console port 8080 through another. Port 9443 is a
  separate ClusterIP Service selected by ingress policy. Preserve device source
  IP as described in [Kubernetes](kubernetes.md).
- For **inband** devices, these flows traverse the existing operator-owned
  management VLAN and its SVI; IRIS adds no VLAN, SVI, gateway, route, or VRF.
  Preflight checks prerequisites over SSH from the server; it does not prove
  the agent's route back to the server. Guest Shell enrollment fetches temporary
  install files from the HTTPS artifact listener; IOx packages and runtime
  trust are delivered over SCP.
  See [Management Type and VLAN Ownership](management-type.md).
- For **router-routed** devices, the operator must route the VPG app subnet to
  the IRIS server and peers. **router-nat** uses the configured outside
  interface; permit inbound TCP 6881 to its outside address for peer reachability.
- Do not use source IP as authentication. Protected API operations require
  their browser, device, monitoring, or tier credential even when a firewall
  or NetworkPolicy also restricts who can reach them.
