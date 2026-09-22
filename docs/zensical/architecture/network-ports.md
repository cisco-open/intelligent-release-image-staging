<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Network ports and flows

Every device reaches one server address, and devices reach each other in both
directions. Every port below is TCP, so a firewall rule may allow any source port.

## Ports at a glance

| Port | Protocol | Service | Reached by |
| --- | --- | --- | --- |
| 6969 | HTTPS | Tracker | Devices and the server's own seeder |
| 8443 | HTTPS | Catalog | Devices |
| 8000 | HTTPS | Artifact server | Devices during onboarding |
| 6881 | BitTorrent | Seeder data | Devices |
| 8080 | HTTPS | Console | Operator browsers |
| 9101 | HTTPS | Telemetry | Prometheus and operator tools |
| 9443 | HTTPS | Management API | The Console only |
| 6800 | HTTP | aria2 control interface | Loopback |

A device announces to the tracker to learn which peers hold an image, and asks
the catalog for instructions: the signed messages the server sends a device
saying which images to stage and how. Bytes then move from the
[origin seeder](../reference/glossary.md#origin-seeder) and its peers.

## Addresses

In Docker Compose, the server and the Console each get a private container
address, and Docker publishes their ports on their hosts. On one host, the
Console reaches `https://iris:9443` through Docker DNS; on separate hosts it
uses the server's private management address on port 9443. On Kubernetes, one
load balancer publishes the device-facing server ports, a second publishes
Console port 8080, and port 9443 stays on a ClusterIP Service. Devices reach
the server at the address in `IRIS_HOST_IP`, and the tracker URL uses it.

## Onboarding flows

The agent runs in Guest Shell on Catalyst 9000 and 8000 series devices; the IOx
app is the alternative on those with app-hosting storage. Industrial Ethernet
switches with app hosting run the IOx app, and Cisco 8000 series routers run
the IOS-XR appmgr container. NCS-540 is partially validated: package
transfer, RPM checksum matching, and registration are confirmed; image
staging, telemetry delivery, and undeploy validation are pending.

| Port | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- |
| 22 | Server or installer host -> device IOS | SSH | Drive onboarding and set up the first HTTPS trust. The device downloads its own packages. |
| 8000 | Guest Shell device IOS -> artifact server | HTTPS, short-lived URL | Bootstrap, bundle, certificate and per-install configuration. |
| 8000 | IOx device IOS -> artifact server | Authenticated HTTPS | `copy https:` of the IOx package, the catalog certificate and the instruction file, with the device's own credential. |
| 8000 | IOS-XR host -> artifact server | Authenticated HTTPS | The router downloads its package and instruction file, with certificate verification. |

## Steady-state flows

| Port | Source -> destination | Protocol | Purpose |
| --- | --- | --- | --- |
| 8443 | Device agent -> catalog | HTTPS | Image policy, sealed instructions and keylist, assignment, token refresh, heartbeats and reports. |
| 6969 | Device or server seeder -> tracker | Authenticated HTTPS | Private BitTorrent announces. IOx and IOS-XR use a bearer header; Guest Shell uses its own query credential inside TLS. Credentials are not logged. |
| 6881 | Device -> server seeder | BitTorrent | First image pieces from the origin seeder, which always listens on 6881. |
| 6881-6999 | Device <-> device | BitTorrent | Peer fetch and reseed traffic. Each device picks a free port in this range and announces it to its peers. |
| 9101 | Prometheus or operator tooling -> server telemetry | HTTPS | Anonymous `/healthz` and `/readyz`; authenticated `/metrics`. |
| 9443 | Console -> server | Authenticated HTTPS | The management API. Keep it on the Compose network, a private server-host binding, or the Kubernetes ClusterIP Service. |
| 22 | IOx agent -> its IOS gateway | SSH/SCP | SSH-to-self control, and the SCP image hand-off when the device has no SSD share. |

`GET /v1/devices/{device_id}/instructions` and
`GET /v1/devices/{device_id}/instruction-keylist` are authenticated requests on
the existing device-to-catalog HTTPS connection on TCP 8443. Instruction
delivery adds **no new listener, port, network path, or firewall flow**. TCP
9443 stays Console-to-server management only.

## How devices reach the tracker securely

The tracker on TCP 6969 is **HTTPS-only** and presents the same server
certificate that devices already pin for the catalog. The origin seeder and
every device aria2 process load that public certificate as their CA and keep
certificate verification enabled. The origin seeder, IOx and IOS-XR send their
announce credential in an `Authorization: Bearer` header, Guest Shell sends a
query credential in the same connection, and TLS encrypts the complete request.

Rotating the announce credential keeps the previous one valid for a
bounded overlap, and the expiry is enforced automatically. There is no
operator command for revoking a previous credential before its expiry.

## Restricted services

| Port | Service | Constraint |
| --- | --- | --- |
| 6800 | aria2 JSON-RPC | Bound to loopback in the device runtime and the seeder container. Keep it closed in every firewall. |
| 9443 | Server management API | Reachable from the Console only. Separate Docker hosts need a private server-host binding and a rule allowing the Console host. |

## Limits

A Dockerfile `EXPOSE` line publishes nothing. Read the Compose files you
selected, or the Kubernetes Service definitions, to see what a deployment publishes.

!!! warning

    Treat a source address as routing, not as proof of identity. Protected API
    operations still require their browser, device, monitoring or management credential.

## Related

- [Open the required ports](../install/open-ports.md)
- [How an image reaches a device](data-path.md)
- [Security model and trust boundaries](security-model.md)
- [Rotate credentials and certificates](../admin-guide/rotations.md)
