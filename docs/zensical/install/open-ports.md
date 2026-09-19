<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Open the required ports

Open the firewall paths IRIS needs, so the server, the Console, your devices and
your monitoring tools can reach each other. Every port is TCP, and the table
lists destination ports only.

## Before you start

- Pick your layout: [one Docker host](one-docker-host.md),
  [separate Docker hosts](separate-docker-hosts.md), or
  [Kubernetes](kubernetes.md).
- Know the server address devices use, and the Console address operators use.
- Know each device's [management type](management-types.md).

## Firewall rules

| Permit | Transport | Destination ports |
| --- | --- | --- |
| Devices -> server | TCP | 6969, 8443, 6881; Guest Shell, IOx and IOS-XR onboarding also need 8000 |
| Operators -> Console host | TCP | 8080 |
| Explicit artifact API clients -> server, when used | TCP | 8000 |
| Prometheus or operator tooling -> server, when used | TCP | 9101 |
| Console -> server over the private management network | TCP | 9443 |
| The server container or manual installer host -> devices during onboarding | TCP | 22 |
| Devices <-> devices | TCP | 6881-6999 in both directions |

!!! warning "Restrict the Console port"
    Permit TCP 8080 from trusted operator sources only, above all before you
    create the first admin account. On Kubernetes, apply the same restriction to
    the Console LoadBalancer. Never open the agent and server control port that
    listens on loopback inside the container.

### On one Docker host

Keep TCP 9443 on the Docker network and publish no host port for it.

### On separate Docker hosts

Bind the management API to a private server address and permit TCP 9443 from the
Console host only.

### On Kubernetes

Services, not host firewall rules, decide what is reachable. Keep the management
port on an internal Service.

## Telemetry on port 9101

Open 9101 only when Prometheus or operator tooling scrapes the server.

## Outbound access for telemetry export

Export over the OpenTelemetry Protocol (OTLP) needs outbound TCP from the server
to your collector, commonly port 4318. See
[Server configuration](../reference/server-configuration.md#telemetry-variables)
and [Export telemetry](../user-guide/telemetry-export.md).

## Verify

1. From a device subnet, reach the server on TCP 6969, 8443, 6881, and 8000 if
   you onboard from that subnet.
2. From the server, reach TCP 22 on every device you plan to onboard.
3. From an operator workstation, reach TCP 8080 on the Console host.
4. From the Console host, reach TCP 9443 on the server.
5. Between two devices that will share pieces, pass TCP 6881-6999 both ways.

Fix any closed path before you install.

## Next steps

- [Check the host before you install](check-the-host.md)
- [Download the tools that build device packages](build-tools.md)
- [Install on one Docker host](one-docker-host.md)
- [Network ports and flows](../architecture/network-ports.md)
