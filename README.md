# IRIS: Intelligent Release and Image Staging

IRIS stages Cisco images and patches across a network before an operator performs any install or reload activity. A server container manages the catalog, private BitTorrent tracker, and origin seeder; a separate Console container provides the browser interface. One shared agent runs in Guest Shell or in the common IOx and IOS-XR device image.

The Console, catalog, tracker, artifact server, telemetry listener, and internal management API use HTTPS. Device agents verify the server certificate. Image transfers use the private BitTorrent swarm; see [network ports and flows](docs/zensical/network-ports.md) for connectivity requirements.

> IRIS distributes, verifies, and stages images. It never installs, activates, reloads, changes boot variables, or mutates the running software state of a device.

> Bringing the server up is a command-line task. After that the [web console](docs/zensical/console.md) covers the everyday workflow — publishing images, assigning them, onboarding devices, and watching progress.

## Documentation

The detailed manual lives in the Zensical documentation tree:

Start at the [documentation overview](docs/zensical/index.md), or jump to a section:

**Get started**

- [Getting started](docs/zensical/getting-started.md) — lab bring-up from zero to a staged image
- [AI-guided PoC](docs/zensical/aiagent.md) — proof of value with an AI assistant driving the steps

**How it works**

- [Architecture](docs/zensical/architecture.md) — components, data flow, trust boundaries
- [Security model](docs/zensical/security.md) — tokens, encryption at rest, TLS, non-root runtime
- [Network ports and flows](docs/zensical/network-ports.md) — every port and what rides it

**Deploy the server**

- [Server](docs/zensical/server.md) — services, state, bootstrap, certificates
- [Container deployments](docs/zensical/containers.md) — the split Compose server/Console and unified device image
- [Kubernetes](docs/zensical/kubernetes.md) — optional split server and Console manifests

**Onboard devices**

- [Device agents](docs/zensical/device-agents.md) — Guest Shell, IOx, and IOS-XR appmgr behavior
- [Management type and VLAN ownership](docs/zensical/management-type.md) — management types, VPG/NAT ownership, deployment records
- [IOx app](docs/zensical/iox.md) — building, staging, and transfer paths

**Operate**

- [Web console](docs/zensical/console.md) — the admin browser workflow end to end
- [Network workflows](docs/zensical/fleet-workflows.md) — CSV inventory, assignments, batch operations
- [Operations](docs/zensical/operations.md) — day-two commands, backups, cleanup
- [Observability](docs/zensical/observability.md) — metrics, swarm map, OTLP export
- [Telemetry export](docs/zensical/telemetry-export.md) — peer-distribution accounting: origin versus peer bytes, per-device peer transfer records, and the limits of each figure
- [Splunk setup](docs/zensical/splunk.md) — collector configuration, HTTPS event ingestion, dashboards, and troubleshooting

**Reference and development**

- [Reference](docs/zensical/reference.md) — environment variables, file layouts, APIs
- [Problem type registry](docs/zensical/problems.md) — stable API error identifiers
- [Validation](docs/zensical/validation.md) — test suites and the lab checklist
- [Development](docs/zensical/development.md) — working on IRIS itself

The public website source is in [docs/](docs/index.html). The GitHub Pages workflow builds Zensical into `site/`, combines it with the website, and publishes the website root plus generated docs under `/docs/`.

## What Ships

| Area | Purpose |
| --- | --- |
| `server/` | Stateful tracker/catalog/seeder/artifact/telemetry tier, stateless web Console, management API, encrypted state, and server tests. |
| `device/` | Catalyst Guest Shell installer, EEM applets, bootstrap, agent code, and device tests. |
| `device/iox/` | ARM64 and x86_64 IOx app packaging and install path for supported Cisco platforms. |
| `device/xr/` | IOS-XR appmgr wrapper metadata, package-build support, and tests for the common device image. |
| `kubernetes/` | Optional split server and stateless Console workloads with server-only persistent storage. |
| `fleet/` | CSV templates for device inventory and image assignments. |
| `tools/` | Operator helpers for agent bundles, per-device installers, assignments, torrents, and releases. |
| `docs/` | Dynamic public website, Zensical documentation source, and importable Splunk and Grafana dashboards. |

## Platform support

IRIS stages Cisco software on IOS-XE switches/routers and IOS-XR routers. Which agent runs where, how each platform stages, and what has been lab-validated is documented in
[device agents](docs/zensical/device-agents.md) and [validation](docs/zensical/validation.md).

## Security, Conduct, and License

See [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CONTRIBUTING.md](CONTRIBUTING.md), [LICENSE](LICENSE), and [NOTICE](NOTICE).
