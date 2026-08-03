# IRIS: Intelligent Release and Image Staging

IRIS stages Cisco IOS-XE images across a network before an operator performs any install or reload activity. It uses a private BitTorrent swarm, a catalog of approved image metadata, and a small device agent to move large images efficiently while keeping verification on the device.

> IRIS distributes, verifies, and stages images. It never installs, activates, reloads, changes boot variables, or mutates the running software state of a device.

## Documentation

The detailed manual now lives in the Zensical documentation tree:

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
- [Container deployments](docs/zensical/containers.md) — the Compose seed server and agent containers
- [Kubernetes](docs/zensical/kubernetes.md) — optional single-replica manifests

**Onboard devices**

- [Device agents](docs/zensical/device-agents.md) — Guest Shell and IOx behavior on the device
- [Management type and VLAN ownership](docs/zensical/network-attachment.md) — attachments, VPG/NAT ownership, receipts
- [IOx app](docs/zensical/iox.md) — building, staging, and transfer paths

**Operate**

- [Web console](docs/zensical/console.md) — the admin browser workflow end to end
- [Network workflows](docs/zensical/fleet-workflows.md) — CSV inventory, assignments, batch operations
- [Operations](docs/zensical/operations.md) — day-two commands, backups, cleanup
- [Observability](docs/zensical/observability.md) — metrics, swarm map, OTLP export

**Reference and development**

- [Reference](docs/zensical/reference.md) — environment variables, file layouts, APIs
- [Validation](docs/zensical/validation.md) — test suites and the lab checklist
- [Development](docs/zensical/development.md) — working on IRIS itself

The public website source is in [docs/](docs/index.html). The GitHub Pages workflow builds Zensical into `site/`, combines it with the website, and publishes the website root plus generated docs under `/docs/`.

## What Ships

| Area | Purpose |
| --- | --- |
| `server/` | Tracker, catalog, seeder, artifact server, console, telemetry, encrypted state, and server tests. |
| `device/` | Catalyst Guest Shell installer, EEM applets, bootstrap, agent code, and device tests. |
| `device/iox/` | ARM64 and x86_64 IOx app packaging and install path for supported Cisco platforms. |
| `kubernetes/` | Optional single-replica seed-server deployment with persistent storage. |
| `fleet/` | CSV templates for device inventory and image assignments. |
| `tools/` | Operator helpers for agent bundles, per-device installers, assignments, torrents, and releases. |
| `docs/` | Dynamic public website and Zensical documentation source. |

## Platform support

IRIS supports Catalyst 9300 Guest Shell, supported IE/Catalyst IOx paths, and
router attachments designed for the Catalyst 8000 family, lab-tested on
C8000v. Catalyst 8000 routers use Guest Shell through an IRIS-managed
VirtualPortGroup and stage to `bootflash:`. Both `router-routed` and
`router-nat` have been lab-validated on C8000v through onboarding, verified
image staging, and receipt-backed undeploy; Swarm Map and Grafana telemetry
were also verified.
Router onboarding repeats read-only preflight immediately before execution and
before minting the enrollment token. Receipts bind management IP and
processor-board identity; router adoption is refused, so re-onboard instead.
Named globals and `guest-share` must be collision-free and are receipt-owned.
NAT interfaces are canonicalized, and pre-existing `ip nat outside` is preserved.

## Quick Start

Create an age identity and export the values the server needs:

```bash
mkdir -p ~/.config/iris
age-keygen -o ~/.config/iris/age.txt
age-keygen -y ~/.config/iris/age.txt

export IRIS_HOST_IP=<server-ip>
export IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age.txt
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>,<break-glass-age-public-key>
```

Build and bootstrap the server from the repository root, then start it:

```bash
docker compose -f server/docker-compose.yml build
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
docker compose -f server/docker-compose.yml up -d
```

`iris-bootstrap` is idempotent. It initializes encrypted server state and the
TLS certificate on a fresh config volume; subsequent runs leave existing state
untouched.

Create the console admin:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

Publish an image mounted under `/opt/images`:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

Generate per-device installers and apply assignments:

```bash
cp fleet/devices.csv.example fleet/devices.csv
tools/gen-device-installers.sh fleet/devices.csv

cp fleet/assignments.csv.example fleet/assignments.csv
tools/apply-assignments.sh fleet/assignments.csv
```

Each generated installer contains a short-lived enrollment token. On first
contact, the agent exchanges it for rotating catalog, announce, and local RPC
credentials; no permanent network token is baked into the installer. Re-provision
a device when replacing its bootstrap configuration or enrollment material.
That cutover still only changes the staging agent and never installs or reloads
an IOS-XE image.

Open the console at:

```text
https://<server-ip>:8080/
```

For the complete deployment flow, see [Getting started](docs/zensical/getting-started.md).

## Container Targets

The seed-server image is self-contained and built from the repository root:

```bash
docker build --platform linux/amd64 -f server/Dockerfile -t iris:docker-alpha .
```

The Cisco app-hosting agent supports ARM64 IE platforms and x86_64 Catalyst 9000
platforms. It downloads into the CAF persistent directory and hands the image
to IOS for a signature-enforcing `copy /verify`: on Catalyst 9000 through the
bind-mounted SSD share at disk speed, on IE-3x00 by SCP over SSH-to-self (see
[IOx app](docs/zensical/iox.md)). Build an image for inspection, or package it
with `ioxclient`:

```bash
# ARM64 package (default)
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh --image-only
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out

# x86_64 package for Catalyst 9000 app hosting
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out
```

`device/iox/install.sh` defaults to the IE-3x00 profile (`TARGET_FS=sdflash:`,
`AppGigabitEthernet1/1`). Console-onboarded C9300 deployments use the amd64
package with `APP_INTF=AppGigabitEthernet1/0/1`, `TARGET_FS=flash:`, and the
SSD-share pair `SHARE_HOST_PATH=/vol/usb1/iox_host_data_share` /
`SHARE_IOS_PATH=usbflash1:iox_host_data_share` carrying the transfer. See
[IOx app](docs/zensical/iox.md) and
[Container deployments](docs/zensical/containers.md) for the complete data path
and [Kubernetes](docs/zensical/kubernetes.md) for the optional seed-server
manifests.

## Network Surfaces

| Port | Service | Purpose |
| --- | --- | --- |
| 6969 | Tracker | Private BitTorrent announces. |
| 8443 | Catalog | Image metadata, device assignments, token refresh, and reports. |
| 8000 | Artifact server | Bootstrap, agent bundle, pinned certificate, and staged install assets. |
| 6881 | Seeder data | Image pieces from the server seeder. |
| 8080 | Web console | Admin browser interface. |
| 9101 | Telemetry | Health, swarm state, and optional Prometheus metrics. |
| 6800 | aria2 RPC | Local-only inside the container. |

## Documentation Development

Install the docs dependency into a temporary virtual environment:

```bash
python3 -m venv /tmp/iris-docs-venv
/tmp/iris-docs-venv/bin/pip install -r requirements-docs.txt
```

Build or serve the Zensical site:

```bash
/tmp/iris-docs-venv/bin/zensical build
/tmp/iris-docs-venv/bin/zensical serve
```

The dynamic website is plain HTML, CSS, and JavaScript under `docs/` and does not require a Node build step.

## Tests

Run the Python suite:

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ device/test_verify_image.py -q
```

Run the Bats suite:

```bash
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ server/tests/*.bats
```

## Security, Conduct, and License

See [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CONTRIBUTING.md](CONTRIBUTING.md), [LICENSE](LICENSE), and [NOTICE](NOTICE).
