# IRIS: Intelligent Release and Image Staging

IRIS stages Cisco IOS-XE images across a fleet before an operator performs any install or reload activity. It uses a private BitTorrent swarm, a catalog of approved image metadata, and a small device agent to move large images efficiently while keeping verification on the device.

> IRIS distributes, verifies, and stages images. It never installs, activates, reloads, changes boot variables, or mutates the running software state of a device.

## Documentation

The detailed manual now lives in the Zensical documentation tree:

- [Documentation overview](docs/zensical/index.md)
- [Getting started](docs/zensical/getting-started.md)
- [Architecture](docs/zensical/architecture.md)
- [Security model](docs/zensical/security.md)
- [Operations](docs/zensical/operations.md)
- [Validation](docs/zensical/validation.md)

The public website source is in [docs/](docs/index.html). The GitHub Pages workflow builds Zensical into `site/`, combines it with the website, and publishes the website root plus generated docs under `/docs/`.

## What Ships

| Area | Purpose |
| --- | --- |
| `server/` | Tracker, catalog, seeder, artifact server, console, telemetry, encrypted state, and server tests. |
| `device/` | Catalyst 9300 Guest Shell installer, EEM applets, bootstrap, agent code, and device tests. |
| `device/iox/` | IOx app packaging and install path for IE-3x00/IE-3400 style platforms. |
| `fleet/` | CSV templates for device inventory and image assignments. |
| `tools/` | Operator helpers for agent bundles, per-device installers, assignments, torrents, and releases. |
| `docs/` | Dynamic public website and Zensical documentation source. |

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

Start the server from the repository root:

```bash
docker compose -f server/docker-compose.yml up -d --build
```

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

Open the console at:

```text
https://<server-ip>:8080/
```

For the complete deployment flow, see [Getting started](docs/zensical/getting-started.md).

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
bats device/test_guestshell_start.bats device/tests/ device/iox/tests/ server/tests/*.bats
```

## Security, Conduct, and License

See [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CONTRIBUTING.md](CONTRIBUTING.md), [LICENSE](LICENSE), and [NOTICE](NOTICE).
