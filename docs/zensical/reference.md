<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Reference

## Command quick reference

| Command | Use |
| --- | --- |
| `docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap` | Initialize a fresh encrypted server config volume. |
| `docker compose -f server/docker-compose.yml up -d --build` | Build and start the IRIS server. |
| `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<image>.bin` | Publish an image into the catalog and seeder. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign` | Show images and assignments. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign <device> <image>` | Assign one image to one device. |
| `tools/gen-device-installers.sh fleet/devices.csv` | Generate per-device installers. |
| `tools/apply-assignments.sh fleet/assignments.csv` | Validate and apply assignment CSV. |
| `tools/make-agent-bundle.sh` | Build the Guest Shell agent bundle manually. |
| `device/device-uninstall.sh` | Remove Guest Shell IRIS wiring from a device. |
| `device/iox/install.sh` | Install the IOx app path. |
| `device/iox/uninstall.sh` | Remove the IOx app path. |
| `device/iox/build.sh --image-only` | Build the ARM64 app-hosting image; set `IOX_ARCH=amd64` for x86_64. |
| `kubectl apply -k kubernetes` | Deploy the optional single-replica Kubernetes seed server. |

## Port quick reference

| Port | Service | Device-facing |
| --- | --- | --- |
| 6969 | Tracker | Yes |
| 8443 | Catalog | Yes |
| 8000 | Artifact server | Yes |
| 6881 | Seeder data | Yes |
| 8080 | Web console | Operator-facing |
| 9101 | Telemetry | Operator-facing |
| 6800 | aria2 RPC | No, local-only |

## Documentation map

| Area | Pages |
| --- | --- |
| Start | [Overview](index.md), [Getting Started](getting-started.md) |
| Design | [Architecture](architecture.md), [Container Deployments](containers.md), [Security Model](security.md), [Observability](observability.md) |
| Components | [Server](server.md), [Kubernetes](kubernetes.md), [Device Agents](device-agents.md), [IOx App](iox.md), [Web Console](console.md) |
| Workflows | [Fleet Workflows](fleet-workflows.md), [Operations](operations.md), [Validation](validation.md), [Development](development.md) |
| Reference | [Reference](reference.md) |

## Generated outputs

| Output | Source |
| --- | --- |
| `site/` | Zensical build output. Not committed. |
| `deploy/` | GitHub Pages assembly directory. Not committed. |
| `fleet/dist/` | Generated device installers. Not committed. |
| `artifacts/` | Served runtime artifacts. Not committed except `.gitkeep`. |
| `release/` | Release packaging output. Not committed. |
