<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Observability

IRIS reports network progress from the point of view that matters most: whether each device has staged the approved image safely.

## Always-on surfaces

| Surface | Purpose |
| --- | --- |
| `/healthz` on port 9101 | Basic service health. |
| `/swarm` on port 9101 | Machine-readable swarm and peer state. |
| `/swarmmap` on port 9101 | Pointer to the console swarm view. |
| Console monitoring | Human-readable network, image, and audit state. |

## Optional metrics

Set `IRIS_OBSERVABILITY=1` to enable Prometheus metrics and optional OTLP export. Use `IRIS_OTLP_ENDPOINT` to point at an OpenTelemetry collector when exporting is enabled.

## Device reports

Device reports are useful for both current status and post-incident review. Typical data includes:

| Field family | Examples |
| --- | --- |
| Identity | Device id, platform, storage target. |
| Assignment | Approved image id and current staged image. |
| Transfer | Download state, progress, peer information, seeder participation. |
| Verification | Hash checks, IOS copy or verify result, failure reason. |
| Timing | Last poll, last report, and operation duration. |

## Failure interpretation

| Symptom | First place to look |
| --- | --- |
| Device never appears | Installer output, artifact server reachability, catalog trustpoint, enrollment token expiry. |
| Download does not start | Tracker port, announce key, seeder port, device route to server. |
| Download stalls | Swarm view, peer count, seeder availability, storage capacity. |
| Verification fails | Catalog hash, file name, IOS copy output, image integrity. |
| Console stale | Telemetry health, catalog service logs, device report interval. |

