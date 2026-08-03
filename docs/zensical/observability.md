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

These stay on regardless of the telemetry settings below.

## Running with telemetry off

External telemetry is opt-in: leaving `IRIS_OBSERVABILITY` unset is the
telemetry-off posture, and IRIS then makes no assumption that a Prometheus,
Loki, or Grafana stack exists. Set it to `1` to turn the external surface on.
[Telemetry variables](reference.md#telemetry-variables) has the exact semantics
of that variable and of `IRIS_OTLP_ENDPOINT`.

With telemetry off, `/metrics` is not served and answers 404, and nothing is
pushed to a collector. Nothing else changes: the port 9101 listener still runs
because `/healthz`, `/swarm`, and the `/swarmmap` pointer live there, and the
console's swarm view, image state, device reports, and audit log are unaffected
— they read the catalog's own state, not the metrics pipeline. The startup log
says which posture is in effect.

A Prometheus job left scraping `<server>:9101/metrics` in that posture therefore
reads the IRIS target as down and renders a Grafana IRIS dashboard blank. That is
telemetry being off, not a broken server. Either set `IRIS_OBSERVABILITY=1` or
remove the scrape job, and use the console and `/swarm` for network state in the
meantime.

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
| Prometheus target down, dashboard blank | `IRIS_OBSERVABILITY` — unset means `/metrics` answers 404 by design; then check reachability to port 9101. |

