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
| `/swarm` on port 9101 | Machine-readable swarm and peer state — loopback peers only by default (the console proxies it); `IRIS_SWARM_PUBLIC=1` opens it. |
| `/swarmmap` on port 9101 | Pointer to the console swarm view. |
| Console monitoring | Human-readable network, image, and audit state. |

These stay on whenever the telemetry listener runs, regardless of the
telemetry settings below. The one exception is `IRIS_METRICS_PORT` set to
empty or `0`, which disables the listener entirely and takes `/healthz`,
`/swarm`, and `/swarmmap` with it.

## Running with telemetry off

External telemetry is opt-in: leaving `IRIS_OBSERVABILITY` unset is the
telemetry-off posture, and IRIS then makes no assumption that any
observability stack exists — it emits OpenTelemetry (OTLP), and the operator
chooses the collector and backend. Set it to `1` to turn the external surface on.
[Telemetry variables](reference.md#telemetry-variables) has the exact semantics
of that variable and of `IRIS_OTLP_ENDPOINT`.

With telemetry off, `/metrics` is not served and answers 404, and nothing is
pushed to a collector. Nothing else changes: the port 9101 listener still runs
because `/healthz`, the loopback-gated `/swarm`, and the `/swarmmap` pointer
live there, and the console's swarm view, image state, device reports, and
audit log are unaffected — they read the catalog's own state, not the metrics
pipeline. The startup log says which posture is in effect.

A Prometheus job left scraping `<server>:9101/metrics` in that posture therefore
reads the IRIS target as down and renders an operator dashboard blank. That is
telemetry being off, not a broken server. Either set `IRIS_OBSERVABILITY=1` or
remove the scrape job. Use the console's Swarm tab for network state in the
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

## Transfer streaming

Transfer streaming adds a live, fleet-scale view of in-flight transfers: which
devices are pulling which image, how fast, from how many peers, and on what
quality of link. It is strictly opt-in and ships dark.

Streaming adds **no new network flows** — live samples ride inside the
heartbeat each device already sends, on the same TLS channel, port, and token.
[Network ports](network-ports.md) is unchanged by this feature.

### Enabling streaming

Streaming is controlled by the device conf key `telemetry_stream`
(default `off`), changed only by re-deploying the agent:

| Platform | Delivery |
| --- | --- |
| Guest Shell / router | `TELEMETRY_STREAM=on` in the installer environment, or the console's *Telemetry streaming* checkbox. |
| IOx | `IRIS_TELEMETRY_STREAM=on` at deploy time; a redeploy reconciles the persistent conf, so toggling takes effect. |

Parsing is fail-closed: only an explicit `on`/`1`/`true`/`yes` enables it —
anything else, including garbage, stays off. Streaming also requires the master
`telemetry` key (reports, default on) to be on. Console onboarding exposes both
as checkboxes, and bulk redeploy covers site-scale enablement.

### The live sample

While a transfer is active, the agent embeds one compact sample (≤250 B) in
its heartbeat:

| Field | Meaning |
| --- | --- |
| `v` | Sample schema version (currently `1`). |
| `image_id` | The device's policy-assigned image (validated server-side). |
| `phase` | `downloading` or `seeding`. |
| `done_bytes` | Bytes completed. |
| `down_bps` / `up_bps` | Current receive / send rate. |
| `peers` | Connected peer count. |
| `tier` | Link quality tier, `good` or `constrained`. |

The sample schema is versioned and transport-independent by design; the server
validates every field against its own policy state and drops anything
malformed without ever failing the heartbeat.

### Cadence and tuning

Sampling adapts to link quality automatically:

| Tier | Cadence |
| --- | --- |
| `good` | Every tick (60 s). |
| `constrained` | Every 4th tick (~4 min). |
| `bad` | No samples (the terminal report tells the story later). |

Fleet-wide tuning without redeploys goes through the console API:
`POST /api/telemetry/stream` with `{"every": <1..60>, "pause": <bool>}`
stretches the cadence (`every` multiplies the interval in ticks) or pauses
sampling entirely. Directives can only reduce volume — the hard ceiling is one
sample per device per tick, and a stale directive reverts to defaults within
three ticks.

### The add-on guarantee

Telemetry is an add-on: no telemetry condition can affect staging. Loss is
silent in operation but visible in three places — the console's *Telemetry
export* badge, the `/healthz` JSON (`otlp_export` block), and one audit entry
per state transition (`otlp-export-degraded` / `otlp-export-recovered`).

### Metrics names (operator contract)

The hub aggregates samples per image and exports OTLP metrics alongside the
Prometheus exposition on `:9101 /metrics`. Point `IRIS_OTLP_ENDPOINT` at your
collector and route to e.g. Splunk — or any other OTLP backend. These names
are contract:

| Prometheus family (`:9101`) | OTLP metric | Unit | Attributes |
| --- | --- | --- | --- |
| `iris_transfer_active` | `iris.transfer.active` | `{transfer}` | `iris.image.id`, `iris.torrent.info_hash` |
| `iris_transfer_down_bps_sum` / `iris_transfer_up_bps_sum` | `iris.transfer.throughput` | `By/s` | image attrs + `network.io.direction` = `receive` \| `transmit` |
| `iris_transfer_progress_ratio` | `iris.transfer.progress` | `1` | image attrs |
| `iris_transfer_stalled` | `iris.transfer.stalled` | `{transfer}` | image attrs |
| `iris_transfer_tier` + `iris_stream_devices` | `iris.stream.devices` | `{device}` | `iris.image.id`, `iris.link.tier` |
| `iris_transfer_samples_rejected_total` | `iris.telemetry.samples.rejected` | `{sample}` | — (counter; no `_total` on the OTLP wire) |
| `iris_otlp_export_failures_total` | `iris.telemetry.export.failures` | `{error}` | `iris.telemetry.signal` = `logs` \| `metrics` |
| `iris_otlp_last_export_success_seconds` | — (Prometheus + `/healthz` only) | | |

`IRIS_OTLP_DEVICE_METRICS=on` additionally exports per-device gauges
(`iris.device.transfer.throughput`, `iris.device.transfer.progress`,
`iris.device.transfer.received` with `device.id` attributes). Default off:
at 10,000 devices this is roughly 30,000 datapoints per push at your backend —
enable it deliberately.

### Log attributes (operator contract)

Terminal per-device reports and swarm lifecycle events flow as OTLP logs with
OpenTelemetry semantic-convention names. Event identity is the top-level
`eventName` field: `iris.device.report` for reports,
`iris.swarm.start|complete|stop|stale` for swarm events. Key attributes:
`device.id`, `device.model.identifier`, `iris.image.id`, `iris.link.tier`,
`iris.transfer.throughput_avg`, `network.peer.address` / `network.peer.port` /
`network.transport`, `iris.torrent.info_hash`, the peers observed during the
transfer as the structured attribute `iris.transfer.peers` (each row: peer
address, resolved `device.id` where known), and `iris.transfer.peers_total`
(exact distinct peers observed; rows beyond the named cap are counted here,
not listed). Per-peer byte counts are deliberately absent: BitTorrent clients
expose only instantaneous per-peer rates, so any per-peer byte figure would
be derived rather than measured. Exact byte totals are transfer-level.

### Sizing

Per device on the WAN, streaming adds ~33 bps on a good link (~250 B/min),
~8 bps constrained, and nothing on a bad link — against the ~800 bps the
heartbeat itself already costs.

#### 200-device deployment

| Resource | Need (control plane + telemetry) |
| --- | --- |
| Server | 2 vCPU, 4 GB RAM ample |
| Ingress | ~0.2–0.3 Mbps sustained (~3.3 heartbeats/s + announces) |
| CPU | a few % of one core (TLS-dominated) |
| Telemetry disk | ≤ ~20 MB total (report rings + snapshot) |
| OTLP egress | < 10 KB/s, LAN-side; per-device metrics safe to enable |
| NIC | 1 GbE — sized by image seeding (~1–2 × image size per rollout wave), not telemetry |

Scale-out telemetry ingestion is on the roadmap; the sample schema is
versioned and transport-independent by design.

## Failure interpretation

| Symptom | First place to look |
| --- | --- |
| Device never appears | Installer output, artifact server reachability, catalog trustpoint, enrollment token expiry. |
| Download does not start | Tracker port, announce key, seeder port, device route to server. |
| Download stalls | Swarm view, peer count, seeder availability, storage capacity. |
| Verification fails | Catalog hash, file name, IOS copy output, image integrity. |
| Console stale | Telemetry health, catalog service logs, device report interval. |
| Prometheus target down, dashboard blank | `IRIS_OBSERVABILITY` — unset means `/metrics` answers 404 by design; then check reachability to port 9101. |
| `403` on `:9101/swarm` | Swarm data is console-gated by design: use the console's Swarm tab, the authenticated `GET /api/swarm`, or `docker compose -f server/docker-compose.yml exec iris curl -s http://127.0.0.1:9101/swarm` (`kubectl exec` on Kubernetes). `IRIS_SWARM_PUBLIC=1` reopens remote access. |

