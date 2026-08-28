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
| Verification | Hash checks, staged-copy byte-size confirmation, failure reason. |
| Timing | Last poll, last report, and operation duration. |

## Legacy participants

A peer whose credential authenticates but cannot be attributed to a device or to
the seeder service is typed `legacy`. It announces normally, is answered, and is
counted in participation totals — but it carries no device identity, is never
written to the durable endpoint map, is not joined to a device row, and cannot be
quarantined individually. The swarm view marks these rows explicitly and warns
when any are present, because a quarantine action cannot reach them.

A rotated-out seeder credential announces this way too: still valid, still
serving, but unattributed until the peer moves to the current credential.

## Event identity

Telemetry reports carry their own identity. A v2 device report is minted with a
`report_id` on the device and frozen before the first POST, so a retry after a
crash sends the byte-identical report and the server stores it once.

Legacy **v1** telemetry has no device-supplied identifier. Its event id is
**stamped at ingest** by the server on receipt, so v1 records are still
deduplicable downstream — but the id reflects when the hub received the event,
not when the device observed it. Do not read a v1 event id as device-side
evidence, and do not compare it with a v2 `report_id` as though they were minted
the same way.

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

While a transfer is active the agent embeds one `telemetry_observation` envelope
in its heartbeat, bounded server-side at 8 KB:

| Field | Meaning |
| --- | --- |
| `v` | Envelope schema version (currently `2`). |
| `obs_state` | `observed`, `not_due`, `paused`, `disabled`, `not_active`, or `rpc_unavailable`. Only `observed` carries transfer fields; the rest are state-only. |
| `observed_at` | Device-side observation time. |
| `transfer_id` / `image_id` | The transfer and the device's policy-assigned image (validated server-side). |
| `sample_seq` | Monotonic per-transfer sequence, checkpointed before the POST. |
| `sampling_class` | `good` or `constrained`. |
| `aria` | `receive_bps`, `send_bps`, `completed_content_bytes`, `total_content_bytes`, `connections`, `status`. |
| `peer_connections` | Up to 32 rows: `ip`, `port`, `send_bps`, `receive_bps`, `peer_client_name`, `progress`. Extra rows are truncated and flagged, not rejected. |

The sample is transport-independent by design — it rides inside the heartbeat
only because that is the current carrier — and carries an explicit schema
version (`v`). Two versions are accepted today: the current agent sends only
`v == 2` `telemetry_observation` envelopes, and `v == 1` `sample` objects are
still accepted from agents that predate the bump (`phase`, `done_bytes`,
`down_bps`/`up_bps`, `peers`, `tier`). Anything else is dropped the same way any
other malformed field is dropped, silently and without ever failing the
heartbeat.

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
collector and route it to whichever OTLP backend you run. These names
are contract:

| Prometheus family (`:9101`) | OTLP metric | Unit | Attributes |
| --- | --- | --- | --- |
| `iris_transfer_devices` | `iris.transfer.devices` | `{device}` | image attrs |
| `iris_transfer_throughput_bytes_per_second` | `iris.transfer.throughput` | `By/s` | image attrs + `network.io.direction` = `receive` \| `transmit` |
| `iris_transfer_progress_ratio` | `iris.transfer.progress` | `1` | image attrs |
| `iris_transfer_zero_receive_devices` | `iris.transfer.zero_receive_devices` | `{device}` | image attrs |
| `iris_transfer_freshness_age_seconds` | `iris.transfer.freshness_age` | `s` | image attrs |
| `iris_stream_devices` | `iris.stream.devices` | `{device}` | image attrs + `sampling_class` = `good` \| `constrained` |
| `iris_seeder_torrent_upload_length_bytes` | `iris.seeder.torrent.upload_length` | `By` | image attrs |
| `iris_seeder_torrent_upload_bytes_per_second` | `iris.seeder.torrent.upload_rate` | `By/s` | image attrs |
| `iris_legacy_announce_participants` | `iris.legacy.announce_participants` | `{participant}` | — |
| `iris_telemetry_samples_rejected_total` | `iris.telemetry.samples.rejected` | `{sample}` | — (counter; no `_total` on the OTLP wire) |
| `iris_telemetry_export_failures_total` | `iris.telemetry.export.failures` | `{error}` | `signal` = `logs` \| `metrics` |
| `iris_telemetry_export_dropped_total` | `iris.telemetry.export.dropped` | `{record}` | `signal` = `logs` \| `metrics` |
| `iris_telemetry_export_last_success_seconds` | — (Prometheus + `/healthz` only) | | |
| `iris_peer_policy_revision` | `iris.peer.policy.revision` | `1` | — |
| `iris_peer_enforcement_applied_revision` | `iris.peer.enforcement.applied_revision` | `1` | — |
| `iris_peer_enforcement_desired_ips` | `iris.peer.enforcement.desired_ips` | `{ip}` | — |
| `iris_peer_enforcement_health` | `iris.peer.enforcement.health` | `1` | — |
| `iris_origin_sent_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_attributed_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_unattributed_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_swarm_peers_attributed` | — (Prometheus only) | `{peer}` | `image`, `info_hash` |
| `iris_swarm_peers_saturated` | — (Prometheus only) | `1` | `image`, `info_hash` |

Throughput and progress are **omitted** for an image with no currently fresh
device rather than published as a zero, and the freshness age is exported so the
omission is explainable.

!!! note "Which throughput number to trust"
    `iris.transfer.throughput` is reported **by the devices**, and a device
    samples once per 60-second agent tick. A transfer that finishes inside one
    tick is therefore never observed: the reading is a truthful instantaneous
    zero taken outside the transfer, not a broken metric. On a fast fabric a
    1 GB image lands in well under a minute, so expect this to read zero there.

    `iris.seeder.torrent.upload_rate` is measured by the **origin's own** aria2
    poll, independent of any device tick, so it does see a short transfer. It is
    a **lower bound** on total swarm throughput: device-to-device reseed traffic
    never passes through the origin and is invisible to it.

!!! warning "Metric names changed in 2026.08.22"
    Several transfer metric families were retired and others renamed in this
    release, and the OTLP names moved with them. The table above is the current
    contract; dashboards and alerts built against an earlier release need
    updating. The release entry in `CHANGELOG.md` lists the exact before-and-after.

`IRIS_OTLP_DEVICE_METRICS` is still accepted so an existing deployment starts,
but it no longer exports anything. The per-device gauges it used to enable were
retired; device- and peer-labelled history now lives only in the OTLP log
records, where it does not multiply metric cardinality.

### Log attributes (operator contract)

Terminal per-device reports, tracker lifecycle events, peer-policy operations and
measured peer rates and byte totals flow as OTLP logs with OpenTelemetry semantic-convention
names. Event identity is the top-level `eventName` field:
`iris.device.transfer.report` (v2 reports), `iris.device.report` (legacy v1
reports), `iris.tracker.peer` (tracker lifecycle), `iris.peer.policy`,
`iris.swarm.peer_rate`, `iris.swarm.peer_bytes` (origin-side traced bytes)
and `iris.device.peer_receipt` (device-side exact per-peer bytes).

Key attributes per event. `iris.device.transfer.report`: `device.id`,
`iris.image.id`, `iris.transfer.id`, `iris.report.event`,
`iris.transfer.content_sha256.state`, `iris.transfer.ios_copy_verify.state`,
`iris.transfer.completed_content_bytes`, `iris.transfer.peers_total`,
`iris.device.observed_at`, and the observed peer addresses as a flat
`network.peer.address` string array. `iris.device.report` (v1) carries a subset:
`device.id`, `iris.image.id`, `iris.report.event`, `iris.transfer.peers_total`,
`network.peer.address`. `iris.tracker.peer`: `iris.principal`,
`iris.torrent.info_hash`, `iris.peer.role`, `network.peer.address`.
`iris.peer.policy`: `iris.policy.revision`, `iris.policy.action`,
`iris.enforcement.state`, `iris.enforcement.applied_revision`,
`iris.enforcement.desired_ip_count`. `iris.swarm.peer_rate`: `iris.principal`,
`iris.image.id`, `iris.torrent.info_hash`, `network.peer.address`,
`network.peer.port`, `iris.transfer.peer_send_bps`, `iris.torrent.left`,
`iris.peer.role`.

The attributes `device.model.identifier`, `iris.link.tier`,
`iris.transfer.throughput_avg`, `network.transport` and the structured
`iris.transfer.peers` list were retired in this release; per-peer detail now
lives in `iris.swarm.peer_rate` and the byte records described below. `iris.transfer.peers_total` still
carries the exact distinct peer count, saturating at the device's 512-IP
tracking cap; rows beyond the named cap are counted there, not listed.

### Per-peer bytes (and what they do not cover)

Earlier releases said per-peer byte counts were impossible, because aria2 1.37
exposed only instantaneous per-peer rates and any byte figure built from them
would be derived rather than measured. That is no longer the client we ship:
aria2-next 2.5.6 keeps a **cumulative per-peer session counter** of its own
(`aria2.getPeers` → `downloaded` / `uploaded`), so a byte total can now be read
rather than integrated. Two records carry it, and they measure different things
— never sum them together.

`iris.device.peer_receipt` is the exact one, emitted once per peer per completed
device transfer. An `--on-bt-download-complete` hook on the device reads the
counters at the instant the last piece lands, before aria2 flips the download to
seed-only and the connections drain. Attributes: `device.id` (the *receiving*
device), `iris.image.id`, `iris.transfer.id`, `network.peer.address`,
`network.peer.port`, `iris.transfer.session_bytes_from_peer` /
`iris.transfer.session_bytes_to_peer`, `iris.peer.attribution`,
`iris.peer.device.id`, `iris.peer.has_complete_file` and
`iris.receipt.capture_complete`.

`iris.peer.attribution` is the attribute that makes the number mean anything.
The origin seeder is an ordinary BitTorrent peer of every device, so it appears
in the device's own peer list like any other sender; the device cannot tell it
apart and does not try. The server classifies each row at ingest against the
tracker's `service:seeder` principal and its own device-address map, into
`origin`, `device`, or `unknown` — an address that resolves to neither is
reported as unknown, never folded into the device figure. The per-transfer
rollups on `iris.device.transfer.report` follow the same split:
`iris.transfer.bytes_from_all_senders_total` is the device's own honest total
**including the origin**, and `iris.transfer.bytes_from_origin_total`,
`iris.transfer.bytes_from_devices_total` and
`iris.transfer.bytes_from_unknown_total` are the classified parts. A peer-assist
ratio is `bytes_from_devices_total ÷ completed_content_bytes` — using
`bytes_from_all_senders_total` there would report every rollout as ~100%
peer-delivered.

`iris.swarm.peer_bytes` is the origin-side counterpart, and it is an estimate.
The origin polls `aria2.getPeers` on an interval and banks each edge's growth in
a durable ledger, because that counter is per *connection* and vanishes with the
connection. On a 7-router pull a 3-second poll traced 73.3% of the bytes to a device the
origin actually sent, a 2-second poll 88.1%; the residue is connections that
opened and closed between two polls. It is kept as its own quantity
(`iris_peer_unattributed_bytes_total`) and never spread across the peers — an
even split would be arithmetic presented as observation.

!!! warning "The receipt is a floor, not a census"
    The hook reads only the peers aria2 still has a live connection to.
    `DefaultPeerStorage` erases a peer from `usedPeers_` the moment it
    disconnects, so a peer that fed the device 400 MB and then dropped before
    the last piece landed leaves **no row and no bytes** — its contribution is
    silently absent from every figure above, not counted as zero.
    `iris.transfer.bytes_from_all_senders_total` is therefore a lower bound on
    what the device received, and it will not reconcile with
    `iris.transfer.completed_content_bytes`. Rows the device or the server
    dropped at a cap *are* accounted for, in
    `iris.transfer.peer_receipts.rows_omitted` and
    `iris.transfer.bytes_from_all_senders_omitted`;
    `iris.transfer.peer_receipts.capture_complete` goes false when the capture
    itself was lossy. A transfer with no usable snapshot carries no peer-receipt
    attributes at all rather than a zeroed set.

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

Scale-out telemetry ingestion is on the roadmap; see
[The live sample](#the-live-sample) for the schema's current version gate and
what a future bump will require.

## Failure interpretation

| Symptom | First place to look |
| --- | --- |
| Device never appears | Installer output, artifact server reachability, catalog trustpoint, enrollment token expiry. |
| Download does not start | Tracker port, announce key, seeder port, device route to server. |
| Download stalls | Swarm view, peer count, seeder availability, storage capacity. |
| Verification fails | Catalog hash, file name, staged-copy byte size, image integrity. |
| Console stale | Telemetry health, catalog service logs, device report interval. |
| Prometheus target down, dashboard blank | `IRIS_OBSERVABILITY` — unset means `/metrics` answers 404 by design; then check reachability to port 9101. |
| `403` on `:9101/swarm` | Swarm data is console-gated by design: use the console's Swarm tab, the authenticated `GET /api/swarm`, or `docker compose -f server/docker-compose.yml exec iris curl -s http://127.0.0.1:9101/swarm` (`kubectl exec` on Kubernetes). `IRIS_SWARM_PUBLIC=1` reopens remote access. |

