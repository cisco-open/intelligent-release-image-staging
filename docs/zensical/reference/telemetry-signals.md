<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Telemetry signals

Prometheus series, OTLP log records and their attributes, and example records. See [Monitor transfers and device reports](../user-guide/monitoring.md) for how to read them.

## Prometheus metrics

IRIS serves Prometheus on `:9101 /metrics` and exports the same values as OTLP metrics. Every family carries `{image, info_hash}` labels only; per-device and per-peer detail is in [OTLP log records](#otlp-log-records).

| Prometheus family | OTLP metric | Unit | Attributes |
| --- | --- | --- | --- |
| `iris_transfer_devices` | `iris.transfer.devices` | `{device}` | image attrs |
| `iris_transfer_throughput_bytes_per_second` | `iris.transfer.throughput` | `By/s` | image attrs + `network.io.direction` = `receive` \| `transmit` |
| `iris_transfer_progress_ratio` | `iris.transfer.progress` | `1` | image attrs |
| `iris_transfer_zero_receive_devices` | `iris.transfer.zero_receive_devices` | `{device}` | image attrs |
| `iris_transfer_freshness_age_seconds` | `iris.transfer.freshness_age` | `s` | image attrs |
| `iris_stream_devices` | `iris.stream.devices` | `{device}` | image attrs + `sampling_class` = `good` \| `constrained` |
| `iris_seeder_torrent_upload_length_bytes` | `iris.seeder.torrent.upload_length` | `By` | image attrs |
| `iris_seeder_torrent_upload_bytes_per_second` | `iris.seeder.torrent.upload_rate` | `By/s` | image attrs |
| `iris_legacy_announce_participants` | `iris.legacy.announce_participants` | `{participant}` | none |
| `iris_telemetry_samples_rejected_total` | `iris.telemetry.samples.rejected` | `{sample}` | (counter; no `_total` on the OTLP wire) |
| `iris_telemetry_export_failures_total` | `iris.telemetry.export.failures` | `{error}` | `signal` = `logs` \| `metrics` |
| `iris_telemetry_export_dropped_total` | `iris.telemetry.export.dropped` | `{record}` | `signal` = `logs` \| `metrics` |
| `iris_telemetry_export_last_success_seconds` | Prometheus only | | export health also on authenticated `/status` |
| `iris_peer_policy_revision` | `iris.peer.policy.revision` | `1` | none |
| `iris_peer_enforcement_applied_revision` | `iris.peer.enforcement.applied_revision` | `1` | none |
| `iris_peer_enforcement_desired_ips` | `iris.peer.enforcement.desired_ips` | `{ip}` | none |
| `iris_peer_enforcement_health` | `iris.peer.enforcement.health` | `1` | none |
| `iris_transfer_lifecycle_plans` | `iris.transfer.lifecycle.plans` | `{plan}` | none |
| `iris_transfer_lifecycle_plan_cap` | `iris.transfer.lifecycle.plan_cap` | `{plan}` | none |
| `iris_transfer_lifecycle_awaiting_report` | `iris.transfer.lifecycle.awaiting_report` | `{plan}` | none |
| `iris_transfer_lifecycle_unconfirmed` | `iris.transfer.lifecycle.unconfirmed` | `{event}` | none |
| `iris_transfer_lifecycle_dropped_unemitted_total` | `iris.transfer.lifecycle.dropped_unemitted` | `{plan}` | (counter) |
| `iris_transfer_lifecycle_live_evicted_total` | `iris.transfer.lifecycle.live_evicted` | `{plan}` | (counter) |
| `iris_transfer_lifecycle_retired_undelivered_total` | `iris.transfer.lifecycle.retired_undelivered` | `{event}` | (counter) |
| `iris_transfer_lifecycle_promoted_recovered_total` | `iris.transfer.lifecycle.promoted_recovered` | `{plan}` | (counter) |
| `iris_origin_sent_bytes_total` | (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_attributed_bytes_total` | (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_unattributed_bytes_total` | (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_swarm_peers_attributed` | (Prometheus only) | `{peer}` | `image`, `info_hash` |
| `iris_swarm_peers_saturated` | (Prometheus only) | `1` | `image`, `info_hash` |
| `iris_instruction_certificate_days_to_expiry`, `iris_instruction_keylist_age_days` | (Prometheus only) | `d` | none |
| `iris_instruction_roots_attested_180d` | (Prometheus only) | `{root}` | none |
| `iris_instruction_root_ceremony_overdue` | (Prometheus only) | `1` | none |
| `iris_instruction_root_quorum_degraded` | (Prometheus only) | `1` | none |

Throughput and progress are omitted for an image with no fresh device, rather than published as zero; freshness age is exported alongside. The `iris_transfer_lifecycle_*` family is omitted whole when the plan store is unreadable. The five `iris_instruction_*` families report on the two offline root keys: certificate and keylist age in days, roots attested within 180 days, and two status gauges (`root_ceremony_overdue` reads `0` on schedule, `1` due, `2` overdue). A field the server cannot read is omitted.

### Traced and untraced origin bytes

The origin seeder knows exactly how many bytes it sent; which device received them is sampled from aria2's per-connection counters.

| Series | Type | Meaning |
| --- | --- | --- |
| `iris_origin_sent_bytes_total` | counter | Bytes the origin seeder uploaded for this torrent. |
| `iris_peer_attributed_bytes_total` | counter | Of those, bytes traced to a device. |
| `iris_peer_unattributed_bytes_total` | gauge | The untraced residue: `max(0, origin - traced)`. Graph the value; never apply `rate()` to it. |
| `iris_swarm_peers_attributed` | gauge | Peer edges with a nonzero traced total right now, not an accumulation. |
| `iris_swarm_peers_saturated` | gauge | `1` when the per-torrent peer cap refused new peers. |

A peer that connects, takes bytes and disconnects between two samples is counted as untraced, not lost. Metric names use `attributed`; the matching OTLP attribute is `iris.peer.attribution`, covered under `iris.device.peer_transfer_record` below.

## OTLP log records

Terminal per-device reports, tracker lifecycle events, peer-policy operations, and measured peer rates and byte totals flow as OTLP logs. Event identity is the top-level `eventName` field. These are the `otel.log.name` values IRIS emits:

| Record name | Source | Nature |
| --- | --- | --- |
| `iris.device.transfer.report` | Device agent | Terminal per-device transfer report. |
| `iris.device.report` | Device agent | Reduced projection of the report. |
| `iris.tracker.peer` | Tracker | Tracker peer lifecycle: announce, join, leave. |
| `iris.peer.policy` | Tracker | Peer-policy revision applied and enforcement outcome. |
| `iris.swarm.peer_rate` | Server-side peer ledger | Sampled per-connection send rate. |
| `iris.transfer.lifecycle` | Tracker | Plan lifecycle: assignment recorded, seeding confirmed. |
| `iris.swarm.peer_bytes` | Server-side peer ledger | Sampled estimate of one edge's bytes. |
| `iris.device.peer_transfer_record` | Device-side completion hook | Device-measured exact bytes received from one peer. |

!!! warning "Int64 attributes ride the wire as strings"
    Byte attributes are int64 and travel as JSON strings in OTLP. A query that sums them must coerce to a number first.

!!! danger "Never sum the two peer record names together"
    `iris.swarm.peer_bytes` and `iris.device.peer_transfer_record` describe the same bytes from opposite ends of the wire, one sampled, one exact. A query that sums both counts every transfer twice. Pick one name per panel; prefer `iris.device.peer_transfer_record` where you need a number you can defend.

### `iris.device.transfer.report`

| Attribute | Meaning |
| --- | --- |
| `device.id` | The reporting device. |
| `iris.image.id` | The image the report is about. |
| `iris.transfer.id` | The transfer this report describes. |
| `iris.report.event` | The report's terminal outcome. |
| `iris.transfer.content_sha256.state` | The device's own hash check result. |
| `iris.transfer.ios_copy_verify.state` | The result of copying the file into place. |
| `iris.transfer.completed_content_bytes` | Bytes present in the staged file. |
| `iris.transfer.peers_total` | Distinct peer count, saturating at the device's 512-IP tracking cap. |
| `iris.device.observed_at` | Device-side observation time; use this for when the measurement was made. |
| `network.peer.address` | A flat string array of the observed peer addresses. |
| `iris.transfer.bytes_from_all_senders_total` | The device's own total, including the origin. |
| `iris.transfer.bytes_from_origin_total`, `iris.transfer.bytes_from_devices_total`, `iris.transfer.bytes_from_unknown_total` | The classified parts: from the origin seeder, from other devices, unattributable. |
| `iris.transfer.peer_records.rows_omitted`, `iris.transfer.bytes_from_all_senders_omitted` | Peer rows dropped at a cap, and the bytes dropped with them. |
| `iris.transfer.peer_records.capture_complete` | `false` when the peer capture itself was lossy. |
| `iris.download.started_at`, `iris.download.completed_at`, `iris.download.duration_seconds` | Elapsed download time, from the optional v2 report `download` block. |

!!! warning "The transfer record is a floor, not a census"
    The device only counts peers aria2 still has an open connection to when the last piece lands. `bytes_from_all_senders_total` is a lower bound, not an exact match for `completed_content_bytes`. A transfer with no usable snapshot carries no peer-transfer-record attributes at all.

The `iris.device.report` record is a reduced projection: `device.id`, `iris.image.id`, `iris.report.event`, `iris.transfer.peers_total`, `network.peer.address`. Use `iris.device.transfer.report` for completed bytes and verification fields; counting both counts one delivery twice.

### `iris.tracker.peer`

| Attribute | Meaning |
| --- | --- |
| `iris.principal` | Who the record is from: a device, the server's seeder, or a legacy device. |
| `iris.torrent.info_hash` | The torrent the peer joined. |
| `iris.peer.role` | The BitTorrent role: `seeder` or `leecher`. |
| `network.peer.address` | The peer's address. |
| `iris.device.role` | The peer's role membership from the loaded policy, present only for an authenticated device. Not the same vocabulary as `iris.peer.role`. |

### `iris.peer.policy`

| Attribute | Meaning |
| --- | --- |
| `iris.policy.revision` | The policy revision the operation concerns. |
| `iris.policy.action` | The action taken. |
| `iris.enforcement.state` | The enforcement outcome. |
| `iris.enforcement.applied_revision` | The revision actually applied. |
| `iris.enforcement.desired_ip_count` | How many addresses the desired state names. |

See [Roles and sharing-policy API](peer-policy-api.md) for the fields behind these attributes.

### `iris.swarm.peer_rate`

| Attribute | Meaning |
| --- | --- |
| `iris.principal` | Who the sending peer is: a device, the server's seeder, or a legacy device. |
| `iris.image.id` | The image being transferred. |
| `iris.torrent.info_hash` | The torrent. |
| `network.peer.address`, `network.peer.port` | The peer's address and port. |
| `iris.transfer.peer_send_bps` | Sampled per-connection send rate. |
| `iris.torrent.left` | Bytes the peer still needs. |
| `iris.peer.role` | `seeder` or `leecher`. |
| `iris.device.role` | The peer's role membership, present only for an authenticated device. |

### `iris.transfer.lifecycle`

A plan is the decision that one device should hold one image. It carries two ids for the life of that transfer:

| Attribute | Meaning |
| --- | --- |
| `iris.plan.id` | Identifies the decision. Stable across both events of one plan. Group on this id. |
| `iris.transfer.id` | Identifies the transfer the device performs for that plan; the device stamps the same value on its own `iris.device.transfer.report`. Join the two record families on this id. |

Two `event` values, in the order they occur:

| `event` | Meaning |
| --- | --- |
| `planned` | The assignment was recorded. Emitted once per plan. |
| `seeding_started` | The server confirmed the device holds verified content and is seeding it. Emitted at most once per plan. |

A `planned` record carries: `event`, `iris.transfer.id`, `iris.plan.id`, `iris.device.id`, `device.id` (both spellings, so either join works), `iris.image.id`, `iris.torrent.info_hash`, `iris.transfer.planned_at`. A `seeding_started` record repeats every `planned` attribute and adds `iris.transfer.seeding_started_at`, `iris.transfer.checksum_verified_at`, `iris.transfer.report_received_at`, `iris.transfer.tracker_seeder_at`, `iris.device.observed_at`, `iris.device.report_created_at` and, on a recovered promotion only, `iris.transfer.recovered_promotion`. See [Monitor transfers and device reports](../user-guide/monitoring.md) for what these events prove.

A missing value is absent, never an empty string or a default: a plan minted before its torrent existed carries no `iris.torrent.info_hash`.

#### A `planned` event

The attributes array of a `planned` record (`eventName` is `iris.transfer.lifecycle`, `severityText` is `INFO`):

```json
[
  { "key": "otel.log.name", "value": { "stringValue": "iris.transfer.lifecycle" } },
  { "key": "iris.telemetry.schema.version", "value": { "intValue": "2" } },
  { "key": "event", "value": { "stringValue": "planned" } },
  { "key": "iris.transfer.id", "value": { "stringValue": "4d1a6e0c73b94f2ea85d10c6b7f3928a" } },
  { "key": "iris.plan.id", "value": { "stringValue": "9f2c4b7a1d8e4f60b3a25c9107de4412" } },
  { "key": "iris.device.id", "value": { "stringValue": "203.0.113.3" } },
  { "key": "device.id", "value": { "stringValue": "203.0.113.3" } },
  { "key": "iris.image.id", "value": { "stringValue": "cat9k_iosxe.26.01.01" } },
  { "key": "iris.torrent.info_hash", "value": { "stringValue": "c8f4e2a1b09d7635fe1428a0d5c93b7614e0af82" } },
  { "key": "iris.transfer.planned_at", "value": { "stringValue": "2026-09-02T12:43:11.482Z" } },
  { "key": "event.id", "value": { "stringValue": "9f2c4b7a1d8e4f60b3a25c9107de4412.planned" } }
]
```

#### A `seeding_started` event

The same plan, ten minutes later. It repeats every `planned` attribute, including `iris.transfer.planned_at`, and adds:

```json
[
  { "key": "event", "value": { "stringValue": "seeding_started" } },
  { "key": "iris.transfer.seeding_started_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
  { "key": "iris.transfer.checksum_verified_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
  { "key": "iris.transfer.report_received_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
  { "key": "iris.transfer.tracker_seeder_at", "value": { "stringValue": "2026-09-02T12:48:30.905Z" } },
  { "key": "iris.device.observed_at", "value": { "doubleValue": 1788353602.0 } },
  { "key": "iris.device.report_created_at", "value": { "doubleValue": 1788353604.4 } },
  { "key": "event.id", "value": { "stringValue": "9f2c4b7a1d8e4f60b3a25c9107de4412.seeding_started" } }
]
```

`iris.transfer.planned_at`, `iris.transfer.seeding_started_at`, `iris.transfer.checksum_verified_at`, `iris.transfer.report_received_at` and `iris.transfer.tracker_seeder_at` are RFC 3339 strings with a fixed shape:

```
2026-09-02T12:43:11.482Z
```

UTC, always; exactly three fractional digits (`...:11.000Z`, never `...:11Z`); a literal `Z`, never `+00:00`. The matching Splunk pattern is `%Y-%m-%dT%H:%M:%S.%N%Z`; these are string attributes, not int64. `iris.device.observed_at` and `iris.device.report_created_at` are float epochs on the device's own clock, not RFC 3339 strings. Show them, but never subtract a server instant from one as though the clocks agreed.

### `iris.swarm.peer_bytes`

| Attribute | Meaning |
| --- | --- |
| `iris.image.id`, `iris.image.name` | The image and its catalog filename at export time. |
| `iris.torrent.info_hash` | The torrent. |
| `network.peer.address` | The peer edge this row measures. |
| `device.id`, `iris.peer.device.id`, `iris.peer.device_id` | The receiving device, and the sending device, when known. |
| `iris.peer.attribution` | `origin`, `device`, or `unknown`. |
| `iris.transfer.session_bytes_from_peer` | The sampled estimate of bytes this edge carried. |
| `iris.transfer_record.capture_complete` | `false` when the sampled capture was incomplete. |
| `iris.device.role` | The peer's role membership, present only for an authenticated device. |
| `iris.peer.tls.configured_mode`, `iris.peer.tls.runtime_mode`, `iris.peer.tls.runtime_source`, `iris.peer.tls.reported_at` | An authenticated device's own reported TLS policy, not proof of one connection's negotiated cipher. |

### `iris.device.peer_transfer_record`

Emitted once per peer per completed transfer, from a device-side completion hook reading aria2's per-peer counters when the last piece lands.

| Attribute | Meaning |
| --- | --- |
| `device.id` | The receiving device. |
| `iris.image.id`, `iris.image.name` | The image and its catalog filename. |
| `iris.transfer.id` | The transfer this row belongs to. |
| `network.peer.address`, `network.peer.port` | The peer's address and port. |
| `iris.transfer.session_bytes_from_peer`, `iris.transfer.session_bytes_to_peer` | Bytes received from, and sent to, that peer in this session. |
| `iris.peer.attribution` | `origin`, `device`, or `unknown`. |
| `iris.peer.device.id`, `iris.peer.device_id` | The sender: a device id, `origin`, or absent for an unknown sender. |
| `iris.peer.has_complete_file`, `iris.transfer_record.capture_complete` | Whether that peer already held the whole file, and whether the capture itself was lossy. |

The server classifies and pins each row's attribution once, at first export; see [Data formats and states](state-and-data.md). A row the server did not resolve stays `unknown` rather than being folded into `device`.

## The telemetry_observation payload

While a transfer is active, a device with streaming enabled embeds one `telemetry_observation` payload in its heartbeat, bounded at 8 KB. Only schema `v == 2` is accepted; a malformed field is dropped without failing the heartbeat.

| Field | Meaning |
| --- | --- |
| `v` | Payload schema version (currently `2`). |
| `obs_state` | `observed`, `not_due`, `paused`, `disabled`, `not_active`, or `rpc_unavailable`. Only `observed` carries transfer fields. |
| `observed_at` | Device-side observation time. |
| `transfer_id` / `image_id` | The transfer and the device's policy-assigned image, validated server-side. |
| `sample_seq` | Monotonic per-transfer sequence, checkpointed before the POST. |
| `sampling_class` | `good` or `constrained`. |
| `aria` | `receive_bps`, `send_bps`, `completed_content_bytes`, `total_content_bytes`, `connections`, `status`. |
| `peer_connections` | Up to 32 rows: `ip`, `port`, `send_bps`, `receive_bps`, `peer_client_name`, `progress`. Extra rows are truncated and flagged, not rejected. |

## Event identity

The device creates a `report_id`, frozen before its first POST. A retry after a crash sends the same report bytes and identifier, so the server stores it once. The exported `event.id` preserves that identity for downstream deduplication. Use the device observation timestamp for when the measurement was made, not the record's ingest timestamp. See [Monitor transfers and device reports](../user-guide/monitoring.md) for how delivery stays consistent across a restart.

## Reading `iris_legacy_announce_participants`

`iris_legacy_announce_participants` counts authenticated peers with no attributed device or seeder identity. A rotated-out seeder credential stays valid for `IRIS_SEEDER_PREV_TTL`; after that, its peer drops out of this gauge. Check `iris_tracker_announces_refused_total` and `iris_tracker_announces_refused_expired_total` alongside it, comparing changes over the same window.
