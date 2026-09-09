<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Observability

IRIS reports device staging progress, tracker participation, and transfer
measurements separately. A tracker seeder has the torrent bytes; the device's
heartbeat reports whether verification and placement have finished.

For collector configuration, Splunk indexes, and dashboard setup, see
[Splunk Setup](splunk.md). The signal contracts and measurements are described
below and in [Telemetry Export](telemetry-export.md).

## Always-on surfaces

| Surface | Purpose |
| --- | --- |
| `/healthz` and `/readyz` on port 9101 | Anonymous, non-disclosing liveness and readiness results over TLS. |
| `/swarm` on port 9101 | Machine-readable swarm and peer state for the management tier; always requires its bearer token. |
| `/status` on port 9101 | Exporter health for the management tier, protected by its bearer token. |
| Console monitoring | Human-readable network, image, and audit state. |

These stay on whenever the telemetry listener runs, regardless of the
telemetry settings below. Keep port 9101 enabled in the shipped deployment:
the server healthcheck uses it, and Compose waits for server health before
starting the Console. `IRIS_METRICS_PORT=0` removes the probes and swarm
routes and breaks that default startup. A directly launched process also
accepts an empty value to disable the listener; Compose substitutes 9101.
Use the export settings below to turn external telemetry off while retaining
local health and Console data.

## Running with telemetry off

External telemetry is opt-in. With no Console override, leaving
`IRIS_OBSERVABILITY` unset disables both the Prometheus endpoint and OTLP export.
Set it to `1` to enable `/metrics`, and configure `IRIS_OTLP_ENDPOINT` to send
OTLP to a collector. The Console's **Settings → Telemetry** can override the
OTLP endpoint and enabled flag at runtime; it does not change the Prometheus
startup setting.
[Telemetry variables](reference.md#telemetry-variables) has the exact semantics
of that variable and of `IRIS_OTLP_ENDPOINT`.

With both export paths off, `/metrics` answers 404 after authentication and
nothing is pushed to a collector. The TLS listener on port 9101
still provides minimal probes and management-authenticated `/swarm`; the
Console's swarm view, image state, device reports, and audit log are
unaffected. The startup log says which posture is in effect.

A Prometheus job left scraping `<server>:9101/metrics` in that posture therefore
reads the IRIS target as down. Enable `IRIS_OBSERVABILITY=1` and restart the
server to serve those metrics, or remove the scrape job. The Console's Swarm
tab remains available for network state.

## Role-policy status and privacy

`GET /api/v1/peer-policy` is the operator status boundary. It is deliberately
**count-only** for network enforcement: role definition/restriction/member
counts, outbox occupancy, applied revision, desired denied-address count,
conflict count/types, aggregate disconnect/removal effects, and origin-QoS
target/applied counts. It never returns the raw blocklist, peer addresses,
aria2 option dictionaries, session IDs, desired-state hashes, or the device IDs
behind the mutual-origin preflight. Role drift is the narrow exception for
repair: at most ten inventory device IDs are returned with `truncated`.

Logging and export code must not serialize an aria2 option dictionary: tracker
Authorization data can be present among those options. Closed state/error codes
and aggregate counts are the supported observability vocabulary.

Read these fields literally:

| Field | Meaning |
| --- | --- |
| `roles_supported` / `roles_present` | This management binary understands roles / role state has existed in this policy. Presence is not an enforcement-success claim. |
| `enforcement.state`, `applied_revision`, `stale` | Tracker blocklist reconciliation result and freshness. An old `enforced` value becomes stale after five minutes. |
| `enforcement.mutual_origin.mode = preflight` | Issue #153 is observation only. `newly_denied_device_count` predicts a future mutual-origin block; those devices are not added to the applied origin blocklist by this phase. |
| `origin_qos.state`, `target_download_count`, `applied_download_count` | Whether the global/per-torrent origin options reached every active origin GID. These are counts, not per-role throughput. |
| `fleet_rollup.issued_revision`, `fleet_rollup.applied` | Nullable current issued policy revision; accepted identity counts grouped by decimal policy revision, never instruction serial. Unavailable heartbeat evidence must not be inferred as zero application. |
| `fleet_rollup.states.pre-instructions` | Inventory devices whose heartbeat lacks the instruction protocol capability marker; IOS software version alone is not capability evidence. |
| `GET /api/v1/devices/<id>/effective-qos` `delivery_state = pre-instructions` | Deprecated legacy Phase 0 sentinel. The required canonical `instruction` object reports current evidence; `qos` values/sources explain compilation. |

Legacy scalar `qos` remains instruction intent. Its deprecated compatibility
sentinel `delivery_state: pre-instructions` is not a current delivery
observation. Use the response's canonical `instruction` object, the matching
Devices projection and fleet rollups for receipt evidence. An explicit
`tracker_qos` explains the selected tracker state and its sources. `tracker_qos` is tracker-only: tracker
state never enters instruction QoS/control, telemetry, semantic hashes, role artifacts,
stamps, serials, envelopes, heartbeat, or device configuration.

Swarm participant `peer_policy` facts retain the raw explicit `assignment` and
separately expose the compiled `effective_acl`, `acl_source`, compiled policy membership
as `role`, `role_unknown`, and `role_shadowed_by`. That role can differ from the
Fleet-declared role shown in Devices while `role_drift` exists. A typed device
may also carry the boolean `mutual_origin_preflight`; this is joined by
authenticated device ID,
never inferred from an address. Shared NAT conflicts report the reason and
`global_block_applied: false` without turning an aggregate count into a claim
that a particular device was blocked.

The preflight fact does not prove activation or compliance. Issue #153 remains
open through one full release of preflight observation; only a later reviewed
change may apply the union across current self-evaluation and mutual-origin
evaluation for every ACL.

## Instruction evidence and custody

**violation = 0 does not mean compliant**. Distinguish server-observed facts
(durable revocation, receipt age and server custody/stamp status), device-authored
reports (claims created on the device), and agent-asserted instruction facts
(raw state, accepted identity, verification level and QoS drift). A privileged
administrator can bypass the agent; absence of a reported violation proves
only that the available evidence contains no violation.

Tracker announce `uploaded` and `downloaded` counters are device-authored;
they are not independent server measurements.

Heartbeat `instr_protocol: 1` is the capability marker; `version` remains IOS
software. An absent protocol marker displays `pre-instructions`; a present
invalid or future marker displays `unknown`. Accepted identity is the complete
`instr_epoch`, `instr_serial`,
`instr_policy_revision` triple. `policy_revision` names server-issued intent;
`instr_serial` plus `instr_epoch` names sealed per-device freshness.
`enforcement.applied_revision` and `iris_peer_enforcement_applied_revision`
are aria2 blocklist change counters unrelated to either. Never compare them as
if they were one sequence.

Raw states are `none`, `applied`, `lkg`, `stale_expired`, `allowlist_expired`,
`rollback_rejected`, `floor_reset`, `audience_mismatch`, `key_rejected`,
`tamper_rejected`, `verifier_missing`, `lkg_rejected`, `lkg_unreadable`,
`oversize`, `reasserted`, `instr_unavailable`, `instr_pending`,
`instr_forbidden`, `tracker-only`. The server separately displays `applied`,
`lkg`, `stale`, `rejected`, `tracker-only`, `pre-instructions`, `unknown`,
`unavailable`, `pending`, `forbidden`, `floor_reset`, `none`, `revoked`.
See [failure actions](device-agents.md#instruction-failures-and-recovery).

Durable `revoked` overrides an agent's LKG claim while retaining the underlying
state and evidence. Within a supported instruction report, raw `stale_expired`
or `allowlist_expired` remains stale by agent assertion before receipt-age
classification, even when age is unknown. Other supported reports with
missing/invalid/future receipt time display unknown; an old valid receipt time
displays stale with the last reported state. `pointer_skew` reports
the existing three-observation latch, and `qos_drift_count` is a bounded count
of agent-reported corrections. `instr_stamp_missing` is a current
inventory-device count, not a lifetime error total. Applied rollups use accepted
policy revision, include retained complete identities and exclude orphan
heartbeats. Missing/corrupt heartbeat, policy, custody or revocation evidence
stays null/unknown; it must never become healthy zero. Server-generated string
labels preserve exact i63 identities in the browser.

Custody is `instruction_keys` on `/api/v1/peer-policy`. The Console shows
`enabled`, `state`, certificate days to expiry, `certificate_renewal_due`,
`signing_refused`, keylist sequence/age, `keylist_resign_due`,
`roots_configured`, `roots_attested_180d`, `root_ceremony_overdue` and
`root_quorum_degraded`. A 30-day online certificate is due for renewal at
half-life; signing refuses in its last seven days. Keylists are due for
re-signing at 90 days; ceremony warning/critical thresholds are 100/135 days.
Fewer than two roots attested in 180 days is degraded quorum. Disabled
custody reads not enabled; absent/invalid status is unavailable. Zero or negative
certificate days is meaningful evidence, not a missing field.

With metrics enabled, custody exposes
`iris_instruction_certificate_days_to_expiry`,
`iris_instruction_keylist_age_days`, `iris_instruction_roots_attested_180d`,
`iris_instruction_root_ceremony_overdue` (0 ok, 1 warn, 2 critical), and
`iris_instruction_root_quorum_degraded`. Unavailable fields are omitted rather
than fabricated as zeros. These alarms measure custody evidence; they cannot
detect the physical loss of an offline private key immediately. Use the
[quarterly ceremony](operations.md#instruction-root-ceremony-and-recovery).

## Device reports

Device reports are useful for both current status and post-incident review. Typical data includes:

| Field family | Examples |
| --- | --- |
| Identity | Device id, platform, storage target. |
| Assignment | Approved image id and current staged image. |
| Transfer | Download state, progress, peer information, seeder participation. |
| Verification | Hash checks, staged-copy byte-size confirmation, failure reason. |
| Timing | Last poll, last report, and operation duration. |

Current assignments and the latest heartbeat can differ until the next agent
poll. The Console shows an assigned image as pending until the device reports
it. For multiple images, use `staged_image_ids` and `errored_image_ids`; the
single `stage_state` describes the device's whole set. Current errors take
precedence over older staged flags. The Swarm Map labels measurements by image
and participant; an unavailable measurement is not a zero rate.

## Unattributed participants

A peer whose credential authenticates but cannot be attributed to a device or to
the seeder service is typed `legacy`. It announces normally, is answered, and is
counted in participation totals — but it carries no device identity, is never
written to the durable endpoint map, is not joined to a device row, and cannot be
quarantined individually. The swarm view marks these rows explicitly and warns
when any are present, because a quarantine action cannot reach them.

A rotated-out seeder credential announces this way too: still valid, still
serving, but unattributed until the peer moves to the current credential.

### Reading `iris_legacy_announce_participants`

`iris_legacy_announce_participants` counts authenticated peers without an
attributed device or seeder identity. An overlap token remains valid only for
`IRIS_SEEDER_PREV_TTL`; after expiry, its announces are refused and its peer no
longer appears in this gauge. A zero gauge therefore does not prove that all
peers can authenticate.

Check `iris_tracker_announces_refused_total` and
`iris_tracker_announces_refused_expired_total` alongside it. These cumulative
counters record refused announces and scrapes, including expired credentials.
Compare changes during the same observation window to identify current failures.

## Event identity

The device creates a `report_id`; the report is frozen before its first POST.
A retry after a crash sends the same report bytes and identifier, so the server
stores it once. The exported `event.id` preserves that identity for downstream
deduplication. Use the device observation timestamp for when the measurement
was made; a report's ingest timestamp describes when the server received it.

## Transfer streaming

Transfer streaming adds a live, fleet-scale view of in-flight transfers: which
devices are pulling which image, how fast, from how many peers, and on what
quality of link. It is off by default.

Live samples travel in the device heartbeat over its authenticated HTTPS
connection. See [Network ports](network-ports.md) for that connection.

### Enabling streaming

Streaming is controlled by the device conf key `telemetry_stream`
(default `off`), changed only by re-deploying the agent:

| Platform | Delivery |
| --- | --- |
| Guest Shell / router | `TELEMETRY_STREAM=on` in the installer environment, or the console's *Telemetry streaming* checkbox. |
| IOx | `IRIS_TELEMETRY_STREAM=on` at deploy time; a redeploy reconciles the persistent conf, so toggling takes effect. |
| IOS-XR appmgr | `IRIS_TELEMETRY_STREAM=on` at deploy time, or the Console checkbox; re-onboard to apply a change. |

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

The agent sends `telemetry_observation` envelopes with schema `v == 2`.
Malformed sample fields are dropped without failing the heartbeat.

### Cadence and tuning

Sampling adapts to link quality automatically:

| Tier | Cadence |
| --- | --- |
| `good` | Every tick (60 s). |
| `constrained` | Every 4th tick (~4 min). |
| `bad` | No samples (the terminal report tells the story later). |

Fleet-wide tuning without redeploys goes through the console API:
`POST /api/v1/telemetry/stream` with `{"every": <1..60>, "pause": <bool>}`
stretches the cadence (`every` multiplies the interval in ticks) or pauses
sampling entirely. Directives can only reduce volume — the hard ceiling is one
sample per device per tick, and a stale directive reverts to defaults within
three ticks.

### The add-on guarantee

Telemetry is an add-on: no telemetry condition can affect staging. Loss is
silent in operation but visible in the Console's *Telemetry export* badge and
one audit entry per state transition (`otlp-export-degraded` /
`otlp-export-recovered`). Anonymous `/healthz` deliberately exposes no export
state.

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
| `iris_telemetry_export_last_success_seconds` | — (Prometheus only; export health also available through authenticated `/status`) | | |
| `iris_peer_policy_revision` | `iris.peer.policy.revision` | `1` | — |
| `iris_peer_enforcement_applied_revision` | `iris.peer.enforcement.applied_revision` | `1` | — |
| `iris_peer_enforcement_desired_ips` | `iris.peer.enforcement.desired_ips` | `{ip}` | — |
| `iris_peer_enforcement_health` | `iris.peer.enforcement.health` | `1` | — |
| `iris_transfer_lifecycle_plans` | `iris.transfer.lifecycle.plans` | `{plan}` | — |
| `iris_transfer_lifecycle_plan_cap` | `iris.transfer.lifecycle.plan_cap` | `{plan}` | — |
| `iris_transfer_lifecycle_awaiting_report` | `iris.transfer.lifecycle.awaiting_report` | `{plan}` | — |
| `iris_transfer_lifecycle_unconfirmed` | `iris.transfer.lifecycle.unconfirmed` | `{event}` | — |
| `iris_transfer_lifecycle_dropped_unemitted_total` | `iris.transfer.lifecycle.dropped_unemitted` | `{plan}` | — (counter) |
| `iris_transfer_lifecycle_live_evicted_total` | `iris.transfer.lifecycle.live_evicted` | `{plan}` | — (counter) |
| `iris_transfer_lifecycle_retired_undelivered_total` | `iris.transfer.lifecycle.retired_undelivered` | `{event}` | — (counter) |
| `iris_transfer_lifecycle_promoted_recovered_total` | `iris.transfer.lifecycle.promoted_recovered` | `{plan}` | — (counter) |
| `iris_origin_sent_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_attributed_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_peer_unattributed_bytes_total` | — (Prometheus only) | `By` | `image`, `info_hash` |
| `iris_swarm_peers_attributed` | — (Prometheus only) | `{peer}` | `image`, `info_hash` |
| `iris_swarm_peers_saturated` | — (Prometheus only) | `1` | `image`, `info_hash` |

Throughput and progress are **omitted** for an image with no currently fresh
device rather than published as a zero, and the freshness age is exported so the
omission is explainable. The `iris_transfer_lifecycle_*` block is omitted whole
when the durable plan store is absent or unreadable, for the same reason: a
missing store is not a store with nothing in it, and a fabricated `0` would
read as "the bound never bit".

Those eight are the durable plan store's own bookkeeping, and they answer the
questions no other signal can. `plans` against `plan_cap` says whether the
store is near the hard row limit; `dropped_unemitted` and `live_evicted` are
non-zero only once it has been exceeded, which means lifecycle events are
being discarded before they ever reach the queue — raise `MAX_PLANS`.
`awaiting_report` counts plans this tracker has watched seed for which no
terminal report bearing that plan's `transfer_id` has arrived. `unconfirmed` is the export backlog: a
steady non-zero value is a collector problem, not a fleet one, and
`retired_undelivered` is where that backlog ends up if the outage outlasts the
retention window — records that were queued, never acknowledged, and are now
gone. `promoted_recovered` counts promotions that rebuilt a lost store row and
therefore replayed the durable instant rather than this tracker's own seeder
observation, which is what explains a `seeding_started_at` a backend already
holds a different value for.

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

Device- and peer-labelled measurements are exported as OTLP log records.
Aggregate metric families are listed in the table above.

### Log attributes (operator contract)

Terminal per-device reports, tracker lifecycle events, peer-policy operations and
measured peer rates and byte totals flow as OTLP logs with OpenTelemetry semantic-convention
names. Event identity is the top-level `eventName` field:
`iris.device.transfer.report` (transfer reports), `iris.device.report`
(report summary), `iris.tracker.peer` (tracker lifecycle), `iris.transfer.lifecycle`
(server-side plan lifecycle), `iris.peer.policy`,
`iris.swarm.peer_rate`, `iris.swarm.peer_bytes` (origin-side traced bytes)
and `iris.device.peer_transfer_record` (device-side exact per-peer bytes).

Key attributes per event. `iris.device.transfer.report`: `device.id`,
`iris.image.id`, `iris.transfer.id`, `iris.report.event`,
`iris.transfer.content_sha256.state`, `iris.transfer.ios_copy_verify.state`,
`iris.transfer.completed_content_bytes`, `iris.transfer.peers_total`,
`iris.device.observed_at`, and the observed peer addresses as a flat
`network.peer.address` string array. `iris.device.report` carries a subset:
`device.id`, `iris.image.id`, `iris.report.event`, `iris.transfer.peers_total`,
`network.peer.address`. `iris.tracker.peer`: `iris.principal`,
`iris.torrent.info_hash`, `iris.peer.role`, `network.peer.address`.
`iris.peer.policy`: `iris.policy.revision`, `iris.policy.action`,
`iris.enforcement.state`, `iris.enforcement.applied_revision`,
`iris.enforcement.desired_ip_count`. `iris.swarm.peer_rate`: `iris.principal`,
`iris.image.id`, `iris.torrent.info_hash`, `network.peer.address`,
`network.peer.port`, `iris.transfer.peer_send_bps`, `iris.torrent.left`,
`iris.peer.role`. `iris.transfer.lifecycle`: `event`, `iris.transfer.id`,
`iris.plan.id`, `iris.device.id`, `device.id`, `iris.image.id`,
`iris.torrent.info_hash`, `iris.transfer.planned_at`, and — on the
`seeding_started` event only — `iris.transfer.seeding_started_at`,
`iris.transfer.checksum_verified_at`, `iris.transfer.report_received_at`,
`iris.transfer.tracker_seeder_at`, `iris.device.observed_at`,
`iris.device.report_created_at` and, on a recovered promotion only,
`iris.transfer.recovered_promotion`. That record is described in full below.

Per-peer detail is carried by `iris.swarm.peer_rate` and the byte records
below. `iris.transfer.peers_total` carries the distinct peer count, saturating
at the device's 512-IP tracking cap; rows beyond the named cap are counted
there, not listed.

### Transfer lifecycle events

Every other log record on this page describes something a *device* said or
something the tracker measured on the wire. The `iris.transfer.lifecycle`
record is different: it is the **server's own account of a transfer plan**,
from the moment an operator assigned an image to the moment the server could
prove the device holds that image and is seeding it. It answers the one
question the per-device reports cannot answer on their own — *how long did it
take, from the decision to the device becoming a source for its neighbours* —
and it answers it on a single clock, because both instants are the tracker's.

A **plan** is the decision that one device should hold one image. It is minted
by the server when an image id **enters** a device's approved set, and it
carries two ids for the life of that transfer:

| Attribute | Meaning |
| --- | --- |
| `iris.plan.id` | 32 lowercase hex. Identifies the *decision*. Stable across both events of one plan, and distinct across two plans for the same device and image. **This is the key to group on.** |
| `iris.transfer.id` | 32 lowercase hex. Identifies the *transfer* the device performs for that plan, and is the same value the device stamps on its own `iris.device.transfer.report`. This is the join between the two record families. |

Re-applying an assignment that has not changed does **not** mint new ids — an
in-flight transfer keeps its identity across repeated Applies. Unassigning and
re-assigning the same image *does*, so the two attempts stay separately
measurable. See [Policy schema](reference.md#policy-schema) for where the ids
live on disk.

The record carries exactly two `event` values, in the only order they can
occur:

| `event` | Meaning |
| --- | --- |
| `planned` | The assignment was recorded. Emitted once per plan, whether or not the transfer ever completes. |
| `seeding_started` | The server has confirmed the device holds verified content **and** is announcing itself as a seeder for it. Emitted at most once per plan. |

There is deliberately no `downloading` event between them. The server has no
honest instant for one: it learns a transfer started only from the device's
next heartbeat, up to a minute later.

#### A `planned` event

```json
{
  "timeUnixNano": "1788352991482000128",
  "eventName": "iris.transfer.lifecycle",
  "severityNumber": 9,
  "severityText": "INFO",
  "body": { "stringValue": "transfer lifecycle planned" },
  "attributes": [
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
}
```

#### A `seeding_started` event

The same plan, ten minutes later. It repeats every attribute of the `planned`
record — including `iris.transfer.planned_at` — so the planned-to-seeding
duration is computable from this one record, without joining back to a
`planned` event that a bounded queue may have dropped.

```json
{
  "timeUnixNano": "1788353624117000192",
  "eventName": "iris.transfer.lifecycle",
  "severityNumber": 9,
  "severityText": "INFO",
  "body": { "stringValue": "transfer lifecycle seeding_started" },
  "attributes": [
    { "key": "otel.log.name", "value": { "stringValue": "iris.transfer.lifecycle" } },
    { "key": "iris.telemetry.schema.version", "value": { "intValue": "2" } },
    { "key": "event", "value": { "stringValue": "seeding_started" } },
    { "key": "iris.transfer.id", "value": { "stringValue": "4d1a6e0c73b94f2ea85d10c6b7f3928a" } },
    { "key": "iris.plan.id", "value": { "stringValue": "9f2c4b7a1d8e4f60b3a25c9107de4412" } },
    { "key": "iris.device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "iris.image.id", "value": { "stringValue": "cat9k_iosxe.26.01.01" } },
    { "key": "iris.torrent.info_hash", "value": { "stringValue": "c8f4e2a1b09d7635fe1428a0d5c93b7614e0af82" } },
    { "key": "iris.transfer.planned_at", "value": { "stringValue": "2026-09-02T12:43:11.482Z" } },
    { "key": "iris.transfer.seeding_started_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
    { "key": "iris.transfer.checksum_verified_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
    { "key": "iris.transfer.report_received_at", "value": { "stringValue": "2026-09-02T12:53:44.117Z" } },
    { "key": "iris.transfer.tracker_seeder_at", "value": { "stringValue": "2026-09-02T12:48:30.905Z" } },
    { "key": "iris.device.observed_at", "value": { "doubleValue": 1788353602.0 } },
    { "key": "iris.device.report_created_at", "value": { "doubleValue": 1788353604.4 } },
    { "key": "event.id", "value": { "stringValue": "9f2c4b7a1d8e4f60b3a25c9107de4412.seeding_started" } }
  ]
}
```

An attribute is **absent when the value is not known** — never defaulted, never
an empty string. A plan minted before its torrent existed carries no
`iris.torrent.info_hash`; a report whose measurement window was unusable
carries no `iris.device.observed_at`. A missing attribute is honest where a
fabricated one is not, so write queries that tolerate absence rather than
matching on a sentinel.

The device id rides **twice**, as `iris.device.id` and as `device.id`.
`iris.device.transfer.report` names it `device.id` and `iris.swarm.peer_bytes`
names it `iris.device.id`, so emitting both lets either join be written without
a coalesce. An attribute cannot be withdrawn once it has shipped, so this is a
permanent commitment, made knowingly, and not a transitional duplication.

#### The timestamp shape

`iris.transfer.planned_at`, `iris.transfer.seeding_started_at`,
`iris.transfer.checksum_verified_at`, `iris.transfer.report_received_at` and
`iris.transfer.tracker_seeder_at` are
RFC 3339 **strings** with a fixed shape, which is contract:

```
2026-09-02T12:43:11.482Z
```

* **UTC**, always — the value is formatted from `gmtime`, so re-zoning a host
  cannot change what an exported instant means.
* **Exactly three fractional digits**, always present. A whole-second instant
  is still written `...:11.000Z`, never `...:11Z`, so an extraction pattern
  never faces a missing or variable-width field.
* **A literal `Z`**, never `+00:00`. Splunk's `%Z` matches a zone *name* and
  will not consume a numeric offset.

The matching Splunk pattern is `%Y-%m-%dT%H:%M:%S.%N%Z`. These are string
attributes by construction and need **no** numeric coercion — the "int64 rides
the wire as a string" caveat that applies to the byte counters does not apply
here.

`timeUnixNano` on both records is the **source** instant — `planned_at` for
`planned`, `seeding_started_at` for `seeding_started` — never the emit instant.
For `planned` that is the server's own decision instant. For `seeding_started`
it is a server *observation*, and in the ordinary case the later of the two
preconditions is the device's report, whose instant is when the server
**received** it. So `timeUnixNano` on a `seeding_started` record can be an
ingestion time, and `iris.transfer.report_received_at` names it as one. This is
still the opposite choice from `iris.device.transfer.report`, which times off
the server's marker unconditionally because the only thing it knows for certain
about a device report is when it arrived.

`iris.device.observed_at` and `iris.device.report_created_at` are the odd
attributes out. `iris.device.transfer.report` uses the same representation:
float epochs, on the
**device's** clock, being the end of the attesting report's measurement window
and the moment that report was composed. They are a second clock. Show them,
but never subtract either from the server instants above as though the clocks
agreed.

#### What `seeding_started` proves

Three conditions must hold before a plan is promoted, and all three are
required:

1. **The content is complete on the device.** The agent reached a terminal
   report only after finding the staged file at the exact catalog size with no
   aria2 control file beside it.
2. **The checksum verified.** That same report carries
   `content_sha256.state = verified`, computed by the device over the staged
   file — and it carries **this plan's** `transfer_id`.
3. **This tracker saw the device seeding.** The device's own aria2 announced
   `left = 0` on the image's torrent, authenticated by the personalised
   announce token that resolves to that device's principal.

Conditions 1 and 2 arrive together on one report and are latched as
`iris.transfer.checksum_verified_at` — **the server's ingest instant for the
earliest attesting report**, which is when the server learned the checksum had
verified, not when the device verified it. The device reports no verification
instant, and its clock is not the server's, so nothing is back-dated to stand
in for one. `iris.transfer.report_received_at` carries the same ingest
timestamp as `iris.transfer.checksum_verified_at`.

Read it against `iris.device.report_created_at` — the device's own clock for
composing that report — to see how much **delivery latency** a plan-to-seed
duration is carrying. This is not a rounding error: the agent arms its terminal
report at completion but defers the whole send on a `bad` link tier, backing
off to about sixteen minutes, so on exactly the constrained devices IRIS exists
for the ingest instant can sit that far behind the physical one. The two are
different clocks, so their difference is that latency plus whatever skew stands
between them: treat it as a magnitude worth explaining, never as an exact
correction to subtract.

Condition 3 is latched separately as `iris.transfer.tracker_seeder_at`.

Neither fact is sufficient alone, which is why both are exported. aria2 begins
announcing `left = 0` the instant the last piece lands, while the agent's
sha256 of a ~1.2 GB image does not start until its next due staging tick and then runs for
minutes: publishing on the tracker fact alone would announce "seeding" for
content nobody has verified. Conversely the device can neither see nor attest
the tracker fact — it never talks to the tracker; only its aria2 announces. The
two attributes let an operator see **which** condition was the laggard:
`tracker_seeder_at` well before `checksum_verified_at` is the ordinary case
(the device was hashing); the reverse ordering means the swarm, not the device,
was the wait. Neither is ever earlier than `iris.transfer.planned_at`: a peer
row outlives the plan it was observed under, so a re-assignment of an image the
device is already seeding would otherwise export a `tracker_seeder_at` from the
*previous* transfer and make that comparison read as nonsense.

Each condition is latched **durably and independently** at first observation,
because neither is durable in itself: a peer row is pruned after 60 seconds,
popped outright on a `stopped` announce, and has its completion instant erased
when a re-download begins. Requiring both to be visible in the same pass would
let a vanishing peer row block the event permanently.

The per-device report ring keeps the newest five reports across all assigned
images and report kinds. IRIS also records the attestation at **ingest** in
`<state>/transfer-attestations.json`, one row per transfer. The promotion pass
reads both stores, so a terminal report rotating out of the ring does not
remove its verification evidence.

`iris.transfer.seeding_started_at` is then `max(checksum_verified_at,
tracker_seeder_at, planned_at)` — the instant the **last** condition became
true, floored at the plan's own creation so a dashboard can never render a
negative duration. All three inputs are server-clock instants from the same
container, so `seeded − planned` is a single-clock subtraction.

The one exception is a **recovered promotion**, which uses
`max(checksum_verified_at, planned_at)` and says so on the record — see
[Replays and recovered promotions](#replays-and-recovered-promotions).

It is a **server observation**, not a device-attested instant. The tracker
evaluates the conditions on its sample pass (`IRIS_SAMPLE_INTERVAL`, 15 s by
default), so the value can be up to one pass late relative to the physical
moment. It is latched once, before any record is built, and is never
recomputed — so a replay after a crash carries the original value rather than a
second, disagreeing one.

#### Delivery and stable event identity

`event.id` is derived from the plan: `<plan_id>.planned` and
`<plan_id>.seeding_started`. Retries keep the same identity, and the export
queue does not add a record whose id is already queued or in flight.

The lifecycle store records queue acceptance in `emitted` and a successful
send to the collector in `delivered`. With a destination configured, IRIS
re-queues records that lack a delivery marker if they leave the bounded
queue. A persisted delivery marker suppresses replay across server restarts.
Collector acceptance does not prove that Splunk or another final destination
has indexed the record.

A crash after a successful send but before the delivery marker is saved can
send the same record again. A failed marker write or recovered lifecycle
store can also cause duplicates. Deduplicate on `event.id`; ordinary retries
retain the latched timestamps, while a recovered promotion follows the rules
below.

Delivery is best-effort. Queue limits, lifecycle-store retention, and
collector or backend failures can lose records. Check
`iris_transfer_lifecycle_unconfirmed` for outstanding lifecycle events and
`iris_transfer_lifecycle_retired_undelivered_total` for records retired without
confirmed collector delivery. Neither a stable id nor a queue marker is an
end-to-end delivery guarantee.

Facts are latched whether or not OTLP export is switched on. Enabling a
destination publishes retained plans and their recorded start instants.

#### Replays and recovered promotions

Recovering a lost lifecycle row can produce a different timestamp under the
same `event.id`.

Of the three inputs to `seeding_started_at`, two are durable outside the
lifecycle store — `planned_at` lives in the policy record and
`checksum_verified_at` in the ingest-time attestation — and one is not.
`tracker_seeder_at` comes from the tracker's in-memory peer registry, so a
device re-announcing after a restart stamps a *fresh, later* instant. A row
rebuilt from a lost store therefore cannot reproduce an original promotion
whose instant came from the announce.

Rather than replay whatever the registry happens to say now — an unbounded
drift into the moment of the last reconnection — a promotion made on a pass
that **detected** a loss takes the durable pair only,
`max(checksum_verified_at, planned_at)`, and every later recovery reproduces
exactly that. It also sets `iris.transfer.recovered_promotion` on the record.

That flag is the honest part. If the original record's instant came from the
announce, the pre-loss value is **not recoverable**, and the replay carries an
earlier one under the same id. IRIS does not invent a value to paper over that;
it marks the record so a backend can attribute the disagreement to a recovery
instead of to a bug. On such a record:

* `iris.transfer.seeding_started_at` is a **lower bound** on the original —
  bounded below by `planned_at`, and a real server observation of that plan;
* `iris.transfer.tracker_seeder_at` is a **post-loss re-announce**, not the
  observation that produced the original promotion, so recomputing `max()` over
  the three instants on this record does not reproduce its
  `seeding_started_at`;
* a backend keeping first-write should keep the first, and this flag says which
  of two values is the replay.

The attribute is **absent**, never `false`, on an ordinary promotion, and never
appears on a `planned` record — that instant comes from the policy row and
replays identically regardless. The
`iris.transfer.lifecycle.promoted_recovered` counter is the fleet-wide total of
promotions that took this path.

#### Why there is no weaker promotion path

A plan is promoted only by a report bearing **that plan's** `transfer_id`.
There is deliberately no fallback that promotes a plan from a report carrying
some other transfer's id — accepting one would mean publishing "seeding" on the
strength of a checksum computed for a different transfer, which is the one
guarantee this event exists to make.

The agent uses the assignment's `transfer_id` in its terminal report.
`tools/apply-assignments.sh` is idempotent for an unchanged assignment.

A plan also remains unconfirmed in these cases:

* **The assignment was withdrawn while the device was still verifying.** A
  terminal report for an image no longer in the device's approved set is
  refused at ingest, so the checksum condition can never be met. The plan is
  cancelled on the next pass and shows planned-never-seeded. The bytes may well
  have landed; the server simply never received the attestation.
* **The device announces with a credential that has no device identity.** Such a
  peer is authenticated but unattributed — it resolves to a `legacy` principal
  with no device identity (see [Unattributed participants](#unattributed-participants)) — so
  it can never satisfy condition 3. This is intentional: an unattributed
  announce is not evidence about a named device.

#### Time-to-seed, as a query

```
index=iris "otel.log.name"="iris.transfer.lifecycle"
| eval planned=strptime('iris.transfer.planned_at', "%Y-%m-%dT%H:%M:%S.%N%Z"),
       seeded =strptime('iris.transfer.seeding_started_at', "%Y-%m-%dT%H:%M:%S.%N%Z")
| stats min(planned) as planned, max(seeded) as seeded
    by 'iris.transfer.id','iris.plan.id','iris.device.id','iris.image.id'
| eval seconds_to_seed = seeded - planned
```

Grouping on `iris.plan.id` is what keeps two attempts at the same
device-and-image pair from collapsing into one row. A plan that produced only a
`planned` event yields a null `seeded` — that is the planned-never-seeded
population, and it is worth alerting on directly rather than filtering away.

`seconds_to_seed` includes **report-delivery latency**, and on a constrained
link that can be minutes. Where the report was the later precondition, `seeded`
is the instant the server received it, not the instant the device finished.
Compare `iris.transfer.report_received_at` against
`iris.device.report_created_at` on the same record to see the size of it before
reading a long tail as slow transfers.

There is deliberately **no** `iris.transfer.seconds_to_seeding` attribute and
no `*_epoch` duplicates of the timestamps: `timeUnixNano` already carries the
epoch on both records, and an attribute that ships once can never be withdrawn.

### Per-peer bytes (and what they do not cover)

The device's aria2 client exposes cumulative per-peer session counters through
`aria2.getPeers` (`downloaded` and `uploaded`). IRIS exports the device capture
and the origin sampler as separate records. They describe overlapping traffic
from different observation points; do not sum the two record families.

`iris.device.peer_transfer_record` is the exact one, emitted once per peer per completed
device transfer. An `--on-bt-download-complete` hook on the device reads the
counters at the instant the last piece lands, before aria2 flips the download to
seed-only and the connections drain. Attributes: `device.id` (the *receiving*
device), `iris.image.id`, `iris.transfer.id`, `network.peer.address`,
`network.peer.port`, `iris.transfer.session_bytes_from_peer` /
`iris.transfer.session_bytes_to_peer`, `iris.peer.attribution`,
`iris.peer.device.id`, `iris.peer.has_complete_file` and
`iris.transfer_record.capture_complete`.

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

!!! warning "The transfer record is a floor, not a census"
    The hook reads only the peers aria2 still has a live connection to.
    `DefaultPeerStorage` erases a peer from `usedPeers_` the moment it
    disconnects, so a peer that fed the device 400 MB and then dropped before
    the last piece landed leaves **no row and no bytes** — its contribution is
    silently absent from every figure above, not counted as zero.
    `iris.transfer.bytes_from_all_senders_total` is therefore a lower bound on
    what the device received, and it will not reconcile with
    `iris.transfer.completed_content_bytes`. Rows the device or the server
    dropped at a cap *are* accounted for, in
    `iris.transfer.peer_records.rows_omitted` and
    `iris.transfer.bytes_from_all_senders_omitted`;
    `iris.transfer.peer_records.capture_complete` goes false when the capture
    itself was lossy. A transfer with no usable snapshot carries no peer-transfer-record
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
| Download does not start | Tracker port and authentication (Bearer header for IOx/XR, query token for Guest Shell), seeder port, device route to server. |
| Download stalls | Swarm view, peer count, seeder availability, storage capacity. |
| Verification fails | Catalog hash, file name, staged-copy byte size, image integrity. |
| Console stale | Telemetry health, catalog service logs, device report interval. |
| Prometheus target down, dashboard blank | `IRIS_OBSERVABILITY` — unset means `/metrics` answers 404 by design; then check reachability to port 9101. |
| `401` on `:9101/swarm` | Swarm data is management-tier only by design. Use the Console's Swarm tab or its authenticated `GET /api/v1/swarm`; do not expose or manually reuse the internal bearer. |
