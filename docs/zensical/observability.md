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

### Reading `iris_legacy_announce_participants`

`iris_legacy_announce_participants` only counts a `legacy` peer that is
CURRENTLY authenticating: a credential must still pass the tracker's
validity check to be counted at all. Past `IRIS_SEEDER_PREV_TTL` (the
rotated-out overlap window) a device still on the old token can no longer
authenticate, so it drops out of this gauge exactly like a fully migrated
one would — `0` here means either "fully migrated" or "every un-migrated
device just got locked out," and the gauge alone cannot tell you which.

Cross-check `iris_tracker_announces_refused_total` and, specifically,
`iris_tracker_announces_refused_expired_total`: the tracker counts every
refused `/announce` or `/scrape`, with a separate bucket for a credential
that was found and valid-shaped but simply timed out. A nonzero
`..._refused_expired_total` alongside `iris_legacy_announce_participants 0`
is the un-migrated-and-locked-out case; `0` on both is the genuinely
migrated one.

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
terminal report bearing that plan's `transfer_id` has arrived (a fleet still
running agents too old to adopt the server's plan sits there, visibly, instead
of presenting as an absence of events). `unconfirmed` is the export backlog: a
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
reports), `iris.tracker.peer` (tracker lifecycle), `iris.transfer.lifecycle`
(server-side plan lifecycle), `iris.peer.policy`,
`iris.swarm.peer_rate`, `iris.swarm.peer_bytes` (origin-side traced bytes)
and `iris.device.peer_transfer_record` (device-side exact per-peer bytes).

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
`iris.peer.role`. `iris.transfer.lifecycle`: `event`, `iris.transfer.id`,
`iris.plan.id`, `iris.device.id`, `device.id`, `iris.image.id`,
`iris.torrent.info_hash`, `iris.transfer.planned_at`, and — on the
`seeding_started` event only — `iris.transfer.seeding_started_at`,
`iris.transfer.checksum_verified_at`, `iris.transfer.report_received_at`,
`iris.transfer.tracker_seeder_at`, `iris.device.observed_at`,
`iris.device.report_created_at` and, on a recovered promotion only,
`iris.transfer.recovered_promotion`. That record is described in full below.

The attributes `device.model.identifier`, `iris.link.tier`,
`iris.transfer.throughput_avg`, `network.transport` and the structured
`iris.transfer.peers` list were retired in this release; per-peer detail now
lives in `iris.swarm.peer_rate` and the byte records described below. `iris.transfer.peers_total` still
carries the exact distinct peer count, saturating at the device's 512-IP
tracking cap; rows beyond the named cap are counted there, not listed.

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
attributes out, and are deliberately unchanged from how
`iris.device.transfer.report` already reports them: float epochs, on the
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
in for one. The same value therefore also ships as
`iris.transfer.report_received_at`, the name that says what it is; the older
name is kept because an exported attribute cannot be withdrawn.

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
sha256 of a ~1.2 GB image does not start until its next tick and then runs for
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

The attesting report is not durable in itself either. The per-device report ring
keeps only the newest five reports, shared by every image assigned to that
device and every report kind, while the tracker re-reads it once per sample
pass. A device finishing several images inside one agent tick — ten are
assignable, and a flash-tight device posts a `seeding-only` report and then a
`staging-complete` upgrade for each — pushes the earliest terminal report out of
the ring before any pass has seen it. So the attestation is recorded at
**ingest**, into `<state>/transfer-attestations.json`, one row per transfer, and
the promotion pass reads that alongside the ring. Without it such a plan latched
its seeder observation, never its checksum, and sat at `planned` with no
`seeding_started` ever emitted — silently, and for good.

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

#### Delivery: exactly once, with a stable identity

Each event is emitted **once per plan**, and the markers are on disk, so a
tracker restart does not re-emit an event that already shipped. This is
stronger than the per-device report ring, which deliberately replays after a
restart.

`event.id` is derived from the plan — `<plan_id>.planned` and
`<plan_id>.seeding_started` — never minted per emission. The two suffixes must
differ, and do: the export queue refuses a key it is already carrying, so a
shared id would make the second record vanish silently rather than fail
loudly.

The guarantee degrades to **at-least-once** in two windows: a crash between the
queue accepting a record and its marker landing on disk, and a lost or corrupt
lifecycle state file. In the first the replayed record is byte-identical —
`event.id` and every timestamp were latched before the emit — so it is a
backend-side duplicate of a record you have already seen. Deduplicate on
`event.id`.

The lifecycle state is *derived*: the plan ids live in the policy record, and
deleting `<state>/transfer-lifecycle.json` costs only the markers. Every row
rebuilds on the next pass with the same ids, and a bounded set of records is
re-emitted under those same `event.id`s.

Facts are latched whether or not OTLP export is switched on. Turning a
destination on later publishes the plans that were already in flight, rather
than losing their start instants.

#### Replays and recovered promotions

The second window is the one that can carry a *different* value under an
identical `event.id`, and it is worth understanding rather than filtering away.

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

IRIS ships a single shared on-device agent, so this change is rolled fleet-wide
with the agent bundle: a change under `device/agent/` requires a fresh Guest
Shell bundle, **both** IOx tars and `iris-xr.rpm` before device rollout. Until a
device has that bundle it mints its own transfer id and its plans emit `planned`
and never `seeding_started` — silence, not a wrong answer.

Standing assignments made before this release carry no plan at all until they
are applied once more, and emit nothing until then;
`tools/apply-assignments.sh` is idempotent for images that already carry a
plan.

Two further cases where a plan legitimately stays at `planned` forever:

* **The assignment was withdrawn while the device was still verifying.** A
  terminal report for an image no longer in the device's approved set is
  refused at ingest, so the checksum condition can never be met. The plan is
  cancelled on the next pass and shows planned-never-seeded. The bytes may well
  have landed; the server simply never received the attestation.
* **The device announces on a legacy or rotated-out seeder credential.** Such a
  peer is authenticated but unattributed — it resolves to a `legacy` principal
  with no device identity (see [Legacy participants](#legacy-participants)) — so
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

Earlier releases said per-peer byte counts were impossible, because aria2 1.37
exposed only instantaneous per-peer rates and any byte figure built from them
would be derived rather than measured. That is no longer the client we ship:
aria2-next 2.5.6 keeps a **cumulative per-peer session counter** of its own
(`aria2.getPeers` → `downloaded` / `uploaded`), so a byte total can now be read
rather than integrated. Two records carry it, and they measure different things
— never sum them together.

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
| Download does not start | Tracker port, announce key, seeder port, device route to server. |
| Download stalls | Swarm view, peer count, seeder availability, storage capacity. |
| Verification fails | Catalog hash, file name, staged-copy byte size, image integrity. |
| Console stale | Telemetry health, catalog service logs, device report interval. |
| Prometheus target down, dashboard blank | `IRIS_OBSERVABILITY` — unset means `/metrics` answers 404 by design; then check reachability to port 9101. |
| `403` on `:9101/swarm` | Swarm data is console-gated by design: use the console's Swarm tab, the authenticated `GET /api/swarm`, or `docker compose -f server/docker-compose.yml exec iris curl -s http://127.0.0.1:9101/swarm` (`kubectl exec` on Kubernetes). `IRIS_SWARM_PUBLIC=1` reopens remote access. |

