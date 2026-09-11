<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Telemetry Export

IRIS does not talk to your monitoring backend directly. It publishes two
surfaces and stops there, so the operator picks the backend: a Prometheus
exposition endpoint to scrape, and an OpenTelemetry OTLP endpoint to push to.
Everything on this page is about getting those two surfaces into Prometheus,
Splunk, Grafana, or Loki.

Telemetry is best-effort. The bounded queue can drop records while a
destination is unreachable; export health reports failures and queue drops.
Image staging continues independently of telemetry export.

## The two export paths

| Path | Transport | Direction | Carries |
| ---- | --------- | --------- | ------- |
| Prometheus scrape | `:9101/metrics`, exposition text, `iris_*` names | your collector pulls | Fleet and per-image **aggregates** |
| OTLP push | `IRIS_OTLP_ENDPOINT`, OTLP/HTTP **JSON** | IRIS pushes | Aggregates as metrics, **per-device and per-peer detail as log records** |

The split is not stylistic. `server/metrics.py:14-18` states the rule the
Prometheus renderer enforces:

> Aggregate metrics are labelled by image only (`image` + `info_hash`) to keep
> Prometheus cardinality low; per-device detail goes to the OTLP logs pipeline,
> not here.

A fleet of several hundred devices multiplied by every peer edge in a swarm
would put six figures of label combinations into a metric store that is built
for time series, not for facts. So the per-edge and per-device rows travel as
**log records**, where high cardinality is normal and free-text search is the
point.

### What each path carries

**Prometheus (aggregate only, labels `{image, info_hash}`):**

| Series | Type | Meaning |
| ------ | ---- | ------- |
| `iris_origin_sent_bytes_total` | counter | Bytes the origin seeder actually uploaded for this torrent |
| `iris_peer_attributed_bytes_total` | counter | Of those, the bytes **traced to a device** — the ledger saw the connection that carried them |
| `iris_peer_unattributed_bytes_total` | gauge | The honest residue: **untraced** — sent for certain, recipient unknown. A gauge because tracing a device late steps it **down**; graph the value, never `rate()` it |
| `iris_swarm_peers_attributed` | gauge | Peer edges the ledger currently has a nonzero traced total for — a level, not an accumulation |
| `iris_swarm_peers_saturated` | gauge | **A 0/1 flag, not a count.** `1` means the ledger's per-torrent peer cap refused new peers, so part of the untraced residue went to peers the cap turned away rather than to connections that ended between samples |

The origin and attributed **byte** series are counters, deliberately: a
finished transfer keeps its history and a panel does not blank out when the
swarm goes idle. The other three families are gauges, and `rate()`,
`increase()` and `resets()` mean nothing on any of them — the residue because
it is the difference of two counters and can decrease, the two peer families
because one is a level and the other is a flag.

!!! info "What it means to trace a byte to a device"
    The origin seeder knows **exactly** how many bytes it uploaded — that total
    is never in doubt. Naming *which device* received them is a second, harder
    question. The only way to answer it is to read aria2's per-connection byte
    counters, and a connection is visible only while it is alive. So a peer
    that connects, takes bytes and disconnects between two samples cannot be
    pinned to anyone afterwards.

    * **origin sent** — exact. Measured by the seeder's own upload counter.
    * **traced to a device** — of those bytes, the ones whose recipient can be
      named.
    * **untraced** — bytes that certainly went out to somebody, recipient
      unknown.

    Untraced bytes are uploads counted by the origin without a sampled
    recipient. This does not establish that the receiving device completed
    its download, verification, or final placement. Use that device's staging
    report for completion. A shorter sampling interval can capture more
    connections, but cannot eliminate untraced bytes.

    **Metric names use `attributed`.** The traced
    total is `iris_peer_attributed_bytes_total`; the untraced residue is
    `iris_peer_unattributed_bytes_total`; the traced-edge count is
    `iris_swarm_peers_attributed`. Boards and docs say *traced* / *untraced*,
    queries use `attributed` / `unattributed` for those quantities.

**OTLP logs (per-peer and per-device detail):**

| Record name | Source | Nature |
| ----------- | ------ | ------ |
| `iris.swarm.peer_bytes` | Server-side peer ledger | Origin-side **sampled estimate** of one edge's bytes |
| `iris.device.peer_transfer_record` | Device-side completion hook | Device-**measured exact** bytes received from one peer |
| `iris.device.transfer.report` | Device agent | **Terminal per-device transfer report.** The record every delivery panel on both boards unwraps, via `iris.transfer.completed_content_bytes`. |
| `iris.device.report` | Device agent | Summary projection of the report with a reduced attribute set. Use `iris.device.transfer.report` for completed bytes and verification fields. |
| `iris.swarm.peer_rate` | Server-side peer ledger | Sampled per-connection send rate (`iris.transfer.peer_send_bps`) |
| `iris.tracker.peer` | Tracker | Tracker peer lifecycle (announce, join, leave) |
| `iris.peer.policy` | Tracker | Peer-policy revision applied / enforcement outcome |
| `iris.transfer.lifecycle` | Tracker (server-side assignment + swarm observation) | Plan lifecycle: assignment recorded, seeding confirmed |

These eight are the `otel.log.name` values IRIS emits. Filter and group
records by these names to select the measurement you need.

Role enrichment does not add a ninth record family. When a peer is an
authenticated device, existing tracker, rate, and byte records may carry
`iris.device.role`, sourced from the loaded compiled policy membership.
`iris.peer.role` keeps its older BitTorrent meaning (`seeder` or `leecher`), so
do not group those two attributes as if they shared a vocabulary. The
`iris.peer.policy` operation record remains count-only: it carries the policy
revision/action and aggregate enforcement state/applied revision/desired IP
count, never role membership lists, raw rules, addresses, or origin-QoS option
values. The management policy view is the source for current preflight and
`pre-instructions` status.

!!! danger "Never sum the two peer record names together"
    `iris.swarm.peer_bytes` and `iris.device.peer_transfer_record` describe the *same
    bytes* from opposite ends of the wire — one badly, one exactly. They carry
    different record names for exactly this reason. A backend query that sums
    both counts every transfer twice. Pick one name per panel, and prefer
    `iris.device.peer_transfer_record` where you need a number you can defend.

Key attributes on the peer records: `iris.image.id`, `iris.image.name`,
`iris.torrent.info_hash`, `network.peer.address`, `device.id`,
`iris.peer.device.id`, `iris.peer.device_id`, `iris.peer.attribution`,
`iris.transfer.session_bytes_from_peer`,
`iris.transfer_record.capture_complete`.

`iris.peer.attribution` is `origin` | `device` | `unknown`. The origin seeder
is an ordinary BitTorrent peer of every device, so its bytes sit in a device's
peer list like any other peer's. **The device cannot tell which peer is the
origin; the server can, and does.** A row the server did not resolve stays
`unknown` rather than being folded into `device` — `unknown` is a normal
outcome (a peer that has not heartbeated, a NAT address, a non-IRIS seeder),
not an error.

On `iris.device.peer_transfer_record`, `iris.peer.device_id` names the sender
in one column: the sending device's id for a `device` row, `origin` for the
seeder's row, and absent for an `unknown` row. `iris.image.name` is the
catalog filename for `iris.image.id` at export time. The classification is
made once, when the report is first exported, and pinned in the server's
`report-attribution.json`, so the copy re-exported under the same `event.id`
after a server restart is identical to the first.

Key attributes on `iris.transfer.lifecycle`: `event` (`planned` or
`seeding_started`), `iris.plan.id` and `iris.transfer.id` (the plan's two
correlation ids, both 32 lowercase hex), `iris.device.id` **and** `device.id`
(the same value under both spellings, so either join can be written without a
coalesce), `iris.image.id`, `iris.torrent.info_hash`, and
`iris.transfer.planned_at`. The `seeding_started` event adds
`iris.transfer.seeding_started_at` together with the two observations behind
it, `iris.transfer.checksum_verified_at` (the same instant also ships under the
name that says what it is, `iris.transfer.report_received_at`) and
`iris.transfer.tracker_seeder_at`, plus the device's own clock as
`iris.device.observed_at` and `iris.device.report_created_at`, and — only on a
promotion that rebuilt a lost store row — `iris.transfer.recovered_promotion`.
Group on
`iris.plan.id`: it is stable across both events of one plan and distinct across
two plans for the same device and image. The full contract — what
`seeding_started` proves, how delivery and deduplication work, and what a
missing `seeding_started` means — is in
[Transfer lifecycle events](observability.md#transfer-lifecycle-events).

!!! warning "Int64 attributes ride the wire as strings"
    Byte attributes are int64 and therefore travel as JSON **strings** in
    OTLP. A backend query that sums them must coerce first.

!!! note "Parse lifecycle timestamps as dates"
    Do not carry the caveat above over to `iris.transfer.lifecycle`.
    `iris.transfer.planned_at`, `iris.transfer.seeding_started_at`,
    `iris.transfer.checksum_verified_at`,
    `iris.transfer.report_received_at` and
    `iris.transfer.tracker_seeder_at` are **RFC 3339 string attributes by
    construction** — UTC, exactly three fractional digits, a literal trailing
    `Z` (`2026-09-02T12:43:11.482Z`, Splunk pattern
    `%Y-%m-%dT%H:%M:%S.%N%Z`). Parse them with a time function, not a numeric
    cast.

    The lifecycle records also time differently from the device report
    records. `timeUnixNano` on a lifecycle record is the **source event
    time** — the instant the plan was minted, or the instant the last seeding
    precondition became true — never the emit time. Where the device report
    records carry server **ingest** time in `timeUnixNano` unconditionally, a
    lifecycle record carries a server *observation*; and when the attesting
    report was the later precondition, that observation is the report's own
    ingest instant, which `iris.transfer.report_received_at` names. Both
    record kinds put the device's own clock in `iris.device.observed_at`, and
    the lifecycle records add `iris.device.report_created_at` beside it. Those
    are a second clock: never subtract either from the RFC 3339 server
    instants — read them against `iris.transfer.report_received_at` to see how
    much report-delivery latency a plan-to-seed duration is carrying.

## Turning export on

To enable OTLP through the deployment defaults, set both values:

```bash
# server/.env on the IRIS host
IRIS_OBSERVABILITY=1
IRIS_OTLP_ENDPOINT=https://collector.example.com:4318
```

Configure the **base** endpoint only. IRIS appends `/v1/logs` and
`/v1/metrics` itself; putting a path in the variable produces
`/v1/logs/v1/logs`.

The Console's **Settings → Telemetry** can override both the endpoint and the
OTLP enabled flag. These settings apply within seconds without a restart.
An enabled flag and endpoint are both required. Prometheus `/metrics` is
controlled separately by `IRIS_OBSERVABILITY` at server startup; changing it
requires a restart.

The `/metrics` endpoint requires authentication. Before enabling a Prometheus scrape,
create a raw token on the IRIS host with private permissions and give Compose
its host path. Mount the identical raw value as the collector or Prometheus
`credentials_file` in the [Splunk collector configuration](splunk.md#configure-the-collector):

```bash
umask 077
mkdir -p ~/.config/iris
openssl rand -hex 32 > ~/.config/iris/observability-token
export IRIS_OBSERVABILITY_TOKEN_FILE_HOST=$HOME/.config/iris/observability-token
sudo chown 10001 "$IRIS_OBSERVABILITY_TOKEN_FILE_HOST"
printf 'IRIS_OBSERVABILITY_TOKEN_FILE_HOST=%s\n' \
  "$IRIS_OBSERVABILITY_TOKEN_FILE_HOST" >> server/.env
```

`IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST` optionally mounts the preceding
raw value during a two-token rotation window; leave it unset otherwise. These
host-side interpolation variables are distinct from `IRIS_OTLP_HEADERS_FILE`,
which authenticates IRIS's outbound push to a collector.

For an authenticated OTLP collector, create the header specification in a
private host file and give Compose its host path. The value is read without
placing it in the container environment, command arguments, or URL:

```bash
umask 077
mkdir -p ~/.config/iris
read -rsp 'OTLP Authorization header value: ' IRIS_OTLP_AUTH_VALUE; echo
printf 'Authorization=%s\n' "$IRIS_OTLP_AUTH_VALUE" > ~/.config/iris/otlp-headers
unset IRIS_OTLP_AUTH_VALUE
sudo chown 10001 ~/.config/iris/otlp-headers
printf '%s\n' \
  'IRIS_OTLP_HEADERS_FILE_HOST='"$HOME"'/.config/iris/otlp-headers' \
  >> server/.env
```

Compose mounts that file read-only at the fixed in-container
`IRIS_OTLP_HEADERS_FILE=/run/secrets/iris_otlp_headers`. The direct
`IRIS_OTLP_HEADERS="Name=Value"` environment form remains available for
non-Compose integrations, but putting a bearer token in `server/.env` is not
recommended. Header values are never logged, and IRIS refuses HTTP redirects
so they cannot leak to a redirect target. With either form present, the OTLP
endpoint must be HTTPS. IRIS validates the collector certificate using system
roots and the CAs installed under **Settings → TLS & trust → Trusted CAs**.

!!! note "Host interpolation and container variables are different"
    `IRIS_OBSERVABILITY_TOKEN_FILE_HOST`, its optional `PREVIOUS` counterpart,
    and `IRIS_OTLP_HEADERS_FILE_HOST` are host-side Compose interpolation
    variables. Compose turns them into fixed, server-only container paths; it
    does not pass the host paths into the process. See
    [How a variable reaches the container](reference.md#environment-variables).

## The collector

[Splunk Setup](splunk.md) provides a complete Collector Contrib configuration
with authenticated OTLP over HTTPS, a verified HTTPS scrape of IRIS, separate
HEC exporters for events and metrics, and connection checks. It includes both
feeds required by the shipped Splunk dashboard.

For another backend, retain the receivers and IRIS filters and select its
exporter. A Grafana/Prometheus deployment needs a Prometheus-compatible output;
a Loki deployment needs an OTLP log output. The Splunk example exports only
to HEC. The two transports do not carry identical metric families: the
`iris_origin_sent_bytes_total`, attribution, and swarm families come from the
Prometheus scrape.

## Dashboards

Two boards ship in this repository under
[`docs/zensical/dashboards/`](dashboards/README.md). They read the same telemetry from the
two different stores, so you can run either backend alone:

* **The Splunk board** reads `iris_metrics` with `mstats` and `iris_logs` with
  `spath`, and reproduces the same panel families in SPL.
* **The Grafana board** reads the Prometheus surface (aggregate series) plus
  Loki for the per-peer log records.

### Panel families

**Byte accounting.** The reconciliation identity, drawn as one stacked
panel per image:

```
origin_sent = peer_attributed + peer_unattributed
```

Sourced from `iris_origin_sent_bytes_total`,
`iris_peer_attributed_bytes_total` and `iris_peer_unattributed_bytes_total`.
On the boards the two right-hand terms read **traced to a device** and
**untraced** — the series behind them are the `attributed` and
`unattributed` families named above. Because these are counters, the panel
keeps its shape after the swarm goes idle.

**Swarm participation.** `iris_swarm_peers_attributed` against total swarm
peers, showing how much of the swarm the ledger can trace bytes to, beside
`iris_swarm_peers_saturated` — the 0/1 flag saying the per-torrent peer cap
refused peers, which is what tells a residue caused by the cap apart from one
caused by short-lived connections.

**Per-peer edges (origin view).** A table built from `iris.swarm.peer_bytes`
log records, one row per edge, keyed on `network.peer.address` and
`iris.image.id`. This is the origin's sampled view.

**Per-device transfer records (device view).**
`iris.device.peer_transfer_record` is exported for every completed transfer,
split by `iris.peer.attribution` into `origin`, `device` and `unknown`, and it
is the exact, device-measured answer to "did this device get its image from a
peer or from the origin?".

!!! warning "Neither shipped board charts it"
    `iris.device.peer_transfer_record` appears in **neither**
    `grafana-iris-swarm.json` nor `splunk-iris-swarm.xml`. Every per-device
    peer-share panel on both boards is built on `iris.swarm.peer_bytes`, the
    origin-side **sampled** estimate with 12–27% documented sampling loss. So
    the number you can read off a shipped board is the estimate; the number you
    can defend has to come from a panel you write yourself against the device
    record. Build it and you will have the better figure — the record is
    already reaching your collector.

**Offload share.** Peer-sourced bytes as a percentage of the image, per device
and per fleet.

### What is measured and what is derived

This distinction is on the boards themselves, and it matters when someone
quotes a number in a meeting.

| Figure | Status | Why |
| ------ | ------ | --- |
| `iris_origin_sent_bytes_total` | **Measured** | The origin seeder's own upload counter, banked across counter resets |
| `iris.device.peer_transfer_record` byte values | **Measured** | The receiving device's own cumulative per-peer counter, read once at the instant the last piece landed |
| `iris.peer.attribution` (`origin`/`device`/`unknown`) | **Derived** | A server-side join of peer address against the device address map — authoritative, but a join |
| `iris_peer_attributed_bytes_total` (bytes traced to a device) | **Measured** | An accumulation of aria2's own per-connection counters, banked into the durable ledger — not arithmetic. Both boards label it measured. Its *coverage* is what sampling limits: an edge that opened and closed between two polls is never banked, so this is a floor on what peers really carried, and the shortfall is published as the untraced residue rather than hidden |
| `iris_peer_unattributed_bytes_total` (untraced bytes) | **Measured** | Both boards label it measured, and it is a real published quantity rather than an error bar. It is computed as `max(0, origin sent − traced)`, so it is arithmetic on two measurements — which is exactly why it is a gauge and never `rate()`d |
| `iris.swarm.peer_bytes` byte values | **Derived (sampled)** | The origin-side estimate of an edge; the device transfer record is the exact form of the same bytes |
| Offload share percentages | **Derived** | A ratio of the above |

## Known limits

These are stated on the boards and are stated here. None of them is a bug to be
fixed by a nicer panel.

**Origin-side sampling is lossy.** aria2's `getPeers` returns only **live**
connections, and its per-peer counter is per *connection* — it disappears with
the connection. Sampling therefore misses bytes moved by peers that came and
went between samples. Measured coverage: **73.3% of origin bytes traced to a
device at 3-second sampling, 88.1% at 2-second sampling.** The gap is not
hidden; it is published as the untraced counter,
`iris_peer_unattributed_bytes_total`.

**A device transfer record is a floor, not a census.** `DefaultPeerStorage` erases a
peer on disconnect, so even the completion-instant snapshot only sees peers
still connected at that moment. Peers that disconnected mid-download leave no
trace in it. `iris.transfer_record.capture_complete = false` on the block is the
flag that says so — the individual rows are still exact either way.

**Absence of a transfer record is not zero.** A device that reported no transfer records emits
no records at all, while a genuine measured zero appears as an explicit `0`.

**`iris_image_size_bytes` is exact, not measured traffic.** It republishes the
catalog entry's own `size` field, recorded from the file itself at publish
time. A missing series means the image has no published catalog entry, and the
panels that need it read "no data" rather than guessing.

**`iris.peer.has_complete_file` does not identify the origin.** It is aria2's
`seeder` flag, true for any peer holding the complete file — which in a
seven-router wave is every device that finished early. It answers "complete vs
partial", a different question.

## Troubleshooting

### An empty board

An empty board has three distinct causes, and they are told apart by *which*
half is empty.

| What you see | Cause | Confirm with |
| ------------ | ----- | ------------ |
| Every panel empty, metrics and logs | Nothing is exporting at all | Check IRIS `/healthz` first |
| Metric panels empty, log tables populated | No scrape job, or the metrics pipeline is filtered out | `mcatalog` / Prometheus target list |
| Metric panels populated, log tables empty | No log export path, or the log filter drops everything | `otelcol_exporter_sent_log_records` |
| Counters present but flat since a past timestamp | Genuinely no traffic — no transfer has run | Widen the time range |

Work the hops cheapest first.

**1. Can the IRIS telemetry listener answer?**

```bash
curl --fail --silent --show-error \
  --cacert /secure/path/iris-catalog.pem \
  https://203.0.113.10:9101/healthz
```

`{"ok": true}` proves only that the TLS telemetry listener is answering; the
anonymous probe deliberately reveals no export or dependency details. Check
the Console's *Telemetry export* badge for `off` or `degraded`, then use the
server audit trail to distinguish a disabled destination from a collector
failure.

**2. Is the collector receiving and forwarding?**

Run this on the collector host; its diagnostic port is bound to loopback.

```bash
curl --fail --silent --show-error http://127.0.0.1:8888/metrics \
  | rg 'otelcol_(receiver_accepted|exporter_sent|exporter_send_failed)'
```

| Counter pattern | Diagnosis |
| --------------- | --------- |
| `accepted` rising, `sent` rising | Healthy |
| `accepted` rising, `sent` flat | The filter drops everything — check `service.name` and the `iris[._].*` regexp |
| `send_failed` rising | The backend is rejecting — read the collector log |
| `accepted` flat | Nothing arriving — check IRIS and the ports |

**3. Are the log records searchable?**

```
index=iris_logs earliest=-24h | stats count by sourcetype
index=iris_logs earliest=-24h "otel.log.name"="iris.device.peer_transfer_record" | stats count by "device.id"
```

The first query separates "no log export" (zero rows) from "no traffic" (rows
present, but none of them peer transfer records). Swarm events are edge-triggered, so
an idle fleet produces none — search a 7-day window before concluding it is
broken.

**4. Are the metrics searchable?**

```
| mcatalog values(metric_name) WHERE index=iris_metrics earliest=-2h
```

Expect the dotted OTLP names and the underscored scrape names side by side. If
`iris_origin_sent_bytes_total` is absent while `iris.transfer.*` is present,
you have the OTLP push but no scrape job — the aggregate peer families are
Prometheus-only.

A first real chart:

```
| mstats avg(_value) WHERE index=iris_metrics AND metric_name="iris.transfer.throughput" span=1m BY iris.image.id
```

### Other common faults

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| `unknown type: "splunk_hec"` | Core collector image | Use the contrib image |
| Collector exits naming a config key | YAML error | Read the first line of the log |
| No data at the collector | Path in `IRIS_OTLP_ENDPOINT` | Drop the `/v1/…` suffix |
| No data at the collector | Endpoint set, flag unset | Enable OTLP in Settings → Telemetry, or set `IRIS_OBSERVABILITY=1` and recreate the server |
| HEC 400 "Incorrect index" | Index missing or not in the token's allowed list | Add both indexes to the token |
| HEC TLS error | Self-signed certificate | Install the issuing CA and use a name in the certificate |
| Metrics rejected, logs fine | `iris_metrics` created as an event index | Recreate it with `datatype = metric` |
| Other tenants' series in `iris_metrics` | Filters added after the first start | Filter from day one; a metric index does not clean easily |
| Byte sums come out wrong by a factor | Both peer record names summed together | Query one record name per panel |
| Byte sums are zero or string-concatenated | int64 attributes arrive as JSON strings | Coerce to number before summing |
