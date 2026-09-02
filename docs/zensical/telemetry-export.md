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

Telemetry is best-effort and silent. A bounded queue drops the oldest records
when the destination is unreachable. **Export loss can never affect image
staging.**

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
| `iris_peer_unattributed_bytes_total` | counter | The honest residue: **untraced** — sent for certain, recipient unknown |
| `iris_swarm_peers_attributed` | gauge | Peer edges the ledger currently has traced totals for |
| `iris_swarm_peers_saturated` | gauge | Peers whose banked total stopped advancing |

These are **counters**, deliberately. A finished transfer keeps its history and
a panel does not blank out when the swarm goes idle.

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

    Untraced bytes are not lost bytes and not an error: they arrived, and the
    transfer completed. It only means nobody was watching that particular
    connection at the moment it moved them. A shorter sampling interval leaves
    fewer of them; nothing removes them entirely.

    **The metric names are unchanged and still say `attributed`.** The traced
    total is `iris_peer_attributed_bytes_total`; the untraced residue is
    `iris_peer_unattributed_bytes_total`; the traced-edge count is
    `iris_swarm_peers_attributed`. Boards and docs say *traced* / *untraced*,
    queries say `attributed` / `unattributed` — same quantities, and existing
    queries keep working.

**OTLP logs (per-peer and per-device detail):**

| Record name | Source | Nature |
| ----------- | ------ | ------ |
| `iris.swarm.peer_bytes` | Server-side peer ledger | Origin-side **sampled estimate** of one edge's bytes |
| `iris.device.peer_transfer_record` | Device-side completion hook | Device-**measured exact** bytes received from one peer |
| `iris.device.report` | Device agent | Terminal per-device transfer report |
| `iris.transfer.lifecycle` | Tracker (server-side assignment + swarm observation) | Plan lifecycle: assignment recorded, seeding confirmed |
| `iris.swarm.start` / `.complete` / `.stop` / `.stale` | Server | Swarm lifecycle events |

!!! danger "Never sum the two peer record names together"
    `iris.swarm.peer_bytes` and `iris.device.peer_transfer_record` describe the *same
    bytes* from opposite ends of the wire — one badly, one exactly. They carry
    different record names for exactly this reason. A backend query that sums
    both counts every transfer twice. Pick one name per panel, and prefer
    `iris.device.peer_transfer_record` where you need a number you can defend.

Key attributes on the peer records: `iris.image.id`, `iris.torrent.info_hash`,
`network.peer.address`, `device.id`, `iris.peer.device.id`,
`iris.peer.attribution`, `iris.transfer.session_bytes_from_peer`,
`iris.transfer_record.capture_complete`.

`iris.peer.attribution` is `origin` | `device` | `unknown`. The origin seeder
is an ordinary BitTorrent peer of every device, so its bytes sit in a device's
peer list like any other peer's. **The device cannot tell which peer is the
origin; the server can, and does.** A row the server did not resolve stays
`unknown` rather than being folded into `device` — `unknown` is a normal
outcome (a peer that has not heartbeated, a NAT address, a non-IRIS seeder),
not an error.

Key attributes on `iris.transfer.lifecycle`: `event` (`planned` or
`seeding_started`), `iris.plan.id` and `iris.transfer.id` (the plan's two
correlation ids, both 32 lowercase hex), `iris.device.id` **and** `device.id`
(the same value under both spellings, so either join can be written without a
coalesce), `iris.image.id`, `iris.torrent.info_hash`, and
`iris.transfer.planned_at`. The `seeding_started` event adds
`iris.transfer.seeding_started_at` together with the two observations behind
it, `iris.transfer.checksum_verified_at` and `iris.transfer.tracker_seeder_at`,
plus the device's own clock as `iris.device.observed_at`. Group on
`iris.plan.id`: it is stable across both events of one plan and distinct across
two plans for the same device and image. The full contract — what
`seeding_started` proves, the exactly-once delivery guarantee, and what a
missing `seeding_started` means during an agent rollout — is in
[Transfer lifecycle events](observability.md#transfer-lifecycle-events).

!!! warning "Int64 attributes ride the wire as strings"
    Byte attributes are int64 and therefore travel as JSON **strings** in
    OTLP. A backend query that sums them must coerce first.

!!! note "The lifecycle timestamps are strings already, and need no coercion"
    Do not carry the caveat above over to `iris.transfer.lifecycle`.
    `iris.transfer.planned_at`, `iris.transfer.seeding_started_at`,
    `iris.transfer.checksum_verified_at` and
    `iris.transfer.tracker_seeder_at` are **RFC 3339 string attributes by
    construction** — UTC, exactly three fractional digits, a literal trailing
    `Z` (`2026-09-02T12:43:11.482Z`, Splunk pattern
    `%Y-%m-%dT%H:%M:%S.%N%Z`). Parse them with a time function, not a numeric
    cast.

    The lifecycle records also time differently from the device report
    records. `timeUnixNano` on a lifecycle record is the **source event
    time** — the instant the plan was minted, or the instant the last seeding
    precondition became true — never the emit or ingest time. The device report records
    carry server **ingest** time in `timeUnixNano` and put the device's own
    clock in `iris.device.observed_at`; the lifecycle records carry that
    attribute too, on `seeding_started`, with the same meaning and the same
    float-epoch shape. It is a second clock: never subtract it from the RFC
    3339 server instants.

## Turning export on

Both lines are required — an endpoint alone is inert.

```bash
# server/.env on the IRIS host
IRIS_OBSERVABILITY=1
IRIS_OTLP_ENDPOINT=http://203.0.113.10:4318
```

Configure the **base** endpoint only. IRIS appends `/v1/logs` and
`/v1/metrics` itself; putting a path in the variable produces
`/v1/logs/v1/logs`.

The endpoint can also be set at runtime from the console under
*Settings → Telemetry*, which wins over the env and applies within seconds
with no restart. `IRIS_OBSERVABILITY` still needs a restart, because it also
gates the `:9101/metrics` surface at startup.

For an authenticated collector, add
`IRIS_OTLP_HEADERS="Authorization=Bearer <token>"` or
`IRIS_OTLP_HEADERS_FILE=/path` for a secret mount. Those values are never
logged, and IRIS refuses HTTP redirects so a header cannot leak to a redirect
target.

## The collector

### Use the contrib build

The core `otel/opentelemetry-collector` image does **not** contain the
`splunk_hec` exporter. Use `otel/opentelemetry-collector-contrib`. The error
`unknown type: "splunk_hec"` at startup means the wrong image.

Bind the published ports to a specific host address rather than `0.0.0.0`, and
supply the HEC token from the container environment, never from the YAML:

```yaml
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.159.0
    environment:
      - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
    restart: unless-stopped
    command: ["--config", "/etc/otelcol-contrib/config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro
    ports:
      - "203.0.113.10:4317:4317"   # OTLP gRPC
      - "203.0.113.10:4318:4318"   # OTLP HTTP  <- IRIS uses this one
      - "203.0.113.10:8888:8888"   # collector's own metrics
```

Keep the file holding `SPLUNK_HEC_TOKEN` out of version control.

### Ports

| From | To | Port | Purpose |
| ---- | -- | ---- | ------- |
| IRIS server | Collector | 4318/tcp | OTLP push — required |
| Collector | Splunk | 8088/tcp | HEC delivery — required |
| Admin host | Collector | 8888/tcp | Collector health — optional |
| Collector | IRIS server | 9101/tcp | Prometheus scrape — optional |

### Receivers

A stock OTLP receiver accepts IRIS as-is. There is no JSON-specific setting and
no per-sender configuration.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
```

The `0.0.0.0` here is *inside* the container; the port binding above is what
limits exposure.

To also pull the Prometheus surface — a belt-and-braces path, so the
underscored families survive an OTLP metric outage:

```yaml
  prometheus/iris9101:
    config:
      scrape_configs:
        - job_name: iris-9101
          scrape_interval: 15s
          static_configs:
            - targets: ["203.0.113.10:9101"]
```

### Filter to IRIS only

Skip this **only** on a collector dedicated to IRIS. On a shared collector,
other tenants' data must not be shipped to your IRIS indexes.

```yaml
processors:
  filter/iris_metrics:
    metrics:
      include:
        match_type: regexp
        metric_names:
          - "iris[._].*"          # matches iris.transfer.* AND iris_swarm_*

  filter/iris_logs:
    logs:
      include:
        match_type: strict
        resource_attributes:
          - key: service.name
            value: iris-tracker

  batch:
    send_batch_size: 512
    timeout: 5s
```

* Metrics filter **by name**, because both styles exist: dotted
  `iris.transfer.*` from the OTLP push, underscored `iris_*` from the scrape.
  The `[._]` character class catches both.
* Logs filter **by resource attribute** — every IRIS record carries
  `service.name = iris-tracker`, `service.namespace = iris`, and
  `service.version = <repo VERSION>`.
* `batch` is not optional in practice. Without it you make one backend call per
  record.

!!! warning "Filter from day one"
    A shared collector wired up without these filters will put other tenants'
    series into your metric index permanently — Splunk does not retro-clean a
    metric index easily. Add the filters before the first start, not after the
    first surprise.

Inside a pipeline, order matters: filter **first**, then batch.

## Splunk: indexes, naming, and the HEC path

Do the Splunk side **before** starting the collector, or the first exports
bounce with HTTP 400 "Incorrect index".

### Index and sourcetype naming

The two indexes are **not** the same kind of index. Metrics sent to an event
index are rejected — this is the single most common mistake.

| Index | Splunk type | Holds | `source` | `sourcetype` |
| ----- | ----------- | ----- | -------- | ------------ |
| `iris_logs` | Events | Peer transfer records, per-device reports, swarm events | `iris` | `otel:logs` |
| `iris_metrics` | **Metrics** (`datatype = metric`) | Numeric aggregate time series | `iris` | `otel:metrics` |

```ini
[iris_logs]
coldPath = $SPLUNK_DB/iris_logs/colddb
homePath = $SPLUNK_DB/iris_logs/db
thawedPath = $SPLUNK_DB/iris_logs/thaweddb

[iris_metrics]
coldPath = $SPLUNK_DB/iris_metrics/colddb
datatype = metric
homePath = $SPLUNK_DB/iris_metrics/db
thawedPath = $SPLUNK_DB/iris_metrics/thaweddb
```

`datatype = metric` is the line that makes it a metric index. Restart Splunk
after editing the file by hand.

### HEC token

Fresh installs ship with HEC globally **disabled**, so enabling it under
*Settings → Data inputs → HTTP Event Collector → Global Settings* (All Tokens
enabled, SSL on, port 8088) is a required step, not a default.

Create one token whose **allowed indexes list contains both** `iris_logs` and
`iris_metrics`. If only one is allowed, the metrics exporter is rejected while
the logs exporter keeps working — a confusing half-failure. Let the source type
be automatic; the collector sets it per event.

### HEC exporters

One exporter per index, because logs and metrics go to different index types.

```yaml
exporters:
  splunk_hec/iris_logs:
    token: "${env:SPLUNK_HEC_TOKEN}"
    endpoint: "https://203.0.113.20:8088/services/collector"
    index: "iris_logs"
    source: "iris"
    sourcetype: "otel:logs"
    tls:
      insecure_skip_verify: true      # only for a self-signed HEC cert
    retry_on_failure:
      enabled: true
    sending_queue:
      enabled: true

  splunk_hec/iris_metrics:
    token: "${env:SPLUNK_HEC_TOKEN}"
    endpoint: "https://203.0.113.20:8088/services/collector"
    index: "iris_metrics"
    source: "iris"
    sourcetype: "otel:metrics"
    tls:
      insecure_skip_verify: true
    retry_on_failure:
      enabled: true
    sending_queue:
      enabled: true
```

* `endpoint` must be the full `https://host:8088/services/collector` path — the
  host alone gives 404s, and HEC has SSL on by default.
* `${env:VAR}` reads the container environment. Never inline the token.
* `index` overrides the token's default, per exporter.
* `insecure_skip_verify` is for a self-signed HEC certificate only. **In
  production, install the real CA and drop the line.**
* `retry_on_failure` and `sending_queue` ride out a backend restart instead of
  dropping data on the floor.

### Pipelines

Add the IRIS pipelines **alongside** whatever the collector already runs; one
receiver can feed any number of pipelines.

```yaml
service:
  pipelines:
    logs/iris_splunk:
      receivers: [otlp]
      processors: [filter/iris_logs, batch]
      exporters: [splunk_hec/iris_logs]
    metrics/iris_splunk:
      receivers: [otlp]
      processors: [filter/iris_metrics, batch]
      exporters: [splunk_hec/iris_metrics]
    metrics/iris9101:
      receivers: [prometheus/iris9101]
      processors: [filter/iris_metrics, batch]
      exporters: [splunk_hec/iris_metrics]
```

A clean start logs `Everything is ready. Begin running and processing data.`
A config error exits immediately; the first error line names the offending key.

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
**untraced** — the series behind them are still the `attributed` and
`unattributed` families named above. Because these are counters, the panel
keeps its shape after the swarm goes idle.

**Swarm participation.** `iris_swarm_peers_attributed` and
`iris_swarm_peers_saturated` against total swarm peers, showing how much of the
swarm the ledger can trace bytes to and how many edges have stopped
advancing.

**Per-peer edges (origin view).** A table built from `iris.swarm.peer_bytes`
log records, one row per edge, keyed on `network.peer.address` and
`iris.image.id`. This is the origin's sampled view.

**Per-device transfer records (device view).** A table built from
`iris.device.peer_transfer_record`, split by `iris.peer.attribution` into `origin`,
`device` and `unknown`. This is the panel family that answers "did this device
get its image from a peer or from the origin?" — and the one to quote.

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
| `iris_peer_attributed_bytes_total` (bytes traced to a device) | **Derived (sampled)** | Sum of per-edge deltas observed by periodic `getPeers` sampling; lossy by construction |
| `iris_peer_unattributed_bytes_total` (untraced bytes) | **Derived** | Origin sent minus traced. A real published quantity, not an error bar |
| `iris.swarm.peer_bytes` byte values | **Derived (sampled)** | The origin-side estimate of an edge; the device transfer record is the exact form of the same bytes |
| Offload share percentages | **Derived** | A ratio of the above |

Measured lab behaviour on real hardware, for calibration: a cold four-router
swarm staging a 928 MiB image reconciled exactly —
origin sent 3,492,982,720 B = 3,227,913,693 B traced to devices (92.4%) +
265,069,027 B untraced (7.6%). Device transfer records on that run showed
**two routers took zero bytes from the origin**, and one pulled from a peer
that was itself still downloading. An earlier seven-router run had the origin
serve 71.1% of bytes and peers 28.9%, with per-device peer share ranging
18.7%–55.9%.

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

**1. Is IRIS exporting?**

```bash
curl -s http://203.0.113.10:9101/healthz
```

Look for `"otlp_export": {"state": "ok", ...}`. `off` means the enable flag or
endpoint is missing; `degraded` means IRIS is trying and the collector is not
answering.

**2. Is the collector receiving and forwarding?**

```bash
curl -s http://203.0.113.10:8888/metrics \
  | grep -E 'otelcol_(receiver_accepted|exporter_sent|exporter_send_failed)'
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
index=iris_logs earliest=-24h "iris.device.peer_transfer_record" | stats count by device.id
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
| No data at the collector | Endpoint set, flag unset | Set `IRIS_OBSERVABILITY=1` and restart |
| HEC 400 "Incorrect index" | Index missing or not in the token's allowed list | Add both indexes to the token |
| HEC TLS error | Self-signed certificate | Install the real CA, or set `insecure_skip_verify` for a lab |
| Metrics rejected, logs fine | `iris_metrics` created as an event index | Recreate it with `datatype = metric` |
| Other tenants' series in `iris_metrics` | Filters added after the first start | Filter from day one; a metric index does not clean easily |
| Byte sums come out wrong by a factor | Both peer record names summed together | Query one record name per panel |
| Byte sums are zero or string-concatenated | int64 attributes arrive as JSON strings | Coerce to number before summing |
