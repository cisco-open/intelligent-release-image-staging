# Dashboards

Importable dashboard definitions for the peer-to-peer distribution telemetry.
They answer one question — does peer-to-peer distribution actually happen, how
much load does it carry, and among whom — and nothing else.

| File | Backend | Board title / UID |
| --- | --- | --- |
| `splunk-iris-swarm.xml` | Splunk (Simple XML view) | *IRIS — Peer-to-Peer Distribution (measured peer tracing)* |
| `grafana-iris-swarm.json` | Grafana (Prometheus + Loki) | *IRIS — Peer-to-Peer Distribution*, uid `iris-swarm-p2p` |

Both are optional. IRIS does not install, require, or talk to either backend;
it emits OpenTelemetry and serves a Prometheus text endpoint, and the operator
chooses what consumes them. Import the board that matches the stack you already
run, or neither.

The addresses in this document are RFC 5737 documentation addresses. Substitute
your own hosts.

## Prerequisite: Prometheus must scrape the IRIS metrics endpoint

**Every aggregate panel on the Grafana board is empty until Prometheus scrapes
IRIS.** This is the single most common reason an imported board looks broken.

IRIS serves the Prometheus text format at `/metrics` on port 9101:

```yaml
scrape_configs:
  - job_name: iris
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/iris-observability-token
    tls_config:
      ca_file: /etc/prometheus/secrets/iris-catalog.pem
      server_name: 203.0.113.10
    static_configs:
      - targets: ['203.0.113.10:9101']
```

Two conditions gate that endpoint:

* `IRIS_OBSERVABILITY=1` must be set. With telemetry off, `/metrics` answers
  404 while the minimal probes and management-authenticated `/swarm` keep
  running — so Prometheus reads the target as **down** and the board renders
  blank. That is telemetry being off, not a broken server. See
  [observability](../observability.md).
* `IRIS_METRICS_PORT` must not be empty or `0`, which disables the listener
  entirely.
* The scraper must present the raw observability bearer from its mounted
  `current` file and verify the TLS identity with the catalog CA. `server_name`
  above must match a certificate IP or DNS SAN.

On a Compose deployment, create that raw token with `umask 077`, export its
host path as `IRIS_OBSERVABILITY_TOKEN_FILE_HOST`, and make it readable by uid
`10001`; then mount the same file into Prometheus at the `credentials_file`
path above. The optional
`IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST` exists only for rotation. See
[Telemetry export](../telemetry-export.md#turning-export-on) for the exact host
commands.

Scraping `/metrics` directly and remote-writing it from a collector are
equally fine — the board only needs the series to reach Prometheus. If you take
the collector route, note that the `metrics/iris9101` pipeline shown in
[Telemetry export](../telemetry-export.md) exports to Splunk HEC: it must gain
a `prometheusremotewrite` exporter pointed at your Prometheus before the
aggregate panels have any data.

The board reads the **scrape leg**, not the OTLP push leg. The OTLP path renames
`image` and `info_hash` to dotted resource attributes, and the swarm byte
counters exist only in `server/metrics.py`. If a collector's `metrics/iris9101`
pipeline is removed, the aggregate panels go dark and the OTLP leg cannot
replace them.

The aggregate families the board is built on, all labelled
`{image, info_hash}` only. Two are counters and three are gauges, and the
difference decides which PromQL functions are legal on them:

```
iris_origin_sent_bytes_total        counter
iris_peer_attributed_bytes_total    counter
iris_peer_unattributed_bytes_total  GAUGE (despite the _total name)
iris_swarm_peers_attributed         GAUGE
iris_swarm_peers_saturated          GAUGE (0/1 flag)
```

The two **counters** keep their history, so a finished transfer's panels do not
blank out when the swarm goes idle, and `rate()` / `increase()` are meaningful
on them.

The three **gauges** are not cumulative and none of `rate()`, `irate()`,
`increase()`, `deriv()` or `resets()` means anything on them:

* `iris_peer_unattributed_bytes_total` keeps the historical `_total` suffix for
  dashboard compatibility but is the difference of two counters,
  `max(0, origin − traced)`. It steps **down** every time a device is traced
  late; `rate()` reads that as a counter reset and invents a burst of untraced
  bytes exactly when tracing improved. Graph the value.
* `iris_swarm_peers_attributed` is the current count of distinct peer edges the
  ledger has a nonzero traced total for on this torrent — a level, not an
  accumulation.
* `iris_swarm_peers_saturated` is a **0/1 flag**, not a count of anything: `1`
  means the ledger's per-torrent peer cap refused new peers, so part of the
  untraced residue went to peers the cap turned away rather than to connections
  that ended between samples. That distinction is the only reason the flag
  exists; reading it as "N peers stalled" points an investigation at the wrong
  cause.

**A word on `attributed`, because the boards say *traced* instead.** The origin
seeder knows exactly how many bytes it uploaded. Saying *which device* got them
means reading aria2's per-connection counters, and a connection can only be
read while it is alive — a peer that connects, takes bytes and leaves between
two samples can never be pinned to anyone. So the boards split origin sent into
bytes **traced to a device** and bytes that stay **untraced**: sent for
certain, recipient unknown. Untraced is a normal outcome, not a failure and not
a lost byte. The metric names above are unchanged —
`iris_peer_attributed_bytes_total` is the traced total,
`iris_peer_unattributed_bytes_total` is the untraced residue, and
`iris_swarm_peers_attributed` counts the edges with traced totals — so a query
you have already written keeps working while the panel above it says *traced*.

Per-peer and per-device detail is deliberately **not** in Prometheus — it would
put unbounded peer identity into label cardinality. That detail arrives as OTLP
log records and is read from the event index (Splunk) or Loki (Grafana).

## Importing the Splunk view

The view is Simple XML and expects two indexes:

| Index | Type | Sourcetype | Read with |
| --- | --- | --- | --- |
| `iris_metrics` | metric | `otel:metrics` | `\| mstats` |
| `iris_logs` | event | `otel:logs` | `search` + `spath` |

You cannot `stats` a metric index or `mstats` an event index, which is why the
panels look so different from one another. Rename the indexes in the XML if
your collector writes elsewhere.

**Via the UI** — Settings → User interface → Views → New View, choose the app
context, then paste the file contents as the view's XML source and save. The
`<label>` in the file supplies the display name.

**Via REST** — `POST` to `data/ui/views` with the XML as the `eai:data` field:

```bash
curl -sS -u "$SPLUNK_USER" \
  https://203.0.113.20:8089/servicesNS/nobody/search/data/ui/views \
  -d name=iris_swarm_p2p \
  --data-urlencode "eai:data@splunk-iris-swarm.xml"
```

Substitute your own app for `search` in the namespace path. To update an
existing view, `POST` to the view's own endpoint with just `eai:data` (no
`name=`):

```bash
curl -sS -u "$SPLUNK_USER" \
  https://203.0.113.20:8089/servicesNS/nobody/search/data/ui/views/iris_swarm_p2p \
  --data-urlencode "eai:data@splunk-iris-swarm.xml"
```

One counter-naming detail is unresolved upstream: the OTel Prometheus receiver
may or may not trim the `_total` suffix before the `splunk_hec` exporter sees
it. Rather than guess, every counter is matched with **both** spellings and
folded back with `replace(...,"_total$","")`. Confirm once against real data and
the `IN()` lists can be halved:

```
| mcatalog values(metric_name) WHERE index=iris_metrics metric_name="iris_*bytes*"
```

## Importing the Grafana board

**No UID rewriting is needed.** The board uses datasource *template variables*
rather than hardcoded datasource UIDs: every panel targets `${ds_prom}` or
`${ds_loki}`, and the two variables are typed `datasource`, so Grafana
populates them from the instance you import into and picks a default. If your
Prometheus or Loki datasource is not the default, change it from the two
pickers at the top of the board.

**Via the UI** — Dashboards → New → Import → *Upload dashboard JSON file* (or
paste the file contents) → Import. Grafana will prompt for a folder.

**Via the API** — the `/api/dashboards/db` endpoint takes the dashboard object
wrapped in an envelope, not the bare file:

```bash
jq '{dashboard: ., folderUid: "", overwrite: true}' grafana-iris-swarm.json \
  | curl -sS -X POST https://grafana.example.net/api/dashboards/db \
      -H "Authorization: Bearer $GRAFANA_TOKEN" \
      -H 'Content-Type: application/json' \
      --data-binary @-
```

The file ships with `"version": 1` and `"id"` absent, so the first POST creates
the board. `overwrite: true` lets a later POST update it in place under the same
uid `iris-swarm-p2p`.

### Prerequisite: the OTLP logs must reach Loki

**Eight panels select the Loki stream `{service_name="iris-tracker"}` — and
that includes all three headline delivery stats** (*Delivered to the fleet*,
*Delivered peer to peer*, *Peer share of delivery*), the per-edge detail
tables, and the per-device peer share. The collector chapter in
[Telemetry export](../telemetry-export.md) builds only the Splunk HEC legs, so
a Grafana-only site must add a Loki exporter and a logs pipeline of its own:

```yaml
exporters:
  otlphttp/loki:
    logs_endpoint: http://203.0.113.30:3100/otlp/v1/logs

service:
  pipelines:
    logs/iris_loki:
      receivers: [otlp]
      exporters: [otlphttp/loki]
```

Two mapping facts the board's queries depend on, both applied by Loki's own
OTLP ingest:

* `service.name` is promoted to the stream label `service_name`. IRIS sets
  `service.name = iris-tracker`, which is what the selector matches.
* Every other attribute becomes **structured metadata** with dots folded to
  underscores — `otel.log.name` → `otel_log_name`, `iris.image.id` →
  `iris_image_id`, `iris.transfer.completed_content_bytes` →
  `iris_transfer_completed_content_bytes`. That is why the queries read
  `| otel_log_name="iris.device.transfer.report"` and unwrap
  `iris_transfer_completed_content_bytes`.

Structured-metadata label filtering needs **Loki 3.0 or newer**, and the board
ships `schemaVersion: 39` with Grafana 11-era keys, so import it into
**Grafana 11 or newer**.

Without Loki those eight panels are empty while the Prometheus aggregate panels
above still work — which reads as a swarm nobody reported on rather than as a
missing ingestion leg.

## Reading the boards honestly

Panel titles carry a `(measured)` or `(derived)` marker, and each panel's
description says which of its inputs are which. Three limits are published
rather than hidden, and they explain most surprising readings:

* **Origin-side sampling is lossy, so some bytes stay untraced.** `getPeers`
  returns only *live* connections, so a peer connection that opens and closes
  between two samples takes its byte counter with it and its bytes can never be
  traced to a device. Measured coverage was 73.3% traced at 3s sampling and
  88.1% at 2s. The untraced remainder is not an error bar — it is published as
  its own counter, `iris_peer_unattributed_bytes_total`, and drawn as the
  untraced band. That band can step *down*: it is a difference of two counters,
  and bytes traced late leave it. A step down is not a counter reset.
* **Device transfer records are a floor, not a census.** The device-side
  `--on-bt-download-complete` hook snapshots `getPeers` at the completion
  instant, which is exact for peers still connected — but `DefaultPeerStorage`
  erases a peer on disconnect, so peers that left mid-download are simply gone.
* **`iris_image_size_bytes` comes from the catalog, not from traffic.** It is
  the published file's own size, recorded at publish time. The *Image size*
  panel reads "no data" only for an image with no catalog entry.

The exact and the estimated per-peer figures are kept in separate OTLP record
names on purpose — `iris.device.peer_transfer_record` (exact, device-reported) versus
`iris.swarm.peer_bytes` (sampled, origin-side estimate) — so a backend `sum`
cannot silently mix them. Do not merge the two record names in a custom panel.

The origin seeder is an ordinary BitTorrent peer of every device, so its bytes
must never be counted as peer-to-peer bytes. The device cannot tell which peer
is the origin; the server can, and classifies each edge origin / device /
unknown before the ledger banks it. That classification is why "delivered peer
to peer" is a meaningful number rather than a restatement of total traffic.

Finally, an idle board is not a broken board. The byte panels are counters and
keep their last value. On the Splunk view, if *Seeder RPC* reads 0 the board is
blind and every other panel on it is stale.
