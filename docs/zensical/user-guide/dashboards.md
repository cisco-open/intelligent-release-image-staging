<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Import the Splunk and Grafana dashboards

## What this is for

IRIS ships three ready-made boards: two Splunk views and one Grafana board.
They show how much of an image your devices carried for each other, and how
healthy the tracker and the transfers are.

| File | Backend | What it draws |
| --- | --- | --- |
| `splunk-iris-swarm.xml` | Splunk, Simple XML view | Peer-to-peer distribution, with measured peer tracing |
| `splunk-iris-rollout.xml` | Splunk, Simple XML view | Tracker and transfer health, view `iris_rollout` |
| `grafana-iris-swarm.json` | Grafana, reading Prometheus and Loki | Peer-to-peer distribution, uid `iris-swarm-p2p` |

The files live in the repository under `docs/zensical/dashboards/`. The
addresses below are documentation addresses, so substitute your own hosts. For
live transfers without a backend, see [Monitor transfers and device
reports](monitoring.md).

## Before you start

1. Turn telemetry on. [Export telemetry](telemetry-export.md) has the settings.
2. For the Splunk views, set up the indexes, the token and the collector with
   [Send telemetry to Splunk](splunk.md).
3. For the Grafana board, let Prometheus scrape IRIS and send the log records
   to Loki, both below.

The boards say **traced** and **untraced**. Traced bytes are bytes the server
could pin to a named device. Untraced bytes were sent for certain, to a
recipient the server cannot name.

### Let Prometheus scrape the metrics endpoint

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

Check each of these before you expect data:

* `IRIS_OBSERVABILITY=1` is set. With telemetry off, `/metrics` answers 404.
* `server_name` above matches an IP address or a DNS name on the server
  certificate, checked against the catalog CA.
* The token file is mounted into Prometheus at the `credentials_file` path
  above. On Compose its host path is `IRIS_OBSERVABILITY_TOKEN_FILE_HOST`,
  readable by uid `10001`. [Export telemetry](telemetry-export.md) carries the
  host commands.
* A collector that remote-writes instead needs a `prometheusremotewrite`
  exporter. The boards read the scrape path, where the swarm byte counters are
  served.

!!! warning
    `IRIS_METRICS_PORT=0` also removes the health and swarm routes and breaks
    the server healthcheck. Use the export settings to turn off external
    telemetry instead.

Per-peer and per-device detail arrives as OTLP log records, read from the event
index in Splunk or from Loki in Grafana. [Telemetry
signals](../reference/telemetry-signals.md) lists the series and record names.

## Import the Splunk view

Both Splunk views are Simple XML. They read the `iris_metrics` metric index
with `mstats` and the `iris_logs` event index with `search` and `spath`. Rename
the indexes in the XML if your collector writes elsewhere.

In the UI, open Settings, User interface, Views, New View. Choose the app
context, paste the file as the view's XML source, and save. The `<label>` in
the file supplies the display name.

With the REST API, POST to `data/ui/views` with the XML as `eai:data`:

```bash
curl -sS -u "$SPLUNK_USER" \
  https://splunk.example.com:8089/servicesNS/nobody/search/data/ui/views \
  -d name=iris_swarm_p2p \
  --data-urlencode "eai:data@splunk-iris-swarm.xml"
```

Substitute your own app for `search` in the namespace path. To update a view
that already exists, POST to its own endpoint with only `eai:data`:

```bash
curl -sS -u "$SPLUNK_USER" \
  https://splunk.example.com:8089/servicesNS/nobody/search/data/ui/views/iris_swarm_p2p \
  --data-urlencode "eai:data@splunk-iris-swarm.xml"
```

### Update the rollout view

`splunk-iris-rollout.xml` is the `iris_rollout` view: ten tracker and
transfer-health panels plus three measured peer-capture panels. Its filters are
`form.tr.earliest`, `form.tr.latest` and `form.dev` (default `*`). The device
filter selects the receiving device in the transfer panels and the named peer
in the tracker panels, and wildcards work. Every search uses the selected
window, and the active tiles also require an observation within the last 15
minutes from now.

!!! warning
    Do not use the creation command above on an existing `iris_rollout`. Save
    the current definition and permissions first, keep the view's name, app,
    owner and sharing, and post only `eai:data` to its own endpoint. The full
    update, rollback and verification steps are in
    [the contributor dashboard notes](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/dashboards.md).

## Import the Grafana board

Every panel targets `${ds_prom}` or `${ds_loki}`, both typed `datasource`, so
Grafana fills them from the instance you import into. If your Prometheus or
Loki data source is not the default, change it from the two pickers at the top
of the board.

In the UI, open Dashboards, New, Import, then upload the JSON file or paste it
in and choose Import. Grafana asks for a folder.

With the API, `/api/dashboards/db` takes the dashboard object wrapped in a
request body of its own, not the bare file:

```bash
jq '{dashboard: ., folderUid: "", overwrite: true}' grafana-iris-swarm.json \
  | curl -sS -X POST https://grafana.example.net/api/dashboards/db \
      -H "Authorization: Bearer $GRAFANA_TOKEN" \
      -H 'Content-Type: application/json' \
      --data-binary @-
```

The first POST creates the board, and `overwrite: true` lets a later POST
update it in place under the same uid `iris-swarm-p2p`.

### Send the OTLP logs to Loki

The Loki-backed panels select the stream `{service_name="iris-tracker"}`, which
feeds the three headline delivery stats, the per-edge detail tables and the
per-device peer share. Add a Loki exporter and a logs pipeline to the collector
configuration in [Send telemetry to Splunk](splunk.md):

```yaml
exporters:
  otlphttp/loki:
    logs_endpoint: https://loki.example.com/otlp/v1/logs

service:
  pipelines:
    logs/iris_loki:
      receivers: [otlp/iris]
      processors: [filter/iris_logs, batch]
      exporters: [otlphttp/loki]
```

Use your own Loki ingest endpoint, and give the exporter the authentication and
CA it needs. Loki's OTLP ingest promotes `service.name` to the stream label
`service_name`, which the selector matches, and folds every other attribute
into structured metadata with dots turned to underscores, so the queries read
`otel_log_name`. Import the board into Grafana 11 and Loki 3.0 or newer.

## What you see

Both boards draw the same panel families from the same telemetry.

| Panel family | What it draws |
| --- | --- |
| Byte accounting | One stacked panel per image, reconciling `origin_sent = peer_attributed + peer_unattributed` |
| Swarm participation | The traced peer count against the total swarm peers, beside a 0/1 flag that says the per-torrent peer cap refused peers |
| Per-peer edges, the origin view | One row per edge from `iris.swarm.peer_bytes`, keyed on `network.peer.address` and `iris.image.id`: the sampled view from the origin seeder, the server's own copy of the image and the first source in the swarm |
| Per-device transfer records, the device view | `iris.device.peer_transfer_record`, exported for every completed transfer and split by `iris.peer.attribution` into `origin`, `device` and `unknown`: the device-measured answer to "did this device get its image from a peer or from the origin?" |
| Offload share | Peer-sourced bytes as a percentage of the image, per device and per fleet |

In that identity, the two right-hand terms read **traced to a device** and
**untraced**. The Splunk swarm view charts the device transfer records in a row
of their own, while the Grafana per-device peer share stays an origin-side
estimate.

!!! danger "Never sum the two peer record names together"
    `iris.swarm.peer_bytes` and `iris.device.peer_transfer_record` describe the
    *same bytes* from opposite ends of the wire. A query that sums both counts
    every transfer twice. Pick one name per panel, and prefer
    `iris.device.peer_transfer_record` for a number you can defend.

## What is measured and what is derived

Panel titles carry a `(measured)` or `(derived)` marker.

| Figure | Status | Where it comes from |
| --- | --- | --- |
| `iris_origin_sent_bytes_total` | **Measured** | The origin seeder's own upload counter, banked across counter resets |
| `iris.device.peer_transfer_record` byte values | **Measured** | The receiving device's own per-peer counter, read at the instant the last piece landed |
| `iris.peer.attribution` (`origin`, `device`, `unknown`) | **Derived** | A server-side join of the peer address against the device address map |
| `iris_peer_attributed_bytes_total`, the bytes traced to a device | **Measured** | Per-connection counters from aria2, the transfer client on the device, banked into the durable ledger. Sampling limits coverage, so the figure is a floor |
| `iris_peer_unattributed_bytes_total`, the untraced bytes | **Measured** | `max(0, origin sent - traced)`, arithmetic on two measurements, so it is a gauge and never takes `rate()` |
| `iris.swarm.peer_bytes` byte values | **Derived, sampled** | The origin-side estimate of an edge; the device transfer record is the exact form of the same bytes |
| Offload share percentages | **Derived** | A ratio of the figures above |

## How to read the numbers

| Reading | What it means |
| --- | --- |
| Untraced bytes, and an untraced band that steps down | Origin-side sampling is lossy: a peer connection that opens and closes between two samples takes its byte counter with it. Bytes traced late leave the band, so a step down is not a counter reset |
| A device transfer record with few peers | The device snapshots its peer list when the last piece lands, so a peer that left mid-download is already gone |
| `iris_image_size_bytes` says "no data" | The size comes from the catalog, not from traffic. The image has no catalog entry |
| An idle board still showing counters | Splunk ledger tiles select the latest cumulative sample in the chosen window, so a different window can select an older value. The Seeder RPC tile uses the fixed last 15 minutes ending now, where a zero means origin sampling is unavailable now |
| A total that looks low, or a 0% peer share | Captures are incomplete. Both Splunk views deduplicate cumulative captures and keep origin and unknown bytes in the peer-share denominator, so no captures read as unavailable and origin-only captures read as 0%. Capture totals are grouped by capture hour, not by hourly throughput |

A missing row in the device-side Splunk panels is a capture gap, not zero
traffic. [Search IRIS data in Splunk](splunk-searches.md#peer-to-peer-evidence)
runs the same evidence by hand, and its
[time-to-seed search](splunk-searches.md#assignment-to-confirmed-seeding)
measures how long a device takes to reach confirmed seeding after assignment.

## Related

* [Export telemetry](telemetry-export.md)
* [Send telemetry to Splunk](splunk.md)
* [Search IRIS data in Splunk](splunk-searches.md)
* [Monitor transfers and device reports](monitoring.md)
* [Telemetry signals](../reference/telemetry-signals.md)
