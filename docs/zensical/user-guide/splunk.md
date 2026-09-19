<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Send telemetry to Splunk

Send IRIS telemetry to Splunk Enterprise or Splunk Cloud Platform through an OpenTelemetry Collector. Every hostname, address, and path below is an example.

Two paths feed Splunk, and you set up both. IRIS pushes log records and metrics
to collector port `4318` with OTLP, the OpenTelemetry Protocol. The collector
scrapes IRIS port `9101` for the peer and origin-byte families the views read.

## Indexes and HEC token

1. In **Settings → Indexes**, create both indexes and let dashboard users
   search them.

    | Index | Data type | Source | Sourcetype |
    | --- | --- | --- | --- |
    | `iris_logs` | Events | `iris` | `otel:logs` |
    | `iris_metrics` | Metrics | `iris` | `otel:metrics` |

2. On Splunk Enterprise, open **Settings → Data inputs → HTTP Event Collector →
   Global Settings**. HEC is Splunk's HTTP Event Collector, the endpoint the
   collector writes to. Turn it on, select **Enable SSL**, set the port to
   `8088`, and leave indexer acknowledgment off. See
   [Splunk's HEC setup instructions](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/10.0/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web).
3. Install a HEC certificate whose subject alternative name matches its hostname.
4. Create an enabled token named `iris-otel`, allow both indexes, and set
   `iris_logs` as its default index.

On Splunk Cloud Platform, create the indexes and token the way your stack
supports, then use its **HEC ingest endpoint**, including `/services/collector`,
in both exporters below. Managed stacks normally use port 443; trial stacks
can use 8088.

Each token has one job: HEC writes to Splunk, the collector bearer token lets IRIS submit OTLP, and the observability token reads `/metrics`.

## Files and tokens

On the collector host, make a working directory outside the IRIS checkout for
`compose.yaml`, `otel-collector.yaml`, `secrets/`, and `tls/`. It holds:

| File on collector host | Contents |
| --- | --- |
| `tls/collector.crt`, `tls/collector.key` | Collector certificate chain and private key, valid for `collector.example.com` |
| `tls/splunk-ca.pem` | CA certificates that validate `splunk.example.com` |
| `tls/iris-catalog.pem` | IRIS server's public catalog certificate or issuing CA |
| `secrets/collector-token` | Raw bearer token accepted by the collector |
| `secrets/iris-observability-token` | Raw token configured on the IRIS server for `/metrics` |

!!! warning

    Keep `.env`, private keys, and tokens out of version control.

Get the collector and HEC certificates from your certificate authority, and
copy `artifacts/iris-catalog.pem` from IRIS over an authenticated channel. When
the HEC endpoint is already trusted by the collector's system roots, omit its
`tls.ca_file` and the matching mount instead of supplying a separate CA file.

1. Create the collector bearer token on the collector host.

    ```bash
    umask 077
    mkdir -p secrets tls
    openssl rand -hex 32 > secrets/collector-token
    ```

2. Follow [Export telemetry](telemetry-export.md) to create the IRIS
   observability token and the OTLP header file. Copy the raw token to
   `secrets/iris-observability-token`; the header file holds
   `Authorization=Bearer ` and the value in `secrets/collector-token`.
3. Give the mounted files to the account the collector runs as, user and group
   id `10001`.

    ```bash
    sudo chown -R 10001:10001 secrets tls
    sudo chmod 0700 secrets tls
    sudo chmod 0600 secrets/* tls/collector.key
    sudo chmod 0644 tls/*.crt tls/*.pem
    ```

4. Save `.env` with mode `0600`, replacing both values.

    ```dotenv
    COLLECTOR_BIND_IP=192.0.2.10
    SPLUNK_HEC_TOKEN=replace-with-your-hec-token
    ```

## Configure the collector

Run Collector Contrib, the distribution that carries `splunk_hec`. Its fields
are documented in the
[exporter reference](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.160.0/exporter/splunkhecexporter/README.md),
[bearer authentication extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.160.0/extension/bearertokenauthextension/README.md),
and [filter processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.160.0/processor/filterprocessor/README.md).

1. Save `compose.yaml`.

    ```yaml
    services:
      otel-collector:
        image: otel/opentelemetry-collector-contrib:0.160.0
        user: "10001:10001"
        restart: unless-stopped
        command: ["--config=/etc/otelcol/otel-collector.yaml"]
        environment:
          SPLUNK_HEC_TOKEN: "${SPLUNK_HEC_TOKEN:?Set SPLUNK_HEC_TOKEN}"
        volumes:
          - ./otel-collector.yaml:/etc/otelcol/otel-collector.yaml:ro
          - ./secrets:/etc/otelcol/secrets:ro
          - ./tls:/etc/otelcol/tls:ro
        ports:
          - "${COLLECTOR_BIND_IP:?Set COLLECTOR_BIND_IP}:4318:4318"
          - "127.0.0.1:8888:8888"
    ```

2. Open the paths between the hosts: the IRIS server to collector port `4318`,
   the collector to IRIS port `9101`, and the collector to your HEC port.
3. Save `otel-collector.yaml`, replacing the example hostnames. If you scrape
   `iris.example.com:9101` by an address that does not match the name on
   `iris-catalog.pem`, add `tls_config.server_name` to `prometheus/iris9101`
   and set it to the name the certificate is valid for.

    ```yaml
    extensions:
      bearertokenauth/iris:
        filename: /etc/otelcol/secrets/collector-token

    receivers:
      otlp/iris:
        protocols:
          http:
            endpoint: 0.0.0.0:4318
            tls:
              cert_file: /etc/otelcol/tls/collector.crt
              key_file: /etc/otelcol/tls/collector.key
            auth:
              authenticator: bearertokenauth/iris

      prometheus/iris9101:
        config:
          scrape_configs:
            - job_name: iris-9101
              scrape_interval: 15s
              scheme: https
              authorization:
                type: Bearer
                credentials_file: /etc/otelcol/secrets/iris-observability-token
              tls_config:
                ca_file: /etc/otelcol/tls/iris-catalog.pem
              static_configs:
                - targets: ["iris.example.com:9101"]

    processors:
      filter/iris_logs:
        error_mode: propagate
        log_conditions:
          - 'resource.attributes["service.name"] != "iris-tracker"'
      filter/iris_metrics:
        error_mode: propagate
        metric_conditions:
          - 'not IsMatch(metric.name, "^iris[._].*")'
      batch:
        send_batch_size: 512
        timeout: 5s

    exporters:
      splunk_hec/iris_logs:
        token: "${env:SPLUNK_HEC_TOKEN}"
        endpoint: https://splunk.example.com:8088/services/collector
        index: iris_logs
        source: iris
        sourcetype: otel:logs
        tls:
          ca_file: /etc/otelcol/tls/splunk-ca.pem
        retry_on_failure:
          enabled: true
        sending_queue:
          enabled: true

      splunk_hec/iris_metrics:
        token: "${env:SPLUNK_HEC_TOKEN}"
        endpoint: https://splunk.example.com:8088/services/collector
        index: iris_metrics
        source: iris
        sourcetype: otel:metrics
        tls:
          ca_file: /etc/otelcol/tls/splunk-ca.pem
        retry_on_failure:
          enabled: true
        sending_queue:
          enabled: true

    service:
      extensions: [bearertokenauth/iris]
      telemetry:
        metrics:
          level: detailed
          readers:
            - pull:
                exporter:
                  prometheus:
                    host: 0.0.0.0
                    port: 8888
      pipelines:
        logs/iris_splunk:
          receivers: [otlp/iris]
          processors: [filter/iris_logs, batch]
          exporters: [splunk_hec/iris_logs]
        metrics/iris_splunk:
          receivers: [otlp/iris]
          processors: [filter/iris_metrics, batch]
          exporters: [splunk_hec/iris_metrics]
        metrics/iris9101:
          receivers: [prometheus/iris9101]
          processors: [filter/iris_metrics, batch]
          exporters: [splunk_hec/iris_metrics]
    ```

    A filter condition names the records to **drop**. These two keep the IRIS
    logs and both metric naming styles, dotted and underscored. On a shared
    collector, merge these components into its configuration.

    The `sending_queue` above is held in memory: it does not survive the
    collector container being replaced. Use the collector's persistent queue
    support if you need that additional protection.

4. Validate the configuration and start the collector.

    ```bash
    docker compose run --rm --no-deps otel-collector validate --config=/etc/otelcol/otel-collector.yaml
    docker compose up -d otel-collector
    docker compose logs --tail 50 otel-collector
    ```

    The logs show the receiver listening and the scrape job running.

## Turn on export in IRIS

Turn OTLP export on in the server deployment file and point it at the collector base URL, as [Export telemetry](telemetry-export.md) describes.

## Verify delivery

1. On the collector host, read its own counters. Accepted and sent counts rise
   while IRIS exports.

    ```bash
    curl --fail --silent --show-error http://127.0.0.1:8888/metrics \
      | rg 'otelcol_(receiver_accepted|exporter_sent|exporter_send_failed)'
    ```

2. In Splunk, list the log records from the last day.

    ```spl
    index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
    | stats count BY "otel.log.name", "service.version"
    ```

3. In Splunk, list the metric names from the last two hours.

    ```spl
    | mcatalog values(metric_name) WHERE index=iris_metrics earliest=-2h
    ```

    Expect `iris.transfer.*` OTLP names, `iris_*` scrape names, and
    `iris_tracker_up`. Per-image byte series appear once that image has data.

## Import the views

IRIS ships the swarm view and the tracker and transfer-health view. Both read
`iris_logs` and `iris_metrics`; edit their searches if you chose other names.

1. Download [splunk-iris-swarm.xml](../dashboards/splunk-iris-swarm.xml) and
   [splunk-iris-rollout.xml](../dashboards/splunk-iris-rollout.xml).
2. Open **Settings → User interface → Views → New View**, choose the app
   context, paste the file contents as the XML source, and save.

To update a view you already imported, save its definition and permissions,
keep its name, app, owner, and sharing, and post the new XML to its own endpoint.
That keeps the saved time picker and device filter.

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The collector cannot read a file | A mount path or a file mode | Check the bind-mount paths, directory traversal permissions, and that user id `10001` can read the file. |
| Nothing arrives and IRIS shows export off | OTLP export is not enabled | Turn OTLP export on, set the base endpoint, and check for a saved Console override. |
| IRIS shows export degraded | The collector is unreachable, or its certificate does not match | Check name resolution, port `4318`, the certificate name and its CA, and the OTLP header file. |
| The collector returns `401` | The OTLP bearer token does not match the collector token file | Copy the raw value again. Do not write a second `Bearer` prefix. |
| The IRIS scrape returns `401` | The observability token on the collector is wrong | Check the raw token file on the collector and the token file the IRIS server reads. |
| The IRIS scrape returns `404` after it authenticates | The metrics endpoint is off on the server | Turn observability on and recreate the server container. |
| TLS validation fails | The issuing CA is missing, or the name does not match | Install the issuing CA and connect to a name or address in the certificate. Keep certificate verification on. |
| HEC reports an invalid token | Wrong token value, or the token is disabled | Check the token value, that it is enabled, and that you send to the right stack. |
| HEC reports an incorrect index | An index is missing or not allowed on the token | Create both indexes and allow them on the token. `iris_metrics` must be a Metrics index. |
| Log searches return rows, metric panels stay empty | The scrape path is not delivering | Check the `/metrics` scrape and the `metrics/iris9101` pipeline. OTLP metrics alone do not supply every family the views use. |

For export health, read the telemetry status in the Console and the collector
logs. For panels that read oddly, see [Troubleshoot: symptoms and first steps](troubleshooting.md).

## Related

- [Export telemetry](telemetry-export.md)
- [Search IRIS data in Splunk](splunk-searches.md)
- [Import the Splunk and Grafana dashboards](dashboards.md)
- [Monitor transfers and device reports](monitoring.md)
- [Telemetry signals](../reference/telemetry-signals.md)
