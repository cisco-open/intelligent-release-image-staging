<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Export telemetry

## What this is for

IRIS publishes two telemetry surfaces: a Prometheus endpoint your collector
scrapes, and an OpenTelemetry Protocol (OTLP) endpoint IRIS pushes to. This
page covers metrics and observability, not proof of what staged. For that, see
[Export the audit trail off the server](../admin-guide/maintenance.md#export-the-audit-trail-off-the-server).

## The two export paths

| Path | Transport | Direction | Carries |
| ---- | --------- | --------- | ------- |
| Prometheus scrape | `:9101/metrics`, exposition text, `iris_*` names | your collector pulls | Fleet and per-image aggregates |
| OTLP push | `IRIS_OTLP_ENDPOINT`, OTLP/HTTP JSON | IRIS pushes | Aggregates as metrics, per-device and per-peer detail as log records |

[Telemetry signals](../reference/telemetry-signals.md) lists what each carries.

## Turn export on

### In the Console

1. Open **Settings → Telemetry**.
2. Set the OTLP endpoint and turn the OTLP flag on. Both are needed. The
   change applies within seconds.

### In the deployment files

Set both values on the IRIS host:

```bash
# server/.env on the IRIS host
IRIS_OBSERVABILITY=1
IRIS_OTLP_ENDPOINT=https://collector.example.com:4318
```

Use the base endpoint. IRIS appends `/v1/logs` and `/v1/metrics` itself. Then
restart the server: it reads `IRIS_OBSERVABILITY` at startup, and serves
Prometheus `/metrics` only while that variable is enabled. A Console override
wins for each field on its own, and the deployment value applies to the other.
Variable names and defaults are in
[Server configuration](../reference/server-configuration.md#telemetry-variables).

### Authenticate the Prometheus scrape

The `/metrics` endpoint requires authentication. Create the scrape token and
give Compose or Kubernetes its path first: see
[Set up certificates and tokens](../install/certificates-and-tokens.md). To
replace it, see [Rotate credentials and certificates](../admin-guide/rotations.md).

## Authenticate the push to a collector

Put the header in a private host file and give Compose its host path.

### On one Docker host

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

### On separate Docker hosts

Run the same commands on the server host, writing the last line to
`server/server.env` instead of `server/.env`. The header file stays on the
server host.

### On Kubernetes

Create the optional Secret on the server cluster:

```bash
kubectl -n iris create secret generic iris-otlp-headers \
  --from-file=headers=/secure/path/otlp-headers
```

Its `headers` key holds the same `Name=Value` header specification, separated
by commas, and only the server mounts it. To replace the value, re-apply the
Secret and restart the server Deployment. See
[Install on Kubernetes](../install/kubernetes.md).

!!! warning

    Keep the header in the file or Secret. A token in a ConfigMap, a URL, or a
    command argument is readable by anyone who can list the deployment.

With a header configured, the OTLP endpoint must be HTTPS. IRIS checks the
collector certificate against the system roots and the CAs under **Settings →
TLS & trust → Trusted CAs**, and never logs the header value.

## How IRIS decides which peer a byte came from

The origin seeder is the server's own copy of the image, the first source in
the swarm. Its upload counter is exact. Naming the device that received those
bytes takes aria2's per-connection counters, readable only while a connection
is alive. Every byte the origin sends lands in one of three buckets.

- **Origin sent.** Exact. Measured by the seeder's own upload counter.
- **Traced to a device.** The bytes whose recipient can be named.
- **Untraced.** Bytes that went out to somebody, recipient unknown.

A shorter sampling interval captures more connections. For completion,
verification and placement, read the device's own report. The metric names use
`attributed`. The traced total is `iris_peer_attributed_bytes_total`, the
untraced residue is `iris_peer_unattributed_bytes_total`, and the traced-edge
count is `iris_swarm_peers_attributed`. Boards and pages say traced and
untraced; queries use `attributed` and `unattributed` for those quantities.
IRIS records the traced total twice: the origin's sampled estimate and the
device's exact count.
[Telemetry signals](../reference/telemetry-signals.md) names both records and
warns against summing them.

A peer-assist ratio is `bytes_from_devices_total ÷ completed_content_bytes`.
Use `bytes_from_all_senders_total` as that denominator instead and every
rollout reports as roughly 100% peer-delivered, because that total already
includes the origin.

## Choosing a collector

[Send telemetry to Splunk](splunk.md#configure-the-collector) gives a full
Collector Contrib configuration: authenticated OTLP over HTTPS, a verified
HTTPS scrape of IRIS, separate exporters for events and metrics, and connection
checks. For another backend, keep the receivers and the IRIS filters and swap
the exporter. Grafana and Prometheus need a Prometheus-compatible output; Loki
needs an OTLP log output. Give the collector both feeds:
`iris_origin_sent_bytes_total`, the attribution families and the swarm families
come from the Prometheus scrape only.

## Limits

Byte-count sampling and floor-vs-census limits are covered once, in
[Byte counts are close, not exact](../architecture/limitations.md#byte-counts-are-close-not-exact).

| Limit | What it means |
| ----- | ------------- |
| Export is best effort | The record queue is a fixed size, so it drops records while a destination is unreachable. Export health reports the failures and the drops. |

## Related

- [Monitor transfers and device reports](monitoring.md)
- [Telemetry signals](../reference/telemetry-signals.md)
- [Send telemetry to Splunk](splunk.md)
- [Import the Splunk and Grafana dashboards](dashboards.md)
- [Troubleshoot: symptoms and first steps](troubleshooting.md)
