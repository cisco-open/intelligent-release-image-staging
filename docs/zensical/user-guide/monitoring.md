<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Monitor transfers and device reports

IRIS tracks staging progress, swarm membership, and transfer speed: this
page shows where to read each one.

## What is always available

| Surface | What it gives you |
| --- | --- |
| `/healthz` and `/readyz` on port 9101 | Anonymous liveness and readiness over TLS. |
| `/swarm` on port 9101 | Swarm and peer state, behind its bearer token. |
| `/status` on port 9101 | Exporter health, behind its bearer token. |
| Console monitoring | Network, image and audit state, for a person to read. |

!!! warning

    Keep port 9101 enabled: disabling it (`IRIS_METRICS_PORT=0`) breaks
    Console startup, which waits on server health here.

With `IRIS_OBSERVABILITY` unset, `/metrics` answers 404; the surfaces above
still work. Set `IRIS_OBSERVABILITY=1` and restart to fix a Prometheus job
scraping `<server>:9101/metrics`, or drop the scrape job. See
[Export telemetry](telemetry-export.md).

## In the Console

| Where | What it shows |
| --- | --- |
| **Swarm** tab | Which peers announce for each image; marks the peers it cannot name. |
| Device page | That device's reports: staging state and checksum result. See [Assign images and check staging status](assignments.md). |
| **Telemetry export** badge | Whether export to a collector is healthy, with `otlp-export-degraded` and `otlp-export-recovered` in the audit log. |

## Peers the swarm view cannot name

A peer whose credential authenticates but ties to no device and no seeder
service is typed `legacy`; the swarm view marks the row. It announces, is
answered, and counts toward participation. Quarantine stops a device from
sharing with every peer; it cannot target this row alone. A rotated-out
seeder credential announces the same way until it moves to the current
credential. Read that counter beside the two refusal counters in
[Telemetry signals](../reference/telemetry-signals.md).

## Turn on and tune live transfer samples

Transfer streaming shows which devices pull which image, how fast, and from
how many peers. It is off by default, set by `telemetry_stream`. See
[Supported devices and platforms](../install/supported-devices.md) for which
path your platform uses.

| Platform | How you set it |
| --- | --- |
| Guest Shell / router | `TELEMETRY_STREAM=on` at install, or the Console's *Telemetry streaming* checkbox. |
| IOx | `IRIS_TELEMETRY_STREAM=on` at deploy time. |
| IOS-XR appmgr | `IRIS_TELEMETRY_STREAM=on` at deploy time, or the Console checkbox; re-onboard to apply. |

Only `on`, `1`, `true` or `yes` turns streaming on. See
[Add and onboard devices](onboarding.md). A tick is one pass of the agent's
check-in loop; sampling follows link quality:

| Link quality | Cadence |
| --- | --- |
| `good` | Every tick (60 s). |
| `constrained` | Every 4th tick (~4 min). |
| `bad` | No samples. |

Call `POST /api/v1/telemetry/stream` with `{"every": <1..60>, "pause":
<bool>}` to change the rate fleet-wide; `pause` stops sampling. See
[Console API](../reference/console-api.md).

## Metrics to know

| Metric | What it means |
| --- | --- |
| `iris.transfer.throughput` | From the devices, sampled at the cadence above. A transfer that finishes inside one 60 s tick reads a truthful zero, taken outside the window; read `iris.seeder.torrent.upload_rate` for a lower-bound signal that is not tick-limited. |
| `iris.seeder.torrent.upload_rate` | The origin's own aria2 poll: a **lower bound** on swarm throughput; it misses device-to-device traffic. For peer-to-peer throughput, read the measured peer-byte panels instead. |
| `iris.download.duration_seconds` | Job acceptance to download finish, including pauses; stops before the SHA-256 check and the copy into flash. |
| `iris.transfer.seeding_started_at` | The last of: file complete, checksum verified, tracker saw the device seeding. |

## Time from plan to seeding

`seeding_started` is only emitted once three conditions all hold:

1. The device reached a terminal report after finding the staged file at the
   exact catalog size, with no aria2 control file beside it.
2. That same report carries `content_sha256.state = verified` for this plan's
   `transfer_id`.
3. The device's own aria2 announced `left = 0` on the image's torrent,
   authenticated by that device's personalised announce token.

A tracker-observed seeder alone, apart from the combined `seeding_started_at`,
does not prove device verification or final placement.

| Compare | Tells you |
| --- | --- |
| `tracker_seeder_at` well before `checksum_verified_at` | The device was still hashing the image. |
| The reverse order | The swarm was the wait, not the device. |
| `checksum_verified_at` vs `iris.device.report_created_at` | The delivery delay; on a bad link the agent backs off to about sixteen minutes. |

## What to alert on

| Metric | Alert when |
| --- | --- |
| `iris_seeder_queued_torrents` | Non-zero: the origin is holding back a published image. |
| `iris_transfer_lifecycle_unconfirmed` | Steady non-zero: a collector problem, not a fleet one. |
| `iris_transfer_lifecycle_retired_undelivered_total` | Records queued, never acknowledged, and now gone. |

## Device-side logging

`IRIS_LOG` controls aria2's continuous transfer log, off by default.
Heartbeats, staging errors, and `%IRIS-6-<MNEMONIC>` messages stay on.

| Runtime | Agent messages | Aria2 log |
| --- | --- | --- |
| Guest Shell / router | IOS-XE syslog | `aria2c.log` in the staging directory. |
| IOx | IOS-XE syslog, through SSH-to-self | `aria2c.log` in the agent working directory. |
| IOS-XR | `show appmgr application name iris logs` | The same log in `harddisk:iris-work/`. |

Turn on **Detailed logs** in the Console's Onboard dialog for IOx and IOS-XR
(undeploy and onboard again to change it), or add `iris_log = on` to
`iris-agent.conf` for Guest Shell. See
[Device agent configuration](../reference/device-configuration.md).

## Related

- [Export telemetry](telemetry-export.md)
- [Telemetry signals](../reference/telemetry-signals.md)
- [Search IRIS data in Splunk](splunk-searches.md)
- [Import the Splunk and Grafana dashboards](dashboards.md)
- [Troubleshoot: symptoms and first steps](troubleshooting.md)
