<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Search IRIS data in Splunk

These searches tell you which devices reported, how many bytes came from
other devices, and how long a device took to start seeding. Set the feed up
first, on [Send telemetry to Splunk](splunk.md).

## How IRIS fields appear in SPL

SPL is the Splunk search language. Every attribute IRIS sends to the HTTP
Event Collector (HEC) is a searchable field.

- Single-quote a dotted field name: `where "iris.image.id"==x` compares a
  string literal and returns nothing.
- Byte counts arrive as strings. Run `tonumber()` on them.
- Count only after `dedup "event.id"`. A report can reach Splunk twice.
- Change `iris_logs` if your index has another name.

## The searches

### Peer transport policy

The latest torrent-TLS policy each device reports, by principal: who the
request is from, a device, the server's seeder, or a legacy device.

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "iris.peer.tls.configured_mode"=*
| stats latest("iris.peer.tls.configured_mode") AS configured
    latest("iris.peer.tls.runtime_mode") AS runtime
    latest("iris.peer.tls.runtime_source") AS source
    latest("iris.peer.tls.reported_at") AS reported_at BY "iris.principal"
```

`configured=required runtime=required source=aria2_rpc` means the device and
its aria2 daemon both report the required policy.

### Device staging reports

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.device.transfer.report"
| dedup "event.id"
| eval completed_bytes=tonumber('iris.transfer.completed_content_bytes')
| table _time "device.id" "iris.image.id" "iris.transfer.id"
    "iris.report.event" completed_bytes "iris.transfer.content_sha256.state" "iris.transfer.ios_copy_verify.state"
```

Read device, image and transfer identity together when a device stages
several images, or the same image twice.

!!! warning

    `iris.device.transfer.report` and `iris.device.report` are two projections
    of one delivery. Count both and you count that delivery twice.

### Bytes received from each peer

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.device.peer_transfer_record"
| dedup "event.id"
| eval received_bytes=tonumber('iris.transfer.session_bytes_from_peer')
| eval image=coalesce('iris.image.name', 'iris.image.id')
| eval source=coalesce('iris.peer.device_id', "unknown")
| stats max(received_bytes) AS received_bytes
    values("iris.transfer_record.capture_complete") AS capture_complete
    BY "device.id", image, "iris.transfer.id", "network.peer.address", source, "iris.peer.attribution"
```

Each row is the largest cumulative capture for one transfer and peer address,
measured by the receiving device. `source` reads `origin` for the seeder, the
server's own copy of the image and the first source in the swarm, the sender's
device id for a `device` row, and `unknown` for a peer the server could not
name. `capture_complete=false` marks a capture that finished short.

### Peer-to-peer evidence

These three fill the peer-to-peer evidence row of the Splunk view IRIS ships,
described in [Import the Splunk and Grafana dashboards](dashboards.md). Each
keeps the largest cumulative byte count per receiver, image, transfer and peer
address.

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.device.peer_transfer_record"
| dedup "event.id"
| eval received_bytes=tonumber('iris.transfer.session_bytes_from_peer')
| sort 0 -received_bytes
| dedup "device.id" "iris.image.id" "iris.transfer.id" "network.peer.address"
| eval source=case('iris.peer.attribution'=="origin","origin",
    'iris.peer.attribution'=="device","peer device",1==1,"unknown")
| eval MiB=received_bytes/1048576
| timechart span=1h sum(MiB) BY source
```

Cumulative bytes by hour of capture. *peer device* is traffic devices served
each other, *origin* is the seeder's share.

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.device.peer_transfer_record"
| dedup "event.id"
| eval received_bytes=tonumber('iris.transfer.session_bytes_from_peer')
| sort 0 -received_bytes
| dedup "device.id" "iris.image.id" "iris.transfer.id" "network.peer.address"
| stats sum(eval(if('iris.peer.attribution'=="device",received_bytes,null()))) AS peer_bytes,
    sum(received_bytes) AS all_bytes
| eval pct=if(isnull(all_bytes) OR all_bytes<=0,null(),
    round(100*coalesce(peer_bytes,0)/all_bytes,1))
| fields pct
```

The share of received bytes that came from a peer device. Origin and unknown
rows stay in the denominator.

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.device.peer_transfer_record"
| dedup "event.id"
| eval received_bytes=tonumber('iris.transfer.session_bytes_from_peer')
| sort 0 -received_bytes
| dedup "device.id" "iris.image.id" "iris.transfer.id" "network.peer.address"
| where 'iris.peer.attribution'=="device"
| eval "MiB from this peer"=round(received_bytes/1048576,1)
| eval Image=coalesce('iris.image.name','iris.image.id')
| rename "iris.peer.device_id" AS Sender, "device.id" AS Receiver,
    "iris.transfer_record.capture_complete" AS "Capture complete"
| table _time, Sender, Receiver, Image, "MiB from this peer", "Capture complete"
| sort - _time
```

One row is one transfer leg. `_time` is when the receiver read its counters.

### Assignment to confirmed seeding

```spl
index=iris_logs source=iris sourcetype=otel:logs earliest=-24h
  "otel.log.name"="iris.transfer.lifecycle" event="seeding_started"
| dedup "event.id"
| eval planned=strptime('iris.transfer.planned_at', "%Y-%m-%dT%H:%M:%S.%N%Z")
| eval seeding=strptime('iris.transfer.seeding_started_at', "%Y-%m-%dT%H:%M:%S.%N%Z")
| eval elapsed_seconds=round(seeding-planned,3)
| table "device.id" "iris.image.id" "iris.plan.id" elapsed_seconds
    "iris.transfer.report_received_at" "iris.transfer.tracker_seeder_at"
    "iris.transfer.recovered_promotion"
```

Server-observed time from assignment to confirmed seeding, report-delivery
delay included. See [Monitor transfers and device reports](monitoring.md).

To roll the same measure up per plan:

```spl
index=iris "otel.log.name"="iris.transfer.lifecycle"
| eval planned=strptime('iris.transfer.planned_at', "%Y-%m-%dT%H:%M:%S.%N%Z"),
       seeded =strptime('iris.transfer.seeding_started_at', "%Y-%m-%dT%H:%M:%S.%N%Z")
| stats min(planned) as planned, max(seeded) as seeded
    by 'iris.transfer.id','iris.plan.id','iris.device.id','iris.image.id'
| eval seconds_to_seed = seeded - planned
```

!!! warning

    This block keeps the index name `iris` from its source search. Check the
    index name before you run it.

Grouping on `iris.plan.id` keeps two attempts at the same device and image
apart. A null `seeded` is a plan that never started seeding.

## Reading the totals

- A peer that dropped before the capture leaves no row, so every total is a
  floor.
- A count of records is not a count of devices. Drop retries, group by
  `device.id`.
- `iris.swarm.peer_bytes` samples the same bytes at the origin. Adding it
  counts one transfer twice.
- An empty result can be a broken feed. See Troubleshooting on
  [Send telemetry to Splunk](splunk.md).

## Related

- [Send telemetry to Splunk](splunk.md)
- [Import the Splunk and Grafana dashboards](dashboards.md)
- [Telemetry signals](../reference/telemetry-signals.md)
- [Monitor transfers and device reports](monitoring.md)
