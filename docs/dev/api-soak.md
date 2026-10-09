<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Sustained API qualification

`tools/api-soak.py` measures a mixed HTTP workload on a new, disposable local
Docker deployment. It complements the short [API exercise](api-exercise.md)
and the per-operation scaling tests. A short fixture run is not a capacity
qualification. Reserve a quiet measurement window before running the default
38-minute workload and its restart and admission checks.

## Isolation and resources

The runner accepts local image references, not a deployment URL. It refuses
remote Docker contexts and requires explicit consent. Every container, volume
and network has a unique ownership label. Cleanup checks both that label and
the recorded resource identity before removing anything.

The server and Console use an internal Docker bridge with no published ports.
The host driver connects only to the two addresses taken from that owned
network. TLS verifies both certificates and hostnames. The Console receives
its browser identity and the private management credential and CA, not the
server age identity or synthetic device credentials. No Docker socket is
mounted in either service.

The server is limited to 4 CPUs and 4 GiB; the Console to 2 CPUs and 2 GiB.
Swap is disabled for both, and each has a 256-process limit. The driver is
pinned to one logical CPU. Allow at least 8 GiB of host memory and 5 GiB of
free disk beyond the workload. The runner stops if those floors are crossed,
host CPU use exceeds 85%, or either service exceeds 80% of its CPU or memory
allocation at a sample. Samples are taken about every five seconds and include
cgroup CPU, memory, pressure, process, thread and file-descriptor counters.

## Workload and objectives

The default fleet has 1,000 synthetic devices. The fixture uses the native
encrypted secrets store to provision their tokens before services start.
This is offline fixture preparation, not an onboarding test. It assigns one
real uploaded synthetic image through the native catalog store.
Heartbeats and terminal reports are small, under 1 KiB, with no peer rows.
Signed instruction delivery, tracker announcements, BitTorrent transfers and
maximum-sized telemetry reports are outside this initial workload.

Four authenticated browser sessions share the Console workload. The steps
request 2, 5, 10 and 15 operations per second, each for two minutes. Reads
make up 80% of these operations: paged inventory, Overview, peer policy and
session status. The other 20% update synthetic device metadata. Each step
also includes one heartbeat per device per minute, one current-format terminal
telemetry report per second, and a 16 MiB image upload each minute.
Upload, publish-job polling and catalog verification requests are counted
separately as `upload_http`; the end-to-end upload duration is `upload`.

Uploads run the real torrent publisher and seeder RPC. The runner waits for
the publish job and compares its catalog SHA256 and byte count with the
uploaded bytes. These are synthetic files, with authenticity reported as
not checked. They are not Cisco software or proof of Cisco hash verification.

| Operation | p95 limit | p99 limit |
| --- | --- | --- |
| Console read | 500 ms | 2 seconds |
| Metadata write, heartbeat or terminal report | 1 second | 3 seconds |
| Upload through completed publication | 30 seconds | 30 seconds |

Every normal response must be HTTP 200. Partial responses, malformed JSON,
unknown write outcomes and transport failures fail the run. At least 95% of
the scheduled Console, heartbeat and terminal-report starts must be delivered.
The driver does not issue catch-up bursts or retry a failed mutation.

The highest passing step runs for 30 minutes with the same mix. A failed
step stops for investigation; the runner does not silently downgrade and
claim qualification. A passing top step establishes a tested rate, not the
system's maximum capacity.

## Run

Use already-built server and Console images from the source being qualified.
The runner records their immutable image IDs. It never builds native device
packages or contacts a device. Stock startup prepares its usual served bundle
inside this disposable deployment only.

```bash
python3 tools/api-soak.py \
  --server-image iris:qualification-candidate \
  --console-image iris-console:qualification-candidate \
  --output agentinfo/api-soak-qualification \
  --accept-isolated-load
```

For a short fixture check, add `--devices 4 --steps 2 --step-seconds 5
--soak-seconds 5`. The result explicitly marks that run as not a qualification.
The output directory must be new. Standard output contains progress and fixed
diagnostics, not credentials or response bodies.

## Persistence, admission and evidence

After the soak, the runner stops both services cleanly and starts them again
with the same volumes. Fresh logins check the last accepted metadata value
for each writer, the latest accepted report for every reporting device, and
each published image's digest. A server-side check rehashes the actual image
files. A further mixed phase checks recovery. A separate dependency check
keeps the Console running while stopping only its owned server. One read must
return the documented HTTP 503 and `Retry-After: 1`. Starting the server again,
logging in and checking durable data proves recovery from that known outage.
It is not evidence about unexplained failures while both tiers are healthy.

The admission check recreates only the owned server with a total Console
budget at 80% of the tested rate. For this check, each read and write budget
allows that whole rate independently, so their combined traffic must still
obey the smaller total. The suggested operational split is 80:20 for reads
and writes. Four sessions exercise the combined budget. HTTP 429 is accepted only
in this phase and must carry a bounded `Retry-After`. The driver waits before
its next operation; it does not replay the rejected mutation. It verifies the
aggregate admitted count, then removes the budgets and checks accepted writes
again.

`result.json` records operation counts, response classes, p95/p99 latency,
durability checks and cleanup. `resources.json` records exact owned resources
and image IDs; `resources.jsonl` records resource samples. Histogram storage is
bounded rather than retaining every response. Temporary driver credentials
are removed after the owned Docker resources are retired.

Record the measured envelope and exclusions in
[Dated lab evidence](validation-records.md), including competing services,
source revision, host resources and disk, request delivery and resource
headroom. Do not reuse a result for another fleet size, image size, topology,
storage backend, release or telemetry cadence without qualification. This
initial runner covers local Docker, not Kubernetes, separate hosts, WAN paths,
multi-GiB files, real device staging, or abrupt power-loss recovery.
