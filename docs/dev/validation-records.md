<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Dated lab evidence

This page keeps the dated lab records that back specific claims made
elsewhere in the docs: what a run measured, what it validated, and what it
left open. It is evidence, not a procedure. For the deployment steps, see
[The assistant-facing deployment runbook](ai-assisted-deployment.md); for
what these numbers mean for a production fleet, see
[Limitations](../zensical/architecture/limitations.md).

## Completion record

After a deployment or a device validation run, record what actually
happened, not what you planned. This is the template
[The assistant-facing deployment runbook](ai-assisted-deployment.md) points
to when it says to keep this evidence separate from the deployment
procedure.

| What to record | Detail |
| --- | --- |
| Deployment | The IRIS version, the layout, each host's role and address, the Console URL, the management endpoint, and the Compose projects or the Kubernetes namespace involved. |
| Checks performed | The checks you actually ran, not the ones you assumed passed. |
| Device work | The image ID, the model and agent choice, the staging target, the job result, and the final state of each image. |
| Gaps | Anything you did not verify. |
| Credentials | Never include a credential or a token in the record. |

Give a repeated test of the same layout its own job IDs and its own report;
an earlier successful check-in does not stand in for a new one. Use a
distinct test image, or confirm you removed the earlier one, before you
download another. A synthetic file proves the transfer and the hash and
placement checks, not that the bytes are an authentic Cisco image.
Afterward, clear the image's assignments, undeploy using the job IDs you
recorded, and remove only the files and catalog entries the test created.
Unassigning an IOS-XR image removes files IRIS downloaded in place; adopted
files and files of unknown origin stay. Preserve real-use assignments and
files outside the test. Undeploy itself leaves any remaining root image files.

## Device certificate withdrawal - 2026-10-10

The eleven-patch AMD64 and ARM64 clients were checked in isolated loopback
environments with generated certificates and synthetic payloads. ARM64 ran under
emulation. This was client behavior qualification, not a deployment, native
performance measurement or live fleet test.

- Ten TLS checks passed on each architecture. A still-valid certificate on the
  previous client lost its established connection after its identity was
  withdrawn. A different certificate using the same IP address continued
  transferring. New connections
  with the withdrawn certificate were rejected.
- Missing, invalid and expired revocation data stopped encrypted peer
  connections. The runtime report reflected the list actually loaded by the
  client. The standalone reader passed 44 malformed-input and enforcement checks.
- Fragmented crossed connections, both peer-ID orders, the peer connection cap,
  and plaintext transfers passed their regression checks.
- Real OpenSSL enrollment tests completed two revoke-and-replace cycles under
  the same inventory ID. Each replacement used a new key and certificate
  identity; the earlier identities remained withdrawn.
- Console browser checks covered confirmation, lost write responses, safe
  status checks, fresh-onboarding approval and narrow-screen layout.
- The complete corresponding-source bundle was extracted and verified. Offline
  rebuilds reproduced both client hashes using cached compiler layers and
  checksum-locked dependencies; this was not a second uncached compilation.
- Fresh Guest Shell bundles for both architectures, both IOx packages and the
  XR RPM contained the current agent and exact tested clients. IOx SHA512
  manifests passed; the AMD64 IOx and XR payloads matched the same canonical
  image. These isolated packages used disposable test-only public roots.

The checks used disposable keys and did not revoke any operator device,
modify a live deployment or qualify native IOx signature admission. The IOx
wrappers were unsigned. Updated
clients enforce certificate withdrawal; earlier clients need replacement.

## Guest Shell, XR and reviewed origin access - 2026-10-09

An independent single-host Docker deployment used source `f7c7f72`, freshly
built device packages, its own signing roots and required peer TLS. An already
BUNDLE-booted Catalyst 9300 on IOS-XE 17.18.04 and two Cisco 8000 routers on
IOS-XR 25.4.2 each staged a synthetic 128 MiB file. Device-native hashes matched;
signed heartbeats and TLS observations were checked separately.

- Guest Shell public trust files remained readable by the agent after a native
  IOS file read changed their ownership. Only the verified public files used
  mode `0644`; the agent source retained mode `0600`.
- Real Console actions changed peer reporting from 60 to 10 seconds and back.
  Adjacent active reports were 9.992 seconds apart. Device-to-device arrows
  appeared during actual transfer; pausing the map stopped its polling.
- A reviewed one-device, one-address origin restriction disconnected the
  origin while the receiving XR still held its earlier instruction. An allowed
  Guest Shell peer continued delivery. Reviewed rollback and a server restart
  left no owned blocked addresses or pending application, with proof from the
  current transfer-service session.
- After the server restart, all three devices recovered fresh signed reports
  without forced polling or agent restarts. The browser required a fresh login.
- Normal unassignment and recorded undeploy completed. Device configuration
  and running software matched the baselines; boot settings were unchanged.
  Only the test's synthetic files and configuration were removed.

The new SHA512 IOx wrapper did **not** pass the IE admission check. On the
tested IOS-XE 17.15.04 / CAF 2.12.0.3 device, architecture and descriptor
validation succeeded, then manifest parsing rejected the first SHA512 entry.
Native signing compatibility remains unresolved. The available Catalyst 8000V
devices retained native verification; no unsigned onboarding was attempted.
These results do not qualify either IOx architecture for native signature
acceptance, or measure an isolated bandwidth cost for ten-second reporting.

## Native security acceptance — 2026-09-20

The then-current ten-patch aria2c client and installed instruction verifier were
checked on a Catalyst 9300 Guest Shell, completing the remaining native
acceptance checks after the earlier IE3400, C8KV and IOS-XR runs.

- A private copy of the device's valid v2 last-known-good cache recovered an
  effective policy without any catalog or network call. Tampered v2 and
  legacy-format copies were rejected. The live configuration and cache were
  unchanged.
- Two isolated instances of the installed client transferred a 262,168-byte
  synthetic file over native loopback with matching SHA-256. Connection logs
  reported TLS 1.3, X25519MLKEM768, AES-256-GCM, the dedicated peer application
  protocol and verified peer authentication. Wrong-CA and expired certificates
  were rejected in both client and server roles before BitTorrent exchange.
  This validates native transport behavior, not cross-device throughput.
- An isolated catalog using the deployed server code and disposable state
  accepted valid enrollment and rejected invalid, wrong-device and revoked
  tokens. The issued certificate lasted 24 hours. No production identity or
  issuing authority was used or changed.

These checks did not interrupt the production agent, change image assignments,
install device software or alter boot state. Token revocation prevents new
enrollment; it does not immediately invalidate issued certificates or terminate
established connections. See the [peer TLS security model](../zensical/architecture/security-model.md#peer-transfer-encryption).

## Historical lab calibration

On 2026-09-15, an unthrottled repeat against 500 devices completed every
create, read-back, and removal with no HTTP 207 partial-failure response.
The slowest clean phase was serial delete, measured at 21.27 requests per
second. That lab deployment set its limit to 80% of that figure, rounded
down: 17 requests per second shared across reads and writes (1,020 requests
per minute), with room for a burst of 4 requests:

```ini
IRIS_API_RATE_TOTAL=17
IRIS_API_BURST_TOTAL=4
IRIS_API_RATE_READ=0
IRIS_API_RATE_WRITE=0
```

That lab deployment has since been retired. Treat this as a worked
calibration example, not a claim about any other running server: put a
chosen limit in the deployment's own Compose environment file, described in
[Server configuration](../zensical/reference/server-configuration.md). It is
a conservative lab setting, not a certified maximum. The run covered fleet
creates, reads, and deletes, and a set of policy fixtures, not sustained
mixed uploads or device jobs, and other deployments default to disabled
limits until you configure them. Retest before you raise the budget or
apply this figure to a different host or fleet. See
[Routine maintenance tasks](../zensical/admin-guide/maintenance.md) for the
method without the figures, and
[tools/api-exercise.py](api-exercise.md) for the harness that produced them.

## Fleet API projection comparisons - 2026-10-08

An isolated comparison used 500 synthetic devices, 64 authenticated HTTP
requests per phase, concurrency 1/4/16, and two before/after trials in reversed
order. Reusing cached row-copy plans reduced CPU work in the storage profile,
but HTTP results overlapped: at concurrency 16, Inventory p95 was 376–406 ms
before and 365–407 ms after; Overview was 428–466 ms before and 429–486 ms
after. All 2,304 requests passed.

A second comparison added assignments and heartbeats for half of the 500
devices. All 2,304 authenticated responses matched the previous implementation.
Skipping unconsumed Inventory detail reduced Overview p95 at concurrency 16
from 1,285–1,301 ms to 1,074–1,231 ms. Throughput rose from 13.0–13.3 to
14.9–15.6 requests per second. Inventory and sharing-policy contention remained.
This richer fixture is not directly comparable with the first run.

A third paired comparison used that richer fixture to test ordered read
admission against commit `b7fb9e4`. All 2,304 responses again returned 200 and
matched the baseline JSON. At concurrency 16:

| Read | Before p95 | After p95 | Before requests/second | After requests/second |
| --- | --- | --- | --- | --- |
| Inventory | 1,136–1,226 ms | 690–751 ms | 13.54–14.77 | 22.17–24.34 |
| Sharing policy | 1,168–1,215 ms | 722–730 ms | 13.95–14.89 | 22.88–22.89 |
| Overview | 1,075–1,149 ms | 681–724 ms | 14.56–15.42 | 23.25–24.57 |

The queue restores throughput near the serial result; it does not provide
linear scaling. A separate short correctness check ran 12 mixed-read workers
alongside one writer: 192 reads, 32 inventory writes and 32 direct heartbeat
writes. Every HTTP response was 200, and the final inventory read showed the
new revision and last write. Deterministic tests cover FIFO entry, failures,
expired waits, independent writes and response sends, and fresh state after
waiting. The measurement and mixed checks used disposable local state.

These short local HTTP checks did not qualify TLS, live deployments, sustained
mixed workload, capacity or higher admission limits. See
[the API test harness](api-exercise.md) for the current read behavior and test
method.

## Sustained mixed API workload - 2026-10-09

The [sustained runner](api-soak.md) passed its four two-minute steps at 2, 5,
10 and 15 Console operations per second, then 30 minutes at 15. The source was
`f7c7f723cd4b40048b32d20589c583a7d0ca0c0a`, using these immutable image IDs:

```text
server  sha256:a5e4a813bb8b9cdf091497bf4a0785967263b57e1850497576de7a76b00e956f
Console sha256:b4bf187a94a696d28056dad531e57ca69d6c2115a8b90dc7f056bb5689793f4a
```

The local Docker host had 18 logical CPUs, 47 GiB RAM, Ubuntu 24.04.4,
kernel 6.8.0-138-generic and Docker 29.8.2. Docker used overlayfs on ext4;
its data and the evidence directory shared a filesystem. The server had
4 CPUs/4 GiB, the Console 2 CPUs/2 GiB, and the driver one pinned logical CPU.
TLS verification remained enabled on the isolated internal bridge.

The fleet had 1,000 synthetic devices provisioned offline. Four authenticated
sessions generated an 80:20 mix of paged reads and metadata writes. Each device
sent one heartbeat per minute. One small terminal report arrived per second;
one real 16 MiB synthetic upload ran through publication each minute.

| Operation during the 30-minute soak | Count | p95 | p99 |
| --- | ---: | ---: | ---: |
| Console read | 21,598 | 194 ms | 234 ms |
| Metadata write | 5,400 | 50 ms | 57 ms |
| Heartbeat | 30,000 | 17 ms | 19 ms |
| Terminal report | 1,800 | 18 ms | 21 ms |
| Upload and publication HTTP requests | 138 | 183 ms | 215 ms |
| Complete upload through publication | 30 | 492 ms | 496 ms |

The last row measures complete operations, not extra HTTP requests. All normal
responses were 200 with valid expected content. The driver delivered 26,998 of
27,000 scheduled Console starts, all 30,000 heartbeats and all 1,800 reports.
Every latency, delivery and resource objective in the method passed unchanged.

Across 402 resource samples, server CPU peaked at 35.2% of its quota and total
cgroup memory at 851.2 MiB (20.8%). Anonymous memory peaked at 174.8 MiB and file
cache at 631.4 MiB; these separate maxima need not coincide. Console CPU peaked
at 15.1% of quota and memory at 65.7 MiB (3.2%). Host CPU peaked at 23.2%, with
at least 41.2 GiB available RAM and 2.86 TB free on both checked paths.

Clean restart preserved four writers' last accepted metadata, all 1,000 latest
reports and 39 published images. Rehashing all 39 files matched their digests.
The recovery workload published a fortieth image. Stopping only the server
returned the expected 503 with `Retry-After: 1`; restart and fresh login restored
access and confirmed durable state. A shared 12-per-second admission budget
then accepted 309 Console requests and returned 38 bounded 429 responses across
four sessions. The driver waited before new work without replaying mutations;
the aggregate budget and final durable state passed. All nine service stops
exited zero without OOM kills. Exact owned resources and driver credentials
were removed; independent label queries found none remaining.

This was a shared-host measurement. Seven monitoring containers and regression
tests pinned to another CPU remained present. A separate device-test deployment
had limits of 2 CPUs/2 GiB plus 1 CPU/1 GiB. Its intermittent work included
three 128 MiB transfers, onboarding attempts, a clean restart and cleanup from
17:24 to 17:55 UTC. One transfer overlapped the soak; the other two preceded it.
Docker and device-package builds finished before the measured run. This is not a clean performance
comparison with the earlier baseline or qualification of those device jobs.

The highest qualified rate was 15 Console operations per second, not a capacity
ceiling. For this recorded mix, an 80% starting budget is 12 total, split into
9.6 reads and 2.4 writes per second. No deployment default or owner setting was
changed. Retest for another fleet, traffic mix, cadence, image size, runtime,
storage or topology. This run excludes signed instructions, maximum-sized peer
reports, multi-GiB files, Cisco authenticity, device onboarding, tracker or
BitTorrent capacity, WAN, Kubernetes, separate hosts and abrupt power loss.
Future image builds require their own source and image provenance review.

## Telemetry WAN cost and peer-sampling coverage

[Limitations](../zensical/architecture/limitations.md) and
[aria2 peer sampling, report ring and promotion design](telemetry-internals.md)
link here for the measured numbers behind two separate claims: what
streaming telemetry costs a device's WAN link, and how much of a peer
transfer the origin's sampling actually traces.

**WAN cost.** Per device, streaming telemetry adds about 33 bps on a good
link (about 250 bytes per minute), about 8 bps on a constrained link, and
nothing at all on a bad link, against the roughly 800 bps the heartbeat
itself already costs. The difference follows from how often a sample goes
out: a `good` link samples every tick (60 s), a `constrained` link samples
every fourth tick (about 4 minutes), and a `bad` link sends no samples at
all, so its terminal report carries the whole story instead of an ongoing
stream.

**Peer-sampling coverage.** The origin seeder polls aria2's `getPeers` on an
interval and banks each connection's growth into a durable ledger, but a
connection's counter disappears the moment the connection closes, so a
connection that opened and closed between two polls contributes nothing. On
a 7-router pull, a 3-second poll interval (`IRIS_SAMPLE_INTERVAL=3`) traced
73.3% of the bytes the origin actually sent to a device; a 2-second poll
interval traced 88.1%. The untraced residue is published as its own
measured quantity rather than folded into the traced figure, so a reader
can tell a sampling gap from a real loss.

## The Catalyst 8000V mount record

On IOS-XE 17.15.5, the Catalyst 8000V app-hosting mount did not expose an
IOS-visible directory to an IOx app. CAF accepted a `-v` run option naming
`bootflash:iox_host_data_share`, but never mounted it. `app-hosting data`
copied only into the app itself, not into IOS. IOx on the Catalyst 8000V
therefore pushes the verified scratch file to IOS over SCP, the same path
IOx on the IE-3400 uses, and leaves the device's SCP server enabled. See
[How an image reaches a device](../zensical/architecture/data-path.md) for
the hand-off this replaces.

A pull-based alternative was measured but never adopted. Having IOS pull
the staged file from the app with `copy http://<app-ip>` moved a 973 MB
image in 153 seconds. The SCP push IRIS actually uses took about 124
seconds for the same image.

## Platform validation narratives

The router path, management type `router-routed` or `router-nat`, targets
the Catalyst 8000 family and is lab-tested on the Catalyst 8000V. Its IOx
onboarding and its record-driven undeploy were validated on 2026-09-10,
with the app running on the VirtualPortGroup IRIS creates. See
[Supported devices and platforms](../zensical/install/supported-devices.md)
for the full platform matrix.

On 2026-09-14, `scp -O` package transfer and a downloaded-copy SHA-256 check
were verified on a Cisco 8201 running IOS-XR 25.4.2. On an NCS-540 running
IOS-XR 25.2.2, the same run transferred the RPM with OpenSSH's default SFTP
upload. The session ended with SSH status 255 and the client reported
failure, and that installer selected SCP explicitly. The current development
installer uses certificate-verified HTTPS instead, and its local tests cover
authentication, certificate, and checksum failures.

On 2026-09-15, the HTTPS delivery path completed onboarding, staged a file
with a fresh SHA-256 check, and undeployed normally on the same Cisco 8201
(IOS-XR 25.4.2). It did this across a single Docker host, separate Docker
hosts, and Kubernetes. A check on the device itself confirmed the staged
file and confirmed the running software had not changed. The test used a
synthetic 16 MiB file, not Cisco's own image signature, so full HTTPS
lifecycle validation on the NCS platform is still pending. A historical SCP
check does not validate this newer delivery path.

The NCS lab device had telemetry turned on but could not reach the catalog
over its default VRF. A separate check that gave the management VRF an
explicit source address did reach the catalog. The current IOS-XR appmgr
recipe runs with `--net=host` and does not select a VRF or a source
address. The app reaching a running state does not, by itself, prove it can
reach the catalog or send a heartbeat. See
[Prepare Cisco 8000 and NCS routers for IOS-XR appmgr](../zensical/install/ios-xr.md).

Beyond the RPM transfer, registration, and app-startup check above, image
staging, telemetry delivery, and undeploy on the NCS-540 remain unvalidated.
This record establishes nothing about any other NCS model.

## The separate-hosts outage drill

On a deployment split across a server host and a Console host, the health
check goes beyond confirming both containers are running. It signs in,
requests the device inventory, checks the Settings addresses and the
browser certificate, imports or uploads an image, and streams a job's log.
It also restarts the Console while the server is stopped, to check that the
Console starts up locally, then restores the server and confirms the
Console recovers API access. Run a drill like this against a separate test
deployment, not a server with real device work in progress. These checks
exercise the same operator API as the one-host Compose and Kubernetes
deployments.

For the log commands this drill reads, see
[Install on separate Docker hosts](../zensical/install/separate-docker-hosts.md).
For what each symptom means, see
[Troubleshoot: symptoms and first steps](../zensical/user-guide/troubleshooting.md).

## Related

- [The assistant-facing deployment runbook](ai-assisted-deployment.md)
- [aria2 peer sampling, report ring and promotion design](telemetry-internals.md)
- [tools/api-exercise.py](api-exercise.md)
- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md)
- [Limitations](../zensical/architecture/limitations.md)
- [Supported devices and platforms](../zensical/install/supported-devices.md)
