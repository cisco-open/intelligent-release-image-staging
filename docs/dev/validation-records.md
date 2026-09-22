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
Undeploying a device does not remove images staged for real use, and a
cleanup should not either.

## Native security acceptance — 2026-09-20

The current ten-patch aria2c client and installed instruction verifier were
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
