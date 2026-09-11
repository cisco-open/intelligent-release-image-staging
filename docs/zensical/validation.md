<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Validation

Validate documentation, server behavior, device packaging, and lab behavior separately. A passing unit test suite is necessary but not enough for a network rollout.

## Automated tests

Run the Python tests:

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ lab/tests/ device/test_verify_image.py -q
```

Run the Bats tests:

```bash
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ device/xr/tests/ server/tests/*.bats
```

Both suites are expected to be fully green on a clean checkout: no host
provisioning, no running IRIS stack, and no dependence on which machine runs
them.

### Opt-in host-integration tests

A few tests cannot be hermetic — they run a real `docker build`, which needs a
reachable Docker daemon, pulls the pinned base image and takes minutes, or they
reach the network. They are skipped by default and run only when you set
`IRIS_TEST_HOST_INTEGRATION=1`:

```bash
IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
IRIS_TEST_HOST_INTEGRATION=1 python3 -m pytest server/tests/test_aria2c_build_pins.py
```

Today that covers the two image-build tests in
`device/xr/tests/test_xr_image.bats` — run them before cutting a release or
after changing `device/container/Dockerfile` — and the pin-resolution test in
`server/tests/test_aria2c_build_pins.py`, which asks the live Alpine package
index whether the pins in the published aria2c build scripts still exist. Run
that one before a release too: an Alpine security bump withdraws the exact
version we pinned, which no hermetic test can notice, and it leaves the
corresponding source we publish unbuildable.

### Capacity harness

`server/tests/test_capacity_harness.py` is a repeatable mixed-workload
capacity harness: it seeds a synthetic fleet of N devices under its own
temporary directory (never the live server, its volumes, or a real device)
and drives a tracker announce, a catalog heartbeat, a device policy read, a
terminal report, a credential resolution, a fleet-wide bulk credential
reassignment, and the console's own fleet projection — the operations a real
fleet drives concurrently — then reports how the cost of each moves as N
grows. Reassigning the whole selected set through
`FleetStore.bulk_upsert` costs at most `keyed_state.SHARD_COUNT` (256) shard
writes, however many devices are selected.
Credential checks call the actual catalog, tracker query and tracker bearer
resolvers with accepted and unknown tokens. The harness counts index lookups
and rejects fleet-wide scans during resolution.

A small pair of sizes (50 and 500 devices) runs by default, in seconds, with
every test suite. The full progression the project's own scale claims are
stated at — 100, 1,000 and 10,000 devices, 10,000 being the top of the
supported fleet size — rebuilds a 10,000-device fleet and is slow by design,
so it is opt-in behind `IRIS_TEST_CAPACITY_LARGE=1`:

```bash
IRIS_TEST_CAPACITY_LARGE=1 python3 -m pytest \
    server/tests/test_capacity_harness.py -q -s -k ten_thousand
```

or standalone: `python3 server/tests/test_capacity_harness.py --sizes 100
1000 10000`. Every operation calls the real production function (the console
check drives the real `gui_server` HTTP handler end to end), never a
reimplementation, against synthetic state shaped like the real thing.

Wall-clock timings the harness prints are informational only, not pass/fail:
this host also runs the live IRIS lab server and real device traffic, so
absolute milliseconds are noisy and **not comparable across separate runs,
days, or machines** — only the growth factor within one run, across its own
sizes, means anything. The assertions that actually run check deterministic
counted work instead — which shard file changed, how many rows it holds, how
many credential-index builds and lookups requests cost, how many bytes a
console response carries — the same style `test_keyed_state_scaling.py`
uses. It deliberately does not measure concurrent load (every call runs
sequentially, never the thousands-of-devices-at-once shape a real fleet
produces), process/thread/FD growth over time, or real disk-hardware latency
(state lives under `tempfile.TemporaryDirectory()`, on whatever filesystem
backs the host's temp directory). See `TESTING.md` and the module's own
docstring for the full accounting.

## Documentation build

Build the docs from the repository root after changing the manual or its
navigation. See [Documentation loop](development.md#documentation-loop) for
the commands and supported tool versions. A build checks generated pages;
review the Console's bundled help pages separately.

## Phase 1 layout validation

Record configuration, unit/static checks, package inspection/build evidence and
actual lab/device observations separately. A disposable-root, unsigned package
build proves buildability and byte propagation only; it proves no production
root ceremony, native signing, release, deployment or live application. Every
shared-agent change requires fresh Guest Shell bundles, unified OCI, both IOx
tars and XR RPM from the same source and the current pinned aria2c binaries.
Compare agent-source and two-public-root bytes across every artifact, record
wrapper/OCI provenance, and run `tools/check-package-freshness.sh`. Its
certificate-drift check does not waive the source rebuild rule.

Apply the checklist only to the selected supported layout:

| Layout | Phase 1 checks to record |
| --- | --- |
| Single-host Compose | Authenticated instructions/keylist GETs on 8443; 9443 management-only; custody/status windows and a current stamp; one device apply, LKG during catalog loss and QoS drift/reassertion observation; all device artifact provenance. Confirm server startup without the optional signing key and the explicit absent-key status. Verify that an already running Console serves its UI during server outage; default cold startup requires the healthy server to supply initial browser TLS. |
| Split-host Compose | The same 8443/9443, custody, stamp, device apply/LKG/drift and artifact checks; prove instruction state, age identity, encrypted signing key and runtime plaintext exist only on the server host and are absent from Console mounts. Confirm server startup without the optional signing key, and Console startup with its independent default TLS while the server is unavailable; forwarded APIs report unavailable. |
| Single-replica Kubernetes | The same 8443/9443, custody, stamp, device apply/LKG/drift and artifact checks; confirm `replicas: 1`, existing `iris-data` PVC at `/data`, runtime tmpfs, and no new Secret, port, Service or NetworkPolicy rule. Confirm server startup without the optional signing key, and Console startup with independently provisioned TLS while the server is unavailable; forwarded APIs report unavailable. |
| Multi-replica server tier | Not covered and unsupported: instruction production has no cross-pod coordination. A one-replica manifest cannot produce multi-replica evidence. |

For each device platform, probe the actual verifier. Both packaged verifier
architectures must accept both provisioned roots and reject wrong roots and
namespaces. Guest Shell `ssh-keygen -Y verify` remains a runtime probe; absence
must yield tracker-only, so do not claim universal Guest Shell instruction
application. Check LKG survival through two instruction-key rotations, expiry
and allow-list/deny-list asymmetry, one-shot refresh and no in-tick retry loop.
Validate IOx's owned verification transaction with state read-back and recovery,
including actual media/signature restrictions, before claiming live support.

Exercise F3 ciphertext bootstrap-envelope redelivery and the transactional
Guest Shell bundle/sidecar drop, including prior-runnable-bundle preservation on
refusal, then observe instruction state after the next tick. These update the
agent only; staged IOS images remain untouched. Use the
[operator runbooks](operations.md#f3-offline-bootstrap-envelope-redelivery).

Issue #153 mutual-origin union remains preflight-only. One complete tagged-release
dwell, a separately authorized activation release, and authorized lab/live
checks for union semantics, connection reconciliation, shared-address handling,
fail-closed behavior and rollback are required before activation. The checklist
above and Unreleased documentation do not cross that boundary.

## Validated platforms

This table records hardware coverage. Verify the packages being rolled out,
including both architectures of the shared IOx/XR image.

| Platform | Device staging | Status |
| --- | --- | --- |
| Catalyst 9300 | Guest Shell | Lab-validated |
| Catalyst 9300 | IOx on app-hosting SSD share | Lab-validated runtime and direct share hand-off to `flash:` |
| Catalyst 8000V | Guest Shell (router, VirtualPortGroup) | Lab-validated |
| Catalyst 8000V | IOx (router, VirtualPortGroup, amd64, `bootflash:`) | Lab-validated onboard and record-backed undeploy 2026-09-10; app runs on the IRIS-owned VirtualPortGroup |
| IE-3400 | IOx | Lab-validated |
| Cisco 8000 series (IOS-XR) | appmgr container (stages to `harddisk:`) | Lab-validated on a Cisco 8201 (IOS-XR 25.4.2): console onboard, direct-to-`harddisk:` staging with sha256 verification against the catalog, telemetry reporting, and record-driven teardown |

IOS-XR validation checks the full agent lifecycle: build `iris-xr.rpm`,
onboard through the Console, stage directly through the `harddisk:` bind
mount, verify SHA-256, report telemetry, and undeploy from the deployment
record. Check interrupted-transfer resume, peer seeding, independent status
for two devices, and cleanup that preserves operator-provided files.

Cisco 8000 series `.iso`, `.tar`, and `.rpm` images use the same catalog and
swarm distribution path as other image formats. Successful image import does
not establish that an agent package works on a particular device.

## Lab checklist

| Check | Expected result |
| --- | --- |
| Server and Console start | Both services are healthy. The Console can reach the internal management API; browsers reach the Console and agents reach the catalog, tracker, and seeder on their intended ports. |
| Runtime uid owns the host paths | The age key file, host `artifacts/` directory, and named volumes have the required uid `10001` access ([Volume permissions](server.md#volume-permissions)). The Console Images screen lists no file as `not readable by the server`. |
| Admin exists | Console login succeeds. |
| Image publishes | Catalog lists image id, hashes, and info hash. |
| Import publishes in place | A file already under the read-only image root imports from the Console, and the read-only root is unchanged: no copy of the image and no `.torrent` beside it. |
| Management type recorded | Device shows routed, inband, router-routed, router-nat, or xr-host; onboarding creates an applied deployment record. |
| Installer runs | The job finishes successfully, the expected agent runtime is running, and a fresh heartbeat follows. Onboard completion alone does not prove image staging. |
| Runtime trust delivered | Guest Shell has its pinned certificate; IOx receives it in application data after activation; XR reads it through the harddisk bind mount. Packages contain no deployment certificate. |
| Shared package provenance | IOx and XR wrappers match their adjacent manifests and the same canonical OCI build. Guest Shell and both container architectures include the current shared agent source. |
| Inband preserves network | For inband, before/after `show running-config` shows the existing VLAN/SVI/gateway/VRF unchanged. |
| Catalyst 8000V router path | `router-routed` and `router-nat` onboard, stage a verified image, and undeploy from their deployment records. Swarm Map shows the device, and the operator's OTLP backend shows its telemetry when observability is enabled. |
| IOS-XR appmgr path | `xr-host` + `xr-appmgr` onboards, stages directly to `harddisk:`, reports telemetry, and converges under record-driven or repeated undeploy without touching router networking. |
| Assignment applies | Device reports each assigned image id. A newly assigned image waits for the agent's report; a second device starting does not reset the first device's completed state. |
| Download completes | Swarm state shows completed pieces. |
| Verification passes | The completed file matches the catalog SHA-256 and final size. IOS-XE places the verified file at the storage root; XR checks it in place. |
| Existing Guest Shell image | A same-name root file with matching size and native SHA-512 is adopted. A mismatch is kept and reported as a staging failure. |
| Partial failure | A current per-image hash, catalog, or RPC error stays visible while other assigned images continue. |
| Clear assignments | Torrents stop, including when the last assignment is cleared. IOS-XE keeps root copies; XR removes downloaded files but retains adopted files or files of unknown origin. |
| Undeploy from deployment record | Teardown targets only resources tracked in the deployment record; router adoption is refused and requires re-onboarding. For `router-nat`, teardown clears only translations for the deployment record's app IP, verifies the overload rule is gone before deleting its ACL, and reports no leftover IRIS NAT rule. |
| Scheduled window stages and stops there | A `once` schedule targeting the current Devices filter fires inside its window, its occurrence records the target it resolved, and every device it reached has a durable outcome. The staged image is verified at the storage root; no install, activation, boot-variable change, or reload happens anywhere in the window. |
| Window closes honestly | At the window end, no new work is admitted and queued jobs are cancelled with `window_closed` outcomes. Already-running jobs are allowed to finish and their terminal outcomes remain recorded. |
| Wave gate holds and stalls visibly | A schedule gated on a preceding one does not admit work until the ratios are met, and an unmet gate ends the occurrence `stalled` at its deadline carrying staged / errored / missing counts, with missing distinguished from errored. |
| No activation occurs | Boot variables, install state, and reload state remain operator-controlled. |

Automated coverage for the management-type/deployment-record behavior lives in
`server/tests/test_deployment_records.py`, `server/tests/test_gui_fleet.py`,
the inband command-stream assertions in
`device/tests/test_device_uninstall.bats`, and the router install/teardown
command streams in `device/tests/test_router_install.bats` and
`device/tests/test_router_uninstall.bats`. See
[Management Type and VLAN Ownership](management-type.md).

## What automated tests do not cover

The Console has Python tests for server projections and Node-based tests that
execute the shipped JavaScript for device fields, status, and Swarm Map
updates. They cover per-image state, participant identity, stale responses,
and open-drawer updates. They do not run a browser layout engine.

Check layout, keyboard behavior, and the rendered graph by hand in a browser
when those views change. Passing the logic tests does not establish that fields
align or graph nodes render correctly.

Check these by hand when the map or its data source changes:

| Check | What to look for |
| --- | --- |
| Hidden-tab pause | Polling stops when the tab is hidden or the view is left, and resumes on return. |
| Backoff | While `/swarm` is unreachable the poll backs off and the header says so, rather than hammering. |
| Keyboard | Graph nodes are reachable and operable from the keyboard; the detail drawer keeps focus and closes on Escape. |
| Reduced motion | The graph respects the reduced-motion preference. |
| Empty and error states | An empty swarm, an unreachable origin RPC, and a stale device observation remain distinguishable. |
| Live details | An open peer drawer updates as polls arrive, retains focus, and shows when its participant disappears. A late response from an older poll does not replace newer data. |
| Multiple devices and images | Completed staging remains complete when another device or image begins. Shared IPs do not duplicate rates, and each image's errors appear on the matching row. |
| Add Device | Management type alone controls network fields; changing the free-text model preserves that selection. Fields and Save/Cancel stay aligned at desktop and narrow widths. |

## Reporting bugs

Include platform, device software version, boot mode, server host OS, Docker
version, image id, agent report, relevant console audit lines, and whether the
Guest Shell, IOx, or XR appmgr path is in use.
