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

A few Bats tests cannot be hermetic — they run a real `docker build`, which
needs a reachable Docker daemon, pulls the pinned base image and takes minutes.
They are skipped by default and run only when you set `IRIS_TEST_HOST_INTEGRATION=1`:

```bash
IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
```

Today that covers the two image-build tests in
`device/xr/tests/test_xr_image.bats`. Run them before cutting a release or
after changing `device/xr/Dockerfile`.

## Documentation build

The docs site builds clean from the repository root, with no reported issues.
For the commands and the pinned Zensical and Python versions, see
[Documentation loop](development.md#documentation-loop).

## Validated platforms

| Platform | Device staging | Status |
| --- | --- | --- |
| Catalyst 9300 | Guest Shell | Lab-validated |
| Catalyst 9300 | IOx on app-hosting SSD share | Lab-validated runtime and direct share hand-off to `flash:` |
| Catalyst 8000V | Guest Shell (router, VirtualPortGroup) | Lab-validated |
| IE-3400 | IOx | Lab-validated |
| Cisco 8000 series (IOS-XR) | appmgr container (stages to `harddisk:`) | Lab-validated on a Cisco 8201 (IOS-XR 25.4.2): console onboard, direct-to-`harddisk:` staging with sha256 verification against the catalog, telemetry reporting, and record-driven teardown |

The IOS-XR validation covers the full lifecycle, not only package delivery:
build the `iris-xr.rpm`, scp it to `harddisk:`, register and activate the
appmgr container, download directly through the bind mount, verify sha256,
report telemetry, and undeploy from the deployment record. The later teardown
hardening was also exercised on 8010-R4: a record-driven teardown completed in
62 seconds after the fail-closed command-adjudication fixes.

Image import and swarm distribution have always worked for Cisco 8000 series
images regardless: `.iso`, `.tar`, and `.rpm` artifacts publish to the catalog
and distribute through the swarm like any other image.

## Lab checklist

| Check | Expected result |
| --- | --- |
| Server starts | Console, catalog, tracker, artifact server, and telemetry ports are reachable. |
| Runtime uid owns the host paths | The age key file and the host `artifacts/` directory are owned by uid `10001`, and any volume carried over from a root-runtime release is migrated ([Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment)). The Console Images screen lists no file as `not readable by the server`. |
| Admin exists | Console login succeeds. |
| Image publishes | Catalog lists image id, hashes, and info hash. |
| Import publishes in place | A file already under the read-only image root imports from the Console, and the read-only root is unchanged: no copy of the image and no `.torrent` beside it. |
| Management type recorded | Device shows routed, inband, router-routed, router-nat, or xr-host; onboarding creates an applied deployment record. |
| Installer runs | Device has the expected Guest Shell, IOx, or XR appmgr agent plus its bootstrap/configuration. |
| Inband preserves network | For inband, before/after `show running-config` shows the existing VLAN/SVI/gateway/VRF unchanged. |
| Catalyst 8000V router path | `router-routed` and `router-nat` onboard, stage a verified image, and undeploy from their deployment records. Swarm Map shows the device, and the operator's OTLP backend shows its telemetry when observability is enabled. |
| IOS-XR appmgr path | `xr-host` + `xr-appmgr` onboards, stages directly to `harddisk:`, reports telemetry, and converges under record-driven or repeated undeploy without touching router networking. |
| Assignment applies | Device reports the approved image id. |
| Download completes | Swarm state shows completed pieces. |
| Verification passes | Agent reports the staged file and a sha256 match against the catalog's known-good value. |
| Undeploy from deployment record | Teardown targets only resources tracked in the deployment record; router adoption is refused and requires re-onboarding. For `router-nat`, teardown clears only translations for the deployment record's app IP, verifies the overload rule is gone before deleting its ACL, and reports no leftover IRIS NAT rule. |
| No activation occurs | Boot variables, install state, and reload state remain operator-controlled. |

Automated coverage for the management-type/deployment-record behavior lives in
`server/tests/test_deployment_records.py`, `server/tests/test_gui_fleet.py`,
the inband command-stream assertions in
`device/tests/test_device_uninstall.bats`, and the router install/teardown
command streams in `device/tests/test_router_install.bats` and
`device/tests/test_router_uninstall.bats`. See
[Management Type and VLAN Ownership](management-type.md).

## What automated tests do not cover

The console swarm map is verified **by hand in a browser**. There are no
automated browser tests in this repository: the Python suites assert the shape of
the documents the map consumes, not the rendering, focus behavior, or polling of
the page itself. A green test run is not evidence that the map behaves.

Check these by hand when the map or its data source changes:

| Check | What to look for |
| --- | --- |
| Hidden-tab pause | Polling stops when the tab is hidden or the view is left, and resumes on return. |
| Backoff | While `/swarm` is unreachable the poll backs off and the header says so, rather than hammering. |
| Keyboard | Graph nodes are reachable and operable from the keyboard; the detail drawer keeps focus and closes on Escape. |
| Reduced motion | The graph respects the reduced-motion preference. |
| Empty and error states | An empty swarm, an unreachable origin RPC, and a stale device observation each render as themselves rather than as a zero. |

## Reporting bugs

Include platform, device software version, boot mode, server host OS, Docker
version, image id, agent report, relevant console audit lines, and whether the
Guest Shell, IOx, or XR appmgr path is in use.
