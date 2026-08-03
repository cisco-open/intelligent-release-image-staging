<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Validation

Validate documentation, server behavior, device packaging, and lab behavior separately. A passing unit test suite is necessary but not enough for a network rollout.

## Automated tests

Run the Python tests:

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ device/test_verify_image.py -q
```

Run the Bats tests:

```bash
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ server/tests/*.bats
```

## Documentation build

The docs site builds clean from the repository root, with no reported issues.
For the commands and the pinned Zensical and Python versions, see
[Documentation loop](development.md#documentation-loop).

## Lab checklist

| Check | Expected result |
| --- | --- |
| Server starts | Console, catalog, tracker, artifact server, and telemetry ports are reachable. |
| Runtime uid owns the host paths | The age key file and the host `artifacts/` directory are owned by uid `10001`, and any volume carried over from a root-runtime release is migrated ([Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment)). The Console Images screen lists no file as `not readable by the server`. |
| Admin exists | Console login succeeds. |
| Image publishes | Catalog lists image id, hashes, and info hash. |
| Import publishes in place | A file already under the read-only image root imports from the Console, and the read-only root is unchanged: no copy of the image and no `.torrent` beside it. |
| Attachment recorded | Device shows routed, inband, router-routed, or router-nat; onboarding records an applied receipt. |
| Installer runs | Device has trustpoint, Guest Shell or IOx app, bootstrap, and agent config. |
| Inband preserves network | For inband, before/after `show running-config` shows the existing VLAN/SVI/gateway/VRF unchanged. |
| C8000v router path | `router-routed` and `router-nat` onboard, stage a verified image, and undeploy from their receipts. Swarm Map shows the device, and Grafana shows its telemetry when observability is enabled. |
| Assignment applies | Device reports the approved image id. |
| Download completes | Swarm state shows completed pieces. |
| Verification passes | Agent reports the staged file and IOS verify success. |
| Undeploy from receipt | Teardown targets only receipt-owned resources; router adoption is refused and requires re-onboarding. For `router-nat`, teardown flushes NAT translations before removing the NAT configuration, and the final verify reports no leftover IRIS NAT rule. |
| No activation occurs | Boot variables, install state, and reload state remain operator-controlled. |

Automated coverage for the attachment/receipt behavior lives in
`server/tests/test_deployment_receipts.py`, `server/tests/test_gui_fleet.py`,
the inband command-stream assertions in
`device/tests/test_device_uninstall.bats`, and the router install/teardown
command streams in `device/tests/test_router_install.bats` and
`device/tests/test_router_uninstall.bats`. See
[Management Type and VLAN Ownership](network-attachment.md).

## Reporting bugs

Include platform, IOS-XE version, boot mode, server host OS, Docker version, image id, agent report, relevant console audit lines, and whether the Guest Shell or IOx path is in use.
