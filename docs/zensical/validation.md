<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Validation

Validate documentation, server behavior, device packaging, and lab behavior separately. A passing unit test suite is necessary but not enough for a fleet rollout.

## Automated tests

Run the Python tests:

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ device/test_verify_image.py -q
```

Run the Bats tests:

```bash
bats device/test_guestshell_start.bats device/tests/ device/iox/tests/ server/tests/*.bats
```

## Documentation build

Build the docs site:

```bash
python3 -m venv /tmp/iris-docs-venv
/tmp/iris-docs-venv/bin/pip install -r requirements-docs.txt
/tmp/iris-docs-venv/bin/zensical build
```

Serve it locally during authoring:

```bash
/tmp/iris-docs-venv/bin/zensical serve
```

## Lab checklist

| Check | Expected result |
| --- | --- |
| Server starts | Console, catalog, tracker, artifact server, and telemetry ports are reachable. |
| Admin exists | Console login succeeds. |
| Image publishes | Catalog lists image id, hashes, and info hash. |
| Attachment recorded | Device shows its management type (routed or inband); onboarding records an applied receipt. |
| Installer runs | Device has trustpoint, Guest Shell or IOx app, bootstrap, and agent config. |
| Inband preserves network | For inband, before/after `show running-config` shows the existing VLAN/SVI/gateway/VRF unchanged. |
| Assignment applies | Device reports the approved image id. |
| Download completes | Swarm state shows completed pieces. |
| Verification passes | Agent reports the staged file and IOS verify success. |
| Undeploy from receipt | Teardown targets only receipt-owned resources; a pre-receipt device is adopted first. |
| No activation occurs | Boot variables, install state, and reload state remain operator-controlled. |

Automated coverage for the attachment/receipt behavior lives in
`server/tests/test_deployment_receipts.py`, `server/tests/test_gui_fleet.py`,
and the inband command-stream assertions in
`device/tests/test_device_uninstall.bats`. See
[Management Type and VLAN Ownership](network-attachment.md).

## Reporting bugs

Include platform, IOS-XE version, boot mode, server host OS, Docker version, image id, agent report, relevant console audit lines, and whether the Guest Shell or IOx path is in use.

