<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Helper commands

Scripts for tasks outside the Console and the `/api/v1` API.

## Publish an image from the command line

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

Creates the catalog entry and torrent, and starts seeding. Run inside the server container. See [Publish and verify images](../user-guide/images.md).

## Apply assignments in bulk

```bash
tools/apply-assignments.sh [--dry-run] [csv]
```

| Flag | Effect |
| --- | --- |
| `--dry-run` | Checks every row without assigning anything. |
| `[csv]` | Path to a CSV file. Defaults to `fleet/assignments.csv`. |

Run on the server host. See [Work with many devices at once](../user-guide/devices.md).

## Build and check IOx packages

| Helper | Purpose | Flags |
| --- | --- | --- |
| `tools/provision-iox-packages.sh` | Builds and stages both architecture packages. | none |
| `tools/stage-iox-package.sh` | Builds one architecture's package. | `--arch amd64\|arm64` (default `amd64`), `--artifacts-dir <dir>` |
| `tools/check-package-freshness.sh` | Checks the served packages against provenance and the certificate. | `--rebuild` |

Run on the Compose host once the server is healthy. `amd64` targets Catalyst 9000 series switches with app-hosting storage, where IOx is the alternative to the Guest Shell agent. `arm64` targets Industrial Ethernet 3000 series switches and IR 1100 and 1800 series routers.

!!! warning
    A package carries no certificate. Rotating the certificate needs devices re-onboarded, not a rebuild. See [Rotate credentials and certificates](../admin-guide/rotations.md) and [Build and publish the device packages](../install/device-packages.md).

## IOx control CLI

```bash
docker compose -f server/docker-compose.yml exec -w /opt/iris/server iris \
  python3 iox_verification.py <operation> [arguments] [--wait [--wait-timeout <seconds>]]
```

| Operation | Arguments | Does |
| --- | --- | --- |
| `submit-install` | `--device-id <id>` | Queues the device's onboard. |
| `submit-uninstall` | `--device-id <id>` `[--force-agent-only]` | Queues the device's undeploy. |
| `recover` | `--device-id <id>` | Replays the device's outstanding verification step. |
| `reconcile-enabled` | `--record-id <id>` `--transaction-id <hex32>` `--revision <n>` `--acknowledge-external-resolution` | Closes a recovery record once you restore app signature verification by hand. |
| `job` | `--job-id <hex16>` | Reads a job, or waits for it with `--wait`. |

`--wait-timeout` is 1 to 7200 seconds (default 7200). Exit status is `0` running or done, `2` error or refused, `3` needs reconciliation, `4` timeout or transport failure, `5` internal fault, `130` cancelled. Job log lines are in the Console or `GET /api/v1/onboard/jobs/<id>`. See [Recover from an interrupted job or damaged state](../admin-guide/recovery.md).

## Create a torrent by hand

```bash
ANNOUNCE_TOKEN=... tools/make-torrent.sh <file> <tracker-host>
```

Requires an HTTPS tracker announce URL carrying a nonempty `announce_token` or `key` value. See [Network ports and flows](../architecture/network-ports.md).

## Rotate or revoke a device's instruction key

```bash
iris-instr-key rotate --no-overlap <device_id>
```

```bash
iris-revoke <device_id>
```

!!! warning
    Revocation blocks catalog access even if the device's last report shows trusted. Never rotate a revoked device's key to spare it. See [Rotate credentials and certificates](../admin-guide/rotations.md).

## Remove IRIS from a device

| Platform | Script |
| --- | --- |
| Guest Shell | `device/device-uninstall.sh` |
| Catalyst 8000 series routers (IOS-XE) | `device/router-uninstall.sh` |
| IOx | `device/iox/uninstall.sh` |
| IOS-XR appmgr | `device/xr-uninstall.sh` |

!!! warning
    Does not reload the device or delete a staged image. See [Undeploy, retire and clean up devices](../user-guide/undeploy.md).

## Check API coverage before a change

`tools/api-exercise.py` exercises the public Console API against an isolated, non-production deployment. Its mutation mode creates and retires synthetic devices and needs an empty inventory.

!!! warning
    Run only against a deployment you can test freely, never production. See [tools/api-exercise.py](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/api-exercise.md) for the full reference.
