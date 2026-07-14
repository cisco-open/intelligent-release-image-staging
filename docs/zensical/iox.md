<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path runs the agent as a Docker-based IOx application. It supports
ARM64 IE-3x00/IE-3400 style platforms and x86_64 Catalyst 9000 app hosting.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle. The
Guest Shell path remains available for Catalyst devices that support that agent
model. Select a writable IOS filesystem appropriate to the platform, such as
`sdflash:` on IE-3x00 or `usbflash1:` on C9300.

## Files

| File | Purpose |
| --- | --- |
| `device/iox/Dockerfile` | Builds the multi-architecture IOx agent container. |
| `device/iox/package.yaml` | ARM64 IOx package metadata. |
| `device/iox/package-amd64.yaml` | x86_64 IOx package metadata. |
| `device/iox/entrypoint.sh` | Starts the agent inside the application container. |
| `device/iox/build.sh` | Builds the IOx package. |
| `device/iox/install.sh` | Installs the IOx app on a target device. |
| `device/iox/uninstall.sh` | Removes the IOx app. |
| `device/iox/rebake_iris_tar.py` | Updates `iris.tar` packaging content. |

## Runtime behavior

The IOx agent follows the same catalog and staging model as the Guest Shell
agent. It downloads resumable swarm data under the CAF persistent directory
(`/iox_data/iris` on the validated C9300 runtime). Because that disk is not an
IOS filesystem root, the
container reaches IOS through SSH-to-self, SCP-pushes the verified scratch file
to `guest-share/iris`, and runs IOS `copy /verify` for the final placement.

`IRIS_TARGET_FS` optionally selects a filesystem prefix such as `sdflash:` or
`bootflash:`. The agent accepts it only when `show file systems` reports a
writable non-crash disk; otherwise it logs the fallback and retains automatic
platform selection. `device/iox/install.sh` exposes this as `TARGET_FS` and
defaults it to `sdflash:`.

## Build modes

```bash
# Docker image only
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh --image-only

# Docker image plus Cisco iris.tar package (requires ioxclient)
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out
```

The clean-clone build path downloads a pinned architecture-matched static
`aria2c` when no local bundle is available and fails if its SHA-256 digest
differs.

## Artifact handling

`iris.tar` is an operator-built artifact and belongs under `artifacts/` for serving. The server container serves the artifact but does not rebuild or mutate it automatically.
