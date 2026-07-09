<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path targets Catalyst IE-3x00 and IE-3400 style platforms where the agent runs as a Docker-based IOx application instead of a Guest Shell process.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle and stages images to `sdflash:`. Use the Guest Shell path for Catalyst 9300 devices that support the Guest Shell agent model.

## Files

| File | Purpose |
| --- | --- |
| `device/iox/Dockerfile` | Builds the aarch64 IOx agent container. |
| `device/iox/package.yaml` | IOx package metadata. |
| `device/iox/entrypoint.sh` | Starts the agent inside the application container. |
| `device/iox/build.sh` | Builds the IOx package. |
| `device/iox/install.sh` | Installs the IOx app on a target device. |
| `device/iox/uninstall.sh` | Removes the IOx app. |
| `device/iox/rebake_iris_tar.py` | Updates `iris.tar` packaging content. |

## Runtime behavior

The IOx agent follows the same catalog and staging model as the Guest Shell agent. The platform-specific difference is the IOS command path: the container reaches IOS through SSH-to-self and stages the final verified image to `sdflash:`.

## Artifact handling

`iris.tar` is an operator-built artifact and belongs under `artifacts/` for serving. The server container serves the artifact but does not rebuild or mutate it automatically.

