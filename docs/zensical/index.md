<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IRIS documentation

IRIS, short for Intelligent Release and Image Staging, stages Cisco images and
patches on your devices. Staging means copying an image to the device's flash
and checking its hash, then stopping. The device keeps running its current
software until you install the image yourself. Devices take pieces of an image
from each other, not from the server alone. The agent runs in Guest Shell on
Catalyst 9000 series switches and Catalyst 8000 series routers, or as the IOx
app on switches with app-hosting storage and on Catalyst 8000 series routers.
Industrial Ethernet switches with app hosting run the IOx app, and Cisco 8000
series and NCS routers run the agent in IOS-XR appmgr. See [Supported devices and platforms](install/supported-devices.md) for which
platforms are validated.

!!! warning "Stage only"
    IRIS never installs or activates a staged software image, changes boot
    variables, or reloads a device. Onboarding deploys the IRIS agent, not the
    software image being staged.

## Where to start

| If you want to | Read |
| --- | --- |
| Plan hosts and device onboarding | [Install IRIS](install/index.md) |
| Set up IRIS with automatic signing and package preparation | [Install the Ubuntu .deb package](install/managed-package.md) |
| Run IRIS every day | [Run IRIS day to day](user-guide/index.md) |
| Maintain deployments, backups, credentials and signing keys | [Keep IRIS running](admin-guide/index.md) |
| See how IRIS works | [How IRIS works](architecture/index.md) |
| Look up one value, route, file format or term | [Look up a setting, route or term](reference/index.md) |

## Common tasks

| Task | Page |
| --- | --- |
| Deploy on one Docker host, separate hosts or Kubernetes | [Install the Ubuntu .deb package](install/managed-package.md) |
| Onboard a device | [Add and onboard devices](user-guide/onboarding.md) |
| Stage your first image | [Stage your first image](user-guide/first-image.md) |
| Check staging status | [Assign images and check staging status](user-guide/assignments.md) |
| Schedule a maintenance window | [Schedule maintenance windows](user-guide/scheduling.md) |
| Deploy a new IRIS release | [Deploy a new release](admin-guide/upgrade.md) |
| Work out why something failed | [Troubleshoot: symptoms and first steps](user-guide/troubleshooting.md) |
