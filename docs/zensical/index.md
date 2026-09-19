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
Catalyst 9000 series switches, or as an IOx app where the switch has
app-hosting storage. Industrial Ethernet 3000 series switches run the IOx app,
and Cisco 8000 series and NCS routers run the agent in IOS-XR appmgr.

!!! warning "Stage only"
    IRIS never installs or activates a staged software image, changes boot
    variables, or reloads a device. Onboarding deploys the IRIS agent, not the
    software image being staged.

## Where to start

| If you want to | Read |
| --- | --- |
| Set up IRIS on a host that has never run it | [Install IRIS](install/index.md) |
| Run IRIS every day | [Run IRIS day to day](user-guide/index.md) |
| See how IRIS works | [How IRIS works](architecture/index.md) |
| Look up one value, route, file format or term | [Look up a setting, route or term](reference/index.md) |

## Common tasks

| Task | Page |
| --- | --- |
| Deploy the server | [Install on one Docker host](install/one-docker-host.md) |
| Onboard a device | [Add and onboard devices](user-guide/onboarding.md) |
| Stage your first image | [Stage your first image](user-guide/first-image.md) |
| Check staging status | [Assign images and check staging status](user-guide/assignments.md) |
| Schedule a maintenance window | [Schedule maintenance windows](user-guide/scheduling.md) |
| Work out why something failed | [Troubleshoot: symptoms and first steps](user-guide/troubleshooting.md) |
