<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Run IRIS day to day

Find your task below and do it. New to IRIS? Read [Find your way around the
Console](console.md), then [Stage your first image](first-image.md).

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot
    variables. See [IRIS documentation](../index.md).

## What you do every day

List your devices, give each one a credential profile, and onboard each. Assign
images, and the agent stages them. Work in the Console, or call `/api/v1`, as
in [Automate with the API](automation.md).

## Common tasks

| Task | Pages, in order |
| --- | --- |
| Stage one image to one device | [Stage your first image](first-image.md) |
| Add an image and check its Bulk Hash | [Publish and verify images](images.md) |
| Add a device and install the agent | [Add and onboard devices](onboarding.md) |
| Stage an image to many devices in a maintenance window | [Publish and verify images](images.md), [Add and onboard devices](onboarding.md), [Work with many devices at once](devices.md), [Assign images and check staging status](assignments.md), [Schedule maintenance windows](scheduling.md), [Monitor transfers and device reports](monitoring.md) |
| Find out why a device is not staging | [Troubleshoot: symptoms and first steps](troubleshooting.md), then [Recover from an interrupted job or damaged state](../admin-guide/recovery.md) |
| Limit which devices share pieces with which | [Control which devices share with each other](roles.md) |

## Pages in this guide

**Start here:** [Find your way around the Console](console.md) · [Stage your first image](first-image.md)

**Everyday tasks:** [Publish and verify images](images.md) · [Add and onboard devices](onboarding.md) · [Work with many devices at once](devices.md) · [Undeploy, retire and clean up devices](undeploy.md) · [Assign images and check staging status](assignments.md) · [Schedule maintenance windows](scheduling.md) · [Control which devices share with each other](roles.md) · [Automate with the API](automation.md)

**Monitoring:** [Monitor transfers and device reports](monitoring.md) · [Export telemetry](telemetry-export.md) · [Import the Splunk and Grafana dashboards](dashboards.md) · [Send telemetry to Splunk](splunk.md) · [Search IRIS data in Splunk](splunk-searches.md)

**Maintenance:** [Upgrade to a new release](../admin-guide/upgrade.md) · [Back up and restore](../admin-guide/backups.md) · [Routine maintenance tasks](../admin-guide/maintenance.md) · [Rotate credentials and certificates](../admin-guide/rotations.md) · [Replace or recover signing keys](../admin-guide/instruction-keys.md)

**Troubleshooting:** [Troubleshoot: symptoms and first steps](troubleshooting.md) · [Recover from an interrupted job or damaged state](../admin-guide/recovery.md)
