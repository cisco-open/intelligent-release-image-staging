<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Stage your first image

Take one image to one device. Do this once, before you stage a fleet.

Staging means copying an image to the device's flash and checking its hash,
then stopping. The device keeps running its current software until you install
the image yourself.

## Before you start

- A running server and a Console sign-in. See [Install IRIS](../install/index.md).
- Instruction signing turned on. An instruction is the signed message the
  server sends a device saying which images to stage and how. See
  [Turn on instruction signing](../install/activate-signing.md).
- The device packages published, and one device that meets the requirements.
  See [Build and publish the device packages](../install/device-packages.md)
  and [What a device needs before onboarding](../install/device-requirements.md).
- The image file, and the Bulk Hash for it, the checksum Cisco publishes for
  an image.

## In the Console

1. **Publish the image.** In **Images**, upload the file, or choose **Import
   from disk** for a file already on the server. The image job finishes and the
   image appears in the catalog. See [Publish and verify images](images.md).
2. **Check the image against the Bulk Hash.** Refresh the Bulk Hash feed, or
   import a feed file when the server has no route to the internet. A mismatch
   puts the image in quarantine, an image that failed the Cisco hash check and
   is held back from devices.
3. **Add the device.** In **Devices**, choose **Add Device**. Pick the
   platform, the series, and the management type, which is how the agent
   reaches the network: on its own address, on your management VLAN, or through
   the router. Add a credential profile, the stored account the server uses to
   reach the device. On Catalyst 9000 series switches the agent runs in Guest
   Shell; the IOx app is the alternative on switches with app-hosting storage.
   Cisco 8000 series and NCS routers use `xr-host` and `xr-appmgr`, with the app
   address, VLAN, SVI, VPG, and NAT fields empty. See
   [Choose a management type](../install/management-types.md).
4. **Onboard the device.** Start onboarding and watch the job to the end. It
   installs the device agent. Read a failed job before you retry it. See
   [Add and onboard devices](onboarding.md).
5. **Wait for the first heartbeat.** Assign nothing until the device has
   reported in once.
6. **Assign the image.** Select the image for the device. The agent downloads
   it from the server and from peers, checks it against the catalog hash, and
   places it in flash.
7. **Read the staged report.** The device reports a staged state for the image.
   That state, not the transfer counters, is the answer. See [Assign images and
   check staging status](assignments.md).

!!! warning

    If the device already runs an IRIS app, remove it first through its
    deployment record, not with a forced cleanup. See
    [Undeploy, retire and clean up devices](undeploy.md).

## With the API

| Step | Route |
| --- | --- |
| Assign the image | `POST /api/v1/devices/{device_id}/assign` |
| Read staging status | `GET /api/v1/devices/{device_id}/reports` |

The ordered `image_ids` list replaces the device's assignment, so send every
image you still want assigned. See [Console API](../reference/console-api.md).

## When the agent reports verifier_missing

`verifier_missing` means the device would check the signature but the tool to do
so is not installed. The device still stages the image. Check signed-instruction
status separately from staging status.

## When the image never reaches the device

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Onboarding fails on every device | The server cannot stamp instructions yet | Finish [Turn on instruction signing](../install/activate-signing.md), then retry the job |
| Onboarding fails on one device | The connectivity fields or the credential profile do not match the management type | Read the job output, correct the device entry, then onboard again |
| The device onboards but no report appears | No assignment reached the agent, or the agent cannot reach the server | Confirm the assignment, then check the device's route to the server |
| The image is published but no device gets it | The file failed the Cisco hash check | Refresh the Bulk Hash feed, then compare the published checksum with your file |

## Related

- [Publish and verify images](images.md)
- [Add and onboard devices](onboarding.md)
- [Assign images and check staging status](assignments.md)
- [Monitor transfers and device reports](monitoring.md)
- [Troubleshoot: symptoms and first steps](troubleshooting.md)
