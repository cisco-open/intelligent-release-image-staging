<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Work with many devices at once

The Devices table acts on a group of devices in one step: onboard, undeploy, set
a credential or a role, or replace the images they stage.

## In the Console

### Select devices

1. Open **Inventory**.
2. Click a row to select it, and click again to deselect it. Selected rows are
   highlighted and show the bulk actions.
3. Read the selected count before you act on it.

**Select page** and **Clear page selection** act on the visible page, **Select
all N matching devices** takes every device the filter matches, and **Cancel**
clears everything. A selection follows device IDs across pages.

### Search and filter

Search by device, IP or model. **Filters** opens the structured filters, and
**Reset** clears them. A filter applies on the server, so it covers every
matching device, not only the page in front of you. **Device series** lists IE
Switches, IR Routers, Catalyst Routers, Catalyst Switches, NCS and Cisco 8000
Series, with legacy and unknown categories retained. Hover a series cell to see
the stored model. For the role filter and **Set role**, see
[Control which devices share with each other](roles.md).

### Run a toolbar action

| Action | Effect |
| --- | --- |
| Onboard | Queues an agent deployment for each selected device. |
| Undeploy | Removes the agent using its deployment record. |
| Adopt | Records a reviewed existing deployment; router adoption is not supported. |
| Delete | Retires inventory and server-side device state. |
| Set credential or role | Updates the selected devices. A role change previews first, so read the impact counts before you commit it. |
| Assign images | Replaces each selected device's image set with the checked images. |

!!! warning

    Delete leaves the agent on the device. Undeploy the devices first, as
    described in [Undeploy, retire and clean up devices](undeploy.md).

The toolbar acts on every selected row. Use **Adopt** when an agent is already
on the device and no record covers it. **Schedule…** targets the current filter,
not the rows you selected, see [Schedule maintenance windows](scheduling.md).

### Assign a set of images

1. Select the devices and click **Assign images**. The picker opens pre-checked
   with the images every selected device already holds.
2. Check the images the whole selection should stage, up to ten.
3. Apply. A selection whose assignments differ is flagged, then confirmed.

!!! warning

    Applying replaces each device's whole set and drops anything left
    unchecked, so it can also remove assignments. An empty set unassigns every
    image on the selected devices. See
    [Assign images and check staging status](assignments.md#unassigned-image-park).

## With the API

For the same work from a script, see [Automate with the API](automation.md).
The device routes and their schemas are in [Console API](../reference/console-api.md).

## What you see

### The deployment details drawer

Each row has a **ⓘ Deployment details** control. It opens a read-only drawer
that lists every image assigned to that device. **Esc** or **✕** closes it.

| State | What it means |
| --- | --- |
| `ready` | Staged and verified. |
| `error` | The agent reported a failure. |
| `staging` | The agent is working on the image. |
| `pending` | Staging has not been reported. |

For one image, the drawer shows the agent's detailed state and error. For
several, the shared error appears in **Last reported error**. The Status column
shows `N of M image(s) failed`.

### The deployment record

Below the images table, the drawer shows the record id and its state: `active`,
`removed`, `superseded`, `needs-reconcile` or `abandoned`. An `abandoned` record
no longer describes a device IRIS manages, and a fresh onboard still works. A
device with no record names adopt or a fresh onboard as the fix.

It also shows the preflight result and what the onboard applied: the management
type, the owned management VLAN or VPG (VirtualPortGroup), the SVI (switched
virtual interface) and app addressing, the NAT interface, the swarm port, the
recorded model, the **Agent install** choice and the device identity. Management
type is how the agent reaches the network: on its own address, on your
management VLAN, or through the router, see
[Choose a management type](../install/management-types.md). **Agent install** is
where the agent runs: on Catalyst 9000 series switches the agent runs in Guest
Shell, and the IOx app is the alternative on switches with app-hosting storage.

The drawer ends with that device's deployment logs, viewable in place. Logs are
keyed on the device id and survive a delete. A run from a box registered earlier
under this name is labeled **previous device**.

## When part of a bulk action fails

A bulk action reports each success and refusal instead of failing the whole
batch. The status line counts the successes and names the devices that refused.
HTTP 207 means partial cleanup. HTTP 429 means the server rejected the request
on admission, and the response carries `Retry-After`. Those limits are in
[Console API](../reference/console-api.md). For a refusal you cannot place, see
[Troubleshoot: symptoms and first steps](troubleshooting.md).

## Related

- [Add and onboard devices](onboarding.md)
- [Assign images and check staging status](assignments.md)
- [Undeploy, retire and clean up devices](undeploy.md)
