<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Undeploy, retire and clean up devices

## What this is for

Undeploy removes the IRIS agent and leaves the device running. Staged images
stay. Use it when a device leaves the swarm or you replace hardware.

## In the Console

Undeploy runs from the deployment record, the record of what IRIS applied.

### Undeploy one device

1. Open **Inventory** and check the device's row.
2. Choose **Undeploy** in the toolbar. The teardown job starts.
3. Follow the job to the end and read its result.

### Adopt an agent that has no deployment record

A device running an agent with no record cannot be undeployed.

1. Choose **Adopt** and confirm.
2. IRIS audits the device, writes a fresh record, and undeploy then runs from it.

Catalyst 8000 series routers cannot be adopted. Use **Force**.

### Force undeploy

Use **Force** when the record is missing or does not match the device.

Force removes everything that carries the IRIS name: the IRIS EEM applets, the IRISQ logging discriminator with its bindings, `crypto pki trustpoint IRIS`, `ip http client secure-trustpoint IRIS`, the app-hosting stanza, and the staged IRIS files. It leaves your VLAN, SVI, VirtualPortGroup and NAT rules. The audit trail records `undeploy_forced`.

A record-driven undeploy verifies the device's processor-board identity
against the deployment record before it removes anything. Force has no record
to check that identity against, which is why its removal is scoped to
IRIS-named artifacts only, never your network configuration.

!!! warning "Force does not repair an IOx verification failure"
    Recover and reconcile the journal first: see [Recover from an interrupted job or damaged state](../admin-guide/recovery.md).

### Retire a device from the inventory

Delete revokes the device's credentials first. If that write fails, the delete stops and nothing else changes. The rest of the cleanup is best effort, and a partial cleanup is reported.

The device's address rows are deliberately **retained** until they age out, so
a revoked device stays denied whatever the sharing policy says, and the order
of cleanup cannot re-permit it by accident. Onboarding the same device again
clears those old rows before the fresh credential works.

!!! warning "Deleting inventory is not an undeploy"
    Undeploy first if you want the agent removed. Delete does not contact the device; it revokes credentials and retires the device's assignments, reports, records and jobs. Adding the same device id again does not bring that state back.

### Forget a changed SSH host key

A re-imaged device presents a new SSH host key, and sessions fail until you clear the old one.

1. Open the device's deployment details drawer and choose **Forget host key**.
2. Confirm. IRIS audits it as `device_forget_host_key`.

From a shell with access to the state volume, you can clear the entry yourself:

```bash
ssh-keygen -R '<device_ip>' -f '<state>/ssh/known_hosts'
```

## With the API

| Route | What it does |
| --- | --- |
| `POST /api/v1/devices/<id>/undeploy` | Starts the teardown job from the device's deployment record. Answers 409 with no record; send `{"force": true}` to run it anyway. |
| `POST /api/v1/devices/<id>/adopt` | Records an existing deployment. Needs `{"acknowledge_adopt": true}`; answers 409 if an active record exists. Routers cannot be adopted. |

Delete and Forget host key have their own routes. See [Console API](../reference/console-api.md).

## What you see

| What you see | What it means |
| --- | --- |
| `undeploy complete: <device-ip>` | The teardown job finished. On IOS-XR, an empty `iris-work/` directory is expected. |
| HTTP 207 | Part of the cleanup failed: a partial cleanup, not a success. |
| `needs-reconcile` | The deployment record is missing, drifted, or uncertain, so cleanup stopped. |
| `undeploy_forced` in the audit trail | The teardown ran with **Force**, planned from inventory. |

## What teardown removes on each management type

Management type is how the agent reaches the network: on its own address, on your management VLAN, or through the router. See [Choose a management type](../install/management-types.md).

| Management type | Teardown removes | Teardown leaves |
| --- | --- | --- |
| Routed | The IRIS VLAN and SVI, the IRIS VLAN in the app-hosting trunk's allowed list, and the agent with its files. | Any other VLAN on that trunk, and anything the record does not name as created by IRIS. |
| Inband | The app footprint (Guest Shell or the IOx app), the IRIS EEM applets, the agent files, and every global with the IRIS name: the IRISQ logging discriminator, `crypto pki trustpoint IRIS`, and `ip http client secure-trustpoint IRIS`. | Your VLAN, SVI, routes, and VRF. The VLAN stays in the trunk's allowed list. |
| Router routed and router NAT | The agent, the IRIS VirtualPortGroup and its app subnet, and the NAT rules IRIS created. | Device-wide NAT state, your routes, and any `ip nat outside` marking that existed before onboarding. |
| XR host | The recorded appmgr application and its package source, the agent RPM and runtime certificate, the contents of `iris-work/`, and torrent sidecars from the `harddisk:` root. | The router's networking configuration, the staged images, and the empty `iris-work/` directory. |

## Who owns the SCP server after an IOx undeploy

With no bind-mounted share, the IOx app uses the device's own SCP server to place a downloaded image.

| At undeploy | What happens to the SCP server |
| --- | --- |
| IRIS enabled it and confirmed that enable | A recorded undeploy disables it, checking first that no hosted apps remain. |
| The setting existed before onboarding, or this is an older deployment or a forced undeploy with no record | It is left unchanged. |
| The enable was interrupted with no confirmation | Confirm SCP is no longer needed, disable it on the device, then run the recorded undeploy again. |

A new onboarding is blocked while an older deployment still holds an SCP claim. See [Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](../install/iox.md).

## Uninstall from the device by hand

When you cannot reach the device through the Console, run its uninstall script.

| Platform | Script |
| --- | --- |
| Catalyst 9000 series switches, where the agent runs in Guest Shell | `device/device-uninstall.sh` |
| Catalyst 8000 series routers | `device/router-uninstall.sh` |
| The IOx app, on Industrial Ethernet 3000 series switches and on Catalyst 9000 series switches with app-hosting storage | `device/iox/uninstall.sh` |
| Cisco 8000 series and NCS routers, in the IOS-XR appmgr container | `device/xr-uninstall.sh` |

Arguments for each script are in [Helper commands](../reference/tools.md). On IOS-XR you can repeat an undeploy: it skips whatever is already gone.

## Related

- [Add and onboard devices](onboarding.md)
- [Work with many devices at once](devices.md)
- [Recover from an interrupted job or damaged state](../admin-guide/recovery.md)
- [Choose a management type](../install/management-types.md)
- [Helper commands](../reference/tools.md)
