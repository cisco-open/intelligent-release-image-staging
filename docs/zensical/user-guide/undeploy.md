<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Undeploy, retire and clean up devices

## What this is for

Undeploy removes the IRIS agent and leaves the device running. Use it when a
device leaves the swarm or you replace hardware. Undeploy itself leaves
assignments and root image files. Unassigning first can remove files IRIS
downloaded on IOS-XR; see
[What happens to an image you unassign](assignments.md#unassigned-image-park).

On IOS-XR, undeploy verifies the IRIS peer identity's public manifest and
certificate layout before removing its private key, enrollment lock and active
manifest. Public certificate directories remain. The next onboarding creates
a fresh peer identity for the selected server.

## In the Console

Undeploy runs from the deployment record, the record of what IRIS applied.

### Undeploy one device

1. Open **Inventory** and check the device's row.
2. Choose **Undeploy** in the toolbar and check **reviewed devices**.
3. Choose **Start undeploy** and confirm. Follow the job in **Activity**.

### Adopt an agent that has no deployment record

A device running an agent with no record cannot run a record-driven undeploy.
Adopt it first, or use Force undeploy instead.

1. Select the device, choose **More actions → Adopt** and confirm.
2. IRIS records the action in the audit trail and creates a deployment record
   from the saved inventory. Check that inventory against the device first;
   adoption does not inspect the device.

Catalyst 8000 series routers use Force instead (see
[Supported devices](../install/supported-devices.md)).

### Force undeploy

Use **Force** when the record is missing or does not match the device.

Force removes the IRIS agent, its named configuration and its support files.
For Guest Shell on Catalyst 8000 series routers, it also removes
VirtualPortGroups with an IRIS ownership description, IRIS-named NAT rules
and static NAT mappings inside those marked subnets. Unmarked operator
interfaces and unrelated NAT rules stay in place. The audit trail records
`undeploy_forced`.

A record-driven undeploy verifies the device's processor-board identity
against the deployment record before it removes anything. Force has no record
to check that identity against. Review the selected device carefully: Force
uses IRIS names and ownership markers on the device to identify its scope.

!!! warning "Force does not repair an IOx verification failure"
    Recover and reconcile the journal first: see [Recover from an interrupted job or damaged state](../admin-guide/recovery.md).

### Revoke a device certificate

Revoke a device's peer certificate when it may have been copied or the device
should no longer join encrypted peer transfers. The inventory row and staged
images stay in place.

1. Open **Inventory** and click the device name.
2. In **Device certificate**, choose **Revoke device certificate**.
3. Review the named device and confirm. Revocation applies to every certificate
   issued for that device identity and cannot be undone.
4. Choose **Check status** to read the saved result. If the request result is
   unknown, this checks the server without sending another revocation.

Peer TLS must be required before the action is available. **Not revoked** means
no revocation is recorded; it does not prove that a certificate has been issued.
**Revoked** confirms the saved decision, not enforcement by every peer.
Updated peers refresh the revocation list or stop encrypted peer connections
when it expires, within five minutes. Clients without this support can still
accept the old certificate. For immediate isolation, block the device's network access
as well. **Certificate and device report details** shows the last reported
list revision and time. This is one device's report, not proof for every peer.

### Return a device after revocation

First secure the device and decide that it can be trusted again. Keep its
inventory row; you can return it under the same device name.

1. Open the device details and choose **Allow fresh onboarding**. Review the
   device and confirm. Its old certificates remain permanently revoked.
2. Close the panel and select that device in **Inventory**. If the IRIS agent
   is still installed, choose **Undeploy** and wait for completion.
3. Choose **Onboard** and follow the job in **Activity**. Onboarding creates
   fresh credentials and a new private key and certificate identity.
4. Check that onboarding completes and the device reports in again.

Approval alone does not change the device or restore access. **Fresh onboarding
required** remains until fresh credentials are created. A new identity does
not prove that the whole onboarding job completed; check **Activity**.
You do not need to copy certificate or key files yourself.

### Retire a device from the inventory

Delete revokes the device's credentials first. If that write fails, the delete stops and nothing else changes. The rest of the cleanup is best effort, and a partial cleanup is reported.

Select the devices, choose **More actions → Delete** and confirm the named
targets. Completed retirements leave the selection. Partial cleanup and unknown
results stay selected for review, even when the row has left Inventory. Check
the named cleanup steps and the audit trail before retrying.

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
| `POST /api/v1/devices/<id>/adopt` | Records an existing deployment. Needs `{"acknowledge_adopt": true}`; answers 409 if an active record exists, or if the device is a router (see Adopt an agent that has no deployment record above). |

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
| XR host | The recorded appmgr application and its package source, the agent RPM and runtime certificate, the contents of `iris-work/`, the active peer identity after ownership checks, and torrent sidecars from the `harddisk:` root. | The router's networking configuration, any image files still on `harddisk:`, public peer-certificate generations, and the empty `iris-work/` directory. |

## Who owns the SCP server after an IOx undeploy

With no bind-mounted share, the IOx app uses the device's own SCP server to place a downloaded image.

| At undeploy | What happens to the SCP server |
| --- | --- |
| IRIS enabled it and confirmed that enable | A recorded undeploy disables it, checking first that no hosted apps remain. |
| The setting existed before onboarding, or this is an older deployment or a forced undeploy with no record | It is left unchanged. |
| The enable was interrupted with no confirmation | Confirm SCP is no longer needed, disable it on the device, then run the recorded undeploy again. |

A new onboarding is blocked while an older deployment still holds an SCP claim. See [Prepare Industrial Ethernet switches with app hosting, Catalyst 9000 and 8000 devices for the IOx app](../install/iox.md).

## Uninstall from the device by hand

When the Console is unavailable, run the matching Guest Shell or IOS-XR
uninstall script from the server host.

| Platform | Script |
| --- | --- |
| Catalyst 9000 series switches, where the agent runs in Guest Shell | `device/device-uninstall.sh` |
| Catalyst 8000 series routers | `device/router-uninstall.sh` |
| Cisco 8000 series and NCS routers, in the IOS-XR appmgr container (NCS-540 undeploy is not yet lab-validated; see [Supported devices and platforms](../install/supported-devices.md)) | `device/xr-uninstall.sh` |

For an IOx app, use **Undeploy** in the Console, the undeploy API, or
`submit-uninstall` in the [IOx control CLI](../reference/tools.md#iox-control-cli).
The IOx shell script requires the controller's private channel and cannot run
standalone.

See [Helper commands](../reference/tools.md). On IOS-XR you can repeat an
undeploy: it skips whatever is already gone.

## Related

- [Add and onboard devices](onboarding.md)
- [Work with many devices at once](devices.md)
- [Recover from an interrupted job or damaged state](../admin-guide/recovery.md)
- [Choose a management type](../install/management-types.md)
- [Helper commands](../reference/tools.md)
