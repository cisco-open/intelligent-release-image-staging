<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Add and onboard devices

You add a device to the inventory, then onboard it. Onboarding installs the
device agent. Images come afterwards, in
[Assign images and check staging status](assignments.md).

## Before you onboard

Each device needs three things:

- A management type: how the agent reaches the network, on its own address, on
  your management VLAN, or through the router. See
  [Choose a management type](../install/management-types.md).
- The network fields that management type asks for, such as the VLAN, the agent
  addresses, or the VirtualPortGroup number.
- A credential profile, so the installer can log in to the device.
- The platform requirements in
  [What a device needs before onboarding](../install/device-requirements.md).

## Prepare the inventory

Add devices one at a time in the Console, or import a CSV file. Use
`fleet/devices.csv.example` as the template. The header row is validated:

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,role,platform
```

Every row declares a `management_type` of `routed`, `inband`, `router-routed`,
`router-nat`, or `xr-host`. The columns each type fills are listed in
[Data formats and states](../reference/state-and-data.md). The optional `role`
column sets which group of devices this one shares pieces with; see
[Control which devices share with each other](roles.md).

Read the file before you import it. Check the `management_type` of each row,
and for inband rows check that the VLAN, the SVI (switch virtual interface) and
the gateway you name already exist.

!!! warning

    Keep passwords, tokens and image binaries out of `fleet/devices.csv`.
    Credentials live in the server's secret store.

### Assign a credential profile

An imported device cannot be onboarded until you give it a profile.

1. Open **Inventory** and select the imported rows.
2. Pick a profile in the *credential for selected* dropdown.
3. Press **Apply**. The rows become onboardable at once.

A re-import replaces a device's network fields and keeps its credential
profile. A CSV that lists a `device_id` twice is rejected as a whole.

## In the Console

1. Open **Inventory → Add Device**.
2. Choose the **Management type**: Routed, Inband, Router routed, Router NAT,
   or XR host. It controls which network fields the form shows.
3. Choose the **Model series**: IE Switches, IR Routers, Catalyst Routers,
   Catalyst Switches, NCS, or Cisco 8000 Series. It narrows the **Agent
   install** choices. The API and CSV take exact model numbers too.
4. Choose **Agent install**. On Catalyst 9000 series switches the agent runs in
   Guest Shell, or in the IOx app on switches with app-hosting storage.
   Catalyst 8000 series routers offer Guest Shell or IOx, and Cisco 8000 series
   and NCS routers use the IOS-XR appmgr installer.
5. For Router routed and Router NAT, fill in the VirtualPortGroup number and
   the app addressing. Router NAT also asks for the outside interface.
6. Select the device and press **Onboard**. The job starts and streams its
   progress.

A device with no management type reads:

```text
Inventory only — management type not chosen
```

Edit that row into one of the management types before you onboard it.

A row imported under the deprecated `vlan`/`guest_ip` CSV headers can sit
unclassified the same way. IRIS onboards it only once its complete historical
routed tuple, `device_id`, `device_ip`, VLAN, SVI address and mask, and app
address, is valid. An incomplete row fails before any onboarding job,
enrollment credential or device connection is created; edit it into one of the
current management types first.

For its first contact the agent uses an enrollment token the server mints for
that one device, then obtains a credential of its own. Wait for an agent
heartbeat before you assign an image to it.

## With the API

| Route | What it does |
| --- | --- |
| `POST /api/v1/devices` | Adds one device to inventory. |
| `POST /api/v1/devices/import-csv` | Imports an inventory CSV. |
| `POST /api/v1/devices/{device_id}/onboard` | Resolves the plan, checks for a conflicting deployment record, and returns a job id. |
| `GET /api/v1/onboard/jobs` | Lists onboard jobs and reports how many may run at once as `max_concurrent`. |

Payloads and conflict checks are in [Console API](../reference/console-api.md).

## What you see

An onboard job reports the same progress for Guest Shell, IOx and IOS-XR:
**Prepare → Deploy/remove IRIS agent → Finalize**. The heading names the series
and the installer. A finished job reads `Onboard completed.` or
`Undeploy completed.`

For installer steps, timings and command output, select **Detailed logs before
starting** Onboard or Undeploy, or send `{"log": true}` through the API. The
job confirms `Detailed logs enabled.`, and `aria2c.log` is turned on for IOx
and IOS-XR. Guest Shell logging is set through `iris_log`; see
[Device agent configuration](../reference/device-configuration.md).

### Device activity

**Inventory → Activity** opens recent jobs in a side panel. Choose **log** on a
job to read its output; **Close** or **Esc** closes the viewer. **Abort** asks
for confirmation, then cancels a queued job or stops a running installer, which
can leave the agent partly configured: onboard the device again or undeploy it.

### Deployment logs

**Monitoring → Deployment logs** keeps the installer output of every finished
onboard and undeploy job on the server. The newest 200 are kept.

The table lists each log's finish time, device, action, result and size. A
histogram bins them over the window you pick: 24h, 7d (the default), 30d, 90d
or All. Drag a range across it to filter the table, narrow it further with the
search box and the Action and Result pickers, and choose **view** to read a
log. Widen the range if a job you expect is missing. The same list, filtered to
one device, sits on that device's panel; see
[Work with many devices at once](devices.md).

Each line starts with its elapsed offset from the start of the job:

```text
[+   42.3s] [4/7] waiting for Guest Shell
```

## Onboard many devices at once

Preflight runs when the job runs, so a large batch returns a job per device
promptly. Router preflight adds read-only collision, identity and NAT checks. A
failure fails that job only; the other queued jobs keep running.

A router's deployment record additionally binds the management IP and the
processor-board identity, and owns only collision-free named globals and the
`guest-share` resources it created. That binding is how IRIS proves what it
owns on a shared router without touching your existing configuration.

The server limits how many onboard jobs run at the same time. The limit and its
variable are in [Server configuration](../reference/server-configuration.md).

To onboard a group of devices inside a maintenance window, see
[Schedule maintenance windows](scheduling.md).

## When a device cannot be reached

Every installer probes the device first, and a device IRIS cannot reach fails
the job at once:

```text
cannot reach device <ip> — ping/SSH probe failed; check the device IP and credentials
```

Every rejection is shown in the Console and recorded in Audit.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The job fails at once and names the device address | Wrong address, wrong credentials, or no network path | Correct the address or the credential profile, then onboard again |
| The row cannot be onboarded and reads inventory only | The row has no management type | Choose a management type and fill its network fields, then onboard |
| The job is refused because the device already carries IRIS configuration | A deployment is still in place | Undeploy it first, then onboard again |
| The job is refused because the device is busy | Another job is running on that device | Wait for that job to finish, then onboard again |

More symptoms: [Troubleshoot: symptoms and first steps](troubleshooting.md).

## First install of a new package version

This applies to IOx. The first time a device sees a given package, the IOx
runtime loads its docker layers into the image cache before the app can
activate. A package the device has run before activates in seconds. The
controller allows 300 seconds for each install, activation and start phase by
default, inside a session deadline of 7,200 seconds. A failed wait names the
step it was waiting on in the job log.

An onboard that fails at activation leaves the app-hosting configuration in
place. Press **Onboard** again, or submit `POST /api/v1/devices/<id>/onboard`:
the installer removes the incomplete app and tries again. An app that is
`RUNNING` is a live deployment and needs an undeploy first.

## Related

- [What a device needs before onboarding](../install/device-requirements.md)
- [Choose a management type](../install/management-types.md)
- [Assign images and check staging status](assignments.md)
- [Work with many devices at once](devices.md)
- [Undeploy, retire and clean up devices](undeploy.md)
