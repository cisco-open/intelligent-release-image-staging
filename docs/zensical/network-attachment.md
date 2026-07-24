<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Management Type And VLAN Ownership

IRIS supports two explicit management type models for the staging agent. The
choice is per device, recorded in inventory, and — critically — determines what
IRIS is allowed to create and remove on the device.

> **Stage-only, network-preserving.** IRIS distributes, verifies, and stages
> images. It never installs, activates, reloads, changes boot variables, or
> mutates running software state. Inband additionally never creates, changes, or
> removes the operator's network.

## Routed — IRIS-managed app network

Routed attachment uses a **dedicated IRIS VLAN and SVI**. Onboarding is
create-only: preflight requires the proposed VLAN/SVI to be absent, the applied
receipt records the resources IRIS created, and teardown removes exactly those.
IRIS never silently adopts a pre-existing VLAN or SVI.

## Inband — existing management VLAN

Inband attachment connects the staging agent — Guest Shell or an IOx app — to an
**existing management VLAN**. IRIS
does not create, configure, select, claim ownership of, or delete that VLAN, its
SVI, gateway, routes, or VRF. The operator-owned SVI (and any VRF it belongs to)
supplies routing; preflight only proves the existing topology can reach IRIS.

The supported inband cells:

| Attachment | Addressing | Platform | Status |
| --- | --- | --- | --- |
| Routed | static | Guest Shell / IOx | supported (receipt/preflight hardened) |
| Inband | static | Guest Shell | supported |
| Inband | static | IOx (IE-3x00, C9300) | supported |
| Inband | DHCP | any | rejected — separate capability gate |

Inband install and teardown command streams never contain `vlan`,
`interface Vlan`, `no vlan`, `no interface Vlan`, VRF, `ip route`, IS-IS, DHCP,
or AppGigabitEthernet trunk configuration. Teardown removes only the app
footprint (Guest Shell or the IOx app, IRIS EEM applets, agent files); it
deliberately leaves shared globals (logging discriminator, PKI trustpoint,
HTTP-client settings) in place because a receipt cannot prove those remain
uniquely IRIS-owned.

### Inband IOx and the IOS SSH endpoint

Guest Shell runs inside IOS, so it configures the device locally. An **IOx** app
runs in a container and reaches IOS by SSH-ing to an IOS IP to run `copy /verify`.
For a routed IOx device that is the IRIS-managed SVI; for an **inband** IOx
device there is no IRIS SVI, the app connects to the switch's management IP (`device_ip`) by default; an
optional `ios_ssh_host` overrides that for asymmetric topologies. The AppGigabitEthernet
trunk must already allow the inband VLAN, because IRIS never modifies it inband.
The IOx app carries a device SSH credential in its run options exactly as the
routed IOx path already does; hardening that credential path is a separate
improvement that applies equally to both.

## Inventory (CSV v2)

Inventory is an attachment-aware, named-header CSV. The header is required and
validated; extra, missing, or misplaced columns are rejected.

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,platform
```

- **routed** rows fill `iris_vlan`, `svi_ip`, `svi_mask`, `app_ip`, `app_mask`,
  `app_gateway`.
- **inband** rows fill `inband_vlan`, `app_ip`, `app_mask`, `app_gateway`, and
  must not carry routed VLAN/SVI fields. There is no IRIS VRF field.
- `ios_ssh_host` is an OPTIONAL advanced override: the IOS endpoint the inband
  IOx app SSHes to for `copy /verify`. It defaults to the device's management IP
  (`device_ip`), which is on the same existing management VLAN. Only set it for an
  asymmetric topology; Guest Shell never uses it.

The same server-side validator is applied to the Console, the API, and CSV
import: strict IDs, IPv4 addresses and contiguous masks, VLAN range 1–4094, and
static host/subnet consistency. Older positional CSVs still import but are
classified `legacy_routed`; they are never inferred as inband.

## Deployment plans and applied receipts

IRIS separates three concepts that were previously conflated:

1. **Desired inventory** — editable operator intent (`fleet.json`).
2. **Deployment plan** — an immutable, resolved plan for one action, including
   the resolved platform and a `plan_hash`. Computed before any device contact.
3. **Applied receipt** — a durable, non-secret record of what IRIS actually
   applied, its resource ownership, and lifecycle state.

Receipts live under `IRIS_STATE` (see below) and contain no passwords, tokens,
certificates, or raw device configuration. Their lifecycle is fail-closed:

```text
planned → applying → active → (applying) → removed
                 ↘ unknown / needs-reconcile / drifted
```

A controller restart converts any non-terminal (`planned`/`applying`) receipt to
`unknown`; in-flight device work is never silently resumed.

Undeploy renders **exclusively from an active receipt**, never from the editable
inventory — so changing a VLAN, model, or CSV import after onboarding cannot
retarget a device's cleanup. If a receipt is missing, uncertain, drifted, or
legacy, cleanup stops in `needs-reconcile` instead of guessing.

### Adopting a pre-existing deployment

Devices deployed before receipts existed have no active receipt, so undeploy is
refused. An explicit, audited **Adopt** action records an `active` receipt from
the device's current validated inventory, after which undeploy can proceed.
Adoption records ownership; it makes no changes to the device.

## Console and CLI

The Console Add Device flow has an explicit **Management type** choice —
*Routed - IRIS-managed app network* or *Inband - existing management VLAN* — and
the device table shows each device's **Attachment**, not a bare VLAN/SVI value.
Routed and inband onboarding are both one-click and receipt-backed. See
[Web Console](console.md).

The legacy `tools/gen-device-installers.sh` generator is routed-only and refuses
a v2 (`management_type`) header: a self-contained installer cannot record a
receipt or run preflight before minting an enrollment token.

## Deployment environments

Receipts use the same contract on both deployments:

- **Docker Compose** persists them under `IRIS_STATE` on the `iris-state`
  volume; Console artifact staging is the host-bind-mounted `/srv/artifacts`.
- **Kubernetes** persists them under `/data/state` on the RWO PVC; Console
  artifact staging is `/data/artifacts` on the same PVC. Kubernetes runs one
  replica with `Recreate`; a pod restart marks in-flight work `unknown` and
  requires reconciliation rather than blind retry.

See [Container Deployments](containers.md) and [Kubernetes](kubernetes.md).
