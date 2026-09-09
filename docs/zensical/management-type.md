<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Management type and VLAN ownership

IRIS supports five explicit management type models for the staging agent. The
choice is per device, recorded in inventory, and determines which network
fields the Console shows and what IRIS may create and remove on the device.
Changing the model or agent installer does not change the management type.

> **Stage-only, network-preserving.** Inband never creates, changes, or removes
> the operator's network, and IRIS never mutates running software state — see
> [Guardrails](security.md#guardrails).

## Routed — IRIS-managed app network

The routed management type uses a **dedicated IRIS VLAN and SVI**. Onboarding is
create-only: the applied deployment record captures the resources IRIS created, and
teardown removes exactly those.
Choose a VLAN and SVI that do not already exist on the device: the installer
applies them as IRIS-created, the deployment record marks them as IRIS-owned, and
routed teardown removes them.

Two details of what routed mode touches beyond the VLAN and SVI:

- The AppGigabitEthernet app-hosting trunk is changed **additively** only
  (`switchport trunk allowed vlan add <vlan>`), exactly as in inband mode, so
  other IOx apps riding the same uplink keep their VLANs. Teardown removes
  only the IRIS VLAN from that allowed list (`... allowed vlan remove`).
- The SVI joins an IGP only when the record says so: `isis` adds
  `ip router isis` (for fabrics such as an SD-Access underlay that need to
  learn the IRIS subnet). The default (`none`) never injects the IRIS subnet
  into the operator's routing protocol and never creates a `router isis`
  process. This is a **per-device** setting —
  one server routinely onboards devices into different fabrics, only some of
  which run IS-IS. Set it on the device's inventory record (the `svi_igp`
  CSV column, or the same field via the console/API), routed devices only;
  it is validated against the closed `none`/`isis` enum before it is ever
  interpolated into the device's config, the same command-injection defense
  every other value on that path gets. A device whose record leaves it blank
  falls back to the fleet-wide `SVI_IGP` env var on the server (default
  `none`). An explicit `svi_igp=none` overrides a server default of `isis`.

Global `ip routing` is a switch-wide setting IRIS never enables on the
operator's behalf — it is an operator decision. Both installers
(`device/device-install.sh`, `device/iox/install.sh`) check for it before
applying any config on a device using the routed management type. The check is semantic, not a grep
for a positive `ip routing` line: that line is absent whenever routing is the
platform default (as on IE-3x00).
Instead the installers treat an explicit `no ip routing` line, or a route
table answering in host mode (`Default gateway ...`), as the authoritative
signal that routing is off — and treat a session that never echoes the
command back as a transport failure, reported as "could not verify ip
routing" rather than misrepresented as a routing problem. When routing is
confirmed off, the installer fails closed with a `PREREQ:` line and the exact
command to run. Without this check, onboarding can report success while the
new VLAN/SVI has no path off the box — a silent failure that is otherwise
invisible until traffic is debugged.

## Inband — existing management VLAN

The inband management type connects the staging agent — Guest Shell or an IOx app — to an
**existing management VLAN**. IRIS
does not create, configure, select, claim ownership of, or delete that VLAN, its
SVI, gateway, routes, or VRF. The operator-owned SVI (and any VRF it belongs to)
supplies routing; preflight only proves the existing topology can reach IRIS.

The supported management-type cells:

| Management type | Addressing | Platform | Status |
| --- | --- | --- | --- |
| Routed | static | Guest Shell / IOx | supported (record/preflight hardened) |
| Inband | static | Guest Shell | supported |
| Inband | static | IOx (IE-3400, Catalyst 9300) | supported |
| Inband | DHCP | any | rejected — separate capability gate |
| `router-routed` | static | Guest Shell (Catalyst 8000) | supported, lab-tested on Catalyst 8000V |
| `router-nat` | static | Guest Shell (Catalyst 8000) | supported, lab-tested on Catalyst 8000V |
| `xr-host` | none | XR appmgr container (Cisco 8000 series, IOS-XR) | supported |

Inband install and teardown command streams never contain `vlan`,
`interface Vlan`, `no vlan`, `no interface Vlan`, VRF, `ip route`, IS-IS, or
DHCP. The one interface IRIS does touch inband is the AppGigabitEthernet
app-hosting port. Install sets `switchport mode trunk` and **adds** the inband
VLAN with `switchport trunk allowed vlan add` — the additive form only, so an
existing allowed list is never replaced — because without it the agent's
traffic has no L2 path off the box. Teardown never removes the VLAN from the
trunk (it is operator-owned and the trunk may carry other apps). Its scope is
decided by name, not by mode: it removes the app footprint (Guest Shell or the
IOx app, IRIS EEM applets, agent files) *and* every IRIS-named global — the
IRISQ logging discriminator with its buffered/console/monitor bindings,
`crypto pki trustpoint IRIS`, and `ip http client secure-trustpoint IRIS` —
because each of those carries IRIS's own name and the next onboard's preflight
refuses while any of them is present. What inband preserves is the operator's
network: the VLAN, its SVI, routes, and VRF.

### Inband IOx and the IOS SSH endpoint

Guest Shell runs inside IOS, so it configures the device locally. An **IOx** app
runs in a container and reaches IOS by SSH-ing to an IOS IP to run the placement copy.
For a routed IOx device that is the IRIS-managed SVI; for an **inband** IOx
device there is no IRIS SVI, the app connects to the switch's management IP (`device_ip`) by default; an
optional `ios_ssh_host` overrides that for asymmetric topologies. IRIS adds the
inband VLAN to the AppGigabitEthernet trunk's allowed list additively at
install time (see above), so no manual trunk preparation is required.
The IOx app carries a device SSH credential in its run options exactly as the
routed IOx path already does; hardening that credential path is a separate
improvement that applies equally to both.

## Router routed and router NAT — IRIS-managed VirtualPortGroup

Catalyst 8000 routers use Guest Shell through `VirtualPortGroup<N>` (VPG), not
a VLAN/SVI or AppGigabitEthernet interface. Support is **designed for the
Catalyst 8000 family, lab-tested on Catalyst 8000V**. Both router modes onboard, stage a
verified image, and undeploy from their deployment record, and both appear on the Swarm Map
with telemetry when observability is enabled.

- **router-routed** creates an IRIS-owned VPG gateway and static app subnet.
  It performs no NAT. The operator must provide routes (static routes or IGP
  redistribution) between that app subnet and the IRIS server, tracker, and
  peers.
- **router-nat** adds overload NAT behind the operator-selected outside
  interface and static TCP PAT for swarm port **6881**, so peers can reach the
  agent through the router outside address. IRIS owns the VPG, NAT ACL, and NAT
  rules. The outside interface is canonicalized before rendering. Its deployment
  record notes whether `ip nat outside` already existed; a pre-existing marking is
  preserved and undeploy removes that marking only when IRIS created it.

  Several `router-nat` participants can share one translated outside address.
  If origin policy would permit one of those principals and deny another, IRIS
  reports a `shared_permit_deny` conflict and leaves the shared address
  unblocked rather than cutting off the permitted principal. The additional
  mutual-origin deny proposed by issue #153 remains a count-only preflight in
  Phase 0; use distinct outside addresses when address-level isolation is
  required.

`device/router-install.sh` destroys any pre-existing Guest Shell before
applying config, then enables it with the selected VPG networking. Agent
state persists on `bootflash:guest-share` across the Guest Shell rebuild.

Undeploy of a **router-nat** device clears only translations whose inside-local
address matches the app IP recorded in the deployment record, using targeted
`clear ip nat translation inside <global> <local> forced` commands before it
removes the NAT configuration. IOS refuses
`no ip nat inside source list ... overload` while translations still reference
that mapping. Teardown therefore verifies that the overload rule is gone before
removing `IRIS-NAT-<vpg>`, and on failure it preserves the ACL for safe
reconciliation. It never flushes device-wide NAT state. Routed teardown does
not clear translations because it configures no NAT.

Both modes stage only to `bootflash:`.

### Sizing the storage root

Allow roughly **2× the image size + 200 MB** of free bootflash (about 4.2 GB for
a 2 GB image) for one image in flight: the staging copy plus the placed copy
coexist while the placement runs. The agent safely refuses to stage when space
is insufficient.

A file already on bootflash consumes space before the free-space check.
Guest Shell can adopt an existing file after checking its size and native
SHA-512 against the catalog. A conflicting or unreadable file is kept, and
staging fails until the operator resolves it. See
[Crash-safe same-name replacement](device-agents.md#crash-safe-same-name-replacement).

Budget beyond that for the images you want **resident at once**, not for the
number of reassignments you expect. Unchecking or reassigning an image parks it
and deliberately keeps the copy already on the storage root — see
[Unassigned image park](device-agents.md#unassigned-image-park). That kept copy
is reclaimable, but it is reclaimed by the *next* placement's space check when
that placement is short of room, not at the moment you reassign. On a device
sized for exactly one image plus headroom this still converges; on a device with
several parked copies and no headroom the reclaim gate has to free them one
rollout at a time.

## XR host — the router's own network stack

`xr-host` is for Cisco 8000 series (IOS-XR) routers, where the agent runs as
an appmgr Docker container on the router's own network stack: there is no
VLAN, SVI, app IP/mask/gateway, VPG, or NAT interface, and IRIS never touches
the router's networking configuration. `xr-host` and platform `xr-appmgr` are
mutually required on any fully-classified device; an inventory-only device
may carry platform `xr-appmgr` before its management type is chosen, but planning
or deploying refuses the half-classified state.

Onboarding creates the appmgr application `iris`, registers the package
source `iris-xr`, and stages `iris-xr.rpm`, `iris-catalog.pem`, and the
`iris-work/` directory under `harddisk:`. Undeploy removes the recorded app
and package, the IRIS files, and torrent sidecars while preserving router
networking. It empties `iris-work/` but can leave that directory in place:
XR's CLI offers no prompt-free directory removal.

The successful job ends with `undeploy complete: <device-ip>`. An empty work
directory is expected. Repeating undeploy probes the router's current state
and skips resources already removed. Files an
operator staged directly on the router (adopted, not downloaded by IRIS)
are never removed by teardown or by the agent, with one exception: a
catalog republish of different content under the same image id replaces
the file IRIS is tracking, and that replacement is logged.

## Inventory

Inventory is a management-type-aware, named-header CSV. The header is required and
validated; extra, missing, or misplaced columns are rejected.

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,role,platform
```

- **routed** rows fill `iris_vlan`, `svi_ip`, `svi_mask`, `app_ip`, `app_mask`,
  `app_gateway`, and may fill `svi_igp` (`none`, `isis`, or blank; every other
  management type must leave it blank).
- **inband** rows fill `inband_vlan`, `app_ip`, `app_mask`, `app_gateway`, and
  must not carry routed VLAN/SVI fields. There is no IRIS VRF field.
- **router-routed** rows fill `app_ip`, `app_mask`, `app_gateway`, and
  `vpg_number`; router fields cannot be combined with switch VLAN/SVI fields.
- **router-nat** rows additionally fill `nat_interface`. `platform=router` is
  explicit in the Add Device form; an imported blank can resolve from a known
  Catalyst 8000 (C8xxx) model at onboard time.
- **xr-host** rows retain `device_id` and the router's `device_ip`, with
  `platform=xr-appmgr` required and an optional model. All app-network fields
  stay empty; the container shares the router's network stack.
- `ios_ssh_host` is an OPTIONAL advanced override: the IOS endpoint the inband
  IOx app SSHes to for the placement copy. It defaults to the device's management IP
  (`device_ip`), which is on the same existing management VLAN. Only set it for an
  asymmetric topology; Guest Shell never uses it.
- `role` is optional server-side peer-policy membership. It uses the same
  meaning for routed, inband, router-routed, router-nat, and xr-host devices and
  never renders an IOS/IOS-XR ACL or changes the device network configuration.
  A blank import preserves existing membership; clear it through the explicit
  role action.

The same server-side validator is applied to the Console, the API, and CSV
import: strict IDs, IPv4 addresses and contiguous masks, VLAN range 1–4094, and
static host/subnet consistency.

The Add Device form requires an explicit agent install. The row editor and CSV
can still hold a blank `platform` as inventory-only intent; onboarding resolves
only known IOS-XE model mappings and fails closed when the platform or OS family
is uncertain. `xr-host` is never inferred from a blank platform: it requires
`xr-appmgr` explicitly.

## Deployment plans and applied records

IRIS records three parts of each deployment:

1. **Desired inventory** — editable operator intent (`fleet.d/`).
2. **Deployment plan** — an immutable, resolved plan for one action, including
   the resolved platform and a `plan_hash`. Computed before any device contact.
3. **Deployment record** — a durable, non-secret account of what IRIS actually
   applied, its resource ownership, lifecycle state, management IP, and
   processor-board identity.

Deployment records live under `IRIS_STATE` (see below) and contain no passwords, tokens,
certificates, or raw device configuration. Their lifecycle is fail-closed:

```text
planned → applying → active → (applying) → removed
                 ↘ unknown / needs-reconcile / drifted / superseded
```

A controller restart converts any non-terminal (`planned`/`applying`) deployment record to
`unknown`; in-flight device work is never silently resumed. A device has exactly
one live deployment, so when a new deployment record becomes `active` — an explicit
adopt, or an onboard of a device that was undeployed first — any previous
`active` deployment record for
that device is retired to the terminal `superseded` state. Undeploy therefore
always finds at most one active deployment record.

Undeploy renders **exclusively from an active deployment record**, never from the editable
inventory — so changing a VLAN, model, or CSV import after onboarding cannot
retarget a device's cleanup. The one exception is a forced undeploy of a device
that has no deployment record at all: with nothing to render from it resolves the device
from inventory and skips the processor-board identity check, so it is limited by
scope instead — it removes only IRIS-named artifacts and never the operator's
VLAN/SVI, VirtualPortGroup, or NAT. If a deployment record is missing, uncertain, drifted,
or legacy, cleanup stops in `needs-reconcile` instead of guessing.

### Adopting a pre-existing deployment

When a device has an IRIS agent but no active deployment record, normal
undeploy is refused. Non-router deployments may use the explicit, audited
**Adopt** action, which records current ownership without changing the device.
Routers cannot be adopted, and preflight refuses to onboard over a live agent,
so their path is the Undeploy dialog's **Force** checkbox: it strips only the
IRIS-named agent footprint (EEM applets, Guest Shell or the IOx app, the
app-hosting stanza, the IRISQ discriminator, the IRIS trustpoint, staged files),
leaves the VLAN/SVI, VirtualPortGroup and NAT untouched, and is recorded in
Audit as `undeploy_forced`. Onboard again after it completes.

### Router preflight and ownership

Router preflight is read-only and runs once, in the bounded onboarding worker
pool, immediately before the enrollment token is minted — not synchronously
inside the `POST /api/v1/devices/<id>/onboard` request. Submitting a batch of
routers therefore returns a job id per device promptly, with progress shown
as each job queues and then runs, instead of the request blocking on live SSH
to every router in turn. Preflight rejects collisions for the VPG, NAT
entries, named IRIS globals, and `bootflash:guest-share`. These names and the
guest share are tracked in the deployment record; teardown removes only resources proven by that
record. Every one of these checks, together with device identity and (for
router NAT) the outside interface, still completes before any enrollment
token is minted or router configuration is applied.

## Console and CLI

The Console Add Device flow offers **Routed**, **Inband**, **Router routed**,
**Router NAT**, and **XR host** management types. This choice alone controls
which network fields appear. Router choices show VPG number and app addressing;
Router NAT also shows the outside interface. XR host keeps the device's
management IP and hides all app-network fields. Its installer is XR appmgr.
The model is optional free text: typing a model does not change the selected
management type. Saving a model name does not establish hardware support.
The device table shows each device's **Management type**, and onboarding uses
an applied deployment record. See
[Web Console](console.md).

A scheduled onboarding needs the same choice: a row that is still inventory
only has no plan to run, so a scheduled window records it as
`unclassified_management_type` and moves on rather than guessing a network for
it. Classify the row, then let the next window pick it up — a late-bound
target re-resolves at each run. See
[Scheduled outcomes](operations.md#scheduled-outcomes).

## Deployment environments

Deployment records use the same contract on both deployments:

- **Docker Compose** persists them in the server's `IRIS_STATE` on the
  `iris-state` volume. The server stages artifacts in the host-bound
  `/srv/artifacts`; the Console accesses them through the management API.
- **Kubernetes** persists them in the server's `/data/state` on the RWO PVC,
  with artifacts in `/data/artifacts`. The separate Console deployment has
  no state PVC. Each deployment runs one replica with `Recreate`; a server
  restart marks in-flight work `unknown` and requires reconciliation.

See [Container Deployments](containers.md) and [Kubernetes](kubernetes.md).
