<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Management type and VLAN ownership

IRIS supports five explicit management type models for the staging agent. The
choice is per device, recorded in inventory, and — critically — determines what
IRIS is allowed to create and remove on the device.

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
  process. Before this was unconditional. This is a **per-device** setting —
  one server routinely onboards devices into different fabrics, only some of
  which run IS-IS. Set it on the device's inventory record (the `svi_igp`
  CSV column, or the same field via the console/API), routed devices only;
  it is validated against the closed `none`/`isis` enum before it is ever
  interpolated into the device's config, the same command-injection defense
  every other value on that path gets. A device whose record leaves it blank
  falls back to the fleet-wide `SVI_IGP` env var on the server (default
  `none`) — the process-wide setting `SVI_IGP=isis` in `server/.env` used to
  be the only way to opt a device in at all; it is now the default a
  per-device override can still opt out of.

Global `ip routing` is a switch-wide setting IRIS never enables on the
operator's behalf — it is an operator decision. Both installers
(`device/device-install.sh`, `device/iox/install.sh`) check for it before
applying any config on a device using the routed management type. The check is semantic, not a grep
for a positive `ip routing` line: that line is absent whenever routing is the
platform default (seen on IE-3x00), which used to false-fail a healthy switch.
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

`device/router-install.sh` destroys any pre-existing Guest Shell before
applying config, instead of reusing one already `RUNNING`. A re-onboard over a
running guest left it on its old networking — `guestshell enable` sees
`RUNNING` and never rebuilds the guest, so the freshly applied VPG gateway
never reaches it and the agent loses egress, silently (inbound ping still
answers). Destroying the guest first forces `guestshell enable` to always
build it from the config this run applies. Agent state persists on
`bootflash:guest-share`, so a re-onboard only costs the ~60-second guest
rebuild.

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

**A same-name replacement — including republishing under a name the `BOOT`
variable currently points at — costs no more free space than the figure
above.** The old file at the destination, the staging copy, and the new
proven copy at its temp name do all coexist on the storage root until the
crash-safe [`rename` that puts it in
place](device-agents.md#crash-safe-same-name-replacement) — but the old
file was already occupying space before this placement began, so it is
already excluded from "free" rather than something this placement newly
needs room for. The only bytes this placement writes that were not already
on the device are the staging copy and its root-side twin — the same **2×
the image size + 200 MB** as a fresh filename.

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
source `iris-xr`, stages the agent RPM at `harddisk:iris-xr.rpm`, and creates
the working directory `harddisk:iris-work`. Undeploy removes exactly those
four resources from its deployment record; every other router setting, including its
networking configuration, is preserved. One qualification on the fourth:
undeploy empties `harddisk:iris-work` but cannot delete the directory itself,
because XR's CLI offers no prompt-free directory removal. An empty
`harddisk:iris-work` left behind is therefore the **normal successful
outcome**, reported as a note rather than a fault — not evidence of an
interrupted run. A second undeploy run converges regardless, because each
step re-probes the router's own
state before acting instead of assuming its own prior success. Files an
operator staged directly on the router (adopted, not downloaded by IRIS)
are never removed by teardown or by the agent, with one exception: a
catalog republish of different content under the same image id replaces
the file IRIS is tracking, and that replacement is logged.

## Inventory (CSV v2)

Inventory is a management-type-aware, named-header CSV. The header is required and
validated; extra, missing, or misplaced columns are rejected.

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,platform
```

- **routed** rows fill `iris_vlan`, `svi_ip`, `svi_mask`, `app_ip`, `app_mask`,
  `app_gateway`, and may fill `svi_igp` (`isis` or blank; every other
  management type must leave it blank).
- **inband** rows fill `inband_vlan`, `app_ip`, `app_mask`, `app_gateway`, and
  must not carry routed VLAN/SVI fields. There is no IRIS VRF field.
- **router-routed** rows fill `app_ip`, `app_mask`, `app_gateway`, and
  `vpg_number`; router fields cannot be combined with switch VLAN/SVI fields.
- **router-nat** rows additionally fill `nat_interface`. `platform=router` is
  explicit in the Add Device form; an imported blank can resolve from a known
  Catalyst 8000 (C8xxx) model at onboard time.
- **xr-host** rows fill only `model` and `platform` (`xr-appmgr`, required);
  every addressing column stays empty.
- `ios_ssh_host` is an OPTIONAL advanced override: the IOS endpoint the inband
  IOx app SSHes to for the placement copy. It defaults to the device's management IP
  (`device_ip`), which is on the same existing management VLAN. Only set it for an
  asymmetric topology; Guest Shell never uses it.

The same server-side validator is applied to the Console, the API, and CSV
import: strict IDs, IPv4 addresses and contiguous masks, VLAN range 1–4094, and
static host/subnet consistency. Older positional CSVs still import but are
classified `legacy_routed`; they are never inferred as inband.

The Add Device form requires an explicit agent install. The row editor and CSV
can still hold a blank `platform` as inventory-only intent; onboarding resolves
only known IOS-XE model mappings and fails closed when the platform or OS family
is uncertain. `xr-host` is never inferred from a blank platform: it requires
`xr-appmgr` explicitly.

## Deployment plans and applied records

IRIS separates three concepts that were previously conflated:

1. **Desired inventory** — editable operator intent (`fleet.json`).
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

Devices deployed before deployment records existed have no active deployment record, so a normal
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
inside the `POST /api/devices/<id>/onboard` request. Submitting a batch of
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
**Router NAT**, and **XR host** management types. Router choices show VPG number
and app addressing; Router NAT also shows the outside interface. XR host hides
every addressing field and is auto-selected for a Cisco 8000 series router
model or the XR appmgr container agent install. The device table shows
each device's **Management type**, not a bare VLAN/SVI value. Onboarding is
record-backed. See
[Web Console](console.md).

The legacy `tools/gen-device-installers.sh` generator is routed-only and refuses
a v2 (`management_type`) header: a self-contained installer cannot create a
deployment record or run preflight before minting an enrollment token.

## Deployment environments

Deployment records use the same contract on both deployments:

- **Docker Compose** persists them under `IRIS_STATE` on the `iris-state`
  volume; Console artifact staging is the host-bind-mounted `/srv/artifacts`.
- **Kubernetes** persists them under `/data/state` on the RWO PVC; Console
  artifact staging is `/data/artifacts` on the same PVC. Kubernetes runs one
  replica with `Recreate`; a pod restart marks in-flight work `unknown` and
  requires reconciliation rather than blind retry.

See [Container Deployments](containers.md) and [Kubernetes](kubernetes.md).
