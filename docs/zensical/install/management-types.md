<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Choose a management type

The management type is how the agent reaches the network: on its own address,
on your management VLAN, or through the router. Pick one per device before you
onboard it. It sets the network fields the Console asks for.

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot
    variables. See the [Overview](../index.md).

## Before you start

Know whether each device is a switch or a router, and whether it has a
management VLAN that reaches the IRIS server. On Catalyst 9000 series switches
the agent runs in Guest Shell, or in the IOx app where the switch has
app-hosting storage. Industrial Ethernet 3000 series switches use the IOx app.

## Routed - IRIS-managed app network

IRIS creates a VLAN and switch virtual interface (SVI) for the agent and adds
the VLAN to the AppGigabitEthernet trunk. You provide a free VLAN and SVI, and
whether the SVI joins your interior gateway protocol. Join it only for a
fabric, such as an SD-Access underlay, that must learn the IRIS subnet.

!!! warning

    Enable `ip routing` on the switch first, and use a VLAN and SVI that do
    not exist yet.

## Inband - existing management VLAN

The agent attaches to your existing management VLAN, and IRIS adds that VLAN
to the AppGigabitEthernet trunk. You provide a management VLAN that reaches
the IRIS server. Onboarding checks the path from the server; confirm the
agent's route back yourself.

### IOx and the IOS SSH endpoint

Guest Shell configures the device from inside IOS. An IOx app reaches IOS over
SSH at the switch's management IP to finish the placement copy. Set
`ios_ssh_host` for a different address.

## Router routed - IRIS-managed VPG subnet

On Catalyst 8000 series routers, IRIS creates a VirtualPortGroup (VPG) and a
static app subnet. The agent runs in Guest Shell or the IOx app. You provide
routes from the app subnet to the IRIS server, tracker, and peers.

## Router NAT - VPG behind NAT

On the same routers, IRIS adds overload network address translation and a
static TCP translation for swarm port 6881. You provide the router's outside
interface, with inbound TCP 6881 permitted to its address.

When two router NAT devices share one outside address and your policy allows
one but denies the other, IRIS reports the conflict and leaves the address
open. See [Peer and sharing policy](../architecture/security-model.md).

## XR host - router's own network stack

On Cisco 8000 series and NCS routers, the agent runs as an IOS-XR appmgr
container on the router's own network stack. You provide a reachable
management address on the router.

## What undeploy removes

| Management type | Removed |
| --- | --- |
| Routed | The VLAN, the SVI, and the trunk entry |
| Inband | The agent and IRIS's Embedded Event Manager (EEM) applets and configuration; the trunk entry stays, because other apps may share the trunk |
| Router routed | The VPG and its subnet configuration |
| Router NAT | The NAT access list, its rules, and the translations for this device. An outside NAT marking on that interface that predates IRIS is left in place. |
| XR host | The appmgr application, its package, and IRIS's staged files |

## Verify

After onboarding, the Console's device table shows the management type. See
[Undeploy, retire and clean up devices](../user-guide/undeploy.md) to reverse it.

## Next steps

- [Prepare Catalyst 9000 and 8000 devices for Guest Shell](guest-shell.md)
- [Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](iox.md)
- [Prepare Cisco 8000 and NCS routers for IOS-XR appmgr](ios-xr.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [Stage your first image](../user-guide/first-image.md)
