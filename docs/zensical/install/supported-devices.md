<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Supported devices and platforms

Find the delivery path for each device series, the storage an image lands on,
and the package you have to build.

## Before you start

- The series and software release of every device you plan to onboard.
- Free space on each device's staging storage, and your image sizes. See
  [What a device needs before onboarding](device-requirements.md).
- How each device reaches the server. See
  [Choose a management type](management-types.md).

## Which delivery path each device family uses

IRIS reaches a device over Guest Shell, IOx, or IOS-XR appmgr. A series name
does not mean every model and software release supports that delivery path.
Check your device's app-hosting support before selecting it.

| Device family | Delivery path | Staging target | When to choose it | What you must build |
| --- | --- | --- | --- | --- |
| Catalyst 9000 series switches | Guest Shell | `flash:` | Your default on these switches. | The Guest Shell agent bundle, `iris-agent.tgz`. |
| Catalyst 9000 series switches | IOx | Chosen by the live writable-media policy, normally `flash:` through the SSD share | The switch has app-hosting storage and you run IOx apps. | The amd64 IOx package, `iris-amd64.tar`. |
| Industrial Ethernet switches with app hosting | IOx | Chosen by the live writable-media policy, normally `sdflash:` | The one path for this family. | The arm64 IOx package, `iris-arm64.tar`. |
| Catalyst 8000 series routers | Guest Shell | `bootflash:` | The agent runs on a VirtualPortGroup that IRIS manages. | The Guest Shell agent bundle, `iris-agent.tgz`. |
| Catalyst 8000 series routers | IOx | `bootflash:` | You run IOx apps. The app attaches to the same VirtualPortGroup. | The amd64 IOx package, `iris-amd64.tar`. |
| Cisco 8000 series routers, IOS-XR | IOS-XR appmgr | `harddisk:` | The one path for IOS-XR. Validated on a Cisco 8201. | The appmgr package, `iris-xr.rpm`. |
| NCS-540 routers, IOS-XR | IOS-XR appmgr | `harddisk:` | The one path for IOS-XR. Package transfer, RPM checksum, registration, and app startup are validated; image staging, telemetry delivery, and undeploy are not yet validated. | The appmgr package, `iris-xr.rpm`. |

On IOx and IOS-XR the agent picks the staging target itself; see
[Data formats and states](../reference/state-and-data.md). Guest Shell keeps the
target in the table. The server build produces the Guest Shell agent bundle;
build the IOx and IOS-XR packages yourself, with
[Build and publish the device packages](device-packages.md). Check
[Limitations](../architecture/limitations.md) before a rollout.

## Choose between IOx and Guest Shell

On Catalyst 9000 series switches the agent runs in Guest Shell; the IOx app is
the alternative on switches with supported app-hosting storage.
[Cisco's app-hosting guide](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/222780-understand-app-hosting-on-catalyst-9000.html)
requires supported external storage for third-party applications. Confirm the
IRIS share and staging path on the exact switch and software release before
using IOx. Both paths run the same agent. On Catalyst 8000 series routers both paths
attach the agent to the same VirtualPortGroup.

- On Guest Shell an Embedded Event Manager (EEM) applet starts the agent on a
  timer inside IOS. On IOx and IOS-XR the container's supervisor runs it. See
  [How an image reaches a device](../architecture/data-path.md).
- Agent upgrades differ by path. See
  [Upgrade to a new release](../admin-guide/upgrade.md).
- For an unsigned IOx install, IRIS temporarily disables device-global signature
  verification when it was enabled, then restores that state before activation.
  An initially disabled setting stays disabled. Read
  [Prepare Industrial Ethernet, Catalyst 9000 and 8000 devices for the IOx app](iox.md#device-global-package-verification)
  first.

## Which management types each path supports

A management type is how the agent reaches the network: on its own address, on
your management VLAN, or through the router.

| Management type | Addressing | Delivery path and platform | Supported |
| --- | --- | --- | --- |
| Routed | Static | Guest Shell or IOx | Yes |
| Inband | Static | Guest Shell | Yes |
| Inband | Static | IOx on Industrial Ethernet switches with app hosting or Catalyst 9000 series switches | Yes |
| `router-routed` | Static | Guest Shell or IOx on Catalyst 8000 series routers | Yes |
| `router-nat` | Static | Guest Shell or IOx on Catalyst 8000 series routers | Yes |
| `xr-host` | None | IOS-XR appmgr on Cisco 8000 series routers; on NCS-540 routers, only package transfer, registration, and app startup are validated (staging and undeploy are not) | Yes |

!!! warning

    Addressing by DHCP is refused. Give every agent a static address.

## Verify

1. Your device series and delivery path have a row under Which delivery path
   each device family uses.
2. The management type you plan to use is marked Yes under Which management
   types each path supports.
3. You know which package each series needs and how to build it. If you serve
   both IOx architectures, build and check both.

## Next steps

- [What a device needs before onboarding](device-requirements.md)
- [Choose a management type](management-types.md)
- [Prepare Catalyst 9000 and 8000 devices for Guest Shell](guest-shell.md)
- [Prepare Industrial Ethernet, Catalyst 9000 and 8000 devices for the IOx app](iox.md)
- [Prepare Cisco 8000 routers, and NCS-540 routers (partially validated), for IOS-XR appmgr](ios-xr.md)
