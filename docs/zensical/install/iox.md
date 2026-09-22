<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Prepare Industrial Ethernet switches with app hosting, Catalyst 9000 and 8000 devices for the IOx app

Use this page for a device that runs the device agent as an IOx application:
Industrial Ethernet switches with app hosting, Catalyst 8000 series routers, and
Catalyst 9000 series switches with app-hosting storage. On Catalyst 9000 series
switches the agent normally runs in [Guest Shell](guest-shell.md), and
[Supported devices and platforms](supported-devices.md) says which path each
series takes.

## Before you start

1. Check the device against [What a device needs before onboarding](device-requirements.md).
2. Pick a management type, which is how the agent reaches the network: on its
   own address, on your management VLAN, or through the router. See [Choose a management type](management-types.md).
3. Build and publish the IOx packages. See [Build and publish the device packages](device-packages.md).
4. Read `show app-hosting infra` and note the package verification state.

!!! warning

    Read `show app-hosting infra` before you onboard. A successful unsigned
    install does not prove that activation will succeed once verification is
    restored.

## Signature verification is a device-wide setting { #device-global-package-verification }

Verification is device-global, so a change affects every IOx app on the device.
Prefer a natively signed wrapper and keep verification enabled. The onboarding
job owns the whole transaction, and this table says what it does in each case.

| Wrapper / initial observation | Owned behavior |
| --- | --- |
| Signed marker present | No verification-state change. Native signature enforcement is a platform setting; marker presence alone is not cryptographic validation. |
| Unsigned / `enabled` | Durably record the initial state and restoration obligation; disable only for installation; restore and read-back before activation/start. |
| Unsigned / `disabled` | Leave disabled; no unowned enable operation. |
| Unsigned / `unknown` | Refuse mutation and installation. Obtain readable platform evidence first. |

Interruption/resume and uninstall recovery use durable obligations. They do
not blindly enable an operator-changed or unowned state.

!!! warning

    Check the onboarding job and deployment record before you retry an
    interrupted onboarding or run an uninstall. Unresolved restoration blocks
    progress.

Cisco documents signature enforcement, SD and bootflash restrictions and the
global setting in the [Industrial Ethernet switches with app hosting IOx deployment guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/cisco_ie3X00/software/17_14/b_cisco-iox-ie3x00-switches/m-ie3400-deploying-iox-applications.html), and the [Catalyst 9000 App Hosting guide](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/222780-understand-app-hosting-on-catalyst-9000.html) limits disabling verification to USB and SSD media.

## What onboarding puts on the device

`device/iox/install.sh` and `device/iox/uninstall.sh` require the
controller's private channel; they are not meant to run standalone.

1. The installer opens an SSH session to IOS and installs the catalog trustpoint over it.
2. The device fetches the package (`iris-arm64.tar` or `iris-amd64.tar`) and
   the public catalog certificate from the artifact server with `copy https:`,
   validated against that trustpoint. Each copy authenticates with the device's
   enrollment credential, which the server sets as `ip http client username` and
   `ip http client password` for one copy and then removes.
3. After the app reaches `ACTIVATED`, the installer copies the certificate and
   the device's first instruction, the signed message that says which images to
   stage, into app-hosting application data and starts the app.

A privileged device administrator can read the app's run options, so the
enrollment token and the SSH-to-self password are readable on the device. See
[Security model and trust boundaries](../architecture/security-model.md).

Submit onboarding from the Console or the onboard API. See
[How an image reaches a device](../architecture/data-path.md) for what happens next.

## Catalyst 8000 routers

Catalyst 8000 series routers have no `AppGigabitEthernet` interface. On a
`router-routed` or `router-nat` row, the installer creates an IRIS-owned
`VirtualPortGroup<N>`, attaches the app with
`app-vnic gateway0 virtualportgroup N`, and points the app's SSH-to-self at the
VirtualPortGroup address. On `router-nat` it also creates the NAT access list,
overload rule and BitTorrent static translation. The package is the amd64 IOx
tar and the staging target is `bootflash:`, over an SCP push. Teardown removes
the app and the VirtualPortGroup, and un-marks a NAT outside interface only when
the deployment record says IRIS marked it.

## Checks that run before onboarding changes anything

The job stops before it writes anything when one of these checks fails.

| Check | What the job does |
| --- | --- |
| Staging target | Reads `show file systems` and picks a writable disk that is not the crash volume. |
| SD card, on Industrial Ethernet switches with app hosting with an `sdflash:` target | Reads `show sdflash: filesys` for an IOx partition, and fails with a `PREREQ:` line when the card was never formatted for IOx. |
| `ip routing`, on the routed management type | Checks that it is on. See [Choose a management type](management-types.md). |
| HTTP client credentials | Refuses a device whose running configuration already carries your own `ip http client username` or `ip http client password`. |
| Device clock | Warns when the clock is old enough to break TLS certificate validation. See [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md#time-synchronization). |
| SCP server claim | Refuses onboarding while an older deployment still holds an unresolved claim. See [Undeploy, retire and clean up devices](../user-guide/undeploy.md). |

On Industrial Ethernet switches with app hosting and Catalyst 8000 series routers,
onboarding also turns on the device's SCP server with `ip scp server enable`,
and undeploy restores that setting. That SCP traffic is addressed to the
device itself, so the platform's default Control Plane Policing caps it at
roughly 1.4 MB/s; IRIS never modifies CoPP. This can make placement on these
platforms much slower than a share-based placement on a Catalyst 9300.

## Which IOS address the app uses

The app runs on the address you configure during onboarding, and the server and
other devices reach it there. It reaches IOS over SSH at an address that depends
on the management type; see [Choose a management type](management-types.md). On
an inband device that address is the device's management IP; set `ios_ssh_host`
to override it for an asymmetric topology.

## Pin the IOS host key

Pinning that SSH connection is optional and off by default. Set
`device_ssh_known_hosts` in the agent configuration to a `known_hosts` file you
provision, and the app runs SSH and SCP with `StrictHostKeyChecking=yes`
against it. See [Device agent configuration](../reference/device-configuration.md).

## Verify

Open the onboarding job in the Console. A finished job leaves the app in the
`RUNNING` state, with the certificate and the first instruction in place.

### Check that the IOx app came up

IOx verification is device-global. See
[Signature verification is a device-wide setting](#device-global-package-verification).
Read the verification state again before you onboard another application.
Interruption, resume and uninstall recovery never blindly enables an
operator-changed or unowned state, so inspect the job and deployment evidence
when restoration is incomplete.

See [Add and onboard devices](../user-guide/onboarding.md#first-install-of-a-new-package-version)
for what to do after a failed onboard.

## Next steps

- [Stage your first image](../user-guide/first-image.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [What a device needs before onboarding](device-requirements.md)
- [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md)
