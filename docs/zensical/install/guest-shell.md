<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Prepare Catalyst 9000 and 8000 devices for Guest Shell

On Catalyst 9000 series switches and Catalyst 8000 series routers, the agent
runs in Guest Shell, the Linux container built into the device software. On
switches with app-hosting storage you can run it as an IOx app instead;
[Supported devices and platforms](supported-devices.md) compares the two.

## Before you start

1. Check the device against
   [What a device needs before onboarding](device-requirements.md).
   A device whose clock is not synchronized is refused.
2. Choose how the agent reaches the network:
   [Choose a management type](management-types.md). A Catalyst 8000 series
   router uses an IRIS-managed VirtualPortGroup and stages to `bootflash:`.
3. Publish the packages the artifact server hands to devices:
   [Build and publish the device packages](device-packages.md).

## What the installer configures

IRIS generates `device/device-install.sh` for a Catalyst 9000 series switch and
`device/router-install.sh` for a Catalyst 8000 series router. The installer
lands the catalog trustpoint, enables IOx and Guest Shell, fetches the bootstrap
script and the agent bundle, and adds a timer in Embedded Event Manager (EEM).
On a router, `router-install.sh` first destroys any pre-existing Guest Shell
before it applies configuration, so a re-onboard cannot leave the guest
running on stale networking from an earlier install.

## What the installer lands on the device

Both installers push these files to the guest share root:

| File | Device-side name | What it is |
| --- | --- | --- |
| Agent config | `iris-agent.conf` | The catalog address, the device id, and an empty secret for the download program's local control port. |
| RPC secret | `rpc-secret` | Seeds that secret for `aria2c`, the download program the agent drives. |
| Agent bundle | `bundle.tgz` | The agent code, the bootstrap script, the Guest Shell start script, the log rotation script, the peer-transfer hook, and a build of `aria2c` for the device architecture. |
| Catalog certificate | `iris-catalog.pem` | The server certificate the agent pins for its calls to the catalog. |
| Bootstrap script | `bootstrap.sh` | The script the EEM applet runs. |

The installer then installs one EEM applet:

```text
event manager applet IRIS-AGENT authorization bypass
 event timer watchdog time 60 maxrun 900
 action 100 cli command "enable"
 action 200 cli command "guestshell run bash <fs>guest-share/bootstrap.sh"
```

Every 60 seconds the applet runs `bootstrap.sh` inside Guest Shell. Bootstrap
checks the bundle, makes sure `aria2c` answers, then runs one tick, one pass of
the agent's check-in loop.

## How the device decides to trust the bundle

`server/pack-agent-bundle.sh` emits Guest Shell's adjacent 64-hex SHA-256
sidecar, a file beside the bundle holding the bundle's digest. Bootstrap reads
the digest first and refuses evidence that is missing, malformed, or does not
match; the device keeps the bundle it has. A validated bundle is the agent
upgrade for Guest Shell, so read
[Upgrade to a new release](../admin-guide/upgrade.md) first.

!!! warning
    Anyone who can sign in to the device as an administrator can replace the
    bootstrap script, the bundle, and its digest. See
    [Security model and trust boundaries](../architecture/security-model.md#device-administrator-trust-boundary).

## Verify

The applet is named `IRIS-AGENT` and fires every 60 seconds. A device that
carries no such applet did not finish the install. The confirmation steps are in
[What a device needs before onboarding](device-requirements.md).

## Next steps

- [Stage your first image](../user-guide/first-image.md): assign an image and
  watch it reach the device.
- [Add and onboard devices](../user-guide/onboarding.md): onboard the device.
- [Prepare Industrial Ethernet switches with app hosting, Catalyst 9000 and 8000 devices for the IOx app](iox.md):
  the other way to run the agent.
