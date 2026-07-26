<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# AI-Guided PoC Deployment

Use this guide for a first proof-of-concept or proof-of-value deployment. It is
not a production runbook: it does not cover high availability, scale hardening,
or change control.

IRIS distributes, verifies, and stages IOS-XE images. It never installs,
activates, reloads, changes boot variables, or otherwise changes a device's
running software state.

## Before You Start

Prepare a local, git-ignored credential file if an assistant will connect to
the server or devices:

```bash
cp creds/deploy.env.example creds/deploy.env
chmod 600 creds/deploy.env
```

Keep credentials in that file or enter them directly in the Console. Do not
paste passwords, tokens, private keys, or certificate material into a chat.

Gather these non-secret decisions before starting:

| Decision | Examples |
| --- | --- |
| Server runtime | Docker Compose for a single host, or Kubernetes for the single-replica alpha deployment. |
| Stable server address | A device-reachable IPv4 address, used in the server certificate and tracker announces. |
| Image source | A host path to the IOS-XE `.bin` file. |
| Device inventory | Management IP, VLAN, SVI/guest addressing, and model for every device. |
| C9300 hosting mode | Guest Shell, or IOx on an SSD-equipped C9300. |
| IOx package availability | `iris-arm64.tar` for IE-3x00/IR; `iris-amd64.tar` for C9300 IOx. |

Review [Network Ports and Flows](network-ports.md) before bringing up the
server. Devices need reachability to the server and to each other for the
private swarm.

## Assistant Operating Rules

Give an assistant the following requirements when it helps operate a PoC:

```text
Operate IRIS as a stage-only system. Never install, activate, reload, change
boot variables, or replace a running image on a device.

Keep credentials and secrets out of chat, output, logs, source control, and
generated artifacts. Read local credentials only from creds/deploy.env when a
step needs them. If a required value is absent or a precondition is unclear,
stop and ask one plain question rather than guessing.

Before any destructive action, state exactly what it changes and obtain my
confirmation. Prefer the Web Console for inventory, onboarding, assignments,
and monitoring. Use the documented CLI only when the Console does not cover the
operation.

Use the current Zensical documentation in docs/zensical/. Follow Getting
Started for Docker Compose, Kubernetes for the Kubernetes alpha path, IOx App
for app-hosting prerequisites, and Network Ports and Flows for firewall rules.
At the end of every step, state the next action required from me.
```

## Guided Sequence

1. **Choose the runtime.** Use [Getting Started](getting-started.md) for Docker
   Compose on one server. Use [Kubernetes](kubernetes.md) only when a
   single-replica Kubernetes deployment and its persistent volume are intended.
2. **Bring up the server.** Create the age identity outside the repository, give
   uid `10001` the age key file and the host `artifacts/` directory (the
   container runs non-root and cannot chown host paths — see
   [Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy)),
   then run
   `tools/start-compose-server.sh` on the Linux Compose host. It
   bootstraps encrypted state idempotently, starts Compose, waits for health,
   and builds/stages both supported IOx packages before any Console onboarding.
   Do not proceed until `https://<server-ip>:8080/` is reachable.
3. **Create the Console admin.** Accept the self-signed certificate warning only
   for the expected server, create the initial admin, and sign in.
4. **Publish an image.** Upload through the Console, import a file that is
   already on the server from the Console **Import from disk** panel, or use
   `iris-publish` from inside the server container. Publishing creates catalog
   and torrent metadata; it does not change any device.
5. **Add devices.** Use the Console Devices page or its example CSV. Set each
   model when known. Leave `platform` blank for automatic selection, force
   `guestshell` for the standard C9300 path, `iox` only for a supported IOx
   device, or `router` for a Catalyst 8000 router VPG attachment.
6. **Confirm IOx packages are ready.** The server bring-up step stages arm64
   `iris-arm64.tar` for IE-3x00/IR and amd64 `iris-amd64.tar` for C9300 IOx. A C9300
   IOx deployment also requires a USB SSD and the C9300 app-hosting interface.
   See [IOx App](iox.md). Re-run `tools/provision-iox-packages.sh` after a
   server certificate rotation.
7. **Onboard devices.** Start one-click onboarding from the Console and watch
   each job to completion. A C9300 can use either Guest Shell or IOx; an
   explicit IOx choice with an unknown model fails before it touches the device.
   A successful lifecycle persists its configuration with `copy running-config
   startup-config`; a failed or partial lifecycle is not saved.
8. **Assign and observe.** Assign the published image, then use the Swarm and
   Monitoring areas to verify downloading, verification, staging, and seeding.
9. **Stop at staged.** Handoff installation, activation, reload, and boot
   management to the normal device-management process. They are outside IRIS.

## Completion Record

For a PoC handoff, record the server runtime and address, version, image id,
device model/platform choice, staging target, Console audit entries, and whether
each device reached staged/seeding state. Do not record credentials or tokens.
