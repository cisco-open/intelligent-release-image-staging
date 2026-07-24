<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Web Console

The console is the preferred operator surface once the server is running. It does not replace the CLI; it wraps common workflows and makes fleet state visible.

## First run

Open:

```text
https://<server-ip>:8080/
```

The server uses a self-signed certificate by default. Create the initial admin in the browser or with:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

## Console areas

| Area | What it does |
| --- | --- |
| Images | Shows published image metadata and staged fleet status. |
| Devices | Lists known devices, their network **attachment**, platform details, current assignment, and recent reports. |
| Assignments | Maps each device to the image it should stage. |
| Onboarding | Starts and tracks install or undeploy jobs when stage-host credentials are configured. |
| Swarm | Shows peer progress and seeder/device participation. |
| Monitoring | Links to health, swarm, metrics, and recent telemetry. |
| Settings | Shows server configuration, version, and operational settings. |
| Audit | Records administrative and workflow actions. |

For IOx devices, the Devices status distinguishes `copying to <filesystem>` from
the torrent download phase while the app transfers a completed image from its
container storage into IOS-visible storage. A final-placement failure is shown
as `placement failed` with a bounded diagnostic; inspect the device's
`IRIS ROOTCOPY-FAIL` syslog entry for the full device-side detail.

## Network attachment

The Add Device form has an explicit **Network attachment** choice, and the
device table shows each device's attachment rather than a bare VLAN/SVI value:

- **Routed - IRIS-managed app network** — IRIS creates a dedicated VLAN and SVI.
  Onboarding is one-click and create-only.
- **Inband - existing management VLAN** — the agent attaches to an existing,
  operator-owned VLAN that IRIS never creates, changes, or removes.

Each onboard records a durable **receipt** of what was applied. **Undeploy**
runs only from that receipt, so editing inventory after onboarding cannot
retarget cleanup. A device deployed before receipts existed shows no active
receipt; use the row's **Adopt** action (an explicit, audited, no-change
recording of current ownership) before undeploying it. See
[Network Attachment and VLAN Ownership](network-attachment.md).

## Onboarding from the console

GUI-driven onboarding uses stage-host credentials to run the same install logic that the CLI generates. The sensitive values belong in the console or the server secret store, not in Git. Generated per-device staging files are temporary and swept after their configured age.

## When to use the CLI

Use the CLI when you want a reproducible batch operation from reviewed CSV files. Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.
