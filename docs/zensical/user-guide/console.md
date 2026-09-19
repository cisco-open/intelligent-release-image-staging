<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Find your way around the Console

The Console is the browser interface you use to run IRIS every day. It forwards
your requests to the server, which owns images, inventory, credentials, jobs
and audit records.

## In the Console

The navigation rail lists nine areas.

| Area | What it does |
| --- | --- |
| Overview | Rollout counters and per-image staging progress. Carries the telemetry export badge. |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on the server's disk. |
| Inventory | Lists known devices with their management type, **Agent install** choice, assigned images, and recent reports. Assign or clear device roles here. |
| Policies | Creates, edits, imports, and exports role definitions. Shows sharing-policy health and instruction delivery diagnostics. |
| Onboarding | Starts and tracks install and undeploy jobs, once the device has a credential profile. |
| Swarm | Shows peer progress and which devices and seeders take part. |
| Monitoring | Holds the audit trail and the deployment log for each job. |
| Settings | Shows server configuration, version, and operational settings. |
| Audit | Records administrative and workflow actions. |

Three words in that table have a fixed meaning in IRIS:

| Word | What it means |
| --- | --- |
| Management type | How the agent reaches the network: on its own address, on your management VLAN, or through the router. See [Choose a management type](../install/management-types.md). |
| Role | A named group of devices that share with each other. A sharing policy is the rules that say which devices may share pieces with which. See [Control which devices share with each other](roles.md). |
| Instruction | The signed message the server sends a device saying which images to stage and how. |

The **?** button shows the running version and the stable id of this
deployment, with a copy button. Quote that id when you report a problem. It
also links to this site and to three pages the Console serves on an isolated
network: the local API reference at `/swagger/`, device troubleshooting, and
server troubleshooting.

## What you see

The Overview carries a telemetry export badge that reads `ok`, `degraded`,
`off`, or `unknown` when the health endpoint cannot be read. See
[Export telemetry](telemetry-export.md).

The device telemetry column and the Swarm Map show **Torrent TLS** as required,
off, or unknown, and mark an observation that has gone stale. This is the
policy the transfer daemon reports, not proof that a connection was encrypted.
The peer drawer adds the configured mode and the heartbeat time. Per-device
status is on [Assign images and check staging status](assignments.md).

## Settings

Open **Settings** and pick a section. Each section keeps its own address, so
you can bookmark it or send it to a colleague.

| Section | Address | What it covers |
| --- | --- | --- |
| General | `#settings/general` | The device-facing server address and the Console's browser URL, which can belong to different hosts. See [Server configuration](../reference/server-configuration.md) |
| TLS & trust | `#settings/tls` | This Console's certificate, the trusted CA store, and peer transfer encryption |
| Telemetry | `#settings/telemetry` | Where swarm progress, device reports and export health are published |
| Image verification | `#settings/bulkhash` | Checks of published images against the Bulk Hash, the checksum Cisco publishes for an image |
| Device packages | `#settings/packages` | Whether the packages devices install are ready to serve |
| Audit export | `#settings/audit` | The encrypted off-box copy of the audit trail |
| Setup checklist | `#settings/setup` | The four states a new server has to reach |

### Setup checklist

The checklist holds four cards: admin account, telemetry destination, device
packages, and image verification. The admin card links to General; the other
two open the setup flow at `#setup`. Every card carries a status chip:

| Chip | What it means |
| --- | --- |
| `ok` | The server checked the state and found it good. |
| `unset` | Nothing is configured yet. |
| `stale` | Something is configured, but the evidence behind it no longer matches. |
| `absent`, `unknown` | The server could not determine the state. A failed status fetch shows every chip as `unknown`. |

In the setup flow, a step panel lists every step with its state. Open the steps
in any order and skip any of them; `#setup` resumes at the first one still
outstanding. Creating the first administrator comes first: see
[Sign in for the first time](../install/first-sign-in.md).

### Device packages

This page reports whether the packages devices install are ready: the two IOx
packages (`iris-arm64.tar`, `iris-amd64.tar`) and the IOS-XR package
(`iris-xr.rpm`). Catalyst 9000 series switches run the agent in Guest Shell
from the bundle the server builds, or the IOx app when they have app-hosting
storage.

Each row binds the SHA-256 of the served package to the provenance manifest
beside it. `ok` means those bytes and that metadata agree, `stale` means the
digest no longer matches, and missing or malformed evidence reads `absent` or
`unknown`. The page prints the build command for every package family that is
not `ok`; run those commands on the Docker host. See
[Build and publish the device packages](../install/device-packages.md).

The card also turns non-green when the certificate the live service presents
differs from the copy onboarding distributes. Reconcile the two, then onboard
those devices again, as
[Rotate credentials and certificates](../admin-guide/rotations.md) describes.

### TLS & trust

**Certificate** installs the certificate this Console serves to browsers. Drop
or browse to a certificate and a private key, or expand **Paste certificate and
key instead**. A combined file works, and an encrypted key brings up a
passphrase field. **Use deployment default certificate** returns to the
deployment's identity.

**Trusted CAs** is the server's outbound trust store. Drop CA certificate files
to install them one by one, or pick a bundle source: the Cisco Trusted Root
Store (the default), the Mozilla CA bundle at `https://curl.se/ca/cacert.pem`,
or a URL of your own. A bundle appears as one row, and **Remove bundle**
returns you to the system store alone.

### Peer transfer encryption

**Peer transfer TLS** requires encryption for every transfer between devices,
and defaults to off. Turning it on migrates the seeder and every device:

1. Undeploy the agents that are already deployed.
2. Switch **Peer transfer TLS** on in the TLS & trust section of Settings.
3. Onboard those devices again, so each one receives the new mode.

The origin seeder, the server's own copy of the image and the first source in
the swarm, restarts by itself. The card shows its observed status next to the
setting you saved, which overrides the server's `IRIS_PEER_TLS_MODE` default.
To turn encryption off, set both sides to `disabled` and restart the IRIS peer
processes. See
[Security model and trust boundaries](../architecture/security-model.md) for
what the encrypted transport proves.

!!! warning
    A device that has not received the updated agent, the current bootstrap
    allowlist and the required peer mode cannot join a protected swarm. Peers
    in required mode never fall back to plaintext and cannot talk to older
    peers.

### Audit export

**Audit export** sets the destination of the encrypted off-box copy of the
audit trail, the recipient it is encrypted to, the SCP password, and a daily
schedule. It carries **Export now** and the outcome of the last run. To run
one, see [Routine maintenance tasks](../admin-guide/maintenance.md).

## Sessions and idle timeout

Your session expires when it goes idle. Only your own input and the changes you
make keep it alive, so a Console left open on a refreshing screen still reaches
the timeout that Settings advertises. Changing your password keeps the session
you are using and ends the others. If nobody can sign in, reset the
administrator account from the server host, as
[Routine maintenance tasks](../admin-guide/maintenance.md) describes.

## With the API

Use the Console for routine work: images, inventory, assignments, onboarding,
schedules, and monitoring. For automation, or for the exact request and
response contract, use the authenticated Console API under `/api/v1`. Image
assignment is per device, and the Console builds bulk selection from one
operation per device. Any request that changes state needs a Console session
and a cross-site request forgery (CSRF) token. For provisioning and signing
keys, follow [Install IRIS](../install/index.md) and
[Replace or recover signing keys](../admin-guide/instruction-keys.md).

## Related

- [Run IRIS day to day](index.md)
- [Stage your first image](first-image.md)
- [Assign images and check staging status](assignments.md)
- [Console API](../reference/console-api.md)
- [Automate with the API](automation.md)
