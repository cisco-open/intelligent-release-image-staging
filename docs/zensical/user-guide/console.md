<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Find your way around the Console

The Console is the browser interface you use to run IRIS every day. It forwards
your requests to the server, which owns images, inventory, credentials, jobs
and audit records.

## In the Console

The navigation rail groups the main views.

| Area | What it does |
| --- | --- |
| Overview | Deployment layout, hosts, containers or pods, rollout counters and per-image staging progress. Carries the telemetry export badge. |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on the server's disk. |
| Inventory | Lists known devices with their management type, **Agent install** choice, assigned images, and recent reports. Assign or clear device roles here. |
| Policies | Creates, edits, imports, and exports role definitions. Shows sharing-policy health and instruction delivery diagnostics. |
| Swarm | Shows peer progress and which devices and seeders take part. |
| Monitoring | Holds the audit trail and the deployment log for each job. |
| Settings | Shows server configuration, version, and operational settings. |

Start onboarding from **Inventory**. **Audit trail** and **Deployment logs**
sit under **Monitoring**.

Three words in that table have a fixed meaning in IRIS:

| Word | What it means |
| --- | --- |
| Management type | How the agent reaches the network: on its own address, on your management VLAN, or through the router. See [Choose a management type](../install/management-types.md). |
| Role | A named group of devices that share with each other. A sharing policy is the rules that say which devices may share pieces with which. See [Control which devices share with each other](roles.md). |
| Instruction | The signed message the server sends a device saying which images to stage and how. |

The **Help** button shows the running version and the stable id of this
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

### Peer transfers

On the Swarm Map, green arrows show server-to-device traffic. Blue arrows show
device-to-device traffic reported by an agent. Select a device for direction,
speed and report age. Gray spokes show participation. Old observations expire,
even when the map is paused;
connections with no unique device match remain unattributed.

Device-to-device arrows and faster reporting need **Telemetry reports** and
**Live telemetry** enabled when you onboard the device. See
[Turn on and tune live transfer samples](monitoring.md#turn-on-and-tune-live-transfer-samples).

The summary counts image-peer entries: one device can appear under several
images. An unavailable snapshot clears the count. The embedded map pauses when
you leave Swarm or hide the tab; a manual pause stays paused when you return.

In the device details, use **Peer telemetry** to choose **60 seconds** (the
default) or **10 seconds**, then **Save interval**. Review the device and
interval in the confirmation dialog when it appears. Faster reporting applies to
that device and needs the updated agent. Allow its next normal check-in to
apply the setting, then check **Reported interval**. Paused telemetry and
resource limits take precedence. While active, this adds up to six small
telemetry reports a minute. Image transfer settings stay unchanged.

If an interval save is unconfirmed, use **Review current interval** before
retrying. **Pull fresh data from device** tracks a specific report request;
unrelated reports do not complete it. Use **Review report request** after a lost
reply or when returning to a pending request.

### Audit trail

In **Monitoring → Audit trail**, choose a time range and category to find an
action. **Load older** keeps those pages in place during automatic refreshes;
**Refresh** returns to the newest events in the selected range. Drag on the
graph to narrow the time range, or focus it and use the arrow keys. If retention
changes the log while you browse, select **Refresh** when prompted.

## Settings

Open **Settings** and pick a section. Each section keeps its own address, so
you can bookmark it or send it to a colleague.

| Section | Address | What it covers |
| --- | --- | --- |
| General | `#settings/general` | The device-facing server address and the Console's browser URL, which can belong to different hosts. See [Server configuration](../reference/server-configuration.md) |
| TLS & trust | `#settings/tls` | This Console's certificate, the trusted CA store, and peer transfer encryption |
| Certificates & keys | `#settings/certificates` | Certificate deadlines, renewals and key rotation |
| Backup & restore | `#settings/backups` | Encrypted backups and recovery checks |
| Telemetry | `#settings/telemetry` | Where swarm progress, device reports and export health are published |
| Image verification | `#settings/bulkhash` | Checks of published images against the Bulk Hash, the checksum Cisco publishes for an image |
| Device packages | `#settings/packages` | Whether the packages devices install are ready to serve |
| Audit export | `#settings/audit` | The encrypted off-box copy of the audit trail |
| Setup checklist | `#settings/setup` | The four states a new server has to reach |

General, TLS & trust, Telemetry and Audit export keep ordinary drafts during
status refreshes. Passwords, private keys and passphrases clear after submission
or when you leave the section or hide the tab.
If a save has an uncertain result, use **Reload current settings** and review
what is stored before retrying. For an uncertain password change, sign in again.
Leaving a page does not cancel an already submitted request.

### Setup checklist

The checklist holds four cards: admin account, telemetry destination, device
packages, and image verification. The admin card links to General; the other
cards open the setup flow at `#setup`. Every card carries a status chip:

| Chip | What it means |
| --- | --- |
| Done | The server checked the state and found it good (`ok`). |
| Not configured | The optional integration is unset. |
| Needs rebuild | Package evidence is stale. |
| Not built | A package is absent; build it if you use that platform. |
| Cannot determine | Evidence is unknown or the status fetch failed. |

The image verification card can also show that it is configured with no
successful run yet: a schedule exists but has not
produced a successful run, which is not the same as never configured at all.

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

Each wrapper row compares the SHA-256 of the served package with its adjacent
provenance manifest. **Done** means they agree; the check does not authenticate
that manifest or verify a native signature. **Artifact updated** is the file's
modification time. Guest Shell uses separate startup provisioning evidence.
Build or repair packages for the platforms you use on the build host, then
select **Re-check packages**. See
[Build and publish the device packages](../install/device-packages.md).

The card also turns non-green when the certificate the live service presents
differs from the copy onboarding distributes. Reconcile the two, then onboard
those devices again, as
[Rotate credentials and certificates](../admin-guide/rotations.md) describes.

### TLS & trust

**Certificate** installs the certificate this Console serves to browsers. Drop
or browse to a certificate and a private key, or expand **Paste certificate and
key instead**. A combined file works, and an encrypted key brings up a
passphrase field. The Console decrypts it at import with `openssl pkey`,
piping the passphrase over stdin and never placing it on the command line, and
stores the key age-encrypted at rest either way. **Use deployment default
certificate** returns to the deployment's identity.
A saved certificate is only active when the Console confirms it was applied.
If it asks for a restart, restart the Console and verify a new browser connection.

**Trusted CAs** is the server's outbound trust store. Drop CA certificate files
to install them one by one, or pick a bundle source: the Cisco Trusted Root
Store (the default), the Mozilla CA bundle at `https://curl.se/ca/cacert.pem`,
or a URL of your own. A bundle appears as one row, and **Remove bundle**
returns you to the system store alone.
Upload public CA certificates without private keys. If one upload has an
uncertain result, the remaining files are left unattempted for you to review.

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
Leave the password blank to keep the saved password. Download and export jobs
continue when you leave their page; returning resumes status checks for the
same job. An unavailable status does not mean the job stopped.

## Deployment information

The **Deployment components** panel on Overview shows the deployment layout.
Expand it to see hosts, containers or pods. It stays open while status refreshes;
unavailable information is flagged even when the panel is collapsed.
Each row identifies the Console or tracker/distribution
component, its host or node, container or pod name, image and observed state.
Runtime details include the operating system, architecture and shared host kernel
when reported. Kubernetes rows also show the pod IP and deployment namespace.

Managed installs read their own containers or pods through the host maintenance
worker. Inventory is cached for 30 seconds; the panel shows its observation time.
Other installs show the server and Console serving the current request, with a
notice that the full inventory is unavailable. **Not reported** means that the
runtime could not provide that fact. A container hostname is not a host address.

The default Docker layout has two containers on one host. A combined runtime is
labelled **Single container** only when its deployment metadata declares that layout.

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
