<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Web Console

The console is the preferred operator surface once the server is running. It does not replace the CLI; it wraps common workflows and makes network state visible.

## First run

Open:

```text
https://<server-ip>:8080/
```

The server uses a self-signed certificate by default. Before an admin account
exists, sign in with the default credential `iris` / `irisisgreat!` — it only
works pre-setup — which takes you straight to the setup wizard to create the
real admin account. Or create the initial admin from the container instead:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

## Console areas

| Area | What it does |
| --- | --- |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on disk. |
| Devices | Lists known devices, their **management type**, platform details, current assignment, and recent reports. |
| Assignments | Maps each device to the image it should stage. |
| Onboarding | Starts and tracks install or undeploy jobs when the device's assigned credential profile is configured. |
| Swarm | Shows peer progress and seeder/device participation. With `IRIS_EVENTS_URL_TEMPLATE` configured, the peer drawer renders a "View this device's events" link into the operator's own backend; without it, no link renders. |
| Monitoring | Holds the audit trail and per-job deployment logs. Carries the *Telemetry export* badge (`ok` / `degraded` / `off`) fed by the hub's OTLP export health. |
| Settings | Shows server configuration, version, and operational settings. |
| Audit | Records administrative and workflow actions. |

For IOx devices, the Devices status distinguishes `copying to <filesystem>` from
the torrent download phase while the app transfers a completed image from its
container storage into IOS-visible storage. A final-placement failure is shown
as `placement failed` with a bounded diagnostic; inspect the device's
`IRIS ROOTCOPY-FAIL` syslog entry for the full device-side detail.

On the Images screen, every picked or dropped file gets its own upload row —
filename, progress bar, then publish state — with its own publish poller, so
concurrent uploads report independently and a failed file names its error
without stopping the others. Finished rows fade out on their own; failed rows
stay until dismissed. A file over the 4 GB upload cap is refused in the
browser before any bytes move.

The header's **?** button opens a help popover with the running version, the
stable per-deployment id (with a copy button — quote it when reporting a
problem so reports from different installations stay distinguishable), a link
to this documentation site, and two guides the console serves itself —
*Device-side troubleshooting* and *Server-side setup & troubleshooting* — so
both stay reachable from a network with no internet access.

## Importing images already on disk

Besides the upload box, the Images screen has an **Import from disk** panel that
lists image files present on the server but missing from the catalog — orphaned
uploads left behind by a catalog reset, and files an operator placed under the
read-only image root. Both image roots are scanned recursively: the read-write
uploads volume (`IRIS_IMAGES_DIR`) and the read-only import root (`IMAGES_ROOT`,
the `IRIS_IMAGE_ROOT` host tree bind mounted `:ro`). See
[Image path variables](reference.md#image-path-variables).

Importing publishes **in place**: the publish seeds from the file's own
directory, so nothing is copied and the read-only root stays read-only, and the
`.torrent` is written to the server's state directory rather than next to the
image. The import runs as an ordinary publish job with the same progress
reporting as an upload, and is recorded in Audit as `image_import` (also with
`result=fail` when a request is rejected).

A file is offered only when it is a `.bin`, passes the filename charset gate, is
not a dotfile or a `.torrent`/`.upload` temporary, resolves inside its own root
(so a symlink cannot reach outside it), is readable by the server, is not
already published, and is not ambiguous. Files failing the silent gates (wrong
extension, dotfiles, temporaries, symlinks escaping the root) are hidden
entirely; the remaining three failure reasons — `already published`,
`ambiguous name in more than one location`, and `not readable by the server` —
are listed greyed out with the reason named. Two of those three are actionable
from this screen:

- `ambiguous name in more than one location` — remove or rename the duplicate so
  exactly one file claims the ID, then re-check the panel.
- `not readable by the server` — fix ownership so uid 10001 can read the file and
  traverse its directory, then re-check the panel. See
  [Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment).

`already published` needs nothing; the image is already in the catalog under its
derived ID. For the exact definitions see
[Import skip reasons](reference.md#import-skip-reasons).

Ambiguity is refused rather than guessed. Reseeding prefers the catalog entry's
recorded `source_dir`. Only for entries published before that field existed, or
whose directory has since gone away, does it fall back to searching both image
roots for a file with the entry's filename. The seeder runs with
`bt-seed-unverified`, so a wrong directory would serve the wrong bytes under
correct piece hashes.

Because publishing records `source_dir`, **Delete** unlinks the file only when
that directory resolves to the uploads volume: an image published in place from
the read-only import root is removed from the catalog and left on disk. See
[Catalog entry fields](reference.md#catalog-entry-fields).

## Management type

The Add Device form has an explicit **Management type** choice, and the
device table shows each device's management type rather than a bare VLAN/SVI value:

- **Routed - IRIS-managed app network** — IRIS creates a dedicated VLAN and SVI.
  Onboarding is one-click and create-only.
- **Inband - existing management VLAN** — the agent attaches to an existing,
  operator-owned VLAN that IRIS never creates, changes, or removes.
- **Router routed - IRIS-managed VPG subnet** — creates a VirtualPortGroup and
  routed app subnet; the operator provides routes to IRIS and peers.
- **Router NAT - VPG behind NAT** — adds overload NAT and static TCP PAT for
  port 6881. The receipt preserves a pre-existing `ip nat outside` marking.

Router choices show the VPG number and app addressing; Router NAT also requires
the outside interface. Both target the Catalyst 8000 family and are validated on
Catalyst 8000V across onboarding, image staging, receipt-backed undeploy, Swarm Map, and
OpenTelemetry (OTLP) export.

Each onboard records a durable **receipt** of what it applied, and **Undeploy**
runs only from that receipt, so editing inventory after onboarding cannot
retarget cleanup. A device deployed before receipts existed shows no active
receipt; check its row and use the toolbar's **Adopt** action (an explicit,
audited, no-change recording of current ownership) before undeploying it. Router deployments cannot
be adopted — re-onboard instead. For preflight and receipt ownership see
[Deployment plans and applied receipts](network-attachment.md#deployment-plans-and-applied-receipts).

Each device row's **ⓘ Deployment details** control opens a read-only panel
under the table showing what the deployment holds: the receipt state
(`active`, `removed`, `superseded`, `needs-reconcile`) and receipt id, the
preflight result, and the resolved configuration the onboard applied — the
attachment type, the owned management VLAN or VPG, SVI and app addressing,
NAT interface, swarm port, and the recorded model, platform, and device
identity. A device with no receipt says so, naming adopt or re-onboard as the
fix. The panel ends with that device's persisted deployment logs
([Deployment logs](#deployment-logs)), each viewable in place.

## Bulk device actions

The Devices toolbar acts on every checked row, so a CSV import can be finished
without touching each device:

| Control | What it does | Confirms first |
| --- | --- | --- |
| Onboard selected | Queues an onboard job per device and tracks them in the batch panel; the server runs a bounded number at a time and queues the rest. | No |
| *Telemetry reports* / *Telemetry streaming* checkboxes | Set the deployed agent's telemetry posture for every onboard started from this toolbar (single-row onboards included). Reports default on; streaming defaults off ([Transfer streaming](observability.md#transfer-streaming)). A bulk redeploy with the boxes toggled is the site-scale enable/disable path. | No |
| Undeploy selected | Runs receipt-driven cleanup on each device. | Yes — one dialog for the whole selection, naming what teardown removes and preserves |
| Adopt selected | Records the ownership receipt for each device. | Yes — a dialog listing the selected devices |
| Delete selected | Removes the inventory rows only. | Yes — a dialog listing the devices and warning that deletion is not an undeploy |
| *credential for selected* + **Apply** | Assigns one credential profile to every checked device. Leaving the picker on either blank entry clears the credential instead. | No |

The **Adopt** dialog names the whole selection. It warns that you should only
adopt a device whose inventory row matches what is really on the box, points at
re-onboarding as the safer and idempotent alternative, states up front that
routers cannot be adopted, and sends the acknowledgement the server requires —
an adopt that omits it is refused.

Bulk operations report per-device refusals rather than failing the whole batch:
the status line shows how many devices succeeded and names the ones that did
not, with the server's reason. Adopting a router, for example, comes back as a
`409` for that device while the rest of the batch proceeds.

Creating or deleting a credential profile re-renders the device rows
immediately, so a device imported before any profile existed becomes assignable
at once instead of after the next ten-second poll.

!!! warning "Deleting inventory is not an undeploy"
    Delete removes the Console record and nothing else. An onboarded device
    keeps its agent and its staged image, with no inventory entry left to manage
    it. Undeploy first if that is what you meant. The deletion cannot be undone.

## Onboarding from the console

GUI-driven onboarding uses the device's assigned credential profile to run the same install logic that the CLI generates. The sensitive values belong in the console or the server secret store, not in Git. Generated per-device staging files are temporary and swept after their configured age.

Guest Shell onboards probe device reachability before running the installer:
an unpingable or unreachable IP fails the job immediately with `cannot reach
device <ip> — ping/SSH probe failed; check the device IP and credentials`,
instead of hanging inside an opaque SSH timeout. Router and IOx onboards
already run their own live preflight, so all three platforms now fail loud on
an unreachable device. Every onboarding rejection — a failed preflight, a
busy device, an unreachable device, a router already holding a deployment
receipt — is rendered in the console and recorded in Audit, whether it is
refused at submit time or fails once the job is running.

### Job log windows

The batch panel's per-row **log** button opens one log window per job, each
with its own live stream, **Abort**, and **Close**, so concurrent onboards
never write into (or blank) each other's window. At most six windows stay
open; opening more closes the oldest. **Abort** is queue-aware: a job still
waiting for an install slot is taken out of the queue instead — scoped to
just that job, other queued work is untouched — while aborting a running job
stops the installer, with the confirmation warning that the device may be
left partially configured (re-onboard, which is idempotent, or undeploy to
clean up). A window opened on a queued job says so and starts streaming the
moment the job wins a slot.

### Deployment logs

Job windows are live views; the durable record is Monitoring →
**Deployment logs** (`#monitoring/deploylogs`). Every finished onboard or
undeploy job's installer output is persisted on the server under the state
directory, so the logs survive console reloads, session changes, and server
restarts; the newest 200 are kept. The table lists each log's finish time,
device, action, result, and size, filters by device id, and shows the full
log in place. The same list, already filtered to one device, sits at the
bottom of that device's deployment-details panel on the Devices screen.

## Settings

Settings is a sidebar feature with its own sub-menu — **General**, **TLS &
trust**, **Telemetry**, and **Audit export** — rather than an in-page tab
strip. Each sub-page is deep-linkable: `#settings/general`, `#settings/tls`,
`#settings/telemetry`, `#settings/audit`.

### TLS & trust

- **Certificate** — drop (or browse to) a certificate and private key, or
  paste PEM directly. Files are classified by their PEM content rather than
  extension, so a single combined cert+key file works. Dropping an encrypted
  private key reveals a passphrase field; the key is decrypted at import
  (`openssl pkey`, passphrase piped over stdin, never on the command line)
  instead of being rejected, and is still stored age-encrypted at rest either
  way. **Use built-in certificate** reverts to the shipped self-signed cert
  and appears only once a custom certificate is installed.
- **Trusted CAs** — drop one or many CA certificate files to install them
  individually, or use the CA bundle source picker to download and trust a
  whole public bundle: Cisco Trusted Root Store (default), the Mozilla CA
  bundle (`https://curl.se/ca/cacert.pem`), or a custom URL. The downloaded
  bundle appears as a single row in the trusted-CA table, labelled with its
  source; removing that row (**remove bundle**) is how you revert to
  system-store-only trust. A failed download never replaces the previous
  bundle.

### Audit export

The **Audit export** sub-page configures the age-encrypted off-box copy of
the audit trail — destination, age recipient, SCP password, daily schedule —
and carries the **Export now** button plus a status line showing the
configured destination and the last run's outcome. The operational behaviour
is described in [Audit export](operations.md#audit-export).

## When to use the CLI

Use the CLI when you want a reproducible batch operation from reviewed CSV files. Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.
