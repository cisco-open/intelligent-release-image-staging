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

The server uses a self-signed certificate by default. Create the initial admin in the browser or with:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

## Console areas

| Area | What it does |
| --- | --- |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on disk. |
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
already published, and is not ambiguous. Everything else is listed greyed out
with its reason. Two of the three reasons are actionable from this screen:

- `ambiguous name in more than one location` — remove or rename the duplicate so
  exactly one file claims the ID, then re-check the panel.
- `not readable by the server` — fix ownership so uid 10001 can read the file and
  traverse its directory, then re-check the panel. See
  [Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment).

`already published` needs nothing; the image is already in the catalog under its
derived ID. For the exact definitions see
[Import skip reasons](reference.md#import-skip-reasons).

Ambiguity is refused rather than guessed. Reseeding prefers the catalog entry's
recorded `source_dir` and falls back to a basename walk only for entries
published before that field existed or whose directory has since gone away; the
seeder runs with `bt-seed-unverified`, so a wrong directory would serve the
wrong bytes under correct piece hashes.

Because publishing records `source_dir`, **Delete** unlinks the file only when
that directory resolves to the uploads volume: an image published in place from
the read-only import root is removed from the catalog and left on disk. See
[Catalog entry fields](reference.md#catalog-entry-fields).

## Management type

The Add Device form has an explicit **Management type** choice, and the
device table shows each device's attachment rather than a bare VLAN/SVI value:

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
C8000v across onboarding, image staging, receipt-backed undeploy, Swarm Map, and
Grafana telemetry.

Each onboard records a durable **receipt** of what it applied, and **Undeploy**
runs only from that receipt, so editing inventory after onboarding cannot
retarget cleanup. A device deployed before receipts existed shows no active
receipt; use the row's **Adopt** action (an explicit, audited, no-change
recording of current ownership) before undeploying it. Router deployments cannot
be adopted — re-onboard instead. For preflight and receipt ownership see
[Deployment plans and applied receipts](network-attachment.md#deployment-plans-and-applied-receipts).

## Bulk device actions

The Devices toolbar acts on every checked row, so a CSV import can be finished
without touching each device:

| Control | What it does | Confirms first |
| --- | --- | --- |
| Onboard selected | Queues an onboard job per device and tracks them in the batch panel; the server runs a bounded number at a time and queues the rest. | No |
| Undeploy selected | Runs receipt-driven cleanup on each device. | Yes — one dialog for the whole selection, naming what teardown removes and preserves |
| Adopt selected | Records the ownership receipt for each device. | Yes — a dialog listing the selected devices |
| Delete selected | Removes the inventory rows only. | Yes — the same confirmation text the per-row delete uses, listing the devices |
| *credential for selected* + **Apply** | Assigns one credential profile to every checked device. Leaving the picker on either blank entry clears the credential instead. | No |

The bulk **Adopt** dialog is not the per-row one: it is shorter and names the
whole selection. Both warn that you should only adopt a device whose inventory
row matches what is really on the box, both point at re-onboarding as the safer
and idempotent alternative, and both send the acknowledgement the server requires
— an adopt that omits it is refused. Only the per-row dialog explains that adopt
makes no change to the device, and only the bulk dialog states up front that
routers cannot be adopted.

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

GUI-driven onboarding uses stage-host credentials to run the same install logic that the CLI generates. The sensitive values belong in the console or the server secret store, not in Git. Generated per-device staging files are temporary and swept after their configured age.

## When to use the CLI

Use the CLI when you want a reproducible batch operation from reviewed CSV files. Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.
