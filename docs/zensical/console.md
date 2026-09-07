<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Web Console

The Console runs in its own container and provides the browser interface and
operator API. It forwards authenticated requests to the server, which owns
images, inventory, credentials, jobs, and audit records.

## First run

Open:

```text
https://<console-address>:8080/
```

Use the configured Console host and port. In the one-host Compose stack this
is `IRIS_HOST_IP`; a separate deployment has its own Console address. Its
browser certificate is independent of the device/catalog certificate. Before an admin account
exists, sign in with the default credential `iris` / `irisisgreat!`. A correct
login creates no session; it yields a one-use setup grant that expires after
ten minutes and takes you to the account-creation page. Creating the real admin
permanently ends this special behavior, after which the pair is checked only
against the stored administrator credentials and normally fails.

!!! warning "The first reachable caller can claim a fresh Console"
    Keep the Console on a trusted management network and complete admin setup
    immediately after deployment. Do not expose a brand-new Console to an
    untrusted network while no administrator exists.

Or create the initial admin from the container instead:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

### Finishing setup

Creating the admin is the first of four things a new server needs. The sign-in
straight after it lands on the **setup flow** (`#setup`) — a real Magnetic
Stepper, not a linking checklist: a step panel on the left, the active step's
own controls on the right — which walks the other three in order:

1. **Telemetry destination** — where swarm progress, device reports and export
   health are published. Already satisfied if the deployment environment sets
   `IRIS_OTLP_ENDPOINT` and observability is enabled, in which case the step
   shows as done rather than being hidden.
2. **Device packages** — whether each served IOx package and the IOS-XR agent
   RPM (`iris-xr.rpm`) matches its canonical-image provenance, plus whether
   the live and distributed copies of the runtime certificate agree — see
   below.
3. **Image verification** — the Cisco Bulk Hash source check against published
   images. Configured inline: refresh now, enable the daily schedule, a
   pointer to downloading Cisco's Bulk Hash feed for air-gapped servers, and
   the offline feed-file import. These are the same controls Settings ›
   Image verification exposes — the wizard step mounts them in place rather
   than duplicating them.

The forms are hosted in the flow itself, so finishing setup does not send you
round the Settings pages. A step panel on the left shows every step with its
current state — completed steps carry a check, the current step is filled in,
upcoming ones stay outline-only — and lets you open any of them directly, in
any order.

Every step can be skipped, and re-entering `#setup` resumes at the first one
still outstanding. The package step shows the server's inspection results and
provides build commands to run on the Docker host. Use **Re-check** after a
build. Neither runtime container has a Docker socket.

While anything is outstanding, a banner offers the way back. It dismisses for
the session rather than permanently, because a package that goes stale later is
a silent failure with no other symptom, and a banner dismissed for good would
hide precisely the case this exists to catch.

Settings › Setup keeps reporting the same four states afterwards, for checking
a server long after it was installed — including a schedule for image
verification that is configured but has not yet produced a successful run,
worded distinctly from one never configured at all.

### Branding

The console's headings render in Cisco's Sharp Sans Bold typeface where it is
available, and in the browser's default sans-serif font otherwise
(`font-display: swap`) — a cosmetic difference only, never a functional one.
The `.woff2` file is excluded from the Docker build context and the release
tarball (`.dockerignore`): Cisco's license for it does not permit
redistribution, so it can never ship inside the image. A deployment that
independently holds the license restores it at runtime, without ever
touching the image, by bind-mounting the file over Compose's
`IRIS_SHARP_SANS_FONT_HOST` variable — see [Reference](reference.md) —
before `docker compose up`. Left unset, the console looks identical apart
from the fallback font.

## Console areas

| Area | What it does |
| --- | --- |
| Overview | Rollout counters and per-image staging progress. Carries the *Telemetry export* badge (`ok` / `degraded` / `off`, or `unknown` when the health endpoint cannot be read), fed by the hub's OTLP export health. |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on disk. |
| Devices | Lists known devices, their **management type**, **Agent install** choice, assigned images, and recent reports. |
| Onboarding | Starts and tracks install or undeploy jobs when the device's assigned credential profile is configured. |
| Swarm | Shows peer progress and seeder/device participation. |
| Monitoring | Holds the audit trail and per-job deployment logs. |
| Settings | Shows server configuration, version, and operational settings. |
| Audit | Records administrative and workflow actions. |

For IOx devices, **Copying to <filesystem>** means the app is copying the
downloaded image to IOS storage. **Staging failed** reports a download,
verification or placement error. Read the diagnostic beside the status; for
placement failures, the device's `IRIS ROOTCOPY-FAIL` syslog entry has more detail.

After a new assignment, an idle device shows **Waiting for staging** until its
agent reports activity. **Staging now** counts devices reporting work. Current
image errors take precedence over older staged flags in Devices and Overview.

On the Images screen, every picked or dropped file gets its own upload row —
filename, progress bar, publish state, then Cisco Bulk Hash verification —
with its own publish poller, so
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
reporting as an upload. After publication it immediately reconciles the
catalog against Cisco's Bulk Hash feed even when the schedule is off; the job
stays in `verifying` until that pass returns and reports `verified`,
`mismatch`, `not in feed`, or an explicit incomplete-check reason. Publication
remains durable if the feed is unavailable. The import is recorded in Audit as
`image_import` (also with `result=fail` when a request is rejected).

A file is offered only when it has an explicit Cisco software suffix (`.bin`,
`.iso`, `.tar`, or `.rpm`), passes the filename charset gate, is not a dotfile
or a `.torrent`/`.upload` temporary, resolves inside its own root
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
  [Volume permissions](server.md#volume-permissions).

`already published` needs nothing; the image is already in the catalog under its
derived ID. For the exact definitions see
[Import skip reasons](reference.md#import-skip-reasons).

Ambiguity is refused rather than guessed at import. Startup reseeding prefers
the catalog entry's recorded `source_dir`. If that field is absent or its
directory is unavailable, it searches both image roots for a file with the
entry's filename. The seeder runs with
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
  port 6881. The deployment record preserves a pre-existing `ip nat outside` marking.
- **XR host - router's own network stack** — the appmgr container runs on
  the router's own network stack; there are no app-network fields to set.

A device without a management type reads **Inventory only — management type
not chosen**. Choose a management type before onboarding it. See
[Inventory](fleet-workflows.md#inventory).

Management type alone controls the network fields in Add Device. Model is
optional free text; known models narrow the **Agent install** choices without
changing the management type. A model such as `C3650` can be saved, but that
does not confirm hardware support. XR host selects `xr-appmgr`, router modes
select `router`, and routed/inband modes require a compatible Guest Shell or
IOx choice.

Router choices show the VPG number and app addressing; Router NAT also requires
the outside interface. Both target the Catalyst 8000 family and are validated on
Catalyst 8000V across onboarding, image staging, record-backed undeploy, Swarm Map, and
OpenTelemetry (OTLP) export.

Each onboard creates a durable **deployment record** of what it applied, and **Undeploy**
runs only from that deployment record, so editing inventory after onboarding cannot
retarget cleanup. If an agent is present without an active deployment record,
check its row and use the toolbar's **Adopt** action (an explicit,
audited, no-change recording of current ownership) before undeploying it. Router deployments cannot
be adopted — force-undeploy the IRIS footprint, then onboard again. For preflight and deployment-record ownership see
[Deployment plans and applied records](management-type.md#deployment-plans-and-applied-records).

Each device row's **ⓘ Deployment details** control opens a read-only drawer
beside the table — it slides in from the right, closes on **Esc** or **✕**, and
leaves the row you opened it from where it was. It opens on an **Images** table
listing every image currently assigned to the device:

- `ready`: staged and verified.
- `error`: the agent reported a failure.
- `staging`: the agent is working on the image.
- `pending`: staging has not been reported.

For a single image, the drawer shows the agent's detailed state and error.
For multiple images, the shared error appears in **Last reported error** below
the table. A device with failed images shows `N of M image(s) failed` in the
Status column.

Below that, it shows the deployment record state (`active`,
`removed`, `superseded`, `needs-reconcile`,
`abandoned`) and record id, the
preflight result, and the resolved configuration the onboard applied — the
management type, the owned management VLAN or VPG, SVI and app addressing,
NAT interface, swarm port, and the recorded model, **Agent install** choice, and device
identity. A device with no deployment record says so, naming adopt or re-onboard as the
fix. The drawer ends with that device's persisted deployment logs
([Deployment logs](#deployment-logs)), each viewable in place. A run that
finished before the current device was registered under this name is labelled
**previous device**. Logs are keyed on the device id and deliberately survive a
delete — they are the record of what actually ran — so a rebuilt or replaced box
added back under the same name inherits its predecessor's runs. They are kept
and shown, never presented as this device's own history. Devices registered
before IRIS started stamping registration time carry no stamp, and nothing is
labelled for them.

The Swarm Map's **Image staging** section lists images from the device's last
heartbeat. The Devices drawer lists current assignments, including pending
ones. A new assignment can therefore appear in Devices before it appears on
the map.

Open swarm details update with the map. **Tracker role** describes torrent
participation: a seeder may still be verifying or placing an image. **Ready**
requires the device to report staging complete. Rates and verification results
identify the image they describe. Measurements that cannot be tied to a
participant are unavailable.

### Roles and peer-policy status

The Devices table's **Role** column shows the declared fleet role, or a dash
when none is declared. **Filters → Role** offers *Role: any*, *— no role —*,
and the complete policy role list, including roles absent from the current
page. The filter is applied by the server before paging.

For a selection, open **More actions → Set role…**. Leaving the disabled initial
placeholder untouched is a no-op; choosing the explicit *— no role —* option
clears membership. **Preview change** sends one aggregate dry run for every
selected device and shows the four access/membership impact counts, whether QoS
changes, per-device failures, and the confirmation threshold. **Set role** uses
the original pre-preview ETag and that preview's confirmation token in one
aggregate commit. Cancel never commits. A concurrent change or confirmation
refusal discards the preview and requires a refresh and new preview; the Console
never silently retries policy intent, and an all-failed preview cannot commit.
If the commit connection or response is
unreadable, **changes may have been saved**: refresh policy and Fleet state,
review drift, and preview again rather than repeating the request.

The collapsed **Peer policy** disclosure above Devices summarizes role and
restricted-role counts, drift, and outbox occupancy (`N/256`). Expanding it
shows per-role member counts, the last origin-QoS state and download counts,
the mutual-origin **preflight count only**, and the explicit-ACL shadowing rule.
It never displays peer addresses or raw deny lists. Degraded, fail-closed, and
unavailable states remain distinct. A capability banner blocks role changes
unless the server explicitly returns `roles_supported: true`; a fully old
Console/server pair cannot show this warning, which is why downgrade uses the
quarantine-first procedure in [Role-policy operations and
rollback](operations.md#role-policy-operations-and-rollback).

The Set role action and its apply controls remain disabled while capability or
policy health is uncertain. The UI's degraded state can cover LKG fallback or
lost role state; the state-owning management process startup log provides the
specific lost-state signal.

The existing quarantine filter and per-row/bulk quarantine actions remain in
place. Quarantine intent uses its existing badge and stays distinct from the
tracker's last enforcement state.

The Console intentionally has no role-policy JSON editor and no QoS editor.
Use `iris-role` for definitions, definition-scoped QoS, membership, ACL
migration, and one device's declared/compiled role and drift. Global QoS and
pair explanations are available only through the documented API.

Phase 0 changes future tracker introductions only; it
does not sever existing connections or remove retained peers. For immediate
containment, unassign every image from the affected device and let its current
agent remove those torrents on the next tick. Device-side rate intent is
cooperative, and a privileged device administrator can alter the device
environment.

An `abandoned` deployment record is one that no longer describes a device IRIS manages:
the device was deleted from the inventory, or a forced teardown stripped the
agent without using the deployment record as authority. It is kept as the account of what
IRIS built on that box, but it never authorises a teardown and never blocks an
onboard again.

## Bulk device actions

The Devices toolbar acts on the current *selection*, so a CSV import can be
finished without touching each device.

Above it, the filter bar narrows what the table shows — free text across
device, IP and model, plus management type, **Agent install**, credential,
telemetry, peer policy and status. Filtering happens on the server, not just
in the browser: every one of these controls (and the free-text search) is
applied by the same `GET /api/v1/devices` request the table polls, so the count
next to the filter bar and the rows on screen can never disagree about what
"matches" means, no matter how large the fleet is. The **Status** choices are
generated from the same derivation the Status column renders, so every state
a row can show can be filtered for. Each dropdown choice shows the same
sentence-case label the column renders: `Onboarding`, `Undeploying`, `Waiting
for heartbeat`, `Waiting for staging`, `Onboard failed`, `Undeploy failed`, `Staged`, `Staging
failed`, `Image(s) failed`, `Copying to IOS storage`, `Staging (other)`,
`Enrolled`, `Not enrolled`, and `Offline (no recent heartbeat)` — but its
`<option>` value, and the wire status the cell itself carries, is the
lowercase/kebab form underneath: `onboarding`, `undeploying`,
`waiting-heartbeat`, `waiting-staging`, `onboard-failed`, `undeploy-failed`, `deployed`,
`placement-failed`, `image-failed`, `copying`, `staging`, `enrolled`,
`not-enrolled`, and `offline` — the last being a modifier, since a device
filtered on `deployed` (rendered `Staged`) can still have gone quiet.

### Paging and selection at fleet scale

A fleet larger than 200 devices (after filtering) pages: the table shows 200
rows at a time with **Previous**/**Next** controls and a "Page *X* of *Y*"
readout next to the results count, instead of re-fetching and re-rendering
every device on every 10-second poll. This is deliberately the *last* piece
of this design, not the first — a table that silently showed a page as if it
were the whole fleet, or a **select all** that silently meant "this page,"
would be worse than a slow table, so two things had to be true first:

- Every filter above is enforced **server-side**, so a page can never hold
  rows the filter bar disagrees with.
- Selection is tracked by **device ID**, not by which checkboxes happen to be
  rendered. Checking rows on page 1, turning to page 2, and checking more
  there keeps every earlier check — the selection count in the bulk bar
  always reflects everything you have checked across every page, filter
  change, and 10-second poll, not just what is currently on screen.

The header checkbox (above the **Device** column) only ever selects or
clears the page currently on screen — with paging, it cannot mean anything
else, and its accessible name says "on this page" to make that explicit.
Once every row on a page is checked, the bulk bar offers **Select all *N*
matching devices**, naming the server's own count for the active filter. That
control performs a real walk of every remaining page under the current
filter and adds each device's ID to the selection; it is never a shortcut
that quietly re-checks the header box. Once every matching device really is
selected, the bar says so plainly ("All *N* matching devices selected")
rather than leaving you to infer it from a checkbox state. Clearing the
selection (**Cancel**) always clears the full cross-page set, not just the
rows in view.

| Control | What it does | Confirms first |
| --- | --- | --- |
| Onboard selected | Queues an onboard job per device and tracks them in the batch panel; the server runs a bounded number at a time and queues the rest. | No |
| *Telemetry reports* / *Telemetry streaming* checkboxes | Set the deployed agent's telemetry posture for every onboard started from this toolbar (single-row onboards included). Reports default on; streaming defaults off ([Transfer streaming](observability.md#transfer-streaming)). A bulk redeploy with the boxes toggled is the site-scale enable/disable path. | No |
| Undeploy selected | Runs record-driven cleanup on each device. | Yes — one dialog for the whole selection, naming what teardown removes and preserves |
| Adopt selected | Creates the ownership deployment record for each device. | Yes — a dialog listing the selected devices |
| Delete selected | Removes the inventory rows only. | Yes — a dialog listing the devices and warning that deletion is not an undeploy |
| *Set credential…* + **Apply** | Assigns one credential profile to every checked device. The picker opens on a disabled placeholder, so Apply with nothing chosen does nothing; choosing *no credential (clear the assignment)* clears it instead. The modal does not open while the profile list has failed to load. | Only when clearing — a dialog naming the device count |
| More actions → Set role… | Previews and applies one role (or an explicit clear) to the whole cross-page selection in a single CAS-protected operation. | Always when effective membership/access or QoS changes; uses the reviewed preview token |
| Assign images to selected | Opens the shared image picker for the whole checked selection — the bulk form of each row's own control in the **Assigned images** column, and the reason the filter bar exists: filter to a platform or model, select all, assign. | Only when it would unassign every image |

A device can have up to ten images assigned at once, staged and transferred in
parallel; the per-row control in the **Assigned images** column (reading `N
image(s)` when images are assigned, `— assign —` when none are) and the
toolbar's **Assign images to *N* devices…** button open the same checkbox
picker, reading `Choose images` with a live `n/10` count — an eleventh box
disables itself rather than waiting for a server-side rejection. Applying to
a multi-device selection pre-checks the *intersection* of what the selection
already has assigned — never the union — so **Apply** can never silently add an
image to a device that lacks it. Apply then writes the checked set to *every*
selected device, so an image a device has that you leave unchecked is dropped
from it: whenever the selection's assignments are not all identical, the picker
says so and **Apply** asks you to confirm before it posts. Applying an empty pick is a
deliberate unassign and confirms first, whether for one device or for the
whole selection. On the next policy poll, the agent stops an unassigned
torrent and removes its download data. IOS-XE keeps an already placed root
image for reuse or later guarded reclaim. IOS-XR downloads directly to the
root, so it removes an IRIS-downloaded file but preserves an operator-adopted
file or one whose origin is unknown. See
[Unassigned image park](device-agents.md#unassigned-image-park) for what
reclaims that space and when.

The **Adopt** dialog names the whole selection. It warns that you should only
adopt a device whose inventory row matches what is really on the box, points at
re-onboarding as the safer and idempotent alternative, states up front that
routers cannot be adopted, and sends the acknowledgement the server requires —
an adopt that omits it is refused.

The **Undeploy** dialog's **Force** checkbox covers a device stranded with no
*usable* deployment record. That is either no deployment record at all — typically an
onboard that enabled the agent but died before its deployment record was written — or a
deployment record that no longer describes the box in front of it. The second case is a
device that was rebuilt or replaced: it keeps its device id and its address but
reports a new board ID, so the teardown recipe refuses it with `device identity
mismatch`, while onboard refuses too and names that same teardown as the fix.
Force is read before the deployment record is, so neither a mismatched deployment record nor two
conflicting recoverable deployment records can keep you from it. Forcing removes every
artifact that
carries IRIS's own name — the EEM applets, Guest Shell or the IOx app and its
app-hosting stanza, the IRISQ logging discriminator and its
buffered/console/monitor bindings, `crypto pki trustpoint IRIS` and `ip http
client secure-trustpoint IRIS`, and the staged files — and preserves only the
operator's network: the VLAN and SVI, the VirtualPortGroup, and the NAT rules,
which without a deployment record nothing proves IRIS created. Everything IRIS-named has
to go, or the next onboard's preflight refuses the device the forced teardown
just rescued. It behaves the same on every platform, including a router, which
has no other way to clear an agent with no deployment record — it cannot be adopted, and
its preflight refuses to re-onboard over an already-enabled Guest Shell.
Recorded in Audit as `undeploy_forced`.

An IOx onboard that failed while the app was activating is also **not** a case
for Force. It leaves the app installed but never started, which preflight reads
as a resumable retry: press Onboard again and the second attempt finds the
package's layers already cached. See
[First install of a new package version](iox.md#first-install-of-a-new-package-version).

One refusal is **not** a case for Force or for adopt: an Undeploy that answers
`503` naming an unreadable `deployment_records.json`. The records exist and
cannot be parsed, so nothing yet knows whether IRIS deployed this device.
Repair or remove that file — adopting the device instead would write a
deployment record asserting a deployment nobody verified.

Once a forced teardown succeeds, every deployment record the device still held is marked
`abandoned` — only on success, because failing to reach a device is not proof
that its deployment record is wrong. Without that step the next onboard would be refused
on the very deployment record the force was run to get past.

Bulk operations report per-device refusals rather than failing the whole batch:
the status line shows how many devices succeeded and names the ones that did
not, with the server's reason. Adopting a router, for example, comes back as a
`409` for that device while the rest of the batch proceeds.

Creating or deleting a credential profile re-renders the device rows
immediately, so a device imported before any profile existed becomes assignable
at once instead of after the next ten-second poll.

!!! warning "Deleting inventory is not an undeploy"
    Delete removes the Console inventory entry — it does not touch the box. An onboarded
    device keeps its agent and its staged image, with no inventory entry left to
    manage it. Undeploy first if that is what you meant. The deletion cannot be
    undone.

    Delete *is* terminal for the device id, though. Alongside the inventory row
    it revokes the device's credentials, clears its image assignment, heartbeat,
    telemetry history, pending pull and seen-report ledger, marks its
    deployment records `abandoned`, and cancels any onboard or undeploy still
    queued or running for it. Re-adding the same device id afterwards starts
    from scratch: nothing the previous device left behind can block or
    authorise anything for its replacement. Peer endpoint rows are the one
    deliberate exception — they are retained until they age out, so the revoked
    principal keeps deriving a deny.

## Onboarding from the console

Console onboarding uses the device's assigned credential profile to run the platform installer. Credentials belong in the Console or the server secret store. Generated per-device staging files are temporary and swept after their configured age.

Guest Shell onboards probe device reachability before running the installer:
an unpingable or unreachable IP fails the job immediately with `cannot reach
device <ip> — ping/SSH probe failed; check the device IP and credentials`.
Router, IOx, and XR onboarding also check device reachability in their
preflight. Every onboarding rejection — a failed preflight, a
busy device, an unreachable device, a router already holding a deployment
record — is rendered in the console and recorded in Audit, whether it is
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

Successful jobs end with `onboard complete: <IP>` or `undeploy complete: <IP>`.
Errors name the failed check and any recovery steps. Onboarding completion
means the agent is set up; check Devices for image staging progress.

### Deployment logs

Job windows are live views; the durable record is Monitoring →
**Deployment logs** (`#monitoring/deploylogs`). Every finished onboard or
undeploy job's installer output is persisted on the server under the state
directory, so the logs survive console reloads, session changes, and server
restarts; the newest 200 are kept. The table lists each log's finish time,
device, action, result, and size. A histogram above it bins the retained logs
over the selected window — 24h, 7d (the default), 30d, 90d or All — and
dragging a range across the graph filters the table to that span; a search box
plus Action and Result pickers narrow it further, and rows page 25 at a time.
**view** opens the log in a drawer beside the table. If a job you expect is
missing, widen the range before concluding the log was not kept: the table only
ever shows the selected window. The same list, already filtered to one device,
sits at the bottom of that device's deployment-details panel on the Devices
screen.

Each line in the persisted log is prefixed with its elapsed offset from the job
start, for example `[+   42.3s] [4/7] waiting for Guest Shell`. The live SSE
stream remains unchanged. These offsets identify whether a slow onboard spent
its time in device reachability, Guest Shell readiness, artifact download, or a
later verification step instead of exposing only one total duration.

## Settings

Settings is a sidebar feature with its own sub-menu — **Setup**, **Device
packages**, **General**, **TLS & trust**, **Telemetry**, and **Audit export** —
rather than an in-page tab strip. Each sub-page is deep-linkable, including
`#settings/setup`, `#settings/packages`, `#settings/general`,
`#settings/tls`, `#settings/telemetry`, and `#settings/audit`.

General shows the device-facing server IP and the Console's browser URL
separately. They can belong to different hosts. `IRIS_CONSOLE_URL` on the
server supplies the published Console URL; the Console host's Compose binding
controls where it actually listens.

### Setup

The **Setup** sub-page (`#settings/setup`) is a post-install status panel: four
cards — **admin account**, **telemetry destination**, **device packages**, and
**image verification** — each carrying a live status chip and a short
rationale, meant to be revisited any time after installing a server rather
than completed in one sitting. The admin card links to Settings › General; the
telemetry and image verification cards both open the setup flow (`#setup`),
which hosts those controls as steps 1 and 3. The telemetry card also names the
endpoint in effect and whether it is a console override or the deployment
default. Every card's status is one of `ok`, `unset`, `stale`, `absent`, or
`unknown`, plus a sixth reading unique to image verification — a schedule
that is configured but has not yet produced a successful run, worded
distinctly ("Configured — no successful run yet") from one never configured
at all. `absent` and
`unknown` both mean the server could not determine the state; a failed or
malformed status fetch shows every chip as `unknown` rather than leaving a
previous, possibly stale, render on screen. Neither is ever presented as
success — and `absent` is rendered as a neutral, not-applicable chip rather
than a warning, since (as the device packages paragraph below explains) it
routinely just means an architecture this deployment does not use.

The Setup card links to the persistent **Settings › Device packages** page,
where the same status remains available after the first-run flow is dismissed.
That page re-checks all three artifacts on demand and prints the complete
Docker-host build command for every absent, stale, or unverifiable package
family. The server inspects the artifacts and returns the results through the
management API; neither runtime container has a Docker socket.

The **device packages** status covers deployment-neutral wrappers. The two IOx
packages (`iris-arm64.tar`, `iris-amd64.tar`) and IOS-XR RPM (`iris-xr.rpm`)
contain the shared agent but no deployment certificate. Each row binds the
served wrapper's SHA-256 to an adjacent provenance manifest naming its wrapper
kind, platform, and canonical OCI image/source digests. `ok` means those bytes
and metadata agree; it does not claim to inspect the package contents or
validate its native signature. `stale` means the wrapper digest no longer
matches its manifest, while missing or malformed evidence is `absent` or
`unknown`. `absent` for an architecture you do not deploy needs no action.
Build time is informational, never a proxy for certificate freshness.

The card performs a separate TLS readiness check between the certificate the
live service presents and the public `iris-catalog.pem` copy that onboarding
distributes. A mismatch or unreadable copy makes the aggregate state non-green
because new onboards would receive unusable trust, but it does not make any
package row certificate-stale. Reconcile the served/distributed certificate;
rebuilding a deployment-neutral package cannot fix that condition.

When a wrapper or its provenance really needs rebuilding, use
`tools/provision-iox-packages.sh` for both IOx tars and
`tools/build-xr-package.sh --out artifacts/` for the XR RPM. Certificate
rotation needs no package rebuild: re-onboard affected devices to replace the
runtime certificate delivered through IOx app data, the IOS-XR harddisk bind
mount, or the Guest Shell artifact flow. See
[TLS rotation and device packages](operations.md#tls-rotation-and-device-packages).

### TLS & trust

- **Certificate** — drop (or browse to) a certificate and private key, or
  paste PEM directly. Files are classified by their PEM content rather than
  extension, so a single combined cert+key file works. Dropping an encrypted
  private key reveals a passphrase field; the key is decrypted at import
  (`openssl pkey`, passphrase piped over stdin, never on the command line)
  instead of being rejected, and is still stored age-encrypted at rest either
  way. The card shows the identity this Console is serving.
  **Use deployment default certificate** reverts to the deployment's default browser identity
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

Nothing in the everyday workflow requires it. Publishing images, assigning them,
onboarding and undeploying devices, importing inventory, and watching progress
are all console operations, and most entries in the
[command quick reference](reference.md#command-quick-reference) have a console
equivalent.

The command line stays the right tool for four things:

| Task | Why it stays on the CLI |
| --- | --- |
| Bringing the deployment up | Build and start the containers and provision their certificates and credentials on the hosts. |
| Reproducible batch operations | Reviewed CSV files give you a diff and a rollback path. |
| Building agent bundles and IOx packages | Build-time tooling, not a runtime operation. |
| Credential minting, revocation, and seeder rotation | Deliberately kept off the browser surface. |

Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.
