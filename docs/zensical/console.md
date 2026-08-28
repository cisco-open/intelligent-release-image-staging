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
works pre-setup — which takes you straight to the account-creation page for the
real admin account. Or create the initial admin from the container instead:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

### Finishing setup

Creating the admin is the first of four things a new server needs. The sign-in
straight after it lands on the **setup flow** (`#setup`), which walks the other
three in order:

1. **Telemetry destination** — where swarm progress, device reports and export
   health are published. Already satisfied if the deployment environment sets
   `IRIS_OTLP_ENDPOINT` and observability is enabled, in which case the step
   shows as done rather than being hidden.
2. **Stage host** — the credentials IRIS uses to reach the Docker host that
   builds and serves device onboarding material. Without them, onboarding over
   the Docker path cannot start.
3. **Device packages** — whether each served IOx package still pins the
   certificate this server hands to devices.

The forms are hosted in the flow itself, so finishing setup does not send you
round the Settings pages. A step list across the top shows every step with its
current state and lets you open any of them directly, in any order.

Every step can be skipped, and re-entering `#setup` resumes at the first one
still outstanding. That is not merely a convenience: **the device-packages step
can never be completed from the console**, because the console container has no
Docker socket and so can detect a stale package but not rebuild one. That step
is therefore a report and a command to run on the Docker host, plus a
**Re-check** button — not a form whose submit button would be pretending to do
something. A wizard that insisted on completion could never be finished.

While anything is outstanding, a banner offers the way back. It dismisses for
the session rather than permanently, because a package that goes stale later is
a silent failure with no other symptom, and a banner dismissed for good would
hide precisely the case this exists to catch.

Settings › Setup keeps reporting the same four states afterwards, for checking a
server long after it was installed.

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

A device with no attachment chosen yet — imported from an older positional CSV,
or added without picking one of the four types above — reads **Inventory only —
attachment not chosen** in that column instead. See
[Older positional CSVs](fleet-workflows.md#inventory).

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

Each device row's **ⓘ Deployment details** control opens a read-only drawer
beside the table — it slides in from the right, closes on **Esc** or **✕**, and
leaves the row you opened it from where it was. It opens on an **Images** table
listing every image currently assigned to the device with its own state:
`ready` once that image is staged and verified, the agent's own in-progress
state (for example `staging`, `downloading`, `transferring_to_ios`, optionally
with the reported error) for whichever image is current, and `queued` for the
rest. Below that, it shows the deployment itself: the receipt state (`active`,
`removed`, `superseded`, `needs-reconcile`,
`abandoned`) and receipt id, the
preflight result, and the resolved configuration the onboard applied — the
attachment type, the owned management VLAN or VPG, SVI and app addressing,
NAT interface, swarm port, and the recorded model, **Agent install** choice, and device
identity. A device with no receipt says so, naming adopt or re-onboard as the
fix. The drawer ends with that device's persisted deployment logs
([Deployment logs](#deployment-logs)), each viewable in place. A run that
finished before the current device was registered under this name is labelled
**previous device**. Logs are keyed on the device id and deliberately survive a
delete — they are the record of what actually ran — so a rebuilt or replaced box
added back under the same name inherits its predecessor's runs. They are kept
and shown, never presented as this device's own history. Devices registered
before IRIS started stamping registration time carry no stamp, and nothing is
labelled for them.

An `abandoned` receipt is one that no longer describes a device IRIS manages:
the device was deleted from the inventory, or a forced teardown stripped the
agent without using the receipt as authority. It is kept as the record of what
IRIS built on that box, but it never authorises a teardown and never blocks an
onboard again.

## Bulk device actions

The Devices toolbar acts on every checked row, so a CSV import can be finished
without touching each device.

Above it, the filter bar narrows what is rendered — free text across device, IP
and model, plus management type, **Agent install**, credential, telemetry, peer policy
and status. Only matching rows are drawn, so filtering and then **select all**
is how you act on a subset instead of hand-picking rows out of the whole fleet.
The **Status** choices are generated from the same derivation the Status column
renders, so every state a row can show can be filtered for: `onboarding`,
`undeploying`, `waiting for heartbeat`, `onboard failed`, `undeploy failed`,
`deployed`, `placement failed`, `copying to IOS storage`, `staging (other)`,
`enrolled`, `not enrolled`, and `offline` — the last being a modifier, since a
device can read `deployed` and still have gone quiet.

| Control | What it does | Confirms first |
| --- | --- | --- |
| Onboard selected | Queues an onboard job per device and tracks them in the batch panel; the server runs a bounded number at a time and queues the rest. | No |
| *Telemetry reports* / *Telemetry streaming* checkboxes | Set the deployed agent's telemetry posture for every onboard started from this toolbar (single-row onboards included). Reports default on; streaming defaults off ([Transfer streaming](observability.md#transfer-streaming)). A bulk redeploy with the boxes toggled is the site-scale enable/disable path. | No |
| Undeploy selected | Runs receipt-driven cleanup on each device. | Yes — one dialog for the whole selection, naming what teardown removes and preserves |
| Adopt selected | Records the ownership receipt for each device. | Yes — a dialog listing the selected devices |
| Delete selected | Removes the inventory rows only. | Yes — a dialog listing the devices and warning that deletion is not an undeploy |
| *credential for selected* + **Apply** | Assigns one credential profile to every checked device. Leaving the picker on either blank entry clears the credential instead. | No |
| Assign images to selected | Opens the shared image picker for the whole checked selection — the bulk form of each row's own **Assigned images** button, and the reason the filter bar exists: filter to a platform or model, select all, assign. | Only when it would unassign every image |

A device can have up to ten images assigned at once, staged and transferred in
parallel; the per-row **Assigned images** button and the toolbar's **Assign
images to *N* devices…** button open the same checkbox picker, reading `Choose
images` with a live `checked/10` count — an eleventh box disables itself
rather than waiting for a server-side rejection. Applying to a multi-device
selection pre-checks the *intersection* of what the selection already has
assigned — never the union — so **Apply** can never silently add an image to
one device or drop it from another; when the selection's assignments actually
differ, a note says so before you apply. Applying an empty pick is a
deliberate unassign and confirms first, whether for one device or for the
whole selection: unchecking an image stops its torrent and frees the staging
copy, but leaves any already-staged file on the device's boot filesystem,
still tracked by IRIS.

The **Adopt** dialog names the whole selection. It warns that you should only
adopt a device whose inventory row matches what is really on the box, points at
re-onboarding as the safer and idempotent alternative, states up front that
routers cannot be adopted, and sends the acknowledgement the server requires —
an adopt that omits it is refused.

The **Undeploy** dialog's **Force** checkbox covers a device stranded with no
*usable* deployment receipt. That is either no receipt at all — typically an
onboard that enabled the agent but died before its receipt was written — or a
receipt that no longer describes the box in front of it. The second case is a
device that was rebuilt or replaced: it keeps its device id and its address but
reports a new board ID, so the teardown recipe refuses it with `device identity
mismatch`, while onboard refuses too and names that same teardown as the fix.
Force is read before the receipt is, so neither a mismatched receipt nor two
conflicting recoverable receipts can keep you from it. Forcing removes every
artifact that
carries IRIS's own name — the EEM applets, Guest Shell or the IOx app and its
app-hosting stanza, the IRISQ logging discriminator and its
buffered/console/monitor bindings, `crypto pki trustpoint IRIS` and `ip http
client secure-trustpoint IRIS`, and the staged files — and preserves only the
operator's network: the VLAN and SVI, the VirtualPortGroup, and the NAT rules,
which without a receipt nothing proves IRIS created. Everything IRIS-named has
to go, or the next onboard's preflight refuses the device the forced teardown
just rescued. It behaves the same on every platform, including a router, which
has no other way to clear a receipt-less agent — it cannot be adopted, and
its preflight refuses to re-onboard over an already-enabled Guest Shell.
Recorded in Audit as `undeploy_forced`.

Once a forced teardown succeeds, every receipt the device still held is marked
`abandoned` — only on success, because failing to reach a device is not proof
that its receipt is wrong. Without that step the next onboard would be refused
on the very receipt the force was run to get past.

Bulk operations report per-device refusals rather than failing the whole batch:
the status line shows how many devices succeeded and names the ones that did
not, with the server's reason. Adopting a router, for example, comes back as a
`409` for that device while the rest of the batch proceeds.

Creating or deleting a credential profile re-renders the device rows
immediately, so a device imported before any profile existed becomes assignable
at once instead of after the next ten-second poll.

!!! warning "Deleting inventory is not an undeploy"
    Delete removes the Console record — it does not touch the box. An onboarded
    device keeps its agent and its staged image, with no inventory entry left to
    manage it. Undeploy first if that is what you meant. The deletion cannot be
    undone.

    Delete *is* terminal for the device id, though. Alongside the inventory row
    it revokes the device's credentials, clears its image assignment, heartbeat,
    telemetry history, pending pull and seen-report ledger, marks its
    deployment receipts `abandoned`, and cancels any onboard or undeploy still
    queued or running for it. Re-adding the same device id afterwards starts
    from scratch: nothing the previous device left behind can block or
    authorise anything for its replacement. Peer endpoint rows are the one
    deliberate exception — they are retained until they age out, so the revoked
    principal keeps deriving a deny.

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
device, action, result, and size. A histogram above it bins the retained logs
over the selected window — 24h, 7d (the default), 30d, 90d or All — and
dragging a range across the graph filters the table to that span; a search box
plus Action and Result pickers narrow it further, and rows page 25 at a time.
**view** opens the log in a drawer beside the table. If a job you expect is
missing, widen the range before concluding the log was not kept: the table only
ever shows the selected window. The same list, already filtered to one device,
sits at the bottom of that device's deployment-details panel on the Devices
screen.

## Settings

Settings is a sidebar feature with its own sub-menu — **Setup**, **General**,
**TLS & trust**, **Telemetry**, and **Audit export** — rather than an in-page
tab strip. Each sub-page is deep-linkable: `#settings/setup`,
`#settings/general`, `#settings/tls`, `#settings/telemetry`,
`#settings/audit`.

### Setup

The **Setup** sub-page (`#settings/setup`) is a post-install status panel: four
cards — **admin account**, **telemetry destination**, **stage-host
credentials**, and **device packages** — each carrying a live status chip and a
short rationale, meant to be revisited any time after installing a server
rather than completed in one sitting. The admin card links to Settings ›
General; the telemetry and stage-host cards open the setup flow (`#setup`),
which hosts those forms. The telemetry card also names the endpoint in effect
and whether it is a console override or the deployment default. Every card's
status is one of `ok`, `unset`, `stale`, `absent`, or
`unknown`. `absent` and `unknown` both mean the server could not determine
the state; a failed or malformed status fetch shows every chip as `unknown`
rather than leaving a previous, possibly stale, render on screen. Neither is
ever presented as success.

The **device packages** card exists because the IOx device packages
(`iris-arm64.tar`, `iris-amd64.tar`) bake the catalog's TLS certificate in at
**build** time. If the server's certificate later changes — a rebuilt
server, a fresh volume, a deliberate rotation — every package already built
against the old certificate silently stops working: the device installs and
its app reports RUNNING, but it can never authenticate to the catalog and so
never checks in. See
[TLS rotation and IOx packages](operations.md#tls-rotation-and-iox-packages)
for the full failure mode and the fix. The card lists each package's build
time and state against the server's live certificate; `absent` for an
architecture you do not deploy (for example `iris-amd64.tar` at a site with
no Catalyst 9300 IOx devices) needs no action. A `stale` row links to the
rebuild command; if instead the certificate the server currently serves
disagrees with the copy already handed to devices, the card names that
condition specifically, because rebuilding packages alone would not fix it.

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

Nothing in the everyday workflow requires it. Publishing images, assigning them,
onboarding and undeploying devices, importing inventory, and watching progress
are all console operations, and most entries in the
[command quick reference](reference.md#command-quick-reference) have a console
equivalent.

The command line stays the right tool for four things:

| Task | Why it stays on the CLI |
| --- | --- |
| Bringing the server up | The console does not exist until the server is running. |
| Reproducible batch operations | Reviewed CSV files give you a diff and a rollback path. |
| Building agent bundles and IOx packages | Build-time tooling, not a runtime operation. |
| Credential minting, revocation, and seeder rotation | Deliberately kept off the browser surface. |

Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.
