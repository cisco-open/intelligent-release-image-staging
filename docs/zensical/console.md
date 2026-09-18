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

### Finishing setup

Creating the admin is the first of four things a new server needs. The sign-in
straight after it lands on the **setup flow** (`#setup`): a step panel on the left, the active step's
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

The Console uses self-hosted Inter for headings, body text, IP addresses and
logs, with system sans-serif fallbacks. React and legacy pages share this
font stack. The independent IRIS theme includes no proprietary component
assets and does not require Cisco fonts.

The legacy `IRIS_SHARP_SANS_FONT_HOST` mount remains for compatibility but
does not change the current theme. Licensed font files are excluded from
Docker builds and release tarballs; see [Reference](reference.md).

## Console areas

| Area | What it does |
| --- | --- |
| Overview | Rollout counters and per-image staging progress. Carries the *Telemetry export* badge (`ok` / `degraded` / `off`, or `unknown` when the health endpoint cannot be read), fed by the hub's OTLP export health. |
| Images | Shows published image metadata and staged network status, uploads new images, and imports images already on disk. |
| Inventory | Lists known devices, their **management type**, **Agent install** choice, assigned images, and recent reports. Assign or clear device roles here. |
| Policies | Creates, edits, imports, and exports role definitions; shows peer-policy health and instruction delivery diagnostics. |
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
to this documentation site, and three pages the console serves itself —
the *Local API reference (Swagger)* at `/swagger/`, *Device-side
troubleshooting*, and *Server-side setup & troubleshooting* — so all of them
stay reachable from a network with no internet access.

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

Management type controls the network fields in Add Device. **Model series** is
a dropdown: IE Switches, IR Routers, Catalyst Routers, Catalyst Switches, NCS,
or Cisco 8000 Series. Series narrow **Agent install** choices without changing
the management type. Choosing a series does not confirm hardware support.
Existing devices display their series while retaining their actual model for
diagnostics. The API and CSV still accept exact model numbers. XR host selects
`xr-appmgr`, router modes
offer `router` (Guest Shell) or `iox`, and routed/inband modes require a
compatible Guest Shell or IOx choice.

Router choices show the VPG number and app addressing; Router NAT also requires
the outside interface. Both target the Catalyst 8000 family. Current hardware
coverage is recorded in [Validated platforms](validation.md#validated-platforms).

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

The Inventory table's **Role** column shows the declared fleet role, or a dash
when none is declared. **Filters → Role** offers *Role: any*, *— no role —*,
and the complete policy role list, including roles absent from the current
page. The filter is applied by the server before paging.

For a selection in **Inventory**, open **More actions → Set role…**. Leaving the disabled initial
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

Open **Policies** to see which roles can share images and use the distribution
server. Sharing needs permission from both roles. This is configured intent,
not a connectivity test: quarantine and explicit device/server ACLs may further
restrict access. The Enforcement section distinguishes the existing server
blocklist from additional role restrictions, which remain **preview-only**.

**Advanced** opens role and restricted-role counts, drift, and outbox
occupancy (`N/256`). Its **Peer access and roles** panel also shows per-role
member counts, the last origin-QoS state and download counts,
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

### Role definitions

The **Policies → Advanced → Role definitions** table shows one
row per defined role with its restricted flag, peer roles, origin access,
networks, and QoS overrides, plus **Edit** and **Delete** per row. **New
role** or **Edit** opens sharing permissions. **Limit sharing to these roles**
enables the peer list and distribution-server restriction; without it, this
role permits all roles and the server, but the other role must still permit it.
The editor's **Advanced** section holds IPv4 networks, instruction-expiry
fallback, the eight speed limits in bytes per second (0 = unlimited, otherwise
at least 8192; a live hint shows the Mbit/s equivalent), and the swarm and
agent cadence values. A blank QoS field inherits the global default. Saving
follows the Set role contract exactly: **Preview change** sends one dry run
with the pre-preview ETag and shows the impact counts; **Save role** commits
that candidate with the preview's confirmation token; editing any field after
a preview discards it. Delete previews first and asks for confirmation before
the committed DELETE. Editing an existing role carries its tracker `qos_state`
overlay along unchanged, because a definition write is a full replacement.

**Import CSV…** replaces every definition with the chosen file, using the
`fleet/roles.csv.example` format, after a preview
and an explicit confirmation that names how many roles the file holds; roles
missing from the file are removed, and a role a device still declares refuses
the import as `role_in_use`. **Export CSV** downloads the current definitions
in that format. All three controls, like Set role, are disabled while the
capability banner shows or the policy is degraded.

The Console has no role-policy JSON editor: definitions are edited as typed
fields. Global/role QoS and tracker `qos_state` are API-only, managed through the
versioned API's `PUT /api/v1/peer-policy/qos`; there is no per-device QoS write
route. Mutual-access pair explanations are available only through
`GET /api/v1/peer-policy/explain`. See the [interactive API reference](swagger/index.html)
for schemas and conditional-write requirements; do not edit server state files
directly.

Tracker/quarantine discovery alone does not sever existing connections or
remove retained peers. Applied verified device deny lists may cooperatively
disconnect matching peers. Image unassignment requests containment; torrent
removal waits for the next successful due policy poll and successful aria2
policy apply, subject to signed logical cadence and catalog/RPC failures.
Device-side rate intent is cooperative, and a privileged device administrator
can alter the device environment.

An `abandoned` deployment record is one that no longer describes a device IRIS manages:
the device was deleted from the inventory, or a forced teardown stripped the
agent without using the deployment record as authority. It is kept as the account of what
IRIS built on that box, but it never authorises a teardown and never blocks an
onboard again.

## Instruction status and custody

Devices shows a canonical instruction chip with a server-created exact label,
source evidence and report age. Raw instruction state, accepted
`{epoch, instr_serial, policy_revision}`, verification level, pointer skew and
QoS drift are agent-asserted. Device-authored reports are not independent
measurements. Durable revocation and report age are server-observed: revoked
wins visually while the underlying agent LKG/state remains visible. Within a
supported instruction report, raw `stale_expired` or `allowlist_expired` is
stale by agent assertion before report-age classification, even when age is
unknown. Other supported reports with missing/invalid/future report arrival time display unknown;
old valid report arrival times display stale with the last reported state. The chip's
`reason` distinguishes `unknown_key` from `bad_mac` rejection.

The separate raw and display state vocabularies, including legacy
`pre-instructions`, derived `stale`/`rejected`/`unavailable`/`unknown` and durable
`revoked`, are listed in [Reference](reference.md#instruction-protocol-and-state-reference).
Capability comes from `instr_protocol: 1`, not IOS `version`. Labels retain exact
i63 values as strings, so browser rounding cannot change identity.

Open **Policies → Advanced → Instruction delivery and key custody** for issued policy revision, accepted application
counts grouped by policy revision, state counts, current `instr_stamp_missing`
and `pointer_skew` device counts, and observation time. It excludes orphan
heartbeats and retains accepted identities beneath stale/rejected/revoked
states. `policy_revision` is server-issued intent; `instr_serial` with
`instr_epoch` is sealed freshness; `enforcement.applied_revision` and
`iris_peer_enforcement_applied_revision` are unrelated aria2 blocklist counters.
Unavailable heartbeat/policy/revocation/custody evidence stays null/unknown,
never a healthy zero. **violation = 0 does not mean compliant**.

The custody panel shows enablement/state, certificate days remaining (including
zero/negative values), renewal/signing-refusal flags, keylist age and re-signing
due, root ceremony status, and roots attested in 180 days. Disabled reads not
enabled; unavailable evidence stays unavailable. Quorum healthy means recorded
attestations support both roots, not that the Console inspected private-key
custody. Follow [root recovery](operations.md#instruction-root-ceremony-and-recovery)
for warning, critical or degraded status. The current bounded schemas are in
[OpenAPI](openapi.yaml); the deprecated effective-QoS `delivery_state` sentinel is not
evidence of instruction application. That response now includes the same canonical
`instruction` object as Devices.

### IOx onboarding verification

IOx verification is device-global. The onboarding job prefers a signed wrapper
with no verification-state change. Unsigned/enabled records the obligation,
disables only for installation and restores with read-back before
activation/start; initial disabled stays disabled; unknown refuses. Durable
interruption/resume and uninstall recovery never blindly enables an
operator-changed or unowned state. Inspect the job/deployment evidence when
restoration is incomplete. Package readiness and signature-marker presence do
not validate a native signature. See [IOx prerequisites](iox.md#device-global-package-verification)
before onboarding other applications on the same device.

## Bulk device actions

In **Inventory**, click a row to select or deselect it. Selected rows are
highlighted and expose bulk actions; there are no selection checkboxes. You can
also focus a row and press **Space** or **Enter**. Device names open details,
and buttons or dropdowns inside a row do not change its selection.
**Select page** selects the visible page; **Clear page selection** reverses it.
**Cancel** clears the entire selection.

Search by device, IP or model. **Filters** expands the structured filters;
remove an individual filter chip or use **Reset** to clear all filters. Filters
apply on the server before paging. **Device series** includes IE Switches,
IR Routers, Catalyst Routers, Catalyst Switches, NCS and Cisco 8000 Series,
with legacy and unknown categories retained. These are display labels for the
existing API families, not a promise that every model in a series is supported.
The table shows series names; hover the series cell to see the stored model.

CSV import results stay visible independently of inventory refreshes. A refused
role import names the role/device when the API provides them; define missing
roles in Policies first. You can select the same file again after correcting it.
If the response is unavailable, refresh inventory before retrying: the request
may already have completed, and the Console does not resend it automatically.

### Schedules

**Devices → Schedules** opens the schedule list: what is going to run, against
what, when it next runs, its state, and how its latest run went. Each row
carries the target summary, the server-computed next run (local time in the
schedule's own zone, so the console never recomputes a weekly time across a
daylight-saving boundary), and, for the latest occurrence, its state, the
`+N / −M since preview` delta and the wave gate's staged / errored / missing
counts.

**Schedule…** in the bulk bar creates one. Its target is the **current Devices
filter**, not the rows that happen to be checked: the filter is re-resolved at
each run, which is the reason to schedule against it. The modal says how many
devices that filter matches now and offers naming the selected devices instead
as the explicit second choice. Editing a window, wave gate, or full payload is
not available in the Console. Use only schedule operations and fields listed
in the [OpenAPI contract](openapi.yaml); do not assume schedule CSV
import/export is available.

A schedule whose creator is gone shows `created_by <actor> (actor no longer
exists)`, and **Re-affirm** on that row takes ownership of it. Firing never
depended on that account, so the schedule kept running either way.
Re-affirming rewrites `created_by` to the current operator and bumps `rev`,
against the revision on screen — a concurrent edit makes it a refusal, not an
overwrite.

Any device row a pending schedule's approved preview names carries a
**Scheduled** marker, so a **manual** assignment is not made in ignorance of a
scheduled one. The marker reads the schedule's last approved preview; a
late-bound target is re-resolved when it fires, so it is the last approved
answer, not a promise about the next run.

### Paging and selection at fleet scale

The Devices table pages large filtered inventories. Selection follows device
IDs across pages. **Select page** selects the current page only;
**Select all N matching devices** expands it to the active filter. **Cancel**
clears the entire selection. Review the selected count before any bulk action.

| Action | Effect |
| --- | --- |
| Onboard | Queues an agent deployment for each selected device. |
| Undeploy | Removes the agent using its deployment record. |
| Adopt | Records a reviewed existing deployment; router adoption is not supported. |
| Delete | Retires inventory and server-side device state; does not uninstall the agent. |
| Set credential or role | Updates the selected devices; review clears and policy previews carefully. |
| Assign images | Replaces each selected device's image set with the checked images. |

The image picker allows up to ten images. For a mixed selection it initially
checks only images common to every device. Applying the set can therefore
remove assignments; review the warning and the full checked set. Empty means
unassign all. Cleanup after unassignment follows
[platform ownership rules](device-agents.md#unassigned-image-park), not a promise
to delete every staged image.

Bulk actions report individual successes and refusals. Review each result and
follow asynchronous jobs to completion. HTTP 207 means partial cleanup, not a
fully successful operation; HTTP 429 is admission rejection and includes
`Retry-After`. See [API limits](api-testing.md#api-admission-limits).

#### Force undeploy

Use **Force** only when the normal deployment record is missing or no longer
describes the device. Review the platform's cleanup scope: it removes IRIS
agent configuration without treating unproven network resources as IRIS-owned.
Do not use it as an image-deletion shortcut. Successful forced teardown
abandons the old deployment records.

Force does not bypass an unresolved IOx signature-verification recovery
obligation. Recover and reconcile the journal first; see
[interrupted IOx attempts](operations.md#recovering-an-iox-attempt-cut-off-mid-run).
An app activation failure may be resumable through **Onboard**, without Force.

An unreadable deployment-record store is a storage/recovery problem, not proof
that no record exists. Repair it from verified state; do not delete evidence or
adopt an unverified deployment to bypass the error.

!!! warning "Deleting inventory is not an undeploy"
    Undeploy first if you intend to remove the agent. Delete does not contact
    the device to remove it, but does revoke credentials and retire associated
    server-side assignments, reports, records, and jobs. Re-adding the ID does
    not restore that state. Peer endpoint records are retained until expiry so
    revoked principals remain denied. Check partial-cleanup responses.

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

### Device activity

**Inventory → Activity** opens recent jobs in a side panel. Choose **log** on
a job to read its output; only one log is displayed at a time and job streams
remain separate. **Close** or **Esc** closes the viewer, not the jobs. Reopening
a log reconnects its stream. Older persisted logs remain under **Monitoring →
Deployment logs**.

**Abort** requires confirmation: it cancels that queued job or stops its running
installer, which can leave the agent partly configured. Re-onboard or undeploy
to recover. Completed jobs do not offer Abort.

New jobs use the same broad progress across Guest Shell, IOx and IOS-XR:
**Prepare → Deploy/remove IRIS agent → Finalize**. The heading identifies the
device series and installer. Device Details lists the chassis model separately,
with its source; a series selection is never presented as a detected chassis.
Completion is reported as `Onboard completed.` or `Undeploy completed.` only
after the job finishes successfully. This concerns the agent, not completion of
an image download or installation of device software.

Errors, warnings and recovery instructions remain visible. For individual
installer steps, timings and available command diagnostics, select **Detailed
logs before starting** Onboard or Undeploy, or submit `{"log": true}` through
the API. The job confirms `Detailed logs enabled.`; the option defaults to off.
IOx additionally includes its redacted device session, which is retained under
the state directory's `iox/transcripts`. Existing saved logs are not rewritten,
and enabling detail on a later job does not expand an earlier summary log.
Onboarding with this option also enables `aria2c.log` on IOx and IOS-XR. Guest Shell logging is
configured separately through `iris_log` in its agent configuration (see the
[reference](reference.md#device-container-environment-variables)).

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

Open **Settings** in the navigation rail, then use the section bar: **General**,
**TLS & trust**, **Telemetry**, **Image verification**, **Device packages**,
**Audit export**, and **Setup checklist**. Each section keeps its deep link:
`#settings/general`, `#settings/tls`, `#settings/telemetry`,
`#settings/bulkhash`, `#settings/packages`, `#settings/audit`, and `#settings/setup`.

General shows the device-facing server IP and the Console's browser URL
separately. They can belong to different hosts. `IRIS_CONSOLE_URL` on the
server supplies the published Console URL; the Console host's Compose binding
controls where it actually listens.

### Setup

The **Setup checklist** section (`#settings/setup`) is a post-install status panel: four
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

[Peer transfer TLS](security.md#peer-payload-transport-boundary) is configured at deployment, defaults to `disabled`, and has no Console toggle.

- **Certificate** — drop (or browse to) a certificate and private key, or
  expand **Paste certificate and key instead**. Files are classified by their PEM content rather than
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

<a id="when-to-use-the-cli"></a>

## Console and API

Use the Console for routine image publishing/import, inventory, assignments,
onboarding, schedules, and monitoring. IRIS distributes, verifies, and stages
images only: it never installs or activates them, reloads a device, changes
boot variables, or alters running software.

For automation or the exact request/response contract, use the authenticated
Console API under `/api/v1` and consult the [interactive API reference](swagger/index.html)
or [OpenAPI contract](openapi.yaml). The compact [API quick reference](reference.md#api-quick-reference)
lists operations without replacing their full schemas. The registry defines
the supported methods and paths; a Console capability is not evidence that an
unlisted API operation exists. In particular, image assignment is per-device
at the API layer; the Console implements bulk selection by coordinating device
operations.

Protected mutations require a Console session and CSRF token; each operation's
security and conditional-write requirements are in OpenAPI. For server
provisioning and offline instruction-root custody, follow the separate
[deployment](getting-started.md) and [custody](operations.md#instruction-root-ceremony-and-recovery)
procedures rather than inferring a workflow from the browser API.
