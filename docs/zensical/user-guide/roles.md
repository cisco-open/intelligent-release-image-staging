<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Control which devices share with each other

## What this is for

Use **Policies** to edit roles and **Inventory** to assign devices to them.
The Console uses named fields for sharing permissions, speed limits and agent settings.

IRIS moves an image over a private swarm: a device takes pieces from other
devices. A role is a named group of devices that share with each other. Use
roles to keep a site, a tenant or a test bench apart, and to give a group its
own speed limits. Sharing needs permission from both roles.

## In the Console

### Set a role on selected devices

1. In **Inventory**, select the devices.
2. Open **More actions → Set role…** and check **Reviewed devices**. This list
   stays fixed while the dialog is open. Choose a role, or `— no role —` to
   clear membership.
3. Select **Preview change**. One dry run covers every reviewed device and
   reports the impact on access and membership, the speed limits, per-device
   failures, and the confirmation threshold.
4. Select **Set role**. It commits that preview, and an
   all-failed preview cannot commit. If the policy changed under you, or the
   server refuses the confirmation, the Console discards the preview: refresh
   and preview again.

!!! warning
    If the commit request or its reply never arrives, then
    **changes may have been saved**. Use **Refresh policy before retrying**,
    check the device roles and reported drift, then preview again. Closing the
    dialog does not cancel a request already sent.

### Edit role definitions

Open **Policies → Device-to-device sharing**. Each row shows a role, the other
roles it may share with, and its distribution-server permission.
The page loads when you open it and after a save. Select **Refresh policies**
to check for changes from elsewhere while keeping your open role draft.

1. Select **New role**, or **Edit** on a row.
2. Turn on **Limit sharing to selected roles**, then enter **Other roles to
   allow**. Both roles must permit sharing. Use **Allow transfers with the distribution
   server** to set this role's distribution permission. Without a sharing limit,
   the role permits every role and the server.
3. Open **Speed limits and agent settings** for the IPv4 networks, the instruction expiry fallback,
   the eight speed limits and the cadence values. A speed limit of 0 means
   unlimited, any other value is at least 8192 bytes per second, and a blank
   field takes the global default.
4. Select **Preview change**, then **Save role**. Editing any field after a
   preview discards it. **Delete** previews first too.

If a save cannot be confirmed, refresh and review the current definition before
trying again. **Reload current definition** discards your draft. Closing the
editor leaves an already-submitted save running.

The Console sets per-role speed limits in **Speed limits and agent settings**
(above). Global defaults use `PUT /api/v1/peer-policy/qos`. Tracker timing
overrides (`qos_state`) use the management API or the role CSV below; editing other role fields preserves
them. Pair explanations are available only through
`GET /api/v1/peer-policy/explain`.

### Choose behavior when instructions expire

Under **Speed limits and agent settings**, find **If the device cannot get fresh
settings**. The server sends each device a signed
[instruction](../reference/glossary.md#instruction) with transfer settings and an
expiry time. Choose what happens if it expires before a valid replacement arrives.

| Choice | What the device agent does |
| --- | --- |
| **Follow the server setting** | Uses the server's effective setting. Without an override, roles with sharing limits keep verified settings; other roles use built-in settings. Server-wide overrides can change this. |
| **Keep last verified settings** | Keeps the last verified transfer limits and check-in timing until a valid replacement arrives. |
| **Use built-in device settings** | Restores the agent's built-in settings, including no upload or download speed limit. These are not your current role or server defaults. |

Transfers can continue with either behavior. This setting does not extend
expired peer permissions or stop every existing connection. Save the role
through **Preview change**, then **Save role**.

!!! warning
    Do not edit server state files by hand.

### Review distribution access

Open **Policies → Distribution access**. The default is **Preview only**.
The saved mode is separate from the transfer service's confirmed effect.

1. Under **Change distribution access**, choose **Enforce reviewed blocks** to apply the current device-to-server
   access rules at the distribution service.
2. Check **New address limit** and **New device limit**. Both start at 10 and
   limit additions in this review, not the total already approved.
3. Select **Preview change**. Review new and retained counts and resolve any
   checks shown. Applying can disconnect existing transfers from those addresses.
4. Select **Apply reviewed change**. **Saved mode** records the request;
   **Transfer-service status at last refresh** first shows **Waiting for confirmation**.
   Select **Refresh status** to check for **Blocks confirmed** before treating the reviewed blocks as applied.

**Approved for blocking** counts the devices and addresses you approved.
**Confirmed at last refresh** counts what the transfer service confirmed at that
read. Select **Refresh status** for current confirmation. **Not
confirmed** means that proof is unavailable, not that the count is zero.
The **Next step** text tells you whether to preview, wait or refresh.

A changed policy or a newly observed address needs another review. Unknown
origin information or shared allowed/denied addresses prevents full enforcement.
Use distinct addresses for those devices. Returning to **Preview only** uses the
same preview and apply steps; ordinary quarantine and revocation remain active.
If a save is uncertain, select **Refresh status** and check the current settings
before previewing again. If you have unsaved changes, refreshing asks before
discarding your draft and preview. Canceling keeps them and sends no read.

### Import and export the definitions file

Under **Policies → Advanced → Role definitions**, **Import CSV…** replaces every definition with a comma-separated values (CSV)
file in the `fleet/roles.csv.example` format, and asks you to confirm a count of
the roles it holds. Roles missing from the file are removed, and a role a device
still declares refuses the import. **Export CSV** downloads the definitions.

`fleet/roles.csv.example` is the tracked template.
`fleet/roles.csv` is operator-owned and ignored by Git, so back it up with your
site inventory. Lists in
`peers` and `nets` are semicolon-separated, rates are integer bytes per second,
and `*_s` values are integer seconds. The `seeder_numwant`, `leecher_numwant`,
`seeder_announce_min_interval_s` and `leecher_announce_min_interval_s` columns
preserve tracker timing overrides. Blank or missing columns inherit defaults;
import replaces those overrides too.

An import validates the whole role graph, including symmetric restricted-role
links and reserved names, before it writes anything, and a write that only
partly succeeds reports the exact failed rows and the `role_drift` figure.

## With the API

1. Read the current policy. Each read hands you a revision marker.
2. Send your request with `dry_run=1` and review `member_delta`,
   `origin_access_lost`, `empty_permitted_sets`, `role_pairs_stopped` and
   `qos_changed`.
3. Send the unchanged request again with its `confirm_token` and that marker.

Every effective change to access, membership or speed limits needs that
confirmation. A commit from someone else voids both the marker and the token, so
read and preview again. Create a definition before you assign members to it, and
clear its members and every peer role that points at it before you delete it.

For routes, request fields and refusal codes, see
[Roles and sharing-policy API](../reference/peer-policy-api.md).

## What you see

| Where | What it shows |
| --- | --- |
| Inventory, **Role** column | the role a device declares, or a dash |
| **Filters → Role** | *Role: any*, `— no role —`, and every role in the policy, including roles not on the page you are looking at |
| **Policies → Device-to-device sharing** | saved role permissions, with sharing shown only when both roles permit it |
| **Policies → Distribution access** | saved mode, approved blocks, confirmed effect and the next action |
| **Advanced** | role and restricted-role counts, drift, how full the pending-operation queue is (`N/256`), and, under **Peer access and roles**, per-role member counts and the rule that an explicit ACL entry shadows a role |

The role table shows configured intent. Quarantine and explicit ACLs can
restrict access further. Open **How sharing rules take effect** to check the
existing server blocklist separately from reviewed distribution blocks.
**Not current** means its tracker status is stale; check the tracker.

The role controls stay disabled while the server's support for roles is
uncertain or the policy is degraded. Degraded means the tracker fell back to the
last policy the devices accepted, or role state was lost; the startup log says
which.

## Move a device from an access list to a role

A direct role assignment is refused when an explicit ACL entry other than
quarantine already shadows that device. To convert one deliberately:

1. Preview the change without writing anything.

    ```bash
    iris-role migrate <ACL> <ROLE> --dry-run
    ```

2. Run the same command with `--apply` and confirm it.

The migration records the role membership first, then a second commit removes
the matching ACL assignments. If that commit fails, enforcement stays on the old
ACL: read the `role_drift` figure, fix it, and preview again.

## Stop one device sharing

Quarantine the device from its row action or the bulk action in **Inventory**. A
quarantined device is told to stop sharing with every peer, and the badge
records your intent, not the tracker's last enforcement state.

The bulk confirmation names the selected devices. Changes run one device at a
time. An uncertain result stops the batch; later devices are shown as **not
attempted**. Refresh and review the named outcomes before trying again.

Quarantine is held separately from that device's ordinary ACL assignment, and
applying it preserves the current ordinary ACL entry, which takes effect again
when you release the quarantine. Revoke a device's credentials and only that
ordinary ACL entry is cleared: the quarantine, the role membership and the
device speed limits are all retained. Retiring the device clears the quarantine
along with the ordinary ACL entry, the role membership and the speed limits.

A quarantine written by an earlier release sits in the ordinary ACL instead,
and the next policy change moves it to its own container. Such a legacy
quarantine row has no surviving ordinary ACL: releasing it leaves the device
with no role or ACL assignment, and you must set one directly.

### Containment takes time

!!! warning
    Tracker or quarantine discovery alone does not sever existing connections
    or remove peers a device already holds. An
    independent quarantine alone is not sufficient containment, and quarantine
    is not immediate isolation.

To request containment, unassign every image from the affected device. Its agent
removes torrents only after the next successful due policy poll and a successful
aria2 policy apply. Signed `catalog_tick_s`, mechanical scheduling and catalog
failures delay that removal.

## How a role move is classified

The server classifies each membership move as a tightening or a relaxation, so
it can tell you what the change costs before you commit it. A device in no role
enters a restricted role as a tightening and clears back to no role as a
relaxation; every other move is classified on its permitted sets, and a move
between two roles whose sets do not nest is refused with
`incomparable_role_change`. One bulk action or CSV import must be all tightening
or all relaxing, so split a mixed set into separate previews.

## When the pending-operation queue is full

The queue holds at most 256 entries the tracker has not acknowledged yet, and
one bulk membership change adds one entry. A change that meets a full queue is
refused before it writes anything (`operation_backlog_full`). Check that the
tracker is running and that the queue is draining before you retry. Every
refusal on these routes has an entry in
[API error codes (problem types)](../problems.md).

## When a role change half-succeeds

A role change writes two stores: the inventory and the sharing policy. When one
write lands and the other fails, the response is `partial`. That is not a
rollback. A later policy restore changes policy content only and
does not roll back a completed Fleet write. Repair the failed store and send the
same request again; the request is idempotent.

Rolling policy content back is a reviewed maintenance step, not a button. The
internal primitive copies reviewed historical content into a
monotonic new revision, keeps the queue of changes the tracker has not
acknowledged, and rotates its acknowledgement epoch. There is
no public restore route or CLI, so never overwrite a healthy policy file with an
older snapshot by hand.

Each queued change carries a stable event ID, so a failed export replays the
same change at least once instead of losing it. The tracker
persists both the accepted revision and its epoch in the enforcement status. Do
not edit those fields by hand to clear a backlog: an acknowledgement with no
matching epoch counts as zero, and the queued changes replay anyway.

## Related

- [Security model and trust boundaries](../architecture/security-model.md)
- [Roles and sharing-policy API](../reference/peer-policy-api.md)
- [Work with many devices at once](devices.md)
- [Assign images and check staging status](assignments.md)
