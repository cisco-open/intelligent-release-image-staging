<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Control which devices share with each other

## What this is for

IRIS moves an image over a private swarm: a device takes pieces from other
devices. A role is a named group of devices that share with each other. Use
roles to keep a site, a tenant or a test bench apart, and to give a group its
own speed limits. Sharing needs permission from both roles.

## In the Console

### Set a role on selected devices

1. In **Inventory**, select the devices.
2. Open **More actions → Set role…** and choose a role. The explicit
   `— no role —` option clears membership.
3. Select **Preview change**. One dry run covers every selected device and
   reports the impact on access and membership, the speed limits, per-device
   failures, and the confirmation threshold.
4. Select **Set role**. It commits that preview, and an
   all-failed preview cannot commit. If the policy changed under you, or the
   server refuses the confirmation, the Console discards the preview: refresh
   and preview again.

!!! warning
    If the commit request or its reply never arrives, then
    **changes may have been saved**. Refresh the policy and inventory views,
    review the reported drift, and preview again rather than sending the same
    request twice.

### Edit role definitions

Open **Policies → Advanced → Role definitions**. Each row is one role, with its
restricted flag, peer roles, origin access, networks and speed limit overrides.

1. Select **New role**, or **Edit** on a row.
2. Turn on **Limit sharing to these roles** to hold the role to a peer list and
   the distribution-server restriction. Without it, the role permits every role
   and the server.
3. Open **Advanced** for the IPv4 networks, the instruction expiry fallback,
   the eight speed limits and the cadence values. A speed limit of 0 means
   unlimited, any other value is at least 8192 bytes per second, and a blank
   field takes the global default.
4. Select **Preview change**, then **Save role**. Editing any field after a
   preview discards it. **Delete** previews first too.

The Console has no role-policy JSON editor. The global and per-role speed
limits, and the tracker's `qos_state`, are API-only, through the management API
route `PUT /api/v1/peer-policy/qos`. Pair explanations are available only
through `GET /api/v1/peer-policy/explain`.

!!! warning
    Do not edit server state files by hand.

### Import and export the definitions file

**Import CSV…** replaces every definition with a comma-separated values (CSV)
file in the `fleet/roles.csv.example` format, and asks you to confirm a count of
the roles it holds. Roles missing from the file are removed, and a role a device
still declares refuses the import. **Export CSV** downloads the definitions.

`fleet/roles.csv.example` is the tracked template.
`fleet/roles.csv` is operator-owned and ignored by Git, so back it up with your
site inventory. Lists in
`peers` and `nets` are semicolon-separated, rates are integer bytes per second,
and `*_s` values are integer seconds.

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
| **Policies** | which roles may share images and which may use the distribution server |
| **Advanced** | role and restricted-role counts, drift, how full the pending-operation queue is (`N/256`), and, under **Peer access and roles**, per-role member counts and the rule that an explicit ACL entry shadows a role |

Policies shows configured intent. Quarantine and explicit ACLs can restrict
access further. A badge that reads `<state> (stale)`
means the tracker last reconciled more than five minutes ago, or never; its
tooltip carries the last reconcile time and error, so check the tracker.

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

Quarantine is held separately from that device's ordinary ACL assignment, and
applying it preserves the current ordinary ACL entry, which takes effect again
when you release the quarantine. Revoke a device's credentials and only that
ordinary ACL entry is cleared: the quarantine, the role membership and the
device speed limits are all retained. Retiring the device clears the quarantine
along with the ordinary ACL entry, the role membership and the speed limits.

A quarantine written by an earlier release sits in the ordinary ACL instead,
and the next policy change moves it to its own container. Such a legacy
quarantine row has no surviving ordinary ACL, so IRIS cannot recover the
assignment that earlier behavior already overwrote.

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
