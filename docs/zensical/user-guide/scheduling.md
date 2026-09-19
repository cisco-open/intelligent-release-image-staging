<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Schedule maintenance windows

Run work inside a maintenance window instead of when you press a button.

## Scheduling

A schedule runs one action inside one maintenance window: **assign**, which
approves images for staging, or **onboard**, which deploys the IRIS agent to
devices that do not have it. A schedule never installs, activates, reloads, or
changes a boot variable. Each run is an occurrence, and records what it did on
every device it reached.

## In the Console

1. Open **Devices → Schedules**. Each row shows the target, the next run in the
   schedule's own time zone, the state, and how the last run went.
2. Set the **Devices** filter to the devices you want.
3. Choose **Schedule…** in the bulk bar. The modal shows how many devices the
   filter matches now.
4. Name the schedule, set the time, and save. The row shows the next run.

The target is the current Devices filter, re-resolved at each run; the modal
also offers the selected devices as a fixed list. Edit windows, wave gates and
payloads with the API.

## With the API

- `GET /api/v1/schedules` lists the schedules the server holds.
- `POST /api/v1/schedules` creates one.

An update is a conditional write, so send the revision you read. For the schema
and the refusals, see [Console API](../reference/console-api.md) and [API error
codes (problem types)](../problems.md). The command line round-trips schedules
as a file:

```bash
iris-schedule import FILE
iris-schedule export
```

`fleet/schedules.csv.example` is the schema template for that file.

## What you see

- The occurrence records the target it resolved, and every device it reached
  carries a durable outcome.
- Each staged image sits at the device's storage root with a matching hash.

For per-device progress, see
[Assign images and check staging status](assignments.md).

## What a schedule targets

A target is a **filter** plus an optional list of named `device_ids`. Named ids
narrow the filter, they never widen it. An empty filter with an empty id list
selects the whole fleet. The filter keys are the Devices table's own: `q`,
`management_type`, `platform`, `cred`, `telemetry`, `peer`, `role`,
`model_family`, `os_family` and `status`. `bind` decides when the set is fixed:

| `bind` | Meaning |
| --- | --- |
| `late` (default) | The target is **resolved at fire** time, against the fleet as it then is. A device added, retired or re-roled since is included or dropped accordingly. |
| `early` | The set frozen in the **preview** at creation time is the set that runs. |

Either way the occurrence records the `+N / −M` delta between the preview and
what fired. Each fired target is bound to its registration identity, so
deleting and re-adding a device name cannot redirect the occurrence to the
replacement.

A `role` filter selects on the **declared** role, the value you set in the
inventory `role` column. A difference from the compiled sharing policy the
tracker enforces with is reported as `role_drift`. Fix the drift first.

A scheduled onboard also needs a management type, which is how the agent
reaches the network: on its own address, on your management VLAN, or through
the router. An inventory-only row records `unclassified_management_type`;
classify it and the next window picks it up.

## When it runs

`once` names an absolute instant (`at`, an epoch), which daylight saving does
not move. `recurring` names a local weekday and time in a named time zone, and
records which case that local time was:

| Case | What happens |
| --- | --- |
| `normal` | The local time exists exactly once. It fires there. |
| `gap` | Spring forward: the local time does not exist. It fires at the **first valid** instant after the gap. |
| `fold` | Fall back: the local time happens **twice**. It fires at the **first** of the two. |

The window is `window_seconds` long and half-open: work is admitted from the
scheduled instant up to, but not including, the end. Every device it never
reached gets a `window_closed` outcome.

## Sizing a maintenance window

Size the window from these budgets:

| Budget | Value | Where it comes from |
| --- | --- | --- |
| Worker pool | 25 simultaneous jobs | `IRIS_ONBOARD_CONCURRENCY` |
| Queue depth | 1000 waiting jobs | fixed; a submission past it is refused |
| Per-job deadline | 7200 s | `IRIS_ONBOARD_JOB_TIMEOUT` |
| First device contact | 75 s | the reachability and `show version` probe |
| Preflight session | 90 s | the job's first real session against the device |
| Router recipe | 7-10 minutes | measured, per router, end to end |

Half the pool and half the queue are reserved for manual work, so at most 12
scheduled jobs run at once by default. Size from pool rounds, not device count:
a **250-device** wave of routers needs at least **21 rounds**, each costing a
router recipe, so budget 147-210 minutes plus margin.

## Scheduled outcomes

Every scheduled attempt against one device leaves a durable outcome with a
reason. Work is **idempotent per occurrence and device**, so a restart mid
window cannot double-assign or double-onboard.

| Reason | What it means |
| --- | --- |
| `conflict` | Another writer changed the device, or the current same-name fleet row has a different registration identity from the occurrence binding. Manual work wins. Inspect `target_snapshot.registration_ids` and receipt `fleet_registration_id`, then schedule new work if intended. |
| `identity_unavailable` | The claimed target cannot prove a durable registration identity. See [What a schedule targets](#what-a-schedule-targets). |
| `vanished` | The device is no longer in the fleet. |
| `device_revoked` | The device's credentials are revoked; nothing was attempted. |
| `unclassified_management_type` | The row is inventory only and has no management type yet. See [Choose a management type](../install/management-types.md). |
| `window_closed` | The window ended before this device was reached. |
| `wave_deadline` | A wave gate never opened before its deadline; the occurrence ends `stalled` with the counts that held it. |
| `gate_unavailable` | The wave gate could not be evaluated. Nothing is admitted on an unreadable gate. |

Two reasons are notes beside the outcome, not refusals. A quarantined device is
one told to stop sharing with every peer. `peer_quarantined` marks a device
quarantined from peering and still assigned to; `all_targets_quarantined`, an
occurrence whose whole target set was quarantined at window start.

## Deployment waves

A wave is a group of devices a schedule releases together. A schedule may
declare an `after` gate naming a preceding schedule and the ratios it must
reach, `min_staged_ratio`, `max_errored_ratio` and `max_missing_ratio`, before
this one admits any work. `deadline_seconds` stops the waiting. That is how you
order core, then distribution, then access.

The gate reports three counts over the preceding occurrence's target:

- **staged**: the device's heartbeat reports every image of that run staged,
  corroborated by the tracker's own `left == 0` where it has anything to say.
  The tracker can contradict a staged claim but never creates one.
- **errored**: the run failed, or the heartbeat reports the image as errored.
- **missing**: no evidence at all, such as a powered-off device.
  `max_missing_ratio` says how many silent devices a wave may proceed over.

The wave gate is an **operational** signal about when work is admitted. It is
**not a security** boundary: every per-device authority check still runs.

## Scheduled and manual work on the same device

A scheduled `assign` writes the same approved set a manual one does, and a
device row named by a pending schedule's approved preview carries a
**Scheduled** marker.

Narrowing is what loses work. A manual replacement, or a scheduled assignment
with `"mode":"replace"`, replaces the whole approved set, including images
assigned by the other path. Merge mode adds without removing and is the default
(`"mode":"merge"`). Every scheduled outcome records `before_image_ids`,
`after_image_ids` and `removed_image_ids`.

A schedule whose creator is gone shows `created_by <actor> (actor no longer
exists)`. **Re-affirm** on that row rewrites `created_by` to you and bumps
`rev` against the revision on screen; a concurrent edit makes it a refusal.

## Related

- [Assign images and check staging status](assignments.md)
- [Add and onboard devices](onboarding.md)
- [Work with many devices at once](devices.md)
- [Control which devices share with each other](roles.md)
- [Console API](../reference/console-api.md)
