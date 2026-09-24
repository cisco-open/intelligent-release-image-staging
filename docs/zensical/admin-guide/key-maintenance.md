<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Schedule key maintenance

Open **Settings > Certificates & keys > Scheduled key maintenance**.
Create a schedule for each credential you maintain. All schedules start disabled.
The management service checks due work every 30 seconds.

## Choose the action

| Key family | Scheduled action | Your next step |
| --- | --- | --- |
| Online instruction signer | Prepare a replacement public key | Complete [offline approval and retirement](signer-rotation.md). |
| Device instruction encryption key | Replace one enrolled device's key and publish fresh instructions | Confirm that the device accepts the new instructions. |
| Console management credential | Replace the credential and retain the previous value | Verify every Console, then retire the previous credential. |
| Browser, management and device TLS | Create a review reminder | Follow [Rotate credentials and certificates](rotations.md). |
| Private swarm issuing CA and offline signing roots | Create a review reminder | Plan the trust rollout before replacing any root. |
| Encryption-at-rest identity and recipients | Create a review reminder | Back up, stop writers and follow the [recipient procedure](rotations.md#rotate-the-age-recipients). |
| Seeder, metrics and outbound telemetry credentials | Create a review reminder | Follow the credential's [rotation procedure](rotations.md). |

Review reminders leave credentials unchanged. **Acknowledge review** records
that you reviewed the procedure, not that a rotation succeeded.
Device agents already renew their private-swarm leaf certificates six hours
before their one-day validity ends. Replacing the issuing CA is a separate task.

## Create a schedule

1. Select **New schedule**, then a key family.
2. For a device instruction key, enter the enrolled device ID.
3. Enter the next window's start in UTC, repeat interval and window length.
4. Check **Enable schedule**, choose **Save schedule**, and confirm the action.
5. Refresh maintenance to check the scheduler and operation state.

Device instruction keys require an interval of 8–21 days. The previous key
remains usable for seven days. Other families accept intervals of 1–365 days.
Windows can last 5–1,440 minutes. A schedule supports one family and target;
the deployment supports up to 32 schedules.

Select an existing schedule to change it or clear **Enable schedule**.
You can disable an active schedule; finish its operation before other edits.
Disabling leaves an active transition available for recovery. Saving with an
outdated revision is rejected; refresh and review the current settings.

## Complete the operation

| State | Action |
| --- | --- |
| Approval required | Use the signer controls above the schedule to download the public key and complete offline approval. |
| Verification required | Update and verify every Console, then choose **Retire previous credential**. |
| Review required | Follow the relevant procedure, then acknowledge the review. |
| Intervention required | Check the credential files and rotation state before using the recovery control. |
| Completed | Confirm device or consumer acceptance separately. |
| Missed | The window elapsed without a credential change. Check the next start time. |
| Cancelled | The pending change was cancelled. Check the next start time. |

Only one scheduled credential transition runs at a time. An unfinished approval
or uncertain result pauses further rotations. Review reminders can coexist.
Keep manual maintenance separate from scheduled work.

### On one Docker host

The server and Console share their management credential files. After a scheduled
replacement, load **Devices** and verify other Console instances, if present.
Retirement requires your confirmation and an API request authenticated with
the replacement credential. An old credential cannot authorize its own removal.

### On separate Docker hosts

Copy the replacement management credential to every Console using the
[separate-host procedure](rotations.md#on-separate-docker-hosts). Verify each
Console before retiring the previous value. The scheduler leaves the overlap
active until you confirm.

### On Kubernetes

Signer preparation, device instruction keys and review reminders use server
storage. Mounted Kubernetes Secrets are read-only: use the
[management credential procedure](rotations.md#on-kubernetes) instead of
enabling that family's automated rotation.

## Recover an interrupted operation

The scheduler records its intent before changing a credential. After a restart,
an interrupted operation needs explicit review. It does not retry automatically.

For device keys, **Retry after custody review** reuses an already committed key
and retries instruction publication. For signer preparation, it reuses the same
operation ID. Check the active signer before retrying.

For management credentials, **Check credential recovery** compares the current
and previous files with the recorded public fingerprints. A proven replacement
returns to verification. A proven unchanged original cancels the interrupted
operation. Conflicting files require repair before recovery can proceed.
If credential storage rejected the operation before any change was admitted,
the recovery control cancels it without writing to that storage.

Never delete the maintenance journal to clear an uncertain operation.
Include `state/key-maintenance/` with the rest of the server state in backups.
The journal retains at most 256 operations and removes the oldest finished
record when admitting new work. Active records are retained.

## Check scheduler health

**Observed** means the management worker checked its journal within 90 seconds.
**Stale** or **not observed** requires a management-service check.
**Clock error** means the clock moved behind the last recorded observation;
restore accurate time before maintenance resumes.

Missed windows advance to the next future interval. They never cause a burst
of delayed rotations. Review certificate deadlines even when a schedule exists:
offline approval and consumer rollout can take longer than the planned window.
