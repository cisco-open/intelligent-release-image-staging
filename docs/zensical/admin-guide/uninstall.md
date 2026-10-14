<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Remove an IRIS deployment

Use `irisctl uninstall` on the managed deployment's controller. It supports
Docker, separate Docker hosts, and Kubernetes installations recorded by the
installer. Keep the installation state directory and its original credentials.

## Prepare devices and data

Undeploy every IRIS device and wait for confirmed removal. Keep device inventory
until uninstall completes. Finish or recover outstanding maintenance jobs.
Uninstall checks device removal before and after stopping the server.

Keep any required [backup](backups.md) and its separate recovery key. Review the
data choice before generating a plan:

| Choice | Application data | Other retained files and resources |
| --- | --- | --- |
| Default | Retains recorded Docker volumes, or the Kubernetes persistent volume claim (PVC) and credential Secrets | Installation history, private keys, backup and recovery storage, external image directories, host packages, shared images, and Kubernetes namespace |
| `--purge-data` | Deletes only the plan's recorded Docker volumes, or Kubernetes PVC and credential Secrets | The same retained files and resources as the default |

!!! warning "Data deletion"
    Purging application data is permanent. Kubernetes storage deletion follows
    the existing storage provider's policy. A `Retain` policy keeps the volume
    and its data after the claim is removed. Ask your storage administrator to
    remove that data when required. Private files retained on the controller
    can still contain credentials; protect that directory after uninstall.

## Review a plan

Create a plan using the original state directory:

```bash
sudo irisctl uninstall plan --state-dir /var/lib/iris-installer/my-iris
```

Add `--purge-data` to that command only when deleting application data. The
output lists exact removal targets and retained resources, an `operation_id`,
and a `plan_sha256`. Review them before continuing. Planning leaves services
running.

To replace an unapplied plan, run `irisctl uninstall cancel` with the same
`--state-dir`, `--operation-id`, and `--plan-sha256`. The cancelled plan remains
in the installation history.

## Apply the reviewed plan

Use the two values printed by the plan:

```bash
sudo irisctl uninstall apply --state-dir /var/lib/iris-installer/my-iris \
  --operation-id OPERATION_ID --plan-sha256 PLAN_SHA256 --allow-downtime
```

Repeat `--purge-data` here if the plan selected it. A different data choice
requires a new unapplied plan.

The command disables and stops the recorded lifecycle worker, stops application
writers, and removes only the captured resource identities. It then checks
resource absence and removes the recorded worker service definition. Kubernetes
keeps its namespace and any unrelated contents. A maintenance isolation policy
created while stopping Kubernetes writers also remains.

The final `uninstalled` status lists what was removed and what remains. The
retained state directory is historical evidence, not an active deployment.

## Recover an interruption

Inspect the original operation:

```bash
sudo irisctl uninstall status --state-dir /var/lib/iris-installer/my-iris
```

Run `irisctl uninstall recover` with the original `--state-dir`,
`--operation-id`, `--plan-sha256`, `--allow-downtime`, and data choice. Recovery
checks whether the pending target still exists before continuing. Changed
resource identities, active writers, or an unresolved deletion stop recovery.
Keep the original operation and investigate the reported resource; do not erase
the journal or replace its ownership records.
