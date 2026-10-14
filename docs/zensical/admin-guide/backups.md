<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Back up and restore

## Console backup controls

**Settings → Backup & restore** connects to the installer host's lifecycle
worker. For installer-owned Docker, split Docker and Kubernetes deployments,
**Back up now**
stops the server and Console, captures encrypted data and a separate identity
recovery set, then starts the services that were running. Confirm the downtime
before proceeding. The host worker continues while the Console is unavailable.
An accepted request shows an operation ID, not a completed backup.
After reconnecting, select **Refresh backup history** and check that operation.
If its outcome is uncertain, review the history before starting another request.
Returning to this page does not repeat a backup or restore.
For an interrupted backup, select **Recover services after this backup** beside
its history entry. If the Console is offline, use the
[host recovery command](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped).
The worker checks the original job and restarts its recorded services. It marks
the backup captured only when both completed archives pass authentication;
otherwise it marks the attempt failed and keeps incomplete files for inspection.
Start a new backup after recovery if needed.
If capture stopped before it could change services, recovery closes that failed
attempt without restarting anything. Missing or changed recovery records require
inspection; keep the original records and files in place.
If the worker restarts during verification or isolated extraction, that attempt
is marked failed. Start a new request after reviewing the result. Partial
extraction files remain private on the host; they are not verified recovery data.
Backups include Console uploads and the host image folder recorded by the
managed Docker installer. A restore puts both back as they were in the backup;
keep the host folder dedicated to IRIS and avoid editing it during maintenance.
For an interrupted credential rotation, use the
[host recovery command](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped)
even while the Console is stopped.

**Verify backup** checks the signature, decryption and every captured file in
both sets. **Extract for isolated recovery** writes to a new protected directory.
First configure recovery access on the worker. Keep encrypted
copies and the trusted backup public key off the deployment host.

The Ubuntu installer starts the worker as a managed host service for all three
layouts. It restarts at boot and after a process failure. Data archives and
identity archives use separate private directories created by the installer.
The default directories share the host's storage. Copy both encrypted sets and
the trusted public backup key to independently protected storage.

Use `irisctl worker-status --state-dir <installation-state-directory>` on the
installer host to check service and storage health. Set recovery access with:

```bash
sudo irisctl maintenance --state-dir /var/lib/iris-installer/iris configure-recovery \
  --identity /protected/path/recovery.age --independent-copy
```

Keep that recovery key outside deployment and backup folders. The command
checks its public recipient and retains protected access on this host.
Keep an independent copy away from the host. Use the `disable-recovery` action
when finished; retained keys remain available for older backups.

Choose separate mounted storage during installation when required. The worker
records those mounts and refuses new work if they disappear or change. Reconnect
the recorded storage before restarting the service. For Kubernetes,
`irisctl maintenance` also shows connection status and works locally when
the connection certificates need renewal.

!!! warning "Recovery scope"

    These controls require an installer-owned deployment and its recorded topology.
    Restore requires current security records from the same deployment.
    Missing records, changed credentials or changed sharing rules block restoration.
    Keep separate copies for recovery from host loss. See
    [Install the Ubuntu package](../install/managed-package.md) for managed deployment setup.

Split Docker also captures the Console's protected configuration from the recorded remote
host. Kubernetes stops every Console replica and the server, checks clean writer
shutdown evidence tied to the exact pod and process start, then captures the
server PVC. A vanished or forcibly terminated pod is not sufficient evidence.
The service age identity remains in the separate recovery set. The external
worker and its transport credentials must remain available during downtime.

## Trust the backup signer

Before your first restore or managed upgrade:

1. Select **Back up now**, confirm downtime and wait for `captured` in backup
   history. The first capture creates a separate backup signing key. Its public
   file is `<installation-state-directory>/backup-custody/signer.pub`.
2. Obtain that public file through an authenticated host connection. Record its
   fingerprint with `ssh-keygen -lf <public-file>` and keep an independent copy
   away from the deployment host. Only the `.pub` file is needed; leave the
   private signing key in place.
3. Put a reviewed copy at a protected path outside the installation state,
   check it against your independent record, then run:

   ```bash
   sudo irisctl maintenance --state-dir /var/lib/iris-installer/iris trust-signer \
     --signer /protected/path/backup-signer.pub
   ```

Use your actual state directory and public-file path. Confirm the key when
prompted. A signer supplied only with the selected archive is not independent
trust. Keep this public record with the recovery material for future restores.

## Make room for new operations

**Settings → Backup & restore** shows space for 100 recent maintenance records
and 20 saved backups. Failed attempts use history space. An attempt that leaves
no saved files does not use a backup slot.

**Protected upgrade backups** are listed separately. They also use host storage
but stay with their upgrade recovery records, outside the 20 ordinary backup
slots. The list shows which archives are present. Use the recorded upgrade
operation on the installer host to [review recovery](upgrade.md#managed-single-host-docker);
these archives cannot be deleted from the Console.

Use **Clear finished history** to remove up to 25 finished records from the
recent list. The worker keeps saved backups, security records, recovery records
and the evidence that prevents old requests from running again. Records still
needed by unfinished maintenance stay in place.

To free backup storage, choose a **Saved backup to delete**, then select
**Delete selected backup**. Review the backup ID before confirming. This permanently
removes its encrypted deployment and recovery archives from this host. Independently stored
copies are unchanged. A backup still needed for recovery cannot be deleted.
Published archives left by a failed capture can also be deleted once services
have recovered; the worker checks each remaining archive before removing it.
Unpublished partial files stay in protected host storage for inspection.

After either action, select **Refresh backup history** to check the result.
If the response was lost, the Console checks that same request before allowing
more work. An interrupted deletion has a **Resume backup deletion** action.
Resolve the host error, then use that action to finish the original deletion.

## What to back up

Back up before an upgrade, a key rotation, a move, or a reset.

| Item | Where it lives | What it holds |
| --- | --- | --- |
| Server state | the `iris-state` volume or the server volume claim | devices, assignments, deployment records |
| Encrypted configuration | the `iris-config` volume or the server volume claim | settings and device credentials |
| Age identity | the file named by `IRIS_AGE_KEY_FILE_HOST`, or its own Secret | the key that decrypts the configuration |
| Uploaded images | the `iris-images` volume or the server volume claim | images published through the Console |
| Imported images | the import root on the host | images you publish in place |
| Device packages | the artifacts directory on the host | the builds you deployed to devices |

Store the age identity apart from the data it decrypts. Restore with the same deployment files, environment files, project names, and volume paths. Back up before rotating the age recipients: it rewrites every encrypted file.

| Layout | Also back up |
| --- | --- |
| One Docker host | The `iris-tier-auth` and `iris-management-ca` volumes. The credential backup is a secret. |
| Separate Docker hosts | The management private key on the server host and the default browser private key on the Console host. |
| Kubernetes | Snapshot the `iris-data` PVC. Back up the credential Secret and the management certificate Secrets. A public address change is a certificate rotation: see [Rotate credentials and certificates](rotations.md). |

!!! warning

    Never copy the server data, the age identity, or the management private key to the Console host.

## Signing keys and instruction state

Keep the encrypted signing key, its certificate, the public roots and keylist
with the configuration backup. Back up the instruction serial state with the
server state. The server recreates runtime plaintext from ciphertext at startup.
Keep the age identity in its separate protected backup. After a loss, see
[Replace or recover signing keys](instruction-keys.md).

!!! warning

    Never restore instruction serial history backwards, and never copy these stores to the Console host.

## Restore a backup

For an installer-owned deployment:

1. Set recovery access on the installer host as described above and
   [trust the backup signer](#trust-the-backup-signer) using your independent record.
2. In **Settings → Backup & restore**, select the captured backup and choose
   **Restore selected backup**. From the host terminal, use the maintenance
   action `restore --job-id <backup-job-id> --allow-downtime` instead.
3. Review the selected backup and confirm downtime and replacement of deployment
   data. Keep the same hosts, storage, deployment configuration and service images.
4. Wait for `restored`. The worker checks both encrypted sets, stops every writer,
   restores file ownership and data, and starts the server followed by the Console.
   Completion includes an authenticated management request from the Console.
5. Sign in again. Restarting the Console invalidates existing sessions. Check the
   restored inventory, jobs, assignments and images before continuing operations.

The worker preserves the current audit trail, instruction counters, revocations,
disclosure records and completed-operation evidence. It requires matching
credentials, sharing rules, device ownership, account data, image quarantine
decisions and external trust.
A refusal before replacement resumes the original services. Original data remains
available in protected directories beside restored storage after publication.

Restores keep the current **Policies → Distribution access** settings and safety
records for shared IP addresses. The server verifies application again after
restarting. Check its status before relying on enforcement.

!!! warning

    An old backup cannot prove current revocations or instruction counters.
    Missing current authority blocks restoration. Never bypass this refusal by
    deleting journals, resetting counters or choosing a later timestamp.
    Recovery onto a replacement host or cluster requires separate security review.

If publication or restart fails, select **Resume this interrupted restore** beside
the matching operation. If the Console is offline, use the same operation ID
with the [host recovery command](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped).
The worker keeps affected services stopped and resumes its approved publication.
It preserves newer data written after a restart attempt.

For deployments configured manually, stop all writers and restore matching state,
configuration, images and identity together. Establish current revocation and
instruction-counter authority before starting services. Use the same deployment
files, project names and volume paths, then verify ownership and Console access.

## Repair volume ownership after a restore

If restored files carry the wrong owner, the Images screen may report
`not readable by the server`. The server uses uid and gid `10001` for its
state, configuration and uploads. Private files also require restrictive modes.

Use the deployment's recorded project, volumes and paths; `server_` is not a
universal volume prefix. Stop its writers before repairing storage. Compare
the affected files with trusted ownership and mode records, then repair only
the verified paths. Never use recursive `chmod` or `chown` on the whole store.
See [Repair changed file permissions](recovery.md#recover-a-volume-whose-private-modes-were-changed)
for the Kubernetes checks.

For an installer-managed restore, preserve the operation files and use its
recovery controls. Do not run a separate Compose stack or bypass a stopped
restore to change permissions.

## Reset and relocation

!!! warning

    A reset removes the inventory, the assignments, the deployment records, the settings, and the credentials. Ask the owner of the deployment first.

1. Undeploy the agents while their records still exist. See [Undeploy, retire and clean up devices](../user-guide/undeploy.md).
2. Back up everything on this page, including the data you plan to discard.
3. Remove the server data you selected, then build the replacement with [Install IRIS](../install/index.md).

## Related

- [Upgrade to a new release](upgrade.md)
- [Rotate credentials and certificates](rotations.md)
- [Recover from an interrupted job or damaged state](recovery.md)
- [Data formats and states](../reference/state-and-data.md)
- [Server configuration](../reference/server-configuration.md)
- [Install on separate Docker hosts](../install/separate-docker-hosts.md)
