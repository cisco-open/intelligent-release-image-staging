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
For an interrupted credential rotation, use the
[host recovery command](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped)
even while the Console is stopped.

**Verify backup** checks the signature, decryption and every captured file in
both sets. **Extract for isolated recovery** writes to a new protected directory.
The operator must provision recovery access on the worker first. Keep encrypted
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
    Keep separate copies for recovery from host loss. Scheduled retention remains
    a separate operation. See
    [Install the Ubuntu package](../install/managed-package.md) for managed deployment setup.

Split Docker also captures encrypted Console custody from the recorded remote
host. Kubernetes stops every Console replica and the server, checks clean writer
shutdown evidence tied to the exact pod and process start, then captures the
server PVC. A vanished or forcibly terminated pod is not sufficient evidence.
The service age identity remains in the separate recovery set. The external
worker and its transport credentials must remain available during downtime.

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

1. Set recovery access on the installer host as described above. Set the trusted
   backup signer with `irisctl maintenance --state-dir <installation-state-directory>
   trust-signer --signer /protected/path/backup-signer.pub`, using `sudo`.
   Check this public key against your independently held record.
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

The worker preserves current instruction counters, revocations, disclosure records
and completed-operation evidence. It requires matching credentials, sharing rules,
device ownership, account data, image quarantine decisions and external trust.
A refusal before replacement resumes the original services. Original data remains
available in protected directories beside restored storage after publication.

!!! warning

    An old backup cannot prove current revocations or instruction counters.
    Missing current authority blocks restoration. Never bypass this refusal by
    deleting journals, resetting counters or choosing a later timestamp.
    Recovery onto a replacement host or cluster requires separate security review.

If publication or restart fails, use **Recover approved operation** with the same
operation ID with the [host recovery command](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped).
The worker keeps affected services stopped and resumes its approved publication.
It preserves newer data written after a restart attempt.

For deployments configured manually, stop all writers and restore matching state,
configuration, images and identity together. Establish current revocation and
instruction-counter authority before starting services. Use the same deployment
files, project names and volume paths, then verify ownership and Console access.

## Repair volume ownership after a restore

If restored files carry the wrong owner, the Images screen reports `not readable by the server`. The server owns its state, configuration, and uploads volumes as uid and gid `10001`. Volume names carry the Compose project prefix `server_`; check yours with `docker volume ls`. Stop the stack and repair:

```bash
docker compose -f server/docker-compose.yml stop
docker run --rm -u 0 \
  -v server_iris-state:/var/lib/iris \
  -v server_iris-config:/etc/iris \
  -v server_iris-images:/var/lib/iris-images \
  iris:latest chown -R 10001:10001 /var/lib/iris /etc/iris /var/lib/iris-images
docker compose -f server/docker-compose.yml up -d
```

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
