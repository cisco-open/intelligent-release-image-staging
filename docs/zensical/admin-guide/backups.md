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
[host recovery window](recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped)
even while the Console is stopped.

**Verify backup** checks the signature, decryption and every captured file in
both sets. **Extract for isolated recovery** writes to a new protected directory.
The operator must provision recovery access on the worker first. Keep encrypted
copies and the trusted backup public key off the deployment host.

!!! warning "Installer candidate scope"

    These controls require an installer-owned deployment and its recorded topology.
    Isolated extraction does not start a restored deployment or authorize
    cutover. Scheduled retention and automated
    recovery cutover remain under development. Use the layout-specific manual
    procedure below for existing installations. Worker setup and qualification
    are documented in the [installer lifecycle development guide](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/lifecycle.md).

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

1. Stop the server.
2. Restore the state, the configuration, and the images from one point in time.
3. Put the age identity back where `IRIS_AGE_KEY_FILE_HOST` points.
4. Restore the credentials and certificates on the host or cluster that owns them.
5. Start the stack with the same files, project names, and volume paths.
6. Check file ownership on the restored volumes, and repair it if it changed. Sign in to the Console: it lists what was in the backup.

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
