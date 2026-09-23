<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Installer lifecycle development

The current candidate implements same-key instruction certificate renewal in
the Console, and a single-host Docker cold-backup worker with file verification
and isolated extraction. It does not yet implement production recovery cutover,
scheduled retention, split-host/Kubernetes backup adapters or automated key
rotation. These are still release gates, not optional production follow-ups.

## Certificate maintenance

Settings → Certificates & keys shows public certificate validity and key
fingerprints. File observations are not a live TLS handshake or a custody proof.
The existing custody status has its own timestamp and stale-evidence handling.
Renewal follows the existing OpenSSH validation and custody lock. It compares
the exported key/certificate hashes, permits an identical safe retry, requires
expiry extension and more than seven days remaining, and never initializes the
producer or replaces a key. An expired certificate can be renewed with the same
key. The root private key stays offline; only the public approval is uploaded.

Browser TLS replacement remains in TLS & trust. Management/device-facing trust
changes still follow the manual rotation guide. No background automatic renewal
or new reminder delivery service is supplied by this slice.

## Deployment-side worker

New candidate installations mount only their dedicated `control/` directory
into the server, read-only. An external root worker listens on its Unix socket;
the socket accepts root or the server's uid 10001. The Console has no Docker
socket or cluster-admin access. Owner session and CSRF checks happen at the
existing management boundary. RPC accepts fixed operations and backup IDs, never
shell commands, host paths, private keys or arbitrary resource names.

Provision private backup and identity-recovery directories on operator-approved
storage, then run on the installer host:

```bash
sudo irisctl lifecycle-worker \
  --state-dir /var/lib/iris-installer/my-instance \
  --backup-dir /protected-backups/iris-data \
  --recovery-dir /protected-recovery/iris-identity
```

Directories must already exist, be root-owned, mode 0700, without symlink
components. Place the two sets in separate protected directories. A directory
on the same host is not off-host protection. Storage provisioning and a system
service for this foreground worker are not yet installer-managed. Earlier
candidate instances without the control mount are not silently modified/adopted.

To permit verification or isolated extraction, temporarily provision the
independently held age recovery identity on the worker and pass
`--recovery-identity /protected/recovery-key`. For extraction also pass
`--extract-dir /protected/isolated-restores` (a private existing directory).
This is an explicit custody decision. Remove temporary private recovery material
after use; never upload it or an offline signing root through the Console.

Only one worker and one conflicting installer operation can run per instance.
Request IDs are journalled so retrying an accepted request returns the same job,
including after a worker restart, rather than creating another backup.
A stopped worker with a running job returns `recovery-required` after restart;
inspect the protected `backup-operation.json` and actual service state before
reconciling it. Automated crash recovery for this state is not yet implemented.
There is no web API to delete backups or acknowledge an unresolved failure.
The worker bounds history at 100 operations and 20 capture requests, and refuses
more rather than silently deleting a backup. This is not a retention policy.
Host diagnostics retain safe refusal reasons; browser history never receives
subprocess output or raw exception text.

## Cold capture

The same engine is available without a running worker:

```bash
sudo irisctl backup --state-dir /var/lib/iris-installer/my-instance \
  --output /protected-backups/iris-data/new-set \
  --recovery-output /protected-recovery/iris-identity/new-set \
  --allow-downtime
```

Both output directories must be new. Capture checks source/root/configuration
drift, resource ownership, local volume drivers and unaccounted/shared mounts.
It exports the service images, stops both containers, and captures all managed
volumes plus source, deployment configuration, imported images and artifacts.
Service age identity and the dedicated backup signing key go in the separate
identity set. Both sets share an authenticated encrypted backup-set ID. The
backup signing key is not an instruction root and never changes device trust.

Record the public key at `backup-custody/signer.pub` outside the deployment host
through an independently trusted channel before relying on the backups. Age
encrypts to the configured recovery public recipient; OpenSSH signs the payload
manifest in the `iris-backup-v1` namespace. Decryption requires the independently
held recovery identity. The encrypted inventory records hashes, ownership and
modes; public manifests contain ciphertext hashes, not secret payload bytes.

Stop other host-side writers as well. File-change detection is a safeguard, not
a substitute for quiescing external import/build processes. Capture refuses
symlinks, hard-linked files and special files rather than silently omitting them.
Capacity estimation tolerates only the known live IOx control socket; graceful
shutdown must remove it before the actual capture, which still rejects sockets.
Budget temporary space for exported service images and the encrypted archives.
Preflight estimates these together on shared filesystems and requires one GiB
of extra headroom. External writers still need to respect that capacity reserve.
Do not use this candidate for an arbitrary pre-existing Compose installation.

The normal error path attempts to restart exactly the services originally
running. A host crash or forced worker termination requires operator recovery.
`captured` means the archives were written; it does not prove decryption, healthy
application startup, a restored service, or fleet acceptance.

## Verify and extract

On an isolated recovery machine with age and OpenSSH available:

```bash
irisctl verify-backup --backup /protected/backup-set \
  --identity /protected/recovery-key --trusted-signer /protected/approved-backup.pub

irisctl extract-backup --backup /protected/backup-set \
  --identity /protected/recovery-key --trusted-signer /protected/approved-backup.pub \
  --destination /protected/new-extraction
```

Repeat for the matching identity recovery set. Compare backup-set and instance
IDs. Parent directories must be private and caller-owned; the extraction target
must not exist. `--max-bytes` bounds the plaintext payload (default one TiB).
Verification checks the independent signature before decryption, authenticates
the final encrypted chunk and compares every file against the encrypted
inventory. Traversal, links, special members, duplicate names and excess sizes
fail closed. Incomplete temporary extractions are removed.

Extracted files remain private, with original ownership/modes recorded in
`RESTORE-INVENTORY.json`; the engine does not chown them, load container images,
run hooks, start services or contact devices. The result always states
`cutover_permitted: false`. A real recovery must also fence the former primary
and reconcile post-backup revocations and replay floors. Restoring an old epoch
or merely selecting a higher wall-clock value cannot prove safety.

## Verification scope

Tests cover real age/OpenSSH round trips, malformed archives, untrusted signers,
wrong recovery identities, byte limits, peer-credential checks and owner-session/
CSRF enforcement. Browser tests use intercepted APIs. An opt-in Docker storage
rehearsal uses unique disposable containers/volumes, no exposed ports and no
inventory devices; see `server/tests/test_backup_docker.py`. It tests storage
capture, extraction and failure restart, not production application recovery.
