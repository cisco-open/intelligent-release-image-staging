<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Installer lifecycle development

The current candidate implements same-key instruction certificate renewal and
guided online signer rotation in the Console, and a topology-aware
cold-backup worker with file verification and isolated extraction. It does not
yet implement production recovery cutover or scheduled retention. These are still
release gates, not optional production follow-ups. Scheduled signer preparation,
device instruction-key rotation and management-token rotation now have
opt-in adapters. Browser TLS and telemetry credentials have operator-driven UI
workflows; their schedules remain review reminders. Installer-owned Docker,
split Docker and Kubernetes
deployments also have planned maintenance adapters for management/device TLS,
peer CA, offline roots, service age identity and seeder credentials. The host UI
also changes the independent recovery recipient without sending a private
identity through the browser. Device
consumer rollout remains an explicit remove/re-onboard/verify procedure.

## Certificate maintenance

Settings → Certificates & keys shows public certificate validity and key
fingerprints. File observations are not a live TLS handshake or a custody proof.
The existing custody status has its own timestamp and stale-evidence handling.
Renewal follows the existing OpenSSH validation and custody lock. It compares
the exported key/certificate hashes, permits an identical safe retry, requires
expiry extension and more than seven days remaining, and never initializes the
producer or replaces a key. An expired certificate can be renewed with the same
key. The root private key stays offline; only the public approval is uploaded.

Browser TLS now also has the public request/approval workflow below.
Management/device-facing trust changes use the scoped host-worker workflow below.
No background automatic renewal or external reminder delivery service is supplied.

## Deployment trust transactions

`server/trust_rotation.py` prepares encrypted candidates and validates public
approvals without publishing them. Root replacement preserves the exact installed
KRL, revocations and instruction epoch, and advances the keylist sequence. Its strict
drain check includes orphan credentials and abandoned deployment records, and
runs again after every normal writer has stopped.

Existing-root attestations use a separate public request journal and the normal
Console API, without host-worker downtime or root replacement. Initial approval
creates an empty signed revocation list; later approvals preserve the KRL and
advance the sequence. Each root needs its own signed approval. Status derives
fresh attested root IDs from current evidence within the 180-day window.

`tools/iris_installer/credential_maintenance.py` owns the shared transaction:
independently decrypt both cold-backup sets, stop writers, apply approved bytes,
restart the server, verify the family, restart Console, then prove authenticated
management HTTPS from Console. Recovery is explicit, same-ID and normally
old-or-approved hash bounded. Age identity and recovery-recipient recovery can
preserve newer ciphertext from a restarted writer only if the current service
recipient matches the approved transition and service and independent recovery
identities decrypt it to identical plaintext. `trust_maintenance.py` also updates installer root pins and
rebuilds both IOx architectures and XR when signing roots change.

Seeder maintenance runs only tracker and seeder on an isolated Docker network
with no published ports. It uses a temporary runtime loopback certificate and
the existing authenticated serving predicate. Normal startup restores canonical
public announces, and serving is proved again before completion. Kubernetes uses
an isolated helper pod and a deny-all NetworkPolicy for the same maintenance
callback. NetworkPolicy is not equivalent to Docker's network isolation: traffic
to the pod's own node is exempt. Keep the node and its services trusted, and
qualify CNI enforcement with a reachable off-node positive control and a denied
helper connection to that same endpoint. See the
[Kubernetes NetworkPolicy limitations](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
Public tracker
validation still refuses loopback outside this explicit maintenance process mode.

The worker accepts fixed UUID/family requests, not browser-provided paths or
commands. `irisctl maintenance-ui` reaches the same protected Unix socket when
the Console is stopped. `irisctl custody-ui` handles offline approvals separately.
Neither UI transports offline private roots. See the
[operator procedure](../zensical/admin-guide/deployment-rotation.md).

### Topology adapters

`split_deploy.py` pins SSH host/identity custody and the remote Console project.
Only tier credentials, the public management CA and Console browser identity
cross that boundary. Capture includes encrypted remote Console custody; rotation
proves authenticated management access from the actual remote container.

`kube_deploy.py` records the explicit cluster UID/context, namespace ownership,
PVC identity, intended resource specifications and immutable image references.
The server remains one replica, with one to eight independent Console consumers.
`topology_lifecycle.py` bounds PVC reads and candidate writes by paths, digests
and object identities; mutable private host mirrors live in protected tmpfs.
Snapshot reads batch at most 128 members and 4 MiB per transport, with the full
stopped-writer check on every batch, per-file identity and digest verification,
and a final unchanged inventory. No ownership checks are cached across batches.
Each check bulk-reads the owned objects and the namespace's complete pod/policy
lists after cluster preflight. It still rejects unexpected PVC writers or network
policies and verifies the helper's current execution immediately before transfer.
The shutdown marker binds pod UID and a fresh process nonce to child exit status.
Forced pod deletion cannot substitute for stopped-writer proof. Age-identity
proof checks the restarted PVC rather than trusting a pre-restart local mirror.

The external worker accepts the same fixed requests through deployment-specific
mutual TLS (`lifecycle_network.py`). The CA private key and worker private key
remain on the controller. Only the public CA and client certificate/key enter
the server pod; none enter Console pods. No browser-selected host, path or
command is accepted. Scheduled management
token changes publish overlap to remote consumers through a bounded public job
ID, then prove current-token use. A failed sync retains overlap and requires
reconciliation; explicit retirement performs a fresh consumer check.
Consumer proof binds the credential used for the HTTPS request to the inspected
container or pod execution. A replacement or restart during verification refuses
completion; evidence from the previous execution cannot authorize retirement.

`lifecycle_transport_maintenance.py` renews the Kubernetes worker CA and leaf
certificates while preserving all three private keys. Host-root Unix requests
are separate from remote RPC. A journalled old/new client-certificate overlap
lasts until the owned server proves the replacement through an actual TLS
connection. Recovery uses the same operation ID and remains available through
the host UI after certificate expiry. This does not implement replacement of
compromised transport keys.

Recovery-recipient replacement pins the original key for the operation's backup
and encrypted write plan. The worker's protected `recovery-access.json` retains
per-operation key locations and prior backup access, activates the new identity
only after verified completion, and survives a crash between custody activation
and job completion. These locations are never returned through the API.

## Browser TLS and service credentials

`server/tls_rotation.py` holds encrypted candidates and public approvals in
`config/tls/rotation.json`, serialized with existing direct TLS uploads. Exact
names, key binding, current validity and server purpose are checked before a
publication is admitted. The durable intent records original file hashes;
explicit recovery writes only original-or-approved bytes, tolerating loss of
the derived runtime copy after restart. Recovery repairs an admitted transaction,
not certificate expiry. The authenticated Console reloads its own listener;
publication alone does not prove browser trust or every Console's adoption.

`server/service_credentials.py` stores metrics and collector overrides inside
the existing age-encrypted secrets store. Mounted deployment files stay unchanged.
Metrics accepts the current and previous values during migration. Collector
headers bind to an exact HTTPS destination; a changed destination disables
export rather than leaking credentials or falling back to anonymous delivery.
The telemetry worker reloads replacements and rollbacks between sample passes.

Consumer-use evidence records only an operation ID and time under
`state/credential-proof/`. Retirement requires matching evidence and owner
confirmation. One observed scrape/delivery cannot prove all consumers migrated
or that an external collector revoked its old credential. Pending rollback
restores the preceding override or the deployment-file authority. No response
returns stored tokens or headers. See the
[operator workflow](../zensical/admin-guide/console-credentials.md).

Tests exercise real OpenSSL/age, each publication boundary, temporary-file loss,
stale approvals, split-tier TLS handshake/reload failure and retry, a real metrics
listener, and a trusted HTTPS collector with live credential replacement/rollback.
Browser workflow tests use intercepted APIs, not production account sessions.

## Online signer rotation

The [operator workflow](../zensical/admin-guide/signer-rotation.md) uses
`server/instruction_rotation.py` and the existing custody lock. Only encrypted
candidate material and public approvals persist in `instr/online-rotation.json`.
Plaintext candidates use the runtime directory. An approved `committing` intent
is rolled forward before any subsequent custody operation; each published file
must still match its old or approved replacement digest. No producer reset or
per-device encryption-key changes occur.

Retirement extends the installed KRL and requires a separate offline signature.
The public `irisctl approve-keylist` companion uses the existing keylist format.
Exact approval retries repair interrupted metadata publication. Tests cover real
age/OpenSSH, all signer publication boundaries, prior revocation preservation,
authenticated Console-to-management requests and both native SSHSIG helpers
(ARM64 under emulation when available). Browser tests intercept APIs; these
tests do not claim inventory-device acceptance.

## Scheduled key maintenance

`server/key_maintenance.py` runs in the state-owning management process, never
the Console or the server factory used by tests. Its public-only journal lives
under `state/key-maintenance/`, protected by a nonblocking process lock and
atomic fsynced writes. No private credentials enter API responses or exception
details. Owner session and CSRF checks cover every mutation. Policy revision
comparison rejects stale writes.

Schedules use UTC epoch seconds, explicit windows and stable operation IDs.
The worker checks every 30 seconds and skips elapsed windows without catch-up.
An interrupted running intent becomes intervention-required, never a blind
automatic retry. Only one credential transition is admitted at a time; review
reminders do not block unrelated families. The last 256 public operations are
retained, pruning only completed, cancelled, reviewed or missed records.

The device adapter holds the producer/device locks across encrypted persistence
and restamping. Recovery recognizes the committed replacement and republishes
instructions without generating another key. Management-token rotation shares
the CLI lock, retains previous credentials, and requires a request using the
new credential plus operator confirmation before retirement. Interrupted
management writes can be reconciled against recorded public fingerprints.
Installer-owned split Docker and Kubernetes deployments use the host worker to
publish credential overlap and prove current-token use on every owned Console.
An unsuccessful synchronization retains overlap for explicit reconciliation.
Manually provisioned Kubernetes deployments use the separate manual procedure.

Signer preparation retains offline approval boundaries and polls the existing
rotation journal for completion or cancellation. Review-only entries cover TLS,
roots, age identity, seeder, metrics and collector headers; acknowledging them
must never be interpreted as completed rotation. Private-swarm leaf renewal is
already device-managed and distinct from CA replacement. No email/webhook
delivery, enterprise-CA integration or automated trust rollout is included.

CLI recipient rekey includes the encrypted peer CA, independent management key
and default Console identity. It refuses pending signer, browser TLS or deployment
trust candidates because their journals embed ciphertext under the existing
recipients. Writers must be stopped. This recipients-only command does not replace
the runtime service identity; use the guided
[encryption identity rotation](../zensical/admin-guide/deployment-rotation.md#rotate-management-tls-encryption-identity-or-seeder-credentials)
for that change.

## Deployment-side worker

Installer-owned Docker deployments mount their dedicated `control/` directory
into the server, read-only. An external root worker listens on its Unix socket;
the socket accepts root or the server's uid 10001. Kubernetes instead connects
the server to that external worker over the recorded mutual-TLS endpoint, with
no host control-directory mount. Its host desktop still uses the local Unix
socket. The Console has no Docker
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

For Kubernetes, the same command also serves the installation's recorded
`--lifecycle-url`; allow the server pod to reach that controller address and port.
The listener binds that address by default. Use the worker's `--listen-address`
only when the local bind address must differ; this does not change the recorded
URL or certificate names.

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
It exports the service images and stops the owned server and all Console
consumers. Docker captures the managed volumes; Kubernetes captures the server
PVC through an owned helper pod. Both include source, deployment configuration,
imported images and artifacts. Split Docker also captures encrypted remote
Console custody, and Kubernetes includes the host worker's transport custody.
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
fail closed. Extension metadata is bounded before tar parsing expands it;
global, chained and sparse extensions are refused. Normal long/Unicode paths
remain supported. Incomplete temporary extractions are removed.

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
