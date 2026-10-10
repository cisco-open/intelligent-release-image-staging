<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate deployment trust and keys

Open **Settings > Certificates & keys**, then **Advanced: replace deployment keys**.
Credential replacement uses the Ubuntu installer's host worker. It supports an
installer-owned Docker, split Docker or Kubernetes deployment. The worker
shows the saved layout and the keys it can maintain. Use the
[topology-specific procedures](rotations.md) for deployments without that worker.
Signed root confirmations use the Console directly and do not require this worker.

For Kubernetes, the worker connection has its own CA and client/server
certificates. Check them on the installer host with
`sudo irisctl maintenance --state-dir <installation-state-directory> status`.
Renew them with the `renew-transport --allow-downtime` action and confirm when
asked. This keeps the existing private keys. It restarts the server, checks
the new connection, then retires the old client certificate. The command
connects locally, so it also works after the network certificate has expired.

## Before starting

Configure the [lifecycle worker](backups.md#console-backup-controls) with separate
backup and recovery directories and the independently held recovery identity.
The worker must decrypt both backup sets before changing a credential. Merely
creating encrypted backup files is not enough. Keep off-host copies and protect
the recovery identity separately from the server identity.

Schedule downtime. The Console disconnects while its server is stopped; a
request being accepted does not mean rotation finished. Keep a host session
available for recovery. Do not delete an operation journal to clear an error.
The Console shows the accepted operation ID. If a response is lost or refused,
select **Refresh maintenance evidence** and review that operation before continuing.
Returning to the page does not resubmit it. Backup and rotation history both
block new maintenance while an operation is running or needs recovery.

| Family | What changes | Required follow-through |
| --- | --- | --- |
| Console-to-server certificate | Internal HTTPS key, certificate and Console trust | Worker verifies authenticated, trusted connections from the remote Console or every Console pod. |
| Device connection certificate | Server key, certificate and public copy supplied at onboarding | Remove IRIS deployments first, then onboard and verify devices. |
| Private swarm certificate authority | Authority that signs peer certificates and the seeder's peer identity | Remove IRIS deployments first, then onboard and verify peers. |
| Root signing keys | Both public roots, approved signing certificate and preserved revocation list | Key holders approve requests; remove deployments, rebuild packages, then onboard devices. |
| Server encryption key | Key protecting saved server configuration | Independent recovery recipient stays unchanged; existing backups still need their original keys. |
| Independent recovery recipient | Recovery recipient for encrypted configuration; service identity stays unchanged | Import the protected identity through the host terminal and retain original keys for older backups. |
| Seeder announce credential | Token the server uses to join image swarms and the torrent announce URLs | Worker proves serving on an isolated tracker and again after normal restart. |

## Rotate management TLS, encryption identity or seeder credentials

1. Select the credential family and **Refresh maintenance evidence**.
2. Check that the worker is available and recovery access is configured.
   Seeder rotation requires published, active torrents; it cannot prove serving
   with an empty catalog or only quarantined images.
3. Select **Back up and rotate during downtime** and confirm.
4. Reconnect after maintenance. Select **Refresh maintenance evidence** and
   check the matching operation's state and evidence. A failure requires
   recovery, not another new request.

Encryption identity rotation changes the server's service recipient, not the
external recovery recipient. It refuses unresolved encrypted candidates so
they cannot become unreadable. Finish or cancel pending browser, signer and
trust requests first. To change the recovery key, follow
[Replace the independent recovery recipient](recovery.md#replace-the-independent-recovery-recipient).
Keep an independent copy away from the host. The worker checks both old and new
keys, changes the configured recipient,
and retains access to older backup sets. Keep their original keys until those
sets are retired under your backup policy.

## Replace device TLS or the private swarm CA

1. Use the normal device removal controls to remove the IRIS deployment from
   every affected device. The workflow lists blocking device IDs. An abandoned,
   missing or unknown deployment is not proof of removal.
2. Select **Device connection certificate** or **Private swarm certificate authority**.
   For device TLS, enter the exact names/IP addresses devices use and choose
   CA approval or an explicit 90-day self-signed replacement.
3. Select **Prepare replacement trust**. For CA approval, download the public
   request, obtain its signed certificate and import it with **Validate public
   approval**. Private swarm CA preparation generates its encrypted issuer
   directly; no private key is downloaded.
4. Review the public fingerprint. Select **Back up and rotate during downtime**.
   The worker rechecks removal after stopping all service writers.
5. Check the matching operation's evidence after reconnecting. Onboard devices
   using the normal onboarding controls, then verify their reports and staging
   access. Server-side completion alone does not prove device acceptance.

Device TLS refreshes the Guest Shell bundle and onboarding pin. Native IOx and
XR packages are deployment-neutral for catalog TLS; this change does not by
itself require rebuilding them. Signing-root replacement does require rebuilding
all native packages.

## Replace the root signing keys { #replace-the-offline-signing-roots }

1. Each root holder uses `iris-key-setup` to create a replacement. For keys on
   the deployment host, use `iris-key-setup --local`. Use [separate key holders](../install/offline-approval.md)
   or your chosen [local setup](../install/managed-package.md#guided-local-setup).
   Return only public keys and approvals to the Console.
2. Select **Root signing keys** in the Console. Keep the
   existing root names and choose both replacement public `.pub` files.
3. Select **Prepare replacement trust**, then **Download public approval files**.
4. In the key script, approve the online public key with either new
   root. Approve the prepared revocation-list payload with the first root named
   in the Console. The payload preserves existing revocations and advances the sequence.
5. Import both public approvals and select **Validate public approval**.
6. Remove existing IRIS device deployments and check that no removal blockers
   remain. Select **Back up and rotate during downtime**.
7. Allow time for both IOx architectures and the XR RPM to rebuild. The worker
   verifies those packages and the refreshed Guest Shell bundle before starting
   the Console. Check evidence, onboard devices and verify their acceptance.
8. Under **Confirm root key access**, select the second root and
   download its confirmation request. Its holder approves that payload in the
   key script. Import the signed revocation list and select **Validate
   root confirmation**. Check that both root names have recent signed confirmations.
   Repeat each confirmation before its 180-day freshness expires.

This replaces trust during a planned maintenance window. It is not a rolling
root-overlap protocol and does not reset instruction epochs or discard revoked
keys.

## Attest existing signing roots

Use this procedure for the initial production review and each quarterly check.
It keeps the existing roots and needs neither device removal nor downtime.
Complete or cancel any pending trust replacement first.

1. Select **Root signing keys**. Under **Confirm root key access**,
   select the first root and **Download root confirmation request**.
2. Its holder runs `iris-key-setup`, or `iris-key-setup --local` for host-held keys,
   chooses **Approve server request**, and approves the retirement-list request with the matching
   private root. Follow the fingerprint checks in
   [offline approval](../install/offline-approval.md).
3. Return only the signed public file. Choose it under **Approved public
   revocation list** and select **Validate root confirmation**.
4. Select the other root, download a new request and repeat with its holder.
   Check that **Recent signed confirmations** lists both root names.

The first approval creates a signed empty revocation list when none exists.
Later approvals preserve all existing revocations and advance the sequence.
Each holder must approve their own request; one signature does not confirm both
roots. Repeat quarterly, before the 180-day evidence freshness expires.
Online certificate renewal remains a [separate approval](instruction-keys.md#renew-the-instruction-signing-certificate).

## Recover an interrupted operation

If the Console is reachable, use **Recover approved operation** beside the
interrupted job. When the server is left stopped, connect to the installer host
over SSH and list the saved operations:

```bash
sudo irisctl maintenance --state-dir /var/lib/iris-installer/my-instance status
```

Run the same command with `recover --job-id <operation-id> --allow-downtime`
and confirm when asked. The worker must be running. Recovery checks the
independent backup and original or
already-approved replacement bytes. For encryption identity or recovery-recipient
changes, it can preserve newer encrypted state written after restart only when
the service identity matches the approved transition and both that identity and
the approved independent recovery identity decrypt it to identical content.
It does not approve new trust, wipe conflicting state or claim that devices have
migrated.

If recovery refuses a conflict, preserve the protected installation directory
and backups. Resolve the reported key or access problem before retrying the same
operation. Do not reset, delete or start a second rotation around it.

Schedules for these families remain review reminders. They do not automatically
start downtime, approve new trust or replace recovery keys.
