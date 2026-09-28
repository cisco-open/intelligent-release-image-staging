<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate deployment trust and keys

Open **Settings > Certificates & keys > Rotate deployment trust and keys**.
These controls use the Ubuntu installer's host worker. They support an
installer-owned, single-host Docker deployment. Split Docker and Kubernetes
do not yet have this maintenance adapter; their controls remain unavailable.
Use the [topology-specific procedures](rotations.md) for those deployments.

## Before starting

Configure the [lifecycle worker](backups.md#console-backup-controls) with separate
backup and recovery directories and the independently held recovery identity.
The worker must decrypt both backup sets before changing a credential. Merely
creating encrypted backup files is not enough. Keep off-host copies and protect
the recovery identity separately from the server identity.

Schedule downtime. The Console disconnects while its server is stopped; a
request being accepted does not mean rotation finished. Keep a host session
available for recovery. Do not delete an operation journal to clear an error.

| Family | What changes | Required follow-through |
| --- | --- | --- |
| Console-to-server TLS identity | A separate encrypted management key and certificate; local Console trust | Worker verifies an authenticated, trusted connection from the Console. |
| Device-pinned server TLS identity | Server key, certificate and distributed onboarding pin | Remove IRIS deployments first, then onboard and verify devices. |
| Private swarm issuing CA | Encrypted peer issuer and newly issued origin identity | Remove IRIS deployments first, then onboard and verify peers. |
| Offline instruction signing roots | Both public roots, approved online certificate and preserved revocation list | Approve offline, remove deployments, rebuild packages, then onboard devices. |
| Server encryption identity | Service age identity and encrypted configuration | Independent recovery recipient stays unchanged; existing backups retain their original custody. |
| Seeder announce credential | Seeder token and canonical torrent announces | Worker proves serving on an isolated tracker and again after normal restart. |

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
trust requests first. To change external recovery custody, use **Create recovery
identity** in the offline desktop application. Retain an independent off-host
copy, then use **Replace recovery identity** in the host maintenance window to
import it and confirm the change. No private identity crosses the browser API.
The worker verifies both old and new custody, changes the configured recipient,
and retains access to older backup sets. Keep their original keys until those
sets are retired under your backup policy.

## Replace device TLS or the private swarm CA

1. Use the normal device removal controls to remove the IRIS deployment from
   every affected device. The workflow lists blocking device IDs. An abandoned,
   missing or unknown deployment is not proof of removal.
2. Select **Device-pinned server TLS identity** or **Private swarm issuing CA**.
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
   access. Server-side proof does not attest to device acceptance.

Device TLS refreshes the Guest Shell bundle and onboarding pin. Native IOx and
XR packages are deployment-neutral for catalog TLS; this change does not by
itself require rebuilding them. Signing-root replacement does require rebuilding
all native packages.

## Replace the offline signing roots

1. Each root holder uses **IRIS Offline signing** on their separate custodian
   machine to generate a replacement root. Follow
   [offline approval](../install/offline-approval.md); private roots stay there.
2. Select **Offline instruction signing roots** in the Console. Keep the
   existing root names and choose both replacement public `.pub` files.
3. Select **Prepare replacement trust**, then **Download public approval files**.
4. In the offline application, approve the online public key with either new
   root. Approve the prepared revocation-list payload with the first root named
   in the Console. The payload preserves existing revocations and sequence.
5. Import both public approvals and select **Validate public approval**.
6. Remove existing IRIS device deployments and check that no removal blockers
   remain. Select **Back up and rotate during downtime**.
7. Allow time for both IOx architectures and the XR RPM to rebuild. The worker
   verifies those packages and the refreshed Guest Shell bundle before starting
   the Console. Check evidence, onboard devices and verify their acceptance.
8. Under **Confirm each offline root's custody**, select the second root and
   download its attestation request. Its holder approves that payload in the
   offline application. Import the signed revocation list and select **Validate
   root attestation**. Check that both root names have fresh signed evidence.
   Repeat independent attestations before their 180-day freshness expires.

This replaces trust during a planned maintenance window. It is not a rolling
root-overlap protocol and does not reset instruction epochs or discard revoked
keys.

## Recover an interrupted operation

If the Console is reachable, use **Recover approved operation** beside the
interrupted job. When the server is intentionally left stopped, use the host
desktop tool:

```bash
sudo irisctl maintenance-ui --state-dir /var/lib/iris-installer/my-instance
```

It needs a local graphical session and the lifecycle worker running for that
installation. Select the interrupted operation and **Recover approved
operation**. Recovery revalidates the independent backup and permits only the
original or already-approved replacement bytes. It does not approve new trust,
wipe conflicting state or claim that devices have migrated.

If recovery refuses a conflict, preserve the protected installation directory
and backups. Resolve the reported custody problem before retrying the same
operation. Do not reset, delete or start a second rotation around it.

Schedules for these families remain review reminders. They do not automatically
start downtime, approve new trust or change recovery custody.
