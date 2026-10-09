<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate the online signing key

Use **Settings → Certificates & keys → Replace signing key** to replace
the server's instruction-signing key and revoke the previous one. To extend
the certificate without changing its key, use
[certificate renewal](instruction-keys.md#renew-the-instruction-signing-certificate).

The guided workflow keeps the two device-trusted roots, producer epoch and
instruction counters. It applies to the shared verifier in Guest Shell, both
IOx architectures and IOS-XR. It does not change TLS certificates, device
encryption keys, the server's age identity or offline roots.

## Before starting

- Have a root signing key holder available for two public approvals. Use
  `iris-key-setup` wherever that key is held; never upload it to the Console.
- Check signing health, the current revocation list and synchronized time. Keep the age
  recovery recipient and a protected backup available.
- Arrange a staging check on representative devices. Server completion alone
  does not prove that an offline device received the revocation.

The current key keeps working while the replacement awaits approval. A
compromised key needs incident handling: this approval workflow does not make
an attacker-held key unusable until devices receive its signed revocation.

## Prepare and approve the replacement

1. Select **Prepare replacement key**, then **Download replacement public key**.
   Open **Compare public keys and request details**. Record the previous and
   replacement public-file SHA256 values. Confirm the downloaded file with the
   key holder through an independently trusted channel.
2. The key holder uses
   [iris-key-setup](../install/offline-approval.md#approve-a-public-request)
   and choose **Approve server request**. To provide the filenames directly:

   ```bash
   iris-key-setup approve --request iris-replacement.pub \
     --root-key /offline/root-a --output replacement-cert.pub
   ```

3. Return only `replacement-cert.pub`. Select it under **Approved replacement
   certificate**, then choose **Validate and switch signer** and confirm.
4. Check for **New key active; old key retirement needed**. New instructions use the
   replacement key. The old key is not yet revoked.

You can cancel before switching. After approval is committed, the server
finishes the switch even if interrupted; it does not roll back to the old key.
Validation checks the key match, trusted root, principal and validity, including
more than seven days remaining. A change to the active key or roots while approval is
pending requires cancelling and preparing a new request.

## Revoke the previous signer

1. Choose the approving root and **Download retirement request**. The public
   `keylist.payload` preserves existing revocations and adds the previous key.
2. Have that root's holder review the request, sequence and revocation-list hash
   against your independent record. In
   [iris-key-setup](../install/offline-approval.md#approve-a-public-request),
   choose **Approve server request** and select the retirement-list type.
   To provide the filenames directly:

   ```bash
   iris-key-setup approve --kind keylist --request keylist.payload \
     --root-key /offline/root-a --output keylist.envelope
   ```

3. Return only `keylist.envelope`. Select it under **Approved retirement list**,
   then choose **Validate and retire previous key** and confirm.
4. Check for **Replacement published**. Expand the request details to record
   the revocation-list sequence. Confirm fresh instructions and the new list on Guest Shell,
   IOx and IOS-XR devices in your fleet before closing the maintenance task.

The server accepts only the exact requested public approval, authenticated by
the selected root. It proves that the previous signer is revoked and that the
replacement still verifies. It does not delete historical backups containing
the old encrypted key. Protect those backups; never restore an older keylist
or replay state into an active deployment to undo a rotation.

## If a response is lost

Select **Refresh rotation** and review the request ID, fingerprints and state.
The Console requires this check before another action after an uncertain response.
Leaving the page clears selected files but does not cancel a submitted request.
If the state still needs approval, select the same public approval file again.
An interrupted keylist publication is repaired by the identical approved envelope.
If another administrator changed the keylist, download and approve a fresh
retirement request instead.

Do not delete the rotation journal, reset the producer or copy private keys
into place. If the trusted keys changed, review their current state first.
A schedule can prepare a replacement; applying approval and retiring the old
key still require these steps.
