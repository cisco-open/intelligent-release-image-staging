<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate the online signing key

Use **Settings → Certificates & keys → Rotate the instruction signing key** to replace
the server's instruction-signing key and revoke the previous one. To extend
the certificate without changing its key, use
[certificate renewal](instruction-keys.md#renew-the-instruction-signing-certificate).

The guided workflow keeps the two device-trusted roots, producer epoch and
instruction counters. It applies to the shared verifier in Guest Shell, both
IOx architectures and IOS-XR. It does not change TLS certificates, device
encryption keys, the server's age identity or offline roots.

## Before starting

- Have an offline root custodian available for two public approvals. Their
  private root stays on their own machine, never in the Console or server.
- Check signing health, current keylist and synchronized time. Keep the age
  recovery recipient and a protected backup available.
- Arrange a staging check on representative devices. Server completion alone
  does not prove that an offline device received the revocation.

The current key keeps working while the replacement awaits approval. A
compromised key needs incident handling: this approval workflow does not make
an attacker-held key unusable until devices receive its signed revocation.

## Prepare and approve the replacement

1. Select **Prepare replacement key**, then **Download replacement public key**.
   Record the previous and replacement public-file SHA256 values shown in the
   Console. Confirm the downloaded file with the custodian through your
   independently trusted custody channel.
2. On the offline machine, use
   [iris-key-setup](../install/offline-approval.md#approve-a-public-request)
   and choose **Approve server request**. To provide the filenames directly:

   ```bash
   iris-key-setup approve --request iris-replacement.pub \
     --root-key /offline/root-a --output replacement-cert.pub
   ```

3. Return only `replacement-cert.pub`. Select it under **Approved replacement
   certificate**, then choose **Validate and switch signer** and confirm.
4. Check that the state is **retirement pending**. New instructions use the
   replacement key. The old key is not yet revoked.

You can cancel before switching. After approval is committed, the server
finishes the switch even if interrupted; it does not roll back to the old key.
Validation checks the key match, trusted root, principal and validity, including
more than seven days remaining. A change to current custody while approval is
pending requires cancelling and preparing a new request.

## Revoke the previous signer

1. Choose the approving root and **Download retirement request**. The public
   `keylist.payload` preserves existing revocations and adds the previous key.
2. Have that root's custodian review the request, sequence and KRL digest through
   the custody procedure. In
   [iris-key-setup](../install/offline-approval.md#approve-a-public-request),
   choose **Approve server request** and select the retirement-list type.
   To provide the filenames directly:

   ```bash
   iris-key-setup approve --kind keylist --request keylist.payload \
     --root-key /offline/root-a --output keylist.envelope
   ```

3. Return only `keylist.envelope`. Select it under **Approved retirement list**,
   then choose **Validate and retire previous key** and confirm.
4. Record the completed keylist sequence. Confirm fresh instructions are
   accepted and the new keylist is observed on representative Guest Shell,
   IOx and IOS-XR devices in your fleet before closing the maintenance task.

The server accepts only the exact requested public approval, authenticated by
the selected root. It proves that the previous signer is revoked and that the
replacement still verifies. It does not delete historical backups containing
the old encrypted key. Protect those backups; never restore an older keylist
or replay state into an active deployment to undo a rotation.

## If a response is lost

Select **Refresh rotation**. The server records the operation durably; a page
reload does not create another key. Retry the same approval if the outcome is
uncertain. An interrupted keylist publication is repaired by the identical
approved envelope. If another administrator changed the keylist, download and
approve a fresh retirement request instead.

Do not delete the rotation journal, reset the producer or copy private keys
into place. A refusal about changed authority requires reviewing custody first.
The workflow is operator initiated, not scheduled automatic rotation.
