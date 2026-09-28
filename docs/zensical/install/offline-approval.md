<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Approve signing requests on your desktop

Use **IRIS Offline signing** on the private key holder's Ubuntu desktop. The
installer package includes this application and its desktop dependencies.
Transfer the package and its dependencies through your approved offline
software process. Open the application from the desktop menu, without `sudo`.
You can also open it with `irisctl custody-ui`.

## Create your root

1. Open **Create my root**. Choose **root-a** or **root-b** and a private storage
   location. Each holder uses a separate offline machine.
2. Select **Create protected root** and confirm. Enter a nonempty passphrase
   in the separate passphrase window, then repeat it when asked.
3. Record the displayed fingerprint. Transfer only the `.pub` file shown in
   the result through your approved public file transfer process.

The application creates a private directory and refuses an existing directory.
If generation is interrupted, inspect the selected location before trying
again. Existing files are retained.

## Approve a public request

1. Download the public key or retirement request from the Console. Obtain its
   SHA256 value independently from the person requesting approval.
2. Open **Approve a request**. Choose **Online signing certificate** or
   **Retirement list**, then select the public request and your private root.
3. Choose a new output file and select **Review and approve**. Compare the
   displayed SHA256 value with the independent record. For a retirement list,
   also confirm its sequence, approving root and revocation list digest.
4. Confirm the request and enter your private root's passphrase in the separate
   window. Wait for **Public approval saved**.
5. Return only the public approval file to the Console. The Console validates
   the approval against its pending request before applying it.

Signing certificates last 30 days. The application signs the exact reviewed
request, even if the original request file changes after your confirmation.
Existing approval files are never overwritten.

## Create an independent recovery identity

1. Open **Create recovery identity** and choose a protected storage location.
2. Select **Create recovery identity** and confirm. The application creates
   `iris-recovery/recovery.age` and a separate public recipient file.
3. Keep an independent copy of the private identity off the deployment host.
   For a new installation, provide only the public recipient to the installer.
   To replace an existing recipient, use the
   [host recovery window](../admin-guide/recovery.md#replace-the-independent-recovery-recipient).

!!! warning

    The native age identity file has no passphrase. Protect its storage and
    transfer. It is a different key from the offline instruction signing roots;
    never provision a signing root on the deployment host.

!!! warning

    Private roots stay on their holders' machines. Never upload a private root
    or its passphrase to the Console. Keep your desktop session trusted while
    entering a passphrase.

## If approval stops

Canceling the passphrase window stops that operation. An incorrect passphrase
or unreadable file also stops it. Check the selected files and output location,
then choose a new output file before retrying. The application does not display
raw signing diagnostics.

Use [Rotate the online signing key](../admin-guide/signer-rotation.md) to apply
replacement approvals, or [Create the two offline signing keys](signing-roots.md)
to assemble the public roots for your deployment.
