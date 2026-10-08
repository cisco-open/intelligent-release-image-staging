<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Create keys and approve signing requests

Run `iris-key-setup` in a terminal on the private key holder's machine.
It asks for the files it needs, checks them and tells you what to transfer.
The installer package includes the script. Use your approved process to bring
the package and its dependencies to an offline machine.

```bash
iris-key-setup
```

Choose a task from the menu. You can run the same script again to continue.
On the server, `irisctl install` creates the deployment's online keys and
certificates. The steps below handle the keys that stay with their holders.

## Create your root

1. Choose **Create my signing key**. Enter `root-a` or `root-b` and a private
   folder. Each holder uses a separate offline machine.
2. Enter a passphrase when asked, then repeat it. Store it safely, separate
   from the private key.
3. Record the public fingerprint. Choose **Copy public file** to copy the
   `.pub` file to your transfer folder.

The script creates a protected folder. If the key already exists, it checks
and reuses it instead of replacing it. Transfer only `root-a.pub` and
`root-b.pub` to the server. See [Create the two offline signing keys](signing-roots.md)
for the public roots directory used by package builds.

For approved transfers from a connected machine, the menu also offers **Send
public file over SSH** and **Read public request over SSH**. Verify the server's
SSH host key first. The destination folder must already exist. Keep offline
signing machines offline; use a transfer machine or removable storage instead.

## Approve a public request

1. Get the public request from the installer or Console. Obtain its
   SHA256 value independently from the person requesting approval.
2. Choose **Approve server request**. Select the request, your private signing
   key and a new output file. Choose signing approval or a retirement list.
3. Compare the displayed SHA256 value with the independent record. Confirm
   the full value when asked, then enter your private key's passphrase.
4. Use **Copy public file** to return only the saved public approval. Apply it
   with `irisctl resume` during installation, or upload it to the matching
   request in the Console.

Signing certificates last 30 days. The script signs the exact request you
reviewed. It refuses to overwrite an existing approval file.

## Create an independent recovery identity

1. Choose **Create recovery key** and enter a private folder.
2. Keep `recovery.age` in protected storage, with an independent copy away
   from the deployment host.
3. Choose **Copy public file** to transfer `recovery-recipient.pub`. Give the
   installer the public `age1...` value in that file.

To replace a recovery key in an existing deployment, follow
[Replace the independent recovery recipient](../admin-guide/recovery.md#replace-the-independent-recovery-recipient).

!!! warning

    The native age identity file has no passphrase. Protect its storage and
    transfer. It is a different key from the offline instruction signing roots.
    Private roots stay on their holders' machines. Never upload a private root
    or its passphrase to the Console or copy it to the server.

## If approval stops

Check the request, key and output location, then rerun the script. Use a new
output filename if an approval already exists. Keep the original request and
compare its SHA256 value again before approving it.

Use [Rotate the online signing key](../admin-guide/signer-rotation.md) to apply
replacement approvals, or [Create the two offline signing keys](signing-roots.md)
to assemble the public roots for your deployment.
