<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Create keys and approve signing requests

For guided installation, use the [managed installer](../../install/managed-package.md).

Use this advanced workflow for separate key holders and later local approvals.
For automatic key creation and initial approval without typing key passphrases,
use [local setup](../../install/managed-package.md#guided-local-setup). Choose `--key-mode manual`
there when using existing manual keys; automatic setup does not unlock them.

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

## Use keys kept on the deployment host

For renewal, replacement or root confirmation with locally held keys, run:

```bash
iris-key-setup --local
```

Choose a task, then confirm **LOCAL KEY HOLDER** when asked. If you provide command
arguments, put `--local` before the task, such as `iris-key-setup --local approve`.
Keep each root in its own protected folder. Private keys stay on that host;
only public approval files return to the Console. A compromised deployment host
can also expose locally stored keys. The normal command keeps the separate-holder
checks. Private-key operations are refused inside containers in both modes.

## Create your root

1. Choose **Create my signing key**. Enter `root-a` or `root-b` and a private
   folder. With separate holders, each uses a separate offline machine.
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
2. Choose **Approve server request**, then **Server signing key** or **Key
   retirement list**. Select the request, your private signing key and a new
   output file.
3. Compare the displayed SHA256 value with the independent record. Confirm
   the full value when asked. Automatically managed keys use their saved passphrase;
   manually managed keys ask you to enter theirs.
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
[Replace the independent recovery recipient](../../admin-guide/recovery.md#replace-the-independent-recovery-recipient).

!!! warning

    The native age identity file has no passphrase. Protect its storage and
    transfer. It is a different key from the offline instruction signing roots.
    Private roots stay on their holders' machines in this workflow. Never upload
    a private root or its passphrase to the Console.

## Install with separate key holders

Use this procedure on the deployment controller after
[authenticating and installing the Ubuntu package](../../install/managed-package.md#download-and-authenticate).
The controller needs network access for builds and dependencies. Key holders
can remain offline.

1. Create both signing roots using [Create your root](#create-your-root).
   Assemble only `root-a.pub` and `root-b.pub` in the
   [public roots directory](signing-roots.md#build-host-assemble-the-public-roots).
   Check their fingerprints with the holders.
2. [Create an independent recovery identity](#create-an-independent-recovery-identity).
   Bring only its public `age1...` recipient to the controller.
3. Choose a new instance and empty state directory. Replace the placeholders
   below and append the options for your
   [layout](../../install/managed-package.md#choose-the-layout) to the same command:

```bash
sudo irisctl install --instance my-iris \
  --state-dir /var/lib/iris-installer/my-iris \
  --host <device-facing-ipv4> \
  --roots-dir /path/to/two-reviewed-public-roots \
  --recovery-recipient <independent-age-public-recipient> \
  --accept-changes
```

The installer prepares the deployment and returns exit `20` while waiting for
signing approval. Its public request is `requests/online.pub` inside the state
directory. Record its SHA256 value on the controller:

```bash
sudo sha256sum /var/lib/iris-installer/my-iris/requests/online.pub
```

Transfer only that public request to a key holder through your approved process.
Share the SHA256 value independently so the holder can compare it before approval.
On the holder's machine, run:

```bash
iris-key-setup
```

Choose **Approve server request**, then **Server signing key**, and follow
[Approve a public request](#approve-a-public-request). Return only the public
certificate, `online-cert.pub`, to the controller. Apply it there:

```bash
sudo irisctl resume --state-dir /var/lib/iris-installer/my-iris \
  --certificate /path/to/online-cert.pub
```

Keep the same installer version, state directory and source until setup finishes.
Resume checks recorded identities and prepares the device packages before
starting the Console. Exit `21` means you must
[claim the administrator account](../../install/first-sign-in.md).
Exit `22` means the deployment needs production review. Complete
[root attestations](../../admin-guide/deployment-rotation.md#attest-existing-signing-roots),
backup access and renewal arrangements before production use.

## If approval stops

Check the request, key and output location, then rerun the script. Use a new
output filename if an approval already exists. Keep the original request and
compare its SHA256 value again before approving it.

Use [Rotate the online signing key](../../admin-guide/signer-rotation.md) to apply
replacement approvals, or [Create the two offline signing keys](signing-roots.md)
to assemble the public roots for your deployment.
