<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Create the two offline signing keys

Two offline keys, the signing roots, sign every instruction the server sends a
device. Create both, keep the private halves offline, and put the two public
halves where the package build reads them. The
[Glossary](../reference/glossary.md) defines root key and instruction.

Skip this page if your organization already has an approved pair: ask the
holders for the two `.pub` files and put them in the roots directory below.

## Before you start

- Decide who holds each private key. Two people, two machines, two places.
- Check that `ssh-keygen` is available on each machine that creates a key.
- Choose a passphrase for each key. `ssh-keygen` asks for one.
- Know which host builds your device packages. The table below says where.

## Create the keys

### Holder A: on the first custody machine

```bash
install -d -m 0700 ~/iris-custody
ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a
ssh-keygen -lf ~/iris-custody/root-a.pub
```

Record the fingerprint. Transfer only `root-a.pub` through your approved public
file transfer process to `~/iris-root-import/root-a.pub` on the build host.

### Holder B: on the second custody machine

```bash
install -d -m 0700 ~/iris-custody
ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b
ssh-keygen -lf ~/iris-custody/root-b.pub
```

Record the fingerprint. Transfer only `root-b.pub` through your approved public
file transfer process to `~/iris-root-import/root-b.pub` on the build host.
Each private key stays on its holder's offline custody machine.

### Build host: assemble the public roots

After receiving both public files, compare their fingerprints with the holders'
records and install them:

```bash
ssh-keygen -lf ~/iris-root-import/root-a.pub
ssh-keygen -lf ~/iris-root-import/root-b.pub
install -d -m 0755 ~/iris-roots
install -m 0644 ~/iris-root-import/root-a.pub ~/iris-root-import/root-b.pub ~/iris-roots/
ls -A ~/iris-roots
```

The listing prints `root-a.pub` and `root-b.pub`, and nothing else.

!!! warning

    Never copy a private half to the server host, to a device, into an
    installer argument or into a message, and never generate roots inside a
    Kubernetes pod. If an unexpected file turns up in the roots directory, ask
    the key holders about it rather than deleting it.

## Put the public halves where the build reads them

The builders read one directory holding the two `.pub` files and nothing else;
anything else there is refused with `must hold exactly two public roots
(*.pub)`. Each builder is passed `IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"`
and also accepts `--instruction-roots-dir DIR`. Use the same pair every time.

| Layout | Where the two `.pub` files go |
| --- | --- |
| [One Docker host](one-docker-host.md) | `$HOME/iris-roots` on that host |
| [Separate Docker hosts](separate-docker-hosts.md) | `$HOME/iris-roots` on the server host, which also builds the packages |
| [Kubernetes](kubernetes.md) | `$HOME/iris-roots` on the build machine, and in the pod |

On Kubernetes, install the same two files in the pod and expect the same two
names back:

```bash
for r in root-a root-b; do kubectl -n iris exec -i deployment/iris-seed-server -c iris -- sh -c "install -d -m 0755 /data/config/instr/roots.d && cat > /data/config/instr/roots.d/$r.pub" < ~/iris-roots/$r.pub; done && kubectl -n iris exec deployment/iris-seed-server -c iris -- ls -A /data/config/instr/roots.d
```

## Verify

1. Run `ls -A ~/iris-roots` on the build host: exactly two `.pub` files.
2. Check both names and fingerprints against what the key holders wrote down.
3. On Kubernetes, the listing above shows those two names under
   `/data/config/instr/roots.d`.

## Next steps

- [Download the tools that build device packages](build-tools.md)
- [Build and publish the device packages](device-packages.md)
- [Turn on instruction signing](activate-signing.md)
- [Replace or recover signing keys](../admin-guide/instruction-keys.md)
