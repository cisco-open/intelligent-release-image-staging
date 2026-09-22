<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# KDF, PAE layout, iris-aead adapter and the OpenSSL pin

This page is for a contributor changing or auditing the code that encrypts and
decrypts an instruction, the signed message the server sends a device saying
which images to stage and how. It carries the byte-level detail: the
key-derivation function, the layout of the data the cipher authenticates, the
adapter that runs the cipher, and the pinned OpenSSL version. For the trust
model an architect needs, see
[How instructions are signed and trusted](../zensical/architecture/security-model.md#how-instructions-are-signed-and-trusted).
That page covers who signs an instruction and what the agent checks before it
trusts one; this page covers how the envelope, the encrypted file that carries
an instruction, is actually encrypted.

The format is `IRIS-INSTR/2`. It replaced an earlier custom HMAC keystream
with AES-256-SIV (RFC 5297) through OpenSSL's maintained EVP implementation.
Rebuilding this code is a coordinated server-and-agent change; see
[Migration notes for contributors](upgrade-notes.md) before you touch it.

## The key-derivation function

Each device gets its own key material. The server derives it with an
SP800-108 counter-mode key-derivation function built on HMAC-SHA-256. One
per-device derivation produces 96 bytes: 64 bytes of AES-SIV key material and
a separate 32-byte nonce-derivation key. The derivation binds an audience
context, the device identity and the instruction-key identity together,
under a label specific to the v2 format. Key material minted for one device
or one instruction key cannot be replayed against another.

## The nonce

AES-SIV takes a 16-byte nonce. IRIS derives it instead of drawing it at
random: the nonce binds the device, the instruction key, the epoch and the
serial number (`instr_serial`) together. AES-SIV is misuse-resistant, so
reusing that deterministic nonce by accident does not break confidentiality
the way it would with a classic stream cipher; identical plaintext and
associated data produce identical ciphertext. That is not the same as
replay protection: seeing the same ciphertext twice does not make it safe to
apply twice. The agent keeps its own forward-only floor on `(epoch,
instr_serial)` and rejects anything at or behind it; see
[How instructions are signed and trusted](../zensical/architecture/security-model.md#how-instructions-are-signed-and-trusted)
for how that floor is enforced.

## The PAE layout

AES-SIV authenticates associated data alongside the ciphertext. IRIS builds
that associated data as one PAE value: a single length-framed byte string
that concatenates several fields. A change to any one of them, not only to
the ciphertext, invalidates the SIV tag. In order, the fields are:

| Order | Field |
| --- | --- |
| 1 | Format magic |
| 2 | Exact header |
| 3 | Signed role body |
| 4 | Signature |
| 5 | Nonce |

The 16-byte SIV tag authenticates this whole PAE block together with the
ciphertext in one operation.

## The size cap

The server rejects a response over 256 KiB before any cryptographic work
begins. A cap enforced first means an oversized message cannot be used to
force the agent to spend CPU time on a cipher it was never going to accept.

## The iris-aead adapter

`iris-aead` is the bounded, static helper that runs the cipher. It emits
plaintext only after successful authentication of the SIV tag: a message that
fails authentication never reaches the code that would parse it. Keys and
plaintext travel through pipes between the agent and the helper, never as
command-line arguments and never through a temporary file, so neither shows up
in a process listing or on disk.

The same adapter also protects the device's local last-known-good record. A
device's `IRIS-LKG/2` recovery record is encrypted with a separate local key
and a separate key-derivation and associated-data domain from the network
envelope, so a leak of one does not expose the other.

This adapter replaces the old custom cipher. It is not, by itself, an
independent audit of the rest of the instruction pipeline.

## The OpenSSL pin

Both build architectures pin OpenSSL 3.5.8 and use its maintained
[EVP AES-SIV interface](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/#siv-mode),
implementing [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297). Pinning the
version means a local build matches what shipped, and a security fix to
OpenSSL's SIV code is picked up by bumping one version rather than auditing a
hand-rolled cipher again.

## The Guest Shell helper

Guest Shell has no package manager of its own, so its copy of `iris-aead`
ships inside the agent bundle rather than being installed from a host
repository. On start, Guest Shell promotes the bundled helper to a private
executable directory and runs a known-answer and tamper probe against it
before trusting it. This means the helper does not depend on the switch's
older Python crypto packages or on whatever OpenSSL version the host already
has.

Build it with:

```bash
bash tools/build-instruction-crypto.sh
```

The server and the shared device image compile the same helper source, so the
two never disagree about the wire format.

## The SSH signature verifier build

Instruction signatures are checked with a second static binary: a statically
linked `ssh-keygen`, used only for its `-Y verify` SSHSIG subcommand. This is
a separate build from `iris-aead` above and from the dynamically linked
`ssh-keygen` that `apk add openssh-keygen` installs into the shared IOx/XR
device image; the static one feeds Guest Shell bundles only, where no system
package manager is available to install one.

`server/Dockerfile`'s `ssh-verifier-source`, `ssh-verifier-amd64` and
`ssh-verifier-arm64` stages fetch a pinned, checksum-verified upstream
OpenSSH release and hand it to `tools/build-ssh-verifier.sh`, which
configures OpenSSH with `--without-openssl --without-zlib --without-pam
--without-libedit --without-security-key-builtin`, builds only the
`ssh-keygen` target, strips it, and fails the build if `readelf` finds a
dynamic interpreter or a `NEEDED` entry — the binary must carry no runtime
library dependency at all. Before accepting the binary, the script signs and
verifies a throwaway SSHSIG message with it as a build-time sanity check.

Build both architectures with:

```bash
tools/build-ssh-verifiers.sh
```

which runs `docker buildx build --pull --target ssh-verifier-artifacts` against
`server/Dockerfile` and writes `bin/ssh-keygen-amd64`, `bin/ssh-keygen-arm64`
and a shared `bin/ssh-keygen.LICENCE` (upstream OpenSSH's license plus the
statically linked musl libc notice). `server/pack-agent-bundle.sh` picks the
architecture-matched binary by default, checks its ELF machine type against
the `aria2c` binary going into the same bundle, and copies it into the Guest
Shell agent bundle as `agent/ssh-keygen`; the same build stage also copies
the amd64 binary into the server image at `/opt/iris/bin/ssh-keygen-amd64`
for the server's own use verifying instruction signatures. Rebuild it
whenever `tools/build-ssh-verifier.sh` or the pinned OpenSSH source changes,
the same as `iris-aead`.

## Related

- [How instructions are signed and trusted](../zensical/architecture/security-model.md#how-instructions-are-signed-and-trusted):
  who signs an instruction and what the agent checks before it trusts one.
- [Replace or recover signing keys](../zensical/admin-guide/instruction-keys.md):
  the operator procedure for rotating a device's instruction key or
  replacing a root.
- [Migration notes for contributors](upgrade-notes.md): the v1-to-v2 envelope
  upgrade and how to roll it out without locking out an agent.
- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md):
  where this helper is built into the shipped packages.
