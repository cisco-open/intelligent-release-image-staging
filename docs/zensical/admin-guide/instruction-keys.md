<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Replace or recover signing keys

An instruction is the signed message the server sends a device saying which
images to stage and how. A root key, also called a signing root, is one of the
two offline keys that certify the online signer and sign revocation lists.
Use this page to replace both roots, recover a lost root, answer a leaked key, publish a new Guest
Shell agent bundle, or deliver a first instruction file by hand.

Run every server command in the shell of your deployment:
`docker compose -f server/docker-compose.yml exec iris sh`, the split-host
server equivalent, or `kubectl -n iris exec -it deployment/iris-seed-server -c
iris -- sh`.

!!! warning

    Keep private root keys on their offline stations. Never put one on the
    server, in installer arguments, or in device configuration.

## In the Console

Open **Policies → Advanced → Instruction delivery and key custody**. The panel
shows signing status, certificate and keylist age, ceremony status, and
attested roots; the terms it uses are in the next section.

## What you see

| Term | What it is |
| --- | --- |
| Keylist | the signed list of keys devices must no longer accept |
| Attestation | a signed record that a root is still in use |
| Quorum | the state of those records across both roots |
| Stamp | the freshness mark the server puts on an instruction for one device |

`enabled: false` means signing is off, and a null value means the evidence is
unavailable. Degraded quorum means the records no longer cover both roots, so
check who holds the private keys. A command that returns success is not proof
that a device accepted anything.

## What happens at startup

The encrypted online signing key, `$IRIS_CONFIG/instr/signing-key.age`, is
optional. If it is missing, the server removes any leftover runtime signing
key and certificate copies and starts anyway: signing shows disabled, and
existing services keep running without producing new signed instructions. If
the file is present but is not a regular file, is a symlink, or cannot be
decrypted, the server refuses to start rather than treat it as missing. If a
server that used to sign instructions will not come up after you touched a
file under `$IRIS_CONFIG/instr/`, check that file first.

## Replace the two root keys { #instruction-root-ceremony-and-recovery }

Exactly two distinct public roots belong in `$IRIS_CONFIG/instr/roots.d/`, with
private keys held by separate custodians at separate sites. The encrypted
online key is `$IRIS_CONFIG/instr/signing-key.age`; the runtime plaintext is
`$IRIS_RUN/instr/signing-key`. For the file inventory, see [Data formats and
states](../reference/state-and-data.md).

### Quarterly two-root ceremony

1. Have both custodians confirm they hold their private key at separate sites.
   Compare public fingerprints with the approved inventory by running
   `ssh-keygen -lf root-a.pub` and `ssh-keygen -lf root-b.pub` on public
   copies.
2. In the server shell, export the online public half:

   ```bash
   install -d -m 0700 "$IRIS_RUN/ceremony"
   iris-instructions --export-public "$IRIS_RUN/ceremony/signing-key.pub"
   iris-instructions --status
   ```

   On first setup, run `iris-instructions --generate-online-key` first.
3. At one offline station, issue a 30-day certificate for the `iris-server`
   principal, the name for who a request is from:

   ```bash
   ssh-keygen -s /offline/root-a -I iris-online -n iris-server \
     -V +0s:+30d signing-key.pub
   ```
4. Return only `signing-key-cert.pub`, then import it:

   ```bash
   iris-instructions --import-certificate "$IRIS_RUN/ceremony/signing-key-cert.pub"
   ```

   Renew after 15 days. Signing refuses with seven days or less left.
5. Build the keylist request from the approved revocation list.
   `IRIS_CEREMONY_SEQ` is the next reviewed sequence, `IRIS_CEREMONY_ROOT_ID`
   the public-root ID, for example `root-a`:

   ```bash
   iris-instructions --keylist-request "$IRIS_RUN/ceremony/revocations.krl" \
     --keylist-seq "$IRIS_CEREMONY_SEQ" --root-id "$IRIS_CEREMONY_ROOT_ID" \
     --output "$IRIS_RUN/ceremony/keylist.payload"
   ```
6. Move that payload offline and sign its exact bytes:

   ```bash
   ssh-keygen -Y sign -f /offline/root-a -n iris-keylist-v1 keylist.payload
   ```
7. Return only `keylist.payload.sig`, then assemble and install it:

   ```bash
   iris-instructions --assemble-keylist "$IRIS_RUN/ceremony/keylist.payload.sig" \
     --payload "$IRIS_RUN/ceremony/keylist.payload" \
     --output "$IRIS_RUN/ceremony/keylist.envelope"
   iris-instructions --install-keylist "$IRIS_RUN/ceremony/keylist.envelope"
   iris-instructions --status
   ```

   The status shows the new keylist sequence.
8. Repeat steps 5 to 7 with the other custodian, the other root and the next
   sequence, so both roots are attested on their own.
9. Compare the Console panel and the `iris_instruction_*` metrics with the
   windows you recorded, then record identities, fingerprints, times and
   outcomes.

Keylist re-signing is due at 90 days, warns at 100 and is critical at 135.
Both roots need attestations within 180 days for a healthy quorum. The online
certificate follows the shorter renewal window in steps 3 and 4.

!!! warning

    Never change bytes at the same keylist sequence, and keep every intended
    revocation when you sign the list again. An identical retry of the same
    artifact is safe and repairs an interrupted publication.

## If one root key is lost

1. Keep both public root files and the existing device trust bytes.
2. Identify the surviving offline custodian.
3. Repeat the export, issue and import steps above with the surviving root for
   the next online certificate and keylist. No device trust change is required.
4. Record the quorum as degraded until a replacement root and a new signed
   device release are in place. The 180-day attestation metric only reports
   signed records, not physical custody, so confirm the loss with your
   custodians directly rather than relying on that metric alone.

## If both root keys are lost

1. Declare the outage. Keep the public keys, the state evidence, and the
   server's tracker and origin controls. Devices fall back to the last policy
   they accepted, then to the documented stale behavior.
2. At two separate offline sites, create two new independent roots with
   passphrase protection: `ssh-keygen -t ed25519 -f /offline/root-a`, and the
   matching root-b command at its site. Record their public fingerprints.
3. Reconcile root configuration, keylist and revocation state, and the sequence
   under a reviewed maintenance procedure, then provision the new
   online certificate/keylist. Single commands do not recover a fleet in place.
4. Build fresh Guest Shell bundles, the unified container image, both IOx tars
   and the XR RPM with the new public roots and the current pinned aria2c
   binaries, for both architectures. See [Build and publish the device
   packages](../install/device-packages.md) and the [build entry
   points](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/device-packages.md).
5. Re-onboard every device with the new trust material, then check the
   accepted identity and the key state on each one. A disconnected device takes
   [the first instruction file by
   hand](#f3-offline-bootstrap-envelope-redelivery) once its new agent arrives.
   `iris-instr-key recover` advances the epoch; `iris-instr-key initialize`
   starts a fresh activation.

!!! warning

    Do not delete local replay floors to force acceptance, and never substitute
    a throwaway proof root.

## If a signing key leaks or devices reject instructions

For a leaked instruction key on an otherwise honest device:

```bash
iris-instr-key rotate --no-overlap <device_id>
```

A committed rotation can report incomplete restamping. Fix the producer state,
then run `iris-instr-key restamp <device_id>` rather than rotating again. For
retirement or compromise, use `iris-revoke <device_id>`. A revocation the
server holds outweighs the policy a device reports, and rotation refuses a
revoked device.

A failed instruction fetch or verification affects the instruction step only:
the heartbeat and staging continue on the last accepted policy or the defaults.
If the aria2 remote-control call that applies policy fails, the device still
sends its heartbeat but skips staging for that tick, one pass of the agent's
check-in loop. Every failure state is listed in [Data formats and
states](../reference/state-and-data.md).

## Publish a new Guest Shell agent bundle

On Catalyst 9000 series switches the agent runs in Guest Shell; switches with
app-hosting storage can run the IOx app instead. Treat a bundle update as a
fleet operation.

1. For standalone bundles, run `tools/build-ssh-verifiers.sh` on a Docker
   builder that supports both amd64 and arm64.
2. Upgrade each device's `bootstrap.sh` through onboarding. Older bootstraps
   reject the new archive members.
3. Build each architecture with the approved binary and exactly two approved
   public roots, using the [build
   options](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/device-packages.md).
   Record the archive and sidecar hashes and the source provenance.
4. Publish the bundle and its 64-hex SHA-256 sidecar on the artifact server,
   with installer and bootstrap evidence for both public-root files. Deliver
   sidecar before archive: missing, malformed or mismatched evidence, unsafe
   members or incomplete writes refuse the new bundle and keep the prior
   runnable bundle.
5. Check the next tick's `instr_protocol` value, the accepted identity and the
   instruction state, including the fallback to tracker-only when the bundled
   verifier is unavailable.

Roll back by restoring the reviewed prior bundle and its evidence as one set.
On IOx, signature verification is a device-wide setting, not a per-app one. See
[Prepare Industrial Ethernet switches with app hosting, Catalyst 9000 and 8000
devices for the IOx app](../install/iox.md#device-global-package-verification).

## Deliver the first instruction file by hand { #f3-offline-bootstrap-envelope-redelivery }

An envelope is the encrypted file that carries an instruction. A device that
cannot reach the server needs its first envelope by hand. What you carry is a
ciphertext bootstrap envelope for one device; it is not a secret key, an OS
image, or a bypass of signature, audience and replay checks.

1. In the server shell, write the envelope to a private destination:

   ```bash
   install -d -m 0700 "$IRIS_RUN/ceremony"
   iris-instruction-bootstrap <device_id> --output "$IRIS_RUN/ceremony/bootstrap.envelope"
   ```

   The output is mode 0600, and the command prints no envelope or key bytes.
2. Transfer it with the authorized platform installer or controller, keeping
   the exact bytes and the device identity:

   | Platform | How it arrives |
   | --- | --- |
   | Guest Shell | `tools/gen-device-installers.sh` stages a short-lived envelope bound to one capability, and the installer places `iris-instructions.bootstrap` |
   | IOx | the application-data delivery of the app |
   | IOS-XR appmgr | `IRIS_INSTRUCTION_BOOTSTRAP_FILE` copies the ciphertext to `harddisk:iris-instructions.bootstrap` |

3. Give the device correct time, usable verification trust and a fresh
   authenticated refresh, then watch the accepted identity and the application
   state after its next policy poll.

Authenticated refresh can self-heal current and prior key availability. The
agent takes a verified envelope at a due policy poll, and applying it also
needs a successful aria2 policy apply. Follow the failure table when the device
stays pending or unavailable.

## Related

- [Turn on instruction signing](../install/activate-signing.md)
- [Create the two offline signing keys](../install/signing-roots.md)
- [How instructions are signed and trusted](../architecture/security-model.md)
- [Find your way around the Console](../user-guide/console.md)
- [Rotate credentials and certificates](rotations.md)
