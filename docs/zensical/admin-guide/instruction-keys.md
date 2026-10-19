<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Replace or recover signing keys

Use this page for root replacement, key recovery, Guest Shell agent replacement
and manual delivery of a first instruction file. See the glossary for
[signing roots](../reference/glossary.md#root-key-signing-root) and [instructions](../reference/glossary.md#instruction).

Run server commands in your deployment shell:
`docker compose -f server/docker-compose.yml exec iris sh`, the split-host
server equivalent, or `kubectl -n iris exec -it deployment/iris-seed-server -c
iris -- sh`.

!!! warning

    Keep private root keys in your chosen protected storage. Use separate
    holders or guided local setup. Use `iris-key-setup --local` for host-held keys.
    Never upload a root private key to the Console or put it in device configuration.

## In the Console

Open **Policies → Advanced → Instruction delivery and signing keys**. The panel
shows signing status, certificate time remaining and revocation list age. **Action needed** lists required work.
Root confirmations show how many roots were confirmed within the last 180 days.

## Renew the instruction signing certificate

Renew the existing key's 30-day certificate here. To change the key itself, use [Replace signing key](signer-rotation.md).

1. Open **Settings → Certificates & keys**, then **Renew signing certificate**.
   The overview shows renewal and expiry dates. **Technical details: all public keys,
   dates and fingerprints** shows the **New instruction signing stops** deadline,
   seven days before expiry.
2. Select **Download public renewal request**. Send `iris-online.pub` to the
   root signing key holder, who selects **Approve server request** in
   [iris-key-setup](../reference/manual-installation/offline-approval.md#approve-a-public-request).
   To provide filenames directly, use this command; add `--local` before `approve` for host-held keys:

   ```bash
   iris-key-setup approve --request iris-online.pub \
     --root-key /offline/root-a --output online-cert.pub
   ```

3. Return only `online-cert.pub`. Select it in the Console and choose
   **Validate and apply renewal**.
4. Check the new expiry and signing cutoff. A changed online key or certificate
   invalidates a pending request; prepare it again before importing.

Keys created by automatic local setup use their saved passphrases for approval.
Review each request. Renewal is not automatic; manual keys still ask for passphrases.

If the response is unavailable, the server may already have applied the renewal.
Download a fresh public renewal request before submitting again. Leaving the
page clears the selected approval file; it does not cancel a submitted renewal.

Renewal keeps the online key, device trust and instruction counters. It checks
the configured root, identity, key match and validity before publication.
Public keys have no expiry date; certificates and signed confirmations have separate deadlines.

The inventory reads server files, not live service certificates. Signing checks are separate.

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
private keys kept in your chosen protected storage. The encrypted
online key is `$IRIS_CONFIG/instr/signing-key.age`; the runtime plaintext is
`$IRIS_RUN/instr/signing-key`. For the file inventory, see [Data formats and
states](../reference/state-and-data.md).

### Quarterly two-root ceremony

Use the [Console root attestation procedure](deployment-rotation.md#attest-existing-signing-roots)
for initial and quarterly confirmations by both holders. Renew the online
certificate separately when due. The CLI example below uses separately held offline keys.

1. Have both root key holders confirm access to their private keys.
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
8. Repeat steps 5 to 7 with the other key holder, the other root and the next
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
2. Identify the surviving root key holder.
3. Repeat the export, issue and import steps above with the surviving root for
   the next online certificate and keylist. No device trust change is required.
4. Record the quorum as degraded until a replacement root and a new signed
   device release are in place. The 180-day attestation metric only reports
   signed records, not whether someone still has the private key. Confirm the
   loss with the key holders.

## If both root keys are lost

1. Declare the outage. Keep the public keys, the state evidence, and the
   server's tracker and origin controls. Devices fall back to the last policy
   they accepted, then to the documented stale behavior.
2. Use `iris-key-setup` to create two new independent roots with passphrase
   protection in your chosen protected storage. Use separate holders or guided
   local setup. Record their public fingerprints.
3. Reconcile root configuration, keylist and revocation state, and the sequence
   under a reviewed maintenance procedure, then provision the new
   online certificate/keylist. Single commands do not recover a fleet in place.
4. Build fresh Guest Shell bundles, the unified container image, both IOx tars
   and the XR RPM with the new public roots and the current pinned aria2c
   binaries, for both architectures. See [Build and publish the device
   packages](../reference/manual-installation/device-packages.md) and the [build entry
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

## Replace a Guest Shell agent { #publish-a-new-guest-shell-agent-bundle }

Replace the agent through removal and re-onboarding. For a new IRIS release,
follow [Deploy a new release](upgrade.md), including deployment replacement.
For an agent replacement within the same deployment:

1. Open **Inventory**, select the devices and choose **Undeploy**. Wait for
   confirmed removal before continuing. See
   [Undeploy, retire and clean up devices](../user-guide/undeploy.md).
2. Check that **Settings → Device packages** reports `ok` for **Guest Shell**.
   The server prepares its Guest Shell bundles automatically.
3. Choose **Onboard**. The installer delivers the bootstrap and the matching
   agent bundle, including both approved public roots.
4. Check each device's fresh heartbeat and accepted signed instruction.

The package tools publish the bundle and its SHA-256 file. Missing or
mismatched evidence stops bundle installation.

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

- [Turn on instruction signing](../reference/manual-installation/activate-signing.md)
- [Create the two root signing keys](../reference/manual-installation/signing-roots.md)
- [How instructions are signed and trusted](../architecture/security-model.md)
- [Find your way around the Console](../user-guide/console.md)
- [Rotate credentials and certificates](rotations.md)
