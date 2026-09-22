<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Turn on instruction signing

An instruction is the signed message the server sends a device saying which
images to stage and how. This page gives the server the key that signs them. Do
it before you onboard a device: until it is done, onboarding fails with
`ERROR: instruction bootstrap unavailable`.

## Before you start

- The server runs in the layout you chose: [Install on one Docker
  host](one-docker-host.md), [Install on separate Docker
  hosts](separate-docker-hosts.md) or [Install on Kubernetes](kubernetes.md).
- The two offline root keys exist, each with a passphrase. A root key is one of
  the two offline keys that sign every instruction key. See
  [Create the two offline signing keys](signing-roots.md).
- The person who holds root key A can run one command. That private key and its
  passphrase stay with that person.
- The server has no signing key yet: check with `docker exec iris
  iris-instructions --status`. Reuse a working key and stop here; a key from
  another deployment needs an approved server-state migration.

## Start signing instructions { #initialise-instruction-custody }

The steps are the same in every layout. Only the way you reach the container
changes.

!!! warning
    Copy the public half of the signing key out of the config volume, never from
    the runtime directory `$IRIS_RUN`: `docker cp` cannot read it, so the export
    reports success and the file never reaches the host.

### On one Docker host

**1. Generate the online key and copy its public half to the host. It lands in
`~/iris-online.pub` as one `ssh-ed25519 …` line.**

```bash
docker exec iris iris-instructions --generate-online-key
docker cp iris:/etc/iris/instr/signing-key.pub ~/iris-online.pub
```

**2. Hand this command to the person who holds root key A. It prompts for the
passphrase and writes `~/iris-online-cert.pub`. Wait for that file.**

```bash
ssh-keygen -q -s ~/iris-custody/root-a -I iris-online -n iris-server \
  -V +0s:+30d ~/iris-online.pub
```

**3. Import the certificate, turn on the producer (the part of the server that
stamps each instruction), and read the status back as JSON.**

```bash
docker cp ~/iris-online-cert.pub iris:/etc/iris/instr/signing-key-cert.pub
docker exec iris iris-instructions --import-certificate \
  /etc/iris/instr/signing-key-cert.pub
docker exec iris iris-instr-key initialize
docker exec iris iris-instructions --status
```

### On separate Docker hosts

Run the same commands on the server host. If the container is not named `iris`,
find its name with `docker ps --format '{{.Names}}'` and use that.

### On Kubernetes

Run the same sequence through `kubectl`, with `/data/config` in place of
`/etc/iris` and the server pod's name for `<server-pod>`. The `ssh-keygen` line
is still the root key holder's to run:

```bash
kubectl -n iris exec deployment/iris-seed-server -c iris -- \
  iris-instructions --generate-online-key
kubectl -n iris cp iris/<server-pod>:/data/config/instr/signing-key.pub \
  ~/iris-online.pub -c iris
ssh-keygen -q -s ~/iris-custody/root-a -I iris-online -n iris-server \
  -V +0s:+30d ~/iris-online.pub
kubectl -n iris cp ~/iris-online-cert.pub \
  iris/<server-pod>:/data/config/instr/signing-key-cert.pub -c iris
kubectl -n iris exec deployment/iris-seed-server -c iris -- \
  iris-instructions --import-certificate /data/config/instr/signing-key-cert.pub
kubectl -n iris exec deployment/iris-seed-server -c iris -- \
  iris-instr-key initialize
kubectl -n iris exec deployment/iris-seed-server -c iris -- \
  iris-instructions --status
```

## Verify

Signing is ready when the status reports `enabled: true` with
`signing_refused: false` and the producer on. Then onboard one device.

### Reading the status

A new deployment prints something close to this:

```json
{"enabled":true,"signing_refused":false,"state":"keylist_missing",
 "certificate_days_to_expiry":29,"roots_configured":2,
 "root_ceremony_overdue":"critical","root_quorum_degraded":true,
 "roots_attested_180d":0}
```

- `state: keylist_missing`: the keylist is the signed list of withdrawn keys the
  server sends to devices. Onboarding works without it; install one for
  production, see
  [Replace or recover signing keys](../admin-guide/instruction-keys.md#instruction-root-ceremony-and-recovery).
- `root_ceremony_overdue`, `root_quorum_degraded` and `roots_attested_180d`:
  nobody has attested these root keys yet. Expected on a new deployment.
- `certificate_days_to_expiry`: the server stops signing with seven days or
  fewer left, so a 30-day certificate lasts about three weeks.

Do not read the two booleans alone as readiness: `state: invalid` or
`state: error` still needs investigation.

## Next steps

- [Set up certificates and tokens](certificates-and-tokens.md)
- [Build and publish the device packages](device-packages.md)
- [Verify the installation](verify.md)
- [Add and onboard devices](../user-guide/onboarding.md)
