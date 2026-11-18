<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Automatic signing certificate renewal

IRIS can renew the instruction signing certificate using an existing locally
managed signing root. It keeps the online key, device trust, and instruction
counters. Devices do not need re-onboarding for this renewal.

New `irisctl setup` installations using automatic local keys enable renewal as
part of setup. Offline roots and manually protected roots retain the
[public approval workflow](instruction-keys.md#renew-the-instruction-signing-certificate).

## When renewal runs

The host service checks daily at 03:00 UTC and after startup, with up to fifteen
minutes of scheduling jitter. It renews halfway through the 30-day certificate
lifetime, about eight days before the seven-day signing cutoff. A failed check
retries after an hour. Missed daily checks run when the host returns.

An interrupted import is reconciled against the installed certificate. A changed
online key or signing root requires explicit enrollment again. The service
never creates a replacement root or changes the signing cutoff. Once identity
review is required, restoring the old identity does not resume automatic
signing: an operator must explicitly enable renewal again.

## Check its status

Open **Settings > Certificates & keys**. Automatic renewal shows its last check,
next renewal date, last successful renewal, and any problem requiring attention.
The Overview also warns when signing, the producer, or automatic renewal needs
attention. A check older than 26 hours is reported as overdue.

Signing readiness is separate from container and listener health. Deployment
completion checks both signing and the instruction producer before reporting
that their checks passed. Other custody work, such as root attestations and
revocation-list maintenance, remains visible separately. Inventory-only devices
without enrollment keys do not make the producer unavailable. Its status records
scan progress and completion separately from per-device stamping failures.

## Enable it for an existing installation

Use the existing managed root key and the recorded installation state directory.
For example, replace these paths with your installation's values:

```bash
sudo irisctl signing-renewal enable \
  --state-dir /var/lib/iris-installer/my-iris \
  --root-key /home/operator/.local/share/iris-setup-keys/my-iris/root-a/root-a
```

The command checks that the root matches the deployed public roots, binds the
current online public key, and installs the daily host timer. It checks renewal
immediately. It accepts only keys already created with automatic local custody;
manual passphrases are never guessed or converted.

Private roots and their saved passphrases stay in the existing owner's protected
folder. The signing helper runs as that owner. Only public requests and approved
certificates cross into the server container. Keep a secure independent copy of
the complete key folder; ordinary deployment backups exclude it.

```bash
sudo irisctl signing-renewal status --state-dir /var/lib/iris-installer/my-iris
sudo irisctl signing-renewal run --state-dir /var/lib/iris-installer/my-iris
sudo irisctl signing-renewal disable --state-dir /var/lib/iris-installer/my-iris
```

`run` checks the due date immediately. `disable` stops future scheduled renewal
without changing the current certificate, including while the server runtime is
unavailable. Split-host renewal does not depend on Console availability. Managed
uninstall reviews and removes both renewal units, retaining the enrollment
history, public runtime and holder keys. A missing key, changed identity, or
unavailable runtime leaves the current deployment intact and reports a problem.
