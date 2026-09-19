<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Keep IRIS running

This guide is for the person who looks after the IRIS server: upgrades,
backups, credentials, certificates, signing keys, and recovery when something
breaks. Day-to-day staging work is in the [User Guide](../user-guide/index.md).

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot
    variables. See the [Overview](../index.md).

## Common tasks

| Task | Page |
| --- | --- |
| Move to a new IRIS release | [Upgrade to a new release](upgrade.md) |
| Back up the server, or restore it | [Back up and restore](backups.md) |
| Export the audit trail, set the API request budget, reset the admin account | [Routine maintenance tasks](maintenance.md) |
| Rotate a credential or a certificate | [Rotate credentials and certificates](rotations.md) |
| Replace or recover the signing keys | [Replace or recover signing keys](instruction-keys.md) |
| Recover after an interrupted job or damaged state | [Recover from an interrupted job or damaged state](recovery.md) |

## Pages in this guide

- [Upgrade to a new release](upgrade.md): the order to upgrade the server, the Console and the device packages, per layout.
- [Back up and restore](backups.md): what to back up per layout, and how to restore it.
- [Routine maintenance tasks](maintenance.md): audit export, the API request budget, and the admin account reset.
- [Rotate credentials and certificates](rotations.md): one procedure per credential, per layout.
- [Replace or recover signing keys](instruction-keys.md): the two root keys, a lost key, a leaked key, and hand delivery of the first instruction file.
- [Recover from an interrupted job or damaged state](recovery.md): interrupted device jobs, damaged volumes, and state rollback.
