<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Deploy a new release

Replace a deployment through removal and a new installation. Remove the old
device agents and onboard them to the replacement after its checks pass.

## Before you start

- Read the new release's entry in `CHANGELOG.md`.
- Let device jobs and server maintenance finish.
- Keep an independent encrypted backup and the separate recovery keys.
- Record the deployment's addresses, inventory, roles, assignments and schedules.

## 1. Back up and undeploy

1. Follow [Back up and restore](backups.md) and verify the encrypted backup.
   Keep the encrypted data and identity sets and their independent recovery keys.
   Complete first-time [backup signer trust](backups.md#trust-the-backup-signer)
   before verifying an archive.
2. Open **Devices**, select each onboarded device and choose **Undeploy**.
3. Wait for every device to confirm that its agent was removed. Keep the
   inventory export for the replacement. See
   [Undeploy, retire and clean up devices](../user-guide/undeploy.md).

Do not remove the server while a device's agent removal remains unconfirmed.

## 2. Remove the old deployment

### Managed deployment replacement { #managed-single-host-docker }

Use [Remove a managed deployment](uninstall.md) to review the exact resources,
choose whether to retain data and confirm removal. Run it from the original
controller and keep the same state directory and recorded topology.

A retained volume or backup is not automatically adopted by the next install.
Keep the old private files and encrypted sets until the replacement is verified.
Restoring a managed backup targets its original deployment; it is not a
cross-deployment migration procedure.

### Source-checkout deployments

Remove only the selected server and Console resources using the same Compose
project or Kubernetes namespace and manifests that created them. On separate
Docker hosts, remove the Console and server from their respective hosts.
Preserve unrelated applications, images, networks and storage. Keep the original
environment files and private keys with the recovery material.

## 3. Install and onboard

Download and authenticate the selected release. Follow the matching installation
guide:

- [Install with the managed package](../install/managed-package.md)
- [Install on one Docker host](../install/one-docker-host.md)
- [Install on separate Docker hosts](../install/separate-docker-hosts.md)
- [Install on Kubernetes](../install/kubernetes.md)

A managed replacement is a new installation. Choose a new state directory and
instance name, or a fresh dedicated Kubernetes namespace. Complete its normal
signing approval, certificate checks and Console account setup. Do not point it
at retained storage or edit ownership records to make it adopt the old deployment.

Import your inventory and re-create the required roles, assignments and
schedules. Check the server and device packages before selecting the
devices and choosing **Onboard**. Each device receives the replacement agent and
its deployment-specific credentials.

## Verify

- The Console Help popover names the selected release.
- **Settings → Device packages** shows `ok` for every package.
- Each onboarded device reports a heartbeat to the replacement.
- The intended image assignments and schedules are correct.

## Related

- [Back up and restore](backups.md)
- [Remove a managed deployment](uninstall.md)
- [Undeploy, retire and clean up devices](../user-guide/undeploy.md)
- [Add and onboard devices](../user-guide/onboarding.md)
