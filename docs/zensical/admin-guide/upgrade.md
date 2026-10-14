<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Upgrade to a new release

!!! warning "Check how this deployment was installed"
    Use the managed procedure below for source-built Docker on one or separate
    hosts, created by `irisctl`. The source-checkout procedure later on
    this page is separate. Managed upgrades of prebuilt release kits and
    Kubernetes are not supported by this command yet.

## Managed Docker deployments { #managed-single-host-docker }

Installing a newer `.deb` updates the installer tools. The separate upgrade
command rebuilds and replaces the server, Console and device packages while
keeping your accounts, keys, inventory, images and deployment storage.

1. [Download and authenticate](../install/managed-package.md#download-and-authenticate)
   the new installer and its source inventory. Install that exact `.deb` with
   `sudo apt install ./<installer-package>.deb`.
2. Finish running jobs. Undeploy every IRIS agent and wait for confirmed
   removal. Keep the device inventory; you will onboard it again afterwards.
3. Check that the managed worker is running and that recovery access and the
   independent backup signer are configured. For first-time setup, follow
   [Trust the backup signer](backups.md#trust-the-backup-signer).

Prepare the candidate using the authenticated release's full commit and the
SHA256 of its `.deb.source.json` file:

```bash
sudo irisctl upgrade prepare \
  --state-dir /var/lib/iris-installer/my-instance \
  --source-proof /path/to/installer.deb.source.json \
  --source-proof-sha256 <reviewed-source-inventory-sha256> \
  --source-commit <full-release-commit> --accept-changes
```

Preparation builds the candidate in a separate directory. Your running server
and Console stay on their existing version. The command prints an operation ID,
a plan file and the plan's SHA256. Review that plan, then use those exact values:

```bash
sudo irisctl upgrade apply \
  --state-dir /var/lib/iris-installer/my-instance \
  --operation-id <operation-id> --plan-sha256 <plan-sha256> \
  --allow-downtime
```

IRIS takes and verifies separate encrypted data and identity backups, stops the
old services, updates the application and checks the new server, Console and
maintenance worker. The backups use your recorded backup locations. Previous
source, device packages and container images are retained for inspection.
Rebuilding an IOx package does not certify its native platform signature.

For separate Docker hosts, run every upgrade command on the server host with
the existing state directory. Keep its recorded SSH key, host-key file and
remote Console directory. Preparation transfers the candidate Console image
through that pinned SSH connection before downtime. The approved plan records
both hosts' existing service identities and separate Compose definitions.
Apply verifies the new server first, then the remote Console's authenticated
management connection. The Console's credentials and browser certificate stay
in their existing remote directory; server keys and data stay on the server.
If the server recreates its internal certificate, IRIS updates only the Console's
public management trust file after verifying the same public key and issuer.
That update is recorded before writing and reconciled during same-operation
recovery. The bearer credentials and browser private key are unchanged.

If preparation reports a build failure before printing a plan SHA256, the
running deployment is unchanged. Fix that problem and run `upgrade prepare` again.
It creates a new operation and retains the failed attempt's files for inspection.
For retained build output, see [Installer command failures](../user-guide/troubleshooting.md#installer-command-failures).
An unfinished preparation cannot use `upgrade recover`.

If `upgrade apply` stops, inspect the recorded status:

```bash
sudo irisctl upgrade status --state-dir /var/lib/iris-installer/my-instance
```

Use `irisctl upgrade recover` with the same state directory, operation ID,
plan SHA256 and `--allow-downtime` to finish that approved upgrade. Recovery
continues forward; it does not restart old code over data the new code may have
changed. Do not delete the operation files, edit installer checkpoints or run
Compose commands to bypass a refusal.

After a successful upgrade, onboard the devices again to receive the new agent.
Managed upgrade refuses a release that changes the Docker storage
or service layout; such a change needs a separately supported migration.

## Source-checkout deployments

An upgrade is three steps: back up the server, undeploy the devices, and
deploy the new release with fresh device agents. Your inventory, images, roles
and schedules stay in place.

## Before you start

- Read the entry for the new version in `CHANGELOG.md`.
- Let running device jobs finish. Open **Devices** and check that no onboard,
  undeploy or staging job is in progress.

## 1. Back up the server

Follow [Back up and restore](backups.md). Keep the Compose project, the
volumes, the age identity file, the environment files and the artifact
directory you use today. The upgrade reuses all of them.

## 2. Undeploy the devices

1. Open **Devices**, select every onboarded device and choose **Undeploy**.
2. Wait until each record shows the agent removed. See
   [Undeploy, retire and clean up devices](../user-guide/undeploy.md).

## 3. Deploy the new release

On the host that runs the server, check out the release:

```bash
git fetch --tags
git checkout v<version>
```

Then deploy it the same way you installed it.

### On one Docker host

Load `server/.env` as on the install page, then run the start script again:

```bash
IRIS_INSTRUCTION_ROOTS_DIR=/path/to/reviewed/roots tools/start-compose-server.sh
```

It rebuilds both images, keeps every volume and secret, restarts the two
containers and rebuilds the device packages. See
[Install on one Docker host](../install/one-docker-host.md).

### On separate Docker hosts

Check out the release on both hosts. Rebuild and restart the server host
first, then the Console host, with the commands in
[Install on separate Docker hosts](../install/separate-docker-hosts.md). Then
rebuild and publish the device packages as in
[Build and publish the device packages](../install/device-packages.md).

### On Kubernetes

Build and push both images, replace both digests in `kustomization.yaml`,
apply, and wait for both rollouts, as in
[Install on Kubernetes](../install/kubernetes.md). Then copy the rebuilt
device packages to the server pod as in
[Build and publish the device packages](../install/device-packages.md).

### Onboard the devices again

Open **Devices**, select the devices and choose **Onboard**. Each device gets
the new agent package. Re-provision a device when replacing its bootstrap
configuration or enrollment material: the cutover replaces only the staging
agent's credentials and never touches the device's software.

## Verify

- The Console Help popover names the new release.
- **Settings → Device packages** shows `ok` for every package.
- Each onboarded device reports a heartbeat on the new agent.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The Help popover shows an older version than the `VERSION` file | `IRIS_VERSION` is a build argument that overrides the image's `VERSION` file | Remove it from `server/.env` and the build shell, then rebuild both images. |
| A device still reports the old agent | It was not undeployed before the upgrade | Undeploy it, then onboard it again. |

## Related

- [Back up and restore](backups.md)
- [Undeploy, retire and clean up devices](../user-guide/undeploy.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [Build and publish the device packages](../install/device-packages.md)
