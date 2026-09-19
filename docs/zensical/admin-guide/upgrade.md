<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Upgrade to a new release

An upgrade is three steps: back up the server, undeploy the devices, and
deploy the new release the same way you installed it. Then onboard the
devices again. Your inventory, images, roles and schedules stay in place.

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
tools/start-compose-server.sh
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

## 4. Onboard the devices again

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
