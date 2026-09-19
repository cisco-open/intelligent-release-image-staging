<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Upgrade to a new release

A release changes the server, the Console and the device agent together.
Upgrade in that order, then the devices whose agent changed.

## Before you start

- Read `CHANGELOG.md`, then check out that version on every host.
- Note the Compose project name, container names, state volumes, age identity
  file and artifact directory in use now. Keep all of them.
- Let running device jobs finish, then back up the server. See
  [Back up and restore](backups.md).

!!! warning

    Do not run the bootstrap command, take the stack `down`, or remove a
    volume. Each one destroys state the new release expects to find.

## Upgrade the server and the Console

Build both images first: see [Build the server and Console images](../install/build-images.md).

### On one Docker host

Keep the Compose project and environment files you already use, select both
image tags, and recreate the two services:

```bash
export IRIS_SERVER_IMAGE=iris:approved-server-tag
export IRIS_CONSOLE_IMAGE=iris-console:approved-console-tag
docker compose -p server --env-file server/.env \
  -f server/docker-compose.yml -f server/docker-compose.images.yml config --quiet
docker compose -p server --env-file server/.env \
  -f server/docker-compose.yml -f server/docker-compose.images.yml \
  up -d --no-build --force-recreate iris console
```

Both containers restart. Check both image ids and health states.

### On separate Docker hosts

Upgrade the server host first:

```bash
iris_server() {
  docker compose --env-file server/server.env \
    -f server/docker-compose.server.yml "$@"
}

iris_server build --pull
iris_server up -d
iris_server ps
```

Then the Console host:

```bash
iris_console() {
  docker compose --env-file server/console.env \
    -f server/docker-compose.console.yml "$@"
}

iris_console build --pull
iris_console up -d
iris_console ps
```

Each `ps` shows that host's container healthy on the new image.

### On Kubernetes

Push both images to a registry every node can pull from, replace both names
and both `digest: sha256:...` values in `kustomization.yaml`, then apply:

```bash
kubectl apply -k kubernetes
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console
```

Both rollouts report complete. Make one authenticated Console API request
before device jobs.

## Update the device agents

The agent ships in four files: the Guest Shell bundle, the two IOx packages and
`iris-xr.rpm`. Rebuild all four, and on Kubernetes copy each one to the server
pod again: see [Build and publish the device packages](../install/device-packages.md).
Then run `tools/check-package-freshness.sh`, or open **Settings → Device
packages** in the Console:

| State | What it means |
| --- | --- |
| `ok` | The served wrapper bytes match the provenance manifest beside them. |
| `stale` | The served wrapper digest no longer agrees with its manifest. Publish the package and its `.manifest` together again. |
| `absent` or `unknown` | The file, its manifest or the evidence is missing or unreadable. Treat it as not ready. |

Then redeploy each affected device. The same status also compares the
certificate the live services present with the public copy onboarding hands
out. After a certificate rotation, redeploy devices with the package you
already have. See [Rotate credentials and certificates](rotations.md).

### Guest Shell

On Catalyst 9000 series switches the agent runs in Guest Shell; on switches
with app-hosting storage the IOx app is the alternative. Run the installer
script again, and the device adopts the new bundle on its next check-in.

### IOx

On Industrial Ethernet 3000 series switches, Catalyst 9000 series switches with
app-hosting storage (the alternative to Guest Shell), and Catalyst 8000 series
routers, upgrade is undeploy, then onboard. Use the Console, or these
[Console API](../reference/console-api.md) routes:

1. `POST /api/v1/devices/<id>/undeploy`, and wait for its job to succeed.
2. `POST /api/v1/devices/<id>/onboard`, then read
   `GET /api/v1/onboard/jobs/<job_id>`.

Re-provision a device when replacing its bootstrap configuration or enrollment material: the cutover replaces only the staging agent's credentials and never touches the device's software.

### IOS-XR

On Cisco 8000 series and NCS routers, `xr-install.sh` installs the rebuilt
`iris-xr.rpm` and starts the application; `xr-uninstall.sh` removes it. Run
them from the Console, or with the same two routes.

## Upgrade the instruction format

An instruction is the signed message the server sends a device saying which
images to stage and how. A release that changes its format upgrades the server
and every agent together.

!!! warning

    Old agents cannot read new instructions and new agents reject old ones. Do
    not downgrade an agent that has already moved.

## What you see after an upgrade

The Console Help popover names the running release, and the **Setup checklist**
shows what is left. Your devices, images, roles and schedules survive.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The Help popover shows an older version than the `VERSION` file | `IRIS_VERSION` is a build argument that overrides the image's `VERSION` file | Remove it from `server/.env` and the build shell, then rebuild both images. Compare `docker exec iris sh -c 'echo $IRIS_VERSION'` with `docker exec iris cat /opt/iris/VERSION`. |
| A device still reports the old agent | A package rebuild does not change a running agent | Redeploy that device: undeploy it, then onboard it with the rebuilt package. |

## Related

- [Build and publish the device packages](../install/device-packages.md)
- [Back up and restore](backups.md)
- [Rotate credentials and certificates](rotations.md)
- [Add and onboard devices](../user-guide/onboarding.md)
