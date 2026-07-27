<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Getting Started

This path brings up the IRIS server, publishes an IOS-XE image, generates device installers, and assigns an image to a device. It assumes Docker Compose is the server runtime.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Linux host with Docker and Docker Compose | Runs the IRIS server container. |
| Reachable server IP | Devices must reach the host on the published IRIS ports. |
| `age` identity | Encrypts server secrets at rest. Keep the private identity outside the repository. |
| IOS-XE image files | Store outside Git, normally under `/opt/images`. |
| Device credentials | Used only for installation or GUI-driven onboarding. Do not commit real credentials. |

## Configure the server

Create the secret identity and export the values Docker Compose expects:

```bash
mkdir -p ~/.config/iris
age-keygen -o ~/.config/iris/age.txt
age-keygen -y ~/.config/iris/age.txt

export IRIS_HOST_IP=<server-ip>
export IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age.txt
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>,<break-glass-age-public-key>
```

Build the image, initialize a fresh encrypted config volume, start the stack,
and prepare both IOx packages from the repository root:

```bash
tools/start-compose-server.sh
```

`iris-bootstrap` is idempotent and does not overwrite existing encrypted state.
The running container exposes the tracker, catalog, artifact server, seeder data
port, console, and telemetry endpoints. Plaintext secrets are decrypted into
`/run/iris` tmpfs at runtime and encrypted under the `iris-config` volume at
rest.

`start-compose-server.sh` runs `tools/provision-iox-packages.sh` after the
container becomes healthy. It produces `iris-arm64.tar` for IE-3x00/IR and
`iris-amd64.tar` for C9300 IOx, both pinned to the current server certificate.

## Create the console admin

Use the first-run browser flow at `https://<server-ip>:8080/`, or set the admin account from the container:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

For scripted setup, provide the password with `IRIS_GUI_ADMIN_PASSWORD`.

## Publish an image

The Compose file mounts `IRIS_IMAGE_ROOT` from the host at `/opt/images`
(`IRIS_IMAGE_ROOT` defaults to `/opt/images`). Publish from inside the container
so the seeder RPC remains local-only:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

`iris-publish` computes `sha256` and `sha512`, creates a private torrent, hands it to the seeder, and records catalog metadata. The server does not decide whether the Cisco image signature is trusted; the device-side copy and verify path is the final gate.

## Prepare devices

Create an inventory from the template:

```bash
cp fleet/devices.csv.example fleet/devices.csv
```

The inventory contains network onboarding information only, as an
attachment-aware CSV v2. Each device declares a `management_type` of `routed`
(IRIS creates a dedicated VLAN/SVI) or `inband` (attach to an existing,
operator-owned VLAN that IRIS never changes):

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,platform
```

Fill the routed columns (`iris_vlan`, `svi_*`) for routed devices, or the inband
columns (`inband_vlan`, `app_*`) for inband devices. `model`/`platform` are
optional; blank `platform` auto-selects from the model. See
[Management Type and VLAN Ownership](network-attachment.md).

Attachment-aware onboarding runs through the **Console** (or API), which records
a durable receipt and drives teardown from it. The legacy CLI generator below is
routed-only and refuses a v2 (`management_type`) header:

```bash
# legacy routed inventory only
tools/gen-device-installers.sh fleet/devices.csv
```


## Assign images

Create assignments from the template:

```bash
cp fleet/assignments.csv.example fleet/assignments.csv
```

Each row maps a device to the approved image id:

```text
device_id,image_id
```

Apply the assignments from the server host:

```bash
tools/apply-assignments.sh fleet/assignments.csv
```

Agents poll the catalog on a short interval, download the approved image, verify it, and stage it on the target storage. A changed assignment causes the agent to clean up the previous staged image before staging the replacement.

## Open the console

Use `https://<server-ip>:8080/` for image status, device state, onboarding jobs, swarm information, settings, and audit data.
