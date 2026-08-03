<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Getting Started

This path brings up the IRIS server, publishes an IOS-XE image, generates device installers, and assigns an image to a device. It assumes Docker Compose is the server runtime.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Linux host with Docker Engine 23.0 or newer and Docker Compose | Runs the IRIS server container. The runtime tmpfs uses the `uid=`, `gid=`, and `mode=` mount options, which older engines reject. |
| Reachable server IP | Devices must reach the host on the published IRIS ports. |
| `age` identity | Encrypts server secrets at rest. Keep the private identity outside the repository. |
| IOS-XE image files | Store outside Git, normally under `/opt/images`. The tree must be readable and traversable by uid `10001`. |
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

## Give the runtime user the host paths

Every service in the container runs as the fixed uid/gid `10001` with all Linux
capabilities dropped. The image cannot chown host paths, so grant that uid the
two host paths that cross the container boundary before the first start, and
again whenever either one is recreated:

```bash
# from the repository root
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"   # keep it mode 600
sudo chown -R 10001:10001 "${IRIS_ARTIFACTS_HOST_DIR:-artifacts}"
```

Compose reads the same directory as `${IRIS_ARTIFACTS_HOST_DIR:-../artifacts}`,
resolved relative to `server/docker-compose.yml` — the repository's `artifacts/`
directory either way. Without these two, the server starts and then cannot read
its key material or write served artifacts; see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).

A fresh install needs nothing more — a new named volume inherits the image's
`10001` ownership. Volumes carried over from an earlier root-runtime release stay
root-owned and need a one-time migration first:
[Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment).

## Start the server

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

### Import an image already on disk

Uploading a multi-gigabyte file through the browser is unnecessary when the file
is already on the server. The **Import from disk** panel on the Console Images
screen lists every `.bin` under the uploads volume (`IRIS_IMAGES_DIR`) and under
the read-only import root (`IMAGES_ROOT`) that is not yet in the catalog, and
publishes it in place with one click: nothing is copied, and the `.torrent` is
written to the state directory rather than next to the image, so the read-only
import root stays read-only. See
[Importing images already on disk](server.md#importing-images-already-on-disk)
for what makes a file eligible, and
[Import skip reasons](reference.md#import-skip-reasons) for the reasons a file is
listed greyed out instead.

## Prepare devices

Create an inventory from the template:

```bash
cp fleet/devices.csv.example fleet/devices.csv
```

The inventory contains network onboarding information only, as an
attachment-aware CSV v2. Each device declares `routed`, `inband`,
`router-routed`, or `router-nat` as its `management_type`:

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,platform
```

Fill the routed columns (`iris_vlan`, `svi_*`) for routed devices, or the inband
columns (`inband_vlan`, `app_*`) for inband devices. `model`/`platform` are
optional; blank `platform` auto-selects from the model. See
[Inventory (CSV v2)](network-attachment.md#inventory-csv-v2).

For a Catalyst 8000 router, use `router-routed` with a VPG number, plus routes
you provide between the app subnet and IRIS, or `router-nat` with an outside
interface, which adds static TCP PAT on port 6881. Both router modes stage to
`bootflash:` only, so size it for about 2× the image plus 200 MB. Support is
designed for the Catalyst 8000 family and lab-tested on C8000v; see
[Router routed and router NAT](network-attachment.md#router-routed-and-router-nat-iris-managed-virtualportgroup).

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
