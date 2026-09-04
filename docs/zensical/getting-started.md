<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Getting Started

This path brings up the IRIS server and Console tiers, publishes an image,
generates device installers, and assigns an image to a device. Docker Compose
runs the two-container stack.

It uses the command line throughout because it starts from an empty host. Once the server is running, everything after bring-up can also be done in the browser — see [Web Console](console.md).

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Linux host with Docker Engine 23.0 or newer and Docker Compose | Runs the IRIS server and Console containers. Their runtime tmpfs mounts use the `uid=`, `gid=`, and `mode=` options, which older engines reject. |
| Reachable server IP | Devices must reach the host on the published IRIS ports. |
| Handed-in `aria2c` binary | Not downloaded or built by this repository. `tools/get-aria2c.sh amd64` installs the pinned static binary before the first build — the Dockerfile's `COPY bin/aria2c` step fails without it. |
| `age` identity | Encrypts server secrets at rest. Keep the private identity outside the repository. |
| Cisco image files | Store outside Git, normally under `/opt/images`. The tree must be readable and traversable by uid `10001`. The required license tier for the target platform is outside IRIS's scope — check [cisco.com](https://www.cisco.com/). |
| Device credentials | Used only for installation or GUI-driven onboarding. Do not commit real credentials. |
| `BINFMT_IMAGE_DIGEST` — only if you deploy IE-3x00 IOx | The bring-up below stages **both** IOx packages, and the arm64 build needs Docker's ARM64 emulation. On an amd64 host that has never registered it, the build fails closed rather than pull an unpinned image, and the bring-up command exits non-zero *after* the server is already up and reachable. Export the audited `tonistiigi/binfmt` sha256 digest — see [IOx: Build and stage for Console onboarding](iox.md#build-and-stage-for-console-onboarding) — or skip the arm64 package if you deploy no IE-3x00. |

## Configure the server

Create the secret identity and export the values Docker Compose expects:

```bash
umask 077
mkdir -p ~/.config/iris
age-keygen -o ~/.config/iris/age.txt
age-keygen -y ~/.config/iris/age.txt
openssl rand -hex 32 > ~/.config/iris/console-setup-token

export IRIS_HOST_IP=<server-ip>
export IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age.txt
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>,<break-glass-age-public-key>
export IRIS_CONSOLE_SETUP_TOKEN_FILE_HOST=$HOME/.config/iris/console-setup-token
```

## Give the runtime user the host paths

Every service in the container runs as the fixed uid/gid `10001` with all Linux
capabilities dropped. The image cannot chown host paths, so grant that uid the
two credential files and writable artifacts directory that cross the container
boundary before the first start, and again whenever one is recreated:

```bash
# from the repository root
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"                 # keep it mode 600
sudo chown 10001 "$IRIS_CONSOLE_SETUP_TOKEN_FILE_HOST"     # keep it mode 600
sudo chown -R 10001:10001 "${IRIS_ARTIFACTS_HOST_DIR:-artifacts}"
```

If you enable authenticated Prometheus scraping, create another raw token with
the same private umask, export its host path, and mount the identical value as
the scraper's bearer credentials file:

```bash
openssl rand -hex 32 > ~/.config/iris/observability-token
export IRIS_OBSERVABILITY_TOKEN_FILE_HOST=$HOME/.config/iris/observability-token
sudo chown 10001 "$IRIS_OBSERVABILITY_TOKEN_FILE_HOST"
```

The optional previous-token host path is needed only during rotation; see
[Telemetry export](telemetry-export.md).

Compose reads the same directory as `${IRIS_ARTIFACTS_HOST_DIR:-../artifacts}`,
resolved relative to `server/docker-compose.yml` — the repository's `artifacts/`
directory either way. Without these three paths, the server cannot read its
key/setup material or write served artifacts; see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).

A fresh install needs nothing more — a new named volume inherits the image's
`10001` ownership. Volumes carried over from an earlier root-runtime release stay
root-owned and need a one-time migration first:
[Upgrading from a root-runtime deployment](server.md#upgrading-from-a-root-runtime-deployment).

## Start the server

`start-compose-server.sh` builds both server-tier images, so hand in the pinned `aria2c`
binary first — the Dockerfile's `COPY bin/aria2c` step fails without it.
Then build the images, initialize a fresh encrypted config volume, start the
stack, and prepare both IOx packages from the repository root:

```bash
tools/get-aria2c.sh amd64
tools/start-compose-server.sh
```

`iris-bootstrap` never overwrites existing encrypted state on a plain run: a
volume that already holds all three `.age` files (and whose files decrypt with
the mounted identity) is left untouched, and a volume holding only some of them
is refused rather than silently regenerated. Name the one missing file with
`--repair <secrets.json|rpc-secret|tls/key.pem>` to recreate just that file. To
add a break-glass recipient later, run
`IRIS_AGE_RECIPIENTS=<primary>,<break-glass> iris-bootstrap --rekey`, which
re-encrypts the existing store without touching any token, key, or the pinned
certificate. `--force --yes` is disaster recovery only: it mints new secrets and
a new certificate, so every onboarded device must be re-onboarded and every
prebuilt package rebuilt. Both recipients on the first bootstrap avoids all of
this.
The server container exposes the tracker, catalog, artifact server, seeder data
port, and telemetry endpoints. The separate state-free Console publishes 8080
and reaches the server's internal 9443 management API with a file-mounted,
rotatable credential over pinned HTTPS. Plaintext server secrets are decrypted
into `/run/iris` tmpfs at runtime and encrypted under the `iris-config` volume
at rest; the Console does not mount that volume.

`start-compose-server.sh` runs `tools/provision-iox-packages.sh` after the
container becomes healthy. It produces `iris-arm64.tar` for IE-3400 and
`iris-amd64.tar` for Catalyst 9300 IOx, both pinned to the current server certificate.

!!! warning "The arm64 package needs ARM64 emulation"
    That step builds arm64 first. On an amd64 host with no ARM64 binfmt handler
    registered it stops at
    `set BINFMT_IMAGE_DIGEST to an audited tonistiigi/binfmt sha256 digest`,
    and because it runs *after* the health gate the failure is easy to miss: the
    console is already reachable, the command exits non-zero, and **neither**
    IOx package exists. Export `BINFMT_IMAGE_DIGEST` before running the
    bring-up, or — if you only deploy Guest Shell C9300s and no IE-3x00 — skip
    the IOx packages entirely and stage the amd64 one on its own later with
    `tools/stage-iox-package.sh --arch amd64`. Verify what was actually built
    with `tools/check-package-freshness.sh`, or the console's Settings › Setup
    *Device packages* card.

## Create the console admin

Open `https://<server-ip>:8080/`. Before an admin exists, sign in as `iris`
using the exact contents of `$IRIS_CONSOLE_SETUP_TOKEN_FILE_HOST` as the
password. The token is deployment-unique and server-mounted; it does not create
a session, but exchanges once for the ten-minute account-creation grant. To
read it without changing host-file ownership, use:

```bash
docker compose -f server/docker-compose.yml exec iris \
  cat /run/iris/console-setup-token
```

Or set the admin account from the container instead:

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

`iris-publish` computes `sha256` and `sha512`, creates a private torrent, hands it to the seeder, and records catalog metadata. The server can check the recorded `sha512` against Cisco's signed Bulk Hash feed and quarantines the image on a mismatch; what the device checks is the staged file's `sha256` against this catalog entry.

### Import an image already on disk

Uploading a multi-gigabyte file through the browser is unnecessary when the file
is already on the server. The **Import from disk** panel on the Console Images
screen lists every eligible `.bin`, `.iso`, `.tar`, or `.rpm` under the uploads
volume (`IRIS_IMAGES_DIR`) and read-only import root (`IMAGES_ROOT`) that is not
yet in the catalog, and
publishes it in place with one click. Nothing is copied, and the `.torrent` is
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
management-type-aware CSV v2. Each device declares `routed`, `inband`,
`router-routed`, `router-nat`, or `xr-host` as its `management_type`:

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,platform
```

Fill the routed columns (`iris_vlan`, `svi_*`) for routed devices, or the inband
columns (`inband_vlan`, `app_*`) for inband devices. The Add Device form requires
an explicit `platform`: `guestshell`, `iox`, `router`, or `xr-appmgr`; it narrows
the choices from `model` rather than silently choosing one. Existing inventory
and CSV imports may leave the field blank as an inventory-only transition state,
in which case onboarding resolves known IOS-XE models and refuses uncertainty.
See
[Inventory (CSV v2)](management-type.md#inventory-csv-v2).

For a Catalyst 8000 router, use `router-routed` with a VPG number, plus routes
you provide between the app subnet and IRIS, or `router-nat` with an outside
interface, which adds static TCP PAT on port 6881. Both router modes stage to
`bootflash:` only, so size it for about 2× the image plus 200 MB. Support is
designed for the Catalyst 8000 family and lab-tested on Catalyst 8000V; see
[Router routed and router NAT](management-type.md#router-routed-and-router-nat-iris-managed-virtualportgroup).

For a Cisco 8000-series IOS-XR router, use `management_type=xr-host` and
`platform=xr-appmgr`; leave every VLAN, SVI, app-address, VPG, and NAT field
empty. Build `artifacts/iris-xr.rpm` before onboarding.

Management-type-aware onboarding runs through the **Console** (or API), which creates
a durable deployment record and drives teardown from it. The legacy CLI generator below is
routed-only and refuses a v2 (`management_type`) header:

```bash
# legacy routed inventory only
tools/gen-device-installers.sh path/to/legacy-routed.csv
```

It takes the old positional columns
`device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip`, and no template for that
format ships — `fleet/devices.csv.example` is CSV v2 and the generator refuses
it. It exists for sites that still hold such a file; anything new goes through
the console.

It requires the running `iris` container to mint enrollment tokens and read
the server certificate; set `IRIS_CONTAINER=<name>` if yours is named
differently.

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

This requires the running `iris` container by that name; set
`IRIS_CONTAINER=<name>` if yours differs.

Agents poll the catalog on a short interval, download the approved image, verify it, and stage it on the target storage. A changed assignment **parks** the previous image rather than deleting it: its torrent stops and its staging copy is freed, but the copy already placed on the storage root is deliberately kept, and is reclaimed only when a later placement needs the room. Size storage for the images you want resident at once — see [Unassigned image park](device-agents.md#unassigned-image-park).

## Open the console

Use `https://<server-ip>:8080/` for image status, device state, onboarding jobs, swarm information, settings, and audit data.
