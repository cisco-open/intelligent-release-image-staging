<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Getting Started

This path brings up the IRIS server and Console tiers, publishes an image,
onboards devices, and assigns an image to a device. Docker Compose
runs the two-container stack on one host by default. To place the Console on another
host, follow [Docker on separate hosts](docker-hosts.md).

For an assistant-led deployment that chooses and verifies either Docker
layout, use [AI-guided PoC](aiagent.md).

Start from the command line on an empty host. Once both services are running
and the required device packages are built, use the browser for image import, device onboarding, and assignments — see
[Web Console](console.md). Native package builds still run on the Docker host.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Linux host with Docker Engine 23.0 or newer and Docker Compose | Runs the IRIS server and Console containers. Their runtime tmpfs mounts use the `uid=`, `gid=`, and `mode=` options, which older engines reject. |
| Reachable server IP | Devices must reach the host on the published IRIS ports. |
| `aria2c` binary | `tools/get-aria2c.sh amd64` fetches the published deliverable, verifies it against `tools/aria2c.sha256` and installs it before the first build — the Dockerfile's `COPY bin/aria2c` step fails without it. A host with no route to the release can hand one in or build it; see [Obtain the handed-in inputs](#obtain-the-handed-in-inputs). |
| `age` identity | Encrypts server secrets at rest. Keep the private identity outside the repository. |
| Cisco image files | Store outside Git, normally under `/opt/images`. The tree must be readable and traversable by uid `10001`. The required license tier for the target platform is outside IRIS's scope — check [cisco.com](https://www.cisco.com/). |
| Device credentials | Used by server-side device operations. IOx also needs an IOS-XE credential for agent SSH-to-self. Do not commit real credentials. |
| Device-image build inputs | The IOx/XR builder always creates an amd64 + arm64 OCI image, so both pinned `aria2c` binaries and a builder able to run both architectures are required. On an amd64 host, the IOx staging helper can register ARM64 emulation using an audited `BINFMT_IMAGE_DIGEST`; see [IOx builds](iox.md#build-and-stage-for-console-onboarding). |

## Obtain the handed-in inputs

A fresh clone has neither of these, on purpose, and
`tools/start-compose-server.sh` reports both before it builds anything.

### The `aria2c` client

Install it for both architectures you need:

```bash
tools/get-aria2c.sh amd64
tools/get-aria2c.sh arm64
```

The helper fetches this project's published deliverable, refuses anything that
does not match `tools/aria2c.sha256`, installs it into `bin/`, and keeps a
verified copy in `deliverables/`, where the device-package builders look. Take
`arm64` only for IOx on IE-3400 and other IE-3x00 devices.

A host with no route to that release can take a hand-in instead — at
`deliverables/aria2c-<cpu>`, or via `ARIA2C_DELIVERABLE` — or build one:

```bash
git clone https://github.com/AnInsomniacy/aria2-next \
  tools/aria2c-build/vendor/aria2-next
git -C tools/aria2c-build/vendor/aria2-next checkout v2.5.6
(cd tools/aria2c-build && ./build.sh x86_64)
```

A binary you built will not match `tools/aria2c.sha256`, and
`tools/get-aria2c.sh` fails closed on that, so adopting it is deliberate: copy
`tools/aria2c-build/out/x86_64/aria2c` to `deliverables/aria2c-x86_64`, put its
`sha256sum` on the `x86_64` line of `tools/aria2c.sha256`, and record what you
built. That local modification is expected; never edit the file to clear a
mismatch on a binary you did not build, and a mismatch on the downloaded asset
means the asset is wrong and must not be adopted. Leave the file
world-readable: the server image copies it in and reads it as the runtime uid,
so a rewrite that lands as `0600` — which an atomic write through a temporary
file does by default — breaks the build that uses it. Run
`chmod 0644 tools/aria2c.sha256` after editing.

The `aarch64` build is the expensive fallback: it compiles under emulation,
takes tens of minutes and keeps every core busy. Start it detached so a closing
SSH session cannot cancel the `buildx` client, and leave Docker's cache alone:

```bash
cd tools/aria2c-build
setsid nohup ./build.sh aarch64 > build-aarch64.log 2>&1 < /dev/null &
```

It has no exit status to collect that way. It finished if the log ends with a
size gate (`UNDER TARGET` or `OVER TARGET`, not `HARD FAIL`) and
`out/aarch64/aria2c` exists. It is safe to rerun; the layer cache makes a
second attempt much shorter.
[`tools/aria2c-build/README.md`](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/tools/aria2c-build/README.md)
covers the patch set, the pinned toolchain, and publishing a new deliverable.

### ARM64 emulation

The arm64 package builders need Docker's arm64 emulation on an amd64 host.
Check for it, and prefer your distribution's static QEMU package, which needs
no digest and no privileged container:

```bash
grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready
```

Where that is unavailable, the builders register the handler themselves and
require `BINFMT_IMAGE_DIGEST` rather than pulling a floating tag. Review the
`tonistiigi/binfmt` tag you intend to use, resolve it to a digest, and export
it:

```bash
docker buildx imagetools inspect tonistiigi/binfmt:<reviewed-tag> \
  --format '{{println .Manifest.Digest}}'
export BINFMT_IMAGE_DIGEST=sha256:<the digest printed above>
```

### The two instruction roots

Every device package embeds exactly two public roots and the build fails closed
without them. Create them yourself — no installer generates trust anchors — and
keep `~/iris-roots` holding the two public keys and nothing else:

```bash
install -d -m 0700 ~/iris-custody && ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a && ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b && rm -rf ~/iris-roots && install -d -m 0755 ~/iris-roots && install -m 0644 ~/iris-custody/root-a.pub ~/iris-custody/root-b.pub ~/iris-roots/ && ls -A ~/iris-roots
```

Use a real passphrase at each prompt; the last command must print exactly the
two `.pub` names. In production run the two `ssh-keygen` commands on separate
custodians' machines and carry only the public halves over. See
[Prepare instruction trust](#prepare-instruction-trust).

## Configure the server

Create the secret identity and export the values Docker Compose expects:

```bash
umask 077
mkdir -p ~/.config/iris
age-keygen -o ~/.config/iris/age.txt
age-keygen -y ~/.config/iris/age.txt

export IRIS_HOST_IP=<server-ip>
export IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age.txt
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>,<break-glass-age-public-key>
```

Compose publishes the Console only on `IRIS_HOST_IP`, rather than on every
interface of a multi-homed host. Choose the intended IRIS-facing address and
restrict its TCP 8080 firewall rule to trusted operator sources.

## Give the runtime user the host paths

Both server and Console services run as the fixed uid/gid `10001` with all Linux
capabilities dropped. The image cannot chown host paths, so grant that uid the
age identity file and writable artifacts directory that cross the container
boundary before the first start, and again whenever either is recreated:

```bash
# from the repository root
mkdir -p artifacts
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"                 # keep it mode 600
sudo chown -R 10001:"$(id -g)" artifacts && sudo chmod -R g+w artifacts   # server owns it; you can write it
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
directory either way. If you override `IRIS_ARTIFACTS_HOST_DIR`, create and chown
that resolved directory instead. Without access to these paths, the server
cannot read its key material or write served artifacts; see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).

A new named volume inherits the image's `10001` ownership. For restored or
manually created volumes, check [Volume permissions](server.md#volume-permissions).

## Start the server

`start-compose-server.sh` is the whole first start. Before it builds anything
it checks every input a fresh clone lacks and reports all of them in one list:
the handed-in `aria2c` (`bin/aria2c`), `ioxclient`, the per-architecture
`aria2c` deliverables the IOx builder needs, and the two instruction-root
public keys. It then grants uid 10001 the `artifacts/` directory (or tells you
the exact `chown`), builds the images, initializes a fresh encrypted config
volume, installs the two public roots, starts the stack, waits for health, and
builds the Guest Shell bundle (self-provisioned by the server), both IOx
packages and the XR RPM — everything the Console's **Device packages** screen
lists. From the repository root:

```bash
tools/get-aria2c.sh amd64
IRIS_INSTRUCTION_ROOTS_DIR=/path/to/reviewed/roots tools/start-compose-server.sh
```

`IRIS_INSTRUCTION_ROOTS_DIR` defaults to `instr-roots/` in the repository and
must hold exactly two `.pub` files and nothing else. The helper reads those
public halves and **never creates roots**: they come from the
[custody ceremony](operations.md#instruction-root-ceremony-and-recovery), and
the private halves stay with their custodians. Set `IRIS_SKIP_XR=1` on a
deployment with no XR devices.

`iris-bootstrap` never overwrites existing encrypted state on a plain run: a
volume that already holds all three `.age` files (and whose files decrypt with
the mounted identity) is left untouched, and a volume holding only some of them
is refused rather than silently regenerated. Name the one missing file with
`--repair <secrets.json|rpc-secret|tls/key.pem>` to recreate just that file. To
add a break-glass recipient later, run
`IRIS_AGE_RECIPIENTS=<primary>,<break-glass> iris-bootstrap --rekey`, which
re-encrypts the existing store without touching any token, key, or the pinned
certificate. `--force --yes` is disaster recovery only: it mints new secrets and
a new certificate, so every onboarded device must be re-onboarded with the new
runtime trust anchor. The deployment-neutral IOx and XR packages can be reused
unless their agent source also changed. Set both recipients on the first
bootstrap so either identity can recover the store.

The server container exposes the tracker, catalog, artifact server, seeder data
port, and telemetry endpoints. The separate state-free Console publishes 8080
and reaches the server's internal 9443 management API with a file-mounted,
rotatable credential over pinned HTTPS. The age-encrypted server store lives
on `iris-config` and is decrypted into `/run/iris` tmpfs; the Console does not
mount that volume. The separate tier credential persists in `iris-tier-auth`.

After the container becomes healthy the helper runs
`tools/provision-iox-packages.sh`, which produces `iris-arm64.tar` for IE-3400
and `iris-amd64.tar` for Catalyst 9300 IOx as deployment-neutral wrappers of
the same canonical device image, and then `tools/build-xr-package.sh` for the
XR RPM, placed through the running container so `artifacts/` stays owned by
the runtime uid. Onboarding supplies the current public server certificate
separately as IOx application data.

Because the hand-ins are checked up front, a build failure after the stack is
up is now limited to emulation or the build itself; a reachable Console still
does not mean packages are ready, so read the helper's exit status. Fix the
reported problem and rerun `tools/provision-iox-packages.sh` or
`tools/build-xr-package.sh --out artifacts/`. A Guest Shell-only deployment can
bring up the two services without native package builds:

```bash
docker compose -f server/docker-compose.yml build --pull
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
docker compose -f server/docker-compose.yml run --rm \
  -v "$HOME/iris-roots:/pub:ro" --entrypoint sh iris -c \
  'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && \
   install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
docker compose -f server/docker-compose.yml up -d
```

The third command is the one `start-compose-server.sh` would have run for you:
it installs the two public roots into the server's config volume, which is a
different thing from handing them to the package builders. Without it the
server cannot self-provision a trust-bound Guest Shell bundle, and nothing
reports the omission. Confirm it with
`docker compose -f server/docker-compose.yml exec iris ls -l "$IRIS_CONFIG/instr/roots.d"`.

For IOS-XR, also run `tools/build-xr-package.sh --out artifacts/`; the startup
helper does not build the RPM. Check the artifacts and manifests in
**Settings → Device packages** before onboarding. Readiness checks wrapper
bytes against their build manifests and checks the distributed runtime
certificate separately. It does not detect newer agent source or verify native
signatures. After source changes, follow the complete
[package rebuild procedure](development.md#embedded-agent-packages), including
replacement of an existing canonical image when needed.

## Create the console admin

Open `https://<server-ip>:8080/` and sign in with the default first-run
credential `iris` / `irisisgreat!`. This works only before an admin account
exists. It does not create a session; it returns a one-use setup grant that
expires after ten minutes and takes you to account creation. Creating the admin
permanently ends that special behavior.

!!! warning "Complete the first-run claim on a trusted network"
    Whoever reaches a brand-new Console first can claim the administrator
    account. The Compose host binding excludes other host interfaces, but does
    not authenticate callers that can reach `IRIS_HOST_IP`. Keep port 8080
    restricted to a trusted management network and complete this step
    immediately after deployment.

Or set the admin account from the container instead:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

For scripted setup, pass `IRIS_GUI_ADMIN_PASSWORD` into the `iris-gui-admin`
process; setting it only in the host shell does not pass it through
`docker compose exec`.

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

## Prepare instruction trust

Before building device packages, provision exactly two distinct offline-root
public keys. [Obtain the handed-in inputs](#the-two-instruction-roots) has the
commands that create them; the
[custody ceremony](operations.md#instruction-root-ceremony-and-recovery) covers
certificates, rotation and revocation for a production deployment.
Keep private roots with separate custodians/sites. Point package builders at the
public `.pub` directory with `IRIS_INSTRUCTION_ROOTS_DIR` or
`--instruction-roots-dir DIR`; use the current pinned amd64/arm64 aria2c inputs.
Initialize server online certificate/keylist custody and producer authority
before expecting a device instruction stamp. Build success with disposable
roots is not production custody or signing evidence. Guest Shell can remain
tracker-only when its runtime verifier is absent.

## IOx verification prerequisite

Before IOx onboarding, read `show app-hosting infra`: app-hosting verification
is device-global. A signed wrapper is preferred and causes no verification-state
change. The unsigned transaction durably records initial enabled state,
disables only for installation, then restores with read-back before
activation/start. Initial disabled stays disabled; unknown refuses mutation
and installation. Interruption/resume and uninstall recovery honor owned
obligations, never blindly enabling an operator-changed or unowned state.
Check media/platform restrictions in [IOx verification](iox.md#device-global-package-verification).
Unsigned proof packages do not establish successful live activation.

A privileged device administrator can read the bootstrap enrollment bearer in
IOx `run-opts` or XR `docker-run-opts`, plus IOx's SSH-to-self password. The
bearer defaults to a 3,600-second TTL; complete the first authenticated refresh
promptly (normal token overlap is 120 seconds). Instruction/LKG/signing/root
private keys never belong in platform configuration. See the
[security boundary](security.md#two-root-trust-and-custody).

## Prepare devices

Create an inventory from the template:

```bash
cp fleet/devices.csv.example fleet/devices.csv
```

The inventory contains network onboarding information only, as a
management-type-aware CSV. Each device declares `routed`, `inband`,
`router-routed`, `router-nat`, or `xr-host` as its `management_type`:

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,platform
```

Fill the routed columns (`iris_vlan`, `svi_*`) for routed devices, or the inband
columns (`inband_vlan`, `app_*`) for inband devices. The Add Device form requires
an explicit management type and `platform`: `guestshell`, `iox`, `router`, or
`xr-appmgr`. Management type controls which network fields appear and bounds
the installer choices; model can narrow those choices further. Model is free
text and changing it does not change management type. Existing inventory
and CSV imports may leave the field blank as an inventory-only transition state,
in which case onboarding resolves known IOS-XE models and refuses uncertainty.
See
[Inventory](management-type.md#inventory).

For a Catalyst 8000 router, use `router-routed` with a VPG number, plus routes
you provide between the app subnet and IRIS, or `router-nat` with an outside
interface, which adds static TCP PAT on port 6881. Both router modes stage to
`bootflash:` only, so size it for about 2× the image plus 200 MB. Support is
designed for the Catalyst 8000 family and lab-tested on Catalyst 8000V; see
[Router routed and router NAT](management-type.md#router-routed-and-router-nat-iris-managed-virtualportgroup).

For a Cisco 8000-series IOS-XR router, use `management_type=xr-host` and
`platform=xr-appmgr`; leave every VLAN, SVI, app-address, VPG, and NAT field
empty. XR uses the router's host network, so no app IP is needed. Build
`artifacts/iris-xr.rpm` and its manifest before onboarding.

Onboard through the **Console** or API. The server creates a durable deployment
record, delivers enrollment credentials and certificate trust, and uses the
record to determine what it owns during undeploy.

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
Each CSV device id appears once, and its image is merged into that device's
existing ordered assignment. Use `iris-assign DEVICE IMAGE [IMAGE ...]` to add
several directly, or `iris-assign --replace DEVICE IMAGE [IMAGE ...]` when the
reviewed intent is to remove images omitted from the new set.

Agents poll the catalog, transfer assigned images, verify them, and stage them
on the device filesystem. Removing an assignment stops that image's torrent
and clears its working copy after the next successful due policy poll and
successful aria2 policy apply, including when the last assignment is removed.
Signed logical cadence and catalog/RPC failures can delay that cleanup.
IOS-XE keeps the placed root file for reuse. XR removes root files recorded as
IRIS downloads; operator-adopted files and files with unknown ownership remain.
See [Unassigned image park](device-agents.md#unassigned-image-park) for storage
and ownership rules.

## Open the console

Use `https://<server-ip>:8080/` for image status, device state, onboarding jobs, swarm information, settings, and audit data.
