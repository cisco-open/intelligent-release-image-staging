<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Getting Started

This path brings up the IRIS server and Console tiers, publishes an image,
onboards devices, and assigns an image to a device. IRIS verifies and stages
images only; it never installs or activates them, reloads a device, changes boot
variables, or mutates running software. Docker Compose
runs the two-container stack on one host by default. To place the Console on another
host, follow [Docker on separate hosts](docker-hosts.md).

For an assistant-led deployment that chooses and verifies either Docker
layout, use [AI-guided PoC](aiagent.md).

Complete host deployment, package preparation, and trust provisioning first.
Then use the [Console](console.md) or [API](swagger/index.html) for image import,
device onboarding, and assignments. The API does not replace host provisioning
or offline signing by a root custodian.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| `skopeo` | Selects each architecture's image from the canonical OCI artifact when building IOx packages and the IOS-XR RPM. `device/iox/build.sh` and `tools/build-xr-package.sh` fail closed without it. |
| `rpmbuild` | Assembles the IOS-XR appmgr RPM. Debian and Ubuntu ship it in the `rpm` package; `tools/build-xr-package.sh` fails closed without it. Not needed when no XR device is in scope. |
| Linux host with Docker Engine 23.0 or newer and Docker Compose | Runs the IRIS server and Console containers. Their runtime tmpfs mounts use the `uid=`, `gid=`, and `mode=` options, which older engines reject. |
| Reachable server IP | Devices must reach the host on the published IRIS ports. |
| `aria2c` binary | `tools/get-aria2c.sh amd64` fetches the published deliverable, verifies it against `tools/aria2c.sha256` and installs it before the first build — the Dockerfile's `COPY bin/aria2c` step fails without it. A host with no route to the release can hand one in or build it; see [Obtain the handed-in inputs](#obtain-the-handed-in-inputs). |
| `age` identity | Encrypts server secrets at rest. Keep the private identity outside the repository. |
| Cisco image files | Store outside Git, normally under `/opt/images`. The tree must be readable and traversable by uid `10001`. The required license tier for the target platform is outside IRIS's scope — check [cisco.com](https://www.cisco.com/). |
| Device credentials | Used by server-side device operations. IOx also needs an IOS-XE credential for agent SSH-to-self. Do not commit real credentials. |
| Device-image build inputs | The standard startup helper builds both IOx architectures, requiring both pinned `aria2c` binaries and a builder able to run them. The underlying device-image builder supports an explicit amd64-only build for a narrower deployment. On an amd64 host, the IOx staging helper can register ARM64 emulation using an audited `BINFMT_IMAGE_DIGEST`; see [IOx builds](iox.md#build-and-stage-for-console-onboarding). |

## Obtain the handed-in inputs

A fresh clone intentionally omits release binaries and trust roots.
`tools/start-compose-server.sh` checks for them before building.

### The aria2c client

For the usual amd64 server path, fetch the pinned client:

```bash
tools/get-aria2c.sh amd64
```

For IOx ARM64 builds, also fetch `tools/get-aria2c.sh --no-install arm64`;
this keeps the server's amd64 `bin/aria2c` in place. The helper verifies
published inputs against `tools/aria2c.sha256`. Hand-in and source-build
fallbacks are documented in the
[aria2c build guide](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/tools/aria2c-build/README.md).

### The `ioxclient` packaging profile

No operator profile is needed. The builder supplies a temporary inert profile
for packaging and discards it; `IOXCLIENT_HOME`, if set, must not contain real
device credentials.

### ARM64 emulation

ARM64 package builds on amd64 need QEMU/binfmt. The IOx guide covers checking or
registering an audited, digest-pinned handler:
[IOx builds](iox.md#build-and-stage-for-console-onboarding).

### The two instruction roots

Every package embeds exactly two distinct public trust roots. Generate them
yourself with real passphrases, and keep the private halves offline with
separate custodians. Copy only the public halves into an otherwise empty
`~/iris-roots` directory:

```bash
install -d -m 0700 ~/iris-custody
ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a
ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b
install -d -m 0755 ~/iris-roots
install -m 0644 ~/iris-custody/root-a.pub ~/iris-custody/root-b.pub ~/iris-roots/
ls -A ~/iris-roots
```

Verify the final listing contains exactly the two `.pub` files. In production,
generate each root on a separate custodian's machine and carry only public
halves across. The [custody ceremony](operations.md#instruction-root-ceremony-and-recovery)
covers rotation and recovery. Installers never generate trust anchors. See
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
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>
```

That one key is a complete configuration. The list has to contain the public
half of the key in `IRIS_AGE_KEY_FILE_HOST`, and bootstrap refuses if it does
not.

A production deployment usually lists a second key as well, kept by someone
else and stored somewhere else, so the encrypted state can still be opened if
the first key is lost:

```bash
export IRIS_AGE_RECIPIENTS=<primary-age-public-key>,<second-age-public-key>
```

There is no need to create a second key now. One stored next to the first
protects nothing, and `--rekey` below adds one at any time without redoing the
deployment.

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

From the repository root, with the prerequisites and permissions above prepared:

```bash
IRIS_INSTRUCTION_ROOTS_DIR=/path/to/reviewed/roots tools/start-compose-server.sh
```

The helper bootstraps encrypted configuration, installs the two public roots,
starts the server and Console, and builds the device packages. It builds the XR
RPM unless `IRIS_SKIP_XR` is set. It never creates trust roots.

Check the helper's exit status and **Settings → Device packages**. A reachable
Console does not mean package preparation succeeded. Package readiness checks
do not replace a source rebuild or prove native device acceptance; follow
[package rebuilds](development.md#embedded-agent-packages) after agent changes.

Existing encrypted state is preserved by a normal bootstrap. Do not force-reset
a deployment to resolve a missing file or package. Use the recovery guidance in
[Operations](operations.md) and preserve its volumes, identity, and certificates.

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

For automation, the API exposes login and first-admin setup with the same
setup-grant requirements; see the [API reference](swagger/index.html). Host-level
administrator recovery is a separate [maintenance task](operations.md).

## Publish an image

In **Images**, upload a file or choose **Import from disk** for an eligible file
already available to the server. API equivalents are:

- `PUT /api/v1/images/upload/{filename}`
- `GET /api/v1/images/importable`
- `POST /api/v1/images/import`

Follow the returned image job to completion before assigning the image. Use the
[API reference](swagger/index.html) for request bodies, session/CSRF requirements,
and responses.

Publishing records SHA-256 and SHA-512 metadata. Device agents verify the
download against catalog SHA-256. The separate Cisco Bulk Hash check can
quarantine a mismatch; publication alone is not proof of a matching vendor hash.

### Import an image already on disk

The default host import root is `/opt/images`, configured through
`IRIS_IMAGE_ROOT`. The Console lists eligible files and explains why others
cannot be imported. Import uses the existing file in place; keep it available
to the server while it is published. See
[import requirements](server.md#importing-images-already-on-disk).

## Prepare instruction trust

Before building device packages, provision exactly two distinct offline-root
public keys. [Obtain the handed-in inputs](#the-two-instruction-roots) has the
commands that create them; the
[custody ceremony](operations.md#instruction-root-ceremony-and-recovery) covers
certificates, rotation and revocation for a production deployment.
Keep private roots with separate custodians/sites. Point package builders at the
public `.pub` directory with `IRIS_INSTRUCTION_ROOTS_DIR` or
`--instruction-roots-dir DIR`; use the current pinned amd64/arm64 aria2c inputs.
Then initialize the server's online certificate and producer authority, once
the stack is up and before onboarding any device. Every onboarding fails with
`ERROR: instruction bootstrap unavailable` until this is done, because each
device's onboarding envelope is stamped by the instruction producer:

```bash
docker exec iris iris-instructions --generate-online-key
docker cp iris:/etc/iris/instr/signing-key.pub ~/iris-online.pub
ssh-keygen -q -s ~/iris-custody/root-a -I iris-online -n iris-server \
  -V +0s:+30d ~/iris-online.pub
docker cp ~/iris-online-cert.pub iris:/etc/iris/instr/signing-key-cert.pub
docker exec iris iris-instructions --import-certificate \
  /etc/iris/instr/signing-key-cert.pub
docker exec iris iris-instr-key initialize
docker exec iris iris-instructions --status
```

Export the public half from the config volume as shown, not the runtime tmpfs;
see [Docker's copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/#corner-cases).
Signing uses the **private** root and its passphrase and remains a custodian's
responsibility.

`iris-instr-key initialize` activates the producer, which is the authority half
of this: the certificate alone leaves the stamper without an activated epoch,
and onboarding keeps failing with the same message. On a cluster, use
`kubectl exec` and `kubectl cp` against the server pod with `/data/config` in
place of `/etc/iris`.

Onboarding is ready when `iris-instructions --status` reports `enabled: true`
with `signing_refused: false`. A proof of concept also reports
`state: keylist_missing` and an overdue root ceremony: the keylist is the
device-facing revocation list and does not gate stamping, and no custodian has
attested these roots. Both are expected until a production ceremony. Build success with disposable
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

Use **Devices → Add Device** or import inventory in the Console. API automation
uses `POST /api/v1/devices` or `POST /api/v1/devices/import-csv`.

Select a platform and management type, then supply the required connectivity
fields and a credential profile. These choices control onboarding, not just
inventory labels. See [management types](management-type.md#inventory).

For Cisco 8000 and NCS IOS-XR routers, use `xr-host` and `xr-appmgr`, without
VLAN, SVI, app-address, VPG, or NAT fields. The app uses router networking and
must reach the catalog; management SSH reachability alone does not prove that.
This recipe does not select a VRF.

Onboard from the Console or `POST /api/v1/devices/{device_id}/onboard`.
Follow the job and wait for an agent heartbeat before assigning an image.
Onboarding creates a deployment record used for ownership-aware undeploy.
Check [device requirements](device-agents.md) for the selected platform.

## Assign images

Select an image for the device in the Console. API automation uses
`POST /api/v1/devices/{device_id}/assign`; its ordered `image_ids` list
**replaces** the assignment rather than merging it. Preserve images you still
want assigned and use the documented conflict checks when updating concurrently.

Agents poll for assignments, transfer and verify the image, then report staging
status. Confirm that status in the Console or
`GET /api/v1/devices/{device_id}/reports`; a successful assignment request does
not mean the download is complete.

Removing an assignment stops its torrent and cleans owned working files after
a successful policy update. Platform storage and ownership rules differ; do not
assume it deletes every staged image. See
[unassigned image handling](device-agents.md#unassigned-image-park).

## Open the console

Use `https://<server-ip>:8080/` for image status, device state, onboarding jobs, swarm information, settings, and audit data.
