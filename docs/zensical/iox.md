<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path runs the agent as a Docker-based IOx application. It supports
ARM64 IE-3400 style platforms and x86_64 Catalyst 9300 app hosting. IOx and
IOS-XR package the same canonical device image and run the same entrypoint;
`IRIS_DEVICE_PLATFORM=iox` selects this profile.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle. The
Guest Shell path remains available for Catalyst devices that support that agent
model. The staging target is platform-appropriate and selected by the existing
live filesystem/model policy rather than a second platform knob: IE-3400
normally selects `sdflash:`, while Catalyst 9300 normally selects `flash:`
(bootflash, like Guest Shell) and uses the SSD share to carry the transfer. The table in
[Device Agents](device-agents.md#platform-targets) reflects the same rule.

The installer reads the selected package from the server's local
`artifacts/` directory and pushes it to IOS over its authenticated,
host-key-checked SCP session before driving app hosting. It does not put a
credential in an artifact URL.

## Files

| File | Purpose |
| --- | --- |
| `device/container/Dockerfile` | Builds the canonical multi-architecture IOx/XR agent container. |
| `device/container/entrypoint.sh` | Validates `IRIS_DEVICE_PLATFORM` and supervises either runtime profile. |
| `device/iox/package.yaml` | ARM64 IOx package metadata. |
| `device/iox/package-amd64.yaml` | x86_64 IOx package metadata. |
| `device/iox/build.sh` | Packages the canonical image in the IOx envelope. |
| `device/iox/install.sh` | Installs the IOx app on a target device. |
| `device/iox/uninstall.sh` | Removes the IOx app. |
| `device/iox/rebake_iris_tar.py` | Legacy content rewriter for unsigned IOx packages; refuses signed packages. |

## Runtime behavior

The IOx agent follows the same catalog and staging model as the Guest Shell
agent. It downloads resumable swarm data under the CAF persistent directory
(`/iox_data/iris` on the validated Catalyst 9300 runtime).

The IOx package contains no deployment certificate. On every onboarding,
`device/iox/install.sh` validates the current public certificate from the
served artifacts directory, pushes it with the package, and uses IOS-XE's
`app-hosting data` channel to place it in the app's application-data directory
after installation and before activation. The entrypoint requires and validates
that runtime-delivered certificate before it starts either the catalog client
or the aria2 tracker client.

The hand-off of the verified scratch file to IOS depends on the platform:

- **Catalyst 9300 (share mount)**: onboarding bind-mounts the app-hosting SSD share —
  `usbflash1:iox_host_data_share`, host-side `/vol/usb1/iox_host_data_share` —
  into the container (`run-opts "-v …:/mnt/share"`). The agent copies the
  scratch to the share ROOT under its fixed `iris-staged.bin` name at disk
  speed, then drives an IOS-internal
  `copy usbflash1:iox_host_data_share/iris-staged.bin flash:<img>`
  over its SSH-to-self CLI. That is the same bootflash-root placement as Guest
  Shell, with no image bytes crossing the device CPU; the copy is a plain
  copy that restores the real image name, and the agent attests the
  placement by polling for the file and confirming it matches the catalog's
  declared byte size exactly. The image was already verified by sha256
  against the catalog before the placement copy; the catalog can separately
  verify authenticity against Cisco's signed Bulk Hash feed, and a mismatch
  quarantines the image. IRIS never creates a subdirectory in the
  share (a container-created subdir becomes inaccessible to the container
  itself on this platform) and confines
  itself to `iris-` prefixed filenames: each attempt sweeps only its own
  leftovers, a tiny probe proves IOS can actually read the share before any
  multi-GB copy is committed (falling back to scp otherwise), the transient
  copy is removed after placement, and undeploy deletes the prefixed files.
- **IE-3400 (scp push)**: IOx cannot bind-mount the SD card there, so the
  container SCP-pushes the scratch to `guest-share/iris` through the device's
  SCP server and then runs a plain `copy` for the final placement, attested
  afterward by the agent polling for an exact byte-size match at the
  destination. The agent also falls back to this path automatically if the
  share mount is absent or unreadable from IOS. This scp traffic is addressed
  to the device itself, so default CoPP caps it at roughly 1.4 MB/s; IRIS
  never modifies CoPP.

Both platforms drive IOS over the app's SSH-to-self CLI, for the placement copy and
for the one-shot EEM applets that place and reclaim files at the target-FS root. That
connection can optionally be pinned: set `device_ssh_known_hosts` in the agent config
and, when that file exists, the app's `ssh` and `scp` calls verify the IOS host key
against it instead of running unverified. See
[Device Agents](device-agents.md).

The agent selects a target only after `show file systems`, model evidence, and
the existing flash-target rules prove a writable non-crash disk. It does not
fall back to a guessed `flash:` target. When the selected target is `sdflash:`
(the IE3x00 case), the installer checks
`show sdflash: filesys` for an IOx partition before applying any config and
fails closed with a `PREREQ:` line if the SD card was never formatted for
IOx. The installer also checks `ip routing` on a device using the routed management type (see
[Management type and VLAN ownership](management-type.md#routed-iris-managed-app-network))
and warns — without blocking — on a device clock old enough to break TLS
certificate validation.

### First install of a new package version

The first time a device sees a given package, the IOx runtime has to load its
docker layers into the image cache before the app can activate; a
byte-identical package the box has run before activates in seconds because
those layers are already cached. The installer's lifecycle waits are sized for
that cold case: `INSTALL_TIMEOUT`, `ACTIVATE_TIMEOUT` and `START_TIMEOUT`
default to 300 seconds each (`STATE_POLL`, the poll interval, to 5), the same
budget `device/xr-install.sh` uses. They are flat rather than scaled by package
size — each wait returns as soon as the state is reached, so a generous ceiling
costs a healthy install nothing — and every one of them is an environment
override for a device that needs longer. A wait that does run out prints the
device's full, unfiltered reply to the `app-hosting` command and the last state
it observed.

An onboard that fails at activation leaves the app-hosting configuration in
place, because the activation may still be in flight. That is deliberate and
does **not** need an undeploy or a forced teardown: re-run the installer, or
press Onboard again in the console. Console preflight treats an IRIS app that
is `DEPLOYED` or `ACTIVATED` but never started as a resumable retry (it serves
nothing, and the installer's own step [1/9] tears down whatever it finds),
while an app that is `RUNNING` is a live deployment and still refuses.

## Build modes

The canonical build always persists one OCI archive with one image manifest
per CPU architecture under one multi-architecture identity. `--image-only`
still builds/verifies both `linux/amd64` and `linux/arm64`; the architecture
flag selects only a later native wrapper. The default signable output is
`artifacts/iris-device-$VERSION.oci.tar` with an adjacent `.manifest` recording
its index, archive, and source digests. `device/iox/build.sh` places that image inside an
`ioxclient` package; `tools/build-xr-package.sh` places the same amd64 image
inside an appmgr RPM. The outer tar and RPM necessarily differ in metadata and
format, but their embedded amd64 image config and rootfs digest must match.
Signing the OCI identity therefore signs one common payload; deployments that
also require native IOx/RPM signatures still sign each native envelope. Each
wrapper is published atomically beside a `.manifest` tying its own SHA-256 and
selected platform back to the canonical index/archive/source digests.

```bash
# Docker image only
device/iox/build.sh --image-only

# Docker image plus Cisco iris-arm64.tar package (requires ioxclient)
device/iox/build.sh device/iox/out

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  device/iox/build.sh device/iox/out
```

The build deliberately accepts no `CATALOG_PEM`, `CATALOG_PEM_URL`, or
certificate fingerprint input. The canonical OCI image and the native IOx/XR
wrappers contain no deployment-specific trust material, so one signed package
can be used across deployments. The current public certificate remains a
required onboarding input and never includes the server's private key.

Rebuild the canonical image and every native wrapper after a change to source
included in the shared device image. Certificate rotation alone is not a
package source change and does not require a rebuild.

The common device-image builder and `device/iox/build.sh` never download
`aria2c`. The binary is a handed-in
deliverable, produced elsewhere by the aria2-next-static project and only
verified here — never fetched from a third party, never built in this
repository (`tools/get-aria2c.sh` and `tools/aria2c.sha256` document the same
producer/consumer split and the same verify-or-fail idiom the build uses
internally). It resolves each architecture-matched `aria2c` in order:
`ARIA2C_BIN_AMD64` or `ARIA2C_BIN_ARM64` if set, else the matching local agent bundle
(`artifacts/iris-agent-arm.tgz` or `iris-agent.tgz`, whose `aria2c` is still
checksum-verified — a bundle's provenance is not otherwise pinned), else
`deliverables/aria2c-<arch>` checksum-verified against `tools/aria2c.sha256`.
With none of those present the build hard-errors; there is no network
fallback. For package builds, `tools/stage-iox-package.sh` downloads Cisco's
pinned Linux amd64 `ioxclient` release to git-ignored `tools/bin/` on first use;
set `IOXCLIENT` to use an existing installation instead.

## Build and stage for Console onboarding

Run this on the Linux Compose host after the IRIS container is healthy. The same
Linux amd64 `ioxclient` package tool builds both architecture-specific packages;
the `--arch` choice selects the Docker image, package descriptor, and output
name.

```bash
# Build and stage both packages during server bring-up (recommended).
tools/provision-iox-packages.sh

# IE-3x00 / IR1101 / IR18xx: arm64 package served as iris-arm64.tar
tools/stage-iox-package.sh --arch arm64

# SSD-equipped Catalyst 9300 IOx: amd64 package served as iris-amd64.tar
tools/stage-iox-package.sh --arch amd64
```

On first use the helper downloads Cisco's pinned `ioxclient` 1.18.0.0 to
`tools/bin/ioxclient`, verifying the extracted binary against
`tools/ioxclient.sha256` and refusing a mismatch or an unrecorded version
(`IOXCLIENT_SKIP_VERIFY=1` is the explicit one-off escape hatch, which prints
the sha256 to record); that binary is git-ignored and not embedded in the
repository or seed-server image. The helper does not retrieve a catalog
certificate for the build. It builds the deployment-neutral package and places
it with its provenance manifest in `/srv/artifacts`. When the served host
directory is not writable by the invoking user — the normal case, since the
server runs as uid 10001 and its artifacts directory is owned by that uid —
the helper places both files with `docker cp` rather than requiring a host
ownership change. On an amd64 server, the arm64 build registers Docker's ARM64
emulation handler when it is missing, using the audited `tonistiigi/binfmt`
image digest supplied via the required `BINFMT_IMAGE_DIGEST` environment
variable; with the digest unset the build fails closed rather than pull an
unpinned image. The helper only builds and places artifacts; it never contacts
or changes a device.

After a server certificate rotation, re-onboard each deployed IOx app so the
installer delivers the current public certificate as application data. The
package itself remains valid and does not need rebuilding.

Check served package readiness with `tools/check-package-freshness.sh`, or in
the Console's Settings → Device packages page backed by the setup-status API.
A ready package has readable wrapper bytes matching its adjacent
canonical-image provenance; this does not inspect package contents, validate a
native signature, or compare the package against certificate age. The same
status separately verifies that the certificate served by the live catalog
matches the public copy available to onboarding.
See
[TLS rotation and device packages](operations.md#tls-rotation-and-device-packages).

## Artifact handling

`iris-arm64.tar` and `iris-amd64.tar` are operator-built artifacts and belong
under `artifacts/` for serving. Keep each adjacent `.manifest` with its package;
the readiness check binds the served bytes to that provenance. The server
container serves them but does not rebuild or mutate them automatically.

Treat a signed wrapper as immutable. If native signing changes the wrapper
bytes, publish the signed output with a manifest recording that output's
SHA-256 while retaining its canonical image provenance. A manifest for the
unsigned input will correctly report a digest mismatch beside the signed
output. This manifest is a readiness check, not a signature or an attestation
from the signer; native signature verification remains the platform's job.
The IOx installer keeps app-hosting verification enabled when the tar carries
signature metadata.

`device/iox/rebake_iris_tar.py` is only for legacy unsigned packages. It refuses
to rewrite a package containing `package.sign` or `package.cert`, including
inside nested archives. For a source change, rebuild from source and obtain a
new signature. For a certificate change, re-onboard using the existing package
so the installer replaces only the runtime trust file.
