<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path runs the agent as a Docker-based IOx application. It supports
ARM64 IE-3400 style platforms and x86_64 Catalyst 9300 app hosting.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle. The
Guest Shell path remains available for Catalyst devices that support that agent
model. The staging target is platform-appropriate, and the rule is stated once
here: the CLI installer (`device/iox/install.sh`) defaults `TARGET_FS` to
`sdflash:` (the IE-3400 case); console onboarding overrides it to `flash:`
(bootflash, like Guest Shell) for Catalyst 9300 IOx, with the SSD share
carrying the transfer. The table in
[Device Agents](device-agents.md#platform-targets) reflects the same rule.

## Files

| File | Purpose |
| --- | --- |
| `device/iox/Dockerfile` | Builds the multi-architecture IOx agent container. |
| `device/iox/package.yaml` | ARM64 IOx package metadata. |
| `device/iox/package-amd64.yaml` | x86_64 IOx package metadata. |
| `device/iox/entrypoint.sh` | Starts the agent inside the application container. |
| `device/iox/build.sh` | Builds the IOx package. |
| `device/iox/install.sh` | Installs the IOx app on a target device. |
| `device/iox/uninstall.sh` | Removes the IOx app. |
| `device/iox/rebake_iris_tar.py` | Updates an existing IOx package's content. |

## Runtime behavior

The IOx agent follows the same catalog and staging model as the Guest Shell
agent. It downloads resumable swarm data under the CAF persistent directory
(`/iox_data/iris` on the validated Catalyst 9300 runtime). The hand-off of the verified
scratch file to IOS depends on the platform:

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

`IRIS_TARGET_FS` optionally selects a filesystem prefix such as `sdflash:` or
`bootflash:`. The agent accepts it only when `show file systems` reports a
writable non-crash disk; otherwise it logs the fallback and retains automatic
platform selection. `device/iox/install.sh` exposes this as `TARGET_FS` and
defaults it to `sdflash:`.

When `TARGET_FS` is `sdflash:` (the IE3x00 default), the installer checks
`show sdflash: filesys` for an IOx partition before applying any config and
fails closed with a `PREREQ:` line if the SD card was never formatted for
IOx. The installer also checks `ip routing` on a device using the routed management type (see
[Management type and VLAN ownership](management-type.md#routed-iris-managed-app-network))
and warns — without blocking — on a device clock old enough to break TLS
certificate validation.

## Build modes

```bash
# Docker image only
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh --image-only

# Docker image plus Cisco iris-arm64.tar package (requires ioxclient)
CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  CATALOG_PEM=/path/to/iris-catalog.pem device/iox/build.sh device/iox/out
```

`CATALOG_PEM` must be the certificate block **only** — the public cert IRIS
hands to devices, never the server's combined cert+key file (`IRIS_CERT`).
The build refuses a file carrying a private-key block, and only CERTIFICATE
blocks reach the image. The same cert-only bytes are packaged a second time
as a top-level `iris-catalog.pem` inside `artifacts.tar.gz`: that is the
pinned-cert probe member `tools/check-package-freshness.sh` and the console's
Setup "device packages" card read, so a served package can be checked
against the live certificate without unpacking its image.

`device/iox/build.sh` never downloads `aria2c`. The binary is a handed-in
deliverable, produced elsewhere by the aria2-next-static project and only
verified here — never fetched from a third party, never built in this
repository (`tools/get-aria2c.sh` and `tools/aria2c.sha256` document the same
producer/consumer split and the same verify-or-fail idiom the build uses
internally). It resolves an architecture-matched `aria2c` in order:
`ARIA2C_BIN` if set, else the matching local agent bundle
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

# IE-3400 / IE-3400 / IR: arm64 package served as iris-arm64.tar
tools/stage-iox-package.sh --arch arm64

# SSD-equipped Catalyst 9300 IOx: amd64 package served as iris-amd64.tar
tools/stage-iox-package.sh --arch amd64
```

On first use the helper downloads Cisco's pinned `ioxclient` 1.18.0.0 to
`tools/bin/ioxclient`, verifying the extracted binary against
`tools/ioxclient.sha256` and refusing a mismatch or an unrecorded version
(`IOXCLIENT_SKIP_VERIFY=1` is the explicit one-off escape hatch, which prints
the sha256 to record); that binary is git-ignored and not embedded in the
repository or seed-server image. The helper retrieves the live catalog
certificate from the running `iris` container, builds a package that pins it,
and places the result in `/srv/artifacts`. When the served host directory is not
writable by the invoking user — the normal case, since the server runs as uid
10001 and its artifacts directory is owned by that uid — the helper places the
package with `docker cp` rather than requiring a host ownership change. On an
amd64 server, the arm64 build registers Docker's ARM64 emulation handler when
it is missing, using the audited `tonistiigi/binfmt` image digest supplied via
the required `BINFMT_IMAGE_DIGEST` environment variable; with the digest unset
the build fails closed rather than pull an unpinned image.

Rebuild both packages after rotating the server certificate, because each
package contains the pinned catalog certificate. The helper only builds and
places artifacts; it never contacts or changes a device.

To check whether a served package is already stale — including after a
catalog certificate change nobody triggered locally, such as a rebuilt server
or a fresh volume — run the read-only `tools/check-package-freshness.sh`
(`--rebuild` fixes what it finds), or check the console's Settings → Setup
page, which surfaces the same drift per package. See
[TLS rotation and device packages](operations.md#tls-rotation-and-device-packages).

## Artifact handling

`iris-arm64.tar` and `iris-amd64.tar` are operator-built artifacts and belong under
`artifacts/` for serving. The server container serves them but does not rebuild
or mutate them automatically.
