<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path runs the agent as a Docker-based IOx application. It supports
ARM64 IE-3x00/IE-3400 style platforms and x86_64 Catalyst 9000 app hosting.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle. The
Guest Shell path remains available for Catalyst devices that support that agent
model. The staging target is platform-appropriate: `sdflash:` on IE-3x00;
Console-onboarded C9300 IOx targets `flash:` (bootflash, like Guest Shell)
with the SSD share carrying the transfer.

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
(`/iox_data/iris` on the validated C9300 runtime). The hand-off of the verified
scratch file to IOS depends on the platform:

- **C9k (share mount)**: onboarding bind-mounts the app-hosting SSD share —
  `usbflash1:iox_host_data_share`, host-side `/vol/usb1/iox_host_data_share` —
  into the container (`run-opts "-v …:/mnt/share"`). The agent copies the
  scratch to the share ROOT under its fixed `iris-staged.bin` name at disk
  speed, then drives an IOS-internal
  `copy /verify usbflash1:iox_host_data_share/iris-staged.bin flash:<img>`
  over its SSH-to-self CLI — the same bootflash-root placement as Guest
  Shell, with no bulk data on the control-plane punt path, and `copy /verify`
  restores the real image name and checks the Cisco signature from the bytes.
  IRIS never creates a subdirectory in the share (a container-created subdir
  becomes inaccessible to the container itself on this platform) and confines
  itself to `iris-` prefixed filenames: each attempt sweeps only its own
  leftovers, a tiny probe proves IOS can actually read the share before any
  multi-GB copy is committed (falling back to scp otherwise), the transient
  copy is removed after placement, and undeploy deletes the prefixed files.
- **IE-3x00 (scp push)**: IOx cannot bind-mount the SD card there, so the
  container SCP-pushes the scratch to `guest-share/iris` through the device's
  SCP server and then runs `copy /verify` for the final placement. The agent
  also falls back to this path automatically if the share mount is absent or
  unreadable from IOS.

`IRIS_TARGET_FS` optionally selects a filesystem prefix such as `sdflash:` or
`bootflash:`. The agent accepts it only when `show file systems` reports a
writable non-crash disk; otherwise it logs the fallback and retains automatic
platform selection. `device/iox/install.sh` exposes this as `TARGET_FS` and
defaults it to `sdflash:`.

## Transfer throughput and CoPP

The C9k share-mount hand-off above never carries image bytes over the network,
so it is not subject to any of this section — it runs at disk speed. This
section applies to the **scp push path** (IE-3x00, or a C9k where the share
mount is unavailable and the agent fell back): that traffic is addressed to
the switch itself, so it crosses the control-plane punt path and is subject to
Control Plane Policing (CoPP). On Catalyst 9300 the default CoPP policy caps
that path long before any transport setting does. Measured on C9300
(IOS-XE 17.18.3):

| Transfer path | Throughput | Notes |
| --- | --- | --- |
| Agent SCP push (default CoPP) | ~1.4 MB/s | identical for chacha20, aes128-gcm, aes128-ctr |
| IOS `copy https:` pull (default CoPP) | ~1.4 MB/s | same ceiling — not a protocol property |
| Agent SCP push, forus policer at 10000 pps | ~7.3 MB/s | next limit is the IOSd file-write path |

The ceiling is the `system-cpp-police-forus` CoPP class: its default
1000 packets/sec ≈ 1.4 MB/s of full-size frames, and the policer visibly drops
the transfer's frames (`show platform hardware fed switch active qos queue
stats internal cpu policer`). Raising `ip ssh window-size`,
`ip tcp window-size`, or `ip ssh bulk-mode` does not help on 17.18 — bulk-mode
and the 128 KB TCP window are already platform defaults there, and the policer
sits below all of them.

**IRIS never modifies CoPP.** The policer protects the switch CPU from
traffic floods; weakening it is a security decision only the operator can
make. Until a faster transfer path exists in IRIS, an operator who accepts the
tradeoff can raise the class on devices that stage over IOx:

```text
configure terminal
policy-map system-cpp-policy
 class system-cpp-police-forus
  police rate 10000 pps
end
```

This yields roughly 5x faster staging (a 1.2 GB image drops from ~15 to ~3
minutes); `police rate 1000 pps` restores the default. The change does not
affect the actual network: transit traffic is forwarded in hardware and never
crosses this policer, so no data-plane, VLAN, or routing behavior changes. Its
only effect is on the switch's own control plane — the CPU will accept more
traffic addressed to the switch itself, which is the resource CoPP exists to
protect.

Guest Shell staging is unaffected: the C9300 Guest Shell writes through the
bind-mounted guest-share at disk speed and never crosses the punt path.

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

The clean-clone build path downloads a pinned architecture-matched static
`aria2c` when no local bundle is available and fails if its SHA-256 digest
differs. For package builds, `tools/stage-iox-package.sh` downloads Cisco's
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

# IE-3x00 / IE-3400 / IR: arm64 package served as iris-arm64.tar
tools/stage-iox-package.sh --arch arm64

# SSD-equipped C9300 IOx: amd64 package served as iris-amd64.tar
tools/stage-iox-package.sh --arch amd64
```

On first use the helper downloads Cisco's pinned `ioxclient` 1.18.0.0 to
`tools/bin/ioxclient`; that binary is git-ignored and not embedded in the
repository or seed-server image. The helper retrieves the live catalog
certificate from the running `iris` container, builds a package that pins it,
and places the result in `/srv/artifacts`. If Docker created the default bind
mount as root, the helper uses `docker cp` rather than requiring a host ownership
change. On an amd64 server, the arm64 build automatically registers Docker's
ARM64 emulation handler when it is missing.

Rebuild both packages after rotating the server certificate, because each
package contains the pinned catalog certificate. The helper only builds and
places artifacts; it never contacts or changes a device.

## Artifact handling

`iris-arm64.tar` and `iris-amd64.tar` are operator-built artifacts and belong under
`artifacts/` for serving. The server container serves them but does not rebuild
or mutate them automatically.
