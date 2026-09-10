<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IOx App

The IOx path runs the agent as a Docker-based IOx application. It supports
ARM64 IE-3400 style platforms and x86_64 Catalyst 9300 and Catalyst 8000V app
hosting. IOx and IOS-XR package the same canonical device image and run the same entrypoint;
`IRIS_DEVICE_PLATFORM=iox` selects this profile.

## When to use it

Use the IOx app when the platform expects an IOx application lifecycle. The
Guest Shell path remains available for Catalyst devices that support that agent
model. The staging target is platform-appropriate and selected by the existing
live filesystem/model policy rather than a second platform knob: IE-3400
normally selects `sdflash:`, while Catalyst 9300 normally selects `flash:`
(bootflash, like Guest Shell) and uses the SSD share to carry the transfer. The table in
[Device Agents](device-agents.md#platform-targets) reflects the same rule.

The installer first pastes the catalog trustpoint over its authenticated,
host-key-checked SSH session — the same block the Guest Shell installers
use — and then has the **device** fetch the package, the public catalog
certificate and its sealed instruction envelope from the artifact server with
`copy https:`, validated against that trustpoint. Each copy authenticates
with the device's own enrollment credential (HTTP Basic: the device id and
its enrollment token, the artifact API's resource-bound form), which the
controller configures as `ip http client username` / `ip http client
password` for the span of that copy and removes right after it. The token
never enters a URL or a job log (it is redacted from every capture and
transcript), and the envelope is published under `staging/<device-id>/` for
that one fetch. Package delivery uses HTTPS; a device whose running-config
already carries an operator's `ip http client username` or `password` is refused at preflight
rather than having them overwritten. `ip scp server enable` is configured for
the agent, not the installer, and only on a platform with no bind-mounted
share (IE-3400 or Catalyst 8000V): the runtime image hand-off described below
pushes the downloaded image to `guest-share` through the device's SCP server.
A Catalyst 9300 job uses its configured SSD share, and onboarding leaves that
device's SCP server untouched.

IOx preflight requests the app list, narrowly filtered IRIS collision lines,
and counts of HTTP client credential settings. It does not request the full
running configuration or stored password values. Each count is checked against
its own completed command response; missing or ambiguous evidence stops the
job. Transcripts retained by older builds may still contain full configuration
and must be treated as sensitive.

## Catalyst 8000 routers

A Catalyst 8000 router has no `AppGigabitEthernet`. With platform `iox` on a
`router-routed` or `router-nat` row, the installer creates the same
IRIS-owned `VirtualPortGroup<N>` (and, for `router-nat`, the same NAT ACL,
overload rule and BitTorrent static translation) that the Guest Shell router
recipe creates, attaches the app with `app-vnic gateway0 virtualportgroup N`,
and points its SSH-to-self at the VPG address. The package is the amd64 IOx
tar and the staging target is `bootflash:`, reached over the scp push — a
C8000V cannot bind-mount its bootflash into the app — see the hand-off
section below.
Teardown removes the app and the VPG, and un-marks a NAT outside interface
only when the deployment record says IRIS marked it. Package verification is
handled exactly as below — the controller disables and restores the
device-global setting around an unsigned install — so nothing needs to be
changed by hand on the router first.

## Device-global package verification

Before onboarding, inspect `show app-hosting infra` and the other IOx apps on
the device. Verification is device-global, so a change affects more than IRIS.
Prefer a natively signed wrapper and keep verification enabled. The controller
in `server/iox_verification.py`, consumed by `device/iox/install.sh`, owns the
entire transaction:

| Wrapper / initial observation | Owned behavior |
| --- | --- |
| Signed marker present | No verification-state change. Native signature verification depends on platform enforcement being enabled; marker presence alone is not cryptographic validation. |
| Unsigned / `enabled` | Durably record the initial state and restoration obligation; disable only for installation; restore and read-back before activation/start. |
| Unsigned / `disabled` | Leave disabled; no unowned enable operation. |
| Unsigned / `unknown` | Refuse mutation and installation. Obtain readable platform evidence first. |

Interruption/resume and uninstall recovery use durable obligations. They do
not blindly enable an operator-changed or unowned state. Inspect the onboarding
job and deployment record before retrying; unresolved restoration blocks
progress. This is the current supported unsigned transaction, not evidence of
production signing. Current proof artifacts are unsigned.

Cisco documents signature enforcement, SD/bootflash restrictions and the global
setting in the [IE-3x00 IOx deployment guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/cisco_ie3X00/software/17_14/b_cisco-iox-ie3x00-switches/m-ie3400-deploying-iox-applications.html).
The [Catalyst 9000 App Hosting guide](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/222780-understand-app-hosting-on-catalyst-9000.html)
limits disabling verification to USB/SSD media. Platform/media signature
refusals remain failures; do not interpret an unsigned build as proof that
activation succeeds after verification is restored. The claim that the
container never changes in the field depends on a natively signed IOx wrapper
and platform verification remaining enabled.

The enrollment bearer and SSH-to-self password remain in IOx `run-opts`,
readable by a privileged device administrator and potentially diagnostic
output. Enrollment defaults to 3,600 seconds (one hour), followed promptly by
authenticated refresh with normal 120-second token overlap. Instruction keys,
LKG keys, online signing private keys and offline-root private keys never enter
`run-opts` or installer arguments. The agent's mode-0600 config receives
instruction keys only from refresh. F3 redelivery uses an encrypted bootstrap
envelope through the controller's application-data channel; see
[offline recovery](operations.md#f3-offline-bootstrap-envelope-redelivery).

## Files

| File | Purpose |
| --- | --- |
| `device/container/Dockerfile` | Builds the canonical multi-architecture IOx/XR agent container. |
| `device/container/entrypoint.sh` | Validates `IRIS_DEVICE_PLATFORM` and supervises either runtime profile. |
| `device/iox/package.yaml` | ARM64 IOx package metadata. |
| `device/iox/package-amd64.yaml` | x86_64 IOx package metadata. |
| `device/iox/build.sh` | Packages the canonical image in the IOx envelope. |
| `device/iox/install.sh` | Private controller recipe for IOx onboarding. |
| `device/iox/uninstall.sh` | Private controller recipe for IOx removal. |

Submit jobs through the Console, API, or [IOx control CLI](reference.md#iox-control-cli).
The recipes require the controller's private channel and cannot be run standalone.

## Runtime behavior

The IOx agent follows the same catalog and staging model as the Guest Shell
agent. It downloads resumable swarm data under the CAF persistent directory
(`/iox_data/iris` on the validated Catalyst 9300 runtime).

The IOx package contains no deployment certificate. On every onboarding,
the controller validates the current public certificate from the served
artifacts directory, has the device fetch it over HTTPS, and uses IOS-XE's
`app-hosting data` channel to copy it into the app's application-data directory
after activation and before app start. Activation mounts application storage;
the `DEPLOYED` state cannot accept the copy. The entrypoint requires and validates
that runtime-delivered certificate before it starts either the catalog client
or the aria2 tracker client.

The hand-off of the verified scratch file to IOS depends on the platform:

- **Catalyst 9300 (share mount)**: onboarding bind-mounts the app-hosting SSD share —
  `usbflash1:iox_host_data_share`, host-side `/vol/usb1/iox_host_data_share` —
  into the container (`run-opts "-v …:/mnt/share"`). The agent copies the
  scratch to the share ROOT under its fixed `iris-staged.bin` name at disk
  speed, then drives an IOS-internal
  `copy usbflash1:iox_host_data_share/iris-staged.bin flash:<img>.iris-tmp`
  over its SSH-to-self CLI. After confirming the temporary file matches the
  catalog's exact byte size, the agent renames it to the final image name and
  confirms the final size and the temporary file's absence. The image was
  already verified by SHA-256 against the catalog before the placement copy; the catalog can separately
  verify authenticity against Cisco's signed Bulk Hash feed, and a mismatch
  quarantines the image. IRIS never creates a subdirectory in the
  share (a container-created subdir becomes inaccessible to the container
  itself on this platform) and confines
  itself to `iris-` prefixed filenames: each attempt sweeps only its own
  leftovers, a tiny probe proves IOS can actually read the share before any
  multi-GB copy is committed, the transient copy is removed after placement,
  and undeploy deletes the prefixed files.
- **Catalyst 8000V (scp push)**: the router exposes no IOS-visible directory
  to an IOx app (verified on IOS-XE 17.15.5: CAF accepts a `-v` run option for
  `bootflash:iox_host_data_share` but never mounts it, and `app-hosting data`
  copies only into the app), so it uses the same scp push as the IE-3400 and
  its SCP server stays enabled. Measured alternative, not implemented: IOS
  pulling the staged file from the app with `copy http://<app-ip>` moved a
  973 MB image in 153 s against about 124 s over scp.
- **IE-3400 (scp push)**: IOx cannot bind-mount the SD card there, so the
  container SCP-pushes the scratch to `guest-share/iris` through the device's
  SCP server. As on the other IOx paths, IOS copies it to `<img>.iris-tmp`,
  the agent verifies the exact byte size, then renames it and confirms the
  final size and temporary file's absence. This scp traffic is addressed to
  the device itself, so default CoPP caps it at roughly 1.4 MB/s; IRIS never modifies CoPP.

There is no fallback between the two. Onboarding enables the device's SCP
server (`ip scp server enable`) **only on platforms with no share**, whose
agents need it. Where a share is configured, an unusable share (not mounted,
unreadable from IOS, or a failed local copy into
it) fails the placement with a `ROOTCOPY-FAIL` naming what the share probe
found, rather than pushing the same bytes over a control plane the device is
not even listening on. Nothing is deleted and no placement command runs in
that case; the agent retries on later ticks.

Both hand-off paths drive IOS over the app's SSH-to-self CLI for placement and
reclaim commands at the target-FS root. That connection can optionally be
pinned: set `device_ssh_known_hosts` in the agent config
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
those layers are already cached. The controller allows 300 seconds by default
for each install, activation, and start phase, within the remaining overall
session deadline (7,200 seconds by default). Each onboarding lifecycle wait
makes at most 24 state polls, spaced adaptively across the remaining phase
budget with a default five-second minimum, and returns as soon as the state is reached. These are
controller-owned limits, not shell environment overrides. A failed wait names
the failed step in the job log; enable **Detailed logs** when submitting the
job to include its command output.

An onboard that fails at activation leaves the app-hosting configuration in
place, because the activation may still be in flight. That is deliberate and
does **not** need an undeploy or a forced teardown: press **Onboard** again in
the Console, submit the onboard API request, or use the IOx control CLI's
`submit-install` command. Preflight treats an IRIS app that
is `DEPLOYED` or `ACTIVATED` but never started as a resumable retry. The
installer removes that incomplete app before retrying. An app that is
`RUNNING` is a live deployment and requires undeploy first.

## Build modes

Builds require exactly two distinct approved public-root `.pub` files in
`IRIS_INSTRUCTION_ROOTS_DIR` (or `--instruction-roots-dir DIR`). Use
`ARIA2C_BIN_AMD64` and `ARIA2C_BIN_ARM64` for the current pinned binaries when
older fallback artifacts remain on disk; architecture/checksum verification
fails closed. These public-root inputs do not provide native package signing.

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
included in the shared device image. If a canonical archive already exists
for the same `VERSION`, the builder refuses to overwrite it after a source
change. Set `IRIS_FORCE_DEVICE_IMAGE_BUILD=1` to replace that local build, or
set `IRIS_DEVICE_IMAGE_OCI` to a new archive path. Both wrapper builders must
use the same archive. Certificate rotation alone does not require a rebuild.

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
The IOx installer makes no verification-state change for a wrapper carrying
signature metadata; only native platform verification establishes authenticity.
For unsigned wrappers, use the [owned transaction](#device-global-package-verification).

For a source change, rebuild the package and obtain a new signature. For a
certificate change, re-onboard using the existing package so the installer
replaces only the runtime trust file.
