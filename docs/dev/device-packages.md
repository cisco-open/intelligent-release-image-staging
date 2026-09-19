<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Building the device image, IOx wrappers, IOS-XR rpm and aria2c

This page is for a contributor who builds the device packages. That is the
one shared container image that IOx and IOS-XR appmgr both run, the IOx
tars, the IOS-XR RPM, and the `aria2c` binary all three carry. It covers the
files that define the image, the commands that build each package, and what
a package provenance manifest records. It also covers how to build `aria2c`
yourself or set up ARM64 emulation when the published release is out of
reach.
[Build and publish the device packages](../zensical/install/device-packages.md)
is the operator procedure that runs these same builds during a deployment;
this page is the detail underneath it.

## Why the server and Console builds pass `--pull`

The server and Console images are unrelated to the device packages above, but
their build command carries the same floating-tag hazard, so the reason
belongs here rather than nowhere. Their base, `python:3.12-slim-trixie`, is a
floating tag: without `--pull`, `docker compose ... build` reuses whatever
copy the host already cached, which can be weeks behind on Debian security
updates. `tools/start-compose-server.sh` passes `--pull` for you; a manual
`docker compose build` needs it added by hand.

## Files

These files define and build the shared image and package it for each
platform:

| File | What it does |
| --- | --- |
| `device/container/Dockerfile` | Builds the one multi-architecture image IOx and IOS-XR appmgr both run. |
| `device/container/entrypoint.sh` | Checks the required `IRIS_DEVICE_PLATFORM` value and runs the matching profile. |
| `device/iox/package.yaml` | ARM64 IOx package metadata. |
| `device/iox/package-amd64.yaml` | x86_64 IOx package metadata. |
| `device/iox/build.sh` | Wraps the image in the IOx package format. |
| `device/iox/install.sh` | The controller-side recipe for IOx onboarding. |
| `device/iox/uninstall.sh` | The controller-side recipe for IOx removal. |

## Build modes

A build needs exactly two distinct approved public root files (`.pub`) in
`IRIS_INSTRUCTION_ROOTS_DIR`, or passed with `--instruction-roots-dir DIR`.
Set `ARIA2C_BIN_AMD64` and `ARIA2C_BIN_ARM64` to point at the current pinned
`aria2c` binaries when older ones are still sitting in the fallback
locations; a mismatched architecture or checksum stops the build. These
public roots do not provide native package signing on their own.

A build always writes one OCI archive holding one image manifest per CPU
architecture, under one multi-architecture identity, together with an
adjacent `.manifest` file recording its index, archive and source digests.
`--image-only` still builds and verifies both `linux/amd64` and
`linux/arm64`; an architecture flag only selects a later native wrapper. The
default output is `artifacts/iris-device-$VERSION.oci.tar`.

```bash
# Docker image only
device/iox/build.sh --image-only

# Docker image plus Cisco iris-arm64.tar package (requires ioxclient)
device/iox/build.sh device/iox/out

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  device/iox/build.sh device/iox/out
```

Build the IOS-XR wrapper from the same shared image:

```bash
tools/build-xr-package.sh --out artifacts/
```

For the normal Compose workflow, run `tools/provision-iox-packages.sh` after
the server becomes healthy. It fetches the pinned Cisco `ioxclient` tool on
the Linux server when needed, and places both architecture-specific packages
and their provenance manifests in served artifacts. Use
`tools/stage-iox-package.sh --arch arm64` or `--arch amd64` only when
rebuilding a single package. Building the arm64 package on an amd64 host
needs the ARM64 emulation covered below; without it,
`tools/stage-iox-package.sh` stops with an error.

`device/iox/build.sh` and `tools/build-xr-package.sh` place the same amd64
image inside their own native envelope, an `ioxclient` package or an appmgr
RPM. The outer tar and RPM differ in format, but the image configuration and
root filesystem digest embedded in each must match. Signing the OCI
identity therefore signs one shared payload. A deployment that also requires
a native IOx or RPM signature still signs that envelope separately. Each wrapper is
published next to a `.manifest` tying its own SHA-256 and selected platform
back to those shared digests. The build accepts no `CATALOG_PEM`,
`CATALOG_PEM_URL`, or certificate fingerprint as input: neither the image nor
its wrappers carry
any deployment-specific trust material, so one signed set of packages works
across every deployment. The current public certificate stays a required
onboarding input, and it never includes the server's private key.

Rebuild the shared image and every native wrapper after a change to any
source the device image carries. If an archive already exists for the same
version, the builder refuses to overwrite it once that source has changed.
Set `IRIS_FORCE_DEVICE_IMAGE_BUILD=1` to replace it, or point
`IRIS_DEVICE_IMAGE_OCI` at a new archive path instead. Both wrapper builders
must use the same archive. Rotating the deployment certificate alone does not
need a rebuild.

When the pinned `aria2c` in `tools/aria2c.sha256` changes, refresh both the
`ARIA2C_BIN_AMD64` and `ARIA2C_BIN_ARM64` inputs and rebuild every device
package from them. The embedded `aria2c` binary must stay file-identical
across every published package.
[Build and publish the device packages](../zensical/install/device-packages.md)
covers when an operator has to run this rebuild and publish the results.

## Package footprint

Measure the shared OCI image per platform by compressed layer bytes and
uncompressed root filesystem bytes, using the current archive and its
adjacent manifest for identity. Measure the IOx tars and the IOS-XR RPM
separately, because their native envelopes differ. Guest Shell bundles and
staged IOS images are separate artifacts again.

The shared Alpine runtime carries OpenSSH and `sshpass` for IOx, a small set
of diagnostic tools, the agent sources, and an `aria2c` matched to its
architecture. The IOx descriptor's `memory: 768` and `disk: 2048` values are
runtime quotas in MB, not package sizes. The runtime drops unused Python
package installers and applies the upstream Expat security backport until
the pinned Python base carries it. Run
`device/container/tests/check_runtime.py` inside each built architecture to
check the dependency floors, the agent's imports, and HTTPS and SSH signature
verification.

The build never downloads `aria2c` itself; see
[Build the aria2c client from source](#build-the-aria2c-client-from-source)
for where it comes from instead.

The provenance manifest beside the archive records `index_digest`,
`archive_sha256`, `source_sha256`, and the two platforms. A matching archive
is reused as is; an existing archive whose manifest or source digest does not
match is refused unless `IRIS_FORCE_DEVICE_IMAGE_BUILD=1` allows the
replacement. A replacement build runs in a private sibling directory, and
each file is published by rename, so neither the archive nor its manifest is
ever visible half-written. The old manifest is removed before the new
archive appears, so a reader always finds either matching provenance or
none, never a stale manifest beside new bytes. Each IOx tar and the IOS-XR
RPM publish the same way, each with its own adjacent `.manifest` tying its
SHA-256 and platform back to those three digests.

The shared device image has one filesystem layer, so IOx cannot restore an
older library or a deleted file by mounting layers out of order. IOx and
IOS-XR appmgr still use the same architecture-matched image.

## Build the aria2c client from source

The build resolves each architecture-matched `aria2c` in order. First it
tries the `ARIA2C_BIN_AMD64` or `ARIA2C_BIN_ARM64` override, if set. Next it
tries the matching local agent bundle, whose `aria2c` is still
checksum-verified since a bundle's origin is not otherwise pinned. Last it
tries the committed `deliverables/aria2c-<arch>` binary, checksum-verified
against `tools/aria2c.sha256`. With none of those present the build stops
with an error; there is no network fallback. A clone already carries the
tested clients for both architectures — `bin/aria2c`,
`deliverables/aria2c-x86_64` and `deliverables/aria2c-aarch64` are committed —
so nothing is downloaded. `tools/get-aria2c.sh` re-verifies them and fetches
the published release only when one of those files is missing; see
[Download the tools that build device packages](../zensical/install/build-tools.md).

Build your own binary only when you are adopting a different build. Accept a
hand-in instead, at `deliverables/aria2c-<cpu>` or pointed to by
`ARIA2C_DELIVERABLE`, or build it from the producer this repository ships:

```bash
mkdir -p tools/aria2c-build/vendor
git clone https://github.com/AnInsomniacy/aria2-next \
  tools/aria2c-build/vendor/aria2-next
git -C tools/aria2c-build/vendor/aria2-next checkout v2.5.6
(cd tools/aria2c-build && ./build.sh x86_64)
```

`build.sh` needs Docker, and refuses to run unless the checkout sits at that
pinned commit and every patch in `tools/aria2c-patches/` applies cleanly, so
a build either matches the published patch set or fails outright.

A binary you build will not match `tools/aria2c.sha256`, and that is
expected: a different toolchain or musl version produces different bytes,
and `tools/get-aria2c.sh` fails closed on the mismatch. Adopting your own
build is therefore a deliberate step:

```bash
cp tools/aria2c-build/out/x86_64/aria2c deliverables/aria2c-x86_64
sha256sum deliverables/aria2c-x86_64
```

Edit `tools/aria2c.sha256` in place with that digest, and leave it
world-readable. `server/Dockerfile` copies it into the server image and
reads it as the runtime user. An atomic write through a temporary file lands
as mode `0600` by default, and that mode breaks the build that uses it.
Check the mode after editing:

```bash
chmod 0644 tools/aria2c.sha256
ls -l tools/aria2c.sha256
```

Then `tools/get-aria2c.sh amd64` installs it. Never edit that file to
silence a mismatch on a binary you did not build yourself. There, the
mismatch is the mechanism working: a mismatch on a downloaded asset means
the asset is wrong and must not be adopted.

The `aarch64` build is the expensive one: it compiles under emulation, takes
tens of minutes, and keeps every core busy, because the whole toolchain runs
emulated. Needing it at all means the release could not be reached, so try
that first. If you do have to build it, launch it detached, so a closing
session cannot cancel the `buildx` client, and leave Docker's build cache
alone:

```bash
(
  cd tools/aria2c-build || exit 1
  setsid nohup ./build.sh aarch64 > build-aarch64.log 2>&1 < /dev/null &
  echo $! > build-aarch64.pid
)
```

A detached build leaves no exit status behind. It finished once the log ends
with a size gate, `UNDER TARGET` or `OVER TARGET`, never `HARD FAIL`, and
`out/aarch64/aria2c` exists:

```bash
grep -E 'HARD FAIL|OVER TARGET|UNDER TARGET' tools/aria2c-build/build-aarch64.log
ls -l tools/aria2c-build/out/aarch64/aria2c
```

`tools/aria2c-build/README.md` covers the patch set, the pinned toolchain,
and what to do when an upstream Alpine security update withdraws one of the
pins.

## Resolve ARM64 emulation for the build host

An amd64 host needs ARM64 emulation to build the arm64 IOx package, whose
image runs `apk add` and `chmod` steps inside the target platform. The host
also needs it to build the `aarch64` `aria2c` binary in the fallback case
above.
[Download the tools that build device packages](../zensical/install/build-tools.md)
covers checking whether the host already has a working handler and
installing the distribution package that provides one. Run those checks on
the host where the Docker daemon builds the packages, not on the Console
host or a Kubernetes worker chosen at random.

When no handler is registered, the builders register one themselves, and
require an audited `tonistiigi/binfmt` digest rather than a floating tag.
Review the tag you intend to use, resolve it to a digest, and export it:

```bash
docker buildx imagetools inspect tonistiigi/binfmt:<reviewed-tag> \
  --format '{{println .Manifest.Digest}}'
export BINFMT_IMAGE_DIGEST=sha256:<the digest printed above>
```

With the digest unset, the build fails instead of pulling an image nobody
reviewed.

Use a Buildx builder that supports multi-platform OCI export. Reuse an
approved one, or, once it is approved, create a dedicated
`docker-container` builder:

```bash
docker buildx create --name iris-device-builder --driver docker-container
export BUILDX_BUILDER=iris-device-builder
docker buildx inspect --bootstrap "$BUILDX_BUILDER"
```

If that name already exists, inspect it instead of recreating it, and
confirm its platform list includes `linux/amd64` and `linux/arm64`. IRIS
exports an OCI archive, so do not substitute `--load` or assume the default
Docker driver can export one. See
[OCI exporters](https://docs.docker.com/build/exporters/oci-docker/).

## The ioxclient packaging profile

`ioxclient` refuses every command, `--help` included, until a configuration
file exists in its home directory, and it tries to create one by asking
questions on the terminal. A scripted build would stop at that prompt before
it packaged anything.

`device/iox/build.sh` avoids this itself: for the length of the `ioxclient
package` call, it points `HOME` at a scratch directory holding an inert
profile it writes there. That profile names `localhost` and a placeholder
credential, and the build discards it with the rest of the build context.

Packaging never reaches a device: it assembles and signs a directory,
offline. Because packaging runs with this throwaway profile in place, an
ordinary operator profile, which may hold a real device address and
credential, plays no part in it. IRIS reaches devices through its own
onboarding, never through `ioxclient`.

Set `IOXCLIENT_HOME` to a directory holding a prepared `.ioxclientcfg.yaml`
only when a build must use one particular profile. Do not create one for an
ordinary build, and never put a real device credential in one.

## Related

- [Build and publish the device packages](../zensical/install/device-packages.md):
  the operator procedure that runs these builds and publishes the results.
- [Download the tools that build device packages](../zensical/install/build-tools.md):
  the pinned `aria2c` clients a clone already carries, and checking for ARM64
  emulation before you fall back to building anything yourself.
- [Components and images](../zensical/architecture/components.md):
  what the shared image and its packages run inside IOx and IOS-XR appmgr.
- [Writing and building the docs](documentation.md):
  the pinned tool versions for `aria2c` and `ioxclient`.
