<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Build and publish the device packages

Build the three packages that IOx and IOS-XR devices install, and publish them
where the server serves them: `iris-arm64.tar`, `iris-amd64.tar` and
`iris-xr.rpm`, each beside its provenance manifest.

Skip this page if you onboard only through Guest Shell. On Catalyst 9000 series
switches the agent runs in Guest Shell, and the server rebuilds that bundle
every time it starts. The IOx app is the alternative on switches with
app-hosting storage.

## Before you start

- Finish [Check the host before you install](check-the-host.md).
- Install the build tools: the two pinned `aria2c` binaries, `ioxclient`, arm64
  emulation and the appmgr builder. See
  [Download the tools that build device packages](build-tools.md).
- Have the two public root files ready. See
  [Create the two offline signing keys](signing-roots.md).
- Point `IRIS_INSTRUCTION_ROOTS_DIR` at the reviewed directory holding exactly
  two distinct public `.pub` files. Every package embeds these public roots.
- Have the server healthy, with no onboarding job fetching a package right now.

## Where to build and publish

| Layout | Build here | Publish here |
| --- | --- | --- |
| Single Docker host | Server host checkout | That Compose project's server container, `/srv/artifacts` |
| Separate Docker hosts | Server host checkout, never the Console host | Server container's `/srv/artifacts` bind mount |
| Kubernetes | Approved amd64 Docker build host, outside the pods | Server pod's PVC at `/data/artifacts`, never the Console pod |

### Docker on one host

Build in the server host's checkout once the stack is healthy:

```bash
# Build and stage both packages during server bring-up (recommended).
tools/provision-iox-packages.sh

# IE-3x00 / IR1101 / IR18xx: arm64 package served as iris-arm64.tar
tools/stage-iox-package.sh --arch arm64

# SSD-equipped Catalyst 9300 IOx: amd64 package served as iris-amd64.tar
tools/stage-iox-package.sh --arch amd64
```

`tools/stage-iox-package.sh` rebuilds one package. On first use it downloads
Cisco's pinned `ioxclient` release and checks it against
`tools/ioxclient.sha256`. Set `IOXCLIENT` to use an installation you already
have. For a full rebuild, or to publish `iris-xr.rpm`, follow
[Build the packages](#build-and-publish-the-arm64-iox-package).

The default browser identity is encrypted in `tls/console-fallback.pem.age` and
reused on restart. See
[Set up certificates and tokens](certificates-and-tokens.md).

### Docker on separate hosts

Run these commands on the server host to build both IOx wrappers and the XR
RPM and publish them:

```bash
set -a
. server/server.env
set +a
export IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"
tools/provision-iox-packages.sh
tools/build-xr-package.sh --out device/xr/out
sudo install -o 10001 -g 10001 -m 444 device/xr/out/iris-xr.rpm \
  "$IRIS_ARTIFACTS_HOST_DIR/.iris-xr.rpm.next"
sudo install -o 10001 -g 10001 -m 444 device/xr/out/iris-xr.rpm.manifest \
  "$IRIS_ARTIFACTS_HOST_DIR/.iris-xr.rpm.manifest.next"
sudo rm -f "$IRIS_ARTIFACTS_HOST_DIR/iris-xr.rpm.manifest"
sudo mv "$IRIS_ARTIFACTS_HOST_DIR/.iris-xr.rpm.next" \
  "$IRIS_ARTIFACTS_HOST_DIR/iris-xr.rpm"
sudo mv "$IRIS_ARTIFACTS_HOST_DIR/.iris-xr.rpm.manifest.next" \
  "$IRIS_ARTIFACTS_HOST_DIR/iris-xr.rpm.manifest"
```

Sourcing `server/server.env` gives these helpers the same container name and
artifact directory as Compose. For one wrapper only, follow
[Build the packages](#build-and-publish-the-arm64-iox-package).

### Kubernetes

Build outside the pods, then copy each package and its `.manifest` into the
server pod's volume. Follow
[Build the packages](#build-and-publish-the-arm64-iox-package) and use the
Kubernetes publishing commands.

Put the two approved public root files under `/data/config/instr/roots.d`. See
[Create the two offline signing keys](signing-roots.md).

## Build the packages { #build-and-publish-the-arm64-iox-package }

Use this procedure for every layout. Only the destination changes.

**1. Collect the binaries and check their architectures**, in the same shell:

```bash
tools/get-aria2c.sh amd64
tools/get-aria2c.sh --no-install arm64
tools/get-ioxclient.sh
file bin/aria2c deliverables/aria2c-aarch64
```

`file` reports x86-64 for `bin/aria2c` and ARM aarch64 for the second file.

!!! warning

    `--no-install` must come **before** `arm64`. The other order replaces the
    server's own `aria2c` with the ARM binary.

**2. Set the build environment and build the ARM wrapper** into a private
directory:

```bash
export IRIS_DEVICE_PLATFORMS=linux/amd64,linux/arm64
export IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"
export ARIA2C_BIN_AMD64="$PWD/bin/aria2c"
export ARIA2C_BIN_ARM64="$PWD/deliverables/aria2c-aarch64"
IRIS_ARM_BUILD_DIR="$(mktemp -d)"
export IRIS_DEVICE_IMAGE_OCI="$IRIS_ARM_BUILD_DIR/iris-device.oci.tar"

tools/stage-iox-package.sh --arch arm64 \
  --artifacts-dir "$IRIS_ARM_BUILD_DIR"
```

The command exits zero and writes `iris-arm64.tar` and its `.manifest` into
`$IRIS_ARM_BUILD_DIR`. Keep the image archive and its provenance in approved
build storage.

**3. Check the wrapper against its manifest:**

```bash
PYTHONPATH="$PWD/server" python3 - "$IRIS_ARM_BUILD_DIR" <<'PY'
import json, os, sys
from setup_status import package_readiness
name = "iris-arm64.tar"
result = package_readiness(os.path.join(sys.argv[1], name), name,
                           "iox", "linux/arm64", "rebuild ARM64 IOx")
print(json.dumps(result))
sys.exit(0 if result["state"] == "ok" else 1)
PY
sha256sum "$IRIS_ARM_BUILD_DIR/iris-arm64.tar" \
  "$IRIS_ARM_BUILD_DIR/iris-arm64.tar.manifest"
```

The state is `ok`. On failure, read
[If a build or publish fails](#if-a-build-or-publish-fails).

**4. Build the other two packages** in the same shell, with the same roots,
platform list and `IRIS_DEVICE_IMAGE_OCI`:

```bash
tools/stage-iox-package.sh --arch amd64 --artifacts-dir "$IRIS_ARM_BUILD_DIR"
tools/build-xr-package.sh --out "$IRIS_ARM_BUILD_DIR"
```

**5. Publish each package with its matching `.manifest`**, using the section for
your layout and the filename substituted.

### Publish to either Docker layout

Publish when the stack is healthy and no onboarding is fetching this package.
Resolve the **server** container, keeping any `-p` or `--project-name` option
you use. Run only the matching line:

```bash
# One host, from that host's checkout:
IRIS_CONTAINER="$(docker compose --env-file server/.env -f server/docker-compose.yml ps -q iris)"
# Separate hosts, from the SERVER host's checkout:
IRIS_CONTAINER="$(docker compose --env-file server/server.env -f server/docker-compose.server.yml ps -q iris)"
```

Then confirm the container and the bind mount, and copy the pair in:

```bash
test -n "$IRIS_CONTAINER"
docker inspect "$IRIS_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/srv/artifacts"}}{{.Source}}{{end}}{{end}}'
docker cp "$IRIS_ARM_BUILD_DIR/iris-arm64.tar" "$IRIS_CONTAINER:/srv/artifacts/.iris-arm64.tar.tmp"
docker cp "$IRIS_ARM_BUILD_DIR/iris-arm64.tar.manifest" "$IRIS_CONTAINER:/srv/artifacts/.iris-arm64.tar.manifest.tmp"
docker exec "$IRIS_CONTAINER" sh -ec '
  cd /srv/artifacts
  test -r .iris-arm64.tar.tmp && test -r .iris-arm64.tar.manifest.tmp
  rm -f iris-arm64.tar.manifest
  mv -f .iris-arm64.tar.tmp iris-arm64.tar
  mv -f .iris-arm64.tar.manifest.tmp iris-arm64.tar.manifest
  sha256sum iris-arm64.tar iris-arm64.tar.manifest'
```

The printed hashes equal the build-host hashes. Uid 10001 must be able to read
the files and write the destination directory. If the readability check fails,
fix the mode of the two source files on the build host and copy them again.

!!! warning

    Do not run `chown` inside the container, and do not widen the modes of
    state or secret files.

### Publish to Kubernetes

Apply your manifests and wait for the server Deployment. The example uses
namespace `iris`.

```bash
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris get pods -l app.kubernetes.io/name=iris-seed-server
IRIS_SERVER_POD="$(kubectl -n iris get pods -l app.kubernetes.io/name=iris-seed-server -o jsonpath='{.items[0].metadata.name}')"
test -n "$IRIS_SERVER_POD"
kubectl -n iris exec "$IRIS_SERVER_POD" -c iris -- test -w /data/artifacts
kubectl -n iris cp --no-preserve "$IRIS_ARM_BUILD_DIR/iris-arm64.tar" "$IRIS_SERVER_POD:/data/artifacts/.iris-arm64.tar.tmp" -c iris
kubectl -n iris cp --no-preserve "$IRIS_ARM_BUILD_DIR/iris-arm64.tar.manifest" "$IRIS_SERVER_POD:/data/artifacts/.iris-arm64.tar.manifest.tmp" -c iris
kubectl -n iris exec "$IRIS_SERVER_POD" -c iris -- sh -ec '
  cd /data/artifacts
  rm -f iris-arm64.tar.manifest
  mv -f .iris-arm64.tar.tmp iris-arm64.tar
  mv -f .iris-arm64.tar.manifest.tmp iris-arm64.tar.manifest
  sha256sum iris-arm64.tar iris-arm64.tar.manifest'
```

Match both hashes against the build host.
[`kubectl cp --no-preserve`](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_cp/)
keeps host ownership off the non-root pod, and needs `tar` in the container.

## Verify

Run `tools/check-package-freshness.sh` on the server host, or open
**Settings → Device packages** in the Console. Both print one row per package
family, and the Console prints the full build command for any family that is
missing, stale or unverifiable.

A row is ready when the readable wrapper bytes match the adjacent provenance
manifest, so keep each `.manifest` beside its package.

The same status compares the certificate the live services present with the
public copy onboarding distributes.

!!! warning

    A mismatch blocks new onboarding. Rebuilding the packages does not fix it.

## When to rebuild the packages { #embedded-agent-packages }

Every Python source file under `device/agent/` goes into the Guest Shell bundle,
both IOx packages and the IOS-XR RPM. After a change to shared agent source or
to the common device image, rebuild, republish, and redeploy each affected
device:

```bash
docker compose -f server/docker-compose.yml up -d --build
tools/provision-iox-packages.sh
tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

On Kubernetes, rebuild the server image as well, then copy every package again.

When the `aria2c` pin in `tools/aria2c.sha256` changes, refresh both handed-in
binaries, rebuild both images and every device package from them, and copy the
packages again. The agents must be file-identical across packages.

!!! warning

    A certificate rotation needs no rebuild. Re-onboard the affected devices so
    each one receives the current public certificate. See
    [Rotate credentials and certificates](../admin-guide/rotations.md).

If native signing changes the wrapper bytes, publish the signed output with a
manifest recording that output's SHA-256.

## If a build or publish fails

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `file` reports ARM for `bin/aria2c` | The ARM download replaced the server binary | Restore it with `tools/get-aria2c.sh amd64`, then collect the ARM binary with `--no-install arm64`. |
| The aarch64 client is missing, or its checksum does not match | The pinned binary was never handed in, or the download is not the pinned build | Run the download commands in the order shown. Ask for a verified hand-in when you cannot download. Never replace a pin to accept an untrusted download. |
| `exec format error`, a missing handler, or a request for a binfmt digest | The amd64 build host has no arm64 emulation | Set emulation up as [Download the tools that build device packages](build-tools.md) describes. Do not pull an unpinned privileged image. |
| No OCI exporter, or the ARM manifest is missing | The Buildx builder cannot write the archive, or only amd64 was built | Inspect the builder and set `IRIS_DEVICE_PLATFORMS=linux/amd64,linux/arm64`. Do not reuse an amd64-only archive. |
| The builder refuses to replace the existing image archive | The archive on disk came from different source | Build into the private build directory and keep the previous archive. |
| The two public roots are not available | The reviewed roots directory is missing or holds the wrong files | Get the two approved public roots the deployment already uses. Do not generate replacements. |
| The artifact directory is not writable, or the package never appears in the Console | The build wrote straight into the server-owned directory | Build into the private output directory, then publish to the server mount or volume. |
| The package row is still not ready | One of the two files, a hash, the platform or the provenance is wrong | Check both published files and their hashes, check the platform, and read the reported provenance reason. |

## Next steps

- [Verify the installation](verify.md)
- [Prepare IE-3x00 series and 8000 series devices for the IOx app](iox.md)
- [Prepare Cisco 8000 and NCS routers for IOS-XR appmgr](ios-xr.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [Upgrade to a new release](../admin-guide/upgrade.md)
