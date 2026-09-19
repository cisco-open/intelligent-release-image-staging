<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Download the tools that build device packages

Get the tools that build the IRIS device packages. Run every command from your
IRIS checkout, on the host where the Docker daemon builds packages. Skip this
page on the Console host.

## Before you start

Supply what the devices you plan to onboard need.

| What you will onboard | Supply first |
| --- | --- |
| Server and Console only, no devices yet | `aria2c` amd64 |
| Guest Shell on Catalyst 9000 series switches and Catalyst 8000 series routers | `aria2c` amd64, the two roots |
| IOx app on Catalyst 9000 series switches and Catalyst 8000 series routers | `aria2c` amd64, `ioxclient`, the two roots |
| IOx app on Industrial Ethernet 3000 series switches and IR 1100 and 1800 series routers | the amd64 set, plus `aria2c` arm64 and ARM64 emulation |
| IOS-XR appmgr on Cisco 8000 series and NCS routers | `aria2c` amd64, the two roots, Docker and network access |

On Catalyst 9000 series switches the agent runs in Guest Shell. On switches with
app-hosting storage, the IOx app is the alternative.

The two roots are the public signing keys every device package embeds: see
[Create the two offline signing keys](signing-roots.md). For which models take
which installer, see [Supported devices](supported-devices.md).

## 1. Get the aria2c client

`aria2c` is the transfer client the server and every device agent run. Every
deployment needs the amd64 client. Run these in the shell that builds the
packages. For both architectures:

```bash
export IRIS_DEVICE_PLATFORMS=linux/amd64,linux/arm64
tools/get-aria2c.sh amd64
tools/get-aria2c.sh --no-install arm64
```

The amd64 client lands in `bin/aria2c`, the arm64 client in `deliverables/`.

For an amd64-only package set:

```bash
export IRIS_DEVICE_PLATFORMS=linux/amd64
tools/get-aria2c.sh amd64
```

!!! warning

    Keep `--no-install` before `arm64`. In any other order the arm64 binary
    replaces `bin/aria2c`, and the next server image build fails its
    architecture check.

## 2. Get ioxclient

IOx device types need Cisco's IOx packaging command line tool, on Linux amd64.

```bash
tools/get-ioxclient.sh
```

The tool installs at `tools/bin/ioxclient`, checked against
`tools/ioxclient.sha256`. Set `IOXCLIENT` to use your own copy.

## 3. Check ARM64 emulation

Building the arm64 IOx package on an amd64 host needs QEMU emulation. Check the
host:

```bash
grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready
```

`ready` means the handler is registered and turned on. If the command prints
nothing, install your distribution's static QEMU package, `qemu-user-static` on
Ubuntu and Debian, then check again. The builders can also register the handler
for you, from the `tonistiigi/binfmt` image named by digest in
`BINFMT_IMAGE_DIGEST`.

## 4. Install skopeo and rpmbuild

The builders read the device image archive with `skopeo`, and the IOS-XR
builder assembles its package with `rpmbuild`. Install both with your package
manager. Debian and Ubuntu ship `rpmbuild` in the `rpm` package.

## 5. Prepare the IOS-XR appmgr builder

`tools/build-xr-package.sh` wraps the device image as an appmgr RPM package
file. Its first run clones Cisco's `ios-xr/xr-appmgr-build` into
`~/.cache/iris/xr-appmgr-build`, so it needs Docker and network access.
`tools/start-compose-server.sh` runs the builder for you, and `IRIS_SKIP_XR=1`
skips it where no IOS-XR device is in scope. Run it directly on a later
rebuild:

```bash
tools/build-xr-package.sh --out artifacts/
```

## Verify

Run the lines that match the device types in your scope, from the checkout:

```bash
file bin/aria2c deliverables/aria2c-aarch64
ls -l tools/bin/ioxclient
command -v skopeo rpmbuild
grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready
```

`file` reports x86-64 then ARM aarch64. The rest print the `ioxclient` path,
the two tool paths, and `ready`.

## Next steps

- [Build the server and Console images](build-images.md)
- [Build and publish the device packages](device-packages.md)
- [Install on one Docker host](one-docker-host.md)
