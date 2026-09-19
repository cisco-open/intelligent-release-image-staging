<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Check the host before you install

Work through this page on every host your layout uses. At the end each host
has the right size, the tools IRIS needs, a verified clock, and the code.

## Before you start

- Pick your layout. See [Install IRIS](index.md).
- Pick your devices; they decide which packages you build. See
  [Supported devices and platforms](supported-devices.md).

## Size the host

These numbers cover the control plane and telemetry for 200 devices; the
images come on top. A wave is a group of devices a schedule releases together.

| Resource | Need |
| --- | --- |
| Server | 2 vCPU, 4 GB RAM |
| Ingress | ~0.2–0.3 Mbps sustained |
| Telemetry | ≤ ~20 MB on disk, < 10 KB/s out on the LAN |
| NIC | 1 GbE, sized by image seeding: one to two times the image size per wave |

## Check Docker Engine and the tools

IRIS runs in containers. The host needs Linux, Docker Engine 23.0 or newer,
and Docker Compose. Install what is missing with your own approved method.

| Need it for | Check | Ubuntu or Debian package |
| --- | --- | --- |
| Everything | `docker version`, `docker compose version`, `docker buildx version` | `docker.io` plus the Compose plugin, or Docker's own repository |
| Everything | `id -nG \| grep -w docker` | membership in `docker`, or every command needs `sudo` |
| Encrypted server state | `command -v age age-keygen` | `age` |
| Package tools and checksums | `command -v git curl ssh-keygen sha256sum file python3 tar` | `git`, `curl`, `openssh-client`, `coreutils`, `file`, `python3`, `tar` |
| The arm64 IOx package | `grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready` | `qemu-user-static` |
| IOx and IOS-XR packaging | `command -v skopeo` | `skopeo` |
| The IOS-XR appmgr RPM | `command -v rpmbuild` | `rpm` |

Keep the `age` private identity, which unlocks the server's secrets, outside
the checkout. Give the host a stable address your devices can route to; see
[Open the required ports](open-ports.md).

### On one Docker host

This host needs every row above.

### On separate Docker hosts

The server host needs every row above. The Console host needs Docker, the
Compose plugin, and room for its image. The host that prepares the bundles
needs `python3` and SSH to both.

### On Kubernetes

The build host needs the rows above, plus a registry the nodes pull from. On
the cluster:

| Need it for | Check |
| --- | --- |
| Everything | `kubectl version --client` and `kubectl config current-context` |
| Creating the namespace and workloads | `kubectl auth can-i create deployment -A` |
| The server's persistent volume claim (PVC) | `kubectl get storageclass` |
| Reaching the server and Console | that Services of type LoadBalancer get addresses on this cluster |
| Running amd64 images | amd64 worker capacity |

Ask whoever runs the cluster to confirm that the network plugin (CNI) enforces
NetworkPolicy. Then check the storage driver (CSI):

```bash
kubectl get csidriver \
  -o custom-columns=NAME:.metadata.name,FSGROUPPOLICY:.spec.fsGroupPolicy
```

A driver that handles `VOLUME_MOUNT_GROUP` itself must keep the server pod's
private file modes. If it does not, set volume ownership out of band.

!!! warning

    Never run either container as root to work around storage ownership. If a
    mount has already widened the private modes, see [Repair a volume whose file
    permissions were changed](../admin-guide/recovery.md#recover-a-volume-whose-private-modes-were-changed).

The server PVC defaults to `50Gi`, mounted only by the server. Size it for the
images you keep; `10Gi` is enough for a small overlay.

## Get the code

Every command in the Installation Guide runs from the checkout. Create it and
clone into it, with your own path in the first line:

```bash
IRIS_DIR=/opt/iris/intelligent-release-image-staging
(
  set -eu
  if [ -e "$IRIS_DIR" ] || [ -L "$IRIS_DIR" ]; then
    echo "Checkout path already exists; inspect and reuse it instead of cloning." >&2
    exit 1
  fi
  sudo install -d -o "$(id -un)" -g "$(id -gn)" "$IRIS_DIR" &&
    git clone https://github.com/cisco-open/intelligent-release-image-staging \
      "$IRIS_DIR"
) && cd "$IRIS_DIR"
```

The clone finishes and you land in the checkout. Stop if it fails.

!!! warning

    Never change the ownership of the parent directory.

## Verify time before deployment

Run this on each Docker host, and on every Kubernetes node that can run an
IRIS pod:

```bash
bash tools/check-host-time.sh
```

It passes. If it fails, configure the host's approved NTP service, then confirm
its selected peer with `chronyc tracking` and `chronyc sources -v`. A running
service is not proof of synchronization, so keep watching the host clock.

!!! warning

    Do not run NTP inside the IRIS containers, and do not grant `SYS_TIME` or
    privileged mode. Containers take the clock of their node: fix the host.

A certificate the host reports as not yet valid is often a clock problem; see
[Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md#time-synchronization).

## Let the server read the image tree

Store Cisco image files outside Git, normally under `/opt/images`. The tree
bind-mounted there (`IRIS_IMAGE_ROOT`) must be readable and traversable by uid
`10001`, the user both containers run as. A `755` tree works; a `700`
root-owned tree fails.

## Verify

On every host, at the same IRIS version:

- Docker Engine, Compose and buildx report 23.0 or newer, and every
  `command -v` check above returns a path.
- `df -h` shows room for two builds, the server image, and your images.
- `bash tools/check-host-time.sh` passes, and NTP reports a selected peer.
- The image tree is readable and traversable by uid `10001`.
- On Kubernetes: NetworkPolicy is enforced, the driver keeps private file
  modes, and the PVC fits your images.

## Next steps

- [Supported devices and platforms](supported-devices.md)
- [What a device needs before onboarding](device-requirements.md)
- [Download the tools that build device packages](build-tools.md)
- [Install IRIS](index.md)
