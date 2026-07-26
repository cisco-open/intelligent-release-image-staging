<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Server

The server is a single Docker service that runs several small Python and shell components. It intentionally keeps runtime dependencies narrow: Python standard library services, `aria2c` for BitTorrent, `mktorrent` for torrent metadata, and OpenSSL/age tooling for certificates and encrypted secret material.

The image is self-contained: device installer sources and the SSH helper used by
console onboarding are copied in at build time. Build it from the repository
root for `linux/amd64`:

```bash
docker build --platform linux/amd64 -f server/Dockerfile -t iris:latest .
```

Compose builds and runs `iris:latest`, so tag a hand-built image the same way —
the volume-ownership migration below runs a throwaway container from that tag.

The root `.dockerignore` excludes credentials, firmware, network state, generated
artifacts, and test output from the build context.

## Network surfaces

| Port | Protocol | Service | Purpose |
| --- | --- | --- | --- |
| 6969 | HTTP | Tracker | Private BitTorrent announces with an announce key. |
| 8443 | HTTPS | Catalog | Image metadata, device assignments, token refresh, and reports. |
| 8000 | HTTPS | Artifact server | Bootstrap, agent bundle, pinned certificate, and staged install assets. |
| 6881 | BitTorrent | Seeder data | Initial image pieces from the server seeder. |
| 8080 | HTTPS | Web console | Admin browser interface. |
| 9101 | HTTP | Telemetry | Health, swarm view, and optional Prometheus metrics. |
| 6800 | HTTP | aria2 RPC | Local-only inside the container; not published by Compose. |

## Runtime identity

The image creates a system user `iris` with the fixed uid and gid `10001` and
declares `USER iris`. Every service — tracker, catalog, artifact server, the
seeder and its `aria2c`, the web console, and the telemetry listener — runs as
uid `10001`. No listener in the table above needs a privileged port, so the
runtime needs no Linux capabilities at all.

Compose restates the identity and removes the remaining privilege surface:

| Setting | Effect |
| --- | --- |
| `user: "10001:10001"` | `docker compose run` and `exec` cannot silently regress to root. |
| `cap_drop: [ALL]` | No capabilities; nothing binds low ports or changes ownership at runtime. |
| `security_opt: [no-new-privileges:true]` | No setuid binary or file capability can re-gain privilege. |

The tmpfs for `/run/iris` is mounted with `uid=`, `gid=`, and `mode=` mount
options so the plaintext-secret directory belongs to uid `10001` and is private
to it. Those mount options require Docker Engine 23.0 or later.

### Host paths to chown on every deploy

The uid is fixed precisely so host-side ownership is deterministic, but the
Dockerfile cannot chown paths on the host. Run both of these from the repository
root on every deploy, fresh or upgraded, or the server starts and then fails to
read its own key material and cannot write served artifacts:

```bash
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown -R 10001:10001 artifacts          # or "$IRIS_ARTIFACTS_HOST_DIR"
```

Keep the age identity at mode `600` (or `400`); changing the owner does not
change the mode. `IRIS_ARTIFACTS_HOST_DIR` defaults to `../artifacts` relative to
`server/docker-compose.yml`, which is the repository's `artifacts/` directory.

### Upgrading from a root-runtime deployment

A fresh named volume inherits the image's `10001` ownership automatically. An
existing volume created under a root runtime stays root-owned, so an upgraded
deployment needs this one-time migration. Run it as a throwaway container with
default capabilities, not through the Compose service:

```bash
docker run --rm -u 0 \
  -v server_iris-state:/var/lib/iris \
  -v server_iris-config:/etc/iris \
  -v server_iris-images:/var/lib/iris-images \
  iris:latest chown -R 10001:10001 /var/lib/iris /etc/iris /var/lib/iris-images
```

`iris:latest` is the image Compose builds. The volume names carry the Compose
project prefix — `server_` for the default project name, which comes from the
directory holding the compose file.

`docker compose run --user 0` does not work for this: that form inherits the
service's `cap_drop: [ALL]`, so every path is denied with
`Operation not permitted`, and `chown -R` still exits 0. A deployment migrated
that way is still unmigrated even though the command reports success, so confirm
volume ownership rather than trusting the exit status.

!!! warning "The migration is per volume, so a partial reset needs it again"
    Removing some volumes while keeping others still requires the migration for
    the ones kept. Wiping `iris-config` and `iris-state` to redo admin setup
    while preserving `iris-images` leaves the published `.bin` files root-owned
    at mode `0600`, and the non-root server cannot read them. The Images screen
    then lists those files as `not readable by the server`.

### Host image tree permissions

The host image tree bind-mounted at `/opt/images` (`IRIS_IMAGE_ROOT`) must be
readable and traversable by uid `10001`. A conventional `755` tree is fine; a
`700` root-owned tree fails to publish and seed.

## Important paths

| Path | Role |
| --- | --- |
| `/var/lib/iris` | Catalog state, policies, torrent metadata, audit state, and deployment receipts. |
| `/etc/iris` | Encrypted secrets and generated TLS material. |
| `/run/iris` | Plaintext runtime secrets on tmpfs. |
| `/var/lib/iris-images` | Uploads volume (`IRIS_IMAGES_DIR`); images the console received over HTTP. |
| `/opt/images` | Read-only import root (`IMAGES_ROOT`), the host `IRIS_IMAGE_ROOT` tree mounted `:ro`. |
| `/srv/artifacts` | Served bootstrap and agent artifacts. |

Those two image locations are the server's only image roots. The uploads volume
is writable and owned by the runtime uid; the import root is where operators
stage images on the host and stays read-only to the container.

Deployment receipts (`deployment_receipts.json`, the applied-lifecycle state
that drives undeploy) live under `IRIS_STATE` — `/var/lib/iris` on Compose,
`/data/state` on the Kubernetes PVC — and hold no secrets. See
[Management Type and VLAN Ownership](network-attachment.md).

Docker Compose uses separate named volumes for state, encrypted config, and GUI
image uploads. The Kubernetes alpha maps all durable paths into one ReadWriteOnce
PVC under `/data` and keeps `/run/iris` memory-backed.

## Publishing images

Publishing is the handoff from an operator-owned image file to IRIS-managed metadata:

1. `iris-publish` derives or accepts an image id.
2. It calculates `sha256` and `sha512`.
3. It creates a private torrent with the authenticated tracker announce URL.
4. It asks the local seeder RPC to seed that torrent.
5. It persists the catalog entry.

The command normally runs inside the container:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

Publishing happens **in place**. The seeder is pointed at the image file's own
directory, so nothing is copied and the read-only import root stays read-only.
The `.torrent` is written under the state dir, never next to the image. Each
catalog entry records its `source_dir`, which the server uses to re-seed the
right file after a restart and to decide whether deleting the entry may unlink
the file. Deleting an image only unlinks it when `source_dir` resolves to the
uploads volume, so an image published in place from the import root is left on
disk, and a same-named file in the uploads volume is never destroyed by
mistake. Entries published before `source_dir` was recorded keep the older
behaviour of unlinking `IRIS_IMAGES_DIR/<filename>`.

### Importing images already on disk

The console Images screen also lists image files that are present on disk but
absent from the catalog, and publishes a chosen one in place. Both roots are
scanned recursively, and each distinct tree is walked once, so an import root
that resolves to the uploads volume — or sits inside it — is not scanned twice.

A file is offered only when it structurally qualifies as an image file, is
readable by the server, is not already published, and is not ambiguous. A file
that fails one of the last three checks stays in the list, greyed out, with the
reason — see
[Import skip reasons](reference.md#import-skip-reasons).

## Secret handling

IRIS uses age recipients for encrypted-at-rest server secrets. The private age identity is mounted as a Docker secret, and decrypted values are written only to `/run/iris`. This protects long-lived token material from landing in the persistent Docker volume in plaintext.

The seeder RPC secret is not published to the network. Tools that need it, such as `iris-publish`, run inside the container where `127.0.0.1:6800` is reachable.

## Kubernetes

The optional manifests under `kubernetes/` run the same image as one pod behind
a source-IP-preserving LoadBalancer. They add an idempotent bootstrap init
container, persistent storage, startup/readiness/liveness probes, and a
Kubernetes Secret mount for the age identity. See [Kubernetes](kubernetes.md)
for the address and scaling constraints.

## Self-provisioned artifacts

On startup, the container refreshes derivable served files such as the Guest Shell agent bundle, bootstrap script, and catalog certificate. Operator-supplied IOx packaging artifacts, such as `iris-arm64.tar`, remain operator-owned; the container serves them but does not modify them.
