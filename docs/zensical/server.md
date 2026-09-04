<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Server

IRIS runs two Docker services. The stateful server tier runs the tracker,
catalog, artifact server, seeder, telemetry, and an internal management API.
The state-free Console tier serves the browser application and forwards its
versioned API calls to that management API. The server keeps runtime
dependencies narrow: Python standard-library services, `aria2c` for
BitTorrent, `mktorrent` for torrent metadata, and OpenSSL/age tooling for
certificates and encrypted secret material.

Docker Compose and the Kubernetes manifests are the supported ways to run both
tiers. There is no separate host install — the two images are the units of
deployment.

The image is self-contained: device installer sources and the SSH helper used by
console onboarding are copied in at build time. `aria2c` is handed in, not
downloaded or built — run `tools/get-aria2c.sh amd64` first, or the
Dockerfile's `COPY bin/aria2c` step fails. Then build it from the repository
root for `linux/amd64`:

```bash
tools/get-aria2c.sh amd64
docker build --pull --platform linux/amd64 -f server/Dockerfile -t iris:latest .
```

`--pull` matters: the base is a floating tag, and without it Docker reuses
whatever `python:3.12-slim-trixie` the host cached, which can be weeks of
Debian security updates behind the tag. `tools/start-compose-server.sh`
passes it for you.

Compose builds and runs `iris:latest` and `iris-console:latest`, so tag
hand-built images the same way. The volume-ownership migration below runs a
throwaway container from the server tag; the Console has no durable volume to
migrate.

The root `.dockerignore` excludes credentials, firmware, network state, generated
artifacts, and test output from the build context.

## Network surfaces

| Port | Transport | Protocol | Service | Purpose |
| --- | --- | --- | --- | --- |
| 6969 | TCP | HTTPS | Tracker | Private BitTorrent announces: IOx/XR use a Bearer header; Guest Shell retains query-token compatibility inside TLS. All agents pin the server certificate. |
| 8443 | TCP | HTTPS | Catalog | Image metadata, device assignments, token refresh, and reports. |
| 8000 | TCP | HTTPS | Artifact server | Bootstrap, agent bundle, pinned certificate, and staged install assets. |
| 6881 | TCP | BitTorrent | Seeder data | Initial image pieces from the server seeder. |
| 8080 | TCP | HTTPS | Web console | Admin browser interface. |
| 9101 | TCP | HTTPS | Telemetry | Non-disclosing probes, authenticated optional metrics, and management-authenticated swarm state. |
| 9443 | TCP | HTTPS | Management API | Internal Console-to-server API; exposed only on the Compose network or internal Kubernetes Service. |
| 6800 | TCP | HTTP | aria2 RPC | Local-only inside the container; not published by Compose. |

Every listener is TCP; IRIS opens no UDP port. Port 9443 must never be
host-published: a file-mounted service credential and TLS still protect it,
but network reachability is restricted to the Console tier as a second layer.
See
[Network ports and flows](network-ports.md#firewall-rules).

## Runtime identity

Both images create a system user `iris` with the fixed uid and gid `10001` and
declare `USER iris`. Every server component and the separate web Console run as
uid `10001`. No listener in the table above needs a privileged port, so either
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
Dockerfile cannot chown paths on the host. Run these from the repository
root on every deploy, fresh or upgraded, or the server starts and then fails to
read its own key material and cannot write served artifacts:

```bash
chmod 600 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown -R 10001:10001 artifacts          # or "$IRIS_ARTIFACTS_HOST_DIR"
```

Keep the age identity at mode `600` (or `400`); changing the owner does
not change the mode. `IRIS_ARTIFACTS_HOST_DIR` defaults to `../artifacts` relative to
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
project prefix — `server_`, from the `name:` in `server/docker-compose.yml`
(see [Compose project name](#compose-project-name) below). If you run the stack
under your own `COMPOSE_PROJECT_NAME`, substitute the prefix your
`docker volume ls` actually shows.

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

## Compose project name

`server/docker-compose.yml` declares `name: server`, so the Compose project —
and with it the five named volumes `server_iris-state`, `server_iris-config`,
`server_iris-images`, `server_iris-tier-auth`, and
`server_iris-management-ca` — is stable wherever the repository is checked
out.

Without that line Compose names the project after the directory holding the
compose file, which is always `server`. Every checkout of this repository on a
host therefore resolved to the *same* project, so a second checkout beside a
live deployment shared its volumes: `docker compose up` adopted the production
container, `docker compose run --rm iris iris-bootstrap` re-bootstrapped
production state, and `docker compose down -v` deleted the state, the encrypted
config and the published images.

The declared value is deliberately the same string the directory used to
derive. **An existing deployment therefore needs no migration**: it keeps the
`server_`-prefixed volumes it already has, and nothing moves. What the line
buys is that the project name is now a fact of this file rather than an
accident of where it was checked out, so it cannot change under a directory
rename, and a second clone no longer silently inherits the live deployment's
data.

Check which volumes are live with `docker volume ls | grep iris`.

### Running a second stack on the same host

A dev checkout beside a live deployment needs a project name **and** a container
name of its own — container names are host-global:

```bash
COMPOSE_PROJECT_NAME=iris-dev IRIS_CONTAINER=iris-dev \
  IRIS_CONSOLE_CONTAINER=iris-console-dev \
  docker compose -f server/docker-compose.yml up -d
```

`IRIS_CONTAINER` is the same variable `tools/apply-assignments.sh`,
`tools/stage-iox-package.sh`, `tools/gen-device-installers.sh`, and
`tools/check-package-freshness.sh` already honour, so one setting names the
container and points the helpers at it. `tools/start-compose-server.sh` resolves
the container from its own Compose project, so it needs no override.

## Important paths

| Path | Role |
| --- | --- |
| `/var/lib/iris` | Catalog state, policies, torrent metadata, the peer ledger, peer endpoints, and deployment records. |
| `/etc/iris` | The age-encrypted secret store and generated TLS material, **plus two plaintext files**: the console certificate override `tls/gui-crt.pem` (its private key is the age-encrypted `tls/gui-key.pem.age`) and the append-only audit trail `audit.jsonl`. |
| `/run/iris` | Plaintext runtime secrets on tmpfs. |
| `/var/lib/iris-images` | Uploads volume (`IRIS_IMAGES_DIR`); images the Console received over its authenticated HTTPS API. |
| `/opt/images` | Read-only import root (`IMAGES_ROOT`), the host `IRIS_IMAGE_ROOT` tree mounted `:ro`. |
| `/srv/artifacts` | Served bootstrap and agent artifacts. |

None of these paths is mounted into the Console. Its only server-side inputs
are the public management CA and the current/previous tier-credential files,
all read-only. Its active browser TLS identity is fetched over that authenticated
hop into Console tmpfs; Compose generates a console-only fallback distinct from
the catalog identity, while Kubernetes mounts its independent default Secret.
The management API certificate and private key stay in the server container.

!!! warning "`/etc/iris` is not wholly encrypted"
    Only `secrets.json.age`, `gui-key.pem.age` and the other `.age` files on
    that volume are encrypted at rest. `audit.jsonl` is plaintext JSONL and
    carries console usernames, device ids, and every settings and onboarding
    action; deliberately so, since encrypting it would put a live secret's
    key material on the same volume it protects. Treat a snapshot or off-box
    copy of `/etc/iris` as sensitive. The audit trail's path is
    `IRIS_AUDIT` — `/etc/iris/audit.jsonl` on Compose,
    `/data/config/audit.jsonl` on Kubernetes. The console's *export audit
    trail* action is a separate thing and is always age-encrypted
    ([Operations](operations.md#audit-export)).

Those two image locations are the server's only image roots. The uploads volume
is writable and owned by the runtime uid; the import root is where operators
stage images on the host and stays read-only to the container.

Deployment records (`deployment_records.json`, the applied-lifecycle state
that drives undeploy) live under `IRIS_STATE` — `/var/lib/iris` on Compose,
`/data/state` on the Kubernetes PVC — and hold no secrets. See
[Management Type and VLAN Ownership](management-type.md).

Docker Compose uses separate named volumes for state, encrypted config, GUI
image uploads, the narrow tier credential, and its public management CA. The
Kubernetes alpha maps all durable server paths into one ReadWriteOnce PVC under
`/data` and keeps `/run/iris` memory-backed; the Console mounts no PVC.

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
behavior of unlinking `IRIS_IMAGES_DIR/<filename>`.

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

## Console-to-server authentication

The management API listens on internal HTTPS port 9443. On first Compose start,
the server atomically creates a management-scoped token in the
`iris-tier-auth` named volume; both tiers mount it, and the Console's mount is
read-only. Kubernetes uses a Secret projection instead. The token is not
accepted by the catalog, tracker, or any device resource, and it never appears
in Compose environment, a process argument, a URL, logs, or audit text. The
server compares credentials in constant time before route lookup, body
buffering, or state access.

Rotation keeps a bounded two-token window: retain the former record as
`previous.json`, atomically install the replacement as `current.json`, verify
an authenticated Console request, then remove `previous.json`. Both processes
reread the files on every request, so Compose needs no restart; Kubernetes
rotates the equivalent `current`/`previous` Secret keys in two
rollouts so every replica sees an overlap. Missing, unreadable, wrongly scoped,
or unmatched material fails closed. TLS is independently fail closed: the
Console pins the management CA and cannot opt into plaintext for this hop.

For Compose, the server-side helper generates the replacement without ever
printing the credential. Run the first command, verify a normal Console API
request, and then retire the overlap:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token rotate
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token retire-previous
```

The browser still uses its session cookie and CSRF token. Those checks are in
addition to tier authentication, not replaced by it; `X-IRIS-Poll` continues
through the proxy so polling does not extend an idle session.

## Kubernetes

The optional manifests under `kubernetes/` run server and Console as separate
Deployments and Services. They add an idempotent server bootstrap init
container, server-only persistent storage, per-tier probes/resources,
management TLS/auth Secret projections, and an internal management Service.
See [Kubernetes](kubernetes.md) for address and scaling constraints.

## Self-provisioned artifacts

On startup, the container refreshes derivable served files such as the Guest
Shell agent bundle, bootstrap script, and catalog certificate. The two IOx tars
and `iris-xr.rpm` remain operator-built: the container serves them but does not
modify them. They contain the shared agent and carry adjacent manifests binding
their wrapper bytes to the canonical OCI image, but contain no deployment
certificate. Rebuild all package families after any `device/agent/` or common
device-image change. A certificate rotation instead requires re-onboarding
devices so the current public certificate is delivered at runtime; the same
packages can be reused.
See [TLS rotation and device packages](operations.md#tls-rotation-and-device-packages)
and [Embedded agent packages](development.md#embedded-agent-packages).
