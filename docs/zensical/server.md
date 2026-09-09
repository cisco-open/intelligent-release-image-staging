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

Docker Compose and the Kubernetes manifests run both tiers. Docker supports
one host or [separate server and Console hosts](docker-hosts.md). The two images
are the units of deployment.

The server image includes the device installers and SSH helper used by Console
onboarding. The browser application is built separately into the Console image.
`aria2c` is handed in, not downloaded or built — run `tools/get-aria2c.sh amd64` first, or the
Dockerfile's `COPY bin/aria2c` step fails. Build both images from the repository
root; Compose selects `linux/amd64`:

```bash
tools/get-aria2c.sh amd64
docker compose -f server/docker-compose.yml build --pull
```

`--pull` matters: the base is a floating tag, and without it Docker reuses
whatever `python:3.12-slim-trixie` the host cached, which can be weeks of
Debian security updates behind the tag. `tools/start-compose-server.sh`
passes it for you.

Compose builds and runs `iris:latest` and `iris-console:latest`, so tag
hand-built images the same way. The Console has no durable state volume.

The root `.dockerignore` excludes credentials, firmware, network state, generated
artifacts, and test output from the build context.

## Network surfaces

| Port | Transport | Protocol | Service | Purpose |
| --- | --- | --- | --- | --- |
| 6969 | TCP | HTTPS | Tracker | Private BitTorrent announces: IOx/XR use a Bearer header; Guest Shell sends a query token inside TLS. All agents pin the server certificate. |
| 8443 | TCP | HTTPS | Catalog | Image metadata, device assignments, token refresh, and reports. |
| 8000 | TCP | HTTPS | Artifact server | Bootstrap, agent bundle, pinned certificate, and staged install assets. |
| 6881 | TCP | BitTorrent | Seeder data | Initial image pieces from the server seeder. |
| 8080 | TCP | HTTPS | Web console | Admin browser interface. |
| 9101 | TCP | HTTPS | Telemetry | Non-disclosing probes, authenticated optional metrics, and management-authenticated swarm state. |
| 9443 | TCP | HTTPS | Management API | Console-to-server API over the Compose network, a private server-host binding, or an internal Kubernetes Service. |
| 6800 | TCP | HTTP | aria2 RPC | Local-only inside the container; not published by Compose. |

Every listener is TCP; IRIS opens no UDP port. The default Compose stack
connects the services over its private network at `https://iris:9443`.
Separate Docker hosts publish 9443 only on a private server address, with
firewall access restricted to the Console host. Kubernetes restricts 9443
ingress to Console pods. All layouts require the management credential and
verified TLS.

Devices use `IRIS_HOST_IP` and the published server ports; operators use the
Console's published address. The containers do not need separate LAN IPs.
The one-host Compose stack binds Console 8080 only on `IRIS_HOST_IP`; the
standalone Console uses `IRIS_CONSOLE_BIND_IP`. Device-facing server mappings
bind all host interfaces by default. Restrict those server ports with the host
firewall. See
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
root on every deploy so the server can read its key material and write served
artifacts:

```bash
chmod 600 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown -R 10001:10001 artifacts          # or "$IRIS_ARTIFACTS_HOST_DIR"
```

Keep the age identity at mode `600` (or `400`); changing the owner does
not change the mode. `IRIS_ARTIFACTS_HOST_DIR` defaults to `../artifacts` relative to
`server/docker-compose.yml`, which is the repository's `artifacts/` directory.

### Volume permissions

The server needs ownership of its state, configuration, and uploads volumes as
uid and gid `10001`. New named volumes inherit that ownership from the image.
If restored or manually copied files have different ownership, stop the stack
and repair the affected volumes:

```bash
docker compose -f server/docker-compose.yml stop
docker run --rm -u 0 \
  -v server_iris-state:/var/lib/iris \
  -v server_iris-config:/etc/iris \
  -v server_iris-images:/var/lib/iris-images \
  iris:latest chown -R 10001:10001 /var/lib/iris /etc/iris /var/lib/iris-images
docker compose -f server/docker-compose.yml up -d
```

The volume names use the Compose project prefix `server_`. Substitute your
actual names if you set `COMPOSE_PROJECT_NAME`; check with `docker volume ls`.
Use a separate `docker run` for the ownership repair: the Compose service drops
all capabilities, including the one required by `chown`, even when started as
root. Confirm ownership and that the Images screen no longer reports
`not readable by the server`.

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

The fixed name keeps volume names stable across directory renames. It does
not isolate another checkout: without overrides, every checkout on the same
Docker host still targets this same project and its data. Check the active
stack with `docker compose -f server/docker-compose.yml ps` and inspect volume
names with `docker volume ls --filter name=iris` before maintenance.

### Running a second stack on the same host

A separate checkout needs all of the following:

- A distinct `COMPOSE_PROJECT_NAME` for its network and named volumes.
- Distinct `IRIS_CONTAINER` and `IRIS_CONSOLE_CONTAINER` names.
- A separate `IRIS_ARTIFACTS_HOST_DIR`, age identity, and configuration.
- Nonconflicting host bindings for every published port. Setting
  `IRIS_GUI_PUBLISH` changes only the Console port; server mappings still use
  6969, 8443, 8000, 6881, and 9101. Use a reviewed Compose override or a separate
  host, and make the advertised catalog, tracker, and seeder endpoints match.

`IRIS_CONTAINER` also selects the server for helpers such as
`tools/apply-assignments.sh` and `tools/check-package-freshness.sh`.
`tools/start-compose-server.sh` resolves its server from the Compose project
unless that variable is set. Use the same project and override configuration
for every subsequent Compose command.

## Important paths

| Path | Role |
| --- | --- |
| `/var/lib/iris` | Catalog state, policies, torrent metadata, the peer ledger, peer endpoints, and deployment records. |
| `/etc/iris` | The age-encrypted secret store and generated TLS material, **plus plaintext public material and audit data**: the console certificate override `tls/gui-crt.pem` (its private key is the age-encrypted `tls/gui-key.pem.age`) and the append-only audit trail `audit.jsonl`. |
| `/run/iris` | Plaintext runtime secrets on tmpfs. |
| `/var/lib/iris-images` | Uploads volume (`IRIS_IMAGES_DIR`); images the Console received over its authenticated HTTPS API. |
| `/opt/images` | Read-only import root (`IMAGES_ROOT`), the host `IRIS_IMAGE_ROOT` tree mounted `:ro`. |
| `/srv/artifacts` | Served bootstrap and agent artifacts. |

None of these paths is mounted into the Console. Its only server-side inputs
are the public management CA and the current/previous tier-credential files,
all read-only. Its active browser TLS identity is kept in Console tmpfs. The
default Compose stack fetches a Console-only fallback over the authenticated
management connection. Docker on separate hosts and Kubernetes mount an
independent default identity; a custom identity installed through Settings is
fetched from the server.
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

## Instruction state and processes

Phase 1 adds custody and stamper daemon threads inside the management process.
`server/docker-entrypoint.sh` still supervises five processes; this is not a
sixth service or container. New authenticated application paths
`GET /v1/devices/{device_id}/instructions` and
`GET /v1/devices/{device_id}/instruction-keylist` share TCP 8443. There is no
new listener, port, network path or firewall flow; TCP 9443 is management-only.

`InstructionPaths` and `StamperPaths` define the following exact locations:

| Base | Files / directories |
| --- | --- |
| `$IRIS_CONFIG/instr/` | Optional `signing-key.age` (encrypted online private key), `signing-key.pub`, `signing-key-cert.pub`, `roots.d/` (public roots only) |
| `$IRIS_RUN/instr/` | `signing-key` (runtime plaintext only), `signing-key-cert.pub` (runtime certificate cache) |
| `$IRIS_STATE/` | `instructions-epoch.json`, `instructions-epoch.json.lock`, `instruction-key-status.json`, `instruction-stamper-status.json` |
| `$IRIS_STATE/instructions/` | `keylist.current`, `keylist-state.json`, `keylist.lock`, `roles.d/`, `role-state.json`, `activation.json`, `producer.lock`, `admitted-devices.json`, `serial-history.json`, `roles.lock` |

Keep the encrypted signing key, age identity, runtime plaintext and durable
instruction state on the server host. Public roots are not secret. Back up
config and state consistently while keeping the age identity separate; never
restore serial history backwards or copy these stores to the Console. Use
[producer recovery and custody runbooks](operations.md#instruction-root-ceremony-and-recovery)
for an intentional recovery epoch. A green certificate-freshness check does
not waive rebuilding all device packages after shared-agent changes.

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
mistake.

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

IRIS encrypts catalog credentials, device credentials, RPC secrets, and private
TLS material with age. The private age identity is mounted separately as a
Docker secret; decrypted copies of this encrypted store live in `/run/iris`
tmpfs. The Console-to-server credential is separate: Compose persists its
plaintext current/previous files in the narrowly mounted `iris-tier-auth`
volume. Protect that volume and its backups as credentials.

The seeder RPC secret is not published to the network. Tools that need it, such as `iris-publish`, run inside the container where `127.0.0.1:6800` is reachable.

## Console-to-server authentication

The management API listens on internal HTTPS port 9443. On first Compose start,
the server atomically creates a management-scoped token in the
`iris-tier-auth` named volume; both tiers mount it, and the Console's mount is
read-only. Separate Docker hosts use local credential directories populated
through the [provisioning procedure](docker-hosts.md), while Kubernetes uses a
Secret projection. The token is not
accepted by the catalog, tracker, or any device resource, and it never appears
in Compose environment, a process argument, a URL, logs, or audit text. The
server compares credentials in constant time before route lookup, body
buffering, or state access.

Rotation keeps a bounded two-token window: retain the former record as
`previous.json`, atomically install the replacement as `current.json`, confirm
both tiers received it, verify an authenticated Console request, then remove
`previous.json`. The files must have distinct paths and file identities. Both processes
reread the files on every request, so Compose needs no restart; Kubernetes
rotates the equivalent `current`/`previous` Secret keys in two
rollouts so every replica sees an overlap. If the Console receives the update
first, it can use the previous token after the server rejects the current
management credential. It keeps the accepted token through a mutation's
preflight and forwarding, without replaying the body. Missing, unreadable, wrongly scoped,
or unmatched material fails closed. TLS is independently fail closed: the
Console pins the management CA and cannot opt into plaintext for this hop.

For a shared Compose volume, the server-side helper generates the replacement without ever
printing the credential. Run the first command, verify a normal Console API
request, and then retire the overlap:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token rotate
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token retire-previous
```

For separate Docker hosts, deliver the replacement to the Console host before
retiring the previous value. Follow the
[remote credential rotation procedure](docker-hosts.md#rotate-the-management-credential).

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
