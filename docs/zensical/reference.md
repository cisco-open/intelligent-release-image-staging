<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Reference

Lookup tables for commands, ports, environment variables, the console API, and
the catalog schema. Every page is listed in the [Overview](index.md).

## Command quick reference

| Command | Use |
| --- | --- |
| `docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap` | Initialize a fresh encrypted server config volume. |
| `docker compose -f server/docker-compose.yml up -d --build` | Build and start the IRIS server. |
| `tools/start-compose-server.sh` | Bootstrap/start Compose and automatically stage both IOx packages. |
| `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<image>.bin` | Publish an image into the catalog and seeder. In place: the image is seeded from its own directory and nothing is copied. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign` | Show images and assignments. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign <device> <image>` | Assign one image to one device. |
| `tools/gen-device-installers.sh fleet/devices.csv` | Generate per-device installers. |
| `tools/apply-assignments.sh fleet/assignments.csv` | Validate and apply assignment CSV. |
| `tools/make-agent-bundle.sh` | Build the Guest Shell agent bundle manually. |
| `device/device-uninstall.sh` | Remove Guest Shell IRIS wiring from a device. |
| `device/iox/install.sh` | Install the IOx app path. |
| `device/iox/uninstall.sh` | Remove the IOx app path. |
| `device/iox/build.sh --image-only` | Build the ARM64 app-hosting image; set `IOX_ARCH=amd64` for x86_64. |
| `kubectl apply -k kubernetes` | Deploy the optional single-replica Kubernetes seed server. |

Docs build commands and their tool pins live in [Development](development.md#documentation-loop).

## Port quick reference

| Port | Service | Device-facing |
| --- | --- | --- |
| 6969 | Tracker | Yes |
| 8443 | Catalog | Yes |
| 8000 | Artifact server | Yes |
| 6881 | Seeder data | Yes |
| 8080 | Web console | Operator-facing |
| 9101 | Telemetry | Operator-facing |
| 6800 | aria2 RPC | No, local-only |

## Environment variables

### Required at deploy time

Compose refuses to start without these; none has a default.

| Variable | Effect |
| --- | --- |
| `IRIS_HOST_IP` | The docker host's IP — the address devices reach. Baked into the catalog's self-signed TLS certificate on first start, so changing it later means recreating the config volume. |
| `IRIS_AGE_RECIPIENTS` | Comma-separated age public keys the at-rest secret store is encrypted to: the primary key plus an offline break-glass recipient. |
| `IRIS_AGE_KEY_FILE_HOST` | Host path of the age identity (private key), mounted as the Docker secret `iris_age_key` at `/run/secrets/iris_age_key`. |

### Optional at deploy time

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_ARTIFACTS_HOST_DIR` | `../artifacts` | Host directory bind-mounted read-write at `/srv/artifacts`. |
| `IRIS_GUI_PUBLISH` | `8080` | Published host port for the console. The container always listens on 8080 internally. |
| `IRIS_CONSOLE_URL` | unset | Overrides the console link on the port 9101 pointer page verbatim, for hosts publishing the console somewhere other than `https://<IRIS_HOST_IP>:8080/`. Read per request. |
| `IRIS_VERSION` | unset | Build argument that bakes the release string the console's Settings page shows. Unset means the `VERSION` file in the image. |

The host-side ownership these paths need is in
[Server](server.md#host-paths-to-chown-on-every-deploy).

### Container paths

`server/docker-compose.yml` sets each container-side path explicitly, so one-shot
commands launched with `docker compose exec` see the same layout as the supervised
services. What each directory holds is in
[Server](server.md#important-paths).

| Variable | Compose value |
| --- | --- |
| `IRIS_STATE` | `/var/lib/iris` |
| `IRIS_CONFIG` | `/etc/iris` |
| `IRIS_RUN` | `/run/iris` (tmpfs) |
| `IRIS_SECRETS` | `/run/iris/secrets.json` |
| `IRIS_SECRETS_ENC` | `/etc/iris/secrets.json.age` |
| `IRIS_RPC_SECRET_FILE` | `/run/iris/rpc-secret` |
| `IRIS_CERT` | `/run/iris/tls/cert.pem` |
| `IRIS_AUDIT` | `/etc/iris/audit.jsonl` |
| `IRIS_ARTIFACTS_DIR` | `/srv/artifacts` |

The Kubernetes alpha maps the durable paths into one PVC under `/data` instead —
see [Kubernetes](kubernetes.md).

### Image path variables

The server reads images from two places, and the distinction decides what a
delete removes and what an import offers.

| Variable | Default | Role |
| --- | --- | --- |
| `IRIS_IMAGE_ROOT` | `/opt/images` | Host directory holding images you staged yourself. Bind-mounted into the container at `/opt/images` read-only. |
| `IMAGES_ROOT` | `/opt/images` | Container-side path of that read-only bind. Scanned recursively for importable images, and walked by the seeder's startup re-seed when it has to locate a torrent's image. |
| `IRIS_IMAGES_DIR` | `/var/lib/iris-images` | The uploads volume: where a console upload lands. Also scanned recursively for importable images, and walked first by the startup re-seed. This is the only directory whose files a catalog delete unlinks. |
| `IMAGES_DIR` | `/opt/images/iosxe/c9300` | Fallback seed directory, used for a torrent whose image the startup re-seed cannot locate under either root. |

The host tree behind `IRIS_IMAGE_ROOT` must be readable and traversable by uid
10001 — see [Server](server.md#host-image-tree-permissions).

### Telemetry variables

External telemetry is off by default: IRIS does not assume a Prometheus, Loki, or
Grafana stack exists.

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_OBSERVABILITY` | unset (off) | Enables the external observability surface when set to `1`, `true`, `yes`, or `on`. Any other value, empty, or unset leaves it off. |
| `IRIS_OTLP_ENDPOINT` | unset | OTLP/HTTP endpoint of your collector, e.g. `http://<collector-ip>:4318`. |
| `IRIS_METRICS_PORT` | `9101` | Port for the telemetry listener. Empty or `0` disables the listener entirely. |
| `IRIS_SWARM_URL` | `http://127.0.0.1:9101/swarm` | Where the console fetches swarm state from. |

#### Telemetry gating rule

* Prometheus `/metrics` is served only while `IRIS_OBSERVABILITY` is enabled; otherwise the path answers 404.
* OTLP export requires **both** `IRIS_OBSERVABILITY` enabled **and** `IRIS_OTLP_ENDPOINT` set. `IRIS_OTLP_ENDPOINT` on its own is inert — nothing is exported.
* `/healthz`, `/swarm`, and the `/swarmmap` pointer page are served whenever the listener runs, regardless of either variable.
* The console reads `/swarm` over container loopback (`127.0.0.1:9101`), so port 9101 needs external reachability only for Prometheus scraping or operator tools — never for the console.

`IRIS_OBSERVABILITY` and `IRIS_OTLP_ENDPOINT` are read at startup, so a change
takes effect on the next container restart. The startup log states which posture
is in effect.

!!! note "A down Prometheus target is not a fault"
    With observability off, a Prometheus job scraping IRIS reads down and a
    Grafana IRIS dashboard is blank. That is telemetry being off, not a broken
    server. Set `IRIS_OBSERVABILITY` to get the scrape surface, and
    `IRIS_OTLP_ENDPOINT` as well to get event export.

## Console API

Every `/api` route requires an authenticated console session cookie except two
pre-auth routes: `POST /api/login` and `POST /api/setup`. State-changing methods
on the authenticated routes additionally require the session's CSRF token in an
`X-CSRF-Token` header (double submit); without it the request is rejected with
403. The two pre-auth routes carry no CSRF token, because there is no session
yet. JSON request bodies are capped at 64 KiB — the exceptions are the CSV import
at 8 MiB and the streamed image upload at 4 GiB.

### Session and settings

| Route | Body / result |
| --- | --- |
| `POST /api/login` | Pre-auth. `{username, password}` → `{username, csrf}` plus the session cookie; 401 on bad credentials. |
| `POST /api/setup` | Pre-auth, first run only. `{username, password}` creates the admin account; 409 once one exists. |
| `POST /api/logout` | Revokes the current session and expires the cookie. |
| `GET /api/session` | The current session's info, or 401. |
| `GET /api/settings` | Console settings, published port, and the running version. |
| `POST /api/settings/password` | `{current, new, confirm}`; changes the admin password and revokes every other session. |
| `POST /api/settings/sessions/revoke-others` | Revokes every session except the caller's. |
| `POST /api/settings/stage-host` | Stores the stage-host SSH credential; returns the redacted record. |
| `DELETE /api/settings/stage-host` | `{deleted: <bool>}` — clears that credential. |

### Images

| Route | Body / result |
| --- | --- |
| `GET /api/images` | `{images: [...]}` — the catalog entries. |
| `GET /api/images/importable` | `{importable: [...], skipped: [...]}` — image files on disk under either root that are not in the catalog. A pure read; nothing is published or moved. |
| `PUT /api/images/upload/<filename>` | Streams the body into the uploads volume and starts a publish job; returns `{job_id}`. 413 for a missing body or one over 4 GiB. |
| `POST /api/images/import` | Body `{"path": "<candidate path>"}`; returns `{job_id}`. Publishes the file in place. |
| `GET /api/images/jobs/<job_id>` | Publish job state (`publishing`, `done`, `error`). Shared by upload and import. |
| `DELETE /api/images/<image_id>` | `{deleted: true}`, or 409 with `{assigned: [...]}` when a live device still has the image approved. |

`POST /api/images/import` authorizes on candidate identity, not on a path prefix,
so a path that merely starts inside a root is refused with 400. It answers 404 if
the file vanished between listing and import, and 409 if a publish of the same
catalog id is already in flight. Every outcome writes an `image_import` audit
event, with `result=fail` and the reason on a rejection.

### Devices

| Route | Body / result |
| --- | --- |
| `GET /api/devices` | `{devices: [...], now}` — the inventory view plus the server clock, so the UI computes freshness server-clock-to-server-clock. |
| `POST /api/devices` | Creates or updates one inventory row; returns `{device: ...}`. |
| `DELETE /api/devices/<id>` | `{deleted: <bool>}`. |
| `GET /api/devices/export-csv`, `GET /api/devices/example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/devices/import-csv` | Bulk inventory import (8 MiB cap, all-or-nothing); returns per-row stats. |
| `GET /api/devices/<id>/plan` | `{plan}` — the resolved deployment plan; 409 when it cannot resolve. |
| `GET /api/devices/<id>/reports` | `{reports: [...]}` — the device's stored telemetry ring. |
| `POST /api/devices/<id>/assign`, `.../credential`, `.../platform` | Sets the approved image, the credential profile, or the platform and storage target; each returns `{ok: true}`. |
| `POST /api/devices/<id>/request-report` | Requests a fresh telemetry report; `{ok: true, expires_at}`, or 429 while one is already pending. |
| `POST /api/devices/<id>/adopt` | Requires `{"acknowledge_adopt": true}`; returns `{receipt_id}`. 409 when the device already has an active receipt; routers cannot be adopted. |
| `POST /api/devices/<id>/onboard`, `POST /api/devices/<id>/undeploy` | Starts the job; `{job_id}`. 409 when the device is busy with the opposite action. |

Router deployments carry extra preflight and ownership rules — see
[Management Type and VLAN Ownership](network-attachment.md#router-preflight-and-ownership).

### Onboarding jobs

| Route | Body / result |
| --- | --- |
| `GET /api/onboard/jobs` | `{jobs: [...], max_concurrent, now}`. |
| `GET /api/onboard/jobs/<id>` | One job, or 404. |
| `GET /api/onboard/jobs/<id>/stream` | Server-sent events for that job until it reaches a terminal state. |
| `POST /api/onboard/jobs/<id>/abort` | `{aborted: true}`. |
| `POST /api/onboard/cancel-queued` | `{cancelled: <count>}` — drops jobs still queued. |

### Credentials

| Route | Body / result |
| --- | --- |
| `GET /api/credentials` | `{profiles: [...]}` — id, name, and device user only, never passwords. |
| `POST /api/credentials` | Creates or updates a profile; returns `{profile}` redacted the same way. |
| `DELETE /api/credentials/<id>` | `{deleted: <bool>}`. |

### Monitoring

| Route | Body / result |
| --- | --- |
| `GET /api/overview` | The dashboard rollup: image, device, and rollout state. |
| `GET /api/swarm` | The telemetry `/swarm` JSON, fetched over loopback. Answers 200 with `{"peers": [], "error": ...}` when the telemetry listener is unreachable. |
| `GET /api/audit` | `{events: [...]}`; `category`, `limit` (max 500), `before_ts`, and `after_ts` query parameters. |
| `GET /api/audit/histogram` | Per-bucket audit event counts for the activity strip. |
| `GET /swarmmap` | The swarm map page itself. Session-gated like the `/api` routes, but not under `/api`. |

### Import skip reasons

`skipped` entries carry the same fields as importable ones plus a `reason`, and
the console greys them out so a file you expected to see does not just silently
fail to appear. There are exactly three reasons.

| Reason | Meaning |
| --- | --- |
| `already published` | The derived catalog id is already in the catalog, or a publish for that id is in flight — an in-flight publish counts, because the entry appears only when the async job finishes. A catalog `filename` match counts too. `publish.derive_id()` strips `.SPA.bin` or `.bin`, so `foo.bin` and `foo.SPA.bin` are one catalog id. |
| `ambiguous name in more than one location` | The same basename, or the same derived id, exists under more than one root. The startup re-seed can resolve a torrent to a directory by basename and the seeder runs with `bt-seed-unverified`, so a wrong guess would serve the wrong bytes under correct piece hashes. IRIS refuses rather than guess: keep one copy. |
| `not readable by the server` | The file exists but uid 10001 cannot open it. Listing a file needs only its directory, so without this check an unreadable image would pass discovery and fail deep inside publish. Root-owned mode `0600` images left in a volume by an older root-runtime container land here; the fix is the volume-ownership migration in [Server](server.md#upgrading-from-a-root-runtime-deployment). |

A file is only listed at all if it is a `.bin`, its basename passes the catalog
filename charset (`A-Za-z0-9._-`), it is not a dotfile, sidecar `.torrent`, or
`.upload-*` temp file, and its resolved path is still inside the root it was
found under — a symlink cannot pull a file from outside the mount into the set.
Each distinct tree is walked once, so pointing both roots at the same directory,
or nesting one inside the other, yields each file exactly once.

## Catalog entry fields

Catalog entries live in `<state>/catalog.json`; each image's metainfo file is
written to `<state>/torrents/<image_id>.torrent`, never next to the image itself.

| Field | Meaning |
| --- | --- |
| `id` | Catalog id, derived from the filename by stripping `.SPA.bin` or `.bin`. What a device policy names. |
| `filename` | Basename of the image file, as it reaches the device. |
| `source_dir` | Absolute directory the image is seeded from. Set by `publish()`. |
| `size` | Image size in bytes. |
| `sha256` | Checked by the agent against the staged file. |
| `sha512` | Checked by the agent against the flash-root copy via `verify /sha512` (IOS has `/sha512` but not `/sha256`). |
| `cisco_signature_verified` | Whether the Cisco signature was verified elsewhere. The server never checks it; the device is the on-box trust gate. |
| `info_hash_hex` | Torrent info hash, used to stop seeding on delete. |
| `published_at` | Unix timestamp of the publish. |

`source_dir` is what makes in-place publishing safe. A delete unlinks the image
file only when `source_dir` resolves to `IRIS_IMAGES_DIR`, so an image published
from the read-only root stays on disk and a same-named file in the uploads volume
is never destroyed. Entries published before `source_dir` was recorded keep the
older behaviour: their delete unlinks `IRIS_IMAGES_DIR/<filename>`. The startup
re-seed likewise prefers `source_dir`, falling back to its basename walk for
entries with no `source_dir` or whose recorded directory has gone away.

## Device agent config keys

The agent reads `key = value` lines from
`/flash/guest-share/iris/iris-agent.conf` (override with `IRIS_AGENT_CONF`).

| Key | Default | Effect |
| --- | --- | --- |
| `device_ssh_known_hosts` | unset | Path to a `known_hosts` file pinning the device's SSH host key. When the key is set and the file exists, the agent's SSH and SCP calls use `StrictHostKeyChecking=yes` against it. Otherwise they keep the default `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null`. |

The pin is opt-in and verify-if-present, the same shape as the catalog client's
TLS pinning: setting it on one device changes nothing elsewhere, and an agent
upgrade on a fleet whose config omits it behaves identically. It applies to the
container runtime mode (the IOx SSH-to-self path) only — the Guest Shell agent
uses the on-box `cli` module and never opens an SSH session. Nothing in IRIS
writes this key for you.

## Generated outputs

| Output | Source |
| --- | --- |
| `site/` | Zensical build output. Not committed. |
| `deploy/` | GitHub Pages assembly directory. Not committed. |
| `fleet/dist/` | Generated device installers. Not committed. |
| `artifacts/` | Served runtime artifacts. Not committed except `.gitkeep`. |
| `release/` | Release packaging output. Not committed. |
