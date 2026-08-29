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

Most of these have a console equivalent; the command line is not the only way to run them — see [When to use the CLI](console.md#when-to-use-the-cli).

Docs build commands and their tool pins live in [Development](development.md#documentation-loop).

## Port quick reference

| Port | Transport | Protocol | Service | Device-facing |
| --- | --- | --- | --- | --- |
| 6969 | TCP | HTTP | Tracker | Yes |
| 8443 | TCP | HTTPS | Catalog | Yes |
| 8000 | TCP | HTTPS | Artifact server | Yes |
| 6881 | TCP | BitTorrent | Seeder data | Yes |
| 8080 | TCP | HTTPS | Web console | Operator-facing |
| 9101 | TCP | HTTP | Telemetry | Operator-facing |
| 6800 | TCP | HTTP | aria2 RPC | No, local-only |

Every port is TCP. IRIS opens no UDP listener.

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
| `IRIS_SAMPLE_INTERVAL` | `15` (seconds) | Seeder/telemetry poll cadence. A transfer that completes inside one interval can be observed with no connected peer, so per-peer rates and the map's measured edges never appear — a 1 GB image at ~90 MB/s lands in about 15 seconds. Lower it to 2–5 on a fast fabric or for a live demo; the cost is more aria2 RPC calls. |
| `IRIS_REQUIRE_IDENTITY_GATE` | unset (off) | Set to `1` to make the catalog answer 503 to every per-device torrent request until the checkpoint file `identity-compatible-ready` exists under `IRIS_STATE` — the file a proven seeder rotation writes and `--recover` removes. Read per request, so opening or closing the gate needs no restart. The canonical (service) torrent path is unaffected. A deployment that does not set it serves per-device torrents as before. |
| `IRIS_ONBOARD_CONCURRENCY` | `25` | Maximum onboard/undeploy jobs the worker pool runs at once; the rest queue. `GET /api/onboard/jobs` reports the active value as `max_concurrent`. |

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

### TLS trust and console certificate

The console's *Settings → TLS & trust* sub-page (Certificate and Trusted CAs sections)
manage these; none needs to be set anywhere — the defaults below are the
container paths, and with no override installed and an empty
trust dir the behavior is identical to releases without the feature.

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_GUI_CERT` | `/run/iris/tls/gui-cert.pem` | Combined cert+key the web console serves **when the file exists**; otherwise the console serves the shared `IRIS_CERT`. Only the console reads it — the catalog and artifact server keep the device-pinned certificate either way. |
| `IRIS_TRUST_DIR` | `/etc/iris/tls/trust` | Durable directory of installed root-CA PEMs: one `<sha256-fingerprint>.pem` per manual install, plus the downloaded public bundle as the distinguished file `downloaded-bundle.pem`. |
| `IRIS_CA_BUNDLE` | `/run/iris/tls/ca-bundle.pem` | Runtime concatenation of the trust dir, rebuilt at every boot and on every trust change. Absent while the trust dir is empty. Outbound TLS (OTLP export, the CA-bundle download) verifies against the system store plus this bundle. |

The console certificate override persists as
`/etc/iris/tls/gui-crt.pem` (plaintext certificate, leaf or fullchain) plus
`/etc/iris/tls/gui-key.pem.age` (private key, age-encrypted to the same
recipients as the rest of the secret store); boot rebuilds `IRIS_GUI_CERT`
from the pair. An override that fails to decrypt — or whose certificate and key
do not form a matching pair — is skipped with a warning, so the console falls
back to the built-in certificate and a bad upload can never lock you out of the
console.

The public-CA download settings live in `$IRIS_STATE/ca-trust-settings.json`
(`{"url": ..., "auto": ...}`, console-owned): the URL must be `https://`, and
while `auto` is on the console re-downloads the bundle every 24 hours. The
default URL when none is configured is Cisco's Trusted Root Store,
`https://www.cisco.com/security/pki/trs/ios.p7b` (Cisco refreshes this bundle
over time; enable the daily auto-download to track it). The downloader accepts plain PEM, a certs-only
PKCS#7 bundle (DER or PEM), or a CMS-signed wrapper in that shape — a signed
wrapper's own transport-signer certificates are never imported, only the
payload once its signature verifies, and a tampered wrapper is rejected
outright. Failed downloads never overwrite the previous good bundle.

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

External telemetry is off by default: IRIS does not assume any observability
stack exists — it emits OpenTelemetry (OTLP), and the operator chooses the
collector and backend.

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_OBSERVABILITY` | unset (off) | Enables the external observability surface when set to `1`, `true`, `yes`, or `on`. Any other value, empty, or unset leaves it off. For OTLP export this is the deployment default only — a console override (below) takes precedence. The Prometheus `:9101` surface stays startup-gated by this variable alone. |
| `IRIS_OTLP_ENDPOINT` | unset | OTLP/HTTP endpoint of your collector, e.g. `http://<collector-ip>:4318`. Deployment default only — the console's *Settings → Telemetry* sub-page can override it at runtime. |
| `IRIS_METRICS_PORT` | `9101` | Port for the telemetry listener. Empty or `0` disables the listener entirely. |
| `IRIS_METRICS_HOST` | `0.0.0.0` | Bind host for the telemetry listener. Bind it to `127.0.0.1` when only the console's session-gated proxy consumes it. |
| `IRIS_SWARM_URL` | `http://127.0.0.1:9101/swarm` | Where the console fetches swarm state from. A non-loopback value requires `IRIS_SWARM_PUBLIC=1` on the target listener — `/swarm` answers only loopback peers by default. |
| `IRIS_SWARM_PUBLIC` | unset (off) | Opens `:9101/swarm` to any peer that can reach the port. Default: loopback peers only — the console proxies swarm data over container loopback, so remote access is normally unnecessary. The flag relaxes only the peer-address gate; `IRIS_METRICS_HOST` still controls where the listener binds, so a `127.0.0.1` bind keeps everything local regardless. |
| `IRIS_OTLP_HEADERS` | unset | Comma-separated `Name=Value` headers attached to every OTLP POST (collector authentication). Values are secrets: never logged, never echoed in errors, and the exporters refuse HTTP redirects so they cannot leak to a redirect target. |
| `IRIS_OTLP_HEADERS_FILE` | unset | Read the header spec from a file instead (secret mounts). `IRIS_OTLP_HEADERS` wins when both are set. |
| `IRIS_OTLP_DEVICE_METRICS` | unset (off) | Still accepted so an existing deployment starts, but retired: the per-device OTLP gauges it enabled are no longer exported. Device- and peer-labelled history lives in the OTLP log records instead. |
| `IRIS_EVENTS_URL_TEMPLATE` | unset | Still injected into the swarm map's page config as `eventsUrlTemplate`, but the current map renders no events link — setting it has no visible effect. |

#### Telemetry gating rule

* Prometheus `/metrics` is served only while `IRIS_OBSERVABILITY` is enabled; otherwise the path answers 404.
* OTLP export requires **both** an effective enabled flag **and** an effective endpoint. Each field is the console override from `$IRIS_STATE/telemetry-destination.json` when set, else the deployment env (`IRIS_OBSERVABILITY` / `IRIS_OTLP_ENDPOINT`). An endpoint on its own is inert — nothing is exported.
* `/healthz` and the `/swarmmap` pointer page are served whenever the listener runs, regardless of either variable. `/swarm` answers only loopback peers by default (the console proxies it); `IRIS_SWARM_PUBLIC=1` opens it to remote peers.
* The console reads `/swarm` over container loopback (`127.0.0.1:9101`), so port 9101 needs external reachability only for Prometheus scraping or operator tools — never for the console.

`IRIS_OBSERVABILITY` still decides the Prometheus `/metrics` surface at
startup — that gate is unchanged and takes effect on the next restart. The
OTLP destination, by contrast, is re-read on every sample pass: the console's
*Settings → Telemetry* stores a per-field override in
`$IRIS_STATE/telemetry-destination.json` (`endpoint`, `enabled`; a `null`
field inherits the env), applied within seconds without a restart. *Revert to
deployment default* deletes the file, restoring exact env behavior. The
startup log states which posture is in effect at boot.

!!! note "A down Prometheus target is not a fault"
    With observability off, a Prometheus job scraping IRIS reads down and an
    operator dashboard is blank. That is telemetry being off, not a broken
    server. Set `IRIS_OBSERVABILITY` to get the scrape surface, and
    `IRIS_OTLP_ENDPOINT` as well to get event export.

## Console API

Every `/api` route requires an authenticated console session cookie except two
pre-auth routes: `POST /api/login` and `POST /api/setup`. State-changing methods
on the authenticated routes additionally require the session's CSRF token in an
`X-CSRF-Token` header (double submit); without it the request is rejected with
403. The two pre-auth routes carry no CSRF token, because there is no session
yet. JSON request bodies are capped at 64 KiB — the exceptions are the CSV import
at 8 MiB, the streamed image upload at 4 GiB, and the offline Bulk Hash feed
upload at 256 MiB.

### Session and settings

| Route | Body / result |
| --- | --- |
| `POST /api/login` | Pre-auth. `{username, password}` → `{username, csrf}` plus the session cookie; 401 on bad credentials. Before any admin exists, signing in with the default `iris` / `irisisgreat!` credential instead returns `{setup: true, setup_grant}` — no session — for use with `POST /api/setup` below. |
| `POST /api/setup` | Pre-auth, first run only. `{username, password, setup_grant}` creates the admin account, where `setup_grant` is the one-time, 10-minute grant from the default-credential login above; 403 on a missing/invalid/expired grant, 409 once an admin exists. |
| `POST /api/logout` | Revokes the current session and expires the cookie. |
| `GET /api/session` | The current session's info, or 401. |
| `GET /api/settings` | Console settings, published port, and the running version — plus the active console certificate (`gui_cert`), the installed trust entries (`trust`), the CA download settings (`ca_trust`), the effective telemetry destination with its source (`telemetry_destination`), and the audit-export destination with its last-run status (`audit_export`; a `password_set` flag only, never the password). |
| `GET /api/settings/setup-status` | The setup status behind both the first-run wizard (`#setup`) and the Settings → Setup panel: `admin`, `telemetry`, `stage_host`, and `packages`, each with a `state` of `ok`, `unset`, `stale`, `absent`, or `unknown`. `telemetry` is `ok` only when export is enabled *and* an endpoint resolves, and also carries `source` (`override` or `env`), `endpoint`, and `enabled`. `packages` additionally carries `items` (per-package build time, state, and reason), `reference_fingerprint`, and a `remedy` command. See [Setup](console.md#setup). |
| `POST /api/settings/password` | `{current, new, confirm}`; changes the admin password and revokes every other session. |
| `POST /api/settings/sessions/revoke-others` | Revokes every session except the caller's. |
| `POST /api/settings/stage-host` | Stores the stage-host SSH credential; returns the redacted record. |
| `DELETE /api/settings/stage-host` | `{deleted: <bool>}` — clears that credential. |
| `POST /api/settings/gui-cert` | `{cert_pem, key_pem}` — validates (real `load_cert_chain`; per-field errors on garbage PEM or key mismatch) and installs the console certificate, hot-applied. |
| `DELETE /api/settings/gui-cert` | Reverts the console to the built-in certificate, hot-applied. |
| `POST /api/settings/trust` | `{pem}` — installs one or more CA certificates as one trust entry; returns `{entry}`, the new trust-store row. |
| `DELETE /api/settings/trust/<name>` | Removes one trust entry and rebuilds the runtime bundle. |
| `POST /api/settings/ca-trust` | `{url, auto}` — configures the public-CA bundle download; the URL must be `https://`. |
| `POST /api/settings/ca-trust/refresh` | Starts a download-now job; returns `{job}`. Downloads refuse redirects, cap at 2 MiB, and must yield at least one certificate (plain PEM, a certs-only PKCS#7 bundle, or a verified CMS-signed wrapper). |
| `GET /api/settings/ca-trust/refresh/<id>` | `{state, detail, certs}` — `running`, `done`, or `failed`. |
| `POST /api/settings/telemetry-destination` | `{endpoint, enabled}` — telemetry destination override, hot-applied by the hub. The endpoint must be an `http`/`https` URL with a host, no query or fragment; a trailing slash is stripped. |
| `DELETE /api/settings/telemetry-destination` | Removes the override — telemetry reverts to the deployment env defaults. |
| `POST /api/settings/audit-export` | `{host, port, user, path, age_recipient, auto, password}` — validates and stores the audit-export destination; 400 on any invalid field. An absent or empty `password` keeps the stored one. |
| `DELETE /api/settings/audit-export` | `{deleted: <bool>}` — clears the destination and the stored password. |
| `POST /api/settings/audit-export/run` | Starts one export job; returns `{job_id}`. 409 when the export is not fully configured (invalid or absent destination, or no stored password). |
| `GET /api/settings/audit-export/run/<id>` | `{state, detail}` — `running`, `done`, or `error`; `detail` is the uploaded filename or the failure reason. Jobs are in-memory, so a restart forgets them (404). |

The audit-export settings live in `$IRIS_STATE/audit-export-settings.json`
(`host`, `port`, `user`, `path`, `age_recipient`, `auto`, plus the
server-maintained `last_run_ts` / `last_result`; console-owned). The SCP
password is not in this file — it lives in the age-encrypted secrets store —
and the destination's SSH host key is pinned trust-on-first-use in
`$IRIS_STATE/audit-export-known-hosts`. See
[Audit export](operations.md#audit-export).

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

### Image verification

| Route | Body / result |
| --- | --- |
| `GET /api/settings/image-verification` | `{mode, hour_utc, last_run}` — the Cisco Bulk Hash reconciliation schedule and the outcome of its most recent run. |
| `POST /api/settings/image-verification` | `{mode, hour_utc}` — a full replace of the schedule; `mode` is `off`, `daily`, or `weekly` (weekly always anchors to Monday UTC — there is no day-of-week field), `hour_utc` is 0-23. `last_run` is server-managed and cannot be set here. |
| `POST /api/image-verification/refresh` | Runs the reconciler now (`source=manual`), synchronously on this request. `{outcome: "ok", matched, mismatched, not_in_feed}` (200); `{outcome: "already_running"}` (409, another run is already in flight); `{outcome: "fail", detail}` (502 — fetch, signature, parse, or reconcile failed, and the catalog is left untouched). |
| `POST /api/image-verification/offline` | Raw `.tar` body (256 MiB cap), for air-gapped servers — runs the identical verify-then-parse pipeline against the uploaded file instead of fetching one (`source=offline`); same result shape and status codes as refresh. |
| `POST /api/images/<id>/release-quarantine` | `{override, confirm_text}` — lifts an active quarantine. `override=false` re-checks the image's sha512 against the stored feed verdict and releases it if that now agrees, else 409 `quarantine_still_mismatched` with the verdict. `override=true` requires `confirm_text` to exactly match the image's filename (400 otherwise) and releases regardless of the mismatch, recorded as a distinct `release_override` audit action; the stored verdict itself is left as `mismatch`. 404 if the image does not exist; 400 if it is not currently quarantined. |

Each catalog entry in `GET /api/images` carries a `quarantined` bool and a
`hash_verification` object — `{state, checked_at, feed_published_at, source,
deferral}` — once at least one reconciliation run has covered it; both are
absent/falsy on an entry the reconciler has never touched. `state` is
`verified`, `mismatch`, or `not_in_feed` (no feed row matches the image by
file name and size, or by file name alone against a feed row publishing no
size — the expected state for a customer-built image Cisco never
published); `source` is `scheduled`, `manual`, or `offline`,
whichever run last produced the verdict; `deferral` is `true` when the
matched feed row's `DEFERRAL_STATUS` is present and not `Active` — a
Cisco-side warning that never affects `state`. `checked_at` is the Unix
timestamp of that run; `feed_published_at` is Cisco's own `PUBLISH_DATE`
string from the feed row, carried through unparsed. See [Cisco Bulk Hash
verification](security.md#cisco-bulk-hash-verification) and [Image
verification](operations.md#image-verification).

### Devices

| Route | Body / result |
| --- | --- |
| `GET /api/devices` | `{devices: [...], now}` — the inventory view plus the server clock, so the UI computes freshness server-clock-to-server-clock. |
| `POST /api/devices` | Creates or updates one inventory row; returns `{device: ...}`. |
| `DELETE /api/devices/<id>` | Retires the device: revokes its credentials first, then clears peer-policy assignment, inventory row, and catalog state. `{deleted: <bool>, degraded: [...]}` — 200 when cleanup was complete, 207 when part of it failed (`degraded` names the areas), 500 `{deleted: false, error: "secret revoke failed"}` when the revoke could not be persisted, in which case nothing was changed. Endpoint rows are retained until they age out. See [Retiring a device](operations.md#retiring-a-device). |
| `GET /api/devices/export-csv`, `GET /api/devices/example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/devices/import-csv` | Bulk inventory import (8 MiB cap, all-or-nothing); returns per-row stats. |
| `GET /api/devices/<id>/plan` | `{plan}` — the resolved deployment plan; 409 when it cannot resolve. |
| `GET /api/devices/<id>/reports` | `{reports: [...]}` — the device's stored telemetry ring. |
| `GET /api/devices/<id>/deployment` | `{receipt, total}` — the receipt that best describes the device (the active one, else the teardown-authorizing one, else the newest) plus the stored-receipt count; `receipt` is `null` when none exists. Read-only — feeds the deployment-details panel. |
| `POST /api/devices/<id>/assign` | `{image_ids: [...]}` sets the device's ordered, up-to-ten-image approved set (an empty array unassigns); the singular `{image_id: <id or null>}` is the pre-multi-image compat shape and always means a one-element set. 400 for more than ten ids, a duplicate, or an id not in the catalog; 400 `image_quarantined` with the blocking verdict if one of the ids is currently quarantined by the Cisco Bulk Hash reconciler (see [Image verification](#image-verification)). See [Policy schema](#policy-schema). |
| `POST /api/devices/<id>/credential`, `.../platform` | Sets the credential profile, or the platform (Agent install choice) and storage target; each returns `{ok: true}`. |
| `POST /api/devices/<id>/request-report` | Requests a fresh telemetry report; `{ok: true, expires_at}`, or 429 while one is already pending. |
| `POST /api/devices/<id>/adopt` | Requires `{"acknowledge_adopt": true}`; returns `{receipt_id}`. 409 when the device already has an active receipt; routers cannot be adopted. |
| `POST /api/devices/<id>/onboard`, `POST /api/devices/<id>/undeploy` | Starts the job; `{job_id}`. 409 when the device is busy with the opposite action. Undeploy also answers 409 when the device has no deployment receipt — send `{"force": true}` to run it anyway, which removes only the IRIS-named agent footprint and leaves operator-owned network state (VLAN/SVI, VirtualPortGroup, NAT) untouched, audited as `undeploy_forced`. |

Router deployments carry extra preflight and ownership rules — see
[Management Type and VLAN Ownership](network-attachment.md#router-preflight-and-ownership).

### Onboarding jobs

| Route | Body / result |
| --- | --- |
| `GET /api/onboard/jobs` | `{jobs: [...], max_concurrent, now}`. |
| `GET /api/onboard/jobs/<id>` | One job, or 404. |
| `GET /api/onboard/jobs/<id>/stream` | Server-sent events for that job until it reaches a terminal state. |
| `POST /api/onboard/jobs/<id>/abort` | `{aborted: true}`. |
| `POST /api/onboard/cancel-queued` | `{cancelled: <count>}` — drops jobs still queued. An optional `{"job_ids": [...]}` body scopes the cancel to those jobs (the console always scopes); without it every queued job is cancelled, other sessions' included. |

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
| `GET /api/deploy-logs` | `{logs: [...]}` — metadata for the persisted per-job deployment logs (file, device, action, state, rc, finish time, size), newest first. `device_id` filters to one device; `after_ts` / `before_ts` (Unix seconds, inclusive at both ends) filter by finish time — the range the Deployment logs brush selects. |
| `GET /api/deploy-logs/histogram` | `{buckets: [{start, count}], now}` — evenly spaced counts of finished jobs, for the time filter's histogram. Takes `window` (seconds, default 604800) or an explicit `since_ts`/`until_ts` pair, `buckets` (default 30, capped at 200), and `device_id`; 400 when `until_ts` is not greater than `since_ts`. |
| `GET /api/deploy-logs/<file>` | One persisted log as `text/plain`; 404 for a name that does not resolve to a direct child of the log directory. |
| `GET /api/help` | `{version, deployment_id, docs_url, guides}` — the "?" popover data: the running version, the stable per-deployment id, and the documentation links. |
| `POST /api/telemetry/stream` | `{"every": <int 1..60>, "pause": <bool>}` — network-wide stream tuning, echoed to every device on its next heartbeat. Audited. |
| `GET /api/telemetry/health` | The hub's `/healthz` JSON (OTLP export health), proxied behind the console session. `{"ok": false, "error": "unavailable"}` when the hub is unreachable. |
| `GET /swarmmap` | The swarm map page itself. Session-gated like the `/api` routes, but not under `/api`. |

Persisted deployment logs are plain files under `$IRIS_STATE/deploy-logs`,
one per finished onboard or undeploy job with a machine-parseable header
line; the newest 200 are kept. `/api/help`'s `deployment_id` comes from
`$IRIS_STATE/instance-id`, minted once on first start and immutable after.

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
| `size` | Image size in bytes. What the agent attests the placed copy against. |
| `sha256` | Checked by the agent against the staged file. |
| `sha512` | Recorded at publish time and never recomputed on a device. Once this image is joined to a Cisco Bulk Hash feed row (by file name and size), this is the value compared against that row's published sha512 — see [Image verification](#image-verification). |
| `cisco_signature_verified` | `True` exactly when this entry's `hash_verification.state` is `verified` — kept in sync by the Cisco Bulk Hash reconciler on every run that covers this image. `False` for `mismatch`, `not_in_feed`, or before the first run ever covers it. On the device, the check is still the agent's sha256 of the staged file against this entry's `sha256`; nothing re-hashes the placed copy. |
| `hash_verification` | `{state, checked_at, feed_published_at, source, deferral}` — the reconciler's most recent verdict for this image; absent until the first reconciliation run covers this entry. See [Image verification](#image-verification). |
| `quarantined` | `True` once a `mismatch` verdict has quarantined this image. Only `POST /api/images/<id>/release-quarantine` clears it — a later `verified` verdict alone does not. See [Releasing a quarantine](operations.md#releasing-a-quarantine). |
| `info_hash_hex` | Torrent info hash, used to stop seeding on delete. |
| `published_at` | Unix timestamp of the publish. |

`source_dir` is what makes in-place publishing safe. A delete unlinks the image
file only when `source_dir` resolves to `IRIS_IMAGES_DIR`, so an image published
from the read-only root stays on disk and a same-named file in the uploads volume
is never destroyed. Entries published before `source_dir` was recorded keep the
older behaviour: their delete unlinks `IRIS_IMAGES_DIR/<filename>`. The startup
re-seed likewise prefers `source_dir`, falling back to its basename walk for
entries with no `source_dir` or whose recorded directory has gone away.

## Policy schema

`policy.json` (`<state>/policy.json`) holds per-device staging approval — what
IRIS is allowed to stage, never what it installs, activates, or reloads.

| Field | Meaning |
| --- | --- |
| `approved_image_ids` | Ordered list of catalog image ids, up to ten. The agent stages and verifies every id in the set, transferring them in parallel. Authoritative: a raw read of this file, or a stale write, is resolved from this key, never from `approved_image_id`. |
| `approved_image_id` | The set's first element, or `null` when empty. Recomputed from `approved_image_ids` on every read and write — kept only so a reader that predates the ordered set (a raw `policy.json` parse, or an agent that has not yet upgraded) still sees a single assignment. |

`POST /api/devices/<id>/assign` (see [Devices](#devices)) writes this file.

The device's heartbeat (`devices.json`, `<state>/devices.json`) reports
per-image staging progress against that set:

| Field | Meaning |
| --- | --- |
| `current_image_id` | Wire-compatible identity pointer: the first image of the set that produced heartbeat data this tick — typically one already staged. It is **not** the image being transferred, and per-image state must not be read from it; it exists so a reader that predates the ordered set still sees a single image id. |
| `stage_state` | One state string for the whole tick. On a one-image heartbeat it is that image's own state (for example `staging`, `downloading`, `transferring_to_ios`, `ready`, `error`). For a set the agent collapses the tick into the single most actionable state across every assigned image, so it describes the set, not `current_image_id`. `stage_error`, likewise, is one reason per tick. |
| `staged_image_ids` | Which of the assigned images this agent has staged and verified, as of its last heartbeat. Absent on a one-image heartbeat (and on an agent that predates multi-image staging), in which case staged/not-staged falls back to `stage_state == "ready"` paired with `current_image_id`. |
| `errored_image_ids` | Which of the assigned images hit a terminal per-image failure on the agent's last tick, including retryable ones such as a full boot filesystem. Absent on a one-image heartbeat and on an agent that predates the field. |

## Device agent config keys

The agent reads `key = value` lines from
`/flash/guest-share/iris/iris-agent.conf` (override with `IRIS_AGENT_CONF`).

| Key | Default | Effect |
| --- | --- | --- |
| `device_ssh_known_hosts` | unset | Path to a `known_hosts` file pinning the device's SSH host key. When the key is set and the file exists, the agent's SSH and SCP calls use `StrictHostKeyChecking=yes` against it. Otherwise they keep the default `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null`. |
| `telemetry_stream` | `off` | Live transfer-sample streaming ([Transfer streaming](observability.md#transfer-streaming)). Fail-closed: only an explicit `on`/`1`/`true`/`yes` enables; requires `telemetry` on. Delivered by the installers (`TELEMETRY_STREAM`) and IOx deploy env (`IRIS_TELEMETRY_STREAM`), and changed by redeploy. |

The pin is opt-in and verify-if-present, the same shape as the catalog client's
TLS pinning: setting it on one device changes nothing elsewhere, and an agent
upgrade on a network whose device configs omit it behaves identically. It applies to the
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
