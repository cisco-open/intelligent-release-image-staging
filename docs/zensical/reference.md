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
| `tools/provision-iox-packages.sh` | Build and stage both architecture-specific IOx packages. |
| `CATALOG_PEM=<pem> tools/build-xr-package.sh --out artifacts/` | Build the IOS-XR appmgr RPM against the live catalog certificate. |
| `device/xr-install.sh` | Onboard the IOS-XR appmgr agent. |
| `device/xr-uninstall.sh` | Remove the IOS-XR appmgr agent footprint. |
| `tools/check-package-freshness.sh` | Check IOx certificate pins and the XR RPM build-time proxy against the live certificate. |
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

!!! important "How a variable reaches the container"
    Compose injects **only** the keys named in the `environment:` block of
    `server/docker-compose.yml`. Exporting a variable in your shell, or adding a
    line to `server/.env`, sets it for *interpolation* — Compose substitutes it
    into `"${VAR:-…}"` on the right-hand side of that block, and a variable the
    block never names is silently dropped. Every variable in the tables below is
    named there, so `server/.env` (or an `export`) is the supported way to set
    any of them. A variable that is **not** in these tables — an internal tuning
    value, or one added to the code later — needs a line added to the
    `environment:` block before it has any effect.

    Kubernetes differs: `kubernetes/kustomization.yaml` generates the ConfigMap
    from `kubernetes/iris-seed-server.env` and the pod pulls it with `envFrom`,
    so any key in that file reaches the process without a manifest change.

### Optional at deploy time

| Variable | Default | Effect |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `server` (the `name:` in `server/docker-compose.yml`) | Compose project name, and therefore the prefix on the named volumes (`server_iris-state`, `server_iris-config`, `server_iris-images`). Host-side only: read by Compose itself, never passed into the container. The declared default is the same name the directory used to derive, so an existing deployment keeps its volumes and needs no migration. Set it to give a second checkout on the same host its own volumes — see [Server](server.md#compose-project-name). |
| `IRIS_CONTAINER` | `iris` | Name of the server container: Compose applies it as `container_name`, and `tools/apply-assignments.sh`, `tools/stage-iox-package.sh`, `tools/gen-device-installers.sh` and `tools/check-package-freshness.sh` address that name. Host-side only. Container names are host-global, so a second stack needs this as well as `COMPOSE_PROJECT_NAME`. `tools/start-compose-server.sh` resolves the container from its own Compose project when this is unset. |
| `IRIS_ARTIFACTS_HOST_DIR` | `../artifacts` | Host directory bind-mounted read-write at `/srv/artifacts`. Host-side only: it is interpolated into the bind mount, not passed into the container. |
| `IRIS_SHARP_SANS_FONT_HOST` | `/dev/null` | Host path of the licensed Sharp Sans Bold `.woff2`, bind-mounted read-only over `server/webroot/fonts/SharpSans-Bold.woff2` inside the container. The font is excluded from the build context (`.dockerignore`) and the release tarball — Cisco's license does not permit redistributing it — so the console falls back to its default font stack without it (`font-display: swap`). Set this only on a deployment that independently holds the license; left unset it mounts `/dev/null`, a harmless no-op every other deployment never has to think about. Host-side only: interpolated into the bind mount, never passed into the container. See [Console](console.md#branding). |
| `IRIS_GUI_PUBLISH` | `8080` | Published host port for the console. The container always listens on 8080 internally. |
| `IRIS_CONSOLE_URL` | unset | Overrides the console link on the port 9101 pointer page verbatim, for hosts publishing the console somewhere other than `https://<IRIS_HOST_IP>:8080/`. Read per request. |
| `IRIS_GUI_ALLOW_PLAINTEXT` | unset | `1` lets the console serve plain HTTP when no usable certificate exists (`IRIS_GUI_CERT` / `IRIS_CERT`). Without it `iris-gui` refuses to start in that state. The session cookie loses its `Secure` attribute under the opt-in. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_CATALOG_ALLOW_PLAINTEXT` | unset | `1` lets the catalog serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `catalog.py` refuses to start in that state — every route answers a device bearer token. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped `docker-entrypoint.sh` always provisions `IRIS_CERT`, so this only matters running `catalog.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_ARTIFACTS_ALLOW_PLAINTEXT` | unset | `1` lets the artifact server serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `artifact_server.py` refuses to start in that state — staging URLs are the only authorization on the capability-bearing enrollment files it serves. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped `docker-entrypoint.sh` always provisions `IRIS_CERT`, so this only matters running `artifact_server.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_VERSION` | unset | Build argument that bakes the release string the console's Settings page shows. Unset means the `VERSION` file in the image. Build-time only: it is not a container variable. |
| `IRIS_GUI_ADMIN_PASSWORD` | unset (prompts) | Read by `iris-gui-admin` to set the console admin password non-interactively. Pass it on the one-shot command (`docker compose … run --rm -e IRIS_GUI_ADMIN_PASSWORD=… iris iris-gui-admin`); it is deliberately **not** in the Compose `environment:` block, so a long-running container never holds the password in its environment. |
| `IRIS_SAMPLE_INTERVAL` | `15` (seconds) | Seeder/telemetry poll cadence. A transfer that completes inside one interval can be observed with no connected peer, so per-peer rates and the map's measured edges never appear — a 1 GB image at ~90 MB/s lands in about 15 seconds. Lower it to 2–5 on a fast fabric or for a live demo; the cost is more aria2 RPC calls. |
| `IRIS_TRACKER_PORT` | `6969` | Port the tracker listens on. The canonical (seeder) announce, per-device personalized announces and the rotation CLI all derive their announce base from `IRIS_HOST_IP` and this port, so changing it needs the compose port mapping changed to match. |
| `IRIS_TRACKER_ANNOUNCE` | unset | Full announce base (`http://host:port/announce`, no query) used verbatim in place of the `IRIS_HOST_IP` + `IRIS_TRACKER_PORT` derivation, by every path that builds an announce URL. |
| `IRIS_REQUIRE_IDENTITY_GATE` | unset (off) | Set to `1` to make the catalog answer 503 to every per-device torrent request until the checkpoint file `identity-compatible-ready` exists under `IRIS_STATE` — the file a proven seeder rotation writes and `--recover` removes. Read per request, so opening or closing the gate needs no restart. The canonical (service) torrent path is unaffected. A deployment that does not set it serves per-device torrents as before. |
| `IRIS_ONBOARD_CONCURRENCY` | `25` | Maximum onboard/undeploy jobs the worker pool runs at once; the rest queue. `GET /api/onboard/jobs` reports the active value as `max_concurrent`. |
| `IRIS_XR_SESSION_TIMEOUT` | `150` seconds | Wall-clock bound for each IOS-XR command session. `0` disables it; an invalid value falls back to the default with a warning. |
| `IRIS_XR_SKIP_MOUNT_CHECK` | unset | **Test-only escape hatch — never set this on a device.** The IOS-XR entrypoint refuses to start unless its staging directory sits on a real bind mount, because an appmgr container activated without `-v /misc/disk1:/hostmount` would stage into its own filesystem and report an image staged to `harddisk:` while `harddisk:` holds nothing. Setting it to `1` disables that check, which the Bats suite needs to run the entrypoint against a plain temporary directory. |
| `IRIS_DEVICE_ENABLE_ALWAYS` | unset (off) | Compatibility escape hatch: each agent process starts by sending `enable` plus its secret on IOS-XE SSH sessions, and drops the pair for the rest of that process once a session's own prompt shows the login was already privileged (`#`). Normally IRIS learns whether escalation is needed from the device prompt and sends neither line to already-privileged logins. |
| `IRIS_ONBOARD_JOB_TIMEOUT` | `7200` seconds | Wall-clock deadline for one onboard/undeploy job, measured from the moment it starts **running** (never from when it was queued). A running job past the deadline is stopped like an operator abort. |
| `IRIS_ONBOARD_REAP_GRACE` | `60` seconds | Grace between the `SIGTERM` sent to a deadline-expired installer's process group and the `SIGKILL` that follows. |
| `IRIS_SEEDER_PREV_TTL` | `2592000` seconds (30 days) | How long a rotated-out seeder announce token keeps working, measured from the rotation that retired it — the overlap that lets a device which missed the rotation keep announcing while its torrent is re-personalised. Past it the tracker refuses the old token like any other expired credential, and the next rotation drops the record. Set it once, for the whole deployment: every process computes the deadline from this value, so a per-process override would make the same credential expire at different times. `0` means no overlap at all — the previous token is dead the moment it is rotated out — and a value that is not an integer raises at startup rather than falling back. See [Security](security.md#rotating-the-seeder-announce-credential). |
| `IRIS_HTTP_TIMEOUT` | `30` seconds | Per-connection socket timeout for the tracker and catalog request handlers: a connection that stalls mid-request is closed instead of pinning a thread. A non-numeric or non-positive value falls back to the default. |
| `IRIS_ENDPOINT_TTL` | `900` seconds | Freshness window for a device's durable peer endpoint in the endpoint map (`peer-endpoints.d/`). A missing, non-integer or non-positive value falls back to the default (a TTL of 0 would make every row stale and apply an empty blocklist under an `enforced` status). Endpoint rows for quarantined or revoked devices are retained regardless — see [Operations](operations.md#peer-policy-operations-and-their-backlog). |
| `IRIS_ENROLL_TTL` | `3600` seconds | Lifetime of the one-shot enrollment token minted into a per-device installer, overriding the standard catalog-token TTL for that first exchange only. |
| `IRIS_HEALTH_LISTENERS` | `tracker:6969,catalog:8443,artifacts:8000,console:8080` | What `:9101/readyz` TCP-probes, as `name:port,name:port`. Blank keeps the default set; the literal `off` checks nothing, for a deployment that runs a subset of the services and does not want the missing ones reported down. |
| `IRIS_AUDIT_RETENTION_DAYS` | `90` days | Audit entries older than this are dropped by timestamp on the next amortized prune. A non-integer or non-positive value falls back to the default. |
| `IRIS_AUDIT_MAX_EVENTS` | `50000` | Hard cap on surviving audit entries. A prune above the cap evicts the **oldest by file position** (append order), so a forged far-future timestamp cannot shield an entry and a wrong clock cannot mass-delete fresh ones. A non-integer or non-positive value falls back to the default. Raise both of these if you have a longer retention obligation — the trail is append-only JSONL and prunes itself. |
| `SEED_MAX_CONCURRENT` | `1000` | `--max-concurrent-downloads` for the origin seeder's aria2c. See [Operations](operations.md#scaling-notes) for when this matters; the device-side equivalent is `IRIS_MAX_CONCURRENT` in the container agents. |
| `IRIS_SSH_LEGACY` | `0` | `1` re-enables SHA-1 KEX, `ssh-rsa` and CBC ciphers for server-side device sessions, for old IOS-XE images that offer nothing else. |
| `IRIS_SSH_HOST_KEY` | unset | Pin one device/stage-host public host key (`<type> <base64>`) for strict verification. See [Security](security.md#device-ssh-host-keys). |
| `IRIS_SSH_KNOWN_HOSTS` | unset | Path to a `known_hosts` file to verify strictly against. With neither this nor `IRIS_SSH_HOST_KEY` set, host keys are recorded on first contact into a persistent `known_hosts` under `$IRIS_STATE/ssh` and must match afterwards; `/dev/null` is never used. |
| `SVI_IGP` | `none` | Routed Guest Shell installs only: `isis` adds `ip router isis` to the IRIS SVI, for fabrics (an SD-Access underlay, say) that must learn the IRIS subnet. The default injects nothing into your IGP. This is the fleet-wide fallback; a device's own inventory record (`svi_igp` column/field) overrides it per device, since one server can onboard devices into different fabrics. See [Management type](management-type.md). |

Parser behaviour is not uniform, so each row above states its own. Several of
the numeric knobs (`IRIS_HTTP_TIMEOUT`, `IRIS_ENDPOINT_TTL`,
`IRIS_XR_SESSION_TIMEOUT`, `IRIS_AUDIT_RETENTION_DAYS`,
`IRIS_AUDIT_MAX_EVENTS`) fall back to their default on a value they cannot
parse. `IRIS_HTTP_TIMEOUT`, `IRIS_ENDPOINT_TTL` and both audit knobs also fall
back on a **non-positive** one, so `0` is not a meaningful setting for them and
is treated as unset — it does not mean "no cap" on `IRIS_AUDIT_MAX_EVENTS`, and
it does not mean "keep nothing" on `IRIS_AUDIT_RETENTION_DAYS`. For an
effectively unbounded audit trail set a large number and give the volume the
space for it. (`IRIS_XR_SESSION_TIMEOUT` is the exception: `0` genuinely
disables its deadline, as its row says.)
The others are parsed with a bare `int()` and a garbage value raises at
startup rather than degrading — an *empty* value does too for
`IRIS_ONBOARD_CONCURRENCY`, `IRIS_ENROLL_TTL` and `IRIS_METRICS_PORT`, which is
why `server/docker-compose.yml` restates their defaults instead of passing an
empty string through. Set a real value or leave the variable unset; do not set
one to the empty string.

The host-side ownership these paths need is in
[Server](server.md#host-paths-to-chown-on-every-deploy).

The code also reads `IRIS_TOKEN_TTL`, `IRIS_TOKEN_REFRESH_AT`,
`IRIS_TOKEN_OVERLAP`, and `IRIS_TOKEN_SKEW_GRACE`. These are internal protocol
tuning values rather than supported independent deployment knobs: server and
device timing must remain coordinated, and Compose deliberately does not expose
them. Do not override one side in isolation.

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
* `/healthz`, `/readyz` and the `/swarmmap` pointer page are served whenever the listener runs, regardless of either variable. `/healthz` answers 200 unconditionally and proves only that the telemetry listener is alive; `/readyz` TCP-probes the tracker, catalog, artifact server and console and answers 503 naming any that are down — it is what the Compose `HEALTHCHECK` and the Kubernetes probes use, and `IRIS_HEALTH_LISTENERS` narrows or disables its probe set. `/swarm` answers only loopback peers by default (the console proxies it); `IRIS_SWARM_PUBLIC=1` opens it to remote peers.
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
| `POST /api/login` | Pre-auth. `{username, password}` → `{username, csrf}` plus the session cookie (`HttpOnly; SameSite=Strict`, plus `Secure` when the listener serves TLS); 401 on bad credentials, 429 with `Retry-After` when throttled, 503 with `Retry-After` when both password-verification slots are busy (not a credential failure: no limiter penalty, no audit row). Before any admin exists, signing in with the default `iris` / `irisisgreat!` credential instead returns `{setup: true, setup_grant}` — no session — for use with `POST /api/setup` below. |
| `POST /api/setup` | Pre-auth, first run only. `{username, password, setup_grant}` creates the admin account, where `setup_grant` is the one-time, 10-minute grant from the default-credential login above; 403 on a missing/invalid/expired grant, 409 once an admin exists. |
| `POST /api/logout` | Revokes the current session and expires the cookie. |
| `GET /api/session` | The current session's info, or 401. Any GET carrying `X-IRIS-Poll: 1` (the console's periodic refreshers) is validated without refreshing the session's idle clock. All `/api/*` responses carry `Cache-Control: private, no-store`; a present-but-unreadable secrets store answers 503 on every store-backed route. |
| `GET /api/settings` | Console settings, published port, and the running version — plus the active console certificate (`gui_cert`), the installed trust entries (`trust`), the CA download settings (`ca_trust`), the effective telemetry destination with its source (`telemetry_destination`), and the audit-export destination with its last-run status (`audit_export`; a `password_set` flag only, never the password). |
| `GET /api/settings/setup-status` | The setup status behind both the first-run wizard (`#setup`) and the Settings → Setup panel: `admin`, `telemetry`, `packages`, and `image_verification`, each with a `state` of `ok`, `unset`, `stale`, `absent`, or `unknown`. `telemetry` is `ok` only when export is enabled *and* an endpoint resolves, and also carries `source` (`override` or `env`), `endpoint`, and `enabled`. `packages` additionally carries `items` — the two IOx tars plus the IOS-XR agent RPM (`iris-xr.rpm`), each with its own build time, state, reason, and rebuild `remedy` command (the RPM's differs from the tars' — see [Setup](console.md#setup)); the RPM entry also carries a `detail` string naming exactly what was and was not verified, since its baked certificate cannot be pinned the way the tars' can — `reference_fingerprint`, and the card-level `remedy` command (the IOx tars' rebuild script). See [Setup](console.md#setup). |
| `POST /api/settings/password` | `{current, new, confirm}`; changes the admin password and revokes every other session. |
| `POST /api/settings/sessions/revoke-others` | Revokes every session except the caller's. |
| `POST /api/settings/gui-cert` | `{cert_pem, key_pem}` — validates (real `load_cert_chain`; per-field errors on garbage PEM or key mismatch) and installs the console certificate, hot-applied. Returns `{gui_cert, applied, note}`: `applied` is `false` (with a `note`) when the listener is not serving TLS, in which case the saved certificate takes effect at the next restart. |
| `DELETE /api/settings/gui-cert` | Reverts the console to the built-in certificate, hot-applied. |
| `POST /api/settings/trust` | `{pem}` — installs one or more CA certificates as one trust entry; returns `{entry}`, the new trust-store row. Every block must parse as an X.509 certificate; a decodable-but-not-a-certificate block rejects the whole upload (400). |
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
| `GET /api/devices` | `{devices: [...], now, total, offset, limit, revision}` — the inventory view plus the server clock, so the UI computes freshness server-clock-to-server-clock. `total` is the size of the whole (filtered) projection and `limit` is `null` unless a page was asked for, so a caller can always tell a page from the fleet. Optional `limit` (1…1000, clamped and echoed) and `offset` (≥ 0) page it; a malformed or non-positive `limit`/`offset` is a 400 rather than a silent default. A page is sorted by `device_id`, while the unpaged response keeps its long-standing store order. `revision` is the fleet store revision behind the same read: a client walking pages compares it to tell a coherent walk from one that raced a fleet edit, and re-walks if it changed. Row order carries no meaning for the actions built on the projection — those are keyed by `device_id`. Optional filters narrow the projection *before* it is paged, so `total` always reflects every filter together, not just the page: `q` (case-insensitive substring over `device_id`, `device_ip`, `model` and `heartbeat_model`), `management_type` (a device's classified type, or `legacy` for one stored as the unclassified `legacy_routed`), `platform` (the Agent install choice; `__none` matches an unset one), `cred` (a credential profile id; `__none` matches none assigned), `telemetry` (`on` / `off` / `unknown` — tri-state, `unknown` for a device that has never heartbeated), `peer` (`quarantined` / `not-quarantined`, read from the same peer-policy assignment set `GET /api/peer-policy` exposes), and `status` — one of the Status column's own keys (`onboarding`, `undeploying`, `waiting-heartbeat`, `onboard-failed`, `undeploy-failed`, `deployed`, `placement-failed`, `image-failed`, `copying`, `staging`, `unassigned`, `enrolled`, `not-enrolled`), the freshness modifier `offline` (last heartbeat 600s+ old), or the `__attention` rollup (any row at the Status column's negative/severe/warning level). Every filter is the same rule the console's own filter bar and Status column use — see [Paging and selection at fleet scale](console.md#paging-and-selection-at-fleet-scale) — so a page can never disagree with what the filter bar promises. An unrecognized filter value matches zero rows rather than erroring, the same as a `q` that matches nothing. |
| `POST /api/devices` | Creates or updates one inventory row; returns `{device: ...}`. |
| `DELETE /api/devices/<id>` | Retires the device: revokes its credentials first, then clears peer-policy assignment, inventory row, and catalog state. `{deleted: <bool>, degraded: [...]}` — 200 when cleanup was complete, 207 when part of it failed (`degraded` names the areas), 500 `{deleted: false, error: "secret revoke failed"}` when the revoke could not be persisted, in which case nothing was changed. Endpoint rows are retained until they age out. See [Retiring a device](operations.md#retiring-a-device). |
| `GET /api/devices/export-csv`, `GET /api/devices/example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/devices/import-csv` | Bulk inventory import (8 MiB cap, all-or-nothing); returns per-row stats. |
| `GET /api/install-options?model=<model>` | `{options: [...]}` — the agent-install platforms that model may run, which is what the console's platform picker offers. An 8000-series (IOS-XR) model returns exactly `["xr-appmgr"]` and nothing else; a blank model, or one this table has no opinion on, returns `null` — meaning no guardrail applies and every explicit choice stays available. |
| `GET /api/devices/<id>/plan` | `{plan}` — the resolved deployment plan; 409 when it cannot resolve. |
| `GET /api/devices/<id>/reports` | `{reports: [...]}` — the device's stored telemetry ring. |
| `GET /api/devices/<id>/deployment` | `{record, total}` — the deployment record that best describes the device (the active one, else the teardown-authorizing one, else the newest) plus the stored-record count; `record` is `null` when none exists. Read-only — feeds the deployment-details panel. |
| `POST /api/devices/<id>/assign` | `{image_ids: [...]}` sets the device's ordered, up-to-ten-image approved set (an empty array unassigns); the singular `{image_id: <id or null>}` is the pre-multi-image compat shape and always means a one-element set. 400 for more than ten ids, a duplicate, or an id not in the catalog; 400 `image_quarantined` with the blocking verdict if one of the ids is currently quarantined by the Cisco Bulk Hash reconciler (see [Image verification](#image-verification)). See [Policy schema](#policy-schema). |
| `POST /api/devices/<id>/credential`, `.../platform` | Sets the credential profile, or the platform (Agent install choice) and storage target; each returns `{ok: true}`. |
| `POST /api/devices/bulk-credential` | `{device_ids: [...], credential_profile_id: <id or "">}` sets ONE credential profile on every listed device in a single call — the bulk form of the route above, backing the console's "Select all *N* matching devices" bulk credential action (issue #125). 400 for a non-array/empty `device_ids`, one over the supported fleet size, or an unknown `credential_profile_id`. Not all-or-nothing: returns `{ok: true, applied: <count>, failed: {<device_id>: <reason>, ...}}`, naming exactly which selected ids (e.g. one deleted out from under a stale selection) did not apply, while every other id still does. Audited once as `device_credential_bulk_change`, not once per device. |
| `POST /api/devices/<id>/forget-host-key` | Removes the device's entry from the persistent SSH known_hosts accept-new mode records into (`lab/iris-ssh-policy.sh`) — for a device that was re-imaged or replaced and now fails every session with a changed-key error. `{ok: true, peer: <device_ip>}` on success, including when nothing was recorded (already effectively forgotten). 400 `{error: ...}` when the device has no `device_ip` on record or the removal itself fails. Audited as `device_forget_host_key` (device id, actor, and the peer address). Only the persistent accept-new file is touched — an `IRIS_SSH_HOST_KEY` pin or an operator-supplied `IRIS_SSH_KNOWN_HOSTS` file is untouched. The next session re-verifies and pins the device's new key; this never disables verification. See [Operations → Forgetting a device's SSH host key](operations.md#forgetting-a-devices-ssh-host-key). |
| `POST /api/devices/<id>/request-report` | Requests a fresh telemetry report; `{ok: true, expires_at}`, or 429 while one is already pending. |
| `POST /api/devices/<id>/adopt` | Requires `{"acknowledge_adopt": true}`; returns `{record_id}`. 409 when the device already has an active deployment record; routers cannot be adopted. |
| `POST /api/devices/<id>/onboard`, `POST /api/devices/<id>/undeploy` | Starts the job; `{job_id}`. 409 when the device is busy with the opposite action. Undeploy also answers 409 when the device has no deployment record — send `{"force": true}` to run it anyway, which removes only the IRIS-named agent footprint and leaves operator-owned network state (VLAN/SVI, VirtualPortGroup, NAT) untouched, audited as `undeploy_forced`. A `503` naming an unreadable `deployment_records.json` is a different answer: the records cannot be read at all, so whether this device has a deployment is unknown — repair the file rather than adopting the device. |

Router deployments carry extra preflight and ownership rules — see
[Management Type and VLAN Ownership](management-type.md#router-preflight-and-ownership).

### Peer policy

The read side of the swarm's isolation posture, and the one compare-and-set
write in the whole API.

| Route | Body / result |
| --- | --- |
| `GET /api/peer-policy` | The count-only policy view: `schema`, `revision`, `degraded`, `fail_closed`, `quarantine` (the reserved-ACL descriptor), `quarantine_assignments` (the sorted device ids currently quarantined), and `enforcement` — the tracker's reconciler status as `state`, `desired_ip_count`, `applied_revision`, `last_reconciled_at`, `conflict_count`, `conflict_types`, `last_effect` (aggregate `disconnected_peers` / `removed_peers` counts only), `last_error`, and `last_operation_exported_revision`. Deliberately count-only: no peer address ever crosses this boundary. |
| `PUT /api/peer-policy/quarantine/<device_id>` | Quarantines or releases one device. The body must be **exactly** `{"quarantined": <bool>, "if_revision": <int ≥ 1>}` — no other keys, no other types. `if_revision` is the revision you read from `GET /api/peer-policy`, and the write commits only if the policy is still at that revision. 200 `{ok: true, revision, quarantined}` on success. |

Refusals on the write, all of them fail-closed:

| Status | Body | Meaning |
| --- | --- | --- |
| 400 | `{"error": "bad peer-policy request"}` | The body is not exactly the two required keys with the required types. |
| 409 | `{"error": "revision_conflict", "revision": <current>}` | Someone else committed since you read; re-read and retry against the revision returned. |
| 422 | `{"error": "unknown device"}` | No such device in inventory (an encoded `/` in the id is rejected here too). |
| 422 | `{"error": "policy_error"}` | The policy document is degraded, or the mutation was refused. |
| 503 | `{"error": "policy_fail_closed"}` | The policy could not be loaded; nothing is mutated. |
| 503 | `{"error": "operation_backlog_full"}` | Too many committed operations still un-exported to the tracker. |
| 413 | `{"error": "payload too large"}` | Body over the 64 KiB cap. |

The backlog bound and what to do about each refusal are in
[Peer-policy operations and their backlog](operations.md#peer-policy-operations-and-their-backlog).

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
| `GET /api/swarm` | The telemetry `/swarm` JSON, fetched over loopback and passed through byte for byte. Answers 200 with `{"peers": [], "error": ...}` when the telemetry listener is unreachable. Optional `limit`/`offset` (same rules as `/api/devices`) return a page instead: participants are flattened across `images` in image order and only their `peers` arrays are sliced (every image entry survives, since the map's image selector is built from them), with `peers_total`, `peers_offset` and `peers_limit` added. A payload that is not the documented `{"images": [{"peers": [...]}]}` shape answers `{"peers": [], "error": "swarm data not paginatable"}` rather than being passed through whole to a caller that asked for a page. |
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

### The device-facing catalog API is not in this table

Everything above is the **console** API on port 8080 — a browser session
cookie plus CSRF on every state-changing route. The four surfaces below are
not that: each is its own HTTP listener, authenticated (or not) on its own
terms, and none of them carries a session cookie or a CSRF token. The catalog
protocol specifically is versioned and changed in lockstep with
`device/agent/`, and it is not an integration surface — it is documented by
behaviour on [Device agents](device-agents.md) and
[Architecture](architecture.md) as well as route-by-route immediately below,
and nothing outside the agent should call it.

### Import skip reasons

`skipped` entries carry the same fields as importable ones plus a `reason`, and
the console greys them out so a file you expected to see does not just silently
fail to appear. There are exactly three reasons.

| Reason | Meaning |
| --- | --- |
| `already published` | The derived catalog id is already in the catalog, or a publish for that id is in flight — an in-flight publish counts, because the entry appears only when the async job finishes. A catalog `filename` match counts too. `publish.derive_id()` strips `.SPA.bin` or `.bin`, so `foo.bin` and `foo.SPA.bin` are one catalog id. |
| `ambiguous name in more than one location` | The same basename, or the same derived id, exists under more than one root. The startup re-seed can resolve a torrent to a directory by basename and the seeder runs with `bt-seed-unverified`, so a wrong guess would serve the wrong bytes under correct piece hashes. IRIS refuses rather than guess: keep one copy. |
| `not readable by the server` | The file exists but uid 10001 cannot open it. Listing a file needs only its directory, so without this check an unreadable image would pass discovery and fail deep inside publish. Root-owned mode `0600` images left in a volume by an older root-runtime container land here; the fix is the volume-ownership migration in [Server](server.md#upgrading-from-a-root-runtime-deployment). |

A file is only listed at all if it ends in `.bin`, `.iso`, `.tar`, or `.rpm`,
its basename passes the catalog filename charset (`A-Za-z0-9._-`), it is not a
dotfile, sidecar `.torrent`, or
`.upload-*` temp file, and its resolved path is still inside the root it was
found under — a symlink cannot pull a file from outside the mount into the set.
Each distinct tree is walked once, so pointing both roots at the same directory,
or nesting one inside the other, yields each file exactly once.

## Device catalog, tracker, telemetry, and artifact HTTP contracts

### Device catalog API (port 8443)

Every route requires `Authorization: Bearer <token>`; a missing bearer answers
401 `{"error": "unauthorized"}` before any route is matched. Two auth scopes:

* **Device-bound** (`heartbeat`, `telemetry`, `policy`, `token-refresh`): the
  token must resolve to that path's own `<device_id>` under `catalog_token` —
  or, on `token-refresh` only, the immediately preceding
  `catalog_token_prev`, so a device that never saw the response to its own
  rotation can recover it idempotently rather than being stranded. `policy`
  is device-bound (not shared) because its response carries this device's own
  minted `plan_id`/`transfer_id` pair — a shared route would let any enrolled
  device walk `/v1/devices` then read every other device's plan/transfer ids
  off its policy.
* **Shared** (every other route): any currently valid catalog-scoped
  credential — a device's own token, or the service (seeder) credential.

| Route | Auth | Body / result |
| --- | --- | --- |
| `GET /v1/images` | Shared | `{images: [...]}` — the device-facing view of each catalog entry (no `source_dir`, no reconciler internals). |
| `GET /v1/images/<id>` | Shared | Device-facing view of one image; 404 `{"error": "no such image"}`. |
| `GET /v1/torrents/<id>` (also accepts `<id>.torrent`) | Shared | A device principal gets an in-memory torrent personalized with that device's own announce token, plus `Cache-Control: private, no-store` and `Vary: Authorization`; a service/other principal gets the canonical bytes unmodified. 404 no such torrent; 503 `{"error": "catalog not open for device personalization"}` before the `IRIS_REQUIRE_IDENTITY_GATE` checkpoint exists; 500 `{"error": "no announce credential for device"}` or `{"error": "torrent personalization failed"}` — fails closed rather than falling back to the shared seeder token, and never places a token or announce URL in the error body. |
| `GET /v1/devices` | Shared | `{devices: [...]}` — the same heartbeat rows the console's device table reads. |
| `GET /v1/devices/<id>/policy` | Device-bound | The device's own policy view — see [Policy schema](#policy-schema). |
| `POST /v1/devices/<id>/heartbeat` | Device-bound | Body: the device's heartbeat JSON — see [Keyed per-device state](#keyed-per-device-state). 200 `{ok: true, stream_every, stream_pause, report_requested?, report_request_id?}`. |
| `POST /v1/devices/<id>/telemetry` | Device-bound | Body: a v1 or v2 telemetry report. 400 `{"error": "bad json"}` or `{"error": "bad report"}` (a v2 report naming an image outside the device's currently approved set is a bad report). 200 `{ok: true}`. |
| `POST /v1/devices/<id>/token-refresh` | Device-bound (current **or** previous token) | Rotates `catalog_token`. A request presenting the just-rotated previous token replays the same successor rather than rotating again, so a lost response can't strand the device. 401 unauthorized; 409 `{"error": "device revoked"}`; 500 `{"error": "durable persist failed: ..."}` when the encrypted secret store can't be written (nothing is committed in that case); 200 `{catalog_token, expires_at, announce_token?, rpc_secret?}` — the last two appear only when the device actually has one, never as an empty string that would overwrite the agent's working value. |

Every POST additionally requires `Content-Length` (a chunked or length-less
body is refused with 411), rejects a non-numeric or negative
`Content-Length` with 400, and caps the body at 64 KiB — after gzip
decompression, so a compressed bomb is still caught — with 413 over. Like
every keyed-state store, a shard the catalog can't read fails the request
closed with 503 `{"error": "state unavailable"}` rather than answering as if
that device (or the whole store) were empty.

### Tracker API (port 6969)

BitTorrent-standard `GET /announce` and `GET /scrape`, bencoded responses
(`Content-Type: text/plain`), authenticated by a **query-string** credential
rather than a header: the dedicated `announce_token=` parameter, or the
legacy BEP-style `key=` parameter for a previous/rotated-out token still
inside its overlap window (see `IRIS_SEEDER_PREV_TTL`). A request with no
valid credential of either kind gets a token-free 403 bencoded
`{"failure reason": "missing or invalid token"}`; the token itself is never
echoed in a log, audit entry, or error body.

| Route | Body / result |
| --- | --- |
| `GET /announce` | Query: `info_hash` (20 raw bytes, percent-encoded), `announce_token` or `key`, `peer_id`, `port` (1-65535; an out-of-range value is treated as absent, so the request still answers 200 but registers no peer), `left`, `event`, `numwant` (default 50), `compact` (`1` for BEP23 compact peers), and an `ip` override honoured **only** for the service (origin seeder) principal and only when it names a private/CGNAT IPv4 address — containerized seeders whose socket source is loopback/bridge-local. 400 `{"failure reason": "info_hash must be 20 bytes"}` on a malformed hash (checked only after auth, so an unauthenticated caller learns nothing about the request shape). 200 bencoded `{interval, min interval, peers}`, where `peers` is BEP23 compact bytes or a list of `{ip, peer id, port}` dicts. The candidate set is further filtered by the peer-policy mutual-permit predicate whenever peer policy is configured — see [Peer policy](#peer-policy) and [Peer-policy operations and their backlog](operations.md#peer-policy-operations-and-their-backlog); a legacy credential announcing from an address a durable endpoint attributes to a quarantined or revoked device gets zero peers. |
| `GET /scrape` | Query: `info_hash`, plus the same credential parameter as `/announce` (scrape only checks that the credential is valid — it discards the typed principal). 400 `{"failure reason": "scrape requires info_hash"}` / `{"failure reason": "info_hash must be 20 bytes"}`. 200 bencoded `{"files": {<raw info_hash bytes>: {complete, incomplete, downloaded}}}` (BEP48). |

Every valid, port-bearing announce from a device or service principal durably
records that principal's endpoint (`<state>/peer-endpoints.d/` — see [Keyed
per-device state](#keyed-per-device-state)) before peer selection runs; a
legacy principal's endpoint is never persisted. A durable-write failure never
changes the HTTP 200 — the tuple is queued for retry and the tracker's own
reconciler reports the degrade.

### Telemetry listener (port 9101)

Unauthenticated by design — the Prometheus/operator surface, gated by
presence and posture rather than a session. GET-only; no CSRF. See
[Telemetry gating rule](#telemetry-gating-rule) for exactly which environment
variable controls which path.

| Route | Result |
| --- | --- |
| `GET /metrics` | 200 `text/plain; version=0.0.4` Prometheus exposition when `IRIS_OBSERVABILITY` is enabled; 404 otherwise. |
| `GET /healthz` | Always 200 — this path never signals failure by status code. `{"ok": true, "otlp_export"?: {...}, "listeners"?: {"<name>": "up"\|"down"}}`; the `listeners` block appears only when `IRIS_HEALTH_LISTENERS` names a probe set, and is informational here — `ok` stays `true` regardless of what it shows. |
| `GET /readyz` | TCP-probes the `IRIS_HEALTH_LISTENERS` set (default: the tracker, catalog, artifact server and console listeners). 200 `{"ok": true}` when every probed listener answers, else 503 `{"ok": false, "listeners": {...}, "down": [...]}` naming the down ones. `IRIS_HEALTH_LISTENERS=off` (or nothing to probe) makes the path inert — always 200, nothing probed. This is the status-code probe the Compose `HEALTHCHECK` and the Kubernetes probes use; `/healthz` proves only that the `:9101` process itself is alive. |
| `GET /swarm` | Loopback peers only unless `IRIS_SWARM_PUBLIC=1`: a non-loopback caller without it gets 403 `{"error": "swarm data is served through the authenticated console; set IRIS_SWARM_PUBLIC=1 to expose it here", "console": "<url>"}`. Otherwise 200 JSON `{"images": [{"peers": [...]}, ...]}` — byte-identical to what the session-gated `GET /api/swarm` proxies. |
| `GET /swarmmap`, `GET /` | 200 `text/html` — the swarm map pointer page, when the listener was started with one. |
| anything else | 404 `not found`. |

### Artifact server (port 8000)

Static-file GET/HEAD over the artifacts directory (`IRIS_ARTIFACTS_DIR`),
authorized purely by the high-entropy, per-device staging filename in the
URL — there is no token, session, or CSRF on this surface at all. Directory
listing is disabled (any directory request answers 404, never an index), and
a resolved path that escapes the artifacts root — including through a
symlink — also answers 404 rather than serving the target.

`GET` additionally enforces the `staging/` permission contract: a file under
`staging/` must be mode `0600`-or-tighter before it is served — the server
tightens it in place when this process owns the file, and refuses with 403
`Staging file permissions are unsafe` when it does not own the file and the
mode is loose. Files under `staging/` are swept off disk on a background
timer an hour after they were staged, not synchronously on the request that
fetches them — long enough to cover the whole onboarding retry window, not
just the copy retries, so a slow install can still retry its fetch inside
that hour without racing its own file's deletion. `HEAD` applies the exact
same containment and `staging/` permission checks as `GET` before answering
(headers only, no body) — it cannot disclose existence, size, or mtime for a
path `GET` would have refused with 404/403.

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
| `cisco_signature_verified` | `True` exactly when this entry's `hash_verification.state` is `verified` — kept in sync by the Cisco Bulk Hash reconciler on every run that covers this image, and by it alone. `False` for `mismatch`, `not_in_feed`, or before the first run ever covers it. Distinct from `operator_attested_signature`, below — the two used to share this one field, so an operator's own attestation was silently overwritten by the reconciler's next run (#88); they are now separate. On the device, the check is still the agent's sha256 of the staged file against this entry's `sha256`; nothing re-hashes the placed copy. |
| `operator_attested_signature` | `True` when `iris-publish` was run with `--signature-verified` — the publishing operator's own attestation that the Cisco signature was checked elsewhere. Written once, at publish time, by `publish.py` alone; the Cisco Bulk Hash reconciler never reads or writes it, so it survives every reconciliation run untouched. Advisory only — nothing on the device consults it. |
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
entries with no `source_dir` or whose recorded directory has gone away. The
catalog is the authority on *what* is re-seeded: a `.torrent` file with no
catalog entry (left by a publish that failed after the torrent was built and
before the entry was written — normally rolled back, but a crash can leave
one) and the torrent of a `quarantined` image are skipped, so a restart never
serves what the API says is absent or withheld.

## Keyed per-device state

Every per-device store the server keeps under `IRIS_STATE` — heartbeats,
staging approval, telemetry reports, the seen-report-id ledger, transfer
attestations, pending pull directives, the tracker's durable peer-endpoint
map, and (since issue #125) the operator inventory itself — is **keyed**
state: one row per device (or per principal), spread over 256 shard files in
a directory, rather than one whole-fleet JSON document.

| Store | Directory |
| --- | --- |
| Heartbeats | `<state>/devices.d/` |
| Staging approval | `<state>/policy.d/` |
| Telemetry report rings | `<state>/telemetry.d/` |
| Seen-report-id ledger | `<state>/report_ledger.d/` |
| Transfer attestations | `<state>/transfer-attestations.d/` |
| Pending pull directives | `<state>/pull_requests.d/` |
| Durable peer endpoints | `<state>/peer-endpoints.d/` |
| Operator inventory (fleet) | `<state>/fleet.d/` |

A heartbeat, a policy read, a terminal report, a tracker announce, and a
credential/platform reassignment lock, parse and rewrite only the shard their
own device lands in. Before this, each of those operations held one lock on
the whole document while it re-parsed and re-serialised every device in the
fleet, so a single device's request cost grew with fleet size and unrelated
devices serialised behind one writer.

The inventory store carries one thing the others do not:
`<state>/fleet-revision.json`, a small counter bumped once per fleet-editing call
(create/edit/delete a device, a CSV import, a bulk reassignment) and read
back alongside a fleet listing so a console client walking pages can tell
whether the fleet changed between two page reads. It is deliberately its own
tiny file rather than a per-shard field, because "did the fleet change" is a
whole-store question a single shard cannot answer on its own — it is the one
thing every inventory write still serialises on, but the file is a few bytes
regardless of fleet size, so that serialisation stays O(1) per write. A
console bulk action reassigning a credential or platform across many
selected devices at once — the console's own "Select all N matching
devices" — additionally goes through `POST /api/devices/bulk-credential`
(see [Console API](#console-api)) rather than one request per device: it
groups the underlying shard writes the same way, so a shard holding many of
the selected devices is rewritten once, not once per device in it.

What has not changed: each shard is written atomically (a unique temp file in
the same directory, then a rename), so a reader never sees a partial write; and
a shard that exists but cannot be read or parsed **fails closed** — the request
that needs it answers `503`, and no writer replaces its content — rather than
reading as an empty store. The blast radius is narrower than it was: damage to
one shard no longer takes out every device's state, only the devices in that
shard and any whole-fleet listing.

The whole-fleet documents from earlier releases (`devices.json`, `policy.json`,
`telemetry.json`, `report_ledger.json`, `transfer-attestations.json`,
`pull_requests.json`, `peer-endpoints.json`, and — as of issue #125 —
`fleet.json`) are migrated into their shard directories the first time the
server touches each store, and are then left in place renamed to
`<name>.json.migrated`. There is nothing to run by hand, and nothing is
deleted. A migration that cannot read its source document fails closed and
leaves the document exactly where it is. `fleet-revision.json` is not part
of that migration — a store migrated from a pre-shard `fleet.json` simply
starts its counter fresh at 0 rather than carrying the old document's own
`revision` field forward; nothing compares that number across a migration
or a restart; it exists only so a page and the fleet it was read from can be
told apart within one running process's page-to-page walk.

Migration also leaves a deliberately-invalid placeholder at each retired
legacy path, so that a **rollback** to a release from before this migration
refuses to start against what it would otherwise read as an empty fleet,
rather than silently serving one — see [Rollback after the shard
migration](operations.md#rollback-after-the-shard-migration) for the
recovery procedure and what it does and does not restore.

Whole-fleet reads — the console's device and assignment tables, the telemetry
sidecar's per-pass snapshots, the tracker's blocklist derivation, and a device
purge — still read every row, which costs what the single document cost,
because it is the same bytes in 256 pieces.

## Policy schema

The policy store (`<state>/policy.d/`) holds per-device staging approval —
what IRIS is allowed to stage, never what it installs, activates, or reloads.
It is **keyed** state: one row per device, spread over 256 shard files, so a
device's policy read or write touches only its own shard. See
[Keyed per-device state](#keyed-per-device-state) below.

| Field | Meaning |
| --- | --- |
| `approved_image_ids` | Ordered list of catalog image ids, up to ten. The agent stages and verifies every id in the set, transferring them in parallel. Authoritative: a raw read of this file, or a stale write, is resolved from this key, never from `approved_image_id`. |
| `approved_image_id` | The set's first element, or `null` when empty. Recomputed from `approved_image_ids` on every read and write — kept only so a reader that predates the ordered set (a raw read of the stored row, or an agent that has not yet upgraded) still sees a single assignment. |
| `plans` | Per-image transfer identity, keyed by image id: `plan_id` and `transfer_id` (both 32 lowercase hex), `planned_at` (epoch seconds) and `info_hash` (the torrent info hash of the image as the catalog held it at mint time, `null` when the catalog has no entry yet). Minted when an image **enters** the set and carried forward verbatim while it stays there, so a repeat Apply — including one that only adds or removes some other image, and the quarantine auto-unassign rewrite — never re-mints and never restarts an in-flight transfer's identity. Unassigning an image drops its entry and re-assigning it mints a new plan, which is what keeps two successive transfers of the same image to the same device distinct. A row written before this key existed simply has no `plans`, and gains one at its next Apply. |

`POST /api/devices/<id>/assign` (see [Devices](#devices)) writes this file.

The agent reads its own row from `GET /v1/devices/<device_id>/policy`. That
response carries the two approval keys above plus a `plans` map projected down
to the two device-visible fields, `plan_id` and `transfer_id`, for image ids
that are in the approved set and whose stored ids are both 32 lowercase hex;
`planned_at` and `info_hash` stay on the server, because the agent has no use
for either. The key is always present, possibly empty. The agent adopts the
`transfer_id` before it starts a download and stamps it on every observation
and terminal report for that image, so one transfer carries one id from
assignment to seed; an agent that predates the key ignores it and keeps minting
its own id, which is what makes the addition safe mid-rollout. The internal
`get_policy()` contract is deliberately left at its two keys — the `plans` map
exists only on the wire projection.

The device's heartbeat (`<state>/devices.d/`) reports per-image staging
progress against that set:

| Field | Meaning |
| --- | --- |
| `current_image_id` | Wire-compatible identity pointer: the first image of the set that produced heartbeat data this tick — typically one already staged. It is **not** the image being transferred, and per-image state must not be read from it; it exists so a reader that predates the ordered set still sees a single image id. |
| `stage_state` | One state string for the whole tick. On a one-image heartbeat it is that image's own state (for example `staging`, `downloading`, `transferring_to_ios`, `ready`, `error`). For a set the agent collapses the tick into the single most actionable state across every assigned image, so it describes the set, not `current_image_id`. `stage_error`, likewise, is one reason per tick. |
| `staged_image_ids` | Which of the assigned images this agent has staged and verified, as of its last heartbeat. Absent on a one-image heartbeat (and on an agent that predates multi-image staging), in which case staged/not-staged falls back to `stage_state == "ready"` paired with `current_image_id`. |
| `errored_image_ids` | Which of the assigned images hit a terminal per-image failure on the agent's last tick, including retryable ones such as a full boot filesystem. Absent on a one-image heartbeat and on an agent that predates the field. |

## Transfer lifecycle

Every plan is followed from the moment it is minted to the moment the server can
honestly say the device is seeding it, and both transitions leave the server as
OTLP log records named `iris.transfer.lifecycle`. The schemas are here; what to
join on and how to query them is in
[Observability](observability.md#log-attributes-operator-contract), and how the
records leave the server is in [Telemetry export](telemetry-export.md).

### `transfer-lifecycle.json`

`<state>/transfer-lifecycle.json` holds one row per plan. It is **derived
state**: plan identity lives in `policy.json`, and this file keeps only the
latched observations behind the seeding decision plus the markers saying which
records have already reached the export queue. It is therefore safe to delete —
the next sample pass rebuilds every row from `policy.json` with the same ids,
and the bounded re-emission that follows carries byte-identical records under
the same `event.id`, so a backend sees duplicates of events it already has
rather than new ones. The tracker process is the file's only writer; the catalog
writes plan identity into `policy.json` and never touches this file.

| Field | Meaning |
| --- | --- |
| `plan_id`, `transfer_id`, `device_id`, `image_id`, `info_hash`, `planned_at` | Copied from the plan's `policy.json` row and refreshed from it on every pass. This file mints no identity of its own. |
| `state` | `planned` at creation; `seeding` once both latches below are set; `cancelled` when the assignment is withdrawn before that. Both `seeding` and `cancelled` are terminal — a later unassign never un-seeds a transfer that already happened, and a cancelled plan can never be promoted. |
| `checksum_verified_at` | First precondition, latched first-write-wins: the server-stamped `received_at` of the earliest terminal report (`staging-complete` or `seeding-only`) from that device carrying **this plan's own** `transfer_id` with `content_sha256.state == "verified"`. Both terminal events are reachable only after the agent hashed the fully downloaded file, so this single fact carries both "the content is complete on the device" and "its checksum verified". `null` until such a report arrives. **It is an ingest instant, not the device's verification instant.** It says when the *server* learned the checksum had verified. The device reports no verification instant at all, so none is invented here; the gap between the two is made visible by `report_created_at` below rather than guessed away. The gap is not marginal: the agent arms a terminal report at completion but defers the whole send on a bad link, backing off to about sixteen minutes, so on exactly the constrained devices IRIS exists for this instant can sit that far behind the physical one. The fact is recorded durably at ingest in `transfer-attestations.json`, so it survives the report ring rotating past it. |
| `tracker_seeder_at` | Second precondition, latched first-write-wins: when this tracker saw the device itself announce `left = 0` on the image's torrent under its own authenticated principal — the peer registry row's `completed_at`, falling back to `last_seen`, and finally to the pass's own instant. A device announcing on a legacy or shared seeder token proves no identity and can never satisfy this. `null` until then. **Never earlier than `planned_at`:** a peer row belongs to a peer, not to a plan, so unassigning and re-assigning an image the device is already seeding leaves a row carrying the *previous* transfer's `completed_at`. That instant is not this plan's evidence — the tracker did not watch this plan seed before it existed — so a candidate predating the plan is skipped and the next one down the chain stands in. |
| `seeding_started_at` | `max(checksum_verified_at, tracker_seeder_at, planned_at)`: the instant the later of the two preconditions became true, floored at the plan's own creation so a planned→seeding duration can never render negative. Computed once, at promotion, before any record is built, and never recomputed — which is what makes a replay after a crash byte-identical. A **recovered** promotion (below) uses `max(checksum_verified_at, planned_at)` instead. |
| `observed_at` | The end of the attesting report's measurement window, on the **device's** clock. Carried for correlation only, and never subtracted from the server instants above: two clocks. |
| `report_created_at` | When the attesting report was composed, on the **device's** clock. Read against `checksum_verified_at` it shows how long that report spent getting here — the delivery latency a planned→seeding duration would otherwise carry as if it were transfer time. Two clocks, so the difference is that latency *plus* whatever skew stands between them; it is a magnitude to look at, never an exact correction to subtract. `null` when the report carried no such field. |
| `recovered_promotion` | Present and `true` only on a row that was promoted on the same pass that **rebuilt** it from a lost store. Absent otherwise — never `false`. See below. |
| `updated_at` | When this row was last written. Drives retention and eviction order. |
| `emitted` | The durable markers, `{"planned": <ts>, "seeding_started": <ts>}`, each key absent until the export queue has accepted that record. Written only after the queue accepts, never before — marking first would lose an event permanently the moment the queue refused it. |

Bounds: at most 4096 rows, and rows that owe nothing — terminal **and** fully
emitted — are pruned a week after their last write. At the cap the oldest such
rows go first; an eviction forced to drop a row that still owes an event is
counted in the store's `plans_dropped_unemitted` rather than disappearing
quietly. `plans_awaiting_report` counts plans the tracker has already watched
seed for which no matching report has arrived.

Retirement is keyed on the export queue having *accepted* a record, never on
the collector having acknowledged it — the alternative holds every row forever
whenever a collector is down. A collector outage longer than the retention
window therefore costs those records, and `events_retired_undelivered` counts
exactly how many, alongside `plans_unconfirmed` for the backlog that has not
yet aged out. Every counter here leaves the process as an
`iris.transfer.lifecycle.*` metric point and an `iris_transfer_lifecycle_*`
Prometheus family (see
[Observability](observability.md#metrics-names-operator-contract)): a bound
nothing reports is a bound an operator cannot check.

### Lifecycle events

Two events per plan, in this order and no other: `planned` when the assignment
mints it, and `seeding_started` when **both** preconditions above have been
observed. There is deliberately nothing in between — the server has no honest
instant for "downloading" — and a plan whose transfer never completes simply
never produces the second record. Records are queued only where telemetry export
is configured, but the facts are latched whether or not it is, so turning a
destination on later still publishes the plans that were in flight while it was
off.

| Attribute | Events | Meaning |
| --- | --- | --- |
| `event` | both | `planned` or `seeding_started`. |
| `iris.plan.id` | both | The join key: stable across both records of one plan, and distinct across two plans for the same device and image. |
| `iris.transfer.id` | both | The id the device stamps on every observation and terminal report for this transfer — the join to `iris.device.transfer.report`. |
| `iris.device.id`, `device.id` | both | The same device id under both spellings. Emitted deliberately, so a query joining either existing record's convention works without a coalesce; an exported attribute cannot be withdrawn additively, so this is a permanent commitment. |
| `iris.image.id` | both | Catalog image id. |
| `iris.torrent.info_hash` | both | The image's torrent, as captured when the plan was minted. Omitted when the plan captured none. |
| `iris.transfer.planned_at` | both | When the assignment minted the plan. Repeated on the `seeding_started` record on purpose, so planned→seeding duration is computable from that one record without joining back to a `planned` record a bounded queue may have dropped. |
| `iris.transfer.seeding_started_at` | `seeding_started` | The latched promotion instant described above. |
| `iris.transfer.checksum_verified_at`, `iris.transfer.tracker_seeder_at` | `seeding_started` | The two preconditions, exported separately so it is visible which one was the laggard: a device whose sha256 of a ~1.2 GB image runs minutes after aria2 first announced `left = 0` shows `tracker_seeder_at` well ahead of `checksum_verified_at`, and the reverse ordering means the swarm, not the device, was the wait. |
| `iris.transfer.report_received_at` | `seeding_started` | The **same value** as `iris.transfer.checksum_verified_at`, under the name that says what it is: the server's ingest instant for the attesting report. The older name is kept because an exported attribute cannot be withdrawn; prefer this one when the distinction matters, and read it against `iris.device.report_created_at`. |
| `iris.device.observed_at`, `iris.device.report_created_at` | `seeding_started` | The attesting report's two device-clock instants, as epoch floats — the end of its measurement window and when it was composed — named exactly as `iris.device.transfer.report` names them. Show them; never subtract either from a server instant as though the clocks agreed. |
| `iris.transfer.recovered_promotion` | `seeding_started` | `true`, and present at all, only on a record whose row was rebuilt from a lost store. It says three things at once: this may be a *replay* of a record the backend already holds under this `event.id`; its `seeding_started_at` is `max(checksum_verified_at, planned_at)` and may be **earlier** than what that first record carried; and its `iris.transfer.tracker_seeder_at` is a post-loss re-announce, so recomputing `max()` over the three instants on this record will not reproduce its `seeding_started_at`. Absent — never `false` — on an ordinary promotion. |
| `event.id` | both | `<plan_id>.<event>`, derived and never minted per emission, so a replay after a crash between the queue accepting a record and its marker landing carries an identical key the backend can dedupe. |
| `iris.telemetry.schema.version` | both | `2`. A new record name is not a schema revision; nothing existing changed. |

The five timestamp attributes — `iris.transfer.planned_at`,
`seeding_started_at`, `checksum_verified_at`, `report_received_at` and
`tracker_seeder_at` — are RFC3339 in UTC with **exactly** three
fractional digits and a literal `Z` (`2026-09-02T14:03:11.482Z`), which is what
the Splunk extraction `%Y-%m-%dT%H:%M:%S.%N%Z` needs: a whole-second instant
rendered without the fraction, or a `+00:00` offset in place of the `Z`, fails
that pattern outright. An attribute whose source value is missing or uncoercible
is omitted from the record entirely — an absent attribute means *not known*, and
nothing here is defaulted. `timeUnixNano` is the record's **source** instant
(`planned_at`, or `seeding_started_at`), never the emit instant. For `planned`
that instant is the server's own decision. For `seeding_started` it is a server
*observation*, and when the report was the later of the two preconditions that
observation is the report's ingest instant — so `timeUnixNano` on a
`seeding_started` record can be an ingestion time, and
`iris.transfer.report_received_at` is there to say when. This is still the
opposite choice from `iris.device.transfer.report`,
which times off the server's `received_at` because the only thing the server
knows for certain about a device report is when it arrived. Its trailing digits
are an artefact of converting a float epoch to nanoseconds, not precision.

A `planned` record, exactly as exported:

```json
{
  "timeUnixNano": "1788357791482000128",
  "eventName": "iris.transfer.lifecycle",
  "severityNumber": 9,
  "severityText": "INFO",
  "body": { "stringValue": "transfer lifecycle planned" },
  "attributes": [
    { "key": "otel.log.name", "value": { "stringValue": "iris.transfer.lifecycle" } },
    { "key": "iris.telemetry.schema.version", "value": { "intValue": "2" } },
    { "key": "event", "value": { "stringValue": "planned" } },
    { "key": "iris.transfer.id", "value": { "stringValue": "4b7e0c92d1a54f38a6c25e91b307fd6c" } },
    { "key": "iris.plan.id", "value": { "stringValue": "9f3c1a77b0d24e5188ac0b6f7d21e4a3" } },
    { "key": "iris.device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "iris.image.id", "value": { "stringValue": "cat9k_iosxe.26.01.01" } },
    { "key": "iris.torrent.info_hash", "value": { "stringValue": "3a9f1c0b8e7d6452af10cd3b92e5170864bd2fa1" } },
    { "key": "iris.transfer.planned_at", "value": { "stringValue": "2026-09-02T14:03:11.482Z" } },
    { "key": "event.id", "value": { "stringValue": "9f3c1a77b0d24e5188ac0b6f7d21e4a3.planned" } }
  ]
}
```

The `seeding_started` record for the same plan, 24 minutes later. The device
announced `left = 0` at 14:22:57, and its sha256 of the staged file only
finished — and was reported and accepted — at 14:27:24, so the later of the two,
the checksum, is the promotion instant:

```json
{
  "timeUnixNano": "1788359244118000128",
  "eventName": "iris.transfer.lifecycle",
  "severityNumber": 9,
  "severityText": "INFO",
  "body": { "stringValue": "transfer lifecycle seeding_started" },
  "attributes": [
    { "key": "otel.log.name", "value": { "stringValue": "iris.transfer.lifecycle" } },
    { "key": "iris.telemetry.schema.version", "value": { "intValue": "2" } },
    { "key": "event", "value": { "stringValue": "seeding_started" } },
    { "key": "iris.transfer.id", "value": { "stringValue": "4b7e0c92d1a54f38a6c25e91b307fd6c" } },
    { "key": "iris.plan.id", "value": { "stringValue": "9f3c1a77b0d24e5188ac0b6f7d21e4a3" } },
    { "key": "iris.device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "device.id", "value": { "stringValue": "203.0.113.3" } },
    { "key": "iris.image.id", "value": { "stringValue": "cat9k_iosxe.26.01.01" } },
    { "key": "iris.torrent.info_hash", "value": { "stringValue": "3a9f1c0b8e7d6452af10cd3b92e5170864bd2fa1" } },
    { "key": "iris.transfer.planned_at", "value": { "stringValue": "2026-09-02T14:03:11.482Z" } },
    { "key": "iris.transfer.seeding_started_at", "value": { "stringValue": "2026-09-02T14:27:24.118Z" } },
    { "key": "iris.transfer.checksum_verified_at", "value": { "stringValue": "2026-09-02T14:27:24.118Z" } },
    { "key": "iris.transfer.report_received_at", "value": { "stringValue": "2026-09-02T14:27:24.118Z" } },
    { "key": "iris.transfer.tracker_seeder_at", "value": { "stringValue": "2026-09-02T14:22:57.905Z" } },
    { "key": "iris.device.observed_at", "value": { "doubleValue": 1788359241.7 } },
    { "key": "iris.device.report_created_at", "value": { "doubleValue": 1788359244.1 } },
    { "key": "event.id", "value": { "stringValue": "9f3c1a77b0d24e5188ac0b6f7d21e4a3.seeding_started" } }
  ]
}
```

### Rolling this change

IRIS ships a single shared on-device agent, so the `plans` key and the agent
that adopts it roll together. Per the shared-agent rule, any change under
`device/agent/` requires a fresh Guest Shell bundle, both IOx tars and
`iris-xr.rpm` before device rollout; see
[Embedded agent packages](development.md#embedded-agent-packages).

A device that has not yet received the bundle ignores `plans` and keeps minting
its own `transfer_id`, so its plans emit `planned` and never `seeding_started`.
There is deliberately **no** fallback that promotes a plan from a report bearing
some other transfer's id.

## Device container environment variables

Cadence jitter and overload backoff (issue #59 — see [Device agents →
Cadence jitter and overload
backoff](device-agents.md#cadence-jitter-and-overload-backoff)) are tuned by
these variables. They are deploy-time knobs like `IRIS_TICK_SECONDS`,
`IRIS_RPC_PORT` and `IRIS_MAX_PEERS`: IOx/XR set them as numbered
`run-opts -e` Docker options at `app-hosting install`/activation time (never
baked into the image), and Guest Shell/router set them in the shell
environment `bootstrap.sh` runs under. None of these are `server/`
Compose/container variables — they never reach the `iris` server container.

| Variable | Default | Platform | Effect |
| --- | --- | --- | --- |
| `IRIS_TICK_JITTER_PCT` | `10` | IOx, XR | Dithers every ordinary tick by ±this percent of `IRIS_TICK_SECONDS`. |
| `IRIS_STARTUP_JITTER` | `1` (on) | IOx, XR | Spreads the first tick after container start across the whole `IRIS_TICK_SECONDS` window. `0` disables it. |
| `IRIS_TICK_BACKOFF_MAX` | `600` (seconds) | IOx, XR, Guest Shell, router | Cap on the exponential backoff applied after a tick's agent process fails outright. |
| `IRIS_TICK_JITTER_MAX` | `8` (seconds) | Guest Shell, router | Bound (0..N-1, uniform) on the per-tick sleep `bootstrap.sh` takes before contacting the catalog. The EEM timer's own 60s period is unaffected — IOS owns that clock. |
| `IRIS_LOG` | `off` | IOx, XR, Guest Shell | Device-side `aria2c.log` opt-in — see [Device agents → Device-side logging (flash write endurance)](device-agents.md#device-side-logging-flash-write-endurance). **Off by default**: flash has finite write endurance, and aria2c's own log is chatty and continuous for the whole life of a transfer. `on`/`1`/`true`/`yes` (case-insensitive) enables it; anything else, including unset, stays off. `device/xr-install.sh` and `device/iox/install.sh` forward an operator's setting verbatim (`--env IRIS_LOG=…` in `docker-run-opts`, `run-opts N "-e IRIS_LOG=…"`) — before this plumbing existed neither installer passed it at all, so the opt-in was unreachable on exactly the two platforms whose entrypoints implement it. On IOx/XR the launch line adds `--log=<STAGE_DIR or WORK_DIR>/aria2c.log --log-max-size=50M --log-max-files=1`; Guest Shell adds `--log=<STAGE_DIR>/aria2c.log` and relies on the existing `rotate-logs.sh`/EEM cadence to trim it. On Guest Shell, set `iris_log` in `iris-agent.conf` instead — see [Device agent config keys](#device-agent-config-keys) below; `bootstrap.sh` reads it (and `rpc_port`/`max_peers`, which had the identical gap) from that persisted file and exports it before every `guestshell-start.sh` launch, so it survives an EEM tick and a reboot without a reinstall. **`IRIS_LOG` governs only that one file — the `aria2c.log` transfer log** — never the `%IRIS-6-<MNEMONIC>` operator lines `emit()` writes on every platform, which `IRIS_LOG` never touches either way: real IOS syslog (`send log`) on Guest Shell and IOx, or the XR container's stdout on IOS-XR, captured into the container log appmgr keeps (`show appmgr application name iris logs`) — that stdout capture happens **regardless of `IRIS_LOG`**, so "off" does not mean zero recurring write on XR, only that `aria2c.log` itself stops growing; see the container-log bound below. The heartbeat's `stage_error` field is unaffected on every platform either way. |
| `IRIS_LOG` (XR container-log bound) | — | XR | `device/xr-install.sh`'s `docker-run-opts` always adds `--log-driver json-file --log-opt max-size=1m --log-opt max-file=3` — independent of `IRIS_LOG` and not configurable per device. This bounds (not eliminates) the one recurring write `IRIS_LOG=off` cannot stop on XR: appmgr's capture of `emit()`'s `%IRIS-6-<MNEMONIC>` stdout lines, roughly one per 60s tick. 3&nbsp;MiB total, rotated, retains roughly 11 days of that history at the emit rate above — comfortably past a long weekend — for about 0.08% of the ~3.9&nbsp;GB `/misc/app_host` partition XR's container logs live on. Deliberately never `--log-driver=none`: XR has no syslog path for `%IRIS` lines (see the deviation note in `device/agent/xr_deps.py`), so `none` would silently discard every device diagnostic, including pre-heartbeat startup failures, with no second channel. |

## Device agent config keys

The agent reads `key = value` lines from
`/flash/guest-share/iris/iris-agent.conf` (override with `IRIS_AGENT_CONF`).

| Key | Default | Effect |
| --- | --- | --- |
| `device_ssh_known_hosts` | unset | Path to a `known_hosts` file pinning the device's SSH host key. When the key is set and the file exists, the agent's SSH and SCP calls use `StrictHostKeyChecking=yes` against it. Otherwise they keep the default `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null`. |
| `telemetry_stream` | `off` | Live transfer-sample streaming ([Transfer streaming](observability.md#transfer-streaming)). Fail-closed: only an explicit `on`/`1`/`true`/`yes` enables; requires `telemetry` on. Delivered by the installers (`TELEMETRY_STREAM`) and IOx deploy env (`IRIS_TELEMETRY_STREAM`), and changed by redeploy. |
| `iris_log` | unset (off) | Guest Shell's only persistent path to the `IRIS_LOG` device-side logging opt-in — see [Device agents → Device-side logging (flash write endurance)](device-agents.md#device-side-logging-flash-write-endurance). `bootstrap.sh` reads this key on every EEM tick and exports it as `IRIS_LOG` before running `guestshell-start.sh` (issue #122); an operator sets `iris_log = on` in the device's `iris-agent.conf` and the next tick picks it up, no reinstall. Validated before export: only letters/digits are accepted (`on`/`1`/`true`/`yes` enable it, case-insensitive, matching every other platform's parsing), anything else — including an attempt to inject shell syntax — is dropped with a warning and the built-in default (off) applies. |
| `rpc_port` | `6800` | Also read by `bootstrap.sh` and exported as `RPC_PORT` for `guestshell-start.sh`'s own aria2c launch line (issue #122), in addition to the Python agent's existing use of this key for its own RPC calls to aria2c. Validated as an integer 1–65535; an out-of-range or non-numeric value is dropped with a warning and `guestshell-start.sh`'s built-in default (`6800`) applies. |
| `max_peers` | `10` | Also read by `bootstrap.sh` and exported as `MAX_PEERS` for `guestshell-start.sh`'s `--bt-max-peers` (issue #122). Validated as an integer 1–65535; an out-of-range or non-numeric value is dropped with a warning and `guestshell-start.sh`'s built-in default (`10`) applies. |

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
