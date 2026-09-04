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
| `docker compose -f server/docker-compose.yml up -d --build` | Build and start the IRIS server and state-free Console. |
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
| `device/iox/build.sh --image-only` | Build or verify the one persisted OCI archive containing both linux/amd64 and linux/arm64 device images. |
| `tools/provision-iox-packages.sh` | Build and stage both architecture-specific IOx packages. |
| `tools/build-xr-package.sh --out artifacts/` | Build the deployment-neutral IOS-XR appmgr RPM and its canonical-image provenance manifest. |
| `device/xr-install.sh` | Onboard the IOS-XR appmgr agent. |
| `device/xr-uninstall.sh` | Remove the IOS-XR appmgr agent footprint. |
| `tools/check-package-freshness.sh` | Check package wrapper/provenance integrity and live-versus-distributed runtime certificate readiness. |
| `kubectl apply -k kubernetes` | Deploy the optional split server and stateless Console workloads on Kubernetes. |

Most of these have a console equivalent; the command line is not the only way to run them — see [When to use the CLI](console.md#when-to-use-the-cli).

Docs build commands and their tool pins live in [Development](development.md#documentation-loop).

## Port quick reference

| Port | Transport | Protocol | Service | Device-facing |
| --- | --- | --- | --- | --- |
| 6969 | TCP | HTTPS | Tracker | Yes |
| 8443 | TCP | HTTPS | Catalog | Yes |
| 8000 | TCP | HTTPS | Artifact server | Yes |
| 6881 | TCP | BitTorrent | Seeder data | Yes |
| 8080 | TCP | HTTPS | Web console | Operator-facing |
| 9101 | TCP | HTTPS | Telemetry | Operator-facing |
| 9443 | TCP | HTTPS | Internal management API | No, Console tier only |
| 6800 | TCP | HTTP | aria2 RPC | No, local-only |

Every port is TCP. IRIS opens no UDP listener.

## Environment variables

### Required at deploy time

Compose refuses to start without these; none has a default.

| Variable | Effect |
| --- | --- |
| `IRIS_HOST_IP` | The docker host's IP — the address devices reach. Compose also publishes the Console only on this host address, rather than every host interface. It is baked into the catalog's self-signed TLS certificate on first start, so changing it later means recreating the config volume. |
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
| `COMPOSE_PROJECT_NAME` | `server` (the `name:` in `server/docker-compose.yml`) | Compose project name, and therefore the prefix on the named volumes (`server_iris-state`, `server_iris-config`, `server_iris-images`, `server_iris-tier-auth`, and `server_iris-management-ca`). Host-side only: read by Compose itself, never passed into the container. The declared default is the same name the directory used to derive, so an existing deployment keeps its original volumes and gains the two narrow split-tier volumes. Set it to give a second checkout on the same host its own volumes — see [Server](server.md#compose-project-name). |
| `IRIS_CONTAINER` | `iris` | Name of the server container: Compose applies it as `container_name`, and `tools/apply-assignments.sh`, `tools/stage-iox-package.sh`, `tools/gen-device-installers.sh`, and `tools/check-package-freshness.sh` address that name. Host-side only. Container names are host-global, so a second stack needs this as well as `COMPOSE_PROJECT_NAME`. `tools/start-compose-server.sh` resolves the container from its own Compose project when this is unset. |
| `IRIS_CONSOLE_CONTAINER` | `iris-console` | Name of the state-free Console container. Host-side only; a second stack needs a distinct value because container names are host-global. |
| `IRIS_OBSERVABILITY_TOKEN_FILE_HOST` | `/dev/null` | Host path of the raw, observability-scoped bearer token mounted read-only into the server. Required when `IRIS_OBSERVABILITY=1` and `/metrics` will be scraped; keep it mode 600 and give the identical raw value to the scraper's `credentials_file`. Host-side only. |
| `IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST` | `/dev/null` | Optional previous observability token during a bounded rotation overlap. Remove it after every scraper has moved to the new current token. Host-side only. |
| `IRIS_OTLP_HEADERS_FILE_HOST` | `/dev/null` | Host path of an optional mode-600 file containing the collector authentication header specification. Compose mounts it only into the server tier at the fixed path named by `IRIS_OTLP_HEADERS_FILE`; host-side only. Prefer this to putting collector credentials in `server/.env`. |
| `IRIS_ARTIFACTS_HOST_DIR` | `../artifacts` | Host directory bind-mounted read-write at `/srv/artifacts`. Host-side only: it is interpolated into the bind mount, not passed into the container. |
| `IRIS_SHARP_SANS_FONT_HOST` | `/dev/null` | Host path of the licensed Sharp Sans Bold `.woff2`, bind-mounted read-only over `server/webroot/fonts/SharpSans-Bold.woff2` inside the container. The font is excluded from the build context (`.dockerignore`) and the release tarball — Cisco's license does not permit redistributing it — so the console falls back to its default font stack without it (`font-display: swap`). Set this only on a deployment that independently holds the license; left unset it mounts `/dev/null`, a harmless no-op every other deployment never has to think about. Host-side only: interpolated into the bind mount, never passed into the container. See [Console](console.md#branding). |
| `IRIS_GUI_PUBLISH` | `8080` | Published host port for the console, bound only to `IRIS_HOST_IP` by Compose. The container always listens on 8080 internally. |
| `IRIS_CONSOLE_URL` | unset | Lets server-side status derive a non-default published Console port when `IRIS_GUI_PUBLISH` is unset. Prefer setting `IRIS_GUI_PUBLISH` directly. |
| `IRIS_GUI_ALLOW_PLAINTEXT` | unset | `1` makes the Console deliberately skip its TLS identity and serve plain HTTP. Without it the Console obtains its active identity through the authenticated management hop (or uses the independently mounted Kubernetes default) and refuses to start when no usable identity exists. The session cookie loses its `Secure` attribute under the opt-in. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_CATALOG_ALLOW_PLAINTEXT` | unset | `1` lets the catalog serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `catalog.py` refuses to start in that state — every route answers a device bearer token. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped `docker-entrypoint.sh` always provisions `IRIS_CERT`, so this only matters running `catalog.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_ARTIFACTS_ALLOW_PLAINTEXT` | unset | `1` lets the artifact server serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `artifact_server.py` refuses to start: the authenticated v1 API carries resource-bound credentials, while unchanged Guest Shell enrollment relies on TLS to protect short-lived capability paths. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped entrypoint always provisions `IRIS_CERT`, so this only matters running `artifact_server.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_VERSION` | unset | Build argument that bakes the release string the console's Settings page shows. Unset means the `VERSION` file in the image. Build-time only: it is not a container variable. |
| `IRIS_GUI_ADMIN_PASSWORD` | unset (prompts) | Read by `iris-gui-admin` to set the console admin password non-interactively. Pass it on the one-shot command (`docker compose … run --rm -e IRIS_GUI_ADMIN_PASSWORD=… iris iris-gui-admin`); it is deliberately **not** in the Compose `environment:` block, so a long-running container never holds the password in its environment. |
| `IRIS_SAMPLE_INTERVAL` | `15` (seconds) | Seeder/telemetry poll cadence. A transfer that completes inside one interval can be observed with no connected peer, so per-peer rates and the map's measured edges never appear — a 1 GB image at ~90 MB/s lands in about 15 seconds. Lower it to 2–5 on a fast fabric or for a live demo; the cost is more aria2 RPC calls. |
| `IRIS_TRACKER_PORT` | `6969` | Port the tracker listens on. The canonical (seeder) announce, per-device personalized announces and the rotation CLI all derive their announce base from `IRIS_HOST_IP` and this port, so changing it needs the compose port mapping changed to match. |
| `IRIS_TRACKER_ANNOUNCE` | unset | Full HTTPS announce base (`https://host:port/announce`, no credentials, query, or fragment) used in place of the `IRIS_HOST_IP` + `IRIS_TRACKER_PORT` derivation by every path that builds an announce URL. Plain HTTP and malformed overrides fail closed. |
| `IRIS_REQUIRE_IDENTITY_GATE` | unset (off) | Set to `1` to make the catalog answer 503 to every per-device torrent request until the checkpoint file `identity-compatible-ready` exists under `IRIS_STATE` — the file a proven seeder rotation writes and `--recover` removes. Read per request, so opening or closing the gate needs no restart. The canonical (service) torrent path is unaffected. A deployment that does not set it serves per-device torrents as before. |
| `IRIS_ONBOARD_CONCURRENCY` | `25` | Maximum onboard/undeploy jobs the worker pool runs at once; the rest queue. `GET /api/v1/onboard/jobs` reports the active value as `max_concurrent`. |
| `IRIS_XR_SESSION_TIMEOUT` | `150` seconds | Wall-clock bound for each IOS-XR command session. `0` disables it; an invalid value falls back to the default with a warning. |
| `IRIS_CONTAINER_TESTING` / `IRIS_TEST_SKIP_MOUNT_CHECK` | unset | **Test-only escape hatches — never set these on a device.** The common entrypoint accepts temporary path overrides only with the first set to `1`; the XR mount check is skipped only when both are `1`. Production `xr-appmgr` refuses to start unless `/hostmount` is a real bind mount, so it cannot report a stage to `harddisk:` while writing into its disposable rootfs. |
| `IRIS_DEVICE_ENABLE_ALWAYS` | unset (off) | Compatibility escape hatch: each agent process starts by sending `enable` plus its secret on IOS-XE SSH sessions, and drops the pair for the rest of that process once a session's own prompt shows the login was already privileged (`#`). Normally IRIS learns whether escalation is needed from the device prompt and sends neither line to already-privileged logins. |
| `IRIS_ONBOARD_JOB_TIMEOUT` | `7200` seconds | Wall-clock deadline for one onboard/undeploy job, measured from the moment it starts **running** (never from when it was queued). A running job past the deadline is stopped like an operator abort. |
| `IRIS_ONBOARD_REAP_GRACE` | `60` seconds | Grace between the `SIGTERM` sent to a deadline-expired installer's process group and the `SIGKILL` that follows. |
| `IRIS_SEEDER_PREV_TTL` | `2592000` seconds (30 days) | How long a rotated-out seeder announce token keeps working, measured from the rotation that retired it — the overlap that lets a device which missed the rotation keep announcing while its torrent is re-personalised. Past it the tracker refuses the old token like any other expired credential, and the next rotation drops the record. Set it once, for the whole deployment: every process computes the deadline from this value, so a per-process override would make the same credential expire at different times. `0` means no overlap at all — the previous token is dead the moment it is rotated out — and a value that is not an integer raises at startup rather than falling back. See [Security](security.md#rotating-the-seeder-announce-credential). |
| `IRIS_HTTP_TIMEOUT` | `30` seconds | Per-connection socket timeout for the tracker and catalog request handlers: a connection that stalls mid-request is closed instead of pinning a thread. A non-numeric or non-positive value falls back to the default. |
| `IRIS_ENDPOINT_TTL` | `900` seconds | Freshness window for a device's durable peer endpoint in the endpoint map (`peer-endpoints.d/`). A missing, non-integer or non-positive value falls back to the default (a TTL of 0 would make every row stale and apply an empty blocklist under an `enforced` status). Endpoint rows for quarantined or revoked devices are retained regardless — see [Operations](operations.md#peer-policy-operations-and-their-backlog). |
| `IRIS_ENROLL_TTL` | `3600` seconds | Lifetime of the one-shot enrollment token minted into a per-device installer, overriding the standard catalog-token TTL for that first exchange only. |
| `IRIS_HEALTH_LISTENERS` | `tracker:6969,catalog:8443,artifacts:8000,management:9443` | What the server tier's `:9101/readyz` TCP-probes, as `name:port,name:port`. Console readiness is local to its own `/readyz`; the server does not depend on it. Blank keeps the default set; the literal `off` checks nothing, for a deployment that runs a subset of the services and does not want the missing ones reported down. |
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

The browser Console's *Settings → TLS & trust* sub-page manages these through
the management API. The durable certificate and trust state belongs to the
server tier; the state-free Console owns only its active runtime TLS copy.

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_GUI_CERT` | Server: `/run/iris/tls/gui-cert.pem`; Compose Console: `/run/iris-console/cert.pem` | The server rebuilds an installed custom identity in its tmpfs. The Console obtains the active custom or Console-only fallback identity through the authenticated management API and atomically writes its own tmpfs copy. The catalog/device private key is never mounted into or sent to the Console. |
| `IRIS_TRUST_DIR` | `/etc/iris/tls/trust` | Durable directory of installed root-CA PEMs: one `<sha256-fingerprint>.pem` per manual install, plus the downloaded public bundle as the distinguished file `downloaded-bundle.pem`. |
| `IRIS_CA_BUNDLE` | `/run/iris/tls/ca-bundle.pem` | Runtime concatenation of the trust dir, rebuilt at every boot and on every trust change. Absent while the trust dir is empty. Outbound TLS (OTLP export, the CA-bundle download) verifies against the system store plus this bundle. |

The server-owned console certificate override persists as
`/etc/iris/tls/gui-crt.pem` (plaintext certificate, leaf or fullchain) plus
`/etc/iris/tls/gui-key.pem.age` (private key, age-encrypted to the same
recipients as the rest of the secret store); boot rebuilds `IRIS_GUI_CERT`
from the pair. An override that fails to decrypt — or whose certificate and key
do not form a matching pair — is skipped with a warning, so the console falls
back to the built-in certificate and a bad upload can never lock you out of the
console.

The public-CA download settings live in `$IRIS_STATE/ca-trust-settings.json`
(`{"url": ..., "auto": ...}`, owned and consumed by the server management
tier): the URL must be `https://`, and while `auto` is on the server
re-downloads the bundle every 24 hours. The
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
| `IRIS_METRICS_HOST` | `0.0.0.0` | Bind host for the TLS telemetry listener. Bind it to `127.0.0.1` when no external Prometheus scraper consumes it. |
| `IRIS_SWARM_URL` | `https://127.0.0.1:9101/swarm` | Where the state-owning management process fetches swarm state. The request uses the file-mounted management bearer and verifies the catalog CA; this is not a browser-facing URL. |
| `IRIS_OTLP_HEADERS` | unset | Comma-separated `Name=Value` headers attached to every OTLP POST (collector authentication). Values are secrets: never logged, never echoed in errors, and the exporters refuse HTTP redirects so they cannot leak to a redirect target. |
| `IRIS_OTLP_HEADERS_FILE` | `/run/secrets/iris_otlp_headers` (Compose) | Read the header spec from a file instead of the environment. Compose fixes this container path and obtains the host path from `IRIS_OTLP_HEADERS_FILE_HOST`; Kubernetes mounts its optional `iris-otlp-headers` Secret here. `IRIS_OTLP_HEADERS` wins when both are set. |
| `IRIS_OTLP_DEVICE_METRICS` | unset (off) | Still accepted so an existing deployment starts, but retired: the per-device OTLP gauges it enabled are no longer exported. Device- and peer-labelled history lives in the OTLP log records instead. |
| `IRIS_EVENTS_URL_TEMPLATE` | unset | Still injected into the swarm map's page config as `eventsUrlTemplate`, but the current map renders no events link — setting it has no visible effect. |

#### Telemetry gating rule

* Prometheus `/metrics` is served only while `IRIS_OBSERVABILITY` is enabled; otherwise the path answers 404.
* OTLP export requires **both** an effective enabled flag **and** an effective endpoint. Each field is the console override from `$IRIS_STATE/telemetry-destination.json` when set, else the deployment env (`IRIS_OBSERVABILITY` / `IRIS_OTLP_ENDPOINT`). An endpoint on its own is inert — nothing is exported.
* `/healthz` and `/readyz` are served whenever the listener runs, regardless of either variable, and disclose only `{"ok": true|false}`. `/healthz` answers 200 unconditionally and proves only that the telemetry listener is alive; `/readyz` TCP-probes the tracker, catalog, artifact server, and management API and communicates dependency failure through status 503 plus `Retry-After`, without naming the failed listener. It is what the Compose `HEALTHCHECK` and Kubernetes probes use; `IRIS_HEALTH_LISTENERS` narrows or disables its probe set.
* `/swarm` always requires the file-mounted management bearer. The management process reads it over pinned loopback TLS, so port 9101 needs external reachability only for authenticated Prometheus scraping or operator tools — never for the Console.

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

The checked-in [OpenAPI 3.1 contract](openapi.yaml) is the machine-readable
source of truth for every Console, management, catalog, tracker, telemetry, and
artifact operation. A bidirectional test compares its method/path set with the
dispatch registries, so an undocumented handler or stale specification fails
the build. This section explains the browser/operator behavior and deliberately
does not duplicate every schema field from the specification.

The browser surface is versioned under `/api/v1`; its server-tier peer is the
internal `/internal/v1` management API on port 9443. Breaking changes require a
new major base path. Before removing a published major, IRIS will retain it for
at least two dated releases, return `Deprecation`, `Sunset`, and successor
`Link` headers, and announce the removal in the changelog. This first versioned
surface exposes no public unversioned API aliases.

Every `/api/v1` route requires an authenticated console session cookie except two
authentication-establishment routes: `POST /api/v1/login` and
`POST /api/v1/setup`. State-changing methods
on the authenticated routes additionally require the session's CSRF token in an
`X-CSRF-Token` header (double submit); without it the request is rejected with
403. The two pre-auth routes carry no CSRF token, because there is no session
yet. JSON request bodies are capped at 64 KiB — the exceptions are the CSV import
at 8 MiB, the streamed image upload at 4 GiB, and the offline Bulk Hash feed
upload at 256 MiB.

Registered JSON API errors use RFC 9457 Problem Details with
`Content-Type: application/problem+json`: `type` and `code` are stable,
documented identifiers in the [Problem type registry](problems.md), and
`detail` is redacted. Paths, credentials, exception
text, and resource existence before authentication are never exposed. The
BitTorrent tracker deliberately keeps BEP-compatible bencoded failures because
that wire protocol's clients do not consume Problem Details; the OpenAPI entry
marks that error-format exception. The unchanged Guest Shell enrollment files
remain on their legacy, TLS-protected capability paths rather than the v1 API.
Successful downloads retain their static-file response semantics; errors use
Problem Details. Probe success bodies and BitTorrent success bodies retain
their protocol-native formats.

Status codes, pagination, concurrency, and retry guarantees are operation
specific and enumerated in the OpenAPI contract. In particular, fleet and
swarm projections retain their established `limit`/`offset` response shapes;
peer policy publishes a strong `ETag` and accepts `If-Match` while v1's body
`if_revision` compatibility field remains; device assignment retains its
domain-specific `expect_image_ids` compare-and-set form. Only operations that
explicitly advertise `Idempotency-Key` keep a bounded, process-local 24-hour
successful-response replay. Reusing a key with a different body is 409; after a
server restart, the durable job/resource is authoritative.

Several established v1 Console paths still contain action names. Renaming them
would itself break deployed browser and integration clients, so their OpenAPI
operations mark that compatibility decision explicitly. Resource-oriented
replacements belong in the next major base path; no verb path will be removed
silently inside v1.

The Console-to-server request additionally carries the management-scoped tier
bearer over CA-pinned HTTPS. That credential is checked before route lookup or
body buffering. It never replaces the browser session/CSRF checks, and a device
catalog token cannot call management operations.

### Session and settings

| Route | Body / result |
| --- | --- |
| `POST /api/v1/login` | Authentication-establishment route. `{username, password}` → `{username, csrf}` plus the session cookie (`HttpOnly; SameSite=Strict`, plus `Secure` when the listener serves TLS); 401 on bad credentials, 429 with `Retry-After` when throttled, 503 with `Retry-After` when both password-verification slots are busy (not a credential failure: no limiter penalty, no audit row). Before any admin exists, the default `iris` / `irisisgreat!` credential instead returns `{setup: true, setup_grant}` — no session — for use with `POST /api/v1/setup` below. Creating the administrator permanently ends that special behavior. Because the first caller who can reach a fresh Console can claim it, restrict access to a trusted management network until setup is complete. |
| `POST /api/v1/setup` | Authentication-establishment route, first run only. `{username, password, setup_grant}` creates the permanent admin account, where `setup_grant` is the one-use, 10-minute grant from the default-credential login above; 403 on a missing/invalid/expired grant, 409 once an admin exists. |
| `POST /api/v1/logout` | Revokes the current session and expires the cookie. |
| `GET /api/v1/session` | The current session's info, or 401. Any GET carrying `X-IRIS-Poll: 1` (the console's periodic refreshers) is validated without refreshing the session's idle clock. All `/api/v1/*` responses carry `Cache-Control: private, no-store`; a present-but-unreadable secrets store answers 503 on every store-backed route. |
| `GET /api/v1/settings` | Console settings, published port, and the running version — plus the active console certificate (`gui_cert`), the installed trust entries (`trust`), the CA download settings (`ca_trust`), the effective telemetry destination with its source (`telemetry_destination`), and the audit-export destination with its last-run status (`audit_export`; a `password_set` flag only, never the password). |
| `GET /api/v1/settings/setup-status` | The setup status behind the first-run wizard (`#setup`), Settings → Setup, and the persistent Settings → Device packages view: `admin`, `telemetry`, `packages`, and `image_verification`, each with a `state` of `ok`, `unset`, `stale`, `absent`, or `unknown`. `telemetry` is `ok` only when export is enabled *and* an endpoint resolves, and also carries `source` (`override` or `env`), `endpoint`, and `enabled`. `packages.items` covers the two IOx tars and `iris-xr.rpm`; each item reports artifact modification time (the legacy `built_at` field, not an attested build time), state/reason, its wrapper-specific remedy, and canonical OCI provenance only after the served wrapper SHA-256 matches the adjacent manifest. An `ok` item does not claim package-content or native-signature inspection. The aggregate package state separately fails closed when the live served certificate or distributed `iris-catalog.pem` is unavailable or the two disagree; `reference_fingerprint` identifies the live certificate. Certificates are never compared with package build time or contents. See [Setup](console.md#setup). |
| `POST /api/v1/settings/password` | `{current, new, confirm}`; changes the admin password and revokes every other session. |
| `POST /api/v1/settings/sessions/revoke-others` | Revokes every session except the caller's. |
| `POST /api/v1/settings/gui-cert` | `{cert_pem, key_pem}` — validates (real `load_cert_chain`; per-field errors on garbage PEM or key mismatch) and installs the console certificate, hot-applied. Returns `{gui_cert, applied, note}`: `applied` is `false` (with a `note`) when the listener is not serving TLS, in which case the saved certificate takes effect at the next restart. |
| `DELETE /api/v1/settings/gui-cert` | Reverts the console to the built-in certificate, hot-applied. |
| `POST /api/v1/settings/trust` | `{pem}` — installs one or more CA certificates as one trust entry; returns `{entry}`, the new trust-store row. Every block must parse as an X.509 certificate; a decodable-but-not-a-certificate block rejects the whole upload (400). |
| `DELETE /api/v1/settings/trust/<name>` | Removes one trust entry and rebuilds the runtime bundle. |
| `POST /api/v1/settings/ca-trust` | `{url, auto}` — configures the public-CA bundle download; the URL must be `https://`. |
| `POST /api/v1/settings/ca-trust/refresh` | Starts a download-now job; returns `{job}`. Downloads refuse redirects, cap at 2 MiB, and must yield at least one certificate (plain PEM, a certs-only PKCS#7 bundle, or a verified CMS-signed wrapper). |
| `GET /api/v1/settings/ca-trust/refresh/<id>` | `{state, detail, certs}` — `running`, `done`, or `failed`. |
| `POST /api/v1/settings/telemetry-destination` | `{endpoint, enabled}` — telemetry destination override, hot-applied by the hub. The endpoint must be an `http`/`https` URL with a host, no query or fragment; a trailing slash is stripped. |
| `DELETE /api/v1/settings/telemetry-destination` | Removes the override — telemetry reverts to the deployment env defaults. |
| `POST /api/v1/settings/audit-export` | `{host, port, user, path, age_recipient, auto, password}` — validates and stores the audit-export destination; 400 on any invalid field. An absent or empty `password` keeps the stored one. |
| `DELETE /api/v1/settings/audit-export` | `{deleted: <bool>}` — clears the destination and the stored password. |
| `POST /api/v1/settings/audit-export/run` | Starts one export job; returns `{job_id}`. 409 when the export is not fully configured (invalid or absent destination, or no stored password). |
| `GET /api/v1/settings/audit-export/run/<id>` | `{state, detail}` — `running`, `done`, or `error`; `detail` is the uploaded filename or the failure reason. Jobs are in-memory, so a restart forgets them (404). |

The audit-export settings live in `$IRIS_STATE/audit-export-settings.json`
(`host`, `port`, `user`, `path`, `age_recipient`, `auto`, plus the
server-maintained `last_run_ts` / `last_result`; management-tier owned). The SCP
password is not in this file — it lives in the age-encrypted secrets store —
and the destination's SSH host key is pinned trust-on-first-use in
`$IRIS_STATE/audit-export-known-hosts`. See
[Audit export](operations.md#audit-export).

### Images

| Route | Body / result |
| --- | --- |
| `GET /api/v1/images` | `{images: [...]}` — the catalog entries. |
| `GET /api/v1/images/importable` | `{importable: [...], skipped: [...]}` — image files on disk under either root that are not in the catalog. A pure read; nothing is published or moved. |
| `PUT /api/v1/images/upload/<filename>` | Streams the body into the uploads volume and starts a publish job; returns `{job_id}`. 413 for a missing body or one over 4 GiB. |
| `POST /api/v1/images/import` | Body `{"path": "<candidate path>"}`; returns `{job_id}`. Publishes the file in place. |
| `GET /api/v1/images/jobs/<job_id>` | Publish job state (`publishing`, `done`, `error`). Shared by upload and import. |
| `DELETE /api/v1/images/<image_id>` | `{deleted: true}`, or 409 with `{assigned: [...]}` when a live device still has the image approved. |

`POST /api/v1/images/import` authorizes on candidate identity, not on a path prefix,
so a path that merely starts inside a root is refused with 400. It answers 404 if
the file vanished between listing and import, and 409 if a publish of the same
catalog id is already in flight. Every outcome writes an `image_import` audit
event, with `result=fail` and the reason on a rejection.

### Image verification

| Route | Body / result |
| --- | --- |
| `GET /api/v1/settings/image-verification` | `{mode, hour_utc, last_run}` — the Cisco Bulk Hash reconciliation schedule and the outcome of its most recent run. |
| `POST /api/v1/settings/image-verification` | `{mode, hour_utc}` — a full replace of the schedule; `mode` is `off`, `daily`, or `weekly` (weekly always anchors to Monday UTC — there is no day-of-week field), `hour_utc` is 0-23. `last_run` is server-managed and cannot be set here. |
| `POST /api/v1/image-verification/refresh` | Runs the reconciler now (`source=manual`), synchronously on this request. `{outcome: "ok", matched, mismatched, not_in_feed}` (200); `{outcome: "already_running"}` (409, another run is already in flight); `{outcome: "fail", detail}` (502 — fetch, signature, parse, or reconcile failed, and the catalog is left untouched). |
| `POST /api/v1/image-verification/offline` | Raw `.tar` body (256 MiB cap), for air-gapped servers — runs the identical verify-then-parse pipeline against the uploaded file instead of fetching one (`source=offline`); same result shape and status codes as refresh. |
| `POST /api/v1/images/<id>/release-quarantine` | `{override, confirm_text}` — lifts an active quarantine. `override=false` re-checks the image's sha512 against the stored feed verdict and releases it if that now agrees, else 409 `quarantine_still_mismatched` with the verdict. `override=true` requires `confirm_text` to exactly match the image's filename (400 otherwise) and releases regardless of the mismatch, recorded as a distinct `release_override` audit action; the stored verdict itself is left as `mismatch`. 404 if the image does not exist; 400 if it is not currently quarantined. |

Each catalog entry in `GET /api/v1/images` carries a `quarantined` bool and a
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
| `GET /api/v1/devices` | `{devices: [...], now, total, offset, limit, revision}` — the inventory view plus the server clock, so the UI computes freshness server-clock-to-server-clock. `total` is the size of the whole (filtered) projection and `limit` is `null` unless a page was asked for, so a caller can always tell a page from the fleet. Optional `limit` (1…1000, clamped and echoed) and `offset` (≥ 0) page it; a malformed or non-positive `limit`/`offset` is a 400 rather than a silent default. A page is sorted by `device_id`, while the unpaged response keeps its long-standing store order. `revision` is the fleet store revision behind the same read: a client walking pages compares it to tell a coherent walk from one that raced a fleet edit, and re-walks if it changed. Row order carries no meaning for the actions built on the projection — those are keyed by `device_id`. Optional filters narrow the projection *before* it is paged, so `total` always reflects every filter together, not just the page: `q` (case-insensitive substring over `device_id`, `device_ip`, `model` and `heartbeat_model`), `management_type` (a device's classified type, or `legacy` for one stored as the unclassified `legacy_routed`), `platform` (the Agent install choice; `__none` matches an unset one), `cred` (a credential profile id; `__none` matches none assigned), `telemetry` (`on` / `off` / `unknown` — tri-state, `unknown` for a device that has never heartbeated), `peer` (`quarantined` / `not-quarantined`, read from the same peer-policy assignment set `GET /api/v1/peer-policy` exposes), and `status` — one of the Status column's own keys (`onboarding`, `undeploying`, `waiting-heartbeat`, `onboard-failed`, `undeploy-failed`, `deployed`, `placement-failed`, `image-failed`, `copying`, `staging`, `unassigned`, `enrolled`, `not-enrolled`), the freshness modifier `offline` (last heartbeat 600s+ old), or the `__attention` rollup (any row at the Status column's negative/severe/warning level). Every filter is the same rule the console's own filter bar and Status column use — see [Paging and selection at fleet scale](console.md#paging-and-selection-at-fleet-scale) — so a page can never disagree with what the filter bar promises. An unrecognized filter value matches zero rows rather than erroring, the same as a `q` that matches nothing. |
| `POST /api/v1/devices` | Creates or updates one inventory row; returns `{device: ...}`. |
| `DELETE /api/v1/devices/<id>` | Retires the device: revokes its credentials first, then clears peer-policy assignment, inventory row, and catalog state. `{deleted: <bool>, degraded: [...]}` — 200 when cleanup was complete, 207 when part of it failed (`degraded` names the areas), 500 `{deleted: false, error: "secret revoke failed"}` when the revoke could not be persisted, in which case nothing was changed. Endpoint rows are retained until they age out. See [Retiring a device](operations.md#retiring-a-device). |
| `GET /api/v1/devices/export-csv`, `GET /api/v1/devices/example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/v1/devices/import-csv` | Bulk inventory import (8 MiB cap, all-or-nothing); returns per-row stats. |
| `GET /api/v1/install-options?model=<model>` | `{options: [...]}` — the agent-install platforms that model may run, which is what the console's platform picker offers. An 8000-series (IOS-XR) model returns exactly `["xr-appmgr"]` and nothing else; a blank model, or one this table has no opinion on, returns `null` — meaning no guardrail applies and every explicit choice stays available. |
| `GET /api/v1/devices/<id>/plan` | `{plan}` — the resolved deployment plan; 409 when it cannot resolve. |
| `GET /api/v1/devices/<id>/reports` | `{reports: [...]}` — the device's stored telemetry ring. |
| `GET /api/v1/devices/<id>/deployment` | `{record, total}` — the deployment record that best describes the device (the active one, else the teardown-authorizing one, else the newest) plus the stored-record count; `record` is `null` when none exists. Read-only — feeds the deployment-details panel. |
| `POST /api/v1/devices/<id>/assign` | `{image_ids: [...]}` sets the device's ordered, up-to-ten-image approved set (an empty array unassigns); the singular `{image_id: <id or null>}` is the pre-multi-image compat shape and always means a one-element set. 400 for more than ten ids, a duplicate, or an id not in the catalog; 400 `image_quarantined` with the blocking verdict if one of the ids is currently quarantined by the Cisco Bulk Hash reconciler (see [Image verification](#image-verification)). See [Policy schema](#policy-schema). |
| `POST /api/v1/devices/<id>/credential`, `.../platform` | Sets the credential profile, or the platform (Agent install choice) and storage target; each returns `{ok: true}`. |
| `POST /api/v1/devices/bulk-credential` | `{device_ids: [...], credential_profile_id: <id or "">}` sets ONE credential profile on every listed device in a single call — the bulk form of the route above, backing the console's "Select all *N* matching devices" bulk credential action (issue #125). 400 for a non-array/empty `device_ids`, one over the supported fleet size, or an unknown `credential_profile_id`. Not all-or-nothing: returns `{ok: true, applied: <count>, failed: {<device_id>: <reason>, ...}}`, naming exactly which selected ids (e.g. one deleted out from under a stale selection) did not apply, while every other id still does. Audited once as `device_credential_bulk_change`, not once per device. |
| `POST /api/v1/devices/<id>/forget-host-key` | Removes the device's entry from the persistent SSH known_hosts accept-new mode records into (`lab/iris-ssh-policy.sh`) — for a device that was re-imaged or replaced and now fails every session with a changed-key error. `{ok: true, peer: <device_ip>}` on success, including when nothing was recorded (already effectively forgotten). 400 `{error: ...}` when the device has no `device_ip` on record or the removal itself fails. Audited as `device_forget_host_key` (device id, actor, and the peer address). Only the persistent accept-new file is touched — an `IRIS_SSH_HOST_KEY` pin or an operator-supplied `IRIS_SSH_KNOWN_HOSTS` file is untouched. The next session re-verifies and pins the device's new key; this never disables verification. See [Operations → Forgetting a device's SSH host key](operations.md#forgetting-a-devices-ssh-host-key). |
| `POST /api/v1/devices/<id>/request-report` | Requests a fresh telemetry report; `{ok: true, expires_at}`, or 429 while one is already pending. |
| `POST /api/v1/devices/<id>/adopt` | Requires `{"acknowledge_adopt": true}`; returns `{record_id}`. 409 when the device already has an active deployment record; routers cannot be adopted. |
| `POST /api/v1/devices/<id>/onboard`, `POST /api/v1/devices/<id>/undeploy` | Starts the job; `{job_id}`. 409 when the device is busy with the opposite action. Undeploy also answers 409 when the device has no deployment record — send `{"force": true}` to run it anyway, which removes only the IRIS-named agent footprint and leaves operator-owned network state (VLAN/SVI, VirtualPortGroup, NAT) untouched, audited as `undeploy_forced`. A `503` naming an unreadable `deployment_records.json` is a different answer: the records cannot be read at all, so whether this device has a deployment is unknown — repair the file rather than adopting the device. |

Router deployments carry extra preflight and ownership rules — see
[Management Type and VLAN Ownership](management-type.md#router-preflight-and-ownership).

### Peer policy

The read side of the swarm's isolation posture, and the one compare-and-set
write in the whole API.

| Route | Body / result |
| --- | --- |
| `GET /api/v1/peer-policy` | The count-only policy view: `schema`, `revision`, `degraded`, `fail_closed`, `quarantine` (the reserved-ACL descriptor), `quarantine_assignments` (the sorted device ids currently quarantined), and `enforcement` — the tracker's reconciler status as `state`, `desired_ip_count`, `applied_revision`, `last_reconciled_at`, `conflict_count`, `conflict_types`, `last_effect` (aggregate `disconnected_peers` / `removed_peers` counts only), `last_error`, and `last_operation_exported_revision`. Deliberately count-only: no peer address ever crosses this boundary. |
| `PUT /api/v1/peer-policy/quarantine/<device_id>` | Quarantines or releases one device. The body must be **exactly** `{"quarantined": <bool>, "if_revision": <int ≥ 1>}` — no other keys, no other types. `if_revision` is the revision you read from `GET /api/v1/peer-policy`, and the write commits only if the policy is still at that revision. 200 `{ok: true, revision, quarantined}` on success. |

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
| `GET /api/v1/onboard/jobs` | `{jobs: [...], max_concurrent, now}`. |
| `GET /api/v1/onboard/jobs/<id>` | One job, or 404. |
| `GET /api/v1/onboard/jobs/<id>/stream` | Server-sent events for that job until it reaches a terminal state. |
| `POST /api/v1/onboard/jobs/<id>/abort` | `{aborted: true}`. |
| `POST /api/v1/onboard/cancel-queued` | `{cancelled: <count>}` — drops jobs still queued. An optional `{"job_ids": [...]}` body scopes the cancel to those jobs (the console always scopes); without it every queued job is cancelled, other sessions' included. |

### Credentials

| Route | Body / result |
| --- | --- |
| `GET /api/v1/credentials` | `{profiles: [...]}` — id, name, and device user only, never passwords. |
| `POST /api/v1/credentials` | Creates or updates a profile; returns `{profile}` redacted the same way. |
| `DELETE /api/v1/credentials/<id>` | `{deleted: <bool>}`. |

### Monitoring

| Route | Body / result |
| --- | --- |
| `GET /api/v1/overview` | The dashboard rollup: image, device, and rollout state. |
| `GET /api/v1/swarm` | The telemetry `/swarm` JSON, fetched by the management tier over pinned loopback TLS with its file-mounted bearer and passed through byte for byte. Answers 200 with `{"peers": [], "error": ...}` when the telemetry listener is unreachable. Optional `limit`/`offset` (same rules as `/api/v1/devices`) return a page instead: participants are flattened across `images` in image order and only their `peers` arrays are sliced (every image entry survives, since the map's image selector is built from them), with `peers_total`, `peers_offset` and `peers_limit` added. A payload that is not the documented `{"images": [{"peers": [...]}]}` shape answers `{"peers": [], "error": "swarm data not paginatable"}` rather than being passed through whole to a caller that asked for a page. |
| `GET /api/v1/audit` | `{events: [...]}`; `category`, `limit` (max 500), `before_ts`, and `after_ts` query parameters. |
| `GET /api/v1/audit/histogram` | Per-bucket audit event counts for the activity strip. |
| `GET /api/v1/deploy-logs` | `{logs: [...]}` — metadata for the persisted per-job deployment logs (file, device, action, state, rc, finish time, size), newest first. `device_id` filters to one device; `after_ts` / `before_ts` (Unix seconds, inclusive at both ends) filter by finish time — the range the Deployment logs brush selects. |
| `GET /api/v1/deploy-logs/histogram` | `{buckets: [{start, count}], now}` — evenly spaced counts of finished jobs, for the time filter's histogram. Takes `window` (seconds, default 604800) or an explicit `since_ts`/`until_ts` pair, `buckets` (default 30, capped at 200), and `device_id`; 400 when `until_ts` is not greater than `since_ts`. |
| `GET /api/v1/deploy-logs/<file>` | One persisted log as `text/plain`; 404 for a name that does not resolve to a direct child of the log directory. |
| `GET /api/v1/help` | `{version, deployment_id, docs_url, guides}` — the "?" popover data: the running version, the stable per-deployment id, and the documentation links. |
| `POST /api/v1/telemetry/stream` | `{"every": <int 1..60>, "pause": <bool>}` — network-wide stream tuning, echoed to every device on its next heartbeat. Audited. |
| `GET /api/v1/telemetry/health` | The hub's authenticated `/status` JSON (including OTLP export health), proxied behind the console session. `{"ok": false, "error": "unavailable"}` when the hub is unreachable. |
| `GET /swarmmap` | The swarm map page itself. Session-gated like the `/api` routes, but not under `/api`. |

Persisted deployment logs are plain files under `$IRIS_STATE/deploy-logs`,
one per finished onboard or undeploy job with a machine-parseable header
line; the newest 200 are kept. `/api/v1/help`'s `deployment_id` comes from
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

## Device catalog, tracker, telemetry, and artifact HTTP(S) contracts

### Device catalog API (port 8443)

Every route requires `Authorization: Bearer <token>`; a missing or invalid
bearer answers a Problem Details 401 before any route is matched. Authorization
is narrower than successful authentication:

* **Identity-bound** (`heartbeat`, `telemetry`, `policy`, `token-refresh`): the
  token must resolve to that path's own `<device_id>` under `catalog_token` —
  or, on `token-refresh` only, the immediately preceding
  `catalog_token_prev`, so a device that never saw the response to its own
  rotation can recover it idempotently rather than being stranded. `policy`
  is identity-bound because its response carries the caller's minted
  `plan_id`/`transfer_id` pair.
* **Assignment-bound** (`images`, image detail, and torrents): a device sees
  only ids in its own approved-image set. An unassigned or nonexistent id has
  the same 404, and the fleet-wide `/v1/devices` collection no longer exists.
  A service credential can authenticate but does not acquire a device's
  assignment and therefore receives no device catalog entries.

| Route | Auth | Body / result |
| --- | --- | --- |
| `GET /v1/images` | Assignment-bound | `{images: [...]}` — only the caller's approved entries, with no `source_dir` or reconciler internals; an unassigned device receives an empty list. |
| `GET /v1/images/<id>` | Assignment-bound | Device-facing view of one approved image; an unassigned and nonexistent id both return 404. |
| `GET /v1/torrents/<id>` (also accepts `<id>.torrent`) | Assignment-bound | An IOx/XR request advertises `X-IRIS-Tracker-Auth: bearer` and receives a torrent with a token-free tracker URL; its agent supplies the separately rotated announce bearer as an aria2 per-download header. A request without that opt-in receives the established query-token personalization required by unchanged Guest Shell bundles. Both forms carry `Cache-Control: private, no-store` and `Vary: Authorization, X-IRIS-Tracker-Auth`. 404 means the id is not approved or no torrent exists; 503 means the identity-compatibility gate is closed; missing announce material or personalization failure is a redacted 500. There is no cross-device or shared-token fallback. |
| `GET /v1/devices/<id>/policy` | Identity-bound | The device's own policy view — see [Policy schema](#policy-schema). |
| `POST /v1/devices/<id>/heartbeat` | Identity-bound | Body: the device's heartbeat JSON — see [Keyed per-device state](#keyed-per-device-state). 200 `{ok: true, stream_every, stream_pause, report_requested?, report_request_id?}`. |
| `POST /v1/devices/<id>/telemetry` | Identity-bound | Body: a v1 or v2 telemetry report. Malformed input is a Problem Details 400 (a v2 report naming an image outside the device's currently approved set is invalid). 200 `{ok: true}`. |
| `POST /v1/devices/<id>/token-refresh` | Identity-bound (current **or** previous token) | Rotates `catalog_token`. A request presenting the just-rotated previous token replays the same successor rather than rotating again, so a lost response cannot strand the device. Errors use Problem Details; 200 returns `{catalog_token, expires_at, announce_token?, rpc_secret?}` — the last two appear only when the device actually has one, never as an empty string that would overwrite the agent's working value. |

Every POST additionally requires `Content-Length` (a chunked or length-less
body is refused with 411), rejects a non-numeric or negative
`Content-Length` with 400, and caps the body at 64 KiB — after gzip
decompression, so a compressed bomb is still caught — with 413 over. Like
every keyed-state store, a shard the catalog can't read fails the request
closed with a Problem Details 503 rather than answering as if
that device (or the whole store) were empty.

### Tracker API (port 6969)

BitTorrent-standard `GET /announce` and `GET /scrape` return bencoded success
payloads (`Content-Type: text/plain`). The unified IOx/XR image sends
`Authorization: Bearer <announce-token>` as an aria2 per-download option.
Unchanged Guest Shell bundles continue to authenticate with their personalized
query token; the tracker prefers a valid header when both are present. Neither
form is logged or returned in an error, and the new container flow never puts
the credential in torrent metadata, a URL, or argv. Missing/invalid
authentication returns a token-free bencoded 401 before request shape or
resource existence is examined. All tracker errors remain bencoded `failure
reason` dictionaries for BitTorrent-client compatibility; this is the
documented RFC 9457 exception. Current and bounded previous seeder credentials
follow the `IRIS_SEEDER_PREV_TTL` overlap.

| Route | Body / result |
| --- | --- |
| `GET /announce` | Query: `info_hash` (20 raw bytes, percent-encoded), `peer_id`, `port` (1-65535), `left`, `event`, `numwant` (default 50), `compact` (`1` for BEP23 compact peers), and an `ip` override honoured **only** for the service origin-seeder principal and only for a private/CGNAT IPv4 address. A malformed hash is a bencoded 400 after auth. Success is bencoded `{interval, min interval, peers}`; peer policy filters candidates before return. |
| `GET /scrape` | Query: `info_hash`; the same bearer rules apply. A missing/malformed hash is a bencoded 400. Success is bencoded `{"files": {<raw info_hash bytes>: {complete, incomplete, downloaded}}}` (BEP48). |

Every valid, port-bearing announce from a device or service principal durably
records that principal's endpoint (`<state>/peer-endpoints.d/` — see [Keyed
per-device state](#keyed-per-device-state)) before peer selection runs; a
legacy principal's endpoint is never persisted. A durable-write failure never
changes the HTTP 200 — the tuple is queued for retry and the tracker's own
reconciler reports the degrade.

### Telemetry listener (port 9101)

GET-only; no CSRF. `/healthz` and `/readyz` are the only anonymous operations
and disclose only process/listener posture. Metrics uses the documented
monitoring bearer, and swarm state uses the management bearer. See
[Telemetry gating rule](#telemetry-gating-rule) for exactly which environment
variable controls which path.

| Route | Result |
| --- | --- |
| `GET /metrics` | Monitoring bearer. 200 `text/plain; version=0.0.4` Prometheus exposition when `IRIS_OBSERVABILITY` is enabled; Problem Details 404 otherwise. |
| `GET /healthz` | Always 200 `{"ok": true}`. This path proves only that the TLS telemetry process can answer and reveals no exporter or dependency state. |
| `GET /readyz` | TCP-probes the `IRIS_HEALTH_LISTENERS` set (default: tracker, catalog, artifact server, and internal management API). Returns 200 `{"ok": true}` when every probed listener answers, else 503 `{"ok": false}` with `Retry-After`; it never names the failed listener. `IRIS_HEALTH_LISTENERS=off` (or nothing to probe) makes the path inert. This is the server Compose/Kubernetes readiness probe; the Console has independent local probes. |
| `GET /swarm` | Management bearer. 200 JSON `{"images": [{"peers": [...]}, ...]}` for the management API; it is not an operator-public listener. |
| `GET /status` | Management bearer. Detailed listener and OTLP exporter status for the management API; the browser-facing telemetry badge reaches it only through the authenticated Console route. |
| anything else | Auth is checked first, then a Problem Details 404. The old pointer pages moved to the Console. |

### Artifact server (port 8000)

Authenticated static-file GET/HEAD under
`/v1/devices/<device-id>/artifacts/<path>` over `IRIS_ARTIFACTS_DIR`. HTTP Basic
uses the device id as username and that device's current/overlap catalog token
as password. This API is available to explicit HTTPS clients; shipped device
onboarding does not call it because IOS-XE has no safe per-copy channel for
supplying HTTP Basic credentials. The server-side installer instead pushes its
locally generated enrollment files and package over the already authenticated,
host-key-checked device SCP session. The server authenticates and binds an
artifact API credential to `<device-id>` before
decoding/translating the path or testing existence. Directory listing is
disabled, and a resolved path escaping the root through traversal or symlink is
refused.

Guest Shell is deliberately outside the IOx/XR container work and retains its
existing installer unchanged. Its static bootstrap, bundle, certificate, and
`staging/<128-bit-capability>` paths therefore remain available over verified
HTTPS without HTTP Basic. The secret-bearing names are generated per install,
written mode `0600`, redacted from access logs, and swept after one hour. This
is a narrow compatibility exception to the authenticated v1 API; IOx and XR do
not use it.

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
| `quarantined` | `True` once a `mismatch` verdict has quarantined this image. Only `POST /api/v1/images/<id>/release-quarantine` clears it — a later `verified` verdict alone does not. See [Releasing a quarantine](operations.md#releasing-a-quarantine). |
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
devices" — additionally goes through `POST /api/v1/devices/bulk-credential`
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

`POST /api/v1/devices/<id>/assign` (see [Devices](#devices)) writes this file.

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

These are the production environment variables understood by the unified IOx
and IOS-XR appmgr image. Installers supply the required identity fields and the
platform selector; the entrypoint derives storage and runtime behavior from
that selector, validates every value before persisting it, and otherwise uses
the defaults below. None are `server/` Compose variables. Guest Shell is not
part of the unified image and keeps its existing bundle, bootstrap, EEM, and
environment behavior; the two explicitly marked legacy rows below also apply
to it. Cadence behavior is described under [Device agents → Cadence jitter
and overload backoff](device-agents.md#cadence-jitter-and-overload-backoff).

| Variable | Default | Platform | Effect |
| --- | --- | --- | --- |
| `IRIS_DEVICE_PLATFORM` | **required** (`iox` or `xr-appmgr`) | IOx, XR | Selects the storage and runtime profile before any write. New installers pass it; the common entrypoint persists it as `device_platform` for restarts and already-deployed upgrades. Missing, unknown, or conflicting values fail closed. `iox` uses CAF persistent scratch plus live writable-media selection and SSH-to-self; `xr-appmgr` verifies `/hostmount`, fixes the target to `harddisk:`, and rejects SSH/share variables. |
| `IRIS_CATALOG_URL` | **required on first start** | IOx, XR | Reachable HTTPS catalog base URL. An existing persistent config supplies it on later starts. |
| `IRIS_CATALOG_TOKEN` | **required on first start** | IOx, XR | This device's enrollment/catalog credential. It is written only to the mode-0600 persistent config and may subsequently rotate there. |
| `IRIS_DEVICE_ID` | **required on first start** | IOx, XR | Catalog identity. Limited to letters, digits, `.`, `_`, `:`, and `-` before it reaches config or a request path. |
| `CAF_APP_APPDATA_DIR` | **required; supplied by CAF** | IOx only | Application-data directory containing the runtime-delivered `iris-catalog.pem`. The entrypoint derives and validates this trust path before starting either catalog or tracker traffic. XR instead uses the fixed `harddisk:` bind path `/hostmount/iris-catalog.pem`. |
| `IRIS_TELEMETRY` | `on` | IOx, XR | Enables normal device reports. Only the documented boolean spellings are accepted. A redeploy value reconciles an existing persistent config. |
| `IRIS_TELEMETRY_STREAM` | `off` | IOx, XR | Enables live transfer samples when telemetry is on. A redeploy value reconciles an existing persistent config. |
| `IRIS_TICK_SECONDS` | `60` | IOx, XR | Base interval for the common agent loop; integer 1–86400. |
| `IRIS_TICK_JITTER_PCT` | `10` | IOx, XR | Dithers every ordinary tick by ±this percent of `IRIS_TICK_SECONDS`. |
| `IRIS_STARTUP_JITTER` | `1` (on) | IOx, XR | Spreads the first tick after container start across the whole `IRIS_TICK_SECONDS` window. `0` disables it. |
| `IRIS_TICK_BACKOFF_MAX` | `600` (seconds) | IOx, XR, Guest Shell, router | Cap on the exponential backoff applied after a tick's agent process fails outright. |
| `IRIS_TICK_JITTER_MAX` | `8` (seconds) | Guest Shell, router | Bound (0..N-1, uniform) on the per-tick sleep `bootstrap.sh` takes before contacting the catalog. The EEM timer's own 60s period is unaffected — IOS owns that clock. |
| `IRIS_RPC_PORT` | `6800` | IOx, XR | Local aria2 JSON-RPC port; integer 1–65535. It is persisted as `rpc_port`. |
| `IRIS_MAX_PEERS` | `10` | IOx, XR | Per-torrent peer limit; integer 1–1000. It is persisted as `max_peers`. |
| `IRIS_MAX_CONCURRENT` | `100` | IOx, XR | aria2 concurrent-download ceiling; integer 1–1000. |
| `CAF_APP_PERSISTENT_DIR` | `/data` | IOx only | CAF persistent root. The profile stages and keeps its work/config/state under `<root>/iris`; it must be an absolute path without `..`. XR neither reads nor accepts it as a storage selector. |
| `IRIS_TARGET_FS` | unset (auto-detect) | IOx only | Optional IOS filesystem preference such as `sdflash:`. The prefix grammar is checked here and the agent still requires live proof that the filesystem is writable and is not `crashinfo:`. XR rejects the variable and always uses `harddisk:`. |
| `IRIS_SHARE_DIR` | `/mnt/share` | IOx only | Container side of the optional IOx host-data share; absolute path without `..`. If it is not usable, IOx uses SCP. XR rejects it. |
| `IRIS_SHARE_IOS_PATH` | `usbflash1:iox_host_data_share` | IOx only | IOS path corresponding to the IOx share, restricted to a filesystem prefix and safe path components. XR rejects it. |
| `IRIS_DEVICE_SSH_HOST` | **required on first start** | IOx only | IOS SSH-to-self address used for read-only discovery and staged-file placement. XR rejects every `IRIS_DEVICE_SSH_*` variable. |
| `IRIS_DEVICE_SSH_USER` / `IRIS_DEVICE_SSH_PASS` | **required on first start** | IOx only | Scoped IOS transport credential persisted in the owner-only config. Values are rejected if they could create another config line; the user and host have tighter identifier grammars. |
| `IRIS_DEVICE_SSH_ENABLE` | SSH password | IOx only | Optional enable secret for platforms that require it. It is data sent to the existing CLI transport, never shell syntax. |
| `IRIS_DEVICE_SSH_PORT` | `22` | IOx only | SSH-to-self port; integer 1–65535. |
| `IRIS_DEVICE_SSH_KNOWN_HOSTS` | unset | IOx only | Optional absolute `known_hosts` path; enables strict host-key verification. |
| `IRIS_MODEL` / `IRIS_VERSION` | unset | XR only | Optional observed device metadata persisted as `device_model` / `device_version`. XR has no SSH discovery path. |
| `IRIS_LOG` | `off` | IOx, XR, Guest Shell | Device-side `aria2c.log` opt-in — see [Device agents → Device-side logging (flash write endurance)](device-agents.md#device-side-logging-flash-write-endurance). **Off by default**: flash has finite write endurance, and aria2c's own log is chatty and continuous for the whole life of a transfer. `on`/`1`/`true`/`yes` (case-insensitive) enables it; anything else, including unset, stays off. `device/xr-install.sh` and `device/iox/install.sh` forward an operator's setting verbatim (`--env IRIS_LOG=…` in `docker-run-opts`, `run-opts N "-e IRIS_LOG=…"`) — before this plumbing existed neither installer passed it at all, so the opt-in was unreachable on exactly the two platforms whose entrypoints implement it. On IOx/XR the launch line adds `--log=<STAGE_DIR or WORK_DIR>/aria2c.log --log-max-size=50M --log-max-files=1`; Guest Shell adds `--log=<STAGE_DIR>/aria2c.log` and relies on the existing `rotate-logs.sh`/EEM cadence to trim it. On Guest Shell, set `iris_log` in `iris-agent.conf` instead — see [Device agent config keys](#device-agent-config-keys) below; `bootstrap.sh` reads it (and `rpc_port`/`max_peers`, which had the identical gap) from that persisted file and exports it before every `guestshell-start.sh` launch, so it survives an EEM tick and a reboot without a reinstall. **`IRIS_LOG` governs only that one file — the `aria2c.log` transfer log** — never the `%IRIS-6-<MNEMONIC>` operator lines `emit()` writes on every platform, which `IRIS_LOG` never touches either way: real IOS syslog (`send log`) on Guest Shell and IOx, or the XR container's stdout on IOS-XR, captured into the container log appmgr keeps (`show appmgr application name iris logs`) — that stdout capture happens **regardless of `IRIS_LOG`**, so "off" does not mean zero recurring write on XR, only that `aria2c.log` itself stops growing; see the container-log bound below. The heartbeat's `stage_error` field is unaffected on every platform either way. |
| `IRIS_LOG` (XR container-log bound) | — | XR | `device/xr-install.sh`'s `docker-run-opts` always adds `--log-driver json-file --log-opt max-size=1m --log-opt max-file=3` — independent of `IRIS_LOG` and not configurable per device. This bounds (not eliminates) the one recurring write `IRIS_LOG=off` cannot stop on XR: appmgr's capture of `emit()`'s `%IRIS-6-<MNEMONIC>` stdout lines, roughly one per 60s tick. 3&nbsp;MiB total, rotated, retains roughly 11 days of that history at the emit rate above — comfortably past a long weekend — for about 0.08% of the ~3.9&nbsp;GB `/misc/app_host` partition XR's container logs live on. Deliberately never `--log-driver=none`: XR has no syslog path for `%IRIS` lines (see the deviation note in `device/agent/xr_deps.py`), so `none` would silently discard every device diagnostic, including pre-heartbeat startup failures, with no second channel. |

There is no production `IRIS_CATALOG_CA` override: IOx trust must come from CAF
application data and XR trust from the verified harddisk bind mount. A package
cannot redirect either path or supply a built-in fallback.

`IRIS_RUNTIME_MODE` is retired and is not an alias for the selector. Production
containers also reject `IRIS_STAGE_DIR`, `IRIS_WORK_DIR`, `IRIS_AGENT_CONF`,
`IRIS_AGENT_STATE`, and `IRIS_CATALOG_CA`; those overrides, plus
`IRIS_CONTAINER_TESTING=1`/`IRIS_TEST_SKIP_MOUNT_CHECK=1`, exist only for the
source-level test harness. This prevents a deployment from redirecting a
multi-gigabyte stage away from the selected platform's storage policy.

## Device agent config keys

The agent reads `key = value` lines from
`/flash/guest-share/iris/iris-agent.conf` (override with `IRIS_AGENT_CONF`).

| Key | Default | Effect |
| --- | --- | --- |
| `device_platform` | **required in a device container** | Persisted copy of `IRIS_DEVICE_PLATFORM`, limited to `iox` or `xr-appmgr`. It is read before storage paths are chosen; it is not inferred from directory existence. Guest Shell does not use this container selector. |
| `catalog_ca` | Platform-derived runtime path | Certificate used for catalog calls and HTTPS tracker announces. Guest Shell uses the certificate copied during its artifact flow; IOx uses CAF application data; XR uses `/hostmount/iris-catalog.pem`. The container entrypoint reconciles this fact on every start and refuses a missing or invalid certificate. |
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
