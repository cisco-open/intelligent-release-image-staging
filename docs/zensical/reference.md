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
| `tools/start-compose-server.sh` | The complete first start: list every missing hand-in up front, grant uid 10001 `artifacts/`, build, bootstrap, install the two public instruction roots from `IRIS_INSTRUCTION_ROOTS_DIR`, start, and stage the Guest Shell bundle, both IOx packages and the XR RPM (`IRIS_SKIP_XR=1` to omit). It never creates roots. |
| `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<image>.bin` | Publish an image into the catalog and seeder. In place: the image is seeded from its own directory and nothing is copied. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign` | Show images and assignments. |
| `docker compose -f server/docker-compose.yml exec iris iris-assign <device> <image> [<image> ...]` | Merge one or more images into the device's ordered assignment. Use `iris-assign --replace <device> <image> [<image> ...]` to replace and intentionally narrow it. |
| `tools/gen-device-installers.sh fleet/devices.csv` | Generate per-device installers. |
| `tools/apply-assignments.sh fleet/assignments.csv` | Validate and apply assignment CSV. |
| `tools/make-agent-bundle.sh` | Build the x86_64 Guest Shell bundle; `--arch arm64 --aria2 PATH` builds the ARM bundle from a verified aarch64 binary. |
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

The server Compose service requires these; none has a default. The standalone
Console has its own [deployment variables](docker-hosts.md#deployment-settings).

| Variable | Effect |
| --- | --- |
| `IRIS_HOST_IP` | Server address reached by devices; the default one-host Compose stack also binds the Console port here. The generated catalog certificate includes it at first start. An address change requires updating TLS trust, the origin seeder's tracker URL, existing torrent announce URLs, and deployed agent configuration. Preserve the config and state volumes, update the address-dependent material, and re-onboard affected devices. See [TLS rotation and device packages](operations.md#tls-rotation-and-device-packages). |
| `IRIS_AGE_RECIPIENTS` | Comma-separated age public keys the at-rest secret store is encrypted to: the primary key plus an offline break-glass recipient. |
| `IRIS_AGE_KEY_FILE_HOST` | Host path of the age identity (private key), mounted as the Docker secret `iris_age_key` at `/run/secrets/iris_age_key`. |

!!! important "How a variable reaches the container"
    Compose injects **only** the keys named in the `environment:` block of
    the selected Compose files. Exporting a variable in your shell, or adding a
    line to `server/.env`, sets it for *interpolation* — Compose substitutes it
    into `"${VAR:-…}"` on the right-hand side of that block, and a variable the
    block never names is silently dropped. Use `server/.env`, an explicit
    `--env-file`, or an `export` for interpolation. Host paths and published
    ports are consumed by Compose itself; runtime variables must be named in
    the service's `environment:` block. A variable added to the code — an internal tuning
    value, or one added to the code later — needs a line added to the
    `environment:` block before it has any effect.

    Kubernetes differs: `kubernetes/kustomization.yaml` generates the ConfigMap
    from `kubernetes/iris-seed-server.env` and the pod pulls it with `envFrom`,
    so any key in that file reaches the process without a manifest change.

### Optional at deploy time

| Variable | Default | Effect |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `server` (the `name:` in `server/docker-compose.yml`) | Compose project name, and therefore the prefix on the named volumes (`server_iris-state`, `server_iris-config`, `server_iris-images`, `server_iris-tier-auth`, and `server_iris-management-ca`). Host-side only: read by Compose itself, never passed into the container. Set it to give a second checkout on the same host its own volumes — see [Server](server.md#compose-project-name). |
| `IRIS_CONTAINER` | `iris` | Name of the server container: Compose applies it as `container_name`, and `tools/apply-assignments.sh`, `tools/stage-iox-package.sh`, `tools/gen-device-installers.sh`, and `tools/check-package-freshness.sh` address that name. Host-side only. Container names are host-global, so a second stack needs this as well as `COMPOSE_PROJECT_NAME`. `tools/start-compose-server.sh` resolves the container from its own Compose project when this is unset. |
| `IRIS_CONSOLE_CONTAINER` | `iris-console` | Name of the state-free Console container. Host-side only; a second stack needs a distinct value because container names are host-global. |
| `IRIS_OBSERVABILITY_TOKEN_FILE_HOST` | `/dev/null` | Host path of the raw, observability-scoped bearer token mounted read-only into the server. Required when `IRIS_OBSERVABILITY=1` and `/metrics` will be scraped; keep it mode 600 and give the identical raw value to the scraper's `credentials_file`. Host-side only. |
| `IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST` | `/dev/null` | Optional previous observability token during a bounded rotation overlap. Remove it after every scraper has moved to the new current token. Host-side only. |
| `IRIS_OTLP_HEADERS_FILE_HOST` | `/dev/null` | Host path of an optional mode-600 file containing the collector authentication header specification. Compose mounts it only into the server tier at the fixed path named by `IRIS_OTLP_HEADERS_FILE`; host-side only. Prefer this to putting collector credentials in `server/.env`. |
| `IRIS_ARTIFACTS_HOST_DIR` | `../artifacts` | Host directory bind-mounted read-write at `/srv/artifacts`. Host-side only: it is interpolated into the bind mount, not passed into the container. |
| `IRIS_SHARP_SANS_FONT_HOST` | `/dev/null` | Host path of the licensed Sharp Sans Bold `.woff2`, bind-mounted read-only over `server/webroot/fonts/SharpSans-Bold.woff2` inside the container. The font is excluded from the build context (`.dockerignore`) and the release tarball — Cisco's license does not permit redistributing it — so the console falls back to its default font stack without it (`font-display: swap`). Set this only on a deployment that independently holds the license; left unset it mounts `/dev/null`, a harmless no-op every other deployment never has to think about. Host-side only: interpolated into the bind mount, never passed into the container. See [Console](console.md#branding). |
| `IRIS_GUI_PUBLISH` | `8080` | Published Console host port. The one-host Compose stack binds it to `IRIS_HOST_IP`; the standalone Console binds it to `IRIS_CONSOLE_BIND_IP`. The container always listens on 8080 internally. |
| `IRIS_CONSOLE_URL` | unset | Full external HTTPS Console URL reported in server settings, for example `https://console.example.com:8080`. An explicit URL takes precedence over `IRIS_GUI_PUBLISH`; it does not change Docker's port binding. |
| `IRIS_GUI_ALLOW_PLAINTEXT` | unset | `1` makes the Console deliberately skip its TLS identity and serve plain HTTP. Without it the Console obtains its active identity through the authenticated management hop or uses its independently mounted default and refuses to start when no usable identity exists. The session cookie loses its `Secure` attribute under the opt-in. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_CATALOG_ALLOW_PLAINTEXT` | unset | `1` lets the catalog serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `catalog.py` refuses to start in that state — every route answers a device bearer token. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped `docker-entrypoint.sh` always provisions `IRIS_CERT`, so this only matters running `catalog.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_ARTIFACTS_ALLOW_PLAINTEXT` | unset | `1` lets the artifact server serve plain HTTP when `IRIS_CERT` names no usable certificate. Without it `artifact_server.py` refuses to start: the authenticated v1 API carries resource-bound credentials, while Guest Shell enrollment relies on TLS to protect short-lived capability paths. Same convention as `IRIS_GUI_ALLOW_PLAINTEXT`. The shipped entrypoint always provisions `IRIS_CERT`, so this only matters running `artifact_server.py` directly. Loopback or an isolated lab only — see [Security](security.md#tls-and-certificates). |
| `IRIS_VERSION` | unset | Build argument that bakes the release string the console's Settings page shows. Unset means the `VERSION` file in the image. Build-time only: it is not a container variable. |
| `IRIS_GUI_ADMIN_PASSWORD` | unset (prompts) | Read by `iris-gui-admin` to set the console admin password non-interactively. Pass it on the one-shot command (`docker compose … run --rm -e IRIS_GUI_ADMIN_PASSWORD=… iris iris-gui-admin`); it is deliberately **not** in the Compose `environment:` block, so a long-running container never holds the password in its environment. |
| `IRIS_SAMPLE_INTERVAL` | `15` (seconds) | Seeder/telemetry poll cadence. A transfer that completes inside one interval can be observed with no connected peer, so per-peer rates and the map's measured edges never appear — a 1 GB image at ~90 MB/s lands in about 15 seconds. Lower it to 2–5 on a fast fabric or for a live demo; the cost is more aria2 RPC calls. |
| `IRIS_TRACKER_PORT` | `6969` | Port the tracker listens on. The canonical (seeder) announce, per-device personalized announces and the rotation CLI all derive their announce base from `IRIS_HOST_IP` and this port, so changing it needs the compose port mapping changed to match. |
| `IRIS_TRACKER_ANNOUNCE` | unset | Full HTTPS announce base (`https://host:port/announce`, no credentials, query, or fragment) used in place of the `IRIS_HOST_IP` + `IRIS_TRACKER_PORT` derivation by every path that builds an announce URL. Plain HTTP and malformed overrides fail closed. |
| `IRIS_REQUIRE_IDENTITY_GATE` | unset (off) | Set to `1` to make the catalog answer 503 to every per-device torrent request until the checkpoint file `identity-compatible-ready` exists under `IRIS_STATE` — the file a proven seeder rotation writes and `--recover` removes. Read per request, so opening or closing the gate needs no restart. The canonical (service) torrent path is unaffected. Without the gate, approved devices can request their torrents immediately. |
| `IRIS_ONBOARD_CONCURRENCY` | `25` | Maximum onboard/undeploy jobs the worker pool runs at once; the rest queue. `GET /api/v1/onboard/jobs` reports the active value as `max_concurrent`. |
| `IRIS_XR_SESSION_TIMEOUT` | `150` seconds | Wall-clock bound for each IOS-XR command session. `0` disables it; an invalid value falls back to the default with a warning. |
| `IRIS_CONTAINER_TESTING` / `IRIS_TEST_SKIP_MOUNT_CHECK` | unset | **Test-only escape hatches — never set these on a device.** The common entrypoint accepts temporary path overrides only with the first set to `1`; the XR mount check is skipped only when both are `1`. Production `xr-appmgr` refuses to start unless `/hostmount` is a real bind mount, so it cannot report a stage to `harddisk:` while writing into its disposable rootfs. |
| `IRIS_DEVICE_ENABLE_ALWAYS` | unset (off) | For devices that require enable at login: each agent process starts by sending `enable` plus its secret on IOS-XE SSH sessions, and drops the pair for the rest of that process once a session's own prompt shows the login was already privileged (`#`). Normally IRIS learns whether escalation is needed from the device prompt and sends neither line to already-privileged logins. |
| `IRIS_ONBOARD_JOB_TIMEOUT` | `7200` seconds | Wall-clock deadline for one onboard/undeploy job, measured from the moment it starts **running** (never from when it was queued). A running job past the deadline is stopped like an operator abort. |
| `IRIS_ONBOARD_REAP_GRACE` | `60` seconds | Grace between the `SIGTERM` sent to a deadline-expired installer's process group and the `SIGKILL` that follows. |
| `IRIS_SEEDER_PREV_TTL` | `2592000` seconds (30 days) | How long a rotated-out seeder announce token keeps working, measured from the rotation that retired it — the overlap that lets a device which missed the rotation keep announcing while its torrent is re-personalised. Past it the tracker refuses the old token like any other expired credential, and the next rotation drops the record. Set it once, for the whole deployment: every process computes the deadline from this value, so a per-process override would make the same credential expire at different times. `0` means no overlap at all — the previous token is dead the moment it is rotated out — and a value that is not an integer raises at startup rather than falling back. See [Security](security.md#rotating-the-seeder-announce-credential). |
| `IRIS_HTTP_TIMEOUT` | `30` seconds | Per-connection socket timeout for the tracker and catalog request handlers: a connection that stalls mid-request is closed instead of pinning a thread. A non-numeric or non-positive value falls back to the default. |
| `IRIS_ENDPOINT_TTL` | `900` seconds | Freshness window for a device's durable peer endpoint in the endpoint map (`peer-endpoints.d/`). A missing, non-integer or non-positive value falls back to the default (a TTL of 0 would make every row stale and apply an empty blocklist under an `enforced` status). Endpoint rows for quarantined or revoked devices are retained regardless — see [Operations](operations.md#peer-policy-operations-and-their-backlog). |
| `IRIS_ENROLL_TTL` | `3600` seconds | Lifetime of the one-shot enrollment token minted into a per-device installer, overriding the standard catalog-token TTL for that first exchange only. |
| `IRIS_HEALTH_LISTENERS` | `tracker:6969,catalog:8443,artifacts:8000,management:9443` | What the server tier's `:9101/readyz` TCP-probes, as `name:port,name:port`. Console readiness is local to its own `/readyz`; the server does not depend on it. Blank keeps the default set; the literal `off` checks nothing, for a deployment that runs a subset of the services and does not want the missing ones reported down. |
| `IRIS_AUDIT_RETENTION_DAYS` | `90` days | Audit entries older than this are dropped by timestamp on the next amortized prune. A non-integer or non-positive value falls back to the default. |
| `IRIS_AUDIT_MAX_EVENTS` | `50000` | Hard cap on surviving audit entries. A prune above the cap evicts the **oldest by file position** (append order), so a forged far-future timestamp cannot shield an entry and a wrong clock cannot mass-delete fresh ones. A non-integer or non-positive value falls back to the default. Raise both of these if you have a longer retention obligation — the trail is append-only JSONL and prunes itself. |
| `SEED_MAX_CONCURRENT` | `1000` | `--max-concurrent-downloads` for the origin seeder's aria2c. See [Operations](operations.md#scaling-notes) for when this matters; device concurrency is signed/default `max_concurrent`; legacy launcher inputs have no enduring policy authority. |
| `IRIS_SSH_LEGACY` | `0` | `1` re-enables SHA-1 KEX, `ssh-rsa` and CBC ciphers for server-side device sessions, for IOS-XE images that offer no modern alternative. |
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
`IRIS_ONBOARD_CONCURRENCY` and `IRIS_ENROLL_TTL`, which is
why `server/docker-compose.yml` restates their defaults instead of passing an
empty string through. Set a real value or leave the variable unset; do not set
one to the empty string. The telemetry process treats an empty
`IRIS_METRICS_PORT` as disabled; Compose replaces an empty value with `9101`.

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

Onboarding reads the public device certificate from `$IRIS_CONFIG/tls/crt.pem`,
unless `IRIS_CRT_PUBLIC` selects another public certificate file. The server's
`IRIS_LOG` names its log directory. It is kept out of device installer options;
the device-side `IRIS_LOG` switch controls aria2 logging separately.

### TLS trust and console certificate

The browser Console's *Settings → TLS & trust* sub-page manages these through
the management API. The durable certificate and trust state belongs to the
server tier; the state-free Console owns only its active runtime TLS copy.
For an independently deployed Docker Console, the default browser certificate
and key are mounted on that host. See
[Docker on separate hosts](docker-hosts.md#certificates-and-trust).

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_GUI_CERT` | Server: `/run/iris/tls/gui-cert.pem`; Compose Console: `/run/iris-console/cert.pem` | The server rebuilds an installed custom identity in its tmpfs. The Console fetches custom identities and the single-host fallback through the authenticated management API; independently mounted defaults are copied locally. It atomically writes the active pair into its own tmpfs. The catalog/device private key is never mounted into or sent to the Console. |
| `IRIS_TRUST_DIR` | `/etc/iris/tls/trust` | Durable directory of installed root-CA PEMs: one `<sha256-fingerprint>.pem` per manual install, plus the downloaded public bundle as the distinguished file `downloaded-bundle.pem`. |
| `IRIS_CA_BUNDLE` | `/run/iris/tls/ca-bundle.pem` | Runtime concatenation of the trust dir, rebuilt at every boot and on every trust change. Absent while the trust dir is empty. Outbound TLS (OTLP export, the CA-bundle download) verifies against the system store plus this bundle. |

The server-owned console certificate override persists as
`/etc/iris/tls/gui-crt.pem` (plaintext certificate, leaf or fullchain) plus
`/etc/iris/tls/gui-key.pem.age` (private key, age-encrypted to the same
recipients as the rest of the secret store); boot rebuilds `IRIS_GUI_CERT`
from the pair. An override that fails to decrypt — or whose certificate and key
do not form a matching pair — is skipped with a warning. The Console then uses
the deployment's valid default identity.

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
| `IRIS_OTLP_ENDPOINT` | unset | OTLP/HTTP base endpoint of your collector, e.g. `https://collector.example.com:4318`. Deployment default only — the console's *Settings → Telemetry* sub-page can override it at runtime. See [Splunk setup](splunk.md) for HTTPS collector configuration. |
| `IRIS_METRICS_PORT` | `9101` | Port for the telemetry listener. Keep `9101` in the shipped deployment: its healthcheck and Console startup depend on this listener. `0` disables it, as does an empty value in a directly launched process; Compose substitutes `9101` for an empty value. Disabling or moving it requires corresponding healthcheck, port-mapping, and swarm-URL changes. Control exports with `IRIS_OBSERVABILITY` and the OTLP settings instead. |
| `IRIS_METRICS_HOST` | `0.0.0.0` | Bind host for the TLS telemetry listener. Bind it to `127.0.0.1` when no external Prometheus scraper consumes it. |
| `IRIS_SWARM_URL` | `https://127.0.0.1:9101/swarm` | Where the state-owning management process fetches swarm state. The request uses the file-mounted management bearer and verifies the catalog CA; this is not a browser-facing URL. |
| `IRIS_OTLP_HEADERS` | unset | Comma-separated `Name=Value` headers attached to every OTLP POST (collector authentication). Values are secrets: never logged, never echoed in errors, and the exporters refuse HTTP redirects so they cannot leak to a redirect target. |
| `IRIS_OTLP_HEADERS_FILE` | `/run/secrets/iris_otlp_headers` (Compose) | Read the header spec from a file instead of the environment. Compose fixes this container path and obtains the host path from `IRIS_OTLP_HEADERS_FILE_HOST`; Kubernetes mounts its optional `iris-otlp-headers` Secret here. `IRIS_OTLP_HEADERS` wins when both are set. |

#### Telemetry gating rule

* Prometheus `/metrics` is served only while `IRIS_OBSERVABILITY` is enabled; otherwise an authenticated request answers 404. A missing or invalid monitoring bearer still returns 401.
* OTLP export requires **both** an effective enabled flag **and** an effective endpoint. Each field is the console override from `$IRIS_STATE/telemetry-destination.json` when set, else the deployment env (`IRIS_OBSERVABILITY` / `IRIS_OTLP_ENDPOINT`). An endpoint on its own is inert — nothing is exported.
* `/healthz` and `/readyz` are served whenever the listener runs, regardless of either variable, and disclose only `{"ok": true|false}`. `/healthz` answers 200 unconditionally and proves only that the telemetry listener is alive; `/readyz` TCP-probes the tracker, catalog, artifact server, and management API and communicates dependency failure through status 503 plus `Retry-After`, without naming the failed listener. It is what the Compose `HEALTHCHECK` and Kubernetes probes use; `IRIS_HEALTH_LISTENERS` narrows or disables its probe set.
* `/swarm` always requires the file-mounted management bearer. The management process reads it over pinned loopback TLS, so port 9101 needs external reachability only for authenticated Prometheus scraping or operator tools — never for the Console.

`IRIS_OBSERVABILITY` controls Prometheus `/metrics` at startup and requires a
restart to change. The OTLP destination is re-read on every sample pass: the console's
*Settings → Telemetry* stores a per-field override in
`$IRIS_STATE/telemetry-destination.json` (`endpoint`, `enabled`; a `null`
field inherits the env), applied within seconds without a restart. *Revert to
deployment default* deletes the file, restoring exact env behavior. The
startup log states which posture is in effect at boot.

!!! note "Prometheus and OTLP have separate controls"
    Without `IRIS_OBSERVABILITY`, an authenticated Prometheus scrape receives
    404 and the target reads down. Enable it and restart the server if you
    want those metrics. OTLP can still export through the Console's runtime
    endpoint and enabled override, so a down scrape target does not establish
    whether OTLP is running. Check the Console's Telemetry export status.

## Console API

The checked-in [OpenAPI 3.2 contract](openapi.yaml) describes the Console,
management, catalog, tracker, telemetry, and artifact operations. It is generated
from `server/openapi_contract.py`, validated against OpenAPI 3.2, and checked
against the runtime route registry. Job streams describe each parsed SSE event;
image, artifact and torrent bodies are raw bytes. The API paths remain versioned
as `/api/v1`, `/internal/v1`, and `/v1`.
This section explains the operator-facing behavior.

The browser calls `/api/v1` on the Console container's HTTPS listener, normally
port 8080. The Console proxies registered operations to `/internal/v1` on the
server's internal management listener at port 9443. The server owns the
inventory, images, credentials, jobs, and audit records; the Console has no
mounts for that state. Use the Console API for operator integrations.
Breaking changes require a
new major base path. Before removing a published major, IRIS will retain it for
at least two dated releases, return `Deprecation`, `Sunset`, and successor
`Link` headers, and announce the removal in the changelog. There are no public unversioned API aliases.

Every `/api/v1` route requires an authenticated console session cookie except two
authentication-establishment routes: `POST /api/v1/login` and
`POST /api/v1/setup`. State-changing methods
on the authenticated routes additionally require the session's CSRF token in an
`X-CSRF-Token` header; without it the request is rejected with
403. The two pre-auth routes carry no CSRF token, because there is no session
yet. JSON request bodies are capped at 64 KiB, except bulk credential assignment
at 2 MiB. CSV import accepts up to 8 MiB, streamed image upload 4 GiB, and offline
Bulk Hash feed upload 256 MiB.

Registered JSON API errors use RFC 9457 Problem Details with
`Content-Type: application/problem+json`: `type` and `code` are stable,
documented identifiers in the [Problem type registry](problems.md), and
`detail` is redacted. Paths, credentials, exception
text, and resource existence before authentication are never exposed. The
BitTorrent tracker deliberately keeps BEP-compatible bencoded failures because
that wire protocol's clients do not consume Problem Details; the OpenAPI entry
marks that error-format exception. Guest Shell enrollment files use
TLS-protected capability paths outside the v1 API.
Successful downloads retain their static-file response semantics; errors use
Problem Details. Probe success bodies and BitTorrent success bodies retain
their protocol-native formats.

Status codes, pagination, concurrency, and retry guarantees are operation
specific and enumerated in the OpenAPI contract. In particular, fleet and
swarm projections retain their established `limit`/`offset` response shapes;
peer policy publishes a strong `ETag` and accepts `If-Match` or the body
field `if_revision`; device assignment uses its
domain-specific `expect_image_ids` compare-and-set form. Only operations that
explicitly advertise `Idempotency-Key` keep a bounded, process-local 24-hour
successful-response replay. Reusing a key with a different body is 409. A
server restart clears the replay ledger and in-memory jobs. Inspect the
catalog, deployment records, and persisted deployment logs before retrying
an operation whose response was lost.

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
| `GET /api/v1/settings` | Server address, full Console URL (`console_url`), published Console port, and running version — plus the certificate this Console serves (`gui_cert`), installed trust entries (`trust`), CA download settings (`ca_trust`), effective telemetry destination with its source (`telemetry_destination`), and audit-export destination with its last-run status (`audit_export`; a `password_set` flag only, never the password). |
| `GET /api/v1/settings/setup-status` | The setup status behind the first-run wizard (`#setup`), Settings → Setup, and the persistent Settings → Device packages view: `admin`, `telemetry`, `packages`, and `image_verification`, each with a `state` of `ok`, `unset`, `stale`, `absent`, or `unknown`. `telemetry` is `ok` only when export is enabled *and* an endpoint resolves, and also carries `source` (`override` or `env`), `endpoint`, and `enabled`. `packages.items` covers the two IOx tars and `iris-xr.rpm`; each item reports artifact modification time (`built_at`, not an attested build time), state/reason, its wrapper-specific remedy, and canonical OCI provenance only after the served wrapper SHA-256 matches the adjacent manifest. An `ok` item does not claim package-content or native-signature inspection. The aggregate package state separately fails closed when the live served certificate or distributed `iris-catalog.pem` is unavailable or the two disagree; `reference_fingerprint` identifies the live certificate. Certificates are never compared with package build time or contents. See [Setup](console.md#setup). |
| `POST /api/v1/settings/password` | `{current, new, confirm}`; changes the admin password and revokes every other session. |
| `POST /api/v1/settings/sessions/revoke-others` | Revokes every session except the caller's. |
| `POST /api/v1/settings/gui-cert` | `{cert_pem, key_pem}` — validates the certificate/key pair and stores the Console override encrypted on the server. Returns `{gui_cert, applied, note}` after the Console attempts to load it. `applied: false` means the saved identity did not reach this Console's TLS listener; follow the note and restart the Console when needed. |
| `DELETE /api/v1/settings/gui-cert` | Removes the override and loads the deployment's default Console certificate. The result reports whether this Console applied it; restart the Console if the response reports a reload failure. |
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
| `GET /api/v1/images/jobs/<job_id>` | Publish job state: `publishing`, then `verifying` during the Cisco Bulk Hash check, then `done`; `error` means publishing failed. A `done` job may still report a verification failure or a mismatched image, so read `verification.outcome`, `verification.image_state`, and `message`. Shared by upload and import; jobs are held in memory and disappear after a server restart. |
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
| `GET /api/v1/devices` | `{devices: [...], now, total, offset, limit, revision}`. Optional `limit` (1–1000, larger values clamped) and `offset` (≥ 0) page results sorted by `device_id`; malformed values, non-positive limits, and negative offsets return 400. Without a limit, `limit` is `null` and all matching rows from the offset onward are returned. Filters apply before paging, so `total` is the filtered count. Compare `revision` across pages and restart the read if inventory changed. See the filter table below. |
| `POST /api/v1/devices` | Creates or updates one inventory row; returns `{device: ...}`. The JSON field set is closed: unknown fields and server-owned `schema_version`, `registered_at`, `registration_id`, and `os_family` return 422 without changing inventory or role policy. Historical `vlan` and `guest_ip` aliases are accepted through legacy CSV import only. |
| `DELETE /api/v1/devices/<id>` | Retires the device: revokes its credentials first, then clears peer-policy assignment, inventory row, and catalog state. `{deleted: <bool>, degraded: [...]}` — 200 when cleanup was complete, 207 when part of it failed (`degraded` names the areas), 500 `{deleted: false, error: "secret revoke failed"}` when the revoke could not be persisted, in which case nothing was changed. Endpoint rows are retained until they age out. See [Retiring a device](operations.md#retiring-a-device). |
| `GET /api/v1/devices/export-csv`, `GET /api/v1/devices/example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/v1/devices/import-csv` | Bulk inventory import (8 MiB cap, all-or-nothing); returns per-row stats. |
| `GET /api/v1/install-options?model=<model>` | `{options: [...]}` gives the model-based installer restriction; `options: null` means the model is blank or unclassified. The Console also restricts installer choices by the selected management type. Management type alone controls the network fields; changing model does not change it. Model accepts free text, but saving a value does not confirm hardware support. |
| `GET /api/v1/devices/<id>/plan` | `{plan}` — the resolved deployment plan; 409 when it cannot resolve. |
| `GET /api/v1/devices/<id>/reports` | `{reports: [...]}` — the device's stored telemetry ring. |
| `GET /api/v1/devices/<id>/deployment` | `{record, total}` — the deployment record that best describes the device (the active one, else the teardown-authorizing one, else the newest) plus the stored-record count; `record` is `null` when none exists. Read-only — feeds the deployment-details panel. |
| `POST /api/v1/devices/<id>/assign` | `{image_ids: [...]}` replaces the ordered approved set, up to ten images; an empty array unassigns all. `{image_id: <id>}` selects one image, and `{image_id: null}` unassigns all. Optional `expect_image_ids` compares against the stored set and returns 409 with `assigned_image_ids` if it changed. Success returns `{ok, assigned_image_ids, removed_image_ids}` from the committed transaction. An id absent from fleet inventory returns 422 and creates no policy or transfer plan. More than ten ids, duplicates, unknown image ids, and quarantined images return 400. Assignment approves staging only. See [Policy schema](#policy-schema) and [Image verification](#image-verification). |
| `POST /api/v1/devices/<id>/credential`, `.../platform` | Sets the credential profile, or the platform (Agent install choice) and storage target; each returns `{ok: true}`. |
| `POST /api/v1/devices/bulk-credential` | `{device_ids: [...], credential_profile_id: <id or "">}` sets ONE credential profile on every listed device in a single call — the bulk form of the route above, backing the console's "Select all *N* matching devices" bulk credential action. 400 for a non-array/empty `device_ids`, one over the supported fleet size, or an unknown `credential_profile_id`. Not all-or-nothing: returns `{ok: true, applied: <count>, failed: {<device_id>: <reason>, ...}}`, naming exactly which selected ids (e.g. one deleted out from under a stale selection) did not apply, while every other id still does. Audited once as `device_credential_bulk_change`, not once per device. |
| `POST /api/v1/devices/<id>/forget-host-key` | Removes the device's entry from the persistent SSH known_hosts accept-new mode records into (`lab/iris-ssh-policy.sh`) — for a device that was re-imaged or replaced and now fails every session with a changed-key error. `{ok: true, peer: <device_ip>}` on success, including when nothing was recorded (already effectively forgotten). 400 `{error: ...}` when the device has no `device_ip` on record or the removal itself fails. Audited as `device_forget_host_key` (device id, actor, and the peer address). Only the persistent accept-new file is touched — an `IRIS_SSH_HOST_KEY` pin or an operator-supplied `IRIS_SSH_KNOWN_HOSTS` file is untouched. The next session re-verifies and pins the device's new key; this never disables verification. See [Operations → Forgetting a device's SSH host key](operations.md#forgetting-a-devices-ssh-host-key). |
| `POST /api/v1/devices/<id>/request-report` | Requests a fresh telemetry report; `{ok: true, expires_at}`, or 429 while one is already pending. |
| `POST /api/v1/devices/<id>/adopt` | Requires `{"acknowledge_adopt": true}`; returns `{record_id}`. 409 when the device already has an active deployment record; routers cannot be adopted. |
| `POST /api/v1/devices/<id>/onboard`, `POST /api/v1/devices/<id>/undeploy` | Starts the job; `{job_id}`. 409 when the device is busy with the opposite action. Undeploy also answers 409 when the device has no deployment record — send `{"force": true}` to run it anyway, which removes only the IRIS-named agent footprint and leaves operator-owned network state (VLAN/SVI, VirtualPortGroup, NAT) untouched, audited as `undeploy_forced`. A `503` naming an unreadable `deployment_records.json` is a different answer: the records cannot be read at all, so whether this device has a deployment is unknown — repair the file rather than adopting the device. |

Router deployments carry extra preflight and ownership rules — see
[Management Type and VLAN Ownership](management-type.md#router-preflight-and-ownership).

Device list filters can be combined:

| Parameter | Values |
| --- | --- |
| `q` | Case-insensitive substring in device id, IP, configured model, or heartbeat model. |
| `management_type` | `routed`, `inband`, `router-routed`, `router-nat`, `xr-host`, or `legacy` for a row with no classified management type. |
| `platform` | Agent installer choice; `__none` selects an unset choice. |
| `cred` | Credential profile id; `__none` selects devices with no profile. |
| `telemetry` | `on`, `off`, or `unknown` when the device has not reported its posture. |
| `peer` | `quarantined` or `not-quarantined`. |
| `role` | Exact declared role name; `__none` selects a row with no declared role. |
| `status` | `onboarding`, `undeploying`, `waiting-heartbeat`, `waiting-staging`, `onboard-failed`, `undeploy-failed`, `deployed`, `placement-failed`, `image-failed`, `copying`, `staging`, `unassigned`, `enrolled`, `not-enrolled`, `offline`, or `__attention`. |

`offline` selects heartbeats at least 600 seconds old; `__attention` selects
negative, severe, or warning status levels. Unknown filter values match no rows.

The `status` filter uses stable API keys. `deployed` displays as **Staged**;
`placement-failed` displays as **Staging failed** and covers download,
verification, and placement errors. `waiting-staging` means images are
assigned but the latest heartbeat is idle or ready for an older assignment.
Current per-image errors override older staged flags. A finished onboard job
first shows `waiting-heartbeat`, then follows the agent's reported status.

### Peer policy

Role and QoS writes share the peer-policy revision. Read the current ETag first,
send that exact strong value in `If-Match`, preview with `dry_run=1`, and send
the preview's `confirm_token` with the identical candidate. The confirmation
threshold is zero: any membership/access count or QoS change needs a token.
A token is bound to the prior revision and candidate content; another policy
commit makes it stale.

| Route | Body / result |
| --- | --- |
| `GET /api/v1/peer-policy` | Count-only policy view and ETag. It includes role definition/restriction/member counts, at most ten drift IDs with a truncation flag, outbox occupancy, tracker enforcement, future mutual-origin preflight count, origin-QoS apply counts, and a fleet rollup by accepted policy revision and canonical instruction display state, plus nullable observation/custody status. No peer address or raw deny list crosses this boundary. `roles_supported` is the binary capability; `roles_present` records that role state has existed. |
| `GET /api/v1/peer-policy/roles` | Full sorted role definitions and the current revision/ETag. Definitions contain policy values, never membership IDs. |
| `PUT /api/v1/peer-policy/roles/<name>` | Create or replace a definition. Body fields are `restricted`, `peers`, `origin`, `nets`, `on_stale`, `qos`, optional `qos_state`, plus `confirm_token` on apply. Preview with `?dry_run=1`. A full role-definition replacement must include `qos_state` to retain the stored state object. |
| `GET /api/v1/peer-policy/roles/export-csv` | The complete definition set as `text/csv` in the `iris-role export` grammar (semicolon lists, bytes/second rates), plus the current ETag. Degraded or fail-closed policy returns `503 policy_unavailable` rather than exporting a fallback document. |
| `POST /api/v1/peer-policy/roles/import-csv` | `{"csv": "<roles CSV text>"}` replaces **every** role definition in one revision, exactly like `iris-role import`: the whole graph is validated first, a role a device still declares or a schedule still names cannot be dropped (`role_in_use`), and a grammar problem returns `422 invalid_roles_csv` whose `detail` names the row or field. Preview with `?dry_run=1`; apply with the pre-preview `If-Match` and the preview's `confirm_token`. The split Console accepts the 8 MiB CSV body. |
| `DELETE /api/v1/peer-policy/roles/<name>` | Delete an unused role after preview/confirmation. The preview returns 200 JSON with candidate revision/ETag; the committed DELETE returns 204 with an empty body and the committed ETag. A role with members or another role referring to it returns `role_in_use` with counts/names. |
| `PUT /api/v1/peer-policy/qos` | Replace global QoS keys with `{"qos": {...}}`, or one role's QoS with `{"role": "<name>", "qos": {...}}`; the optional `qos_state` object selects the seeder/leecher tracker layers at the same scope. Omitted `qos_state` preserves its stored object. Explicit `qos_state: {}` removes only the selected state layer and preserves scalar QoS. At least one of `qos` or `qos_state` is required; preview and confirmation rules apply. |
| `POST /api/v1/devices/<id>/role` | `{"role": "<name>"}` sets membership; `{"role": null}` clears it. The fleet declaration and compiled membership are coordinated and the response reports partial failure/drift. |
| `POST /api/v1/devices/bulk-role` | `{"device_ids": [...], "role": "<name-or-null>"}` applies one membership change as one policy revision and one outbox entry, with `applied`, `failed`, `partial`, and drift detail. The request cap is the supported fleet size and the split Console accepts the 2 MiB bulk body. |
| `GET /api/v1/devices/<id>/effective-qos` | Without a query, the legacy scalar `qos` object remains byte-compatible. With exactly one `tracker_state=seeder|leecher`, the response retains scalar `qos` and adds paired `tracker_state`/`tracker_qos` values and sources; invalid, blank, duplicate, or unknown query input returns `422 invalid_policy_request` after an unknown device returns 404. `delivery_state: pre-instructions` is a deprecated legacy Phase 0 sentinel, not a current delivery observation. The required `instruction` object uses the same canonical bounded projection as `/api/v1/devices`, including unavailable/invalid evidence; `/api/v1/peer-policy` supplies fleet rollups. |
| `GET /api/v1/peer-policy/explain?a=&b=` | Resolve each argument as a device id, `device:<id>`, or `service:seeder`; require one fresh, unambiguous attributed address per side; then return both directional decisions, matched sequences, effective ACL/source, role/shadow facts, `mutual`, revision, and ETag. Returns 422 rather than guessing when identity or address attribution is ambiguous. |
| `PUT /api/v1/peer-policy/quarantine/<device_id>` | Quarantines or releases one device. The body must be **exactly** `{"quarantined": <bool>, "if_revision": <int ≥ 1>}` — no other keys, no other types. `if_revision` is the revision you read from `GET /api/v1/peer-policy`, and the write commits only if the policy is still at that revision. 200 `{ok: true, revision, quarantined}` on success. |

The public routes above map one-for-one to `/internal/v1/...` on the private
management listener. That listener additionally requires its scoped tier
credential; browser sessions and CSRF still protect mutations at either
topology boundary.

Every role-policy read returns 200 JSON plus the current ETag, but the JSON
wrappers differ: the policy view is a sanitized count/status object, the role
list wraps definitions under `roles`, effective QoS wraps per-key provenance
under `qos`, and pair explain wraps directional `a`/`b` results. Every mutation
preview returns 200 JSON with the candidate revision and candidate ETag. That
preview ETag does **not** replace the prior strong ETag: apply the unchanged
candidate with the original pre-preview `If-Match` and its `confirm_token`.
Committed PUT/POST operations return 200 JSON plus the committed ETag; committed
role DELETE alone returns 204 empty plus its ETag.

On `/api/v1`, a missing or expired browser session, including expiry between
preview and apply, returns 401 `console-session-required`; the operator must log
in, reread, and preview again. On `/internal/v1`, a missing/invalid scoped tier
credential returns 401 `management-authentication-required`. A browser mutation
also requires its current CSRF value. Neither interface silently retries a
policy mutation.

Role names use `^[a-z0-9][a-z0-9._-]{0,31}$`, at most 256 roles may exist, and
`default`, `quarantine`, `origin`, `seeder`, and `legacy` are reserved. A role
definition has these fields:

| Field | Default / bound | Meaning |
| --- | --- | --- |
| `restricted` | `false` | When true, compile a virtual ACL; false retains implicit permit. |
| `peers` | the role itself; at most 64 | Permitted role names. The list must contain itself. Links between two restricted roles must be symmetric; lifecycle writes normalize reciprocal links. |
| `origin` | `true` | Whether the tracker may introduce `service:seeder` to this restricted role. Issue #153 origin-side mutual blocking remains preflight-only. |
| `nets` | empty IPv4 list | Optional, validated subnet hints for role management. They do not classify tracker announces or install a network ACL. |
| `on_stale` | `keep` for restricted roles, `defaults` otherwise | Instruction-expiry fallback: retain verified QoS with `keep`, or restore defaults. Peer allow-list expiry independently falls back to tracker-only. |
| `qos` | empty | Overrides the global scalar layer for keys allowed at role scope. |
| `qos_state` | omitted | Closed `seeder`/`leecher` tracker cadence and `numwant` overlays for this role; tracker-only and API-configured. |

The `roles` member is optional in a legacy schema-1 policy document. When it is
present, the roles container, every definition, and every QoS layer are closed,
typed objects; unknown keys are refused. `peers` must be a non-null array of
unique role names, must contain the role itself, and cannot contain more than
64 entries. The role schema sets no per-role member cap; operational membership
still cannot exceed the devices in the supported Fleet. An
unrestricted role permits by default only on its own side of evaluation; the
other principal's restricted ACL still governs the pair. A restricted
`origin:false` role is valid. `origin_unreachable` is an advisory when neither
that role nor a permitted role provides a path to the origin.

Role networks accept bare IPv4 addresses and IPv4 prefixes with host bits.
Prefix syntax may use a decimal length, a contiguous dotted netmask, or a
contiguous dotted hostmask. Address octets with leading zeroes and IPv6 are
refused; a decimal prefix spelling is bounded to 32 digits. Valid supplied text
is preserved rather than canonicalized in raw policy. `iris-role` CSV/import is
the owning interface for canonical-equivalent duplicate detection: it compares
canonical networks while preserving the first valid spelling. The raw policy
validator does not promise duplicate-net rejection.

Stored ACLs still allow 64 names and 256 rules each. Virtual role ACLs consume
none of those slots. One explicit stored-ACL assignment **shadows** role policy;
it does not combine with it. `iris-role migrate ACL ROLE --dry-run` only
previews the two-step migration and persists nothing. A confirmed `--apply`
first stages membership behind the existing shadow, then removes matching
explicit assignments in a second policy commit. Quarantine cannot be migrated.

#### QoS keys

Values are integers. Rates are bytes per second; `0` means unlimited, while a
nonzero rate must be at least 8,192 B/s. Scalar QoS retains its existing
compilation precedence. The exact tracker-state precedence is builtin →
`roles.qos_default` → `roles.qos_state_default.<state>` →
`roles.defs.<role>.qos` → `roles.defs.<role>.qos_state.<state>`; a partial state
map overrides only its supplied key. Phase 1 delivers verified device QoS and
logical cadence through encrypted instructions; there is still no public
device-QoS mutation. Tracker-state overlays stay on the tracker and never enter
the device envelope. Server tracker/origin controls remain independent of
device cooperation.

| Key | Default | Range | Allowed scope | Current behavior |
| --- | ---: | ---: | --- | --- |
| `max_peers` | 10 | 1–1,000 | global, role, device | Verified/default hard per-torrent peer cap, including pending outbound peers. |
| `per_peer_bps` | 12,500,000 | 0–10,000,000,000 | global, role, device | A modelling input only. The builtin does not create a cap; when explicitly set it derives absent per-torrent rates as `per_peer_bps × fanout`. |
| `fanout` | 1 | 1–1,000 and no greater than `max_peers` | global, role, device | Modelling input for derived per-torrent rates. |
| `seed_up_bps`, `seed_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Verified/default device rate; unlimited by default. |
| `leech_up_bps`, `leech_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Verified/default device rate; unlimited by default. |
| `overall_up_bps`, `overall_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Verified/default device rate; unlimited by default. |
| `max_concurrent` | 100 | 1–1,000 | global, role, device | Applied from verified/default device policy. |
| `request_peer_speed_limit_bps` | 51,200 | 0 or 8,192–1,000,000,000 | global, role | Applied from verified/default device policy. |
| `announce_min_interval_s` | 30 s | 10–300 s | global, role, state overlay | Tracker resolves state before applying exactly one bounded ±10% jitter and returns the issued value as both `interval` and `min interval`; a peerless leecher in the pinned client still has a 120 s floor. |
| `numwant` | 50 | 4–200 | global, role, state overlay | Tracker ceiling after selected-state resolution and before selection. The pinned client requests at most 50; an explicit client `numwant=0` receives no peers. |
| `handout_budget` | 0 (off) | 0–1,000 | global, role | Accepted policy input for a later phase; handout-budget accounting is not active. |
| `catalog_tick_s` | 60 s | 60–900 s, multiple of 60 | global, role, device | Signed logical catalog/staging cadence; mechanical tick timing remains separate. For a restricted device, the effective value may not exceed effective `endpoint_ttl()/3`; the endpoint TTL defaults to 900 s but is configurable. |
| `telemetry_every_ticks` | 1 | 1–60 | global, role, device | Applied from verified/default device policy. |
| `telemetry_pause` | `false` | boolean | global, role, device | Applied from verified/default device policy. |
| `on_stale` | `defaults` | `keep` or `defaults` | global or role definition | Verified instruction-expiry fallback. |
| `origin_up_bps` | 0 | 0 or 8,192–10,000,000,000 | global only | Active origin-wide upload limit; unlimited by default. |
| `origin_per_torrent_up_bps` | 0 | 0 or 8,192–10,000,000,000 | global only | Active per-image origin upload limit; unlimited by default. |
| `origin_max_peers` | 55 | 1–1,000 | global only | Active origin per-torrent peer cap. |

Numeric QoS values reject booleans even though Python treats booleans as an
integer subtype; `telemetry_pause` alone is boolean. Connection limits are
connections per torrent, `max_concurrent` is torrents, `fanout` is a multiplier,
`numwant` is peers per announce, `handout_budget` is handouts per window,
telemetry cadence is ticks, and interval fields are seconds. To convert a
decimal display rate once, use `Mbit/s × 1,000,000 ÷ 8`; API and CSV `*_bps`
values are already bytes per second.

An explicitly supplied per-torrent rate wins over a rate derived from
`per_peer_bps × fanout` at the same or a more-specific layer. A derived value
above the 10,000,000,000 B/s bound is refused. A QoS PUT replaces the selected
global or role QoS object. A subset is the complete replacement; `{}` clears
that layer. Role membership accepts only an explicit role string or `null` to
clear. The top-level global QoS object may carry `on_stale`; a role uses the
separate definition field. `defs.<role>.qos.on_stale` and device placement are
forbidden. Omitted `qos_state` preserves the stored state object; explicit
`qos_state: {}` removes only the selected state layer while preserving scalar
QoS. A full role-definition replacement must include `qos_state` to retain it.
Tracker state is selected before exactly one jitter operation; the same issued
interval is returned in both response fields and each row expires after twice
its issued interval. Tracker state is tracker-only, and heartbeats remain
outside any catalog or telemetry pause gate.

Zero is unlimited, so no rate key expresses **never upload**. Use assignment
and peer-access policy to avoid creating an upload path, while accounting for
connections aria2 already retained. Device upload rates are reasserted from
verified/default policy, but a privileged device administrator can bypass them.

Per-role origin shaping is not expressible with aria2's global/per-download
controls. The origin can shape all traffic or one image and the tracker can
withhold the origin from a restricted role, but the origin cannot rate-limit
one role within a shared swarm. Verified device downlink limits remain
cooperative under the privileged-administrator boundary.

Refusals on role/QoS writes use Problem Details. Important codes are:

| Status | Code | Meaning |
| --- | --- | --- |
| 428 | `precondition_required` | New role/QoS write omitted `If-Match`. |
| 412 | `precondition_failed` | The header-time check found an ETag that is stale, weak, duplicated, wildcard, or otherwise not the exact current strong value. Re-read before previewing again. |
| 428 | `confirmation_required` | The candidate changes access/membership/QoS and lacks its exact preview token. |
| 409 | `revision_conflict` | The ETag passed the first check, but another writer committed before the under-lock revision check. Refresh and preview the candidate again. |
| 409 | `role_in_use`, `role_isolated`, `role_reserved_name`, `role_shadowed_by_assignment` | Lifecycle/shadow guard refused the change. Only the migration coordinator may deliberately work beneath an explicit assignment. |
| 409 | `operation_backlog_full` | 256 mutations remain unacknowledged. A backlog seen during preflight refuses before durable mutation; a direct writer racing after Fleet-first preflight can still return a partial outcome. |
| 404 | `device_not_found`, `role_not_found` | The named device or role does not exist on the route that owns it. |
| 422 | `bad_role`, `incomparable_role_change`, `mixed_role_direction`, `invalid_policy`, `invalid_policy_request` | Membership, graph/QoS content, or request fields violate the route's closed grammar or cannot be safely ordered as one bulk change. |
| 503 | `fleet_write_failed` | Policy-first relaxation committed policy but a later Fleet write failed, or a Fleet write itself was partial. Inspect outcome detail. |
| 503 | `policy_unavailable` | Policy was degraded/fail-closed before mutation, a required store failed, or a Fleet-first change wrote Fleet and the later policy write failed. The last case preserves `partial`, `applied`, `failed`, revision, and drift detail. |

Precondition and degraded-state refusals happen before mutation; a backlog
observed during normal preflight does too. Actual store failures are different:
one coordinated store may already have committed. On any error response, inspect
`partial`, `applied`, `failed`, revision, and `role_drift` when present, then
refresh both policy and Fleet state and review before retrying. Never infer
"nothing written" from HTTP 503 alone.

`asymmetric_peers` belongs to raw policy/CSV graph validation. The public role
PUT normalizes reciprocal edges atomically, so a valid one-sided edit through
that lifecycle route updates the other definition in the same candidate.

Legacy quarantine retains its body-carried `if_revision` compatibility shape
and its older refusal bodies. New clients should also send the strong ETag.

The backlog bound and what to do about each refusal are in
[Peer-policy operations and their backlog](operations.md#peer-policy-operations-and-their-backlog).

An abbreviated preview/apply sequence (cookie and CSRF setup omitted) is:

```bash
curl -sS -D headers -b session.cookie \
  https://console.example/api/v1/peer-policy -o policy.json
ETAG=$(awk 'tolower($1)=="etag:" {print $2}' headers | tr -d '\r')

curl -sS -b session.cookie -H "X-CSRF-Token: $CSRF" \
  -H "If-Match: $ETAG" -H 'Content-Type: application/json' \
  -X PUT 'https://console.example/api/v1/peer-policy/roles/wan?dry_run=1' \
  --data '{"restricted":true,"peers":["wan"],"origin":true,
           "qos":{"announce_min_interval_s":60,"numwant":20}}'

# Copy confirm_token from that preview without changing the body or ETag.
curl -sS -b session.cookie -H "X-CSRF-Token: $CSRF" \
  -H "If-Match: $ETAG" -H 'Content-Type: application/json' \
  -X PUT https://console.example/api/v1/peer-policy/roles/wan \
  --data '{"restricted":true,"peers":["wan"],"origin":true,
           "qos":{"announce_min_interval_s":60,"numwant":20},
           "confirm_token":"<preview token>"}'
```

### Onboarding jobs

| Route | Body / result |
| --- | --- |
| `GET /api/v1/onboard/jobs` | `{jobs: [...], max_concurrent, now}`. |
| `GET /api/v1/onboard/jobs/<id>` | One job, or 404. |
| `GET /api/v1/onboard/jobs/<id>/stream` | Server-sent log lines, followed by an `end` event. See the stream format below. |
| `POST /api/v1/onboard/jobs/<id>/abort` | `{aborted: true}`. |
| `POST /api/v1/onboard/cancel-queued` | `{cancelled: <count>}` — drops jobs still queued. An optional `{"job_ids": [...]}` body scopes the cancel to those jobs (the console always scopes); without it every queued job is cancelled, other sessions' included. |

Jobs cover onboarding and undeploy. Their states are `queued`, `running`,
`done`, `error`, or `cancelled`. `done` means the installer or undeployer
finished; it does not mean an assigned image has staged. Use the device's
heartbeat status for that.

The stream sends each log line as an unnamed text `data:` event, with
`: keepalive` comments during quiet periods. The named `end` event carries
`done`, `error`, `cancelled`, `idle`, or `unknown`. `idle` means the stream
timed out without output; `unknown` means the job is no longer available.
Each new connection replays retained lines from the start; there are no event
ids or `Last-Event-ID` resume semantics. Read job status before treating a
closed or idle stream as a job failure.

Successful logs end with `onboard complete: <IP>` or
`undeploy complete: <IP>`. Use the job's `state` and `rc` for automation.

### Credentials

| Route | Body / result |
| --- | --- |
| `GET /api/v1/credentials` | `{profiles: [...]}` — id, name, and device user only, never passwords. |
| `POST /api/v1/credentials` | Creates or updates a profile; returns `{profile}` redacted the same way. |
| `DELETE /api/v1/credentials/<id>` | `{deleted: <bool>}`. |

### Schedules

Every mutation is CAS-protected: a write carries the schedule's strong
`If-Match` ETag, and a stale or missing one is a refusal rather than an
overwrite. Occurrence and outcome history stays readable after a definition is
deleted.

| Route | Body / result |
| --- | --- |
| `GET /api/v1/schedules` | `{schedules: [...], total}`. Each view is the stored definition plus three response-only fields: `etag`, `creator_exists`, and `next_fire`. |
| `POST /api/v1/schedules` | Creates one schedule from `{id, kind, target, payload, when, after?, state?}`; 201 with `Location` and `ETag`. `kind` is `assign` or `onboard` — there is no third verb, and neither installs, activates or reloads anything. |
| `GET /api/v1/schedules/{id}` | `{schedule}` with its `ETag`. |
| `PUT /api/v1/schedules/{id}` | Replaces the whole definition. Requires `If-Match`. |
| `PATCH /api/v1/schedules/{id}` | Changes named fields only; `{"after": null}` removes a wave gate. Requires `If-Match`. |
| `DELETE /api/v1/schedules/{id}` | 204. Requires `If-Match`. Occurrences and outcomes are retained. |
| `POST /api/v1/schedules/{id}/reaffirm` | Empty body. Rewrites `created_by` to the calling operator and bumps `rev`, for a schedule whose creator no longer exists. Requires `If-Match`. |
| `GET /api/v1/schedules/{id}/occurrences` | `{occurrences: [...], total, offset, truncated}`, oldest first, `limit` ≤ 100. Each occurrence carries its frozen definition, slot, target snapshot, `delta`, state, and any annotations — including the wave gate's counts. |
| `GET /api/v1/schedules/{id}/receipts` | `{receipts: [...], total, offset, truncated}` — the durable per-device outcome for every occurrence of the schedule, `limit` ≤ 1000. The response cap bounds the page, never the durable evidence. |

`next_fire` is the schedule's current or next slot, computed by the **server**
from the same authority the runner fires from — `{scheduled_at, window_end,
status, resolution, tz, local_time, next_at}` — so no client recomputes local
weekly time across a daylight-saving boundary. It is `null` for a paused or
completed schedule, and for a one-time schedule with no further slot.
`resolution` is `normal`, `gap`, or `fold`; see
[Scheduling](fleet-workflows.md#scheduling).

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
| `GET /swarmmap` | The swarm map page itself, protected by the same session as `/api/v1`. |

Persisted deployment logs are plain files under `$IRIS_STATE/deploy-logs`,
one per finished onboard or undeploy job with a machine-parseable header
line; the newest 200 are kept. `/api/v1/help`'s `deployment_id` comes from
`$IRIS_STATE/instance-id`, minted once on first start and immutable after.

Swarm `images` entries carry `image_id` when their torrent hash maps to exactly
one catalog image. Device observations and verification reports also carry
their image id when known. Match those ids before combining a measurement
with an image's state. `stage_state` summarizes the device's assigned set;
tracker seeder/leecher counts do not establish staging completion. Peer rates
remain unavailable when a shared address cannot be attributed to one participant.

### Other service APIs

The device catalog, tracker, telemetry, and artifact listeners below use
separate credentials. They do not accept a Console session cookie or CSRF
token. The shared device agent uses the catalog protocol; operator integrations
use `/api/v1` through the Console. See [Device agents](device-agents.md) and
[Architecture](architecture.md) for the service layout.

### Import skip reasons

`skipped` entries carry the same fields as importable ones plus a `reason`, and
the console greys them out so a file you expected to see does not just silently
fail to appear. There are exactly three reasons.

| Reason | Meaning |
| --- | --- |
| `already published` | The derived catalog id is already in the catalog, or a publish for that id is in flight — an in-flight publish counts, because the entry appears only when the async job finishes. A catalog `filename` match counts too. `publish.derive_id()` strips `.SPA.bin` or `.bin`, so `foo.bin` and `foo.SPA.bin` are one catalog id. |
| `ambiguous name in more than one location` | The same basename, or the same derived id, exists under more than one root. The startup re-seed can resolve a torrent to a directory by basename and the seeder runs with `bt-seed-unverified`, so a wrong guess would serve the wrong bytes under correct piece hashes. IRIS refuses rather than guess: keep one copy. |
| `not readable by the server` | The file exists but uid 10001 cannot open it. Listing a file needs only its directory, so without this check an unreadable image would pass discovery and fail deep inside publish. Check volume ownership and file permissions; see [Volume permissions](server.md#volume-permissions). |

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

* **Identity-bound** (`heartbeat`, `telemetry`, `policy`, `instructions`,
  `instruction-keylist`, `token-refresh`): the
  token must resolve to that path's own `<device_id>` under `catalog_token` —
  or, on `token-refresh` only, the immediately preceding
  `catalog_token_prev`, so a device that never saw the response to its own
  rotation can recover it idempotently rather than being stranded. `policy`
  is identity-bound because its response carries the caller's minted
  `plan_id`/`transfer_id` pair.
* **Assignment-bound** (`images`, image detail, and torrents): a device sees
  only ids in its own approved-image set. An unassigned or nonexistent id has
  the same 404. There is no fleet-wide device collection on this listener.
  A service credential can authenticate but does not acquire a device's
  assignment and therefore receives no device catalog entries.

| Route | Auth | Body / result |
| --- | --- | --- |
| `GET /v1/images` | Assignment-bound | `{images: [...]}` — only the caller's approved entries, with no `source_dir` or reconciler internals; an unassigned device receives an empty list. |
| `GET /v1/images/<id>` | Assignment-bound | Device-facing view of one approved image; an unassigned and nonexistent id both return 404. |
| `GET /v1/torrents/<id>` (also accepts `<id>.torrent`) | Assignment-bound | An IOx/XR request advertises `X-IRIS-Tracker-Auth: bearer` and receives a torrent with a token-free tracker URL; its agent supplies the separately rotated announce bearer as an aria2 per-download header. A request without that opt-in receives query-token personalization used by Guest Shell bundles. Both forms carry `Cache-Control: private, no-store` and `Vary: Authorization, X-IRIS-Tracker-Auth`. 404 means the id is not approved or no torrent exists; 503 means the identity-compatibility gate is closed; missing announce material or personalization failure is a redacted 500. There is no cross-device or shared-token fallback. |
| `GET /v1/devices/<id>/policy` | Identity-bound | The device's own policy view — see [Policy schema](#policy-schema). |
| `GET /v1/devices/{device_id}/instructions` | Current catalog bearer, identity-bound | Bounded sealed per-device envelope, maximum 256 KiB; strong ETag/304 on unchanged bytes. 404 missing stamp/artifact, 409 `stale_pointer`, 429 rate limit, 503 unavailable state. |
| `GET /v1/devices/{device_id}/instruction-keylist` | Current catalog bearer, identity-bound | Root-signed keylist/KRL, maximum 128 KiB; ETag/304. 404 missing, 503 unavailable. |
| `POST /v1/devices/<id>/heartbeat` | Identity-bound | Body: the device's heartbeat JSON — see [Keyed per-device state](#keyed-per-device-state). 200 `{ok: true, stream_every, stream_pause, report_requested?, report_request_id?}`. |
| `POST /v1/devices/<id>/telemetry` | Identity-bound | Body: the device telemetry report. Malformed input is a Problem Details 400; a report naming an image outside the device's currently approved set is invalid. 200 `{ok: true}`. |
| `POST /v1/devices/<id>/token-refresh` | Identity-bound (current **or** previous token) | Rotates `catalog_token`. A request presenting the just-rotated previous token replays the same successor rather than rotating again, so a lost response cannot strand the device. Errors use Problem Details; 200 returns `{catalog_token, expires_at, instr_key, instr_key_prev?, announce_token?, rpc_secret?}`. Current/bounded prior instruction keys are private refresh material; optional announce/RPC fields appear only when present, never as empty strings that overwrite working values. |

The instruction and keylist GET routes share one per-device request bucket:
burst 2, refilling one request every 10 seconds. Both consume that same budget;
exhaustion returns 429 with a bounded `Retry-After`. This request limiter does
not authorize an in-tick sleep/retry loop in the agent.

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
Guest Shell bundles authenticate with their personalized
query token. When `Authorization` is present it takes precedence; an invalid
header is rejected rather than falling back to the query token. Neither
form is logged or returned in an error, and the IOx/XR flow never puts
the credential in torrent metadata, a URL, or argv. Missing/invalid
authentication returns a token-free bencoded 401 before request shape or
resource existence is examined. All tracker errors remain bencoded `failure
reason` dictionaries for BitTorrent-client compatibility; this is the
documented RFC 9457 exception. Current and bounded previous seeder credentials
follow the `IRIS_SEEDER_PREV_TTL` overlap.

| Route | Body / result |
| --- | --- |
| `GET /announce` | Query: `info_hash` (20 raw bytes, percent-encoded), `peer_id`, `port` (1-65535), `left`, `event`, `numwant` (default 50), `compact` (`1` for BEP23 compact peers), and an `ip` override honoured **only** for the service origin-seeder principal and only for a private/CGNAT IPv4 address. Exact `left == 0` selects seeder; positive, omitted, malformed, and negative values select leecher. State QoS is resolved before one jitter, with the issued value returned as both `interval` and `min interval`; a valid registration expires after twice that issued interval, while an invalid port receives cadence without registration. A malformed hash is a bencoded 400 after auth. Success is bencoded `{interval, min interval, peers}`; peer policy filters candidates before return. |
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
| anything else | Auth is checked first, then a Problem Details 404. Use the Console for browser pages. |

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

Guest Shell uses the same agent code in a bundle, with its HTTPS
bootstrap flow. Its static bootstrap, bundle, certificate, and
`staging/<128-bit-capability>` paths therefore remain available over verified
HTTPS without HTTP Basic. The secret-bearing names are generated per install,
written mode `0600`, redacted from access logs, and swept after one hour. This
is the Guest Shell enrollment path; IOx and XR use server-initiated SCP.

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
| `sha512` | Computed at publish time and compared with Cisco's Bulk Hash feed. Guest Shell also uses it when checking a pre-existing IOS root file with native `verify /sha512` before adopting that file. See [Image verification](#image-verification) and [same-name placement](device-agents.md#crash-safe-same-name-replacement). |
| `cisco_signature_verified` | `True` when `hash_verification.state` is `verified`, otherwise `False`. The Cisco Bulk Hash reconciler maintains this field. It records the server-side source verdict, separately from the agent's content and placement checks and the operator attestation below. |
| `operator_attested_signature` | `True` when `iris-publish` was run with `--signature-verified` — the publishing operator's own attestation that the Cisco signature was checked elsewhere. Written once, at publish time, by `publish.py` alone; the Cisco Bulk Hash reconciler never reads or writes it, so it survives every reconciliation run untouched. Advisory only — nothing on the device consults it. |
| `hash_verification` | `{state, checked_at, feed_published_at, source, deferral}` — the reconciler's most recent verdict for this image; absent until the first reconciliation run covers this entry. See [Image verification](#image-verification). |
| `quarantined` | `True` once a `mismatch` verdict has quarantined this image. Only `POST /api/v1/images/<id>/release-quarantine` clears it — a later `verified` verdict alone does not. See [Releasing a quarantine](operations.md#releasing-a-quarantine). |
| `info_hash_hex` | Torrent info hash, used to stop seeding on delete. |
| `published_at` | Unix timestamp of the publish. |

`source_dir` is what makes in-place publishing safe. A delete unlinks the image
file only when `source_dir` resolves to `IRIS_IMAGES_DIR`, so an image published
from the read-only root stays on disk and a same-named file in the uploads volume
is never destroyed. Startup re-seeding uses
`source_dir`, falling back to its basename walk for
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
map, and operator inventory — is **keyed**
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
own device lands in.

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

Each shard is written atomically using a temporary file and rename in the
same directory. A shard that exists but cannot be read or parsed fails closed:
requests that need it return `503`, and writers leave its content untouched.
The affected devices and whole-fleet listings remain unavailable until it is
repaired.

Whole-fleet reads — Console listings, telemetry snapshots, tracker blocklist
derivation, and device purges — read every row across the shards.

## Policy schema

The policy store (`<state>/policy.d/`) holds per-device staging approval —
what IRIS is allowed to stage, never what it installs, activates, or reloads.
It is **keyed** state: one row per device, spread over 256 shard files, so a
device's policy read or write touches only its own shard. See
[Keyed per-device state](#keyed-per-device-state).

| Field | Meaning |
| --- | --- |
| `approved_image_ids` | Ordered list of catalog image ids, up to ten. The agent stages and verifies every id in the set, transferring them in parallel. Authoritative: a raw read of this file, or a stale write, is resolved from this key, never from `approved_image_id`. |
| `approved_image_id` | The set's first element, or `null` when empty. Recomputed from `approved_image_ids` on every read and write. |
| `plans` | Per-image transfer identity, keyed by image id: `plan_id` and `transfer_id` (both 32 lowercase hex), `planned_at` (epoch seconds) and `info_hash` (the torrent info hash of the image as the catalog held it at mint time, `null` when the catalog has no entry yet). Minted when an image **enters** the set and carried forward verbatim while it stays there, so a repeat Apply — including one that only adds or removes some other image, and the quarantine auto-unassign rewrite — never re-mints and never restarts an in-flight transfer's identity. Unassigning an image drops its entry and re-assigning it mints a new plan, which is what keeps two successive transfers of the same image to the same device distinct. |

`POST /api/v1/devices/<id>/assign` (see [Devices](#devices)) writes this file.

The agent reads its own row from `GET /v1/devices/<device_id>/policy`. That
response carries the two approval keys above plus a `plans` map projected down
to the two device-visible fields, `plan_id` and `transfer_id`, for image ids
that are in the approved set and whose stored ids are both 32 lowercase hex;
`planned_at` and `info_hash` stay on the server, because the agent has no use
for either. The key is always present, possibly empty. The agent adopts the
`transfer_id` before it starts a download and stamps it on every observation
and terminal report for that image, so one transfer carries one id from
assignment to seed.

The device's heartbeat (`<state>/devices.d/`) reports per-image staging
progress against that set:

| Field | Meaning |
| --- | --- |
| `current_image_id` | The image that supplied this heartbeat's identity and observation, usually the first assigned image with heartbeat data. It does not identify all active transfers, and the aggregate `stage_state` need not describe this image alone. |
| `stage_state` | One state string for the whole tick. On a one-image heartbeat it is that image's own state (for example `staging`, `downloading`, `transferring_to_ios`, `ready`, `error`). For a set the agent collapses the tick into the single most actionable state across every assigned image, so it describes the set, not `current_image_id`. `stage_error`, likewise, is one reason per tick. |
| `staged_image_ids` | Which of the assigned images this agent has staged and verified, as of its last heartbeat. Absent on a one-image heartbeat, in which case staged/not-staged falls back to `stage_state == "ready"` paired with `current_image_id`. |
| `errored_image_ids` | Which of the assigned images hit a terminal per-image failure on the agent's last tick, including retryable ones such as a full boot filesystem. Absent on a one-image heartbeat. |

If an image appears in both arrays, its current error wins over the older
staged flag. A missing catalog entry, catalog lookup failure, torrent-start
failure, or SHA mismatch is reported against the requested image id. Other
assigned images can continue during that tick. For a one-image
heartbeat, match `current_image_id` to the assignment before using its state.

An empty approved set stops the device's torrents on its next successful policy
poll. Download cleanup follows the platform's ownership rules; see
[Unassigned image park](device-agents.md#unassigned-image-park).

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
| `delivered` | The same event-key map, written after a successful send to the collector. IRIS re-queues retained events without this marker when they are no longer queued. A successful send does not prove final backend indexing. |

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
| `iris.transfer.report_received_at` | `seeding_started` | The server's ingest instant for the attesting report; the same value as `iris.transfer.checksum_verified_at`. Compare it with `iris.device.report_created_at` to measure report delivery delay. |
| `iris.device.observed_at`, `iris.device.report_created_at` | `seeding_started` | The attesting report's two device-clock instants, as epoch floats — the end of its measurement window and when it was composed — named exactly as `iris.device.transfer.report` names them. Show them; never subtract either from a server instant as though the clocks agreed. |
| `iris.transfer.recovered_promotion` | `seeding_started` | `true`, and present at all, only on a record whose row was rebuilt from a lost store. It says three things at once: this may be a *replay* of a record the backend already holds under this `event.id`; its `seeding_started_at` is `max(checksum_verified_at, planned_at)` and may be **earlier** than what that first record carried; and its `iris.transfer.tracker_seeder_at` is a post-loss re-announce, so recomputing `max()` over the three instants on this record will not reproduce its `seeding_started_at`. Absent — never `false` — on an ordinary promotion. |
| `event.id` | both | `<plan_id>.<event>`, derived and never minted per emission, so a replay after a crash between the queue accepting a record and its marker landing carries an identical key the backend can dedupe. |
| `iris.telemetry.schema.version` | both | `2`. |

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

## GuestShell root-hash recovery

Guest Shell's [same-name adoption](device-agents.md#crash-safe-same-name-replacement)
uses the native `IRIS-ROOT-HASH` EEM policy only when an IOS root file already
exists. The policy has a 600-second maximum runtime. The agent waits up to
625 seconds for its unique completion record, then removes the policy and
its own result directory. An unavailable hash, ambiguous IOS directory
response, catalog mismatch, or failed cleanup reports `copy_failed` and leaves
the destination image unchanged. Normal copied placement does not use this
policy.

The stage directory contains `.iris-root-hash.lock` and
`.iris-root-hash.json` to serialize jobs across interrupted agent processes.
A known running job blocks another launch until its 625-second lease expires.
If the launch result was lost, the lease has no known expiry and the error
asks for operator inspection; a later tick must not assume that native work
has stopped.

To recover that unconfirmed launch, remove the `IRIS-ROOT-HASH` applet from
running configuration, allow at least 625 seconds for any previously started
job to finish, and inspect the EEM job history. Then remove only
`<stage_dir>/.iris-root-hash.json`; the next ordinary agent tick can retry.
Do not remove the lock file while the agent is running, the staged image, the
IOS root image, or a `BOOT` target. Normal undeploy removes the hash applet
alongside the other IRIS applets.

## Device container environment variables

These are the production environment variables understood by the unified IOx
and IOS-XR appmgr image. Installers supply the required identity fields and the
platform selector; the entrypoint derives storage and runtime behavior from
that selector, validates every value before persisting it, and otherwise uses
the defaults below. None are `server/` Compose variables. Guest Shell is not
part of the unified image; it runs the shared agent from a bundle through
bootstrap and EEM. Rows marked Guest Shell or router also apply to those agents. Cadence behavior is described under [Device agents → Cadence jitter
and overload backoff](device-agents.md#cadence-jitter-and-overload-backoff).

| Variable | Default | Platform | Effect |
| --- | --- | --- | --- |
| `IRIS_DEVICE_PLATFORM` | **required** (`iox` or `xr-appmgr`) | IOx, XR | Selects the storage and runtime profile before any write. Installers pass it; the common entrypoint persists it as `device_platform` for restarts. Missing, unknown, or conflicting values fail closed. `iox` uses CAF persistent scratch plus live writable-media selection and SSH-to-self; `xr-appmgr` verifies `/hostmount`, fixes the target to `harddisk:`, and rejects SSH/share variables. |
| `IRIS_CATALOG_URL` | **required on first start** | IOx, XR | Reachable HTTPS catalog base URL. An existing persistent config supplies it on later starts. |
| `IRIS_CATALOG_TOKEN` | **required on first start** | IOx, XR | This device's enrollment/catalog credential. It is written only to the mode-0600 persistent config and may subsequently rotate there. |
| `IRIS_DEVICE_ID` | **required on first start** | IOx, XR | Catalog identity. Limited to letters, digits, `.`, `_`, `:`, and `-` before it reaches config or a request path. |
| `CAF_APP_APPDATA_DIR` | **required; supplied by CAF** | IOx only | Application-data directory containing the runtime-delivered `iris-catalog.pem`. The entrypoint derives and validates this trust path before starting either catalog or tracker traffic. XR instead uses the fixed `harddisk:` bind path `/hostmount/iris-catalog.pem`. |
| `IRIS_TELEMETRY` | `on` | IOx, XR | Enables normal device reports. Only the documented boolean spellings are accepted. A redeploy value reconciles an existing persistent config. |
| `IRIS_TELEMETRY_STREAM` | `off` | IOx, XR | Enables live transfer samples when telemetry is on. A redeploy value reconciles an existing persistent config. |
| `IRIS_TICK_SECONDS` | `60` | IOx, XR | Mechanical launcher interval/floor; integer 1–86400. Signed `catalog_tick_s` governs logical catalog/staging cadence; every mechanical tick still reasserts QoS and sends heartbeat. |
| `IRIS_TICK_JITTER_PCT` | `10` | IOx, XR | Dithers every ordinary tick by ±this percent of `IRIS_TICK_SECONDS`. |
| `IRIS_STARTUP_JITTER` | `1` (on) | IOx, XR | Spreads the first tick after container start across the whole `IRIS_TICK_SECONDS` window. `0` disables it. |
| `IRIS_TICK_BACKOFF_MAX` | `600` (seconds) | IOx, XR, Guest Shell, router | Cap on the exponential backoff applied after a tick's agent process fails outright. |
| `IRIS_TICK_JITTER_MAX` | `8` (seconds) | Guest Shell, router | Bound (0..N-1, uniform) on the per-tick sleep `bootstrap.sh` takes before contacting the catalog. The EEM timer's own 60s period is unaffected — IOS owns that clock. |
| `IRIS_RPC_PORT` | `6800` | IOx, XR | Local aria2 JSON-RPC port; integer 1–65535. It is persisted as `rpc_port`. |
| `IRIS_MAX_PEERS` | launcher fallback `10`; absent from Dockerfile defaults | IOx, XR | Legacy provisional launch value, integer 1–1000; verified/default policy supersedes it at the first successful tick, before any restored download starts. No enduring policy authority. |
| `IRIS_MAX_CONCURRENT` | launcher fallback `100`; absent from Dockerfile defaults | IOx, XR | Legacy provisional launch ceiling, integer 1–1000; first successful tick writes verified/default global and active-GID options before reconciliation. Every future `addTorrent` uses verified/default values. |
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
| `IRIS_LOG` | `off` | IOx, XR, Guest Shell | Enables `aria2c.log` with `on`, `1`, `true`, or `yes` (case-insensitive). IOx/XR installers pass the value to the container; on Guest Shell set `iris_log` in `iris-agent.conf`. IOx/XR cap the file at 50 MiB; Guest Shell trims it through `rotate-logs.sh` and EEM. Keep it off for normal operation to reduce flash writes. It does not control `%IRIS-6-<MNEMONIC>` status messages or heartbeat errors. See [Device-side logging](device-agents.md#device-side-logging-flash-write-endurance). |
| XR container logs | 3 × 1 MiB | XR | The installer configures Docker `json-file` logging with `max-size=1m` and `max-file=3`. This captures startup and `%IRIS` diagnostics even with `IRIS_LOG=off`. Read it with `show appmgr application name iris logs`. |

There is no production `IRIS_CATALOG_CA` override: IOx trust must come from CAF
application data and XR trust from the verified harddisk bind mount. A package
cannot redirect either path or supply a built-in fallback.

Production containers reject `IRIS_STAGE_DIR`, `IRIS_WORK_DIR`, `IRIS_AGENT_CONF`,
`IRIS_AGENT_STATE`, and `IRIS_CATALOG_CA`; those overrides, plus
`IRIS_CONTAINER_TESTING=1`/`IRIS_TEST_SKIP_MOUNT_CHECK=1`, exist only for the
source-level test harness. This prevents a deployment from redirecting a
multi-gigabyte stage away from the selected platform's storage policy.

## Device agent config keys

The agent reads `key = value` lines from its persistent configuration:

- Guest Shell: `/flash/guest-share/iris/iris-agent.conf` by default; its
  bootstrap supplies the path for the device's filesystem.
- IOx: `<CAF_APP_PERSISTENT_DIR>/iris/iris-agent.conf` (`/data/iris/` by default).
- IOS-XR: `/hostmount/iris-work/iris-agent.conf` on the `harddisk:` bind mount.

The device-container entrypoint sets the path from the platform profile and
rejects production path overrides.

| Key | Default | Effect |
| --- | --- | --- |
| `device_platform` | **required in a device container** | Persisted copy of `IRIS_DEVICE_PLATFORM`, limited to `iox` or `xr-appmgr`. It is read before storage paths are chosen; it is not inferred from directory existence. Guest Shell does not use this container selector. |
| `catalog_ca` | Platform-derived runtime path | Certificate used for catalog calls and HTTPS tracker announces. Guest Shell uses the certificate copied during its artifact flow; IOx uses CAF application data; XR uses `/hostmount/iris-catalog.pem`. The container entrypoint reconciles this fact on every start and refuses a missing or invalid certificate. |
| `device_ssh_known_hosts` | unset | Path to a `known_hosts` file pinning the device's SSH host key. When the key is set and the file exists, the agent's SSH and SCP calls use `StrictHostKeyChecking=yes` against it. Otherwise they keep the default `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null`. |
| `telemetry_stream` | `off` | Live transfer-sample streaming ([Transfer streaming](observability.md#transfer-streaming)). Fail-closed: only an explicit `on`/`1`/`true`/`yes` enables; requires `telemetry` on. Delivered by the installers (`TELEMETRY_STREAM`) and IOx deploy env (`IRIS_TELEMETRY_STREAM`), and changed by redeploy. |
| `iris_log` | unset (off) | Guest Shell's only persistent path to the `IRIS_LOG` device-side logging opt-in — see [Device agents → Device-side logging (flash write endurance)](device-agents.md#device-side-logging-flash-write-endurance). `bootstrap.sh` reads this key on every EEM tick and exports it as `IRIS_LOG` before running `guestshell-start.sh`; an operator sets `iris_log = on` in the device's `iris-agent.conf` and the next tick picks it up, no reinstall. Validated before export: only letters/digits are accepted (`on`/`1`/`true`/`yes` enable it, case-insensitive, matching every other platform's parsing), anything else — including an attempt to inject shell syntax — is dropped with a warning and the built-in default (off) applies. |
| `rpc_port` | `6800` | Also read by `bootstrap.sh` and exported as `RPC_PORT` for `guestshell-start.sh`'s own aria2c launch line, in addition to the Python agent's existing use of this key for its own RPC calls to aria2c. Validated as an integer 1–65535; an out-of-range or non-numeric value is dropped with a warning and `guestshell-start.sh`'s built-in default (`6800`) applies. |
| `max_peers` | legacy only | Parsed-but-ignored for upgrade compatibility, with a value-free `MAX-PEERS-IGNORED` notice once. Guest Shell no longer exports it; active `max_peers` policy uses the signed/default 1–1000 bound above. |

`device_ssh_known_hosts` controls only the IOx agent's SSH-to-self connection.
Strict checking requires both the setting and a file at that path; IRIS does
not create it. Guest Shell uses the on-box `cli` module and XR uses its host
mount, so neither agent opens that SSH connection. Server-initiated onboarding
has its own [SSH host-key policy](security.md#device-ssh-host-keys).

## Instruction protocol and state reference

The [OpenAPI contract](openapi.yaml) defines the bounded wire schema. Device
heartbeat `instr_protocol: 1` denotes capability; `version` continues to mean
IOS software. An absent protocol marker is legacy `pre-instructions`, while a
present invalid/future marker is unknown. Accepted identity is complete
`{instr_epoch, instr_serial, instr_policy_revision}` or absent; legacy
standalone serial remains compatible but is not a complete acceptance claim.

| Revision term | Meaning |
| --- | --- |
| `policy_revision` | Server-issued role/QoS intent; fleet applied counts group by this value. |
| `instr_serial` with `instr_epoch` | Per-device sealed instruction freshness identity; monotonic `(epoch, instr_serial)` replay floor. |
| `enforcement.applied_revision`, `iris_peer_enforcement_applied_revision` | aria2 blocklist change counters, unrelated to policy revision or instruction serial. |

The nineteen raw agent states are `none`, `applied`, `lkg`, `stale_expired`,
`allowlist_expired`, `rollback_rejected`, `floor_reset`, `audience_mismatch`,
`key_rejected`, `tamper_rejected`, `verifier_missing`, `lkg_rejected`,
`lkg_unreadable`, `oversize`, `reasserted`, `instr_unavailable`, `instr_pending`,
`instr_forbidden`, and `tracker-only`. The server display vocabulary is
`applied`, `lkg`, `stale`, `rejected`, `tracker-only`, `pre-instructions`,
`unknown`, `unavailable`, `pending`, `forbidden`, `floor_reset`, `none`, and
`revoked`. Display classifications are not raw device-authored states. For
condition, retained QoS/peer state and retry action, use the complete
[failure table](device-agents.md#instruction-failures-and-recovery).

Each `/api/v1/devices` row and successful
`/api/v1/devices/<id>/effective-qos` response has one canonical `instruction`
object:
`display_state`, `label`, `evidence`, `underlying_state`, `underlying_label`,
`underlying_evidence`, `reason`, `reported_instr_serial`, `accepted_identity`,
`verify_level`, `pointer_skew`, `qos_drift_count`, `report_age_seconds`,
`report_stale`, `revoked`, and `revocation_evidence`. `accepted_identity` is
null or complete `{epoch, instr_serial, policy_revision}`. Durable revocation
and report age are server-observed; raw state, accepted identity, verification
level and QoS drift are agent-asserted. Device-authored reports are statements
from the device, not independent server measurements. Exact i63 identity
labels are server-created strings so browser number rounding cannot alter them.

`/api/v1/peer-policy` adds `fleet_rollup` with exactly `issued_revision`,
`applied` (decimal policy-revision keys), and `states`; `instruction_status`
with `observed_at`, current inventory-device `instr_stamp_missing`,
`pointer_skew` count and exact `issued_revision_label`; and nullable validated
`instruction_keys` custody status. Inventory devices count once and orphan
heartbeats are excluded. Accepted identities remain visible even under stale,
rejected or revoked display states. Null means unavailable/invalid evidence,
not healthy zero. Missing or corrupt heartbeat, policy, revocation and custody
sources remain explicit unknown/unavailable. **violation = 0 does not mean compliant**.

The 256 KiB envelope uses a per-device KDF and audience binding, signature and
MAC-before-decrypt checks. Both authenticated instruction GET paths use existing
8443; 9443 is management-only. The [state path inventory](server.md#instruction-state-and-processes)
distinguishes `$IRIS_CONFIG/instr/signing-key.age`, runtime
`$IRIS_RUN/instr/signing-key`, and `$IRIS_STATE` durable producer state. No
instruction/LKG/online/offline private key enters platform config; IOx/XR
bootstrap enrollment credentials remain a documented [exception](security.md#two-root-trust-and-custody).

## Generated outputs

| Output | Source |
| --- | --- |
| `site/` | Zensical build output. Not committed. |
| `deploy/` | GitHub Pages assembly directory. Not committed. |
| `fleet/dist/` | Generated device installers. Not committed. |
| `artifacts/` | Served runtime artifacts. Not committed except `.gitkeep`. |
| `release/` | Release packaging output. Not committed. |
