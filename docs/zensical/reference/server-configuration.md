<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Server configuration

Environment variables for the server and Console containers, the container
paths they use, and the credential file formats they read.

## Environment variables

### Required at deploy time

The server Compose service needs these; none has a default. A standalone
Console host uses
[Deployment settings for separate hosts](#deployment-settings-for-separate-hosts)
instead.

| Variable | Effect |
| --- | --- |
| `IRIS_HOST_IP` | The server address devices reach. Changing it later means updating TLS trust, announce URLs, and agent configuration, and re-onboarding affected devices. See [Rotate credentials and certificates](../admin-guide/rotations.md). |
| `IRIS_AGE_RECIPIENTS` | Comma-separated age public keys the secret store is encrypted to: the primary key plus an offline recipient. |
| `IRIS_AGE_KEY_FILE_HOST` | Host path of the age identity (private key), mounted as the Docker secret `iris_age_key`. |

!!! note "How a variable reaches the container"
    Compose injects only the keys named in the `environment:` block of the
    Compose files you run. Setting a variable in your shell, or adding it to
    `server/.env`, has no effect until it is also named in that block: a
    variable the block does not name is silently dropped.

    Kubernetes differs: `kubernetes/kustomization.yaml` builds the ConfigMap
    from `kubernetes/iris-seed-server.env`, and every key in that file
    reaches the process.

### Optional at deploy time

| Variable | Default | Effect |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `server` | Compose project name and volume prefix. Set it to run a second stack on this host; see [One Docker host](../install/one-docker-host.md#running-a-second-stack-on-the-same-host). |
| `IRIS_CONTAINER` | `iris` | Server container name, used by helper scripts such as `tools/apply-assignments.sh`. |
| `IRIS_CONSOLE_CONTAINER` | `iris-console` | Console container name. |
| `IRIS_OBSERVABILITY_TOKEN_FILE_HOST` / `_PREVIOUS_TOKEN_FILE_HOST` | `/dev/null` | Host path of the raw observability bearer token, mode 600, and its previous value during a rotation overlap. Required when `IRIS_OBSERVABILITY=1` and something scrapes `/metrics`. |
| `IRIS_OTLP_HEADERS_FILE_HOST` | `/dev/null` | Host path of a mode-600 file holding the collector authentication header. |
| `IRIS_ARTIFACTS_HOST_DIR` | `../artifacts` | Host directory mounted read-write at `/srv/artifacts`. |
| `IRIS_SHARP_SANS_FONT_HOST` | `/dev/null` | Legacy font bind mount. Leave unset. |
| `IRIS_GUI_PUBLISH` | `8080` | Published Console host port. |
| `IRIS_CONSOLE_URL` | unset | Full external HTTPS Console URL shown in server settings, for example `https://console.example.com:8080`. |
| `IRIS_PEER_TLS_MODE` | `disabled` | `required` turns on peer transfer TLS. Set the same value on every process in the swarm. See [Guardrails](../architecture/security-model.md#guardrails). |
| `IRIS_GUI_ALLOW_PLAINTEXT`, `IRIS_CATALOG_ALLOW_PLAINTEXT`, `IRIS_ARTIFACTS_ALLOW_PLAINTEXT` | unset | `1` serves that component over plain HTTP when no usable certificate is set. Loopback or an isolated test network only. |
| `IRIS_VERSION` | unset | Build argument for the release string the Console Settings page shows. |
| `IRIS_GUI_ADMIN_PASSWORD` | unset (prompts) | Read by `iris-gui-admin` to set the Console admin password without a prompt. |
| `IRIS_SAMPLE_INTERVAL` | `15` seconds | Seeder and telemetry poll interval. Lower to 2-5 for a fast fabric or a live demo. |
| `IRIS_TRACKER_PORT` | `6969` | Tracker listen port. Update the Compose port mapping to match. |
| `IRIS_TRACKER_ANNOUNCE` | unset | Full HTTPS announce base, used instead of deriving one from `IRIS_HOST_IP` and `IRIS_TRACKER_PORT`. |
| `IRIS_REQUIRE_IDENTITY_GATE` | unset (off) | `1` blocks per-device torrent requests until a proven seeder rotation completes. |
| `IRIS_ONBOARD_CONCURRENCY` | `25` | Maximum onboard and undeploy jobs running at once; the rest queue. |
| `IRIS_XR_SESSION_TIMEOUT` | `150` seconds | Timeout for one IOS-XR command session. `0` disables it. |
| `IRIS_DEVICE_ENABLE_ALWAYS` | unset (off) | For devices that require `enable` at login: send `enable` and the secret on every IOS-XE SSH session. |
| `IRIS_ONBOARD_JOB_TIMEOUT`, `IRIS_ONBOARD_REAP_GRACE` | `7200`, `60` seconds | Deadline for one onboard or undeploy job (stopped like an operator abort), and the grace between `SIGTERM` and `SIGKILL` that follows. |
| `IRIS_SEEDER_PREV_TTL` | `2592000` seconds (30 days) | How long a rotated-out seeder token still works. Set it once for the whole deployment. See [Rotate credentials and certificates](../admin-guide/rotations.md). |
| `IRIS_HTTP_TIMEOUT` | `30` seconds | Socket timeout for tracker and catalog requests. |
| `IRIS_ENDPOINT_TTL` | `900` seconds | Freshness window for a device's peer endpoint. |
| `IRIS_ENROLL_TTL` | `3600` seconds | Lifetime of the one-shot enrollment token in a per-device installer. |
| `IRIS_HEALTH_LISTENERS` | `tracker:6969,catalog:8443,artifacts:8000,management:9443` | What `:9101/readyz` checks, as `name:port,name:port`. `off` checks nothing. |
| `IRIS_AUDIT_RETENTION_DAYS`, `IRIS_AUDIT_MAX_EVENTS` | `90` days, `50000` | Audit entries older than the retention days, or past the event cap, are pruned. Raise both together. |
| `SEED_MAX_CONCURRENT` | `1000` | Maximum concurrent downloads the origin seeder runs. |
| `IRIS_SSH_LEGACY`, `IRIS_SSH_HOST_KEY`, `IRIS_SSH_KNOWN_HOSTS` | see [SSH variables](#ssh-variables) | Server-side SSH verification policy. |
| `SVI_IGP` | `none` | Routed Guest Shell installs only: `isis` adds `ip router isis` to the IRIS SVI. A device's inventory record can override it. |

Use the documented bounds for each variable. `0` disables
`IRIS_XR_SESSION_TIMEOUT`, `IRIS_METRICS_PORT` and API request-rate budgets;
other settings may reject it or fall back to their defaults.

### Container paths

`server/docker-compose.yml` sets each path explicitly, so a one-shot command
run with `docker compose exec` sees the same layout as the server.

| Variable | Path | Role |
| --- | --- | --- |
| `IRIS_STATE` | `/var/lib/iris` | Catalog state, policies, torrent metadata, the peer ledger, peer endpoints, and deployment records. |
| `IRIS_CONFIG` | `/etc/iris` | The age-encrypted secret store and generated TLS material, plus the Console certificate override and the audit trail. |
| `IRIS_RUN` | `/run/iris` (tmpfs) | Plaintext runtime secrets. |
| `IRIS_SECRETS` | `/run/iris/secrets.json` | Decrypted secret store, read by the server process. |
| `IRIS_SECRETS_ENC` | `/etc/iris/secrets.json.age` | Encrypted secret store on disk. |
| `IRIS_RPC_SECRET_FILE` | `/run/iris/rpc-secret` | aria2 RPC shared secret. |
| `IRIS_CERT` | `/run/iris/tls/cert.pem` | Catalog and device-facing TLS certificate. |
| `IRIS_AUDIT` | `/etc/iris/audit.jsonl` | Append-only audit trail. |
| `IRIS_ARTIFACTS_DIR` | `/srv/artifacts` | Served bootstrap and agent artifacts. |

Onboarding reads the device public certificate from
`$IRIS_CONFIG/tls/crt.pem`; `IRIS_CRT_PUBLIC` overrides that path. The
device-side `IRIS_LOG` is a separate setting; see
[Device agent configuration](device-configuration.md).

Kubernetes maps these paths into one persistent volume under `/data`
instead; see [Data formats and states](state-and-data.md).

!!! warning "`/etc/iris` is not wholly encrypted"
    Only the `.age` files on that volume are encrypted at rest. `audit.jsonl`
    is plaintext JSONL and carries Console usernames, device ids, and every
    settings and onboarding action. Treat a snapshot or off-box copy of
    `/etc/iris` as sensitive.

None of these paths is mounted into the Console. Its only server-side inputs
are the public management CA and the management-credential files, read-only.

### TLS trust and console certificate

The Console's *Settings → TLS & trust* page manages these through the
management API.

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_GUI_CERT` | Server: `/run/iris/tls/gui-cert.pem`; Compose Console: `/run/iris-console/cert.pem` | The server rebuilds a custom identity in its tmpfs. The Console fetches custom identities through the management API. |
| `IRIS_TRUST_DIR` | `/etc/iris/tls/trust` | Durable directory of installed root CA files. |
| `IRIS_CA_BUNDLE` | `/run/iris/tls/ca-bundle.pem` | Runtime concatenation of the trust directory, rebuilt on every trust change. |

The Console certificate override persists as `/etc/iris/tls/gui-crt.pem` plus
the age-encrypted `/etc/iris/tls/gui-key.pem.age`; if it fails to decrypt or
does not match, the Console falls back to the default identity. Public CA
download settings live in `$IRIS_STATE/ca-trust-settings.json`.

### Image path variables

The server reads images from two places; the difference decides what a
delete removes and what an import offers.

| Variable | Default | Role |
| --- | --- | --- |
| `IRIS_IMAGE_ROOT` | `/opt/images` | Host directory holding images you staged yourself. Bind-mounted read-only. |
| `IMAGES_ROOT` | `/opt/images` | Container-side path of that read-only bind. Scanned for importable images. |
| `IRIS_IMAGES_DIR` | `/var/lib/iris-images` | The uploads volume, where a Console upload lands. The only directory a catalog delete unlinks from. |
| `IMAGES_DIR` | `/opt/images/iosxe/c9300` | Fallback seed directory for a torrent whose image is not under either root. |

The host tree behind `IRIS_IMAGE_ROOT` must be readable by the container's
runtime user.

### Telemetry variables

External telemetry is off by default. IRIS emits OpenTelemetry (OTLP); you
choose the collector and backend. See
[Export telemetry](../user-guide/telemetry-export.md).

| Variable | Default | Effect |
| --- | --- | --- |
| `IRIS_OBSERVABILITY` | unset (off) | `1`, `true`, `yes`, or `on` turns on the external observability surface. A Console override takes precedence for OTLP export. |
| `IRIS_OTLP_ENDPOINT` | unset | OTLP/HTTP base endpoint of your collector, for example `https://collector.example.com:4318`. |
| `IRIS_METRICS_PORT` | `9101` | Port for the telemetry listener. `0` disables it. |
| `IRIS_METRICS_HOST` | `0.0.0.0` | Bind host for the telemetry listener. Bind it to `127.0.0.1` when nothing external scrapes it. |
| `IRIS_SWARM_URL` | `https://127.0.0.1:9101/swarm` | Where the management process fetches swarm state, using the management bearer. |
| `IRIS_OTLP_HEADERS` | unset | Comma-separated `Name=Value` headers attached to every OTLP request. |
| `IRIS_OTLP_HEADERS_FILE` | `/run/secrets/iris_otlp_headers` (Compose) | Reads the header specification from a file instead of the environment. `IRIS_OTLP_HEADERS` wins when both are set. |

!!! note "Host interpolation and container variables are different"
    `IRIS_OBSERVABILITY_TOKEN_FILE_HOST`, its previous-token counterpart, and
    `IRIS_OTLP_HEADERS_FILE_HOST` are host-side Compose variables. Compose
    turns them into fixed container paths; it does not pass the host paths
    into the process.

## SSH variables

Every SSH session the server or an installer opens verifies the peer through
one shared policy:

| Setting | Behavior |
| --- | --- |
| `IRIS_SSH_HOST_KEY="<type> <base64>"` | Pin exactly that key for the peer. |
| `IRIS_SSH_KNOWN_HOSTS=<path>` | Strict verification against that file. |
| Neither set (default) | Accept a new key on first contact, recorded under `$IRIS_STATE/ssh`. Every later session must present the same key. |
| `IRIS_SSH_LEGACY=1` | Opt in to SHA-1 key exchange, `ssh-rsa`, and CBC ciphers for older IOS-XE images. Off by default. |

The device agent's own SSH-to-self channel is a separate, opt-in setting; see
[Device agent configuration](device-configuration.md).

## API admission limits

The management server can enforce one shared request budget across every
Console user, session, and Console host.

| Variable | Effect |
| --- | --- |
| `IRIS_API_RATE_TOTAL`, `IRIS_API_BURST_TOTAL` | Requests per second across all Console API traffic, and its burst capacity (default burst: one). `0` rate disables the budget. |
| `IRIS_API_RATE_READ`, `IRIS_API_BURST_READ` | Narrower rate and burst budget for read requests only. |
| `IRIS_API_RATE_WRITE`, `IRIS_API_BURST_WRITE` | Narrower rate and burst budget for write requests only. |

Restart the server after changing any of these. Device-facing tracker,
artifact, and catalog traffic is outside this limit. See
[Console API](console-api.md).

## Build-time variables

These affect only how the device packages are built, not a running
deployment. See
[Build and publish the device packages](../install/device-packages.md#embedded-agent-packages).

| Variable | Effect |
| --- | --- |
| `IRIS_FORCE_DEVICE_IMAGE_BUILD` | `1` rebuilds the device image even when the existing archive already holds the same version. |
| `IRIS_DEVICE_IMAGE_OCI` | Output path for the device image archive. Point it at a new path to keep the old archive. |
| `IRIS_REQUIRE_FRESH_AGENT` | `1` fails a package build that is missing agent or packaging commits from `main`, instead of only warning. |
| `IRIS_ALLOW_STALE_AGENT_ACK` | `1` acknowledges building an older agent version on purpose. |

## Deployment settings for separate hosts

[Install on separate Docker hosts](../install/separate-docker-hosts.md)
splits these across the server host and the Console host. Tokens and private
keys stay in the provisioned files; the environment only names their
directory paths.

Also set, as documented above: `COMPOSE_PROJECT_NAME` (both hosts),
`IRIS_HOST_IP` and `IRIS_CONSOLE_URL` (server), `IRIS_AGE_KEY_FILE_HOST` and
`IRIS_AGE_RECIPIENTS` (server), `IRIS_IMAGE_ROOT` and
`IRIS_ARTIFACTS_HOST_DIR` (server), and `IRIS_GUI_PUBLISH` (Console).

| Variable | Host | Meaning |
| --- | --- | --- |
| `IRIS_MANAGEMENT_BIND_IP` | Server | Private host address publishing TCP 9443. |
| `IRIS_MANAGEMENT_TLS_DIR` | Server | Read-only directory with `tls.crt` and `tls.key` for the management listener. |
| `IRIS_TIER_AUTH_DIR` | Both | Local directory holding the token files in [Credential file formats](#credential-file-formats). |
| `IRIS_MANAGEMENT_API_URL` | Console | HTTPS server management endpoint, normally port 9443; its name must match the certificate. |
| `IRIS_CONSOLE_BIND_IP` | Console | Host browser binding. |
| `IRIS_MANAGEMENT_CA_DIR` | Console | Read-only directory with the trusted management certificate, `ca.pem`. |
| `IRIS_CONSOLE_TLS_DIR` | Console | Read-only directory with the default browser `tls.crt` and `tls.key`. |

The Console mounts no server state volume. A missing provisioned directory
fails deployment instead of being silently created.

## Credential file formats

The management and observability bearer tokens use a two-file rotation
scheme, in `IRIS_TIER_AUTH_DIR` on a Docker host or in a Kubernetes secret:

- `current` (or `current.json`) holds the token that is checked first.
- `previous` (or `previous.json`) holds the prior token during a rotation
  overlap, empty before the first rotation.

Management files accept a raw token or a JSON record such as
`{"scope":"management","token":"<token>"}`. Tokens must be at least 32
bytes long. Observability files hold the raw token value so
Prometheus can read `current` as its `credentials_file`. Use distinct random
values for management and observability: a raw token has no embedded scope.
JSON records must match the listener's scope. See
[Rotate credentials and certificates](../admin-guide/rotations.md) and
[Install on Kubernetes](../install/kubernetes.md).
