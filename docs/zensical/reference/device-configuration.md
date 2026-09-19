<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Device agent configuration

Environment variables, configuration keys, installer variables, files, and
log messages for the device agent on Guest Shell, IOx, and IOS-XR appmgr. See
[Server configuration](server-configuration.md) for the server container's
variables.

## Device container environment variables

These variables configure the unified IOx and IOS-XR appmgr image. Installers
set the identity fields and the platform selector; everything else falls back
to its default. Guest Shell runs the same agent from a bundle started by
`bootstrap.sh` and an EEM applet, so rows marked Guest Shell or router apply
to it too, once per [tick](glossary.md#tick).

| Variable | Default | Platform | Effect |
| --- | --- | --- | --- |
| `IRIS_DEVICE_PLATFORM` | required: `iox` or `xr-appmgr` | IOx, XR | Selects the storage and runtime profile. `iox` uses local storage; `xr-appmgr` always uses `harddisk:`. A missing or unknown value stops the container. |
| `IRIS_CATALOG_URL` | required on first start | IOx, XR | The catalog's HTTPS base URL. Later starts read it from persisted configuration. |
| `IRIS_CATALOG_TOKEN` | required on first start | IOx, XR | The device's catalog enrollment token, stored in the mode-0600 persistent configuration. |
| `IRIS_DEVICE_ID` | required on first start | IOx, XR | The device's catalog identity. Letters, digits, `.`, `_`, `:`, and `-` only. |
| `CAF_APP_APPDATA_DIR` | required, set by CAF | IOx only | Holds the runtime-delivered `iris-catalog.pem` certificate. XR uses `/hostmount/iris-catalog.pem` instead. |
| `IRIS_TELEMETRY` | `on` | IOx, XR | Turns device reports on or off. |
| `IRIS_TELEMETRY_STREAM` | `off` | IOx, XR | Turns on live transfer samples. See [Transfer streaming by platform](#transfer-streaming-by-platform). |
| `IRIS_TICK_SECONDS` | `60` | IOx, XR | The mechanical tick interval, 1 to 86400 seconds. Separate from the signed logical `catalog_tick_s` cadence; every tick still reasserts policy and sends a heartbeat. |
| `IRIS_TICK_JITTER_PCT` / `IRIS_STARTUP_JITTER` | `10` / `1` (on) | IOx, XR | Spread ordinary ticks (as a percent of `IRIS_TICK_SECONDS`) and the first tick (across that window). Set `IRIS_STARTUP_JITTER` to `0` to turn its spread off. |
| `IRIS_TICK_BACKOFF_MAX` | `600` seconds | IOx, XR, Guest Shell, router | The cap on backoff after a failed tick. |
| `IRIS_TICK_JITTER_MAX` | `8` seconds | Guest Shell, router | The random pause `bootstrap.sh` takes before each tick, 0 up to one second less than this value. |
| `IRIS_RPC_PORT` | `6800` | IOx, XR | The local aria2 JSON-RPC port, 1 to 65535. |
| `IRIS_MAX_PEERS` / `IRIS_MAX_CONCURRENT` | launcher fallback `10` / `100` | IOx, XR | Provisional peer and concurrency limits, 1 to 1000, until the first successful tick sets verified or default policy. |
| `CAF_APP_PERSISTENT_DIR` | `/data` | IOx only | The CAF persistent root. The agent keeps its work under `<root>/iris`. |
| `IRIS_TARGET_FS` | unset (auto-detect) | IOx only | An optional preferred IOS filesystem, such as `sdflash:`. Must be writable and not `crashinfo:`. |
| `IRIS_SHARE_DIR` / `IRIS_SHARE_IOS_PATH` | `/mnt/share` / `usbflash1:iox_host_data_share` | IOx only | The container-side and IOS-side paths of the optional host-data share. A failing share stops placement. |
| `IRIS_DEVICE_SSH_HOST` | required on first start | IOx only | The IOS address the agent uses to SSH to itself, for read-only discovery and staged-file placement. |
| `IRIS_DEVICE_SSH_USER` / `IRIS_DEVICE_SSH_PASS` | required on first start | IOx only | The SSH-to-self credential, kept in the owner-only configuration file. |
| `IRIS_DEVICE_SSH_ENABLE` / `IRIS_DEVICE_SSH_PORT` | the SSH password / `22` | IOx only | An optional enable secret, and the SSH-to-self port (1 to 65535). |
| `IRIS_DEVICE_SSH_KNOWN_HOSTS` | unset | IOx only | An optional `known_hosts` path. When set, SSH and SCP check the host key strictly. |
| `IRIS_MODEL` / `IRIS_VERSION` | unset | XR only | Optional device model and version strings, recorded for observation. |
| `IRIS_LOG` | `off` | IOx, XR, Guest Shell | Turns on the aria2 transfer log (`on`, `1`, `true`, or `yes`). IOx and XR cap it at 50 MiB; Guest Shell trims it on a schedule. |

!!! warning
    Keep `IRIS_LOG` off in normal operation. It adds flash writes and does not
    control the device's `%IRIS-6-` status messages.

IOS-XR appmgr also keeps its own container log (three 1 MiB files, captured
even with `IRIS_LOG` off): `show appmgr application name iris logs`.

## Device agent configuration keys

The agent also reads `key = value` lines from a persistent file,
`iris-agent.conf`:

- Guest Shell: `/flash/guest-share/iris/iris-agent.conf` by default.
- IOx: `<CAF_APP_PERSISTENT_DIR>/iris/iris-agent.conf`, `/data/iris/iris-agent.conf` by default.
- IOS-XR appmgr: `/hostmount/iris-work/iris-agent.conf`, on the `harddisk:` bind mount.

| Key | Default | Effect |
| --- | --- | --- |
| `device_platform` | required in a device container | The persisted copy of `IRIS_DEVICE_PLATFORM` (`iox` or `xr-appmgr`). Guest Shell does not use this key. |
| `peer_tls_mode` | `disabled` | `required` turns on peer TLS for every transfer, with automatic certificate enrollment and renewal. It needs matching peers and server mode on. |
| `catalog_ca` | platform-derived path | The certificate the agent uses for catalog calls and HTTPS tracker announces. A missing or invalid certificate stops the container from starting. |
| `device_ssh_known_hosts` | unset | A `known_hosts` path pinning the device's SSH host key, for the IOx agent's SSH-to-self connection only. When set, SSH and SCP check the host key strictly. |
| `telemetry_stream` | `off` | Turns on live transfer-sample streaming; see [Transfer streaming by platform](#transfer-streaming-by-platform). Needs `telemetry` on too. |
| `iris_log` | unset (off) | Guest Shell's persisted opt-in for the aria2 transfer log. `bootstrap.sh` reads it every tick and exports it as `IRIS_LOG`. Non-alphanumeric values are dropped; the default applies. |
| `rpc_port` | `6800` | The local aria2 JSON-RPC port, also read by `bootstrap.sh` for its own aria2 launch line. Out-of-range or non-numeric values are dropped; the default applies. |
| `max_peers` | legacy only | Parsed but ignored, kept for upgrade compatibility. Current policy uses the bound in the environment variable table above. |

## IOS-XR installer connection variables

The IOS-XR installer paces its SSH connections so it does not trip the
router's connection rate limit. See
[Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md).

| Variable | Default | Effect |
| --- | --- | --- |
| `XR_SSH_CONNECT_DELAY` | 2 seconds, 0 to 60 | The pause the installer adds between SSH connections during onboarding. |
| `XR_SCP_ATTEMPTS` | not published here | How many times the installer retries a registration transport failure. |
| `XR_SCP_RETRY_SECONDS` | not published here | How long the installer waits between those retries. |
| `IRIS_ARTIFACT_URL` | unset (derived from the catalog URL) | Overrides the HTTPS origin the installer fetches `iris-xr.rpm` and the catalog certificate from. Set it when the artifact server is reachable on a different hostname than the catalog. |
| `IRIS_ARTIFACTS_PORT` | `8000` | The artifact server's port, used when `IRIS_ARTIFACT_URL` is not set. |

It checks the source table before repeating an interrupted registration and
includes the SSH error in the job log. Package registration and its
confirming query share a session. A package rejection with a successful
transport is reported for diagnosis rather than retried as a connection
failure.

## Instruction files on each platform

Each agent keeps its instruction, the signed message that tells a device
which images to stage and how, in one directory:

| Platform | Instruction work directory | Public signer and root trust directory |
| --- | --- | --- |
| Guest Shell / router | `stage_dir`, normally `/flash/guest-share/iris` | The same directory |
| IOx | `stage_dir`, derived from `CAF_APP_PERSISTENT_DIR`: `/data/iris` by default (`/iox_data/iris` where CAF supplies that mount) | `/opt/iris/agent` in the image |
| IOS-XR appmgr | `/hostmount/iris-work`, visible in IOS as `harddisk:iris-work/` | `/opt/iris/agent` in the image |

Each directory holds the agent's instruction and state files, including
`iris-instructions.lkg`. See [Data formats and states](state-and-data.md) for
the full file list.

## Transfer streaming by platform

Transfer streaming is a live, fleet-wide view of in-flight transfers, off by
default. See [Monitor transfers and device reports](../user-guide/monitoring.md)
for what it shows once it is on.

| Platform | Delivery |
| --- | --- |
| Guest Shell / router | `TELEMETRY_STREAM=on` in the installer environment, or the Console's *Telemetry streaming* checkbox. |
| IOx | `IRIS_TELEMETRY_STREAM=on` at deploy time. A redeploy updates the persisted configuration. |
| IOS-XR appmgr | `IRIS_TELEMETRY_STREAM=on` at deploy time, or the Console checkbox. Re-onboard the device to apply a change. |

## Device log messages

The agent writes these mnemonics to the device log.

| Message | Meaning |
| --- | --- |
| `RESEED` | The agent's aria2 session was recreated, for example by a container restart, and it re-added an already-staged image without downloading it again. |
| `RESEED-DEFERRED` | A `RESEED` attempt could not fetch metadata or re-add the transfer. The agent still reports the image staged and retries on the next tick. |
| `RECLAIM-DEFERRED` / `CLEANUP-PENDING` | The agent could not read the running image or the `BOOT` variable this tick, so it left a parked image's storage-root copy in place. Parking keeps an unassigned image on the device in case it is assigned again; see [What happens to an image you unassign](../user-guide/assignments.md#unassigned-image-park). It retries on a later successful tick. |
| `MAX-PEERS-IGNORED` | The device's legacy `max_peers` configuration key was present and parsed, then ignored, once. |
