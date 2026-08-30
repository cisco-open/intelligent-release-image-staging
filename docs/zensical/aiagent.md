<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# AI-guided PoC deployment

Use this guide for a first proof-of-concept or proof-of-value deployment. It is
not a production runbook: it does not cover high availability, scale hardening,
or change control.

IRIS is stage-only — see [Guardrails](security.md#guardrails).

## Before you start

Prepare a local, git-ignored credential file if an assistant will connect to
the server or devices:

```bash
cp creds/deploy.env.example creds/deploy.env
chmod 600 creds/deploy.env
```

Keep credentials in that file or enter them directly in the Console. Do not
paste passwords, tokens, private keys, or certificate material into a chat.

Gather these non-secret decisions before starting:

| Decision | Examples |
| --- | --- |
| Server runtime | Docker Compose for a single host, or Kubernetes for the single-replica alpha deployment. |
| Stable server address | A device-reachable IPv4 address, used in the server certificate and tracker announces. |
| Image source | A host path to the Cisco image (`.bin`) file. |
| Device inventory | Management IP, management type, VLAN or app addressing, and model for every device — see [Management type](management-type.md) for which columns each type needs. |
| Catalyst 9300 hosting mode | Guest Shell, or IOx on an SSD-equipped Catalyst 9300. |
| IOx package availability | `iris-arm64.tar` for IE-3400; `iris-amd64.tar` for Catalyst 9300 IOx. |
| IOS-XR device support | Cisco 8000 series routers use management type `xr-host` (platform `xr-appmgr`) and need `artifacts/iris-xr.rpm` built before onboarding — see step 6. |

Review [Network Ports and Flows](network-ports.md) before bringing up the
server. Devices need reachability to the server and to each other for the
private swarm.

## Assistant operating rules

Pick a deliberately economical assistant. This sequence is prescriptive
enough that a mid-tier, cost-efficient model — one that can follow a
document, run commands, and ask a question when unsure — completes it well;
a frontier-class model adds cost, not correctness, to a guided PoC. Save
the expensive tier for the moments that go off-script: an error this guide
does not cover, or a decision with real blast radius.

Give the assistant the following requirements when it helps operate a PoC:

```text
Operate IRIS as a stage-only system. Never install, activate, reload, change
boot variables, or replace a running image on a device.

Keep credentials and secrets out of chat, output, logs, source control, and
generated artifacts. Read local credentials only from creds/deploy.env when a
step needs them. If a required value is absent or a precondition is unclear,
stop and ask one plain question rather than guessing.

Before any destructive action, state exactly what it changes and obtain my
confirmation. Prefer the Web Console for inventory, onboarding, assignments,
and monitoring. Use the documented CLI only when the Console does not cover the
operation.

Use the current Zensical documentation in docs/zensical/. Follow Getting
Started for Docker Compose, Kubernetes for the Kubernetes alpha path, IOx App
for app-hosting prerequisites, and Network Ports and Flows for firewall rules.
At the end of every step, state the next action required from me.
```

## Guided sequence

1. **Choose the runtime.** Use [Getting Started](getting-started.md) for Docker
   Compose on one server. Use [Kubernetes](kubernetes.md) only when a
   single-replica Kubernetes deployment and its persistent volume are intended.
2. **Bring up the server.** Create the age identity outside the repository.
   Give uid `10001` the age key file and the host `artifacts/` directory — the
   container runs non-root and cannot chown host paths; see
   [Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).
   Then run
   `tools/start-compose-server.sh` on the Linux Compose host. It
   bootstraps encrypted state idempotently, starts Compose, waits for health,
   and builds/stages both supported IOx packages before any Console onboarding.
   Do not proceed until `https://<server-ip>:8080/` is reachable. The published
   port is overridable in Compose when `:8080` is already taken on the host —
   the container always listens on 8080 internally; substitute your published
   port in every URL in this guide.
3. **Create the Console admin.** Accept the self-signed certificate warning only
   for the expected server, sign in with the default first-run credential
   `iris` / `irisisgreat!`, and create the initial admin account. The default
   credential works only before an admin account exists. The next sign-in opens
   the first-run setup wizard at `#setup`: telemetry destination, stage host,
   device packages, and image verification (the Cisco source check against the
   published Known Good Values feed — enable its daily schedule here or later
   under Settings › Image verification; see [Validation](validation.md)). Any
   step can be skipped and resumed later — a banner keeps offering the
   unfinished ones, and Settings › Setup reports their state. The
   device-packages step is the same check as step 6 below; it cannot be
   completed from the console, because the console container has no Docker
   socket.
4. **Publish an image.** Upload through the Console, import a file that is
   already on the server from the Console **Import from disk** panel, or use
   `iris-publish` from inside the server container. Publishing creates catalog
   and torrent metadata; it does not change any device.
5. **Add devices.** Use the Console Devices page or its example CSV. Set each
   model when known. Leave `platform` blank for automatic selection, force
   `guestshell` for the standard C9300 path, `iox` only for a supported IOx
   device, `router` for a Catalyst 8000 (C8xxx, IOS-XE) router VPG deployment,
   or `xr-appmgr` for a Cisco 8000 series (IOS-XR) router — `xr-appmgr` rows
   use management type `xr-host` and app addressing instead of VLAN/SVI fields;
   see [Management type](management-type.md) for the full column matrix.
6. **Confirm device packages are ready.** The server bring-up step stages arm64
   `iris-arm64.tar` for IE-3400 and amd64 `iris-amd64.tar` for Catalyst 9300 IOx. A Catalyst 9300
   IOx deployment also requires a USB SSD and the Catalyst 9300 app-hosting interface.
   See [IOx App](iox.md). The XR package is **not** staged by the bring-up
   scripts: when Cisco 8000 (IOS-XR) devices are in scope, build it once with
   `tools/build-xr-package.sh --out artifacts/` on the Docker host (x86_64) so
   onboarding finds `artifacts/iris-xr.rpm` to push to the router.
   Rebuild all served packages — both IOx tars and the XR RPM — after **any
   agent code change**, not only after a server certificate rotation: packages
   are prebuilt, so a stale package silently ships the old agent.
   `tools/check-package-freshness.sh` verifies the IOx tars pin the live
   catalog certificate; it does not yet cover the XR RPM, so check that file's
   build date by hand.
7. **Onboard devices.** Start one-click onboarding from the Console and watch
   each job to completion. A Catalyst 9300 can use either Guest Shell or IOx; an
   explicit IOx choice with an unknown model fails before it touches the device.
   A successful lifecycle persists its configuration with `copy running-config
   startup-config`; a failed or partial lifecycle is not saved.
8. **Assign and observe.** Assign the published image, then use the Swarm and
   Monitoring areas to verify downloading, verification, staging, and seeding.
   For the proof-of-value figure, show how the bytes actually travelled — and
   only what was actually measured: the server measures its own origin-to-peer
   send rates, and per-peer receive attribution distinguishes bytes **traced**
   to a specific device from an honest **untraced** residue. State the figure
   as server-sent versus peer-carried using the attributed/unattributed
   counters, and never present the untraced residue as per-device fact. See
   [Telemetry export](telemetry-export.md) and the importable Splunk and
   Grafana boards under `docs/zensical/dashboards/`.
9. **Stop at staged.** Handoff installation, activation, reload, and boot
   management to the normal device-management process. They are outside IRIS.

## Reset or redeploy an existing PoC

To rerun the sequence on a host that already carries a deployment — a fresh
demo, a new operator walkthrough, or picking up a newer build — reset to a
first-run slate instead of deploying over live state:

1. Sync the newer source tree into the Compose project directory if this reset
   accompanies an upgrade, preserving the host's `server/.env` and any local
   `server/docker-compose.override.yml`.
2. From the `server/` Compose directory: `docker compose down` (never `down -v`
   — that deletes the state volumes with no backup).
3. Back up both state volumes before touching them — never skip this:

    ```bash
    STAMP=$(date +%Y%m%d-%H%M%S)
    for v in iris-state iris-config; do
      docker run --rm -v "$(docker compose config --format json | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["name"])')_${v}":/v \
        -v "$HOME/iris-backups":/b alpine \
        tar czf "/b/${v}-${STAMP}.tgz" -C /v .
    done
    ```

    (Compose prefixes volume names with the project name; the snippet resolves
    it. `docker volume ls` shows the exact names if in doubt.)
4. Remove the two state volumes (`docker volume rm <project>_iris-state
   <project>_iris-config`). Image files are untouched by this: they live under
   the host image root (`IRIS_IMAGE_ROOT`, default `/opt/images`), which is
   bind-mounted read-only, and reappear in the catalog through the Console
   **Import from disk** panel after setup.
5. Rebuild served agent packages if the agent changed since they were built
   (step 6 above — stale packages ship the old agent).
6. Bring the server back up with `tools/start-compose-server.sh` — not raw
   `docker compose up`. The entrypoint fails closed when the encrypted secrets
   file is missing from the freshly recreated config volume, and only the
   bring-up script's `iris-bootstrap` step recreates it (raw `up -d` produces a
   restart-looping container, never the first-run page). Then continue from
   step 3 of the guided sequence: the default first-run credential works again
   because no admin account exists in the fresh state.

The reset erases fleet rows, catalog entries and verification verdicts, the
image-verification schedule, deployment records, settings, credential
profiles, and the audit log (all captured in the backup). Devices themselves
are not touched: an agent already running on a device keeps running and
reporting. Re-add such a device to the inventory to reconnect it rather than
onboarding it again blindly — onboarding installs the agent, and the device
already has one.

## Completion record

For a PoC handoff, record the server runtime and address, version, image id,
device model/platform choice, staging target, Console audit entries, and whether
each device reached staged/seeding state. Do not record credentials or tokens.
