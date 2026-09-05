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
| Image source | A host path to a Cisco `.bin`, `.iso`, `.tar`, or `.rpm` software artifact. |
| Device inventory | Management IP, management type, VLAN or app addressing, and model for every device — see [Management type](management-type.md) for which columns each type needs. |
| Catalyst 9300 hosting mode | Guest Shell, or IOx on an SSD-equipped Catalyst 9300. |
| IOx package availability | `iris-arm64.tar` for IE-3400; `iris-amd64.tar` for Catalyst 9300 IOx. |
| IOS-XR device support | Cisco 8000 series routers use management type `xr-host` (platform `xr-appmgr`) and need `artifacts/iris-xr.rpm` built before onboarding — see step 6. |

Review [Network Ports and Flows](network-ports.md) before bringing up the
server. Devices need reachability to the server and to each other for the
private swarm.

### Settings that fail closed

Several controls refuse to guess rather than doing something unsafe. Each
stops with a message naming the variable, so the failure is legible, but
knowing them in advance saves a stalled PoC:

| You see | Why | What to set |
| --- | --- | --- |
| The console refuses to start and exits rather than serving plain HTTP | A console served over HTTP puts the operator password on the wire in clear text | Provide a certificate (the normal path), or set `IRIS_GUI_ALLOW_PLAINTEXT=1` to accept the risk deliberately on an isolated lab network |
| A device refuses the SSH connection, naming unsupported algorithms | SHA-1 key exchange and `ssh-rsa` host keys require explicit opt-in | `IRIS_SSH_LEGACY=1`, only when the device cannot offer stronger algorithms |
| A device's SSH host key does not match the one recorded on first contact | The device was re-imaged or replaced, or the address now answers to a different box | Confirm the device's identity, then use **Forget SSH host key** in its Console drawer before onboarding again |
| Routed Guest Shell onboarding leaves the new interface out of your routing domain | IRIS applies a routing protocol only when configured | Set the device's `svi_igp=isis` when the fabric runs IS-IS; leave blank to use the server's `SVI_IGP` default |
| IOx package staging aborts asking for an image digest | The cross-architecture emulation helper runs privileged, so it is pinned by digest rather than a moving tag | `BINFMT_IMAGE_DIGEST` to the audited digest, or preconfigure emulation on the host |

Set `IRIS_GUI_ALLOW_PLAINTEXT`, `IRIS_SSH_LEGACY`, and `SVI_IGP` in
`server/.env`. Export `BINFMT_IMAGE_DIGEST` in the Docker host's shell before
running the package helper; it is a build setting, not a Compose service setting.

## Assistant operating rules

Use an assistant that can read the repository, run the documented commands,
and report failures accurately. Review its device targets and results as you
would for a manual deployment.

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
2. **Bring up the server.** Complete [Getting Started → Configure the
   server](getting-started.md#configure-the-server): create the age identity
   outside the repository and export its host path. Give uid `10001` that file
   and the host `artifacts/` directory — the container runs non-root and cannot chown host paths; see
   [Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).
   Then run
   `tools/start-compose-server.sh` on the Linux Compose host. It
   bootstraps encrypted state idempotently, starts Compose, waits for health,
   and builds/stages both supported IOx packages before any Console onboarding.
   Do not proceed until `https://<server-ip>:8080/` is reachable. The published
   port is overridable in Compose when `:8080` is already taken on the host —
   the container always listens on 8080 internally; substitute your published
   port in every URL in this guide.
3. **Create the Console admin immediately, before exposing it beyond the trusted
   management network.** Whoever reaches a brand-new Console first can claim
   the administrator account. Accept the self-signed certificate warning only
   for the expected server, sign in with the default first-run credential
   `iris` / `irisisgreat!`, and create the initial admin account. That login
   creates no session: it returns a one-use setup grant that expires after ten
   minutes. Creating the administrator permanently ends this special behavior;
   the pair is then checked only against the stored administrator credentials
   and normally fails. The next sign-in opens
   the first-run setup wizard at `#setup` for telemetry, device packages, and
   image verification against Cisco's Known Good Values feed. Configure the
   verification schedule, run a refresh, or import a feed file for an offline
   deployment. Skipped steps can be resumed under **Settings → Setup**; a
   configured schedule is separate from a successful verification run.
   See [Validation](validation.md). Build device packages on the Docker host
   as described in step 6, then use **Re-check** in the Console to update
   their setup status.
4. **Publish an image.** Upload through the Console, import a file that is
   already on the server from the Console **Import from disk** panel, or use
   `iris-publish` from inside the server container. Publishing creates catalog
   and torrent metadata; it does not change any device.
5. **Add devices.** Use the Console Devices page or its example CSV. Choose the
   management type to set which network fields appear, then the agent install.
   Model is optional free text; a recognized model narrows installer choices
   without changing the management type. Choose **Guest
   Shell** for the standard C9300 path or a Catalyst 8000 (C8xxx, IOS-XE) router
   VPG deployment, **IOx** for a supported IOx device, or **XR appmgr container** for a
   Cisco 8000 series (IOS-XR) router. CSV/API platform values remain
   `guestshell`, `router`, `iox`, and `xr-appmgr`, respectively. `xr-appmgr` rows
   use management type `xr-host` and the router's own network; leave app,
   VLAN/SVI, VPG, and NAT fields empty. See [Management type](management-type.md)
   for the full column matrix.
6. **Confirm device packages are ready.** The server bring-up step stages arm64
   `iris-arm64.tar` for IE-3400 and amd64 `iris-amd64.tar` for Catalyst 9300 IOx. A Catalyst 9300
   IOx deployment also requires a USB SSD and the Catalyst 9300 app-hosting interface.
   See [IOx App](iox.md). The XR package is **not** staged by the bring-up
   scripts: when Cisco 8000 (IOS-XR) devices are in scope, run
   `tools/build-xr-package.sh --out artifacts/` from the repository root on
   the Docker host (x86_64). Onboarding then finds `artifacts/iris-xr.rpm` to
   push to the router.
   The canonical OCI archive, both IOx tars, and the XR RPM are
   deployment-neutral: none contains the server certificate, and none needs
   `CATALOG_PEM` at build time. IOx onboarding supplies the current public
   certificate as application data; XR onboarding copies it to the router's
   `harddisk:` beside the RPM. After certificate rotation, re-onboard deployed
   devices so they receive the new trust anchor; do not rebuild packages just
   because the certificate changed.
   Rebuild all served packages after **any source included in a device package
   changes**: they are prebuilt, so otherwise onboarding silently ships old
   code. A change under `device/agent/` also requires a fresh Guest Shell
   bundle. The Console/API setup status reports package readiness from the
   wrapper bytes and adjacent build-provenance manifest. It does not infer
   readiness from certificate age, inspect package contents, or validate a
   native package signature. Its separate certificate check only confirms that
   the live server and the public copy handed out during onboarding agree.
   `tools/check-package-freshness.sh` provides the same checks from the Docker
   host; a green result does not compare the package with the current checkout
   or confirm that an already-deployed device was upgraded. Keep native signed
   wrappers unchanged: the IOx rebake helper refuses packages containing
   signature metadata. See [Artifact handling](iox.md#artifact-handling) for
   publishing signed output with its matching provenance manifest.
   If an existing canonical OCI archive has older source at the same version,
   use a new `IRIS_DEVICE_IMAGE_OCI` output path for both wrapper builds or
   explicitly rebuild it with `IRIS_FORCE_DEVICE_IMAGE_BUILD=1`. See
   [Embedded agent packages](development.md#embedded-agent-packages).
7. **Onboard devices.** Start one-click onboarding from the Console and watch
   each job to completion. A Catalyst 9300 can use either Guest Shell or IOx; an
   explicit IOx choice with an unknown model fails before it touches the device.
   IOS-XE installers save successful configuration changes with
   `copy running-config startup-config`; they do not save a failed or partial
   lifecycle. XR uses appmgr instead of IOS-XE configuration commands.
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

For a routine upgrade, retain the existing state and rebuild the server and
Console. Rebuild device packages if their source changed, then follow
[Redeploying agents](operations.md#redeploying-agents-after-an-artifact-rebuild).

Use the reset below only when you intend to discard the existing deployment
and repeat first-run setup. Undeploy agents while their deployment records and
credentials are still available, then back up the stopped server:

1. Sync the newer source tree into the Compose project directory if this reset
   accompanies an upgrade, preserving the host's `server/.env` and any local
   `server/docker-compose.override.yml`.
2. From the `server/` Compose directory: `docker compose down` (never `down -v`
   — that deletes the state volumes with no backup).
3. Back up every named volume before touching it — never skip this. The tier
   credential and management-CA volumes are narrow, but they are still part of
   a restorable two-container deployment:

    ```bash
    STAMP=$(date +%Y%m%d-%H%M%S)
    for v in iris-state iris-config iris-images iris-tier-auth iris-management-ca; do
      docker run --rm -v "$(docker compose config --format json | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["name"])')_${v}":/v \
        -v "$HOME/iris-backups":/b alpine \
        tar czf "/b/${v}-${STAMP}.tgz" -C /v .
    done
    ```

    (Compose prefixes volume names with the project name; the snippet resolves
    it. `docker volume ls` shows the exact names if in doubt.)
4. Remove `iris-state`, `iris-config`, `iris-tier-auth`, and
   `iris-management-ca` for a genuine first-run stack. The `iris-images`
   volume holds images that were **uploaded through the Console** — keep it
   (and know it is in your backup) if you want those payloads, or remove it as
   well for an entirely empty upload library. Images imported from the host
   image root (`IRIS_IMAGE_ROOT`, default `/opt/images`, bind-mounted read-only)
   are untouched either way and reappear through the Console **Import from
   disk** panel after setup.
5. Do not treat a deployment-neutral package as stale merely because the wipe
   minted a new server certificate. The canonical OCI archive, both IOx tars,
   and the XR RPM remain reusable when their source is unchanged. The bring-up
   path stages the new public certificate separately; subsequent IOx and XR
   onboarding delivers it at runtime. If this reset also moved to changed
   agent/container source, rebuild every device package before onboarding.
6. Bring the stack back up with `tools/start-compose-server.sh` — not raw
   `docker compose up`. The entrypoint fails closed when the encrypted secrets
   file is missing from the freshly recreated config volume, and only the
   bring-up script's `iris-bootstrap` step recreates it (raw `up -d` produces a
   restart-looping container, never the first-run page). Then continue from
   step 3 of the guided sequence: the default first-run credential works again
   because no admin account exists in the fresh state.

Adding a recovery recipient does **not** need any of this. `iris-bootstrap
--add-recipient` and `--rekey` re-encrypt the existing state in place, keeping
every device credential, the admin account and the pinned certificate.
`--force` is the one that regenerates them all, and it refuses to run
without `--yes` and names what it would destroy first.

The reset erases fleet rows, catalog entries and verification verdicts, the
image-verification schedule, deployment records, settings, credential
profiles, and the audit log (all captured in the backup). Devices themselves
are not touched, but agents deployed before the reset are **orphaned by it**:
they pinned the old server certificate and their enrollment tokens died with
the state, so they cannot reconnect on their own. If agents were not undeployed
before the reset, remove their old IRIS footprint using the documented
recovery procedure before onboarding again. Onboarding refuses an existing
footprint. Restoring the previous deployment instead requires its matching
state and credentials as well as its TLS material; restoring only the old
certificate does not restore enrollment tokens.

## Completion record

For a PoC handoff, record the server runtime and address, version, image id,
device model/platform choice, staging target, Console audit entries, and whether
each device reached staged/seeding state. Do not record credentials or tokens.
