<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# AI-guided PoC deployment

Use this guide to stage an image with an assistant helping run the deployment.
Docker on one host is the default: the server and Console are separate
containers on that host. Docker on separate hosts and Kubernetes are also
supported choices. The device workflow is the same for all three.

IRIS distributes, verifies, and stages images. It never installs, activates,
reloads, or changes boot variables. See [Guardrails](security.md#guardrails).

## Before you start

Prepare a local, git-ignored credential file if an assistant will connect to
the server or devices:

```bash
cp creds/deploy.env.example creds/deploy.env
chmod 600 creds/deploy.env
```

Keep credentials in that file or enter them directly in the Console. Do not
paste passwords, tokens, or private keys into a chat.

Gather these non-secret decisions:

| Decision | What to record |
| --- | --- |
| Deployment layout | One Docker host, separate Docker hosts, or Kubernetes. |
| Server address | Stable device-reachable IPv4 address for the catalog, tracker, artifacts, and origin seeder. |
| Console address | Browser HTTPS URL and published port. On one Docker host it normally uses the server address on 8080; a separate Console has its own address. |
| Private management connection | For separate Docker hosts, the server's private bind address and the HTTPS hostname or IP the Console will use on 9443. |
| Image source | A server-host path or upload source for a Cisco `.bin`, `.iso`, `.tar`, or `.rpm` file. |
| Device inventory | Management IP, management type, network fields, and optional model for every device. See [Management type](management-type.md). |
| Device agent | Guest Shell, IOx, or XR appmgr. A Catalyst 9300 can use Guest Shell or IOx with supported app-hosting storage. |
| Package inputs | Both architecture binaries and required build tools for IOx/XR; the server must serve the packages before onboarding. |

Check out the same IRIS version on every deployment host. For a server already
in use, identify its Compose project, container names, state volumes, age
identity, and artifact directory before changing anything. Preserve those
settings and data unless a reset is explicitly part of the task.

## Choose the layout

| Layout | Deployment files | Connection between containers |
| --- | --- | --- |
| Docker on one host — default | `server/docker-compose.yml`, configured by `server/.env` or exported variables | Docker DNS resolves `iris`; the Console calls `https://iris:9443`. Port 9443 stays unpublished. |
| Docker on separate hosts | `server/docker-compose.server.yml` with `server/server.env`; `server/docker-compose.console.yml` with `server/console.env` | Private HTTPS 9443, a scoped file-mounted token, and verified management TLS. Each host has its own local files. |
| Kubernetes | `kubernetes/` manifests and environment examples | Internal management Service on 9443, restricted by NetworkPolicy; credentials and certificates come from Secrets. |

All layouts have one server and one Console instance. Separating the Console
from the server does not cluster the tracker, catalog, or seeder.

Review [Network ports and flows](network-ports.md). Devices contact the server
and each other for swarm traffic. The server drives onboarding over SSH/SCP.
Operators contact the Console; they do not need direct management API access.

### Settings that stop deployment

| Symptom | Check |
| --- | --- |
| Console exits before serving HTTPS | Its browser certificate and key must be readable and form a matching pair. The one-host stack fetches its default through the management API; separate-host Docker and Kubernetes mount their own default identity. |
| Console loads but API requests return 503 | Server health, the private management route and DNS, the management certificate and CA, and matching scoped token files. Local Console readiness alone does not prove server access. |
| Device SSH reports unsupported algorithms | Set `IRIS_SSH_LEGACY=1` only when the device cannot offer stronger algorithms. |
| Device SSH host key differs from the saved key | Confirm the device identity before using **Forget SSH host key** in its Console drawer. |
| Routed Guest Shell needs IS-IS on its new interface | Set the device's `svi_igp=isis`, or the server's `SVI_IGP=isis` default, when that matches the fabric. |
| IOx staging requests an emulation image digest | Export the audited `BINFMT_IMAGE_DIGEST` on the package-build host, or configure ARM64 emulation there beforehand. |

Put server runtime settings such as `IRIS_SSH_LEGACY` and `SVI_IGP` in the
selected server environment file. For Kubernetes, use
`kubernetes/iris-seed-server.env`. Package-build variables belong in the
build host's shell. Tokens and private keys stay in protected files.

## Assistant operating rules

Give the assistant these requirements along with the chosen layout:

```text
Operate IRIS as a stage-only system. Never install, activate, reload, change
boot variables, or replace the running software on a device.

Read CLAUDE.md and the current docs/zensical/ guide for the selected layout.
Use Getting Started for Docker on one host, Docker on Separate Hosts for
independent Docker hosts, or Kubernetes for the cluster manifests. Keep the
same layout, Compose project, environment files, and container names in every
command. Preserve existing server state and device assignments.

Keep credentials and secrets out of chat, command output, logs, and source
control. Read local credentials only when a step needs them. Do not copy
server state, the age identity, or the management private key to the Console.

Continue work within the authorized scope. Ask for a missing value only when
it prevents a safe next step. Obtain approval for a destructive action unless
it has already been explicitly authorized. Use the Console for ordinary
inventory, image, onboarding, assignment, and monitoring work.

Verify the chosen layout and report observed results. Distinguish container
health from an authenticated Console request, and distinguish torrent seeding
from verified staging. Record any untested behavior without claiming success.
```

## Start the selected deployment

### Docker on one host

Follow [Getting Started](getting-started.md) to create the age identity outside
Git and configure `IRIS_HOST_IP`, `IRIS_AGE_KEY_FILE_HOST`, and
`IRIS_AGE_RECIPIENTS` in `server/.env`. Give uid 10001 access to the key, image
root, artifacts, and volumes as documented there. From the repository root:

```bash
set -a
. server/.env
set +a
tools/get-aria2c.sh amd64
tools/start-compose-server.sh
docker compose -f server/docker-compose.yml ps
```

The helper builds both server images, bootstraps a fresh encrypted store,
starts both services, and stages both IOx packages. An existing complete
store is preserved. If an IOx build prerequisite fails, the stack may be
running even though the helper exits nonzero; correct the prerequisite and
rerun `tools/provision-iox-packages.sh` before onboarding IOx devices.

Open `https://<server-ip>:8080/`, or the host port set by
`IRIS_GUI_PUBLISH`. A Guest Shell deployment can use the manual Compose
commands in [Getting Started](getting-started.md#start-the-server) without
building native packages. XR requires its RPM separately.

### Docker on separate hosts

Follow [Docker on separate hosts](docker-hosts.md) to prepare and deliver the
separate host bundles. The helper creates a management token, an independent
management certificate, and an independent browser certificate:

```bash
python3 tools/prepare-docker-hosts.py \
  --out "$HOME/.config/iris/docker-hosts" \
  --management-host iris-mgmt.example.com \
  --console-host console.example.com
```

Use your actual hostnames and a new output directory whose parent exists.
Deliver only each host's bundle through verified SSH and set its ownership to
uid/gid 10001. The full guide covers host paths, certificate trust, and file
permissions.

On the server host, copy `server/server.env.example` to `server/server.env`
and set the device-facing server IP, private management bind IP, full Console
URL, age identity and recipients, and local storage paths. From the repository
root, for a fresh server:

```bash
tools/get-aria2c.sh amd64
docker compose --env-file server/server.env \
  -f server/docker-compose.server.yml build --pull
docker compose --env-file server/server.env \
  -f server/docker-compose.server.yml run --rm iris iris-bootstrap
docker compose --env-file server/server.env \
  -f server/docker-compose.server.yml up -d
docker compose --env-file server/server.env \
  -f server/docker-compose.server.yml ps
```

For an existing server, preserve its project name, volumes, identity, and
paths; skip bootstrap. The standalone server file does not launch a Console.

On the Console host, copy `server/console.env.example` to
`server/console.env`. Set its browser bind address and port, the management
HTTPS URL, and its three local credential/certificate directories. Then:

```bash
docker compose --env-file server/console.env \
  -f server/docker-compose.console.yml build --pull
docker compose --env-file server/console.env \
  -f server/docker-compose.console.yml up -d
docker compose --env-file server/console.env \
  -f server/docker-compose.console.yml ps
```

Open the Console host's configured HTTPS URL. The Console can start while the
server is unavailable using its local browser identity; API requests return
503 until the authenticated server connection works. No server data volume
or age key belongs on the Console host. Build device packages on the server
host using the [package steps](docker-hosts.md#start-the-server-host).

### Kubernetes

Use a cluster with amd64 worker capacity, a suitable storage class,
LoadBalancer support, and enforced NetworkPolicy. Follow
[Kubernetes](kubernetes.md) for the complete configuration. For a small lab,
use the [K3s setup choices](kubernetes.md#small-lab-with-k3s); Docker can remain
on the same host with separate service addresses.

Configure IRIS:

1. Build the server and Console images from their Dockerfiles, publish them to
   a registry reachable by the nodes, and pin both digests in
   `kubernetes/kustomization.yaml`.
2. Configure `kubernetes/iris-seed-server.env` with the reserved device-facing
   Service address, age recipients, and full `IRIS_CONSOLE_URL`. Configure
   `kubernetes/iris-console.env` with the internal management URL. The public
   server and Console Services have independent addresses.
3. Configure the server PVC and Service exposure. Preserve device source IPs
   on the server Service and restrict the Console Service to operators.
   Keep management 9443 on its internal Service.
4. Provision the namespace, age identity, management and observability token
   pairs, management certificate, public management CA, and Console
   certificate using [Secrets and storage](kubernetes.md#secrets-and-storage).
   The management certificate covers the internal Service names; the browser
   certificate covers the external Console URL. Neither private key belongs
   in a ConfigMap or image.
   During token rotation, retain the previous value until both pods have the
   new current value and authenticated Console access passes. The Console can
   temporarily use the previous token, so readiness alone cannot confirm that
   both projections have updated.
5. Build the needed device packages and stage them with their manifests in
   the server's artifact storage before onboarding devices.

Apply the configured manifests and wait for both Deployments:

```bash
kubectl apply -k kubernetes
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console
```

Use the Console Service's browser address. It is independent of the server
Service address used by devices.

## Verify the deployment

Run these checks for the selected layout before onboarding. When verifying
both Docker options, use separate projects and data for each test, with
nonconflicting container names and host ports. See
[Running a second stack](server.md#running-a-second-stack-on-the-same-host).

| Check | Docker on one host | Docker on separate hosts |
| --- | --- | --- |
| Containers | Both services are healthy in the same Compose project. | Server and Console are healthy in their respective projects. |
| Management route | Console reaches `https://iris:9443` through its Docker network; no host port publishes 9443. | Console reaches the configured private HTTPS endpoint, with hostname and CA verification and matching token files. |
| Browser and API | Login, inventory, Settings, image import/upload, and job logs work through the published Console URL. | The same operations work through the Console host's URL. |
| Addresses and certificate | Settings shows the intended server IP, Console URL, and certificate actually served to the browser. | Settings distinguishes the device-facing server address from the Console URL and reports the Console's own browser certificate. |
| Server restart | The running Console remains locally ready and API requests recover when the server returns. | Also check that the Console starts with its local identity while the server is stopped, then recovers API access when it returns. |
| Storage | Only the server mounts state, images, artifacts, and encrypted configuration. | The Console host has only its scoped credential, public management trust, and default browser identity. |

Use an isolated test deployment for server outage checks when device work is
active. Check readiness and one authenticated API request after each restart.
For Kubernetes, use the corresponding checks in
[Health and operation](kubernetes.md#health-and-operation).

## Stage an image

1. **Create the administrator.** Open the configured Console URL from a trusted
   management network. Verify the expected browser certificate, then sign in
   with the first-run credential `iris` / `irisisgreat!` and create the admin.
   That first login returns a one-use setup grant valid for ten minutes; it
   does not create a session. The administrator account is stored on the
   server and ends first-run setup. See [Console first run](console.md#first-run).
2. **Complete setup.** Configure telemetry and image verification, and check
   **Settings → Device packages**. A verification schedule alone does not prove
   a successful verification run. Refresh Cisco's Bulk Hash feed or import a
   feed file for an offline deployment. See [Validation](validation.md).
3. **Publish an image.** Upload through the Console or use **Import from disk**
   for a file already on the server. Publishing hashes the file and creates
   catalog and torrent metadata; it does not change a device.
4. **Add devices.** Management type controls the network fields. Model is
   optional free text; a recognized model narrows installer choices without
   changing management type. Choose Guest Shell, IOx, or XR appmgr as
   appropriate. XR uses `xr-host` and the router's network, with app, VLAN/SVI,
   VPG, and NAT fields empty. See [Management type](management-type.md).
5. **Confirm packages.** IE-3400 IOx needs `iris-arm64.tar`; Catalyst 9300 IOx
   needs `iris-amd64.tar` and supported app-hosting storage. XR needs
   `iris-xr.rpm`. Serve each package with its matching provenance manifest.
   See [IOx App](iox.md) and
   [Embedded agent packages](development.md#embedded-agent-packages).
6. **Onboard.** Start one-click onboarding and watch each job to completion.
   Inspect failures before retrying. IRIS app/container lifecycle operations
   do not install or activate the staged operating-system image.
7. **Assign and observe.** Assign the image, then watch download, hash
   verification, final staging, and seeding. A tracker seeder can still be
   verifying or placing its file; confirm the device's final per-image staged
   state. Use [Telemetry export](telemetry-export.md) for origin/peer traffic
   measurements and their limits.
8. **Stop at staged.** Installation, activation, reload, and boot management
   belong to the operator's normal device-management process outside IRIS.

Device packages contain no deployment certificate. Onboarding supplies public
server trust separately; a device certificate rotation needs re-onboarding,
not a package rebuild. A shared-agent source change requires rebuilding the
Guest Shell bundle, both IOx packages, and the XR RPM before rollout. Package
readiness checks wrapper bytes and provenance; it does not prove those bytes
match newer source or validate a native signature.

## Maintenance and cleanup

Use the same deployment files, environment files, project names, and volume
paths for maintenance. Retain server data when rebuilding containers. Rebuild
and redeploy device agents when their source changes; see
[Redeploying agents](operations.md#redeploying-agents-after-an-artifact-rebuild).

Back up server state, encrypted configuration, uploaded images, and host
artifacts as described in [Backups](operations.md#backups). Keep the age
identity separately. A one-host stack also has local tier-token and management
CA volumes. Separate hosts have independent credential/TLS directories; back
up each on its owning host. Restoring only a certificate does not restore
device credentials or assignments.

A reset requires explicit authorization because it removes inventory,
assignments, deployment records, settings, and credentials. Undeploy agents
while their records and credentials are available, then back up before
removing any selected server data. Use the chosen topology's fresh-bootstrap
steps for the replacement. A Console relocation by itself does not require
resetting server state or onboarding devices again.

## Completion record

Record the IRIS version, deployment layout, each host's role and address,
Console URL, management endpoint, Compose projects or Kubernetes namespace,
and checks actually performed. For device work, include image ID,
model/agent choice, staging target, job result, and final per-image state.
List anything not verified. Keep credentials and tokens out of the record.
