<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# AI-guided PoC deployment

This page is the assistant's runbook: what to ask, what to check, what to run,
and what to report, for Docker on one host, Docker on separate hosts, and
Kubernetes. The device workflow is the same for all three.
[Getting Started](getting-started.md) is the same deployment written for a
person to read; use it for background, and use the commands here.

IRIS distributes, verifies, and stages images. It never installs, activates,
reloads, or changes boot variables. See [Guardrails](security.md#guardrails).

## If you are the assistant, start here

Ask the operator these four questions in one message and wait for the answers
before running anything. Do not guess a layout, and do not start a Docker
deployment because it is the default:

1. **Where should the deployment live?** Offer
   `/opt/iris/intelligent-release-image-staging` as the default. You create
   the directory and clone into it.
2. **Which layout — Docker on one host, Docker on separate hosts, or
   Kubernetes?** For separate hosts also ask for the Console host; for
   Kubernetes ask for the cluster context and a registry the nodes can pull
   from.
3. **Which device types will be onboarded** — Guest Shell, IOx on amd64
   (Catalyst 9300, Catalyst 8000V), IOx on arm64 (IE-3400 and other IE-3x00),
   IOS-XR appmgr, or none yet? This tells you what to onboard. Build every
   package regardless: a proof of concept prepares all of them, and
   [Supply the handed-in inputs](#supply-the-handed-in-inputs) is the
   assistant's own work, not the operator's.
4. **The server's device-reachable IPv4 address**, and the Console URL if it
   is not that address on port 8080.

Repeat the answers back, then [check the host](#check-the-host-first) and say
what it is missing before installing anything. Follow this guide within the
chosen layout and the full
[Assistant operating rules](#assistant-operating-rules).

## Before you start

Prepare a local, git-ignored credential file if an assistant will connect to
the server or devices:

```bash
cp creds/deploy.env.example creds/deploy.env
chmod 600 creds/deploy.env
```

Keep credentials in that file or enter them directly in the Console. Do not
paste passwords, tokens, or private keys into a chat.

These are the non-secret decisions a deployment needs. An assistant asks for
them as it goes, so an operator does not have to settle them all in advance:

| Decision | What to record |
| --- | --- |
| Deployment layout | One Docker host, separate Docker hosts, or Kubernetes. |
| Server address | Stable device-reachable IPv4 address for the catalog, tracker, artifacts, and origin seeder. |
| Console address | Browser HTTPS URL and published port. On one Docker host it normally uses the server address on 8080; a separate Console has its own address. |
| Private management connection | For separate Docker hosts, the server's private bind address and the HTTPS hostname or IP the Console will use on 9443. |
| Image source | A server-host path or upload source for a Cisco `.bin`, `.iso`, `.tar`, or `.rpm` file. |
| Device inventory | Management IP, management type, network fields, and optional model for every device. See [Management type](management-type.md). |
| Device agent | Guest Shell, IOx, or XR appmgr. A Catalyst 9300 can use Guest Shell or IOx with supported app-hosting storage. |
| Package inputs | Both architecture `aria2c` binaries, `ioxclient`, and the XR build tooling; the server must serve the packages before onboarding. `tools/start-compose-server.sh` lists every missing one before building anything. A fresh clone has none of them: see [Supply the handed-in inputs](#supply-the-handed-in-inputs). |
| Instruction trust roots | A directory holding exactly two public root keys (`.pub`). The private halves stay with their custodians; no installer or assistant may generate them, and the operator creates them as described in [Supply the handed-in inputs](#supply-the-handed-in-inputs). Every device package embeds these roots and the build fails closed without them. |

Decide where the deployment lives. Any directory the operator prefers works;
this guide uses `/opt/iris/intelligent-release-image-staging`, and every
command below runs from there unless it says otherwise. An assistant should
ask for this one up front, then use it everywhere without asking again.

Create it and clone into it — substitute the operator's directory for the
default in the first line:

```bash
IRIS_DIR=/opt/iris/intelligent-release-image-staging
sudo install -d -o "$USER" -g "$USER" "$(dirname "$IRIS_DIR")"
git clone https://github.com/cisco-open/intelligent-release-image-staging \
  "$IRIS_DIR"
cd "$IRIS_DIR"
```

`sudo` is needed only for a directory the operator cannot already write, such
as one under `/opt`.

Check out the same IRIS version on every deployment host. For a server already
in use, identify its Compose project, container names, state volumes, age
identity, and artifact directory before changing anything. Preserve those
settings and data unless a reset is explicitly part of the task.

## Check the host first

Run through this before cloning anything, report what is present and what is
missing in one message, and ask the operator before installing a package or
changing the host. Nothing here installs itself.

| Need it for | Check | Ubuntu or Debian package |
| --- | --- | --- |
| Everything | `docker version`, `docker compose version`, `docker buildx version` | `docker.io` plus the Compose plugin, or Docker's own repository |
| Everything | `id -nG \| grep -w docker` | membership in `docker`, or every command needs `sudo` |
| Encrypted server state | `command -v age age-keygen` | `age` |
| The two roots, checksums | `command -v git curl ssh-keygen sha256sum` | normally already installed |
| The arm64 IOx package only | `grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready` | `qemu-user-static` |

Also report `nproc`, `free -g` and `df -h` for the disk holding
`/var/lib/docker` and the deployment directory. Two builds and the server
image live there, and every image staged later needs its own size again on top.

Check every host the chosen layout uses, and say which host each result came
from.

**Docker on separate hosts** has two, and they need different things. The
server host needs everything in the table above, because it holds the state
and builds the packages. The Console host needs only Docker with the Compose
plugin and room for its own image: no `age`, no emulation, no build inputs, no
server volume. The host that prepares the bundles also needs `python3` for
`tools/prepare-docker-hosts.py`, and SSH to both hosts to deliver them.

**Kubernetes** splits the same way, between a cluster and the host that builds
images and packages. That build host needs the table above, minus `age` if the
identity is created elsewhere, plus rights to push to a registry the nodes can
pull from. For the cluster:

| Need it for | Check |
| --- | --- |
| Everything | `kubectl version --client` and `kubectl config current-context` |
| Creating the namespace and workloads | `kubectl auth can-i create deployment -A` |
| The server PVC | `kubectl get storageclass` |
| Reaching the server and Console | that Services of type LoadBalancer get addresses on this cluster |
| Running amd64 images | amd64 worker capacity |

NetworkPolicy is the one prerequisite a command cannot settle: a cluster whose
CNI does not enforce it accepts the manifests and silently ignores them.
Confirm enforcement with whoever runs the cluster, and say plainly that you
confirmed it by asking rather than by testing.

The `aarch64` `aria2c` build is the one step whose cost is worth stating before
it starts: it compiles under emulation, takes tens of minutes, and keeps every
core busy. It is needed only for IOx on IE-3400 and other IE-3x00 devices. If
none are in scope, say so and skip both that build and the arm64 package; if
they are, offer a native arm64 machine as the faster place to build, or confirm
that the operator wants it built here.

## Supply the handed-in inputs

A fresh clone lacks these inputs deliberately, and
`tools/start-compose-server.sh` lists every missing one before it builds
anything. Do not treat that list as a broken checkout and do not invent a
seeder binary or a trust anchor.

Do every step below yourself except step 4, the trust roots, which only the
operator creates. In a proof of concept prepare all of them and build every
device package: an unbuilt package reports **Needs rebuild** in Console
**Settings -> Device packages** and its device type cannot be onboarded.

Supply what the device types in scope need:

| What you will onboard | Supply first |
| --- | --- |
| Server and Console only, no devices yet | `aria2c` amd64 |
| Guest Shell (Catalyst 9300, Catalyst 8000V) | `aria2c` amd64 |
| IOx on amd64 (Catalyst 9300, Catalyst 8000V) | `aria2c` amd64, `ioxclient`, the two roots |
| IOx on arm64 (IE-3400 and other IE-3x00) | the amd64 set, plus `aria2c` arm64 and ARM64 emulation |
| IOS-XR appmgr | `aria2c` amd64, the two roots, Docker and network for the pinned appmgr builder |

Every device type is reachable from a clean Ubuntu Docker host with these
steps. Work through the ones your table row names, in order.

### 1. The `aria2c` client — every deployment

`server/Dockerfile` copies `bin/aria2c` into the server image, so no stack
builds without it. `deliverables/` is git-ignored and a release archive carries
the producer rather than the binary, so a clone starts with nothing.

Accept a hand-in from whoever built it — put it at `deliverables/aria2c-x86_64`,
or point `ARIA2C_DELIVERABLE` at it — or build it from the producer this
repository ships for exactly that purpose:

```bash
git clone https://github.com/AnInsomniacy/aria2-next \
  tools/aria2c-build/vendor/aria2-next
git -C tools/aria2c-build/vendor/aria2-next checkout v2.5.6
(cd tools/aria2c-build && ./build.sh x86_64)
```

Run `./build.sh aarch64` as well for IOx on IE-3x00; that build needs the ARM64
emulation of step 3.

**Build `x86_64` first and leave `aarch64` until the stack is up.** The arm64
build compiles under emulation and takes far longer than the native one — tens
of minutes on a modest host — and it prints nothing for long stretches while
the compiler runs. It is heavy as well as slow: the compile runs one job per
host core and the link phase runs parallel LTO jobs, with every one of them an
emulated compiler, so expect the host to be busy throughout. Build it on a
native arm64 machine instead when you have one; nothing else about the step
changes. `tools/start-compose-server.sh` checks for both
architectures before it builds anything, so running it first means waiting out
that whole build before anything works. Instead: build `x86_64`, bring the
stack up with the Compose commands under
[Docker on one host](#docker-on-one-host), confirm the Console, and only then
start the arm64 build and the package builders. An interruption then costs the
IE-3x00 package, not the deployment.

On a fresh proof-of-concept host there is no fast version of this build: the
whole toolchain is emulated, and nothing in the repository shortens that. Work
down this list before starting it.

1. **Do not build it at all.** It is needed only for IOx on IE-3400 and other
   IE-3x00 devices. With none in scope, skip this build and the arm64 IOx
   package. This is the only option that removes the cost rather than trimming
   it, and on most proofs of concept it applies.
2. **Install a newer QEMU first.** A distribution's emulation is often older
   than the one in a reviewed `tonistiigi/binfmt` image, and emulation speed
   varies by QEMU version, so installing the handler from a digest the operator
   reviewed may cut the build time. Offer it before starting, not after, since
   switching afterwards means building twice. Measure it; do not claim a
   figure.
3. **Protect the build you start.** Launch it detached as shown below so a
   closing session cannot cancel it, and never prune Docker's cache while it or
   a retry is in progress: a resumed build is far cheaper than a cold one. An
   aborted build is the most expensive outcome here.

Then build it, and say plainly that this is the slow path: tens of minutes with
every core busy.

If the operator happens to have any arm64 machine reachable over SSH, that
removes the emulation entirely and is worth asking about once. `build.sh`
passes no `--builder`, so it uses whichever buildx builder is current and
exports the artifact back here:

```bash
docker context create arm64-builder --docker "host=ssh://user@arm-host"
docker buildx create --name iris-arm --driver docker-container \
  --platform linux/arm64 arm64-builder
docker buildx use iris-arm
(cd tools/aria2c-build && ./build.sh aarch64)
docker buildx use default
```

Keep the result. `deliverables/aria2c-aarch64` is git-ignored, so it survives
pulls and branch changes, and `tools/build-device-image.sh` also accepts a
prebuilt client from `ARIA2C_BIN_ARM64` or a staged
`artifacts/iris-agent-arm.tgz`. A second deployment on the same host, or
another host the operator can copy that file to, never repeats this build.

This ordering is the same for all three layouts. Only the host changes: the one
Docker host, the server host of a separate-host pair, or the host that builds
packages for Kubernetes. A cluster emulates nothing on your behalf.

Start it so that it survives the session, and watch its log rather than its
terminal. A plain `&` is not enough: the `docker buildx` client drives the
build, so when an SSH session ends and takes the client with it, the build is
cancelled on the daemon — which looks exactly like a compiler failure with no
compiler error in the log.

```bash
cd tools/aria2c-build
setsid nohup ./build.sh aarch64 > build-aarch64.log 2>&1 < /dev/null &
echo $! > build-aarch64.pid
```

Follow it with the pid and the log, as often as you like:

```bash
kill -0 "$(cat tools/aria2c-build/build-aarch64.pid)" 2>/dev/null \
  && echo "still building" || echo "finished or stopped"
tail -n 5 tools/aria2c-build/build-aarch64.log
```

A detached build has no exit status to collect, so judge it by what it left
behind. The log ends with a verification block and a size gate, and the
artifact appears only on success:

```bash
grep -E 'HARD FAIL|OVER TARGET|UNDER TARGET' tools/aria2c-build/build-aarch64.log
ls -l tools/aria2c-build/out/aarch64/aria2c
```

`UNDER TARGET` or `OVER TARGET` with the artifact present is a completed build;
`HARD FAIL`, or no artifact, is not. The build is safe to interrupt and safe to
rerun — Docker's layer cache picks up most of the work again — so when in
doubt, rerun `./build.sh aarch64`. `build.sh` needs Docker, and refuses to run unless the
checkout sits at the pinned commit and every patch in `tools/aria2c-patches/`
applies cleanly, so a build either corresponds to the published patch set or it
fails.

**A binary you built will not match `tools/aria2c.sha256`, and that is
expected.** A different toolchain or musl version produces different bytes, and
`tools/get-aria2c.sh` fails closed on the mismatch. Adopting your own build is
therefore a deliberate act. The build leaves its artifact in
`tools/aria2c-build/out/<arch>/aria2c`, beside a `BUILD-INFO.json` describing
it:

```bash
cp tools/aria2c-build/out/x86_64/aria2c deliverables/aria2c-x86_64
sha256sum deliverables/aria2c-x86_64
```

Edit the file in place and leave it world-readable. `server/Dockerfile` copies
`tools/aria2c.sha256` into the server image and reads it as the runtime uid, so
a rewrite that lands as `0600` — which an atomic write through a temporary file
does by default — breaks the build that uses it. Check after editing:

```bash
chmod 0644 tools/aria2c.sha256
ls -l tools/aria2c.sha256
```

Replace the `x86_64` line in `tools/aria2c.sha256` with that checksum and
record in that file what you built, then install it:

```bash
tools/get-aria2c.sh amd64
```

Repeat both steps with `aarch64` / `arm64` when you built that architecture.
That leaves `tools/aria2c.sha256` modified in your checkout, which is the
expected state for a self-built client: leave the modification in place, and
do not offer it upstream, where it would replace the checksum of the binary the
project ships. Never edit that file to silence a mismatch on a binary you did
not build yourself — there, the mismatch is the mechanism working.
`tools/aria2c-build/README.md` covers the patch set, the pinned toolchain, and
what to do when an Alpine security bump withdraws a pin.

### 2. `ioxclient` — IOx device types only

```bash
tools/get-ioxclient.sh
```

It downloads Cisco's IOx packaging CLI from its public documentation host, and
installs it at `tools/bin/ioxclient`; set `IOXCLIENT` instead to use a copy you
already have. Cisco publishes no checksum for that artifact and `ioxclient`
signs every package a device installs, so the helper pins the binary itself
against `tools/ioxclient.sha256` and refuses both a mismatch and a version that
file does not record. Linux amd64 only.

### 3. ARM64 emulation — only to build arm64 on an amd64 host

Needed for the `aarch64` `aria2c` build and the arm64 IOx package. Check
whether the host already has it:

```bash
grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 && echo ready
```

If that prints nothing, the simplest fix is your distribution's static QEMU
package (`qemu-user-static` on Ubuntu and Debian), then run the check again.
That needs no digest and no privileged container.

Otherwise the builders register the handler themselves, and require an audited
`tonistiigi/binfmt` digest rather than pulling a floating tag. Review the tag
you intend to use, resolve it to a digest, and export it:

```bash
docker buildx imagetools inspect tonistiigi/binfmt:<reviewed-tag> \
  --format '{{println .Manifest.Digest}}'
export BINFMT_IMAGE_DIGEST=sha256:<the digest printed above>
```

With the digest unset the build fails closed instead of pulling an unpinned
image.

### 4. The two instruction trust roots — every device package

Every device package embeds exactly two public roots, and the build fails
closed without them. They are the trust anchors devices use to judge signed
instructions, so **no installer and no assistant creates them.** The operator
pastes one line. An assistant hands over the line for the chosen layout and
waits.

Each line creates both keypairs, keeps the private halves in `~/iris-custody`,
and leaves `~/iris-roots` holding the two public keys and nothing else — which
is what the builders require. Answer each passphrase prompt with a real
passphrase: these are signing keys. The last command prints the directory, and
`root-a.pub  root-b.pub` is the expected output.

**Docker on one host** — run it on that host:

```bash
install -d -m 0700 ~/iris-custody && ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a && ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b && rm -rf ~/iris-roots && install -d -m 0755 ~/iris-roots && install -m 0644 ~/iris-custody/root-a.pub ~/iris-custody/root-b.pub ~/iris-roots/ && ls -A ~/iris-roots
```

**Docker on separate hosts** — run the same line on the **server** host, which
builds the packages. The Console host needs no roots at all:

```bash
install -d -m 0700 ~/iris-custody && ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a && ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b && rm -rf ~/iris-roots && install -d -m 0755 ~/iris-roots && install -m 0644 ~/iris-custody/root-a.pub ~/iris-custody/root-b.pub ~/iris-roots/ && ls -A ~/iris-roots
```

**Kubernetes** — run it on the host that builds device packages:

```bash
install -d -m 0700 ~/iris-custody && ssh-keygen -t ed25519 -C iris-root-a -f ~/iris-custody/root-a && ssh-keygen -t ed25519 -C iris-root-b -f ~/iris-custody/root-b && rm -rf ~/iris-roots && install -d -m 0755 ~/iris-roots && install -m 0644 ~/iris-custody/root-a.pub ~/iris-custody/root-b.pub ~/iris-roots/ && ls -A ~/iris-roots
```

Kubernetes needs one more line, because the server reads the roots from its own
storage as well. Run it once the server pod is up, and expect the same two
names back:

```bash
for r in root-a root-b; do kubectl -n iris exec -i deployment/iris-seed-server -c iris -- sh -c "install -d -m 0755 /data/config/instr/roots.d && cat > /data/config/instr/roots.d/$r.pub" < ~/iris-roots/$r.pub; done && kubectl -n iris exec deployment/iris-seed-server -c iris -- ls -A /data/config/instr/roots.d
```

Never generate roots inside the pod, and never copy a private root there.

A directory holding anything but the two public keys is refused with `must hold
exactly two public roots (*.pub)` before anything is built; the `rm -rf` in the
line above is what keeps a second run from leaving a third file behind. Every
builder in this guide is passed `IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"`,
so there is nothing further to configure.

For production, have each custodian run one `ssh-keygen` command on their own
machine, carry only the `.pub` halves to the server host, and place them with
the same `install` pair. Never accept a private root: not on the server host,
not in an installer argument, not on a device, not in chat. One person holding
both is acceptable for a proof of concept and is not production custody or
signing evidence — say so when reporting it, as
[Prepare instruction trust](getting-started.md#prepare-instruction-trust)
requires. Certificates, rotation and revocation are in the
[ceremony runbook](operations.md#instruction-root-ceremony-and-recovery).

### 5. The appmgr builder — IOS-XR only

`tools/build-xr-package.sh` wraps the canonical device image as an appmgr RPM.
It clones Cisco's `ios-xr/xr-appmgr-build` at a pinned commit into
`~/.cache/iris/xr-appmgr-build` on first use, so that step needs Docker and
network access. `tools/start-compose-server.sh` runs it for you; set
`IRIS_SKIP_XR=1` only on a deployment that is certain to have no XR devices;
a proof of concept leaves it unset and builds the RPM with everything else.
Run the builder directly when rebuilding later:

```bash
tools/build-xr-package.sh --out artifacts/
```

### The shortest path to a first staged image

This is the quickest possible look at a staged image, not the proof-of-concept
default: it produces no device package, so **Settings -> Device packages** will
report every one of them as needing a build. Take it only when that is what the
operator asked for. It still needs the `aria2c` client of step 1, and no roots:

```bash
docker compose -f server/docker-compose.yml build --pull
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
docker compose -f server/docker-compose.yml up -d
```

It installs no roots and builds no packages, so instruction custody is not
configured and IOx and XR devices have nothing to onboard with. Work through
the steps above before going past a demonstration.

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

Give the assistant these requirements. It asks for the layout and the rest
itself, so the operator does not have to decide everything in advance:

```text
Operate IRIS as a stage-only system. Never install, activate, reload, change
boot variables, or replace the running software on a device.

Before running anything, ask the operator these four questions in one message
and wait for the answers. Do not guess a layout, and do not start a Docker
deployment because it is the default:

1. Where should the deployment live? Offer
   /opt/iris/intelligent-release-image-staging as the default. You create the
   directory and clone into it.
2. Which layout: Docker on one host, Docker on separate hosts, or Kubernetes?
   For separate hosts also ask for the Console host, and for Kubernetes ask
   for the cluster context and the registry the nodes can pull from.
3. Which device types will be onboarded: Guest Shell, IOx on amd64
   (Catalyst 9300, Catalyst 8000V), IOx on arm64 (IE-3400 and other IE-3x00),
   IOS-XR appmgr, or none yet? The answer decides which handed-in inputs you
   need; asking later wastes a build.
4. The server's device-reachable IPv4 address, and the Console URL if it is
   not that address on port 8080.

Repeat the answers back before acting on them, then work only within the
layout that was chosen.

Read CLAUDE.md and the current docs/zensical/ guide for the selected layout.
Use Getting Started for Docker on one host, Docker on Separate Hosts for
independent Docker hosts, or Kubernetes for the cluster manifests. Keep the
same layout, Compose project, environment files, and container names in every
command. Preserve existing server state and device assignments.

Keep credentials and secrets out of chat, command output, logs, and source
control. Read local credentials only when a step needs them. Do not copy
server state, the age identity, or the management private key to the Console.
Check the host before anything else, as "Check the host first" describes, and
report what is present and what is missing in one message. Check every host
the layout uses and name which host each result came from: on separate Docker
hosts the Console host needs far less than the server host, and on Kubernetes
the cluster checks and the build host's checks are different lists. Ask before
installing a package, adding a user to the docker group, or registering
emulation handlers: those change the operator's machine. Install what they
approve, then continue rather than handing the list back.

Before starting the aarch64 aria2c build, work down the list in step 1 of
"Supply the handed-in inputs". On a fresh host that build has no fast version:
skip it when no IE-3x00 device is in scope, offer a newer QEMU from a reviewed
binfmt digest before starting rather than after, then launch it detached and
leave the cache alone. State that it is the slow path and what it costs: tens
of minutes with every core busy. Ask once whether any arm64 machine is
reachable over SSH, since that removes the emulation. This ordering applies to
all three layouts; only the host running the build changes.

A fresh clone is missing inputs on purpose. Work through "Supply the handed-in
inputs" in this guide for the device types in scope, rather than reporting the
deployment as blocked and stopping. Announce which steps you are taking.

Ask once, at the start, where the deployment should live, and use
/opt/iris/intelligent-release-image-staging when the operator has no
preference. Create that directory and clone into it yourself rather than
handing the operator a step. Every later command runs from there. Do not ask for the
other paths this guide fixes: the two public instruction roots go in
$HOME/iris-roots on the host that builds packages, whatever the checkout is.

You may run the project's own helpers yourself: tools/aria2c-build/build.sh,
tools/get-aria2c.sh, tools/get-ioxclient.sh, tools/build-xr-package.sh, and
tools/start-compose-server.sh. Never download or substitute an aria2c binary
from anywhere else.

Build the Guest Shell bundle, the amd64 IOx package and the XR RPM in every
proof of concept: they need no emulation and a missing one blocks that device
type later. Build the arm64 IOx package too whenever an IE-3400 or other
IE-3x00 device is in scope. Only skip it when none is, because it carries the
emulated build.
tools/start-compose-server.sh builds all four in one run once its inputs are
present, so leave IRIS_SKIP_XR unset; tools/stage-iox-package.sh --arch amd64
builds one IOx package when the arm64 one is out of scope, which
tools/provision-iox-packages.sh cannot do.

Console Settings -> Device packages lists every package type, so one you
skipped on purpose stays "Not built / absent" forever. That is the correct end
state. Report which packages you built and which you skipped and why, and never
present a deliberately skipped package as a failure or try to hide it.

Do that preparation yourself and announce each step as you take it:
- Build both aria2c architectures with tools/aria2c-build/build.sh, place them
  in deliverables/, record their sha256sums in tools/aria2c.sha256, say that
  you adopted your own build, and install them with tools/get-aria2c.sh. The
  edit leaves that file locally modified, which is expected and fine: leave it,
  do not revert it, and do not commit it. Never put a checksum in that file for
  a binary you did not build in this session. Leave it world-readable:
  server/Dockerfile copies it into the image and reads it as the runtime uid,
  so a rewrite that lands as 0600 breaks the build. Run chmod 0644 and ls -l on
  it after editing.
- When you start the stack without tools/start-compose-server.sh, install the
  two public roots into the server's config volume yourself, with the compose
  run command in the layout section, and confirm them with ls in
  $IRIS_CONFIG/instr/roots.d. Handing the roots to the package builders is a
  different thing and does not cover this. Nothing later fails loudly for a
  missing root: the Guest Shell bundle simply cannot be trust-bound.
- Run tools/get-ioxclient.sh.
- Enable arm64 emulation for the arm64 IOx package by installing the
  distribution's static QEMU package, then confirm the registration.

Exactly one thing is the operator's: the two instruction trust roots. Never
create them. Paste the operator the single line for the chosen layout from
step 4 of "Supply the handed-in inputs", wait for $HOME/iris-roots to hold the
two public halves, and refuse a private key if one is offered. On Kubernetes,
give them the second line for the server pod once it is running. Also ask before
accepting a tonistiigi/binfmt digest, which trusts a third-party image, rather
than the distribution package.

Offer the two-service Guest Shell path, which builds no packages and needs no
roots, only when the operator asks for the quickest possible look at a staged
image. It is not the proof-of-concept default.

Order the work so the operator has something working early: build the x86_64
aria2c, bring the stack up, confirm the Console, and only then run the arm64
aria2c build and the package builders. Do not run
tools/start-compose-server.sh before both architectures exist, because it
checks for both and will not start the stack until the long emulated build has
finished.

Before starting the arm64 build, say that it runs under emulation, takes tens
of minutes, and is silent for long stretches, so the operator does not read
silence as a hang and stop it. Start it detached with setsid nohup, writing to
a log, exactly as step 1 of "Supply the handed-in inputs" shows. A plain & is
not enough: the docker buildx client drives the build, so a client that dies
with its SSH session cancels the build on the daemon, and the log then shows a
build that stopped with no compiler error in it. While it runs, report every
few minutes: the elapsed time, the last line of the log, and that it is still
going. A detached build leaves no exit status to collect, so judge it by the
size-gate line in the log and the artifact on disk rather than a return code.
If it stopped, say so, rerun ./build.sh aarch64, and say that the layer cache
makes the rerun shorter.

Do not describe the whole sequence and then go quiet until it ends. Say which
step is starting, and report each one as it finishes with the evidence it
produced:

- the roots directory validated: the two file names and their fingerprints
- the public roots installed into the server's config volume, listed back from
  inside the container
- each aria2c architecture built, with the sha256 you recorded, then installed
- ioxclient fetched, with its version
- the Guest Shell bundle staged
- each IOx package built, by architecture, with its provenance manifest
- the XR RPM built
- Console Settings -> Device packages read back, naming anything that still
  reports needing a build

On Docker on one host, also report the environment file written with the age
recipients used, the images built, the encrypted store bootstrapped, and both
services up and healthy.

On Docker on separate hosts, report each host separately and never imply the
Console proves the server: the host bundles prepared, each bundle delivered and
owned by uid/gid 10001, server.env and console.env written on their own hosts,
the server image built and its store bootstrapped, the server healthy, the
Console image built and serving browser HTTPS, and then an authenticated
Console request reaching the server. A Console that loads while API requests
return 503 is not a working deployment; say so plainly rather than reporting
the Console as up.

On Kubernetes, report the images built and pushed with the digests you pinned
in kustomization.yaml, the namespace and every Secret provisioned, the PVC
bound, the Services and NetworkPolicy applied, each Deployment reaching ready,
the two public roots installed into /data/config/instr/roots.d and listed back
from the pod, and the device packages staged into the server's artifact
storage. Pod readiness is not an authenticated Console request; report them
separately.

If a step is still running when there is nothing new to report, say that it is
still running rather than nothing at all. If one fails, report which one, quote
the error, and say what is unaffected — a package build that fails after the
stack is up leaves the stack running.

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

Do steps 1 to 4 of
[Supply the handed-in inputs](#supply-the-handed-in-inputs) for the `x86_64`
architecture, leaving the long `aarch64` build for later, then start the stack:

```bash
set -a
. server/.env
set +a
tools/get-aria2c.sh amd64
docker compose -f server/docker-compose.yml build --pull
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
docker compose -f server/docker-compose.yml run --rm \
  -v "$HOME/iris-roots:/pub:ro" --entrypoint sh iris -c \
  'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && \
   install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
docker compose -f server/docker-compose.yml up -d
docker compose -f server/docker-compose.yml ps
```

The third command is easy to miss and nothing later reports it: it installs the
two public roots into the server's config volume, which is separate from
handing them to the package builders. Without it the server cannot
self-provision a trust-bound Guest Shell bundle. `tools/start-compose-server.sh`
does this for you; this sequence does not, because it starts the stack before
the packages exist. It runs inside the server image as the runtime uid, so
ownership is right, mounts only the `.pub` files read-only, and is idempotent.

Confirm it before moving on:

```bash
docker compose -f server/docker-compose.yml exec iris \
  ls -l "$IRIS_CONFIG/instr/roots.d"
```

Open `https://<server-ip>:8080/`, or the host port set by `IRIS_GUI_PUBLISH`.
A working Console here means the deployment stands; everything that follows
adds device packages to it.

Now finish the packages, including the `aarch64` `aria2c` build that takes tens
of minutes under emulation:

```bash
tools/get-ioxclient.sh
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/stage-iox-package.sh --arch amd64
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/build-xr-package.sh --out artifacts/
```

Add the arm64 package only when an IE-3x00 device is in scope. It needs the
emulated `aarch64` `aria2c` build of step 1 first, and then:

```bash
cp tools/aria2c-build/out/aarch64/aria2c deliverables/aria2c-aarch64
sha256sum deliverables/aria2c-aarch64     # record it in tools/aria2c.sha256
tools/get-aria2c.sh arm64
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/stage-iox-package.sh --arch arm64
```

`tools/provision-iox-packages.sh` builds both architectures in one run and is
the right command when both are in scope; it cannot be used to build only one.

Then read **Settings -> Device packages**. Every package you built must report
as built. A package you deliberately skipped stays **Not built / absent**, and
that is the correct end state, not a failure: say which ones you skipped and
why, so nobody reads that screen as a broken deployment. `iris-arm64.tar` sits
there for every deployment without an IE-3x00 device.

`tools/start-compose-server.sh` does all of this in one run instead — grants
uid 10001 the `artifacts/` directory, builds the images, bootstraps the store,
installs the two public roots into the config volume, starts both services and
builds the Guest Shell bundle, both IOx packages and the XR RPM, preserving an
existing complete store. It is the better path once both `aria2c` binaries
exist, because it checks every input first and stops before building if one is
missing. On a first deployment it also means the stack cannot start until the
emulated arm64 build has finished, which is why the sequence above puts the
Console first. If a package build fails after the stack is up, the helper exits
nonzero while the stack keeps running; fix the reported problem and rerun
`tools/provision-iox-packages.sh` or `tools/build-xr-package.sh --out artifacts/`.

### Docker on separate hosts

The server host builds the server image and every device package, so
[Supply the handed-in inputs](#supply-the-handed-in-inputs) applies to that
host's checkout: `aria2c` before the image build, and `ioxclient`, ARM64
emulation, the two roots and the appmgr builder for the device types in scope.
The Console host needs none of them; it builds only the Console image.

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
  -f server/docker-compose.server.yml run --rm \
  -v "$HOME/iris-roots:/pub:ro" --entrypoint sh iris -c \
  'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && \
   install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
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
or age key belongs on the Console host.

Build device packages on the server host, where the inputs live, once its
stack is up. The `aarch64` `aria2c` build belongs here too, and it is the long
emulated one: put the options for making it cheaper to the operator first, then
start it detached and follow its log, both exactly as
[step 1](#1-the-aria2c-client-every-deployment) shows, rather than running it
in the foreground of an SSH session that may end:

```bash
tools/get-ioxclient.sh
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/stage-iox-package.sh --arch amd64
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/build-xr-package.sh --out artifacts/

# only with an IE-3x00 device in scope, after the emulated build finishes:
cd tools/aria2c-build
setsid nohup ./build.sh aarch64 > build-aarch64.log 2>&1 < /dev/null &
cd ../..
cp tools/aria2c-build/out/aarch64/aria2c deliverables/aria2c-aarch64
sha256sum deliverables/aria2c-aarch64     # record it in tools/aria2c.sha256
tools/get-aria2c.sh arm64
IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
  tools/stage-iox-package.sh --arch arm64
```

Run only the ones your device types need. The
[package steps](docker-hosts.md#start-the-server-host) cover placement and
ownership on that host.

### Kubernetes

Use a cluster with amd64 worker capacity, a suitable storage class,
LoadBalancer support, and enforced NetworkPolicy. Follow
[Kubernetes](kubernetes.md) for the complete configuration. For a small lab,
use the [K3s setup choices](kubernetes.md#small-lab-with-k3s); Docker can remain
on the same host with separate service addresses.

Configure IRIS:

1. Build the server and Console images from their Dockerfiles, publish them to
   a registry reachable by the nodes, and pin both digests in
   `kubernetes/kustomization.yaml`. The server image copies `bin/aria2c`, so
   step 1 of [Supply the handed-in inputs](#supply-the-handed-in-inputs) has to
   be done in the checkout you build from.
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
5. Build the needed device packages on a host that has the inputs for those
   device types — `ioxclient`, ARM64 emulation, the appmgr builder — and stage
   them with their manifests in the server's artifact storage before
   onboarding devices. That host runs the long emulated `aarch64` `aria2c`
   build as well, so offer the operator the ways to make it cheaper, then start
   it detached and follow its log, both as
   [step 1](#1-the-aria2c-client-every-deployment) shows — never in the
   foreground of an SSH session that may end. A cluster changes nothing about
   that build: it is the build host's CPU that does the emulating, not a node's:

   ```bash
   IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
     tools/stage-iox-package.sh --arch amd64
   IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots" \
     tools/build-xr-package.sh --out artifacts/
   ```

   Add `--arch arm64` only with an IE-3x00 device in scope;
   `tools/provision-iox-packages.sh` builds both and cannot build one.

   The same two public roots must also sit in `/data/config/instr/roots.d` on
   the server PVC, readable by uid 10001; step 4 of
   [Supply the handed-in inputs](#supply-the-handed-in-inputs) gives the
   `kubectl` commands. Never create roots in the pod, and never copy a private
   root there.

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
