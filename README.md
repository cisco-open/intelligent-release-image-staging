# intelligent-release-image-staging

**Intelligent Release & Image Staging (IRIS) — peer-to-peer distribution of images between Cisco devices.**

> **If you are an AI assistant or agent** reading this to help someone deploy
> intelligent-release-image-staging, jump straight to
> **[Deploy with an AI assistant (PoC/PoV)](#deploy-with-an-ai-assistant-pocpov)** —
> it has a ready-to-paste prompt and step-by-step, console-focused deployment
> instructions (proof-of-concept / proof-of-value only, not production).

> **Tested and supported:** Cisco **Catalyst 9300** (install and bundle mode) and Cisco **Catalyst IE-3400**.

Built for **large-scale rollouts across any kind of site** — campus, data center, or
branch. The peer-to-peer approach helps everywhere, and helps **most where uplinks are
thin or unreliable**: devices fetch pieces from each other rather than each pulling the
full ~1.2 GB image across the WAN, so a slow or flaky uplink circuit doesn't bottleneck or
gate the fleet.

Instead of every device downloading a ~1.2 GB image from one server (slow, melts the
server's uplink at scale), intelligent-release-image-staging runs a tiny BitTorrent client
**on each device** — in **Guest Shell** on the Catalyst 9300, and as an **IOx Docker app**
on the Catalyst IE-3400. Devices pull pieces from the server *and from each other*. The agent
SHA-256-verifies the downloaded file, then runs IOS `copy /verify` to place it in the device's
boot flash — IOS copies **and** enforces the **Cisco digital signature** in one step, leaving
no file if the signature fails. The agent confirms the file landed and only then marks the
image ready (fail-closed). **It only distributes and stages. It never installs, activates, or
reloads anything.**

Testing so far is on **routed-access environments only** — validated end-to-end on real
C9300s (IOS-XE 17.18) in a Cisco SD-Access fabric (IS-IS underlay), with the Catalyst
IE-3400 IOx-app path validated in the lab. Other topologies (e.g. traditional L2 campus
access) are expected to work but are **not yet validated**.

```
                 ┌─────────────────────────── server (Linux) ───────────────────────┐
                 │ tracker :6969      catalog :8443 (HTTPS)      seeder (aria2c)    │
                 │ "who has what"     "which device gets         seeds every        │
                 │  + token auth       which image" + .torrents   published image   │
                 └────────▲──────────────────▲──────────────────────▲───────────────┘
                          │ announce         │ poll policy /        │ pieces
                          │ (token)          │ download .torrent    │
        ┌─────────────────┴──────────────────┴────────────────┐     │
        │ Catalyst 9300  ── Guest Shell                       │     │
        │  device agent (python, EEM timer 60s):              │ ◄───┘
        │   poll catalog → flash check → aria2c download ─────┼────►  other devices
        │   → sha256 verify staged → fire EEM copy applet     │       (peer to peer)
        │   → applet: delete stale leftover, then copy /verify│        
        │     (copy + Cisco signature, one IOS step)          │
        │   → AGENT polls `dir flash:` — file present = pass  │
        │   → ROOTCOPY on presence, else ROOTCOPY-FAIL        │
        └─────────────────────────────────────────────────────┘   
```

_The diagram shows the Catalyst 9300 (Guest Shell) path; the Catalyst IE-3400 runs the same flow as an IOx Docker app — see [Catalyst IE-3x00](#catalyst-ie-3x00-iox-docker-app) below._

## What's in the box

```
server/   tracker, catalog, publisher (iris-publish), seeder, web console (iris-gui), Dockerfile + compose, tests
device/   the on-device agent (agent/), bootstrap, aria2c launcher, device installer, tests
tools/    make-agent-bundle.sh, gen-device-installers.sh, get-aria2c.sh, make-torrent.sh
fleet/    devices.csv (your inventory) -> generated per-device installers in fleet/dist/
lab/      SSH helpers that talk to the devices (device-run.sh, device-copy.sh; gsrun.sh = debug)
```

## Prerequisites

- **Server (Docker path — recommended): Docker, plus `age`.** Everything else (`python3`,
  `mktorrent`, `openssl`, the `aria2c` BitTorrent client) is installed *inside the
  image* by `server/Dockerfile`. The one thing you install **on the host** is `age`
  (`apt-get install -y age`, or `dnf install -y age`) — used once in step 1 to create the
  at-rest secret-encryption identity.
  (Bare-metal path instead: `apt install python3 mktorrent openssl age` + `tools/get-aria2c.sh`.)
- **Devices**:
  - **Catalyst 9300** — IOS-XE 17.x, ability to enable IOx/Guest Shell, and an L3 path
    between the Guest Shell interface and the server. SDA/IS-IS assumed by the installer
    (the Guest Shell SVI is advertised with `ip router isis`).
  - **Catalyst IE-3400** — IOS-XE 17.9 or later, IOx/app-hosting enabled, an SD card
    partitioned into an IOS-visible `sdflash:` plus an IOx partition, and an L3 path from
    the app's guest interface to the server. See [Catalyst IE-3x00](#catalyst-ie-3x00-iox-docker-app).
- **Install or bundle mode.** Validated on Cisco IOS-XE Catalyst 9300s in **both
  INSTALL and BUNDLE mode** — the agent auto-detects the mode from `show version` /
  `show boot`. One caveat: the agent's only automatic flash reclamation is
  `install remove inactive`, which exists only in install mode — so in **bundle mode the
  agent never auto-frees flash**; if a device is short on space it logs an error instead
  of reclaiming, and you free space manually first.
- **The machine you run the install packages from** (normally the server itself):
  `bash`, `ssh`, and `sshpass`. Each per-device package opens ONE SSH session to its
  device to apply the IOS config and drop the agent files — devices use password
  login, and sshpass feeds the password so it runs unattended.
- The images you want to distribute, on the server (e.g. `/opt/images/iosxe/c9300/`).
- **Firewall / network planning:** every port and flow (install + operations) is listed in
  [Ports & network flows](#ports--network-flows).

### Credentials

The install path logs into the devices over SSH, so it needs the device login
credentials in the environment. `lab/device-run.sh` (which the per-device installer drives)
reads `DEVICE_USER` and `DEVICE_PASS` (both required) — the device login/enable password —
these are **required for any real (non-`--dry-run`) install**. `--dry-run` just prints
the config and needs nothing.

Provide them either by exporting in your shell:
```bash
# device login (used by lab/device-run.sh to reach the devices) — required for a real install
export DEVICE_USER=<device-login-user>
export DEVICE_PASS='REPLACE_WITH_DEVICE_PASSWORD'
```
…or, recommended/repeatable, from a gitignored creds file you `source`:
```bash
mkdir -p creds
cat > creds/lab.env <<'EOF'
export DEVICE_USER=<device-login-user>
export DEVICE_PASS='REPLACE_WITH_DEVICE_PASSWORD'
# only if installing from a machine OTHER than the server (remote STAGE_HOST):
# export HOST_USER=REPLACE_WITH_STAGEHOST_LOGIN
# export HOST_PASS='REPLACE_WITH_STAGEHOST_PASSWORD'
EOF
chmod 600 creds/lab.env
source creds/lab.env
```

`creds/` is **gitignored** — real credentials must never be committed. `HOST_USER`/
`HOST_PASS` are only needed when the installer runs **somewhere other than the stage
host itself** (a remote `STAGE_HOST`, which the installer SSHes the per-device config
to); running it directly on the server host — the normal CLI case — needs neither.
The **Console** shipped in the standard single-container deployment runs *co-located*
with the artifact server, so Console-driven onboarding stages each device's config
**directly** — no stage-host credentials needed. You only configure a **Settings →
Stage host** login when the artifact server lives on a *different* host than the
Console (a genuinely remote `STAGE_HOST`); see
[Onboarding from Docker](#onboarding-from-docker-stage-host-credentials).

## Quick start

Everything below is the **command-line** path. Once the server is up (step 1) you can also
do all of it — publish, add devices, assign, onboard, watch the swarm — from a browser; see
[The Console (the web GUI)](#the-console-the-web-gui). The CLI and the Console act on the
same catalog, state, and swarm, so use either or both.

> Prefer to drive a first deployment with an AI assistant? A ready-to-paste,
> console-focused prompt is in [Deploy with an AI assistant (PoC/PoV)](#deploy-with-an-ai-assistant-pocpov)
> further down — proof-of-concept / proof-of-value only, not production.

### 1. Stand up the server

Pick ONE:

**Docker (easiest):**
```bash
# one time: install age, then create an at-rest secret-encryption identity (or reuse one).
sudo apt-get install -y age          # Debian/Ubuntu — or: sudo dnf install -y age
mkdir -p ~/.config/iris && age-keygen -o ~/.config/iris/age-key.txt

# write server/.env. `age-keygen -y` re-derives the PUBLIC recipient (age1…) from the
# identity file, so the ONLY value you fill in by hand is the server's IP.
cat > server/.env <<EOF                                    # one time
IRIS_HOST_IP=<this server's IP>
IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age-key.txt
IRIS_AGE_RECIPIENTS=$(age-keygen -y ~/.config/iris/age-key.txt)
EOF

# first time only: mint the encrypted secret store (seeder announce token,
# rpc-secret, TLS key) onto the iris-config volume so the server can start.
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap

docker compose -f server/docker-compose.yml up -d --build
```
`IRIS_AGE_KEY_FILE_HOST` is the host path to your age **identity** (private key,
mounted read-only as a Docker secret); `IRIS_AGE_RECIPIENTS` is a comma-separated
list of age **public** keys (primary[,break-glass]) the at-rest store is encrypted to.
`iris-bootstrap` is idempotent and only needs to run once — subsequent code changes
just need `up -d --build` (volumes, and therefore the secrets, persist).
To have the Console's Settings page show the release version, pass it at build time —
`IRIS_VERSION="$(cat VERSION)" docker compose -f server/docker-compose.yml up -d --build` —
or add `IRIS_VERSION=<version>` (the repo-root `VERSION` file's content) to `server/.env`
once per release. It is baked into the image at build time; unset, Settings shows `unknown`.
There is nothing to prepare beforehand: the build fetches everything the server needs
by itself — `python3`, `mktorrent` and `openssl` via apt, and the static `aria2c`
BitTorrent client, which it downloads and checksum-verifies (version + sha256 are
pinned; the build fails on a mismatch). All of it is declared in one file:
`server/Dockerfile`.

`IRIS_HOST_IP` is always **the machine running docker** — the devices must be able to
reach it. It exists because the catalog's TLS certificate (provisioned from the
age-encrypted secret material and decrypted to tmpfs at container start) must carry
this server's IP in its SAN. Putting it in `server/.env` once means every
later `docker compose` command just works without it.

**Inside the container, these paths matter** — only the first is part of the image;
the rest are storage on the host, mounted in:

```
path in container      comes from                        holds
--------------------   -------------------------------   --------------------------------
/opt/iris/             baked into the image at build     server/ code + aria2c
/etc/iris/             named volume iris-config          age-encrypted secrets (secrets.json.age
                                                         — incl. the Console admin + device
                                                         credential profiles; rpc-secret.age,
                                                         tls/key.pem.age), tls/crt.pem, audit.jsonl
/run/iris/             tmpfs (RAM only, never persisted) plaintext secrets decrypted at start
/var/lib/iris/         named volume iris-state           catalog/device state, .torrents,
                                                         the Console's fleet.json inventory
/var/lib/iris-images/  named volume iris-images          images uploaded via the web Console
/opt/images/           the host's /opt/images (ro)       your IOS-XE .bin images
```

The three **named volumes** are directories Docker manages on the host (physically
under `/var/lib/docker/volumes/` — see `docker volume inspect iris-config`).
Because the secrets and state live there and not in the image, they survive every
rebuild and restart. Day-2 rules:

- Edited code under `server/`? Rebuild and restart:
  ```bash
  docker compose -f server/docker-compose.yml up -d --build
  ```
  If the server runs from a **copy** of the repo (e.g. you develop on a workstation and
  the server has its own checkout), sync the code there *before* rebuilding, or the image
  picks up stale code. Exclude the heavy and host-local paths so the sync stays fast and
  never clobbers the server's own data:
  ```bash
  rsync -az \
    --exclude '.git' --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.DS_Store' \
    --exclude 'artifacts/' --exclude 'fleet/dist/' --exclude 'fleet/*.csv' \
    --exclude 'creds/' --exclude 'server/.env' \
    --exclude 'images/' --exclude 'release/' --exclude 'torrents/' \
    ./ <user>@<server>:~/iris/
  ```
  The excludes matter: `images/`, `release/`, and `torrents/` are large local-only
  artifacts (multi-GB `.bin` copies) that the server already has under `/opt/images` or
  in its `iris-state` volume — pushing them is wasteful and can stall the sync. `creds/`,
  `server/.env`, and `fleet/*.csv` are host-specific (credentials, `IRIS_HOST_IP`,
  inventory) and must not be overwritten. Avoid `--delete` on the first sync.
- New `.bin` to distribute? Just put it in `/opt/images/iosxe/c9300/` on the host —
  visible in the container immediately, no rebuild.
- Want to wipe the secrets/state and start over (e.g. you changed `IRIS_HOST_IP` in
  `server/.env` and need the TLS cert regenerated)? Delete the volumes and start fresh:
  ```bash
  docker compose -f server/docker-compose.yml down -v
  docker compose -f server/docker-compose.yml up -d --build
  ```

**Bare metal (systemd):**
```bash
tools/get-aria2c.sh             # bare-metal only: fetch + verify the aria2c binary
sudo IRIS_HOST_IP=<this server's IP> ./server/install.sh   # creates user, dirs, TLS cert, tokens, 3 services
```

Either way you get: tracker on `:6969`, HTTPS catalog on `:8443`, and a seeder.

#### Secrets (good news: you never touch them — and nothing permanent is baked)

Secrets live encrypted-at-rest on the config volume and are brokered to devices on
demand — **no permanent token or RPC secret is ever written into an installer or onto
a device's flash.** Instead:

- The fleet generator (step 5) asks the server for a **short-lived enrollment token**
  per device (`iris-mint-enrollment <device_id>`, TTL `IRIS_ENROLL_TTL`, default **1 h**)
  and bakes only that into the installer.
- On its **first tick** the agent posts that enrollment token to
  `POST /v1/devices/<id>/token-refresh` and receives its full **7-day catalog token**,
  its **announce token**, and the **RPC secret** — which it writes to its own config and
  refreshes automatically thereafter (at half-life). If an enrollment token leaks, it
  expires within the hour and was never device-bound to anything durable.

Tokens are short-lived and auto-rotate — there is nothing to list or manage by hand.
To revoke a device immediately (fails that device's catalog requests on its next
attempt; the action is audited in `/etc/iris/audit.jsonl`):
```bash
docker compose -f server/docker-compose.yml exec iris iris-revoke <device-ip>
```

### 2. Publish an image

Nothing to copy anywhere: the host's `/opt/images` directory is already mounted into
the container, so any `.bin` under `/opt/images/iosxe/c9300/` on the host is visible
inside. One command:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/cat9k_iosxe.26.01.01.SPA.bin
```

Run directly on the server's interactive shell this is fine as written. If you drive
it over a non-interactive SSH session (`ssh server 'docker compose … exec …'`), add
`-T` so Compose doesn't try to allocate a TTY that isn't there — without it the command
aborts with `the input device is not a TTY`:

```bash
docker compose -f server/docker-compose.yml exec -T iris \
  iris-publish /opt/images/iosxe/c9300/cat9k_iosxe.26.01.01.SPA.bin
```

`iris-publish` finds everything else itself (the tracker URL from `IRIS_HOST_IP`, the
seeder token and rpc-secret from its own config files). It computes the SHA-256,
builds a private `.torrent`, registers it in the catalog, and starts seeding:
```
published cat9k_iosxe.26.01.01 sha256=7de3c687… info_hash=c9fd2e2b…
```
Publishing alone changes nothing on any device — devices act when you *assign* an
image to them (step 6).

### 3. Device agent bundle — auto-staged for Guest Shell

For **Catalyst 9300 (Guest Shell)** there is **nothing to build by hand**: the server
container **self-provisions the served agent files at startup** — it rebuilds the agent
bundle (`iris-agent.tgz`) from the current sources, plus `bootstrap.sh` and
`iris-catalog.pem` (the pinned cert), into `artifacts/`, which it serves on `:8000` over
HTTPS. Because it rebuilds on every start, the served bundle always matches the deployed
agent code. Devices fetch everything from `https://<server>:8000/…` during install,
verified against the server cert via a per-device PKI trustpoint the installer configures
first.

You only run the packer by hand if you want to build a bundle outside the container:

```bash
tools/make-agent-bundle.sh      # optional — packs the agent + aria2c into one .tgz
```

For **Catalyst IE-3400 (IOx)** there is **one artifact the server cannot build itself** —
the aarch64 IOx package `iris.tar` (it needs an arm64 Docker build + `ioxclient`). Build it
once and drop it in `artifacts/`; see [Catalyst IE-3x00](#catalyst-ie-3x00-iox-docker-app).
The server logs a note at startup when `iris.tar` is absent, and the console's IE-3400
onboard fails fast with a clear message (device untouched) until it is staged.

### 4. Describe your devices in one CSV — network info ONLY

```bash
cp fleet/devices.csv.example fleet/devices.csv    # then edit
```
```csv
device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model
100.92.9.x,100.92.9.x,666,100.92.9.x,255.255.255.252,100.92.9.x,C9300
100.90.168.x,100.90.168.x,666,100.92.100.x,255.255.255.252,100.92.100.x,IE-3400
```
The optional `model` column selects the onboarding path (Catalyst 9300 → Guest Shell,
IE-3400 → IOx); leave it blank to auto-detect on onboard. No tokens, no secrets — that's
all handled for you in the next step.

### 5. Generate one installer per device, and run it

Run this **on the server machine** (it talks to the running container):
```bash
tools/gen-device-installers.sh                  # CSV -> fleet/dist/install-<device>.sh
fleet/dist/install-100.92.9.x.sh --dry-run      # preview the exact IOS config first
fleet/dist/install-100.92.9.x.sh                # do it (or fleet/dist/install-all.sh)
```
The generator asks the container for a **short-lived enrollment token** per device
(default 1 h) and bakes only that — **no permanent token or RPC secret is written into
the installer**. The catalog/stage URLs come from this machine's IP
(`IRIS_HOST_IP=<ip>` to override). On its first tick each agent self-promotes the
enrollment token to a full catalog token and fetches its RPC secret.

Each generated package is self-contained. Running it opens **one SSH session to the
device** (this is the only time anything connects to a device) and does pure
IOS-side work: enables IOx + Guest Shell with that device's VLAN/SVI, then **drops
four files** on it (a bootstrap script, the per-device config carrying only a 1 h
enrollment token, an empty RPC-secret placeholder, and the agent bundle). Everything
after that is the device's own doing — the agent self-promotes the token and fetches
the RPC secret on its first tick — no further
ssh: a 60-second EEM timer runs the bootstrap, which unpacks the bundle, starts the
BitTorrent client (capped at **10 peers** per device), and runs the agent.
Re-running a package is safe (idempotent).

> **Cutover (clean, no backward compatibility):** the secrets broker is a clean
> cutover — the new store starts empty and previously-baked permanent tokens are NOT
> honored. **Re-provision the fleet from scratch:** rebuild installers with
> `tools/gen-device-installers.sh` and re-run them on every device. Treat every secret
> ever baked into a past installer as compromised and rotate it.

**Upgrading the agent fleet-wide** is the same trick: rebuild the bundle
(`tools/make-agent-bundle.sh`) and copy the new `bundle.tgz` onto each device — the
bootstrap notices it on the next tick and applies it. No other steps.

### 6. Tell the devices which image they should have — one CSV

```bash
cp fleet/assignments.csv.example fleet/assignments.csv    # then edit
```
```csv
device_id,image_id
100.92.9.x,cat9k_iosxe.26.01.01
100.92.9.x,cat9k_iosxe.26.01.01
```
```bash
tools/apply-assignments.sh        # applies every row (run on the server)
```

To check what's published and who's assigned what, or to assign a single device:
```bash
docker compose -f server/docker-compose.yml exec iris iris-assign
docker compose -f server/docker-compose.yml exec iris iris-assign 100.92.9.x cat9k_iosxe.26.01.01
```
That's the whole "push": within ~60 s the device sees the new assignment, checks free
flash (reclaiming only via `install remove inactive` — it **never deletes image files
it didn't create**; if still short it just logs an error), downloads over the swarm,
sha256-verifies the staged file, then a native EEM applet clears any stale same-named
leftover and runs `copy /verify` (copy + Cisco signature in one IOS-enforced step — a bad
signature fails the copy and leaves no file). On the IE-3400 IOx runs from the SD card,
so the agent stages and copies on `sdflash:` instead of `flash:` (the C9300 uses `flash:`);
install/bundle mode detection applies identically on both platforms.
The agent polls `dir flash:` and emits
`ROOTCOPY … placed at flash root + verified` once the file appears, or `ROOTCOPY-FAIL` if
it never does. See [Security model](#security-model-short-version) for the trust boundary
in full.

**Assigning a DIFFERENT image later cleans up automatically**: before downloading
the new one, the device removes the old torrent from its BitTorrent client, deletes
the old staged files, and deletes the old `flash:` copy *that the agent itself
placed there* (it tracks its own copies and never touches anything else). No stale
files accumulate. Watch it happen:

```bash
printf 'show logging | include IRIS\n' | lab/device-run.sh 100.92.9.x
```
```
%IRIS-6-STAGING:           "downloading cat9k_iosxe.26.01.01.SPA.bin via private swarm"
%IRIS-6-PROGRESS:          "cat9k_iosxe.26.01.01.SPA.bin 64% (771MB/1202MB)"
%IRIS-6-DONE:              "cat9k_iosxe.26.01.01.SPA.bin complete sha256-ok id=cat9k_iosxe.26.01.01"
%HA_EM-6-LOG: IRIS-COPYROOT: ROOTCOPY-ATTEMPTED cat9k_iosxe.26.01.01.SPA.bin               # applet fired copy /verify (no success claim)
%IRIS-6-ROOTCOPY-VERIFYING: "cat9k_iosxe.26.01.01.SPA.bin applet running copy /verify"
%IRIS-6-ROOTCOPY:          "cat9k_iosxe.26.01.01.SPA.bin placed at flash root + verified"   # AGENT: file present at flash root after copy /verify
# on failure (bad signature -> copy /verify leaves no file) you would see instead, e.g.:
# %IRIS-6-ROOTCOPY-FAIL:   "cat9k_iosxe.26.01.01.SPA.bin verify timed out (no file appeared at flash root)"
```

### 7. See the fleet

```bash
DEVICE_TOK=<any device token>
curl -sk -H "Authorization: Bearer $DEVICE_TOK" https://<server-ip>:8443/v1/images     # what's published
curl -sk -H "Authorization: Bearer $DEVICE_TOK" https://<server-ip>:8443/v1/devices   # who has what (heartbeats)
```

## The Console (the web GUI)

Everything the CLI quick start does — publish an image, add devices, store login
credentials, assign an image, onboard a device, watch the swarm — can also be driven from
a browser. The Console is a small stdlib-only service (`iris-gui`) baked into the **same
server image**; it comes up automatically with the stack on
**`https://<IRIS_HOST_IP>:8080/`** (port `8080` is published by `server/docker-compose.yml`).
There is nothing extra to install or start. It reads and writes the same catalog, state,
and swarm as the CLI, so you can mix the two freely. It **stages only** — like the rest of
the tool it never installs, activates, or reloads a device (assigning an image just sets the
catalog's `approved_image_id`; `install_allowed` stays false).

### First run: create the admin

The Console has a **single admin account**. On the first visit it has none, so it sends you
to a one-time setup page:

1. Open `https://<IRIS_HOST_IP>:8080/`. The TLS cert is **self-signed** (the same cert the
   catalog and artifact server present), so the browser warns once — accept it to proceed.
2. You land on the setup wizard: pick a username and password (entered twice) and submit.
3. You're redirected to the login page — sign in with what you just set.

Prefer to set the admin ahead of time (automation, break-glass, or a password reset)? Do
it from the CLI instead — this creates or overwrites the single admin account:
```bash
# interactive (prompts for the new password twice):
docker compose -f server/docker-compose.yml exec iris iris-gui-admin <username>

# non-interactive (scripted): supply the password in the environment
docker compose -f server/docker-compose.yml exec \
  -e IRIS_GUI_ADMIN_PASSWORD='REPLACE_WITH_ADMIN_PASSWORD' iris iris-gui-admin <username>
```
The admin credential is scrypt-hashed and, like the server's other secrets, stored
age-encrypted at rest on the `iris-config` volume and decrypted to tmpfs at container
start — it is never baked into the image or an installer. The session is an
HttpOnly/Secure/SameSite cookie; state-changing requests carry a double-submit CSRF token.

### What you can do

- **Overview** — fleet totals (images, devices, staged, staging now) and a per-image
  rollout table (how many devices are assigned vs. actually staged), plus a link to the
  live [swarm map](#always-on-swarm-data-map-now-lives-in-the-console).
- **Images** — drag-and-drop (or pick) an IOS-XE `.bin` to upload; it is streamed to the
  server (4 GiB cap, filename whitelisted to `[A-Za-z0-9._-]`), SHA-256'd, turned into a
  torrent and seeded — the same work `iris-publish` does from the CLI. Each row shows
  id / file / size / SHA-256 / published-time with a **delete** action: a full delete
  (catalog entry + uploaded file + `.torrent`, and it stops seeding), refused with the list
  of devices if any device is still assigned that image.
- **Devices** — your fleet inventory. Add a device inline (management IP, VLAN/SVI, guest
  IP, model, credential profile) or **import/export CSV** (an **Example CSV** button
  downloads a ready-to-edit template); assign an image from a per-row dropdown
  (stage-only); **onboard** with one click — the server mints a short-lived enrollment
  token and runs the SSH installer, streaming the live log — or delete it. **Credentials**
  are reusable login profiles (username + password + optional enable secret) you define
  once and attach to many devices; passwords are stored age-encrypted and are never sent
  back to the browser.

  Console onboarding is **platform-aware**: it picks the installer by device family — Guest
  Shell (`device/device-install.sh`) for the Catalyst 9300/ISR/ASR/CSR/C8000v families, or
  the IOx Docker installer (`device/iox/install.sh`) for the IE-3x00/IR1101/IR18xx families,
  which cannot run Guest Shell. Set a device's `model` (or an explicit `platform`) to pick
  deterministically; leave both blank and the first onboard auto-detects the model via a
  live `show version` probe and caches it back onto the device row. IOx onboarding requires
  `iris.tar` (built by `device/iox/build.sh`) to already be staged in `artifacts/` — onboard
  fails fast with a clear error if it's missing, before touching the device.

  Onboarding is **parallel**: select any number of rows and hit **Onboard selected** — the
  server runs up to **25 installers at once** (`IRIS_ONBOARD_CONCURRENCY` to change) and
  queues the rest, so a several-hundred-device fleet onboards in waves instead of one at a
  time. A batch panel shows every device's live state (queued / running / done / failed /
  cancelled) with queue position, duration and its last log line; click a row's **log**
  for the full live stream, or **Cancel queued** to stop this batch's devices that haven't
  started yet (scoped to your batch — other sessions' queued onboards survive, and running
  installs are never killed mid-flight). A device never runs two installers at once
  (re-clicking joins the active job), and reloading the page re-attaches the panel to
  whatever is still running.

  **Undeploy selected** is the inverse (confirm-gated, same batch panel + pool): it removes
  exactly what onboarding added from each device and leaves generic config plus the staged
  image in place, so the next onboard is fast and nothing delivered is destroyed. It is
  **fleet-wide** — the console picks the right teardown per platform: Guest Shell
  (`device/device-uninstall.sh`: EEM applets, guestshell, app-hosting config, VLAN/SVI,
  logging discriminator, PKI trustpoint, `guest-share`) or IOx
  (`device/iox/uninstall.sh`: the IOx app stop→deactivate→uninstall, app-hosting appid,
  VLAN/SVI, trustpoint, `iris.tar`). A device busy onboarding can't be undeployed mid-flight
  (409). The devices table shows a green **deployed** badge once a device's assigned image
  is staged and verified.
- **Swarm** — the live swarm map, embedded: radial per-device view with progress
  rings; double-click a device for its detail drawer, which now shows the
  device's **telemetry report** (link tier, RTT, throughput, per-peer `~bytes`
  received/sent) and a **Pull fresh data from device** button — the device
  uploads a fresh report on its next poll (≤60 s). Double-click the central
  seed hub for the server's own per-device `~sent` table.
- **System** — a nav group holding **Settings** and **Monitoring**:
  - **Settings** — server & build info (version, admin user, host IP, ports, observability),
    change the admin password (a successful change signs out every other session), see and
    revoke other active sessions, and store the
    [stage-host SSH login](#onboarding-from-docker-stage-host-credentials) used by
    Docker-based onboarding.
  - **Monitoring** — the audit trail: a bounded 90-day circular log (`/etc/iris/audit.jsonl`,
    shared with the catalog process) of console actions — logins, password changes, device
    and image changes, credential and stage-host changes (never the password itself),
    onboarding starts/finishes, and telemetry pull requests. Filter by category (`auth`,
    `device`, `image`, `onboard`, `settings`, `telemetry`, `token`), refresh, and page
    further back with **Load older**.

Uploaded images live on the `iris-images` volume; the device inventory (`fleet.json`) lives
on `iris-state`; the admin account and credential profiles live age-encrypted on
`iris-config`. All three persist across rebuilds, exactly like the rest of the server state.

### Onboarding from Docker (stage-host credentials)

One-click onboarding shells out to the same `device/device-install.sh` the CLI uses.
In the standard single-container deployment the Console is co-located with the artifact
server and stages the per-device config directly (it writes into the read-write
`artifacts/staging/` bind). **Stage-host credentials are only needed when the artifact
server runs on a *different* host than the Console** — then the installer must SSH the
files to that remote `STAGE_HOST`.

For that remote case, configure the login once in **Settings → Stage host**: an SSH
user + password for the stage host (a low-privilege account is fine, but the installer
writes to `~/iris/artifacts/`, so that account's `~/iris` must be the checkout — or a
symlink to it — with `artifacts/` writable). Like the admin account and the device
credential profiles, it is stored **age-encrypted at rest** on `iris-config`, decrypted
only to the tmpfs at container start, never sent back to the browser, and handed to the
installer via the environment — it appears in neither the compose file, `docker
inspect`, nor the streamed onboard log. Clearing it (or never setting it) falls back to
`HOST_USER`/`HOST_PASS` from the container environment, for parity with the CLI path —
but the stored credential is the intended mechanism; passing real passwords through
compose `environment:` leaves them readable in plaintext on the host.

Co-located installs (Docker or native) where the Console runs on the stage host itself
need none of this — the installer detects the local case and writes directly.

## Catalyst IE-3x00 (IOx Docker app)

The IE-3x00 (e.g. the IE-3400) **cannot run Guest Shell** (removed from IOS-XE
≥17.9), so it runs there as a plain **aarch64 IOx Docker app** instead of inside
Guest Shell. The agent reaches IOS over an **SSH-to-self** session (the device's
own Vlan666 SVI) rather than the in-process `cli` module; catalog, swarm download
and seeding are otherwise identical to the C9300 path. Build context, a reproducible
build script, and a **one-shot installer** (`device/iox/install.sh`, the IOx analog of
`device/device-install.sh`) live in [`device/iox/`](device/iox/README.md).

**Prerequisites:** the SD card must be **partitioned** into an IOS-visible `sdflash:`
(vfat) plus an IOx (ext4) partition — `show sdflash: filesys` shows both. The agent
**stages the image to `sdflash:`** (the IE3x00 analog of the C9300's `flash:`): since
IOx can't bind-mount `sdflash:` into the container, the agent **scp-pushes** the
downloaded image to `sdflash:guest-share/iris/` via the device's SCP server, then
`copy /verify`s it to `sdflash:<img>`. The quickest path is the installer:

```bash
DEVICE_IP=100.90.168.99 VLAN=666 SVI_IP=100.92.100.253 SVI_MASK=255.255.255.252 \
  GUEST_IP=100.92.100.254 CATALOG_TOKEN=<minted> DEVICE_ID=100.90.168.99 \
  STAGE_HOST=100.90.168.20 DEVICE_SSH_PASS=<device-pw> IRIS_CRT_FILE=<server crt.pem> \
  device/iox/install.sh
```

The manual steps below are what `install.sh` automates. The lab example uses device
`100.90.168.99`, guest VLAN 666 (guest
`100.92.100.254/30`, SVI/gateway `100.92.100.253`), server `100.90.168.20`.

**1. Build `iris.tar`** (machine with Docker — Apple silicon builds arm64
natively — and a configured `ioxclient`):

```bash
device/iox/build.sh                 # -> device/iox/out/iris.tar  (~119 MB)
```

> **Server re-keyed, or agent code fixed, and no ioxclient at hand?** `iris.tar`
> bakes the catalog CA (and the agent code) at build time, so a re-keyed server
> strands every IE-3400: the agent pins the old cert and can never reach the
> catalog again (the console shows the device as *not enrolled* even though the
> onboard succeeded). You don't need to rebuild: `device/iox/rebake_iris_tar.py`
> swaps files inside an already-built package offline and recomputes the full
> OCI + package hash chain (stdlib Python, runs anywhere — the aarch64 binaries
> are untouched):
>
> ```bash
> python3 device/iox/rebake_iris_tar.py artifacts/iris.tar artifacts/iris-new.tar \
>   opt/iris/iris-catalog.pem=<the server crt.pem> \
>   opt/iris/agent/iris_agent.py=device/agent/iris_agent.py
> mv artifacts/iris-new.tar artifacts/iris.tar   # then re-onboard the IE-3400s
> ```

**2. Publish + assign an IE image** (on the server). IE images live in their own
`/opt/images/iosxe/IE3400` subdir. Unlike the C9300 publish in step 2 above — which
runs through the container entrypoint and so inherits the seeder token and RPC secret
automatically — this path uses `docker exec`, which **does not inherit the entrypoint's
environment**. You therefore have to hand `iris-publish` two things explicitly: the
seeder's RPC secret (`-e IRIS_RPC_SECRET_FILE=…`) and a `--tracker-url` carrying the
seeder's announce key (`?key=<seeder token>`). The first line below reads that token out
of the running container's tmpfs secret store:

```bash
KEY=$(docker exec iris sh -c 'python3 -c "import json;print(json.load(open(\"/run/iris/secrets.json\"))[\"seeder\"][\"announce_token\"][\"value\"])"')
docker exec -e IRIS_RPC_SECRET_FILE=/run/iris/rpc-secret iris \
  iris-publish /opt/images/iosxe/IE3400/ie3x00-universalk9.17.18.03.SPA.bin \
  --tracker-url "http://100.90.168.20:6969/announce?key=$KEY"
docker exec iris iris-assign 100.90.168.99 ie3x00-universalk9.17.18.03
```

Success signal: `iris-publish` prints `published ie3x00-universalk9.17.18.03 sha256=…
info_hash=…`, and the image appears in the catalog. (The catalog's
`cisco_signature_verified` field stays `false` — that is metadata recording that the
*server* did not pre-verify the Cisco signature, **not** a failure. The real signature
check happens on the device via `copy /verify` in step 6.)

**3. Mint the device's enrollment token** (on the server):

```bash
docker exec iris iris-mint-enrollment 100.90.168.99
```

**4. Copy `iris.tar` onto the device's flash.** Drop the built `iris.tar` into the
server's `artifacts/` directory — the container **already serves it on `:8000` over
HTTPS**, so there is no throwaway web server to start. The device pulls it over verified
HTTPS (against the server cert, via the per-device PKI trustpoint the installer
configures first), exactly the way `device/iox/install.sh` does it. The one-shot
installer at the top of this section automates this; if you are doing it by hand, the
file lands at `flash:iris.tar` on the device.

Expected signal: after the pull, `dir flash: | include iris.tar` on the device lists the
file.

**5. On the device** — disable app signing (EXEC mode, *not* config), configure
the app, then install/activate/start:

```
app-hosting verification disable
configure terminal
app-hosting appid iris
 app-vnic AppGigabitEthernet trunk
  vlan 666 guest-interface 0
   guest-ipaddress 100.92.100.254 netmask 255.255.255.252
 app-default-gateway 100.92.100.253 guest-interface 0
 app-resource profile custom
  cpu 400
  memory 768
  persist-disk 2048
  vcpu 1
 app-resource docker
  run-opts 1 "-e IRIS_DEVICE_ID=100.90.168.99 -e IRIS_DEVICE_SSH_PASS=<device-pw> -e IRIS_CATALOG_TOKEN=<minted-token>"
end
! then in EXEC:
app-hosting install appid iris package flash:iris.tar    ! wait for DEPLOYED
app-hosting activate appid iris
app-hosting start appid iris
```

> Apply the `app-hosting appid iris` block with **no explicit `exit` lines** (IOS
> auto-pops; an explicit `exit` silently drops the `app-vnic` and `activate` then
> fails "No interface configured"). The catalog token and device password are
> passed at deploy time via `run-opts -e` — never baked into the image.

**6. Verify**: `show app-hosting list` → `iris RUNNING`; `show app-hosting detail
appid iris` → `Status : 0`. The device refreshes its token, downloads the assigned
image over the swarm, and appears on the swarm map
(Console → Swarm, `https://100.90.168.20:8080/`) labelled by model. The agent reaches IOS by
SSH-to-self, so its conf carries `device_ssh_host`/`device_ssh_user`/
`device_ssh_pass` (defaulted in the image to the Vlan666 SVI + `dnac`).

See [`device/iox/README.md`](device/iox/README.md) for the full recipe and deploy
gotchas. The image is staged to **`sdflash:`** (via scp-push + `copy /verify`) — the
IE3x00 analog of the C9300 placing it on `flash:`.

## Day-to-day: which command when

```
this happened                       you run
---------------------------------   ----------------------------------------------------
new image to distribute             iris-publish (step 2), edit fleet/assignments.csv,
                                    tools/apply-assignments.sh — nothing else
new device joins the fleet          add a row to fleet/devices.csv,
                                    tools/gen-device-installers.sh,
                                    run its fleet/dist/install-<device>.sh
device agent code changed           tools/make-agent-bundle.sh, then re-run each
(upgrading the agent itself)        device's fleet/dist/install-<device>.sh — it
                                    re-drops the bundle and the device self-applies
                                    it on the next 60s tick (regenerate the packages
                                    first with tools/gen-device-installers.sh if you
                                    don't have fleet/dist/ anymore)
server code changed                 docker compose -f server/docker-compose.yml up -d --build
```

The container serves `artifacts/` on `:8000` over HTTPS by itself, so there is never a
web service to start; the bundle only needs rebuilding when the agent code changes. In
steady state, distributing images is just: publish, edit the assignments CSV, apply.

## Ports & network flows

Every port intelligent-release-image-staging uses, and the exact **source → destination**
of each flow, split into **install** (one-time, per device) and **operations**
(steady-state rollout). **All ports are TCP** and every source port is ephemeral, so the
port shown is the **destination** — the one you open in a firewall. Everything talks to a
**single server host** plus **device-to-device** peer traffic on a flat L3 fabric. (See
[Observability](#observability) for the opt-in telemetry layer and
[Firewall & caveats](#firewall--caveats) below.)

### Install

```
port  from -> to                             proto  purpose
-----------------------------------------------------------------------------------------
22    install host -> device IOS             SSH    drive CLI, push config + trustpoint
22    install host -> remote STAGE_HOST      SSH    stage per-device config (remote install
                                                    host, or a Console whose stage host is
                                                    on a different machine)
8000  install host -> artifact server        HTTPS  preflight the artifact server
8000  device copy https: -> artifact server  HTTPS  pull agent bundle / config / pkg
```

Console one-click onboarding runs the same installer from the iris container. The
installer→device `22` flow still applies (drive CLI + push trustpoint). The
container→stage-host `22` hop applies **only when the stage host is a different machine**
than the Console; in the standard single-container deployment the Console is co-located
with the artifact server and stages the per-device config directly (no ssh) — see
[Onboarding from Docker](#onboarding-from-docker-stage-host-credentials).

### Operations

```
port       from -> to                    proto     purpose
-----------------------------------------------------------------------------------
8443       device agent -> catalog       HTTPS     policy, torrent, heartbeat (60s)
6969       device / seeder -> tracker    HTTP      BitTorrent announce (30s)
6881       device -> server seeder       BT wire   pull pieces from the origin
6881-6999  seeder / peers -> device      BT wire   inbound P2P re-seed
6881-6999  device -> other devices       BT wire   outbound P2P fetch
8080       operator browser -> console   HTTPS     Console UI/API (admin session)
6800       agent -> local aria2c         JSON-RPC  control download (loopback)
6800       server tools -> seeder        JSON-RPC  publish + sample (loopback)
9101       console /api/swarm -> :9101   HTTP      swarm summary proxy (loopback)
22         IE-3400 agent -> its own IOS  SSH/SCP   SCP image, then copy /verify
```

### Telemetry

The `/swarm` JSON and `/healthz` on `:9101` are **always on** (the map page moved into the
Console); `/metrics` and the OTLP push are **opt-in** (`IRIS_OBSERVABILITY=1`). Point your own
Prometheus at `<server>:9101` and set `IRIS_OTLP_ENDPOINT` to your collector — these live in your
monitoring stack, not this project's compose.

```
port       from -> to                        proto  purpose
----------------------------------------------------------------------------------
9101       console (loopback) + Prometheus   HTTP   /swarm JSON + health (always on)
9101       Prometheus -> /metrics            HTTP   scrape iris_* (opt-in)
4318       tracker -> OTel collector         OTLP   push lifecycle events (opt-in)
3100       OTel collector -> Loki            HTTP   forward events to Loki
9090/3000  operator -> Prometheus / Grafana  HTTP   open dashboards
```

### Firewall & caveats

```
open (all TCP)                   ports
----------------------------------------------------
inbound to server, from devices  6969 8443 6881
inbound to server, operators     8080
inbound to server, install only  8000
device <-> device, both ways     6881-6999
inbound to each device, install  22
outbound from server, opt-in     4318 3100 3000
```

The `8080` Console is reached from operator browsers; `9101` only from the
Prometheus host (and the Console's loopback proxy) — devices never call
`9101`; their telemetry reports ride the authenticated catalog on `8443`.

- **`EXPOSE` ≠ what's published.** `server/Dockerfile` `EXPOSE`s `6969 8443 6800 9101 8080` —
  it *omits* `8000` and `6881` (both published in `docker-compose.yml` and **required**) and
  *includes* `6800` (deliberately **not** published). Trust `docker-compose.yml`, not `EXPOSE`.
- **`6800` never touches the network.** Both aria2 JSON-RPC ports bind `127.0.0.1`
  (`--rpc-listen-all=false`); the server's is reached via `docker compose exec`. Don't open it.
- **No UDP tracker, no DHT.** Torrents are private and every aria2c disables DHT/PEX/LPD, so
  `6969/tcp` is the *sole* peer-discovery path — there is no `6969/udp` and no DHT port.
- **`6881` is pinned only on the origin seeder;** each device uses aria2's first-free port in
  `6881-6999` and announces whichever it picked.
- **Catalog (`:8443`) and artifact server (`:8000`) are HTTPS** in every deployed config; the
  **tracker (`:6969`) and telemetry (`:9101`) are plain HTTP** by design.

## Observability

intelligent-release-image-staging ships two layers of observability. The first is always on and
self-contained — no external dependencies. The second is opt-in for sites that
already run a Grafana/Prometheus stack.

### Always on: swarm data (map now lives in the Console)

The tracker container exposes live swarm data on port `9101`:

- **`GET /swarm`** — JSON snapshot of every swarm (per-image, per-peer rows:
  ip, role, progress, upload rate, `~sent` bytes, model, device id, and the
  latest device-report summary). This is the loopback feed the Console's
  `/api/swarm` proxy reads.
- **The swarm map page moved into the Console** (`https://<iris-host>:8080/`,
  Swarm tab — session-gated). `GET /swarmmap` on `:9101` now answers with a
  small pointer page to the Console; old bookmarks fail helpfully.
- **`GET /healthz`** — liveness probe (`ok`).

### Device telemetry reports (issue #13)

After a device finishes staging (or lands in seeding-only), its agent reports
how the transfer went to the catalog (`POST /v1/devices/<id>/telemetry`,
device-bound token): transfer totals, link quality (HTTPS RTT median,
heartbeat-failure streak — no ICMP), and a per-peer breakdown of `~bytes`
received/sent per peer. Per-peer numbers are rate-integrated samples (aria2
exposes no cumulative per-peer counter), so they carry a `~` in the GUI.

Reporting is **polite by design**: on a healthy link the full report goes out
once, with 0–10 s random jitter so a finishing batch doesn't phone home in
sync; on a constrained link (high RTT / slow transfer) the per-peer rows are
dropped and bodies over 1 KiB are gzipped; on a lossy link (repeated failures)
the agent backs off exponentially (up to ~16 min between tries) and keeps the
data for a later pull. The server stores the **last 5 reports per device**
(~16 KB each, hard-capped) under the state volume — bounded disk by
construction.

Toggle: the agent conf key `telemetry` (default **on**; set `telemetry = off`
in `iris-agent.conf`, or `TELEMETRY=off` / `-e IRIS_TELEMETRY=off` at install
time). When off the device samples nothing and sends nothing, and its
heartbeat says so — the Console shows *telemetry disabled* instead of an
empty drawer. Manual pull: Console → Swarm → double-click a device → **Pull
fresh data from device** (delivered on the device's next 60 s poll).
With `IRIS_OBSERVABILITY=1`, each ingested report is also exported to Loki as
an OTLP log record (`event=device-report`).

### Opt-in: Prometheus + OTLP → Loki (off by default)

For sites that already run Grafana/Prometheus/Loki (or a full OpenTelemetry
collector), the server can additionally:

* expose `GET /metrics` (low-cardinality Prometheus exposition — `iris_swarm_*`,
  `iris_seeder_*`, `iris_tracker_*` gauges/counters) on the same port `9101`,
* push per-device lifecycle events (`join` / `complete` / `stop` / `stale`) to
  an OpenTelemetry collector via OTLP/HTTP-JSON `/v1/logs` (the collector then
  fans those out to Loki, where they're queryable by `service_name="iris-tracker"`
  and structured-metadata fields like `event`, `ip`, `info_hash`).

This whole layer is **opt-in**. The system makes no assumption that you have a
Grafana stack around; with the flag off, `/metrics` returns 404 and no events
are pushed, while the swarm map keeps working.

**Turn it on** by setting both env vars on the `iris` container — for example
in `server/docker-compose.yml`:

```yaml
    environment:
      IRIS_HOST_IP: "${IRIS_HOST_IP:?...}"
      IRIS_OBSERVABILITY: "1"
      IRIS_OTLP_ENDPOINT: "http://<your-otel-collector>:4318"
```

Then point Prometheus at `<iris-host>:9101` and load the `iris-fleet-rollout`
Grafana dashboard (the JSON spec lives in `docs/dashboard/`).

- **`IRIS_OBSERVABILITY`** *(default: unset / `0`)* — external observability OFF: `/metrics`
  404s, no OTLP push.
- **`IRIS_OBSERVABILITY=1`** — turns on `/metrics` + (if endpoint set) OTLP push.
- **`IRIS_OTLP_ENDPOINT`** *(default: unset)* — base URL of an OTLP/HTTP collector, e.g.
  `http://10.0.0.5:4318`. Inert unless `IRIS_OBSERVABILITY=1`.
- **`IRIS_METRICS_PORT`** *(default: `9101`)* — swarm-JSON + (when on) metrics-listener port.
  Empty or `0` disables this HTTP surface (`/swarm`, `/healthz`, `/metrics`); the swarm map
  itself lives in the Console and is unaffected — though its data feed via `/api/swarm` needs
  `/swarm` up.
- **`IRIS_SAMPLE_INTERVAL`** *(default: `15`)* — seconds between local seeder RPC polls +
  OTLP batch flushes.
- **`IRIS_GUI_PUBLISH`** *(default: `8080`)* — the host-side port the console is published on;
  override on shared hosts where `:8080` is already taken (e.g. Jenkins).
- **`IRIS_CONSOLE_URL`** *(default: unset)* — overrides the console link on the `:9101` pointer
  page verbatim; set this alongside `IRIS_GUI_PUBLISH` so old bookmarks redirect to the right port.

Stdlib-only — no third-party Python dependencies. Telemetry is best-effort:
a failed metrics bind, unreachable collector, or downed seeder RPC can never
disrupt the tracker.

## Scaling

intelligent-release-image-staging is a **private BitTorrent swarm**, which is what makes it scale: every
device that finishes an image keeps **seeding** it to the others (the agent runs
aria2c with `--seed-ratio=0.0` = seed indefinitely), so the single server seeder
is the *origin*, not the bottleneck — distribution load fans out across the fleet
as the rollout progresses. The lab proves this: after staging, all four C9300s
and the IE-3400 show `seeder` on the swarm map and serve pieces to each other.

What scales, and the knobs:

- **Origin bandwidth** — devices re-seed to peers, so the server serves each image a bounded
  number of times, not once per device. Add dedicated secondary seed nodes for huge sites
  (run the seeder against the same images + tracker URL).
  *Knob:* `server/seed-launch.sh` (re-seeds every `*.torrent` in the state volume on boot).
- **Per-device fan-out** — each device caps simultaneous BT peer connections so a
  constrained device isn't overwhelmed, while the mesh stays well-connected.
  *Knob:* `max_peers` (agent conf) · `IRIS_MAX_PEERS` (IOx app) · `MAX_PEERS`
  (guestshell-start) — default `10`.
- **Tracker load** — stdlib threaded HTTP; clients re-announce every 30 s, silent peers are
  pruned at >60 s, and each announce returns at most `NUMWANT_CAP=200` peers. Hundreds of
  devices = a few requests/second. *Knob:* `peer_registry.INTERVAL`, `NUMWANT_CAP`.
- **Many images at once** — each image is its own private torrent/swarm; the server seeds
  all of them and the swarm map shows every image+device together (colour = image).
  *Knob:* one `iris-publish` per image.
- **Visibility at scale** — the unified swarm map renders all devices across all torrents on
  one screen; the per-image selector narrows focus. *Knob:* Console → Swarm.

**Capacity rule of thumb:** one server-seed origin + device-to-device re-seeding
comfortably covers a few hundred devices per image on a flat L3 fabric. Beyond
that, add per-site secondary seeders (closer to the devices) and raise
`max_peers` modestly so the mesh heals faster.

**Known limits (honest):** there is a single tracker process and a single
server-seed origin, and devices are enrolled from a per-device CSV +
`gen-device-installers.sh`. For *thousands* of devices across many sites the next
steps are zero-touch / group-policy enrollment (no per-device script),
hierarchical/site-local seeders, and a redundant tracker — a roadmap item, not in
this release.

## Quick reference (cheat sheet)

Copy-paste, swap the `<placeholders>`. Run server-side commands on the server host.

**Bring up the server (one shot):**
```bash
echo "IRIS_HOST_IP=<server-ip>" > server/.env        # once — every later `docker compose` command then has it
docker compose -f server/docker-compose.yml up -d --build
# CLI path continues below; OR drive it all from the browser — the web Console is now at
# https://<server-ip>:8080/ (self-signed cert; create the single admin on first visit).
docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/iosxe/c9300/<image>.SPA.bin
tools/make-agent-bundle.sh && tools/gen-device-installers.sh
```

**Deploy / cut over a device:**
```bash
source creds/lab.env                                  # DEVICE_USER/DEVICE_PASS — see Credentials above
fleet/dist/install-<device-ip>.sh                     # add --dry-run first to preview
docker compose -f server/docker-compose.yml exec iris iris-assign <device-ip> <image-id>
printf 'show logging | include IRIS\n' | lab/device-run.sh <device-ip>   # watch: %IRIS-6-DONE + ROOTCOPY … verified
```

**Clear a device to a clean state (decommission — config + staged files, NO reload):**
```bash
source creds/lab.env
# 1) remove IRIS EEM applets (IRIS-COPYROOT is runtime-templated; harmless if absent)
#    + fully remove the logging discriminator (all 3 destinations + the definition)
printf '%s\n' 'configure terminal' \
  'no event manager applet IRIS-AGENT' \
  'no event manager applet IRIS-COPYROOT' \
  'no event manager applet IRIS-MONITOR' \
  'no event manager applet IRIS-BOOT' \
  'no logging buffered discriminator IRISQ' \
  'no logging console discriminator IRISQ' \
  'no logging monitor discriminator IRISQ' \
  'no logging discriminator IRISQ' \
  'end' | lab/device-run.sh <device-ip>
# 1b) remove the IRIS PKI trustpoint + http-client binding the HTTPS install adds
#      (the exact inverse of what device-install.sh issues). SKIP if you're re-installing
#      right after — the installer re-templates the IRIS trustpoint idempotently.
printf '%s\n' 'configure terminal' \
  'no ip http client secure-trustpoint IRIS' \
  'no crypto pki trustpoint IRIS' \
  'yes' \
  'end' | lab/device-run.sh <device-ip>
# `no crypto pki trustpoint` prompts "% Removing an enrolled trustpoint will
# destroy all certificates. Are you sure? [yes/no]:". The `yes` answers it; skip
# it and the rest of the cleanup gets eaten as the prompt's answer.
# 2) tear down Guest Shell + delete staged files (NO reload — stage-only)
printf 'guestshell destroy\n'                               | lab/device-run.sh <device-ip>
printf 'delete /force /recursive flash:/guest-share/iris\n'  | lab/device-run.sh <device-ip>
printf 'delete /force flash:/guest-share/bootstrap.sh\n'     | lab/device-run.sh <device-ip>
printf 'delete /force flash:/guest-share/iris-catalog.pem\n' | lab/device-run.sh <device-ip>
# 3) OPTIONAL full network revert (skip if re-installing IRIS right after):
printf '%s\n' 'configure terminal' \
  'default interface AppGigabitEthernet1/0/1' \
  'no interface Vlan<vlan>' 'no vlan <vlan>' \
  'no app-hosting appid guestshell' 'no iox' \
  'end' | lab/device-run.sh <device-ip>
# 4) persist the clean slate so it survives a reboot (saves config; still NO reload)
printf 'copy running-config startup-config\n' | lab/device-run.sh <device-ip>
```
Running-config + staged files only — **no reload anywhere** (the stage-only invariant).
`IRIS-AGENT` is the installed timer; `IRIS-COPYROOT` is the applet the agent
templates+fires at runtime (the `no … IRIS-COPYROOT` is harmless if it isn't present).
Step 1b removes the `IRIS` PKI trustpoint the HTTPS install adds (plus `iris-catalog.pem`,
the agent's pinned CA); both are only needed for a true clean slate — re-installing
re-creates them. Step 3 is optional — skip it if you're re-installing right after
(the installer re-applies that config). Step 4 (`copy running-config startup-config`)
persists the cleared config so it survives a reboot; skip it too if you're re-installing
right after.

## Deploy with an AI assistant (PoC/PoV)

This is for a **proof-of-concept / proof-of-value** run — a first, guided deployment on
a lab or pilot fleet. It is **not a production procedure**: no HA, no scale hardening, no
change-control. For anything beyond a PoC, follow the full chapters above and your own
production process.

The block below is a **copy-paste prompt**. Hand it to your own AI assistant (paste it as
the first message), then answer the questions it asks. It is written for **front-end
(Console) users**: it drives the browser Console — the **Devices**, **Swarm**, and
**Monitoring** tabs — and points back to the real chapters in this README for the server
bring-up rather than duplicating commands. The assistant will ask you a few plain
questions first, then walk you through server bring-up, publishing an image, and
onboarding devices from the Console, telling you at each step exactly what to answer or
click next.

Everything staged this way is **stage-only**: the tool distributes and stages images; it
**never installs, activates, or reloads** a device. Keep it that way.

````text
You are helping me run a first proof-of-concept deployment of a tool called
intelligent-release-image-staging. It does peer-to-peer distribution of Cisco IOS-XE
images to Catalyst 9300 and IE-3400 devices: devices pull image pieces from a server
AND from each other, then stage the image into device flash. It ONLY stages and
distributes images — it never installs, activates, or reloads anything on a device.

This is a proof-of-concept / proof-of-value, NOT production. Be explicit, literal, and
step-by-step; do not assume I am an expert and do not be clever. Where a step is
genuinely involved (server bring-up, ports), point me to the named README chapter
instead of inventing commands. Prefer the browser Console over raw command-line wherever
the Console can do the job.

RULES you must follow at all times (guardrails):
- Never delete or overwrite the boot image or the running image on any device.
- Confirm with me before any destructive or irreversible action, and describe exactly
  what it will change first.
- This tool only stages/distributes images. Never install, activate, or reload a device.
  If I ask you to, refuse and remind me that is out of scope for this tool.
- The server uses HTTPS with a self-signed certificate. Accept the browser's
  certificate warning for THIS server only. Never broadly disable TLS verification and
  never add flags that turn off certificate checking across the board.
- Keep secrets (device passwords, admin password, tokens) out of anything you print or
  log. Do not echo passwords back to me.
- NEVER ask me to type a password into this chat, and never accept one here. Any
  credentials you need live in a file: `creds/deploy.env` (copied from
  `creds/deploy.env.example`; the `creds/` directory is gitignored). Read that file
  directly when you need the server SSH login or the device login. Both blocks in it are
  OPTIONAL (see STEP 0): if a value you need for a step is missing or still the
  `change-me` placeholder, STOP and tell me to either fill it in or do that step myself
  (run the server bring-up / type the device login into the Console form), then
  continue — do NOT loop asking me for the value in chat.
- If a precondition is not met, or you are unsure, STOP and ask me a plain question.
  Do not guess and do not proceed on an assumption.
- At the END of every step, state clearly in one line WHAT THE NEXT STEP IS for me —
  what I need to answer, or what I need to click.

STEP 0 — First, credentials go in a FILE, never in this chat. Tell me to run
`cp creds/deploy.env.example creds/deploy.env` and fill in `creds/deploy.env`. Both
blocks in it are OPTIONAL: the server SSH login (`SERVER_HOST` / `SERVER_USER` /
`SERVER_PASS`) is only needed if I want you to do the server bring-up for me, and the
device login (`DEVICE_USER` / `DEVICE_PASS` / `DEVICE_ENABLE`) is only needed if I want
you to fill in the Console credential profile for me — I can instead type the device
login into the Console myself in STEP 4. `creds/` is gitignored. Once the file exists you
read it directly — do not ask me to paste any password here, and if a value you need is
still `change-me`, stop and tell me to either fill it in or do that step myself, rather
than looping.

Then ask me these questions, one short list, in plain language, and wait for my answers
before doing anything else. (These are all non-secret — passwords stay in
`creds/deploy.env` or get typed into the browser, never into this chat.)
1. What is the server's host name or IP address? (the Linux box that will run the
   tool — example: 100.90.168.20. If `SERVER_HOST` is filled in in `creds/deploy.env`,
   it should match.)
2. Is Docker already installed on that server? (yes / no / not sure)
3. What image file do I want to distribute, and where is it on the server? (example:
   /opt/images/iosxe/c9300/cat9k_iosxe.26.01.01.SPA.bin)
4. My device inventory: how many devices, their management IP addresses, and for each
   whether it is a Catalyst 9300 or an IE-3400. (a short list is fine — example:
   100.92.9.10 is a 9300, 100.90.168.99 is an IE-3400)
5. The admin login I want to CREATE for the web Console — pick a username; I will set
   the password myself in the browser on first visit. (This is the Console admin, separate
   from the device and server logins.)

STEP 1 — Stand up the server. Point me to the README chapter "Stand up the server"
(anchor #1-stand-up-the-server) for the Docker path. If you run the bring-up commands on
the server yourself, SSH in using `SERVER_HOST` / `SERVER_USER` / `SERVER_PASS` from
`creds/deploy.env` — never ask me for the server login in chat. If `SERVER_*` is not
filled in, I am doing the bring-up myself: walk me through that chapter and wait for my
confirmation instead of SSHing anywhere. If Docker is not
installed, stop and tell me to install Docker first (or ask a server admin), then
resume. The bring-up needs
one host package besides Docker: `age` (for the one-time secret-encryption identity). If
`age-keygen` is not found, installing it with the host's package manager
(`apt-get install -y age`, or `dnf install -y age`) is EXPECTED and allowed — install it
and continue; do not stop and ask just for this. Follow the README's snippet exactly,
including the `age-keygen -y …` line that fills IRIS_AGE_RECIPIENTS automatically — the
only value you need from me is the server's IP (from STEP 0). The Console comes up
automatically with the server on https://<server>:8080/ (the standard published port; some
hosts remap it — if 8080 is already taken, the README documents the IRIS_GUI_PUBLISH
override). Next step for me: confirm the server is up and I can load the Console URL in a
browser.

STEP 2 — Create the Console admin. On first visit the Console has no admin, so it shows a
one-time setup page. See the chapter "First run: create the admin"
(anchor #first-run-create-the-admin). Tell me to open https://<server>:8080/, accept the
self-signed certificate warning once, and set the admin username and password on the setup
page, then sign in. Next step for me: sign in to the Console.

STEP 3 — Publish the image. This puts the image into the catalog and starts seeding it.
The Console "Images" tab can upload-and-publish a .bin by drag-and-drop; if the image is
already on the server under /opt/images, the README chapter "Publish an image"
(anchor #2-publish-an-image) shows the one-command server-side publish. Choose whichever
matches where my image is. Next step for me: confirm the image shows up in the Console
Images tab.

STEP 4 — Add my devices in the Console. Use the "Devices" tab (see "What you can do",
anchor #what-you-can-do). I can add devices one at a time inline, or import them as a CSV
(there is an "Example CSV" button that downloads a ready-to-edit template — use it so the
columns are right). Create a reusable credential profile once and attach it to my
devices, so I do not retype the login per device. If `DEVICE_USER` / `DEVICE_PASS` are
filled in in `creds/deploy.env`, use those (and `DEVICE_ENABLE`, if set) to fill the
profile; if they are not, tell me to type the device login into the credential-profile
form in my browser — never into this chat. Next step for me:
confirm all my devices are listed in the Devices tab with a credential profile attached.

STEP 5 — Onboard the devices from the Console. In the "Devices" tab, select the devices
(multi-select is supported) and use the one-click onboard. The Console mints a short-lived
enrollment token and runs the installer, streaming the live log. Note: onboarding a
Catalyst 9300 uses its Guest Shell; an IE-3400 runs as an IOx app and has extra
prerequisites — if any device is an IE-3400, read the chapter "Catalyst IE-3x00"
(anchor #catalyst-ie-3x00-iox-docker-app) with me BEFORE onboarding it, and stop to
confirm those prerequisites are met. Next step for me: watch the onboard log per device
and confirm each finishes without error.

STEP 6 — Assign the image and watch it stage. Assign the published image to each device
(a per-row dropdown in the Devices tab; this is stage-only and does NOT install or
reload). Then open the "Swarm" tab to watch the live map — devices pull the image over
the swarm and show progress rings; double-click a device for its telemetry drawer. Use
the "Monitoring" tab to see the audit trail of what happened. Next step for me: confirm on
the Swarm map that each device reaches "staged" / becomes a seeder.

STEP 7 — Stop here. Staging is complete. Installing/activating/reloading the new image is
a separate, deliberate action I perform through my normal device-management process — this
tool does not and must not do it. Tell me the PoC is complete and summarize what was
staged where.

If at any point a port seems blocked or a device is unreachable, point me to the README
chapter "Ports & network flows" (anchor #ports--network-flows) and ask me to confirm the
relevant port is open, rather than guessing.
````

### Public resources

The public mirror of the project — for fetching the docs referenced above — is at
**https://github.com/enihlen_cisco/iris**. Point your assistant there if it needs to read
the README chapters or other files directly.

### A rudimentary check that the server code is sane

Before or after the PoC you can run the project's main system tests (Python) to confirm
the server code base is healthy. This is the pytest command already documented in
[Running the tests](#running-the-tests):

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/test_verify_image.py -q
```

This runs the main system tests only. It does **not** touch hardware and does **not** spin
up virtual routers — it is purely a code-level sanity check. Do not write new tests for a
PoC.

## Running the tests

```bash
python3 -m pytest server/tests/ device/agent/tests/ device/test_verify_image.py -q
bats device/test_guestshell_start.bats device/tests/ server/tests/*.bats             # shell tests
```

## Security model (short version)

- Private swarm: DHT, PEX, and local peer discovery are **off**; the tracker requires a
  token; the catalog requires a per-device Bearer token over HTTPS.
- **Install-time transfers are verified HTTPS.** The installer pushes the server's cert
  into a per-device PKI trustpoint (`IRIS`) over SSH first, then `copy https://…:8000/…`
  delivers the bootstrap, per-device config, RPC secret, agent bundle, and the agent's
  pinned CA — so the per-device catalog token and the RPC secret never travel in
  cleartext.
- **The agent verifies the catalog cert.** Each agent pins the server cert
  (`catalog_ca`) and verifies the `:8443` catalog connection against it (verify-if-
  present: an un-pinned legacy config still works but logs a warning).
- **The chain of trust** is enforced end-to-end and fails closed at every step:
  1. catalog reached over **verified HTTPS** (pinned cert);
  2. BitTorrent piece hashes during download;
  3. **SHA-256 of the staged file** (`/flash/guest-share/iris/<f>`, hashed in
     guestshell) vs the catalog `sha256` — gates whether the copy runs at all;
  4. a native EEM applet does the privileged work in one shot: `delete /force
     flash:<f>` to clear any stale same-named leftover, then `copy /verify
     flash:/guest-share/iris/<f> flash:<f>` — copy **and** Cisco signature in
     one IOS-enforced step. A bad signature **fails the copy and leaves no
     destination file**. The applet has to do this — the agent's guestshell
     can't run `copy`/`verify` (`verify` hangs). It logs only a NEUTRAL
     `ROOTCOPY-ATTEMPTED` breadcrumb and makes no success claim;
  5. the agent owns the final pass/fail by **polling `dir flash:<f>`**. Because
     the applet deleted any leftover first, a file present afterwards can only
     be one this attempt's `copy /verify` wrote *and* signature-verified — so
     file presence **is** the verdict. On presence it emits `%IRIS-6-ROOTCOPY …
     placed at flash root + verified` and marks the image staged; if the file
     never appears within the poll budget (signature failed, or the copy never
     ran) it emits `%IRIS-6-ROOTCOPY-FAIL` and leaves nothing behind. The agent
     can't read the flash root as a file or run `verify` from guestshell, so it
     **trusts `copy /verify`** for authenticity rather than re-hashing.

  A `%IRIS-6-ROOTCOPY-VERIFYING` line marks the start of the (~2–4 min) applet
  run so the window isn't silent.
- **Defense-in-depth at the boundaries.** Catalog-supplied filenames are
  whitelisted against `^[A-Za-z0-9._-]+$` before any IOS interpolation, closing a
  catalog-controlled injection path into the templated EEM applet. On agent
  upgrade, persisted "copied" trust from any pre-v2 agent (whose `copy_to_root`
  returned True unconditionally — fixed in this release) is dropped and the
  flash-root file is re-verified on the first tick.
- The seeder's RPC listens on localhost only. Each device client caps at 10 peers.
- **Console credentials never rest in plaintext.** The admin login (scrypt-hashed),
  the device credential profiles, and the stage-host SSH login all live in the same
  age-encrypted store as the broker's tokens — decrypted to tmpfs at start, never
  returned to the browser, and passed to the onboard installer via the environment
  (sshpass reads them from env, so the streamed install log echoes no password).

## Hardware notes (the hard-won ones — all already handled by the code)

1. aria2c runs as the **guestshell user** (not root) and `--daemon=true`, or it dies
   when the `guestshell run` session ends. It can't execute from `/flash` (SELinux),
   so the launcher copies it to `/home/guestshell` first.
2. The Guest Shell `cli` Python module only works *inside* `guestshell run` — hence the
   EEM-timer-driven agent instead of a long-running daemon.
3. `guestshell run` accepts ONE program: no quotes, no `;`, no redirects, never `?`.
4. Extracting tars into `/flash/guest-share` needs
   `--no-same-owner --no-same-permissions -m` (SELinux-labeled mount).
5. EEM applets on AAA/TACACS-managed devices need **`authorization bypass`** or their
   CLI actions silently do nothing. EEM syslog-pattern triggers and `$_arg1` proved
   unreliable, so the agent *templates* the copy applet and fires `event manager run`.
6. `guestshell destroy` does NOT clean `/flash/guest-share` — old staged images linger.
7. Same directory, two names: the guest sees `/flash/guest-share/iris`, IOS sees
   `flash:/guest-share/iris`. Mixing them up gives `%Error opening flash:/flash/…`.
8. A directory created with IOS `mkdir` is root-owned — the guest user can't write
   inside it (`tar: Cannot mkdir: Permission denied`). That's why the installer drops
   files at the guest-share root and the bootstrap (guest user) creates the working
   directory itself.

## Uninstall / cleanup

- Server (Docker): bring down **only** iris — the compose file defines just the `iris`
  service, so this never touches your other containers:
  `docker compose -f server/docker-compose.yml down` (removes the iris container + network,
  keeps the `iris-state`/`iris-config` volumes = tokens/cert/catalog); add `-v` to wipe
  those volumes too, or `docker rm -f iris` to drop just the container.
- Server (bare metal): `sudo ./server/install.sh --uninstall` (keeps `/var/lib/iris` data).
- **Catalyst 9300 (Guest Shell, `flash:`):** `guestshell destroy`, remove the
  `IRIS-AGENT`/`IRIS-COPYROOT` applets, the `IRIS` PKI trustpoint (`no ip http client
  secure-trustpoint IRIS` + `no crypto pki trustpoint IRIS`), the `Vlan<id>`/`vlan <id>`
  config and `app-hosting appid guestshell`, then delete staged files under
  `flash:/guest-share/iris/` (incl. `iris-catalog.pem`). The full step-by-step
  (logging discriminators, the trustpoint prompt, optional network revert) is in
  [Clear a device to a clean state](#quick-reference-cheat-sheet) above.
  (Nothing is saved to startup-config unless you `write memory`.)
- **Catalyst IE-3x00 (IOx app, `sdflash:`):** the IE-3x00 has **no `IRIS-AGENT` timer** —
  it runs the agent as an IOx Docker app, so teardown is app-hosting lifecycle commands
  (EXEC mode) plus the same trustpoint/file cleanup, but on `sdflash:` instead of
  `flash:`. Stop, deactivate, and uninstall the app, then remove its config block,
  trustpoint, and staged files:
  ```bash
  # 1) app lifecycle (EXEC mode) — wait for each to clear before the next
  printf 'app-hosting stop appid iris\n'       | lab/device-run.sh <device-ip>
  printf 'app-hosting deactivate appid iris\n' | lab/device-run.sh <device-ip>
  printf 'app-hosting uninstall appid iris\n'  | lab/device-run.sh <device-ip>
  printf '%s\n' 'configure terminal' 'no app-hosting appid iris' 'end' | lab/device-run.sh <device-ip>
  # 2) IRIS applet + PKI trustpoint + http-client binding ('yes' answers the
  #    enrolled-trustpoint destroy prompt)
  printf '%s\n' 'configure terminal' \
    'no event manager applet IRIS-COPYROOT' \
    'no ip http client secure-trustpoint IRIS' \
    'no crypto pki trustpoint IRIS' \
    'yes' \
    'end' | lab/device-run.sh <device-ip>
  # 3) staged files + the IOx package + the agent-placed image (IE uses sdflash:, not flash:)
  printf 'delete /force /recursive sdflash:guest-share/iris\n'          | lab/device-run.sh <device-ip>
  printf 'delete /force sdflash:<ie-image>.SPA.bin\n'                   | lab/device-run.sh <device-ip>
  printf 'delete /force flash:iris.tar\n'                               | lab/device-run.sh <device-ip>
  ```
  Success signal: `show app-hosting list` no longer lists `iris`; `show run | section
  app-hosting appid iris` is empty; `dir sdflash: | include .bin|guest-share` shows
  neither the staged image nor the working directory. (Nothing persists to
  startup-config unless you `write memory`.) Note: `device/iox/install.sh` runs this
  same stop/deactivate/uninstall first, so for a **redeploy** you can skip the teardown
  and just re-run the installer — do the manual teardown only for a true decommission.

## License

intelligent-release-image-staging is licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE)
and [`NOTICE`](NOTICE). Copyright 2026 Cisco Systems, Inc.

The project itself contains no third-party source. The runtime tools it drives — `aria2c`,
`mktorrent`, and `openssl` — are **invoked as separate programs (subprocesses)**, not
linked into or derived from the project code: `aria2c` is fetched and verified at build
time, and `mktorrent`/`openssl` are system packages. Those tools remain under their
own licenses; see [`NOTICE`](NOTICE) for the per-tool attribution and details.

## Security & conduct

- Report security issues per [`SECURITY.md`](SECURITY.md) (GitHub private
  vulnerability reporting; fallback `oss-security@cisco.com`).
- Participation in this project is governed by our
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1).
