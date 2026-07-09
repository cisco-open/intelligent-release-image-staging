# intelligent-release-image-staging on the IE-3x00 (aarch64 IOx Docker app)

The Catalyst IE-3400 cannot run Guest Shell (removed from IOS-XE ≥17.9), so
intelligent-release-image-staging (IRIS) runs as a plain **aarch64 IOx Docker app**
instead of inside Guest Shell. The only functional difference from the C9300 build
is the CLI transport:

| | C9300 (Guest Shell) | IE-3x00 (this app) |
|---|---|---|
| reach IOS | in-process `cli` module | **SSH-to-self** (`cli_ssh`) to the Vlan666 SVI |
| runtime gate | default | `IRIS_RUNTIME_MODE=container` (baked in the image) |

`device/agent/cli_ssh.py` re-binds `cli_execute`/`cli_configure` behind a runtime
seam (`build_deps` → `cli_ssh.select_cli`). The C9300 Guest Shell path is
unchanged (default mode still does `from cli import execute, configure`).

## Build

```
./build.sh [OUTPUT_DIR]      # -> OUTPUT_DIR/iris.tar  (default device/iox/out/)
```
Needs Docker (Apple-silicon builds linux/arm64 natively) and a configured
`ioxclient` (v1.18 darwin_arm64; first run drives its profile wizard). The
aarch64 `aria2c` is extracted from `artifacts/iris-agent-arm.tgz`; the pinned
catalog cert is fetched from the artifacts server (override via `ARIA2C_BIN` /
`CATALOG_PEM`).

## Config delivery

`entrypoint.sh` (PID 1) generates `/data/iris/iris-agent.conf` from environment
on first boot (a conf dropped on a persistent mount wins), starts `aria2c` as the
BT RPC daemon, and runs `iris_agent.py --once` every `IRIS_TICK_SECONDS`. Secrets
are passed at deploy time via app-hosting docker `run-opts -e`, never baked in:

| env | conf key | notes |
|---|---|---|
| `IRIS_CATALOG_TOKEN` | `catalog_token` | **secret** — `iris-mint-enrollment <device_id>` on the server |
| `IRIS_DEVICE_ID` | `device_id` | the device's mgmt IP (convention), e.g. `100.90.168.99` |
| `IRIS_DEVICE_SSH_PASS` | `device_ssh_pass` | **secret** — login for SSH-to-self |
| `IRIS_DEVICE_SSH_HOST` | `device_ssh_host` | default `100.92.100.253` (Vlan666 SVI) |
| `IRIS_DEVICE_SSH_USER` | `device_ssh_user` | default `dnac` |
| `IRIS_CATALOG_URL` | `catalog_url` | default `https://100.90.168.20:8443` (must be the IP — cert SAN) |
| `IRIS_TELEMETRY` | `telemetry` | default `on` — post-staging telemetry reports + pull (set `off` to silence) |

> **Security follow-up:** the device login is held in cleartext in the conf on SD.
> Scope it (AAA `parser view` / command-authorization to `copy`/`dir`/`event
> manager`), restrict the VTY ACL to VLAN 666, prefer SSH **key** auth, and issue
> a rotating credential via the #27 secrets-broker. Pending security review.

## Deploy to the device (proven recipe)

1. **Publish + assign an IE image** (server) — required for the device to join a
   swarm and appear on the map:
   ```
   KEY=$(docker exec iris sh -c 'python3 -c "import json;print(json.load(open(\"/run/iris/secrets.json\"))[\"seeder\"][\"announce_token\"][\"value\"])"')
   docker exec -e IRIS_RPC_SECRET_FILE=/run/iris/rpc-secret iris \
     iris-publish /opt/images/iosxe/IE3400/ie3x00-universalk9.17.18.03.SPA.bin \
     --tracker-url "http://100.90.168.20:6969/announce?key=$KEY"
   docker exec iris iris-assign 100.90.168.99 ie3x00-universalk9.17.18.03
   ```
   (`-e IRIS_RPC_SECRET_FILE=/run/iris/rpc-secret` is required — `docker exec`
   does not inherit the entrypoint's exported env, so the seeder RPC secret must
   be pointed at the tmpfs copy or the seed step fails HTTP 400.)

2. **Mint the device token** (server): `docker exec iris iris-mint-enrollment 100.90.168.99`

3. **Get iris.tar onto the device flash**: drop the built `iris.tar` into the
   server's `artifacts/` directory — the `iris` container already serves it on
   `:8000` over HTTPS, so there is no throwaway web server to start. The device
   pulls it over verified HTTPS (against the server cert, via the per-device PKI
   trustpoint configured first), landing it at `flash:iris.tar`. This is exactly
   what `install.sh` automates; do it by hand only if you are not using the
   one-shot installer.

   This is also the only manual prerequisite for **Console one-click onboarding**:
   once `iris.tar` is staged in `artifacts/`, the Console picks this installer
   automatically for IE-3x00/IR1101/IR18xx devices (by `model`/`platform`, or by
   live auto-detection) — see the Console's Devices section in the top-level
   README. Onboarding fails fast, before touching the device, if `iris.tar` is
   missing.

4. **On the device** — 3 gotchas, all required:
   - **Disable app signing in EXEC mode** (config mode rejects it):
     `app-hosting verification disable`
   - The `app-hosting appid iris` block **must** include an `app-vnic` interface,
     and is applied with **no explicit `exit` lines** (IOS auto-pops; explicit
     exits silently drop the app-vnic). Networking = VLAN 666 / guest
     `100.92.100.254` / gw `100.92.100.253` (see the block below).
   - `app-hosting install appid iris package flash:iris.tar` → `activate` → `start`
     (DEPLOYED → ACTIVATED → RUNNING).

   ```
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
     run-opts 1 "-e IRIS_DEVICE_ID=100.90.168.99 -e IRIS_DEVICE_SSH_PASS=<pw> -e IRIS_CATALOG_TOKEN=<token>"
   ```

5. **Verify**: `show app-hosting list` (RUNNING), `show app-hosting detail appid
   iris` (Status 0). The device then refreshes its token, downloads the assigned
   image over the swarm, and appears on the Console swarm map
   (`https://100.90.168.20:8080/`, Swarm tab) labeled `IE-3400-8T2S`; the
   heartbeat carries model/version/free read over SSH-to-self.

## On-box staging to sdflash:

The agent stages the downloaded image to the IOS-visible `sdflash:` (the IE3x00 analog
of the C9300's `flash:`). IOx can't bind-mount `sdflash:` into the container and inbound
to the container is blocked, so the agent **scp-pushes** the image to
`sdflash:guest-share/iris/` via the device's SCP server (`ip scp server enable`, set by
`install.sh`), then the `IRIS-COPYROOT` applet runs `copy /verify
sdflash:guest-share/iris/<img> sdflash:<img>`. See `../../HANDOFF-iris-iox-app.md` for the
current verification status of that final copy step.
