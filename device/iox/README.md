# intelligent-release-image-staging as a Cisco IOx Docker app

IRIS can run as an architecture-matched IOx Docker app on supported Cisco
devices. ARM64 packages target IE-3x00/IE-3400 style platforms; x86_64 packages
target Catalyst 9000 app hosting, including C9300. Guest Shell remains an
alternative on platforms where it is supported. The container path reaches IOS
through SSH-to-self:

| | Guest Shell agent | IOx app agent |
|---|---|---|
| reach IOS | in-process `cli` module | **SSH-to-self** (`cli_ssh`) to the app VLAN SVI |
| runtime gate | default | `IRIS_RUNTIME_MODE=container` (baked in the image) |

`device/agent/cli_ssh.py` re-binds `cli_execute`/`cli_configure` behind a runtime
seam (`build_deps` → `cli_ssh.select_cli`). The C9300 Guest Shell path is
unchanged (default mode still does `from cli import execute, configure`).

## Build

```
# ARM64 is the default
CATALOG_PEM=/path/to/iris-catalog.pem ./build.sh --image-only
CATALOG_PEM=/path/to/iris-catalog.pem ./build.sh [OUTPUT_DIR]

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar \
  CATALOG_PEM=/path/to/iris-catalog.pem ./build.sh [OUTPUT_DIR]
```
The default output is `device/iox/out/iris-arm64.tar`. Packaging also needs a
configured `ioxclient`; `--image-only` does not. The build uses an
architecture-matched `aria2c` from `ARIA2C_BIN` or a local agent bundle when
available, otherwise it downloads a pinned static build and verifies its SHA-256
digest. Supply the pinned catalog cert with `CATALOG_PEM`, or set both
`CATALOG_PEM_URL` and `CATALOG_PEM_FINGERPRINT`.

## Config delivery

`entrypoint.sh` (PID 1) generates `iris/iris-agent.conf` under the CAF persistent
directory (`/iox_data` on the validated C9300 runtime, with `/data` as fallback)
on first boot, starts `aria2c` as the BT RPC daemon, and runs
`iris_agent.py --once` every `IRIS_TICK_SECONDS`. The generated secret-bearing
config is mode `0600`. Environment-specific values are required at deployment
time via numbered app-hosting Docker `run-opts -e` entries, never baked in:

| env | conf key | notes |
|---|---|---|
| `IRIS_CATALOG_TOKEN` | `catalog_token` | **secret** — `iris-mint-enrollment <device_id>` on the server |
| `IRIS_DEVICE_ID` | `device_id` | the device's mgmt IP (convention), e.g. `100.90.168.99` |
| `IRIS_DEVICE_SSH_PASS` | `device_ssh_pass` | **secret** — login for SSH-to-self |
| `IRIS_DEVICE_SSH_HOST` | `device_ssh_host` | required IOS SVI for SSH-to-self |
| `IRIS_DEVICE_SSH_USER` | `device_ssh_user` | required scoped IOS user |
| `IRIS_CATALOG_URL` | `catalog_url` | required reachable URL covered by the pinned cert |
| `IRIS_TARGET_FS` | `target_fs` | optional writable IOS disk prefix; installer default `sdflash:` |
| `IRIS_TELEMETRY` | `telemetry` | default `on` — post-staging telemetry reports + pull (set `off` to silence) |

The IOx agent reuses one short-lived SSH control connection for CLI and SCP
work. This avoids opening a new VTY login for every filesystem check, transfer,
and verification call during an agent tick.

> **Security follow-up:** the device login is held in cleartext in the conf on SD.
> Scope it (AAA `parser view` / command-authorization to `copy`/`dir`/`event
> manager`), restrict the VTY ACL to VLAN 666, prefer SSH **key** auth, and issue
> a rotating credential via the #27 secrets-broker. Pending security review.

## Deploy to the device (proven recipe)

1. **Publish + assign an IE image** (server) — required for the device to join a
   swarm and appear on the map:
   ```
   docker compose -f server/docker-compose.yml exec iris \
     iris-publish /opt/images/iosxe/IE3400/<image>.bin
   docker compose -f server/docker-compose.yml exec iris \
     iris-assign <device-id> <image-id>
   ```

2. **Mint the device token** (server):
   `docker compose -f server/docker-compose.yml exec iris iris-mint-enrollment <device-id>`

3. **Get the package onto the device flash**: drop the architecture-matched tar into the
   server's `artifacts/` directory — the `iris` container already serves it on
   `:8000` over HTTPS, so there is no throwaway web server to start. The device
   pulls it over verified HTTPS (against the server cert, via the per-device PKI
   trustpoint configured first), landing it at `flash:iris-arm64.tar`. This is exactly
   what `install.sh` automates; do it by hand only if you are not using the
   one-shot installer.

   This is also the only manual prerequisite for **Console one-click onboarding**:
    once `iris-arm64.tar` is staged in `artifacts/`, the Console picks this installer
   automatically for IE-3x00/IR1101/IR18xx devices (by `model`/`platform`, or by
   live auto-detection) — see the Console's Devices section in the top-level
    README. Onboarding fails fast, before touching the device, if `iris-arm64.tar` is
   missing.

4. **On the device** — 3 gotchas, all required:
   - **Disable app signing in EXEC mode** (config mode rejects it):
     `app-hosting verification disable`
   - The `app-hosting appid iris` block **must** include an `app-vnic` interface,
     and is applied with **no explicit `exit` lines** (IOS auto-pops; explicit
     exits silently drop the app-vnic). Use the VLAN, guest address, and SVI
     selected for this device (see the block below).
   - `app-hosting install appid iris package flash:<package>.tar` → `activate` → `start`
     (DEPLOYED → ACTIVATED → RUNNING).

   ```
   app-hosting appid iris
    app-vnic AppGigabitEthernet trunk
     vlan <vlan> guest-interface 0
      guest-ipaddress <guest-ip> netmask <mask>
    app-default-gateway <svi-ip> guest-interface 0
    app-resource profile custom
     cpu 400
     memory 768
     persist-disk 2048
     vcpu 1
    app-resource docker
     run-opts 1 "-e IRIS_DEVICE_ID=<device-id>"
     run-opts 2 "-e IRIS_DEVICE_SSH_PASS=<pw>"
     run-opts 3 "-e IRIS_CATALOG_TOKEN=<token>"
     run-opts 4 "-e IRIS_CATALOG_URL=https://<server-ip>:8443"
     run-opts 5 "-e IRIS_DEVICE_SSH_HOST=<svi-ip>"
     run-opts 6 "-e IRIS_DEVICE_SSH_USER=<user>"
     run-opts 7 "-e IRIS_TARGET_FS=<ios-filesystem>:"
     run-opts 8 "-e IRIS_TELEMETRY=on"
   ```

   `install.sh` emits separate numbered `run-opts` lines because Catalyst app
   hosting limits each option line. For the validated C9300-24UX path, use the
   amd64 package, `APP_INTF=AppGigabitEthernet1/0/1`, and
   `TARGET_FS=usbflash1:`. IE-3x00 defaults remain ARM64,
   `AppGigabitEthernet1/1`, and `sdflash:`.

5. **Verify**: `show app-hosting list` (RUNNING), `show app-hosting detail appid
   iris` (Status 0). The device then refreshes its token, downloads the assigned
   image over the swarm, and appears on the Console swarm map
   (`https://<server-ip>:8080/`, Swarm tab) labeled with its model; the
   heartbeat carries model/version/free read over SSH-to-self.

## On-box staging target

The agent stages the downloaded image to the selected IOS filesystem (`sdflash:`
by installer default; use a writable platform disk such as `usbflash1:` on the
validated C9300). IOx can't bind-mount that filesystem into the container, so
the agent **scp-pushes** the image to
`<target>guest-share/iris/` through the device's SCP server (`ip scp server
enable`, set by `install.sh`). It then runs `copy /verify
<target>guest-share/iris/<img> <target><img>` directly over the SSH-to-self IOS
session and confirms the destination appears before reporting `ready`.
