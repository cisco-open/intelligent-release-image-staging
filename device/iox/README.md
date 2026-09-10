# intelligent-release-image-staging as a Cisco IOx Docker app

IRIS can run as an architecture-matched IOx Docker app on supported Cisco
devices. ARM64 packages target IE-3x00/IE-3400 style platforms; x86_64 packages
target Catalyst 9000 app hosting, including C9300. Guest Shell remains an
alternative on platforms where it is supported. The container path reaches IOS
through SSH-to-self:

| | Guest Shell agent | IOx app agent |
|---|---|---|
| reach IOS | in-process `cli` module | **SSH-to-self** (`cli_ssh`) to the app VLAN SVI |
| runtime gate | no container selector | `IRIS_DEVICE_PLATFORM=iox` (set by the installer) |

`device/agent/cli_ssh.py` re-binds `cli_execute`/`cli_configure` behind a runtime
seam (`build_deps` → `cli_ssh.select_cli`). The C9300 Guest Shell path is
unchanged (default mode still does `from cli import execute, configure`).

## Build

```
# Build/verify the one persisted amd64+arm64 OCI archive; architecture flags
# do not select or reduce an --image-only build.
./build.sh --image-only

# ARM64 is the default only when producing an IOx wrapper.
./build.sh [OUTPUT_DIR]

# x86_64 Catalyst package
IOX_ARCH=amd64 PACKAGE_NAME=iris-amd64.tar ./build.sh [OUTPUT_DIR]
```
The default native-wrapper output is `device/iox/out/iris-arm64.tar`.
`--image-only` instead persists the signable multi-platform archive at
`artifacts/iris-device-$VERSION.oci.tar` and its adjacent `.manifest`.
Each IOx tar also has an adjacent `.manifest` binding its SHA-256 to the
canonical image provenance. A ready status means those bytes and that sidecar
agree; it is not a certificate-age check or a native-signature validation.
Packaging needs a configured `ioxclient`; `--image-only` does not. The shared
multi-platform build uses `ARIA2C_BIN_AMD64` / `ARIA2C_BIN_ARM64` overrides,
local agent bundles, or `deliverables/aria2c-<arch>`, verifying both
architectures against `tools/aria2c.sha256` and failing closed on a mismatch.
The build never downloads a client: an earlier network fallback could silently
ship an unpatched third-party build into the image. The builder accepts no
`CATALOG_PEM`, certificate URL, or certificate fingerprint: the OCI archive
and IOx/XR wrappers are deployment-neutral and contain no server certificate.
Rebuild the canonical image and every native wrapper whenever their shared
source changes; a certificate rotation alone is not a package rebuild trigger.

Signed wrappers are immutable. The legacy `rebake_iris_tar.py` helper refuses
packages carrying `package.sign` or `package.cert`, including in nested
archives. Rebuild and re-sign for a source change; re-onboard with the existing
package for a certificate change. If native signing changes wrapper bytes,
publish a matching manifest for the signed output while retaining its
canonical image provenance. The manifest does not validate a native signature;
the device's app-hosting verifier does. See
[Artifact handling](../../docs/zensical/iox.md#artifact-handling).

## Config delivery

`device/container/entrypoint.sh` (PID 1) generates `iris/iris-agent.conf` under the CAF persistent
directory (`/iox_data` on the validated C9300 runtime, with `/data` as fallback)
on first boot, starts `aria2c` as the BT RPC daemon, and runs
`iris_agent.py --once` every `IRIS_TICK_SECONDS`. The generated secret-bearing
config is mode `0600`. The installer separately validates the current public
server certificate and delivers it through IOS-XE's application-data channel;
the entrypoint reads `iris-catalog.pem` from `CAF_APP_APPDATA_DIR` and refuses
to start when it is missing or invalid. Environment-specific values are
required at deployment time via numbered app-hosting Docker `run-opts -e`
entries, never baked in:

| env | conf key | notes |
|---|---|---|
| `IRIS_CATALOG_TOKEN` | `catalog_token` | **secret** — `iris-mint-enrollment <device_id>` on the server |
| `IRIS_DEVICE_ID` | `device_id` | the device's mgmt IP (convention), e.g. `192.0.2.99` |
| `IRIS_DEVICE_SSH_PASS` | `device_ssh_pass` | **secret** — login for SSH-to-self |
| `IRIS_DEVICE_SSH_HOST` | `device_ssh_host` | required IOS SVI for SSH-to-self |
| `IRIS_DEVICE_SSH_USER` | `device_ssh_user` | required scoped IOS user |
| `IRIS_CATALOG_URL` | `catalog_url` | required reachable URL covered by the runtime-delivered cert |
| `IRIS_TARGET_FS` | `target_fs` | optional writable IOS disk prefix; installer default `sdflash:` |
| `IRIS_TELEMETRY` | `telemetry` | default `on` — post-staging telemetry reports + pull (set `off` to silence) |
| `IRIS_DEVICE_PLATFORM` | `device_platform` | required selector; this package accepts only `iox` |
| `IRIS_SHARE_DIR` | `share_dir` | optional validated override; `iox` default `/mnt/share` |
| `IRIS_SHARE_IOS_PATH` | `share_ios_path` | optional validated override; `iox` default `usbflash1:iox_host_data_share` |

The `iox` profile derives the container share path (`/mnt/share`) and IOS share
name (`usbflash1:iox_host_data_share`) itself. A Catalyst package supplies only
the corresponding `-v` mount. Direct deployments may retain the existing
overrides, but the entrypoint validates both before use; XR rejects them.

The IOx agent reuses one short-lived SSH control connection for CLI and SCP
work. This avoids opening a new VTY login for every filesystem check, transfer,
and verification call during an agent tick.

After the server certificate rotates, re-run onboarding for each deployed IOx
app. That delivers the new public certificate as application data; the package
itself remains unchanged and does not need rebuilding.

> **Residual risk — device login held in cleartext.** The generated
> `iris-agent.conf` holds the SSH-to-self password in cleartext on the app's
> persistent storage (SD on IE-3x00), mode `0600` and readable only inside the
> app. There is no secrets broker; the credential is static until an operator
> rotates it. Mitigate it at the device: scope the account with AAA
> (`parser view` / command authorization limited to `copy`, `dir`, and `event
> manager`), restrict the VTY ACL to the IRIS app subnet, and prefer SSH **key**
> auth where the platform supports it. Rotating the credential means re-running
> the installer with the new value.

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

3. **Make the package and certificate available**: place the
   architecture-matched tar in the server's `artifacts/` directory; server
   bring-up already stages the current public certificate there as
   `iris-catalog.pem`. `install.sh` validates both locally, installs the
   catalog trustpoint over its authenticated, host-key-checked SSH session,
   and has the device fetch them (and its sealed instruction envelope) from
   the artifact server with `copy https:`, authenticated with the device's
   own enrollment credential (`ip http client username` / `password`, set
   for each copy and removed after it). Nothing is pushed over SCP. If you
   are not using the one-shot installer, copy both files to the device
   manually.

   These are also the artifact prerequisites for **Console one-click
   onboarding**: once `iris-arm64.tar` and the public certificate are staged,
   the Console picks this installer automatically for
   IE-3x00/IR1101/IR18xx devices (by `model`/`platform`, or by live
   auto-detection) — see [Web Console](../../docs/zensical/console.md).
   Onboarding fails fast if the package is missing or the certificate cannot
   be validated.

4. **On the device** — 3 gotchas, all required:
   - Keep app-hosting signature verification enabled for a signed package.
     Only an unsigned local package requires `app-hosting verification
     disable`, issued in EXEC mode; `install.sh` detects which policy applies.
   - The `app-hosting appid iris` block **must** include an `app-vnic` interface,
     and is applied with **no explicit `exit` lines** (IOS auto-pops; explicit
     exits silently drop the app-vnic). Use the VLAN, guest address, and SVI
     selected for this device (see the block below).
   - `app-hosting install appid iris package flash:<package>.tar` → `activate` →
     `app-hosting data appid iris copy flash:iris-catalog.pem
     iris-catalog.pem` → `start` (DEPLOYED → ACTIVATED → application-data
     certificate → RUNNING). Activation mounts application storage. Deliver the
     certificate before starting the app; a failed copy leaves it unstarted.

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
     run-opts 7 "-e IRIS_DEVICE_PLATFORM=iox"
     run-opts 8 "-e IRIS_TELEMETRY=on"
    !                                  C9k share-mount transfer only:
     run-opts 11 "-v /vol/usb1/iox_host_data_share:/mnt/share"
   ```

   `install.sh` emits separate numbered `run-opts` lines because Catalyst app
   hosting limits each option line. For the validated C9300 path, use the
   amd64 package, `APP_INTF=AppGigabitEthernet1/0/1`, `TARGET_FS=flash:`, and
   `SHARE_HOST_PATH=/vol/usb1/iox_host_data_share` (run-opts 11 above; also
   `mkdir usbflash1:iox_host_data_share` before activation so the bind-mount
   target exists). IE-3x00 defaults remain ARM64, `AppGigabitEthernet1/1`, and
   `sdflash:` with no share mount.

5. **Verify**: `show app-hosting list` (RUNNING), `show app-hosting detail appid
   iris` (Status 0). The device then refreshes its token, downloads the assigned
   image over the swarm, and appears on the Console swarm map
   (`https://<server-ip>:8080/`, Swarm tab) labeled with its model; the
   heartbeat carries model/version/free read over SSH-to-self.

## On-box staging target

How the agent hands the downloaded image to IOS depends on the platform:

- **C9k (share mount, the Console default)**: the app-hosting SSD share
  (`usbflash1:iox_host_data_share`, host-side `/vol/usb1/…`) is bind-mounted
  into the container, so the agent writes the image to the share ROOT as
  `iris-staged.bin` at disk speed and places it at the bootflash root over
  the SSH-to-self session with the same crash-safe, two-phase sequence
  Guest Shell uses (see below) — no image bytes on the CoPP-policed punt
  path. IRIS uses only `iris-` prefixed filenames at the share root
  (container-created subdirs lock the container out on this platform).
  Before the multi-GB copy the agent probes that IOS can actually read the
  share and otherwise falls back to the scp push below; the transient share
  copy is removed after a verified placement.
- **IE-3x00 (scp push)**: IOx can't bind-mount `sdflash:` there, so the agent
  **scp-pushes** the image to `<target>guest-share/iris/` through the device's
  SCP server (`ip scp server enable`, set by `install.sh`), then places it at
  the target-FS root with the same two-phase sequence.

Both container paths place the image by running plain `copy`/`rename`
commands DIRECTLY over the SSH-to-self vty rather than through the
IRIS-COPYROOT EEM applet Guest Shell uses (`cli_ssh` drives `copy` to
completion; EEM's `cli command "copy …"` is a no-op on this platform). The
sequence itself is identical: `copy` first lands the bytes at a reserved
temp name (`<img>.iris-tmp`), never at `<img>` directly — a copy failure or
a power loss leaves `<img>` (an older copy, or the file the `BOOT` variable
currently names) untouched — the agent reverifies the temp copy by dir
presence and exact catalog byte size, and only once that passes does a
single `rename` put it at `<img>` (a directory-entry update, not a data
transfer). The agent attests the final placement the same way: dir presence
and catalog byte size, plus its own sha256 against the catalog for content
integrity. See [Crash-safe same-name
replacement](../../docs/zensical/device-agents.md#crash-safe-same-name-replacement)
for the full contract, shared with the Guest Shell path.
