<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install on separate Docker hosts

Put the browser interface on one machine and the server on another. At the end
the Console reaches the server over an authenticated private connection.

Skip this page if you run both containers on one machine, described in
[Install on one Docker host](one-docker-host.md), or on a cluster, described in
[Install on Kubernetes](kubernetes.md).

## Before you start

1. Two Linux hosts on amd64 with Docker Engine 23.0 or newer and Docker Compose
   2.24.4 or newer, that meet
   [Check the host before you install](check-the-host.md). Check out the same
   IRIS release on both.
2. Both container images, from
   [Build the server and Console images](build-images.md), and the pinned
   `aria2c` binary the server build needs, from
   [Download the tools that build device packages](build-tools.md).
3. The two public signing roots on the server host, from
   [Create the two offline signing keys](signing-roots.md), and the firewall
   permits in [Open the required ports](open-ports.md#firewall-rules).

Run the time check on each host:

```bash
bash tools/check-host-time.sh
```

Both hosts must report a healthy clock.

## Choose the addresses

Pick all three before you provision either host.

| Address | Used by |
| --- | --- |
| Server device address, `IRIS_HOST_IP` | Device catalog, tracker, artifacts, and origin seeder. |
| Server private management address | The Console's `IRIS_MANAGEMENT_API_URL`, normally `https://iris-mgmt.example.com:9443`. Its hostname must resolve from the Console container. |
| Console browser address | Operators, for example `https://console.example.com:8080`. Set the same full URL as `IRIS_CONSOLE_URL` on the server. |

Bind port 9443 to the management address and let only the Console host through
the firewall. Restrict the Console browser port to trusted operator sources.

## What lives on which host

Only the server host holds `$IRIS_CONFIG/instr/signing-key.age`, the separate
age identity, `$IRIS_RUN/instr/signing-key` runtime plaintext, and durable
instruction state under `$IRIS_STATE`. The Console holds its management token
and CA files and its browser identity. The two offline-root public keys are
public material; their private keys stay with separate offline custodians.

!!! warning

    Never copy server data, the age identity, or the management private key to
    the Console host.

Keep the Compose project name, environment files, and server volumes unchanged.

## Certificates and trust

| Identity | Private key location | Trusted by |
| --- | --- | --- |
| Catalog/device certificate | Encrypted server configuration, decrypted into server tmpfs | Device agents and installers. |
| Management certificate | Server host's `management-tls` directory | Console's `management-ca/ca.pem`. |
| Default browser certificate | Console host's `console-tls` directory | Operator browsers. |

The management certificate must cover the exact DNS name or IP in
`IRIS_MANAGEMENT_API_URL`. The browser certificate must cover the Console URL.

1. On a trusted operator machine, create both host bundles:

    ```bash
    umask 077
    mkdir -p ~/.config/iris
    python3 tools/prepare-docker-hosts.py \
      --out "$HOME/.config/iris/docker-hosts" \
      --management-host iris-mgmt.example.com \
      --console-host console.example.com
    ```

    A `server/` and a `console/` directory hold self-signed certificates and
    one scoped management token, valid for 365 days.

2. Copy `server/` to `/etc/iris/docker-hosts/` on the server host and
   `console/` to the same path on the Console host, over SSH or SCP.

3. On each host, set ownership and keep the generated permissions:

    ```bash
    sudo chown -R 10001:10001 /etc/iris/docker-hosts
    sudo find /etc/iris/docker-hosts -type d -exec chmod 700 {} +
    sudo find /etc/iris/docker-hosts -type f -exec chmod 600 {} +
    ```

4. Compare the management certificate fingerprint with the Console's `ca.pem`,
   then install the browser certificate in the operator trust store.

## Start the server host

1. Copy the server environment example from the repository root:

    ```bash
    cp server/server.env.example server/server.env
    ```

2. Set every example address and path, at least `COMPOSE_PROJECT_NAME`,
   `IRIS_HOST_IP`, `IRIS_MANAGEMENT_BIND_IP`, `IRIS_CONSOLE_URL`,
   `IRIS_AGE_KEY_FILE_HOST`, `IRIS_AGE_RECIPIENTS`, `IRIS_MANAGEMENT_TLS_DIR`,
   `IRIS_TIER_AUTH_DIR`, `IRIS_IMAGE_ROOT` and `IRIS_ARTIFACTS_HOST_DIR`. See
   [Server configuration](../reference/server-configuration.md) and
   [Install on one Docker host](one-docker-host.md#configure-the-server).

3. Start a fresh server:

    ```bash
    iris_server() {
      docker compose --env-file server/server.env \
        -f server/docker-compose.server.yml "$@"
    }

    iris_server run --rm iris iris-bootstrap
    iris_server run --rm \
      -v "$HOME/iris-roots:/pub:ro" --entrypoint sh iris -c \
      'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && \
       install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
    iris_server up -d
    iris_server ps
    ```

    `iris_server ps` shows the server container running. Put your approved
    directory of two distinct public roots in place of `$HOME/iris-roots`.

    !!! warning

        Do not replace roots on an existing server. Reuse its
        `COMPOSE_PROJECT_NAME`, container name, age identity and host paths,
        and skip bootstrap and the roots command.

4. Turn on signing, described in
   [Turn on instruction signing](activate-signing.md#initialise-instruction-custody).

5. Export the server settings so the package helpers match Compose:

    ```bash
    set -a
    . server/server.env
    set +a
    export IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"
    ```

    Then follow the commands for separate hosts in
    [Build and publish the device packages](device-packages.md#build-and-publish-the-arm64-iox-package).

## Start the Console host

1. Copy the Console environment example:

    ```bash
    cp server/console.env.example server/console.env
    ```

2. Set its bind address, browser port, management URL, and directory paths.

3. Start the Console:

    ```bash
    iris_console() {
      docker compose --env-file server/console.env \
        -f server/docker-compose.console.yml "$@"
    }

    iris_console up -d
    iris_console ps
    ```

    `iris_console ps` shows the Console container running. While the server is
    unreachable, API requests return a redacted `503` with `Retry-After`.

4. Open the Console URL and claim the administrator account, described in
   [Sign in for the first time](first-sign-in.md#claim-the-administrator-account).
   The account lives on the server, so a second Console shares it.

## Verify

Run `iris_server ps` on the server host and `iris_console ps` on the Console
host. Both report their container as running. If one does not, read its log:

```bash
iris_server logs --tail=100 iris
```

```bash
iris_console logs --tail=100 console
```

Then check the path end to end: sign in, open the device list, read the
addresses in Settings, import an image, and stream a job log.

## Next steps

- [Sign in for the first time](first-sign-in.md)
- [Set up certificates and tokens](certificates-and-tokens.md)
- [Build and publish the device packages](device-packages.md)
- [Verify the installation](verify.md)
- [Rotate credentials and certificates](../admin-guide/rotations.md)
