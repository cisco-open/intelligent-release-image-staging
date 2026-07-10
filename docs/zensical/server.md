<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Server

The server is a single Docker service that runs several small Python and shell components. It intentionally keeps runtime dependencies narrow: Python standard library services, `aria2c` for BitTorrent, `mktorrent` for torrent metadata, and OpenSSL/age tooling for certificates and encrypted secret material.

## Network surfaces

| Port | Protocol | Service | Purpose |
| --- | --- | --- | --- |
| 6969 | HTTP | Tracker | Private BitTorrent announces with an announce key. |
| 8443 | HTTPS | Catalog | Image metadata, device assignments, token refresh, and reports. |
| 8000 | HTTPS | Artifact server | Bootstrap, agent bundle, pinned certificate, and staged install assets. |
| 6881 | BitTorrent | Seeder data | Initial image pieces from the server seeder. |
| 8080 | HTTPS | Web console | Admin browser interface. |
| 9101 | HTTP | Telemetry | Health, swarm view, and optional Prometheus metrics. |
| 6800 | HTTP | aria2 RPC | Local-only inside the container; not published by Compose. |

## Important paths

| Path | Role |
| --- | --- |
| `/var/lib/iris` | Catalog state, policies, torrent metadata, audit state. |
| `/etc/iris` | Encrypted secrets and generated TLS material. |
| `/run/iris` | Plaintext runtime secrets on tmpfs. |
| `/opt/images` | Read-only image mount used by publish operations. |
| `/srv/artifacts` | Served bootstrap and agent artifacts. |

## Publishing images

Publishing is the handoff from an operator-owned image file to IRIS-managed metadata:

1. `iris-publish` derives or accepts an image id.
2. It calculates `sha256` and `sha512`.
3. It creates a private torrent with the authenticated tracker announce URL.
4. It asks the local seeder RPC to seed that torrent.
5. It persists the catalog entry.

The command normally runs inside the container:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

## Secret handling

IRIS uses age recipients for encrypted-at-rest server secrets. The private age identity is mounted as a Docker secret, and decrypted values are written only to `/run/iris`. This protects long-lived token material from landing in the persistent Docker volume in plaintext.

The seeder RPC secret is not published to the network. Tools that need it, such as `iris-publish`, run inside the container where `127.0.0.1:6800` is reachable.

## Self-provisioned artifacts

On startup, the container refreshes derivable served files such as the Guest Shell agent bundle, bootstrap script, and catalog certificate. Operator-supplied IOx packaging artifacts, such as `iris.tar`, remain operator-owned; the container serves them but does not modify them.

