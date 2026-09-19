<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IRIS: Intelligent Release and Image Staging

IRIS distributes Cisco images and patches through a private peer-to-peer swarm.
Device agents verify and stage assigned images. Staging copies an image to the
device and checks its hash, then stops: the device keeps running its current
software until you install the image yourself. Software installation,
activation, boot changes, and reloads remain outside IRIS.

Use the [Console](docs/zensical/user-guide/index.md) for everyday operations and the
[API reference](https://cisco-open.github.io/intelligent-release-image-staging/docs/swagger/) for automation
([source](docs/zensical/swagger/index.html)). The published manual is at
https://cisco-open.github.io/intelligent-release-image-staging/docs/.

## Start here

- [Documentation](docs/zensical/index.md) — start of the manual, with a reading
  order for each guide.
- [Installation Guide](docs/zensical/install/index.md) — deploy IRIS and stage
  your first image.
- [Administration Guide](docs/zensical/admin-guide/index.md) — upgrades,
  backups, credentials, signing keys, and recovery.
- [User Guide](docs/zensical/user-guide/index.md) — everyday tasks,
  monitoring, and troubleshooting.
- [Architecture Guide](docs/zensical/architecture/index.md) — components, trust
  boundaries, and limitations.
- [Reference](docs/zensical/reference/index.md) — routes, file formats, and
  terms.

The server and stateless Console run on one Docker host, separate Docker
hosts, or Kubernetes; see the Installation Guide for each layout. Device
families include Catalyst, Industrial Ethernet, Cisco 8000, and NCS;
prerequisites vary by model and software.

Control services use HTTPS. Image pieces move between devices over the
private swarm, and an operator can turn on TLS with mutual certificates for
those peer transfers; see
[Security model and trust boundaries](docs/zensical/architecture/security-model.md)
for how that setting works.

## Repository

| Path | Contents |
| --- | --- |
| `server/` | Server services, Console, API, and tests. |
| `device/` | Shared agent and platform packaging. |
| `kubernetes/` | Server and Console deployment manifests. |
| `tools/`, `fleet/` | Administrative helpers and inventory templates. |
| `docs/` | Public website and Zensical documentation sources. |

For contribution and project policies, see [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[LICENSE](LICENSE), and [NOTICE](NOTICE).
