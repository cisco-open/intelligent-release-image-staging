# IRIS: Intelligent Release and Image Staging

IRIS distributes Cisco images and patches through a private peer-to-peer swarm.
Device agents verify and stage assigned images. Software installation,
activation, boot changes, and reloads remain outside IRIS.

Use the [Console](docs/zensical/console.md) for everyday operations and the
[API reference](docs/zensical/swagger/index.html) for automation.

## Start here

- [Getting started](docs/zensical/getting-started.md) — deploy IRIS and stage an image.
- [Documentation](docs/zensical/index.md) — task-oriented guide to the manual.
- [Architecture](docs/zensical/architecture.md) and [security](docs/zensical/security.md) — components, trust boundaries, and limitations.
- [Device requirements](docs/zensical/device-agents.md) — Guest Shell, IOx, and IOS-XR appmgr deployment paths.
- [API testing and limits](docs/zensical/api-testing.md) — reproducible checks and capacity caveats.
- [Troubleshooting](docs/zensical/troubleshooting.md) — diagnose and recover service.

The server and stateless Console run on [one Docker host](docs/zensical/getting-started.md),
[separate Docker hosts](docs/zensical/docker-hosts.md), or
[Kubernetes](docs/zensical/kubernetes.md). Device families include Catalyst,
Industrial Ethernet, Cisco 8000, and NCS; prerequisites vary by model and software.

Control services use HTTPS; image pieces use the private BitTorrent swarm.
See [network ports](docs/zensical/network-ports.md) for connectivity requirements
and [validation](docs/zensical/validation.md) for verification scope.

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
