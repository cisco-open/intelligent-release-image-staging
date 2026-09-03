# Development

This document covers project-specific development setup, conventions, and the
release process for **intelligent-release-image-staging**. For how to report
issues and send pull requests, see [CONTRIBUTING.md](CONTRIBUTING.md); for
running the test suites, see [TESTING.md](TESTING.md).

## Project scope

The project **distributes, verifies, and STAGES** Cisco software on IOS-XE and
IOS-XR devices: to `flash:` / `bootflash:` / `sdflash:` through Guest Shell or
IOx, and directly to `harddisk:` from the IOS-XR appmgr container. It **never
installs, activates, or reloads the staged software** and never changes boot
variables. Contributions must respect this hard invariant: do not add code,
automation, or documentation that crosses the staging boundary or otherwise
mutates the running/booted software state of a device.

## Development setup

1. **Clone the repository:**
   ```
   git clone https://github.com/cisco-open/intelligent-release-image-staging.git
   cd intelligent-release-image-staging
   ```
2. **Prerequisites:**
   - **Python 3** with **pytest** (for the Python test suite)
   - **bats** (for the shell test suite)
   - **Docker** and **Docker Compose** (for the server stack)
3. **Run the server stack** (tracker / catalog / seeder) locally with Docker
   Compose from the repository root. Bootstrap is needed once per fresh config
   volume:
   ```
   tools/get-aria2c.sh amd64
   docker compose -f server/docker-compose.yml build
   docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
   docker compose -f server/docker-compose.yml up
   ```

   The first step installs the handed-in `aria2c` binary that the image build
   copies in; it verifies the binary against `tools/aria2c.sha256` and fails
   closed on a mismatch, with no override. Point `ARIA2C_DELIVERABLE` at a
   handed-in binary whose sha256 is the one recorded there.

   Building your own from the corresponding source
   (`tools/aria2c-patches/README.md`) will **not** reproduce those bytes — a
   different toolchain or flag set produces a different binary — so
   `get-aria2c.sh` will refuse it. Building one is adopting your own client,
   which means updating `tools/aria2c.sha256` to its sha256 on purpose, and
   accepting that the pin no longer matches what the project ships.

The seed-server Dockerfile uses the repository root as its build context so the
image can carry the device installers and console onboarding helper. Build it
directly with `docker build --platform linux/amd64 -f server/Dockerfile .`.

### Running a dev checkout beside a live deployment

`server/docker-compose.yml` declares `name: iris`, so every checkout of this
repository resolves to the **same** Compose project and the same named volumes
(`server_iris-state`, `server_iris-config`, `server_iris-images`). Bringing a dev
checkout up on a host that already runs IRIS would otherwise adopt the live
container, re-bootstrap live state with `run --rm iris iris-bootstrap`, and
delete all three volumes on `down -v`. Give the dev stack its own project name
and its own container name — container names are host-global:

```bash
COMPOSE_PROJECT_NAME=iris-dev IRIS_CONTAINER=iris-dev \
  docker compose -f server/docker-compose.yml up -d
```

Put both in `server/.env` if you work in that checkout regularly.
`IRIS_CONTAINER` is the override the helpers under `tools/` already honour, so
it also points them at the dev container. A deployment created before the
project name was declared keeps `server_`-prefixed volumes and needs a one-time
migration — see [Compose project
name](docs/zensical/server.md#compose-project-name).

## Embedded agent packages

The shared sources under `device/agent/` are embedded into the Guest Shell
bundle, both IOx tars, and the IOS-XR RPM. After **any** shared-agent change,
rebuild every package used by the deployment before testing or redeploying
devices:

```bash
# rebuilt automatically when the server image starts
docker compose -f server/docker-compose.yml up -d --build

# prebuilt packages; run explicitly
tools/provision-iox-packages.sh
CATALOG_PEM=<live-certificate-only-pem> \
  tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

`tools/check-package-freshness.sh` detects certificate drift. It inspects the
certificate inside the IOx tars and compares the XR RPM's build time with the
certificate's `notBefore`; it does **not** prove that any package contains the
current source. For an agent-code release, rebuild rather than relying on a
green freshness report, then redeploy affected devices.

## Commit message format

Keep commit messages light and consistent with the repo's existing style: a
clear, concise, **imperative** subject line (e.g., "Add flash reclaim guard"),
with an optional body explaining the *why* when it isn't obvious. Conventional
Commits are **not** required.

For an ordinary release-worthy change, add its operator-visible description
under `CHANGELOG.md` → `Unreleased`; do not bump `VERSION` per commit.

To cut a release:

- Move the accumulated Unreleased entries under a dated release heading.
- **Bump the `VERSION` file** using CalVer: `YYYY.0M.0D` with an optional
  `.MICRO` (`1`, `2`, …) for multiple releases on the same day
  (e.g., `2026.06.11`, then `2026.06.11.1`).
- Run both test suites, build the Zensical site, assemble the release with
  `tools/make-release.sh`, and rebuild all prebuilt device packages when the
  shared agent changed.
- Tag `v<VERSION>` — for example `v2026.06.11.1`. Keep `VERSION`, the changelog
  heading, and the tag exactly in sync, including any `.MICRO` suffix.

## License headers

The project is licensed under the **Apache License, Version 2.0** (see
[LICENSE](LICENSE) and [NOTICE](NOTICE)). Every source file carries a short SPDX
header rather than repeating the full license block.

Each source file must carry, after any shebang line:

```
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
```

Copy that block verbatim into any new source file (adjusting the comment
character to match the file's syntax).

Two kinds of file are excepted and left unannotated; both inherit the
repository's Apache-2.0 license:

1. **Files whose syntax has no comment form at all** — JSON, for example, which
   is why `docs/zensical/dashboards/grafana-iris-swarm.json` carries no header.
2. **Files where a header would change the artifact's meaning** — IOS-XE EEM
   `.cfg` applets, which are pasted into a device configuration verbatim, and
   the `tools/aria2c-patches/*.patch` files, where added lines would alter the
   patch content and stop it applying.

A format that *can* carry a comment is not excepted: `.xml`, `.yaml`, `.toml`,
`.css`, `.html` and `.md` all take the header (Markdown and HTML as an
`<!-- ... -->` block, XML likewise).
