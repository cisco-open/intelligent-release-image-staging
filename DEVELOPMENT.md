<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Repository map and contributor entry point

This page orients a contributor who has a checkout and wants to change code.
For the pull request process, see [Contributor front door](CONTRIBUTING.md).
For running the test suites, see
[Manual checks and the test-file map](TESTING.md).

## Repository map

| Path | What's there |
| --- | --- |
| `server/` | The stateful server, the Console web frontend, Docker build files, and the server test suite. |
| `device/` | The Guest Shell installer, bootstrap scripts, EEM applets, the device agent, and the device test suite. |
| `device/container/` | The single device-container image, its entrypoint, and the reconcile script that IOx and IOS-XR appmgr both use. |
| `device/iox/` | The IOx wrapper-package build, its install logic, and its tests. |
| `device/xr/` | The IOS-XR appmgr image, its entrypoint, package-build support, and its tests. |
| `fleet/` | CSV templates and the generated per-device installer output. |
| `tools/` | Helper scripts for building bundles, installers, assignments, release packaging, and torrents. |
| `lab/` | Lab helpers and diagnostics. |
| `docs/` | The public website and the Zensical documentation source. |

## Core invariant

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot variables.

    Read the full rule on [IRIS documentation](docs/zensical/index.md).

Never write code, automation, or documentation that crosses this line, even to
make a test or a demo easier to run.

## Before you change anything

1. Read the tests near the code you're about to change before you change it.
2. Keep each change scoped to the component it touches.
3. Run the focused tests first, then the full suites in
   [Manual checks and the test-file map](TESTING.md).
4. Update the docs when you change how an operator uses IRIS.
5. Don't commit generated files, credentials, images, or evidence from your
   own test runs.

## Run a checkout for local development

Follow [Install on one Docker host](docs/zensical/install/one-docker-host.md)
to bring up the server and Console from your checkout; the same steps work
for a development instance.

Give a second checkout its own compose project name, container names, and
artifacts directory so it doesn't collide with a deployment that's already
running. See
[Running a second stack on the same host](docs/zensical/install/one-docker-host.md#running-a-second-stack-on-the-same-host).

The Console frontend builds separately from the server. See
[The React build, mount roots and CSP](docs/dev/console-ui.md) for how to
build and test it locally.

## Change the shared device agent

Every file under `device/agent/` ships inside the Guest Shell bundle, both
IOx tars, and the IOS-XR RPM. Rebuild all of them before you test or
redeploy a shared-agent change:

```bash
docker compose -f server/docker-compose.yml up -d --build
tools/provision-iox-packages.sh
tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

The first command rebuilds the image the server container starts from. The
other three build the prebuilt IOx and IOS-XR packages and check that they
match that rebuilt image. See
[When to rebuild the packages](docs/zensical/install/device-packages.md#embedded-agent-packages)
for the operator-facing rule on when a rebuild is required.

If the image archive already holds source at the same version, the build
refuses to replace it. Run
`IRIS_FORCE_DEVICE_IMAGE_BUILD=1 tools/provision-iox-packages.sh` for an
intentional rebuild, or set `IRIS_DEVICE_IMAGE_OCI` to a new path to keep the
old archive alongside the new one.

The IOx and IOS-XR wrappers carry no server certificate. Each one ships a
provenance file that ties its bytes to the shared device image, but a
certificate rotation needs devices to re-onboard, not a package rebuild.
`tools/check-package-freshness.sh` checks that binding and separately checks
that the running and distributed certificates agree; it does not compare a
package with your current checkout or check a native signature.

The build scripts also warn when your checkout is missing agent or packaging
commits from `origin/main`. Set `IRIS_REQUIRE_FRESH_AGENT=1` to fail the
build on that finding, or `IRIS_ALLOW_STALE_AGENT_ACK=1` to build an older
version on purpose.

See [Server configuration](docs/zensical/reference/server-configuration.md#image-path-variables)
for the build-time variables, and
[Building the device image, IOx wrappers, IOS-XR rpm and aria2c](docs/dev/device-packages.md)
for the full build.

## Cut a release

Add each operator-visible change to `CHANGELOG.md` under Unreleased as you
make it; don't bump `VERSION` for an ordinary commit.

To cut a release:

1. Move the accumulated Unreleased entries under a dated release heading.
2. Set `VERSION` to that same date, using `YYYY.0M.0D` with an optional
   `.MICRO` suffix for a second release on the same day.
3. Run the complete Python and Bats test suites and the documentation build.
4. Run `tools/make-release.sh`, which packages tracked files only (from
   `git ls-files`, so commit new files first), writes `release/iris.tgz`
   with `release/iris.tgz.sha256` and a per-file `MANIFEST.txt`, and leaves
   the previous release alone if any step fails.
5. Tag `v<VERSION>`, keeping `VERSION`, the changelog heading, and the tag in
   sync.

Rebuild every device package family first when the release includes a
shared-agent change.

## Vendored third-party assets

The Console image ships a vendored copy of the Swagger UI assets under
`docs/zensical/swagger/`. See
[Swagger UI provenance record](docs/zensical/swagger/SOURCE.txt) for what's
vendored and how to update it.

## Developer documentation

See [Developer documentation index](docs/dev/README.md) for the full set.
The pages of most use while you're changing code:

- [Writing and building the docs](docs/dev/documentation.md)
- [The assistant-facing deployment runbook](docs/dev/ai-assisted-deployment.md)
- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](docs/dev/device-packages.md)
- [Installer files, staging retention, bootstrap and supervisor internals](docs/dev/device-agent-internals.md)
- [Process and thread topology, preflight and internal rationale](docs/dev/server-internals.md)
- [aria2 peer sampling, report ring and promotion design](docs/dev/telemetry-internals.md)
- [KDF, PAE layout, iris-aead adapter and the OpenSSL pin](docs/dev/instruction-crypto.md)
- [Migration notes for contributors](docs/dev/upgrade-notes.md)
- [tools/api-exercise.py](docs/dev/api-exercise.md)
- [The React build, mount roots and CSP](docs/dev/console-ui.md)
- [Where the dashboard metrics come from in code](docs/dev/dashboards.md)
- [Dated lab evidence](docs/dev/validation-records.md)
- [Release and verifier checklist](docs/dev/release-checklist.md)
