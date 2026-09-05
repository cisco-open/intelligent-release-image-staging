<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Development

This page explains where to make changes without changing the repository's core safety model.

## Repository map

| Path | Purpose |
| --- | --- |
| `server/` | Stateful server tier, state-free web-console tier, Docker builds, and server tests. |
| `device/` | Guest Shell installer, bootstrap, EEM applets, agent code, and device tests. |
| `device/container/` | The one device-container image definition, entrypoint, and reconcile script shared by IOx and IOS-XR appmgr. |
| `device/iox/` | IOx wrapper-package build, install logic, and tests. |
| `device/xr/` | IOS-XR appmgr wrapper metadata and tests. |
| `fleet/` | CSV templates and generated per-device installer output. |
| `tools/` | Operator helpers for bundles, installers, assignments, release packaging, and torrents. |
| `lab/` | Lab helpers and diagnostics. |
| `docs/` | Public website and Zensical documentation source. |

## Core invariant

Do not add code or documentation that causes IRIS to install, activate, commit, change boot variables, or reload a device. Staging is the boundary.

## Local development loop

1. Read the nearby tests before changing behavior.
2. Keep changes scoped to the component being changed.
3. Run focused tests first, then the wider Python and Bats suites.
4. Update documentation when the operator workflow changes.
5. Avoid committing generated artifacts, credentials, images, or lab-only evidence.

### Test dependencies

The shipped code is stdlib-only, but the test suites are not. Install the
declared test dependencies once, then run the suites from `TESTING.md`:

```bash
python3 -m pip install -r requirements-dev.txt
```

| Pin | Where | Value |
| --- | --- | --- |
| Test dependencies | `requirements-dev.txt` | `pytest>=8`, `PyYAML>=6` |

`.github/workflows/tests.yml` installs that same file, so a clean machine and
CI run the same set. `PyYAML` is required, not optional: the Kubernetes
manifest and `docker-compose.yml` tests parse the shipped YAML to assert
security properties, and a missing dependency fails the run instead of quietly
removing those checks from it.

## Embedded agent packages

Every Python source under `device/agent/` is embedded into the Guest Shell
bundle, both IOx tars, and the IOS-XR RPM. An agent change is therefore not
ready for device testing until the packages in use have been rebuilt:

```bash
docker compose -f server/docker-compose.yml up -d --build
tools/provision-iox-packages.sh
tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

If the existing canonical OCI archive contains older source at the same
version, the builder refuses to replace it. For an intentional rebuild, run
`IRIS_FORCE_DEVICE_IMAGE_BUILD=1 tools/provision-iox-packages.sh`, then build
the XR wrapper from that updated image. To preserve the old archive, set
`IRIS_DEVICE_IMAGE_OCI` to a new absolute output path for both wrapper builds.

The IOx and XR wrappers are deployment-neutral: no server certificate enters
these build commands. Each builder publishes an adjacent provenance manifest
that binds the wrapper SHA-256 and platform to the canonical multi-platform OCI
index, archive, and source digests. Console package readiness verifies that
binding; it does not compare the package with the current checkout or validate
a native signature. Rebuild after any shared-agent change and redeploy each
affected device. Certificate rotation instead requires re-onboarding devices to deliver
the new runtime trust anchor; it does not require rebuilding these packages.
The final check also verifies that the live and distributed runtime
certificates agree; it never compares certificate age with a package.

`tools/build-device-image.sh`, `device/iox/build.sh`,
`tools/build-xr-package.sh`, and `tools/make-agent-bundle.sh` check whether the
checkout is missing agent or packaging commits from `origin/main` (or local
`main`). They warn and name the missing commits. Set
`IRIS_REQUIRE_FRESH_AGENT=1` to fail the build on that finding, or
`IRIS_ALLOW_STALE_AGENT_ACK=1` to deliberately build an older version.
The check has no effect outside a Git checkout or when neither reference
branch is available. It does not fetch updates. See
`tools/agent-source-freshness.sh`.

## Release process

Keep operator-visible changes under `CHANGELOG.md` → `Unreleased` during normal
development. To cut a release, move those entries under the current CalVer
heading, set `VERSION` to the same `YYYY.0M.0D[.MICRO]` value, run the complete
tests and documentation build, and run `tools/make-release.sh`. The assembler
ships tracked files only (from `git ls-files`, so commit new files first),
writes `release/iris.tgz` together with `release/iris.tgz.sha256` and a
per-member `MANIFEST.txt`, and leaves the previous release untouched if any
step fails; send the tarball with its `.sha256`. The release tag is `v` plus
the exact `VERSION`, including a `.MICRO` suffix when present.

## Documentation loop

The public website is the dependency-free static app under `docs/`. The reference documentation is generated by Zensical from `docs/zensical`, configured by `zensical.toml`.

Build the site once from the repository root, or serve it with live reload while authoring:

```bash
python3 -m venv /tmp/iris-docs-venv
/tmp/iris-docs-venv/bin/pip install -r requirements-docs.txt
/tmp/iris-docs-venv/bin/zensical build   # writes site/, which is gitignored
/tmp/iris-docs-venv/bin/zensical serve   # http://127.0.0.1:8091
```

Both commands read `zensical.toml`, so run them from the repository root rather than from `docs/`.

The Console's `?` menu also links two bundled guides:
`server/webroot/help-device.html` and `server/webroot/help-server.html`.
Update those alongside the manual when troubleshooting steps change. They
ship in the Console image and require a Console rebuild to appear in a
deployment. The public homepage uses `docs/index.html` and `docs/app.js`;
Zensical does not build either file.

The API contract comes from `server/api_routes.py` and
`server/openapi_contract.py`. After a contract change, regenerate and check it:

```bash
python3 server/openapi_contract.py > docs/zensical/openapi.yaml
python3 -m pytest server/tests/test_openapi_contract.py -q
```

Two versions are pinned so a local build matches the published one. Change either only deliberately:

| Pin | Where | Value |
| --- | --- | --- |
| Zensical | `requirements-docs.txt` | `zensical==0.0.51` |
| Python | `.github/workflows/docs.yml` (`actions/setup-python`) | `3.12` |

The GitHub Pages workflow publishes the static website at the root of the `gh-pages` branch and the generated Zensical site under `/docs/`.
