<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Manual checks and the test-file map

This page covers what a contributor runs before opening a pull request: the
automated Python and shell test suites, the documentation build, and the
Console checks that only work by hand in a browser. Validate the
documentation, the server, the device packaging, and lab behavior separately.
A passing test suite is necessary, but it does not by itself prove a change
is safe to roll out to a real fleet.

## Run the automated tests

Use Python 3.12 with the dependencies in `requirements-dev.txt`: `pytest`,
`PyYAML`, an independent `cryptography` AES-SIV test oracle, and an OpenAPI
3.2 validator. Continuous integration (CI) installs the same file. `bats`,
`mktorrent`, and the `age` CLI, which carries `age-keygen`, come from your
package manager. A few tests drive those two binaries for real instead of
stubbing them, and skip themselves when the binary is missing, so install
both to get the result CI reports. OpenSSH's `ssh-keygen` is assumed to be
present.

```bash
python3 -m pip install -r requirements-dev.txt
IRIS_CRYPTO_ARCHES=amd64 bash tools/build-instruction-crypto.sh  # arm64 on an ARM host
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ device/xr/tests/ lab/tests/ device/test_verify_image.py tools/test_api_exercise.py -q
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ device/xr/tests/ server/tests/*.bats
```

Build the static instruction helper once with Docker and BuildKit; it needs
network access for the pinned build inputs. The test commands then run
without a live IRIS stack or network access. A missing helper fails the
crypto tests instead of silently skipping them. To package both
architectures, omit `IRIS_CRYPTO_ARCHES` from the build command.

### Console and Swagger browser checks

With Node 24, run from `server/console-ui`:

```bash
npm ci --no-audit --no-fund
npm test
npx --no-install playwright install --with-deps chromium
npm run test:browser
npm run test:swagger
```

These bounded Chromium checks use local fixtures, not live devices. They
cover Console workflows and the vendored Swagger UI: its operations and
schemas, filtering, deep links, read-only controls, and mobile layout. CI
runs the same commands.

### Opt-in host-integration tests

A few tests are not hermetic by nature: they run a real `docker build`, which
needs a reachable Docker daemon, pulls the pinned base image, and takes
minutes, or they reach the network. They are skipped by default so a clean
checkout stays green, and run only when you ask for them:

```bash
IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
IRIS_TEST_HOST_INTEGRATION=1 python3 -m pytest server/tests/test_aria2c_build_pins.py
```

Today that covers the two image-build tests in
`device/xr/tests/test_xr_image.bats` and the pin-resolution test in
`server/tests/test_aria2c_build_pins.py`, which asks the live Alpine package
index whether the pins in the published aria2c build scripts still exist. An
Alpine security update can withdraw the exact version pinned there, and no
hermetic test can see that. Run both before you cut a release or after you
change `device/container/Dockerfile`. Everything else runs unconditionally;
use the same variable if you add a test that cannot avoid depending on the
machine it runs on.

### Capacity harness

`server/tests/test_capacity_harness.py` is a repeatable, mixed-workload
capacity harness. It seeds a synthetic fleet of N devices in its own
temporary directory, never the live server, its volumes, or a real device.
It then drives a tracker announce, a catalog heartbeat, a device policy
read, and a terminal report. It also drives a credential resolution, a
fleet-wide bulk credential reassignment, and the Console's own fleet
projection, paged and unpaged. These are the operations a real fleet drives
concurrently. It reports how the cost of each moves as N grows.
`FleetStore.bulk_upsert` writes at most
`keyed_state.SHARD_COUNT` (256) shard files to reassign the whole selected
set, however many devices are selected. Credential checks call the actual
catalog, tracker query, and tracker bearer resolvers with accepted and
unknown tokens; the harness counts index lookups and rejects fleet-wide scans
during resolution.

A small, fast pair of sizes (50 and 500 devices) runs by default with every
test suite, in a few seconds:

```bash
python3 -m pytest server/tests/test_capacity_harness.py -q
```

The larger synthetic progression, 100, 1,000, and 10,000 devices, checks how
the implementation's cost grows, not a supported production fleet size. It
rebuilds a 10,000-device synthetic fleet and is slow by design, so it is
opt-in behind its own variable, following the `IRIS_TEST_HOST_INTEGRATION=1`
convention above:

```bash
IRIS_TEST_CAPACITY_LARGE=1 python3 -m pytest \
    server/tests/test_capacity_harness.py -q -s -k ten_thousand
```

`-s` shows the printed report table; without it, pytest still runs the same
checks but swallows the table. It can also run standalone, outside pytest,
for a report at any sizes:

```bash
python3 server/tests/test_capacity_harness.py --sizes 100 1000 10000
```

**What the numbers mean, and what would invalidate them.** Every operation
calls the real production function. For the Console, it drives the real
`gui_server` HTTP handler end to end. Both run against synthetic state
shaped like the real thing, never a reimplementation of the logic under
test. Wall-clock timings are printed for context, but they are not checks.
Other work on the build host affects the absolute timings. A number from
one run is not comparable to a number from a different run, day, or
machine. Only the growth factor within one run, across its own sizes, means
anything. The checks that actually run are all deterministic counted work,
in the style `server/tests/test_keyed_state_scaling.py` established. They
count which shard file changed, how many rows a touched shard holds, how
many credential-index builds and lookups a request costs, and how many
bytes a Console response carries. It does not measure concurrent load.
Every call in the harness runs one at a time, never the
thousands-of-devices-at-once shape a real fleet produces. It also does not
measure process, thread, or file-descriptor growth over time, or real disk
hardware latency. State lives under a plain `tempfile.TemporaryDirectory()`,
on whatever filesystem backs the host's temp directory, which is not
necessarily what backs a production volume. See the module's own docstring
for the full accounting.

`PyYAML` is not optional: the Kubernetes manifest and Docker Compose tests
parse the shipped YAML to check security properties, and they fail rather
than skip when it is missing. The code under test is stdlib-only; nothing in
`requirements-dev.txt` ships to a device or into the server image.

Add tests for any new feature or bug fix, and check that all tests pass
before you open a pull request.

## Build the documentation

Build the documentation site from the repository root whenever you change a
page under `docs/zensical` or its navigation. See
[Writing and building the docs](docs/dev/documentation.md) for the commands
and the pinned tool versions. A build checks that the generated site
compiles; check the Console's bundled help pages by hand, since the
documentation build does not touch them.

## The test-file map

Some behavior is proven by exactly one part of the test suite and nowhere
else. Automated coverage for management-type and deployment-record behavior
lives in `server/tests/test_deployment_records.py`,
`server/tests/test_gui_fleet.py`, the inband command-stream checks in
`device/tests/test_device_uninstall.bats`, and the router install and
teardown command streams in `device/tests/test_router_install.bats` and
`device/tests/test_router_uninstall.bats`. See
[Choose a management type](docs/zensical/install/management-types.md).

## Checks you do by hand in the Console

The Console has Python tests for server-side projections, and Node-based
tests that run the shipped JavaScript for device fields, status, and Swarm
Map updates. They cover per-image state, participant identity, stale
responses, and open-drawer updates, but they do not run a browser layout
engine.

Check layout, keyboard behavior, and the rendered graph by hand in a browser
whenever those views change. Passing the automated tests does not prove that
fields line up or that graph nodes render where they should.

| Check | What to look for |
| --- | --- |
| Hidden-tab pause | Polling stops when the tab is hidden or you leave the view, and starts again when you return. |
| Backoff | While `/swarm` is unreachable, the poll interval backs off and the header says so, instead of retrying as fast as it can. |
| Keyboard | Graph nodes are reachable and operable from the keyboard; the detail drawer keeps focus and closes when you press Escape. |
| Reduced motion | The graph follows the reduced-motion preference. |
| Empty and error states | An empty swarm, a failed origin request, and a stale device observation each look different from one another. |
| Live details | An open peer drawer updates as polls arrive, keeps focus, and shows when its participant disappears. A late response from an older poll does not overwrite newer data. |
| Multiple devices and images | Completed staging for one device or image stays complete when another device or image starts. Shared IP addresses do not duplicate rates, and each image's errors appear on the matching row. |
| Add Device | Management type alone controls the network fields; changing the free-text model preserves that selection. Fields and the Save and Cancel buttons stay aligned at desktop and narrow widths. |

## Report a problem

When you file a bug report, list the environment details from
[Troubleshoot: symptoms and first steps](docs/zensical/user-guide/troubleshooting.md).
