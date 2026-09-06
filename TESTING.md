# Testing

This document describes how to run the **intelligent-release-image-staging**
test suites and what to include when reporting a bug.

## Running the tests

The project has a Python test suite (pytest) and a shell test suite (bats). Run
both before submitting a change.

Use Python 3.12 with the dependencies in `requirements-dev.txt`: `pytest`,
`PyYAML`, and the OpenAPI 3.2 validator. CI installs the same file. `bats`
comes from your package manager.

```
python3 -m pip install -r requirements-dev.txt
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ lab/tests/ device/test_verify_image.py -q
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ device/xr/tests/ server/tests/*.bats
```

Both commands are expected to be fully green on a clean checkout, with no
host provisioning and no running IRIS stack.

### Opt-in host-integration tests

A few tests are not hermetic by nature: they run a real `docker build`, which
needs a reachable Docker daemon, pulls the pinned base image and takes minutes,
or they reach the network. They are skipped by default so that a clean checkout
is green, and run only when you ask for them:

```
IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
IRIS_TEST_HOST_INTEGRATION=1 python3 -m pytest server/tests/test_aria2c_build_pins.py
```

Today that covers the two image-build tests in `device/xr/tests/test_xr_image.bats`
and the pin-resolution test in `server/tests/test_aria2c_build_pins.py`, which
asks the live Alpine package index whether the pins in the published aria2c
build scripts still exist — an Alpine security bump withdraws the version we
pinned, and nothing hermetic can see that. Everything else runs
unconditionally. Use the same variable if you add a test that cannot avoid
depending on the machine it runs on.

### Capacity harness

`server/tests/test_capacity_harness.py` is a repeatable mixed-workload
capacity harness. It seeds a synthetic fleet of N devices in its own
temporary directory and drives a tracker announce, a catalog heartbeat, a
device policy read, a terminal report, a credential resolution, a fleet-wide
bulk credential reassignment, and the Console's fleet projection (paged and
unpaged). It reports how the cost of each changes as N grows.
Credential checks run the actual catalog, tracker query and tracker bearer
resolvers with accepted and unknown tokens. The harness counts index lookups
and rejects fleet-wide scans during resolution.
`FleetStore.bulk_upsert` writes at most `keyed_state.SHARD_COUNT` (256) shard
files, however many devices are selected.

A small, fast pair of sizes (50 and 500 devices) runs by default with every
test suite, in a few seconds:

```
python3 -m pytest server/tests/test_capacity_harness.py -q
```

The full progression this project's scale claims are stated at — 100, 1,000
and 10,000 devices, a hundredfold range, 10,000 being the top of the
supported fleet size — rebuilds a 10,000-device synthetic fleet and is slow
by design, so it is opt-in behind its own variable, following the
`IRIS_TEST_HOST_INTEGRATION=1` convention above:

```
IRIS_TEST_CAPACITY_LARGE=1 python3 -m pytest \
    server/tests/test_capacity_harness.py -q -s -k ten_thousand
```

`-s` is needed to see the printed report table; without it pytest still runs
the same assertions but swallows the table. It can also run standalone,
outside pytest, for an ad hoc report at any sizes:

```
python3 server/tests/test_capacity_harness.py --sizes 100 1000 10000
```

**What the numbers mean, and what would invalidate them.** Every operation
calls the real production function (or, for the console, drives the real
`gui_server` HTTP handler end to end) against synthetic state shaped like the
real thing — never a reimplementation of the logic under test. Wall-clock
timings are reported for context but are **not** assertions: other work on
the build host affects absolute timings, and a number from one run is not
comparable to a number from a different run, day, or machine — only the
growth factor *within one run*, across its own sizes, is meaningful. The
assertions that actually run are all deterministic counted work, in the
style `server/tests/test_keyed_state_scaling.py` established: which shard
file changed, how many rows a touched shard holds, how many credential-index
builds and lookups requests cost, how many bytes a console response carries.
Not measured at all: concurrent load (every call in the harness runs
sequentially, one at a time, never the thousands-of-devices-at-once shape a
real fleet produces), process/thread/file-descriptor growth over time, and
real disk hardware latency (state lives under a plain `tempfile
.TemporaryDirectory()`, on whatever filesystem backs the host's temp
directory — not necessarily what backs a production volume). See the
module's own docstring for the full accounting.

`PyYAML` is not optional: the Kubernetes manifest and docker-compose tests
parse the shipped YAML to assert security properties, and they fail rather than
skip when it is missing. The code under test is stdlib-only; nothing in
`requirements-dev.txt` ships to a device or into the server image.

Add tests for any new functionality or bug fix, and ensure all tests pass before
opening a pull request.

## Environment details for bug reports

When reporting a problem, include the environment details relevant to the
system so a maintainer can reproduce it:

- **Device OS and version** (`IOS-XE` or `IOS-XR`)
- **Device platform / model** (e.g., Catalyst 9300)
- **Boot mode**: INSTALL vs. bundle
- **Agent install**: Guest Shell, IOx, router Guest Shell, or XR appmgr
- **Server host OS** (distribution and version)
- **Docker / Docker Compose version** used for the server stack
- **aria2c version** (on the device Guest Shell agent and/or seeder)
- For onboard latency, the persisted deployment log with `[+offset]` prefixes
  and matching artifact-server access lines (`duration`, `inflight`)
