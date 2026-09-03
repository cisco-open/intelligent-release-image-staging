# Testing

This document describes how to run the **intelligent-release-image-staging**
test suites and what to include when reporting a bug.

## Running the tests

The project has a Python test suite (pytest) and a shell test suite (bats). Run
both before submitting a change.

The Python suites need `pytest` and `PyYAML`, declared in
`requirements-dev.txt` — the same file CI installs. `bats` comes from your
package manager.

```
python3 -m pip install -r requirements-dev.txt
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ lab/tests/ device/test_verify_image.py -q
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ device/xr/tests/ server/tests/*.bats
```

Both commands are expected to be fully green on a clean checkout, with no
host provisioning and no running IRIS stack.

### Opt-in host-integration tests

A few bats tests are not hermetic by nature: they run a real `docker build`,
which needs a reachable Docker daemon, pulls the pinned base image and takes
minutes. They are skipped by default so that a clean checkout is green, and run
only when you ask for them:

```
IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
```

Today that covers the two image-build tests in `device/xr/tests/test_xr_image.bats`.
Everything else runs unconditionally. Use the same variable if you add a test
that cannot avoid depending on the machine it runs on.

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
