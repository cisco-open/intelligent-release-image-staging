# Testing

This document describes how to run the **intelligent-release-image-staging**
test suites and what to include when reporting a bug.

## Running the tests

The project has a Python test suite (pytest) and a shell test suite (bats). Run
both before submitting a change:

```
python3 -m pytest server/tests/ device/agent/tests/ device/iox/tests/ lab/tests/ device/test_verify_image.py -q
bats device/test_guestshell_start.bats device/test_bootstrap.bats device/tests/ device/iox/tests/ device/xr/tests/ server/tests/*.bats
```

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
