<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Production installer development

The production installer is under development. It is not yet an alternative
to the published installation guide. This first slice provides read-only
runtime diagnostics; it does not install services, provision signing, compile
packages, create accounts or implement lifecycle operations.

## Implemented: native-package runtime checks

From a source checkout or release bundle:

```bash
python3 tools/irisctl doctor --target docker --container iris
python3 tools/irisctl doctor --target kubernetes \
  --context lab --namespace iris --pod iris-seed-server-example --container iris
```

Replace Kubernetes values with the exact context, namespace and server pod.
The Kubernetes adapter refuses to infer these from the current context or a
label selector. Docker optionally accepts `--context` for a selected local or
remote Docker endpoint. The command uses existing Docker/kubectl authentication;
it does not install those clients or acquire broader privileges.

Both adapters stream the same Python probe to the server over stdin, without
copying files or installing software there. The probe uses the running image's
`setup_status` implementation and refuses any identity other than uid/gid
10001. Python runs in isolated mode with bytecode writes disabled. The command
has a configurable timeout (120 seconds by default).

By default both IOx architectures and the XR RPM are required. `--optional-xr`
only permits an absent XR RPM, never a present but invalid one. The existing
Docker freshness helper uses this option to preserve its IOx-only contract.
All failures, including unavailable clients and invalid responses, return 1;
invalid command arguments return 2. `--format json` emits schema version 1 with
the scope `native-package-readability-and-provenance`. Only complete evidence
within that scope returns `checks-passed` and exit 0, never installation READY.

The probe reads complete wrapper bytes and their provenance sidecars, and
fingerprints the distributed catalog certificate. It does not authenticate the
sidecar, inspect package contents/native signatures, check live TLS endpoints,
qualify Guest Shell, test instruction signing or establish Console ownership.
The existing Docker freshness helper still performs its separate live versus
distributed certificate comparison. Errors from transport clients are not
echoed because they can contain authentication material.

## Delivery contract and next implementation slices

Production is the default design target. First-release qualification requires
single/split Docker and single-/multi-node Kubernetes, prebuilt and managed
source-build paths, both device architectures, custody/signing activation,
resumable operations, upgrades, renewal, backup/restore and failure recovery.
The server remains single-replica; multi-node scheduling is not multi-writer HA.
Optional demo mode cannot satisfy production acceptance gates.

Next work is the authenticated release/build kit and resumable transaction
engine, followed by production custody and artifact finalization, deployment
adapters and lifecycle qualification. Existing crypto operations remain the
authority; builders receive public roots only. No install command is exposed
until it performs a real supported workflow with truthful readiness results.

## Tests

```bash
python3 -m pytest server/tests/test_installer_runtime.py -q
bats server/tests/test_package_freshness.bats device/iox/tests/test_stage_iox_package.bats
```

The ordinary suite stubs transports and checks real fixture bytes. For the
opt-in Docker permission regression, set `IRIS_INSTALLER_DOCKER_TEST_IMAGE` to
an existing, trusted server image's immutable `sha256:` image ID. It starts one
isolated container, exposes no ports, mounts only disposable test fixtures,
tests real service-user EACCES and removes its container afterward. It does not
contact inventory devices or an existing IRIS deployment. Docker transport
evidence does not qualify Kubernetes; its live test matrix remains outstanding.
