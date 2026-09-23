<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Production installer development

The production installer is under development. An Ubuntu 24.04 amd64 `.deb`
candidate now contains the source-build installation engine as well as runtime
diagnostics. It is not yet the qualified all-topology production release.

## Ubuntu installation candidate

Build from a reviewed commit (uncommitted working-tree changes are NOT included):

```bash
python3 tools/build-installer-package.py --out /path/to/candidate-output
```

The package includes only allowlisted committed source, both committed aria2c
architectures, notices and a file inventory. It has no maintainer hooks that
deploy services, generate keys or create accounts. The adjacent checksum is
local corruption detection, NOT a release signature. An approved release
signing/distribution process is still required before public production use.

On an isolated Ubuntu 24.04 amd64 test host, install the reviewed package with
`sudo apt install ./iris-installer_<version>_amd64.deb`. Then:

Run `sudo irisctl install` for prompts, or supply the same public inputs explicitly:

```bash
sudo irisctl install --state-dir /var/lib/iris-installer/my-instance \
  --instance my-instance --host <device-facing-ipv4> \
  --roots-dir /path/to/two-reviewed-public-roots \
  --recovery-recipient <separately-held-age-public-recipient> \
  --accept-changes
```

Dependencies are installer-managed: Ubuntu tools, missing engine/plugins and
ARM64 emulation. An existing engine is not replaced. Host time must already be
synchronized with the organization's approved source; the installer does not
select an NTP source or rewrite firewall policy. This source-build candidate
needs network access for dependency/image/tool downloads. It is NOT an offline
kit. Source manifests detect later drift but do not authenticate a publisher.

The default peer TLS policy is required. The Console binds loopback by default;
set `--console-bind` and `--console-port` explicitly for approved management
network exposure. Restrict first-claim access before deployment. A named,
installer-owned Compose project isolates containers, images, volumes and state.
Existing instances are refused, not adopted. Private offline roots stay with
their custodians; the installer generates only the server's age and online keys.

The engine pauses with exit 20 and exports `requests/online.pub` below its state
directory. Take that public file to the offline custodian machine and run:

```bash
irisctl approve-signing --public-key online.pub --root-key /offline/root-a
```

The holder enters the passphrase directly into OpenSSH. Return only
`online-cert.pub`, then run on the server:

```bash
sudo irisctl resume --state-dir /var/lib/iris-installer/my-instance \
  --certificate /path/to/online-cert.pub
```

Resume validates the saved source, roots, configuration and built image IDs.
It does not regenerate an existing online key or reinitialize an activated
producer. It builds both IOx packages and the XR RPM, checks runtime readability,
and starts the Console. Exit 21 means owner claim is still required. No account
is created or logged in automatically. Exit 22 means deployed services await
production review: root attestations/keylist, renewal and backup arrangements
are not yet orchestrated. Neither status is a production READY declaration.

Kubernetes deployment, split Docker, a prebuilt/offline kit, guided root creation,
fully recoverable initial reservation, upgrade/uninstall and automated recovery
cutover remain unfinished. Single-host cold backup, verification and isolated
extraction are implemented as described in [Lifecycle development](lifecycle.md).
The Kubernetes doctor below is diagnostic support, not deployment
support. Do not use this candidate as evidence that those release gates passed.

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

Next work is completion of the authenticated release/build kit and transaction
recovery, deployment adapters and lifecycle qualification. Existing crypto operations remain the
authority; builders receive public roots only. No install command is exposed
as production-complete until the required qualification gates pass.

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
