<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Production installer development

The Ubuntu 24.04 amd64 `.deb` contains the deployment engine,
managed maintenance service, terminal key and recovery tools, and runtime
diagnostics. It supports single-host Docker, split Docker and Kubernetes.

## Build the Ubuntu installer

Build from a reviewed commit (uncommitted working-tree changes are NOT included):

```bash
python3 tools/build-installer-package.py --out /path/to/candidate-output
```

The package includes only allowlisted committed source, both committed aria2c
architectures, notices and a file inventory. It has no maintainer hooks that
deploy services, generate keys or create accounts. Local output is unauthenticated.
The public `release.yml` workflow builds the tagged commit and authenticates every
asset with GitHub artifact attestations. It publishes the `.deb`, its committed
source inventory, the source archive and member manifest, matching aria2 binaries
and corresponding source, and an authenticated release inventory. Follow
[download and authentication](../zensical/install/managed-package.md#download-and-authenticate)
before installing a public package. The publisher identity is the public GitHub
repository and tagged release workflow, separate from deployment instruction roots.

On an isolated Ubuntu 24.04 amd64 test host, install the reviewed package with
`sudo apt install ./iris-installer_<version>_amd64.deb`. Then:

Run `irisctl setup` without sudo for the owner-selected local-key workflow. It
creates or checks protected signing roots and the recovery identity outside
deployment storage, then invokes the matching privileged installer with public
inputs only. It checks the selected signing key against the journal's pinned
public roots before approving the exact reviewed request. Existing deployments
resume without regenerating keys or changing their recorded configuration.

For separate holders, run `sudo irisctl install` for prompts, or supply public inputs:

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
select an NTP source or rewrite firewall policy. The source-build installer
needs network access for dependency/image/tool downloads. It is NOT an offline
kit. Source manifests detect later drift but do not authenticate a publisher.

The default peer TLS policy is required. The Console binds loopback by default;
set `--console-bind` and `--console-port` explicitly for approved management
network exposure. Restrict first-claim access before deployment. A named,
installer-owned Compose project isolates containers, images, volumes and state.
Existing instances are refused, not adopted. The deployment engine generates
online signing, age and TLS identities; root creation is handled by the chosen
local or separate-holder helper. Private setup keys are outside the deployment
snapshot and backup. Keep an independent recovery copy and protect local custody.

Docker installs accept `--image-root` for a dedicated host import folder.
`irisctl image-root` can connect one to an existing one-host deployment while
its previous import folder is empty. The recorded folder is mounted read-only
and included in backup and restore alongside the separate uploads volume.
Folder changes retain a recovery record until restart and backup checks pass.

The engine pauses with exit 20 and exports `requests/online.pub` below its state
directory. Local setup guides approval and resumes automatically. For separate
holders, take that public file to the custodian machine and run:

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
then provisions and verifies the Guest Shell bundle, exact digest sidecar,
bootstrap and embedded public trust as the server user. It starts the Console
only after those checks pass. Exit 21 means owner claim is still required. No account
is created or logged in automatically. Exit 22 means deployed services await
production review: the operator must complete root attestations/keylist, renewal
and backup arrangements through the documented Console, offline and host workflows.
The installer does not complete those approvals automatically. See
[root attestations](../zensical/admin-guide/deployment-rotation.md#attest-existing-signing-roots)
and [backup controls](../zensical/admin-guide/backups.md#console-backup-controls).
Neither status is a production READY declaration.

The packaged `iris-key-setup` script guides separate key holders through creating
protected keys, approving public requests and copying only public files. Owners
keeping keys on the deployment host use `iris-key-setup --local` for later
approvals. See
[offline approval](../zensical/install/offline-approval.md).

The installer also has explicit `docker-split` and `kubernetes` targets; see the
[managed installation procedure](../zensical/install/managed-package.md).
The split Console host must also run Ubuntu 24.04 amd64 and provide Python 3,
verified SSH and noninteractive root sudo. Missing Docker, Compose and OpenSSL
dependencies are provisioned there. Kubernetes uses an existing cluster; the
controller preserves an installed client or provisions the pinned `kubectl`.
Client/API-server minor versions must differ by no more than one.
Each adapter requires its own live qualification; a passing single-Docker
test does not qualify another topology. The installer provisions a persistent
maintenance service and separate private backup directories after approval.
Host recovery controls manage service availability, independently provided
recovery-key access and trusted public backup signers. Topology-aware cold
backup, verification, isolated extraction and same-deployment restore cutover
are implemented as described in [Lifecycle development](lifecycle.md).
Restore requires current security authority and the same credential generation;
it does not adopt a replacement host or reset missing replay history.
The source-build package needs network access and is not an offline kit.
The same scoped worker supports planned credential maintenance, with a verified
backup prerequisite and `irisctl maintenance` for interrupted-operation
recovery when the Console is stopped.
The Kubernetes doctor below is a separate read-only diagnostic command.
Keep live qualification evidence separate from unit tests and build results.

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
The installation engine separately requires fresh Guest Shell publication
evidence; the standalone native-package doctor's scope is unchanged.
The existing Docker freshness helper still performs its separate live versus
distributed certificate comparison. Errors from transport clients are not
echoed because they can contain authentication material.

## Prebuilt input implementation

The default install uses source builds. `install --release-kit` selects local
prebuilt inputs; `setup` accepts the same options. Supply the independently
selected `--release-tag` and full `--release-commit`, plus a licensed local
`--ioxclient` matching the committed checksum. The installer checks these inputs
before changing the host. A rejected kit never falls back to source builds.

`release_kit.py` authenticates the release inventory and every payload using an
independently installed GitHub verifier. Offline verification also requires
independently supplied trust material. A kit cannot provide its own authority.
Use `--release-verifier` for the independently installed, root-owned GitHub CLI;
the default is `/usr/bin/gh`. `--offline` requires `--release-trusted-root` and
keeps release verification local. Retain the release directory and verifier at
their recorded paths so `resume` can authenticate the same inputs again.

For Kubernetes without an installed client, supply `--kubectl` with the local
binary matching the installer's pinned version and checksum. This input is
checked before host changes and copied without downloading. An existing
`kubectl` or `k3s` client is preserved and still checked against the cluster.

The prepared-host profile checks existing dependencies without installing them.
The `ubuntu-dependencies` profile additionally binds the local Ubuntu package
archive and its inner manifest to the authenticated release inventory.
The separate Ubuntu dependency producer verifies official signed indexes, exact
package hashes and the complete dependency set. Its apply step checks the
approved package plan again while apt holds its mutation lock. This module's
disconnected package tests do not establish complete deployment qualification.

Core image imports use installation-owned tags and record intent before changes.
Resume checks the authenticated kit, matching installed controller and source,
image configuration digest and Docker image ID. These two image identities can
differ. The adapters retain their existing remote-transfer and Kubernetes digest
checks; prebuilt image acquisition disables source builds and image pulls.

The neutral device finalizer validates both architectures, preserves runtime
content and adds the selected public instruction roots. Its receipt records
those exact inputs and outputs. This is distinct from native IOx package signing.
Native wrappers use the finalized image and pinned local packaging tools.
Completed package bytes are recorded before publication and checked on resume.
The public packaging-tools archive contains the selected XR builder source and
its license, not Cisco's ioxclient executable. Source builds keep their existing
wrapper path and provenance format; finalized wrappers use a distinct format.

The Guest Shell input archive references the matching installer source files,
both committed aria2 architectures and their notices. It is checked before host
changes. The server image supplies the compiled helpers, and the runtime
publisher adds the deployment's public roots and checks the served bundle.

Prebuilt backups include the finalized runtime and the recorded native package
cache. Same-deployment restore can recover a missing cache from a matching
backup; it preserves and refuses altered or incomplete existing directories.
A backup without these caches needs the originals to remain intact. Keep the
release kit, verifier and independent trust files at their recorded locations.

The current publication workflow supplies source-build artifacts. Complete kit
publication, dependency bootstrap and offline topology qualification remain
release gates. A local candidate or a successful wrapper build is not proof of
publisher authentication or native Cisco signature acceptance.

## Delivery and qualification contract

Production is the design target. Release qualification covers
single/split Docker and single-/multi-node Kubernetes, prebuilt and managed
source-build paths, both device architectures, custody/signing activation,
resumable operations, upgrades, renewal, backup/restore and failure recovery.
The server remains single-replica; multi-node scheduling is not multi-writer HA.
Optional demo mode cannot satisfy production acceptance gates.

The authenticated release workflow publishes the reviewed source and installer.
Installation resumes from its protected journal after offline approval; the
managed worker performs backup, credential maintenance and approved restore.
Existing crypto operations remain the authority; builders receive public roots
only. Publication requires passing tests and recorded live topology and device
qualification, not just a successful package build.

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
evidence does not qualify Kubernetes; record its live tests separately.
