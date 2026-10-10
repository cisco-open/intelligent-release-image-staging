<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Production installer development

The Ubuntu 24.04 amd64 `.deb` contains deployment, maintenance, key, recovery and
diagnostic tools. It supports single-host Docker, split Docker and Kubernetes.

## Build the Ubuntu installer

Build from a reviewed commit (uncommitted working-tree changes are NOT included):

```bash
python3 tools/build-installer-package.py --out /path/to/candidate-output
```

The package includes only allowlisted committed source, both committed aria2c
architectures, notices and a file inventory. It has no maintainer hooks that
deploy services, generate keys or create accounts. Local output is unauthenticated.
The public `release.yml` workflow authenticates the tagged commit's assets with
GitHub artifact attestations: the `.deb`, source inventories and archive,
matching aria2 binaries, corresponding source and release inventory. Follow
[download and authentication](../zensical/install/managed-package.md#download-and-authenticate)
before installing a public package. The publisher identity is the public GitHub
repository and tagged release workflow, separate from deployment instruction roots.

On an isolated Ubuntu test host, run `sudo apt install ./iris-installer_<version>_amd64.deb`.

Run `irisctl setup` without sudo for automatic local keys by default
(`--key-mode automatic`). Its four steps cover settings review, key/server
preparation, trusted approval/package completion, and opening the Console.
It creates protected signing roots and a recovery identity outside deployment
storage, then invokes the matching privileged installer with public inputs only.
Each root has its own strong random passphrase in a mode-0600 file inside the
owner's mode-0700 key folder. OpenSSH receives it through `SSH_ASKPASS`, never
through secret arguments, environment values or logs. The default folder is
`~/.local/share/iris-setup-keys/<instance>`; `--key-directory` selects another.

Automatic approval checks the exact pending request against the deployment's
pinned public roots and its recorded managed keys. Resume preserves those keys
and the recorded configuration. Existing manual keys require `--key-mode manual`
and their original passphrases; automatic mode never replaces or unlocks them.
Manual local setup retains OpenSSH prompts and explicit request approval.
Operating-system sudo authentication and the owner-chosen Console password are
separate. Keeping keys with their passphrases does not protect against full host
compromise. Keep a secure independent copy of the entire key folder, including
passphrase files and the recovery identity; deployment backups exclude it.

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
`irisctl image-root` can change it while the previous folder is empty. The folder
is mounted read-only and included in backup and restore alongside uploads.
Changes retain a recovery record until restart and backup checks pass.

The engine pauses with exit 20 and exports `requests/online.pub` below its state
directory. Automatic setup approves its matching managed request and resumes;
manual local setup asks for approval. For separate
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

`iris-key-setup` guides separate key holders through key creation and approvals,
copying only public files. Use `iris-key-setup --local` for later approvals with
locally held keys. Managed roots reuse their saved passphrases; request review
and SHA256 confirmation remain required. See [offline approval](../zensical/install/offline-approval.md).

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
The scoped worker requires a verified backup for credential maintenance;
`irisctl maintenance` recovers interrupted work while the Console is stopped.
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

Both adapters stream the running image's `setup_status` probe over stdin.
It requires uid/gid 10001 and isolated Python with bytecode writes disabled.
The configurable timeout defaults to 120 seconds. Both IOx architectures and
the XR RPM are required; `--optional-xr` permits only an absent XR RPM.
The Docker freshness helper retains that IOx-only option.

Failures return 1; invalid arguments return 2. `--format json` emits schema 1
with scope `native-package-readability-and-provenance`. Complete evidence returns
`checks-passed` and exit 0, never installation READY. The probe reads wrapper
bytes, sidecars and the distributed certificate fingerprint. It does not prove
publisher or native signatures, live TLS, Guest Shell readiness, instruction
signing or Console ownership. The engine separately checks Guest Shell publication.
The Docker freshness helper separately compares live and distributed certificates.
Transport errors are withheld because they can contain authentication material.

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

The installer records the accepted dependency plan before applying it. Resume
can retry an unchanged host or recognize that the exact plan finished before
its completion was recorded. Partial apt operations and unexpected changes
stop for inspection with the plan retained. Once complete, ordinary Ubuntu
security updates are allowed when the required dependencies remain available;
resume does not silently install a new dependency plan.

Split Docker uses a separate accepted plan for the selected Console host. It
checks the SSH identity, host identity and Ubuntu signatures there, then installs
only Docker, Compose, OpenSSL and their required dependencies. Ownership checks
remain read-only. The remote host needs Python, SSH, sudo and Ubuntu's package
tools and archive keyring before this step.

Core image imports use installation-owned tags and record intent before changes.
Resume checks the authenticated kit, matching installed controller and source,
image configuration digest and Docker image ID. These two image identities can
differ. The adapters retain their existing remote-transfer and Kubernetes digest
checks; prebuilt image acquisition disables source builds and image pulls.

The neutral device finalizer validates both architectures, preserves runtime
content and adds the selected public instruction roots. Its finalization record identifies
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
publication and offline topology qualification remain release gates. A local
candidate does not prove publisher authentication or native Cisco signature acceptance.
Release preparation refuses the new prebuilt assets until those gates are connected.

## Assemble a local candidate

Use a reviewed local commit, the pinned XR builder checkout and an existing
Buildx builder supporting amd64 and arm64. Build dependencies may need network access.

```bash
python3 tools/build-release-candidate.py --repo /path/to/iris-checkout \
  --commit '<full-commit>' --tag 'v<version>' \
  --appmgr-repository /path/to/xr-appmgr-build \
  --builder existing-amd64-arm64-builder --output-dir /path/to/new-private-candidate
```

The helper checks committed source in a private checkout and reuses the package,
source, image and input builders. It checks installer/source agreement before
image builds and writes `local-candidate.json` with `authenticated: false`.
Add `--ubuntu-dependencies /path/to/iris-ubuntu-dependencies.tar.gz` for a prepared
Ubuntu dependency archive. Use a new output directory within a protected parent.

Add `--aria2-sources /path/to/aria2c-2.5.6-p10-source.tar.gz` to carry the reviewed
aria2 source companion. Before building, the helper checks the selected commit's
source checksum, source-input manifest and both client binaries, including ARM64.
It keeps an immutable private copy and records the binding in `local-candidate.json`.
Keep this companion with the clients when redistributing them; it covers aria2
and its bundled dependencies, not every component in the IRIS images.

### Ubuntu source and notice companion

Collect exact source files under a local `pool/...` mirror and prepare an
`iris-ubuntu-source-inputs-v1` JSON descriptor. Its `indexes` list contains
`repository`, `suite`, `component`, absolute `inrelease` and `sources` paths,
and boolean `historical` for each index. Include all six current noble,
noble-updates and noble-security main/universe indexes; explicitly mark retained
historical source evidence. Current InRelease bytes must match the binary closure.

```bash
python3 tools/build-offline-sources.py --binary-closure /path/to/dependency-payload \
  --manifest-sha256 '<dependency-manifest-sha256>' --indexes /path/to/indexes.json \
  --source-pool /path/to/source-mirror --out /path/to/iris-ubuntu-sources.tar.gz
```

The producer verifies Ubuntu signatures, exact Source and Built-Using versions,
source files, `.dsc` inventories and carried copyright/license bytes. Inputs are
local; source recipes are not executed. Use `--verify-bundle` instead of `--out`,
`--indexes` and `--source-pool` to independently recheck an existing companion.

Add `--ubuntu-sources /path/to/iris-ubuntu-sources.tar.gz` together with
`--ubuntu-dependencies` to candidate assembly. Both archives are privately
snapshotted and complete source coverage is checked before any builder runs.
The immutable companion is recorded in `local-candidate.json` with its exact
dependency binding; it is not an installer asset role. The candidate remains
unauthenticated. Ubuntu coverage does not establish Docker/Alpine image coverage.

Before publication, review corresponding source and notices for every shipped
component, including Ubuntu packages, and confirm redistribution permission.
Cisco's licensed ioxclient remains separately supplied. Candidate checks do not
create release attestations or satisfy these publication and topology gates.

### Inspect image source requirements

Run `python3 tools/inspect-image-components.py --help` for the input options.
Supply the exact server, Console and neutral runtime archives, their independently
recorded SHA-256 values, the full source commit and a new protected output directory.
The helper reads the images without starting containers or running their programs.

The resulting `image-components.json` lists package versions and incorporated
sources, runtime components and notice files in each layer and the final image.
It includes both neutral runtime architectures. Core image revision labels must
match the selected commit; the neutral image's source-commit binding is not assessed.

This is an inventory, not complete source delivery or release authentication.
Resolve the listed source requirements and unknown components before publication.
Keep the record and exact input hashes with the candidate's review evidence.

### Debian image source companion

Use `tools/build-debian-sources.py` with that reviewed inventory and its SHA-256,
an independently trusted Debian archive keyring, a local source pool and an
`iris-debian-source-inputs-v1` descriptor. Its three `indexes` entries name
`repository`, `suite`, `component`, and absolute `inrelease` and `sources` paths:
Debian trixie/main, Debian trixie-updates/main and security trixie-security/main.

The producer includes exact direct and incorporated source versions from every
distributed layer. It checks signed indexes and every source file, then writes
a new archive with `--out`. Use `--verify-bundle` instead to independently check
an existing archive against the same external inventory and keyring. Neither
operation runs source recipes. This companion covers Debian source files only;
other image components and notice preservation need their own review.

For a retained archive whose repository metadata has expired, add
`--archived-integrity` to `--verify-bundle`. This still checks signatures, exact
versions and every file hash, but reports archived integrity rather than current
metadata. It cannot build a new companion or establish publication readiness.
Installer and apt freshness checks remain unchanged.

### Alpine and core Python companions

`tools/build-alpine-sources.py` takes the reviewed image inventory and its SHA-256,
a local aports Git repository, a source pool and a new output directory. Name
each external source input by its complete lowercase SHA-512. The helper retains
the exact port recipes and checks every listed source and patch, including inputs
for both architectures. It reads Git objects without fetching or running recipes.
Its independent validator is `alpine_sources.validate_source_archive()`.

`tools/build-core-python-sources.py` covers the supported server and Console
CPython/pip versions. Supply the reviewed inventory, exact image configurations,
local source archives and an independently reviewed pip source checksum. CPython
is bound to the source pin in those configurations; observed pip source/data
files must match its archive. Original source archives and notices are retained.
Use `--verify-bundle` to check an existing companion with the same external inputs.
Generated bytecode and installed metadata are identified separately, not presented
as source equality. These companions do not establish complete image coverage.

### Neutral runtime and static helper sources

`tools/build-runtime-sources.py` collects the supported neutral Python/XML and
static verifier source inputs. Supply the original candidate and image inventory
with their reviewed hashes, the exact Alpine companion and the local source pool.
It checks the neutral build context, original source archives, patch and notices,
and retains the installed Python build configuration for both architectures.

Use `--verify-bundle` to check an existing companion against the same external
inputs. Keep its referenced Alpine archive alongside it. Source-file matches
are reported separately from generated binaries; the tool does not establish
binary reproducibility or publisher authentication.

### Image notices and candidate completion

`tools/build-image-source-notices.py` collects original notices, package ownership
and exact source references from every image layer and the final filesystems.
Supply the candidate and inventory with their reviewed hashes, the five image
source companions with their hashes, and the pinned debuerreotype script and
license. Use `--verify-bundle` to reconstruct an existing catalogue. Recipe-only
license declarations remain distinct from original notice text; package ownership
does not prove a reproducible binary build.

Once the companions are ready, use `tools/complete-release-candidate.py` with the
original candidate hash, tag, full commit, source companions, notice catalogue,
independent Debian keyring and reviewed pip source hash. Include Ubuntu sources
for the dependency profile. The helper rechecks the installer against its source,
recomputes the image inventory and independently validates each companion.

It writes a new private directory with `candidate-evidence.json`, preserving the
original candidate bytes. It does not rebuild images or download source. This
evidence still needs source and redistribution review, release authentication
and live qualification. See the [release checklist](release-checklist.md) for
the separate authentication and publication steps.

### Prepare prebuilt authentication inputs

Use `tools/prepare-prebuilt-release.py --check` with `--completed-dir` and its
independently recorded `--evidence-sha256`. Select a clean local checkout with
`--repository`, its exact `--tag` and full `--commit`. Supply the independent
`--debian-keyring` and `--pip-sdist-sha256` used for that candidate.
This repeats the source checks and verifies every shipped source file against
Git without building or executing candidate code.

For unsigned release output, replace `--check` with `--output-dir` naming a new
protected output path. Also supply `--source-review` with `--review-sha256`,
and `--stage-record` with `--stage-sha256`, using independently recorded hashes.
The review must identify its reviewer and cover the exact payload and companions.
The run record must name the selected tag, commit, workflow run and attempt.
The helper preserves both records and the original candidate, copies the public
verification helper and clients from checked source, and writes the release
inventory and checksums.
It checks the original source manifest rather than replacing it.

These inputs remain unsigned until the authorized hosted workflow authenticates
them. The helper checks the review's file bindings, not the reviewer's authority.
The tag workflow still authenticates source-only builds; prebuilt upload and
authentication require their separately approved integration. The manual
publisher accepts an explicit profile and its matching qualification record.

## Bootstrap the installer offline

This developer route needs an authenticated `ubuntu-dependencies` kit and its
matching `.deb`. Start with Ubuntu 24.04 amd64 server, Python 3.12, apt,
dpkg/dpkg-deb, gpgv and Ubuntu's archive keyring. Independently provision and trust
the loader, root-owned GitHub CLI and trusted-root file before running anything
from the kit. A minimal image without Python needs a separately prepared baseline.

Preview the prerequisite plan using a new bootstrap state path:

```bash
sudo /usr/bin/python3 -I /path/to/trusted/bootstrap-offline.py \
  --deb '/path/to/kit/iris-installer_<version>_amd64.deb' --release-kit /path/to/kit \
  --release-tag 'v<version>' --release-commit '<full-commit>' \
  --release-verifier /usr/bin/gh --release-trusted-root /path/to/independent-root.json \
  --state-dir /var/lib/iris-offline-bootstrap
```

Review the plan, then repeat with `--accept-changes`. The loader authenticates
the private package before importing its controller. The controller records the
accepted Python, age, CA-certificate and SSH-client dependency plan before applying
it, then installs the exact local `.deb`. Unrecorded installer packages and unknown
destination files are refused. Dependencies never fall back to network downloads.

Resume with the original inputs, `--accept-changes` and the same state path.
Keep bootstrap and deployment journals separate. Missing bootstrap records, partial package
changes and altered files stop for inspection; preserve that evidence. Deployment
authentication, approvals and public-kit qualification remain separate requirements.

## Delivery and qualification contract

Qualify single/split Docker and single-/multi-node Kubernetes, source and prebuilt
inputs, both device architectures, signing, resume, upgrades, renewal, backup/restore
and failure recovery. The server remains single-replica. Multi-node scheduling
and optional demo mode alone do not satisfy high-availability or production acceptance.

Builders receive public roots only. Existing crypto approvals remain authoritative.
Publication requires passing tests and recorded live topology and device
qualification, not just a successful package build.

## Tests

```bash
python3 -m pytest server/tests/test_installer_runtime.py -q
bats server/tests/test_package_freshness.bats device/iox/tests/test_stage_iox_package.bats
```

Ordinary tests stub transports and check fixture bytes. The optional Docker
permission test uses `IRIS_INSTALLER_DOCKER_TEST_IMAGE`, an existing trusted image's
immutable `sha256:` ID. Its temporary container exposes no ports and uses disposable
fixtures; inventory devices and existing deployments remain untouched.
