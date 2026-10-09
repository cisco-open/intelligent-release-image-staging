<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# The assistant-facing deployment runbook

Use this runbook when helping someone install or validate IRIS. Confirm the
requested layout, use the supported tools, preserve existing deployments and
record what was actually verified.

## Before you start

Read the repository contributor instructions and the current
[Installation Guide](../zensical/install/index.md). On Ubuntu, start with the
[managed package procedure](../zensical/install/managed-package.md). The manual
Docker and Kubernetes guides describe deployments not owned by that installer.
Do not mix their commands or state directories with a managed installation.

Keep SSH and device credentials in a protected, git-ignored file such as
`creds/deploy.env`, using `creds/deploy.env.example` as the template. Preserve an
existing file. Keep passwords, tokens, private keys and passphrases out of chat,
command output, logs and source control.

## The four decisions the assistant confirms

Reuse answers already given and verified settings. Ask for missing decisions
together before making changes:

1. **Which host and instance:** for a managed install, record the instance name
   and state directory. For a manual install, confirm the checkout directory.
2. **Which layout:** Docker on one host, Docker on separate hosts, or Kubernetes.
   For split Docker, identify the Console host. For Kubernetes, identify the
   context, namespace, storage and image distribution method.
3. **Which devices are in scope:** Guest Shell, amd64 or ARM64 IOx, IOS-XR appmgr,
   or infrastructure checks only. Record which onboarding tests are requested.
4. **Which addresses:** the device-facing server address and full browser
   Console URL, including its HTTPS port.

Repeat the selected configuration before changing it. For an existing managed
install, use its recorded instance and state directory. Resume checks existing
inputs; it does not adopt an unrelated deployment. Keep the same Compose
projects, environment files, volumes or Kubernetes namespace during maintenance.

## What it checks and reads first

Use [Check the host before you install](../zensical/install/check-the-host.md)
and report missing prerequisites. Explain dependency installation, engine access,
emulation and network exposure before applying changes within the approved task.
An authorized installer run handles its dependencies; do not repeat those steps
by hand. The current source-build installer needs network access and is not an
offline kit.

Verify a published package through the managed guide's attestation procedure.
A locally built candidate has a different evidence boundary: record its exact
source and hashes, without describing it as an authenticated public release.

Preserve existing accounts and assignments. A new installation leaves first
account creation to its owner; do not claim the account or sign in unless asked.
For authorized checks of an existing deployment, use its own protected credential
record. Do not guess credentials or substitute those from another deployment.
Never copy server state, the age identity or the management private key to a
separate Console host.

## Building the device packages

The managed installer builds Guest Shell bundles, both IOx architectures and the
IOS-XR RPM as part of its current workflow. Selecting devices for a test does not
change that installer contract. For a manual or isolated validation workflow,
build only what the agreed test scope needs. Infrastructure-only checks can
reuse qualified images without building device packages or onboarding devices.

The tested aria2c clients are committed: `bin/aria2c` for amd64 and
`deliverables/aria2c-aarch64` for ARM64. Builders verify their pinned checksums.
Normal installation does not fetch or compile replacement clients. See
[Build and publish the device packages](../zensical/install/device-packages.md)
for manual package assembly and the shared-agent rebuild rule.

The two approved public instruction roots are build inputs. Keep private keys
outside build contexts, deployment volumes and containers. Native IOx package
signing is a separate Cisco approval process; a SHA512 manifest is not a native
signature. Keep device signature verification enabled and report missing native
signing or admission evidence as a deployment gate.

## The arm64 aria2c build

Rebuilding aria2c is contributor maintenance, not an installation fallback. Use
the committed ARM64 client for normal installs. When a source rebuild is
explicitly requested, follow the pinned source and verification process in
[Device package development](device-packages.md). Explain emulation costs before
starting, retain the build log and report progress. Do not silently substitute
a different binary when a download or package build fails.

## Who holds the private signing keys

The owner chooses separate key holders or protected local storage. Guided
`irisctl setup` creates or reuses protected local keys and passes only public
inputs to the privileged installer. The owner enters passphrases directly into
OpenSSH and reviews the signing request. Keep an independent recovery copy;
deployment backups do not include private setup keys.

For later approvals on the deployment host, the owner runs
`iris-key-setup --local` and confirms **LOCAL KEY HOLDER**. The normal
`iris-key-setup` command retains separate-holder checks. Private-key operations
are refused inside containers in both modes. A host compromise can expose keys
kept there; explain that tradeoff without choosing storage on the owner's behalf.
See [Create keys and approve signing requests](../zensical/install/offline-approval.md).

## Start signing instructions

The managed installer generates the online key, exports its public request,
waits for approval, imports the returned certificate and activates the producer.
Use its guided approval or resume workflow rather than recreating keys manually.
Only public requests and approvals move between the deployment and key holder.

For a manual deployment, use
[Turn on instruction signing](../zensical/install/activate-signing.md).
Check that every input file exists before giving the owner its approval command.
Read the complete signing status and producer health before onboarding; two
status booleans alone do not establish readiness. Root confirmations, renewal
and backup arrangements remain explicit owner actions.

## Assistant operating rules

Use the selected workflow throughout. Do not reset state to bypass a failed
resume, replace roots to bypass an approval, or weaken native verification to
complete a device test. For device tests, preserve the running software, boot
variables and unrelated files. Publishing a release or creating a PR requires
separate authorization from installing or testing a local candidate.

## Reporting as it goes

Report each meaningful result with its scope: source revision, image or package
hash, public-key fingerprint, runtime access check or device outcome. Keep these
facts separate:

- A package build, runtime readability and native signed admission.
- Container or pod readiness and an authenticated Console-to-server request.
- A published certificate and confirmed adoption by each consumer.
- Configuration tests, local container tests and live device qualification.

If a step is still running, report progress and its last safe milestone. If it
fails, report a sanitized error and what remains available. Do not paste raw
command output that may contain credentials. Avoid repeating completed suites
when a focused follow-up covers the changed files.

## The completion record

Record the layout, host roles, addresses, Console URL, management endpoint and
Compose projects or Kubernetes namespace. Include exact tested source and image
identities, commands, outcomes, exclusions and unresolved gates. Agent notes and
logs belong under `agentinfo/`; publish selected dated measurements in
[Dated lab evidence](validation-records.md), not in the user guides.

Use separate test job IDs and distinct test images. Clear only test assignments
and undeploy using the recorded jobs. Remove only files, catalog entries and
resources the test created. Unassigning an IOS-XR image removes files IRIS
downloaded in place; adopted files and files of unknown origin stay. Undeploy
itself leaves any remaining root image files. Preserve real-use assignments and unrelated
services, and verify cleanup by exact resource identity.

## Related

- [Install IRIS](../zensical/install/index.md)
- [Troubleshoot: symptoms and first steps](../zensical/user-guide/troubleshooting.md)
- [Security model and trust boundaries](../zensical/architecture/security-model.md)
- [Repository map and contributor entry point](../../DEVELOPMENT.md)
