<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# The assistant-facing deployment runbook

Many IRIS deployments start with an AI assistant driving the checkout, the
build, and the first device onboarding, working from your answers instead of
a fixed script. This page documents the runbook that assistant follows: what
it asks before it changes anything, what it must never guess, and what it
reports back when the work is done. Read it if you maintain that runbook, or
if you want to know what an assistant did to your host.

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes
    boot variables. See [IRIS documentation](../zensical/index.md).

## Before you start

Prepare a local, git-ignored credential file if the assistant will connect to
the server or to devices:

```bash
cp creds/deploy.env.example creds/deploy.env
chmod 600 creds/deploy.env
```

Keep credentials in that file, or enter them directly in the Console. Do not
paste passwords, tokens, or private keys into a chat.

## The four decisions the assistant confirms

Before it touches a host, the assistant confirms four things. It reuses any
answer you already gave, asks only for what is missing, and asks in one
message rather than one question at a time:

1. **Where the deployment lives.** It offers
   `/opt/iris/intelligent-release-image-staging` as the default, then creates
   that directory and clones into it. See [Install IRIS](../zensical/install/index.md).
2. **Which layout:** Docker on one host, Docker on separate hosts, or
   Kubernetes. For separate hosts it also asks for the Console host; for
   Kubernetes it asks for the cluster context and a registry the nodes can
   reach.
3. **Which device types to onboard:** Guest Shell, IOx on amd64, IOx on
   arm64, IOS-XR appmgr, or none yet. This choice decides which device
   packages it needs to build.
4. **The server's device-reachable IPv4 address**, and the Console URL if it
   differs from that address on port 8080.

It repeats the answers back, checks the host, and states what is missing
before installing anything. It stays within the layout you chose, and it
reuses an existing deployment's compose project, volumes, age identity,
approved instruction roots, and administrator account rather than asking you
to settle them again.

## What it checks and reads first

Before cloning anything, the assistant runs the host checks in
[Check the host before you install](../zensical/install/check-the-host.md)
and reports, in one message, what is present and what is missing. It asks
before installing a package, adding a user to the docker group, or
registering an emulation handler, because those change your machine, and it
continues only once you approve.

It reads this repository's own contributor guide and the current deployment
guide for the layout you chose: [Install on one Docker host](../zensical/install/one-docker-host.md),
[Install on separate Docker hosts](../zensical/install/separate-docker-hosts.md),
or [Install on Kubernetes](../zensical/install/kubernetes.md). It keeps the
same layout, compose project, environment files, and container names in
every command, and it leaves your existing server state and device
assignments in place.

It keeps credentials out of chat, command output, logs, and source control,
and reads local credentials only when a step needs them. It never copies
server state, the age identity, or the management private key to the Console
host.

## Building the device packages

By default the assistant builds the Guest Shell bundle, the amd64 IOx
package, and the IOS-XR RPM, whatever the device types you chose in the
third decision. It adds the arm64 IOx package only when you explicitly ask
for an ARM device or package, following
[Build and publish the device packages](../zensical/install/device-packages.md#build-and-publish-the-arm64-iox-package).
It skips a package only when you explicitly exclude it, and a package you
excluded stays listed as not built. That is a correct end state, not a
failure, and the assistant reports it that way.

It fetches the verified `aria2c` release for each architecture in scope,
rather than using a binary from anywhere else. It also builds the IOx and
IOS-XR appmgr packages with the project's own helper scripts; see
[Helper commands](../zensical/reference/tools.md) for what each one does.
When a package's source changes after publishing, the rebuild rule is in
[Build and publish the device packages](../zensical/install/device-packages.md#embedded-agent-packages).

## The arm64 aria2c build

Building the arm64 `aria2c` client from source is the fallback for a host
that cannot reach the published release. It is slow: it runs under CPU
emulation, can take tens of minutes, and stays silent for long stretches.

Before starting it, the assistant asks once whether an arm64 machine is
reachable over SSH, since that removes the need for emulation. It states the
cost up front, so you do not read the silence as a hang.

It starts the build detached, so the build keeps running if the session that
launched it drops, and it reports the elapsed time and the log's last line
every few minutes. See
[Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md)
for the build command and its flags.

## Who holds the private signing keys

Two signing roots, the offline keys that sign every instruction key, must
exist before any device package can be built, and only you create them. The
assistant never generates them, and it refuses a private key if one is
offered. It waits for the two public halves in `$HOME/iris-roots`, and on
Kubernetes it copies only that public pair to the server's storage once the
pod is running. See
[Create the two offline signing keys](../zensical/install/signing-roots.md).

One person holding both private keys works for a proof of concept only. It is
not production custody and not signing evidence: say so explicitly when you
report on a deployment set up this way.

## Start signing instructions

Once the stack is up and before you onboard any device, the assistant sets
up the online signing key. This lets the server start signing instructions:
each instruction is the signed message the server sends a device saying
which images to stage and how.

It never hands you a command before the file it reads exists. It generates
the online key first, confirms `~/iris-online.pub` holds an `ssh-ed25519`
line, and only then gives you the command that signs it. Certifying that key
is yours to do, like creating the two signing roots. Without a signed
instruction key, every onboarding fails on every platform with the same
fixed, unhelpful message.

See [Turn on instruction signing](../zensical/install/activate-signing.md#initialise-instruction-custody)
for the exact commands. Read the same page's status guidance at
[Turn on instruction signing](../zensical/install/activate-signing.md#reading-the-status)
before you trust a quick two-field check.

## Assistant operating rules

The paragraphs above describe the runbook in prose. The block below carries
the same rules with the duplicate restatements removed, in a form you can
paste into an assistant's system prompt as-is:

```text
Operate IRIS as a stage-only system. Never install, activate, reload, change
boot variables, or replace the running software on a device.

Confirm these four decisions using any answers already given and any
verified settings. Ask only what is still unanswered, together in one
message, and wait when a question blocks safe progress. Do not guess a
layout, and do not start a Docker deployment only because it is the default:

1. Where should the deployment live? Offer
   /opt/iris/intelligent-release-image-staging as the default. Create the
   directory and clone into it yourself.
2. Which layout: Docker on one host, Docker on separate hosts, or
   Kubernetes? For separate hosts, also ask for the Console host. For
   Kubernetes, ask for the cluster context and a registry the nodes can pull
   from.
3. Which device types will be onboarded: Guest Shell, IOx on amd64, IOx on
   arm64, IOS-XR appmgr, or none yet? Ask before building packages: asking
   later wastes a build.
4. The server's device-reachable IPv4 address, and the Console URL if it is
   not that address on port 8080.

Repeat the answers back before acting on them, and work only within the
layout you were given.

Read this repository's own contributor guide and the current install guide
for the chosen layout. Keep the same layout, compose project, environment
files, and container names in every command. Preserve existing server state
and device assignments.

Keep credentials and secrets out of chat, command output, logs, and source
control. Read local credentials only when a step needs them. Never copy
server state, the age identity, or the management private key to the
Console host.

Check the host before anything else, and report what is present and what is
missing in one message, naming which host each result came from. Ask before
installing a package, adding a user to the docker group, or registering an
emulation handler, because those change the operator's machine. Install
what is approved, then continue.

A fresh checkout is missing inputs on purpose. Build what the device types
in scope need instead of reporting the deployment as blocked. Build the
Guest Shell bundle, the amd64 IOx package, and the XR RPM regardless of
which device types were chosen, and add the arm64 IOx package only when an
ARM device or package was explicitly requested. Skip a package only on an
explicit exclusion, and report a skipped package as a correct end state,
not a failure.

Fetch the verified aria2c release for each architecture in scope with the
project's own helper scripts; never substitute a binary from anywhere else.
Building the arm64 client from source is the slow fallback: it runs under
emulation, can take tens of minutes, and stays silent for long stretches.
Ask once whether an arm64 machine is reachable over SSH, since that removes
the need for emulation. Start the build detached so it survives a dropped
session, and report the elapsed time and the log's last line every few
minutes.

The two instruction trust roots are the operator's alone. Never generate
them, and refuse a private key if one is offered. Wait for the two public
halves before building any device package, and on Kubernetes copy only that
public pair to the server's storage once the pod is running.

Set up the online signing key once the stack is up and before onboarding
any device. Never hand over a command before the file it reads exists:
generate the online key, confirm the public key file holds an ssh-ed25519
line, and only then give the command that signs it. Certifying that key is
the operator's to do, like creating the two roots.

Report each step as it starts and as it finishes, with the evidence behind
it:

- the two signing roots found, and their fingerprints
- the public roots installed in the server's configuration volume
- the signing key set up
- each aria2c architecture built or fetched
- ioxclient fetched, with its version
- the Guest Shell bundle staged
- each IOx package and the IOS-XR RPM built
- what Device packages in Settings still reports as needing a build

On Docker on one host, report the environment file written, the images
built, the encrypted state store set up, and both containers healthy. On
Docker on separate hosts, report each host separately, and never treat a
loading Console page as proof the server is reachable: only an
authenticated Console request that reaches the server counts. On
Kubernetes, report the images built and pushed, the namespace and secrets
created, the bound storage claim, and the deployments that reached ready,
and treat pod readiness and an authenticated Console request as two
separate facts.

If a step is still running when there is nothing new to report, say so
instead of going quiet. If a step fails, report which one, show the error,
and say what else kept working.

Record the deployment layout, each host's role and address, the Console
URL, the management endpoint, and the checks actually performed, not the
ones assumed. For device work, record the image ID, the model and agent
choice, the staging target, the job result, and the final state of each
image, and list anything not verified. Keep credentials and tokens out of
the record.
```

## Reporting as it goes

Rather than describing the whole sequence up front and going quiet until it
ends, the assistant announces each step as it starts. It reports each one as
it finishes, with the evidence behind it:

- the two signing roots it found, and their fingerprints
- the public roots it installed in the server's configuration volume
- the signing key it set up
- each `aria2c` architecture it built or fetched
- the Guest Shell bundle it staged
- each IOx package and the IOS-XR RPM it built
- what [Build and publish the device packages](../zensical/install/device-packages.md)
  still reports as needing a build

On Docker on one host, it reports the environment file it wrote, the images
it built, the encrypted state store it set up, and both containers healthy.
On Docker on separate hosts, it reports each host separately and never
treats a loading Console page as proof the server is reachable: only an
authenticated Console request that reaches the server counts.

On Kubernetes, it reports the images it built and pushed, the namespace and
secrets it created, the bound storage claim, and the deployments that
reached ready. It also reports the roots it installed, and it treats pod
readiness and an authenticated Console request as two separate facts.

If a step is still running when there is nothing new to report, it says so
instead of going silent. If a step fails, it reports which one, shows the
error, and says what else kept working: a package build that fails after the
stack starts does not take the stack down with it.

## The completion record

When the work is done, the assistant records the deployment layout, each
host's role and address, the Console URL, the management endpoint, and the
compose projects or Kubernetes namespace involved. It records the checks it
actually performed, not the ones it assumed. For device work, it records the
image ID, the model and agent choice, the staging target, the job result,
and the final state of each image, and it lists anything it did not verify.
Credentials and tokens never go in the record.

Repeated tests of the same layout get their own fresh job IDs and reports
each time; an earlier successful check-in does not stand in for a new one. A
test image should be a distinct file, so cleanup removes only what the
assistant added. After a test, it clears the image's assignments, undeploys
with the job IDs it recorded, and removes only the files and catalog entries
it created. Undeploying a device does not remove images already staged for
real use.

The assistant keeps this record separate from dated evidence with real
numbers; that lives in [Dated lab evidence](validation-records.md), not on
this page or in a chat transcript.

## Related

- [Install IRIS](../zensical/install/index.md)
- [Troubleshoot: symptoms and first steps](../zensical/user-guide/troubleshooting.md)
- [Security model and trust boundaries](../zensical/architecture/security-model.md)
- [Repository map and contributor entry point](../../DEVELOPMENT.md)
