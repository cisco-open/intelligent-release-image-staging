<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Release and verifier checklist

This page is for a release engineer or contributor confirming a build is
ready to ship. It also covers testing a device's verifier. A verifier checks
the signature on an instruction, the signed message the server sends a
device saying which images to stage and how. Use the first checklist before
you cut a release, and the second before you trust a platform's signature
check.

## Before you cut a release

Treat these as four separate kinds of evidence. None of them substitutes for
another:

- Configuration checks.
- Unit and static test results.
- Package inspection and build evidence.
- Actual observations from a device.

A build made from a disposable, unsigned root proves only that the package
builds and that its bytes reach a device. It proves nothing about the real
key ceremony, a native signature check, an actual release, a real
deployment, or the device's running software.

Any change under the shared agent code needs a fresh build of every package
before it ships. Build the Guest Shell bundle, both IOx tars, and the IOS-XR
rpm from the same source and the same pinned aria2c binary. For the full
build and publish steps, including the ARM64 IOx package, see
[Build and publish the device packages](../zensical/install/device-packages.md#build-and-publish-the-arm64-iox-package).

Compare the agent source bytes and the two public instruction root files
across every built package, and record the wrapper and OCI provenance. Then
run `tools/check-package-freshness.sh`. Its certificate-drift check does not
replace this rebuild step: it checks the served wrapper bytes against the
provenance manifest next to them, not whether the source has changed.

## Confirm each platform's verifier

Test the actual verifier on each device platform, not only the tracker-side
signature check on the server. Both packaged verifier builds, amd64 and
arm64, must accept both provisioned instruction roots and reject a wrong
root or the wrong namespace.

- On Guest Shell, check whether the signature-verification tool is installed
  at runtime (`ssh-keygen -Y verify`). It is not always present; see
  [Limitations](../zensical/architecture/limitations.md) for what that means
  for coverage.
- Also on Guest Shell, deliver a new instruction envelope, the encrypted file
  that carries an instruction, by hand and confirm the agent's bundle and
  sidecar drop is transactional: it keeps the previous working bundle if the
  new one is refused. Check instruction state again after the next
  check-in. See [Replace or recover signing keys](../zensical/admin-guide/instruction-keys.md#f3-offline-bootstrap-envelope-redelivery).
- Confirm the device's last known good policy, the last policy it accepted,
  survives two rotations of the instruction key, key expiry, and the
  difference between an allow list and a deny list. Confirm a refresh
  happens once and does not retry inside the same check-in loop.
- On IOx, validate its own verification step end to end: state read-back and
  recovery, and the actual media and signature restrictions, before you
  treat it as working on a live device.
- On IOS-XR appmgr devices, apply the same check: confirm the packaged
  verifier accepts both provisioned roots and rejects the wrong one.

## Kubernetes release scope

This release covers the single-replica Kubernetes layout, the same as
single-host and split-host Compose. Before you sign off a Kubernetes
release, confirm the deployment still matches
[Storage, state and deployment records](../zensical/architecture/storage-and-state.md).
A multi-replica server is out of scope; see
[Limitations](../zensical/architecture/limitations.md).

## Related

- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md):
  the build details behind the rebuild rule above.
- [Storage, state and deployment records](../zensical/architecture/storage-and-state.md):
  what the Kubernetes PVC holds and why the server runs as one replica.
- [Limitations](../zensical/architecture/limitations.md): what multi-replica
  Kubernetes and an absent verifier tool do not cover.
- [Manual checks and the test-file map](../../TESTING.md): the automated
  test-file map and the checks a person still has to run by hand.
