<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Release compatibility checks

Use these checks when changing instruction formats, the shared device agent,
role policy or deployment identity. Compatibility tests protect stored security
state; they do not define an in-place upgrade or rollback procedure.
Release replacement uses device undeploy, deployment removal, a fresh install
and device re-onboarding. See
[Deploy a new release](../zensical/admin-guide/upgrade.md).

## Instruction format and replay protection

An instruction-format change requires matching server and agent code.
Rebuild the server, both Guest Shell bundles, both IOx packages and the XR RPM
before testing the release on devices. Building a Guest Shell bundle needs
`bash tools/build-instruction-crypto.sh`, run alongside the SSH verifier
build described in
[Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md).

The current agent rejects a v1 envelope and a v1 recovery cache. It does not
fall back to decrypting that format. Keep format compatibility tests separate
from the supported deployment-replacement workflow.

Tests that exercise retained v1 replay state must preserve its instruction
keys and epoch-and-serial history. A fully authenticated v2 envelope may
replace the v1 bytes at the same epoch and serial exactly once. After that
one replacement, the agent's version floor is permanently 2, and it goes
back to rejecting a same-identity message whose bytes differ.

The agent applies a new envelope as one atomic step: it replaces its local
cache and saves the new digest, replay floor, and version together. If that
step is interrupted, the agent keeps or recovers the previous bytes and
floor. It never treats leftover v1 cache bytes as a usable v2 instruction;
it fetches fresh from the server instead.

Do not delete replay state or run older code to make a rejected cached envelope
work. Use the documented recovery procedure for the original deployment, or
undeploy and onboard to a fresh installation. AES-256-SIV's resistance to
nonce misuse does not stop this kind of
rollback when an administrator restores both the old ciphertext and all of
the trusted replay state alongside it.

For each release, verify a freshly applied, signed instruction report and a
v2 recovery from the device's last-known-good copy, on every platform you
support. A helper that is missing, mismatched, or fails its check rejects
the instruction outright; it never falls back to the old cipher or treats an
unverified policy as trustworthy. See
[KDF, PAE layout, iris-aead adapter and the OpenSSL pin](instruction-crypto.md)
for how the v2 format is actually built.

## Rolling out a change to the shared agent

IRIS ships one shared on-device agent across Guest Shell, IOx, and IOS-XR
appmgr, so a change to what the agent reports rolls out with the agent that
reads it, not ahead of it. Any change under `device/agent/` needs a fresh
Guest Shell bundle, both IOx tars, and `iris-xr.rpm` before you roll it out;
see
[Build and publish the device packages](../zensical/install/device-packages.md#embedded-agent-packages)
for when to rebuild each one.

The catalog's `plans` map is keyed by image ID. Each entry carries a
server-selected `plan_id` and `transfer_id`. The matching agent stores the
`plan_id` locally and reports the `transfer_id`; the server joins that report
to its plan so `planned` and `seeding_started` describe the same transfer.
Test that join with freshly onboarded agents. A report carrying a different
transfer ID must not advance the plan.

## Role-policy compatibility

Older servers that predate independent quarantine ignore that membership,
so independent quarantine alone is not sufficient containment with such code.
Compatibility tests must preserve this refusal boundary. Do not convert a
restricted-role policy into ordinary ACL assignments or remove state-aware
QoS fields to make a deployment run on older code.

Keep `peer-policy.json` and `peer-policy.lkg.json` intact when investigating
policy drift. Deleting either file to silence a warning can lose recorded
role, ACL and quarantine intent. Test recovery against the original deployment;
for a release replacement, re-create the intended policy in the fresh install
before onboarding devices.

## Browser identity on a fresh installation

The Console's default browser identity is stored encrypted as
`tls/console-fallback.pem.age` and reused across restarts of that deployment.
A fresh installation creates a new identity. Verify its public certificate
through a trusted channel before using it. Load a matching operator certificate
in Settings when needed; never disable TLS verification to work around a
certificate or address mismatch. See
[Find your way around the Console](../zensical/user-guide/console.md) for how
to import a certificate.

## Related

- [How instructions are signed and trusted](../zensical/architecture/security-model.md#how-instructions-are-signed-and-trusted):
  the trust model and what the agent checks before it applies an instruction.
- [KDF, PAE layout, iris-aead adapter and the OpenSSL pin](instruction-crypto.md):
  how the v2 envelope is actually built.
- [Build and publish the device packages](../zensical/install/device-packages.md#embedded-agent-packages):
  when a change under `device/agent/` needs a package rebuild.
- [Deploy a new release](../zensical/admin-guide/upgrade.md): undeploy, remove,
  install the replacement and onboard its agents.
- [Roles and peer sharing](../zensical/architecture/security-model.md#roles-and-peer-sharing):
  how role policy and device quarantine are stored and enforced.
