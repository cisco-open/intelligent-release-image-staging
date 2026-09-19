<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Migration notes for contributors

This page is for a contributor rolling out a change to the instruction
envelope, the shared on-device agent, or role policy. It covers what a
device on the old code still does and how to move a deployment backward
without losing state. The operator-facing steps for a routine upgrade live
on [Upgrade to a new release](../zensical/admin-guide/upgrade.md); this page
covers what changes underneath that procedure.

## Upgrading the instruction envelope from v1 to v2

Moving from the v1 envelope to v2 is a coordinated server-and-agent change,
not one that rolls out on its own. Rebuild the server, both Guest Shell
bundles, both IOx packages, and the XR RPM before you roll it out to any
device. Building a Guest Shell bundle on its own first needs
`bash tools/build-instruction-crypto.sh`, run alongside the SSH verifier
build described in
[Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md).

Keep the server available so every agent gets its first v2 fetch. An agent
still running old code cannot read a v2 envelope. An agent already upgraded
rejects a v1 envelope and a v1 recovery cache. There is no automatic
fallback that decrypts the older format.

Instruction keys, the epoch-and-serial history, role signatures, and device
assignments all carry over unchanged. A fully authenticated v2 envelope may
replace the v1 bytes at the same epoch and serial exactly once. After that
one replacement, the agent's version floor is permanently 2, and it goes
back to rejecting a same-identity message whose bytes differ.

The agent applies a new envelope as one atomic step: it replaces its local
cache and saves the new digest, replay floor, and version together. If that
step is interrupted, the agent keeps or recovers the previous bytes and
floor. It never treats leftover v1 cache bytes as a usable v2 instruction;
it fetches fresh from the server instead.

Do not downgrade an already-upgraded agent back to v1, and do not delete its
replay state to make an old cached envelope work again. Restore or
reprovision it with the documented key-and-history recovery procedure
instead. AES-256-SIV's resistance to nonce misuse does not stop this kind of
rollback when an administrator restores both the old ciphertext and all of
the trusted replay state alongside it.

After the upgrade, verify a freshly applied, signed instruction report and a
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

One example is the catalog's `plans` map, keyed by the `plan_id` the server
assigns when it plans a transfer. A device running the matching agent
reports that `plan_id` back, so the server's `planned` and `seeding_started`
records line up as one plan. A device that has not yet received the bundle
ignores `plans` and keeps minting its own `transfer_id` instead, so its
events emit `planned` but never a matching `seeding_started`. There is
deliberately no fallback that promotes a plan from a report carrying some
other transfer's id.

## Rolling back the server to an older binary

Before you roll the server back to an older binary, review role-policy
containment and compatibility as a separate, reviewed step from the
rollback itself. Any restricted-role downgrade needs this same review. A
role is a named group of devices that share images with each other, and
quarantining a device tells it to stop sharing with every peer.

Older servers that predate independent quarantine ignore that membership,
so independent quarantine alone is not sufficient containment for a
downgrade, even after the current server has already applied it. Do not
work around this by folding the quarantine into the device's ordinary ACL
assignment instead.

If the older binary also predates roles and state-aware QoS, first use the
newer binary to remove every global and role state container.
Then make one additional, scalar-only policy commit.
Before you start the older binary, check that both `peer-policy.json` and
`peer-policy.lkg.json` hold state-free, schema-1 documents;
do not hand it a retained, state-bearing ring snapshot instead.
None of this preparation makes an older server enforce independent
quarantine on its own: code that predates roles ignores the
`roles_present` field entirely and cannot enforce or warn about role
definitions.

After you restore a version that supports roles and independent quarantine,
verify the quarantine intent you retained, repair any reported drift, check
the policy and origin-QoS status, and release each quarantine deliberately.
Do not delete `peer-policy.json` or its last-known-good copy to silence a
warning: doing so loses the role, ACL, and quarantine intent it holds.

## The default browser certificate after an image upgrade

The Console's default browser identity is stored encrypted as
`tls/console-fallback.pem.age` and normally reused across restarts. An older
build regenerated this identity every time its container started; upgrading
from that kind of build to a current one creates a new identity once, the
first time the new image starts. Verify and provision that new public
certificate through a trusted channel before you rely on it. If the address
you browse to has also changed, load a matching operator certificate in
Settings instead of trusting the default one; never disable TLS verification
to work around the change. See
[Find your way around the Console](../zensical/user-guide/console.md) for how
to import a certificate.

## Open questions

- The onboarding inventory keeps a device's machine-determined registration
  stamp across a re-import. The sources for this page do not describe a
  migration step tied to that stamp, so this page does not claim one exists.

## Related

- [How instructions are signed and trusted](../zensical/architecture/instruction-trust.md):
  the trust model and what the agent checks before it applies an instruction.
- [KDF, PAE layout, iris-aead adapter and the OpenSSL pin](instruction-crypto.md):
  how the v2 envelope is actually built.
- [Build and publish the device packages](../zensical/install/device-packages.md#embedded-agent-packages):
  when a change under `device/agent/` needs a package rebuild.
- [Upgrade to a new release](../zensical/admin-guide/upgrade.md): the operator
  procedure for a routine upgrade.
- [Roles: which devices share with which](../zensical/architecture/peer-policy.md):
  how role policy and device quarantine are stored and enforced.
