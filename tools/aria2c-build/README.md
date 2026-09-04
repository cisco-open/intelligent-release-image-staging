# aria2c build scripts (GPLv2 corresponding source)

<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates

     SPDX-License-Identifier: Apache-2.0 -->

The `aria2c` that IRIS redistributes — in the server image, the Guest Shell
agent bundle, both IOx packages and the IOS-XR RPM — is a patched build of
**Aria2 Next 2.5.6**, which is licensed under the GNU General Public License
version 2. Section 3 of that licence requires that a recipient of the binary
can also get the source it was built from *and the scripts used to control its
compilation*.

The source and the patches are described in
[`../aria2c-patches/README.md`](../aria2c-patches/README.md). **The scripts are
these two files.** Together the four items are the complete corresponding
source:

| Item | Where |
| --- | --- |
| Upstream fork and exact commit | named in `../aria2c-patches/README.md` |
| The four patches | `../aria2c-patches/*.patch` |
| The build container definition | `Dockerfile` here |
| The build driver | `build.sh` here |

## IRIS does not run this

`tools/get-aria2c.sh` installs a binary that was **handed in** and verifies it
against `tools/aria2c.sha256`, failing closed on a mismatch. Nothing in a
normal IRIS build, release or device rollout executes anything in this
directory. It is published to discharge the licence obligation and to let you
reproduce or audit what we ship.

## The patch set is not duplicated here

`build.sh` reads the patches from `../aria2c-patches`, the one tracked copy.
An earlier version of this directory carried its own copy of the patch set and
was deleted precisely because two copies drift, and a build that silently
applies a stale patch set produces a binary that does not correspond to the
patches we publish. `PATCH_DIR` overrides the location, but only for trying a
candidate set — the default is the single home.

## Rebuilding

```bash
git clone https://github.com/AnInsomniacy/aria2-next vendor/aria2-next
git -C vendor/aria2-next checkout v2.5.6
./build.sh x86_64      # or: ./build.sh aarch64
```

`build.sh` refuses to proceed unless the checkout is at the pinned commit, and
refuses any patch that does not apply cleanly to it, so a build either
corresponds to the published patches or it fails.

### When a pin has been withdrawn

`Dockerfile` pins the base image by digest and every Alpine package by exact
version, so a rebuild either resolves the same inputs or fails. It can fail:
an Alpine release branch indexes only the newest `-rN` of each package, so a
security bump withdraws the version we pinned and `apk add` refuses the set:

```
ERROR: unable to select packages:
  openssl-dev-3.5.8-r0: breaks: world[openssl-dev=3.5.7-r0]
```

That is the pinning working, not a bug to route around. Bump the withdrawn pin
to the version the branch now carries — deliberately, in the file, keeping the
`=version` — and note that the rebuilt binary then links the newer library and
will not reproduce the shipped bytes. Never replace a pin with a floating
package name to make the error go away.

**Your binary will not match `tools/aria2c.sha256`,** and that is expected: a
different toolchain, musl version or flag set produces different bytes. The
checksum pins the exact artifact IRIS ships, not the recipe. If you adopt a
binary you built yourself, update that file deliberately — never edit it to
silence a mismatch, because the mismatch is the mechanism working.
