# aria2c corresponding source

<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates

     SPDX-License-Identifier: Apache-2.0 -->

The `aria2c` binaries this project redistributes (server image, Guest Shell
agent bundle, IOx packages, IOS-XR appmgr RPM) are **Aria2 Next 2.5.6**, a fork
of aria2, licensed under the GNU General Public License v2 with the OpenSSL
exception.

IRIS neither downloads nor builds `aria2c`. It is handed in as an artifact and
verified against `tools/aria2c.sha256`; see `tools/get-aria2c.sh`.

## The corresponding source (GPLv2 §3)

1. **Upstream fork** — <https://github.com/AnInsomniacy/aria2-next> at commit
   `d4971f0e12322e2ffcdb1721911b7d5c6206d0e5`.
2. **The four patches in this directory**, applied in numeric order.
3. **The build scripts** — see *Build* below.

## Applying the patches

The patches are unmodified `git diff` output. They carry `index` lines but no
`From:`/`Subject:` headers, so `git am` does not apply them; use `git apply`:

```bash
git clone https://github.com/AnInsomniacy/aria2-next aria2-next
cd aria2-next
git checkout d4971f0e12322e2ffcdb1721911b7d5c6206d0e5
for p in ../iris/tools/aria2c-patches/0*.patch; do
  git apply --3way "$p"      # --3way needs the index lines; plain `git apply` also works
done
```

Which patches matter to IRIS:

| Patch | What it does | Load-bearing for IRIS? |
| --- | --- | --- |
| `0001-getpeers-keys-filter.patch` | Adds a `keys` filter to the `getPeers` RPC method | **Yes** — `server/telemetry.py` and `device/agent/peer-transfer-hook.sh` both pass that keys array; per-peer byte attribution depends on it |
| `0002-fix-uaf-peer-blocklist-disconnect.patch` | Fixes a use-after-free when a blocked BitTorrent peer is disconnected | **Yes** — reachable in normal swarm operation with peer policy enforced |
| `0003-fix-pkcs12-chain-type-confusion.patch` | Fixes a PKCS#12 chain type confusion in the OpenSSL TLS context | No — IRIS configures no `.p12` credential; upstream hardening, carried at no cost |
| `0004-fix-ed2k-iterator-invalidation.patch` | Fixes iterator invalidation in the ed2k attribute handling | No — IRIS drives aria2c for BitTorrent and HTTP only |

## Build

The binaries are produced by a separate project, **`aria2-next-static`**, which
owns the source pin, the patch set, the toolchain and the build flags; this
repository is purely the consumer, so that the patch set has exactly one home
and cannot drift between two copies. `tools/get-aria2c.sh` looks for its output
at `../aria2-next-static/out/<arch>/aria2c` by default.

What is fixed about the deliverable:

- fully **static** binaries linked against **musl** libc (no runtime loader, so
  one binary runs on Guest Shell, an IOx container and an IOS-XR appmgr
  container alike);
- two architectures, `x86_64` and `aarch64`;
- the exact bytes are pinned in `tools/aria2c.sha256`, one line per
  architecture.

**A binary you build yourself will not reproduce those checksums** — a
different toolchain, musl version, or flag set produces different bytes — and
`tools/get-aria2c.sh` fails closed on a mismatch with no override. If you build
from source you are adopting your own binary, which means updating
`tools/aria2c.sha256` to its sha256 deliberately, not working around the check.

### The build configuration

Recorded here so the corresponding source is *reconstructable*, not only
promised. The binaries are configured with CMake and Ninja inside a pinned
Alpine builder, and every dependency is linked statically:

- **Builder image**: `alpine:3.24.1`, pinned by digest
  `sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b`.
- **Build type**: `Release`, size-optimized, with link-time optimization
  required rather than best-effort — the build asserts that LTO was not
  silently skipped.
- **Linked statically**, no position-independent executable, RPATH skipped.
- **Enabled**: BitTorrent, WebSocket, OpenSSL, c-ares.
- **Disabled**: Metalink, Expat, SQLite3, libssh2.

`ARIA2_STATIC_DEPENDENCIES` alone is not sufficient: upstream resolves OpenSSL
through a code path that discards the static flag, so the builder also forces
CMake to prefer `.a` archives before the feature checks run. A build without
that step links dynamically against the host's OpenSSL and is not the
deliverable described here.

Requesting the build scripts: the `aria2-next-static` build scripts are part of
the corresponding source for these binaries. Ask any maintainer listed in
[`MAINTAINERS.md`](../../MAINTAINERS.md), or write to
<oss-security@cisco.com>, and they will be provided.

## Licensing of the patches themselves

The patch files are modifications to GPLv2 code and are provided under GPLv2.
They carry no inline SPDX header because a header would alter the patch content
and stop it applying; see the licensing notes in
[`DEVELOPMENT.md`](../../DEVELOPMENT.md).
