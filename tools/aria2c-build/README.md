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
| The seven patches | `../aria2c-patches/*.patch` |
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

## Peer-cap regression checks

Patch `0005-hard-bt-max-peers.patch` makes `bt-max-peers` an admission limit
for seeders and leechers, regardless of download speed. Pending outbound
connections reserve slots before dialing. Zero retains upstream's unlimited
meaning. The limit is per torrent; inbound sockets cannot be attributed to a
torrent until their handshake identifies it. Lowering a running torrent's
limit stops new admissions but does not evict existing peers.

The existing inactivity policy is unchanged: established peers disconnect
at 30 seconds when neither side is interested, or at 60 seconds without
receiving a piece message or block request. Keepalives do not reset this
activity timer. These two thresholds are hardcoded in
`DefaultBtInteractive::checkActiveInteraction`; the peer cap is tunable.
Receiving block requests counts as activity even if that peer sends us no
payload. For ordinary torrents, the outbound sweep runs every 10 seconds;
available peers and speed/minimum-peer heuristics determine replacement.

Run the isolated loopback tests against the exact deliverable:

```bash
python3 test-peer-cap.py out/x86_64/aria2c
python3 test-peer-cap.py out/x86_64/aria2c --mixed
python3 test-peer-cap.py out/x86_64/aria2c --runtime
python3 test-transfer.py out/x86_64/aria2c
```

The cap test offers 18 peers to stalled downloads, checking inbound and
outbound limits of 10 and 1, unlimited mode, and seeder admission. `--mixed`
exercises concurrent inbound and outbound attempts. `--runtime` verifies live
RPC changes from 1 to 5 to 2, including retention of existing peers on a decrease. `--baseline` instead
expects an unpatched binary to exceed 10 on both paths. Add `--parallel` to
run up to four isolated cases concurrently. Peers deliberately
send only the handshake, then remain idle without providing data. The
transfer check stages a generated 3.125 MiB payload between two real clients
with a cap of one and verifies its SHA-256. All processes and data are local
and temporary; no running Iris services are involved.

Use the same commands with `out/aarch64/aria2c` on ARM64, or with a registered
QEMU binfmt handler. Emulated checks verify behavior, not native performance.

## Coalesced BitTorrent handshake regression

Patch `0006-preserve-coalesced-bt-handshake.patch` accepts a handshake and
subsequent messages delivered in the same TCP read. It consumes exactly the
68-byte handshake, retains trailing bytes for message parsing, and handles
an already buffered complete handshake immediately. Fragmented handshakes
and the existing peer admission cap retain their behavior.

The builder includes pinned GNU make alongside Ninja. GCC's existing
`-flto=auto` requires make to run LTO workers concurrently; without it, GCC
falls back to serial optimization. This adds a build tool and preserves the
existing runtime dependency versions, optimization flags and static linking.

Run the handshake regression against the exact binary:

```bash
python3 test-handshake.py out/x86_64/aria2c --log-dir out/issue-174-validation/handshake-x86_64
```

The six handshake layouts cover handshake-only control, a coalesced bitfield,
multiple coalesced messages, a partial trailing message, and two fragmented
handshake paths. Tests require completed handshakes and the expected RPC
bitfield/interest/choke state, then verify unknown-infohash rejection and ten
admitted coalesced peers with the eleventh rejected. `--baseline` expects the
old stall/rejection and requires the five-patch binary (patches 0001–0005,
without 0006), because its admission check still requires patch 0005. The
four-patch binary is suitable for the peer-cap baseline, not this baseline.
Results, console output and protocol traces are retained in the log directory.
Use the aarch64 binary for ARM64 tests; a registered QEMU binfmt handler or
`--runner qemu-aarch64-static` also works for emulated validation.

## Seeder good-bye grace

Patch `0007-seeder-goodbye-grace.patch` keeps a seeder↔seeder connection for
5 s after both sides are complete before the `Good Bye Seeder` drop, instead
of dropping it in the same event-loop iteration. The device's
`--on-bt-download-complete` hook (`device/agent/peer-transfer-hook.sh`) reads
per-peer session counters over RPC after the last piece lands, and upstream
had erased every seeder that fed the download before that RPC could be
served, so a device fed only by the origin reported zero attributed bytes
(issue #68). The grace is enforced in
`DefaultBtInteractive::checkActiveInteraction`, and the HAVE, HAVE_ALL and
BITFIELD handlers defer to it instead of throwing on the message that
completes the peer's copy: the finishing side advertises its last piece to
every peer at once, and without that deferral the far end closed the
connection under the grace. The 30 s mutual-disinterest and 60 s inactivity
drops are unchanged; the peer-cap and handshake checks above are unaffected
because their fixtures never announce a complete copy.

There is no dedicated script for this patch. It was validated on loopback
with two RPC-enabled instances of the exact deliverable (one seeding a
generated 3 MiB payload, the other downloading it rate-limited with the real
`peer-transfer-hook.sh` as its completion hook) while polling `getPeers` on
both every 5 ms. Adoption criteria, all checked against the shipped
checksum: the seeder stays listed on the downloader for about 5 s after
completion with its `downloaded` counter at the payload size, the downloader
stays listed on the seeder for the same window, the hook's `.peers.json`
sidecar carries that peer rather than `[]`, and the six-patch binary fails
the same check (peer list already empty at the first sample after
completion, sidecar `[]`).
