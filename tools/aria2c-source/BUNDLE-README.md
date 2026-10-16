<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates
SPDX-License-Identifier: Apache-2.0 -->

# IRIS aria2c 2.5.6-p12 corresponding source

This archive accompanies the exact local p12 clients named in inputs.json.
It is not evidence of a published release or GitHub authentication.
See LICENSE-DISTRIBUTION.md and COPYING3 for the GPLv3 distribution selection.
Original copyright, exception and dependency license texts are preserved.

## Contents and integrity

- upstream/aria2-next.tar: the unmodified pinned upstream tree.
- original-producer-recipe/: the unchanged p10 recipe and patches 0001-0010.
- patches/: patches 0011-0012, applied after that preserved series.
- notice-added-source/: reconstructed p12 source with dated modification notices.
- current-recipe/: the static compiler recipe, build driver, complete APK lock
  and checksum-locked offline rebuild helper.
- dependencies/: full source archives, exact Alpine recipes, patches, helpers,
  notices and provenance for musl, zlib, c-ares, OpenSSL and GCC runtimes.
- candidate-build-provenance/: preserved p11 candidate build records.
- p12-candidate-build-provenance/: per-architecture build inputs, source inventories,
  actual binary hashes, installed dependencies and static-link checks.
- tests/: the revocation parser probe and exact-client TLS, transfer, handshake,
  peer-cap and capped tracker-announcement regression drivers.
- inputs.json: all input identities and exact corresponding client hashes.

Run `sha256sum -c SHA256SUMS` after extraction. All dependency archive contents
and their original notices remain present. APK binaries, operational credentials,
Git metadata and compiled clients are not part of this source archive.

## Rebuild from retained dependencies

Use Python 3.11+, git, Docker Engine and Docker buildx. Retain the exact Alpine
base image and both architecture APK sets identified in current-recipe/apk-lock.json.
A native builder or already configured emulator must support the architecture.

```sh
python3 rebuild.py x86_64 --cache /path/to/retained-apks --offline --jobs 4 --output /absolute/new/amd64
python3 rebuild.py aarch64 --cache /path/to/retained-apks --offline --jobs 4 --output /absolute/new/arm64
```

The helper snapshots and verifies the complete extracted source, reconstructs
the ordered patches, checks APK sizes, hashes and Alpine signatures, then builds
with network-disabled steps. It requires the exact binary hash recorded in
inputs.json before adopting a new output directory. Existing output is preserved.

Omitting `--offline` permits downloading only the pinned APK bytes into the
retained cache. Omitting `--cache` uses the original rolling-index build path;
withdrawn pinned versions can make that path fail. No dependency is substituted.
The archive includes sources for the linked libraries and GCC runtimes, rather
than every independent build utility in the toolchain. ARM emulation is not a
device performance test. This source record makes no legal certification claim.
