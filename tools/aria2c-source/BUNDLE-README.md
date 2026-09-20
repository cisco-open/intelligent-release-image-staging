<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates
SPDX-License-Identifier: Apache-2.0 -->

# IRIS aria2c 2.5.6-p10 corresponding source

This archive accompanies the exact p10 clients in the existing IRIS release.
See LICENSE-DISTRIBUTION.md and COPYING3 for the GPLv3 distribution selection.
No upstream or dependency notices are replaced. This is not legal certification.

## Contents and integrity

- upstream/aria2-next.tar: full unmodified git archive of the pinned upstream.
- original-producer-recipe/: unchanged original Dockerfile, build.sh and patches.
- notice-added-source/: original source plus dated notices in 38 modified files.
- current-recipe/: bounded-worker IRIS Dockerfile/build.sh.
- dependencies/: full upstream source archives, exact Alpine recipes, patches,
  helpers, licenses and provenance manifests for musl, zlib, c-ares, OpenSSL,
  and GCC runtime sources.
- inputs.json: source identities, original recipe/patch hashes, dependency URLs,
  versions and SHA-256/SHA-512 values, and exact distributed binary hashes.

Run `sha256sum -c SHA256SUMS` after extracting. No compiled clients, APK packages,
git metadata, credentials, or operational logs are included. Dependency manifests
may reference inspected APK metadata; those APK binaries are not bundled.
The archive retains every nested dependency notice in the complete source tarballs.

## Rebuild without a source git checkout

Install Python 3.11 or newer, git, and Docker Engine with the Docker buildx plugin on
the build host. Docker requires access to the pinned Alpine image and exact APK
versions specified in current-recipe/Dockerfile. A native builder for the selected
architecture, or an already-configured emulator, is required. The script does not
install privileged emulation helpers. No git checkout is needed for this path.

```sh
python3 rebuild.py x86_64 --output /absolute/new/output-directory --jobs 2
python3 rebuild.py aarch64 --output /absolute/new/arm-output-directory --jobs 2
```

Existing output directories are rejected. The driver verifies all inputs,
reconstructs the original patched source in a private temporary directory,
checks the resulting binary against the distributed hash, and refuses to adopt a
mismatch. It uses git to apply patches, without requiring a source git checkout.
`--verify-only` checks the archive without running Docker. The scripts
control compilation; Docker installs the exact build packages into its isolated
build image, not onto the host. original-producer-recipe/build.sh is preserved
historical input and expects a vendor git checkout; use rebuild.py instead.

Fresh x86_64 and aarch64 builds using this archive rebuild path matched the
distributed bytes exactly. The x86_64 build used two compiler/LTO workers;
the aarch64 build used eight workers under existing QEMU emulation. Both passed
the static-link and version checks. This is build/source correspondence evidence,
not an ARM hardware performance claim. The original clients were compiled before
the comment-only modification notices were added.

The archive is not an offline package mirror or complete build environment.
Exact Alpine package withdrawals cause the build to fail rather than silently
substitute dependencies. Source is included for the five linked-library origins,
not every separate compiler/build utility present in the image.
