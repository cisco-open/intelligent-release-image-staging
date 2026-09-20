<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates
SPDX-License-Identifier: Apache-2.0 -->

# Source publication tooling

## Download and verify the matching source

The [aria2c 2.5.6-p10 release](https://github.com/cisco-open/intelligent-release-image-staging/releases/tag/aria2c-2.5.6-p10)
provides both compiled clients and `aria2c-2.5.6-p10-source.tar.gz`. Download
that source asset into a new working directory, then verify it against the
tracked [source.sha256](source.sha256) before extraction. The adjacent release
checksum file carries the same digest. Inside the extracted directory, run
`sha256sum -c SHA256SUMS` and follow its `README.md` to rebuild.

The binary identities remain pinned in [`../aria2c.sha256`](../aria2c.sha256).
The source archive supplements those clients; normal installations do not need
to compile them. The combined client is distributed under GPLv3; original
source and dependency grants are preserved. See
[distribution terms](LICENSE-DISTRIBUTION.md).

## Assemble a source archive

`inputs.json` pins every external source input for aria2c 2.5.6-p10. Collect the
listed paths under an explicit input directory, preserving the original recipe,
patches and dependency archive bytes. Obtain the unmodified upstream tar with
`git archive d4971f0e12322e2ffcdb1721911b7d5c6206d0e5` from the upstream repository
listed in the manifest. No private workspace path is assumed.

```sh
python3 tools/aria2c-source/build-source-bundle.py \
  --inputs /path/to/collected-inputs \
  --upstream-archive /path/to/upstream.tar \
  --output /path/to/aria2c-2.5.6-p10-source.tar.gz
```

Packaging requires Python 3.11+ and git. It does not execute dependency recipes,
install packages, contact devices or publish assets. It rejects missing or
changed inputs, path traversal, symlinks, and existing output archives. It
reconstructs original patched source, adds separately dated notices, normalizes
archive timestamps/ownership/modes, and verifies extraction and every SHA-256.
The checksum sidecar is named `<archive>.sha256`.

Publish the source archive and sidecar alongside both exact binaries in the
existing IRIS `aria2c-2.5.6-p10` release. Publication is a separate owner-authorized
operation. The GPLv3 text is pinned by SHA-256 and preserved verbatim from GNU.
See BUNDLE-README.md for recipient rebuild instructions and scope limits.
