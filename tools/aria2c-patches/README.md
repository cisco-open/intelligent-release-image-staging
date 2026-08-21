# aria2c corresponding source

<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates

     SPDX-License-Identifier: Apache-2.0 -->

The `aria2c` binaries this project redistributes (server image, Guest Shell
agent bundle, IOx packages) are **Aria2 Next 2.5.6**, a fork of aria2,
licensed under the GNU General Public License v2 with the OpenSSL exception.

The complete corresponding source is:

- the upstream fork <https://github.com/AnInsomniacy/aria2-next> at commit
  `d4971f0e12322e2ffcdb1721911b7d5c6206d0e5`, plus
- the four patches in this directory, applied in numeric order.

The result is built as a static (musl) binary for `x86_64` and `aarch64`;
`tools/aria2c.sha256` pins the exact binaries. The patch files themselves are
modifications to GPLv2 code and are provided under GPLv2; they carry no inline
header because a header would alter the patch content (see the licensing
notes in `DEVELOPMENT.md`).
