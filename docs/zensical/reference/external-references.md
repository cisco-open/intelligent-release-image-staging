<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Cisco references and third-party components

Cisco documentation and third-party tools that the guides link to.

## Cisco documentation

| Document | Used by |
| --- | --- |
| [IOx package descriptor](https://developer.cisco.com/docs/iox/package-descriptor/) | [Prepare devices for the IOx app](../install/iox.md) — Catalyst 9000 series switches (Guest Shell, or the IOx app on switches with app-hosting storage), Catalyst 8000 series routers, and Industrial Ethernet 3000 series switches |
| [IOS XE app-hosting](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/m_1717_prog_application_hosting.html) | [Prepare devices for the IOx app](../install/iox.md) |

## Third-party tools

| Component | License | Used by |
| --- | --- | --- |
| aria2c | GPLv2 | [How an image reaches a device](../architecture/data-path.md) |
| mktorrent | GPLv2 | [Helper commands](tools.md) |
| openssl | Apache-2.0 | [Security model and trust boundaries](../architecture/security-model.md) |
| Mermaid | MIT | Diagrams on this documentation site |
| Swagger UI | Apache-2.0 | [Console API](console-api.md) |

The repository [NOTICE](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/NOTICE) has the license text and copyright notice for every tool IRIS uses.

aria2c's source and build scripts are at [tools/aria2c-build/README.md](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/tools/aria2c-build/README.md) and [tools/aria2c-patches/README.md](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/tools/aria2c-patches/README.md).

Swagger UI's vendored files and pinned release are in the [Swagger UI provenance record](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/zensical/swagger/SOURCE.txt).
