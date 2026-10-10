<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates
SPDX-License-Identifier: Apache-2.0 -->

# IRIS downstream modifications

Upstream: Aria2 Next 2.5.6, commit
`d4971f0e12322e2ffcdb1721911b7d5c6206d0e5`.

The original p10 source inputs and patches 0001-0010 are preserved byte for byte.
They provide peer telemetry, disconnect and handshake fixes, peer admission limits,
a seeder grace period and authenticated hybrid peer TLS.

On 2026-10-10, IRIS added patch 0011 for certificate-identity withdrawal.
Required peer TLS now requires fresh local authorization data. It rejects
withdrawn identities and closes their existing connections, while retaining
other permitted identities that share an address. Missing, invalid or expired
authorization data stops private peer connections. A read-only RPC reports the
loaded generation and its validity. This is not CRL or OCSP processing.

The notice-added-source tree contains dated comment-only notices on all modified
source, build and test files. source-verification.json lists those files exactly.
The actual compiler input is reconstructed from the original upstream and ordered
patches, without the added notice comments. All original copyright, license and
exception texts remain intact.
