#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
set -eu
apk add --no-cache gcc=15.2.0-r5 musl-dev=1.2.6-r2 openssl-dev=3.5.8-r0 openssl-libs-static=3.5.8-r0
mkdir -p /out
cc -std=c99 -Os -Wall -Wextra -Werror -static /src/iris-aead.c -o /out/iris-aead -lcrypto -pthread
strip /out/iris-aead
if readelf -l /out/iris-aead | grep -q INTERP || readelf -d /out/iris-aead | grep -q NEEDED; then
    echo 'AEAD helper must be static' >&2
    exit 1
fi
cp /src/openssl-LICENSE /out/iris-aead.LICENCE
printf '\n\nStatically linked musl libc 1.2.6:\n\n' >> /out/iris-aead.LICENCE
cat /src/musl-COPYRIGHT >> /out/iris-aead.LICENCE
