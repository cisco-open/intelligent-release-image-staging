# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS build
COPY tools/iris-aead.c /src/iris-aead.c
COPY tools/build-instruction-crypto-inner.sh /src/build.sh
COPY tools/licenses/musl-COPYRIGHT /src/musl-COPYRIGHT
ADD --checksum=sha256:7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.8/LICENSE.txt /src/openssl-LICENSE
RUN sh /src/build.sh
FROM scratch AS artifact
COPY --from=build /out/iris-aead /iris-aead
COPY --from=build /out/iris-aead.LICENCE /iris-aead.LICENCE
