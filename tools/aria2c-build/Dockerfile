# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Reproducible static-musl build of aria2-next.
#
# Corresponding source for the redistributed aria2c binaries (GPLv2 section 3).
# Driven by build.sh beside it; see the README in this directory.
#
# Base image and every dependency are pinned exactly. No `latest` anywhere.
# A rebuild that cannot resolve a pinned package version FAILS rather than
# silently drifting to a newer one.
#
# syntax=docker/dockerfile:1

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS build

# Toolchain and dependency pins verified against alpine:3.24.1 on 2026-09-03,
# by resolving every `pkg=version` below against the v3.24 APKINDEX for both
# x86_64 and aarch64 (server/tests/test_aria2c_build_pins.py does exactly that,
# under IRIS_TEST_HOST_INTEGRATION=1).
# c-ares 1.34.8 is the latest upstream release and ships libcares.a in -dev
# (there is no c-ares-static package).
#
# A pin here has a shelf life. An Alpine release branch indexes only the newest
# -rN of each package, so a security bump WITHDRAWS the version we pinned and
# `apk add` then refuses the whole set:
#     ERROR: unable to select packages:
#       openssl-dev-3.5.8-r0: breaks: world[openssl-dev=3.5.7-r0]
# That hard failure is the design working -- it is why nothing floats. The
# response is to bump the withdrawn pin here on purpose (openssl-dev and
# openssl-libs-static always move together, they are the same source package),
# never to drop the `=version`. openssl 3.5.7-r0 was withdrawn from v3.24 in
# favour of 3.5.8-r0 and was bumped here on 2026-09-03; a binary rebuilt on the
# newer OpenSSL will not match tools/aria2c.sha256, which pins the artifact
# IRIS ships rather than the recipe (see README.md in this directory).
RUN apk add --no-cache \
      gcc=15.2.0-r5 \
      g++=15.2.0-r5 \
      musl-dev=1.2.6-r2 \
      cmake=4.2.3-r0 \
      samurai=1.2-r8 \
      pkgconf=2.5.1-r0 \
      linux-headers=7.0.0-r1 \
      zlib-dev=1.3.2-r0 \
      zlib-static=1.3.2-r0 \
      openssl-dev=3.5.8-r0 \
      openssl-libs-static=3.5.8-r0 \
      c-ares-dev=1.34.8-r0 \
      file=5.47-r2

# Record exactly what got installed, for VERSIONS.txt and for audit.
RUN { \
      echo "alpine: $(cat /etc/alpine-release)"; \
      echo "musl:   $(ls /lib/ld-musl-*.so.1)"; \
      apk list --installed 2>/dev/null | sort; \
    } > /dependency-manifest.txt

WORKDIR /src
COPY aria2-next/ /src/

# SOURCE_DATE_EPOCH is supplied by build.sh from the pinned commit date so the
# build is time-invariant.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Feature set:
#   ON  - BitTorrent, WebSocket (JSON-RPC), OpenSSL, c-ares, zlib
#   OFF - Metalink, expat (=> no XML-RPC, XML-free), sqlite3, libssh2
#   ED2K cannot be disabled: cmake/modules/FeatureChecks.cmake:269 hardcodes
#         set(ENABLE_ED2K 1). Documented, not worked around.
#
# -static gives a fully static executable. ARIA2_STATIC_DEPENDENCIES alone does
# NOT do this - it only passes --static to pkg-config
# (cmake/modules/Options.cmake:28-30).
# -no-pie is required because cmake/modules/Options.cmake:6 forces
# CMAKE_POSITION_INDEPENDENT_CODE ON, which conflicts with -static.
# pipefail is mandatory here: without it `tee` masks a cmake configure failure
# and the build marches on against stale or absent build files.
# CMAKE_FIND_LIBRARY_SUFFIXES must be forced to .a, but it cannot be set from
# the command line: CMake's platform module overwrites it during project(), so
# -DCMAKE_FIND_LIBRARY_SUFFIXES is silently discarded. CMAKE_PROJECT_INCLUDE is
# evaluated immediately after project() and before cmake/modules/FeatureChecks
# runs, which is the only supported hook early enough to matter.
RUN printf 'set(CMAKE_FIND_LIBRARY_SUFFIXES .a)\n' > /static-prefs.cmake

#
# Every dependency is located through pkg_check_modules(... IMPORTED_TARGET ...),
# whose find_library() calls prefer .so, so the link otherwise pulls
# /usr/lib/libz.so et al and fails with "attempted static link of dynamic
# object". Worse, OpenSSL is looked up via aria2_pkg_check_dynamic
# (cmake/modules/FeatureChecks.cmake:221), which deliberately clears
# PKG_CONFIG_ARGN (cmake/modules/Options.cmake:65-72) and therefore discards
# the --static that ARIA2_STATIC_DEPENDENCIES sets. Upstream actively resolves
# OpenSSL dynamically even in "static" mode.
RUN set -o pipefail; cmake -S /src -B /build -G Ninja \
      -DCMAKE_PROJECT_INCLUDE=/static-prefs.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DARIA2_STATIC_DEPENDENCIES=ON \
      -DARIA2_ENABLE_BITTORRENT=ON \
      -DARIA2_ENABLE_WEBSOCKET=ON \
      -DARIA2_ENABLE_METALINK=OFF \
      -DARIA2_WITH_OPENSSL=ON \
      -DARIA2_WITH_CARES=ON \
      -DARIA2_WITH_EXPAT=OFF \
      -DARIA2_WITH_SQLITE3=OFF \
      -DARIA2_WITH_LIBSSH2=OFF \
      -DARIA2_RELEASE_SIZE_OPTIMIZED=ON \
      -DARIA2_RELEASE_LTO=ON \
      -DCMAKE_EXE_LINKER_FLAGS="-static -no-pie" \
      -DCMAKE_SKIP_RPATH=ON \
      2>&1 | tee /configure.log

# ARIA2_RELEASE_LTO warns and continues if IPO is unsupported
# (cmake/modules/Targets.cmake:195-201). That is a silent downgrade, so assert
# it did not happen.
RUN if grep -q 'ARIA2_RELEASE_LTO requested but IPO is not supported' /configure.log; then \
      echo "FAIL: LTO was requested but silently skipped."; exit 1; \
    fi

RUN cmake --build /build --target aria2-next -j"$(nproc)"

RUN cp /build/aria2-next /aria2-next.unstripped && strip /build/aria2-next

# Static verification. Any dynamic fallback is a hard failure, never a silent
# substitute. Raw tool output is captured verbatim for the report.
RUN { \
      echo "=== file ==="; file /build/aria2-next; \
      echo; echo "=== ldd ==="; ldd /build/aria2-next 2>&1 || true; \
      echo; echo "=== size (stripped) ==="; stat -c '%s bytes' /build/aria2-next; \
      echo "=== size (unstripped) ==="; stat -c '%s bytes' /aria2-next.unstripped; \
      echo; echo "=== --version ==="; /build/aria2-next --version 2>&1 || true; \
    } > /verification.txt 2>&1; cat /verification.txt

# Hard gate: the binary must not be dynamically linked.
RUN if ldd /build/aria2-next 2>&1 | grep -qi 'not a dynamic executable\|Not a valid dynamic program'; then \
      echo "STATIC: confirmed"; \
    else \
      echo "FAIL: binary is dynamically linked - reporting, not substituting."; \
      ldd /build/aria2-next 2>&1; exit 1; \
    fi

FROM scratch AS artifact
COPY --from=build /build/aria2-next /aria2-next
COPY --from=build /verification.txt /verification.txt
COPY --from=build /configure.log /configure.log
COPY --from=build /dependency-manifest.txt /dependency-manifest.txt
