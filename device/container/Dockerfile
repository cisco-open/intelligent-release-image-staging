# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# One IRIS device-agent image for IOx and IOS-XR appmgr. The runtime profile is
# selected by IRIS_DEVICE_PLATFORM in entrypoint.sh; both packaging wrappers
# consume the architecture-matched object from the same multi-platform index.
# The multi-architecture index digest is pinned so both CPU builds share one
# audited definition. Alpine is the measured smallest qualified Python runtime
# for this payload (see the package-footprint section of
# docs/dev/device-packages.md).
FROM python:3.12-alpine3.24@sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b AS python-base

# CPython 3.12.14 embeds Expat 2.8.3. Apply the merged upstream 3.12
# security backport (https://github.com/python/cpython/pull/156785) and
# rebuild BOTH XML extensions: ElementTree checks the exact Expat capsule ABI.
# Sources, compiler and upstream tests stay out of the runtime image.
FROM python-base AS xml-build
RUN apk add --no-cache gcc=15.2.0-r5 musl-dev=1.2.6-r2 patch=2.8-r0
ADD --checksum=sha256:5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a https://www.python.org/ftp/python/3.12.14/Python-3.12.14.tar.xz /src/python.tar.xz
ADD --checksum=sha256:ff8e455739170216c358d2fdbf2782a8257a4dc7230179a31ba62a54a4ded384 https://github.com/python/cpython/commit/278c3c2f0733e06613cf3e7a1d9c8c3c03248638.patch /src/expat.patch
COPY rebuild-xml.py /src/rebuild-xml.py
RUN tar -xJf /src/python.tar.xz -C /src \
    && patch --batch --fuzz=0 -p1 -d /src/Python-3.12.14 < /src/expat.patch \
    && python3 /src/rebuild-xml.py \
    && PYTHONPATH=/src/Python-3.12.14/Lib python3 -m test \
        test_pyexpat test_xml_etree test_xml_etree_c test_minidom test_sax test_pulldom

FROM python-base AS crypto-build
COPY iris-aead.c /src/iris-aead.c
COPY build-instruction-crypto-inner.sh /src/build.sh
COPY musl-COPYRIGHT /src/musl-COPYRIGHT
ADD --checksum=sha256:7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.8/LICENSE.txt /src/openssl-LICENSE
RUN sh /src/build.sh

FROM python-base AS runtime-files
COPY --from=crypto-build /out/iris-aead /opt/iris/bin/iris-aead
COPY --from=crypto-build /out/iris-aead.LICENCE /usr/local/share/licenses/iris-aead.LICENCE
COPY --from=xml-build /out/*.so /usr/local/lib/python3.12/lib-dynload/
COPY --from=xml-build /out/PYTHON-LICENSE /out/EXPAT-COPYING /usr/local/share/licenses/iris-python/

# openssh-client + sshpass are required by the IOx profile's SSH-to-self CLI
# and SCP placement. xr-appmgr rejects the corresponding environment/config
# surface before startup and never selects cli_ssh, but the signed image bytes
# remain identical for both wrappers.
# curl drives the loopback RPC health probe and completion hook. BusyBox in
# Alpine supplies ps, top, free and kill for field diagnosis; keep all four.
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh-client openssh-keygen sshpass ca-certificates curl openssl 'xz-libs>=5.8.4-r0' \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.12/ensurepip /usr/local/bin/pip*

# Both architecture binaries are checksum-verified into the canonical build
# context. BuildKit selects exactly one for each platform manifest in the OCI
# index; neither image carries the other architecture's binary.
ARG TARGETARCH
COPY agent_bin/aria2c-${TARGETARCH} /opt/iris/bin/aria2c
# One complete source set prevents per-platform COPY-list drift.
COPY agent/*.py /opt/iris/agent/
# the aria2 --on-bt-download-complete program (peer-transfer capture). aria2c
# execs it directly -- execlp, no shell -- so it needs the exec bit below.
COPY agent/peer-transfer-hook.sh /opt/iris/agent/peer-transfer-hook.sh
COPY agent/VERSION /opt/iris/agent/VERSION
COPY agent/iris-signers.allowed_signers /opt/iris/agent/iris-signers.allowed_signers
COPY agent/iris-root.allowed_signers /opt/iris/agent/iris-root.allowed_signers
COPY entrypoint.sh /entrypoint.sh
COPY reconcile.sh /reconcile.sh
RUN chmod +x /entrypoint.sh /opt/iris/bin/aria2c /opt/iris/agent/peer-transfer-hook.sh \
    && chmod 0444 /reconcile.sh /opt/iris/agent/iris-signers.allowed_signers \
        /opt/iris/agent/iris-root.allowed_signers

# CAF on IOS-XE can mount a multi-layer archive in an order different from
# manifest.json, restoring overwritten libraries and deleted installer files.
# Export the completed filesystem as one layer for BOTH IOx and XR; they still
# consume the same architecture manifest from the canonical OCI archive.
FROM scratch
COPY --from=runtime-files / /

LABEL org.opencontainers.image.title="IRIS device staging agent" \
      org.opencontainers.image.description="Cisco IOx and IOS-XR appmgr image staging agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

ENV PATH="/opt/iris/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LANG="C.UTF-8" \
    PYTHONPATH="/opt/iris/agent" \
    PYTHONUNBUFFERED=1 \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_TELEMETRY="on" \
    IRIS_LOG="off"

WORKDIR /opt/iris
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
