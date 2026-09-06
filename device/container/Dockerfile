# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# One IRIS device-agent image for IOx and IOS-XR appmgr. The runtime profile is
# selected by IRIS_DEVICE_PLATFORM in entrypoint.sh; both packaging wrappers
# consume the architecture-matched object from the same multi-platform index.
# The multi-architecture index digest is pinned so both CPU builds share one
# audited definition. Alpine is the measured smallest qualified Python runtime
# for this payload (see the package-footprint section of
# docs/zensical/containers.md).
FROM python:3.12-alpine3.24@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a

LABEL org.opencontainers.image.title="IRIS device staging agent" \
      org.opencontainers.image.description="Cisco IOx and IOS-XR appmgr image staging agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

# openssh-client + sshpass are required by the IOx profile's SSH-to-self CLI
# and SCP placement. xr-appmgr rejects the corresponding environment/config
# surface before startup and never selects cli_ssh, but the signed image bytes
# remain identical for both wrappers.
# curl drives the loopback RPC health probe and completion hook. BusyBox in
# Alpine supplies ps, top, free and kill for field diagnosis; keep all four.
RUN apk add --no-cache openssh-client sshpass ca-certificates curl

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
COPY entrypoint.sh /entrypoint.sh
COPY reconcile.sh /reconcile.sh
RUN chmod +x /entrypoint.sh /opt/iris/bin/aria2c /opt/iris/agent/peer-transfer-hook.sh \
    && chmod 0444 /reconcile.sh

ENV PATH="/opt/iris/bin:${PATH}" \
    PYTHONPATH="/opt/iris/agent" \
    PYTHONUNBUFFERED=1 \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_MAX_PEERS="10" \
    IRIS_MAX_CONCURRENT="100" \
    IRIS_TELEMETRY="on" \
    IRIS_LOG="off"

WORKDIR /opt/iris
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
