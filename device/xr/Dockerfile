# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS agent as an x86_64 appmgr Docker app for Cisco IOS-XR (Cisco 8000
# series, e.g. 8201). Delivered via docker-save -> ios-xr/xr-appmgr-build ->
# appmgr package install rpm, then activated with
# "--net=host -v /misc/disk1:/hostmount" (NEVER --name -- rejected by the
# appmgr opts validator). That bind mount IS harddisk: -- write-through is
# hardware-proven (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md), so there
# is no placement step: the agent downloads an image straight to its final
# harddisk: location and hashes the same bytes it seeds.
# Debian trixie (OpenSSL 3.5 LTS) -- kept in lockstep with server/Dockerfile
# and device/iox/Dockerfile; see the rationale there and issue #13.
FROM python:3.12-slim-trixie

LABEL org.opencontainers.image.title="IRIS XR staging agent" \
      org.opencontainers.image.description="Cisco IOS-XR appmgr image synchronization agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

# procps: pkill/pgrep for the aria2c supervisor in entrypoint.sh
# ca-certificates/curl: TLS roots + the RPC health probe
# (no openssh-client/sshpass here: XR needs no CLI transport -- the bind
# mount at /hostmount writes through to harddisk: directly, so there is no
# SSH-to-self and no scp-push the way the IOx image needs for its platforms)
RUN apt-get update && apt-get install -y --no-install-recommends \
      procps ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Architecture-matched statically-linked aria2c (x86_64 only -- Cisco 8000 is
# x86_64; same provenance and staging pattern as the IOx amd64 image, see
# device/iox/build.sh's ARIA2C_BIN / deliverables/aria2c-x86_64 handling).
COPY agent_bin/aria2c /opt/iris/bin/aria2c
# the agent control plane
COPY agent/*.py /opt/iris/agent/
# the aria2 --on-bt-download-complete program (peer-transfer capture). aria2c
# execs it directly -- execlp, no shell -- so it needs the exec bit below.
COPY agent/peer-transfer-hook.sh /opt/iris/agent/peer-transfer-hook.sh
COPY agent/VERSION /opt/iris/agent/VERSION
# pinned catalog server cert (public; used to VERIFY catalog TLS)
COPY iris-catalog.pem /opt/iris/iris-catalog.pem
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/iris/bin/aria2c /opt/iris/agent/peer-transfer-hook.sh

ENV PATH="/opt/iris/bin:${PATH}" \
    PYTHONPATH="/opt/iris/agent" \
    PYTHONUNBUFFERED=1 \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_MAX_PEERS="10" \
    IRIS_TELEMETRY="on" \
    IRIS_CATALOG_CA="/opt/iris/iris-catalog.pem"

WORKDIR /opt/iris
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
