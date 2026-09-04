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
# Official python image on Alpine (musl, BusyBox, OpenSSL 3.5.x from Alpine's
# libssl3/libcrypto3), pinned by INDEX DIGEST so a rebuild is reproducible:
# the tag is informational, the digest is what docker actually pulls -- bump
# both together, and review the digest monthly (docker-library republishes
# on every CPython 3.12.x patch and Alpine point release). This deliberately
# diverges from the Debian trixie lineage server/Dockerfile and
# device/iox/Dockerfile keep in lockstep (issue #13): the XR image has no
# openssl CLI consumer (no trust.py, no CA-bundle processing -- catalog TLS is
# the pinned PEM below, verified by CPython's ssl module), and the appmgr RPM
# is the size-critical delivery: measured 2026-09-02, this base halves it
# (51.6 MB -> 26.4 MB delivered, 145 MB -> 71 MB unpacked) with every
# functional gate identical to the Debian image.
FROM python:3.12-alpine3.24@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a

LABEL org.opencontainers.image.title="IRIS XR staging agent" \
      org.opencontainers.image.description="Cisco IOS-XR appmgr image synchronization agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

# curl: the RPC health probe in entrypoint.sh and the peer-transfer hook's
#       one-shot aria2.getPeers capture (both loopback-only, http://127.0.0.1)
# ca-certificates: TLS roots (already in the base; named so the intent stays
#       explicit and in parity with device/iox/Dockerfile's apt line)
# (no procps: entrypoint.sh supervises aria2c by the exact PID of its own
# tracked child and never needs pgrep/pkill)
# (no openssh-client/sshpass here: XR needs no CLI transport -- the bind
# mount at /hostmount writes through to harddisk: directly, so there is no
# SSH-to-self and no scp-push the way the IOx image needs for its platforms)
RUN apk add --no-cache curl ca-certificates

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
    IRIS_LOG="off" \
    IRIS_CATALOG_CA="/opt/iris/iris-catalog.pem"

WORKDIR /opt/iris
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
