# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS agent as an arm64 or amd64 IOx Docker app for Cisco app hosting.
# The selected build platform must match the aria2c staged by build.sh. The agent
# reaches IOS via an
# SSH-to-self transport (cli_ssh) instead of the Guest Shell `cli` bridge.
# Debian trixie (OpenSSL 3.5 LTS) — kept in lockstep with server/Dockerfile;
# see the rationale there and issue #13.
FROM python:3.12-slim-trixie

LABEL org.opencontainers.image.title="IRIS IOx staging agent" \
      org.opencontainers.image.description="Cisco app-hosting image synchronization agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

# openssh-client + sshpass: the SSH-to-self CLI transport (cli_ssh._default_runner)
# ca-certificates/curl: TLS roots + diagnostics
# procps: ps, top, free, uptime and /bin/kill. The supervisor does NOT need
# them -- it owns aria2c by the exact PID of its own tracked child and never
# shells out to pgrep/pkill. They are here for the operator: without procps a
# `docker exec`/app-hosting shell on a device cannot run `ps` or `top` at all,
# which is the first thing anyone reaches for when an agent misbehaves on a
# switch they cannot easily get to. Costs ~0.9 MB on x86_64 (~1.5 MB on
# aarch64), and the image is about to be frozen for signing -- after that it
# cannot be added back. Deliberate call: keep field debuggability.
# The Alpine XR image needs no equivalent; busybox already provides all of
# these, which is why only this image carries the package.
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client sshpass ca-certificates curl procps \
    && rm -rf /var/lib/apt/lists/*

# Architecture-matched statically-linked aria2c staged by build.sh.
COPY agent_bin/aria2c /opt/iris/bin/aria2c
# the agent control plane (includes cli_ssh.py — the container CLI transport)
COPY agent/*.py /opt/iris/agent/
# the aria2 --on-bt-download-complete program (peer-transfer capture). aria2c
# execs it directly -- execlp, no shell -- so it needs the exec bit below.
COPY agent/peer-transfer-hook.sh /opt/iris/agent/peer-transfer-hook.sh
COPY agent/VERSION /opt/iris/agent/VERSION
# pinned catalog server cert (public; used to VERIFY catalog TLS)
COPY iris-catalog.pem /opt/iris/iris-catalog.pem
COPY entrypoint.sh /entrypoint.sh
COPY reconcile.sh /reconcile.sh
RUN chmod +x /entrypoint.sh /opt/iris/bin/aria2c /opt/iris/agent/peer-transfer-hook.sh

ENV PATH="/opt/iris/bin:${PATH}" \
    PYTHONPATH="/opt/iris/agent" \
    PYTHONUNBUFFERED=1 \
    IRIS_RUNTIME_MODE="container" \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_MAX_PEERS="10" \
    IRIS_TELEMETRY="on" \
    IRIS_LOG="off" \
    IRIS_CATALOG_CA="/opt/iris/iris-catalog.pem"

WORKDIR /opt/iris
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
