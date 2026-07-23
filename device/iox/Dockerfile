# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS agent as an arm64 or amd64 IOx Docker app for Cisco app hosting.
# The selected build platform must match the aria2c staged by build.sh. The agent
# reaches IOS via an
# SSH-to-self transport (cli_ssh) instead of the Guest Shell `cli` bridge.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="IRIS IOx staging agent" \
      org.opencontainers.image.description="Cisco app-hosting image synchronization agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

# openssh-client + sshpass: the SSH-to-self CLI transport (cli_ssh._default_runner)
# procps: pkill/pgrep for the aria2c supervisor in entrypoint.sh
# ca-certificates/curl: TLS roots + diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client sshpass procps ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Architecture-matched statically-linked aria2c staged by build.sh.
COPY agent_bin/aria2c /opt/iris/bin/aria2c
# the agent control plane (includes cli_ssh.py — the container CLI transport)
COPY agent/*.py /opt/iris/agent/
# pinned catalog server cert (public; used to VERIFY catalog TLS)
COPY iris-catalog.pem /opt/iris/iris-catalog.pem
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/iris/bin/aria2c

ENV PATH="/opt/iris/bin:${PATH}" \
    PYTHONPATH="/opt/iris/agent" \
    PYTHONUNBUFFERED=1 \
    IRIS_RUNTIME_MODE="container" \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_MAX_PEERS="10" \
    IRIS_TELEMETRY="on" \
    IRIS_CATALOG_CA="/opt/iris/iris-catalog.pem"

WORKDIR /opt/iris
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/entrypoint.sh"]
