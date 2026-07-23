# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS coordination and seed server. Build from the repository root so the
# image contains the device installers and lab transport used by console-driven
# onboarding; no checkout bind mounts are required at runtime.
#
#   docker build --platform linux/amd64 -f server/Dockerfile -t iris:latest .
#
# The alpha server image is intentionally amd64: the static aria2c copied into
# the Guest Shell bundle must match the x86_64 Catalyst platforms it serves.
FROM python:3.12-slim-bookworm

ARG TARGETARCH
RUN case "${TARGETARCH:-amd64}" in \
      amd64) ;; \
      *) echo "IRIS seed server alpha supports linux/amd64 only (got ${TARGETARCH})" >&2; exit 1 ;; \
    esac

LABEL org.opencontainers.image.title="IRIS seed server" \
      org.opencontainers.image.description="Private image staging coordinator, tracker, catalog, and seeder" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cisco-open/intelligent-release-image-staging"

RUN apt-get update \
    && apt-get install -y --no-install-recommends mktorrent openssl curl ca-certificates unzip age openssh-client sshpass iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Static (musl) aria2c — the BitTorrent seeder. Version + checksum pinned here;
# the build FAILS CLOSED on any mismatch.
ARG ARIA2_VERSION=1.37.0
ARG ARIA2_SHA256=e0a09b12ef67f35f8a8e4fdddbec851d235b7c31da549d0578bff459032b499a
RUN set -eux; \
    curl -fsSL -o /tmp/aria2.zip \
      "https://github.com/abcfy2/aria2-static-build/releases/download/${ARIA2_VERSION}/aria2-x86_64-linux-musl_static.zip"; \
    echo "${ARIA2_SHA256}  /tmp/aria2.zip" | sha256sum -c -; \
    unzip -o /tmp/aria2.zip -d /tmp/aria2; \
    install -D -m 0755 "$(find /tmp/aria2 -name aria2c -type f | head -n1)" /opt/iris/bin/aria2c; \
    rm -rf /tmp/aria2.zip /tmp/aria2

WORKDIR /opt/iris
COPY server/ /opt/iris/server/
COPY device/ /opt/iris/device/
COPY lab/ /opt/iris/lab/
COPY VERSION /opt/iris/VERSION

# Docker Desktop's amd64 emulation on Apple Silicon can advertise Go crypto CPU
# features that Rosetta does not implement correctly. age handles only small
# secret files here, so its generic path is a cheap cross-platform safeguard.
ARG IRIS_VERSION=
ENV PATH="/opt/iris/server:${PATH}" \
    PYTHONUNBUFFERED=1 \
    GODEBUG=cpu.all=off
ENV IRIS_VERSION=${IRIS_VERSION}

RUN chmod +x /opt/iris/server/seed-launch.sh \
    /opt/iris/server/iris-publish \
    /opt/iris/server/iris-assign \
    /opt/iris/server/iris-bootstrap \
    /opt/iris/server/pack-agent-bundle.sh \
    /opt/iris/server/provision-served.sh \
    /opt/iris/server/docker-entrypoint.sh \
    /opt/iris/device/*.sh \
    /opt/iris/device/iox/*.sh \
    /opt/iris/lab/*.sh

# Device/operator-facing ports. aria2 RPC (:6800) is loopback-only and omitted.
EXPOSE 6969 8443 8000 6881 8080 9101
VOLUME ["/var/lib/iris", "/etc/iris", "/opt/images", "/srv/artifacts"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:9101/healthz || exit 1

ENTRYPOINT ["/opt/iris/server/docker-entrypoint.sh"]
