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
# ---------------------------------------------------------------------------
# The IRIS server image.
# ---------------------------------------------------------------------------
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

# Static (musl) aria2c — the BitTorrent seeder.
#
# HANDED IN, not downloaded and not built here. The binary is produced by the
# aria2-next-static project, which owns the source pin, patch set and build
# flags, and is installed into bin/ by tools/get-aria2c.sh, which verifies it
# against tools/aria2c.sha256 and fails closed on a mismatch.
#
# Run tools/get-aria2c.sh before building this image, or the COPY below fails.
COPY bin/aria2c /opt/iris/bin/aria2c

# Fail the build rather than ship a client that would not run in the device
# Guest Shell: it must be executable and statically linked.
RUN set -eux; \
    chmod 0755 /opt/iris/bin/aria2c; \
    /opt/iris/bin/aria2c --version >/dev/null; \
    if ldd /opt/iris/bin/aria2c 2>&1 | grep -qiv 'not a dynamic executable'; then \
      echo "FAIL: /opt/iris/bin/aria2c is not statically linked" >&2; \
      ldd /opt/iris/bin/aria2c 2>&1 || true; exit 1; \
    fi


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

# Run unprivileged: every listener binds >1024 and nothing in the entrypoint
# needs root (secretfs shells out to age; no mounts, no chown at runtime). The
# uid/gid are FIXED at 10001 so host-side ownership is deterministic: a fresh
# named volume copies these dirs' image ownership, and the operator chowns of
# bind mounts / the age key target the same uid on every host (see the
# migration note in docker-compose.yml). /var/log/iris lives on the container
# layer (not a volume) and /run/iris backs bare `docker run` without a tmpfs —
# both must pre-exist writable or the entrypoint's mkdir fails.
RUN groupadd --system --gid 10001 iris \
    && useradd --system --uid 10001 --gid iris --home-dir /var/lib/iris \
         --shell /usr/sbin/nologin iris \
    && install -d -o iris -g iris \
         /var/lib/iris /etc/iris /etc/iris/tls /var/lib/iris-images \
         /srv/artifacts /opt/images /var/log/iris /run/iris

# Device/operator-facing ports. aria2 RPC (:6800) is loopback-only and omitted.
EXPOSE 6969 8443 8000 6881 8080 9101
VOLUME ["/var/lib/iris", "/etc/iris", "/opt/images", "/srv/artifacts", "/var/lib/iris-images"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:9101/healthz || exit 1

USER iris

ENTRYPOINT ["/opt/iris/server/docker-entrypoint.sh"]
