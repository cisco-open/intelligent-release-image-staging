# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS coordination and seed server. Build from the repository root so the
# image contains the device installers and lab transport used by console-driven
# onboarding; no checkout bind mounts are required at runtime.
#
#   docker build --pull --platform linux/amd64 -f server/Dockerfile -t iris:latest .
#
# --pull is part of the command, not an optimisation: the base below is a
# floating tag, so without it the build reuses whatever the host cached and
# silently ships an out-of-date base (issue #13). tools/start-compose-server.sh
# passes it for the same reason.
#
# The alpha server image is intentionally amd64: the static aria2c copied into
# the Guest Shell bundle must match the x86_64 Catalyst platforms it serves.
# ---------------------------------------------------------------------------
# The IRIS server image.
# ---------------------------------------------------------------------------
# Debian trixie, NOT bookworm: trixie carries OpenSSL 3.5 LTS while bookworm's
# OpenSSL 3.0 branch reached upstream EOL on 2026-09-07 (Debian security
# support for bookworm continues on its own track, but we do not want to run on
# an upstream-EOL crypto branch). server/trust.py shells out to this image's
# `openssl` binary to parse the TLS trust store and verify CMS integrity for
# downloaded CA bundles (PKCS#7/CMS), so the TLS/crypto stack here is a security
# boundary, not just a build detail. Note this is trust-store/CA-bundle
# processing only: IOS image authenticity is established server-side at
# publish time, not by a device-side signature check — the device places the
# image with a plain `copy`, and the agent attests placement and content
# integrity itself. Device IOx/XR images now use their independently pinned
# Alpine definition under `device/container/`.
FROM python:3.12-slim-trixie


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
COPY tools/aria2c.sha256 /opt/iris/tools/aria2c.sha256

# Fail the build rather than ship a client that is not the manifest-pinned
# handed-in build, or that would not run in the device Guest Shell: it must
# match the x86_64 entry in tools/aria2c.sha256 (running get-aria2c.sh
# beforehand is only a convention — the pin is enforced HERE, so a stale or
# substituted bin/aria2c cannot be baked in silently), be executable, and be
# statically linked.
RUN set -eux; \
    chmod 0755 /opt/iris/bin/aria2c; \
    expected="$(awk '$2 == "x86_64" {print $1}' /opt/iris/tools/aria2c.sha256)"; \
    test -n "$expected"; \
    actual="$(sha256sum /opt/iris/bin/aria2c | awk '{print $1}')"; \
    if [ "$actual" != "$expected" ]; then \
      echo "FAIL: bin/aria2c sha256 $actual does not match the x86_64 entry in tools/aria2c.sha256 ($expected) — run tools/get-aria2c.sh" >&2; \
      exit 1; \
    fi; \
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
    /opt/iris/server/iris-instructions \
    /opt/iris/server/iris-instr-key \
    /opt/iris/server/iris-management-token \
    /opt/iris/server/rotate_seeder_announce.py \
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
         /srv/artifacts /opt/images /var/log/iris /run/iris \
         /run/iris-tier /run/iris-management-ca \
    && rm -rf /opt/iris/server/webroot /opt/iris/server/gui_server.py \
         /opt/iris/server/iris-gui

# Device/operator-facing ports. aria2 RPC (:6800) is loopback-only and omitted.
EXPOSE 6969 8443 8000 6881 9101 9443
VOLUME ["/var/lib/iris", "/etc/iris", "/opt/images", "/srv/artifacts", "/var/lib/iris-images"]

# /readyz, NOT /healthz: /healthz answers 200 unconditionally (telemetry.py)
# and only ever proved the :9101 telemetry server was alive, so a container
# whose catalog or artifact server had died still showed `healthy` and
# tools/start-compose-server.sh went on to stage packages against it.
# /readyz TCP-probes the listeners named by IRIS_HEALTH_LISTENERS (2s each,
# ~8s worst case with everything down), hence the 12s timeout -- the same
# reasoning as kubernetes/deployment.yaml.
HEALTHCHECK --interval=30s --timeout=12s --start-period=20s --retries=3 \
  CMD curl -fsS --cacert /etc/iris/tls/crt.pem \
      --resolve "$IRIS_HOST_IP:9101:127.0.0.1" \
      "https://$IRIS_HOST_IP:9101/readyz" || exit 1

USER iris

ENTRYPOINT ["/opt/iris/server/docker-entrypoint.sh"]
