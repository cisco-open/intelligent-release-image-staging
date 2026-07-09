# IRIS coordination server — fully self-contained build (P6).
# Everything the image needs is fetched and verified RIGHT HERE; no pre-downloads.
#   docker build -t iris:latest server/
FROM python:3.12-slim

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
COPY . /opt/iris/server/
ENV PATH="/opt/iris/server:${PATH}"

RUN chmod +x /opt/iris/server/seed-launch.sh \
    /opt/iris/server/iris-publish \
    /opt/iris/server/iris-assign \
    /opt/iris/server/iris-bootstrap \
    /opt/iris/server/pack-agent-bundle.sh \
    /opt/iris/server/provision-served.sh \
    /opt/iris/server/docker-entrypoint.sh

# Release version, baked at BUILD time and shown on the console's Settings
# page (gui_server._read_version reads IRIS_VERSION first). OPTIONAL — the
# empty default keeps plain `docker build server/` working; without it the
# console shows "unknown" (the repo-root VERSION file is outside this build
# context, so it can never be COPY'd here).
#   IRIS_VERSION="$(cat VERSION)" docker compose -f server/docker-compose.yml up -d --build
ARG IRIS_VERSION=
ENV IRIS_VERSION=${IRIS_VERSION}

# tracker / catalog / seeder-rpc / telemetry metrics / web console
EXPOSE 6969 8443 6800 9101 8080
VOLUME ["/var/lib/iris", "/etc/iris", "/opt/images"]

ENTRYPOINT ["/opt/iris/server/docker-entrypoint.sh"]
