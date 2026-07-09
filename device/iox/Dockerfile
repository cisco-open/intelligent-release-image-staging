# IRIS agent as an aarch64 IOx Docker app for the Cisco IE-3400 (no Guest Shell).
# Built natively on macOS arm64 (linux/arm64). The agent reaches IOS via an
# SSH-to-self transport (cli_ssh) instead of the Guest Shell `cli` bridge.
FROM arm64v8/python:3.12-slim-bookworm

# openssh-client + sshpass: the SSH-to-self CLI transport (cli_ssh._default_runner)
# procps: pkill/pgrep for the aria2c supervisor in entrypoint.sh
# ca-certificates/curl: TLS roots + diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client sshpass procps ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# aarch64 statically-linked aria2c (from the server's iris-agent-arm.tgz bundle)
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
    IRIS_STAGE_DIR="/data/iris" \
    IRIS_AGENT_CONF="/data/iris/iris-agent.conf" \
    IRIS_AGENT_STATE="/data/iris/iris-agent.state" \
    IRIS_RPC_PORT="6800" \
    IRIS_TICK_SECONDS="60" \
    IRIS_MAX_PEERS="10" \
    IRIS_TELEMETRY="on" \
    IRIS_CATALOG_CA="/opt/iris/iris-catalog.pem"

WORKDIR /opt/iris
ENTRYPOINT ["/entrypoint.sh"]
