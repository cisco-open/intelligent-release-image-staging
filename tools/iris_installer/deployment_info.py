# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only inventory of this installer's containers or pods; no browser inputs."""

import json
import socket
import time

from .state import InstallError, Journal


def clean(value):
    return value if isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable() else None


def docker_rows(raw, host, roles):
    # Compose v2 releases emit either an array or newline-delimited objects.
    content = raw.decode().strip()
    rows = json.loads(content) if content.startswith("[") else [json.loads(line) for line in content.splitlines()]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("Invalid container inventory")
    result = []
    for row in rows:
        if row.get("Service") not in roles:
            continue
        state = clean(row.get("State"))
        health = clean(row.get("Health"))
        result.append(dict(role="server" if row["Service"] == "iris" else "console",
                           kind="container", name=clean(row.get("Name")), host=clean(host),
                           image=clean(row.get("Image")), address=None,
                           state=(state + " / " + health) if state and health else state))
    return sorted(result, key=lambda row: (row["role"] != "server", row["name"] or ""))


def pod_rows(data, identifier):
    from .kube_deploy import LABEL, SERVICES

    rows = data["items"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("Invalid pod inventory")
    result = []
    for pod in rows:
        metadata = pod.get("metadata", {})
        labels = metadata.get("labels", {})
        if labels.get(LABEL) != identifier:
            continue
        role = next((role for role, name in SERVICES.items() if labels.get("app.kubernetes.io/name") == name), None)
        if role not in ("iris", "console"):
            continue
        spec, status = pod.get("spec", {}), pod.get("status", {})
        image = next((c.get("image") for c in spec.get("containers", []) if c.get("name") == role), None)
        state = "terminating" if metadata.get("deletionTimestamp") else clean(status.get("phase"))
        if state == "Running":
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []))
            state += " / " + ("ready" if ready else "not ready")
        result.append(dict(role="server" if role == "iris" else "console", kind="pod",
                           name=clean(metadata.get("name")), host=clean(spec.get("nodeName")),
                           address=clean(status.get("podIP")), image=clean(image), state=state))
    return sorted(result, key=lambda row: (row["role"] != "server", row["name"] or ""))


def collect(state_dir):
    from .deploy import installation

    # Snapshot authority under its existing nonblocking lock, then release it
    # before any bounded read. Never checkpoint or alter deployment resources.
    with Journal(state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError("Installation metadata unavailable")
        adapter = installation(journal)
    config = journal.document["config"]
    result = dict(layout=config["target"], source="managed-worker", observed_at=int(time.time()),
                  instance=config["instance"], namespace=config.get("kube_namespace"), components=[], note=None)
    if config["target"] == "kubernetes":
        from .kube_deploy import LABEL
        raw = adapter.kube("get", "pods", "-l", LABEL + "=" + journal.document["id"],
                           "-o", "json", "--request-timeout=3s", capture=True, timeout=4)
        result["components"] = pod_rows(json.loads(raw), journal.document["id"])
    else:
        # Explicit Docker host is pinned by the installer's clean environment.
        raw = adapter.compose("ps", "--all", "--format", "json", capture=True, timeout=2)
        result["components"] = docker_rows(raw, socket.gethostname(),
                                           {"iris"} if config["target"] == "docker-split" else {"iris", "console"})
        for component in result["components"]:
            component["address"] = clean(config.get("host"))
        if config["target"] == "docker-split":
            try:
                raw = adapter.remote_console("ps", "--all", "--format", "json", capture=True, timeout=2)
                result["components"] += docker_rows(raw, config["console_ssh_host"], {"console"})
            except (InstallError, OSError, ValueError, KeyError, TypeError):
                result["note"] = "Remote Console inventory is unavailable. Its configured SSH host is shown."
                result["components"].append(dict(role="console", kind="container", name=None,
                    host=clean(config["console_ssh_host"]), address=None, image=None, state="not observed"))
    if not result["components"]:
        result["note"] = "No containers or pods were observed for this deployment."
    return result
