# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, public runtime facts for the authenticated dashboard.

Never enumerate environment variables, mounts, credentials or process arguments.
The Console supplies only its own runtime facts across the authenticated tier hop.
"""

import base64
import json
import os
from pathlib import Path
import platform
import socket
import time


HEADER = "X-IRIS-Console-Runtime"
FIELDS = ("role", "kind", "name", "host", "address", "image", "state",
          "os", "architecture", "kernel")
LAYOUTS = ("docker", "docker-split", "kubernetes", "single-container", "unknown")


def text(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    return value if all(char.isprintable() for char in value) else None


def runtime(role):
    pod = text(os.environ.get("IRIS_POD_NAME"))
    kind = ("pod" if pod or os.environ.get("KUBERNETES_SERVICE_HOST") else
            "container" if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists() else "process")
    try:
        system = platform.freedesktop_os_release().get("PRETTY_NAME")
    except OSError:
        system = platform.system()
    return dict(role=role, kind=kind,
                name=pod or text(os.environ.get("IRIS_RUNTIME_NAME")) or text(socket.gethostname()),
                host=text(os.environ.get("IRIS_NODE_NAME") if kind == "pod" else os.environ.get("IRIS_RUNTIME_HOST")),
                address=text(os.environ.get("IRIS_POD_IP")), image=None,
                state="serving", os=text(system), architecture=text(platform.machine()),
                kernel=text(platform.release()))


def console_header():
    return base64.b64encode(json.dumps(runtime("console")).encode()).decode("ascii")


def read_console(value):
    try:
        if not isinstance(value, str) or len(value) > 4096:
            return None
        data = json.loads(base64.b64decode(value, validate=True))
        if (not isinstance(data, dict) or set(data) != set(FIELDS)
                or data.get("role") != "console" or data.get("kind") not in ("pod", "container", "process")):
            return None
        return {key: text(data[key]) for key in FIELDS}
    except (ValueError, UnicodeError):
        return None


def summary(console=None):
    import lifecycle_client

    current = [runtime("server")]
    if console is not None:
        current.append(console)
    try:
        result = lifecycle_client.call({"action": "deployment-info"})
        if (not isinstance(result, dict) or result.get("layout") not in LAYOUTS
                or type(result.get("observed_at")) is not int or result["observed_at"] < 0
                or not isinstance(result.get("components"), list) or len(result["components"]) > 64
                or any(not isinstance(item, dict) or item.get("role") not in ("server", "console")
                       or item.get("kind") not in ("pod", "container", "process") for item in result["components"])):
            raise ValueError("Invalid deployment inventory")
        # Only the documented public fields cross the browser boundary, even
        # when an older/newer worker has a different response contract.
        components = [{key: text(item.get(key)) for key in FIELDS}
                      for item in result["components"] if isinstance(item, dict)]
        for item in components:
            matches = [r for r in current if r["role"] == item["role"] and
                       (r["name"] == item["name"] or item["kind"] == "container")]
            if len(matches) == 1:
                item.update({key: matches[0][key] for key in ("os", "architecture", "kernel")})
        return dict(layout=result["layout"], source="managed-worker",
                    observed_at=result.get("observed_at"),
                    instance=text(result.get("instance")), namespace=text(result.get("namespace")),
                    components=components, note=text(result.get("note")))
    except (lifecycle_client.LifecycleUnavailable, ValueError, TypeError):
        layout = os.environ.get("IRIS_RUNTIME_LAYOUT", "unknown")
        if current[0]["kind"] == "pod":
            layout = "kubernetes"
        return dict(layout=layout if layout in LAYOUTS else "unknown", source="runtime",
                    observed_at=int(time.time()), instance=None,
                    namespace=text(os.environ.get("IRIS_POD_NAMESPACE")), components=current,
                    note="Showing the server and Console serving this request. Full deployment inventory is unavailable.")
