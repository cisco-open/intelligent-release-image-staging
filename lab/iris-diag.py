#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""One-shot IRIS diagnostic: TCP reachability to tracker+seeder, and
aria2c RPC download status + peer list.

A lab helper, NOT part of the agent bundle (tools/make-agent-bundle.sh does
not ship it). Copy it to the device first, then run it in Guest Shell:
  guestshell run python3 /flash/guest-share/iris/iris-diag.py [server-ip]
Exits 1 when any probe fails, so it is usable from automation.
"""
import json
import os
import socket
import sys
import urllib.request

# No real IP baked in: take the server IP from argv[1] or IRIS_HOST_IP, else a
# neutral placeholder. Run e.g.:  python3 iris-diag.py <server-ip>
HOST = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("IRIS_HOST_IP")) or "<server-ip>"

# rpc-secret file: same default path the on-device daemon and bootstrap use
# ($STAGE_DIR/rpc-secret, default /flash/guest-share/iris/rpc-secret).
# Override via IRIS_RPC_SECRET_FILE env var when running off-device.
_DEFAULT_STAGE = "/flash/guest-share/iris"
RPC_SECRET_FILE = os.environ.get(
    "IRIS_RPC_SECRET_FILE",
    os.path.join(os.environ.get("STAGE_DIR", _DEFAULT_STAGE), "rpc-secret"),
)

# aria2c never runs with an EMPTY secret: guestshell-start.sh (and the IOx
# entrypoint) launch it on the placeholder `iris` when the file is missing or
# empty, so a probe that sent `token:` reported Unauthorized against a healthy
# daemon -- the exact placeholder-secret state the 2026-08-20 incident hinged on.
PLACEHOLDER_SECRET = "iris"


def _read_secret():
    try:
        with open(RPC_SECRET_FILE) as _f:
            return _f.read().strip() or PLACEHOLDER_SECRET
    except OSError:
        return PLACEHOLDER_SECRET


FAILED = False


def tcp(host, port):
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.close()
        return "OPEN"
    except Exception as e:
        return "FAIL:%s" % e


for _name, _port in (("tracker", 6969), ("seeder ", 6881)):
    _result = tcp(HOST, _port)
    print("%s %s:%d -> %s" % (_name, HOST, _port, _result))
    if _result != "OPEN":
        FAILED = True


def rpc(method, params=None):
    token_param = "token:" + _read_secret()
    body = json.dumps({"jsonrpc": "2.0", "id": "s",
                       "method": method,
                       "params": [token_param] + (params or [])}).encode()
    req = urllib.request.Request("http://127.0.0.1:6800/jsonrpc", data=body,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())["result"]


try:
    a = rpc("aria2.tellActive", [["gid", "completedLength", "totalLength",
                                  "downloadSpeed", "uploadSpeed", "connections",
                                  "numSeeders", "status", "errorMessage"]])
    if not a:
        print("ACTIVE: none")
    for d in a:
        comp = int(d.get("completedLength", "0"))
        tot = int(d.get("totalLength", "1")) or 1
        print("STATUS=%s pct=%.1f%% conns=%s seeders=%s dn=%sB/s up=%sB/s err=%s"
              % (d.get("status"), comp * 100.0 / tot, d.get("connections"),
                 d.get("numSeeders"), d.get("downloadSpeed"),
                 d.get("uploadSpeed"), d.get("errorMessage", "")))
        peers = rpc("aria2.getPeers", [d["gid"]])
        print("NUMPEERS=%d" % len(peers))
        for p in peers[:5]:
            print("  peer %s:%s seeder=%s dn=%s up=%s amChoking=%s peerChoking=%s"
                  % (p.get("ip"), p.get("port"), p.get("seeder"),
                     p.get("downloadSpeed"), p.get("uploadSpeed"),
                     p.get("amChoking"), p.get("peerChoking")))
except Exception as e:
    print("RPC error: %s" % e)
    FAILED = True

if FAILED:
    sys.exit(1)
