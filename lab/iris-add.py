#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Add a .torrent to the already-running aria2c via JSON-RPC (aria2.addTorrent).

A lab helper, NOT part of the agent bundle (tools/make-agent-bundle.sh does
not ship it). Copy it to the device first, then run it in Guest Shell:
  guestshell run python3 /flash/guest-share/iris/iris-add.py /flash/guest-share/iris/some.torrent
Lets one aria2c daemon distribute several images (base + WLC add-on) at once.
The download directory follows STAGE_DIR (default /flash/guest-share/iris),
the same knob the secret path honours, so a router (/bootflash/...) is not
sent to the switch path. Exits 1 on an RPC error."""
import base64
import json
import os
import sys
import urllib.request

if len(sys.argv) < 2:
    sys.exit("usage: iris-add.py <path-to.torrent>")

# rpc-secret file: same default path the on-device daemon and bootstrap use
# ($STAGE_DIR/rpc-secret, default /flash/guest-share/iris/rpc-secret).
# Override via IRIS_RPC_SECRET_FILE env var when running off-device.
_DEFAULT_STAGE = "/flash/guest-share/iris"
_stage_dir = os.environ.get("STAGE_DIR", _DEFAULT_STAGE)
_secret_file = os.environ.get(
    "IRIS_RPC_SECRET_FILE", os.path.join(_stage_dir, "rpc-secret"),
)
# aria2c runs on the placeholder `iris` when the secret file is missing or
# empty (guestshell-start.sh); an empty token is rejected by a healthy daemon.
PLACEHOLDER_SECRET = "iris"
try:
    with open(_secret_file) as _f:
        _secret = _f.read().strip() or PLACEHOLDER_SECRET
except OSError:
    _secret = PLACEHOLDER_SECRET

torrent = sys.argv[1]
with open(torrent, "rb") as f:
    data = base64.b64encode(f.read()).decode()
body = json.dumps({"jsonrpc": "2.0", "id": "a", "method": "aria2.addTorrent",
                   "params": ["token:" + _secret, data, [],
                               {"dir": _stage_dir}]}).encode()
req = urllib.request.Request("http://127.0.0.1:6800/jsonrpc", data=body,
                            headers={"Content-Type": "application/json"})
try:
    reply = json.loads(urllib.request.urlopen(req, timeout=10).read())
except Exception as e:  # noqa: BLE001 - any transport/RPC failure is a failed add
    sys.exit("RPC error: %s" % e)
print(reply)
if "error" in reply:
    sys.exit(1)
