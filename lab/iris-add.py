#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Add a .torrent to the already-running aria2c via JSON-RPC (aria2.addTorrent).
Usage (in Guest Shell):
  guestshell run python3 .../iris-add.py .../some.torrent
Lets one aria2c daemon distribute several images (base + WLC add-on) at once."""
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
_secret_file = os.environ.get(
    "IRIS_RPC_SECRET_FILE",
    os.path.join(os.environ.get("STAGE_DIR", _DEFAULT_STAGE), "rpc-secret"),
)
try:
    with open(_secret_file) as _f:
        _secret = _f.read().strip()
except OSError:
    _secret = ""

torrent = sys.argv[1]
with open(torrent, "rb") as f:
    data = base64.b64encode(f.read()).decode()
body = json.dumps({"jsonrpc": "2.0", "id": "a", "method": "aria2.addTorrent",
                   "params": ["token:" + _secret, data, [],
                               {"dir": "/flash/guest-share/iris"}]}).encode()
req = urllib.request.Request("http://127.0.0.1:6800/jsonrpc", data=body,
                            headers={"Content-Type": "application/json"})
print(json.loads(urllib.request.urlopen(req, timeout=10).read()))
