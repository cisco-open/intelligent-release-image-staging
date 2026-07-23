# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Load the IRIS agent config: simple `key = value` lines, '#' comments.
Required keys: catalog_url, catalog_token, device_id. Optional: stage_dir,
target_fs, rpc_port (default 6800), rpc_secret, max_peers, catalog_ca. `target_fs`
selects a writable IOS filesystem prefix such as `sdflash:`; an empty value keeps
platform auto-detection. `catalog_ca` is the
on-device path to the pinned server cert (iris-catalog.pem) used to VERIFY the
catalog TLS connection; when unset the agent keeps today's unverified behavior but
warns (verify-if-present, spec §4.6). Stdlib only."""
import os
import re
import tempfile

REQUIRED = ("catalog_url", "catalog_token", "device_id")
DEFAULTS = {
    "stage_dir": "/flash/guest-share/iris",
    "target_fs": "",       # optional writable IOS prefix, e.g. sdflash:
    "rpc_port": "6800",
    "rpc_secret": "",
    "max_peers": "10",     # cap BT peer connections per torrent on a device
    "catalog_ca": "",      # path to pinned server cert; "" => verify-if-present off (#12)
    "token_expires_at": "0",   # epoch secs of catalog_token expiry; 0 => refresh next tick
}


def validate_target_fs(value):
    if value and not re.match(r"^[A-Za-z][A-Za-z0-9_-]*:$", value):
        raise ValueError("invalid target_fs (expected an IOS prefix such as sdflash:)")
    return value


def load(path):
    cfg = dict(DEFAULTS)
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            cfg[k.strip()] = v.strip()
    for key in REQUIRED:
        if not cfg.get(key):
            raise KeyError("missing required config key: %s" % key)
    validate_target_fs(cfg.get("target_fs", ""))
    return cfg


def write_conf(path, cfg):
    """Atomically rewrite the agent conf as sorted `key = value` lines.
    Writes a sibling tmp file then os.replace()s it over `path` so a crash
    mid-write never leaves a half-written conf the next tick would fail to
    parse. Only `key = value` lines are written — comments in the original
    file are NOT preserved (this is a machine-managed file; comment-stripping
    is intentional). Stdlib only."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=".%s-" % os.path.basename(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for k in sorted(cfg):
                f.write("%s = %s\n" % (k, cfg[k]))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
