# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Load the IRIS agent config: simple `key = value` lines, '#' comments.
Required keys: catalog_url, catalog_token, device_id. Optional: stage_dir,
target_fs, rpc_port (default 6800), rpc_secret, max_peers, catalog_ca. `target_fs`
selects a writable IOS filesystem prefix such as `sdflash:`; an empty value keeps
platform auto-detection. `catalog_ca` is the
on-device path to the pinned server cert (iris-catalog.pem) used to VERIFY the
catalog TLS connection; the agent now FAILS CLOSED when it is unset or the file
is missing (iris_agent.make_catalog_context refuses the connection rather than
falling back to unverified TLS). Deliberately NOT in DEFAULTS below: a conf that
omits catalog_ca must load with the key still absent, not backfilled to "" and
then persisted by the next write_conf() round-trip (security fix -- an earlier
version invented catalog_ca = "" here, which silently and permanently pinned a
dropped-conf device to unverified TLS the moment anything else reconciled its
conf). Stdlib only."""
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
    "telemetry_stream": "off",  # live sample streaming opt-in (fail-closed; spec §5.5)
    "token_expires_at": "0",   # epoch secs of catalog_token expiry; 0 => refresh next tick
    # catalog_ca is intentionally absent from DEFAULTS -- see module docstring.
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


def _file_keys(path):
    """Keys physically present in the conf at `path` (empty set when there is
    no file). Same line grammar as load(), no validation."""
    keys = set()
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                keys.add(s.split("=", 1)[0].strip())
    except OSError:
        pass
    return keys


def write_conf(path, cfg):
    """Atomically rewrite the agent conf as sorted `key = value` lines.
    Writes a sibling tmp file then os.replace()s it over `path` so a crash
    mid-write never leaves a half-written conf the next tick would fail to
    parse. Only `key = value` lines are written — comments in the original
    file are NOT preserved (this is a machine-managed file; comment-stripping
    is intentional).

    A DEFAULTS key that was not in the file and still carries its default
    value is NOT written. load() backfills every DEFAULTS key into the dict
    it returns, so writing that dict back froze the agent's defaults into
    each device conf on its first token refresh — a later agent release that
    changes a default (max_peers, telemetry_stream, ...) never reached a
    deployed device. Keys the file already had, values that differ from the
    default, REQUIRED keys and keys outside DEFAULTS (catalog_ca, tokens) are
    always written, so an explicit setting — including one explicitly set to
    the default value — survives every round-trip. Stdlib only."""
    present = _file_keys(path)
    rows = {k: v for k, v in cfg.items()
            if k in present or k in REQUIRED or k not in DEFAULTS
            or str(v) != DEFAULTS[k]}
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=".%s-" % os.path.basename(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for k in sorted(rows):
                f.write("%s = %s\n" % (k, rows[k]))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
