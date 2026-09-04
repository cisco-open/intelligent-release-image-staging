# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Load the IRIS agent config: simple `key = value` lines, '#' comments.
Required keys: catalog_url, catalog_token, device_id. Device containers also
carry one `device_platform` selector (`iox` or `xr-appmgr`). Optional: stage_dir,
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
from urllib.parse import urlsplit

REQUIRED = ("catalog_url", "catalog_token", "device_id")
DEVICE_PLATFORMS = ("iox", "xr-appmgr")
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

PLATFORM_DEFAULTS = {
    "iox": {
        "stage_dir": "/data/iris",
        "target_fs": "",       # proven live from IOS show/dir output
        "runtime_mode": "container",
    },
    "xr-appmgr": {
        "stage_dir": "/hostmount",
        "target_fs": "harddisk:",
        "mode": "xr",
        "runtime_mode": "xr-container",
    },
}

_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
_IOS_PATH_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]*:(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?$")
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
_FACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/ -]*$")
_BOOL_VALUES = frozenset((
    "on", "off", "1", "0", "true", "false", "yes", "no",
    "ON", "OFF", "TRUE", "FALSE", "YES", "NO"))


def validate_target_fs(value):
    if value and not re.match(r"^[A-Za-z][A-Za-z0-9_-]*:$", value):
        raise ValueError("invalid target_fs (expected an IOS prefix such as sdflash:)")
    return value


def validate_device_platform(value, required=False):
    value = (value or "").strip()
    if not value:
        if required:
            raise ValueError(
                "missing device_platform (expected iox or xr-appmgr)")
        return ""
    if value not in DEVICE_PLATFORMS:
        raise ValueError(
            "invalid device_platform (expected iox or xr-appmgr)")
    return value


def validate_single_line(name, value):
    value = "" if value is None else str(value)
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("%s must be a single line" % name)
    return value


def validate_bearer_token(name, value, allow_empty=True):
    """Validate RFC 6750's b64token shape before forming an HTTP header."""
    value = validate_single_line(name, value).strip()
    if not value and allow_empty:
        return value
    if not _BEARER_TOKEN_RE.fullmatch(value):
        raise ValueError("invalid %s" % name)
    return value


def validate_ios_path(name, value, allow_empty=True):
    value = validate_single_line(name, value).strip()
    if not value and allow_empty:
        return value
    if not _IOS_PATH_RE.fullmatch(value) or ".." in value.split(":", 1)[-1].split("/"):
        raise ValueError("invalid %s (expected a safe IOS filesystem path)" % name)
    return value


def _validate_uint(cfg, key, minimum, maximum):
    if key not in cfg:
        return
    value = str(cfg.get(key, ""))
    if not value.isdigit() or not minimum <= int(value) <= maximum:
        raise ValueError("invalid %s (expected %d..%d)" % (key, minimum, maximum))


def validate_config(cfg):
    """Validate values before they can reach a shell/config/IOS command.

    Guest Shell configurations intentionally remain valid without a container
    platform selector. A selector, when present, is strict and controls the
    whole container backend.
    """
    platform = validate_device_platform(cfg.get("device_platform"))
    # target_fs had this validation before the container selector existed;
    # preserve that hard invariant for Guest Shell. Everything else below is
    # platform-input hardening for the unified IOx/XR container only: an absent
    # selector is the legacy Guest Shell grammar and must remain compatible.
    validate_target_fs(cfg.get("target_fs", ""))
    if not platform:
        return cfg

    for key, value in cfg.items():
        if not _KEY_RE.fullmatch(str(key)):
            raise ValueError("invalid config key: %r" % key)
        validate_single_line(key, value)

    catalog_url = str(cfg.get("catalog_url", ""))
    try:
        parsed_url = urlsplit(catalog_url)
        parsed_port = parsed_url.port
        valid_url = (parsed_url.scheme == "https"
                     and parsed_url.hostname is not None
                     and parsed_url.username is None
                     and parsed_url.password is None
                     and (parsed_port is None or 1 <= parsed_port <= 65535))
    except ValueError:
        valid_url = False
    if not valid_url:
        raise ValueError("invalid catalog_url (expected an https URL without credentials)")
    validate_bearer_token(
        "catalog_token", cfg.get("catalog_token"), allow_empty=False)
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", str(cfg.get("device_id", ""))):
        raise ValueError("invalid device_id")

    for key in ("telemetry", "telemetry_stream"):
        if key in cfg and str(cfg.get(key, "")) not in _BOOL_VALUES:
            raise ValueError("invalid %s (expected a boolean value)" % key)
    for key in ("device_model", "device_version", "agent_version"):
        value = str(cfg.get(key, ""))
        if value and not _FACT_RE.fullmatch(value):
            raise ValueError("invalid %s" % key)

    if platform and "announce_token" in cfg:
        validate_bearer_token("announce_token", cfg.get("announce_token"))
    validate_ios_path("share_ios_path", cfg.get("share_ios_path", ""))
    _validate_uint(cfg, "rpc_port", 1, 65535)
    _validate_uint(cfg, "max_peers", 1, 1000)

    for key in ("stage_dir", "share_dir", "device_ssh_known_hosts"):
        value = (cfg.get(key) or "").strip()
        if value and (not os.path.isabs(value)
                      or ".." in value.split(os.sep)):
            raise ValueError("invalid %s (expected an absolute safe path)" % key)

    host = (cfg.get("device_ssh_host") or "").strip()
    user = (cfg.get("device_ssh_user") or "").strip()
    if host and not _SSH_HOST_RE.fullmatch(host):
        raise ValueError("invalid device_ssh_host")
    if user and not _SSH_USER_RE.fullmatch(user):
        raise ValueError("invalid device_ssh_user")
    if cfg.get("device_ssh_port") not in (None, ""):
        _validate_uint(cfg, "device_ssh_port", 1, 65535)

    ssh_values = [cfg.get(key) for key in (
        "device_ssh_host", "device_ssh_user", "device_ssh_pass",
        "device_ssh_enable", "device_ssh_port", "device_ssh_known_hosts")]
    if platform == "xr-appmgr" and any(value not in (None, "")
                                       for value in ssh_values):
        raise ValueError("xr-appmgr forbids device_ssh_* configuration")
    if platform == "xr-appmgr" and cfg.get("target_fs") != "harddisk:":
        raise ValueError("xr-appmgr target_fs must be harddisk:")
    if platform == "iox" and (not host or not user
                               or not cfg.get("device_ssh_pass")):
        raise ValueError("iox requires device_ssh_host/user/pass")
    return cfg


def load(path):
    parsed = {}
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            parsed[k.strip()] = v.strip()
    platform = validate_device_platform(parsed.get("device_platform"))
    cfg = dict(DEFAULTS)
    cfg.update(PLATFORM_DEFAULTS.get(platform, {}))
    cfg.update(parsed)
    for key in REQUIRED:
        if not cfg.get(key):
            raise KeyError("missing required config key: %s" % key)
    return validate_config(cfg)


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
    validate_config(cfg)
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
