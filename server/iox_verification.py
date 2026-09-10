# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authoritative IOx application execution and verification recovery.

This module is deliberately the only bridge between service jobs, durable IOx
verification records, and the bounded IOx transport.  It never installs or
activates network operating-system software; ``install`` below refers only to
the IRIS IOx application.
"""
from __future__ import print_function

import argparse
import base64
import copy
import errno
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import select
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

try:
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover - Python 2 is not supported in IRIS
    from urlparse import urlsplit

import deployment_records


_MAX_INT = (1 << 63) - 1
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_RECORD_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_BOARD_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

_SESSION_FILES = 8192
_TRANSCRIPT_FILES = 8192
_ORDINARY_TRANSCRIPTS = 4096
_ACTIVE_FENCES = 512
_SESSION_FILE_BYTES = 16 * 1024
_TRANSCRIPT_FILE_BYTES = 1024 * 1024
_SUPERVISOR_PACKET_BYTES = 64 * 1024
_SUPERVISOR_MAX_FDS = 16
_SUPERVISOR_REAP_SECONDS = 10.0
_INSTRUCTION_MAX_BYTES = 256 * 1024
_INSTRUCTION_UPLOAD_SECONDS = 300

_RESULT_CODES = {
    "identity_mismatch": 2, "board_busy": 2,
    "wrapper_unreadable": 2, "wrapper_not_regular": 2,
    "wrapper_oversize": 2, "wrapper_changed": 2,
    "wrapper_archive_invalid": 2, "wrapper_archive_limit": 2,
    "unsupported_syntax_local": 2,
    "reconciliation_required": 3,
    "rejected": 4, "unsupported_syntax": 4,
    "unsupported_response": 4, "silence": 4, "timeout": 4,
    "ssh_authentication": 4, "host_key": 4, "connection": 4,
    "transport": 4, "caf_transient": 4, "readback_unknown": 4,
    "readback_mismatch": 4, "wrapper_copy_timeout": 4,
    "wrapper_scan_failed": 4,
    "cancelled": 130,
    "journal_unreadable": 5, "journal_durability": 5,
    "stale_cas": 5, "invalid_transition": 5,
    "authority_mismatch": 5, "transcript_limit": 5,
    "descendant_unreaped": 5,
}

# Filtered deliberately. _classify_read (server/iox_transport.py) enforces a
# closed grammar: the payload must be the ONE authoritative field and nothing
# else, and its own comment says so. Unfiltered, `show app-hosting infra`
# returns a whole block -- IOX version, CAF health, the interface mapping,
# CPU quotas -- so the read could never satisfy the grammar on real hardware
# and every install died at "initial verification read unknown" before the
# device was touched. Filtering leaves the grammar strict: a device that
# reports nothing still reads as silence, and a device that reports something
# unexpected still fails closed.
_VERIFY_READ = b"show app-hosting infra | include App signature verification"
_VERIFY_DISABLE = b"app-hosting verification disable"
_VERIFY_ENABLE = b"app-hosting verification enable"
_IDENTITY = b"show version"

_COMMANDS = frozenset((
    "iox_status", "app_list", "routing_prereq", "storage_prereq", "clock",
    "prepare_iox_scp", "configure_network", "mkdir_share", "app_stop",
    "app_deactivate", "app_uninstall", "remove_app_config", "configure_app",
    "app_install", "app_activate", "copy_instructions", "remove_instructions",
    "copy_certificate", "app_start", "save", "remove_wrapper",
    "remove_certificate", "cleanup_config", "cleanup_files",
    "cleanup_config_probe", "cleanup_stage_probe",
    # Controller-internal steps of the device-side artifact fetch: the recipe
    # never names them, the controller runs them under upload_wrapper,
    # upload_certificate and stage_instructions.
    "configure_trustpoint", "http_client_credentials", "clear_http_client",
    "fetch_wrapper", "fetch_certificate", "fetch_instructions"))

# The artifact server's device-facing resource paths (server/api_routes.py
# artifactBasic): HTTP Basic with username = device id and password = that
# device's catalog enrollment token, which IOS attaches to `copy https:` from
# `ip http client username` / `ip http client password`.
_ARTIFACT_ROUTE = "/v1/devices/%s/artifacts/%s"

_TARGET_KEYS = frozenset((
    "host", "port", "platform", "model", "os_family",
    "management_type", "device_identity", "resources", "device_ip",
    "package_fs", "iox_appid", "vlan", "svi_ip", "svi_mask",
    "guest_ip", "inband_vlan", "app_ip", "app_mask", "app_gateway",
    "vpg_number", "nat_interface", "bt_listen_port",
    "nat_outside_owned", "ios_ssh_host", "target_fs",
    "share_host_path", "share_ios_path", "app_intf", "pkg",
    "telemetry", "telemetry_stream", "log"))
_SECRET_TARGET_FRAGMENTS = ("pass", "password", "secret", "token",
                            "credential", "private", "key")
# A Catalyst 8000 has no AppGigabitEthernet: on a router the app attaches to
# the IRIS-owned VirtualPortGroup the Guest Shell router recipe also creates,
# the target carries the VPG/NAT plan instead of a VLAN, and staging goes to
# bootflash:. These are the management types that select that path.
_ROUTER_MODES = frozenset(("router-routed", "router-nat"))
_IOX_APP_RESOURCE = {"kind": "iox-app", "ownership": "iris-created"}
# The ownership claims a router record may carry for an IOx app: the
# VirtualPortGroup/NAT footprint device/iox/install.sh creates and
# device/iox/uninstall.sh removes, plus the device-global settings it
# preserves. Anything else is not something the IOx recipe can take back.
_ROUTER_RESOURCE_KINDS = frozenset((
    "iox-app", "virtualportgroup", "pki-trustpoint", "http-client-trustpoint",
    "iox-global", "file-prompt-quiet", "nat-acl", "nat-overload",
    "nat-static", "nat-outside-marking"))
_RESOURCE_OWNERSHIPS = frozenset(
    ("iris-created", "iris-added-preserved", "pre-existing"))
# Written into every VirtualPortGroup the IOx recipe creates on a router, the
# same literal device/iox/install.sh prints and gui_onboard's router preflight
# recognises on a resumable retry. Deliberately not the Guest Shell recipe's
# marker: device/router-uninstall.sh's record-less reclaim must never remove
# the group an IOx app is still attached to.
_VPG_DESCRIPTION = "description IRIS IOx VPG"
_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
_SAFE_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_SAFE_APPID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SAFE_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9./_-]{0,127}$")
_SAFE_FILESYSTEM = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}:$")
_SAFE_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_HOST_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,254}$")
_SAFE_IOS_PATH = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]{0,31}:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_NETMASKS = frozenset(str(ipaddress.IPv4Network(
    "0.0.0.0/%d" % prefix).netmask) for prefix in range(33))

_INSTALL_ONLY = frozenset(("upload_wrapper", "upload_certificate",
                           "begin_install", "deployed"))
# Recipe operations that get no job-log line when they succeed: the two
# lifecycle polls (the recipe prints the state it was waiting for once it is
# reached) and the closing protocol handshake.
_SILENT_RECIPE_STEPS = frozenset(("app_list", "iox_status", "cleanup", "finish"))
_UNINSTALL_COMMANDS = frozenset((
    "iox_status", "app_list", "app_stop", "app_deactivate",
    "app_uninstall", "remove_app_config", "remove_wrapper",
    "remove_certificate", "cleanup_config", "cleanup_files",
    "cleanup_config_probe", "cleanup_stage_probe", "save"))

_IRIS_NAMED_COLLISIONS = (
    (r"(?m)^event manager applet IRIS-(?:AGENT|COPYROOT|RECLAIM|RECLAIM-BUNDLE)(?:\s|$)",
     "an IRIS EEM applet"),
    (r"(?m)^logging discriminator IRISQ(?:\s|$)",
     "logging discriminator IRISQ"),
    (r"(?m)^logging (?:buffered|console|monitor) discriminator IRISQ\s*$",
     "an IRISQ logging binding"),
)
# The catalog trustpoint and its HTTP client binding are this recipe's OWN
# artifacts now (the HTTPS fetch installs them, removing and re-adding the
# trustpoint first, exactly like device-install.sh), so a leftover from an
# earlier attempt -- a timed-out paste left `crypto pki trustpoint IRIS`
# half-configured on two lab devices on 2026-09-10 -- is walked over, not
# refused. Nothing is reinstated on retry any more; the set stays for the
# preflight loop that consults it.
_IOX_RETRY_REINSTATED = frozenset()

# What the transcript writer (tempfile.mkstemp) and the fence/record writers
# (_durable_json) stage beside the file they are about to rename into place.
_AUTHORITY_TEMPORARY = re.compile(r"^\.(?:transcript-[A-Za-z0-9_]+\.tmp|iox-[0-9a-f]+\.tmp)$")
_AUTHORITY_ENTRY_ATTEMPTS = 6


class _ControllerFailure(Exception):
    def __init__(self, category, detail="", code=None):
        Exception.__init__(self, detail or category)
        self.category = category
        self.detail = _bounded_text(detail or category)
        self.code = _RESULT_CODES.get(category, 4) if code is None else code


class _SyntheticCommandFailure(Exception):
    """A legacy injected transport failed at its command call boundary."""
    def __init__(self, original):
        Exception.__init__(self, str(original))
        self.original = original


class _NoopContext(object):
    def __enter__(self):
        return self

    def __exit__(self, unused_kind, unused_value, unused_traceback):
        return False


class _StoreLockContext(object):
    """Translate a bounded record-lock miss into the controller taxonomy."""
    def __init__(self, context):
        self.context = context

    def __enter__(self):
        try:
            return self.context.__enter__()
        except deployment_records.StoreLockTimeout:
            raise _ControllerFailure(
                "timeout", "deployment-record store lock timed out", 4)

    def __exit__(self, kind, value, traceback):
        return self.context.__exit__(kind, value, traceback)


def _bounded_text(value, limit=1024):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value)
    raw = value.encode("utf-8")[:limit]
    while True:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raw = raw[:-1]


def _get(value, key, default=None):
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _has(value, key):
    return key in value if isinstance(value, dict) else hasattr(value, key)


def _cancelled(cancel):
    if cancel is None:
        return False
    if callable(cancel):
        return bool(cancel())
    return bool(cancel.is_set())


def _ascii_value(value, pattern, name):
    if (not isinstance(value, str) or pattern.fullmatch(value) is None or
            any(ord(character) < 33 or ord(character) > 126
                for character in value)):
        raise ValueError("invalid IOx target %s" % name)
    return value


def _ipv4_value(value, name):
    if not isinstance(value, str):
        raise ValueError("invalid IOx target %s" % name)
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError("invalid IOx target %s" % name)
    if str(parsed) != value:
        raise ValueError("noncanonical IOx target %s" % name)
    return value


def _boolean_word(value, name):
    if type(value) is bool:
        return "on" if value else "off"
    if isinstance(value, str) and value in ("on", "off"):
        return value
    raise ValueError("invalid IOx target %s" % name)


def _https_url(value):
    if (not isinstance(value, str) or not value or len(value) > 2048 or
            any(ord(character) < 33 or ord(character) > 126
                for character in value) or
            re.fullmatch(
                r"https://[a-z0-9.-]+(?::[0-9]{1,5})?"
                r"(?:/[A-Za-z0-9._~/%+,-]*)?"
                r"(?:\?[A-Za-z0-9._~/%+,&=-]*)?", value) is None):
        raise ValueError("invalid IOx catalog URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid IOx catalog URL")
    if (parsed.scheme != "https" or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            (port is not None and not 1 <= port <= 65535) or
            parsed.fragment or parsed.hostname != parsed.hostname.lower() or
            parsed.netloc != parsed.hostname +
            ((":" + str(port)) if port is not None else "")):
        raise ValueError("invalid IOx catalog URL")
    return value


def _validate_resources(resources, router):
    """The record's ownership claims, closed to what the IOx recipe can take
    back. Off a router the app is the only thing IRIS ever claims. On a
    router the record must also claim the VirtualPortGroup the app rides and
    may claim only the footprint device/iox/uninstall.sh removes."""
    if not isinstance(resources, list):
        raise ValueError("invalid IOx target resources")
    if not router:
        if resources != [_IOX_APP_RESOURCE]:
            raise ValueError("invalid IOx target resources")
        return
    kinds = []
    for resource in resources:
        if (not isinstance(resource, dict) or
                resource.get("kind") not in _ROUTER_RESOURCE_KINDS or
                resource.get("ownership") not in _RESOURCE_OWNERSHIPS):
            raise ValueError("invalid IOx target resources")
        kinds.append(resource["kind"])
    if (len(kinds) != len(set(kinds)) or "virtualportgroup" not in kinds or
            not any(resource == _IOX_APP_RESOURCE for resource in resources)):
        raise ValueError("invalid IOx target resources")


def _router_subnet_check(app_ip, app_mask, app_gateway):
    """The app and its VirtualPortGroup gateway must be two distinct usable
    addresses of one subnet -- the check the router recipe makes before it
    writes the group, so a plan that passed the Console never reaches the
    device with an address IOS would refuse or route nowhere."""
    network = ipaddress.IPv4Network("%s/%s" % (app_ip, app_mask), strict=False)
    address = ipaddress.IPv4Address(app_ip)
    gateway = ipaddress.IPv4Address(app_gateway)
    unusable = (network.network_address, network.broadcast_address)
    if (network.prefixlen > 30 or gateway not in network or
            gateway == address or address in unusable or gateway in unusable):
        raise ValueError("IOx router target app_ip and app_gateway must be "
                         "distinct usable addresses in the app subnet")


def _unexpected_detail(label, exc):
    """Name an unexpected controller exception in the operator's job log.

    These paths used to collapse every unforeseen failure into one fixed
    sentence, so a job said only "IOx uninstall controller failed" and the
    type and message were lost -- the operator's next move was a guess, and
    each guess cost a rebuild. The controller's own exceptions carry fixed,
    non-secret strings; the text is bounded and stripped of control
    characters so a surprising payload cannot reshape the log.
    """
    text = "".join(ch for ch in str(exc) if 32 <= ord(ch) < 127)[:200]
    return "%s: %s%s" % (label, type(exc).__name__,
                         ": " + text if text else "")


_IOS_REFUSAL_RE = re.compile(rb"^%[^\r\n]+", re.M)


def _http_client_credentials_collision(running, device_id):
    """True when running-config carries an IOS HTTP client credential that
    is not IRIS's own (username = this device id): the fetch would
    overwrite and then delete an operator's pair."""
    own = re.search(
        r"(?m)^ip http client username %s\s*$" % re.escape(device_id),
        running)
    return own is None and re.search(
        r"(?m)^ip http client (?:username|password)(?:\s|$)", running) is not None


def _command_failure_detail(purpose, result):
    """Name the failed step and quote the device's own refusal line.

    A job used to end with only "IOx command failed", and the operator had to
    decode the transcript to learn that the router had answered
    '% node--1:dbm:IOxMan:Resource Profile-names is not specified' to the
    first line of the app block. The first '%' line the device printed is
    the verdict IOS itself chose to show; quote it bounded and printable.
    The transport already redacts credentials from captured output.
    """
    detail = "IOx command failed: %s" % purpose
    # A timeout is the transport giving up on a prompt, not a verdict: an
    # earlier '%' line in the same step (the tolerated "% Can't find policy
    # IRIS" answer to a trustpoint removal, say) would misname the cause.
    if _get(result, "timed_out", False):
        return detail + ": timed out waiting for the device's prompt"
    stdout = _get(result, "stdout", b"")
    if isinstance(stdout, (bytes, bytearray)):
        match = _IOS_REFUSAL_RE.search(bytes(stdout))
        if match is not None:
            line = "".join(ch for ch in match.group(0).decode("ascii", "replace")
                           if 32 <= ord(ch) < 127).strip()
            if line:
                detail += ": device said %s" % line[:160]
    return detail


def _command_bytes(lines):
    if isinstance(lines, bytes):
        body = lines
    else:
        body = "\n".join(lines).encode("ascii")
    executable = [line for line in body.split(b"\n")
                  if line and not line.startswith(b"!")]
    if (not executable or len(body) > 16384 or
            any(not 1 <= len(line) <= 320 or
                any(byte < 32 or byte > 126 for byte in bytearray(line))
                for line in executable)):
        raise _ControllerFailure(
            "unsupported_syntax", "rendered IOx command is invalid", 2)
    return body


def _open_public_certificate(path, validate_x509=True):
    if (not isinstance(path, str) or not os.path.isabs(path) or
            any(ord(character) < 32 for character in path)):
        raise ValueError("invalid IOx catalog certificate")
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    before = os.lstat(path)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(path)
        if (not stat.S_ISREG(opened.st_mode) or
                opened.st_uid != os.geteuid() or opened.st_nlink != 1 or
                stat.S_IMODE(opened.st_mode) & 0o022 or
                not 1 <= opened.st_size <= 65536 or
                (before.st_dev, before.st_ino) !=
                (opened.st_dev, opened.st_ino) or
                (named.st_dev, named.st_ino) !=
                (opened.st_dev, opened.st_ino)):
            raise ValueError("unsafe IOx catalog certificate")
        chunks = []
        remaining = 65537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != opened.st_size or len(raw) > 65536:
            raise ValueError("invalid IOx catalog certificate")
        if validate_x509:
            text = raw.decode("ascii")
            if ("PRIVATE KEY" in text or
                    text.count("-----BEGIN CERTIFICATE-----") != 1 or
                    text.count("-----END CERTIFICATE-----") != 1):
                raise ValueError("invalid IOx catalog certificate")
            ssl.PEM_cert_to_DER_cert(text)
            ssl._ssl._test_decode_cert("/proc/self/fd/%d" % descriptor)
        final_opened = os.fstat(descriptor)
        final_named = os.lstat(path)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(opened, key) != getattr(final_opened, key) or
               getattr(opened, key) != getattr(final_named, key)
               for key in fields):
            raise ValueError("IOx catalog certificate changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


class _InstructionSnapshot(object):
    """One private, unlinked, read-only bootstrap ciphertext snapshot."""

    def __init__(self, descriptor, digest):
        self.fd = descriptor
        self.sha256 = digest
        self._closed = False

    def close(self):
        if not self._closed:
            self._closed = True
            os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        self.close()


def _instruction_metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size,
            getattr(value, "st_mtime_ns", int(value.st_mtime * 1000000000)),
            getattr(value, "st_ctime_ns", int(value.st_ctime * 1000000000)))


def _admit_instruction_bootstrap(value, snapshot_dir, deadline, cancel,
                                 monotonic_fn):
    """Copy callback output into controller-owned private inode custody."""
    source_fd = -1
    source_initial = None
    temporary = None
    result_fd = -1
    try:
        if callable(cancel) and cancel():
            raise ValueError("cancelled")
        if monotonic_fn() >= deadline:
            raise ValueError("deadline")
        if isinstance(value, bytes):
            body = value
        elif isinstance(value, str):
            if (not os.path.isabs(value) or
                    any(ord(character) < 32 for character in value)):
                raise ValueError("path")
            flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0))
            source_fd = os.open(value, flags)
            source_initial = os.fstat(source_fd)
            if (not stat.S_ISREG(source_initial.st_mode) or
                    source_initial.st_uid != os.geteuid() or
                    source_initial.st_nlink != 1 or
                    stat.S_IMODE(source_initial.st_mode) != 0o600 or
                    not 1 <= source_initial.st_size <=
                    _INSTRUCTION_MAX_BYTES):
                raise ValueError("source")
            chunks = []
            remaining = _INSTRUCTION_MAX_BYTES + 1
            while remaining:
                if callable(cancel) and cancel():
                    raise ValueError("cancelled")
                if monotonic_fn() >= deadline:
                    raise ValueError("deadline")
                chunk = os.read(source_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            source_final = os.fstat(source_fd)
            if (_instruction_metadata(source_initial) !=
                    _instruction_metadata(source_final) or
                    len(body) != source_initial.st_size):
                raise ValueError("changed")
        else:
            raise ValueError("type")
        if not 1 <= len(body) <= _INSTRUCTION_MAX_BYTES:
            raise ValueError("size")
        temporary = tempfile.TemporaryFile(mode="w+b", dir=snapshot_dir)
        os.fchmod(temporary.fileno(), 0o600)
        temporary.write(body)
        temporary.flush()
        os.fsync(temporary.fileno())
        held = os.fstat(temporary.fileno())
        if (not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid() or
                stat.S_IMODE(held.st_mode) != 0o600 or
                held.st_size != len(body)):
            raise ValueError("snapshot")
        result_fd = os.open(
            "/proc/self/fd/%d" % temporary.fileno(),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        reopened = os.fstat(result_fd)
        if ((reopened.st_dev, reopened.st_ino) !=
                (held.st_dev, held.st_ino) or
                reopened.st_size != held.st_size):
            raise ValueError("snapshot")
        temporary.close()
        temporary = None
        os.lseek(result_fd, 0, os.SEEK_SET)
        snapshot = _InstructionSnapshot(
            result_fd, hashlib.sha256(body).hexdigest())
        result_fd = -1
        return snapshot
    except Exception:
        raise _ControllerFailure(
            "rejected", "IOx install controller failed", 2)
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temporary is not None:
            temporary.close()
        if result_fd >= 0:
            os.close(result_fd)


def _service_job_context(cancel, default_device, default_credential=None):
    """Read the private service-job binding carried by a cancel token."""
    job_id = getattr(cancel, "_iris_job_id", "0" * 16)
    device_id = getattr(cancel, "_iris_device_id", default_device)
    credential_ref = getattr(
        cancel, "_iris_credential_ref", default_credential)
    if not isinstance(job_id, str) or not _HEX16.fullmatch(job_id):
        raise ValueError("invalid recovery service job id")
    if (not isinstance(device_id, str) or not device_id or
            len(device_id.encode("utf-8")) > 128 or
            any(ord(character) < 32 for character in device_id)):
        raise ValueError("invalid recovery service device id")
    if (credential_ref is not None and
            (not isinstance(credential_ref, str) or not credential_ref or
             len(credential_ref.encode("utf-8")) > 256 or
             any(ord(character) < 32 for character in credential_ref))):
        raise ValueError("invalid recovery credential reference")
    return job_id, device_id, credential_ref


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


def _read_json_strict(path, maximum):
    directory = os.path.dirname(path)
    name = os.path.basename(path)
    directory_fd = _open_directory_anchor(directory, required_mode=0o700)
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(fd)
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino) or
                (after.st_dev, after.st_ino) !=
                (metadata.st_dev, metadata.st_ino) or
                not stat.S_ISREG(metadata.st_mode) or
                metadata.st_uid != os.geteuid() or metadata.st_nlink != 1):
            raise ValueError("unsafe authority file")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > maximum:
            raise ValueError("unsafe authority file metadata")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise ValueError("authority file exceeds limit")
        final_metadata = os.fstat(fd)
        final_path = os.stat(
            name, dir_fd=directory_fd, follow_symlinks=False)
        stable_fields = ("st_dev", "st_ino", "st_uid", "st_mode",
                         "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(metadata, field) != getattr(final_metadata, field) or
               getattr(metadata, field) != getattr(final_path, field)
               for field in stable_fields):
            raise ValueError("authority file changed during read")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              ValueError("non-finite JSON")))
    finally:
        os.close(fd)
        os.close(directory_fd)


def _open_directory_anchor(path, required_mode=None):
    before = os.lstat(path)
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
             getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        after = os.lstat(path)
        if (not stat.S_ISDIR(metadata.st_mode) or
                metadata.st_uid != os.geteuid() or
                (required_mode is not None and
                 stat.S_IMODE(metadata.st_mode) != required_mode) or
                (before.st_dev, before.st_ino) !=
                (metadata.st_dev, metadata.st_ino) or
                (after.st_dev, after.st_ino) !=
                (metadata.st_dev, metadata.st_ino)):
            raise ValueError("unsafe authority directory")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _fsync_directory(path):
    fd = _open_directory_anchor(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _AnchoredPath(os.PathLike):
    """A dirfd-anchored syscall path retaining its diagnostic identity."""
    def __init__(self, directory_fd, name, display):
        self._path = "/proc/self/fd/%d/%s" % (directory_fd, name)
        self._display = display

    def __fspath__(self):
        return self._path

    def __eq__(self, other):
        try:
            return os.fspath(other) == self._display
        except TypeError:
            return False

    def __str__(self):
        return self._display


def _durable_json(path, value, replace=True):
    directory = os.path.dirname(path)
    name = os.path.basename(path)
    body = _canonical(value)
    if len(body) > _SESSION_FILE_BYTES and "/sessions/" in path:
        raise _ControllerFailure("journal_durability", "session fence exceeds limit", 5)
    directory_fd = _open_directory_anchor(directory, required_mode=0o700)
    temporary = ".iox-%s.tmp" % os.urandom(12).hex()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0), 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_metadata = os.stat(
            temporary, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(temporary_metadata.st_mode) or
                stat.S_IMODE(temporary_metadata.st_mode) != 0o600 or
                temporary_metadata.st_uid != os.geteuid() or
                temporary_metadata.st_nlink != 1):
            raise ValueError("unsafe temporary authority file")
        anchored_source = _AnchoredPath(directory_fd, temporary,
                                        os.path.join(directory, temporary))
        anchored_destination = _AnchoredPath(directory_fd, name, path)
        if replace:
            os.replace(anchored_source, anchored_destination)
        else:
            os.link(anchored_source, anchored_destination,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory_fd)
        committed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((committed.st_dev, committed.st_ino) !=
                (temporary_metadata.st_dev, temporary_metadata.st_ino) or
                not stat.S_ISREG(committed.st_mode) or
                stat.S_IMODE(committed.st_mode) != 0o600 or
                committed.st_uid != os.geteuid() or committed.st_nlink != 1):
            raise ValueError("authority commit path changed")
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        os.close(directory_fd)


def _safe_directory(path, create=False):
    expected = None
    if create:
        parent = os.path.dirname(path)
        name = os.path.basename(path)
        parent_fd = _open_directory_anchor(parent)
        try:
            try:
                # Keep the durable-creation syscall observable at its full
                # authority path, then prove that it created the entry below
                # the parent descriptor held across the operation.
                os.mkdir(path, 0o700)
                os.fsync(parent_fd)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
            metadata = os.stat(
                name, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(metadata.st_mode) or
                    metadata.st_uid != os.geteuid() or
                    stat.S_IMODE(metadata.st_mode) != 0o700):
                raise ValueError("unsafe authority directory")
            expected = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(parent_fd)
    descriptor = _open_directory_anchor(path, required_mode=0o700)
    try:
        if expected is not None:
            metadata = os.fstat(descriptor)
            if expected != (metadata.st_dev, metadata.st_ino):
                raise ValueError("authority directory path changed")
    finally:
        os.close(descriptor)


def _reject_symlink_components(raw_path):
    current = os.path.sep
    for component in os.path.abspath(raw_path).split(os.path.sep)[1:]:
        current = os.path.join(current, component)
        if os.path.lexists(current) and stat.S_ISLNK(os.lstat(current).st_mode):
            raise ValueError("state_dir must not traverse symlinks")


def _safe_state_root(raw_path):
    if (not isinstance(raw_path, str) or not raw_path or
            not os.path.isabs(raw_path)):
        raise ValueError("state_dir must be a non-empty absolute path")
    _reject_symlink_components(raw_path)
    canonical = os.path.realpath(raw_path)
    if os.path.abspath(raw_path) != canonical:
        raise ValueError("state_dir must not traverse symlinks")
    metadata = os.lstat(raw_path)
    if (stat.S_ISLNK(metadata.st_mode) or
            not stat.S_ISDIR(metadata.st_mode) or
            metadata.st_uid != os.geteuid()):
        raise ValueError("unsafe state_dir")
    return canonical


def _board_key(board):
    return hashlib.sha256(b"IRIS-IOX-BOARD-v1\0" +
                          board.encode("ascii")).hexdigest() + ".lock"


def _open_board_lock(directory, board):
    name = _board_key(board)
    directory_fd = _open_directory_anchor(directory, required_mode=0o700)
    flags = (os.O_RDWR | getattr(os, "O_CLOEXEC", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        created = False
        try:
            descriptor = os.open(
                name, flags | os.O_CREAT | os.O_EXCL, 0o600,
                dir_fd=directory_fd)
            created = True
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or
                    metadata.st_uid != os.geteuid() or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_nlink != 1 or
                    metadata.st_size > _SESSION_FILE_BYTES or
                    (metadata.st_dev, metadata.st_ino) !=
                    (path_metadata.st_dev, path_metadata.st_ino)):
                raise ValueError("unsafe physical-board lock")
            if created:
                os.fsync(directory_fd)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise
    finally:
        os.close(directory_fd)


def _revalidate_board_lock(directory, board, descriptor):
    directory_fd = _open_directory_anchor(directory, required_mode=0o700)
    try:
        held = os.fstat(descriptor)
        named = os.stat(_board_key(board), dir_fd=directory_fd,
                        follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid() or
                stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1 or
                (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError("physical-board lock pathname changed")
    finally:
        os.close(directory_fd)


def _boot_id():
    """The identity a session fence binds its supervisor to.

    A same-boot active fence is taken as a live descendant: the supervisor,
    or a device session it spawned, may still be running, and nothing short
    of a reboot proves otherwise. The server runs in a container, and a
    container restart keeps the host boot id while killing every process in
    the namespace -- an attempt cut off by a redeploy left its device
    refusing every later attempt with 'active same-boot IOx session fence'
    until the fence was removed by hand (2026-09-10). Fold pid 1's start
    ticks into the identity: pid 1 is the container's entrypoint, so a
    restart is a new boot and the fence it orphaned is stale, while a
    supervisor crash inside a running container still fails closed.
    """
    with open("/proc/sys/kernel/random/boot_id") as stream:
        value = stream.read().strip().lower()
    if not _BOOT_ID.fullmatch(value):
        raise ValueError("invalid host boot identity")
    try:
        epoch = _process_start_ticks(1)
    except (OSError, ValueError, IndexError):
        return value
    # A name-based UUID keeps the RFC 4122 shape the fence schema requires.
    return str(uuid.uuid5(uuid.UUID(value), "pid1:%d" % epoch))


def _process_start_ticks(pid):
    with open("/proc/%d/stat" % pid) as stream:
        return int(stream.read().split()[21])



def _supervisor_send(peer, value, descriptors=()):
    body = _canonical(value)
    if len(body) > _SUPERVISOR_PACKET_BYTES:
        raise ValueError("supervisor message exceeds limit")
    descriptors = tuple(descriptors)
    if len(descriptors) > _SUPERVISOR_MAX_FDS:
        raise ValueError("too many supervisor descriptors")
    ancillary = []
    if descriptors:
        packed = struct.pack("%di" % len(descriptors), *descriptors)
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, packed))
    sent = peer.sendmsg([body], ancillary)
    if sent != len(body):
        raise IOError("short supervisor message")


def _supervisor_receive(peer):
    body, ancillary, flags, unused_address = peer.recvmsg(
        _SUPERVISOR_PACKET_BYTES + 1,
        socket.CMSG_SPACE(_SUPERVISOR_MAX_FDS * struct.calcsize("i")))
    descriptors = []
    invalid_ancillary = False
    try:
        width = struct.calcsize("i")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                usable = len(data) - (len(data) % width)
                if usable:
                    descriptors.extend(struct.unpack(
                        "%di" % (usable // width), data[:usable]))
                if usable != len(data):
                    invalid_ancillary = True
            else:
                invalid_ancillary = True
        if not body:
            raise EOFError("supervisor peer closed")
        if flags & (getattr(socket, "MSG_TRUNC", 0) |
                    getattr(socket, "MSG_CTRUNC", 0)):
            raise ValueError("truncated supervisor message")
        if invalid_ancillary:
            raise ValueError("unexpected supervisor ancillary data")
        if len(descriptors) > _SUPERVISOR_MAX_FDS:
            raise ValueError("too many supervisor descriptors")
        value = json.loads(
            body.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError("non-finite JSON")))
    except Exception:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    return value, descriptors


class _SupervisedProcess(object):
    """Small Popen-compatible view of a child owned by the supervisor."""
    def __init__(self, supervisor, token, pid, streams):
        self._supervisor = supervisor
        self._token = token
        self.pid = pid
        self.returncode = None
        self.stdin = streams.get("stdin")
        self.stdout = streams.get("stdout")
        self.stderr = streams.get("stderr")

    def poll(self, timeout=2.0):
        if (not isinstance(timeout, (int, float)) or
                isinstance(timeout, bool) or timeout <= 0):
            raise ValueError("invalid poll timeout")
        response, descriptors = self._supervisor._request(
            "poll", {"token": self._token}, timeout=min(2.0, timeout))
        for descriptor in descriptors:
            os.close(descriptor)
        self.returncode = response["returncode"]
        return self.returncode

    def wait(self, timeout=None):
        if timeout is None:
            timeout = _SUPERVISOR_REAP_SECONDS
        if (not isinstance(timeout, (int, float)) or
                isinstance(timeout, bool) or timeout < 0):
            raise ValueError("invalid wait timeout")
        response_value = self._supervisor._request(
            "wait", {"token": self._token, "timeout": min(
                float(timeout), _SUPERVISOR_REAP_SECONDS)},
            timeout=min(float(timeout), _SUPERVISOR_REAP_SECONDS),
            allow_timeout=True)
        if response_value is None:
            raise subprocess.TimeoutExpired(["supervised"], timeout)
        response, descriptors = response_value
        for descriptor in descriptors:
            os.close(descriptor)
        if response.get("timed_out"):
            raise subprocess.TimeoutExpired(["supervised"], timeout)
        self.returncode = response["returncode"]
        return self.returncode

    def send_signal(self, sig, timeout=2.0):
        if (not isinstance(sig, int) or isinstance(sig, bool) or
                sig not in (signal.SIGTERM, signal.SIGKILL,
                            signal.SIGINT, signal.SIGHUP)):
            raise ValueError("unsupported supervised signal")
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                timeout <= 0):
            raise ValueError("invalid signal timeout")
        response, descriptors = self._supervisor._request(
            "signal", {"token": self._token, "signal": sig},
            timeout=timeout)
        for descriptor in descriptors:
            os.close(descriptor)
        self.returncode = response["returncode"]

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        self.send_signal(signal.SIGKILL)


class _RecipeCapture(object):
    """Continuously drain recipe pipes with bounded streaming redaction.

    The reader threads accumulate each stream; ``drain`` hands the caller
    what has arrived so far, so the controller can forward the recipe's own
    progress lines at every request boundary instead of only after the
    recipe exits. The 32 KiB bound counts everything ever captured on a
    stream, drained or not, so draining does not widen it."""
    def __init__(self, process, secret_values):
        import iox_transport
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._values = {"stdout": bytearray(), "stderr": bytearray()}
        self._captured = {"stdout": 0, "stderr": 0}
        self._threads = []
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            redactor = iox_transport._StreamingRedactor(secret_values)
            wake_read, wake_write = socket.socketpair()
            thread = threading.Thread(
                target=self._reader,
                args=(name, stream, redactor, wake_read))
            thread.daemon = True
            thread.start()
            self._threads.append((thread, wake_write))

    def _reader(self, name, stream, redactor, wake):
        descriptor = stream.fileno()
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            while not self._stop.is_set():
                readable, unused, unused2 = select.select(
                    [descriptor, wake], [], [])
                if wake in readable:
                    break
                try:
                    chunk = os.read(descriptor, 4096)
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    break
                if not chunk:
                    break
                self._append(name, redactor.feed(chunk))
        finally:
            self._append(name, redactor.finish())
            try:
                stream.close()
            except OSError:
                pass
            wake.close()

    def _append(self, name, body):
        with self._lock:
            remaining = 32768 - self._captured[name]
            if remaining > 0:
                self._values[name].extend(body[:remaining])
                self._captured[name] += min(len(body), remaining)

    def drain(self):
        """Take what each stream has accumulated since the last drain, in
        (stream, bytes) pairs; streams with nothing new are omitted."""
        with self._lock:
            drained = [(name, bytes(body))
                       for name, body in self._values.items() if body]
            for name in self._values:
                self._values[name] = bytearray()
        return drained

    def finish(self, writers_reaped, deadline, monotonic_fn):
        if not writers_reaped:
            self._stop.set()
            for unused_thread, wake in self._threads:
                try:
                    wake.send(b"x")
                except OSError:
                    pass
        for thread, unused_wake in self._threads:
            remaining = deadline - monotonic_fn()
            if remaining > 0:
                thread.join(remaining)
        complete = not any(thread.is_alive()
                           for thread, unused_wake in self._threads)
        if not complete:
            self._stop.set()
            for unused_thread, wake in self._threads:
                try:
                    wake.send(b"x")
                except OSError:
                    pass
        for unused_thread, wake in self._threads:
            try:
                wake.close()
            except OSError:
                pass
        with self._lock:
            return complete, dict((name, bytes(body))
                                  for name, body in self._values.items())


def _wait_local_process(process, timeout):
    """Wait without the process-wide ``time.sleep`` monkeypatch surface."""
    end = time.monotonic() + max(0.0, timeout)
    while True:
        if process.returncode is not None:
            return process.returncode
        try:
            pid, status = os.waitpid(process.pid, os.WNOHANG)
        except ChildProcessError:
            return process.returncode
        if pid == process.pid:
            process._handle_exitstatus(status)
            return process.returncode
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        select.select([], [], [], min(0.01, remaining))


class _SupervisorClient(object):
    """Authenticated local handle for one dedicated Linux subreaper."""
    def __init__(self, peer, process, ready, monotonic_fn):
        self._peer = peer
        self._process = process
        self._monotonic = monotonic_fn or time.monotonic
        self._lock = threading.RLock()
        self._sequence = 0
        self._released = False
        self.pid = ready["pid"]
        self.start_ticks = ready["start_ticks"]

    @classmethod
    def start(cls, lock_fd, monotonic_fn, deadline):
        remaining_budget = deadline - monotonic_fn()
        if remaining_budget <= 0:
            raise socket.timeout("supervisor start deadline elapsed")
        supervisor_deadline = time.monotonic() + remaining_budget
        kind = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_DGRAM)
        parent, child = socket.socketpair(socket.AF_UNIX, kind)
        inherited = [child.fileno()]
        lock_value = -1
        if lock_fd is not None:
            inherited.append(lock_fd)
            lock_value = lock_fd
        argv = [sys.executable, os.path.abspath(__file__),
                "--_iris-iox-supervisor", str(child.fileno()),
                str(lock_value), repr(float(supervisor_deadline))]
        process = None
        try:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, pass_fds=tuple(inherited),
                close_fds=True, start_new_session=True)
            child.close()
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise socket.timeout("supervisor start deadline elapsed")
            parent.settimeout(min(5.0, remaining))
            ready, descriptors = _supervisor_receive(parent)
            for descriptor in descriptors:
                os.close(descriptor)
            if (not isinstance(ready, dict) or set(ready) != {
                    "version", "type", "pid", "start_ticks", "lock_held"} or
                    type(ready["version"]) is not int or
                    ready["version"] != 1 or ready["type"] != "ready" or
                    type(ready["pid"]) is not int or ready["pid"] != process.pid or
                    type(ready["start_ticks"]) is not int or
                    ready["start_ticks"] != _process_start_ticks(process.pid) or
                    type(ready["lock_held"]) is not bool or
                    ready["lock_held"] != (lock_fd is not None)):
                raise ValueError("invalid supervisor readiness proof")
            parent.settimeout(None)
            return cls(parent, process, ready, monotonic_fn)
        except Exception:
            child.close()
            parent.close()
            if process is not None:
                try:
                    remaining = deadline - monotonic_fn()
                    if remaining > 0:
                        process.terminate()
                        _wait_local_process(process, remaining)
                except Exception:
                    pass
            raise

    def _request(self, operation, arguments, descriptors=(), timeout=5.0,
                 allow_timeout=False):
        with self._lock:
            if self._released:
                raise OSError(errno.EPIPE, "supervisor was released")
            self._sequence += 1
            sequence = self._sequence
            message = {"version": 1, "type": "request",
                       "sequence": sequence, "operation": operation,
                       "arguments": arguments}
            previous = self._peer.gettimeout()
            timeout = min(float(timeout), 12.0)
            if timeout <= 0:
                if allow_timeout:
                    return None
                raise socket.timeout("supervisor deadline elapsed")
            self._peer.settimeout(timeout)
            try:
                _supervisor_send(self._peer, message, descriptors)
                response, received = _supervisor_receive(self._peer)
            except socket.timeout:
                if allow_timeout:
                    self._released = True
                    self._peer.close()
                    return None
                raise
            finally:
                if not self._released:
                    self._peer.settimeout(previous)
            if (not isinstance(response, dict) or set(response) != {
                    "version", "type", "sequence", "ok", "result"} or
                    type(response["version"]) is not int or
                    response["version"] != 1 or response["type"] != "response" or
                    type(response["sequence"]) is not int or
                    response["sequence"] != sequence or response["ok"] is not True or
                    not isinstance(response["result"], dict)):
                for descriptor in received:
                    os.close(descriptor)
                raise RuntimeError("invalid supervisor acknowledgement")
            return response["result"], received

    def popen(self, args, stdin=None, stdout=None, stderr=None, env=None,
              pass_fds=(), close_fds=True, start_new_session=True,
              role="transport", timeout=5.0):
        if role not in ("transport", "recipe"):
            raise ValueError("invalid supervised child role")
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                timeout <= 0):
            raise ValueError("invalid supervised spawn timeout")
        if close_fds is not True or start_new_session is not True:
            raise ValueError("supervised children require isolated descriptors and session")
        modes = []
        for value in (stdin, stdout, stderr):
            if value not in (None, subprocess.PIPE, subprocess.DEVNULL):
                raise ValueError("unsupported supervised stdio")
            modes.append(value)
        pass_fds = tuple(pass_fds)
        if (len(pass_fds) > _SUPERVISOR_MAX_FDS or
                any(type(value) is not int or value < 3 for value in pass_fds) or
                len(set(pass_fds)) != len(pass_fds)):
            raise ValueError("invalid supervised pass_fds")
        response, received = self._request("spawn", {
            "args": list(args), "env": dict(env or {}),
            "stdio": modes, "pass_fds": list(pass_fds), "role": role,
        }, descriptors=pass_fds, timeout=timeout)
        slots = response.get("stdio")
        if (set(response) != {"token", "pid", "stdio"} or
                not isinstance(response["token"], str) or
                not _HEX32.fullmatch(response["token"]) or
                type(response["pid"]) is not int or response["pid"] <= 0 or
                not isinstance(slots, dict) or set(slots) != {
                    "stdin", "stdout", "stderr"}):
            for descriptor in received:
                os.close(descriptor)
            raise RuntimeError("invalid supervisor spawn acknowledgement")
        streams = {}
        used = set()
        for name, mode in zip(("stdin", "stdout", "stderr"), modes):
            slot = slots[name]
            if mode == subprocess.PIPE:
                if type(slot) is not int or not 0 <= slot < len(received) or slot in used:
                    for descriptor in received:
                        os.close(descriptor)
                    raise RuntimeError("invalid supervisor stream descriptor")
                used.add(slot)
                streams[name] = os.fdopen(received[slot], "wb" if name == "stdin" else "rb", 0)
            elif slot is not None:
                for descriptor in received:
                    os.close(descriptor)
                raise RuntimeError("unexpected supervisor stream descriptor")
        for index, descriptor in enumerate(received):
            if index not in used:
                os.close(descriptor)
        return _SupervisedProcess(self, response["token"], response["pid"], streams)

    def reap_process(self, process, deadline):
        if not isinstance(process, _SupervisedProcess) or process._supervisor is not self:
            return False
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return False
        seconds = min(_SUPERVISOR_REAP_SECONDS, remaining)
        try:
            response, descriptors = self._request(
                "reap", {"scope": "token", "value": process._token,
                         "timeout": seconds}, timeout=seconds)
            for descriptor in descriptors:
                os.close(descriptor)
            process.returncode = response.get("returncode")
            return (set(response) == {"reaped", "remaining", "returncode"} and
                    response["reaped"] is True and response["remaining"] == 0)
        except Exception:
            return False

    def reap_role(self, role, deadline):
        return self._reap_scope("role", role, deadline)

    def reap_all(self, deadline):
        return self._reap_scope("all", None, deadline)

    def _reap_scope(self, scope, value, deadline):
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return False
        seconds = min(_SUPERVISOR_REAP_SECONDS, remaining)
        try:
            response, descriptors = self._request(
                "reap", {"scope": scope, "value": value,
                         "timeout": seconds}, timeout=seconds)
            for descriptor in descriptors:
                os.close(descriptor)
            return (set(response) == {"reaped", "remaining", "returncode"} and
                    response["reaped"] is True and response["remaining"] == 0)
        except Exception:
            return False

    def release(self, deadline):
        """Release a clean supervisor without crossing the enclosing deadline."""
        with self._lock:
            if self._released:
                return self._process.poll() is not None
        acknowledged = False
        try:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return False
            response, descriptors = self._request(
                "release", {}, timeout=remaining)
            for descriptor in descriptors:
                os.close(descriptor)
            if response != {"released": True}:
                raise RuntimeError("supervisor did not acknowledge release")
            acknowledged = True
        finally:
            with self._lock:
                self._released = True
                self._peer.close()
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return False
        try:
            _wait_local_process(self._process, remaining)
            return acknowledged
        except subprocess.TimeoutExpired:
            return False

    def abandon(self, deadline):
        """Trigger controller-EOF cleanup, bounded by the enclosing deadline."""
        with self._lock:
            if not self._released:
                self._released = True
                self._peer.close()
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return self._process.poll() is not None
        try:
            _wait_local_process(self._process, remaining)
            return True
        except subprocess.TimeoutExpired:
            return False

    def disconnect(self, deadline):
        """Trigger controller-EOF cleanup and observe supervisor exit."""
        with self._lock:
            if not self._released:
                self._released = True
                self._peer.close()
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return self._process.poll() is not None
        try:
            _wait_local_process(self._process, remaining)
            return True
        except subprocess.TimeoutExpired:
            return False

def _supervisor_children(pid):
    try:
        with open("/proc/%d/task/%d/children" % (pid, pid)) as stream:
            return [int(value) for value in stream.read().split()]
    except (OSError, ValueError):
        return []


def _supervisor_start(pid):
    try:
        return _process_start_ticks(pid)
    except (OSError, IOError, ValueError, IndexError):
        return None


def _supervisor_tree(root):
    result = {}
    pending = [root]
    while pending and len(result) <= 4096:
        pid = pending.pop()
        if pid in result:
            continue
        started = _supervisor_start(pid)
        if started is None:
            continue
        result[pid] = started
        pending.extend(_supervisor_children(pid))
    return result


def _supervisor_signal(entry, sig):
    process = entry["process"]
    root_started = entry["root_started"]
    if _supervisor_start(process.pid) == root_started:
        try:
            os.killpg(process.pid, sig)
        except OSError:
            try:
                os.kill(process.pid, sig)
            except OSError:
                pass
    for pid, started in list(entry["known"].items()):
        if _supervisor_start(pid) == started:
            try:
                os.kill(pid, sig)
            except OSError:
                pass


def _supervisor_refresh(entries):
    for entry in entries.values():
        tree = _supervisor_tree(entry["process"].pid)
        entry["known"].update(tree)
        entry["process"].poll()
    claimed = set()
    active = []
    for entry in entries.values():
        claimed.update(entry["known"])
        alive = [pid for pid, started in entry["known"].items()
                 if pid != entry["process"].pid and
                 _supervisor_start(pid) == started]
        if entry["process"].returncode is None or alive:
            active.append(entry)
    unknown = set(_supervisor_children(os.getpid())) - claimed
    if len(active) == 1:
        for pid in unknown:
            started = _supervisor_start(pid)
            if started is not None:
                active[0]["known"][pid] = started


def _supervisor_reap(entries, selected, timeout):
    if timeout <= 0:
        selected = set(selected)
        _supervisor_refresh(entries)
        for token in selected:
            entry = entries.get(token)
            if entry is not None:
                _supervisor_signal(entry, signal.SIGKILL)
        _supervisor_refresh(entries)
        remaining = 0
        for token in selected:
            entry = entries.get(token)
            if entry is None:
                continue
            process = entry["process"]
            process.poll()
            remaining += process.returncode is None
            remaining += sum(
                pid != process.pid and _supervisor_start(pid) == started
                for pid, started in entry["known"].items())
        return remaining == 0, remaining
    started = time.monotonic()
    end = started + min(timeout, _SUPERVISOR_REAP_SECONDS)
    term_end = min(end, started + 5.0)
    selected = set(selected)
    _supervisor_refresh(entries)
    for token in selected:
        entry = entries.get(token)
        if entry is not None:
            _supervisor_signal(entry, signal.SIGTERM)
    killed = False
    empty_rounds = 0
    while time.monotonic() < end:
        _supervisor_refresh(entries)
        reserved = set()
        for token, entry in entries.items():
            if token not in selected:
                reserved.update(entry["known"])
                reserved.add(entry["process"].pid)
        adopted = set(_supervisor_children(os.getpid()))
        unknown = adopted - reserved
        if selected:
            # Once a descendant is reparented to this subreaper, its former
            # ancestry is unavailable.  The controller admits only sequential
            # transport children; exclude every still-known other-role tree
            # and bind remaining orphans to the set currently being reaped.
            target = entries.get(next(iter(selected)))
            if target is not None:
                for pid in unknown:
                    started = _supervisor_start(pid)
                    if started is not None:
                        target["known"][pid] = started
        if not killed and time.monotonic() >= term_end:
            for token in selected:
                entry = entries.get(token)
                if entry is not None:
                    _supervisor_signal(entry, signal.SIGKILL)
            killed = True
        remaining = 0
        for token in selected:
            entry = entries.get(token)
            if entry is None:
                continue
            process = entry["process"]
            process.poll()
            for pid, started in list(entry["known"].items()):
                if pid == process.pid:
                    continue
                waited = 0
                try:
                    waited, unused_status = os.waitpid(pid, os.WNOHANG)
                except (OSError, ChildProcessError):
                    pass
                if waited == pid or _supervisor_start(pid) != started:
                    entry["known"].pop(pid, None)
            alive = [pid for pid, started in entry["known"].items()
                     if pid != process.pid and _supervisor_start(pid) == started]
            if process.returncode is None or alive:
                remaining += 1 + len(alive)
        if remaining == 0:
            empty_rounds += 1
            if empty_rounds >= 2:
                return True, 0
        else:
            empty_rounds = 0
        now = time.monotonic()
        phase_end = end if killed else term_end
        remaining_wait = phase_end - now
        if remaining_wait > 0:
            time.sleep(min(0.005, remaining_wait))
    if not killed:
        # A total budget shorter than the TERM allowance has no blocking KILL
        # phase.  Still issue the immediate safety signal at expiry, then
        # report the nonblocking reap observation truthfully.
        for token in selected:
            entry = entries.get(token)
            if entry is not None:
                _supervisor_signal(entry, signal.SIGKILL)
        _supervisor_refresh(entries)
    remaining = 0
    for token in selected:
        entry = entries.get(token)
        if entry is None:
            continue
        entry["process"].poll()
        if entry["process"].returncode is None:
            remaining += 1
        remaining += sum(
            pid != entry["process"].pid and _supervisor_start(pid) == started
            for pid, started in entry["known"].items())
    return remaining == 0, remaining


def _supervisor_response(peer, sequence, result):
    descriptors = result.pop("_descriptors", ())
    _supervisor_send(peer, {"version": 1, "type": "response",
        "sequence": sequence, "ok": True, "result": result}, descriptors)


def _supervisor_spawn(peer, entries, arguments, received, critical):
    keys = {"args", "env", "stdio", "pass_fds", "role"}
    if not isinstance(arguments, dict) or set(arguments) != keys:
        raise ValueError("invalid supervisor spawn request")
    argv = arguments["args"]
    environment = arguments["env"]
    modes = arguments["stdio"]
    targets = arguments["pass_fds"]
    role = arguments["role"]
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 256 or
            any(not isinstance(value, str) or not value or "\0" in value or
                len(value.encode("utf-8")) > 8192 for value in argv) or
            not isinstance(environment, dict) or len(environment) > 128 or
            any(not isinstance(key, str) or not key or "\0" in key or
                not isinstance(value, str) or "\0" in value or
                len(key.encode("utf-8")) > 256 or
                len(value.encode("utf-8")) > 8192
                for key, value in environment.items()) or
            not isinstance(modes, list) or len(modes) != 3 or
            any(value not in (None, subprocess.PIPE, subprocess.DEVNULL)
                for value in modes) or
            not isinstance(targets, list) or len(targets) != len(received) or
            len(targets) > _SUPERVISOR_MAX_FDS or
            any(type(value) is not int or not 3 <= value <= 1048575
                for value in targets) or len(set(targets)) != len(targets) or
            role not in ("transport", "recipe")):
        raise ValueError("invalid supervisor spawn binding")

    # SCM_RIGHTS chooses receiver descriptor numbers.  Duplicate each source
    # out of the requested range, then bind it to the exact number named in
    # argv/environment.  This occurs in the single-threaded supervisor before
    # Popen, so no preexec_fn is needed.
    safe = []
    floor = max([64] + targets) + 32
    for descriptor in received:
        safe.append(fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, floor))
        os.close(descriptor)
    received[:] = []
    for target in targets:
        if target in critical:
            raise ValueError("pass descriptor collides with supervisor authority")
    try:
        for source, target in zip(safe, targets):
            os.dup2(source, target, inheritable=True)
        process = subprocess.Popen(
            argv, stdin=modes[0], stdout=modes[1], stderr=modes[2],
            env=environment, pass_fds=tuple(targets), close_fds=True,
            start_new_session=True)
    finally:
        for descriptor in safe:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for target in targets:
            try:
                os.close(target)
            except OSError:
                pass
    token = os.urandom(16).hex()
    entries[token] = {"process": process, "role": role,
                      "root_started": _process_start_ticks(process.pid),
                      "known": {process.pid: _process_start_ticks(process.pid)}}
    streams = {"stdin": None, "stdout": None, "stderr": None}
    outgoing = []
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, name)
        if stream is not None:
            streams[name] = len(outgoing)
            outgoing.append(stream.fileno())
    result = {"token": token, "pid": process.pid, "stdio": streams,
              "_descriptors": tuple(outgoing)}
    # The sent SCM_RIGHTS copies become the controller's sole pipe endpoints.
    # Close the supervisor copies immediately after send in the caller.
    result["_close_streams"] = tuple(
        stream for stream in (process.stdin, process.stdout, process.stderr)
        if stream is not None)
    return result


def _supervisor_main(control_fd, lock_fd, deadline):
    import ctypes
    import resource
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        return 111
    descriptor_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    authority_floor = max(64, min(int(descriptor_limit) - 16, 65520))
    moved_control = fcntl.fcntl(
        control_fd, fcntl.F_DUPFD_CLOEXEC, authority_floor)
    os.close(control_fd)
    peer = socket.socket(fileno=moved_control)
    if lock_fd >= 0:
        moved_lock = fcntl.fcntl(
            lock_fd, fcntl.F_DUPFD_CLOEXEC, authority_floor)
        os.close(lock_fd)
        lock_fd = moved_lock
    lock_held = lock_fd >= 0
    if lock_held:
        metadata = os.fstat(lock_fd)
        if (not stat.S_ISREG(metadata.st_mode) or
                metadata.st_uid != os.geteuid() or
                stat.S_IMODE(metadata.st_mode) != 0o600):
            return 112
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize("3i"))
    unused_pid, uid, unused_gid = struct.unpack("3i", credentials)
    if uid != os.geteuid():
        return 113
    entries = {}
    released = False
    try:
        _supervisor_send(peer, {"version": 1, "type": "ready",
            "pid": os.getpid(), "start_ticks": _process_start_ticks(os.getpid()),
            "lock_held": lock_held})
        while True:
            _supervisor_refresh(entries)
            try:
                request, received = _supervisor_receive(peer)
            except EOFError:
                break
            try:
                if (not isinstance(request, dict) or set(request) != {
                        "version", "type", "sequence", "operation", "arguments"} or
                        type(request["version"]) is not int or
                        request["version"] != 1 or request["type"] != "request" or
                        type(request["sequence"]) is not int or request["sequence"] <= 0 or
                        not isinstance(request["arguments"], dict)):
                    raise ValueError("invalid supervisor request")
                operation = request["operation"]
                arguments = request["arguments"]
                result = None
                close_streams = ()
                if operation == "spawn":
                    result = _supervisor_spawn(
                        peer, entries, arguments, received,
                        {peer.fileno(), lock_fd})
                    close_streams = result.pop("_close_streams")
                elif received:
                    raise ValueError("unexpected supervisor descriptors")
                elif operation in ("poll", "wait", "signal"):
                    if set(arguments) not in (
                            {"token"}, {"token", "timeout"},
                            {"token", "signal"}):
                        raise ValueError("invalid process request")
                    token = arguments.get("token")
                    if token not in entries:
                        raise ValueError("unknown supervised process")
                    process = entries[token]["process"]
                    if operation == "poll":
                        result = {"returncode": process.poll()}
                    elif operation == "wait":
                        timeout = arguments.get("timeout")
                        if (not isinstance(timeout, (int, float)) or
                                isinstance(timeout, bool) or
                                not 0 <= timeout <= _SUPERVISOR_REAP_SECONDS):
                            raise ValueError("invalid process wait")
                        try:
                            code = process.wait(timeout=timeout)
                            result = {"returncode": code, "timed_out": False}
                        except subprocess.TimeoutExpired:
                            result = {"returncode": None, "timed_out": True}
                    else:
                        sig = arguments.get("signal")
                        if (not isinstance(sig, int) or isinstance(sig, bool) or
                                sig not in (signal.SIGTERM, signal.SIGKILL,
                                            signal.SIGINT, signal.SIGHUP)):
                            raise ValueError("invalid process signal")
                        _supervisor_signal(entries[token], sig)
                        result = {"returncode": process.poll()}
                elif operation == "reap":
                    if set(arguments) != {"scope", "value", "timeout"}:
                        raise ValueError("invalid reap request")
                    scope, value = arguments["scope"], arguments["value"]
                    timeout = arguments["timeout"]
                    if (not isinstance(timeout, (int, float)) or
                            isinstance(timeout, bool) or
                            not 0 <= timeout <= _SUPERVISOR_REAP_SECONDS):
                        raise ValueError("invalid reap timeout")
                    if scope == "token" and value in entries:
                        selected = [value]
                    elif scope == "role" and value in ("transport", "recipe"):
                        selected = [token for token, entry in entries.items()
                                    if entry["role"] == value]
                    elif scope == "all" and value is None:
                        selected = list(entries)
                    else:
                        raise ValueError("invalid reap scope")
                    reaped, remaining = _supervisor_reap(entries, selected, timeout)
                    returncode = (entries[value]["process"].returncode
                                  if scope == "token" else None)
                    result = {"reaped": reaped, "remaining": remaining,
                              "returncode": returncode}
                elif operation == "release" and arguments == {}:
                    remaining_budget = max(0.0, deadline - time.monotonic())
                    reaped, remaining = _supervisor_reap(
                        entries, list(entries), remaining_budget)
                    if not reaped or remaining:
                        raise ValueError("supervisor release before reap")
                    result = {"released": True}
                    released = True
                else:
                    raise ValueError("unknown supervisor operation")
                _supervisor_response(peer, request["sequence"], result)
                for stream in close_streams:
                    stream.close()
                if released:
                    break
            finally:
                for descriptor in received:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
    except Exception:
        pass
    finally:
        if not released:
            remaining_budget = max(0.0, deadline - time.monotonic())
            if remaining_budget > 0:
                _supervisor_reap(entries, list(entries), remaining_budget)
            else:
                _supervisor_refresh(entries)
                for entry in entries.values():
                    _supervisor_signal(entry, signal.SIGKILL)
                    entry["process"].poll()
        peer.close()
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass
    return 0 if released else 114


def _load_or_create_controller_id(record_store, state_dir):
    """Return the persistent controller domain, creating it once if empty.

    This private bootstrap seam keeps production startup race-safe while the
    public ``IoxController`` constructor retains its strict, caller-supplied
    authority contract.
    """
    raw_root = os.fspath(state_dir)
    if (not isinstance(raw_root, str) or not raw_root or
            not os.path.isabs(raw_root)):
        raise ValueError("state_dir must be a non-empty absolute path")
    _reject_symlink_components(raw_root)
    root = os.path.realpath(raw_root)
    if os.path.abspath(raw_root) != root and os.path.lexists(raw_root):
        raise ValueError("state_dir must not traverse symlinks")
    raw_store_path = os.fspath(record_store.path)
    if (not isinstance(raw_store_path, str) or not raw_store_path or
            not os.path.isabs(raw_store_path)):
        raise ValueError("record store path must be absolute")
    _reject_symlink_components(raw_store_path)
    store_path = os.path.realpath(raw_store_path)
    if os.path.dirname(store_path) != root:
        raise ValueError("state_dir and record-store authority diverge")
    if not os.path.isdir(root):
        try:
            os.makedirs(root, 0o700)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    if os.path.abspath(raw_root) != root:
        raise ValueError("state_dir must not traverse symlinks")
    root_metadata = os.lstat(raw_root)
    if (stat.S_ISLNK(root_metadata.st_mode) or
            not stat.S_ISDIR(root_metadata.st_mode) or
            root_metadata.st_uid != os.geteuid()):
        raise ValueError("unsafe state_dir")
    iox_directory = os.path.join(root, "iox")
    try:
        _safe_directory(iox_directory, create=True)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        _safe_directory(iox_directory)
    authority_path = os.path.join(iox_directory, "authority.json")

    def load():
        authority = _read_json_strict(authority_path, 16 * 1024)
        if (not isinstance(authority, dict) or set(authority) !=
                {"schema_version", "controller_id", "record_store"} or
                type(authority.get("schema_version")) is not int or
                authority.get("schema_version") != 1 or
                not isinstance(authority.get("controller_id"), str) or
                not _HEX32.fullmatch(authority["controller_id"]) or
                authority.get("record_store") != store_path):
            raise ValueError("IOx authority mismatch")
        return authority["controller_id"]

    if os.path.lexists(authority_path):
        return load()
    try:
        records = record_store.list(strict=True)
    except TypeError:
        records = record_store.list()
    if any(record.get("iox_verification") is not None for record in records):
        raise ValueError("IOx authority missing for existing journal")
    candidate = os.urandom(16).hex()
    try:
        _durable_json(authority_path, {
            "schema_version": 1, "controller_id": candidate,
            "record_store": store_path}, replace=False)
        return candidate
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        return load()


def _public_journal(journal):
    if journal is None:
        return None
    keys = ("schema_version", "record_id", "transaction_id", "revision",
            "board_identity", "prior_state", "current_state", "phase",
            "unresolved", "created_at", "updated_at", "observed_at",
            "terminal_at")
    value = dict((key, journal[key]) for key in keys)
    value["error_category"] = (journal.get("error") or {}).get("category")
    if journal.get("instruction_cleanup_pending"):
        value["instruction_cleanup_pending"] = True
    return value


# The operator runbook for a journal the controller cannot resolve on its
# own (docs/zensical/operations.md, "Recovering an IOx attempt cut off
# mid-run"). Carried in the refusal's detail because a forced teardown's
# result reports the operation's own null binding, not the predecessor's,
# so the log line is the only place the operator sees which record to
# reconcile (issue #231).
_RECONCILE_RUNBOOK = ("https://cisco-open.github.io/intelligent-release-image-staging/"
                      "docs/operations/#recovering-an-iox-attempt-cut-off-mid-run")
# gui_onboard refuses a controller detail longer than this.
_DETAIL_LIMIT = 512


def _reconciliation_detail(summary, journal):
    """Name the exact reconcile-enabled binding in a reconciliation refusal.

    The binding must be the journal's *current* revision: reconcile-enabled
    compares record id, transaction id and revision against the stored
    journal and refuses a stale triple, and recovery may have just written
    an ``indeterminate`` event that advanced the revision.
    """
    if not isinstance(journal, dict):
        return summary
    return _bounded_text(
        "%s: IOx verification journal for record %s (transaction %s, "
        "revision %s) is %s; enable app signature verification on the "
        "device, then run iox_verification.py reconcile-enabled with these "
        "values (%s)" % (
            summary, journal.get("record_id"), journal.get("transaction_id"),
            journal.get("revision"), journal.get("phase"), _RECONCILE_RUNBOOK),
        _DETAIL_LIMIT)


def _session_summary(fence):
    keys = ("attempt_id", "job_id", "device_id", "board_identity",
            "operation", "teardown_mode", "record_id", "state")
    value = dict((key, fence[key]) for key in keys)
    value["mutation_blocked"] = fence["state"] == "active"
    return value


class _Attempt(object):
    def __init__(self, controller, operation, request, cancel, recovery=False,
                 started=None):
        self.controller = controller
        self.operation = operation
        self.request = request
        self.cancel = cancel
        self.recovery = recovery
        self.attempt_id = os.urandom(16).hex()
        self.started = (controller._monotonic() if started is None else
                        started)
        self.session_deadline = self.started + controller.session_seconds
        self.ordinary_deadline = self.session_deadline - controller.reserve_seconds
        self.command_id = 0
        self.transcript = None
        self.transport = None
        self.supervisor = None
        self.lock_fd = None
        self.fence = None
        self.fence_owned = False
        self.fence_path = None
        self.board = None
        self.identity = None
        self.record_id = _get(request, "record_id") if request is not None else None
        self.journal = None
        self.primary = None
        self.recovery_code = None
        self.recipe_returncode = None
        self.snapshot = None
        self.upload_deadline = None
        self.instruction_snapshot = None
        self.instruction_upload_deadline = None
        self.credentials = {}
        self.notice = ""
        self.target = copy.deepcopy(_get(request, "target", {})) if request is not None else {}
        self.finished_protocol = False
        self.prechecked_obligations = {}
        self.safety_recovery = False
        self.shutdown = threading.Event()
        self.continuations = {}
        self.operation_results = []
        self.durability_uncertain = False
        self.retire_device_on_success = False
        self.owner_thread = threading.current_thread()

    def remaining(self):
        return self.session_deadline - self.controller._monotonic()

    def check(self):
        if self.is_cancelled():
            self.invalidate_continuations()
            raise _ControllerFailure("cancelled", "operation cancelled", 130)
        if self.controller._monotonic() >= self.session_deadline:
            raise _ControllerFailure("timeout", "IOx session deadline elapsed", 4)

    def is_cancelled(self):
        return (self.shutdown.is_set() or
                (not self.safety_recovery and _cancelled(self.cancel)))

    def invalidate_continuations(self):
        self.continuations.clear()

    def deadline(self, seconds, ordinary=False):
        now = self.controller._monotonic()
        enclosing = self.ordinary_deadline if ordinary else self.session_deadline
        return min(now + seconds, enclosing)

    def next_context(self, purpose, kind="ssh", record=True):
        self.command_id += 1
        journal = self.journal if record else None
        return {
            "schema_version": 1, "type": "command_start",
            "command_id": self.command_id, "kind": kind, "purpose": purpose,
            "board_identity": self.board,
            "record_id": journal.get("record_id") if journal else None,
            "transaction_id": journal.get("transaction_id") if journal else None,
            "revision": journal.get("revision") if journal else None,
            "phase": journal.get("phase") if journal else None,
            "started_at": int(self.controller._now()),
        }


class _IoxContinuation(object):
    """Opaque, same-process, one-use device-I/O continuation."""
    __slots__ = ("_pid", "_token")

    def __init__(self, token):
        self._pid = os.getpid()
        self._token = token

    def __reduce__(self):
        raise TypeError("IOx continuations cannot be serialized")


class IoxController(object):
    """Run IOx work under durable physical-board authority."""
    _mints_enrollment_token = True

    def __init__(self, record_store, authority_config, transport_factory,
                 now_fn, monotonic_fn):
        self.store = record_store
        self.config = dict(authority_config)
        self.transport_factory = transport_factory
        self._now = now_fn
        self._monotonic = monotonic_fn
        self._closed = False
        self._active = set()
        self._active_lock = threading.Lock()
        self._admission_lock = threading.Lock()
        try:
            import iox_transport
            self._strict_target = transport_factory is iox_transport.IoxTransport
        except Exception:
            self._strict_target = False
        self._validate_config()
        self._initialize_authority()

    def _validate_config(self):
        controller_id = self.config.get("controller_id")
        if (not isinstance(controller_id, str) or
                not _HEX32.fullmatch(controller_id)):
            raise ValueError("invalid controller_id")
        self.controller_id = controller_id
        raw_state_dir = self.config.get("state_dir")
        if (not isinstance(raw_state_dir, str) or not raw_state_dir or
                not os.path.isabs(raw_state_dir)):
            raise ValueError("state_dir must be a non-empty absolute path")
        _reject_symlink_components(raw_state_dir)
        if os.path.lexists(raw_state_dir):
            if os.path.abspath(raw_state_dir) != os.path.realpath(raw_state_dir):
                raise ValueError("state_dir must not traverse symlinks")
            state_metadata = os.lstat(raw_state_dir)
            if (stat.S_ISLNK(state_metadata.st_mode) or
                    not stat.S_ISDIR(state_metadata.st_mode) or
                    state_metadata.st_uid != os.geteuid()):
                raise ValueError("unsafe state_dir")
        configured_root = os.path.realpath(raw_state_dir)
        store_root = os.path.realpath(os.path.dirname(self.store.path))
        if not os.path.isabs(self.store.path) or not store_root:
            raise ValueError("record store must have an absolute authority root")
        # Deployment records resolve transcript evidence relative to their own
        # durable state root.  Keep one authority tree even when an older
        # caller supplied its enclosing application-state directory here.
        self.state_dir = _safe_state_root(store_root)
        if configured_root != store_root:
            if os.path.dirname(store_root) != configured_root:
                raise ValueError("state_dir and record-store authority diverge")
            self.config["state_dir"] = store_root
        session = self.config.get("session_seconds", 7200)
        reserve = self.config.get("restoration_reserve_seconds", 180)
        if type(session) is not int or session <= 0 or session > _MAX_INT:
            raise ValueError("invalid session_seconds")
        if type(reserve) is not int or reserve != 180:
            raise ValueError("restoration_reserve_seconds must be 180")
        self.session_seconds = session
        self.reserve_seconds = reserve
        appid = self.config.get("application_id", "iris")
        if (not isinstance(appid, str) or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", appid) is None):
            raise ValueError("invalid IOx application_id")
        self.application_id = appid
        catalog_url = self.config.get("catalog_url")
        if catalog_url is not None:
            self.config["catalog_url"] = _https_url(catalog_url)
        # The device-facing artifact server the IOx device fetches from, and
        # the directory it serves (where the per-device instruction envelope
        # is published for the span of its fetch).
        artifact_url = self.config.get("artifact_url")
        if artifact_url is not None:
            try:
                self.config["artifact_url"] = _https_url(artifact_url)
            except ValueError:
                raise ValueError("invalid IOx artifact URL")
        elif self._strict_target:
            raise ValueError("IOx artifact URL is required")
        artifacts_dir = self.config.get("artifacts_dir")
        if artifacts_dir is not None:
            if (not isinstance(artifacts_dir, str) or
                    not os.path.isabs(artifacts_dir) or
                    any(ord(character) < 32 for character in artifacts_dir)):
                raise ValueError("IOx artifacts_dir must be an absolute path")
        elif self._strict_target:
            raise ValueError("IOx artifacts directory is required")
        certificate_path = self.config.get("catalog_certificate_path")
        if self._strict_target and certificate_path is None:
            raise ValueError("IOx catalog certificate is required")
        if certificate_path is not None:
            descriptor = _open_public_certificate(
                certificate_path, self._strict_target)
            os.close(descriptor)
        if self._strict_target and catalog_url is None:
            raise ValueError("IOx catalog URL is required")
        if not callable(self.config.get(
                "instruction_bootstrap_materializer")):
            raise ValueError("IOx instruction bootstrap materializer is required")
        for key, default in (("install_timeout", 300),
                             ("activate_timeout", 300),
                             ("start_timeout", 300),
                             ("state_poll", 5)):
            value = self.config.get(key, default)
            if type(value) is not int or not 1 <= value <= 86400:
                raise ValueError("invalid %s" % key)
            self.config[key] = value
        limits = self.config.get("test_limits")
        expected = frozenset(("session_files", "transcript_files",
                              "ordinary_transcripts", "active_fences"))
        if limits is None:
            limits = {"session_files": _SESSION_FILES,
                      "transcript_files": _TRANSCRIPT_FILES,
                      "ordinary_transcripts": _ORDINARY_TRANSCRIPTS,
                      "active_fences": _ACTIVE_FENCES}
        if not isinstance(limits, dict) or frozenset(limits) != expected:
            raise ValueError("invalid test_limits")
        maxima = {"session_files": _SESSION_FILES,
                  "transcript_files": _TRANSCRIPT_FILES,
                  "ordinary_transcripts": _ORDINARY_TRANSCRIPTS,
                  "active_fences": _ACTIVE_FENCES}
        for key in expected:
            if type(limits[key]) is not int or not 1 <= limits[key] <= maxima[key]:
                raise ValueError("invalid test limit: %s" % key)
        if limits["ordinary_transcripts"] > limits["transcript_files"] or \
                limits["active_fences"] > limits["session_files"]:
            raise ValueError("inconsistent test limits")
        self.limits = limits

    def _initialize_authority(self):
        if not os.path.isdir(self.state_dir):
            os.makedirs(self.state_dir, 0o700)
        self.iox_dir = os.path.join(self.state_dir, "iox")
        self.lock_dir = os.path.join(self.iox_dir, "locks")
        self.session_dir = os.path.join(self.iox_dir, "sessions")
        self.transcript_dir = os.path.join(self.iox_dir, "transcripts")
        self.snapshot_dir = os.path.join(self.iox_dir, "snapshots")
        authority_path = os.path.join(self.iox_dir, "authority.json")
        store_path = os.path.realpath(self.store.path)
        configured = self.config.get("record_store")
        if configured is not None:
            if not isinstance(configured, str) or not configured:
                raise ValueError("record_store path is invalid")
            if not os.path.isabs(configured):
                # The historical private constructor accepted only a store
                # basename, resolved under its already validated state root.
                # Do not interpret a relative path against the process CWD.
                if (configured != os.path.basename(configured) or
                        configured in (".", "..")):
                    raise ValueError("relative record_store path is invalid")
                configured = os.path.join(self.state_dir, configured)
            _reject_symlink_components(configured)
            configured_path = configured
            if os.path.realpath(configured_path) != store_path:
                raise ValueError("record_store authority mismatch")
        journals_exist = False
        try:
            records = self.store.list(strict=True)
            journals_exist = any(record.get("iox_verification") is not None
                                 for record in records)
        except TypeError:
            records = self.store.list()
            journals_exist = any(record.get("iox_verification") is not None
                                 for record in records)
        if os.path.lexists(authority_path):
            _safe_directory(self.iox_dir)
            authority = _read_json_strict(authority_path, 16 * 1024)
            if set(authority) != {"schema_version", "controller_id", "record_store"}:
                raise ValueError("malformed IOx authority")
            if (type(authority["schema_version"]) is not int or
                    authority["schema_version"] != 1 or
                    authority["controller_id"] != self.controller_id or
                    authority["record_store"] != store_path):
                raise ValueError("IOx authority mismatch")
        else:
            # Persisted journals require their original controller-domain
            # authority.  In-memory test stores have no durable store path and
            # therefore cannot carry that cross-restart binding.
            if journals_exist and os.path.exists(store_path):
                raise ValueError("IOx authority missing for existing journal")
            _safe_directory(self.iox_dir, create=True)
            _durable_json(authority_path, {
                "schema_version": 1, "controller_id": self.controller_id,
                "record_store": store_path}, replace=False)
        for path in (self.iox_dir, self.lock_dir, self.session_dir,
                     self.transcript_dir, self.snapshot_dir):
            _safe_directory(path, create=path != self.iox_dir)
        self._scan_authority()

    def _scan_authority(self):
        self._scan_directory(self.lock_dir, ".lock",
                             self.limits["session_files"],
                             _SESSION_FILE_BYTES)
        sessions = self._scan_directory(self.session_dir, ".lock.json",
                                        self.limits["session_files"],
                                        _SESSION_FILE_BYTES)
        transcripts = self._scan_directory(self.transcript_dir, ".transcript",
                                           self.limits["transcript_files"],
                                           _TRANSCRIPT_FILE_BYTES)
        active = 0
        for path in sessions:
            fence = self._read_sibling_fence(path)
            if fence is None:
                continue
            self._validate_fence(fence, path)
            active += fence["state"] == "active"
        if active > self.limits["active_fences"]:
            raise ValueError("too many active IOx fences")
        store_lock = self.store.path + ".lock"
        if os.path.lexists(store_lock):
            directory_fd = _open_directory_anchor(
                os.path.dirname(store_lock))
            name = os.path.basename(store_lock)
            flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0))
            try:
                before = os.stat(name, dir_fd=directory_fd,
                                 follow_symlinks=False)
                descriptor = os.open(name, flags, dir_fd=directory_fd)
                try:
                    metadata = os.fstat(descriptor)
                    after = os.stat(name, dir_fd=directory_fd,
                                    follow_symlinks=False)
                    if (not stat.S_ISREG(metadata.st_mode) or
                            stat.S_IMODE(metadata.st_mode) != 0o600 or
                            metadata.st_uid != os.geteuid() or
                            metadata.st_nlink != 1 or
                            metadata.st_size > _SESSION_FILE_BYTES or
                            (before.st_dev, before.st_ino) !=
                            (metadata.st_dev, metadata.st_ino) or
                            (after.st_dev, after.st_ino) !=
                            (metadata.st_dev, metadata.st_ino)):
                        raise ValueError(
                            "unsafe deployment-record store lock")
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory_fd)
        return sessions, transcripts

    @staticmethod
    def _stable_authority_entry(directory_fd, name, flags, maximum):
        """Require a private regular file that held still for three looks.

        Returns False for an entry that vanished (a reaped fence, a renamed
        temporary). An entry whose identity or size moved between the looks
        is a sibling attempt replacing it atomically; look again a bounded
        number of times before calling it unsafe. Type, owner and mode are
        refused at once.
        """
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        for attempt in range(_AUTHORITY_ENTRY_ATTEMPTS):
            try:
                before = os.stat(name, dir_fd=directory_fd,
                                 follow_symlinks=False)
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                return False
            try:
                metadata = os.fstat(descriptor)
                try:
                    after = os.stat(name, dir_fd=directory_fd,
                                    follow_symlinks=False)
                except FileNotFoundError:
                    return False
            finally:
                os.close(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_uid != os.geteuid() or
                    metadata.st_size > maximum):
                raise ValueError("unsafe IOx authority entry")
            if (metadata.st_nlink == 1 and
                    all(getattr(before, field) == getattr(metadata, field) and
                        getattr(after, field) == getattr(metadata, field)
                        for field in fields)):
                return True
            time.sleep(0.02)
        raise ValueError("unsafe IOx authority entry")

    def _scan_directory(self, directory, suffix, limit, maximum):
        patterns = {
            ".lock": re.compile(r"^[0-9a-f]{64}\.lock$"),
            ".lock.json": re.compile(r"^[0-9a-f]{64}\.lock\.json$"),
            ".transcript": re.compile(r"^[0-9a-f]{32}\.transcript$"),
        }
        pattern = patterns.get(suffix)
        if pattern is None:
            raise ValueError("unknown IOx authority directory class")
        result = []
        directory_fd = _open_directory_anchor(directory, required_mode=0o700)
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
        directory_before = os.fstat(directory_fd)
        try:
            anchored_directory = "/proc/self/fd/%d" % directory_fd
            with os.scandir(anchored_directory) as entries:
                for entry in entries:
                    name = entry.name
                    if len(result) >= limit:
                        raise ValueError("IOx authority capacity exceeded")
                    if (isinstance(name, str) and
                            _AUTHORITY_TEMPORARY.fullmatch(name)):
                        # A sibling attempt mid-write: the transcript
                        # writer and the fence writer both stage a private
                        # temporary next to the file and rename it into
                        # place. Not an entry, not foreign.
                        continue
                    if (not isinstance(name, str) or
                            pattern.fullmatch(name) is None):
                        raise ValueError("unknown IOx authority entry")
                    if not self._stable_authority_entry(
                            directory_fd, name, flags, maximum):
                        continue
                    result.append(os.path.join(directory, name))
            directory_after = os.fstat(directory_fd)
            named_after = os.lstat(directory)
            directory_fields = ("st_dev", "st_ino", "st_uid", "st_mode",
                                "st_nlink")
            if (not stat.S_ISDIR(directory_after.st_mode) or
                    directory_after.st_uid != os.geteuid() or
                    stat.S_IMODE(directory_after.st_mode) != 0o700 or
                    any(getattr(directory_before, field) !=
                        getattr(directory_after, field) or
                        getattr(directory_before, field) !=
                        getattr(named_after, field)
                        for field in directory_fields)):
                raise ValueError("authority directory changed during scan")
        finally:
            os.close(directory_fd)
        return result

    @staticmethod
    def _read_sibling_fence(path):
        """Read another attempt's fence, tolerating that attempt's own writes.

        Fences are replaced atomically (temporary file + rename), so a
        sibling attempt updating its fence while this one is admitted gives
        the strict reader a file whose inode or size changed between its
        looks -- legitimate churn, not tampering, and the next read sees a
        whole new file. Four devices onboarded in the same second failed
        one of them with 'session fence admission failed' (2026-09-10). A
        fence that disappears was reaped and no longer counts.
        """
        last = None
        for _ in range(4):
            try:
                return _read_json_strict(path, _SESSION_FILE_BYTES)
            except FileNotFoundError:
                return None
            except ValueError as exc:
                text = str(exc)
                if ("unsafe authority file" not in text and
                        "changed during read" not in text):
                    raise
                last = exc
                time.sleep(0.05)
        raise last

    def _validate_fence(self, fence, path=None):
        keys = set("schema_version controller_id board_identity attempt_id device_id job_id operation teardown_mode record_id boot_id supervisor_pid supervisor_start_ticks transcript_ref state created_at updated_at".split())
        if not isinstance(fence, dict) or set(fence) != keys:
            raise ValueError("malformed IOx session fence")
        if (type(fence["schema_version"]) is not int or
                fence["schema_version"] != 1 or
                not isinstance(fence["controller_id"], str) or
                fence["controller_id"] != self.controller_id):
            raise ValueError("foreign IOx session fence")
        if (not isinstance(fence["board_identity"], str) or
                not _BOARD_ID.fullmatch(fence["board_identity"]) or
                not isinstance(fence["attempt_id"], str) or
                not _HEX32.fullmatch(fence["attempt_id"])):
            raise ValueError("invalid IOx session identity")
        if (not isinstance(fence["job_id"], str) or
                not _HEX16.fullmatch(fence["job_id"])):
            raise ValueError("invalid IOx session job")
        if fence["state"] not in ("active", "reaped"):
            raise ValueError("invalid IOx session state")
        if fence["operation"] not in ("install", "uninstall", "recover", "reconcile_enabled"):
            raise ValueError("invalid IOx session operation")
        if fence["teardown_mode"] not in ("none", "recorded", "force_agent_only"):
            raise ValueError("invalid IOx teardown mode")
        if (not isinstance(fence["device_id"], str) or
                not _BOARD_ID.fullmatch(fence["device_id"])):
            raise ValueError("invalid IOx session device")
        if (fence["record_id"] is not None and
                (not isinstance(fence["record_id"], str) or
                 not _RECORD_ID.fullmatch(fence["record_id"]))):
            raise ValueError("invalid IOx session record")
        if (not isinstance(fence["boot_id"], str) or
                not _BOOT_ID.fullmatch(fence["boot_id"])):
            raise ValueError("invalid IOx session boot identity")
        for key in ("supervisor_pid", "supervisor_start_ticks",
                    "created_at", "updated_at"):
            if (type(fence[key]) is not int or
                    not 0 <= fence[key] <= _MAX_INT):
                raise ValueError("invalid IOx session timestamp or process")
        if (fence["supervisor_pid"] <= 0 or
                fence["updated_at"] < fence["created_at"]):
            raise ValueError("invalid IOx session timestamp or process")
        reference = fence["transcript_ref"]
        if (not isinstance(reference, dict) or set(reference) != {
                "id", "attempt_id", "stored_bytes", "observed_bytes",
                "dropped_bytes", "truncated"} or
                not isinstance(reference["id"], str) or
                not _HEX32.fullmatch(reference["id"]) or
                reference["attempt_id"] != reference["id"] or
                type(reference["stored_bytes"]) is not int or
                not 1 <= reference["stored_bytes"] <=
                _TRANSCRIPT_FILE_BYTES or
                type(reference["observed_bytes"]) is not int or
                not 0 <= reference["observed_bytes"] <= _MAX_INT or
                type(reference["dropped_bytes"]) is not int or
                not 0 <= reference["dropped_bytes"] <=
                reference["observed_bytes"] or
                type(reference["truncated"]) is not bool or
                reference["attempt_id"] != fence["attempt_id"]):
            raise ValueError("invalid IOx session transcript reference")
        import iox_transport
        iox_transport._load_transcript_prefix(
            self.state_dir, reference, self.controller_id)
        if path is not None:
            expected = _board_key(fence["board_identity"]) + ".json"
            if os.path.basename(path) != expected:
                raise ValueError("session fence board-key mismatch")

    def _authority_store_lock(self, attempt):
        lock_method = getattr(self.store, "_store_lock", None)
        owner = getattr(lock_method, "__self__", None)
        if isinstance(owner, deployment_records.DeploymentRecordStore):
            return _StoreLockContext(lock_method(
                deadline=attempt.session_deadline,
                monotonic_fn=self._monotonic))
        if callable(lock_method):
            return lock_method()
        return _NoopContext()

    def _store_call(self, method_name, args, attempt=None, deadline=None,
                    kwargs=None, mutation=False, required_completion=False):
        method = getattr(self.store, method_name)
        call_kwargs = dict(kwargs or {})
        if isinstance(self.store, deployment_records.DeploymentRecordStore):
            bound = (attempt.session_deadline if attempt is not None else
                     deadline)
            if bound is not None:
                call_kwargs["deadline"] = bound
                call_kwargs["monotonic_fn"] = self._monotonic
        if attempt is not None:
            if required_completion:
                if self._monotonic() >= attempt.session_deadline:
                    raise _ControllerFailure(
                        "timeout", "IOx session deadline elapsed", 4)
            else:
                attempt.check()
        try:
            result = method(*args, **call_kwargs)
        except deployment_records.StoreLockTimeout:
            raise _ControllerFailure(
                "timeout", "deployment-record store lock timed out", 4)
        # A durable mutation may commit before its return value is published
        # into the attempt.  Its caller publishes first; the next operation
        # admission observes cancellation or expiry.  Reads retain both checks.
        if attempt is not None and not mutation:
            attempt.check()
        return result

    def _new_attempt(self, operation, request, cancel, recovery=False,
                     started=None):
        with self._admission_lock:
            if self._closed:
                raise ValueError("controller is closed")
            attempt = _Attempt(
                self, operation, request, cancel, recovery, started=started)
            attempt.check()
            try:
                with self._authority_store_lock(attempt):
                    attempt.check()
                    sessions, transcripts = self._scan_authority()
                    expected_board = _get(
                        _get(request, "target", {}), "device_identity")
                    if (len(sessions) >= self.limits["session_files"] and
                            isinstance(expected_board, str) and
                            _BOARD_ID.fullmatch(expected_board) is not None and
                            os.path.join(
                                self.session_dir,
                                _board_key(expected_board) + ".json") not in
                            sessions):
                        raise _ControllerFailure(
                            "journal_durability",
                            "session fence capacity exhausted", 5)
                    ceiling = (self.limits["transcript_files"] if recovery else
                               self.limits["ordinary_transcripts"])
                    if len(transcripts) >= ceiling:
                        raise _ControllerFailure(
                            "transcript_limit",
                            "transcript capacity exhausted", 5)
                    import iox_transport
                    attempt.check()
                    try:
                        attempt.transcript = iox_transport._TranscriptWriter(
                            self.state_dir, attempt.attempt_id,
                            self.controller_id, created_at=int(self._now()))
                    except Exception:
                        raise _ControllerFailure(
                            "transcript_limit",
                            "transcript creation failed", 5)
            except _ControllerFailure:
                raise
            except Exception:
                raise _ControllerFailure(
                    "journal_durability",
                    "authority admission failed", 5)
            with self._active_lock:
                if self._closed:
                    raise ValueError("controller is closed")
                self._active.add(attempt)
            return attempt

    def _transport_config(self, attempt):
        target = attempt.target
        user = attempt.credentials.get("device_user", "")
        password = attempt.credentials.get("device_pass", "")
        enable = attempt.credentials.get("enable_secret") or password
        credentials = {
            "DEVICE_PASS": password, "DEVICE_ENABLE": enable,
            "DEVICE_SSH_PASS": password, "CATALOG_TOKEN":
                attempt.credentials.get("catalog_token", ""),
            "SSHPASS": password,
        }
        return {
            "host": str(_get(target, "host", "")),
            "port": _get(target, "port", 22), "user": str(user),
            "state_dir": self.state_dir,
            "tmp_dir": os.path.join(self.iox_dir, "tmp-" + attempt.attempt_id),
            "home": self.state_dir, "attempt_id": attempt.attempt_id,
            "controller_id": self.controller_id,
            "ssh_binary": self.config.get("ssh_binary", "/usr/bin/ssh"),
            "scp_binary": self.config.get("scp_binary", "/usr/bin/scp"),
            "sshpass_binary": self.config.get("sshpass_binary", "/usr/bin/sshpass"),
            "ssh_policy_path": self.config.get("ssh_policy_path",
                os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lab", "iris-ssh-policy.sh"))),
            "ssh_policy_env": dict(self.config.get("ssh_policy_env", {})),
            "credentials": credentials, "command_contexts": {},
            "session_deadline": attempt.session_deadline,
            "cancel": attempt.is_cancelled,
        }

    def _make_transport(self, attempt, supervisor=None):
        config = self._transport_config(attempt)
        transport = self.transport_factory(config, attempt.transcript,
                                           supervisor, self._monotonic)
        transport._iris_config = config
        return transport

    def _start_supervisor(self, attempt):
        if attempt.supervisor is not None:
            raise _ControllerFailure(
                "journal_durability", "duplicate IOx supervisor", 5)
        try:
            supervisor = _SupervisorClient.start(
                attempt.lock_fd, self._monotonic,
                attempt.session_deadline)
        except Exception:
            raise _ControllerFailure(
                "descendant_unreaped", "IOx supervisor unavailable", 5)
        attempt.supervisor = supervisor
        # Its inherited open-file description keeps the flock held.  LOCK_UN
        # here would also unlock the supervisor's copy.
        if attempt.lock_fd is not None:
            os.close(attempt.lock_fd)
            attempt.lock_fd = None

    def _command(self, attempt, purpose, body, seconds=45, ordinary=False,
                 record=True, transport=None, deadline=None):
        if attempt.durability_uncertain:
            raise _ControllerFailure(
                "journal_durability",
                "device work blocked after durability failure", 5)
        attempt.check()
        context = attempt.next_context(purpose, record=record)
        active = transport or attempt.transport
        config = getattr(active, "_iris_config", None)
        if config is None:
            config = getattr(active, "config", None)
        if config is not None:
            config.setdefault("command_contexts", {})[context["command_id"]] = context
        try:
            result = active.command(
                context["command_id"], body,
                attempt.deadline(seconds, ordinary=ordinary)
                if deadline is None else deadline)
        except Exception as exc:
            import iox_transport
            if (transport is None and purpose == "verification_read" and
                    not isinstance(active, iox_transport.IoxTransport)):
                raise _SyntheticCommandFailure(exc)
            raise
        self._validate_transport_result(result)
        if transport is None:
            self._adopt_synthetic_result(attempt, result, context, active)
            attempt.operation_results.append(result)
        if transport is None and attempt.fence is not None:
            self._fence_barrier(attempt)
        return result, context

    def _adopt_synthetic_result(self, attempt, result, context, transport):
        """Bind legacy in-process transport doubles to the real transcript.

        Production transport writes this command itself.  A controller-side
        adapter is necessary for older injected transports: durable record
        evidence must still name the controller-owned attempt transcript.
        """
        reference = _get(result, "transcript_ref")
        import iox_transport
        if isinstance(transport, iox_transport.IoxTransport):
            if reference != attempt.transcript.reference():
                raise _ControllerFailure(
                    "authority_mismatch",
                    "production transport transcript binding changed", 5)
            return
        if (isinstance(reference, dict) and
                reference.get("attempt_id") == attempt.attempt_id):
            return
        if context["command_id"] in getattr(attempt.transcript, "_commands", {}):
            raise _ControllerFailure(
                "journal_unreadable", "transport transcript binding changed", 5)
        purpose = context["purpose"]
        restoration = (purpose == "verification_enable" or
                       context.get("phase") in
                       ("ownership_probe", "restore_intent"))
        attempt.transcript.append(context, restoration=restoration)
        stdout = bytes(_get(result, "stdout", b""))
        stderr = bytes(_get(result, "stderr", b""))
        for name, body in (("stdout", stdout), ("stderr", stderr)):
            if body:
                attempt.transcript.append({
                    "schema_version": 1, "type": "stream",
                    "command_id": context["command_id"], "stream": name,
                    "offset": 0,
                    "data_b64": base64.b64encode(body).decode("ascii")},
                    restoration=restoration)
        framing = bool(_get(result, "framing_complete", False))
        observed_state = None
        transition = None
        if purpose == "verification_read":
            observed_state = self._parse_state(result) if framing else "unknown"
        elif purpose in ("verification_disable", "verification_enable"):
            transition, unused_category = iox_transport._classify_transition(
                purpose, stdout)
        attempt.transcript.append({
            "schema_version": 1, "type": "command_end",
            "command_id": context["command_id"],
            "finished_at": int(self._now()),
            "returncode": _get(result, "returncode"),
            "timed_out": bool(_get(result, "timed_out", False)),
            "stdout_truncated": bool(_get(result, "stdout_truncated", False)),
            "stderr_truncated": bool(_get(result, "stderr_truncated", False)),
            "framing_complete": framing,
            "error_category": _get(result, "error_category"),
            "stdout_observed_bytes": len(stdout),
            "stderr_observed_bytes": len(stderr),
            "stdout_dropped_bytes": 0, "stderr_dropped_bytes": 0,
            "payload_spans": ([{"offset": 0, "length": len(stdout)}]
                              if framing and context["kind"] == "ssh" else []),
            "observed_state": observed_state,
            "transition_response": transition,
        }, restoration=restoration)
        actual = attempt.transcript.reference()
        if isinstance(result, dict):
            result["transcript_ref"] = actual
        else:
            setattr(result, "transcript_ref", actual)

    @staticmethod
    def _transport_ok(result):
        return (type(_get(result, "returncode")) is int and
                _get(result, "returncode") == 0 and
                _get(result, "timed_out") is False and
                _get(result, "stdout_truncated") is False and
                _get(result, "stderr_truncated") is False and
                _get(result, "framing_complete") is True)

    @staticmethod
    def _validate_transport_result(result):
        reference = _get(result, "transcript_ref")
        returncode = _get(result, "returncode")
        no_process_failure = (
            returncode is None and
            _get(result, "error_category") in _RESULT_CODES and
            _get(result, "framing_complete") is False)
        if ((not no_process_failure and
             (type(returncode) is not int or
              not -255 <= returncode <= 255)) or
                any(type(_get(result, key)) is not bool for key in
                    ("timed_out", "stdout_truncated", "stderr_truncated",
                     "framing_complete")) or
                not isinstance(_get(result, "stdout"), bytes) or
                not isinstance(_get(result, "stderr"), bytes) or
                (_get(result, "error_category") is not None and
                 _get(result, "error_category") not in _RESULT_CODES) or
                not isinstance(reference, dict) or set(reference) != {
                    "id", "attempt_id", "stored_bytes", "observed_bytes",
                    "dropped_bytes", "truncated"} or
                not isinstance(reference["id"], str) or
                not _HEX32.fullmatch(reference["id"]) or
                not isinstance(reference["attempt_id"], str) or
                not _HEX32.fullmatch(reference["attempt_id"]) or
                type(reference["stored_bytes"]) is not int or
                not 0 <= reference["stored_bytes"] <=
                _TRANSCRIPT_FILE_BYTES or
                type(reference["observed_bytes"]) is not int or
                reference["observed_bytes"] < 0 or
                type(reference["dropped_bytes"]) is not int or
                not 0 <= reference["dropped_bytes"] <=
                reference["observed_bytes"] or
                type(reference["truncated"]) is not bool):
            raise _ControllerFailure(
                "unsupported_response", "malformed IOx transport result", 4)

    def _identity_from_result(self, result):
        if not self._transport_ok(result):
            raise _ControllerFailure(_get(result, "error_category") or "transport",
                                     "identity discovery failed")
        text = _get(result, "stdout", b"").decode("utf-8", "replace")
        boards = re.findall(r"^Processor board ID ([A-Za-z0-9._:-]{1,128})\s*$",
                            text, re.I | re.M)
        models = re.findall(r"^Model Number\s*:\s*([A-Za-z0-9._-]{1,128})\s*$",
                            text, re.I | re.M)
        if not models:
            # A Catalyst 8000V has no "Model Number:" line and reports
            #   cisco C8000V (VXE) processor (revision VXE) with ... memory.
            # The old anchor required the line to END at "processor", which an
            # IE-3400 satisfied via its Model Number line but a C8000V, falling
            # to this branch, never did -- so every C8000V IOx onboard failed
            # at identity discovery with "unable to establish exact IOx
            # identity". Match "processor" as a word; the trailing
            # revision/memory text is expected.
            models = re.findall(r"^cisco\s+([A-Za-z0-9._-]{1,128})\s+\([^\n]+\)\s+processor\b",
                                text, re.I | re.M)
        family = "xe" if re.search(r"IOS XE Software", text, re.I) else (
            "xr" if re.search(r"IOS XR Software", text, re.I) else None)
        if len(boards) != 1 or len(models) != 1 or family is None:
            raise _ControllerFailure("identity_mismatch", "unable to establish exact IOx identity", 2)
        return {"board_identity": boards[0], "board": boards[0],
                "device_identity": boards[0],
                "model": models[0], "os_family": family, "platform": "iox"}

    def _discover_and_lock(self, attempt):
        try:
            discovery_supervisor = _SupervisorClient.start(
                None, self._monotonic, attempt.session_deadline)
        except Exception:
            raise _ControllerFailure(
                "descendant_unreaped", "discovery supervisor unavailable", 5)
        discovery = None
        context_board = attempt.board
        attempt.board = None
        discovery_reaped = False
        discovery_error = None
        try:
            discovery = self._make_transport(attempt, discovery_supervisor)
            result, unused = self._command(attempt, "identity_discovery", _IDENTITY,
                                           75, record=False, transport=discovery)
            identity = self._identity_from_result(result)
        except Exception as exc:
            discovery_error = exc
        finally:
            deadline = min(self._monotonic() + _SUPERVISOR_REAP_SECONDS,
                           attempt.session_deadline)
            transport_reaped = True
            if discovery is not None:
                try:
                    transport_reaped = discovery.cancel_and_reap(deadline)
                except Exception:
                    transport_reaped = False
            try:
                supervisor_reaped = discovery_supervisor.reap_all(deadline)
            except Exception:
                supervisor_reaped = False
            discovery_reaped = transport_reaped and supervisor_reaped
            if supervisor_reaped:
                try:
                    discovery_reaped = (discovery_supervisor.release(deadline)
                                        and discovery_reaped)
                except Exception:
                    discovery_reaped = False
            else:
                try:
                    discovery_supervisor.abandon(deadline)
                except Exception:
                    pass
            attempt.board = context_board
        if not discovery_reaped:
            raise _ControllerFailure(
                "descendant_unreaped",
                "identity discovery descendants were not reaped", 5)
        if discovery_error is not None:
            raise discovery_error
        board = identity["board_identity"]
        expected = _get(attempt.target, "device_identity")
        if expected and expected != board:
            raise _ControllerFailure("identity_mismatch", "recorded board identity mismatch", 2)
        expected_model = _get(attempt.target, "model")
        if (expected_model and
                expected_model.upper() != identity["model"].upper()):
            raise _ControllerFailure(
                "identity_mismatch", "recorded device model mismatch", 2)
        if identity["os_family"] != "xe" or (
                _get(attempt.target, "os_family") is not None and
                _get(attempt.target, "os_family") != "xe"):
            raise _ControllerFailure(
                "identity_mismatch", "target is not IOS XE", 2)
        package = _get(attempt.target, "pkg")
        # C8000 and C9000 are x86 (amd64); IE-3x00 and IR are arm64. The
        # match had only C9, so a Catalyst 8000V's correct amd64 package was
        # rejected as an architecture mismatch -- the last discovery-time gate
        # a C8000V IOx onboard hit. Kept in step with _validate_target and
        # _record_target, which already use ^C[89].
        expected_package = ("iris-amd64.tar" if re.match(
            r"^C[89]", identity["model"], re.I) else "iris-arm64.tar")
        if package and package != expected_package:
            raise _ControllerFailure(
                "identity_mismatch", "IOx package architecture mismatch", 2)
        attempt.board = board
        attempt.identity = identity
        try:
            fd = _open_board_lock(self.lock_dir, board)
        except (OSError, ValueError):
            raise _ControllerFailure(
                "journal_durability", "unsafe physical-board lock", 5)
        wait_deadline = min(self._monotonic() + 60, attempt.session_deadline)
        while True:
            if attempt.is_cancelled():
                os.close(fd)
                raise _ControllerFailure("cancelled", "operation cancelled", 130)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    _revalidate_board_lock(self.lock_dir, board, fd)
                except Exception:
                    os.close(fd)
                    raise _ControllerFailure(
                        "journal_durability",
                        "physical-board lock changed after acquisition", 5)
                break
            except BlockingIOError:
                now = self._monotonic()
                if now >= wait_deadline:
                    os.close(fd)
                    if wait_deadline >= attempt.session_deadline:
                        raise _ControllerFailure("timeout", "board lock wait exhausted", 4)
                    raise _ControllerFailure("board_busy", "physical board is busy", 2)
                time.sleep(min(0.05, wait_deadline - now))
            except (IOError, OSError):
                os.close(fd)
                raise _ControllerFailure(
                    "journal_durability",
                    "physical-board lock acquisition failed", 5)
        attempt.lock_fd = fd
        self._start_supervisor(attempt)
        self._admit_fence(attempt)
        attempt.transport = self._make_transport(attempt, attempt.supervisor)
        result, unused = self._command(attempt, "identity_revalidation", _IDENTITY,
                                       75, record=False)
        locked = self._identity_from_result(result)
        if any(locked[key] != identity[key]
               for key in ("board_identity", "model", "os_family")):
            raise _ControllerFailure("identity_mismatch", "identity changed after board lock", 2)

    def _acquire_known_board_lock(self, attempt):
        try:
            fd = _open_board_lock(self.lock_dir, attempt.board)
        except (OSError, ValueError):
            raise _ControllerFailure(
                "journal_unreadable", "unsafe physical-board lock", 5)
        wait_deadline = min(
            self._monotonic() + 60, attempt.session_deadline)
        while True:
            if attempt.is_cancelled():
                os.close(fd)
                raise _ControllerFailure("cancelled", "operation cancelled", 130)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    _revalidate_board_lock(
                        self.lock_dir, attempt.board, fd)
                except Exception:
                    os.close(fd)
                    raise _ControllerFailure(
                        "journal_unreadable",
                        "physical-board lock changed after acquisition", 5)
                attempt.lock_fd = fd
                return
            except BlockingIOError:
                now = self._monotonic()
                if now >= wait_deadline:
                    os.close(fd)
                    category = ("timeout" if
                                wait_deadline >= attempt.session_deadline else
                                "board_busy")
                    raise _ControllerFailure(
                        category, "physical board lock wait exhausted",
                        4 if category == "timeout" else 2)
                time.sleep(min(0.05, wait_deadline - now))
            except (IOError, OSError):
                os.close(fd)
                raise _ControllerFailure(
                    "journal_unreadable",
                    "physical-board lock acquisition failed", 5)

    def _admit_fence(self, attempt):
        path = os.path.join(self.session_dir, _board_key(attempt.board) + ".json")
        if attempt.supervisor is None:
            raise _ControllerFailure(
                "descendant_unreaped", "missing IOx supervisor custody", 5)
        reference = attempt.transcript.reference()
        now = int(self._now())
        fence = {
            "schema_version": 1, "controller_id": self.controller_id,
            "board_identity": attempt.board, "attempt_id": attempt.attempt_id,
            "device_id": _get(attempt.request, "device_id", "recovery"),
            "job_id": _get(attempt.request, "job_id", "0" * 16),
            "operation": attempt.operation,
            "teardown_mode": (_get(attempt.request, "teardown_mode", "none")
                              if attempt.operation == "uninstall" else "none"),
            "record_id": attempt.record_id, "boot_id": _boot_id(),
            "supervisor_pid": attempt.supervisor.pid,
            "supervisor_start_ticks": attempt.supervisor.start_ticks,
            "transcript_ref": reference, "state": "active",
            "created_at": now, "updated_at": now,
        }
        attempt.check()
        try:
            with self._authority_store_lock(attempt):
                attempt.check()
                sessions, unused_transcripts = self._scan_authority()
                old = None
                if path in sessions:
                    old = _read_json_strict(path, _SESSION_FILE_BYTES)
                    self._validate_fence(old, path)
                    if (old["state"] == "active" and
                            old["boot_id"] == _boot_id()):
                        attempt.fence = old
                        attempt.fence_path = path
                        raise _ControllerFailure(
                            "descendant_unreaped",
                            "active same-boot IOx session fence", 5)
                active = 0
                for session_path in sessions:
                    existing = self._read_sibling_fence(session_path)
                    if existing is None:
                        continue
                    self._validate_fence(existing, session_path)
                    active += existing["state"] == "active"
                projected_total = len(sessions) + (old is None)
                projected_active = active + (
                    old is None or old["state"] == "reaped")
                if projected_total > self.limits["session_files"]:
                    raise _ControllerFailure(
                        "journal_durability",
                        "session fence capacity exhausted", 5)
                if projected_active > self.limits["active_fences"]:
                    raise _ControllerFailure(
                        "journal_durability",
                        "active session capacity exhausted", 5)
                attempt.check()
                _durable_json(path, fence, replace=old is not None)
        except _ControllerFailure:
            raise
        except ValueError as exc:
            if "store lock timed out" in str(exc):
                raise _ControllerFailure(
                    "timeout", "store lock wait exhausted", 4)
            raise _ControllerFailure(
                "journal_durability", "session fence admission failed", 5)
        except Exception:
            raise _ControllerFailure(
                "journal_durability", "session fence admission failed", 5)
        attempt.fence = fence
        attempt.fence_path = path
        attempt.fence_owned = True

    def _update_fence(self, attempt, state=None, record_id=None):
        if attempt.fence is None:
            return
        updated = copy.deepcopy(attempt.fence)
        if state is not None:
            updated["state"] = state
        if record_id is not None:
            updated["record_id"] = record_id
        updated["transcript_ref"] = attempt.transcript.reference()
        updated["updated_at"] = int(self._now())
        _durable_json(attempt.fence_path, updated)
        attempt.fence = updated

    def _fence_barrier(self, attempt, state=None, record_id=None):
        try:
            self._update_fence(
                attempt, state=state, record_id=record_id)
        except _ControllerFailure:
            attempt.durability_uncertain = True
            raise
        except Exception:
            attempt.durability_uncertain = True
            raise _ControllerFailure(
                "journal_durability",
                "unable to persist IOx session fence", 5)

    def _resolve_credentials(self, attempt):
        resolver = self.config.get("credential_resolver")
        reference = _get(attempt.request, "credential_ref") if attempt.request else None
        if callable(resolver) and reference is not None:
            value = resolver(reference)
            if not isinstance(value, dict):
                raise ValueError("credential resolver returned no credentials")
            if set(value) - {"name", "device_user", "device_pass",
                             "enable_secret"}:
                raise ValueError(
                    "credential resolver returned unknown fields")
            if ("name" in value and
                    (not isinstance(value["name"], str) or
                     len(value["name"].encode("utf-8")) > 256)):
                raise ValueError("invalid credential profile name")
            attempt.credentials = dict(
                (key, value[key]) for key in
                ("device_user", "device_pass", "enable_secret")
                if key in value)
        if set(attempt.credentials) - {
                "device_user", "device_pass", "enable_secret",
                "catalog_token"}:
            raise ValueError("credential resolver returned unknown fields")
        for key, value in attempt.credentials.items():
            if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
                raise ValueError("invalid credential value")
        user = attempt.credentials.get("device_user")
        password = attempt.credentials.get("device_pass")
        if (self._strict_target and
                (_SAFE_USER.fullmatch(user or "") is None or not password)):
            raise ValueError("incomplete IOx device credentials")
        for key in ("device_pass", "enable_secret"):
            value = attempt.credentials.get(key)
            if value is not None and (not value or '"' in value or
                                      "\\" in value or
                                      "\r" in value or "\n" in value or
                                      any(ord(character) > 126
                                          for character in value)):
                raise ValueError("invalid IOx credential syntax")

    def _observation(self, attempt, result, context, state=None):
        import iox_transport
        reference = _get(result, "transcript_ref")
        # Frozen transport doubles predate the durable writer and return their
        # own synthetic reference.  The production transport is domain-bound
        # to this attempt and always takes the strict parser path below.
        if reference.get("attempt_id") != attempt.attempt_id:
            complete = self._transport_ok(result)
            observed = state if state is not None else self._parse_state(result)
            stdout = _get(result, "stdout", b"")
            stderr = _get(result, "stderr", b"")
            return {
                "state": observed if complete else "unknown",
                "observed_at": int(self._now()),
                "command_id": context["command_id"],
                "transcript_id": reference["id"],
                "stdout_offset": 0,
                "stdout_length": len(stdout) if complete else 0,
                "stderr_offset": 0, "stderr_length": len(stderr),
                "returncode": _get(result, "returncode"),
                "timed_out": bool(_get(result, "timed_out", False)),
                "truncated": bool(_get(result, "stdout_truncated", False) or
                                  _get(result, "stderr_truncated", False)),
                "framing_complete": bool(_get(
                    result, "framing_complete", False)),
            }
        prefix = iox_transport._load_transcript_prefix(
            self.state_dir, reference, self.controller_id)
        command = prefix["commands"].get(context["command_id"])
        if command is None or command.get("end") is None:
            raise _ControllerFailure(
                "journal_unreadable", "verification evidence is incomplete", 5)
        end = command["end"]
        spans = end["payload_spans"]
        if len(spans) == 1:
            stdout_offset = spans[0]["offset"]
            stdout_length = spans[0]["length"]
        elif not spans:
            stdout_offset = 0
            stdout_length = 0
        else:
            raise _ControllerFailure(
                "journal_unreadable", "verification evidence is ambiguous", 5)
        if state is None:
            state = end["observed_state"] or "unknown"
        return {
            "state": state,
            "observed_at": end["finished_at"],
            "command_id": context["command_id"],
            "transcript_id": reference["id"],
            "stdout_offset": stdout_offset,
            "stdout_length": stdout_length,
            "stderr_offset": 0,
            "stderr_length": len(command["stderr"]),
            "returncode": end["returncode"],
            "timed_out": end["timed_out"],
            "truncated": (end["stdout_truncated"] or
                          end["stderr_truncated"]),
            "framing_complete": end["framing_complete"],
        }

    def _parse_state(self, result):
        if not self._transport_ok(result):
            return "unknown"
        lines = _get(result, "stdout", b"").replace(b"\r\n", b"\n").splitlines()
        matches = []
        for line in lines:
            match = re.match(br"^App signature verification: (enabled|disabled)$",
                             line, re.I)
            if match:
                matches.append(match.group(1).decode("ascii").lower())
        return matches[0] if len(matches) == 1 else "unknown"

    def _verification_read(self, attempt):
        try:
            result, context = self._command(
                attempt, "verification_read", _VERIFY_READ, 45)
        except _SyntheticCommandFailure as failed:
            # A transport adapter can fail after its durable command_end was
            # committed (for example, while notifying an observer).  Continue
            # only when the strict transcript proves the complete result;
            # otherwise preserve the original exception.
            import iox_transport
            reference = attempt.transcript.reference()
            try:
                prefix = iox_transport._load_transcript_prefix(
                    self.state_dir, reference, self.controller_id)
                command = prefix["commands"].get(attempt.command_id)
                if (command is None or command.get("end") is None or
                        command["start"].get("purpose") !=
                        "verification_read"):
                    raise ValueError("no committed verification result")
            except Exception:
                raise failed.original
            context = command["start"]
            end = command["end"]
            result = {
                "returncode": end["returncode"],
                "timed_out": end["timed_out"],
                "stdout": command["stdout"], "stderr": command["stderr"],
                "stdout_truncated": end["stdout_truncated"],
                "stderr_truncated": end["stderr_truncated"],
                "framing_complete": end["framing_complete"],
                "error_category": end["error_category"],
                "transcript_ref": reference,
            }
        return self._observation(attempt, result, context), result, context

    def _bind_catalog_token(self, attempt, token):
        """Add a freshly minted token to every live bounded redactor."""
        config = getattr(attempt.transport, "_iris_config", None)
        credentials = (config.get("credentials")
                       if isinstance(config, dict) else None)
        if not isinstance(credentials, dict):
            raise _ControllerFailure(
                "authority_mismatch", "transport credential binding missing", 5)
        credentials["CATALOG_TOKEN"] = token
        attempt.credentials["catalog_token"] = token
        import iox_transport
        if isinstance(attempt.transport, iox_transport.IoxTransport):
            encoded = token.encode("utf-8")
            if encoded not in attempt.transport._secret_values:
                attempt.transport._secret_values.append(encoded)

    def _append_ack(self, attempt, event):
        journal = attempt.journal
        attempt.transcript.append({
            "schema_version": 1, "type": "journal_ack",
            "record_id": journal["record_id"],
            "transaction_id": journal["transaction_id"],
            "revision": journal["revision"], "phase": journal["phase"],
            "event": event, "at": int(self._now()),
        })
        self._fence_barrier(attempt)

    def _issue_continuation(self, attempt, kind):
        journal = attempt.journal
        if kind not in ("disable_send", "disable_result", "probe_read",
                        "probe_result", "enable_send", "restore_result"):
            raise _ControllerFailure(
                "invalid_transition", "unknown IOx continuation", 5)
        if journal is None or any(
                binding[-1] == kind
                for binding in attempt.continuations.values()):
            raise _ControllerFailure(
                "invalid_transition", "duplicate IOx continuation", 5)
        token = os.urandom(32).hex()
        capability = _IoxContinuation(token)
        binding = (os.getpid(), self.controller_id, attempt.attempt_id,
                   journal["record_id"], journal["transaction_id"],
                   attempt.board, journal["revision"], journal["phase"], kind)
        attempt.continuations[token] = binding
        return capability

    def _consume_continuation(self, attempt, capability, kind):
        if (type(capability) is not _IoxContinuation or
                capability._pid != os.getpid()):
            attempt.invalidate_continuations()
            raise _ControllerFailure(
                "authority_mismatch", "invalid IOx continuation", 5)
        binding = attempt.continuations.pop(capability._token, None)
        journal = attempt.journal
        expected = ((os.getpid(), self.controller_id, attempt.attempt_id,
                     journal["record_id"], journal["transaction_id"],
                     attempt.board, journal["revision"], journal["phase"], kind)
                    if journal is not None else None)
        if binding != expected:
            attempt.invalidate_continuations()
            raise _ControllerFailure(
                "authority_mismatch", "stale IOx continuation", 5)

    def _event(self, attempt, event, evidence, capability=None, ack=False):
        if attempt.durability_uncertain:
            raise _ControllerFailure(
                "journal_durability",
                "journal work blocked after durability failure", 5)
        journal = attempt.journal
        try:
            updated = self._store_call(
                "iox_event", (
                    journal["record_id"], journal["transaction_id"],
                    journal["revision"], journal["phase"], event, evidence),
                attempt=attempt, kwargs={"capability": capability},
                mutation=True)
        except _ControllerFailure:
            raise
        except Exception as exc:
            category = "stale_cas" if type(exc).__name__ == "StaleIoxRevision" else "journal_durability"
            attempt.durability_uncertain = True
            raise _ControllerFailure(category, "IOx journal update failed", 5)
        attempt.journal = updated
        if ack:
            self._append_ack(attempt, event)
        return updated

    def _instruction_cleanup_update(self, attempt, pending):
        if attempt.durability_uncertain:
            raise _ControllerFailure(
                "journal_durability",
                "instruction cleanup blocked after durability failure", 5)
        journal = attempt.journal
        method = ("iox_instruction_cleanup_intent" if pending else
                  "iox_instruction_cleanup_complete")
        try:
            updated = self._store_call(
                method, (journal["record_id"], journal["transaction_id"],
                         journal["revision"], journal["phase"]),
                attempt=attempt, mutation=True)
        except _ControllerFailure:
            raise
        except Exception as exc:
            category = ("stale_cas" if
                        type(exc).__name__ == "StaleIoxRevision" else
                        "journal_durability")
            attempt.durability_uncertain = True
            raise _ControllerFailure(
                category, "IOx instruction cleanup journal update failed", 5)
        attempt.journal = updated
        self._fence_barrier(attempt)
        return updated

    def _recover_journal(self, attempt, journal, initiating=False):
        if attempt.durability_uncertain:
            raise _ControllerFailure(
                "journal_durability",
                "recovery blocked after durability failure", 5)
        previous = attempt.safety_recovery
        attempt.safety_recovery = True
        try:
            return self._recover_journal_owned(
                attempt, journal, initiating=initiating)
        finally:
            attempt.safety_recovery = previous

    def _recover_journal_owned(self, attempt, journal, initiating=False):
        if (not isinstance(journal, dict) or
                journal.get("controller_id") != self.controller_id):
            raise _ControllerFailure(
                "authority_mismatch", "foreign IOx journal authority", 5)
        attempt.record_id = journal["record_id"]
        attempt.journal = journal
        if journal.get("instruction_cleanup_pending"):
            self._remove_instruction_source(attempt)
            journal = attempt.journal
        phase = journal["phase"]
        probe_read = None
        enable_send = None
        if not journal["unresolved"]:
            return 0
        # Once a durable unresolved ownership phase is held under the board
        # lock, an external cancellation stops ordinary work but cannot abort
        # the bounded safety decision.  Controller shutdown remains fatal.
        if phase == "indeterminate":
            return 3
        # A persisted failure after restore intent proves that the one allowed
        # enable send was already consumed.  Cleanup must preserve the
        # unresolved obligation instead of issuing a second mutation.
        if phase == "restore_intent" and journal.get("error") is not None:
            return 4
        error = lambda category, detail: {
            "category": category, "detail": _bounded_text(detail),
            "at": int(self._now()), "transcript_id": attempt.attempt_id}
        refs = lambda result: [_get(result, "transcript_ref")]
        if phase == "ownership_probe" and probe_read is None:
            prior_transcript = journal["transcript_refs"][-1]["id"]
            self._event(attempt, "indeterminate", {
                "observation": None,
                "error": {
                    "category": "reconciliation_required",
                    "detail": "recovered ownership probe has no continuation",
                    "at": int(self._now()),
                    "transcript_id": prior_transcript,
                },
                "transcript_refs": []})
            return 3
        if phase in ("disabled_confirmed", "installing"):
            self._event(attempt, "ownership_probe", {}, ack=True)
            probe_read = self._issue_continuation(attempt, "probe_read")
            phase = "ownership_probe"
            initiating = True
        if phase == "ownership_probe":
            self._consume_continuation(
                attempt, probe_read, "probe_read")
            observation, result, unused = self._verification_read(attempt)
            if observation["state"] == "unknown":
                self._event(attempt, "error", {"error": error(
                    _get(result, "error_category") or "readback_unknown",
                    "verification ownership probe was not authoritative"),
                    "transcript_refs": refs(result)})
                return 4
            if observation["state"] == "enabled":
                probe_result = self._issue_continuation(
                    attempt, "probe_result")
                self._consume_continuation(
                    attempt, probe_result, "probe_result")
                capability = deployment_records._issue_iox_capability(
                    self.controller_id, attempt.attempt_id, journal["record_id"],
                    journal["transaction_id"], attempt.board,
                    attempt.journal["revision"], attempt.journal["phase"],
                    "relinquished", {"observation": observation,
                                     "transcript_refs": refs(result)})
                self._event(attempt, "relinquished", {
                    "observation": observation, "transcript_refs": refs(result)},
                    capability=capability)
                return 0
            probe_result = self._issue_continuation(
                attempt, "probe_result")
            self._consume_continuation(
                attempt, probe_result, "probe_result")
            self._event(attempt, "restore_intent", {
                "observation": observation, "transcript_refs": refs(result)},
                capability=deployment_records._issue_iox_capability(
                    self.controller_id, attempt.attempt_id, journal["record_id"],
                    journal["transaction_id"], attempt.board,
                    attempt.journal["revision"], attempt.journal["phase"],
                    "restore_intent", {"observation": observation,
                                       "transcript_refs": refs(result)}), ack=True)
            enable_send = self._issue_continuation(attempt, "enable_send")
            phase = "restore_intent"
            initiating = True
        if phase == "restore_intent":
            if enable_send is None:
                observation, result, unused = self._verification_read(attempt)
                if observation["state"] == "enabled":
                    self._event(attempt, "relinquished", {
                        "observation": observation, "transcript_refs": refs(result)})
                    return 0
                self._event(attempt, "indeterminate", {
                    "observation": observation,
                    "error": error("reconciliation_required", "restore intent cannot be replayed"),
                    "transcript_refs": refs(result)})
                return 3
            self._consume_continuation(
                attempt, enable_send, "enable_send")
            result, enable_context = self._command(
                attempt, "verification_enable", _VERIFY_ENABLE, 45)
            if not self._transport_ok(result) or _get(result, "error_category"):
                self._event(attempt, "error", {"error": error(
                    _get(result, "error_category") or "unsupported_response",
                    "verification enable did not complete"),
                    "transcript_refs": refs(result)})
                return 4
            observation, read_result, unused = self._verification_read(attempt)
            combined = refs(read_result)
            if observation["state"] != "enabled":
                self._event(attempt, "error", {"error": error(
                    "readback_mismatch", "verification enable readback was not enabled"),
                    "transcript_refs": combined})
                return 4
            evidence = {"observation": observation, "transcript_refs": combined}
            restore_result = self._issue_continuation(
                attempt, "restore_result")
            self._consume_continuation(
                attempt, restore_result, "restore_result")
            capability = deployment_records._issue_iox_capability(
                self.controller_id, attempt.attempt_id, journal["record_id"],
                journal["transaction_id"], attempt.board,
                attempt.journal["revision"], attempt.journal["phase"],
                "restored", evidence)
            self._event(attempt, "restored", evidence, capability=capability)
            return 0
        if phase == "disable_intent":
            observation, result, unused = self._verification_read(attempt)
            if observation["state"] == "enabled":
                self._event(attempt, "relinquished", {
                    "observation": observation, "transcript_refs": refs(result)})
                return 0
            self._event(attempt, "indeterminate", {
                "observation": observation,
                "error": error("reconciliation_required", "disable effect cannot be inferred"),
                "transcript_refs": refs(result)})
            return 3
        return 0

    def _recover_obligations(self, attempt):
        try:
            # This fresh strict store-derived scan occurs under the physical
            # board lock.  The precontact scan can reject early but never
            # authorizes mutation after contact.
            try:
                self.store.list(strict=True)
            except TypeError:
                self.store.list()
            obligations = self._store_call(
                "iox_obligations", (attempt.board,), attempt=attempt)
        except _ControllerFailure:
            raise
        except Exception:
            raise _ControllerFailure(
                "journal_unreadable", "IOx journal is unreadable", 5)
        if len(obligations) > 1:
            raise _ControllerFailure("reconciliation_required",
                                     "conflicting board verification obligations", 3)
        if not obligations:
            return None
        if any(not isinstance(journal, dict) or
               journal.get("controller_id") != self.controller_id
               for journal in obligations):
            raise _ControllerFailure(
                "authority_mismatch", "foreign IOx journal authority", 5)
        if (attempt.operation == "uninstall" and
                _get(attempt.request, "teardown_mode") ==
                "force_agent_only" and
                obligations[0].get("phase") == "restore_intent"):
            raise _ControllerFailure(
                "reconciliation_required",
                "recovered restore intent has no live continuation", 3)
        incoming_target = attempt.target
        try:
            self._strict_recovery_binding(attempt, obligations[0])
            code = self._recover_journal(
                attempt, obligations[0], initiating=False)
        finally:
            # Recovery uses only the predecessor record's closed projection;
            # the admitted retry resumes with its independently validated
            # request target after the old obligation is discharged.
            attempt.target = incoming_target
        attempt.recovery_code = code
        if code == 3:
            raise _ControllerFailure(
                "reconciliation_required",
                _reconciliation_detail("predecessor recovery failed",
                                       attempt.journal), code)
        if code:
            raise _ControllerFailure(
                "readback_unknown", "predecessor recovery failed", code)
        return obligations[0]

    def _strict_recovery_binding(self, attempt, journal):
        try:
            try:
                record = self.store.get(journal["record_id"], strict=True)
            except TypeError:
                record = self.store.get(journal["record_id"])
        except Exception:
            raise _ControllerFailure(
                "journal_unreadable", "IOx recovery record is unreadable", 5)
        if (not isinstance(record, dict) or
                record.get("iox_verification") != journal):
            raise _ControllerFailure(
                "authority_mismatch", "IOx recovery binding changed", 5)
        validated = self._record_target(record, attempt.target, "recover")
        if (validated.get("host") != attempt.target.get("host") or
                validated.get("device_identity") not in
                (None, journal["board_identity"])):
            raise _ControllerFailure(
                "authority_mismatch", "IOx recovery target changed", 5)
        attempt.target = validated
        return record

    def _record_target(self, record, seed, action):
        resolved = record.get("resolved") or {}
        projected = {}
        aliases = {"host": "device_ip", "vlan": "iris_vlan",
                   "bt_listen_port": "swarm_port"}
        for key in _TARGET_KEYS:
            value = resolved.get(aliases.get(key, key))
            if value in (None, "") and key in resolved:
                value = resolved.get(key)
            if value not in (None, ""):
                projected[key] = copy.deepcopy(value)
        projected["host"] = resolved.get("device_ip", "")
        projected.setdefault("platform", "iox")
        if resolved.get("pkg") in (None, "") and resolved.get("model"):
            projected["pkg"] = ("iris-amd64.tar" if re.match(
                r"^C[89]", resolved["model"], re.I) else "iris-arm64.tar")
        projected["resources"] = copy.deepcopy(record.get("resources") or [])
        validated = self._validate_target(projected, action)
        # Inventory/request values select the durable record; they never
        # retarget it.  The controller uses this closed projection of the
        # record and later compares a fresh strict reread with the preliminary
        # record before device mutation.
        return validated

    def _revalidate_known_identity(self, attempt, journal):
        result, unused = self._command(
            attempt, "identity_revalidation", _IDENTITY, 75)
        identity = self._identity_from_result(result)
        model = attempt.target.get("model")
        if (identity["board_identity"] != journal["board_identity"] or
                identity["os_family"] != "xe" or
                (model and model.upper() != identity["model"].upper())):
            raise _ControllerFailure(
                "identity_mismatch", "recovery device identity mismatch", 2)
        attempt.identity = identity

    def _precheck_target_authority(self, attempt):
        board = _get(attempt.target, "device_identity")
        if board is None:
            return
        if not isinstance(board, str) or not _BOARD_ID.fullmatch(board):
            raise _ControllerFailure(
                "identity_mismatch", "invalid recorded board identity", 2)
        try:
            obligations = self._store_call(
                "iox_obligations", (board,), attempt=attempt)
        except _ControllerFailure:
            raise
        except Exception:
            raise _ControllerFailure(
                "journal_unreadable", "IOx journal is unreadable", 5)
        if any(not isinstance(journal, dict) or
               journal.get("controller_id") != self.controller_id
               for journal in obligations):
            raise _ControllerFailure(
                "authority_mismatch", "foreign IOx journal authority", 5)
        attempt.prechecked_obligations[board] = obligations

    def _ordinary_install_preflight(self, attempt):
        """Run collision checks through the already-custodied transport."""
        result, unused = self._command(
            attempt, "preflight",
            b"show app-hosting list\nshow running-config",
            90, ordinary=True, record=False)
        if (not self._transport_ok(result) or
                _get(result, "error_category")):
            raise _ControllerFailure(
                _get(result, "error_category") or "rejected",
                "IOx preflight could not read collision state", 4)
        # Both read-only command bodies share one bounded, supervised session.
        # Collision and app-state patterns are anchored, so they remain
        # unambiguous in the combined normalized output.
        running = _get(result, "stdout", b"").decode("utf-8", "replace")
        apps = running
        appid = str(_get(attempt.target, "iox_appid",
                         self.config.get("application_id", "iris")))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", appid):
            raise _ControllerFailure(
                "unsupported_syntax_local", "invalid IOx application id", 2)
        match = re.search(
            r"(?im)^[ \t]*%s[ \t]+(\S+)" % re.escape(appid), apps)
        app_state = match.group(1).upper() if match else ""
        stanza = r"(?m)^app-hosting appid %s\s*$" % re.escape(appid)
        resumable = (re.search(stanza, running) is not None and
                     app_state in ("DEPLOYED", "ACTIVATED"))
        collisions = list(_IRIS_NAMED_COLLISIONS)
        if not resumable:
            collisions.insert(0, (stanza,
                                  "the %s app-hosting config" % appid))
        for pattern, description in collisions:
            if resumable and description in _IOX_RETRY_REINSTATED:
                continue
            if re.search(pattern, running):
                raise _ControllerFailure(
                    "rejected", "%s already exists" % description, 2)
        # The fetch sets `ip http client username/password` for the span of
        # each copy and removes them afterwards, so an operator's own pair
        # would be overwritten and then deleted: refuse it. IRIS's own pair
        # (username = this device id, left only when a clear could not run)
        # is walked over; the next fetch replaces and clears it.
        if _http_client_credentials_collision(
                running, str(_get(attempt.request, "device_id", ""))):
            raise _ControllerFailure(
                "rejected",
                "the IOS HTTP client credentials already exist", 2)
        attempt.identity["status"] = "passed"
        if resumable:
            attempt.identity["resumable_app_state"] = app_state

    def _validate_request(self, request, action):
        if not isinstance(request, dict):
            raise ValueError("invalid IOx request")
        allowed = {"action", "device_id", "job_id", "target",
                   "credential_ref", "record_id", "teardown_mode",
                   "wrapper_path"}
        extras = set(request) - allowed
        if extras and not (action == "uninstall" and
                           _get(request, "teardown_mode") ==
                           "force_agent_only" and extras == {"vlan"} and
                           request.get("vlan") is None):
            raise ValueError("invalid IOx request fields")
        if _get(request, "action") != action:
            raise ValueError("request action mismatch")
        device_id = _get(request, "device_id")
        if (not isinstance(device_id, str) or
                not _BOARD_ID.fullmatch(device_id)):
            raise ValueError("invalid device_id")
        job_id = _get(request, "job_id")
        if not isinstance(job_id, str) or not _HEX16.fullmatch(job_id):
            raise ValueError("invalid job_id")
        for forbidden in ("iox_verification", "verification_state", "ownership"):
            if _has(request, forbidden):
                raise ValueError("caller cannot supply %s" % forbidden)
        mode = _get(request, "teardown_mode")
        record_id = _get(request, "record_id")
        wrapper = _get(request, "wrapper_path")
        if action == "install":
            if mode != "none" or record_id is not None or not wrapper:
                raise ValueError("invalid install authority tuple")
        elif mode == "recorded":
            if (not isinstance(record_id, str) or
                    not _RECORD_ID.fullmatch(record_id) or wrapper):
                raise ValueError("invalid recorded uninstall tuple")
        elif mode == "force_agent_only":
            if record_id is not None or wrapper:
                raise ValueError("invalid forced uninstall tuple")
        else:
            raise ValueError("invalid uninstall authority tuple")
        self._validate_target(_get(request, "target"), action)
        credential_ref = _get(request, "credential_ref")
        if (not isinstance(credential_ref, str) or not credential_ref or
                len(credential_ref.encode("utf-8")) > 256 or
                any(ord(character) < 32 for character in credential_ref)):
            raise ValueError("invalid credential reference")

    def _validate_target(self, target, action):
        if not isinstance(target, dict) or set(target) - _TARGET_KEYS:
            raise ValueError("invalid IOx target fields")
        for key in target:
            lowered = key.lower()
            if any(fragment in lowered for fragment in _SECRET_TARGET_FRAGMENTS):
                raise ValueError("secret-like IOx target field")
        if target.get("platform") != "iox":
            raise ValueError("invalid IOx target platform")
        host = _ascii_value(target.get("host"), _SAFE_HOST, "host")
        port = target.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid IOx target port")
        normalized = dict((key, copy.deepcopy(value))
                          for key, value in target.items()
                          if value is not None and value != "")
        normalized["host"], normalized["port"] = host, port
        normalized["platform"] = "iox"
        if "device_ip" in normalized:
            _ascii_value(normalized["device_ip"], _SAFE_HOST, "device_ip")
            if normalized["device_ip"] != host:
                raise ValueError("IOx target address binding changed")
        for key in ("model", "device_identity"):
            if key in normalized:
                _ascii_value(normalized[key], _SAFE_WORD, key)
        if "device_identity" in normalized and not _BOARD_ID.fullmatch(
                normalized["device_identity"]):
            raise ValueError("invalid IOx target device_identity")
        if "os_family" in normalized and normalized["os_family"] != "xe":
            raise ValueError("invalid IOx target os_family")
        mode = normalized.get("management_type", "routed")
        if mode == "legacy_routed":
            mode = "routed"
        if mode not in ("routed", "inband") and mode not in _ROUTER_MODES:
            raise ValueError("invalid IOx target management_type")
        normalized["management_type"] = mode
        router = mode in _ROUTER_MODES
        if router:
            if not re.match(r"^C8[0-9]{3}", normalized.get("model", ""), re.I):
                raise ValueError(
                    "IOx router target requires a Catalyst 8000 model")
            if "vlan" in normalized or "inband_vlan" in normalized:
                raise ValueError("IOx router target carries a VLAN")
        appid = normalized.get("iox_appid", self.application_id)
        if appid != self.application_id:
            raise ValueError("IOx application authority changed")
        normalized["iox_appid"] = self.application_id
        for key in ("package_fs", "target_fs"):
            value = normalized.get(key)
            if value is not None and re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_-]{0,31}:", value) is None:
                raise ValueError("invalid IOx target %s" % key)
        normalized.setdefault("package_fs", "bootflash:" if router else "flash:")
        normalized.setdefault("target_fs", "bootflash:" if router else "sdflash:")
        default_pkg = ("iris-amd64.tar" if re.match(
            r"^C[89]", normalized.get("model", ""), re.I) else
            "iris-arm64.tar")
        pkg = normalized.get("pkg", default_pkg)
        if (not isinstance(pkg, str) or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", pkg) is None):
            raise ValueError("invalid IOx target pkg")
        normalized["pkg"] = pkg
        app_intf = normalized.get("app_intf", "AppGigabitEthernet1/1")
        if (not isinstance(app_intf, str) or
                re.fullmatch(r"[A-Za-z][A-Za-z0-9./_-]{0,127}", app_intf) is None):
            raise ValueError("invalid IOx target app_intf")
        normalized["app_intf"] = app_intf
        vlan_key = "inband_vlan" if mode == "inband" else "vlan"
        vlan = normalized.get(vlan_key)
        if vlan is not None:
            if isinstance(vlan, str) and vlan.isdigit():
                vlan = int(vlan)
            if type(vlan) is not int or not 1 <= vlan <= 4094:
                raise ValueError("invalid IOx target %s" % vlan_key)
            normalized[vlan_key] = vlan
        if mode == "inband" and vlan is not None:
            normalized["vlan"] = vlan
        ipv4_fields = ("svi_ip", "guest_ip", "app_ip", "app_gateway",
                       "ios_ssh_host")
        for key in ipv4_fields:
            if key in normalized:
                _ipv4_value(normalized[key], key)
        for key in ("svi_mask", "app_mask"):
            if key in normalized:
                _ipv4_value(normalized[key], key)
                if normalized[key] not in _NETMASKS:
                    raise ValueError("invalid IOx target %s" % key)
        if mode == "routed":
            if "svi_mask" in normalized:
                normalized.setdefault("app_mask", normalized["svi_mask"])
            if "guest_ip" in normalized:
                normalized.setdefault("app_ip", normalized["guest_ip"])
            # ...and the reverse, which was missing. For routed the two name
            # the same address (_build_env resolves GUEST_IP from app_ip or
            # guest_ip interchangeably), but a deployment record's resolved
            # plan stores only app_ip. _record_target projects record keys
            # verbatim, so a RECORDED undeploy arrived without guest_ip and
            # was refused as an incomplete target plan -- every routed IOx
            # teardown, permanently, with no operator action able to fix it.
            if "app_ip" in normalized:
                normalized.setdefault("guest_ip", normalized["app_ip"])
            if "svi_ip" in normalized:
                normalized.setdefault("app_gateway", normalized["svi_ip"])
                normalized.setdefault("ios_ssh_host", normalized["svi_ip"])
        else:
            if "app_mask" in normalized:
                normalized.setdefault("svi_mask", normalized["app_mask"])
            if "app_ip" in normalized:
                normalized.setdefault("guest_ip", normalized["app_ip"])
        if router:
            # The app SSHes to IOS at the VirtualPortGroup address, the same
            # way the Guest Shell router recipe does.
            if "app_gateway" in normalized:
                normalized.setdefault("ios_ssh_host", normalized["app_gateway"])
            if {"app_ip", "app_mask", "app_gateway"} <= set(normalized):
                _router_subnet_check(normalized["app_ip"],
                                     normalized["app_mask"],
                                     normalized["app_gateway"])
            if "vpg_number" not in normalized:
                raise ValueError("IOx router target has no vpg_number")
            if mode == "router-nat":
                if "nat_interface" not in normalized:
                    raise ValueError(
                        "IOx router-nat target has no nat_interface")
                normalized.setdefault("bt_listen_port", 6881)
                normalized.setdefault("nat_outside_owned", False)
        for key, low, high in (("vpg_number", 0, 31 if router else 4096),
                               ("bt_listen_port", 1, 65535)):
            if key in normalized:
                value = normalized[key]
                if isinstance(value, str) and value.isdigit():
                    value = int(value)
                if type(value) is not int or not low <= value <= high:
                    raise ValueError("invalid IOx target %s" % key)
                normalized[key] = value
        if "nat_interface" in normalized:
            _ascii_value(normalized["nat_interface"],
                         re.compile(r"^[A-Za-z][A-Za-z0-9./_-]{0,127}$"),
                         "nat_interface")
        if "nat_outside_owned" in normalized:
            value = normalized["nat_outside_owned"]
            if value in ("0", "1"):
                value = value == "1"
            if type(value) is not bool:
                raise ValueError("invalid IOx target nat_outside_owned")
            normalized["nat_outside_owned"] = value
        share_host = normalized.get("share_host_path")
        share_ios = normalized.get("share_ios_path")
        if (share_host is None) != (share_ios is None):
            raise ValueError("incomplete IOx share binding")
        if share_host is not None:
            if (not isinstance(share_host, str) or
                    re.fullmatch(r"/[A-Za-z0-9._/-]{1,255}", share_host) is None or
                    any(part in ("", ".", "..")
                        for part in share_host.split("/")[1:])):
                raise ValueError("invalid IOx target share_host_path")
            if (not isinstance(share_ios, str) or re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_-]{0,31}:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*",
                    share_ios) is None):
                raise ValueError("invalid IOx target share_ios_path")
        resources = normalized.get("resources")
        if resources is not None:
            _validate_resources(resources, router)
        for key in ("telemetry", "telemetry_stream", "log"):
            normalized[key] = _boolean_word(
                normalized.get(key, "on" if key == "telemetry" else "off"),
                key)
        required = {"model", "resources", "pkg", "target_fs", "package_fs",
                    "app_ip", "app_mask", "app_gateway", "ios_ssh_host"}
        if router:
            required.add("vpg_number")
            if mode == "router-nat":
                required.update(("nat_interface", "bt_listen_port",
                                 "nat_outside_owned"))
        else:
            required.update((vlan_key, "app_intf"))
        if mode == "routed":
            required.update(("svi_ip", "svi_mask", "guest_ip"))
        if self._strict_target and not required.issubset(normalized):
            # Field names only -- what the operator has to fill in on the
            # fleet row, never a value.
            raise ValueError("incomplete IOx target plan: missing %s" %
                             ", ".join(sorted(required - set(normalized))))
        return normalized

    def _preselect(self, request, action):
        if action == "install" or _get(request, "teardown_mode") == "force_agent_only":
            try:
                self.store.list(strict=True)
            except TypeError:
                self.store.list()
            return self._validate_target(_get(request, "target"), action), None
        record_id = _get(request, "record_id")
        try:
            record = self.store.get(record_id, strict=True)
        except TypeError:
            record = self.store.get(record_id)
        if record is None:
            raise ValueError("recorded uninstall record is unavailable")
        resolved = record.get("resolved") or {}
        if resolved.get("platform") != "iox" or not resolved.get("device_ip"):
            raise ValueError("recorded uninstall target is incomplete")
        target = self._record_target(
            record, self._validate_target(_get(request, "target"), action),
            action)
        return target, copy.deepcopy(record)

    def _base_result(self, attempt, code=0, category=None, detail=""):
        return {
            "result_code": code, "returncode": attempt.recipe_returncode,
            "recovery_code": attempt.recovery_code,
            "record_id": attempt.record_id,
            "iox_verification": _public_journal(attempt.journal),
            "iox_session": _session_summary(attempt.fence) if attempt.fence else None,
            "error_category": category,
            "detail": _bounded_text(detail or attempt.notice) if
                      (detail or attempt.notice) else "",
        }

    def _finalize(self, attempt, primary=None):
        if primary is not None and attempt.primary is None:
            attempt.primary = primary
        reaped = True
        if attempt.transport is not None:
            try:
                transport_reaped = attempt.transport.cancel_and_reap(
                    min(self._monotonic() + _SUPERVISOR_REAP_SECONDS,
                        attempt.session_deadline))
            except Exception:
                transport_reaped = False
            reaped = reaped and transport_reaped
        if attempt.supervisor is not None:
            deadline = min(self._monotonic() + _SUPERVISOR_REAP_SECONDS,
                           attempt.session_deadline)
            supervisor_reaped = attempt.supervisor.reap_all(deadline)
            reaped = reaped and supervisor_reaped
            if reaped and attempt.fence_owned:
                try:
                    self._fence_barrier(attempt, state="reaped")
                except Exception:
                    reaped = False
                    if attempt.primary is None:
                        attempt.primary = _ControllerFailure(
                            "journal_durability",
                            "unable to persist IOx reap acknowledgement", 5)
            if (reaped and attempt.fence_owned and
                    attempt.fence is not None and
                    attempt.fence.get("state") == "reaped" and
                    attempt.retire_device_on_success and
                    attempt.primary is None and attempt.finished_protocol and
                    attempt.recipe_returncode == 0 and
                    attempt.recovery_code in (None, 0)):
                attempt.retire_device_on_success = False
                try:
                    self._store_call(
                        "retire_device", (
                            _get(attempt.request, "device_id"),
                            "forced agent-only teardown; the record no longer describes this device"),
                        attempt=attempt, mutation=True,
                        required_completion=True)
                except _ControllerFailure as exc:
                    attempt.primary = exc
                except Exception:
                    attempt.primary = _ControllerFailure(
                        "journal_durability",
                        "forced teardown record retirement failed", 5)
            if supervisor_reaped:
                try:
                    reaped = attempt.supervisor.release(deadline) and reaped
                except Exception:
                    reaped = False
            else:
                attempt.supervisor.abandon(deadline)
        if not reaped:
            attempt.recovery_code = 5
            if attempt.primary is None:
                attempt.primary = _ControllerFailure(
                    "descendant_unreaped",
                    "device-capable descendants were not reaped", 5)
        try:
            deployment_records._invalidate_iox_capabilities(attempt.attempt_id)
        except Exception:
            pass
        attempt.invalidate_continuations()
        if attempt.lock_fd is not None:
            try:
                fcntl.flock(attempt.lock_fd, fcntl.LOCK_UN)
                os.close(attempt.lock_fd)
            except OSError:
                pass
        with self._active_lock:
            self._active.discard(attempt)
        failure = attempt.primary
        return self._base_result(attempt, failure.code if failure else 0,
                                 failure.category if failure else None,
                                 failure.detail if failure else "")

    def run_install(self, request, prepare, preflight, on_output, cancel):
        execution_started = self._monotonic()
        self._validate_request(request, "install")
        target, unused = self._preselect(request, "install")
        attempt = None
        try:
            attempt = self._new_attempt(
                "install", request, cancel, started=execution_started)
            attempt.target = target
            self._precheck_target_authority(attempt)
            self._resolve_credentials(attempt)
            self._discover_and_lock(attempt)
            self._recover_obligations(attempt)
            attempt.check()
            # Production collision evidence is always collected through the
            # supervised IOx transport.  Frozen in-process transport doubles
            # expose only the older callback seam and cannot classify the
            # combined read-only command without treating it as a mutation.
            import iox_transport
            if isinstance(attempt.transport, iox_transport.IoxTransport):
                self._ordinary_install_preflight(attempt)
            evidence = preflight(request, copy.deepcopy(attempt.identity))
            if evidence is None:
                raise ValueError("IOx preflight returned no evidence")
            with iox_transport.admit_wrapper(
                    _get(request, "wrapper_path"), self.snapshot_dir,
                    min(self._monotonic() + 120, attempt.session_deadline),
                    attempt.is_cancelled, monotonic_fn=self._monotonic) as snapshot:
                attempt.snapshot = snapshot
                minter = self.config.get("enrollment_token_minter")
                if callable(minter):
                    token = minter(_get(request, "device_id"))
                    if (not isinstance(token, str) or not token or
                            len(token) > 4096 or re.fullmatch(
                                r"[A-Za-z0-9._~+/-]+=*", token) is None):
                        raise ValueError("invalid enrollment token")
                    self._bind_catalog_token(attempt, token)
                try:
                    instruction_value = self.config[
                        "instruction_bootstrap_materializer"](
                            _get(request, "device_id"))
                except Exception:
                    raise _ControllerFailure(
                        "rejected", "IOx install controller failed", 2)
                with _admit_instruction_bootstrap(
                        instruction_value, self.snapshot_dir,
                        min(self._monotonic() + 120,
                            attempt.session_deadline),
                        attempt.is_cancelled,
                        self._monotonic) as instruction_snapshot:
                    attempt.instruction_snapshot = instruction_snapshot
                    record_id = prepare(
                        request, copy.deepcopy(attempt.identity))
                    if (not isinstance(record_id, str) or
                            not _RECORD_ID.fullmatch(record_id)):
                        raise ValueError("prepare returned invalid record_id")
                    attempt.record_id = record_id
                    self._fence_barrier(attempt, record_id=record_id)
                    observation, result, unused = self._verification_read(
                        attempt)
                    binding = {"wrapper_sha256": snapshot.sha256,
                               "package_sign_present":
                                   snapshot.package_sign_present,
                               "package_cert_present":
                                   snapshot.package_cert_present}
                    try:
                        attempt.journal = self._store_call(
                            "iox_begin", (
                                record_id, self.controller_id, attempt.board,
                                binding, observation,
                                _get(result, "transcript_ref")),
                            attempt=attempt, mutation=True)
                    except _ControllerFailure:
                        raise
                    except Exception:
                        raise _ControllerFailure(
                            "journal_durability",
                            "IOx journal creation failed", 5)
                    return self._run_recipe(attempt, "install", on_output)
        except _ControllerFailure as exc:
            if attempt is None:
                dummy = _Attempt(self, "install", request, cancel)
                dummy.record_id = None
                return self._base_result(dummy, exc.code, exc.category, exc.detail)
            return self._finalize(attempt, exc)
        except Exception as exc:
            if attempt is None:
                raise
            supplied_category = getattr(exc, "category", None)
            category = supplied_category or "rejected"
            return self._finalize(attempt, _ControllerFailure(
                category, _unexpected_detail("IOx install controller failed", exc),
                _RESULT_CODES.get(category, 2) if supplied_category else 2))

    def run_uninstall(self, request, prepare, preflight, on_output, cancel):
        execution_started = self._monotonic()
        self._validate_request(request, "uninstall")
        target, preliminary = self._preselect(request, "uninstall")
        attempt = None
        try:
            attempt = self._new_attempt(
                "uninstall", request, cancel, started=execution_started)
            attempt.target = target
            self._precheck_target_authority(attempt)
            if (preliminary is not None and
                    not (preliminary.get("resolved") or {}).get(
                        "device_identity")):
                attempt.notice = (
                    "historical identity unavailable; authorization used two "
                    "matching live identity reads")
            self._resolve_credentials(attempt)
            self._discover_and_lock(attempt)
            operation_record_id = attempt.record_id
            operation_journal = attempt.journal
            authorized_preliminary = preliminary
            try:
                recovered_obligation = self._recover_obligations(attempt)
                if (recovered_obligation is not None and
                        operation_record_id is not None and
                        recovered_obligation.get("record_id") ==
                        operation_record_id):
                    if (not isinstance(preliminary, dict) or
                            preliminary.get("iox_verification") !=
                            recovered_obligation):
                        raise _ControllerFailure(
                            "authority_mismatch",
                            "recorded recovery binding changed", 5)
                    authorized_preliminary = copy.deepcopy(preliminary)
                    authorized_preliminary["iox_verification"] = \
                        copy.deepcopy(attempt.journal)
            finally:
                # A predecessor obligation is recovered under this board lock,
                # but it is not the uninstall operation's authority.  Restore
                # the selected recorded binding (or the force operation's null
                # binding) before admitting the recipe or forming a result.
                attempt.record_id = operation_record_id
                attempt.journal = operation_journal
            attempt.check()
            preflight(request, copy.deepcopy(attempt.identity))
            authorized = prepare(request, copy.deepcopy(attempt.identity))
            mode = _get(request, "teardown_mode")
            if mode == "recorded":
                if authorized != attempt.record_id:
                    raise ValueError("recorded teardown authorization changed")
                try:
                    current = self.store.get(attempt.record_id, strict=True)
                except TypeError:
                    current = self.store.get(attempt.record_id)
                applying = copy.deepcopy(authorized_preliminary)
                applying["state"] = "applying"
                # OnboardService prepares recorded teardown by advancing the
                # selected lifecycle state under the durable store lock.  The
                # controller still requires every other authority field to
                # match its pre-contact snapshot exactly.
                if current not in (authorized_preliminary, applying):
                    raise ValueError("recorded teardown binding changed")
            elif authorized is not None:
                raise ValueError("force must remain recordless")
            if mode == "force_agent_only":
                attempt.retire_device_on_success = True
            result = self._run_recipe(attempt, "uninstall", on_output)
            return result
        except _ControllerFailure as exc:
            if attempt is None:
                dummy = _Attempt(self, "uninstall", request, cancel)
                return self._base_result(dummy, exc.code, exc.category, exc.detail)
            return self._finalize(attempt, exc)
        except Exception as exc:
            if attempt is None:
                raise
            supplied_category = getattr(exc, "category", None)
            category = supplied_category or "rejected"
            return self._finalize(attempt, _ControllerFailure(
                category, _unexpected_detail("IOx uninstall controller failed", exc),
                _RESULT_CODES.get(category, 2) if supplied_category else 2))

    def recover_board(self, board_identity, cancel):
        execution_started = self._monotonic()
        if (not isinstance(board_identity, str) or
                not _BOARD_ID.fullmatch(board_identity)):
            raise ValueError("invalid board_identity")
        try:
            obligations = self._store_call(
                "iox_obligations", (board_identity,),
                deadline=execution_started + self.session_seconds)
        except _ControllerFailure as exc:
            dummy = _Attempt(
                self, "recover", None, cancel, True,
                started=execution_started)
            return self._base_result(
                dummy, exc.code, exc.category, exc.detail)
        except Exception:
            dummy = _Attempt(
                self, "recover", None, cancel, True,
                started=execution_started)
            return self._base_result(
                dummy, 5, "journal_unreadable", "IOx journal is unreadable")
        if not obligations:
            dummy = _Attempt(self, "recover", None, cancel, True)
            session_path = os.path.join(
                self.session_dir, _board_key(board_identity) + ".json")
            if os.path.lexists(session_path):
                try:
                    fence = _read_json_strict(
                        session_path, _SESSION_FILE_BYTES)
                    self._validate_fence(fence, session_path)
                except Exception:
                    return self._base_result(
                        dummy, 5, "journal_unreadable",
                        "IOx session fence is unreadable")
                dummy.fence = fence
                if (fence["state"] == "active" and
                        fence["boot_id"] == _boot_id()):
                    return self._base_result(
                        dummy, 5, "descendant_unreaped",
                        "active same-boot IOx session fence")
            return self._base_result(dummy, 0)
        if any(not isinstance(journal, dict) or
               journal.get("controller_id") != self.controller_id
               for journal in obligations):
            dummy = _Attempt(self, "recover", None, cancel, True)
            return self._base_result(
                dummy, 5, "authority_mismatch",
                "foreign IOx journal authority")
        if len(obligations) != 1:
            dummy = _Attempt(self, "recover", None, cancel, True)
            return self._base_result(dummy, 3, "reconciliation_required",
                                     "conflicting board obligations")
        journal = obligations[0]
        try:
            record = self.store.get(journal["record_id"], strict=True)
        except TypeError:
            record = self.store.get(journal["record_id"])
        if (not isinstance(record, dict) or
                record.get("iox_verification") != journal):
            dummy = _Attempt(self, "recover", None, cancel, True)
            dummy.record_id = journal["record_id"]
            return self._base_result(
                dummy, 5, "authority_mismatch",
                "IOx recovery authority changed")
        recorded_credential = (record.get("resolved") or {}).get(
            "credential_profile_id")
        job_id, device_id, credential_ref = _service_job_context(
            cancel, record.get("device_id", "recovery"),
            recorded_credential)
        request = {"device_id": device_id,
                   "job_id": job_id, "record_id": journal["record_id"],
                   "teardown_mode": "none",
                   "target": self._record_target(record, {}, "recover")}
        request["credential_ref"] = credential_ref
        attempt = None
        cancellation_reported = _cancelled(cancel)
        recovery_cancel = (lambda: False) if cancellation_reported else cancel
        try:
            attempt = self._new_attempt(
                "recover", request, recovery_cancel, True,
                started=execution_started)
            if cancellation_reported:
                attempt.primary = _ControllerFailure(
                    "cancelled", "operation cancelled", 130)
            attempt.target = self._validate_target(request["target"], "recover")
            attempt.board = board_identity
            attempt.record_id = journal["record_id"]
            attempt.journal = journal
            self._resolve_credentials(attempt)
            # Recovery already has a durable physical identity; lock/fence first.
            self._acquire_known_board_lock(attempt)
            self._start_supervisor(attempt)
            self._admit_fence(attempt)
            attempt.transport = self._make_transport(attempt, attempt.supervisor)
            self._strict_recovery_binding(attempt, journal)
            self._revalidate_known_identity(attempt, journal)
            code = self._recover_journal(attempt, journal, initiating=False)
            attempt.recovery_code = code
            if code == 3:
                attempt.primary = _ControllerFailure(
                    "reconciliation_required",
                    _reconciliation_detail("recovery unresolved",
                                           attempt.journal), code)
            elif code:
                attempt.primary = _ControllerFailure(
                    "readback_unknown", "recovery unresolved", code)
            return self._finalize(attempt)
        except _ControllerFailure as exc:
            if attempt is None:
                dummy = _Attempt(self, "recover", request, cancel, True)
                dummy.record_id = journal["record_id"]
                dummy.journal = journal
                return self._base_result(dummy, exc.code, exc.category, exc.detail)
            return self._finalize(attempt, exc)
        except Exception:
            if attempt is None:
                raise
            return self._finalize(attempt, _ControllerFailure(
                "journal_durability", "IOx recovery controller failed", 5))

    def reconcile_enabled(self, record_id, transaction_id, expected_revision,
                          acknowledge_external_resolution, cancel):
        execution_started = self._monotonic()
        if (not isinstance(record_id, str) or
                _RECORD_ID.fullmatch(record_id) is None or
                not isinstance(transaction_id, str) or
                _HEX32.fullmatch(transaction_id) is None or
                type(expected_revision) is not int or
                not 0 <= expected_revision <= _MAX_INT):
            raise ValueError("invalid reconciliation binding")
        if acknowledge_external_resolution is not True:
            raise ValueError("acknowledge_external_resolution is required")
        try:
            record = self.store.get(record_id, strict=True)
        except TypeError:
            record = self.store.get(record_id)
        if record is None:
            raise ValueError("unknown record")
        journal = record.get("iox_verification")
        if (journal is not None and
                (not isinstance(journal, dict) or
                 journal.get("controller_id") != self.controller_id)):
            dummy = _Attempt(self, "reconcile_enabled", None, cancel, True)
            dummy.record_id = record_id
            dummy.journal = journal if isinstance(journal, dict) else None
            return self._base_result(
                dummy, 5, "authority_mismatch",
                "foreign IOx journal authority")
        if (journal is None or journal.get("transaction_id") != transaction_id or
                journal.get("revision") != expected_revision or
                journal.get("phase") != "indeterminate"):
            raise ValueError("stale reconciliation binding")
        recorded_credential = (record.get("resolved") or {}).get(
            "credential_profile_id")
        job_id, device_id, credential_ref = _service_job_context(
            cancel, record["device_id"], recorded_credential)
        request = {"device_id": device_id, "job_id": job_id,
                   "record_id": record_id, "teardown_mode": "none",
                   "target": self._record_target(
                       record, {}, "reconcile_enabled")}
        request["credential_ref"] = credential_ref
        attempt = None
        try:
            attempt = self._new_attempt(
                "reconcile_enabled", request, cancel, True,
                started=execution_started)
            attempt.target = request["target"]
            attempt.board = journal["board_identity"]
            attempt.record_id = record_id
            attempt.journal = journal
            self._resolve_credentials(attempt)
            self._acquire_known_board_lock(attempt)
            self._start_supervisor(attempt)
            self._admit_fence(attempt)
            attempt.transport = self._make_transport(attempt, attempt.supervisor)
            self._strict_recovery_binding(attempt, journal)
            self._revalidate_known_identity(attempt, journal)
            observation, result, unused = self._verification_read(attempt)
            if observation["state"] != "enabled":
                attempt.primary = _ControllerFailure(
                    "reconciliation_required",
                    "fresh read did not establish enabled: run "
                    "'app-hosting verification enable' on the device, "
                    "confirm 'show app-hosting infra' reports it enabled, "
                    "then retry reconcile-enabled", 3)
            else:
                refs = [_get(result, "transcript_ref")]
                self._event(attempt, "reconcile_enabled", {
                    "observation": observation,
                    "acknowledge_external_resolution": True,
                    "transcript_refs": refs})
            return self._finalize(attempt)
        except _ControllerFailure as exc:
            if attempt is None:
                dummy = _Attempt(self, "reconcile_enabled", request, cancel, True)
                dummy.record_id, dummy.journal = record_id, journal
                return self._base_result(dummy, exc.code, exc.category, exc.detail)
            return self._finalize(attempt, exc)
        except Exception:
            if attempt is None:
                raise
            return self._finalize(attempt, _ControllerFailure(
                "journal_durability", "IOx reconciliation controller failed", 5))

    def _render_command(self, attempt, name):
        if name not in _COMMANDS:
            raise _ControllerFailure("unsupported_syntax", "unknown IOx command", 2)
        target = attempt.target
        appid = self.application_id
        mode = target.get("management_type", "routed")
        package_fs = target.get("package_fs", "flash:")
        target_fs = target.get("target_fs", "sdflash:")
        app_intf = target.get("app_intf", "AppGigabitEthernet1/1")
        router = mode in _ROUTER_MODES
        # routed derives the app's addressing from the SVI it creates; inband
        # and the router modes carry it directly.
        app_keys = mode != "routed"
        vlan = target.get("inband_vlan" if mode == "inband" else "vlan", 666)
        guest_ip = target.get("app_ip" if app_keys else "guest_ip",
                              "192.0.2.2")
        mask = target.get("app_mask" if app_keys else "svi_mask",
                          "255.255.255.252")
        gateway = target.get("app_gateway" if app_keys else "svi_ip",
                             "192.0.2.1")
        ios_ssh_host = target.get("ios_ssh_host", gateway)
        share_host = target.get("share_host_path")
        share_ios = target.get("share_ios_path")
        force = _get(attempt.request, "teardown_mode") == "force_agent_only"
        vpg = target.get("vpg_number")

        def emptied_app_block():
            # A Catalyst 8000V (IOS-XE 17.15.5) keeps an app's resource
            # profile association after `app-hosting uninstall`, even though
            # the running-config already shows the block bare. Removing the
            # block in that state poisons the name: every later
            # `app-hosting appid <name>` answers "IOxMan: Resource
            # Profile-names is not specified" until the router reloads
            # (issue #230; the IE-3400 does not care). Explicitly taking the
            # profile, docker options, gateway and vnic back out of the block
            # first clears that association; on a device where the block
            # never existed this creates and removes an empty block, which
            # the same router accepts. Every line answers silently.
            if router:
                vnic = (" no app-vnic gateway0 virtualportgroup %s "
                        "guest-interface 0" % vpg_plan())
            else:
                # The vnic keyword is the bare AppGigabitEthernet, exactly as
                # configure_app writes it; the slot/port form is the physical
                # trunk interface and IOS rejects it here (IE-3400, 17.15.4).
                vnic = " no app-vnic AppGigabitEthernet trunk"
            return ["app-hosting appid %s" % appid,
                    " no app-resource docker",
                    " no app-resource profile custom",
                    " no app-default-gateway %s guest-interface 0" % gateway,
                    vnic,
                    "exit"]
        nat_interface = target.get("nat_interface", "")
        bt_port = target.get("bt_listen_port", 6881)
        nat_outside_owned = target.get("nat_outside_owned") in (True, 1, "1")

        def vpg_plan():
            # Every command that touches the router footprint needs the group
            # number (and, with NAT, the outside interface); a target without
            # them is refused here rather than rendered as garbage.
            if vpg is None or (mode == "router-nat" and not nat_interface):
                raise _ControllerFailure(
                    "unsupported_syntax",
                    "IOx router target has no VirtualPortGroup plan", 2)
            return vpg
        transaction = attempt.journal.get("transaction_id") if attempt.journal else None
        wrapper = (package_fs + "iris-" + transaction + ".tar"
                   if transaction else package_fs + target.get(
                       "pkg", "iris-arm64.tar"))
        if not wrapper.startswith(package_fs):
            raise _ControllerFailure(
                "unsupported_syntax", "wrapper filesystem changed", 2)
        wrapper_name = wrapper[len(package_fs):]
        if _SAFE_BASENAME.fullmatch(wrapper_name) is None:
            raise _ControllerFailure(
                "unsupported_syntax", "invalid IOS wrapper filename", 2)
        wrapper_pattern = re.escape(wrapper_name)
        certificate = package_fs + "iris-ca.pem"
        instruction_source = (package_fs + "iris-instructions-" +
                              transaction + ".envelope"
                              if transaction else None)
        instruction_name = ("iris-instructions-" + transaction +
                            ".envelope" if transaction else None)
        stage_dir = target_fs + "guest-share/iris"
        cleanup_common = emptied_app_block() + [
            "no app-hosting appid %s" % appid,
            "no event manager applet IRIS-AGENT",
            "no event manager applet IRIS-COPYROOT",
            "no event manager applet IRIS-RECLAIM",
            "no event manager applet IRIS-RECLAIM-BUNDLE"]
        cleanup_named = [
            "no logging buffered discriminator IRISQ",
            "no logging console discriminator IRISQ",
            "no logging monitor discriminator IRISQ",
            "no logging discriminator IRISQ",
            "no ip http client secure-trustpoint IRIS",
            "no crypto pki trustpoint IRIS"]
        if name == "iox_status":
            lines = ["show iox"]
        elif name == "app_list":
            lines = ["show app-hosting list"]
        elif name == "routing_prereq":
            lines = (["show running-config | include no ip routing",
                      "show ip route | include Gateway|Default gateway"]
                     if mode == "routed" else ["show ip interface brief"])
        elif name == "storage_prereq":
            lines = (["show sdflash: filesys"] if target_fs == "sdflash:"
                     else ["dir %s" % target_fs])
        elif name == "clock":
            lines = ["show clock"]
        elif name == "prepare_iox_scp":
            # `file prompt quiet` lets the device-side `copy https:` below
            # run without a destination prompt, on every platform -- it is
            # not part of the SCP decision.
            #
            # `ip scp server enable` is no longer for the package (nothing is
            # pushed to the device any more) and is now rendered ONLY for a
            # target with NO bind-mounted share: an IE-3x00 cannot mount
            # sdflash: into the app, so its agent hands the image over by
            # SCP-pushing to guest-share (device/agent/iris_agent.py,
            # _push_scratch). Every share-configured target (Catalyst 9300,
            # Catalyst 8000) hands the image to IOS through the mount plus an
            # IOS-internal plain `copy` and has NO scp fallback, so IRIS must
            # not switch the device's SCP server on there (issue #228).
            lines = ["configure terminal", "iox", "file prompt quiet"]
            if not share_ios:
                lines.append("ip scp server enable")
            lines.append("end")
        elif name == "configure_trustpoint":
            # The block device/device-install.sh pastes: drop any earlier
            # IRIS trustpoint, re-add it, paste the public catalog
            # certificate, bind the HTTP client to it. The transport answers
            # the two PKI confirmations and drives the paste.
            lines = (["configure terminal", "no crypto pki trustpoint IRIS",
                      "crypto pki trustpoint IRIS", " enrollment terminal",
                      " revocation-check none", "exit",
                      "crypto pki authenticate IRIS"] +
                     self._catalog_certificate_lines() +
                     ["quit", "ip http client secure-trustpoint IRIS", "end"])
        elif name == "http_client_credentials":
            device_id = _get(attempt.request, "device_id")
            token = attempt.credentials.get("catalog_token", "")
            if (not isinstance(device_id, str) or
                    _BOARD_ID.fullmatch(device_id) is None or not token or
                    re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token) is None):
                raise _ControllerFailure(
                    "unsupported_syntax_local",
                    "IOx artifact fetch credentials are invalid", 2)
            # The transport redacts the token from every capture and
            # transcript the same way it does for the app block's run-opts.
            lines = ["configure terminal",
                     "ip http client username %s" % device_id,
                     "ip http client password 0 %s" % token, "end"]
        elif name == "clear_http_client":
            lines = ["configure terminal", "no ip http client username",
                     "no ip http client password", "end"]
        elif name in ("fetch_wrapper", "fetch_certificate",
                      "fetch_instructions"):
            if name == "fetch_wrapper":
                if transaction is None:
                    raise _ControllerFailure(
                        "unsupported_syntax", "missing wrapper transaction", 2)
                source = target.get("pkg", "iris-arm64.tar")
                destination, probe = wrapper, wrapper_pattern
            elif name == "fetch_certificate":
                source = "iris-catalog.pem"
                destination, probe = certificate, "iris-ca\\.pem"
            else:
                if instruction_source is None:
                    raise _ControllerFailure(
                        "unsupported_syntax", "missing instruction transaction", 2)
                source = "staging/%s/%s" % (
                    self._fetch_device_id(attempt), instruction_name)
                destination, probe = instruction_source, re.escape(
                    instruction_name)
            lines = ["copy %s %s" % (self._artifact_url(attempt, source),
                                     destination),
                     "dir %s | include %s" % (package_fs, probe)]
        elif name == "configure_network":
            lines = ["configure terminal", "iox"]
            if mode == "routed":
                lines.extend([
                    "vlan %s" % vlan,
                    "interface %s" % app_intf,
                    " switchport mode trunk",
                    " switchport trunk allowed vlan %s" % vlan,
                    "interface Vlan%s" % vlan,
                    " description IRIS IOx app inline",
                    " ip address %s %s" % (gateway, mask),
                    " no shutdown"])
            elif router:
                # The VirtualPortGroup and NAT footprint device/router-install.sh
                # creates for Guest Shell, described so an operator can tell
                # whose it is; only a record-backed teardown removes it.
                vpg_plan()
                lines.extend([
                    "interface VirtualPortGroup%s" % vpg,
                    " " + _VPG_DESCRIPTION,
                    " ip address %s %s" % (gateway, mask)])
                if mode == "router-nat":
                    lines.append(" ip nat inside")
                lines.append(" no shutdown")
                if mode == "router-nat":
                    network = ipaddress.IPv4Network(
                        "%s/%s" % (guest_ip, mask), strict=False)
                    lines.extend([
                        "interface %s" % nat_interface,
                        " ip nat outside",
                        "ip access-list standard IRIS-NAT-%s" % vpg,
                        " permit %s %s" % (network.network_address,
                                            network.hostmask),
                        "ip nat inside source list IRIS-NAT-%s interface %s "
                        "overload" % (vpg, nat_interface),
                        "ip nat inside source static tcp %s %s interface %s %s"
                        % (guest_ip, bt_port, nat_interface, bt_port)])
            else:
                lines.extend([
                    "interface %s" % app_intf,
                    " switchport mode trunk",
                    " switchport trunk allowed vlan add %s" % vlan])
            # Same rule as prepare_iox_scp above: the SCP server goes on only
            # where the app has no bind-mounted share to hand the image
            # through (IE-3x00). Issue #228.
            lines.append("file prompt quiet")
            if not share_ios:
                lines.append("ip scp server enable")
            lines.append("end")
        elif name == "mkdir_share":
            lines = (["mkdir %s" % share_ios] if share_ios
                     else ["dir %s" % target_fs])
        elif name in ("app_stop", "app_deactivate", "app_uninstall",
                      "app_activate", "app_start"):
            verb = name.split("_", 1)[1]
            lines = ["app-hosting %s appid %s" % (verb, appid)]
        elif name == "remove_app_config":
            lines = (["configure terminal"] + emptied_app_block() +
                     ["no app-hosting appid %s" % appid, "end"])
        # The app's persist-disk is carved out of the SAME filesystem the
        # image is staged on when IOx runs on a router: a Catalyst 8000V has
        # one 4.8 GiB bootflash: and nothing else. Placement transiently needs
        # the IOS-side scratch AND the root copy at once (~2x the image), so a
        # 2 GiB reservation left a ~1 GiB image with nowhere to land and the
        # agent reported flash_full on a device that looked far from full
        # (issue #238). Switches keep 2048: IOx there lives on sdflash:
        # (IE-3400: 9.6 GiB) or flash:, separate from the staging budget.
        # 1024 MiB still holds any image the swarm can hand this platform,
        # since a bigger one could not be placed on bootflash: anyway.
        elif name == "configure_app":
            catalog_url = self.config.get("catalog_url")
            if catalog_url is None:
                if self._strict_target:
                    raise _ControllerFailure(
                        "unsupported_syntax_local",
                        "trusted IOx catalog URL is not configured", 2)
                # Compatibility for injected, non-production transport
                # doubles.  The real transport never receives this value.
                catalog_url = "https://iris.invalid:8443"
            ssh_user = attempt.credentials.get("device_user", "")
            ssh_password = attempt.credentials.get("device_pass", "")
            token = attempt.credentials.get("catalog_token", "")
            if (_SAFE_USER.fullmatch(ssh_user) is None or not token or
                    re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token) is None):
                raise _ControllerFailure(
                    "unsupported_syntax_local",
                    "IOx application credentials are invalid", 2)
            if router:
                vpg_plan()
                vnic = [
                    " app-vnic gateway0 virtualportgroup %s guest-interface 0"
                    % vpg,
                    "  guest-ipaddress %s netmask %s" % (guest_ip, mask)]
            else:
                vnic = [
                    " app-vnic AppGigabitEthernet trunk",
                    "  vlan %s guest-interface 0" % vlan,
                    "   guest-ipaddress %s netmask %s" % (guest_ip, mask)]
            lines = [
                "configure terminal",
                "app-hosting appid %s" % appid] + vnic + [
                " app-default-gateway %s guest-interface 0" % gateway,
                " app-resource profile custom",
                "  cpu 400", "  memory 768",
                "  persist-disk %d" % (1024 if router else 2048),
                "  vcpu 1", " app-resource docker",
                '  run-opts 1 "-e IRIS_DEVICE_ID=%s"' %
                    _get(attempt.request, "device_id"),
                '  run-opts 2 "-e IRIS_DEVICE_SSH_PASS=%s"' % ssh_password,
                '  run-opts 3 "-e IRIS_CATALOG_TOKEN=%s"' % token,
                '  run-opts 4 "-e IRIS_CATALOG_URL=%s"' % catalog_url,
                '  run-opts 5 "-e IRIS_DEVICE_SSH_HOST=%s"' % ios_ssh_host,
                '  run-opts 6 "-e IRIS_DEVICE_SSH_USER=%s"' % ssh_user,
                '  run-opts 7 "-e IRIS_DEVICE_PLATFORM=iox"',
                '  run-opts 8 "-e IRIS_TARGET_FS=%s"' % target_fs,
                '  run-opts 9 "-e IRIS_TELEMETRY=%s"' % target["telemetry"],
                '  run-opts 10 "-e IRIS_TELEMETRY_STREAM=%s"' %
                    target["telemetry_stream"],
                '  run-opts 11 "-e IRIS_LOG=%s"' % target["log"]]
            if share_host:
                lines.extend([
                    '  run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"',
                    '  run-opts 13 "-e IRIS_SHARE_IOS_PATH=%s"' % share_ios,
                    '  run-opts 14 "-v %s:/mnt/share"' % share_host])
            lines.append("end")
        elif name == "app_install":
            if transaction is None:
                raise _ControllerFailure(
                    "unsupported_syntax", "missing wrapper transaction", 2)
            lines = ["app-hosting install appid %s package %s" %
                     (appid, wrapper)]
        elif name == "copy_certificate":
            lines = ["app-hosting data appid %s copy %s iris-catalog.pem" %
                     (appid, certificate)]
        elif name == "copy_instructions":
            if instruction_source is None:
                raise _ControllerFailure(
                    "unsupported_syntax", "missing instruction transaction", 2)
            lines = [
                "app-hosting data appid %s copy %s "
                "iris-instructions.bootstrap" % (appid, instruction_source)]
        elif name == "save":
            if (_get(attempt.request, "teardown_mode") ==
                    "force_agent_only"):
                raise _ControllerFailure(
                    "unsupported_syntax", "force teardown cannot save config", 2)
            lines = ["write memory"]
        elif name == "remove_wrapper":
            lines = ["delete /force %s" % wrapper,
                     "dir %s | include %s" %
                     (package_fs, wrapper_pattern)]
        elif name == "remove_certificate":
            lines = ["delete /force %s" % certificate,
                     "dir %s | include iris-ca.pem" % package_fs]
        elif name == "remove_instructions":
            if instruction_source is None:
                raise _ControllerFailure(
                    "unsupported_syntax", "missing instruction transaction", 2)
            lines = ["delete /force %s" % instruction_source,
                     "dir %s | include %s" %
                     (package_fs, re.escape(instruction_name))]
        elif name == "cleanup_config":
            lines = ["configure terminal"] + cleanup_common
            if mode == "inband" or force:
                lines.extend(cleanup_named)
            elif router:
                # device/router-uninstall.sh's order: the swarm-port static
                # translation and the overload rule before the ACL they
                # reference, the outside marking only when the record says
                # IRIS added it, then the group itself. IOS keeps an overload
                # rule while translations still reference it; the residue
                # probe below reports that instead of guessing.
                vpg_plan()
                if mode == "router-nat":
                    lines.extend([
                        "no ip nat inside source static tcp %s %s interface "
                        "%s %s" % (guest_ip, bt_port, nat_interface, bt_port),
                        "no ip nat inside source list IRIS-NAT-%s interface "
                        "%s overload" % (vpg, nat_interface),
                        "no ip access-list standard IRIS-NAT-%s" % vpg])
                    if nat_outside_owned:
                        lines.extend(["interface %s" % nat_interface,
                                      " no ip nat outside", "exit"])
                lines.extend(["no interface VirtualPortGroup%s" % vpg,
                              "no ip http client secure-trustpoint IRIS",
                              "no crypto pki trustpoint IRIS"])
            else:
                lines.extend(["no interface Vlan%s" % vlan,
                              "no vlan %s" % vlan,
                              "no ip http client secure-trustpoint IRIS",
                              "no crypto pki trustpoint IRIS"])
            lines.append("end")
        elif name == "cleanup_files":
            lines = ["delete /force %s" % certificate,
                     "delete /force %siris-catalog.pem" % package_fs]
            if wrapper:
                lines.insert(0, "delete /force %s" % wrapper)
            if share_ios:
                lines.extend([
                    "delete /force %s/iris-staged.bin" % share_ios,
                    "delete /force %s/iris-staged.bin.part" % share_ios,
                    "delete /force %s/iris-probe.txt" % share_ios,
                    "delete /force /recursive %s/iris" % share_ios])
            lines.append("delete /force /recursive %s" % stage_dir)
        elif name == "cleanup_config_probe":
            include = ("app-hosting appid %s|applet IRIS-|crypto pki "
                       "trustpoint IRIS|discriminator IRISQ" % appid)
            if mode == "routed" and not force:
                include += "|interface Vlan%s|^vlan %s$" % (vlan, vlan)
            elif router and not force:
                vpg_plan()
                include += "|interface VirtualPortGroup%s$" % vpg
                if mode == "router-nat":
                    include += (
                        "|ip access-list standard IRIS-NAT-%s$"
                        "|ip nat inside source list IRIS-NAT-%s "
                        "|ip nat inside source static tcp %s "
                        % (vpg, vpg, guest_ip))
            lines = ["show app-hosting list",
                     "show running-config | include %s" % include]
        elif name == "cleanup_stage_probe":
            stage_patterns = [wrapper_pattern]
            stage_patterns.extend(["iris-ca\\.pem", "iris-catalog\\.pem"])
            lines = ["dir %s | include %s" %
                     (package_fs, "|".join(stage_patterns)),
                     "dir %s" % stage_dir]
            if share_ios:
                lines.append(
                    "dir %s | include iris-staged.bin|iris-probe.txt|iris" %
                    share_ios)
        else:
            raise _ControllerFailure(
                "unsupported_syntax", "unrendered IOx command", 2)
        return _command_bytes(lines)

    def _fetch_device_id(self, attempt):
        device_id = _get(attempt.request, "device_id")
        if (not isinstance(device_id, str) or
                _BOARD_ID.fullmatch(device_id) is None or
                device_id in (".", "..")):
            raise _ControllerFailure(
                "unsupported_syntax_local", "invalid IOx device id", 2)
        return device_id

    def _artifact_url(self, attempt, relative):
        base = self.config.get("artifact_url")
        if base is None:
            if self._strict_target:
                raise _ControllerFailure(
                    "unsupported_syntax_local",
                    "trusted IOx artifact URL is not configured", 2)
            # Compatibility for injected, non-production transport doubles,
            # as for the catalog URL in configure_app.
            base = "https://iris.invalid:8000"
        return base.rstrip("/") + _ARTIFACT_ROUTE % (
            self._fetch_device_id(attempt), relative)

    def _catalog_certificate_lines(self):
        """The public catalog certificate as the lines the trustpoint paste
        sends: PEM text, stripped, without the blank line that would end the
        paste early."""
        path = self.config.get("catalog_certificate_path")
        if path is None:
            raise _ControllerFailure(
                "unsupported_syntax_local",
                "trusted IOx catalog certificate is not configured", 2)
        try:
            descriptor = _open_public_certificate(path, self._strict_target)
        except Exception:
            raise _ControllerFailure(
                "rejected", "IOx catalog certificate is unreadable", 2)
        try:
            chunks = []
            remaining = 65537
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        lines = [line.strip() for line in
                 b"".join(chunks).decode("ascii", "replace").splitlines()]
        lines = [line for line in lines if line and not line.startswith("!")]
        if not lines:
            raise _ControllerFailure(
                "rejected", "IOx catalog certificate is empty", 2)
        return lines

    def _fetch_deadline(self, attempt, purpose):
        # The budgets the SCP uploads had: one shared ordinary window for the
        # wrapper and certificate, started by whichever fetches first, and a
        # shorter one for the instruction envelope.
        if purpose == "fetch_instructions":
            if attempt.instruction_upload_deadline is None:
                attempt.instruction_upload_deadline = attempt.deadline(
                    _INSTRUCTION_UPLOAD_SECONDS, ordinary=True)
            return attempt.instruction_upload_deadline
        if attempt.upload_deadline is None:
            attempt.upload_deadline = attempt.deadline(1800, ordinary=True)
        return attempt.upload_deadline

    def _ensure_trustpoint(self, attempt, protocol):
        """Install the catalog trustpoint once per attempt, before the first
        device-side `copy https:` has to validate the artifact server."""
        if protocol.get("trust_configured"):
            return
        result, unused = self._command(
            attempt, "configure_trustpoint",
            self._render_command(attempt, "configure_trustpoint"),
            180, ordinary=True)
        if (not self._transport_ok(result) or
                _get(result, "error_category")):
            raise _ControllerFailure(
                _get(result, "error_category") or "rejected",
                _command_failure_detail("configure_trustpoint", result), 4)
        protocol["trust_configured"] = True

    @staticmethod
    def _verify_fetched(purpose, result, basename, expected_size):
        """IOS's own transfer report and the closing `dir` probe must both
        name the source's exact byte count."""
        stdout = bytes(_get(result, "stdout", b""))
        copied = re.search(br"(?m)^\s*(\d{1,20}) bytes copied\b", stdout)
        listed = re.search(
            br"(?m)^\s*\d+\s+-[rwx-]{3}\s+(\d{1,20})\s+.*\s" +
            re.escape(basename.encode("ascii")) + br"\s*$", stdout)
        if copied is None or listed is None:
            raise _ControllerFailure(
                "readback_unknown",
                "IOx artifact fetch was not confirmed: %s" % purpose, 4)
        if (int(copied.group(1)) != expected_size or
                int(listed.group(1)) != expected_size):
            raise _ControllerFailure(
                "readback_mismatch",
                "IOx artifact size mismatch: %s" % purpose, 4)

    def _fetch(self, attempt, purpose, expected_size):
        """Have the device copy one artifact from the artifact server.

        The copy rides the catalog trustpoint installed by _ensure_trustpoint
        and authenticates with the device's own enrollment credential, which
        is configured as the IOS HTTP client username/password for exactly
        the span of the copy and removed afterwards -- also after a failure
        or a cancellation, as bounded safety work. This replaced the SCP push
        so onboarding needs no service enabled on the device for its sake.
        """
        if attempt.durability_uncertain:
            raise _ControllerFailure(
                "journal_durability",
                "artifact fetch blocked after durability failure", 5)
        transaction = attempt.journal.get("transaction_id") if attempt.journal else None
        basename = {
            "fetch_wrapper": "iris-%s.tar" % transaction,
            "fetch_certificate": "iris-ca.pem",
            "fetch_instructions": "iris-instructions-%s.envelope" % transaction,
        }[purpose]
        deadline = self._fetch_deadline(attempt, purpose)
        primary = None
        result = None
        try:
            configured, unused = self._command(
                attempt, "http_client_credentials",
                self._render_command(attempt, "http_client_credentials"),
                45, ordinary=True)
            if (not self._transport_ok(configured) or
                    _get(configured, "error_category")):
                raise _ControllerFailure(
                    _get(configured, "error_category") or "rejected",
                    "IOx HTTP client credentials could not be configured", 4)
            result, unused = self._command(
                attempt, purpose, self._render_command(attempt, purpose),
                deadline=deadline)
            if (not self._transport_ok(result) or
                    _get(result, "error_category")):
                raise _ControllerFailure(
                    _get(result, "error_category") or "rejected",
                    _command_failure_detail(purpose, result), 4)
            import iox_transport
            if isinstance(attempt.transport, iox_transport.IoxTransport):
                # Injected doubles answer with no device output; the size
                # proof is a property of the real device dialogue.
                self._verify_fetched(purpose, result, basename, expected_size)
        except _ControllerFailure as exc:
            primary = exc
        cleanup_failure = None
        previous = attempt.safety_recovery
        attempt.safety_recovery = True
        try:
            cleared, unused = self._command(
                attempt, "clear_http_client",
                self._render_command(attempt, "clear_http_client"), 45)
            if (not self._transport_ok(cleared) or
                    _get(cleared, "error_category")):
                cleanup_failure = _ControllerFailure(
                    _get(cleared, "error_category") or "rejected",
                    "IOx HTTP client credentials could not be removed", 4)
        except _ControllerFailure as exc:
            cleanup_failure = exc
        finally:
            attempt.safety_recovery = previous
        if primary is not None:
            raise primary
        if cleanup_failure is not None:
            raise cleanup_failure
        return result

    def _publish_instruction_source(self, attempt, snapshot):
        """Place the sealed envelope where the artifact server serves it to
        this device alone (staging/<device-id>/, HTTP Basic bound to that
        id, mode 0600, swept by the server if a crash leaves it behind).
        Returns the path to remove once the device has its copy."""
        artifacts_dir = self.config.get("artifacts_dir")
        if artifacts_dir is None:
            if self._strict_target:
                raise _ControllerFailure(
                    "unsupported_syntax_local",
                    "IOx artifacts directory is not configured", 2)
            return None
        device_id = self._fetch_device_id(attempt)
        directory = os.path.join(artifacts_dir, "staging", device_id)
        path = os.path.join(directory, "iris-instructions-%s.envelope" %
                            attempt.journal["transaction_id"])
        temporary = None
        try:
            chunks = []
            offset = 0
            while offset <= _INSTRUCTION_MAX_BYTES:
                chunk = os.pread(snapshot.fd, 65536, offset)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            body = b"".join(chunks)
            if not 1 <= len(body) <= _INSTRUCTION_MAX_BYTES:
                raise ValueError("size")
            os.makedirs(directory, 0o700, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                dir=directory, prefix=".iris-instructions-", suffix=".tmp")
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, body)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            temporary = None
            return path
        except Exception:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise _ControllerFailure(
                "rejected", "IOx instruction source could not be published", 4)

    def _begin_install(self, attempt):
        journal = attempt.journal
        refs = lambda result: [_get(result, "transcript_ref")]
        if journal["package_sign_present"] or journal["package_cert_present"]:
            self._event(attempt, "unchanged", {"reason": "marker_present",
                "observation": None, "transcript_refs": []})
            return
        if journal["prior_state"] == "disabled":
            self._event(attempt, "unchanged", {"reason": "initially_disabled",
                "observation": None, "transcript_refs": []})
            return
        if journal["prior_state"] == "unknown":
            self._event(attempt, "unchanged", {"reason": "initial_read_unknown",
                "observation": None, "transcript_refs": []})
            raise _ControllerFailure("readback_unknown", "initial verification read unknown", 4)
        observation, result, unused = self._verification_read(attempt)
        if observation["state"] != "enabled":
            self._event(attempt, "unchanged", {"reason": "pre_disable_changed",
                "observation": observation, "transcript_refs": refs(result)})
            raise _ControllerFailure("readback_unknown", "pre-disable verification changed", 4)
        retry = None
        for send_index in range(3):
            # Verification is restored at ``deployed`` before activate/start;
            # only disable, disabled readback and the bounded install wait can
            # consume time while the device remains disabled.
            required = (45 + 45 + self.config["install_timeout"] +
                        self.reserve_seconds)
            if attempt.remaining() < required:
                raise _ControllerFailure(
                    "timeout", "insufficient restoration reserve", 4)
            evidence = {"observation": observation, "retry_command": retry,
                        "transcript_refs": refs(result)}
            capability = None
            if retry is not None:
                capability = deployment_records._issue_iox_capability(
                    self.controller_id, attempt.attempt_id,
                    journal["record_id"], journal["transaction_id"],
                    attempt.board, attempt.journal["revision"],
                    attempt.journal["phase"], "disable_intent", evidence)
            self._event(attempt, "disable_intent", evidence,
                        capability=capability, ack=True)
            disable_send = self._issue_continuation(
                attempt, "disable_send")
            self._consume_continuation(
                attempt, disable_send, "disable_send")
            disabled_result, disabled_context = self._command(
                attempt, "verification_disable", _VERIFY_DISABLE, 45)
            category = _get(disabled_result, "error_category")
            if category == "caf_transient":
                if send_index == 2:
                    raise _ControllerFailure(
                        "caf_transient", "CAF retry budget exhausted")
                retry = {
                    "transcript_id": _get(disabled_result,
                                           "transcript_ref")["id"],
                    "command_id": disabled_context["command_id"],
                }
                observation, result, unused = self._verification_read(attempt)
                if observation["state"] != "enabled":
                    raise _ControllerFailure("reconciliation_required",
                                             "CAF retry state is not enabled", 3)
                continue
            if category or not self._transport_ok(disabled_result):
                raise _ControllerFailure(category or "unsupported_response",
                                         "verification disable failed")
            disabled, read_result, read_context = self._verification_read(attempt)
            if disabled["state"] != "disabled":
                raise _ControllerFailure("readback_mismatch", "disable readback mismatch")
            confirmation = {"confirmed_at": disabled["observed_at"],
                "pre_disable_command_id": observation["command_id"],
                "disable_command_id": disabled_context["command_id"],
                "disabled_readback_command_id": read_context["command_id"],
                "transition_response": "disabled_successfully"}
            event_evidence = {"confirmation": confirmation,
                              "transcript_refs": refs(read_result)}
            disable_result = self._issue_continuation(
                attempt, "disable_result")
            self._consume_continuation(
                attempt, disable_result, "disable_result")
            capability = deployment_records._issue_iox_capability(
                self.controller_id, attempt.attempt_id, journal["record_id"],
                journal["transaction_id"], attempt.board,
                attempt.journal["revision"], attempt.journal["phase"],
                "disable_confirmed", event_evidence)
            self._event(attempt, "disable_confirmed", event_evidence,
                        capability=capability)
            self._event(attempt, "installing", {})
            return

    def _ipc_result(self, sequence, code=0, attempt=None, result=None,
                    category=None, detail="", stdout_truncated=False,
                    stderr_truncated=False):
        journal = attempt.journal if attempt else None
        wire_category = ("unsupported_syntax" if
                         category == "unsupported_syntax_local" else category)
        return {"version": 1, "type": "result", "sequence": sequence,
            "ok": code == 0, "operation_code": code,
            "revision": journal.get("revision") if journal else None,
            "phase": journal.get("phase") if journal else None,
            "returncode": _get(result, "returncode") if result is not None else None,
            "timed_out": bool(_get(result, "timed_out", False)) if result is not None else False,
            "stdout_truncated": bool(stdout_truncated or (_get(result, "stdout_truncated", False) if result else False)),
            "stderr_truncated": bool(stderr_truncated or (_get(result, "stderr_truncated", False) if result else False)),
            "framing_complete": bool(_get(result, "framing_complete", True)) if result is not None else True,
            "error_category": wire_category, "detail": _bounded_text(detail),
            "transcript_ref": _get(result, "transcript_ref") if result is not None else
                              (attempt.transcript.reference() if attempt else None),
            "recipe_returncode": None,
            "recovery_code": attempt.recovery_code if attempt else None}

    def _send_response(self, peer, sequence, attempt, result, outputs):
        for stream in ("stdout", "stderr"):
            body = outputs.get(stream, b"")
            truncated = len(body) > 32768
            body = body[:32768]
            for index, offset in enumerate(range(0, len(body), 4096)):
                peer.sendall(_encode_frame({"version": 1, "type": "output",
                    "sequence": sequence, "stream": stream, "index": index,
                    "data_b64": base64.b64encode(body[offset:offset+4096]).decode("ascii")}))
            if stream == "stdout" and truncated:
                result["stdout_truncated"] = True
            if stream == "stderr" and truncated:
                result["stderr_truncated"] = True
        peer.sendall(_encode_frame(result))

    def _admit_recipe_step(self, attempt, action, operation, arguments,
                           protocol):
        """Advance the closed recipe language before any selected device I/O."""
        if protocol["finished"]:
            raise _ControllerFailure("rejected", "operation after recipe finish", 4)
        if protocol["cleanup"]:
            if operation != "finish" or set(arguments) != {"exit_intent"}:
                raise _ControllerFailure(
                    "rejected", "operation after recipe cleanup", 4)
            protocol["finished"] = True
            return
        if operation == "cleanup":
            intent = arguments.get("exit_intent")
            declared_failure = (type(intent) is int and
                                not isinstance(intent, bool) and
                                1 <= intent <= 255)
            if (set(arguments) != {"reason", "exit_intent"} or
                    (attempt.primary is None and
                     not protocol["terminal_ready"] and
                     not declared_failure)):
                raise _ControllerFailure("rejected", "premature recipe cleanup", 4)
            protocol["cleanup"] = True
            return
        if operation == "finish":
            if (set(arguments) != {"exit_intent"} or
                    (attempt.primary is None and not protocol["terminal_ready"])):
                raise _ControllerFailure("rejected", "premature recipe finish", 4)
            protocol["finished"] = True
            return
        if attempt.primary is not None:
            raise _ControllerFailure(
                "rejected", "ordinary operation after recipe failure", 4)
        name = arguments.get("name") if operation == "command" else operation
        if not isinstance(name, str):
            raise _ControllerFailure("rejected", "invalid recipe operation", 4)
        seen = protocol["seen"]
        if action == "install":
            if not protocol["begun"]:
                allowed = {"upload_wrapper", "upload_certificate",
                           "routing_prereq", "storage_prereq", "clock",
                           "prepare_iox_scp", "iox_status"}
                if name == "begin_install":
                    if "upload_wrapper" not in protocol["completed"]:
                        raise _ControllerFailure(
                            "rejected", "begin before wrapper upload", 4)
                    protocol["begun"] = True
                    seen.add(name)
                    return
                if name not in allowed:
                    raise _ControllerFailure(
                        "rejected", "application mutation before admission", 4)
                if name == "iox_status":
                    deadline = protocol["phase_deadlines"].setdefault(
                        "iox", min(attempt.ordinary_deadline,
                                   self._monotonic() + 180))
                    if protocol["iox_polls"]:
                        self._wait_poll(
                            attempt, deadline, protocol["iox_polls"], 24)
                    protocol["iox_polls"] += 1
                    if protocol["iox_polls"] > 24:
                        raise _ControllerFailure("rejected", "excess IOx polling", 4)
                    return
                if name in seen:
                    raise _ControllerFailure("rejected", "replayed recipe step", 4)
                seen.add(name)
                return
            ranks = {
                "app_stop": 1, "app_deactivate": 2, "app_uninstall": 3,
                "remove_app_config": 4, "configure_network": 5,
                "mkdir_share": 6, "configure_app": 7, "app_install": 8,
                "deployed": 9, "app_activate": 10,
                "stage_instructions": 11, "copy_certificate": 12,
                "remove_certificate": 13, "remove_wrapper": 14,
                "app_start": 15, "save": 16,
            }
            if name == "app_list":
                if protocol["rank"] not in (8, 10, 15):
                    raise _ControllerFailure("rejected", "poll outside lifecycle wait", 4)
                key = "install-%d" % protocol["rank"]
                count = protocol["polls"].get(key, 0)
                deadline = protocol["phase_deadlines"].get(key)
                if deadline is None:
                    raise _ControllerFailure(
                        "rejected", "missing lifecycle poll authority", 4)
                if self._monotonic() >= deadline:
                    raise _ControllerFailure(
                        "timeout", "lifecycle polling deadline elapsed", 4)
                if count:
                    self._wait_poll(attempt, deadline, count, 24)
                protocol["polls"][key] = count + 1
                if protocol["polls"][key] > 24:
                    raise _ControllerFailure("rejected", "excess application polling", 4)
                return
            if name not in ranks or name in seen:
                raise _ControllerFailure("rejected", "replayed or unknown install step", 4)
            rank = ranks[name]
            current = protocol["rank"]
            required = {
                1: 0, 2: 1, 3: 2, 4: 3,
                5: 4, 6: 4, 7: 4, 8: 1, 9: 8,
                10: 9, 11: 10, 12: 11, 13: 12, 14: 13,
                15: 14, 16: 15,
            }[rank]
            if current < required or rank < current:
                raise _ControllerFailure("rejected", "out-of-order install step", 4)
            if name == "deployed":
                deadline = protocol["phase_deadlines"].get("install-8")
                if deadline is None or self._monotonic() >= deadline:
                    raise _ControllerFailure(
                        "timeout", "application install deadline elapsed", 4)
            if rank == 7 and current not in (4, 5, 6):
                raise _ControllerFailure("rejected", "out-of-order app config", 4)
            if name == "stage_instructions" and arguments != {}:
                raise _ControllerFailure(
                    "rejected", "invalid instruction staging request", 4)
            if (rank in (12, 13, 14, 15) and
                    "upload_certificate" not in protocol["completed"]):
                raise _ControllerFailure("rejected", "certificate was not uploaded", 4)
            if rank == 15 and current != 14:
                raise _ControllerFailure(
                    "rejected", "incomplete certificate cleanup", 4)
            seen.add(name)
            protocol["rank"] = max(current, rank)
            if name in ("app_stop", "app_activate", "app_start"):
                phase_rank = {"app_stop": 8, "app_activate": 10,
                              "app_start": 15}[name]
                key = "install-%d" % phase_rank
                budget = {"app_stop": self.config["install_timeout"],
                          "app_activate": self.config["activate_timeout"],
                          "app_start": self.config["start_timeout"]}[name]
                protocol["phase_deadlines"][key] = min(
                    attempt.ordinary_deadline, self._monotonic() + budget)
            if name == "save":
                protocol["terminal_ready"] = True
            return
        ranks = {
            "app_stop": 1, "app_deactivate": 2, "app_uninstall": 3,
            "remove_app_config": 4, "cleanup_config": 4,
            "remove_wrapper": 5, "remove_certificate": 6,
            "cleanup_files": 7, "cleanup_config_probe": 8,
            "cleanup_stage_probe": 9, "save": 10,
        }
        if name == "app_list":
            if protocol["rank"] != 3:
                raise _ControllerFailure("rejected", "poll outside uninstall wait", 4)
            count = protocol["polls"].get("uninstall", 0)
            deadline = protocol["phase_deadlines"].get("uninstall")
            if deadline is None:
                raise _ControllerFailure(
                    "rejected", "missing uninstall poll authority", 4)
            if self._monotonic() >= deadline:
                raise _ControllerFailure(
                    "timeout", "lifecycle polling deadline elapsed", 4)
            if count:
                self._wait_poll(attempt, deadline, count, 24,
                                fixed_interval=self.config["state_poll"])
            protocol["polls"]["uninstall"] = count + 1
            if protocol["polls"]["uninstall"] > 24:
                raise _ControllerFailure("rejected", "excess application polling", 4)
            return
        if name not in ranks or name in seen:
            raise _ControllerFailure("rejected", "replayed or unknown uninstall step", 4)
        rank = ranks[name]
        current = protocol["rank"]
        required = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4,
                    6: 4, 7: 4, 8: 4, 9: 8, 10: 9}[rank]
        if current < required or rank <= current:
            raise _ControllerFailure("rejected", "out-of-order uninstall step", 4)
        seen.add(name)
        protocol["rank"] = rank
        if name == "app_uninstall":
            protocol["phase_deadlines"]["uninstall"] = min(
                attempt.ordinary_deadline,
                self._monotonic() + self.config["state_poll"] * 23)
        if name in ("cleanup_stage_probe", "save"):
            protocol["terminal_ready"] = True

    def _wait_poll(self, attempt, phase_deadline, completed, maximum,
                   fixed_interval=None):
        now = self._monotonic()
        remaining_slots = maximum - completed
        if remaining_slots <= 0 or now >= phase_deadline:
            raise _ControllerFailure(
                "timeout", "lifecycle polling deadline elapsed", 4)
        delay = (fixed_interval if fixed_interval is not None else
                 max(float(self.config["state_poll"]),
                     (phase_deadline - now) / remaining_slots))
        poll_at = min(phase_deadline, now + delay)
        while self._monotonic() < poll_at:
            attempt.check()
            select.select([], [], [], min(
                0.01, max(0.0, poll_at - self._monotonic())))
        if self._monotonic() >= phase_deadline:
            raise _ControllerFailure(
                "timeout", "lifecycle polling deadline elapsed", 4)

    def _cleanup_remote_artifacts(self, attempt, protocol):
        """Remove and verify this attempt's admitted transient uploads."""
        previous = attempt.safety_recovery
        attempt.safety_recovery = True
        try:
            completed = protocol["completed"]
            admitted = protocol["seen"]
            for upload, removal in (
                    ("upload_certificate", "remove_certificate"),
                    ("upload_wrapper", "remove_wrapper")):
                if upload not in admitted or removal in completed:
                    continue
                result, unused = self._command(
                    attempt, removal, self._render_command(attempt, removal), 45)
                if (not self._transport_ok(result) or
                        _get(result, "error_category")):
                    raise _ControllerFailure(
                        _get(result, "error_category") or "rejected",
                        "IOx transient cleanup could not be verified", 4)
                completed.add(removal)
            if attempt.journal.get("instruction_cleanup_pending"):
                self._remove_instruction_source(attempt)
                protocol["instruction_source_removed"] = True
        finally:
            attempt.safety_recovery = previous

    def _remove_instruction_source(self, attempt):
        """Discharge only this journal's transaction-derived source."""
        if not attempt.journal.get("instruction_cleanup_pending"):
            return
        result, unused = self._command(
            attempt, "remove_instructions",
            self._render_command(attempt, "remove_instructions"), 45)
        if (not self._transport_ok(result) or
                _get(result, "error_category")):
            raise _ControllerFailure(
                _get(result, "error_category") or "rejected",
                "IOx transient cleanup could not be verified", 4)
        self._instruction_cleanup_update(attempt, False)

    def _stage_instructions(self, attempt, protocol):
        snapshot = attempt.instruction_snapshot
        if snapshot is None:
            raise _ControllerFailure(
                "authority_mismatch", "instruction snapshot custody missing", 5)
        self._instruction_cleanup_update(attempt, True)
        protocol["instruction_source_attempted"] = True
        primary = None
        cleanup_failure = None
        published = None
        try:
            published = self._publish_instruction_source(attempt, snapshot)
            self._fetch(attempt, "fetch_instructions",
                        os.fstat(snapshot.fd).st_size)
            result, unused = self._command(
                attempt, "copy_instructions",
                self._render_command(attempt, "copy_instructions"),
                45, ordinary=True)
            if (not self._transport_ok(result) or
                    _get(result, "error_category")):
                raise _ControllerFailure(
                    _get(result, "error_category") or "rejected",
                    "IOx instruction copy failed", 4)
        except _ControllerFailure as exc:
            primary = exc
        finally:
            if published is not None:
                try:
                    os.unlink(published)
                except OSError:
                    pass
        previous = attempt.safety_recovery
        attempt.safety_recovery = True
        try:
            self._remove_instruction_source(attempt)
            protocol["instruction_source_removed"] = True
        except _ControllerFailure as exc:
            cleanup_failure = exc
        finally:
            attempt.safety_recovery = previous
        if primary is not None:
            raise primary
        if cleanup_failure is not None:
            raise cleanup_failure

    def _report_step(self, on_output, capture, operation, arguments,
                     started, failure):
        """Put one step-level line in the job log for a recipe operation.

        The recipe's own output captured so far (its "[n/8] ..." headers,
        PREREQ notices, poll outcomes) is forwarded first, so it precedes
        the line for the operation it introduced. Successful polls and the
        cleanup/finish protocol steps stay silent -- the recipe reports the
        polled state itself and a clean finish is not news -- while every
        failure is named, including a refusal of the step's admission. The
        failure detail is not repeated here: the recipe writes it to its
        stderr when it receives the response, and the controller result
        carries the primary failure's detail for the job's final line.
        """
        for stream, body in capture.drain():
            on_output(stream, body)
        name = (arguments.get("name") if operation == "command" and
                isinstance(arguments, dict) else operation)
        name = "".join(character for character in str(name)
                       if 32 < ord(character) < 127)[:64] or "?"
        elapsed = max(0.0, self._monotonic() - started)
        if failure is None:
            if name in _SILENT_RECIPE_STEPS:
                return
            line = "  %s ok (%.1fs)" % (name, elapsed)
        else:
            line = "  %s failed (%.1fs)" % (name, elapsed)
        on_output("stdout", (line + "\n").encode("utf-8"))

    def _run_recipe(self, attempt, action, on_output):
        # Cancellation observed after board-scoped revalidation wins over any
        # later local recipe admission failure.  This also lets a waiter leave
        # promptly once it acquires a contended physical-board lock.
        attempt.check()
        argv = (self.config.get("recipe_argv_by_action") or {}).get(action)
        if not argv:
            raise _ControllerFailure("rejected", "IOx recipe is not configured", 4)
        parent, child = socket.socketpair()
        # /usr/local/bin is on this PATH because the recipe's entire control
        # channel is a python3 heredoc (device/iox/install.sh's iox_request),
        # and the server image installs python under /usr/local -- there is no
        # /usr/bin/python3 at all. Without it every IOx install and uninstall
        # died with "python3: command not found" followed by "invalid private
        # recipe protocol", because the recipe cannot speak to the controller
        # before it can run python. The other platforms' recipes never hit
        # this: they are spawned inheriting the full environment, so only this
        # deliberately minimal PATH has to name the interpreter's location.
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
                       ":/sbin:/bin",
               "LANG": "C.UTF-8",
               "LC_ALL": "C.UTF-8", "IRIS_IOX_CONTROL_FD": str(child.fileno()),
               # The job's device-logging opt-in (the same normalized value
               # the app receives as run-opts IRIS_LOG). The recipe echoes
               # the raw device session into the job log only when it is
               # on; by default the log carries the recipe's step headers
               # and this controller's per-step lines, and the session stays
               # in the persisted transcript.
               "IRIS_LOG": ("on" if _get(attempt.target, "log") == "on"
                            else "off")}
        if attempt.supervisor is None:
            raise _ControllerFailure(
                "descendant_unreaped", "missing IOx supervisor custody", 5)
        process = attempt.supervisor.popen(list(argv), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            pass_fds=(child.fileno(),), close_fds=True,
            start_new_session=True, role="recipe",
            timeout=attempt.remaining())
        child.close()
        capture_secrets = [value.encode("utf-8") for value in
                           attempt.transport._iris_config["credentials"].values()
                           if value]
        recipe_capture = _RecipeCapture(process, capture_secrets)
        sequence = 1
        expected_exit = None
        protocol_failure = None
        protocol = {"seen": set(), "completed": set(),
                    "rank": 0, "begun": False,
                    "iox_polls": 0, "polls": {}, "cleanup": False,
                    "finished": False, "terminal_ready": False,
                    "phase_deadlines": {}, "scp_prepared": False,
                    "trust_configured": False,
                    "instruction_source_attempted": False,
                    "instruction_source_removed": False}
        try:
            while True:
                attempt.check()
                ready = {"version": 1, "type": "ready", "next_sequence": sequence,
                    "attempt_id": attempt.attempt_id, "action": action,
                    "teardown_mode": _get(attempt.request, "teardown_mode"),
                    "record_id": attempt.record_id,
                    "transaction_id": attempt.journal["transaction_id"] if action == "install" else None,
                    "expected_revision": attempt.journal["revision"] if action == "install" else None,
                    "board_identity": attempt.board,
                    "wrapper_sha256": attempt.journal["wrapper_sha256"] if action == "install" else None}
                parent.sendall(_encode_frame(ready))
                request = _read_frame_socket(parent, attempt.session_deadline,
                                             attempt.is_cancelled, self._monotonic)
                expected_keys = set("version sequence attempt_id action teardown_mode record_id transaction_id expected_revision board_identity wrapper_sha256 operation arguments".split())
                if not isinstance(request, dict) or set(request) != expected_keys:
                    raise _ControllerFailure("rejected", "invalid recipe request")
                for key in ("version", "sequence", "attempt_id", "action",
                            "teardown_mode", "record_id", "transaction_id",
                            "expected_revision", "board_identity", "wrapper_sha256"):
                    expected = ready["next_sequence"] if key == "sequence" else ready[key]
                    if (type(request[key]) is not type(expected) or
                            request[key] != expected):
                        raise _ControllerFailure("rejected", "recipe binding mismatch")
                operation = request["operation"]
                arguments = request["arguments"]
                if not isinstance(operation, str) or type(arguments) is not dict:
                    raise _ControllerFailure("rejected", "invalid recipe operation")
                step_started = self._monotonic()
                try:
                    self._admit_recipe_step(
                        attempt, action, operation, arguments, protocol)
                except _ControllerFailure as exc:
                    self._report_step(on_output, recipe_capture, operation,
                                      arguments, step_started, exc)
                    raise
                outputs = {"stdout": b"", "stderr": b""}
                transport_result = None
                operation_result_start = len(attempt.operation_results)
                try:
                    if operation == "upload_wrapper" and arguments == {} and action == "install":
                        import iox_transport
                        if (not protocol["scp_prepared"] and
                                isinstance(attempt.transport,
                                           iox_transport.IoxTransport)):
                            prepared, unused = self._command(
                                attempt, "prepare_iox_scp",
                                self._render_command(
                                    attempt, "prepare_iox_scp"),
                                45, ordinary=True)
                            if (not self._transport_ok(prepared) or
                                    _get(prepared, "error_category")):
                                raise _ControllerFailure(
                                    _get(prepared, "error_category") or
                                    "rejected",
                                    "IOx preparation failed", 4)
                            protocol["scp_prepared"] = True
                        self._ensure_trustpoint(attempt, protocol)
                        transport_result = self._fetch(
                            attempt, "fetch_wrapper",
                            os.fstat(attempt.snapshot.fd).st_size)
                    elif operation == "upload_certificate" and arguments == {} and action == "install":
                        certificate = self.config.get("catalog_certificate_path")
                        fd = _open_public_certificate(
                            certificate, self._strict_target)
                        try:
                            certificate_size = os.fstat(fd).st_size
                        finally:
                            os.close(fd)
                        self._ensure_trustpoint(attempt, protocol)
                        transport_result = self._fetch(
                            attempt, "fetch_certificate", certificate_size)
                    elif operation == "begin_install" and arguments == {} and action == "install":
                        self._begin_install(attempt)
                    elif operation == "deployed" and arguments == {} and action == "install":
                        install_deadline = protocol["phase_deadlines"][
                            "install-8"]
                        remaining = install_deadline - self._monotonic()
                        if remaining <= 0:
                            raise _ControllerFailure(
                                "timeout", "application install deadline elapsed", 4)
                        transport_result, unused = self._command(
                            attempt, "app_list",
                            self._render_command(attempt, "app_list"),
                            min(remaining, 180), ordinary=True)
                        if (not self._transport_ok(transport_result) or
                                not re.search(br"(?mi)^iris\s+DEPLOYED\s*$",
                                              _get(transport_result, "stdout", b""))):
                            raise _ControllerFailure(_get(transport_result, "error_category") or
                                                     "rejected", "IRIS application not DEPLOYED")
                        code = self._recover_journal(attempt, attempt.journal, initiating=True)
                        if code:
                            attempt.recovery_code = code
                            raise _ControllerFailure("readback_unknown", "verification restoration failed", code)
                        # `deployed` is a controller operation.  Its internal
                        # authenticated app-list read must not turn the wire
                        # response into a transport operation result.
                        transport_result = None
                    elif (operation == "stage_instructions" and
                          arguments == {} and action == "install"):
                        self._stage_instructions(attempt, protocol)
                    elif operation == "command" and isinstance(arguments, dict) and set(arguments) == {"name"}:
                        name = arguments["name"]
                        if action == "uninstall" and name not in _UNINSTALL_COMMANDS:
                            raise _ControllerFailure("unsupported_syntax", "command not permitted for uninstall", 2)
                        if (name == "storage_prereq" and
                                attempt.target.get("target_fs") != "sdflash:"):
                            transport_result = {
                                "returncode": 0, "timed_out": False,
                                "stdout": b"IOx Partition Exists (not required)\n",
                                "stderr": b"", "stdout_truncated": False,
                                "stderr_truncated": False,
                                "framing_complete": True,
                                "error_category": None,
                                "transcript_ref": attempt.transcript.reference()}
                        elif (name == "prepare_iox_scp" and
                              protocol["scp_prepared"]):
                            transport_result = {
                                "returncode": 0, "timed_out": False,
                                "stdout": b"", "stderr": b"",
                                "stdout_truncated": False,
                                "stderr_truncated": False,
                                "framing_complete": True,
                                "error_category": None,
                                "transcript_ref":
                                    attempt.transcript.reference()}
                        else:
                            body = self._render_command(attempt, name)
                            timeout = {
                                "app_install": self.config["install_timeout"],
                                "app_activate": self.config["activate_timeout"],
                                "app_start": self.config["start_timeout"],
                            }.get(name, 45)
                            if name == "app_list":
                                timeout = min(timeout, 180)
                            phase_key = None
                            if action == "install":
                                if name == "iox_status":
                                    phase_key = "iox"
                                elif name in (
                                        "app_stop", "app_deactivate",
                                        "app_uninstall", "remove_app_config",
                                        "configure_network", "mkdir_share",
                                        "configure_app", "app_install"):
                                    phase_key = "install-8"
                                elif protocol["rank"] in (8, 10, 15):
                                    phase_key = "install-%d" % protocol["rank"]
                            elif action == "uninstall" and name == "app_list":
                                phase_key = "uninstall"
                            if phase_key is not None:
                                phase_deadline = protocol[
                                    "phase_deadlines"].get(phase_key)
                                remaining = (phase_deadline - self._monotonic()
                                             if phase_deadline is not None else 0)
                                if remaining <= 0:
                                    raise _ControllerFailure(
                                        "timeout",
                                        "lifecycle operation deadline elapsed", 4)
                                timeout = min(timeout, remaining)
                            transport_result, unused = self._command(
                                attempt, name, body, timeout, ordinary=True)
                            if name == "prepare_iox_scp":
                                protocol["scp_prepared"] = True
                        if not self._transport_ok(transport_result) or _get(transport_result, "error_category"):
                            raise _ControllerFailure(_get(transport_result, "error_category") or "rejected",
                                                     _command_failure_detail(name, transport_result))
                        if action == "uninstall" and name == "app_stop":
                            outputs["stdout"] += (
                                "IRIS-READY-MODE:%s\n" %
                                _get(attempt.request, "teardown_mode")).encode("ascii")
                    elif operation == "cleanup" and isinstance(arguments, dict) and set(arguments) == {"reason", "exit_intent"}:
                        if arguments["reason"] not in ("success", "error", "term", "int", "hup", "cancel"):
                            raise _ControllerFailure("rejected", "invalid cleanup reason")
                        intent = arguments["exit_intent"]
                        if (intent is not None and
                                (type(intent) is not int or
                                 not 0 <= intent <= 255)):
                            raise _ControllerFailure(
                                "rejected", "invalid cleanup exit intent")
                        if (attempt.journal and
                                attempt.journal["unresolved"] and
                                not attempt.durability_uncertain):
                            attempt.recovery_code = self._recover_journal(
                                attempt, attempt.journal, initiating=True)
                    elif operation == "finish" and isinstance(arguments, dict) and set(arguments) == {"exit_intent"}:
                        intent = arguments["exit_intent"]
                        if type(intent) is not int or not 0 <= intent <= 255:
                            raise _ControllerFailure("rejected", "invalid exit intent")
                        finish_failure = None
                        try:
                            if (attempt.journal and
                                    attempt.journal["unresolved"] and
                                    not attempt.durability_uncertain):
                                attempt.recovery_code = self._recover_journal(
                                    attempt, attempt.journal, initiating=True)
                            if (action == "install" and
                                    attempt.journal is not None and
                                    not attempt.journal["unresolved"] and
                                    not attempt.durability_uncertain):
                                self._cleanup_remote_artifacts(
                                    attempt, protocol)
                        except _ControllerFailure as exc:
                            finish_failure = exc
                            if attempt.primary is None:
                                attempt.primary = exc
                        code = (finish_failure.code if finish_failure else
                                (attempt.recovery_code or 0))
                        for operation_result in attempt.operation_results[
                                operation_result_start:]:
                            outputs["stdout"] += _get(
                                operation_result, "stdout", b"")
                            outputs["stderr"] += _get(
                                operation_result, "stderr", b"")
                        response = self._ipc_result(
                            sequence, code, attempt,
                            category=(finish_failure.category if
                                      finish_failure else None),
                            detail=(finish_failure.detail if
                                    finish_failure else ""))
                        self._send_response(parent, sequence, attempt, response, outputs)
                        self._report_step(on_output, recipe_capture, operation,
                                          arguments, step_started, finish_failure)
                        expected_exit = intent if intent else code
                        attempt.finished_protocol = True
                        break
                    else:
                        raise _ControllerFailure("rejected", "operation is not permitted")
                    completed_name = (arguments.get("name") if
                                      operation == "command" else operation)
                    if completed_name in protocol["seen"]:
                        protocol["completed"].add(completed_name)
                    operation_results = attempt.operation_results[
                        operation_result_start:]
                    for operation_result in operation_results:
                        outputs["stdout"] += _get(
                            operation_result, "stdout", b"")
                        outputs["stderr"] += _get(
                            operation_result, "stderr", b"")
                    if (transport_result is not None and
                            not operation_results):
                        outputs["stdout"] += _get(transport_result, "stdout", b"")
                        outputs["stderr"] += _get(transport_result, "stderr", b"")
                    response = self._ipc_result(sequence, 0, attempt,
                                                result=transport_result)
                    self._report_step(on_output, recipe_capture, operation,
                                      arguments, step_started, None)
                except _ControllerFailure as exc:
                    if attempt.primary is None:
                        attempt.primary = exc
                    response = self._ipc_result(sequence, exc.code, attempt,
                                                result=transport_result,
                                                category=exc.category,
                                                detail=exc.detail)
                    self._report_step(on_output, recipe_capture, operation,
                                      arguments, step_started, exc)
                self._send_response(parent, sequence, attempt, response, outputs)
                sequence += 1
        except _ControllerFailure as exc:
            protocol_failure = exc
            if attempt.primary is None:
                attempt.primary = exc
        except Exception:
            protocol_failure = _ControllerFailure(
                "rejected", "invalid private recipe protocol", 4)
            if attempt.primary is None:
                attempt.primary = protocol_failure
        finally:
            parent.close()
        if (attempt.journal is not None and attempt.journal.get("unresolved") and
                not attempt.finished_protocol and
                not attempt.durability_uncertain):
            try:
                recovery_code = self._recover_journal(
                    attempt, attempt.journal, initiating=False)
                if recovery_code:
                    attempt.recovery_code = recovery_code
            except _ControllerFailure as recovery_failure:
                attempt.recovery_code = recovery_failure.code
            except Exception:
                attempt.recovery_code = 5
        if (action == "install" and attempt.journal is not None and
                not attempt.journal.get("unresolved") and
                not attempt.finished_protocol and
                not attempt.durability_uncertain):
            try:
                self._cleanup_remote_artifacts(attempt, protocol)
            except _ControllerFailure as cleanup_failure:
                if attempt.primary is None:
                    attempt.primary = cleanup_failure
        natural_deadline = min(
            attempt.session_deadline, self._monotonic() + 1.0)
        while self._monotonic() < natural_deadline:
            try:
                remaining = natural_deadline - self._monotonic()
                if remaining <= 0 or process.poll(timeout=remaining) is not None:
                    break
            except Exception:
                break
            select.select([], [], [], min(
                0.01, max(0.0, natural_deadline - self._monotonic())))
        recipe_reaped = attempt.supervisor.reap_process(
            process, attempt.session_deadline)
        attempt.recipe_returncode = process.returncode
        drain_complete, captured = recipe_capture.finish(
            recipe_reaped, attempt.session_deadline, self._monotonic)
        recipe_reaped = recipe_reaped and drain_complete
        if not recipe_reaped:
            attempt.recovery_code = 5
            if attempt.primary is None:
                attempt.primary = _ControllerFailure(
                    "descendant_unreaped",
                    "recipe descendants were not reaped", 5)
        for stream in ("stdout", "stderr"):
            if captured[stream]:
                on_output(stream, captured[stream])
        if not attempt.finished_protocol or process.returncode != expected_exit:
            if attempt.primary is None:
                attempt.primary = _ControllerFailure("rejected", "incomplete recipe protocol", 4)
        elif process.returncode != 0 and attempt.primary is None:
            attempt.primary = _ControllerFailure("rejected", "recipe exited nonzero", 4)
        return self._finalize(attempt)

    def summary_for_device(self, device_id):
        obligations = self.store.iox_summary(device_id)
        boards = set(item["board_identity"] for item in obligations)
        try:
            records = self.store.list(device_id, strict=True)
        except TypeError:
            records = self.store.list(device_id)
        for record in records:
            journal = record.get("iox_verification")
            if (journal is not None and
                    (not isinstance(journal, dict) or
                     journal.get("controller_id") != self.controller_id)):
                raise ValueError("foreign IOx journal authority")
            board = (journal or {}).get("board_identity")
            board = board or (record.get("resolved") or {}).get("device_identity")
            if board:
                boards.add(board)
        sessions = []
        for path in self._scan_directory(self.session_dir, ".lock.json",
                                         self.limits["session_files"],
                                         _SESSION_FILE_BYTES):
            fence = _read_json_strict(path, _SESSION_FILE_BYTES)
            self._validate_fence(fence, path)
            if fence["device_id"] == device_id or fence["board_identity"] in boards:
                sessions.append(_session_summary(fence))
        sessions.sort(key=lambda value: (value["board_identity"], value["attempt_id"]))
        return {"iox_verification_obligations": obligations,
                "iox_sessions": sessions}

    def close(self):
        with self._admission_lock:
            with self._active_lock:
                self._closed = True
                attempts = list(self._active)
        for attempt in attempts:
            attempt.shutdown.set()
            attempt.invalidate_continuations()
            deployment_records._invalidate_iox_capabilities(attempt.attempt_id)
        started_close = self._monotonic()
        deadlines = dict((attempt, min(attempt.session_deadline,
                                      started_close +
                                      _SUPERVISOR_REAP_SECONDS))
                         for attempt in attempts)
        # A controller call that unwound on this thread without reaching
        # `_finalize` has no live caller left to perform cleanup.
        abandoned = [attempt for attempt in attempts
                     if (attempt.owner_thread is threading.current_thread() or
                         not attempt.owner_thread.is_alive())]
        for attempt in abandoned:
            deadline = deadlines[attempt]
            clean = False
            if attempt.supervisor is not None:
                children_reaped = attempt.supervisor.reap_all(deadline)
                fence_reaped = children_reaped
                if children_reaped and attempt.fence_owned:
                    try:
                        self._fence_barrier(attempt, state="reaped")
                    except Exception:
                        fence_reaped = False
                if fence_reaped:
                    clean = attempt.supervisor.release(deadline)
                else:
                    attempt.supervisor.abandon(deadline)
            elif attempt.lock_fd is not None:
                try:
                    fcntl.flock(attempt.lock_fd, fcntl.LOCK_UN)
                    os.close(attempt.lock_fd)
                    attempt.lock_fd = None
                    clean = True
                except OSError:
                    clean = False
            if clean:
                with self._active_lock:
                    self._active.discard(attempt)
        duration = max([max(0.0, deadline - started_close)
                        for attempt, deadline in deadlines.items()
                        if attempt not in abandoned] or [0.0])
        wall_deadline = time.monotonic() + duration
        while time.monotonic() < wall_deadline:
            with self._active_lock:
                remaining_attempts = list(self._active)
            if not remaining_attempts:
                return
            select.select([], [], [], min(0.02,
                max(0.0, wall_deadline - time.monotonic())))
        with self._active_lock:
            remaining_attempts = list(self._active)
        for attempt in remaining_attempts:
            if attempt.supervisor is not None:
                attempt.supervisor.disconnect(
                    deadlines.get(attempt, self._monotonic()))
        with self._active_lock:
            if self._active:
                raise RuntimeError(
                    "IOx controller closed with retained active session fences")


def _encode_frame(value):
    body = _canonical(value)
    if not 1 <= len(body) <= 65536:
        raise ValueError("local-control frame size is invalid")
    return struct.pack("!I", len(body)) + body


def _read_frame_socket(peer, deadline, cancel, monotonic_fn=time.monotonic):
    def exact(size):
        value = b""
        while len(value) < size:
            if _cancelled(cancel):
                raise _ControllerFailure("cancelled", "operation cancelled", 130)
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise _ControllerFailure("timeout", "frame deadline elapsed")
            readable, unused, unused2 = select.select([peer], [], [], remaining)
            if not readable:
                raise _ControllerFailure("timeout", "frame deadline elapsed")
            chunk = peer.recv(size - len(value))
            if not chunk:
                raise EOFError("partial frame")
            value += chunk
        return value
    size = struct.unpack("!I", exact(4))[0]
    if not 1 <= size <= 65536:
        raise ValueError("invalid frame size")
    return json.loads(exact(size).decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("non-finite JSON")))


def _control_peer_credentials(connection):
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    return struct.unpack("3i", raw)


class IoxControlServer(object):
    def __init__(self, state_dir, controller_id, dispatch):
        self.state_dir = _safe_state_root(state_dir)
        if (not isinstance(controller_id, str) or
                not _HEX32.fullmatch(controller_id)):
            raise ValueError("invalid controller_id")
        if not callable(dispatch):
            raise ValueError("invalid IOx control dispatch")
        self.controller_id = controller_id
        self.dispatch = dispatch
        self.path = os.path.join(self.state_dir, "iox", "control.sock")
        self.listener = None
        self.thread = None
        self.stop = threading.Event()
        self.connections = set()
        self.workers = set()
        self.connection_lock = threading.Lock()
        self.connection_slots = threading.BoundedSemaphore(16)
        self.inode = None

    def _endpoint_metadata(self):
        directory = os.path.dirname(self.path)
        descriptor = _open_directory_anchor(directory, required_mode=0o700)
        try:
            metadata = os.stat(os.path.basename(self.path), dir_fd=descriptor,
                               follow_symlinks=False)
            if (not stat.S_ISSOCK(metadata.st_mode) or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_uid != os.geteuid() or
                    metadata.st_nlink != 1 or
                    (self.inode is not None and self.inode !=
                     (metadata.st_dev, metadata.st_ino))):
                raise ValueError("unsafe IOx control endpoint")
            return metadata
        finally:
            os.close(descriptor)

    def start(self):
        iox_directory = os.path.dirname(self.path)
        _safe_directory(iox_directory, create=True)
        if os.path.lexists(self.path):
            raise ValueError("IOx control endpoint already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        directory_fd = _open_directory_anchor(
            iox_directory, required_mode=0o700)
        name = os.path.basename(self.path)
        anchored = "/proc/self/fd/%d/%s" % (directory_fd, name)
        try:
            listener.bind(anchored)
            first = os.stat(name, dir_fd=directory_fd,
                            follow_symlinks=False)
            os.chmod(name, 0o600, dir_fd=directory_fd,
                     follow_symlinks=False)
            metadata = os.stat(name, dir_fd=directory_fd,
                               follow_symlinks=False)
            if ((first.st_dev, first.st_ino) !=
                    (metadata.st_dev, metadata.st_ino) or
                    not stat.S_ISSOCK(metadata.st_mode) or
                    stat.S_IMODE(metadata.st_mode) != 0o600 or
                    metadata.st_uid != os.geteuid() or
                    metadata.st_nlink != 1):
                raise ValueError("unsafe IOx control endpoint")
            os.fsync(directory_fd)
            listener.listen(16)
            self.inode = (metadata.st_dev, metadata.st_ino)
            self._endpoint_metadata()
            # Prove that the currently anchored directory entry routes to this
            # listener before publishing the accept loop.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(1.0)
                listener.settimeout(1.0)
                probe.connect(anchored)
                accepted, unused = listener.accept()
                try:
                    unused_pid, uid, unused_gid = _control_peer_credentials(
                        accepted)
                    if uid != os.geteuid():
                        raise ValueError("foreign IOx control endpoint")
                finally:
                    accepted.close()
            finally:
                probe.close()
            self._endpoint_metadata()
            listener.settimeout(0.1)
            self.listener = listener
            self.thread = threading.Thread(target=self._serve)
            self.thread.daemon = True
            self.thread.start()
        except Exception:
            listener.close()
            if self.inode is not None:
                try:
                    metadata = os.lstat(self.path)
                    if (self.inode == (metadata.st_dev, metadata.st_ino) and
                            stat.S_ISSOCK(metadata.st_mode) and
                            metadata.st_uid == os.geteuid()):
                        os.unlink(self.path)
                except OSError:
                    pass
            raise
        finally:
            os.close(directory_fd)

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, unused = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.connection_slots.acquire(False):
                connection.close()
                continue
            with self.connection_lock:
                self.connections.add(connection)
            thread = threading.Thread(target=self._one, args=(connection,))
            thread.daemon = True
            with self.connection_lock:
                self.workers.add(thread)
            thread.start()

    def _one(self, connection):
        try:
            connection.settimeout(0.2)
            self._endpoint_metadata()
            unused_pid, uid, unused_gid = _control_peer_credentials(connection)
            request = _read_frame_socket(connection, time.monotonic() + 1,
                                         self.stop, time.monotonic)
            if uid != os.geteuid():
                return
            if set(request) != {"schema_version", "controller_id", "request"}:
                return
            if (type(request["schema_version"]) is not int or
                    request["schema_version"] != 1 or
                    request["controller_id"] != self.controller_id):
                return
            response = self.dispatch(request["request"])
            self._endpoint_metadata()
            connection.sendall(_encode_frame({"schema_version": 1,
                "controller_id": self.controller_id, "response": response}))
        except Exception:
            pass
        finally:
            with self.connection_lock:
                self.connections.discard(connection)
                self.workers.discard(threading.current_thread())
            connection.close()
            self.connection_slots.release()

    def close(self):
        self.stop.set()
        if self.listener is not None:
            self.listener.close()
        with self.connection_lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.thread is not None:
            self.thread.join(0.8)
        deadline = time.monotonic() + 1.0
        while True:
            with self.connection_lock:
                workers = list(self.workers)
            if not workers:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for worker in workers:
                worker.join(min(remaining, 0.1))
        try:
            metadata = self._endpoint_metadata()
            if self.inode == (metadata.st_dev, metadata.st_ino):
                directory_fd = _open_directory_anchor(
                    os.path.dirname(self.path), required_mode=0o700)
                try:
                    current = os.stat(
                        os.path.basename(self.path), dir_fd=directory_fd,
                        follow_symlinks=False)
                    if self.inode == (current.st_dev, current.st_ino):
                        os.unlink(os.path.basename(self.path),
                                  dir_fd=directory_fd)
                        os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, ValueError):
            pass
        with self.connection_lock:
            if self.workers:
                raise RuntimeError(
                    "IOx control server retained active dispatch workers")


class _ControlClient(object):
    def __init__(self, state_dir=None):
        raw_state = state_dir if state_dir is not None else os.environ.get(
            "IRIS_STATE", "")
        self.state_dir = _safe_state_root(raw_state)
        iox_directory = os.path.join(self.state_dir, "iox")
        _safe_directory(iox_directory)
        authority = _read_json_strict(
            os.path.join(iox_directory, "authority.json"), 16384)
        if (not isinstance(authority, dict) or set(authority) != {
                "schema_version", "controller_id", "record_store"} or
                type(authority.get("schema_version")) is not int or
                authority.get("schema_version") != 1 or
                not isinstance(authority.get("controller_id"), str) or
                not _HEX32.fullmatch(authority["controller_id"]) or
                not isinstance(authority.get("record_store"), str) or
                not os.path.isabs(authority["record_store"])):
            raise ValueError("invalid IOx authority")
        self.controller_id = authority["controller_id"]
        self.path = os.path.join(self.state_dir, "iox", "control.sock")

    def request(self, request):
        directory = os.path.dirname(self.path)
        name = os.path.basename(self.path)
        directory_fd = _open_directory_anchor(directory, required_mode=0o700)
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(before.st_mode) or
                stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_uid != os.geteuid() or before.st_nlink != 1):
            os.close(directory_fd)
            raise ValueError("unsafe IOx control endpoint")
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.settimeout(1.0)
            peer.connect("/proc/self/fd/%d/%s" % (directory_fd, name))
            after = os.stat(name, dir_fd=directory_fd,
                            follow_symlinks=False)
            if ((before.st_dev, before.st_ino) !=
                    (after.st_dev, after.st_ino) or
                    not stat.S_ISSOCK(after.st_mode) or
                    stat.S_IMODE(after.st_mode) != 0o600 or
                    after.st_uid != os.geteuid() or after.st_nlink != 1):
                raise ValueError("IOx control endpoint changed")
            unused_pid, uid, unused_gid = _control_peer_credentials(peer)
            if uid != os.geteuid():
                raise ValueError("foreign IOx control peer")
            peer.sendall(_encode_frame({"schema_version": 1,
                "controller_id": self.controller_id, "request": request}))
            peer.settimeout(None)
            try:
                response = _read_frame_socket(peer, time.monotonic() + 7200,
                                              None, time.monotonic)
            except (EOFError, _ControllerFailure):
                raise RuntimeError("IOx control response unavailable")
            if (set(response) != {"schema_version", "controller_id", "response"} or
                    type(response["schema_version"]) is not int or
                    response["schema_version"] != 1 or
                    response["controller_id"] != self.controller_id):
                raise ValueError("foreign IOx control response")
            return response["response"]
        finally:
            peer.close()
            os.close(directory_fd)

    def close(self):
        pass


def main(argv=None, client_factory=None, stdout=None):
    parser = argparse.ArgumentParser(prog="iox-verification")
    sub = parser.add_subparsers(dest="operation")
    for name in ("submit-install", "submit-uninstall", "recover"):
        command = sub.add_parser(name)
        command.add_argument("--device-id", required=True)
        command.add_argument("--wait", action="store_true")
        command.add_argument("--wait-timeout", type=int, default=7200)
        if name == "submit-uninstall":
            command.add_argument("--force-agent-only", action="store_true")
        else:
            command.add_argument("--force-agent-only", action="store_true",
                                 help=argparse.SUPPRESS)
    reconcile = sub.add_parser("reconcile-enabled")
    reconcile.add_argument("--record-id", required=True)
    reconcile.add_argument("--transaction-id", required=True)
    reconcile.add_argument("--revision", required=True, type=int)
    reconcile.add_argument("--acknowledge-external-resolution", action="store_true")
    reconcile.add_argument("--wait", action="store_true")
    reconcile.add_argument("--wait-timeout", type=int, default=7200)
    reconcile.add_argument("--force-agent-only", action="store_true", help=argparse.SUPPRESS)
    job = sub.add_parser("job")
    job.add_argument("--job-id", required=True)
    job.add_argument("--wait", action="store_true")
    job.add_argument("--wait-timeout", type=int, default=7200)
    args = parser.parse_args(argv)
    if args.operation is None:
        parser.error("an operation is required")
    if getattr(args, "force_agent_only", False) and args.operation != "submit-uninstall":
        parser.error("force is valid only for submit-uninstall")
    if args.wait and not 1 <= args.wait_timeout <= 7200:
        parser.error("wait timeout must be from 1 through 7200")
    if args.operation == "reconcile-enabled" and not args.acknowledge_external_resolution:
        parser.error("reconciliation acknowledgement is required")
    request = {"operation": args.operation, "wait": bool(args.wait)}
    if args.wait:
        request["wait_timeout"] = args.wait_timeout
    if args.operation in ("submit-install", "submit-uninstall", "recover"):
        request["device_id"] = args.device_id
    if args.operation == "submit-uninstall" and args.force_agent_only:
        request["force_agent_only"] = True
    if args.operation == "job":
        request["job_id"] = args.job_id
    if args.operation == "reconcile-enabled":
        request.update({"record_id": args.record_id,
                        "transaction_id": args.transaction_id,
                        "revision": args.revision,
                        "acknowledge_external_resolution": True})
    client = (client_factory or _ControlClient)()
    try:
        response = client.request(request)
    finally:
        client.close()
    output = stdout or sys.stdout
    output.write(json.dumps(response, sort_keys=True) + "\n")
    if response.get("error"):
        return 2
    if response.get("wait_timed_out"):
        return 4
    if response.get("terminal"):
        return response.get("result_code", 4)
    return 0


if __name__ == "__main__":
    if (len(sys.argv) == 5 and
            sys.argv[1] == "--_iris-iox-supervisor"):
        try:
            supervisor_control = int(sys.argv[2])
            supervisor_lock = int(sys.argv[3])
            supervisor_deadline = float(sys.argv[4])
            if (supervisor_control < 3 or supervisor_lock < -1 or
                    not math.isfinite(supervisor_deadline) or
                    supervisor_deadline <= 0):
                raise ValueError("invalid supervisor descriptors")
        except ValueError:
            sys.exit(110)
        sys.exit(_supervisor_main(
            supervisor_control, supervisor_lock, supervisor_deadline))
    sys.exit(main())
