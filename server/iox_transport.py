# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded local transport and evidence handling for IRIS IOx work.

This module deliberately has no dependency on the management API.  The IOx
controller supplies an already validated command plan and durable transcript;
this module executes that plan, captures sanitized evidence, and fully reaps
the local process tree before reporting completion.
"""

from __future__ import absolute_import

import base64
import copy
import errno
import hashlib
import json
import math
import os
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time


WRAPPER_MAX_BYTES = 256 * 1024 * 1024
WRAPPER_COPY_CHUNK_BYTES = 1024 * 1024
WRAPPER_COPY_MAX_SECONDS = 120
INSTRUCTION_MAX_BYTES = 256 * 1024

ARCHIVE_MAX_MEMBERS = 4096
ARCHIVE_MAX_NAME_BYTES = 4096
ARCHIVE_MAX_MARKERS_PER_KIND = 1
ARCHIVE_SCAN_WALL_SECONDS = 15
ARCHIVE_SCAN_CPU_SECONDS = 10
ARCHIVE_SCAN_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
ARCHIVE_SCAN_RESULT_BYTES = 4096
ARCHIVE_TRAILER_MIN_BYTES = 1024

_FRAME_MAX_BYTES = 65536
_STREAM_CHUNK_BYTES = 4096
_CAPTURE_BYTES = 32768
_VERIFY_CAPTURE_BYTES = 8192
_MAX_INTEGER = (1 << 63) - 1
_REDACTION = b"<redacted>"
_PROCESS_TERM_SECONDS = 0.02
_PROCESS_CLEANUP_RESERVE_SECONDS = 0.05

_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
_RECORD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_BOARD_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PROMPT_RE = re.compile(br"^(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,62})(?P<level>[>#]) ?$")
_CONFIG_PROMPT_RE = re.compile(br"^(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,62})\((?P<body>config(?:-[A-Za-z0-9]+)*)\)#$")
_REMOTE_PATH_RE = re.compile(
    r"^(?:flash|bootflash|sdflash|harddisk):/?[A-Za-z0-9._/-]{1,240}$")

_PHASES = frozenset((
    "observed", "disable_intent", "disabled_confirmed", "installing",
    "ownership_probe", "restore_intent", "restored", "unchanged",
    "relinquished", "indeterminate",
))
_JOURNAL_EVENTS = frozenset((
    "disable_intent", "disable_confirmed", "installing", "ownership_probe",
    "restore_intent", "restored", "unchanged", "relinquished",
    "indeterminate", "error", "reconcile_enabled",
))
_ERROR_CATEGORIES = frozenset((
    "rejected", "unsupported_syntax", "unsupported_response", "silence",
    "timeout", "ssh_authentication", "host_key", "connection", "transport",
    "caf_transient", "readback_unknown", "readback_mismatch",
    "wrapper_unreadable", "wrapper_not_regular", "wrapper_oversize",
    "wrapper_copy_timeout", "wrapper_changed", "wrapper_archive_invalid",
    "wrapper_archive_limit", "wrapper_scan_failed", "journal_unreadable",
    "journal_durability", "stale_cas", "invalid_transition",
    "authority_mismatch", "identity_mismatch", "board_busy", "cancelled",
    "transcript_limit", "descendant_unreaped", "reconciliation_required",
))
_PURPOSES = frozenset((
    "iox_status", "app_list", "routing_prereq", "storage_prereq", "clock",
    "prepare_iox_scp", "configure_network", "mkdir_share", "app_stop",
    "app_deactivate", "app_uninstall", "remove_app_config", "configure_app",
    "app_install", "app_activate", "copy_certificate", "app_start", "save",
    "remove_wrapper", "remove_certificate", "cleanup_config", "cleanup_files",
    "cleanup_config_probe", "cleanup_stage_probe", "upload_wrapper",
    "upload_certificate", "upload_instructions", "copy_instructions",
    "remove_instructions", "identity_discovery", "identity_revalidation",
    "preflight", "verification_read", "verification_disable",
    "verification_enable", "recipe_output",
))


class IoxTransportError(ValueError):
    """A closed, sanitized failure at the IOx transport boundary."""

    def __init__(self, category, detail=None):
        if category not in _ERROR_CATEGORIES:
            category = "transport"
        self.category = category
        self.detail = _bounded_detail(detail or category)
        ValueError.__init__(self, self.detail)


def _bounded_detail(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    else:
        value = str(value)
    encoded = value.encode("utf-8", "replace")[:1024]
    return encoded.decode("utf-8", "ignore")


def _cancelled(cancel):
    if cancel is None:
        return False
    method = getattr(cancel, "is_set", None)
    if method is not None:
        return bool(method())
    if callable(cancel):
        return bool(cancel())
    return bool(cancel)


def _now(monotonic_fn):
    return (monotonic_fn or time.monotonic)()


def _check_wait(deadline, cancel, monotonic_fn, timeout_category="timeout"):
    if _cancelled(cancel):
        raise IoxTransportError("cancelled")
    if deadline is not None and _now(monotonic_fn) >= deadline:
        raise IoxTransportError(timeout_category)


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(unused):
    raise ValueError("non-finite JSON number")


def _json_loads_strict(payload):
    value = json.loads(
        payload.decode("utf-8"), object_pairs_hook=_no_duplicates,
        parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON frame must contain an object")
    return value


def _encode_frame(value):
    try:
        payload = json.dumps(
            value, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise IoxTransportError("rejected", exc)
    if not 1 <= len(payload) <= _FRAME_MAX_BYTES:
        raise IoxTransportError("rejected", "JSON frame length is out of bounds")
    return struct.pack("!I", len(payload)) + payload


class _FrameReader(object):
    def __init__(self, connection, deadline, cancel, monotonic_fn=None):
        self.connection = connection
        self.deadline = deadline
        self.cancel = cancel
        self.monotonic_fn = monotonic_fn or time.monotonic

    def _exact(self, size):
        result = bytearray()
        while len(result) < size:
            _check_wait(self.deadline, self.cancel, self.monotonic_fn)
            remaining = max(0.0, self.deadline - self.monotonic_fn())
            wait = min(0.05, remaining)
            try:
                readable, unused_w, unused_x = select_select(
                    [self.connection], [], [], wait)
            except (OSError, ValueError) as exc:
                raise IoxTransportError("transport", exc)
            if not readable:
                continue
            try:
                chunk = self.connection.recv(size - len(result))
            except (OSError, socket.error) as exc:
                raise IoxTransportError("transport", exc)
            if not chunk:
                raise IoxTransportError("unsupported_response", "partial JSON frame")
            result.extend(chunk)
        return bytes(result)

    def read(self):
        header = self._exact(4)
        length = struct.unpack("!I", header)[0]
        if not 1 <= length <= _FRAME_MAX_BYTES:
            raise IoxTransportError("rejected", "JSON frame length is out of bounds")
        body = self._exact(length)
        try:
            return _json_loads_strict(body)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise IoxTransportError("rejected", exc)


# Kept as a module attribute so tests and callers do not need to import select.
from select import select as select_select


class _StreamingRedactor(object):
    """Byte streaming, deterministic leftmost-longest literal replacement."""

    def __init__(self, secrets):
        values = []
        for value in secrets:
            if isinstance(value, str):
                value = value.encode("utf-8")
            elif not isinstance(value, bytes):
                value = str(value).encode("utf-8")
            if not value:
                continue
            if len(value) > 4096:
                raise IoxTransportError("rejected", "configured secret exceeds 4096 bytes")
            if value not in values:
                values.append(value)
        self.secrets = tuple(sorted(values, key=lambda item: (-len(item), item)))
        self.maximum = max([len(value) for value in self.secrets] or [0])
        self.pending = b""

    def _replace(self, data, final):
        output = bytearray()
        cursor = 0
        while cursor < len(data):
            match = None
            for secret in self.secrets:
                if data.startswith(secret, cursor):
                    if match is None or len(secret) > len(match):
                        match = secret
            if match is not None:
                if (not final and any(
                        len(secret) > len(data) - cursor and
                        secret.startswith(data[cursor:])
                        for secret in self.secrets)):
                    break
                output.extend(_REDACTION)
                cursor += len(match)
                continue
            if not final:
                suffix = data[cursor:]
                if any(secret.startswith(suffix) for secret in self.secrets):
                    break
            output.append(data[cursor])
            cursor += 1
        return bytes(output), data[cursor:]

    def feed(self, data):
        if not isinstance(data, bytes):
            raise TypeError("redactor input must be bytes")
        output, self.pending = self._replace(self.pending + data, False)
        return output

    def finish(self):
        output, remaining = self._replace(self.pending, True)
        self.pending = b""
        return output + remaining


def _is_int(value, minimum=0, maximum=_MAX_INTEGER):
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _exact_keys(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _valid_hex32(value):
    return isinstance(value, str) and _HEX32_RE.fullmatch(value) is not None


def _valid_record_id(value, nullable=False):
    return (nullable and value is None) or (
        isinstance(value, str) and _RECORD_RE.fullmatch(value) is not None)


def _valid_board(value, nullable=False):
    return (nullable and value is None) or (
        isinstance(value, str) and _BOARD_RE.fullmatch(value) is not None)


def _valid_remote_path(value, purpose):
    if not isinstance(value, str) or _REMOTE_PATH_RE.fullmatch(value) is None:
        return False
    relative = value.split(":", 1)[1]
    if relative.startswith("/"):
        relative = relative[1:]
    components = relative.split("/")
    if any(component in ("", ".", "..") for component in components):
        return False
    basename = components[-1]
    if purpose == "upload_wrapper":
        return re.fullmatch(r"iris-[0-9a-f]{32}\.tar", basename) is not None
    if purpose == "upload_instructions":
        return re.fullmatch(
            r"iris-instructions-[0-9a-f]{32}\.envelope", basename) is not None
    return purpose == "upload_certificate" and basename == "iris-ca.pem"


def _durable_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secure_directory(path):
    if os.path.lexists(path):
        metadata = os.lstat(path)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise IoxTransportError("journal_durability", "unsafe transcript directory")
        if metadata.st_uid != os.geteuid():
            raise IoxTransportError("journal_durability", "foreign transcript directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            os.chmod(path, 0o700)
        return
    parent = os.path.dirname(path) or "."
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        # A sibling attempt won the race; hold it to the same standard.
        return _secure_directory(path)
    os.chmod(path, 0o700)
    _durable_directory(parent)


class _TranscriptWriter(object):
    def __init__(self, root, attempt_id, controller_id, created_at,
                 max_bytes=1048576, restore_reserve_bytes=131072):
        if not _valid_hex32(attempt_id) or not _valid_hex32(controller_id):
            raise IoxTransportError("rejected", "invalid transcript identity")
        if not _is_int(created_at) or not _is_int(max_bytes, 1) or not _is_int(
                restore_reserve_bytes, 0) or restore_reserve_bytes >= max_bytes:
            raise IoxTransportError("rejected", "invalid transcript bounds")
        self.attempt_id = attempt_id
        self.controller_id = controller_id
        self.max_bytes = max_bytes
        self.restore_reserve_bytes = restore_reserve_bytes
        iox = os.path.join(root, "iox")
        transcripts = os.path.join(iox, "transcripts")
        try:
            _secure_directory(iox)
            _secure_directory(transcripts)
        except IoxTransportError:
            raise
        except OSError as exc:
            raise IoxTransportError("journal_durability", exc)
        self.path = os.path.join(transcripts, attempt_id + ".transcript")
        if os.path.lexists(self.path):
            raise IoxTransportError("journal_durability", "transcript already exists")
        self._bytes = b""
        self._commands = {}
        self._closed = set()
        self._observed = 0
        self._dropped = 0
        self._truncated = False
        self._lock = threading.RLock()
        self._identity = None
        header = {
            "schema_version": 1, "type": "header", "id": attempt_id,
            "attempt_id": attempt_id, "controller_id": controller_id,
            "created_at": created_at,
        }
        frame = _encode_frame(header)
        self._create(frame)
        self._bytes = frame

    def _create(self, content):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or
                        metadata.st_uid != os.geteuid() or
                        stat.S_IMODE(metadata.st_mode) != 0o600 or
                        metadata.st_nlink != 1):
                    raise IoxTransportError(
                        "journal_durability", "unsafe transcript metadata")
                self._identity = (metadata.st_dev, metadata.st_ino)
            _durable_directory(os.path.dirname(self.path))
        except Exception as exc:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(self.path)
            except OSError:
                pass
            raise IoxTransportError("journal_durability", exc)

    def _check_target(self):
        try:
            return self._check_target_unwrapped()
        except IoxTransportError:
            raise
        except OSError as exc:
            raise IoxTransportError("journal_durability", exc)

    def _check_target_unwrapped(self):
        metadata = os.lstat(self.path)
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino) != self._identity):
            raise IoxTransportError("journal_durability", "unsafe transcript metadata")
        descriptor = os.open(
            self.path, os.O_RDONLY | os.O_CLOEXEC |
            getattr(os, "O_NOFOLLOW", 0) |
            getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(descriptor)
            if ((opened.st_dev, opened.st_ino) !=
                    (metadata.st_dev, metadata.st_ino) or
                    not stat.S_ISREG(opened.st_mode) or
                    opened.st_uid != os.geteuid() or
                    stat.S_IMODE(opened.st_mode) != 0o600 or
                    opened.st_nlink != 1 or
                    (opened.st_dev, opened.st_ino) != self._identity):
                raise IoxTransportError(
                    "journal_durability", "transcript target changed")
            chunks = []
            remaining = len(self._bytes) + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            existing = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = os.lstat(self.path)
        if (stat.S_ISLNK(current.st_mode) or
                not stat.S_ISREG(current.st_mode) or
                current.st_uid != os.geteuid() or
                stat.S_IMODE(current.st_mode) != 0o600 or
                current.st_nlink != 1 or
                _metadata_tuple(opened) != _metadata_tuple(after) or
                _metadata_tuple(opened) != _metadata_tuple(current)):
            raise IoxTransportError(
                "journal_durability", "transcript changed during validation")
        if existing != self._bytes:
            raise IoxTransportError("journal_durability", "transcript prefix changed")

    def _replace(self, content):
        self._check_target()
        directory = os.path.dirname(self.path)
        descriptor, temporary = tempfile.mkstemp(prefix=".transcript-", suffix=".tmp", dir=directory)
        replaced = False
        replacement_identity = None
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or
                        metadata.st_uid != os.geteuid() or
                        stat.S_IMODE(metadata.st_mode) != 0o600 or
                        metadata.st_nlink != 1):
                    raise IoxTransportError(
                        "journal_durability", "unsafe replacement metadata")
                replacement_identity = (metadata.st_dev, metadata.st_ino)
            os.replace(temporary, self.path)
            replaced = True
            _durable_directory(directory)
            self._identity = replacement_identity
        except Exception as exc:
            if descriptor >= 0:
                os.close(descriptor)
            if not replaced:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise IoxTransportError("journal_durability", exc)
        finally:
            if not replaced:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _validated(self, record):
        if (not isinstance(record, dict) or
                not _is_int(record.get("schema_version"), 1, 1)):
            raise IoxTransportError("rejected", "invalid transcript record")
        kind = record.get("type")
        commands = copy.deepcopy(self._commands)
        closed = set(self._closed)
        observed, dropped, truncated = self._observed, self._dropped, self._truncated
        if kind == "journal_ack":
            keys = "schema_version type record_id transaction_id revision phase event at".split()
            if not _exact_keys(record, keys):
                raise IoxTransportError("rejected", "invalid journal acknowledgement")
            if (not _valid_record_id(record["record_id"]) or
                    not _valid_hex32(record["transaction_id"]) or
                    not _is_int(record["revision"]) or
                    record["phase"] not in _PHASES or
                    record["event"] not in _JOURNAL_EVENTS or
                    not _is_int(record["at"])):
                raise IoxTransportError("rejected", "invalid journal acknowledgement")
        elif kind == "command_start":
            keys = "schema_version type command_id kind purpose board_identity record_id transaction_id revision phase started_at".split()
            if not _exact_keys(record, keys):
                raise IoxTransportError("rejected", "invalid command start")
            command_id = record["command_id"]
            purpose = record["purpose"]
            nullable_board = purpose == "identity_discovery"
            if (not _is_int(command_id, 1) or command_id in commands or command_id in closed or
                    record["kind"] not in ("ssh", "scp", "recipe_output") or
                    purpose not in _PURPOSES or
                    not _valid_board(record["board_identity"], nullable_board) or
                    (record["board_identity"] is None and not nullable_board) or
                    not _valid_record_id(record["record_id"], True) or
                    not ((record["transaction_id"] is None) or _valid_hex32(record["transaction_id"])) or
                    not ((record["revision"] is None) or _is_int(record["revision"])) or
                    not ((record["phase"] is None) or record["phase"] in _PHASES) or
                    not _is_int(record["started_at"])):
                raise IoxTransportError("rejected", "invalid command start")
            expected_kind = (
                "scp" if purpose in (
                    "upload_wrapper", "upload_certificate",
                    "upload_instructions")
                else "recipe_output" if purpose == "recipe_output" else "ssh")
            if record["kind"] != expected_kind:
                raise IoxTransportError("rejected", "command kind and purpose disagree")
            commands[command_id] = {
                "purpose": purpose, "kind": record["kind"],
                "stdout": 0, "stderr": 0,
            }
        elif kind == "stream":
            keys = "schema_version type command_id stream offset data_b64".split()
            if not _exact_keys(record, keys) or not _is_int(record.get("command_id"), 1):
                raise IoxTransportError("rejected", "invalid transcript stream")
            command = commands.get(record["command_id"])
            stream_name = record.get("stream")
            if command is None or stream_name not in ("stdout", "stderr"):
                raise IoxTransportError("rejected", "stream has no open command")
            if not _is_int(record.get("offset")) or record["offset"] != command[stream_name]:
                raise IoxTransportError("rejected", "noncontiguous transcript stream")
            encoded = record.get("data_b64")
            if not isinstance(encoded, str):
                raise IoxTransportError("rejected", "invalid base64 stream")
            try:
                raw = base64.b64decode(encoded.encode("ascii"), validate=True)
            except (ValueError, UnicodeError, TypeError):
                raise IoxTransportError("rejected", "invalid base64 stream")
            if (not 1 <= len(raw) <= _STREAM_CHUNK_BYTES or
                    base64.b64encode(raw).decode("ascii") != encoded):
                raise IoxTransportError("rejected", "invalid transcript chunk")
            if (command["purpose"].startswith("verification_") and
                    command[stream_name] + len(raw) > _VERIFY_CAPTURE_BYTES):
                raise IoxTransportError(
                    "rejected", "verification transcript stream exceeds cap")
            command[stream_name] += len(raw)
        elif kind == "command_end":
            keys = "schema_version type command_id finished_at returncode timed_out stdout_truncated stderr_truncated framing_complete error_category stdout_observed_bytes stderr_observed_bytes stdout_dropped_bytes stderr_dropped_bytes payload_spans observed_state transition_response".split()
            if not _exact_keys(record, keys) or not _is_int(record.get("command_id"), 1):
                raise IoxTransportError("rejected", "invalid command end")
            command_id = record["command_id"]
            command = commands.get(command_id)
            if command is None:
                raise IoxTransportError("rejected", "command is not open")
            if not _is_int(record["finished_at"]):
                raise IoxTransportError("rejected", "invalid command timestamp")
            returncode = record["returncode"]
            if not (returncode is None or _is_int(returncode, -255, 255)):
                raise IoxTransportError("rejected", "invalid command status")
            for name in ("timed_out", "stdout_truncated", "stderr_truncated", "framing_complete"):
                if not isinstance(record[name], bool):
                    raise IoxTransportError("rejected", "invalid command flag")
            category = record["error_category"]
            if category is not None and category not in _ERROR_CATEGORIES:
                raise IoxTransportError("rejected", "invalid command category")
            counters = []
            for name in ("stdout_observed_bytes", "stderr_observed_bytes",
                         "stdout_dropped_bytes", "stderr_dropped_bytes"):
                if not _is_int(record[name]):
                    raise IoxTransportError("rejected", "invalid command counter")
                counters.append(record[name])
            so, se, sd, sed = counters
            if (so != command["stdout"] + sd or se != command["stderr"] + sed or
                    record["stdout_truncated"] != bool(sd) or
                    record["stderr_truncated"] != bool(sed)):
                raise IoxTransportError("rejected", "command counters do not match streams")
            spans = record["payload_spans"]
            if not isinstance(spans, list) or len(spans) > 128:
                raise IoxTransportError("rejected", "invalid payload spans")
            for span in spans:
                if (not _exact_keys(span, ("offset", "length")) or
                        not _is_int(span["offset"]) or not _is_int(span["length"]) or
                        span["offset"] + span["length"] > command["stdout"]):
                    raise IoxTransportError("rejected", "invalid payload span")
            state = record["observed_state"]
            if command["purpose"] == "verification_read":
                if state not in ("enabled", "disabled", "unknown"):
                    raise IoxTransportError("rejected", "invalid observed state")
            elif state is not None:
                raise IoxTransportError("rejected", "unexpected observed state")
            transition = record["transition_response"]
            if command["purpose"] in ("verification_disable", "verification_enable"):
                if transition not in ("disabled_successfully", "enabled_successfully", "caf_transient", "other"):
                    raise IoxTransportError("rejected", "invalid transition response")
            elif transition is not None:
                raise IoxTransportError("rejected", "unexpected transition response")
            observed = min(_MAX_INTEGER, observed + so + se)
            dropped = min(_MAX_INTEGER, dropped + sd + sed)
            truncated = truncated or bool(sd or sed)
            del commands[command_id]
            closed.add(command_id)
        else:
            raise IoxTransportError("rejected", "unknown transcript record type")
        return commands, closed, observed, dropped, truncated

    def append(self, record, restoration=False):
        self._append_many((record,), restoration=restoration)

    def _append_many(self, records, restoration=False):
        """Validate and durably replace one internally assembled frame batch."""
        with self._lock:
            prior = (
                self._bytes, copy.deepcopy(self._commands), set(self._closed),
                self._observed, self._dropped, self._truncated)
            content = self._bytes
            try:
                for record in records:
                    state = self._validated(record)
                    frame = _encode_frame(record)
                    content += frame
                    if (record.get("type") == "journal_ack" and
                            record.get("phase") in (
                                "ownership_probe", "restore_intent")):
                        restoration = True
                    limit = (self.max_bytes if restoration else
                             self.max_bytes - self.restore_reserve_bytes)
                    if len(content) > limit:
                        raise IoxTransportError("transcript_limit")
                    (self._commands, self._closed, self._observed,
                     self._dropped, self._truncated) = state
                if content == self._bytes:
                    return
                self._replace(content)
                self._bytes = content
            except Exception:
                (self._bytes, self._commands, self._closed, self._observed,
                 self._dropped, self._truncated) = prior
                raise

    def reference(self):
        with self._lock:
            self._check_target()
            return {
                "id": self.attempt_id, "attempt_id": self.attempt_id,
                "stored_bytes": len(self._bytes),
                "observed_bytes": self._observed,
                "dropped_bytes": self._dropped,
                "truncated": self._truncated,
            }


class _WrapperSnapshot(object):
    def __init__(self, descriptor, digest, sign, cert):
        self.fd = descriptor
        self.sha256 = digest
        self.package_sign_present = sign
        self.package_cert_present = cert
        self._closed = False

    def __enter__(self):
        return self

    def close(self):
        if not self._closed:
            self._closed = True
            os.close(self.fd)

    def __exit__(self, unused_type, unused_value, unused_traceback):
        self.close()


def _metadata_tuple(value):
    return (value.st_dev, value.st_ino, value.st_size,
            getattr(value, "st_mtime_ns", int(value.st_mtime * 1000000000)),
            getattr(value, "st_ctime_ns", int(value.st_ctime * 1000000000)))


def _drain_child(child, deadline, cancel, limit, monotonic_fn, captures=None,
                 supervised=False, termination_deadline=None):
    termination_deadline = (deadline if termination_deadline is None
                            else termination_deadline)
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = {"stdout": False, "stderr": False}
    streams = (("stdout", child.stdout), ("stderr", child.stderr))
    for name, stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    failure = None
    try:
        while selector.get_map():
            try:
                _check_wait(deadline, cancel, monotonic_fn)
            except IoxTransportError as exc:
                failure = exc
                break
            remaining = max(0.0, deadline - _now(monotonic_fn))
            events = selector.select(min(0.05, remaining))
            for key, unused_mask in events:
                try:
                    data = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if captures is not None:
                    captures[key.data].feed(data)
                    continue
                target = buffers[key.data]
                room = max(0, limit + 1 - len(target))
                target.extend(data[:room])
                if len(data) > room or len(target) > limit:
                    overflow[key.data] = True
        if failure is not None:
            _terminate_process(
                child, termination_deadline, monotonic_fn, supervised)
        else:
            remaining = max(0.0, deadline - _now(monotonic_fn))
            try:
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                failure = IoxTransportError("timeout")
                _terminate_process(
                    child, termination_deadline, monotonic_fn, supervised)
    finally:
        selector.close()
        for unused_name, stream in streams:
            try:
                stream.close()
            except Exception:
                pass
    return (bytes(buffers["stdout"][:limit]), bytes(buffers["stderr"][:limit]),
            overflow["stdout"], overflow["stderr"], failure)


def _terminate_process(child, deadline, monotonic_fn, supervised=False):
    def immediate_wait():
        if child.returncode is not None:
            return True
        try:
            child.wait(timeout=0.0)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return child.returncode is not None

    def signal_group(sig):
        try:
            os.killpg(child.pid, sig)
            return
        except (OSError, ProcessLookupError):
            # The exact supervised proxy can signal through its authenticated
            # channel.  Bind that request to the same absolute deadline as the
            # operation; after expiry only the nonblocking killpg attempt above
            # is permitted.
            remaining = deadline - _now(monotonic_fn)
            if supervised and remaining <= 0:
                return
            try:
                child.send_signal(sig, timeout=remaining) if supervised else (
                    child.terminate() if sig == signal.SIGTERM else child.kill())
            except Exception:
                pass

    if immediate_wait():
        return True
    signal_group(signal.SIGTERM)
    remaining = max(
        0.0, min(_PROCESS_TERM_SECONDS, deadline - _now(monotonic_fn)))
    if remaining:
        try:
            child.wait(timeout=remaining)
        except (subprocess.TimeoutExpired, OSError):
            pass
    if child.returncode is not None:
        return True
    signal_group(signal.SIGKILL)
    remaining = max(0.0, deadline - _now(monotonic_fn))
    try:
        child.wait(timeout=remaining)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return child.returncode is not None


def _run_scanner(snapshot_fd, deadline, cancel, monotonic_fn):
    try:
        _check_wait(deadline, cancel, monotonic_fn)
    except IoxTransportError as exc:
        if exc.category == "cancelled":
            raise
        raise IoxTransportError("wrapper_scan_failed", exc)
    wall_deadline = min(deadline, _now(monotonic_fn) + ARCHIVE_SCAN_WALL_SECONDS)
    argv = [
        sys.executable, os.path.abspath(__file__), "--scan-wrapper-fd",
        str(snapshot_fd), str(ARCHIVE_MAX_MEMBERS), str(ARCHIVE_MAX_NAME_BYTES),
        str(ARCHIVE_MAX_MARKERS_PER_KIND), str(ARCHIVE_SCAN_CPU_SECONDS),
        str(ARCHIVE_SCAN_ADDRESS_SPACE_BYTES), str(ARCHIVE_TRAILER_MIN_BYTES),
    ]
    try:
        child = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(snapshot_fd,), close_fds=True,
            start_new_session=True)
    except Exception as exc:
        raise IoxTransportError("wrapper_scan_failed", exc)
    try:
        stdout, stderr, out_over, err_over, failure = _drain_child(
            child, wall_deadline, cancel, ARCHIVE_SCAN_RESULT_BYTES,
            monotonic_fn, termination_deadline=deadline)
    except Exception as exc:
        _terminate_process(child, deadline, monotonic_fn)
        raise IoxTransportError("wrapper_scan_failed", exc)
    if failure is not None and failure.category == "cancelled":
        raise failure
    if failure is not None or out_over or err_over:
        raise IoxTransportError("wrapper_scan_failed")
    try:
        value = _json_loads_strict(stdout)
    except Exception as exc:
        raise IoxTransportError("wrapper_scan_failed", exc)
    status = child.returncode
    success_keys = {"schema_version", "package_sign_present", "package_cert_present", "member_count"}
    reject_keys = {"schema_version", "category", "reason"}
    if (status == 0 and set(value) == success_keys and
            _is_int(value.get("schema_version"), 1, 1)):
        if (not isinstance(value["package_sign_present"], bool) or
                not isinstance(value["package_cert_present"], bool) or
                not _is_int(value["member_count"], 0, ARCHIVE_MAX_MEMBERS) or stderr):
            raise IoxTransportError("wrapper_scan_failed")
        return value
    reasons = {
        "wrapper_archive_invalid": frozenset((
            "bad_size", "bad_header", "bad_checksum", "bad_format",
            "unsupported_type", "unsafe_name", "duplicate_name",
            "bad_terminator", "concatenated_archive", "iterator_mismatch")),
        "wrapper_archive_limit": frozenset(("member_limit", "name_limit", "marker_limit")),
    }
    if (set(value) == reject_keys and
            _is_int(value.get("schema_version"), 1, 1) and not stderr and
            value.get("category") in reasons and value.get("reason") in reasons[value["category"]] and
            status == (2 if value["category"] == "wrapper_archive_invalid" else 3)):
        raise IoxTransportError(value["category"], value["reason"])
    raise IoxTransportError("wrapper_scan_failed")


def admit_wrapper(source_path, snapshot_dir, deadline, cancel, monotonic_fn=None):
    monotonic_fn = monotonic_fn or time.monotonic
    source_fd = -1
    snapshot_fd = -1
    result_fd = -1
    snapshot_path = None
    snapshot_identity = None
    try:
        _check_wait(deadline, cancel, monotonic_fn, "wrapper_copy_timeout")
        flags = (os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
        try:
            source_fd = os.open(source_path, flags)
        except OSError as exc:
            raise IoxTransportError("wrapper_unreadable", exc)
        initial = os.fstat(source_fd)
        if not stat.S_ISREG(initial.st_mode):
            raise IoxTransportError("wrapper_not_regular")
        if initial.st_size < 1:
            raise IoxTransportError("wrapper_unreadable", "empty wrapper")
        if initial.st_size > WRAPPER_MAX_BYTES:
            raise IoxTransportError("wrapper_oversize")
        copy_deadline = min(deadline, monotonic_fn() + WRAPPER_COPY_MAX_SECONDS)
        snapshot_fd, snapshot_path = tempfile.mkstemp(
            prefix=".wrapper-", suffix=".snapshot", dir=snapshot_dir)
        os.fchmod(snapshot_fd, 0o600)
        created_snapshot = os.fstat(snapshot_fd)
        snapshot_identity = (created_snapshot.st_dev, created_snapshot.st_ino)
        if (not stat.S_ISREG(created_snapshot.st_mode) or
                created_snapshot.st_uid != os.geteuid() or
                stat.S_IMODE(created_snapshot.st_mode) != 0o600 or
                created_snapshot.st_nlink != 1):
            raise IoxTransportError(
                "wrapper_unreadable", "unsafe snapshot metadata")
        digest = hashlib.sha256()
        total = 0
        try:
            # Keep the original private inode open throughout admission.  A
            # duplicate is only a buffered writer for that same open file
            # description; it is never reopened through the pathname.
            with os.fdopen(os.dup(snapshot_fd), "wb") as output:
                while True:
                    _check_wait(copy_deadline, cancel, monotonic_fn, "wrapper_copy_timeout")
                    request = min(WRAPPER_COPY_CHUNK_BYTES, WRAPPER_MAX_BYTES - total + 1)
                    chunk = os.read(source_fd, request)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > WRAPPER_MAX_BYTES:
                        raise IoxTransportError("wrapper_oversize")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                try:
                    os.fsync(output.fileno())
                except OSError as exc:
                    raise IoxTransportError("journal_durability", exc)
        except IoxTransportError:
            raise
        except (OSError, IOError) as exc:
            raise IoxTransportError("wrapper_unreadable", exc)
        final_source = os.fstat(source_fd)
        if total != initial.st_size or _metadata_tuple(final_source) != _metadata_tuple(initial):
            raise IoxTransportError("wrapper_changed")
        os.close(source_fd)
        source_fd = -1
        try:
            opened = os.fstat(snapshot_fd)
            named = os.lstat(snapshot_path)
            if (not stat.S_ISREG(opened.st_mode) or
                    not stat.S_ISREG(named.st_mode) or
                    stat.S_ISLNK(named.st_mode) or
                    opened.st_uid != os.geteuid() or
                    named.st_uid != os.geteuid() or
                    stat.S_IMODE(opened.st_mode) != 0o600 or
                    stat.S_IMODE(named.st_mode) != 0o600 or
                    opened.st_nlink != 1 or named.st_nlink != 1 or
                    (opened.st_dev, opened.st_ino) != snapshot_identity or
                    _metadata_tuple(opened) != _metadata_tuple(named)):
                raise IoxTransportError("wrapper_unreadable", "unsafe snapshot metadata")
            os.unlink(snapshot_path)
            snapshot_path = None
            unlinked = os.fstat(snapshot_fd)
            if (unlinked.st_nlink != 0 or
                    (unlinked.st_dev, unlinked.st_ino) != snapshot_identity):
                raise IoxTransportError(
                    "wrapper_changed", "snapshot escaped private custody")
            custody = _metadata_tuple(unlinked)
            second = hashlib.sha256()
            os.lseek(snapshot_fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(snapshot_fd, WRAPPER_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                second.update(chunk)
            if second.hexdigest() != digest.hexdigest():
                raise IoxTransportError("wrapper_changed")
        except IoxTransportError:
            raise
        except OSError as exc:
            raise IoxTransportError("wrapper_unreadable", exc)
        # Convert custody to a read-only description while the original inode
        # is still held.  Once identity is proved, close the final writable
        # description before scanning so the admitted bytes cannot be mutated
        # through a descriptor retained by this process.
        result_fd = os.open(
            "/proc/self/fd/%d" % snapshot_fd,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0))
        returned = os.fstat(result_fd)
        held = os.fstat(snapshot_fd)
        if (returned.st_nlink != 0 or held.st_nlink != 0 or
                _metadata_tuple(returned) != custody or
                _metadata_tuple(held) != custody or
                (returned.st_dev, returned.st_ino) != snapshot_identity or
                (held.st_dev, held.st_ino) != snapshot_identity):
            raise IoxTransportError("wrapper_changed")
        os.close(snapshot_fd)
        snapshot_fd = -1
        os.lseek(result_fd, 0, os.SEEK_SET)
        scan = _run_scanner(result_fd, deadline, cancel, monotonic_fn)
        # The scanner consumed the same unlinked, read-only inode.  Recheck its
        # metadata and bytes before transferring that descriptor to the caller.
        after_scan = os.fstat(result_fd)
        if (after_scan.st_nlink != 0 or
                _metadata_tuple(after_scan) != custody):
            raise IoxTransportError("wrapper_changed")
        verified = hashlib.sha256()
        os.lseek(result_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(result_fd, WRAPPER_COPY_CHUNK_BYTES)
            if not chunk:
                break
            verified.update(chunk)
        os.lseek(result_fd, 0, os.SEEK_SET)
        if (verified.hexdigest() != digest.hexdigest() or
                _metadata_tuple(os.fstat(result_fd)) != custody):
            raise IoxTransportError("wrapper_changed")
        result = _WrapperSnapshot(
            result_fd, digest.hexdigest(), scan["package_sign_present"],
            scan["package_cert_present"])
        result_fd = -1
        return result
    finally:
        for descriptor in (source_fd, snapshot_fd, result_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if snapshot_path is not None:
            try:
                named = os.lstat(snapshot_path)
                if ((named.st_dev, named.st_ino) == snapshot_identity and
                        stat.S_ISREG(named.st_mode)):
                    os.unlink(snapshot_path)
            except OSError:
                pass


class _ScanReject(Exception):
    def __init__(self, category, reason):
        self.category = category
        self.reason = reason


def _tar_number(field):
    if not field:
        raise _ScanReject("wrapper_archive_invalid", "bad_header")
    index = 0
    while index < len(field) and field[index:index + 1] == b" ":
        index += 1
    start = index
    while index < len(field) and field[index:index + 1] in b"01234567":
        index += 1
    if index == start or any(byte not in (0, 32) for byte in bytearray(field[index:])):
        raise _ScanReject("wrapper_archive_invalid", "bad_header")
    value = int(field[start:index], 8)
    if value > _MAX_INTEGER:
        raise _ScanReject("wrapper_archive_invalid", "bad_size")
    return value


def _tar_text(field):
    position = field.find(b"\0")
    if position < 0:
        raw = field
    else:
        if field[position + 1:].strip(b"\0"):
            raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
        raw = field[:position]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
    if value.encode("utf-8") != raw:
        raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
    return value


def _safe_tar_name(header, is_ustar, directory, name_limit):
    name = _tar_text(header[0:100])
    if is_ustar and not name:
        raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
    prefix = _tar_text(header[345:500]) if is_ustar else ""
    value = prefix + "/" + name if prefix else name
    if directory and value.endswith("/"):
        value = value[:-1]
    elif not directory and value.endswith("/"):
        raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
    encoded = value.encode("utf-8")
    if len(encoded) > name_limit:
        raise _ScanReject("wrapper_archive_limit", "name_limit")
    components = value.split("/")
    if (not value or value.startswith("/") or "\\" in value or
            any(component in ("", ".", "..") for component in components) or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _ScanReject("wrapper_archive_invalid", "unsafe_name")
    return value


def _read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _scan_archive(descriptor, member_limit, name_limit, marker_limit, trailer_min):
    # tarfile is intentionally imported only after the scanner resource limits
    # have been installed by _scanner_main.
    import tarfile
    duplicate = set()
    raw_members = []
    markers = {"package.sign": 0, "package.cert": 0}
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        stream.seek(0, os.SEEK_END)
        total_size = stream.tell()
        stream.seek(0)
        cursor = 0
        zero_blocks = 0
        while cursor < total_size:
            header = _read_exact(stream, 512)
            if len(header) != 512:
                raise _ScanReject("wrapper_archive_invalid", "bad_terminator")
            cursor += 512
            if header == b"\0" * 512:
                zero_blocks += 1
                if zero_blocks == 2:
                    trailer = stream.read()
                    if any(byte != 0 for byte in bytearray(trailer)):
                        raise _ScanReject("wrapper_archive_invalid", "concatenated_archive")
                    if len(trailer) % 512:
                        raise _ScanReject("wrapper_archive_invalid", "bad_terminator")
                    if total_size - (cursor - 1024) < trailer_min:
                        raise _ScanReject("wrapper_archive_invalid", "bad_terminator")
                    break
                continue
            if zero_blocks:
                raise _ScanReject("wrapper_archive_invalid", "bad_terminator")
            if len(raw_members) >= member_limit:
                raise _ScanReject("wrapper_archive_limit", "member_limit")
            magic = header[257:263]
            if magic == b"ustar\0" and header[263:265] == b"00":
                is_ustar = True
            elif header[257:512] == b"\0" * 255:
                is_ustar = False
            else:
                raise _ScanReject("wrapper_archive_invalid", "bad_format")
            for start, end in ((100, 108), (108, 116), (116, 124),
                               (124, 136), (136, 148), (148, 156)):
                _tar_number(header[start:end])
            stored_checksum = _tar_number(header[148:156])
            checksum = sum(bytearray(header[:148] + b" " * 8 + header[156:]))
            if checksum != stored_checksum:
                raise _ScanReject("wrapper_archive_invalid", "bad_checksum")
            typeflag = header[156:157]
            if typeflag not in (b"\0", b"0", b"5"):
                raise _ScanReject("wrapper_archive_invalid", "unsupported_type")
            if header[157:257] != b"\0" * 100:
                raise _ScanReject("wrapper_archive_invalid", "unsupported_type")
            if is_ustar:
                for field in (header[329:337], header[337:345]):
                    if any(byte not in (0, 32, 48) for byte in bytearray(field)):
                        raise _ScanReject("wrapper_archive_invalid", "bad_header")
            size = _tar_number(header[124:136])
            directory = typeflag == b"5"
            if directory and size:
                raise _ScanReject("wrapper_archive_invalid", "bad_size")
            name = _safe_tar_name(header, is_ustar, directory, name_limit)
            if name in duplicate:
                raise _ScanReject("wrapper_archive_invalid", "duplicate_name")
            duplicate.add(name)
            data_offset = cursor
            padded = ((size + 511) // 512) * 512
            if cursor + padded > total_size:
                raise _ScanReject("wrapper_archive_invalid", "bad_size")
            raw_members.append((name, directory, size, data_offset))
            if not directory:
                basename = name.rsplit("/", 1)[-1]
                if basename in markers:
                    markers[basename] += 1
                    if markers[basename] > marker_limit:
                        raise _ScanReject("wrapper_archive_limit", "marker_limit")
            stream.seek(padded, os.SEEK_CUR)
            cursor += padded
        if zero_blocks < 2:
            raise _ScanReject("wrapper_archive_invalid", "bad_terminator")
    with os.fdopen(os.dup(descriptor), "rb") as raw:
        try:
            raw.seek(0)
            archive = tarfile.open(fileobj=raw, mode="r:")
            index = 0
            try:
                for member in archive:
                    if index >= len(raw_members):
                        raise _ScanReject("wrapper_archive_invalid", "iterator_mismatch")
                    expected = raw_members[index]
                    directory = member.isdir()
                    if not (member.isfile() or directory):
                        raise _ScanReject("wrapper_archive_invalid", "unsupported_type")
                    normalized = member.name[:-1] if directory and member.name.endswith("/") else member.name
                    if (normalized, directory, member.size, member.offset_data) != expected:
                        raise _ScanReject("wrapper_archive_invalid", "iterator_mismatch")
                    index += 1
                if index != len(raw_members):
                    raise _ScanReject("wrapper_archive_invalid", "iterator_mismatch")
            finally:
                archive.close()
        except _ScanReject:
            raise
        except Exception:
            raise _ScanReject("wrapper_archive_invalid", "iterator_mismatch")
    return {
        "schema_version": 1,
        "package_sign_present": bool(markers["package.sign"]),
        "package_cert_present": bool(markers["package.cert"]),
        "member_count": len(raw_members),
    }


def _scanner_main(argv):
    try:
        if len(argv) != 8 or argv[0] != "--scan-wrapper-fd":
            return 9
        descriptor = int(argv[1])
        member_limit = int(argv[2])
        name_limit = int(argv[3])
        marker_limit = int(argv[4])
        cpu_limit = int(argv[5])
        address_limit = int(argv[6])
        trailer_min = int(argv[7])
        resource.setrlimit(resource.RLIMIT_AS, (address_limit, address_limit))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        result = _scan_archive(descriptor, member_limit, name_limit, marker_limit, trailer_min)
        status = 0
    except _ScanReject as exc:
        result = {"schema_version": 1, "category": exc.category, "reason": exc.reason}
        status = 2 if exc.category == "wrapper_archive_invalid" else 3
    except BaseException:
        return 9
    body = json.dumps(result, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    os.write(1, body)
    return status


class _TranscriptReplaced(Exception):
    """The owning attempt atomically replaced its transcript during a read."""


_TRANSCRIPT_READ_ATTEMPTS = 6


def _load_transcript_prefix(state_dir, transcript_ref, expected_controller_id):
    """Strictly validate and index one journal-referenced transcript prefix.

    The return value is intentionally only evidence structure.  Journal state
    transition and continuation policy remains with the deployment record
    store.

    The writer appends by writing a temporary file and renaming it over the
    transcript, so every append is a new inode. Another attempt validating
    the store can open the old inode a moment before that rename and then
    see it unlinked (link count 0), or see the name point at a different
    inode after the read. That is the owner writing, not tampering; the
    read is retried a bounded number of times and the next attempt sees the
    whole new file. Type, owner and mode refusals are never retried.
    """
    last = None
    for _ in range(_TRANSCRIPT_READ_ATTEMPTS):
        try:
            return _load_transcript_prefix_once(
                state_dir, transcript_ref, expected_controller_id)
        except _TranscriptReplaced as exc:
            last = exc
            time.sleep(0.02)
    raise IoxTransportError("journal_unreadable", str(last))


def _load_transcript_prefix_once(state_dir, transcript_ref,
                                 expected_controller_id):
    reference_keys = {
        "id", "attempt_id", "stored_bytes", "observed_bytes",
        "dropped_bytes", "truncated",
    }
    if (not _exact_keys(transcript_ref, reference_keys) or
            not _valid_hex32(transcript_ref.get("id")) or
            transcript_ref.get("attempt_id") != transcript_ref.get("id") or
            not _is_int(transcript_ref.get("stored_bytes"), 1, 1048576) or
            not _is_int(transcript_ref.get("observed_bytes")) or
            not _is_int(transcript_ref.get("dropped_bytes")) or
            not isinstance(transcript_ref.get("truncated"), bool) or
            not _valid_hex32(expected_controller_id)):
        raise IoxTransportError("journal_unreadable", "invalid transcript reference")
    transcript_id = transcript_ref["id"]
    descriptor = -1
    state_descriptor = -1
    iox_descriptor = -1
    transcripts_descriptor = -1
    try:
        def checked_directory(opened, named, initial, label,
                              required_mode=0o700):
            # Identity, type, owner and mode must hold on every look at the
            # directory, by descriptor and by name: that is what stops the
            # path being swapped underneath this read. Entry churn (size,
            # timestamps, link count) is NOT evidence of tampering. Sibling
            # attempts legitimately create transcripts, session fences and
            # snapshots in these private same-uid directories while this one
            # validates the store, and every other server component writes
            # the state directory. Demanding identical timestamps refused
            # every concurrent IOx onboard as "unsafe directory metadata".
            values = (opened, named, initial)
            if (any(not stat.S_ISDIR(item.st_mode) for item in values) or
                    any(item.st_uid != os.geteuid() for item in values) or
                    (required_mode is not None and
                     any(stat.S_IMODE(item.st_mode) != required_mode
                         for item in values)) or
                    any((item.st_dev, item.st_ino) !=
                        (initial.st_dev, initial.st_ino)
                        for item in values)):
                raise IoxTransportError(
                    "journal_unreadable", "unsafe %s directory metadata" % label)

        directory_flags = (os.O_RDONLY | os.O_CLOEXEC |
                           getattr(os, "O_DIRECTORY", 0) |
                           getattr(os, "O_NOFOLLOW", 0))
        state_descriptor = os.open(state_dir, directory_flags)
        state_metadata = os.fstat(state_descriptor)
        state_named = os.stat(state_dir, follow_symlinks=False)
        checked_directory(
            state_metadata, state_named, state_metadata, "state",
            required_mode=None)
        iox_descriptor = os.open("iox", directory_flags, dir_fd=state_descriptor)
        iox_metadata = os.fstat(iox_descriptor)
        iox_named = os.stat("iox", dir_fd=state_descriptor,
                            follow_symlinks=False)
        checked_directory(iox_metadata, iox_named, iox_metadata, "IOx")
        transcripts_descriptor = os.open(
            "transcripts", directory_flags, dir_fd=iox_descriptor)
        transcripts_metadata = os.fstat(transcripts_descriptor)
        transcripts_named = os.stat(
            "transcripts", dir_fd=iox_descriptor, follow_symlinks=False)
        checked_directory(
            transcripts_metadata, transcripts_named, transcripts_metadata,
            "transcript")
        descriptor = os.open(
            transcript_id + ".transcript",
            os.O_RDONLY | os.O_CLOEXEC |
            getattr(os, "O_NOFOLLOW", 0) |
            getattr(os, "O_NONBLOCK", 0),
            dir_fd=transcripts_descriptor)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size > 1048576):
            raise IoxTransportError("journal_unreadable", "transcript metadata changed")
        if (opened.st_nlink != 1
                or opened.st_size < transcript_ref["stored_bytes"]):
            raise _TranscriptReplaced("transcript metadata changed")
        remaining = transcript_ref["stored_bytes"]
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise _TranscriptReplaced("incomplete transcript prefix")
            chunks.append(chunk)
            remaining -= len(chunk)
        current = os.stat(
            transcript_id + ".transcript", dir_fd=transcripts_descriptor,
            follow_symlinks=False)
        after = os.fstat(descriptor)
        if (stat.S_ISLNK(current.st_mode) or
                not stat.S_ISREG(current.st_mode) or
                not stat.S_ISREG(after.st_mode) or
                current.st_uid != os.geteuid() or
                after.st_uid != os.geteuid() or
                stat.S_IMODE(current.st_mode) != 0o600 or
                stat.S_IMODE(after.st_mode) != 0o600):
            raise IoxTransportError(
                "journal_unreadable", "transcript pathname changed during read")
        if (current.st_nlink != 1 or after.st_nlink != 1 or
                (current.st_dev, current.st_ino) !=
                (opened.st_dev, opened.st_ino) or
                (after.st_dev, after.st_ino) !=
                (opened.st_dev, opened.st_ino) or
                # The journal references a durable prefix; the owning attempt
                # keeps appending behind it while other attempts validate the
                # store, so growth is legitimate and only a shrunk or swapped
                # file is evidence against the bytes just read.
                after.st_size < transcript_ref["stored_bytes"] or
                current.st_size < transcript_ref["stored_bytes"]):
            raise _TranscriptReplaced("transcript pathname changed during read")
        after_state = os.fstat(state_descriptor)
        after_iox = os.fstat(iox_descriptor)
        after_transcripts = os.fstat(transcripts_descriptor)
        current_state = os.stat(state_dir, follow_symlinks=False)
        current_iox = os.stat(
            "iox", dir_fd=state_descriptor, follow_symlinks=False)
        current_transcripts = os.stat(
            "transcripts", dir_fd=iox_descriptor, follow_symlinks=False)
        checked_directory(
            after_state, current_state, state_metadata, "state",
            required_mode=None)
        checked_directory(after_iox, current_iox, iox_metadata, "IOx")
        checked_directory(
            after_transcripts, current_transcripts, transcripts_metadata,
            "transcript")
        content = b"".join(chunks)
    except IoxTransportError:
        raise
    except (OSError, IOError) as exc:
        raise IoxTransportError("journal_unreadable", exc)
    finally:
        for opened_descriptor in (
                descriptor, transcripts_descriptor, iox_descriptor,
                state_descriptor):
            if opened_descriptor >= 0:
                os.close(opened_descriptor)

    records = []
    cursor = 0
    while cursor < len(content):
        if len(content) - cursor < 4:
            raise IoxTransportError("journal_unreadable", "partial transcript frame")
        length = struct.unpack("!I", content[cursor:cursor + 4])[0]
        if not 1 <= length <= _FRAME_MAX_BYTES or cursor + 4 + length > len(content):
            raise IoxTransportError("journal_unreadable", "partial transcript frame")
        payload = content[cursor + 4:cursor + 4 + length]
        try:
            record = _json_loads_strict(payload)
            canonical = json.dumps(
                record, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")
        except Exception as exc:
            raise IoxTransportError("journal_unreadable", exc)
        if payload != canonical:
            raise IoxTransportError("journal_unreadable", "noncanonical transcript frame")
        records.append(record)
        cursor += 4 + length
    if cursor != transcript_ref["stored_bytes"] or not records:
        raise IoxTransportError("journal_unreadable", "incomplete transcript prefix")
    header_keys = {"schema_version", "type", "id", "attempt_id", "controller_id", "created_at"}
    header = records[0]
    if (not _exact_keys(header, header_keys) or
            not _is_int(header.get("schema_version"), 1, 1) or
            header.get("type") != "header" or header.get("id") != transcript_id or
            header.get("attempt_id") != transcript_id or
            header.get("controller_id") != expected_controller_id or
            not _is_int(header.get("created_at"))):
        raise IoxTransportError("authority_mismatch", "transcript header/domain mismatch")

    validator = object.__new__(_TranscriptWriter)
    validator._commands = {}
    validator._closed = set()
    validator._observed = 0
    validator._dropped = 0
    validator._truncated = False
    commands = {}
    active = {}
    acknowledgements = []
    try:
        for order, record in enumerate(records[1:], 1):
            state = validator._validated(record)
            kind = record["type"]
            if kind == "command_start":
                command_id = record["command_id"]
                active[command_id] = {
                    "start": copy.deepcopy(record), "end": None,
                    "stdout": bytearray(), "stderr": bytearray(),
                    "start_order": order, "end_order": None,
                }
            elif kind == "stream":
                raw = base64.b64decode(record["data_b64"].encode("ascii"), validate=True)
                active[record["command_id"]][record["stream"]].extend(raw)
            elif kind == "command_end":
                command_id = record["command_id"]
                entry = active.pop(command_id)
                entry["end"] = copy.deepcopy(record)
                entry["stdout"] = bytes(entry["stdout"])
                entry["stderr"] = bytes(entry["stderr"])
                entry["end_order"] = order
                if entry["start"]["purpose"].startswith("verification_"):
                    spans = record["payload_spans"]
                    if ((record["framing_complete"] and len(spans) != 1) or
                            (not record["framing_complete"] and spans)):
                        raise IoxTransportError(
                            "journal_unreadable",
                            "verification framing contradicts payload spans")
                # The command's observed_state / transition_response were
                # classified at WRITE time and are the authority every reader
                # uses (the journal<->transcript cross-check in
                # deployment_records._validate_journal_relations, the
                # disable/enable confirmations, the caf_transient retry). This
                # parser must NOT re-derive them from the retained bytes with
                # the CURRENT classifier and demand equality: that is a
                # "the classifier never changed" build invariant, not a
                # per-record integrity check -- the real per-record protection
                # is the private 0600 transcript, the structural base64/span/
                # framing checks above, and the stored-value cross-checks. The
                # equality could not even distinguish an improved classifier
                # from tampering (the raw bytes are not signed), and it
                # bricked the server on restart after any classifier change:
                # an interrupted record's transcript recomputed differently
                # and RecordStoreUnreadable / a failed fence scan aborted
                # startup for the whole store (issue #227). Trust the stored
                # classification; keep the structural checks strict.
                commands[command_id] = entry
            elif kind == "journal_ack":
                acknowledgements.append({"record": copy.deepcopy(record), "order": order})
            (validator._commands, validator._closed, validator._observed,
             validator._dropped, validator._truncated) = state
    except IoxTransportError as exc:
        raise IoxTransportError("journal_unreadable", exc.detail)
    if active or validator._commands:
        raise IoxTransportError("journal_unreadable", "referenced command is incomplete")
    if (validator._observed != transcript_ref["observed_bytes"] or
            validator._dropped != transcript_ref["dropped_bytes"] or
            validator._truncated != transcript_ref["truncated"]):
        raise IoxTransportError("journal_unreadable", "transcript counters do not match reference")
    return {
        "id": transcript_id,
        "attempt_id": transcript_id,
        "controller_id": expected_controller_id,
        "stored_bytes": transcript_ref["stored_bytes"],
        "observed_bytes": validator._observed,
        "dropped_bytes": validator._dropped,
        "truncated": validator._truncated,
        "records": tuple(copy.deepcopy(records)),
        "commands": commands,
        "journal_acks": tuple(acknowledgements),
    }


class _Result(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class _NormalizedCapture(object):
    def __init__(self, secrets, limit):
        self.redactor = _StreamingRedactor(secrets)
        self.limit = limit
        self.data = bytearray()
        self.observed = 0
        self.dropped = 0
        self.invalid_control = False
        self.invalid_utf8 = False
        self._pending_cr = False

    def _normalized(self, data, final=False):
        output = bytearray()
        for byte in bytearray(data):
            if self._pending_cr:
                if byte == 10:
                    output.append(10)
                    self._pending_cr = False
                    continue
                output.append(13)
                self.invalid_control = True
                self._pending_cr = False
            if byte == 13:
                self._pending_cr = True
            else:
                output.append(byte)
        if final and self._pending_cr:
            output.append(13)
            self.invalid_control = True
            self._pending_cr = False
        return bytes(output)

    def _store(self, data):
        if not data:
            return
        if any((byte < 32 and byte not in (9, 10)) or byte == 127
               for byte in bytearray(data)):
            self.invalid_control = True
        self.observed = min(_MAX_INTEGER, self.observed + len(data))
        room = max(0, self.limit - len(self.data))
        kept = min(room, len(data))
        self.data.extend(data[:kept])
        omitted = len(data) - kept
        if omitted:
            self.dropped = min(_MAX_INTEGER, self.dropped + omitted)

    def feed(self, raw):
        self._store(self._normalized(self.redactor.feed(raw)))

    def finish(self):
        self._store(self._normalized(self.redactor.finish(), final=True))
        try:
            bytes(self.data).decode("utf-8")
        except UnicodeDecodeError:
            self.invalid_utf8 = True

    @property
    def truncated(self):
        return self.dropped != 0


def _lines(payload):
    if not payload:
        return []
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    return payload.split(b"\n") if payload else []


def _only_ios_warnings(payload):
    """True when a config-mode payload is nothing but IOS advisory banners.

    A configuration command is normally silent, and output from one is a
    strong signal that something is wrong -- which is why the caller treats
    it as a protocol violation. IOS breaks that rule for advisories: an
    IE-3400 answers `iox` with

        Warning: Do not remove SD flash card when IOx is enabled or errors
        on SD device could occur.

    which is purely informational and made every IOx install on that
    platform fail at prepare_iox_scp with "configuration command returned
    payload". IOS's own convention separates the two cases -- errors are
    prefixed '%' and are already caught by _classify_ios_error, advisories
    are prefixed 'Warning:' -- so accept a payload whose every non-empty
    line is an advisory, and nothing else. The banner is still recorded in
    the transcript either way; this only stops it being read as a failure.
    """
    lines = [line for line in payload.split(b"\n") if line.strip()]
    return bool(lines) and all(
        line.lstrip().startswith(b"Warning:") for line in lines)


# The lifecycle steps that CLEAR prior application state. Both recipes run
# them before doing anything else -- the installer to make a re-install
# idempotent, the teardown to remove what is there -- so for all three the
# desired end state is "this app is not running". IOS answers a request to
# stop/deactivate/uninstall an app it does not have with an explicit
# %Error, which _classify_ios_error rightly reads as a rejection in every
# other context. Here it means the step's goal is ALREADY met.
_APP_CLEARING_PURPOSES = frozenset((
    "app_stop", "app_deactivate", "app_uninstall"))
# IOS spells the same condition two ways, and which one you get depends on
# the verb: stop/deactivate answer "The application: <id>, does not exist"
# while uninstall answers "No App found with name '<id>'". Both mean the app
# is not there. Anchored and specific -- neither matches an app that exists
# but refuses the operation.
_APP_ABSENT_RE = re.compile(
    br"(?im)^%\s*Error:\s*(?:The application:\s*\S+,\s*does not exist"
    br"|No App found with name\s*'[^']*')\s*$")


def _app_already_absent(purpose, payload):
    """True when a state-clearing step failed only because there was nothing
    to clear.

    Without this a first install on a CLEAN device died at step one: the
    installer stops any previous app, IOS said the application does not
    exist, and the whole install was rejected -- so onboarding only ever
    worked on a device that already had the app. The teardown had the mirror
    problem: a device already in the desired state could not be reconciled
    (issue #225). Matched narrowly, on these three purposes only: an app that
    EXISTS but refuses to stop still reports its own error and still fails.
    """
    return (purpose in _APP_CLEARING_PURPOSES and
            _APP_ABSENT_RE.search(payload) is not None)


# What IOS prints while saving, ahead of its verdict. The IE-3400 emits
# "Building configuration..." before "[OK]"; other platforms answer with the
# verdict alone.
_SAVE_PROGRESS_RE = re.compile(br"^Building configuration\.*$", re.I)


def _save_confirmed(payload):
    """True when `write memory` reported success.

    The check used to demand the payload be exactly b"[OK]\n". That is one
    platform's output, not IOS's contract: an IE-3400 answers

        Building configuration...
        [OK]

    so a save that had ALREADY SUCCEEDED was read as an unsupported
    response, and the install failed at its very last step with the
    application installed, activated and running on the device. Require the
    verdict, allow the progress line before it, and accept nothing else --
    an empty payload, a missing [OK] or any unrecognized line still fails.
    """
    lines = [line for line in payload.split(b"\n") if line.strip()]
    if not lines or lines[-1].strip() != b"[OK]":
        return False
    return all(_SAVE_PROGRESS_RE.match(line.strip())
               for line in lines[:-1])


# Config-mode teardown steps and the IOS advisories that mean their target is
# ALREADY GONE. cleanup_config removes every IRIS-named artifact
# unconditionally -- that is what makes teardown idempotent -- so on real
# hardware it routinely removes things the deployment never created (a routed
# IOx device has no EEM applets or trustpoint; those belong to the Guest Shell
# recipe) and IOS answers each `no` with an informational notice. These are
# not command failures, but the strict classifier read every %-prefixed line
# as one, so a recorded undeploy failed with the app already removed and the
# config half not reconciled.
_CONFIG_CLEANUP_PURPOSES = frozenset(("cleanup_config", "remove_app_config"))
_CLEANUP_ABSENT_RE = re.compile(
    br"(?im)^%\s*(?:"
    br"EEM:\s*No such applet\b"          # no event manager applet <name>
    br"|There is no\b.*\bto delete\b"    # no crypto/http trustpoint <name>
    br"|Can't find\b"                     # no ... policy <name>
    br"|.*\bnot (?:found|present|configured|exist(?:s)?)\b"
    br")")


def _cleanup_absent(purpose, payload):
    """True when a config cleanup step's ONLY output is already-absent
    advisories.

    Narrow on purpose (config cleanup steps) and on message shape (IOS's
    own 'nothing to remove' notices). A cleanup line that returns anything
    else -- a real syntax error, unexpected output -- still fails, so the
    teardown never waves through residue it could not remove.
    """
    if purpose not in _CONFIG_CLEANUP_PURPOSES:
        return False
    lines = [line for line in payload.split(b"\n") if line.strip()]
    return bool(lines) and all(
        _CLEANUP_ABSENT_RE.match(line.strip()) for line in lines)


# Removing an SVI or L2 VLAN that is already gone is benign during teardown,
# but IOS does not say so kindly: an IE-3400 answers `no interface Vlan666`
# for an absent Vlan666 with "% Invalid input detected", the SAME signal a
# real syntax error gives. It cannot be tolerated by message shape without
# masking genuine errors -- but it CAN be tolerated by COMMAND: these removal
# lines are IRIS-generated and fixed, never operator input, so an invalid-
# input response to one means the target VLAN is already absent. Scoped to
# the two cleanup removal forms and to config cleanup purposes.
_VLAN_REMOVAL_RE = re.compile(br"^no (?:interface Vlan\d+|vlan \d+)\s*$")


def _vlan_already_absent(purpose, line, payload):
    if purpose not in _CONFIG_CLEANUP_PURPOSES:
        return False
    if _VLAN_REMOVAL_RE.match(line.strip()) is None:
        return False
    return b"% Invalid input" in payload


# Deleting a staged file that is already gone is benign during teardown.
# cleanup_files removes the wrapper, certificates and share unconditionally,
# so on a retry (or after a partial teardown) the files are absent and IOS
# answers "%Error deleting <path> (No such file or directory)". remove_wrapper
# and remove_certificate have their own absent-file proof (a closing dir
# probe); cleanup_files does not, so its absent deletes were read as
# rejections and the teardown failed with nothing left to remove.
_FILE_CLEANUP_PURPOSES = frozenset(("cleanup_files",))
_DELETE_ABSENT_RE = re.compile(
    br"(?im)^%\s*Error deleting\b.*\(No such file or directory\)\s*$")


def _delete_absent(purpose, payload):
    if purpose not in _FILE_CLEANUP_PURPOSES:
        return False
    lines = [line for line in payload.split(b"\n") if line.strip()]
    return bool(lines) and all(
        _DELETE_ABSENT_RE.match(line.strip()) for line in lines)


# The stage probe's whole job is to PROVE the staging directory is gone, and
# IOS proves it with "%Error opening <path> (No such file or directory)" on a
# `dir` of the absent path. That is the success condition -- but the strict
# classifier read the %Error as a rejection, so a teardown that had removed
# everything failed at its final verification step. Scoped to the probe's
# `dir` lines and to that exact message; the recipe's own residue check
# already reads it as clean.
_PROBE_PURPOSES = frozenset(("cleanup_stage_probe",))
_DIR_ABSENT_RE = re.compile(
    br"(?im)^%\s*Error opening\b.*\(No such file or directory\)\s*$")


def _dir_absent(purpose, line, payload):
    if purpose not in _PROBE_PURPOSES or not line.strip().startswith(b"dir "):
        return False
    lines = [l for l in payload.split(b"\n") if l.strip()]
    return bool(lines) and all(_DIR_ABSENT_RE.match(l.strip()) for l in lines)


def _classify_ios_error(payload):
    for line in _lines(payload):
        lower = line.lower()
        if (lower.startswith(b"% invalid input") or
                lower.startswith(b"% incomplete command") or
                lower.startswith(b"% ambiguous command")):
            return "unsupported_syntax"
        if (lower.startswith(b"%error") or lower.startswith(b"% error") or
                lower.startswith(b"% authorization failed") or
                lower.startswith(b"% access denied")):
            return "rejected"
        if lower.startswith(b"%") and not (
                lower.startswith(b"%iox") or lower.startswith(b"%app")):
            return "unsupported_response"
    return None


def _classify_read(payload):
    # IOS may surround its one authoritative field with empty display lines.
    # Keep whitespace-bearing and other non-empty lines so they still fail the
    # closed grammar; discard only byte-empty lines.
    lines = [line for line in _lines(payload) if line != b""]
    matches = []
    expression = re.compile(br"^App signature verification: (enabled|disabled)$", re.I)
    for line in lines:
        match = expression.fullmatch(line)
        if match is not None:
            matches.append(match.group(1).lower().decode("ascii"))
    if len(lines) == 1 and len(matches) == 1:
        return matches[0], None
    if not lines:
        return "unknown", "silence"
    return "unknown", "readback_unknown"


def _classify_transition(purpose, payload):
    lines = [line for line in _lines(payload) if line != b""]
    if len(lines) != 1:
        return "other", "silence" if not lines else "unsupported_response"
    value = lines[0].lower()
    # IE-3x00/C9300 say "app hosting verification ..."; a Catalyst 8000V says
    # "app signature verification ...". Same success, different platform
    # wording -- the exact IE/C9K literal made every C8000V install fail here
    # right after the disable that had already succeeded.
    if (purpose == "verification_disable" and value in (
            b"app hosting verification disabled successfully",
            b"app signature verification disabled successfully")):
        return "disabled_successfully", None
    if (purpose == "verification_enable" and value in (
            b"app hosting verification enabled successfully",
            b"app signature verification enabled successfully")):
        return "enabled_successfully", None
    if (purpose == "verification_disable" and value ==
            b"the process for the command is not responding or is otherwise unavailable"):
        return "caf_transient", "caf_transient"
    return "other", "unsupported_response"


_SSH_SHIM = r'''
policy=$1
peer=$2
user=$3
port=$4
binary=$5
sshpass_binary=$6
mode=$7
source "$policy" || exit 125
iris_ssh_policy "$peer" || { rc=$?; iris_ssh_cleanup; exit "$rc"; }
if [ "$mode" = ssh ]; then
  "$sshpass_binary" -e "$binary" -tt -p "$port" -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" "$user@$peer"
else
  source_fd=$8
  destination=$9
  # -O forces the legacy SCP protocol. OpenSSH 9 defaults to SFTP, which
  # IOS-XE's scp server does not implement -- every wrapper upload failed
  # with "scp: Connection closed" (rc 255) before the file left the server.
  # Proven on an IE-3400: identical command, same credentials, fails without
  # -O and succeeds with it.
  "$sshpass_binary" -e "$binary" -O -P "$port" -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" "/proc/self/fd/$source_fd" "$user@$peer:$destination"
fi
rc=$?
iris_ssh_cleanup
exit "$rc"
'''


class _Dialogue(object):
    def __init__(self, transport, child, stdout, stderr, deadline):
        self.transport = transport
        self.child = child
        self.stdout = stdout
        self.stderr = stderr
        self.deadline = deadline
        self.cursor = 0
        self.host = None
        self.level = None
        self.selector = selectors.DefaultSelector()
        for name, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)
        self.eof = {"stdout": False, "stderr": False}

    def close(self):
        self.selector.close()
        for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
            try:
                stream.close()
            except Exception:
                pass

    def _pump(self):
        self.transport._check_active(self.deadline)
        remaining = max(0.0, self.deadline - self.transport._clock())
        events = self.selector.select(min(0.02, remaining))
        for key, unused_mask in events:
            try:
                data = os.read(key.fd, 4096)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(key.fileobj)
                self.eof[key.data] = True
                continue
            (self.stdout if key.data == "stdout" else self.stderr).feed(data)

    def _data(self):
        return bytes(self.stdout.data)

    def wait_until(self, predicate):
        while True:
            value = predicate(self._data())
            if value is not None:
                return value
            if self.eof["stdout"]:
                raise IoxTransportError("unsupported_response", "unexpected SSH EOF")
            self._pump()

    def initial_prompt(self):
        def locate(data):
            suffix_start = data.rfind(b"\n") + 1
            candidate = data[suffix_start:]
            match = _PROMPT_RE.fullmatch(candidate)
            if match is None:
                return None
            for line in data[:suffix_start].splitlines():
                try:
                    line.decode("utf-8")
                except UnicodeDecodeError:
                    raise IoxTransportError("unsupported_response", "invalid login banner")
                if any((byte < 32 and byte != 9) or byte == 127 for byte in bytearray(line)):
                    raise IoxTransportError("unsupported_response", "invalid login banner")
            return suffix_start, match
        start, match = self.wait_until(locate)
        self.host = match.group("host")
        self.level = match.group("level")
        self.cursor = len(self._data())

    def send(self, value):
        self.transport._check_active(self.deadline)
        self.child.stdin.write(value)
        self.child.stdin.flush()

    def _echo_end(self, data, expected_echo):
        tail = data[self.cursor:]
        if tail.startswith(b"\n"):
            tail = tail[1:]
            base = self.cursor + 1
        else:
            base = self.cursor
        expected = expected_echo + b"\n"
        if len(tail) < len(expected):
            return None
        if not tail.startswith(expected):
            # Wait until a complete prompt/output arrives before classifying a
            # partial write as a mismatched echo.
            if b"\n" not in tail and not self.eof["stdout"]:
                return None
            raise IoxTransportError("unsupported_response", "command echo mismatch")
        return base + len(expected)

    @staticmethod
    def _suffix_prompt(data, start):
        line_start = data.rfind(b"\n") + 1
        if line_start < start:
            line_start = start
        candidate = data[line_start:]
        match = _PROMPT_RE.fullmatch(candidate)
        if match is not None:
            return line_start, match, "exec"
        match = _CONFIG_PROMPT_RE.fullmatch(candidate)
        if match is not None:
            if len(match.group("body")) > 96:
                raise IoxTransportError(
                    "unsupported_response", "configuration prompt is overlong")
            return line_start, match, "config"
        return None

    def command_step(self, command, expected, question=None, answer=None):
        self.send(command + b"\n")
        expected_echo = self.transport._redact_literal(command)
        echo_end = self.wait_until(
            lambda data: self._echo_end(data, expected_echo))
        payload_start = echo_end
        # Whether the device actually ASKED the confirmation. It is
        # conditional: `file prompt quiet` suppresses it, and IRIS sets that
        # itself during prepare_iox_scp, so a teardown's `no app-hosting
        # appid` executes silently and returns straight to the config prompt.
        # Waiting unconditionally hung the teardown until its deadline; then
        # stripping an answer echo that was never sent turned the silent
        # success into "interactive answer echo mismatch". Both are gated on
        # this flag now.
        question_asked = False
        if question is not None:
            asked = []
            def question_seen(data):
                tail = data[echo_end:]
                if tail == question:
                    asked.append(True)
                    return len(data)
                if self._suffix_prompt(data, echo_end) is not None:
                    return len(data)
                if len(tail) >= len(question) and not question.startswith(tail):
                    raise IoxTransportError("unsupported_response", "interactive question mismatch")
                return None
            question_end = self.wait_until(question_seen)
            if asked:
                question_asked = True
                self.send(answer + b"\n")
                payload_start = question_end

        def final(data):
            found = self._suffix_prompt(data, payload_start)
            if found is None:
                bound = self.host + (b"#" if expected == "exec" else b">")
                if data.endswith(bound) and data[payload_start:] != bound:
                    raise IoxTransportError("unsupported_response", "prompt lacked a line boundary")
                return None
            position, match, prompt_kind = found
            if match.group("host") != self.host:
                raise IoxTransportError("unsupported_response", "SSH hostname prompt changed")
            if expected == "exec" and not (prompt_kind == "exec" and match.groupdict().get("level") == b"#"):
                raise IoxTransportError("unsupported_response", "unexpected final prompt")
            if expected == "user" and not (prompt_kind == "exec" and match.groupdict().get("level") == b">"):
                raise IoxTransportError("unsupported_response", "unexpected final prompt")
            if expected == "config" and prompt_kind != "config":
                raise IoxTransportError("unsupported_response", "unexpected final prompt")
            if expected == "config_entry" and not (
                    prompt_kind == "config" and match.group("body") == b"config"):
                raise IoxTransportError(
                    "unsupported_response", "unexpected configuration entry prompt")
            return position, len(data), prompt_kind
        prompt_start, prompt_end, prompt_kind = self.wait_until(final)
        payload = self._data()[payload_start:prompt_start]
        if question_asked:
            if answer:
                if not payload.startswith(answer + b"\n"):
                    raise IoxTransportError("unsupported_response", "interactive answer echo mismatch")
                payload = payload[len(answer) + 1:]
            elif payload.startswith(b"\n"):
                payload = payload[1:]
        span_start = prompt_start - len(payload)
        self.cursor = prompt_end
        return payload, (span_start, len(payload)), prompt_kind

    def privilege(self, secret):
        command = b"enable"
        self.send(command + b"\n")
        expected_echo = self.transport._redact_literal(command)
        echo_end = self.wait_until(
            lambda data: self._echo_end(data, expected_echo))

        def outcome(data):
            tail = data[echo_end:]
            if re.fullmatch(br"Password: ?", tail, re.I):
                return "password", len(data)
            found = self._suffix_prompt(data, echo_end)
            if found is not None:
                position, match, prompt_kind = found
                if (position != echo_end or prompt_kind != "exec" or
                        match.group("host") != self.host or match.group("level") != b"#"):
                    raise IoxTransportError("unsupported_response", "unexpected enable outcome")
                return "prompt", len(data)
            return None

        mode, position = self.wait_until(outcome)
        if mode == "password":
            self.send(secret + b"\n")
            password_end = position

            def password_outcome(data):
                found = self._suffix_prompt(data, password_end)
                if found is None:
                    return None
                prompt_start, match, prompt_kind = found
                if (prompt_kind != "exec" or match.group("host") != self.host or
                        match.group("level") != b"#" or
                        data[password_end:prompt_start] != b"\n"):
                    raise IoxTransportError("unsupported_response", "unexpected password outcome")
                return len(data)
            position = self.wait_until(password_outcome)
        self.cursor = position
        self.level = b"#"

    def finish_process(self):
        self.send(b"exit\n")
        while not self.eof["stdout"] or not self.eof["stderr"]:
            self._pump()
        self.stdout.finish()
        self.stderr.finish()
        data = self._data()
        tail = data[self.cursor:]
        if tail.startswith(b"\n"):
            tail = tail[1:]
        if tail != b"exit\n":
            raise IoxTransportError("unsupported_response", "incomplete SSH exit framing")


class IoxTransport(object):
    def __init__(self, config, transcript, supervisor, monotonic_fn=None):
        self.config = dict(config)
        self.transcript = transcript
        self.monotonic_fn = monotonic_fn or time.monotonic
        self.supervisor = supervisor
        self._supervised_process_type = None
        if supervisor is not None:
            # Import lazily: verification deliberately imports this module only
            # when it constructs an attempt.  Exact types prevent a duck object
            # from claiming custody and thereby suppressing local reaping.
            try:
                import iox_verification
                client_type = iox_verification._SupervisorClient
                process_type = iox_verification._SupervisedProcess
            except (ImportError, AttributeError) as exc:
                raise IoxTransportError(
                    "rejected", "supervisor contract is unavailable") from exc
            if type(supervisor) is not client_type:
                raise IoxTransportError(
                    "rejected", "exact IOx supervisor client required")
            self._supervised_process_type = process_type
        self.cancel = self.config.get("cancel")
        self.session_deadline = self.config.get("session_deadline")
        port = self.config.get("port", 22)
        if not _is_int(port, 1, 65535):
            raise IoxTransportError("rejected", "invalid SSH port")
        self.port = port
        self.tmp_dir = self.config["tmp_dir"]
        _secure_directory(self.tmp_dir)
        self._lock = threading.RLock()
        self._reap_lock = threading.Lock()
        self._active = set()
        self._cancel_requested = False
        self._baseline_children = set(self._child_pids())
        credentials = self.config.get("credentials", {})
        self._secret_values = []
        for name in ("DEVICE_PASS", "DEVICE_ENABLE", "DEVICE_SSH_PASS", "CATALOG_TOKEN", "SSHPASS"):
            value = credentials.get(name)
            if value:
                encoded = value.encode("utf-8") if isinstance(value, str) else bytes(value)
                if len(encoded) > 4096:
                    raise IoxTransportError("rejected", "configured secret exceeds 4096 bytes")
                self._secret_values.append(encoded)
        enable = credentials.get("DEVICE_ENABLE", "")
        if isinstance(enable, bytes):
            self.enable_secret = enable
        else:
            self.enable_secret = enable.encode("utf-8")
        if (len(self.enable_secret) > 4096 or b"\0" in self.enable_secret or
                b"\r" in self.enable_secret or b"\n" in self.enable_secret):
            raise IoxTransportError("unsupported_syntax", "invalid enable secret")

    def _clock(self):
        return self.monotonic_fn()

    def _redact_literal(self, value):
        redactor = _StreamingRedactor(self._secret_values)
        return redactor.feed(value) + redactor.finish()

    @staticmethod
    def _child_pids():
        try:
            with open("/proc/self/task/%d/children" % os.getpid()) as stream:
                return [int(value) for value in stream.read().split()]
        except (OSError, ValueError):
            return []

    def _reap_descendants(self, deadline):
        # A production supervisor owns the wider attempt process tree (which
        # includes the concurrently running recipe).  Only an isolated
        # transport may treat every newly adopted child as its own.  The
        # transport process group is still terminated in both modes.
        if self.supervisor is not None:
            return True
        # When the isolated caller is a subreaper, a killed intermediate can
        # make another descendant visible only after the intermediate has been
        # waited.  Rescan after every wait instead of taking a one-time
        # snapshot of the direct children.
        targets = set()
        term_at = {}
        killed = set()
        empty_rounds = 0
        reap_end = min(deadline, self._clock() + 5.0)
        while self._clock() < reap_end:
            current = set(self._child_pids()) - self._baseline_children
            for pid in current - targets:
                targets.add(pid)
                term_at[pid] = self._clock()
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass

            for pid in list(targets):
                try:
                    waited, unused_status = os.waitpid(pid, os.WNOHANG)
                    if waited == pid:
                        targets.discard(pid)
                        term_at.pop(pid, None)
                        killed.discard(pid)
                except ChildProcessError:
                    if not os.path.exists("/proc/%d" % pid):
                        targets.discard(pid)
                        term_at.pop(pid, None)
                        killed.discard(pid)

            # A short grace is sufficient here: the process group has already
            # received the transport's graceful TERM and observed its full
            # grace ceiling.  This TERM also covers descendants adopted during
            # the wait above.
            now = self._clock()
            for pid in list(targets):
                if pid not in killed and now - term_at.get(pid, now) >= 0.02:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                    killed.add(pid)

            remaining = set(self._child_pids()) - self._baseline_children
            if not targets and not remaining:
                empty_rounds += 1
                if empty_rounds >= 2:
                    return True
            else:
                empty_rounds = 0
            time.sleep(min(0.002, max(0.0, reap_end - self._clock())))
        return not (set(self._child_pids()) - self._baseline_children)

    def _deadline(self, phase_deadline):
        values = [value for value in (phase_deadline, self.session_deadline) if value is not None]
        return min(values) if values else self._clock()

    def _operation_deadline(self, deadline):
        """Reserve shutdown time inside, never beyond, the caller deadline."""
        return max(
            self._clock(), deadline - _PROCESS_CLEANUP_RESERVE_SECONDS)

    def _check_active(self, deadline):
        if self._cancel_requested or _cancelled(self.cancel):
            raise IoxTransportError("cancelled")
        if self._clock() >= deadline:
            raise IoxTransportError("timeout")

    def _environment(self):
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": self.config.get("home", "/nonexistent"),
            "TMPDIR": self.config["tmp_dir"],
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        }
        for key, value in self.config.get("ssh_policy_env", {}).items():
            if key in ("IRIS_SSH_HOST_KEY", "IRIS_SSH_KNOWN_HOSTS",
                       "IRIS_SSH_STATE_DIR", "IRIS_SSH_LEGACY", "IRIS_STATE"):
                environment[key] = str(value)
        password = self.config.get("credentials", {}).get("SSHPASS")
        if password is not None:
            environment["SSHPASS"] = password.decode("utf-8") if isinstance(password, bytes) else str(password)
        return environment

    def _context(self, command_id, expected_kind):
        context = self.config.get("command_contexts", {}).get(command_id)
        if not isinstance(context, dict) or context.get("command_id") != command_id or context.get("kind") != expected_kind:
            raise IoxTransportError("rejected", "missing controller command context")
        return copy.deepcopy(context)

    def _spawn(self, mode, deadline, pass_fds=(), extra=()):
        self._check_active(deadline)
        args = [
            "/bin/bash", "--noprofile", "--norc", "-c", _SSH_SHIM,
            "iris-iox-transport", self.config["ssh_policy_path"],
            self.config["host"], self.config["user"], str(self.port),
            self.config["ssh_binary"] if mode == "ssh" else self.config["scp_binary"],
            self.config["sshpass_binary"], mode,
        ] + list(extra)
        options = {
            "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE, "env": self._environment(),
            "pass_fds": tuple(pass_fds), "close_fds": True,
            "start_new_session": True,
        }
        if self.supervisor is None:
            child = subprocess.Popen(args, **options)
        else:
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise IoxTransportError("timeout")
            try:
                child = self.supervisor.popen(
                    args, role="transport", timeout=remaining, **options)
            except (socket.timeout, subprocess.TimeoutExpired):
                raise IoxTransportError("timeout")
        with self._lock:
            self._active.add(child)
        if self.supervisor is not None:
            if (type(child) is not self._supervised_process_type or
                    child._supervisor is not self.supervisor):
                raise IoxTransportError(
                    "descendant_unreaped", "supervisor returned an unowned process")
        return child

    def _record_streams(self, command_id, stdout, stderr, restoration,
                        deadline):
        records = []
        for name, capture in (("stdout", stdout), ("stderr", stderr)):
            data = bytes(capture.data)
            for offset in range(0, len(data), _STREAM_CHUNK_BYTES):
                chunk = data[offset:offset + _STREAM_CHUNK_BYTES]
                records.append({
                    "schema_version": 1, "type": "stream", "command_id": command_id,
                    "stream": name, "offset": offset,
                    "data_b64": base64.b64encode(chunk).decode("ascii"),
                })
        if type(self.transcript) is _TranscriptWriter:
            self._check_active(deadline)
            self.transcript._append_many(records, restoration=restoration)
            self._check_active(deadline)
            return
        for record in records:
            self._check_active(deadline)
            self.transcript.append(record, restoration=restoration)
            self._check_active(deadline)

    def _result(self, child, stdout, stderr, framing, category, deadline):
        reference = self.transcript.reference()
        try:
            self._check_active(deadline)
        except IoxTransportError as exc:
            if category != "descendant_unreaped":
                category = exc.category
            framing = False
        return _Result(
            returncode=child.returncode if child is not None else None,
            timed_out=(category == "timeout"),
            stdout=bytes(stdout.data), stderr=bytes(stderr.data),
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
            framing_complete=bool(framing), error_category=category,
            transcript_ref=reference)

    def _supervisor_reap_process(self, child, deadline):
        if self.supervisor is None:
            return True
        try:
            return self.supervisor.reap_process(child, deadline) is True
        except Exception:
            return False

    def _finish_child(self, child, deadline, force=False):
        with self._reap_lock:
            if force and child.returncode is None:
                _terminate_process(
                    child, deadline, self.monotonic_fn,
                    supervised=self.supervisor is not None)
            else:
                try:
                    child.wait(timeout=max(0.0, deadline - self._clock()))
                except subprocess.TimeoutExpired:
                    _terminate_process(
                        child, deadline, self.monotonic_fn,
                        supervised=self.supervisor is not None)
            if self.supervisor is None:
                stopped = child.returncode is not None
                reaped = stopped and self._reap_descendants(deadline)
            else:
                reaped = self._supervisor_reap_process(child, deadline)
                stopped = child.returncode is not None
            if stopped and reaped:
                with self._lock:
                    self._active.discard(child)
                return True
            return False

    def _stop_child(self, child, deadline):
        with self._reap_lock:
            stopped = _terminate_process(
                child, deadline, self.monotonic_fn,
                supervised=self.supervisor is not None)
            if self.supervisor is None:
                reaped = stopped and self._reap_descendants(deadline)
            else:
                reaped = self._supervisor_reap_process(child, deadline)
                stopped = child.returncode is not None
            if stopped and reaped:
                with self._lock:
                    self._active.discard(child)
                return True
            return False

    def command(self, command_id, command_bytes, phase_deadline):
        deadline = self._deadline(phase_deadline)
        operation_deadline = self._operation_deadline(deadline)
        context = self._context(command_id, "ssh")
        purpose = context["purpose"]
        restoration = purpose == "verification_enable" or context.get("phase") in (
            "ownership_probe", "restore_intent")
        capture_limit = _VERIFY_CAPTURE_BYTES if purpose.startswith("verification_") else _CAPTURE_BYTES
        stdout = _NormalizedCapture(self._secret_values, capture_limit)
        stderr = _NormalizedCapture(self._secret_values, capture_limit)
        child = None
        payload_spans = []
        framed_payloads = []
        observed_state = "unknown" if purpose == "verification_read" else None
        transition = "other" if purpose in ("verification_disable", "verification_enable") else None
        category = None
        framing = False
        semantic_error = None
        try:
            self._check_active(deadline)
            if not isinstance(command_bytes, bytes):
                raise IoxTransportError("unsupported_syntax", "command must be bytes")
            lines = command_bytes.split(b"\n")
            executable = [line for line in lines if line and not line.startswith(b"!")]
            if (not executable or any(not 1 <= len(line) <= 320 or
                    any(byte < 32 or byte > 126 for byte in bytearray(line))
                    for line in executable)):
                raise IoxTransportError("unsupported_syntax", "rendered command is outside the closed grammar")
            self.transcript.append(context, restoration=restoration)
            self._check_active(deadline)
            child = self._spawn("ssh", deadline)
            self._check_active(deadline)
            dialogue = _Dialogue(
                self, child, stdout, stderr, operation_deadline)
            try:
                dialogue.initial_prompt()
                if dialogue.level == b">":
                    dialogue.privilege(self.enable_secret)
                for setup in (b"terminal length 0", b"terminal width 512"):
                    payload, unused_span, unused_kind = dialogue.command_step(setup, "exec")
                    if payload:
                        raise IoxTransportError("unsupported_response", "terminal setup returned payload")
                in_config = False
                for line in executable:
                    question = answer = None
                    expected = "config" if in_config else "exec"
                    if line == b"configure terminal":
                        expected = "config_entry"
                    elif line == b"end":
                        expected = "exec"
                    elif line.startswith(b"app-hosting appid") and in_config:
                        expected = "config"
                    if purpose == "mkdir_share" and line.startswith(b"mkdir "):
                        question = b"Create directory filename [" + line[6:] + b"]?"
                        answer = b""
                    elif purpose == "save" and line == b"write memory":
                        question = b"Destination filename [startup-config]?"
                        answer = b""
                    elif purpose == "cleanup_config" and line.startswith(b"no app-hosting appid"):
                        question = b"Are you sure you want to do this? [yes/no]:"
                        answer = b"yes"
                    payload, span, prompt_kind = dialogue.command_step(
                        line, expected, question=question, answer=answer)
                    framed_payloads.append(payload)
                    payload_spans.append({"offset": span[0], "length": span[1]})
                    payload_error = _classify_ios_error(payload)
                    if (_app_already_absent(purpose, payload) or
                            _cleanup_absent(purpose, payload) or
                            _vlan_already_absent(purpose, line, payload) or
                            _delete_absent(purpose, payload) or
                            _dir_absent(purpose, line, payload)):
                        payload_error = None
                    if payload_error is not None and semantic_error is None:
                        semantic_error = payload_error
                    if line == b"configure terminal":
                        if payload not in (
                                b"",
                                b"Enter configuration commands, one per line.  End with CNTL/Z.\n"):
                            raise IoxTransportError(
                                "unsupported_response", "unexpected configure banner")
                        in_config = True
                    elif line == b"end":
                        if payload:
                            raise IoxTransportError("unsupported_response", "end returned payload")
                        in_config = False
                    elif (in_config and question is None and payload and
                          payload_error is None and
                          not _only_ios_warnings(payload) and
                          not _cleanup_absent(purpose, payload) and
                          not _vlan_already_absent(purpose, line, payload)):
                        raise IoxTransportError("unsupported_response", "configuration command returned payload")
                    if (purpose == "save" and line == b"write memory" and
                            not _save_confirmed(payload) and
                            payload_error is None):
                        raise IoxTransportError("unsupported_response", "save response was not exact")
                dialogue.finish_process()
                if purpose in ("remove_wrapper", "remove_certificate",
                               "remove_instructions"):
                    if (len(executable) != 2 or len(framed_payloads) != 2 or
                            framed_payloads[-1] != b""):
                        semantic_error = semantic_error or "rejected"
                    else:
                        # The closed final directory probe proves the selected
                        # transient is absent.  That is authoritative when a
                        # replayed delete reports that the file was already
                        # missing after a crash before the completion CAS.
                        semantic_error = None
                framing = semantic_error is None
                category = category or semantic_error
            finally:
                dialogue.close()
            if not self._finish_child(child, deadline):
                category = "descendant_unreaped"
                framing = False
            if child.returncode not in (None, 0):
                category = self._startup_category(bytes(stderr.data)) or "transport"
                framing = False
            if stdout.invalid_control or stdout.invalid_utf8 or stderr.invalid_control or stderr.invalid_utf8:
                category = category or "unsupported_response"
                framing = False
            if stdout.truncated or stderr.truncated:
                category = category or "readback_unknown"
                framing = False
            response_payload = b""
            if len(executable) == 1 and payload_spans:
                span = payload_spans[-1]
                response_payload = bytes(stdout.data)[span["offset"]:span["offset"] + span["length"]]
                if self._redact_literal(executable[0]) in _lines(response_payload):
                    category = "unsupported_response"
                    framing = False
            ios_error = _classify_ios_error(response_payload)
            # Same allowance as the per-line pass above: this second
            # classification runs on the final payload and would otherwise
            # re-impose the rejection the loop just forgave.
            if (_app_already_absent(purpose, response_payload) or
                    _delete_absent(purpose, response_payload)):
                ios_error = None
            if ios_error is not None:
                category = ios_error
            if purpose == "verification_read":
                observed_state, parser_category = _classify_read(response_payload)
                category = category or parser_category
            elif purpose in ("verification_disable", "verification_enable"):
                transition, parser_category = _classify_transition(purpose, response_payload)
                category = category or parser_category
        except IoxTransportError as exc:
            category = exc.category
            framing = False
            if child is not None:
                if not self._stop_child(child, deadline):
                    category = "descendant_unreaped"
            stdout.finish()
            stderr.finish()
        except Exception:
            category = "transport"
            framing = False
            if child is not None:
                if not self._stop_child(child, deadline):
                    category = "descendant_unreaped"
            stdout.finish()
            stderr.finish()

        if child is not None and child.returncode not in (None, 0):
            category = self._startup_category(bytes(stderr.data)) or category or "transport"
            framing = False
        if stdout.invalid_control or stdout.invalid_utf8 or stderr.invalid_control or stderr.invalid_utf8:
            category = category or "unsupported_response"
            framing = False

        # Instruction envelopes and their transaction-derived remote names are
        # private controller custody.  The dialogue above authenticates and
        # classifies each command payload before both captures are discarded;
        # neither command echoes, ciphertext, remote diagnostics, nor directory
        # residue may cross into a transcript or caller-visible result.
        if purpose in ("copy_instructions", "remove_instructions"):
            stdout = _NormalizedCapture((), capture_limit)
            stderr = _NormalizedCapture((), capture_limit)
            stdout.finish()
            stderr.finish()
            payload_spans = []

        # A failed pre-spawn validation has no command_start to close.
        if command_id in getattr(self.transcript, "_commands", {}):
            try:
                self._record_streams(
                    command_id, stdout, stderr, restoration, deadline)
                self._check_active(deadline)
                if not framing:
                    if purpose == "verification_read":
                        observed_state = "unknown"
                    elif purpose in ("verification_disable", "verification_enable"):
                        transition = "other"
                end = {
                    "schema_version": 1, "type": "command_end", "command_id": command_id,
                    "finished_at": int(time.time()),
                    "returncode": child.returncode if child is not None else None,
                    "timed_out": category == "timeout",
                    "stdout_truncated": stdout.truncated,
                    "stderr_truncated": stderr.truncated,
                    "framing_complete": bool(framing), "error_category": category,
                    "stdout_observed_bytes": stdout.observed,
                    "stderr_observed_bytes": stderr.observed,
                    "stdout_dropped_bytes": stdout.dropped,
                    "stderr_dropped_bytes": stderr.dropped,
                    "payload_spans": payload_spans if framing else [],
                    "observed_state": observed_state,
                    "transition_response": transition,
                }
                self.transcript.append(end, restoration=restoration)
                self._check_active(deadline)
            except IoxTransportError as exc:
                if category != "descendant_unreaped":
                    category = exc.category
                framing = False
        try:
            self._check_active(deadline)
        except IoxTransportError as exc:
            if category != "descendant_unreaped":
                category = exc.category
            framing = False
        return self._result(
            child, stdout, stderr, framing, category, deadline)

    @staticmethod
    def _startup_category(stderr):
        lower = stderr.lower()
        if b"permission denied" in lower:
            return "ssh_authentication"
        if (b"host key verification failed" in lower or
                b"remote host identification has changed" in lower or
                b"no matching host key" in lower):
            return "host_key"
        if (b"connection refused" in lower or b"connection timed out" in lower or
                b"no route to host" in lower or b"could not resolve hostname" in lower):
            return "connection"
        return None

    def upload(self, snapshot_fd, remote_path, phase_deadline):
        deadline = self._deadline(phase_deadline)
        operation_deadline = self._operation_deadline(deadline)
        candidates = [item for item in self.config.get("command_contexts", {}).values()
                      if item.get("kind") == "scp" and item.get("command_id") not in
                      getattr(self.transcript, "_closed", set())]
        if len(candidates) != 1:
            raise IoxTransportError("rejected", "upload requires one command context")
        context = copy.deepcopy(candidates[0])
        command_id = context["command_id"]
        purpose = context["purpose"]
        restoration = purpose == "upload_certificate" and context.get("phase") == "restore_intent"
        stdout = _NormalizedCapture(self._secret_values, _CAPTURE_BYTES)
        stderr = _NormalizedCapture(self._secret_values, _CAPTURE_BYTES)
        child = None
        category = None
        framing = False
        try:
            self._check_active(deadline)
            if (not _is_int(snapshot_fd, 3) or
                    not _valid_remote_path(remote_path, purpose)):
                raise IoxTransportError("unsupported_syntax", "invalid upload binding")
            source = os.fstat(snapshot_fd)
            source_limit = (INSTRUCTION_MAX_BYTES if
                            purpose == "upload_instructions" else
                            WRAPPER_MAX_BYTES)
            if (not stat.S_ISREG(source.st_mode) or source.st_size < 1 or
                    source.st_size > source_limit):
                raise IoxTransportError(
                    "unsupported_syntax", "upload source is not a bounded regular file")
            self.transcript.append(context, restoration=restoration)
            self._check_active(deadline)
            child = self._spawn("scp", deadline, pass_fds=(snapshot_fd,),
                                extra=(str(snapshot_fd), remote_path))
            self._check_active(deadline)
            unused_out, unused_err, unused_out_over, unused_err_over, failure = _drain_child(
                child, operation_deadline, self.cancel, _CAPTURE_BYTES,
                self.monotonic_fn,
                captures={"stdout": stdout, "stderr": stderr},
                supervised=self.supervisor is not None,
                termination_deadline=deadline)
            stdout.finish()
            stderr.finish()
            reaped = self._finish_child(child, deadline)
            if not reaped:
                category = "descendant_unreaped"
            elif failure is not None:
                category = failure.category
            elif child.returncode not in (None, 0):
                category = self._startup_category(bytes(stderr.data)) or "transport"
            elif stdout.truncated or stderr.truncated:
                category = "transport"
            else:
                framing = True
        except IoxTransportError as exc:
            category = exc.category
            if child is not None:
                if not self._stop_child(child, deadline):
                    category = "descendant_unreaped"
            stdout.finish()
            stderr.finish()
        except Exception:
            category = "transport"
            if child is not None:
                if not self._stop_child(child, deadline):
                    category = "descendant_unreaped"
            stdout.finish()
            stderr.finish()
        if purpose == "upload_instructions":
            # SCP diagnostics can repeat its argv or even source bytes.  The
            # bounded status is sufficient for this private upload; raw streams
            # must not enter durable or recipe-visible evidence.
            stdout = _NormalizedCapture((), _CAPTURE_BYTES)
            stderr = _NormalizedCapture((), _CAPTURE_BYTES)
            stdout.finish()
            stderr.finish()
        if command_id in getattr(self.transcript, "_commands", {}):
            try:
                self._record_streams(
                    command_id, stdout, stderr, restoration, deadline)
                self._check_active(deadline)
                end = {
                    "schema_version": 1, "type": "command_end", "command_id": command_id,
                    "finished_at": int(time.time()),
                    "returncode": child.returncode if child is not None else None,
                    "timed_out": category == "timeout",
                    "stdout_truncated": stdout.truncated, "stderr_truncated": stderr.truncated,
                    "framing_complete": framing, "error_category": category,
                    "stdout_observed_bytes": stdout.observed, "stderr_observed_bytes": stderr.observed,
                    "stdout_dropped_bytes": stdout.dropped, "stderr_dropped_bytes": stderr.dropped,
                    "payload_spans": [], "observed_state": None, "transition_response": None,
                }
                self.transcript.append(end, restoration=restoration)
                self._check_active(deadline)
            except IoxTransportError as exc:
                if category != "descendant_unreaped":
                    category = exc.category
                framing = False
        try:
            self._check_active(deadline)
        except IoxTransportError as exc:
            if category != "descendant_unreaped":
                category = exc.category
            framing = False
        return self._result(
            child, stdout, stderr, framing, category, deadline)

    def cancel_and_reap(self, deadline):
        deadline = self._clock() if deadline is None else deadline
        self._cancel_requested = True
        with self._lock:
            children = list(self._active)
        result = True
        for child in children:
            if not self._stop_child(child, deadline):
                result = False
        if self.supervisor is not None:
            try:
                if self.supervisor.reap_role("transport", deadline) is not True:
                    result = False
            except Exception:
                result = False
        with self._lock:
            result = result and not self._active
        if result:
            try:
                os.rmdir(self.tmp_dir)
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ENOTEMPTY):
                    result = False
        return result


if __name__ == "__main__":
    sys.exit(_scanner_main(sys.argv[1:]))
