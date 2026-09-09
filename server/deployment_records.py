# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, non-secret deployment record lifecycle state."""
import copy
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time

_STATES = frozenset(("planned", "applying", "active", "unknown", "drifted",
                     "needs-reconcile", "removed", "superseded", "abandoned"))
_NONTERMINAL = frozenset(("planned", "applying"))
# States that are not active but still describe a deployment IRIS applied, so a
# teardown may be authorized from them (see recoverable_for_device).
#
# "applying" is here because it is the durable marker written BEFORE the device
# is touched: an onboard that dies mid-run leaves it, and it already carries the
# resolved plan and owned resources teardown validates. Without it the marker
# was readable only after recover_interrupted() ran at process start, so with no
# restart a device stayed stranded forever -- not undeployable (no readable
# record), not adoptable (routers never are), not re-onboardable (preflight
# refuses the live Guest Shell). A genuinely in-flight onboard is NOT at risk:
# its job is still non-terminal, so the busy guard in gui_onboard refuses the
# undeploy before teardown is ever rendered.
_RECOVERABLE = frozenset(("unknown", "drifted", "needs-reconcile", "applying"))
# Recoverable states that describe a deployment nobody is working on. When a
# NEWER record of the same device goes active, these no longer describe the
# box and are abandoned (see _supersede_other_actives).
_STALE_ON_ACTIVATION = frozenset(("unknown", "drifted", "needs-reconcile"))
# States from which nothing further can happen: the record is history.
_TERMINAL = frozenset(("removed", "superseded", "abandoned"))
# Every non-terminal state can also be ABANDONED. That edge is reached when the
# device leaves the fleet (console delete) or when a forced teardown strips only
# the agent footprint: the record then stops describing anything IRIS manages,
# so it must stop being teardown authority and must stop blocking a re-onboard.
# It is deliberately NOT "removed" (which asserts IRIS tore the deployment down)
# and NOT "superseded" (which asserts a newer record replaced it) -- the record
# is kept because it is the only list of resources IRIS created on that box.
_TRANSITIONS = {
    "planned": frozenset(("applying", "unknown", "needs-reconcile", "removed",
                          "abandoned")),
    "applying": frozenset(("active", "unknown", "needs-reconcile", "removed",
                           "abandoned")),
    "active": frozenset(("drifted", "needs-reconcile", "applying", "removed",
                         "superseded", "abandoned")),
    # unknown/drifted/needs-reconcile must all still reach "applying", because
    # reconciling a deployment IS tearing it down. Without that edge a record
    # interrupted by a controller restart became a permanent dead end: the
    # device is already configured, so a re-onboard fails preflight, a router
    # cannot be adopted, and undeploy had no record to authorize it — leaving
    # no Console path to the device at all.
    "unknown": frozenset(("applying", "drifted", "needs-reconcile", "abandoned")),
    "drifted": frozenset(("applying", "needs-reconcile", "abandoned")),
    "needs-reconcile": frozenset(("applying", "abandoned")),
    "removed": frozenset(),
    "superseded": frozenset(),
    "abandoned": frozenset(),
}
_REQUIRED = ("controller_id", "device_id", "inventory_revision", "plan_hash",
             "resolved", "preflight", "resources")
_SECRET_KEYS = frozenset(("password", "pass", "token", "secret", "private_key",
                          "credential", "authorization"))

_STORE_MAX_BYTES = 64 * 1024 * 1024
_STORE_ORDINARY_MAX_BYTES = 48 * 1024 * 1024
_STORE_MAX_RECORDS = 8192
_RECORD_MAX_BYTES = 128 * 1024
# Mandatory state, bounded timestamps, and interruption metadata must remain
# writable after admission; ordinary evidence and IOx payload cannot use this.
_RECORD_LIFECYCLE_RESERVE_BYTES = 512
_IOX_MAX_UNRESOLVED = 512
_IOX_JOURNAL_MAX_BYTES = 16 * 1024
_IOX_TRANSCRIPT_MAX_BYTES = 1024 * 1024
_IOX_MAX_TRANSCRIPT_REFS = 8
_MAX_INTEGER = (1 << 63) - 1

_LOWER_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_BOARD_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SCHEDULE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SCHEDULE_PROVENANCE_KEYS = frozenset((
    "schema_version", "schedule_id", "schedule_rev", "occurrence_id", "device_id"))
_RECOVERY_KEYS = frozenset((
    "schema_version", "interrupted_from", "interrupted_at"))
_SCHEDULE_AUTHORITY_REFUSALS = frozenset(("conflict", "window_closed"))

_IOX_STATES = frozenset(("enabled", "disabled", "unknown"))
_IOX_PHASES = frozenset((
    "observed", "disable_intent", "disabled_confirmed", "installing",
    "ownership_probe", "restore_intent", "restored", "unchanged",
    "relinquished", "indeterminate",
))
_IOX_UNRESOLVED_PHASES = frozenset((
    "disable_intent", "disabled_confirmed", "installing",
    "ownership_probe", "restore_intent", "indeterminate",
))
_IOX_TERMINAL_PHASES = frozenset(("restored", "unchanged", "relinquished"))
_IOX_ERROR_CATEGORIES = frozenset((
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
_IOX_JOURNAL_KEYS = frozenset((
    "schema_version", "transaction_id", "revision", "record_id",
    "controller_id", "board_identity", "wrapper_sha256",
    "package_sign_present", "package_cert_present", "prior_state",
    "current_state", "phase", "unresolved", "created_at", "updated_at",
    "observed_at", "terminal_at", "initial_observation",
    "pre_disable_observation", "disable_confirmation", "restore_observation",
    "error", "transcript_refs",
))
_IOX_JOURNAL_OPTIONAL_KEYS = frozenset(("instruction_cleanup_pending",))
_OBSERVATION_KEYS = frozenset((
    "state", "observed_at", "command_id", "transcript_id", "stdout_offset",
    "stdout_length", "stderr_offset", "stderr_length", "returncode",
    "timed_out", "truncated", "framing_complete",
))
_TRANSCRIPT_REF_KEYS = frozenset((
    "id", "attempt_id", "stored_bytes", "observed_bytes", "dropped_bytes",
    "truncated",
))
_CONFIRMATION_KEYS = frozenset((
    "confirmed_at", "pre_disable_command_id", "disable_command_id",
    "disabled_readback_command_id", "transition_response",
))
_ERROR_KEYS = frozenset(("category", "detail", "at", "transcript_id"))
_COMMAND_REF_KEYS = frozenset(("transcript_id", "command_id"))

_IOX_EVENTS = frozenset((
    "disable_intent", "disable_confirmed", "installing", "ownership_probe",
    "restore_intent", "restored", "unchanged", "relinquished",
    "indeterminate", "error", "reconcile_enabled",
))


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _store_json(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _reject_constant(value):
    raise ValueError("non-finite JSON number: %s" % value)


def _closed_object(value, keys, name):
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % name)
    actual = frozenset(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        detail = []
        if missing:
            detail.append("missing %s" % ", ".join(missing))
        if unknown:
            detail.append("unknown %s" % ", ".join(unknown))
        raise ValueError("%s has %s" % (name, "; ".join(detail)))


def _integer(value, name, minimum=0, maximum=_MAX_INTEGER):
    if type(value) is not int or value < minimum or value > maximum:
        raise ValueError("%s must be an integer from %d through %d" %
                         (name, minimum, maximum))
    return value


def _boolean(value, name):
    if type(value) is not bool:
        raise ValueError("%s must be a boolean" % name)
    return value


def _matching_string(value, regex, name):
    if not isinstance(value, str) or regex.fullmatch(value) is None:
        raise ValueError("invalid %s" % name)
    return value


def _nullable_integer(value, name, minimum=0, maximum=_MAX_INTEGER):
    if value is not None:
        _integer(value, name, minimum, maximum)


def validate_schedule_provenance(value, device_id=None):
    """Return a detached, closed occurrence tag; a tag is not live authority."""
    _closed_object(value, _SCHEDULE_PROVENANCE_KEYS, "schedule provenance")
    _integer(value["schema_version"], "schedule schema_version", 1, 1)
    _integer(value["schedule_rev"], "schedule_rev", 1)
    for key in ("schedule_id", "device_id"):
        _matching_string(value[key], _SCHEDULE_IDENTIFIER, key)
    _matching_string(value["occurrence_id"], _LOWER_HEX_32, "occurrence_id")
    if value["device_id"] == "seeder":
        raise ValueError("reserved schedule device_id")
    if device_id is not None and value["device_id"] != device_id:
        raise ValueError("schedule provenance device_id mismatch")
    return copy.deepcopy(value)


def _record_payload_size(record):
    # Only server-maintained lifecycle fields are excluded. Provenance,
    # predecessor linkage, operator evidence, and the IOx journal are payload.
    payload = {key: value for key, value in record.items()
               if key not in ("state", "timestamps", "recovery")}
    return len(_canonical_json(payload))


def _check_record_growth(record, previous_size=None):
    if (previous_size is None or
            _record_payload_size(record) > previous_size):
        if len(_canonical_json(record)) > (
                _RECORD_MAX_BYTES - _RECORD_LIFECYCLE_RESERVE_BYTES):
            raise ValueError("deployment record lifecycle reserve size limit exceeded")


def _record_is_router(record):
    resolved = record.get("resolved") or {}
    return (resolved.get("platform") == "router" or
            resolved.get("management_type") in (
                "router-routed", "router-nat", "router-host"))


def _pairs_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


class _IoxCapability(object):
    """Opaque, process-local authority for exactly one journal transition."""
    __slots__ = ("_token", "_pid")

    def __init__(self, token):
        self._token = token
        self._pid = os.getpid()

    def __copy__(self):
        raise TypeError("IOx capabilities cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("IOx capabilities cannot be copied")

    def __reduce__(self):
        raise TypeError("IOx capabilities cannot be serialized")

    def __reduce_ex__(self, protocol):
        del protocol
        raise TypeError("IOx capabilities cannot be serialized")


_IOX_CAPABILITY_LOCK = threading.Lock()
_IOX_CAPABILITIES = {}


def _capability_binding(controller_id, attempt_id, record_id, transaction_id,
                        board_identity, expected_revision, expected_phase,
                        event, evidence):
    return (os.getpid(), controller_id, attempt_id, record_id, transaction_id,
            board_identity, expected_revision, expected_phase, event,
            hashlib.sha256(_canonical_json(evidence)).hexdigest())


def _issue_iox_capability(controller_id, attempt_id, record_id, transaction_id,
                          board_identity, expected_revision, expected_phase,
                          event, evidence):
    """Issue an opaque same-process, one-use capability for the controller."""
    _matching_string(controller_id, _LOWER_HEX_32, "controller_id")
    _matching_string(attempt_id, _LOWER_HEX_32, "attempt_id")
    _matching_string(record_id, _RECORD_ID, "record_id")
    _matching_string(transaction_id, _LOWER_HEX_32, "transaction_id")
    _matching_string(board_identity, _BOARD_ID, "board_identity")
    _integer(expected_revision, "expected_revision")
    if expected_phase not in _IOX_PHASES or event not in _IOX_EVENTS:
        raise ValueError("invalid IOx capability transition")
    token = secrets.token_hex(32)
    capability = _IoxCapability(token)
    binding = _capability_binding(
        controller_id, attempt_id, record_id, transaction_id, board_identity,
        expected_revision, expected_phase, event, evidence)
    with _IOX_CAPABILITY_LOCK:
        _IOX_CAPABILITIES[token] = binding
    return capability


def _consume_iox_capability(capability, journal, expected_revision,
                            expected_phase, event, evidence):
    if type(capability) is not _IoxCapability or capability._pid != os.getpid():
        raise ValueError("valid live IOx capability required")
    with _IOX_CAPABILITY_LOCK:
        actual = _IOX_CAPABILITIES.pop(capability._token, None)
    if actual is None:
        raise ValueError("stale or mismatched IOx capability")
    expected = _capability_binding(
        journal["controller_id"], actual[2], journal["record_id"],
        journal["transaction_id"], journal["board_identity"],
        expected_revision, expected_phase, event, evidence)
    if actual != expected:
        raise ValueError("stale or mismatched IOx capability")
    evidence_attempts = set()
    observation = evidence.get("observation")
    if isinstance(observation, dict):
        evidence_attempts.add(observation.get("transcript_id"))
    retry = evidence.get("retry_command")
    if isinstance(retry, dict):
        evidence_attempts.add(retry.get("transcript_id"))
    for reference in evidence.get("transcript_refs", ()):
        if isinstance(reference, dict):
            evidence_attempts.add(reference.get("attempt_id"))
    if event == "disable_confirmed":
        evidence_attempts.add(
            journal["pre_disable_observation"]["transcript_id"])
    if actual[2] not in evidence_attempts:
        raise ValueError("IOx capability attempt has no event evidence")


def _invalidate_iox_capabilities(attempt_id):
    """Invalidate every unconsumed capability belonging to one attempt."""
    _matching_string(attempt_id, _LOWER_HEX_32, "attempt_id")
    pid = os.getpid()
    with _IOX_CAPABILITY_LOCK:
        stale = [token for token, binding in _IOX_CAPABILITIES.items()
                 if binding[0] == pid and binding[2] == attempt_id]
        for token in stale:
            del _IOX_CAPABILITIES[token]


def _sync_directory(path):
    directory_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC |
                           os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _ensure_state_directory(path):
    """Create each missing component and durably commit every parent entry."""
    parent = os.path.dirname(path) or "."
    if parent == path:
        if not os.path.isdir(path):
            raise OSError(errno.ENOTDIR, "state root is not a directory", path)
        return
    try:
        os.mkdir(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            _ensure_state_directory(parent)
            try:
                os.mkdir(path)
            except OSError as retry_exc:
                if (retry_exc.errno != errno.EEXIST or
                        not os.path.isdir(path)):
                    raise
        elif exc.errno != errno.EEXIST or not os.path.isdir(path):
            raise
    # Also sync after a creation race: the process that won may fail before its
    # own barrier, and this process must not build authority below that entry
    # until the entry is durable.
    _sync_directory(parent)


def _validate_authority_file(fd, path, required_mode=None):
    """Require a stable, private regular inode without following a link."""
    opened = os.fstat(fd)
    named = os.lstat(path)
    if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or
            not stat.S_ISREG(opened.st_mode) or
            not stat.S_ISREG(named.st_mode) or opened.st_uid != os.getuid() or
            named.st_uid != os.getuid() or
            opened.st_nlink != 1 or named.st_nlink != 1):
        raise ValueError("unsafe deployment authority file: %s" % path)
    if (required_mode is not None and
            (stat.S_IMODE(opened.st_mode) != required_mode or
             stat.S_IMODE(named.st_mode) != required_mode)):
        raise ValueError("unsafe deployment authority file mode: %s" % path)
    return opened


def _open_existing_authority_file(path, flags, required_mode=None):
    fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = _validate_authority_file(fd, path, required_mode)
    except FileNotFoundError:
        os.close(fd)
        raise ValueError(
            "deployment authority file disappeared after open: %s" % path)
    except Exception:
        os.close(fd)
        raise
    return fd, metadata


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    body = _store_json(obj)
    mode = 0o600
    try:
        existing_fd, metadata = _open_existing_authority_file(
            path, os.O_RDONLY)
    except FileNotFoundError:
        pass
    else:
        os.close(existing_fd)
        mode = stat.S_IMODE(metadata.st_mode)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".records-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _sync_directory(directory)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _contains_secret(value):
    if isinstance(value, dict):
        return any(any(secret_key in str(key).lower() for secret_key in _SECRET_KEYS)
                   or _contains_secret(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


def _validate_transcript_ref(value, name="transcript reference"):
    _closed_object(value, _TRANSCRIPT_REF_KEYS, name)
    _matching_string(value["id"], _LOWER_HEX_32, name + " id")
    _matching_string(value["attempt_id"], _LOWER_HEX_32,
                     name + " attempt_id")
    if value["id"] != value["attempt_id"]:
        raise ValueError("%s id and attempt_id differ" % name)
    _integer(value["stored_bytes"], name + " stored_bytes", 1,
             _IOX_TRANSCRIPT_MAX_BYTES)
    _integer(value["observed_bytes"], name + " observed_bytes")
    _integer(value["dropped_bytes"], name + " dropped_bytes")
    if value["dropped_bytes"] > value["observed_bytes"]:
        raise ValueError("%s dropped bytes exceed observed bytes" % name)
    _boolean(value["truncated"], name + " truncated")


def _validate_observation(value, name, nullable=False):
    if value is None and nullable:
        return
    _closed_object(value, _OBSERVATION_KEYS, name)
    if value["state"] not in _IOX_STATES:
        raise ValueError("invalid %s state" % name)
    _integer(value["observed_at"], name + " observed_at")
    _integer(value["command_id"], name + " command_id", 1)
    _matching_string(value["transcript_id"], _LOWER_HEX_32,
                     name + " transcript_id")
    for key in ("stdout_offset", "stdout_length", "stderr_offset",
                "stderr_length"):
        _integer(value[key], name + " " + key)
    if value["stderr_offset"] != 0:
        raise ValueError("%s stderr_offset must be zero" % name)
    _nullable_integer(value["returncode"], name + " returncode", -255, 255)
    for key in ("timed_out", "truncated", "framing_complete"):
        _boolean(value[key], name + " " + key)
    if value["state"] in ("enabled", "disabled"):
        if (value["returncode"] != 0 or value["timed_out"] or
                value["truncated"] or not value["framing_complete"]):
            raise ValueError("%s is not an authoritative observation" % name)


def _validate_confirmation(value):
    if value is None:
        return
    _closed_object(value, _CONFIRMATION_KEYS, "disable_confirmation")
    _integer(value["confirmed_at"], "disable_confirmation confirmed_at")
    for key in ("pre_disable_command_id", "disable_command_id",
                "disabled_readback_command_id"):
        _integer(value[key], "disable_confirmation " + key, 1)
    if value["transition_response"] != "disabled_successfully":
        raise ValueError("invalid disable_confirmation transition_response")


def _validate_error(value):
    if value is None:
        return
    _closed_object(value, _ERROR_KEYS, "IOx error")
    if value["category"] not in _IOX_ERROR_CATEGORIES:
        raise ValueError("invalid IOx error category")
    if not isinstance(value["detail"], str):
        raise ValueError("IOx error detail must be text")
    try:
        detail = value["detail"].encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("IOx error detail must be valid UTF-8")
    if len(detail) > 1024:
        raise ValueError("IOx error detail exceeds 1024 bytes")
    _integer(value["at"], "IOx error timestamp")
    if value["transcript_id"] is not None:
        _matching_string(value["transcript_id"], _LOWER_HEX_32,
                         "IOx error transcript_id")


def _validate_command_ref(value, name):
    if value is None:
        return
    _closed_object(value, _COMMAND_REF_KEYS, name)
    _matching_string(value["transcript_id"], _LOWER_HEX_32,
                     name + " transcript_id")
    _integer(value["command_id"], name + " command_id", 1)


def _validate_journal_shape(journal, containing_record_id):
    if (not isinstance(journal, dict) or
            not _IOX_JOURNAL_KEYS.issubset(journal) or
            set(journal) - _IOX_JOURNAL_KEYS - _IOX_JOURNAL_OPTIONAL_KEYS):
        raise ValueError("iox_verification journal has unknown or missing fields")
    if len(_canonical_json(journal)) > _IOX_JOURNAL_MAX_BYTES:
        raise ValueError("iox_verification journal exceeds size limit")
    if type(journal["schema_version"]) is not int or journal["schema_version"] != 1:
        raise ValueError("unknown iox_verification schema")
    _matching_string(journal["transaction_id"], _LOWER_HEX_32,
                     "IOx transaction_id")
    _integer(journal["revision"], "IOx revision")
    _matching_string(journal["record_id"], _RECORD_ID, "IOx record_id")
    if journal["record_id"] != containing_record_id:
        raise ValueError("IOx journal containing record mismatch")
    _matching_string(journal["controller_id"], _LOWER_HEX_32,
                     "IOx controller_id")
    _matching_string(journal["board_identity"], _BOARD_ID,
                     "IOx board_identity")
    _matching_string(journal["wrapper_sha256"], _LOWER_HEX_64,
                     "IOx wrapper_sha256")
    _boolean(journal["package_sign_present"], "package_sign_present")
    _boolean(journal["package_cert_present"], "package_cert_present")
    if journal["prior_state"] not in _IOX_STATES:
        raise ValueError("invalid IOx prior_state")
    if journal["current_state"] not in _IOX_STATES:
        raise ValueError("invalid IOx current_state")
    phase = journal["phase"]
    if phase not in _IOX_PHASES:
        raise ValueError("invalid IOx phase")
    _boolean(journal["unresolved"], "IOx unresolved")
    if journal["unresolved"] != (phase in _IOX_UNRESOLVED_PHASES):
        raise ValueError("inconsistent derived IOx unresolved state")
    if ("instruction_cleanup_pending" in journal and
            journal["instruction_cleanup_pending"] is not True):
        raise ValueError("noncanonical IOx instruction cleanup obligation")
    if (journal.get("instruction_cleanup_pending") and
            phase not in _IOX_TERMINAL_PHASES):
        raise ValueError("IOx instruction cleanup requires a terminal phase")
    for key in ("created_at", "updated_at"):
        _integer(journal[key], "IOx " + key)
    for key in ("observed_at", "terminal_at"):
        _nullable_integer(journal[key], "IOx " + key)
    if journal["updated_at"] < journal["created_at"]:
        raise ValueError("IOx updated_at predates created_at")
    if (journal["observed_at"] is not None and
            journal["observed_at"] > journal["updated_at"]):
        raise ValueError("IOx observed_at exceeds updated_at")
    if (journal["terminal_at"] is not None and
            journal["terminal_at"] > journal["updated_at"]):
        raise ValueError("IOx terminal_at exceeds updated_at")
    if phase in _IOX_TERMINAL_PHASES:
        if (journal["terminal_at"] is None or
                journal["observed_at"] is None):
            raise ValueError("terminal IOx phase lacks terminal evidence time")
        if (journal["terminal_at"] < journal["created_at"] or
                journal["terminal_at"] < journal["observed_at"]):
            raise ValueError("terminal IOx timestamp predates its evidence")
    elif journal["terminal_at"] is not None:
        raise ValueError("nonterminal IOx phase has terminal_at")

    _validate_observation(journal["initial_observation"],
                          "initial_observation")
    _validate_observation(journal["pre_disable_observation"],
                          "pre_disable_observation", nullable=True)
    _validate_observation(journal["restore_observation"],
                          "restore_observation", nullable=True)
    _validate_confirmation(journal["disable_confirmation"])
    _validate_error(journal["error"])
    refs = journal["transcript_refs"]
    if not isinstance(refs, list) or not refs or len(refs) > _IOX_MAX_TRANSCRIPT_REFS:
        raise ValueError("IOx transcript reference limit exceeded")
    ref_ids = set()
    for ref in refs:
        _validate_transcript_ref(ref)
        if ref["id"] in ref_ids:
            raise ValueError("duplicate IOx transcript reference")
        ref_ids.add(ref["id"])
    for name in ("initial_observation", "pre_disable_observation",
                 "restore_observation"):
        observation = journal[name]
        if observation is not None and observation["transcript_id"] not in ref_ids:
            raise ValueError("%s references an unretained transcript" % name)
    error = journal["error"]
    if error is not None and error["transcript_id"] is not None:
        if error["transcript_id"] not in ref_ids:
            raise ValueError("IOx error references an unretained transcript")

    initial = journal["initial_observation"]
    pre_disable = journal["pre_disable_observation"]
    confirmation = journal["disable_confirmation"]
    restore = journal["restore_observation"]
    if journal["prior_state"] != initial["state"]:
        raise ValueError("IOx prior_state differs from initial observation")
    if (phase not in ("observed", "unchanged") and
            (initial["state"] != "enabled" or pre_disable is None or
             pre_disable["state"] != "enabled" or
             journal["package_sign_present"] or
             journal["package_cert_present"])):
        raise ValueError("inconsistent IOx ownership path")

    if phase == "observed":
        if (journal["current_state"] != initial["state"] or
                journal["observed_at"] != initial["observed_at"] or
                pre_disable is not None or confirmation is not None or
                restore is not None):
            raise ValueError("inconsistent observed IOx journal")
    elif phase == "disable_intent":
        if (initial["state"] != "enabled" or pre_disable is None or
                pre_disable["state"] != "enabled" or confirmation is not None or
                restore is not None or journal["current_state"] != "enabled" or
                journal["observed_at"] != pre_disable["observed_at"] or
                journal["package_sign_present"] or
                journal["package_cert_present"]):
            raise ValueError("inconsistent disable_intent IOx journal")
    elif phase in ("disabled_confirmed", "installing", "ownership_probe"):
        if (initial["state"] != "enabled" or pre_disable is None or
                pre_disable["state"] != "enabled" or confirmation is None or
                restore is not None or journal["current_state"] != "disabled" or
                journal["observed_at"] != confirmation["confirmed_at"]):
            raise ValueError("inconsistent confirmed IOx journal")
    elif phase == "restore_intent":
        if (confirmation is None or restore is None or
                restore["state"] != "disabled" or
                journal["current_state"] != "disabled" or
                journal["observed_at"] != restore["observed_at"]):
            raise ValueError("inconsistent restore_intent IOx journal")
    elif phase == "restored":
        if (confirmation is None or restore is None or
                restore["state"] != "enabled" or
                journal["current_state"] != "enabled" or
                journal["observed_at"] != restore["observed_at"]):
            raise ValueError("inconsistent restored IOx journal")
    elif phase == "relinquished":
        if (restore is None or restore["state"] != "enabled" or
                journal["current_state"] != "enabled" or
                journal["observed_at"] != restore["observed_at"]):
            raise ValueError("inconsistent relinquished IOx journal")
    elif phase == "indeterminate":
        if (journal["error"] is None or journal["current_state"] not in
                ("disabled", "unknown") or
                (restore is not None and
                 restore["state"] not in ("disabled", "unknown"))):
            raise ValueError("inconsistent indeterminate IOx journal")
        if restore is not None and journal["observed_at"] != restore["observed_at"]:
            raise ValueError("inconsistent indeterminate observation time")
    else:
        # `unchanged` is the only remaining phase. Its reason is deliberately
        # not persisted; the observations and wrapper markers are the evidence.
        if confirmation is not None or restore is not None:
            raise ValueError("unchanged IOx journal carries ownership evidence")
        if pre_disable is None:
            valid = (initial["state"] in ("disabled", "unknown") or
                     journal["package_sign_present"] or
                     journal["package_cert_present"])
            expected = initial
        else:
            valid = (initial["state"] == "enabled" and
                     pre_disable["state"] in ("disabled", "unknown"))
            expected = pre_disable
        if (not valid or journal["current_state"] != expected["state"] or
                journal["observed_at"] != expected["observed_at"]):
            raise ValueError("inconsistent unchanged IOx journal")

    return refs


class StaleIoxRevision(ValueError):
    """A verification event no longer matches its durable CAS precondition."""


class RecordStoreUnreadable(ValueError):
    """The record file is present but cannot be parsed.

    A ``ValueError`` subclass so every existing ``except ValueError`` around a
    write path keeps behaving exactly as before, but distinguishable by callers
    that must not confuse "this device has no deployment record" with "we
    cannot read the records at all". Telling an operator to adopt a device IRIS
    may well already own is worse than saying nothing: adoption writes a record
    asserting an unverified deployment, and the real fault is a file on the
    server."""


class StoreLockTimeout(ValueError):
    """The shared store lock was not acquired by its caller deadline."""


class DeploymentRecordStore:
    """Lock-protected record store persisted beneath ``IRIS_STATE``."""
    def __init__(self, state_dir, now_fn=time.time):
        self.state_dir = os.path.abspath(state_dir)
        _ensure_state_directory(self.state_dir)
        self.path = os.path.join(self.state_dir, "deployment_records.json")
        self._now = now_fn

    @contextlib.contextmanager
    def _store_lock(self, deadline=None, monotonic_fn=None):
        """Take the shared store lock without an unbounded flock wait."""
        clock = time.monotonic if monotonic_fn is None else monotonic_fn
        if not callable(clock):
            raise ValueError("invalid store lock clock")
        if deadline is None:
            deadline = clock() + 30.0
        elif (not isinstance(deadline, (int, float)) or
              isinstance(deadline, bool) or
              not 0 <= deadline <= _MAX_INTEGER):
            raise ValueError("invalid store lock deadline")
        lock_path = self.path + ".lock"
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            fd, unused = _open_existing_authority_file(
                lock_path, os.O_RDWR, required_mode=0o600)
        else:
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                _sync_directory(os.path.dirname(lock_path) or ".")
            except Exception:
                os.close(fd)
                raise
        try:
            _validate_authority_file(fd, lock_path, required_mode=0o600)
        except Exception:
            os.close(fd)
            raise
        acquired = False
        try:
            while True:
                if clock() >= deadline:
                    raise StoreLockTimeout(
                        "deployment record store lock timed out")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    _validate_authority_file(
                        fd, lock_path, required_mode=0o600)
                    if clock() >= deadline:
                        raise StoreLockTimeout(
                            "deployment record store lock timed out")
                    acquired = True
                    break
                except (IOError, OSError) as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    remaining = deadline - clock()
                    if remaining <= 0:
                        raise StoreLockTimeout(
                            "deployment record store lock timed out")
                    time.sleep(min(0.01, remaining))
            yield
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self, strict=False):
        """Load the store. A MISSING file is an empty store. A file that is
        present but unreadable is different: with strict=True (every write
        path) it raises, so the next create/transition cannot rewrite a
        corrupt but repairable file as a store holding one record -- these
        records are the only proof of what IRIS created on each box and the
        gate for undeploy/re-onboard. Without strict (reads) it degrades to
        an empty view.

        The strict failure is a RecordStoreUnreadable, so a reader that cannot
        safely treat "unreadable" as "empty" -- the console's undeploy gate --
        can ask for strict and report the real fault instead of "no record"."""
        try:
            fd, metadata = _open_existing_authority_file(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {"records": {}}
        except (OSError, ValueError) as exc:
            if strict:
                raise RecordStoreUnreadable(
                    "deployment record store %s is unreadable (%s); refusing "
                    "to overwrite it -- repair or remove the file"
                    % (self.path, exc))
            return {"records": {}}
        try:
            with os.fdopen(fd, "rb") as stream:
                size = metadata.st_size
                if size > _STORE_MAX_BYTES:
                    raise ValueError("deployment record store exceeds size limit")
                raw = stream.read(_STORE_MAX_BYTES + 1)
                _validate_authority_file(stream.fileno(), self.path)
            if len(raw) > _STORE_MAX_BYTES:
                raise ValueError("deployment record store exceeds size limit")
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_object,
                              parse_constant=_reject_constant)
        except (OSError, ValueError) as exc:
            if strict:
                raise RecordStoreUnreadable(
                    "deployment record store %s is unreadable (%s); refusing "
                    "to overwrite it -- repair or remove the file"
                    % (self.path, exc))
            return {"records": {}}
        records = data.get("records", {}) if isinstance(data, dict) else None
        if not isinstance(records, dict):
            if strict:
                raise RecordStoreUnreadable(
                    "deployment record store %s is malformed; refusing to "
                    "overwrite it -- repair or remove the file" % self.path)
            return {"records": {}}
        normalized = {"records": records}
        if strict:
            if frozenset(data) != frozenset(("records",)):
                raise RecordStoreUnreadable(
                    "deployment record store %s has unknown top-level fields"
                    % self.path)
            try:
                self._validate_authority_data(normalized)
            except (OSError, ValueError) as exc:
                if isinstance(exc, RecordStoreUnreadable):
                    raise
                raise RecordStoreUnreadable(
                    "deployment record store %s has invalid authority (%s)"
                    % (self.path, exc))
        return normalized

    @staticmethod
    def _validate(record, new_record=True):
        if not isinstance(record, dict):
            raise ValueError("record must be an object")
        missing = [key for key in _REQUIRED if key not in record]
        if missing:
            raise ValueError("record missing %s" % ", ".join(missing))
        if new_record and "iox_verification" in record:
            raise ValueError("generic records cannot supply iox_verification authority")
        if new_record and ("recovery" in record or "predecessor_record_id" in record):
            raise ValueError("generic records cannot supply recovery lineage")
        if "schedule_provenance" in record:
            validate_schedule_provenance(record["schedule_provenance"], record["device_id"])
            if record["schedule_provenance"]["device_id"] != record["device_id"]:
                raise ValueError("schedule provenance device_id mismatch")
        if ("fleet_registered_at" in record
                and record["fleet_registered_at"] is not None):
            _integer(record["fleet_registered_at"], "fleet_registered_at")
        if "fleet_registration_id" in record:
            _matching_string(record["fleet_registration_id"], _LOWER_HEX_32,
                             "fleet_registration_id")
        if "recovery" in record:
            recovery = record["recovery"]
            _closed_object(recovery, _RECOVERY_KEYS, "record recovery")
            _integer(recovery["schema_version"], "recovery schema_version", 1, 1)
            if (not isinstance(recovery["interrupted_from"], str) or
                    recovery["interrupted_from"] not in _NONTERMINAL):
                raise ValueError("invalid interrupted record origin")
            _integer(recovery["interrupted_at"], "interrupted_at")
        if "predecessor_record_id" in record:
            _matching_string(record["predecessor_record_id"], _RECORD_ID,
                             "predecessor_record_id")
            if "schedule_provenance" not in record:
                raise ValueError("record predecessor requires schedule provenance")
        if new_record and record.get("state", "planned") != "planned":
            raise ValueError("new records must start planned")
        if type(record["inventory_revision"]) is not int:
            raise ValueError("inventory_revision must be an integer")
        if not isinstance(record["resolved"], dict):
            raise ValueError("resolved must be an object")
        if not isinstance(record["preflight"], dict):
            raise ValueError("preflight must be an object")
        if not isinstance(record["resources"], list):
            raise ValueError("resources must be a list")
        if _contains_secret(record):
            raise ValueError("records must not contain secrets")

    def _validate_authority_data(self, data):
        records = data["records"]
        if len(records) > _STORE_MAX_RECORDS:
            raise ValueError("deployment record count exceeds limit")
        obligations = 0
        obligation_boards = set()
        journals = []
        claimed_predecessors = set()
        for record_key, record in records.items():
            if not isinstance(record_key, str):
                raise ValueError("deployment record key must be text")
            self._validate(record, new_record=False)
            record_id = record.get("record_id")
            if not isinstance(record_id, str) or record_id != record_key:
                raise ValueError("deployment record key/id mismatch")
            if record.get("state") not in _STATES:
                raise ValueError("invalid persisted deployment record state")
            if len(_canonical_json(record)) > _RECORD_MAX_BYTES:
                raise ValueError("deployment record exceeds size limit")
            if "predecessor_record_id" in record:
                predecessor_id = record["predecessor_record_id"]
                predecessor = records.get(predecessor_id)
                historical = record.get("state") == "removed"
                if (not isinstance(predecessor, dict) or predecessor_id == record_id or
                        (not historical and
                         predecessor_id in claimed_predecessors) or
                        predecessor.get("device_id") != record["device_id"] or
                        predecessor.get("schedule_provenance") != record["schedule_provenance"] or
                        (not historical and
                         predecessor.get("state") != "abandoned") or
                        "recovery" not in predecessor):
                    raise ValueError("invalid scheduled record predecessor lineage")
                journal = predecessor.get("iox_verification")
                if (not isinstance(journal, dict) or
                        journal.get("phase") not in _IOX_TERMINAL_PHASES or
                        journal.get("unresolved") is not False or
                        journal.get("instruction_cleanup_pending", False)):
                    raise ValueError("record predecessor has outstanding IOx recovery")
                # A removed successor retains a pinned audit link, but no
                # longer owns or constrains the restored predecessor. Multiple
                # retired attempts may therefore name it; at most one live
                # successor may claim it as current lineage authority.
                if not historical:
                    claimed_predecessors.add(predecessor_id)
            if "iox_verification" in record:
                journal = record["iox_verification"]
                if record.get("adopted") is True:
                    raise ValueError("adopted record carries IOx authority")
                _validate_journal_shape(journal, record_id)
                journals.append(journal)
                if (journal["unresolved"] or
                        journal.get("instruction_cleanup_pending", False)):
                    obligations += 1
                    if obligations > _IOX_MAX_UNRESOLVED:
                        raise ValueError("IOx journal obligation capacity exceeded")
                    if journal["board_identity"] in obligation_boards:
                        raise ValueError("conflicting IOx board obligation")
                    obligation_boards.add(journal["board_identity"])
        for journal in journals:
            self._validate_journal_transcripts(journal)
        return journals

    def _validate_journal_transcripts(self, journal):
        """Delegate raw transcript parsing, then enforce journal relations."""
        indexes = self._journal_transcript_indexes(journal)
        self._validate_journal_relations(journal, indexes)

    def _journal_transcript_indexes(self, journal):
        try:
            import iox_transport
        except ImportError:
            raise ValueError("IOx transcript authority parser is unavailable")
        loader = getattr(iox_transport, "_load_transcript_prefix", None)
        if loader is None:
            raise ValueError("IOx transcript authority parser is unavailable")
        indexes = {}
        for reference in journal["transcript_refs"]:
            indexes[reference["id"]] = loader(
                self.state_dir, reference, journal["controller_id"])
        return indexes

    @staticmethod
    def _event_command(indexes, reference, purpose, journal):
        index = indexes.get(reference["transcript_id"])
        command = (index["commands"].get(reference["command_id"])
                   if index is not None else None)
        if command is None or command["end"] is None:
            raise ValueError("event references an incomplete command")
        start = command["start"]
        if (start["purpose"] != purpose or
                start["board_identity"] != journal["board_identity"] or
                start["record_id"] != journal["record_id"] or
                start["transaction_id"] != journal["transaction_id"]):
            raise ValueError("event command authority mismatch")
        return command

    @staticmethod
    def _validate_journal_relations(journal, indexes):
        def command(transcript_id, command_id, name):
            index = indexes.get(transcript_id)
            if index is None:
                raise ValueError("%s references an unknown transcript" % name)
            value = index["commands"].get(command_id)
            if value is None or value["end"] is None:
                raise ValueError("%s references an incomplete command" % name)
            return value

        def check_observation(observation, name, initial=False):
            if observation is None:
                return None
            value = command(observation["transcript_id"],
                            observation["command_id"], name)
            start, end = value["start"], value["end"]
            if start["purpose"] != "verification_read":
                raise ValueError("%s is not a verification read" % name)
            if start["board_identity"] != journal["board_identity"]:
                raise ValueError("%s board identity mismatch" % name)
            if initial:
                if any(start[key] is not None for key in (
                        "record_id", "transaction_id", "revision", "phase")):
                    raise ValueError("initial observation is not pre-journal evidence")
            else:
                if (start["record_id"] != journal["record_id"] or
                        start["transaction_id"] != journal["transaction_id"] or
                        start["revision"] is None or
                        start["phase"] not in _IOX_PHASES or
                        start["revision"] >= journal["revision"]):
                    raise ValueError("%s journal binding mismatch" % name)
            spans = end["payload_spans"]
            if len(spans) == 1:
                stdout_offset = spans[0]["offset"]
                stdout_length = spans[0]["length"]
            elif not spans:
                stdout_offset = 0
                stdout_length = 0
            else:
                raise ValueError("verification read has ambiguous payload spans")
            expected = {
                "state": end["observed_state"],
                "observed_at": end["finished_at"],
                "command_id": start["command_id"],
                "transcript_id": observation["transcript_id"],
                "stdout_offset": stdout_offset,
                "stdout_length": stdout_length,
                "stderr_offset": 0,
                "stderr_length": len(value["stderr"]),
                "returncode": end["returncode"],
                "timed_out": end["timed_out"],
                "truncated": (end["stdout_truncated"] or
                              end["stderr_truncated"]),
                "framing_complete": end["framing_complete"],
            }
            if observation != expected:
                raise ValueError("%s contradicts committed transcript evidence" % name)
            if observation["stdout_offset"] + observation["stdout_length"] > len(
                    value["stdout"]):
                raise ValueError("%s stdout range is outside retained evidence" % name)
            return value

        initial_command = check_observation(
            journal["initial_observation"], "initial_observation", initial=True)
        pre_command = check_observation(
            journal["pre_disable_observation"], "pre_disable_observation")
        restore_command = check_observation(
            journal["restore_observation"], "restore_observation")

        if journal["phase"] == "restore_intent":
            start = restore_command["start"]
            acknowledgements = [
                item for item in indexes[journal["restore_observation"][
                    "transcript_id"]]["journal_acks"]
                if (item["record"]["record_id"] == journal["record_id"] and
                    item["record"]["transaction_id"] == journal["transaction_id"] and
                    item["record"]["revision"] == start["revision"] and
                    item["record"]["phase"] == "ownership_probe" and
                    item["record"]["event"] == "ownership_probe" and
                    item["order"] < restore_command["start_order"])]
            if (start["phase"] != "ownership_probe" or
                    len(acknowledgements) != 1 or
                    journal["restore_observation"]["state"] != "disabled"):
                raise ValueError("restore intent lacks durable probe evidence")

        if journal["phase"] == "restored":
            start = restore_command["start"]
            index = indexes[journal["restore_observation"]["transcript_id"]]
            enables = [value for value in index["commands"].values()
                       if (value["end"] is not None and
                           value["start"]["purpose"] == "verification_enable" and
                           value["start"]["record_id"] == journal["record_id"] and
                           value["start"]["transaction_id"] ==
                           journal["transaction_id"] and
                           value["start"]["revision"] == start["revision"] and
                           value["start"]["phase"] == "restore_intent" and
                           value["end"]["transition_response"] ==
                           "enabled_successfully")]
            acknowledgements = [
                item for item in index["journal_acks"]
                if (item["record"]["record_id"] == journal["record_id"] and
                    item["record"]["transaction_id"] == journal["transaction_id"] and
                    item["record"]["revision"] == start["revision"] and
                    item["record"]["phase"] == "restore_intent" and
                    item["record"]["event"] == "restore_intent")]
            if (start["phase"] != "restore_intent" or len(enables) != 1 or
                    len(acknowledgements) != 1 or
                    not (acknowledgements[0]["order"] < enables[0]["start_order"] <
                         enables[0]["end_order"] < restore_command["start_order"])):
                raise ValueError("restored journal lacks one ordered enable attempt")

        confirmation = journal["disable_confirmation"]
        if confirmation is None:
            return
        transcript_id = journal["initial_observation"]["transcript_id"]
        if (journal["pre_disable_observation"] is None or
                journal["pre_disable_observation"]["transcript_id"] != transcript_id):
            raise ValueError("disable confirmation crosses transcripts")
        if confirmation["pre_disable_command_id"] != journal[
                "pre_disable_observation"]["command_id"]:
            raise ValueError("disable confirmation pre-read mismatch")
        disable_command = command(transcript_id,
                                  confirmation["disable_command_id"],
                                  "disable confirmation")
        disabled_command = command(transcript_id,
                                   confirmation["disabled_readback_command_id"],
                                   "disabled readback")
        disable_start, disable_end = (disable_command["start"],
                                      disable_command["end"])
        disabled_start, disabled_end = (disabled_command["start"],
                                        disabled_command["end"])
        if (disable_start["purpose"] != "verification_disable" or
                disabled_start["purpose"] != "verification_read" or
                disable_start["board_identity"] != journal["board_identity"] or
                disabled_start["board_identity"] != journal["board_identity"] or
                disable_start["record_id"] != journal["record_id"] or
                disabled_start["record_id"] != journal["record_id"] or
                disable_start["transaction_id"] != journal["transaction_id"] or
                disabled_start["transaction_id"] != journal["transaction_id"] or
                disable_start["phase"] != "disable_intent" or
                disabled_start["phase"] != "disable_intent" or
                disable_start["revision"] != disabled_start["revision"] or
                disable_start["revision"] >= journal["revision"] or
                disable_end["transition_response"] != "disabled_successfully" or
                disable_end["returncode"] != 0 or disable_end["timed_out"] or
                disable_end["stdout_truncated"] or
                disable_end["stderr_truncated"] or
                not disable_end["framing_complete"] or
                disabled_end["observed_state"] != "disabled" or
                disabled_end["returncode"] != 0 or disabled_end["timed_out"] or
                disabled_end["stdout_truncated"] or
                disabled_end["stderr_truncated"] or
                not disabled_end["framing_complete"] or
                confirmation["confirmed_at"] != disabled_end["finished_at"]):
            raise ValueError("disable confirmation contradicts transcript")
        matching_acks = []
        for item in indexes[transcript_id]["journal_acks"]:
            ack = item["record"]
            if (ack["record_id"] == journal["record_id"] and
                    ack["transaction_id"] == journal["transaction_id"] and
                    ack["revision"] == disable_start["revision"] and
                    ack["phase"] == "disable_intent" and
                    ack["event"] == "disable_intent"):
                matching_acks.append(item)
        if len(matching_acks) != 1:
            raise ValueError("disable confirmation lacks one durable intent ack")
        if not (initial_command["end_order"] < pre_command["start_order"] <
                pre_command["end_order"] < matching_acks[0]["order"] <
                disable_command["start_order"] <
                disable_command["end_order"] < disabled_command["start_order"] <
                disabled_command["end_order"]):
            raise ValueError("disable confirmation evidence is out of order")

    def _check_candidate(self, data, ordinary):
        self._validate_authority_data(data)
        body_size = len(_store_json(data))
        limit = _STORE_ORDINARY_MAX_BYTES if ordinary else _STORE_MAX_BYTES
        if body_size > limit:
            qualifier = "ordinary admission reserve" if ordinary else "store"
            raise ValueError("deployment record %s size limit exceeded" % qualifier)

    def _supersede_other_actives(self, data, device_id, keep_record_id):
        """Retire every OTHER live record of ``device_id`` (caller holds the
        store lock). A device has ONE live deployment: when a new record goes
        active — a re-onboard's idempotent teardown+redeploy, or an explicit
        adopt — the previous active record no longer describes what is on the
        box, and neither does a sibling left in a recoverable but inactive
        state (unknown/drifted/needs-reconcile). Without this, actives
        accumulate and active_for_device() refuses undeploy; and a recoverable
        leftover survived the re-onboard only to resurface as teardown
        authority once the new record was removed -- offering a full recorded
        teardown, rendered from its stale VLAN/SVI numbers, against a box
        that no longer carries any of it. Actives become ``superseded``;
        the stale leftovers are ``abandoned`` with the reason recorded.
        ``planned``/``applying`` siblings are left alone: they belong to a
        job that is still in flight (adopt has no busy guard) and fail closed
        on their own if this activation made them stale."""
        timestamp = int(self._now())
        for record in data["records"].values():
            if (record.get("device_id") != device_id
                    or record.get("record_id") == keep_record_id):
                continue
            if record.get("state") == "active":
                record["state"] = "superseded"
                record.setdefault("timestamps", {})["finished_at"] = timestamp
            elif record.get("state") in _STALE_ON_ACTIVATION:
                previous_size = _record_payload_size(record)
                record["state"] = "abandoned"
                record["evidence"] = {
                    "status": "abandoned",
                    "reason": "superseded by the activation of record %s"
                              % keep_record_id}
                record.setdefault("timestamps", {})["finished_at"] = timestamp
                _check_record_growth(record, previous_size)

    def create(self, record_in):
        """Persist a new planned record and return its immutable initial record."""
        record = copy.deepcopy(record_in)
        if isinstance(record, dict):
            record["state"] = "planned"
        self._validate(record)
        record["record_id"] = record.get("record_id") or secrets.token_hex(16)
        if not isinstance(record["record_id"], str) or not record["record_id"]:
            raise ValueError("record_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "planned"
        record["timestamps"] = {"planned_at": timestamp, "finished_at": None}
        _check_record_growth(record)
        with self._store_lock():
            data = self._read(strict=True)
            if record["record_id"] in data["records"]:
                raise ValueError("record already exists: %s" % record["record_id"])
            data["records"][record["record_id"]] = record
            self._check_candidate(data, ordinary=True)
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def admit_scheduled(self, record_in, *, provenance, attempt, authorize,
                        resume_record_id=None, router=False):
        """Atomically admit new-only work or resume an owned interrupted record.

        ``authorize(provenance, attempt, record_or_none)`` must verify the live
        occurrence, receipt/attempt ownership, and remaining window. Return
        None on success, or ``conflict`` / ``window_closed`` to refuse. A tag
        alone never authorizes recovery. The caller holds all outer authority
        guards (role, fleet, revocation, job) through this call. The callback
        runs under the record lock: it must not acquire those outer guards or
        perform probes, controller work, or other blocking operations.

        Results contain status, reason, and a detached record (when admitted
        or needing IOx recovery). ``recovery_required`` asks the caller to run
        controller recovery outside every admission lock and retry admission.
        A recovered IOx journal stays on an abandoned predecessor; the fresh
        successor alone receives a new journal through the existing IOx API.
        Ordinary interrupted resumes retain their original execution inputs;
        the worker may refresh them through update_planned before applying.
        """
        record = copy.deepcopy(record_in)
        self._validate(record)
        tag = validate_schedule_provenance(provenance, record["device_id"])
        if ("schedule_provenance" in record and
                record["schedule_provenance"] != tag):
            raise ValueError("conflicting schedule provenance")
        record["schedule_provenance"] = tag
        self._validate(record)
        _integer(attempt, "schedule attempt", 1)
        if not callable(authorize):
            raise ValueError("live schedule authority callback required")
        _boolean(router, "router")
        if resume_record_id is not None:
            _matching_string(resume_record_id, _RECORD_ID, "resume_record_id")
        record["record_id"] = record.get("record_id") or secrets.token_hex(16)
        _matching_string(record["record_id"], _RECORD_ID, "scheduled record_id")
        router = router or _record_is_router(record)

        def result(status, reason=None, value=None):
            response = {"status": status, "reason": reason,
                        "record": copy.deepcopy(value)}
            if value is not None and "predecessor_record_id" in value:
                response["predecessor_record_id"] = value["predecessor_record_id"]
            return response

        with self._store_lock():
            data = self._read(strict=True)
            records = data["records"]
            existing = records.get(resume_record_id) if resume_record_id else None
            refusal = authorize(copy.deepcopy(tag), attempt, copy.deepcopy(existing))
            if refusal is not None:
                if (not isinstance(refusal, str) or
                        refusal not in _SCHEDULE_AUTHORITY_REFUSALS):
                    raise ValueError("invalid schedule authority refusal")
                return result("refused", refusal)
            conflicts = [row for row in records.values()
                         if row["device_id"] == tag["device_id"] and
                         row["state"] not in _TERMINAL]
            if any((router or _record_is_router(row)) and
                   (row["state"] in _RECOVERABLE or row["state"] == "active")
                   for row in conflicts):
                return result("refused", "router_requires_undeploy")
            if any(row["state"] == "unknown" and
                   row.get("schedule_provenance") != tag for row in conflicts):
                return result("refused", "foreign_interrupted_record")
            if any(row["record_id"] != resume_record_id for row in conflicts):
                return result("refused", "existing_deployment")
            timestamp = int(self._now())
            if resume_record_id is not None:
                if (existing is None or existing.get("schedule_provenance") != tag or
                        existing["device_id"] != tag["device_id"]):
                    return result("refused", "conflict")
                if (existing["state"] not in ("planned", "unknown") or
                        (existing["state"] == "unknown" and "recovery" not in existing)):
                    return result("refused", "existing_deployment")
                # A legacy row retained at startup because metadata could not
                # fit must not bypass that refusal through a planned resume.
                if _record_payload_size(existing) > (
                        _RECORD_MAX_BYTES - _RECORD_LIFECYCLE_RESERVE_BYTES):
                    return result("refused", "existing_deployment")
                if "iox_verification" not in existing:
                    # A recovered planned record never reached the device, so
                    # it can safely re-enter the ordinary planned lifecycle.
                    # A recovered applying record may already own resources on
                    # the admitted device. Keep it recoverable until the
                    # resumed worker has passed preflight and explicitly moves
                    # it back to applying; a pre-apply refusal must not erase
                    # the only authority capable of tearing those resources
                    # down.
                    if ((existing.get("recovery") or {}).get(
                            "interrupted_from") == "planned"):
                        existing["state"] = "planned"
                        existing.setdefault("timestamps", {})[
                            "finished_at"] = None
                    self._check_candidate(data, ordinary=True)
                    _atomic_write_json(self.path, data)
                    return result("resumed", value=existing)
                journal = existing["iox_verification"]
                if (existing["state"] != "unknown" or
                        journal["phase"] not in _IOX_TERMINAL_PHASES or
                        journal["unresolved"] or
                        journal.get("instruction_cleanup_pending", False)):
                    return result("recovery_required", value=existing)
                # This is the only path allowed to establish successor lineage.
                # The predecessor journal is never rewritten or reinitialized.
                existing["state"] = "abandoned"
                existing.setdefault("timestamps", {})["finished_at"] = timestamp
                record["predecessor_record_id"] = existing["record_id"]
            if record["record_id"] in records:
                return result("refused", "conflict")
            record["state"] = "planned"
            record["timestamps"] = {"planned_at": timestamp, "finished_at": None}
            _check_record_growth(record)
            records[record["record_id"]] = record
            self._check_candidate(data, ordinary=True)
            _atomic_write_json(self.path, data)
            return result("created", value=record)

    def adopt(self, record_in):
        """Create a record directly in ``active`` for an already-deployed device
        that predates records. This is the ONLY path that bypasses the planned
        start; callers must gate it behind an explicit, audited operator action."""
        self._validate(record_in)
        record = copy.deepcopy(record_in)
        record["record_id"] = record.get("record_id") or secrets.token_hex(16)
        if not isinstance(record["record_id"], str) or not record["record_id"]:
            raise ValueError("record_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "active"
        record["adopted"] = True
        record["timestamps"] = {"planned_at": timestamp, "finished_at": timestamp}
        _check_record_growth(record)
        with self._store_lock():
            data = self._read(strict=True)
            if record["record_id"] in data["records"]:
                raise ValueError("record already exists: %s" % record["record_id"])
            self._supersede_other_actives(data, record["device_id"],
                                          record["record_id"])
            data["records"][record["record_id"]] = record
            self._check_candidate(data, ordinary=True)
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def get(self, record_id, strict=False):
        record = self._read(strict=strict)["records"].get(record_id)
        return copy.deepcopy(record) if record else None

    def update_planned(self, record_id, *, plan_hash, resolved, preflight,
                       resources):
        """Atomically refresh execution-time evidence on a planned record.

        Router jobs can wait in the onboarding queue, so ownership-sensitive
        preflight is repeated immediately before apply. Only a still-planned
        record may be refreshed; once applying starts its renderer inputs are
        immutable.
        """
        with self._store_lock():
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            if record.get("state") != "planned":
                raise ValueError("only planned records may refresh preflight")
            candidate = copy.deepcopy(record)
            candidate.update({"plan_hash": plan_hash,
                              "resolved": copy.deepcopy(resolved),
                              "preflight": copy.deepcopy(preflight),
                              "resources": copy.deepcopy(resources)})
            self._validate(candidate, new_record=False)
            _check_record_growth(candidate, _record_payload_size(record))
            data["records"][record_id] = candidate
            self._check_candidate(data, ordinary=True)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(candidate)

    def update_scheduled_recovery(self, record_id, *, provenance, plan_hash,
                                  resolved, preflight, resources):
        """Refresh a resumed applying record without dropping its authority.

        Startup recovery changes an interrupted scheduled apply to ``unknown``.
        Its original occurrence may retry only while retaining that state, its
        recovery origin, and its admitted device identity. The caller supplies
        the exact occurrence provenance under live schedule authority; this
        method only enforces the durable record boundary.
        """
        tag = validate_schedule_provenance(provenance)
        with self._store_lock():
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            if (record.get("state") != "unknown" or
                    (record.get("recovery") or {}).get(
                        "interrupted_from") != "applying" or
                    record.get("schedule_provenance") != tag):
                raise ValueError(
                    "only the owning occurrence may refresh a recovered apply")
            admitted_identity = str(
                (record.get("resolved") or {}).get("device_identity") or "")
            refreshed_identity = str(
                (resolved or {}).get("device_identity") or "")
            if ((record.get("resolved") or {}).get("platform") in
                    ("guestshell", "iox") and not admitted_identity):
                raise ValueError(
                    "recovered record has no admitted device identity")
            if admitted_identity and refreshed_identity != admitted_identity:
                raise ValueError("recovered device identity changed")
            candidate = copy.deepcopy(record)
            candidate.update({"plan_hash": plan_hash,
                              "resolved": copy.deepcopy(resolved),
                              "preflight": copy.deepcopy(preflight),
                              "resources": copy.deepcopy(resources)})
            self._validate(candidate, new_record=False)
            _check_record_growth(candidate, _record_payload_size(record))
            data["records"][record_id] = candidate
            self._check_candidate(data, ordinary=True)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(candidate)

    def retire_planned(self, record_id):
        """Retire a record only if no apply has ever started.

        This is the atomic pre-apply cleanup primitive. In particular, a
        recovered ``unknown`` apply is returned unchanged rather than being
        mistaken for a fresh plan and stripped of teardown authority.
        """
        with self._store_lock():
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            if record.get("state") != "planned":
                return copy.deepcopy(record)
            previous_size = _record_payload_size(record)
            predecessor_id = record.get("predecessor_record_id")
            if predecessor_id is not None:
                predecessor = data["records"].get(predecessor_id)
                if (not isinstance(predecessor, dict) or
                        predecessor.get("state") != "abandoned"):
                    raise ValueError(
                        "invalid scheduled record predecessor lineage")
                predecessor["state"] = "unknown"
                predecessor.setdefault("timestamps", {})[
                    "finished_at"] = int(self._now())
            record["state"] = "removed"
            record.setdefault("timestamps", {})["finished_at"] = int(
                self._now())
            _check_record_growth(record, previous_size)
            self._check_candidate(data, ordinary=False)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(record)

    def list(self, device_id=None, strict=False):
        """Records, optionally for one device. *strict* makes an unreadable
        store raise RecordStoreUnreadable instead of reading as empty; use it
        wherever an empty result would be reported to an operator as a fact
        about the device rather than about the file."""
        records = self._read(strict=strict)["records"].values()
        if device_id is not None:
            records = (record for record in records
                        if record.get("device_id") == device_id)
        return [copy.deepcopy(record) for record in records]

    def transition(self, record_id, state, evidence=None):
        """Advance a record through its fail-closed lifecycle state machine."""
        if state not in _STATES:
            raise ValueError("unknown record state: %s" % state)
        if evidence is not None and _contains_secret(evidence):
            raise ValueError("record evidence must not contain secrets")
        with self._store_lock():
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            current = record.get("state")
            previous_size = _record_payload_size(record)
            if state not in _TRANSITIONS.get(current, frozenset()):
                raise ValueError("invalid record transition: %s -> %s" % (current, state))
            record["state"] = state
            if evidence is not None:
                record["evidence"] = copy.deepcopy(evidence)
            if state in ("active", "unknown", "drifted", "needs-reconcile", "removed"):
                record.setdefault("timestamps", {})["finished_at"] = int(self._now())
            if state == "active":
                self._supersede_other_actives(data, record.get("device_id"),
                                              record_id)
            _check_record_growth(record, previous_size)
            self._check_candidate(data, ordinary=evidence is not None)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(record)

    def recover_interrupted(self):
        """Mark planned/applying work unknown after a controller restart, and
        collapse legacy duplicate actives (written before activation superseded
        siblings): keep each device's NEWEST active — by activation time, then
        plan time, then record id, so the choice is deterministic — and retire
        the rest, restoring the one-active-per-device invariant undeploy needs.

        Legacy rows may predate the lifecycle reserve. Leave a row unchanged
        if its mandatory metadata cannot fit either hard cap, and continue the
        bounded batch. Its original nonterminal state and all authority remain
        intact and fail closed; one full row must not abort global startup.
        """
        changed = []
        with self._store_lock():
            data = self._read(strict=True)
            body_size = len(_store_json(data))

            def retain_if_fits(candidate):
                nonlocal body_size
                record_id = candidate["record_id"]
                original = data["records"][record_id]
                if len(_canonical_json(candidate)) > _RECORD_MAX_BYTES:
                    return
                # The wrappers preserve the exact nesting/indentation of one
                # row in the real store, without serializing the whole store
                # for every row (which would make startup quadratic).
                old_size = len(_store_json({"records": {record_id: original}}))
                new_size = len(_store_json({"records": {record_id: candidate}}))
                candidate_size = body_size + new_size - old_size
                if candidate_size > _STORE_MAX_BYTES:
                    return
                data["records"][record_id] = candidate
                body_size = candidate_size
                changed.append(record_id)

            for original in list(data["records"].values()):
                if original.get("state") in _NONTERMINAL:
                    record = copy.deepcopy(original)
                    record["recovery"] = {
                        "schema_version": 1,
                        "interrupted_from": record["state"],
                        "interrupted_at": int(self._now()),
                    }
                    record["state"] = "unknown"
                    record.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    retain_if_fits(record)
            actives = {}
            for record in data["records"].values():
                if record.get("state") == "active":
                    actives.setdefault(record.get("device_id"), []).append(record)
            for duplicates in actives.values():
                if len(duplicates) < 2:
                    continue
                def _age(record):
                    timestamps = record.get("timestamps") or {}
                    return (timestamps.get("finished_at") or 0,
                            timestamps.get("planned_at") or 0,
                            record.get("record_id") or "")
                for original in sorted(duplicates, key=_age)[:-1]:
                    record = copy.deepcopy(original)
                    record["state"] = "superseded"
                    record.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    retain_if_fits(record)
            if changed:
                self._check_candidate(data, ordinary=False)
                _atomic_write_json(self.path, data)
        return changed

    def retire_device(self, device_id, reason, deadline=None,
                      monotonic_fn=None):
        """Abandon every record of *device_id* that is not already terminal.

        Called when the device leaves the fleet (console delete) and after a
        forced agent-only teardown. Both leave a record that no longer
        describes a device IRIS manages, and a record in a recoverable state
        is what onboard refuses on and what undeploy renders teardown from --
        so leaving one behind hands the NEXT device registered under this id a
        dead predecessor's deployment. That is not hypothetical: it strands the
        device outright, because onboard says "undeploy it first" while the
        teardown it names refuses the box on an identity mismatch.

        The rows are kept, not dropped: a record is the only account of the
        resources IRIS created on that box (the VirtualPortGroup, the NAT
        stanza, the app address), and an operator who deletes a device that is
        still configured needs that list. *reason* is recorded as non-secret
        evidence so the trail says which of the two paths retired it.

        Returns the ids of the records retired, newest first."""
        retired = []
        with self._store_lock(deadline, monotonic_fn):
            data = self._read(strict=True)
            timestamp = int(self._now())
            for record in data["records"].values():
                if (record.get("device_id") != device_id
                        or record.get("state") in _TERMINAL):
                    continue
                previous_size = _record_payload_size(record)
                record["state"] = "abandoned"
                record["evidence"] = {"status": "abandoned", "reason": reason}
                record.setdefault("timestamps", {})["finished_at"] = timestamp
                _check_record_growth(record, previous_size)
                retired.append(record["record_id"])
            if retired:
                self._check_candidate(data, ordinary=True)
                _atomic_write_json(self.path, data)
        return sorted(retired, reverse=True)

    @staticmethod
    def _merge_transcript_refs(existing, incoming):
        if not isinstance(incoming, list):
            raise ValueError("transcript_refs must be a list")
        result = copy.deepcopy(existing)
        positions = dict((ref["id"], index)
                         for index, ref in enumerate(result))
        incoming_ids = set()
        for ref in incoming:
            _validate_transcript_ref(ref, "event transcript reference")
            ref_id = ref["id"]
            if ref_id in incoming_ids:
                raise ValueError("duplicate event transcript reference")
            incoming_ids.add(ref_id)
            if ref_id not in positions:
                if len(result) >= _IOX_MAX_TRANSCRIPT_REFS:
                    raise ValueError("IOx transcript reference limit exceeded")
                positions[ref_id] = len(result)
                result.append(copy.deepcopy(ref))
                continue
            old = result[positions[ref_id]]
            if old["attempt_id"] != ref["attempt_id"]:
                raise ValueError("IOx transcript attempt changed")
            for key in ("stored_bytes", "observed_bytes", "dropped_bytes"):
                if ref[key] < old[key]:
                    raise ValueError("IOx transcript reference regressed")
            if old["truncated"] and not ref["truncated"]:
                raise ValueError("IOx transcript truncation regressed")
            if ref["stored_bytes"] == old["stored_bytes"] and ref != old:
                raise ValueError("IOx transcript counters changed without a prefix")
            result[positions[ref_id]] = copy.deepcopy(ref)
        return result

    @staticmethod
    def _validate_wrapper_binding(value):
        keys = frozenset(("wrapper_sha256", "package_sign_present",
                          "package_cert_present"))
        _closed_object(value, keys, "wrapper_binding")
        _matching_string(value["wrapper_sha256"], _LOWER_HEX_64,
                         "wrapper_binding wrapper_sha256")
        _boolean(value["package_sign_present"],
                 "wrapper_binding package_sign_present")
        _boolean(value["package_cert_present"],
                 "wrapper_binding package_cert_present")

    def iox_begin(self, record_id, controller_id, board_identity,
                  wrapper_binding, initial_observation, transcript_ref,
                  deadline=None, monotonic_fn=None):
        """Create revision zero from committed controller-owned evidence."""
        _matching_string(record_id, _RECORD_ID, "IOx record_id")
        _matching_string(controller_id, _LOWER_HEX_32, "IOx controller_id")
        _matching_string(board_identity, _BOARD_ID, "IOx board_identity")
        self._validate_wrapper_binding(wrapper_binding)
        _validate_observation(initial_observation, "initial_observation")
        _validate_transcript_ref(transcript_ref)
        if initial_observation["transcript_id"] != transcript_ref["id"]:
            raise ValueError("initial observation transcript mismatch")
        with self._store_lock(deadline, monotonic_fn):
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            if record.get("adopted") is True:
                raise ValueError("adopted records cannot create IOx authority")
            if "iox_verification" in record:
                raise ValueError("record already has an IOx journal")
            resolved = record.get("resolved") or {}
            recorded_identity = resolved.get("device_identity")
            if recorded_identity is not None and recorded_identity != board_identity:
                raise ValueError("IOx board identity mismatch")
            for other in data["records"].values():
                journal = other.get("iox_verification")
                if (journal is not None and
                        (journal["unresolved"] or journal.get(
                            "instruction_cleanup_pending", False)) and
                        journal["board_identity"] == board_identity):
                    raise ValueError("conflicting IOx board obligation")
            timestamp = int(self._now())
            _integer(timestamp, "IOx event timestamp")
            journal = {
                "schema_version": 1,
                "transaction_id": secrets.token_hex(16),
                "revision": 0,
                "record_id": record_id,
                "controller_id": controller_id,
                "board_identity": board_identity,
                "wrapper_sha256": wrapper_binding["wrapper_sha256"],
                "package_sign_present": wrapper_binding["package_sign_present"],
                "package_cert_present": wrapper_binding["package_cert_present"],
                "prior_state": initial_observation["state"],
                "current_state": initial_observation["state"],
                "phase": "observed",
                "unresolved": False,
                "created_at": timestamp,
                "updated_at": timestamp,
                "observed_at": initial_observation["observed_at"],
                "terminal_at": None,
                "initial_observation": copy.deepcopy(initial_observation),
                "pre_disable_observation": None,
                "disable_confirmation": None,
                "restore_observation": None,
                "error": None,
                "transcript_refs": [copy.deepcopy(transcript_ref)],
            }
            candidate = copy.deepcopy(data)
            candidate["records"][record_id]["iox_verification"] = journal
            _check_record_growth(candidate["records"][record_id],
                                 _record_payload_size(record))
            self._check_candidate(candidate, ordinary=True)
            _atomic_write_json(self.path, candidate)
            return copy.deepcopy(journal)

    @staticmethod
    def _validate_event_evidence(event, evidence):
        schemas = {
            "disable_intent": frozenset(("observation", "retry_command",
                                         "transcript_refs")),
            "disable_confirmed": frozenset(("confirmation", "transcript_refs")),
            "installing": frozenset(),
            "ownership_probe": frozenset(),
            "restore_intent": frozenset(("observation", "transcript_refs")),
            "restored": frozenset(("observation", "transcript_refs")),
            "unchanged": frozenset(("reason", "observation", "transcript_refs")),
            "relinquished": frozenset(("observation", "transcript_refs")),
            "indeterminate": frozenset(("observation", "error",
                                        "transcript_refs")),
            "error": frozenset(("error", "transcript_refs")),
            "reconcile_enabled": frozenset((
                "observation", "acknowledge_external_resolution",
                "transcript_refs")),
        }
        if event not in schemas:
            raise ValueError("unknown IOx event")
        _closed_object(evidence, schemas[event], "IOx %s evidence" % event)
        if "transcript_refs" in evidence:
            if not isinstance(evidence["transcript_refs"], list):
                raise ValueError("transcript_refs must be a list")
        if "observation" in evidence:
            _validate_observation(evidence["observation"], "event observation",
                                  nullable=True)
        if "confirmation" in evidence:
            _validate_confirmation(evidence["confirmation"])
            if evidence["confirmation"] is None:
                raise ValueError("disable_confirmed requires confirmation")
        if "error" in evidence:
            _validate_error(evidence["error"])
            if evidence["error"] is None:
                raise ValueError("IOx event requires an error")
        if event == "disable_intent":
            _validate_command_ref(evidence["retry_command"], "retry_command")
        if event == "unchanged" and evidence["reason"] not in (
                "marker_present", "initially_disabled", "initial_read_unknown",
                "pre_disable_changed"):
            raise ValueError("invalid unchanged reason")
        if event == "reconcile_enabled":
            if evidence["acknowledge_external_resolution"] is not True:
                raise ValueError("reconciliation acknowledgment is required")

    def iox_event(self, record_id, transaction_id, expected_revision,
                  expected_phase, event, evidence, capability=None,
                  deadline=None, monotonic_fn=None):
        """Apply one closed, transcript-backed journal CAS transition."""
        _matching_string(record_id, _RECORD_ID, "IOx record_id")
        _matching_string(transaction_id, _LOWER_HEX_32, "IOx transaction_id")
        _integer(expected_revision, "expected IOx revision")
        if expected_phase not in _IOX_PHASES:
            raise ValueError("invalid expected IOx phase")
        self._validate_event_evidence(event, evidence)
        with self._store_lock(deadline, monotonic_fn):
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None or "iox_verification" not in record:
                raise ValueError("unknown IOx journal: %s" % record_id)
            journal = record["iox_verification"]
            if journal["transaction_id"] != transaction_id:
                raise ValueError("IOx transaction mismatch")
            if (journal["revision"] != expected_revision or
                    journal["phase"] != expected_phase):
                raise StaleIoxRevision(
                    "stale IOx CAS: expected revision %d phase %s" %
                    (expected_revision, expected_phase))

            current = journal["phase"]
            observation = evidence.get("observation")
            requires_capability = event in (
                "disable_confirmed", "restore_intent", "restored")
            if event == "relinquished" and current == "ownership_probe":
                requires_capability = True
            if event == "disable_intent" and current == "disable_intent":
                requires_capability = True
            if requires_capability and capability is None:
                raise ValueError("valid live IOx capability required")
            if not requires_capability and capability is not None:
                raise ValueError("unexpected IOx capability")

            candidate = copy.deepcopy(journal)
            if "transcript_refs" in evidence:
                candidate["transcript_refs"] = self._merge_transcript_refs(
                    journal["transcript_refs"], evidence["transcript_refs"])
            next_phase = current
            if event == "disable_intent":
                if current not in ("observed", "disable_intent"):
                    raise ValueError("invalid IOx transition to disable_intent")
                if (journal["initial_observation"]["state"] != "enabled" or
                        journal["package_sign_present"] or
                        journal["package_cert_present"] or observation is None or
                        observation["state"] != "enabled"):
                    raise ValueError("disable intent requires fresh enabled evidence")
                if current == "observed" and evidence["retry_command"] is not None:
                    raise ValueError("initial disable intent cannot be a retry")
                if current == "disable_intent" and evidence["retry_command"] is None:
                    raise ValueError("disable retry requires a CAF command")
                candidate["pre_disable_observation"] = copy.deepcopy(observation)
                candidate["current_state"] = "enabled"
                candidate["observed_at"] = observation["observed_at"]
                next_phase = "disable_intent"
            elif event == "disable_confirmed":
                if current != "disable_intent":
                    raise ValueError("invalid IOx transition to disabled_confirmed")
                confirmation = evidence["confirmation"]
                if confirmation["pre_disable_command_id"] != journal[
                        "pre_disable_observation"]["command_id"]:
                    raise ValueError("disable confirmation pre-read mismatch")
                if journal["disable_confirmation"] is not None:
                    raise ValueError("disable confirmation is immutable")
                candidate["disable_confirmation"] = copy.deepcopy(confirmation)
                candidate["current_state"] = "disabled"
                candidate["observed_at"] = confirmation["confirmed_at"]
                next_phase = "disabled_confirmed"
            elif event == "installing":
                if current != "disabled_confirmed":
                    raise ValueError("invalid IOx transition to installing")
                next_phase = "installing"
            elif event == "ownership_probe":
                if current not in ("disabled_confirmed", "installing"):
                    raise ValueError("invalid IOx transition to ownership_probe")
                next_phase = "ownership_probe"
            elif event == "restore_intent":
                if (current != "ownership_probe" or observation is None or
                        observation["state"] != "disabled"):
                    raise ValueError("restore intent requires a disabled probe")
                candidate["restore_observation"] = copy.deepcopy(observation)
                candidate["current_state"] = "disabled"
                candidate["observed_at"] = observation["observed_at"]
                next_phase = "restore_intent"
            elif event == "restored":
                if (current != "restore_intent" or observation is None or
                        observation["state"] != "enabled"):
                    raise ValueError("restored requires an enabled readback")
                candidate["restore_observation"] = copy.deepcopy(observation)
                candidate["current_state"] = "enabled"
                candidate["observed_at"] = observation["observed_at"]
                next_phase = "restored"
            elif event == "unchanged":
                if current != "observed":
                    raise ValueError("invalid IOx transition to unchanged")
                reason = evidence["reason"]
                initial_state = journal["initial_observation"]["state"]
                if reason == "marker_present":
                    valid = (observation is None and
                             (journal["package_sign_present"] or
                              journal["package_cert_present"]))
                elif reason == "initially_disabled":
                    valid = observation is None and initial_state == "disabled"
                elif reason == "initial_read_unknown":
                    valid = observation is None and initial_state == "unknown"
                else:
                    valid = (observation is not None and initial_state == "enabled" and
                             observation["state"] in ("disabled", "unknown"))
                    if valid:
                        candidate["pre_disable_observation"] = copy.deepcopy(observation)
                        candidate["current_state"] = observation["state"]
                        candidate["observed_at"] = observation["observed_at"]
                if not valid:
                    raise ValueError("unchanged reason does not match evidence")
                next_phase = "unchanged"
            elif event == "relinquished":
                if (current not in ("disable_intent", "ownership_probe",
                                    "restore_intent") or observation is None or
                        observation["state"] != "enabled"):
                    raise ValueError("relinquishment requires recovered enabled state")
                candidate["restore_observation"] = copy.deepcopy(observation)
                candidate["current_state"] = "enabled"
                candidate["observed_at"] = observation["observed_at"]
                next_phase = "relinquished"
            elif event == "indeterminate":
                if current not in ("disable_intent", "ownership_probe",
                                   "restore_intent"):
                    raise ValueError("invalid IOx transition to indeterminate")
                if current == "ownership_probe":
                    if observation is not None:
                        raise ValueError("recovered ownership probe has no authority")
                elif observation is None or observation["state"] not in (
                        "disabled", "unknown"):
                    raise ValueError("indeterminate recovery needs disabled/unknown read")
                if observation is not None:
                    candidate["restore_observation"] = copy.deepcopy(observation)
                    candidate["current_state"] = observation["state"]
                    candidate["observed_at"] = observation["observed_at"]
                candidate["error"] = copy.deepcopy(evidence["error"])
                next_phase = "indeterminate"
            elif event == "error":
                candidate["error"] = copy.deepcopy(evidence["error"])
            else:
                if (event != "reconcile_enabled" or current != "indeterminate" or
                        observation is None or observation["state"] != "enabled"):
                    raise ValueError("invalid IOx reconciliation")
                candidate["restore_observation"] = copy.deepcopy(observation)
                candidate["current_state"] = "enabled"
                candidate["observed_at"] = observation["observed_at"]
                next_phase = "relinquished"

            timestamp = int(self._now())
            _integer(timestamp, "IOx event timestamp")
            candidate["revision"] = journal["revision"] + 1
            _integer(candidate["revision"], "IOx revision")
            candidate["updated_at"] = max(timestamp, journal["updated_at"])
            candidate["phase"] = next_phase
            candidate["unresolved"] = next_phase in _IOX_UNRESOLVED_PHASES
            if next_phase in _IOX_TERMINAL_PHASES and journal["terminal_at"] is None:
                candidate["terminal_at"] = timestamp

            candidate_data = copy.deepcopy(data)
            candidate_data["records"][record_id]["iox_verification"] = candidate
            _check_record_growth(candidate_data["records"][record_id],
                                 _record_payload_size(record))
            self._check_candidate(candidate_data, ordinary=False)
            indexes = self._journal_transcript_indexes(candidate)
            if observation is not None:
                observed_command = self._event_command(
                    indexes, {"transcript_id": observation["transcript_id"],
                              "command_id": observation["command_id"]},
                    "verification_read", journal)
                start = observed_command["start"]
                if (start["revision"] != expected_revision or
                        start["phase"] != expected_phase):
                    raise ValueError("event observation has a stale journal binding")
            if event == "disable_intent" and evidence["retry_command"] is not None:
                retry_command = self._event_command(
                    indexes, evidence["retry_command"],
                    "verification_disable", journal)
                retry_start, retry_end = retry_command["start"], retry_command["end"]
                if (retry_start["revision"] != expected_revision or
                        retry_start["phase"] != "disable_intent" or
                        retry_end["transition_response"] != "caf_transient" or
                        retry_end["returncode"] != 0 or retry_end["timed_out"] or
                        retry_end["stdout_truncated"] or
                        retry_end["stderr_truncated"] or
                        not retry_end["framing_complete"] or
                        retry_command["end_order"] >= observed_command["start_order"]):
                    raise ValueError("disable retry lacks exact CAF evidence")
                acknowledgements = [
                    item for item in indexes[evidence["retry_command"][
                        "transcript_id"]]["journal_acks"]
                    if (item["record"]["record_id"] == journal["record_id"] and
                        item["record"]["transaction_id"] ==
                        journal["transaction_id"] and
                        item["record"]["revision"] == expected_revision and
                        item["record"]["phase"] == "disable_intent" and
                        item["record"]["event"] == "disable_intent" and
                        item["order"] < retry_command["start_order"])]
                if len(acknowledgements) != 1:
                    raise ValueError("disable retry lacks durable intent acknowledgment")
            if requires_capability:
                _consume_iox_capability(capability, journal, expected_revision,
                                        expected_phase, event, evidence)
            _atomic_write_json(self.path, candidate_data)
            return copy.deepcopy(candidate)

    def _iox_instruction_cleanup_update(
            self, record_id, transaction_id, expected_revision,
            expected_phase, pending, deadline=None, monotonic_fn=None):
        """CAS one path-free, transaction-derived instruction obligation."""
        _matching_string(record_id, _RECORD_ID, "IOx record_id")
        _matching_string(transaction_id, _LOWER_HEX_32,
                         "IOx transaction_id")
        _integer(expected_revision, "expected IOx revision")
        if expected_phase not in _IOX_TERMINAL_PHASES:
            raise ValueError(
                "instruction cleanup requires a terminal IOx phase")
        if type(pending) is not bool:
            raise ValueError("invalid instruction cleanup state")
        with self._store_lock(deadline, monotonic_fn):
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None or "iox_verification" not in record:
                raise ValueError("unknown IOx journal: %s" % record_id)
            journal = record["iox_verification"]
            if journal["transaction_id"] != transaction_id:
                raise ValueError("IOx transaction mismatch")
            if (journal["revision"] != expected_revision or
                    journal["phase"] != expected_phase):
                raise StaleIoxRevision(
                    "stale IOx cleanup CAS: expected revision %d phase %s" %
                    (expected_revision, expected_phase))
            existing = journal.get("instruction_cleanup_pending", False)
            if pending and existing:
                raise ValueError("IOx instruction cleanup intent already exists")
            if not pending and not existing:
                raise ValueError("IOx instruction cleanup intent is absent")

            candidate = copy.deepcopy(journal)
            if pending:
                candidate["instruction_cleanup_pending"] = True
            else:
                candidate.pop("instruction_cleanup_pending", None)
            candidate["revision"] += 1
            _integer(candidate["revision"], "IOx revision")
            timestamp = int(self._now())
            _integer(timestamp, "IOx cleanup timestamp")
            candidate["updated_at"] = max(timestamp, journal["updated_at"])
            candidate_data = copy.deepcopy(data)
            candidate_data["records"][record_id][
                "iox_verification"] = candidate
            _check_record_growth(candidate_data["records"][record_id],
                                 _record_payload_size(record))
            self._check_candidate(candidate_data, ordinary=False)
            _atomic_write_json(self.path, candidate_data)
            return copy.deepcopy(candidate)

    def iox_instruction_cleanup_intent(
            self, record_id, transaction_id, expected_revision,
            expected_phase, deadline=None, monotonic_fn=None):
        return self._iox_instruction_cleanup_update(
            record_id, transaction_id, expected_revision, expected_phase,
            True, deadline=deadline, monotonic_fn=monotonic_fn)

    def iox_instruction_cleanup_complete(
            self, record_id, transaction_id, expected_revision,
            expected_phase, deadline=None, monotonic_fn=None):
        return self._iox_instruction_cleanup_update(
            record_id, transaction_id, expected_revision, expected_phase,
            False, deadline=deadline, monotonic_fn=monotonic_fn)

    def iox_obligations(self, board_identity, deadline=None,
                        monotonic_fn=None):
        _matching_string(board_identity, _BOARD_ID, "IOx board_identity")
        with self._store_lock(deadline, monotonic_fn):
            data = self._read(strict=True)
            values = [copy.deepcopy(record["iox_verification"])
                      for record in data["records"].values()
                      if (record.get("iox_verification") is not None and
                          (record["iox_verification"]["unresolved"] or
                           record["iox_verification"].get(
                               "instruction_cleanup_pending", False)) and
                          record["iox_verification"]["board_identity"] ==
                          board_identity)]
        return sorted(values, key=lambda item: (item["record_id"],
                                                item["transaction_id"]))

    @staticmethod
    def _iox_safe_summary(journal):
        keys = ("schema_version", "record_id", "transaction_id", "revision",
                "board_identity", "prior_state", "current_state", "phase",
                "unresolved", "created_at", "updated_at", "observed_at",
                "terminal_at")
        value = dict((key, copy.deepcopy(journal[key])) for key in keys)
        value["error_category"] = (journal["error"]["category"]
                                   if journal["error"] is not None else None)
        if journal.get("instruction_cleanup_pending"):
            value["instruction_cleanup_pending"] = True
        return value

    def iox_summary(self, device_id):
        with self._store_lock():
            data = self._read(strict=True)
            board_identities = set()
            for record in data["records"].values():
                if record.get("device_id") != device_id:
                    continue
                journal = record.get("iox_verification")
                if journal is not None:
                    board_identities.add(journal["board_identity"])
                for source in (record.get("resolved"), record.get("preflight")):
                    identity = source.get("device_identity") if isinstance(source, dict) else None
                    if (isinstance(identity, str) and
                            _BOARD_ID.fullmatch(identity)):
                        board_identities.add(identity)
            values = []
            for record in data["records"].values():
                journal = record.get("iox_verification")
                if (journal is None or not (
                        journal["unresolved"] or journal.get(
                            "instruction_cleanup_pending", False))):
                    continue
                if (record.get("device_id") == device_id or
                        journal["board_identity"] in board_identities):
                    values.append(self._iox_safe_summary(journal))
        return sorted(values, key=lambda item: (
            item["board_identity"], item["record_id"], item["transaction_id"]))

    def active_for_device(self, device_id, strict=False):
        active = [record for record in self.list(device_id, strict=strict)
                  if record.get("state") == "active"]
        if len(active) > 1:
            raise ValueError("multiple active records for device: %s" % device_id)
        return active[0] if active else None

    def recoverable_for_device(self, device_id, strict=False):
        """The record that may authorize a TEARDOWN of *device_id*: the active
        one, or — when there is none — a single record left in a recoverable
        state (unknown after a controller restart, or drifted/needs-reconcile).
        Those states still record the resolved plan and the owned resources,
        which is exactly the ownership proof teardown validates, and without
        this the device would be unmanageable.

        Returns None when nothing is left to reconcile. Raises when more than
        one candidate exists: two records mean we cannot prove which one
        describes the box, and tearing down the wrong one could remove
        resources the other still owns.

        *strict* raises RecordStoreUnreadable rather than returning None when
        the store file itself cannot be read -- "no record" and "no readable
        records" call for opposite advice to the operator."""
        active = self.active_for_device(device_id, strict=strict)
        if active is not None:
            return active
        candidates = [record for record in self.list(device_id, strict=strict)
                      if record.get("state") in _RECOVERABLE]
        if len(candidates) > 1:
            raise ValueError(
                "multiple recoverable records for device: %s — resolve them "
                "before undeploying" % device_id)
        return candidates[0] if candidates else None
