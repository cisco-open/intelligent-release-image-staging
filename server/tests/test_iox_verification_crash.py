# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Crash, restart, and custody contracts for IOx verification.

The fixtures are deliberately local.  Transcript tests write the version-1
framing directly so a permissive reader cannot make the test pass.  Recovery
tests use only the frozen ``IoxController`` seam and its three-method transport
interface; the fakes model a device effect separately from durable command
evidence.  A raised ``BaseException`` represents abrupt process loss, not a
catchable operation error.

These are simulated interruption, restart-policy, and mocked syscall-ordering
tests. The separate real-worker matrix exercises SIGKILL and durable-store
restart; a synthetic boot-ID change is explicitly distinguished from a reboot.
No test claims power-loss guarantees or contacts a device.
"""
import base64
import copy
import hashlib
import importlib
import json
import os
import struct

import pytest


_CONTROLLER = "0123456789abcdef0123456789abcdef"
_TRANSACTION = "11111111111111111111111111111111"
_ATTEMPT = "22222222222222222222222222222222"
_OLD_ATTEMPT = "33333333333333333333333333333333"
_BOARD = "FOC1234CRASH"
_DEVICE = "edge-crash"
_RECORD = "record-crash"
_JOB = "0123456789abcdef"
_WRAPPER = "a" * 64
_HOST = "192.0.2.44"


def _verification_module():
    # Keep missing production modules out of collection.  The frozen red run
    # must execute every selector and report missing behavior as test failures.
    return importlib.import_module("iox_verification")


def _records_module():
    return importlib.import_module("deployment_records")


def _frame(record):
    payload = json.dumps(
        record, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert 1 <= len(payload) <= 65536
    return struct.pack("!I", len(payload)) + payload


class _Transcript(object):
    """Build exact framed transcript bytes and committed-prefix references."""

    def __init__(self, attempt_id=_ATTEMPT):
        self.attempt_id = attempt_id
        self.parts = []
        self.observed = 0
        self.dropped = 0
        self.truncated = False
        self.append({
            "schema_version": 1,
            "type": "header",
            "id": attempt_id,
            "attempt_id": attempt_id,
            "controller_id": _CONTROLLER,
            "created_at": 1,
        })

    def append(self, record):
        self.parts.append(_frame(record))

    def ack(self, revision, phase, event, at):
        self.append({
            "schema_version": 1,
            "type": "journal_ack",
            "record_id": _RECORD,
            "transaction_id": _TRANSACTION,
            "revision": revision,
            "phase": phase,
            "event": event,
            "at": at,
        })

    def command(self, command_id, purpose, stdout, observed_state=None,
                transition_response=None, record_id=_RECORD,
                revision=0, phase="observed", started_at=2,
                finished_at=3):
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        self.append({
            "schema_version": 1,
            "type": "command_start",
            "command_id": command_id,
            "kind": "ssh",
            "purpose": purpose,
            "board_identity": _BOARD,
            "record_id": record_id,
            "transaction_id": None if record_id is None else _TRANSACTION,
            "revision": None if record_id is None else revision,
            "phase": None if record_id is None else phase,
            "started_at": started_at,
        })
        if stdout:
            self.append({
                "schema_version": 1,
                "type": "stream",
                "command_id": command_id,
                "stream": "stdout",
                "offset": 0,
                "data_b64": base64.b64encode(stdout).decode("ascii"),
            })
            self.observed += len(stdout)
        spans = [{"offset": 0, "length": len(stdout)}] if stdout else []
        self.append({
            "schema_version": 1,
            "type": "command_end",
            "command_id": command_id,
            "finished_at": finished_at,
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "framing_complete": True,
            "error_category": None,
            "stdout_observed_bytes": len(stdout),
            "stderr_observed_bytes": 0,
            "stdout_dropped_bytes": 0,
            "stderr_dropped_bytes": 0,
            "payload_spans": spans,
            "observed_state": observed_state,
            "transition_response": transition_response,
        })
        return {
            "state": observed_state,
            "observed_at": finished_at,
            "command_id": command_id,
            "transcript_id": self.attempt_id,
            "stdout_offset": 0,
            "stdout_length": len(stdout),
            "stderr_offset": 0,
            "stderr_length": 0,
            "returncode": 0,
            "timed_out": False,
            "truncated": False,
            "framing_complete": True,
        }

    def bytes(self):
        return b"".join(self.parts)

    def reference(self):
        return {
            "id": self.attempt_id,
            "attempt_id": self.attempt_id,
            "stored_bytes": len(self.bytes()),
            "observed_bytes": self.observed,
            "dropped_bytes": self.dropped,
            "truncated": self.truncated,
        }


def _confirmed_transcript(ack_after_disable=False):
    transcript = _Transcript()
    initial = transcript.command(
        1, "verification_read",
        b"App signature verification: enabled\n", "enabled",
        record_id=None, revision=None, phase=None,
        started_at=2, finished_at=3)
    pre_disable = transcript.command(
        2, "verification_read",
        b"App signature verification: enabled\n", "enabled",
        revision=0, phase="observed", started_at=4, finished_at=5)
    if not ack_after_disable:
        transcript.ack(1, "disable_intent", "disable_intent", 6)
    transcript.command(
        3, "verification_disable",
        b"App hosting verification disabled successfully\n",
        transition_response="disabled_successfully",
        revision=1, phase="disable_intent", started_at=7, finished_at=8)
    if ack_after_disable:
        transcript.ack(1, "disable_intent", "disable_intent", 9)
    disabled = transcript.command(
        4, "verification_read",
        b"App signature verification: disabled\n", "disabled",
        revision=1, phase="disable_intent", started_at=10, finished_at=11)
    return transcript, initial, pre_disable, disabled


def _journal(phase="observed", transcript_ref=None, initial=None,
             pre_disable=None, disabled=None):
    if transcript_ref is None:
        raise ValueError("a journal fixture requires its actual committed transcript prefix")
    if initial is None:
        initial = _observation("enabled", 1, 3)
    unresolved = phase in (
        "disable_intent", "disabled_confirmed", "installing",
        "ownership_probe", "restore_intent", "indeterminate")
    revisions = {
        "observed": 0, "disable_intent": 1, "disabled_confirmed": 2,
        "installing": 3, "ownership_probe": 4, "restore_intent": 5,
        "restored": 6, "unchanged": 1, "relinquished": 5,
        "indeterminate": 5,
    }
    after_disable = phase in (
        "disabled_confirmed", "installing", "ownership_probe",
        "restore_intent", "restored", "relinquished", "indeterminate")
    current = "disabled" if phase in (
        "disabled_confirmed", "installing", "ownership_probe",
        "restore_intent") else "enabled"
    if phase == "indeterminate":
        current = "unknown"
    if phase in ("restored", "relinquished"):
        current = "enabled"
    confirmation = None
    if after_disable:
        confirmation = {
            "confirmed_at": 11,
            "pre_disable_command_id": 2,
            "disable_command_id": 3,
            "disabled_readback_command_id": 4,
            "transition_response": "disabled_successfully",
        }
    restore = None
    if phase in ("restore_intent", "restored", "relinquished"):
        restore = _observation(
            "enabled" if phase in ("restored", "relinquished") else "disabled",
            5, 15)
    error = None
    if phase == "indeterminate":
        error = {
            "category": "reconciliation_required",
            "detail": "recovery cannot infer a prior command effect",
            "at": 16,
            "transcript_id": _ATTEMPT,
        }
    return {
        "schema_version": 1,
        "transaction_id": _TRANSACTION,
        "revision": revisions[phase],
        "record_id": _RECORD,
        "controller_id": _CONTROLLER,
        "board_identity": _BOARD,
        "wrapper_sha256": _WRAPPER,
        "package_sign_present": False,
        "package_cert_present": False,
        "prior_state": "enabled",
        "current_state": current,
        "phase": phase,
        "unresolved": unresolved,
        "created_at": 3,
        "updated_at": 16 if phase != "observed" else 3,
        "observed_at": 16 if phase == "indeterminate" else 3,
        "terminal_at": 16 if not unresolved and phase != "observed" else None,
        "initial_observation": initial,
        "pre_disable_observation": pre_disable if pre_disable is not None else (
            _observation("enabled", 2, 5) if phase != "observed" else None),
        "disable_confirmation": confirmation,
        "restore_observation": restore,
        "error": error,
        "transcript_refs": [copy.deepcopy(transcript_ref)],
    }


def _observation(state, command_id, at):
    payload = ("App signature verification: %s\n" % state).encode("ascii")
    return {
        "state": state,
        "observed_at": at,
        "command_id": command_id,
        "transcript_id": _ATTEMPT,
        "stdout_offset": 0,
        "stdout_length": len(payload),
        "stderr_offset": 0,
        "stderr_length": 0,
        "returncode": 0,
        "timed_out": False,
        "truncated": False,
        "framing_complete": True,
    }


def _deployment_record(journal=None, adopted=False, state="active"):
    record = {
        "record_id": _RECORD,
        "controller_id": _CONTROLLER,
        "device_id": _DEVICE,
        "inventory_revision": 1,
        "plan_hash": "b" * 64,
        "resolved": {
            "platform": "iox",
            "management_type": "routed",
            "renderer": "v1",
            "device_ip": _HOST,
            "device_identity": _BOARD,
            "model": "C9300-48UXM",
            "os_family": "xe",
        },
        "preflight": {"status": "passed", "device_identity": _BOARD},
        "resources": [{"kind": "iox-app", "ownership": "iris-created"}],
        "state": state,
        "timestamps": {"planned_at": 1, "finished_at": 2},
    }
    if adopted:
        record["adopted"] = True
    if journal is not None:
        record["iox_verification"] = copy.deepcopy(journal)
    return record


def _mkdir(path):
    if not os.path.isdir(path):
        os.makedirs(path, 0o700)
    os.chmod(path, 0o700)


def _authority_layout(tmp_path, transcripts=None):
    root = str(tmp_path)
    iox = os.path.join(root, "iox")
    _mkdir(iox)
    for name in ("locks", "sessions", "transcripts", "snapshots"):
        _mkdir(os.path.join(iox, name))
    authority = {
        "schema_version": 1,
        "controller_id": _CONTROLLER,
        "record_store": os.path.realpath(
            os.path.join(root, "deployment_records.json")),
    }
    authority_path = os.path.join(iox, "authority.json")
    with open(authority_path, "w") as stream:
        json.dump(authority, stream, sort_keys=True, separators=(",", ":"))
    os.chmod(authority_path, 0o600)
    for attempt_id, content in (transcripts or {}).items():
        path = os.path.join(iox, "transcripts", attempt_id + ".transcript")
        with open(path, "wb") as stream:
            stream.write(content)
        os.chmod(path, 0o600)
    return iox


def _write_record_store(tmp_path, record):
    path = os.path.join(str(tmp_path), "deployment_records.json")
    with open(path, "w") as stream:
        json.dump({"records": {record["record_id"]: record}}, stream,
                  sort_keys=True, separators=(",", ":"))
    os.chmod(path, 0o600)
    return path


def _write_confirmed_authority(tmp_path, ack_after_disable=False,
                               tail=b"", reference_tail=False):
    transcript, initial, pre_disable, disabled = _confirmed_transcript(
        ack_after_disable=ack_after_disable)
    committed = transcript.bytes()
    reference = transcript.reference()
    content = committed + tail
    if reference_tail:
        reference["stored_bytes"] = len(content)
    journal = _journal(
        "disabled_confirmed", reference, initial, pre_disable, disabled)
    journal["revision"] = 2
    journal["current_state"] = "disabled"
    journal["observed_at"] = disabled["observed_at"]
    journal["updated_at"] = disabled["observed_at"]
    journal["disable_confirmation"] = {
        "confirmed_at": disabled["observed_at"],
        "pre_disable_command_id": pre_disable["command_id"],
        "disable_command_id": 3,
        "disabled_readback_command_id": disabled["command_id"],
        "transition_response": "disabled_successfully",
    }
    _authority_layout(tmp_path, {_ATTEMPT: content})
    _write_record_store(tmp_path, _deployment_record(journal))
    return committed, content


class _AttrDict(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class _AbruptControllerDeath(BaseException):
    pass


class _Cancel(object):
    def __init__(self, value=False):
        self.value = value

    def is_set(self):
        return self.value

    def __call__(self):
        return self.value

    def wait(self, _timeout=None):
        return self.value


def _seed_phase(tmp_path, phase):
    """Write self-consistent starting evidence; later events use the real store."""
    transcript, initial, pre, disabled = _confirmed_transcript()
    if phase in (None, "observed", "unchanged", "disable_intent"):
        transcript = _Transcript()
        initial = transcript.command(1, "verification_read",
            b"App signature verification: enabled\n", "enabled", record_id=None)
        pre = None
        if phase == "disable_intent":
            pre = transcript.command(2, "verification_read",
                b"App signature verification: enabled\n", "enabled",
                started_at=4, finished_at=5)
            transcript.ack(1, "disable_intent", "disable_intent", 6)
    journal = None if phase is None else _journal(
        phase, transcript.reference(), initial, pre, disabled)
    if journal is not None:
        journal["pre_disable_observation"] = pre
        journal["observed_at"] = (11 if journal["disable_confirmation"] else
                                  5 if pre else 3)
        journal["current_state"] = ("disabled" if journal["disable_confirmation"] else "enabled")
        if phase == "unchanged":
            journal["package_sign_present"] = True
        if phase in ("restore_intent", "restored", "relinquished"):
            transcript.ack(4, "ownership_probe", "ownership_probe", 12)
            probe = transcript.command(5, "verification_read",
                b"App signature verification: disabled\n", "disabled",
                revision=4, phase="ownership_probe", started_at=13, finished_at=14)
            journal["restore_observation"] = probe
            journal["observed_at"] = 14
            if phase in ("restored", "relinquished"):
                transcript.ack(5, "restore_intent", "restore_intent", 15)
                transcript.command(6, "verification_enable",
                    b"App hosting verification enabled successfully\n",
                    transition_response="enabled_successfully", revision=5,
                    phase="restore_intent", started_at=16, finished_at=17)
                enabled = transcript.command(7, "verification_read",
                    b"App signature verification: enabled\n", "enabled",
                    revision=5, phase="restore_intent", started_at=18, finished_at=19)
                journal["restore_observation"] = enabled
                journal["observed_at"] = 19
                journal["current_state"] = "enabled"
                journal["terminal_at"] = 20
        if phase == "relinquished":
            journal["revision"] = 6
        journal["updated_at"] = max(journal["updated_at"], journal["observed_at"],
                                     journal["terminal_at"] or 0)
        journal["transcript_refs"] = [transcript.reference()]
    _authority_layout(tmp_path, {transcript.attempt_id: transcript.bytes()})
    _write_record_store(tmp_path, _deployment_record(journal))


class _FakeStore(object):
    """Trace adapter delegating all authority decisions to the real durable store."""

    def __init__(self, tmp_path, phase=None, trace=None, existing=False):
        self.path = os.path.join(str(tmp_path), "deployment_records.json")
        self.trace = trace if trace is not None else []
        if not existing:
            _seed_phase(tmp_path, phase)
        self.delegate = _records_module().DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
        self.crash_after_event = None

    @property
    def record(self):
        return _read_json(self.path)["records"][_RECORD]

    @record.setter
    def record(self, value):
        _write_record_store(os.path.dirname(self.path), value)

    @property
    def journal(self):
        return self.record.get("iox_verification")

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def iox_obligations(self, board_identity):
        self.trace.append(("obligations", board_identity))
        return self.delegate.iox_obligations(board_identity)

    def iox_event(self, record_id, transaction_id, expected_revision,
                  expected_phase, event, evidence, capability=None):
        result = self.delegate.iox_event(record_id, transaction_id,
            expected_revision, expected_phase, event, evidence, capability=capability)
        self.trace.append(("journal", event))
        if self.crash_after_event == event:
            raise _AbruptControllerDeath("after durable %s" % event)
        return result


class _Device(object):
    def __init__(self, state="disabled"):
        self.state = state
        self.mutations = []


class _FakeTransport(object):
    """Frozen command/upload/cancel seam with separate effect/evidence points."""

    def __init__(self, device, trace, attempt_id=_ATTEMPT,
                 crash_after_effect=None, reap=True):
        self.device = device
        self.trace = trace
        self.attempt_id = attempt_id
        self.transcript_ref = None
        self.crash_after_effect = crash_after_effect
        self.reap = reap

    @staticmethod
    def _purpose(command_bytes):
        if isinstance(command_bytes, bytes):
            text = command_bytes.decode("ascii", "ignore").lower()
        else:
            text = str(command_bytes).lower()
        if "show version" in text:
            return "identity"
        if "verification disable" in text:
            return "disable"
        if "verification enable" in text:
            return "enable"
        if "show app-hosting infra" in text:
            return "read"
        if "show app-hosting list" in text:
            return "app_list"
        return "application"

    def command(self, command_id, command_bytes, phase_deadline):
        assert command_id > 0
        assert phase_deadline is not None
        purpose = self._purpose(command_bytes)
        self.trace.append(("command_start", purpose))
        if hasattr(self, "transcript"):
            self.transcript.append(dict(self.config["command_contexts"][command_id]))
        if purpose == "disable":
            self.device.state = "disabled"
            self.device.mutations.append("disable")
            stdout = b"App hosting verification disabled successfully\n"
        elif purpose == "enable":
            self.device.state = "enabled"
            self.device.mutations.append("enable")
            stdout = b"App hosting verification enabled successfully\n"
        elif purpose == "identity":
            stdout = (
                b"Cisco IOS XE Software, Version 17.15.01\n"
                b"cisco C9300-48UXM (X86) processor\n"
                b"Processor board ID " + _BOARD.encode("ascii") + b"\n")
        elif purpose == "app_list":
            stdout = b"App id State\niris DEPLOYED\n"
        elif purpose == "application":
            stdout = b""
        elif self.device.state == "unknown":
            stdout = b"verification state unavailable\n"
        else:
            stdout = ("App signature verification: %s\n" %
                      self.device.state).encode("ascii")
        if purpose in ("disable", "enable"):
            self.trace.append(("device_effect", purpose))
            if self.crash_after_effect == purpose:
                raise _AbruptControllerDeath("after %s effect" % purpose)
        if hasattr(self, "transcript"):
            if stdout:
                self.transcript.append({
                "schema_version": 1, "type": "stream", "command_id": command_id,
                "stream": "stdout", "offset": 0,
                "data_b64": base64.b64encode(stdout).decode("ascii")})
            self.transcript.append({
                "schema_version": 1, "type": "command_end", "command_id": command_id,
                "finished_at": 100, "returncode": 0, "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
                "framing_complete": True, "error_category": None,
                "stdout_observed_bytes": len(stdout), "stderr_observed_bytes": 0,
                "stdout_dropped_bytes": 0, "stderr_dropped_bytes": 0,
                "payload_spans": [{"offset": 0, "length": len(stdout)}],
                "observed_state": self.device.state if purpose == "read" else None,
                "transition_response": {"disable": "disabled_successfully",
                                        "enable": "enabled_successfully"}.get(purpose)})
            self.transcript_ref = self.transcript.reference()
        self.trace.append(("command_end", purpose))
        return _AttrDict({
            "returncode": 0,
            "timed_out": False,
            "stdout": stdout,
            "stderr": b"",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "framing_complete": True,
            "error_category": None,
            "transcript_ref": copy.deepcopy(self.transcript_ref),
        })

    def upload(self, snapshot_fd, remote_path, phase_deadline):
        assert isinstance(snapshot_fd, int) and remote_path and phase_deadline is not None
        # The controller supplies one unstarted SCP command context per upload.
        contexts = [value for value in self.config["command_contexts"].values()
                    if value["kind"] == "scp"]
        context = max(contexts, key=lambda value: value["command_id"])
        command_id = context["command_id"]
        self.transcript.append(dict(context))
        self.trace.append(("upload", remote_path))
        self.transcript.append({
            "schema_version": 1, "type": "command_end", "command_id": command_id,
            "finished_at": 100, "returncode": 0, "timed_out": False,
            "stdout_truncated": False, "stderr_truncated": False,
            "framing_complete": True, "error_category": None,
            "stdout_observed_bytes": 0, "stderr_observed_bytes": 0,
            "stdout_dropped_bytes": 0, "stderr_dropped_bytes": 0,
            "payload_spans": [], "observed_state": None, "transition_response": None})
        self.transcript_ref = self.transcript.reference()
        return _AttrDict({
            "returncode": 0, "timed_out": False, "stdout": b"", "stderr": b"",
            "stdout_truncated": False, "stderr_truncated": False,
            "framing_complete": True, "error_category": None,
            "transcript_ref": copy.deepcopy(self.transcript_ref)})

    def cancel_and_reap(self, deadline):
        assert deadline is not None
        self.trace.append(("signal", "TERM"))
        if not self.reap:
            self.trace.append(("signal", "KILL"))
        self.trace.append(("descendants", "reaped" if self.reap else "unreaped"))
        return self.reap


class _TransportFactory(object):
    def __init__(self, transport, tmp_path):
        self.transport = transport
        self.tmp_path = tmp_path
        self.calls = []

    def __call__(self, *args):
        assert len(args) == 4, "transport factory requires four positional arguments"
        config, transcript, supervisor, monotonic_fn = args
        self.calls.append((config, transcript, supervisor, monotonic_fn))
        self.transport.config = config
        self.transport.supervisor = supervisor
        self.transport.transcript = transcript
        self.transport.attempt_id = config["attempt_id"]
        self.transport.transcript_ref = transcript.reference()
        return self.transport


def _controller(tmp_path, store, transport, test_limits=None, **overrides):
    module = _verification_module()
    if not os.path.exists(os.path.join(str(tmp_path), "iox", "authority.json")):
        _authority_layout(tmp_path)
    config = _AttrDict({
        "state_dir": str(tmp_path),
        "controller_id": _CONTROLLER,
        "record_store": "deployment_records.json",
        "session_seconds": 7200,
        "restoration_reserve_seconds": 180,
        "application_id": "iris",
    })
    config.update(overrides)
    if test_limits is not None:
        config["test_limits"] = dict(test_limits)
    clock = [100.0]

    def monotonic():
        clock[0] += 0.01
        return clock[0]

    factory = _TransportFactory(transport, tmp_path)
    controller = module.IoxController(
        store, config, factory, lambda: 100, monotonic)
    return controller, factory


def _concurrent_fence_admission_worker(
        root, board, attempt_id, limits, barrier, results):
    from pathlib import Path

    module = _verification_module()
    tmp_path = Path(root)
    store = _FakeStore(tmp_path, existing=True)
    controller, unused_factory = _controller(
        tmp_path, store, _FakeTransport(_Device("enabled"), []),
        test_limits=limits)
    request = _AttrDict(
        action="uninstall", device_id=_DEVICE, job_id=_JOB,
        teardown_mode="force_agent_only", record_id=None)
    attempt = module._Attempt(
        controller, "uninstall", request, _Cancel(), False)
    attempt.attempt_id = attempt_id
    attempt.board = board
    attempt.transcript = _Transcript(attempt_id)
    attempt.supervisor = _AttrDict(
        pid=os.getpid(), start_ticks=module._supervisor_start(os.getpid()))
    try:
        barrier.wait(10)
        controller._admit_fence(attempt)
        results.put("admitted")
    except BaseException as exc:
        results.put(getattr(exc, "category", type(exc).__name__))
    finally:
        controller.close()


def _host_boot_id():
    with open("/proc/sys/kernel/random/boot_id") as stream:
        return stream.read().strip()


def _board_key(board_identity):
    return hashlib.sha256(
        b"IRIS-IOX-BOARD-v1\0" + board_identity.encode("ascii")).hexdigest()


def _write_fence(tmp_path, state="active", boot_id=None,
                 attempt_id=_OLD_ATTEMPT, device_id=_DEVICE,
                 record_id=None, operation="recover",
                 teardown_mode="none"):
    transcript = _Transcript(attempt_id)
    iox = _authority_layout(tmp_path, {attempt_id: transcript.bytes()})
    ref = transcript.reference()
    fence = {
        "schema_version": 1,
        "controller_id": _CONTROLLER,
        "board_identity": _BOARD,
        "attempt_id": attempt_id,
        "device_id": device_id,
        "job_id": _JOB,
        "operation": operation,
        "teardown_mode": teardown_mode,
        "record_id": record_id,
        "boot_id": boot_id or _host_boot_id(),
        "supervisor_pid": 999999,
        "supervisor_start_ticks": 1,
        "transcript_ref": ref,
        "state": state,
        "created_at": 1,
        "updated_at": 2,
    }
    # ``board-lock-key`` includes the literal ``.lock`` suffix.  The fence is
    # therefore ``<sha256>.lock.json``, beside (not in place of) the stable
    # ``iox/locks/<sha256>.lock`` inode.
    path = os.path.join(iox, "sessions", _board_key(_BOARD) + ".lock.json")
    with open(path, "w") as stream:
        json.dump(fence, stream, sort_keys=True, separators=(",", ":"))
    os.chmod(path, 0o600)
    return path, fence


def _read_json(path):
    with open(path) as stream:
        return json.load(stream)


def _read_bytes(path):
    with open(path, "rb") as stream:
        return stream.read()


def _result_keys(result):
    return set(result) if isinstance(result, dict) else set(vars(result))


# Durable transcript and journal authority ---------------------------------


def test_confirmation_requires_durable_intent_ack_before_disable_command(tmp_path):
    _write_confirmed_authority(tmp_path, ack_after_disable=True)
    records = _records_module()
    store = records.DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    before = _read_bytes(store.path)
    with pytest.raises(ValueError):
        store.iox_obligations(_BOARD)
    assert _read_bytes(store.path) == before


def test_confirmation_requires_command_end_inside_committed_prefix(tmp_path):
    committed, _content = _write_confirmed_authority(tmp_path)
    # Point the journal into the middle of the final framed command_end.  The
    # bytes remain on disk, but uncommitted evidence cannot prove ownership.
    path = os.path.join(str(tmp_path), "deployment_records.json")
    document = _read_json(path)
    journal = document["records"][_RECORD]["iox_verification"]
    journal["transcript_refs"][0]["stored_bytes"] = len(committed) - 3
    with open(path, "w") as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
    store = _records_module().DeploymentRecordStore(
        str(tmp_path), now_fn=lambda: 100)
    with pytest.raises(ValueError):
        store.iox_obligations(_BOARD)


def test_unreferenced_complete_or_partial_tail_cannot_change_confirmation(tmp_path):
    tail_record = _frame({
        "schema_version": 1, "type": "command_start", "command_id": 99,
        "kind": "ssh", "purpose": "verification_enable",
        "board_identity": _BOARD, "record_id": _RECORD,
        "transaction_id": _TRANSACTION, "revision": 2,
        "phase": "disabled_confirmed", "started_at": 20,
    })
    committed, _content = _write_confirmed_authority(
        tmp_path, tail=tail_record + b"\x00\x00")
    store = _records_module().DeploymentRecordStore(
        str(tmp_path), now_fn=lambda: 100)
    obligations = store.iox_obligations(_BOARD)
    assert len(obligations) == 1
    journal = obligations[0]
    assert journal["phase"] == "disabled_confirmed"
    assert journal["current_state"] == "disabled"
    assert journal["transcript_refs"][0]["stored_bytes"] == len(committed)
    assert journal["disable_confirmation"]["disable_command_id"] == 3


def test_referenced_partial_tail_is_authority_failure_not_repair(tmp_path):
    _write_confirmed_authority(
        tmp_path, tail=b"\x00\x00", reference_tail=True)
    store = _records_module().DeploymentRecordStore(
        str(tmp_path), now_fn=lambda: 100)
    before = _read_bytes(store.path)
    with pytest.raises(ValueError):
        store.iox_obligations(_BOARD)
    assert _read_bytes(store.path) == before


# Recovery state machine ---------------------------------------------------


@pytest.mark.parametrize(
    "phase,live_state,expected_phase,enable_count,expected_code", [
    ("observed", "enabled", "observed", 0, 0),
    ("disable_intent", "enabled", "relinquished", 0, 0),
    ("disable_intent", "disabled", "indeterminate", 0, 3),
    ("disable_intent", "unknown", "indeterminate", 0, 3),
    ("disabled_confirmed", "enabled", "relinquished", 0, 0),
    ("disabled_confirmed", "disabled", "restored", 1, 0),
    ("disabled_confirmed", "unknown", "ownership_probe", 0, 4),
    ("installing", "enabled", "relinquished", 0, 0),
    ("installing", "disabled", "restored", 1, 0),
    ("installing", "unknown", "ownership_probe", 0, 4),
    ("ownership_probe", "enabled", "indeterminate", 0, 3),
    ("ownership_probe", "disabled", "indeterminate", 0, 3),
    ("ownership_probe", "unknown", "indeterminate", 0, 3),
    ("restore_intent", "enabled", "relinquished", 0, 0),
    ("restore_intent", "disabled", "indeterminate", 0, 3),
    ("restore_intent", "unknown", "indeterminate", 0, 3),
    ("restored", "enabled", "restored", 0, 0),
    ("unchanged", "enabled", "unchanged", 0, 0),
    ("relinquished", "enabled", "relinquished", 0, 0),
    ("indeterminate", "enabled", "indeterminate", 0, 3),
])
def test_restart_recovery_phase_matrix(
        tmp_path, phase, live_state, expected_phase, enable_count,
        expected_code):
    trace = []
    store = _FakeStore(tmp_path, phase, trace)
    device = _Device(live_state)
    transport = _FakeTransport(device, trace)
    controller, _factory = _controller(tmp_path, store, transport)
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert store.journal["phase"] == expected_phase
    assert device.mutations.count("enable") == enable_count
    assert device.mutations.count("disable") == 0
    assert result["result_code"] == expected_code
    if phase == "ownership_probe":
        # A recovered probe has no continuation.  Even a live enabled read
        # cannot turn it into relinquishment.
        assert not [item for item in trace if item == ("command_start", "read")]


def test_confirmed_recovery_orders_probe_then_restore_intent_then_enable(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    device = _Device("disabled")
    transport = _FakeTransport(device, trace)
    controller, _factory = _controller(tmp_path, store, transport)
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    probe = trace.index(("journal", "ownership_probe"))
    read = trace.index(("command_start", "read"))
    intent = trace.index(("journal", "restore_intent"))
    enable = trace.index(("command_start", "enable"))
    effect = trace.index(("device_effect", "enable"))
    evidence = trace.index(("command_end", "enable"))
    restored = trace.index(("journal", "restored"))
    assert probe < read < intent < enable < effect < evidence < restored
    assert result["result_code"] == 0
    assert result["recovery_code"] == 0


def test_disable_effect_without_durable_evidence_never_auto_enables(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disable_intent", trace)
    device = _Device("enabled")
    first = _FakeTransport(
        device, trace, crash_after_effect="disable")
    # The initial attempt's private continuation is represented by the one
    # scripted disable.  Its effect occurs, but no command_end or confirmation.
    with pytest.raises(_AbruptControllerDeath):
        first.command(3, b"app-hosting verification disable", 100.0)
    assert device.state == "disabled"
    assert ("command_end", "disable") not in trace

    restarted = _FakeTransport(device, trace)
    controller, _factory = _controller(tmp_path, store, restarted)
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert store.journal["phase"] == "indeterminate"
    assert device.mutations == ["disable"]
    assert result["result_code"] == 3


def test_crash_after_enabled_probe_before_relinquishment_becomes_indeterminate(
        tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "ownership_probe", trace)
    device = _Device("enabled")
    # Persisted ownership_probe plus an uncommitted live result cannot be used
    # by a successor.  The successor owns no probe-result capability.
    trace.extend([("command_start", "read"), ("command_end", "read")])
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(device, trace))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert store.journal["phase"] == "indeterminate"
    assert device.mutations == []
    assert result["result_code"] == 3


def test_crash_after_restore_intent_enable_effect_never_replays_enable(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "restore_intent", trace)
    device = _Device("disabled")
    first = _FakeTransport(device, trace, crash_after_effect="enable")
    with pytest.raises(_AbruptControllerDeath):
        first.command(6, b"app-hosting verification enable", 100.0)
    assert device.state == "enabled"
    restarted = _FakeTransport(device, trace)
    controller, _factory = _controller(tmp_path, store, restarted)
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert store.journal["phase"] == "relinquished"
    assert device.mutations == ["enable"]
    assert result["result_code"] == 0


def test_crash_after_restore_intent_with_disabled_read_is_indeterminate(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "restore_intent", trace)
    device = _Device("disabled")
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(device, trace))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert store.journal["phase"] == "indeterminate"
    assert device.mutations == []
    assert result["result_code"] == 3


# Supervisor fences and descendant custody --------------------------------


def test_same_boot_dead_controller_and_supervisor_fence_blocks_mutation(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    fence_path, original = _write_fence(
        tmp_path, state="active", boot_id=_host_boot_id(),
        record_id=_RECORD)
    device = _Device("disabled")
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(device, trace))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 5
    assert result["iox_session"]["mutation_blocked"] is True
    assert device.mutations == []
    assert store.journal["phase"] == "disabled_confirmed"
    assert _read_json(fence_path) == original


def test_reaped_fence_does_not_claim_verification_restoration(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    _write_fence(tmp_path, state="reaped", boot_id=_host_boot_id(),
                 record_id=_RECORD)
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(_Device("disabled"), trace))
    try:
        summary = controller.summary_for_device(_DEVICE)
    finally:
        controller.close()
    assert summary["iox_sessions"][0]["state"] == "reaped"
    assert summary["iox_sessions"][0]["mutation_blocked"] is False
    assert summary["iox_verification_obligations"][0]["unresolved"] is True


def test_changed_boot_replaces_fence_before_new_board_command(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disable_intent", trace)
    old_boot = "00000000-0000-4000-8000-000000000000"
    path, old = _write_fence(
        tmp_path, state="active", boot_id=old_boot, record_id=_RECORD)
    device = _Device("enabled")
    transport = _FakeTransport(device, trace)
    transport.crash_after_effect = None

    original_command = transport.command

    def crash_on_recovery_read(command_id, command_bytes, phase_deadline):
        purpose = transport._purpose(command_bytes)
        if purpose == "read":
            current = _read_json(path)
            assert current["boot_id"] == _host_boot_id()
            assert current["attempt_id"] != old["attempt_id"]
            assert current["state"] == "active"
            raise _AbruptControllerDeath("after changed-boot replacement")
        return original_command(command_id, command_bytes, phase_deadline)

    transport.command = crash_on_recovery_read
    controller, _factory = _controller(tmp_path, store, transport)
    try:
        with pytest.raises(_AbruptControllerDeath):
            controller.recover_board(_BOARD, _Cancel())
        current = _read_json(path)
        assert current["boot_id"] == _host_boot_id()
        assert current["attempt_id"] != old["attempt_id"]
        assert current["state"] == "active"
        assert store.journal["phase"] == "disable_intent"
    finally:
        controller.close()


def test_uncertain_changed_boot_fence_replacement_stops_recovery(
        tmp_path, monkeypatch):
    module = _verification_module()
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    path, old = _write_fence(
        tmp_path, state="active",
        boot_id="00000000-0000-4000-8000-000000000000",
        record_id=_RECORD)
    real_replace = module.os.replace

    def fail_session_replace(source, destination):
        if destination == path:
            raise OSError("injected fence replace failure")
        return real_replace(source, destination)

    monkeypatch.setattr(module.os, "replace", fail_session_replace)
    device = _Device("disabled")
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(device, trace))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 5
    assert _read_json(path) == old
    assert device.mutations == []
    assert store.journal["phase"] == "disabled_confirmed"


def test_cancellation_reaps_descendants_before_reaped_fence_and_result(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    transport = _FakeTransport(_Device("disabled"), trace, reap=True)
    controller, _factory = _controller(tmp_path, store, transport)
    try:
        result = controller.recover_board(_BOARD, _Cancel(True))
    finally:
        controller.close()
    assert result["result_code"] == 130
    assert result["recovery_code"] == 0
    assert result["iox_session"]["state"] == "reaped"
    assert result["iox_session"]["mutation_blocked"] is False
    assert transport.device.state == "enabled"
    assert transport.device.mutations == ["enable"]
    assert trace.index(("journal", "restored")) < trace.index(
        ("descendants", "reaped"))
    fence_path = os.path.join(
        str(tmp_path), "iox", "sessions", _board_key(_BOARD) + ".lock.json")
    generated_fence = _read_json(fence_path)
    assert generated_fence["state"] == "reaped"
    _assert_generated_fence_schema(generated_fence)


def test_cancellation_with_unreaped_descendant_keeps_active_fence(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    transport = _FakeTransport(_Device("disabled"), trace, reap=False)
    controller, _factory = _controller(tmp_path, store, transport)
    try:
        result = controller.recover_board(_BOARD, _Cancel(True))
    finally:
        controller.close()
    assert result["result_code"] == 130
    assert result["recovery_code"] == 5
    assert result["iox_session"]["state"] == "active"
    assert result["iox_session"]["mutation_blocked"] is True
    assert ("signal", "TERM") in trace
    assert ("signal", "KILL") in trace
    assert ("descendants", "unreaped") in trace
    fence_path = os.path.join(
        str(tmp_path), "iox", "sessions", _board_key(_BOARD) + ".lock.json")
    assert _read_json(fence_path)["state"] == "active"


def test_supervisor_eof_reap_uses_only_the_original_absolute_deadline():
    import signal
    import subprocess
    import sys
    import time

    module = _verification_module()
    deadline = time.monotonic() + 0.8
    supervisor = module._SupervisorClient.start(
        None, time.monotonic, deadline)
    child = supervisor.popen(
        [sys.executable, "-c",
         "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={}, pass_fds=(), close_fds=True,
        start_new_session=True, role="transport",
        timeout=max(0.01, deadline - time.monotonic()))
    try:
        assert supervisor.abandon(deadline) is True
        assert supervisor._process.poll() is not None
        assert time.monotonic() <= deadline + 0.25
    finally:
        for pid in (child.pid, supervisor.pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass


@pytest.mark.parametrize("timeout,term_end", [(3.0, 3.0), (10.0, 5.0)])
def test_supervisor_reap_limits_term_phase_to_five_seconds(
        monkeypatch, timeout, term_end):
    import signal

    module = _verification_module()
    now = [0.0]
    signals = []

    class Process(object):
        pid = 4242
        returncode = None

        def poll(self):
            return self.returncode

    process = Process()
    entries = {"token": {
        "process": process, "root_started": 1, "known": {}}}

    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        module.time, "sleep", lambda seconds: now.__setitem__(
            0, now[0] + seconds))
    monkeypatch.setattr(module, "_supervisor_refresh", lambda unused: None)
    monkeypatch.setattr(module, "_supervisor_children", lambda unused: set())
    monkeypatch.setattr(module, "_supervisor_start", lambda unused: None)

    def capture_signal(unused_entry, sent):
        signals.append((sent, now[0]))
        if sent == signal.SIGKILL:
            process.returncode = -signal.SIGKILL

    monkeypatch.setattr(module, "_supervisor_signal", capture_signal)
    reaped, remaining = module._supervisor_reap(
        entries, ["token"], timeout)
    assert reaped is True
    assert remaining == 0
    assert signals[0] == (signal.SIGTERM, 0.0)
    kill_at = [at for sent, at in signals if sent == signal.SIGKILL]
    assert len(kill_at) == 1
    assert term_end <= kill_at[0] <= term_end + 0.01
    assert now[0] <= timeout


def test_truncated_supervisor_packet_closes_all_received_descriptors():
    import socket
    import struct

    module = _verification_module()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET)
    source = os.open(os.devnull, os.O_RDONLY)
    before = len(os.listdir("/proc/self/fd"))
    try:
        rights = struct.pack("20i", *([source] * 20))
        sender.sendmsg(
            [b"{}"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        with pytest.raises(ValueError, match="truncated supervisor message"):
            module._supervisor_receive(receiver)
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(source)
        sender.close()
        receiver.close()


def test_unexpected_supervisor_ancillary_closes_prior_rights():
    import socket
    import struct

    module = _verification_module()
    descriptor = os.open(os.devnull, os.O_RDONLY)

    class Peer(object):
        def recvmsg(self, *unused):
            return (b"{}", [
                (socket.SOL_SOCKET, socket.SCM_RIGHTS,
                 struct.pack("i", descriptor)),
                (999, 999, b"unexpected"),
            ], 0, None)

    with pytest.raises(ValueError, match="unexpected supervisor ancillary"):
        module._supervisor_receive(Peer())
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("path", ["discover", "known"])
def test_post_flock_revalidation_failure_never_leaks_board_lock(
        tmp_path, monkeypatch, path):
    import fcntl

    module = _verification_module()
    trace = []
    store = _FakeStore(tmp_path, None, trace)
    transport = _FakeTransport(_Device("enabled"), trace)
    controller, unused = _controller(tmp_path, store, transport)

    class Supervisor(object):
        pid = os.getpid()
        start_ticks = 0
        def reap_all(self, deadline):
            return True
        def release(self, deadline):
            return True
        def abandon(self, deadline):
            return True

    monkeypatch.setattr(module._SupervisorClient, "start",
                        classmethod(lambda cls, *args: Supervisor()))
    monkeypatch.setattr(
        module, "_revalidate_board_lock",
        lambda *args: (_ for _ in ()).throw(
            ValueError("injected lock pathname replacement")))
    request = _AttrDict(
        device_id=_DEVICE, job_id=_JOB, record_id=None,
        teardown_mode="force_agent_only",
        target=_AttrDict(host=_HOST, port=22, platform="iox",
                         model="C9300-48UXM", os_family="xe"))
    attempt = module._Attempt(
        controller, "uninstall", request, _Cancel(), False)
    attempt.target = request.target
    attempt.board = _BOARD if path == "known" else None
    import iox_transport
    attempt.transcript = iox_transport._TranscriptWriter(
        str(tmp_path), attempt.attempt_id, _CONTROLLER, created_at=1)
    try:
        with pytest.raises((ValueError, module._ControllerFailure)):
            if path == "known":
                controller._acquire_known_board_lock(attempt)
            else:
                controller._discover_and_lock(attempt)
        lock_fd = module._open_board_lock(controller.lock_dir, _BOARD)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(lock_fd)
    finally:
        # Close a leaked descriptor on the rejected implementation so the red
        # regression cannot contaminate another selector in this process.
        lock_suffix = "/" + _board_key(_BOARD) + ".lock"
        for name in os.listdir("/proc/self/fd"):
            try:
                descriptor = int(name)
                if os.readlink("/proc/self/fd/" + name).endswith(lock_suffix):
                    os.close(descriptor)
            except (OSError, ValueError):
                pass
        controller.close()


# Visibility and bounded admission -----------------------------------------


def test_recordless_active_fence_survives_restart_and_remains_visible(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, None, trace)
    _write_fence(
        tmp_path, state="active", record_id=None, operation="uninstall",
        teardown_mode="force_agent_only")
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(_Device("enabled"), trace))
    try:
        summary = controller.summary_for_device(_DEVICE)
    finally:
        controller.close()
    assert summary["iox_verification_obligations"] == []
    assert summary["iox_sessions"] == [{
        "attempt_id": _OLD_ATTEMPT,
        "job_id": _JOB,
        "device_id": _DEVICE,
        "board_identity": _BOARD,
        "operation": "uninstall",
        "teardown_mode": "force_agent_only",
        "record_id": None,
        "state": "active",
        "mutation_blocked": True,
    }]


@pytest.mark.parametrize("adopted", [False, True])
def test_legacy_record_without_journal_does_not_hide_active_session(
        tmp_path, adopted):
    trace = []
    store = _FakeStore(tmp_path, None, trace)
    store.record = _deployment_record(None, adopted=adopted)
    _write_fence(
        tmp_path, state="active", record_id=_RECORD,
        operation="uninstall", teardown_mode="recorded")
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(_Device("enabled"), trace))
    try:
        summary = controller.summary_for_device(_DEVICE)
    finally:
        controller.close()
    assert summary["iox_verification_obligations"] == []
    assert summary["iox_sessions"][0]["record_id"] == _RECORD
    assert summary["iox_sessions"][0]["mutation_blocked"] is True
    assert "iox_verification" not in store.record


def test_terminal_unchanged_journal_does_not_hide_active_session(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "unchanged", trace)
    _write_fence(tmp_path, state="active", record_id=_RECORD)
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(_Device("enabled"), trace))
    try:
        summary = controller.summary_for_device(_DEVICE)
    finally:
        controller.close()
    assert summary["iox_verification_obligations"] == []
    assert summary["iox_sessions"][0]["state"] == "active"
    assert summary["iox_sessions"][0]["mutation_blocked"] is True


def test_low_test_limits_preserve_ordinary_and_shared_recovery_reserves(tmp_path):
    _verification_module()
    trace = []
    store = _FakeStore(tmp_path, "disable_intent", trace)
    iox = _authority_layout(tmp_path)
    # Two transcripts exhaust ordinary admission but leave the shared two-file
    # recovery pool available to unresolved journal and active-fence recovery.
    for index in range(1):
        attempt = ("%032x" % (index + 100))
        transcript = _Transcript(attempt)
        with open(os.path.join(iox, "transcripts", attempt + ".transcript"),
                  "wb") as stream:
            stream.write(transcript.bytes())
        os.chmod(
            os.path.join(iox, "transcripts", attempt + ".transcript"), 0o600)
    limits = {
        "session_files": 4,
        "transcript_files": 4,
        "ordinary_transcripts": 2,
        "active_fences": 2,
    }
    transport = _FakeTransport(_Device("enabled"), trace)
    controller, _factory = _controller(
        tmp_path, store, transport, test_limits=limits)
    try:
        # Recovery is admitted from the shared reserve even though a new
        # ordinary attempt at the same count must be refused.
        recovered = controller.recover_board(_BOARD, _Cancel())
        count_after_recovery = len(os.listdir(
            os.path.join(iox, "transcripts")))
        request = {
            "action": "install",
            "job_id": _JOB,
            "device_id": _DEVICE,
            "target": {"host": _HOST, "port": 22, "platform": "iox"},
            "credential_ref": "credential-crash",
            "record_id": None,
            "teardown_mode": "none",
            "wrapper_path": os.path.join(str(tmp_path), "wrapper.tar"),
        }
        refused = controller.run_install(
            request,
            lambda req, identity: pytest.fail("prepare crossed admission"),
            lambda req, identity: pytest.fail("preflight crossed admission"),
            lambda *_args: None,
            _Cancel())
    finally:
        controller.close()
    assert recovered["result_code"] == 0
    assert count_after_recovery == 3
    assert refused["result_code"] == 5
    assert refused["record_id"] is None
    assert len(os.listdir(os.path.join(iox, "transcripts"))) == 3


@pytest.mark.parametrize("test_limits", [
    {"session_files": 0, "transcript_files": 4,
     "ordinary_transcripts": 2, "active_fences": 2},
    {"session_files": 4, "transcript_files": 4,
     "ordinary_transcripts": 5, "active_fences": 2},
    {"session_files": 4, "transcript_files": 4,
     "ordinary_transcripts": 2, "active_fences": 2, "unknown": 1},
    {"session_files": True, "transcript_files": 4,
     "ordinary_transcripts": 2, "active_fences": 2},
    {"session_files": 8193, "transcript_files": 4,
     "ordinary_transcripts": 2, "active_fences": 2},
    {"transcript_files": 4,
     "ordinary_transcripts": 2, "active_fences": 2},
])
def test_malformed_test_limits_fail_closed(tmp_path, test_limits):
    trace = []
    store = _FakeStore(tmp_path, None, trace)
    with pytest.raises(ValueError):
        _controller(
            tmp_path, store, _FakeTransport(_Device("enabled"), trace),
            test_limits=test_limits)


def test_active_fence_limit_counts_recordless_sessions(tmp_path):
    trace = []
    store = _FakeStore(tmp_path, None, trace)
    iox = _authority_layout(tmp_path)
    limits = {
        "session_files": 4,
        "transcript_files": 4,
        "ordinary_transcripts": 2,
        "active_fences": 1,
    }
    first_path, first = _write_fence(
        tmp_path, state="active", record_id=None,
        operation="uninstall", teardown_mode="force_agent_only")
    second = dict(first)
    second.update({
        "board_identity": "FOC9999OTHER",
        "attempt_id": "44444444444444444444444444444444",
        "device_id": "edge-other",
        "job_id": "fedcba9876543210",
    })
    transcript = _Transcript(second["attempt_id"])
    second["transcript_ref"] = transcript.reference()
    with open(os.path.join(
            iox, "transcripts", second["attempt_id"] + ".transcript"),
            "wb") as stream:
        stream.write(transcript.bytes())
    os.chmod(os.path.join(
        iox, "transcripts", second["attempt_id"] + ".transcript"), 0o600)
    second_path = os.path.join(
        iox, "sessions",
        _board_key(second["board_identity"]) + ".lock.json")
    with open(second_path, "w") as stream:
        json.dump(second, stream, sort_keys=True, separators=(",", ":"))
    os.chmod(second_path, 0o600)
    assert os.path.exists(first_path) and os.path.exists(second_path)
    with pytest.raises(ValueError):
        controller, _factory = _controller(
            tmp_path, store, _FakeTransport(_Device("enabled"), trace),
            test_limits=limits)
        try:
            controller.summary_for_device(_DEVICE)
        finally:
            controller.close()


@pytest.mark.parametrize("limits", [
    {"session_files": 4, "transcript_files": 4,
     "ordinary_transcripts": 4, "active_fences": 1},
    {"session_files": 1, "transcript_files": 4,
     "ordinary_transcripts": 4, "active_fences": 4},
])
def test_fence_capacity_is_reserved_across_processes(tmp_path, limits):
    import multiprocessing

    _seed_phase(tmp_path, None)
    attempts = ("8" * 32, "9" * 32)
    _authority_layout(tmp_path, dict(
        (attempt, _Transcript(attempt).bytes()) for attempt in attempts))
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(2)
    results = context.Queue()
    processes = [context.Process(
        target=_concurrent_fence_admission_worker,
        args=(str(tmp_path), "FENCE-BOARD-%d" % index, attempt,
              limits, barrier, results))
        for index, attempt in enumerate(attempts)]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=20) for unused in processes]
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert outcomes.count("admitted") == 1
    assert outcomes.count("journal_durability") == 1
    session_dir = tmp_path / "iox" / "sessions"
    fences = [
        _read_json(os.path.join(str(session_dir), name))
        for name in os.listdir(str(session_dir))
        if name.endswith(".lock.json")]
    assert len([fence for fence in fences
                if fence["state"] == "active"]) == 1


def test_crash_results_keep_raw_recipe_recovery_and_custody_fields_distinct(
        tmp_path):
    trace = []
    store = _FakeStore(tmp_path, "disabled_confirmed", trace)
    controller, _factory = _controller(
        tmp_path, store, _FakeTransport(_Device("disabled"), trace, reap=False))
    try:
        result = controller.recover_board(_BOARD, _Cancel(True))
    finally:
        controller.close()
    assert {
        "result_code", "returncode", "recovery_code", "record_id",
        "iox_verification", "iox_session",
    }.issubset(_result_keys(result))
    assert result["result_code"] == 130
    assert result["returncode"] is None
    assert result["recovery_code"] == 5
    assert result["record_id"] == _RECORD
    assert result["iox_verification"]["phase"] == store.journal["phase"]
    assert result["iox_session"]["mutation_blocked"] is True


# Real worker death is kept separate from the simulated policy matrix above.
# The parent witnesses SIGKILL and bounded process-group cleanup. A subsequent
# synthetic boot-ID change tests restart policy; it does not claim a real reboot.
def _durable_fixture_json(path, value):
    with open(path, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())


class _FileDevice(object):
    def __init__(self, path):
        self.path = path
        self.mutations = []

    @property
    def state(self):
        return _read_json(self.path)["state"]

    @state.setter
    def state(self, value):
        content = _read_json(self.path)
        content["effects"].append(value)
        content["state"] = value
        _durable_fixture_json(self.path, content)


_INSTALL_RECIPE = r'''import json,os,signal,socket,struct,sys
signal.alarm(6)
sock=socket.socket(fileno=int(os.environ["IRIS_IOX_CONTROL_FD"]))
sock.settimeout(4)
def exact(size):
    result=b""
    while len(result)<size:
        chunk=sock.recv(size-len(result))
        if not chunk: raise RuntimeError("partial controller frame")
        result+=chunk
    return result
def receive():
    size=struct.unpack("!I",exact(4))[0]
    assert 1<=size<=65536
    return json.loads(exact(size).decode("utf-8"))
for operation,arguments in [("upload_wrapper",{}),("begin_install",{}),
    ("command",{"name":"app_stop"}),("command",{"name":"app_install"}),
    ("deployed",{}),("finish",{"exit_intent":0})]:
    ready=receive()
    assert ready["type"]=="ready"
    request=dict((key,ready[key]) for key in ("version","attempt_id","action",
        "teardown_mode","record_id","transaction_id","expected_revision",
        "board_identity","wrapper_sha256"))
    request.update(sequence=ready["next_sequence"],operation=operation,arguments=arguments)
    payload=json.dumps(request,sort_keys=True,separators=(",",":")).encode("utf-8")
    sock.sendall(struct.pack("!I",len(payload))+payload)
    for index in range(17):
        response=receive()
        assert response["sequence"]==request["sequence"]
        if response["type"]=="result": break
        assert response["type"]=="output"
    else: raise RuntimeError("too many output frames")
    if not response["ok"]: sys.exit(response["operation_code"])
    if operation=="finish": sys.exit(response["operation_code"])
'''


def _crash_worker(root, barrier):
    import signal
    from pathlib import Path
    root = Path(root)
    store = _FakeStore(root, existing=True)

    def die(point):
        if point == barrier:
            _durable_fixture_json(str(root / "barrier.json"), {"point": point})
            os.kill(os.getpid(), signal.SIGKILL)

    event = store.iox_event

    def guarded_event(record_id, transaction_id, expected_revision,
                      expected_phase, name, evidence, capability=None):
        die("before_" + name)
        result = event(record_id, transaction_id, expected_revision,
                       expected_phase, name, evidence, capability=capability)
        die("after_" + name)
        return result
    store.iox_event = guarded_event

    class Trace(list):
        def append(self, item):
            list.append(self, item)
            if item == ("device_effect", "enable"):
                die("after_enable_effect")
            if item == ("device_effect", "disable"):
                die("after_disable_effect")
            if item == ("command_end", "read") and store.journal["phase"] == "ownership_probe":
                die("after_probe_read")

    transport = _FakeTransport(_FileDevice(str(root / "device.json")), Trace())
    install = barrier in ("before_disable_intent", "after_disable_intent",
                          "after_disable_effect", "before_disable_confirmed",
                          "after_disable_confirmed")
    overrides = {}
    if install:
        import sys
        overrides["recipe_argv_by_action"] = {"install": [sys.executable, "-c", _INSTALL_RECIPE]}
    controller, unused = _controller(root, store, transport, **overrides)
    try:
        if install:
            request = _AttrDict(action="install", device_id=_DEVICE, job_id=_JOB,
                target=_AttrDict(host=_HOST, port=22, platform="iox",
                                model="C9300-48UXM", os_family="xe"),
                credential_ref="credential-crash", record_id=None,
                teardown_mode="none", wrapper_path=str(root / "wrapper.tar"))
            def prepare(*args):
                store.delegate.create(_deployment_record())
                return _RECORD
            def preflight(*args):
                return _AttrDict(device_identity=_BOARD, platform="iox",
                                model="C9300-48UXM", os_family="xe")
            result = controller.run_install(request, prepare, preflight,
                                             lambda *args: None, _Cancel())
        else:
            result = controller.recover_board(_BOARD, _Cancel())
        _durable_fixture_json(str(root / "result.json"), dict(result))
    finally:
        controller.close()


def _run_crash_worker(tmp_path, barrier):
    import ctypes
    import fcntl
    import selectors
    import signal
    import subprocess
    import sys
    import time
    program = (
        "import importlib.util,sys; "
        "sys.path.insert(0,sys.argv[3]); "
        "spec=importlib.util.spec_from_file_location('crash_fixture',sys.argv[1]); "
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m); "
        "m._crash_worker(sys.argv[2],sys.argv[4])")
    # Adopt orphaned supervisors/recipe peers so a failing crash check cannot
    # leave zombies. Restore the test runner's original subreaper setting.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    child = subprocess.Popen([sys.executable, "-c", program, __file__, str(tmp_path),
        os.path.dirname(os.path.dirname(__file__)), barrier],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    selector = selectors.DefaultSelector()
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
        fcntl.fcntl(stream, fcntl.F_SETFL, fcntl.fcntl(stream, fcntl.F_GETFL) | os.O_NONBLOCK)
        selector.register(stream, selectors.EVENT_READ, label)
    deadline = time.monotonic() + 8
    try:
        while selector.get_map():
            assert time.monotonic() < deadline, "worker exceeded crash deadline"
            for key, unused in selector.select(min(0.05, max(0, deadline-time.monotonic()))):
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                capture = captures[key.data]
                assert len(capture) + len(data) <= 32768, "unbounded worker diagnostic stream"
                capture.extend(data)
        child.wait(timeout=max(0.01, deadline-time.monotonic()))
    finally:
        selector.close()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=1)
        child.stdout.close()
        child.stderr.close()
        reap_deadline = time.monotonic() + 1
        # Only descendants adopted by this test runner are candidates; children
        # of other agents and other processes are outside this process tree.
        try:
            while True:
                try:
                    pid, unused = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    continue
                children_path = "/proc/self/task/%d/children" % os.getpid()
                with open(children_path) as stream:
                    adopted = [int(value) for value in stream.read().split()]
                for pid in adopted:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                assert time.monotonic() < reap_deadline, "unreaped crash-fixture descendant"
                time.sleep(0.005)
        finally:
            assert libc.prctl(36, previous.value, 0, 0, 0) == 0
    stderr = bytes(captures["stderr"])
    # An import error or generic crash cannot stand in for the requested barrier.
    expected = -signal.SIGKILL if barrier != "restart" else 0
    assert child.returncode == expected, stderr.decode("utf-8", "replace")
    if barrier != "restart":
        assert _read_json(str(tmp_path / "barrier.json")) == {"point": barrier}
    return child.returncode


@pytest.mark.parametrize("barrier,live,crash_phase,recovered_phase,effects", [
    ("before_disable_intent", "enabled", "observed", "observed", []),
    ("after_disable_intent", "enabled", "disable_intent", "relinquished", []),
    ("after_disable_effect", "enabled", "disable_intent", "indeterminate", ["disabled"]),
    ("before_disable_confirmed", "enabled", "disable_intent", "indeterminate", ["disabled"]),
    ("after_disable_confirmed", "enabled", "disabled_confirmed", "restored", ["disabled", "enabled"]),
    ("before_ownership_probe", "disabled", "disabled_confirmed", "restored", ["enabled"]),
    ("after_ownership_probe", "disabled", "ownership_probe", "indeterminate", []),
    ("after_probe_read", "enabled", "ownership_probe", "indeterminate", []),
    ("before_relinquished", "enabled", "ownership_probe", "indeterminate", []),
    ("after_relinquished", "enabled", "relinquished", "relinquished", []),
    ("before_restore_intent", "disabled", "ownership_probe", "indeterminate", []),
    ("after_restore_intent", "disabled", "restore_intent", "indeterminate", []),
    ("after_enable_effect", "disabled", "restore_intent", "relinquished", ["enabled"]),
    ("before_restored", "disabled", "restore_intent", "relinquished", ["enabled"]),
    ("after_restored", "disabled", "restored", "restored", ["enabled"]),
])
def test_real_process_crash_restarts_same_durable_store_without_replaying_enable(
        tmp_path, barrier, live, crash_phase, recovered_phase, effects):
    _verification_module()  # Missing implementation is the intended red cause.
    initiating = barrier in ("before_disable_intent", "after_disable_intent",
                             "after_disable_effect", "before_disable_confirmed",
                             "after_disable_confirmed")
    if initiating:
        import io
        import tarfile
        _authority_layout(tmp_path)
        _durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
        with tarfile.open(str(tmp_path / "wrapper.tar"), "w", format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo("package.yaml")
            body = b'descriptor-schema-version: "2.7"\n'
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    else:
        _seed_phase(tmp_path, "disabled_confirmed")
    device_path = str(tmp_path / "device.json")
    _durable_fixture_json(device_path, {"state": live, "effects": []})
    _run_crash_worker(tmp_path, barrier)
    path = str(tmp_path / "deployment_records.json")
    assert _read_json(path)["records"][_RECORD]["iox_verification"]["phase"] == crash_phase
    fence_path = str(tmp_path / "iox" / "sessions" / (_board_key(_BOARD) + ".lock.json"))
    fence = _read_json(fence_path)
    assert fence["state"] in ("active", "reaped")
    before = _read_bytes(path)
    if fence["state"] == "active":
        _run_crash_worker(tmp_path, "restart")
        assert _read_json(str(tmp_path / "result.json"))["result_code"] == 5
        assert _read_bytes(path) == before
        # The controlled local process tree has been killed and reaped. Model a
        # changed boot only after independently observing same-boot refusal.
        fence["boot_id"] = "00000000-0000-4000-8000-000000000000"
        _durable_fixture_json(fence_path, fence)
    # A surviving supervisor may legitimately have witnessed and durably
    # recorded cleanup already. In that case normal same-boot recovery is safe.
    _run_crash_worker(tmp_path, "restart")
    journal = _read_json(path)["records"][_RECORD]["iox_verification"]
    assert journal["phase"] == recovered_phase
    assert _read_json(device_path)["effects"] == effects


@pytest.mark.parametrize("failure", ["mkdir", "parent_fsync"])
def test_authority_initialization_durability_failure_prevents_every_device_command(tmp_path, monkeypatch, failure):
    import stat
    module = _verification_module()
    store = _records_module().DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    calls, injected = [], []
    original_mkdir, original_fsync = os.mkdir, os.fsync
    def mkdir(path, *args, **kwargs):
        if failure == "mkdir" and os.fspath(path).startswith(str(tmp_path / "iox")):
            injected.append("mkdir")
            raise OSError("injected authority directory failure")
        return original_mkdir(path, *args, **kwargs)
    def fsync(fd):
        if failure == "parent_fsync" and stat.S_ISDIR(os.fstat(fd).st_mode):
            injected.append("parent_fsync")
            raise OSError("injected authority parent durability failure")
        return original_fsync(fd)
    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(os, "fsync", fsync)
    def factory(config, transcript, supervisor, monotonic_fn):
        calls.append(config)
        pytest.fail("authority failure crossed into transport")
    config = _AttrDict(state_dir=str(tmp_path), controller_id=_CONTROLLER,
                      session_seconds=7200, restoration_reserve_seconds=180)
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.run_uninstall(
                _AttrDict(action="uninstall", device_id=_DEVICE, job_id=_JOB,
                    target=_AttrDict(host=_HOST, port=22, platform="iox"),
                    credential_ref="credential-crash", record_id=None,
                    teardown_mode="force_agent_only"),
                lambda *args: None, lambda *args: None, lambda *args: None, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] == 5
    finally:
        if controller is not None: controller.close()
    assert injected and calls == []


@pytest.mark.parametrize("fault", ["foreign_domain", "record_store_path", "copied_root",
                                     "authority_symlink", "mode", "owner"])
def test_authority_domain_path_and_filesystem_bindings_refuse_before_transport(tmp_path, monkeypatch, fault):
    module = _verification_module()
    _seed_phase(tmp_path, "disabled_confirmed")
    authority = tmp_path / "iox" / "authority.json"
    original_record = _read_bytes(str(tmp_path / "deployment_records.json"))
    active_root = tmp_path
    if fault == "copied_root":
        import shutil
        active_root = tmp_path / "copied"
        active_root.mkdir(mode=0o700)
        shutil.copytree(str(tmp_path / "iox"), str(active_root / "iox"))
        shutil.copy2(str(tmp_path / "deployment_records.json"), str(active_root / "deployment_records.json"))
    elif fault in ("foreign_domain", "record_store_path"):
        value = _read_json(str(authority))
        if fault == "foreign_domain": value["controller_id"] = "f" * 32
        else: value["record_store"] = str(tmp_path / "elsewhere" / "deployment_records.json")
        _durable_fixture_json(str(authority), value)
    elif fault == "authority_symlink":
        target = tmp_path / "owner-authority"
        authority.rename(target)
        authority.symlink_to(target)
    elif fault == "mode":
        authority.chmod(0o644)
    else:
        original_fstat, original_stat, original_lstat = os.fstat, os.stat, os.lstat
        def foreign_owner(value):
            fields = list(value)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        def fstat(fd):
            value = original_fstat(fd)
            return foreign_owner(value) if os.readlink("/proc/self/fd/%d" % fd) == str(authority) else value
        def stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            return foreign_owner(value) if os.fspath(path) == str(authority) else value
        def lstat(path, *args, **kwargs):
            value = original_lstat(path, *args, **kwargs)
            return foreign_owner(value) if os.fspath(path) == str(authority) else value
        monkeypatch.setattr(os, "fstat", fstat)
        monkeypatch.setattr(os, "stat", stat)
        monkeypatch.setattr(os, "lstat", lstat)
    calls = []
    def factory(config, transcript, supervisor, monotonic_fn):
        calls.append(config)
        pytest.fail("foreign or unsafe authority crossed into transport")
    store = _records_module().DeploymentRecordStore(str(active_root), now_fn=lambda: 100)
    config = _AttrDict(state_dir=str(active_root), controller_id=_CONTROLLER,
                      session_seconds=7200, restoration_reserve_seconds=180)
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.recover_board(_BOARD, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] == 5
    finally:
        if controller is not None: controller.close()
    assert calls == []
    assert _read_bytes(str(active_root / "deployment_records.json")) == original_record


def test_controller_recipe_output_and_public_diagnostics_redact_resolved_overlapping_secrets(tmp_path):
    import io
    import sys
    import tarfile
    _verification_module()
    _authority_layout(tmp_path)
    _durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
    store = _FakeStore(tmp_path, existing=True)
    wrapper = tmp_path / "wrapper.tar"
    with tarfile.open(str(wrapper), "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("package.yaml")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    secrets = ("recipe-overlap-SECRET", "recipe-overlap-SECRETabc")
    calls, outputs = [], []
    def resolver(reference):
        assert reference == "credential-crash"
        calls.append(reference)
        return {"device_user": "fixture-user", "device_pass": secrets[0], "enable_secret": secrets[1]}
    # Pipe writes split every secret and its overlapping extension into bytes.
    prefix = ("import os\nfor fd in (1,2):\n"
              "    for byte in %r: os.write(fd,bytes([byte]))\n" %
              ((secrets[1] + " " + secrets[0] + "\n").encode("ascii"),))
    controller, unused = _controller(tmp_path, store, _FakeTransport(_Device("enabled"), []),
        credential_resolver=resolver,
        recipe_argv_by_action={"install": [sys.executable, "-c", prefix + _INSTALL_RECIPE]})
    request = _AttrDict(action="install", device_id=_DEVICE, job_id=_JOB,
        target=_AttrDict(host=_HOST, port=22, platform="iox", model="C9300-48UXM", os_family="xe"),
        credential_ref="credential-crash", record_id=None, teardown_mode="none", wrapper_path=str(wrapper))
    def prepare(*args):
        store.delegate.create(_deployment_record())
        return _RECORD
    try:
        result = controller.run_install(request, prepare,
            lambda *args: _AttrDict(device_identity=_BOARD, platform="iox", model="C9300-48UXM", os_family="xe"),
            lambda stream, data: outputs.append(data.encode("utf-8") if isinstance(data, str) else data), _Cancel())
        public = controller.summary_for_device(_DEVICE)
    finally:
        controller.close()
    assert calls and result["result_code"] == 0
    rendered = b"".join(outputs)
    assert rendered.count(b"<redacted>") == 4
    rendered += json.dumps(result, sort_keys=True).encode("utf-8")
    rendered += json.dumps(public, sort_keys=True).encode("utf-8")
    for path in (tmp_path / "iox" / "transcripts").glob("*.transcript"):
        data = path.read_bytes()
        cursor = 0
        while cursor < len(data):
            length = struct.unpack("!I", data[cursor:cursor+4])[0]
            row = json.loads(data[cursor+4:cursor+4+length].decode("utf-8"))
            if row["type"] == "stream": rendered += base64.b64decode(row["data_b64"])
            cursor += 4 + length
    assert all(secret.encode("ascii") not in rendered for secret in secrets)


@pytest.mark.parametrize("fault", ["concurrent", "partial_request", "unknown_request_key"])
def test_real_controller_closes_invalid_recipe_channel_before_install_admission(tmp_path, fault):
    import io
    import sys
    import tarfile
    _verification_module()
    _authority_layout(tmp_path)
    _durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
    store = _FakeStore(tmp_path, existing=True)
    wrapper = tmp_path / "wrapper.tar"
    with tarfile.open(str(wrapper), "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("package.yaml"); member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    recipe = _INSTALL_RECIPE
    send = '    sock.sendall(struct.pack("!I",len(payload))+payload)'
    if fault == "concurrent":
        replacement = send + '\n    sock.sendall(struct.pack("!I",len(payload))+payload)'
    elif fault == "partial_request":
        replacement = '    sock.sendall(struct.pack("!I",len(payload))+payload[:3])\n    sock.shutdown(socket.SHUT_WR)'
    else:
        recipe = recipe.replace('    payload=json.dumps(request', '    request["unexpected"]=True\n    payload=json.dumps(request')
        replacement = send
    recipe = recipe.replace(send, replacement)
    device = _Device("enabled")
    transport = _FakeTransport(device, [])
    controller, unused = _controller(tmp_path, store, transport,
        recipe_argv_by_action={"install": [sys.executable, "-c", recipe]})
    request = _AttrDict(action="install", device_id=_DEVICE, job_id=_JOB,
        target=_AttrDict(host=_HOST, port=22, platform="iox", model="C9300-48UXM", os_family="xe"),
        credential_ref="credential-crash", record_id=None, teardown_mode="none", wrapper_path=str(wrapper))
    def prepare(*args):
        store.delegate.create(_deployment_record()); return _RECORD
    try:
        result = controller.run_install(request, prepare,
            lambda *args: _AttrDict(device_identity=_BOARD, platform="iox", model="C9300-48UXM", os_family="xe"),
            lambda *args: None, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] != 0
    assert device.mutations == []
    assert sum(row[0] == "upload" for row in transport.trace) <= 1



def test_environment_state_root_cannot_override_configured_controller_authority(tmp_path, monkeypatch):
    _verification_module()
    store = _FakeStore(tmp_path, "disabled_confirmed")
    foreign = tmp_path / "environment-root"
    foreign.write_bytes(b"untrusted environment owner data")
    monkeypatch.setenv("IRIS_STATE", str(foreign))
    device = _Device("disabled")
    controller, unused = _controller(tmp_path, store, _FakeTransport(device, []))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0 and device.mutations == ["enable"]
    assert store.journal["phase"] == "restored"
    assert foreign.read_bytes() == b"untrusted environment owner data"



@pytest.mark.parametrize("file_class", [
    "iox_directory", "locks_directory", "sessions_directory", "transcripts_directory",
    "snapshots_directory", "session_file", "transcript_file", "lock_file", "store_lock_file",
])
@pytest.mark.parametrize("fault", ["mode", "owner", "symlink"])
def test_every_authority_file_class_refuses_unsafe_metadata_without_disk_change(
        tmp_path, monkeypatch, file_class, fault):
    import stat
    module = _verification_module()
    _seed_phase(tmp_path, "disabled_confirmed")
    session_path, unused = _write_fence(tmp_path, state="reaped", record_id=_RECORD)
    lock = tmp_path / "iox" / "locks" / (_board_key(_BOARD) + ".lock")
    lock.write_bytes(b"")
    lock.chmod(0o600)
    store_lock = tmp_path / "deployment_records.json.lock"
    store_lock.write_bytes(b"")
    store_lock.chmod(0o600)
    paths = {
        "iox_directory": tmp_path / "iox",
        "locks_directory": tmp_path / "iox" / "locks",
        "sessions_directory": tmp_path / "iox" / "sessions",
        "transcripts_directory": tmp_path / "iox" / "transcripts",
        "snapshots_directory": tmp_path / "iox" / "snapshots",
        "store_lock_file": store_lock,
        "session_file": type(tmp_path)(session_path),
        "transcript_file": tmp_path / "iox" / "transcripts" / (_ATTEMPT + ".transcript"),
        "lock_file": lock,
    }
    target = paths[file_class]
    directory = target.is_dir()
    original_lstat = os.lstat
    if fault == "mode":
        target.chmod(0o755 if directory else 0o644)
    elif fault == "symlink":
        owner_target = tmp_path / ("owner-" + file_class)
        target.rename(owner_target)
        target.symlink_to(owner_target, target_is_directory=directory)
    else:
        # Model a foreign inode owner through every supported metadata API,
        # including bounded scandir enumeration, without requiring root/chown.
        original_stat, original_fstat, original_scandir = os.stat, os.fstat, os.scandir
        metadata = original_lstat(str(target))
        identity = (metadata.st_dev, metadata.st_ino)
        def foreign(value):
            if (value.st_dev, value.st_ino) != identity:
                return value
            fields = list(value)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        monkeypatch.setattr(os, "stat", lambda *a, **kw: foreign(original_stat(*a, **kw)))
        monkeypatch.setattr(os, "lstat", lambda *a, **kw: foreign(original_lstat(*a, **kw)))
        monkeypatch.setattr(os, "fstat", lambda *a, **kw: foreign(original_fstat(*a, **kw)))
        class Entry(object):
            def __init__(self, entry): self.entry = entry
            def __getattr__(self, name): return getattr(self.entry, name)
            def stat(self, *args, **kwargs): return foreign(self.entry.stat(*args, **kwargs))
        class Entries(object):
            def __init__(self, iterator): self.iterator = iterator
            def __iter__(self): return self
            def __next__(self): return Entry(next(self.iterator))
            def close(self): self.iterator.close()
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        monkeypatch.setattr(os, "scandir", lambda *a, **kw: Entries(original_scandir(*a, **kw)))

    before = _authority_tree_snapshot(tmp_path, original_lstat)
    calls = []
    def factory(config, transcript, supervisor, monotonic_fn):
        calls.append(config)
        pytest.fail("unsafe authority metadata reached device transport")
    store = _records_module().DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    config = _AttrDict(state_dir=str(tmp_path), controller_id=_CONTROLLER,
                      session_seconds=7200, restoration_reserve_seconds=180)
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.recover_board(_BOARD, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] == 5
    finally:
        if controller is not None:
            controller.close()
    assert calls == []
    assert _authority_tree_snapshot(tmp_path, original_lstat) == before



@pytest.mark.parametrize("event", ["disable_intent", "restore_intent"])
@pytest.mark.parametrize("boundary", ["file_fsync", "replace", "parent_fsync"])
def test_controller_durability_failure_invalidates_mutation_continuation(
        tmp_path, monkeypatch, event, boundary):
    """Drive actual install/restore policy through a failing durable store write."""
    import io
    import stat
    import sys
    import tarfile
    _verification_module()
    _authority_layout(tmp_path)
    _durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
    trace = []
    store = _FakeStore(tmp_path, trace=trace, existing=True)
    wrapper = tmp_path / "wrapper.tar"
    with tarfile.open(str(wrapper), "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("package.yaml")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    active = [None]
    injected = []
    committed_replace = []
    before_event = []
    original_event = store.iox_event
    original_fsync, original_replace = os.fsync, os.replace
    root_identity = (os.stat(str(tmp_path)).st_dev, os.stat(str(tmp_path)).st_ino)

    def tracked_event(record_id, transaction_id, expected_revision,
                      expected_phase, name, evidence, capability=None):
        if name == event:
            before_event.append(_read_json(store.path)["records"][_RECORD]["iox_verification"])
            active[0] = name
        try:
            return original_event(record_id, transaction_id, expected_revision,
                                  expected_phase, name, evidence, capability=capability)
        finally:
            active[0] = None
    store.iox_event = tracked_event

    def fail():
        injected.append((event, boundary))
        trace.append(("durability_failed", event, boundary))
        raise OSError("injected deployment-record %s failure" % boundary)

    def fsync(fd):
        if active[0] == event and not injected:
            metadata = os.fstat(fd)
            if boundary == "file_fsync" and stat.S_ISREG(metadata.st_mode):
                path = os.readlink("/proc/self/fd/%d" % fd)
                # Only the journal writer's regular file in the record-store
                # directory; transcript/fence writes live below iox/ instead.
                if os.path.dirname(path) == str(tmp_path) and path != store.path + ".lock":
                    fail()
            if (boundary == "parent_fsync" and committed_replace and
                    stat.S_ISDIR(metadata.st_mode) and
                    (metadata.st_dev, metadata.st_ino) == root_identity):
                fail()
        return original_fsync(fd)

    def replace(source, destination, *args, **kwargs):
        journal_write = (active[0] == event and os.fspath(destination) == store.path)
        if journal_write and boundary == "replace" and not injected:
            fail()
        result = original_replace(source, destination, *args, **kwargs)
        if journal_write:
            committed_replace.append(event)
        return result
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)

    class RecordingTransport(_FakeTransport):
        def command(self, command_id, command_bytes, phase_deadline):
            trace.append(("sent", command_bytes))
            return _FakeTransport.command(self, command_id, command_bytes, phase_deadline)
    device = _Device("enabled")
    transport = RecordingTransport(device, trace)
    controller, unused = _controller(tmp_path, store, transport,
        recipe_argv_by_action={"install": [sys.executable, "-c", _INSTALL_RECIPE]})
    request = _AttrDict(action="install", device_id=_DEVICE, job_id=_JOB,
        target=_AttrDict(host=_HOST, port=22, platform="iox", model="C9300-48UXM", os_family="xe"),
        credential_ref="credential-crash", record_id=None, teardown_mode="none", wrapper_path=str(wrapper))
    def prepare(*args):
        store.delegate.create(_deployment_record())
        return _RECORD
    try:
        result = controller.run_install(request, prepare,
            lambda *args: _AttrDict(device_identity=_BOARD, platform="iox", model="C9300-48UXM", os_family="xe"),
            lambda *args: None, _Cancel())
    finally:
        controller.close()
    # No early validation/import/recipe error can stand in for the named
    # durability failure. The real store event and exact syscall must run.
    assert injected == [(event, boundary)]
    assert len(before_event) == 1
    assert result["result_code"] != 0
    failure_index = trace.index(("durability_failed", event, boundary))
    def mutations(rows):
        return [row[1] for row in rows if row[0] == "sent" and
                _FakeTransport._purpose(row[1]) in ("disable", "enable", "application")]
    assert mutations(trace[failure_index+1:]) == []
    assert not any(row[0] == "sent" and _FakeTransport._purpose(row[1]) == "enable" for row in trace)
    journal = _read_json(store.path)["records"][_RECORD]["iox_verification"]
    assert journal["phase"] not in ("restored", "relinquished")
    if event == "disable_intent":
        assert mutations(trace) == []
        assert device.mutations == [] and device.state == "enabled"
        assert journal["disable_confirmation"] is None
        assert journal["phase"] in ("observed", "disable_intent", "indeterminate")
    else:
        earlier = mutations(trace[:failure_index])
        assert earlier and _FakeTransport._purpose(earlier[0]) == "disable"
        assert any(b"app-hosting stop" in command.lower() for command in earlier)
        assert any(b"app-hosting install" in command.lower() for command in earlier)
        assert device.mutations == ["disable"] and device.state == "disabled"
        assert journal["disable_confirmation"] == before_event[0]["disable_confirmation"]
        assert journal["phase"] in ("ownership_probe", "restore_intent", "indeterminate")
        assert journal["unresolved"] is True and journal["terminal_at"] is None
    if boundary == "parent_fsync":
        assert committed_replace, "parent-sync injection must follow record replacement"
        assert journal["unresolved"] is True



def _authority_tree_snapshot(root, lstat_fn=None):
    """Retain real inode/metadata/content evidence without following symlinks."""
    import stat
    lstat_fn = os.lstat if lstat_fn is None else lstat_fn
    result = {}
    paths = [str(root)]
    for directory, directories, files in os.walk(str(root), followlinks=False):
        paths.extend(os.path.join(directory, name) for name in directories + files)
    for path in paths:
        value = lstat_fn(path)
        body = (os.readlink(path) if stat.S_ISLNK(value.st_mode) else
                _read_bytes(path) if stat.S_ISREG(value.st_mode) else None)
        result[os.path.relpath(path, str(root))] = (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_mtime_ns, value.st_ctime_ns, body)
    return result


@pytest.mark.parametrize("fault", ["unknown_key", "missing_key", "bad_schema", "absent_with_journal"])
def test_malformed_or_absent_existing_authority_never_regenerates_or_contacts_device(tmp_path, fault):
    module = _verification_module()
    _seed_phase(tmp_path, "disabled_confirmed")
    authority = tmp_path / "iox" / "authority.json"
    if fault == "absent_with_journal":
        authority.unlink()
    else:
        value = _read_json(str(authority))
        if fault == "unknown_key": value["unexpected"] = True
        elif fault == "missing_key": del value["record_store"]
        else: value["schema_version"] = 2
        _durable_fixture_json(str(authority), value)
    store_lock = tmp_path / "deployment_records.json.lock"
    store_lock.write_bytes(b"")
    store_lock.chmod(0o600)
    before = _authority_tree_snapshot(tmp_path)
    calls = []
    def factory(config, transcript, supervisor, monotonic_fn):
        calls.append(config)
        pytest.fail("invalid authority reached device transport")
    store = _records_module().DeploymentRecordStore(str(tmp_path), now_fn=lambda: 100)
    config = _AttrDict(state_dir=str(tmp_path), controller_id=_CONTROLLER,
                      session_seconds=7200, restoration_reserve_seconds=180)
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.recover_board(_BOARD, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] == 5
    finally:
        if controller is not None:
            controller.close()
    assert calls == []
    assert _authority_tree_snapshot(tmp_path) == before
    if fault == "absent_with_journal":
        assert not authority.exists()



def _assert_generated_fence_schema(fence):
    import re
    assert set(fence) == set("schema_version controller_id board_identity attempt_id device_id job_id operation teardown_mode record_id boot_id supervisor_pid supervisor_start_ticks transcript_ref state created_at updated_at".split())
    assert type(fence["schema_version"]) is int and fence["schema_version"] == 1
    assert fence["controller_id"] == _CONTROLLER and fence["board_identity"] == _BOARD
    assert re.fullmatch(r"[0-9a-f]{32}", fence["attempt_id"])
    assert re.fullmatch(r"[0-9a-f]{16}", fence["job_id"])
    assert fence["device_id"] == _DEVICE and fence["record_id"] == _RECORD
    assert fence["operation"] == "recover" and fence["teardown_mode"] == "none"
    assert fence["boot_id"] == _host_boot_id()
    for key in ("supervisor_pid", "supervisor_start_ticks", "created_at", "updated_at"):
        assert type(fence[key]) is int and 0 <= fence[key] <= 2**63-1
    assert fence["supervisor_pid"] > 0
    reference = fence["transcript_ref"]
    assert set(reference) == {"id", "attempt_id", "stored_bytes", "observed_bytes", "dropped_bytes", "truncated"}
    assert reference["id"] == reference["attempt_id"] == fence["attempt_id"]
    # The closed key sets above exclude credentials, secrets, wrapper bindings,
    # filesystem paths, and internal capability objects from persisted fences.


@pytest.mark.parametrize("fault", ["corrupt_authority", "corrupt_store", "active_same_boot_fence"])
def test_recordless_force_cannot_bypass_corrupt_authority_store_or_surviving_fence(
        tmp_path, fault):
    import sys
    module = _verification_module()
    _authority_layout(tmp_path)
    _durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
    if fault == "corrupt_authority":
        (tmp_path / "iox" / "authority.json").write_bytes(b"{malformed")
    elif fault == "corrupt_store":
        (tmp_path / "deployment_records.json").write_bytes(b"{malformed")
    else:
        _write_fence(tmp_path, state="active", boot_id=_host_boot_id(), record_id=None,
                     operation="uninstall", teardown_mode="force_agent_only")
    protected = {}
    for path in (tmp_path / "deployment_records.json", tmp_path / "iox" / "authority.json"):
        protected[str(path)] = path.read_bytes()
    for path in (tmp_path / "iox" / "sessions").glob("*.json"):
        protected[str(path)] = path.read_bytes()
    store = _FakeStore(tmp_path, existing=True)
    retire_calls = []
    def retire_device(*args, **kwargs):
        retire_calls.append((args, kwargs))
        pytest.fail("refused recordless force retired deployment records")
    store.retire_device = retire_device
    trace = []
    device = _Device("enabled")
    transport = _FakeTransport(device, trace)
    factory = _TransportFactory(transport, tmp_path)
    recipe_ran = tmp_path / "forbidden-recipe"
    config = _AttrDict(state_dir=str(tmp_path), controller_id=_CONTROLLER,
        session_seconds=7200, restoration_reserve_seconds=180,
        recipe_argv_by_action={"uninstall": [sys.executable, "-c",
            "open(%r,'wb').write(b'recipe launched');raise SystemExit(99)" % str(recipe_ran)]})
    request = _AttrDict(action="uninstall", device_id=_DEVICE, job_id=_JOB,
        target=_AttrDict(host=_HOST, port=22, platform="iox", model="C9300-48UXM", os_family="xe"),
        credential_ref="credential-crash", record_id=None, teardown_mode="force_agent_only")
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.run_uninstall(request, lambda *args: None,
                lambda *args: _AttrDict(device_identity=_BOARD, platform="iox", model="C9300-48UXM", os_family="xe"),
                lambda *args: None, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] != 0
            assert result["record_id"] is None
    finally:
        if controller is not None: controller.close()
    assert not recipe_ran.exists() and retire_calls == []
    assert device.mutations == []
    assert not any(row[0] == "upload" for row in trace)
    assert all(row[1] == "identity" for row in trace if row[0] == "command_start")
    if fault in ("corrupt_authority", "corrupt_store"):
        assert factory.calls == []
    for path, original in protected.items():
        assert _read_bytes(path) == original


def _inject_inode_size(monkeypatch, target, reported_size):
    """Expose a large inode through metadata while keeping its real bytes tiny."""
    original_stat, original_lstat = os.stat, os.lstat
    original_fstat, original_scandir = os.fstat, os.scandir
    value = original_lstat(str(target))
    identity = (value.st_dev, value.st_ino)
    def sized(value):
        if (value.st_dev, value.st_ino) != identity: return value
        fields = list(value)
        fields[6] = reported_size
        return os.stat_result(fields)
    monkeypatch.setattr(os, "stat", lambda *a, **kw: sized(original_stat(*a, **kw)))
    monkeypatch.setattr(os, "lstat", lambda *a, **kw: sized(original_lstat(*a, **kw)))
    monkeypatch.setattr(os, "fstat", lambda *a, **kw: sized(original_fstat(*a, **kw)))
    class Entry(object):
        def __init__(self, entry): self.entry = entry
        def __getattr__(self, name): return getattr(self.entry, name)
        def stat(self, *a, **kw): return sized(self.entry.stat(*a, **kw))
    class Entries(object):
        def __init__(self, entries): self.entries = entries
        def __iter__(self): return self
        def __next__(self): return Entry(next(self.entries))
        def close(self): self.entries.close()
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    monkeypatch.setattr(os, "scandir", lambda *a, **kw: Entries(original_scandir(*a, **kw)))
    return original_lstat


@pytest.mark.parametrize("fault", ["reaped_fence_capacity", "session_oversize", "transcript_oversize",
                                     "unknown_entry", "nonregular_entry"])
def test_authority_admission_capacity_sizes_and_entries_fail_without_changes(tmp_path, monkeypatch, fault):
    module = _verification_module()
    _seed_phase(tmp_path, "disabled_confirmed")
    original_lstat = os.lstat
    limits = {"session_files": 2, "transcript_files": 8, "ordinary_transcripts": 4, "active_fences": 2}
    if fault == "reaped_fence_capacity":
        # Both entries are reaped: active-fence quota alone cannot detect this.
        # Neither belongs to the target board, so this attempt requires a third
        # fence rather than replacing an existing same-board fence.
        for index in range(2):
            path, fence = _write_fence(tmp_path, state="reaped", attempt_id="%032x" % (index+500))
            board = "OTHER-BOARD-%d" % index
            fence["board_identity"] = board
            destination = tmp_path / "iox" / "sessions" / (_board_key(board) + ".lock.json")
            _durable_fixture_json(str(destination), fence)
            destination.chmod(0o600)
            os.unlink(path)
    elif fault == "session_oversize":
        path, unused = _write_fence(tmp_path, state="reaped", record_id=_RECORD)
        original_lstat = _inject_inode_size(monkeypatch, path, 16385)
    elif fault == "transcript_oversize":
        original_lstat = _inject_inode_size(monkeypatch,
            tmp_path / "iox" / "transcripts" / (_ATTEMPT + ".transcript"), 1048577)
    elif fault == "unknown_entry":
        (tmp_path / "iox" / "sessions" / "unexpected.entry").write_bytes(b"owner data")
    else:
        os.mkfifo(str(tmp_path / "iox" / "transcripts" / ("e"*32 + ".transcript")), 0o600)
    # Pre-existing stable lock files avoid confusing harmless lock acquisition
    # with unauthorized admission/capacity-repair writes.
    lock = tmp_path / "deployment_records.json.lock"
    lock.write_bytes(b""); lock.chmod(0o600)
    board_lock = tmp_path / "iox" / "locks" / (
        _board_key(_BOARD) + ".lock")
    board_lock.write_bytes(b""); board_lock.chmod(0o600)
    before = _authority_tree_snapshot(tmp_path, original_lstat)
    store = _FakeStore(tmp_path, existing=True)
    device, trace = _Device("disabled"), []
    transport = _FakeTransport(device, trace)
    factory = _TransportFactory(transport, tmp_path)
    config = _AttrDict(state_dir=str(tmp_path), controller_id=_CONTROLLER,
        session_seconds=7200, restoration_reserve_seconds=180, test_limits=limits)
    controller = None
    try:
        try:
            controller = module.IoxController(store, config, factory, lambda: 100, lambda: 100.0)
            result = controller.recover_board(_BOARD, _Cancel())
        except (ValueError, OSError):
            pass
        else:
            assert result["result_code"] == 5
    finally:
        if controller is not None: controller.close()
    assert device.mutations == []
    assert not any(row[0] == "upload" or row[:2] == ("command_start", "application") for row in trace)
    assert _authority_tree_snapshot(tmp_path, original_lstat) == before
