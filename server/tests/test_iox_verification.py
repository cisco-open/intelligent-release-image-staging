# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Workstream B red freeze for the IOx authority controller.

The production module intentionally does not exist at the accepted base.  Keep
its import inside tests/helpers so pytest can collect this red suite before the
implementation commit lands.
"""
import copy
import base64
import importlib
import io
import json
import os
import stat
import sys

import pytest


_CONTROLLER_ID = "c" * 32
_BOARD = "FOC0123ABCD"


class _Bag(dict):
    """A dict that also tolerates an implementation's attribute-style reads."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class _Cancel(object):
    def __init__(self, cancelled=False):
        self.cancelled = cancelled

    def __call__(self):
        return self.cancelled

    def is_set(self):
        return self.cancelled


class _Result(_Bag):
    pass


class _Clock(object):
    """A monotonic clock with a manually advanceable offset."""
    def __init__(self, origin=1000.0):
        import time

        self.origin = origin
        self._real_origin = time.monotonic()
        self.offset = 0.0

    def __call__(self):
        import time

        return self.origin + (time.monotonic() - self._real_origin) + self.offset

    def peek(self):
        return self()

    def advance(self, seconds):
        self.offset += seconds


class _ExactClock(object):
    """A deterministic monotonic source for absolute-deadline assertions."""
    def __init__(self, value=1000.0):
        self.origin = value
        self.value = value

    def __call__(self):
        return self.value

    def peek(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def _module():
    return importlib.import_module("iox_verification")


def _transcript_ref(attempt="a" * 32):
    return _Bag(id=attempt, attempt_id=attempt, stored_bytes=512,
                observed_bytes=128, dropped_bytes=0, truncated=False)


def _transport_result(stdout=b"", stderr=b"", returncode=0,
                      error_category=None, timed_out=False,
                      framing_complete=True):
    return _Result(returncode=returncode, timed_out=timed_out, stdout=stdout,
                   stderr=stderr, stdout_truncated=False,
                   stderr_truncated=False, framing_complete=framing_complete,
                   error_category=error_category,
                   transcript_ref=_transcript_ref())


class _StatefulTransport(object):
    """A bounded device model behind the frozen three-method transport API."""
    def __init__(self, calls, board=_BOARD, verification="enabled",
                 scenario=None, config=None, transcript=None,
                 supervisor=None):
        self.calls = calls
        self.board = board
        self.verification = verification
        self.scenario = scenario
        self.config = config or {}
        self.transcript = transcript
        self.supervisor = supervisor
        self.app_present = True
        self.closed = False

    def _purpose(self, command_id, command_bytes):
        context = self.config.get("command_contexts", {}).get(command_id, {})
        purpose = context.get("purpose")
        if purpose:
            return purpose
        lower = command_bytes.lower()
        if b"show version" in lower or b"processor board" in lower:
            return "identity"
        if b"verification disable" in lower:
            return "verification_disable"
        if b"verification enable" in lower:
            return "verification_enable"
        if b"verification" in lower or b"show app-hosting infra" in lower:
            return "verification_read"
        if b"show app-hosting list" in lower:
            return "app_list"
        for name, fragment in (
                ("app_stop", b"app-hosting stop"),
                ("app_deactivate", b"app-hosting deactivate"),
                ("app_uninstall", b"app-hosting uninstall"),
                ("app_install", b"app-hosting install"),
                ("app_activate", b"app-hosting activate"),
                ("app_start", b"app-hosting start")):
            if fragment in lower:
                return name
        if b"write memory" in lower or b"copy running-config" in lower:
            return "save"
        return "application"

    def _scripted_outcome(self, purpose):
        if self.scenario is None:
            return None
        outcomes = self.scenario.command_outcomes.get(purpose, [])
        return outcomes.pop(0) if outcomes else None

    def command(self, command_id, command_bytes, phase_deadline):
        assert isinstance(command_bytes, bytes)
        assert phase_deadline is not None
        lower = command_bytes.lower()
        purpose = self._purpose(command_id, command_bytes)
        started_at = (self.scenario.clock.peek()
                      if self.scenario is not None and
                      self.scenario.clock is not None else None)
        self.calls.append(("command", command_id, command_bytes,
                           phase_deadline, purpose, started_at))
        if (self.scenario is not None and self.scenario.clock is not None and
                purpose in self.scenario.advances):
            self.scenario.clock.advance(self.scenario.advances[purpose])
        if purpose in ("identity", "identity_discovery",
                       "identity_revalidation", "preflight"):
            identity = {"board": self.board, "model": "IE-3400-8T2S",
                        "os_family": "xe"}
            if (self.scenario is not None and
                    self.scenario.identity_results):
                identity.update(self.scenario.identity_results.pop(0))
            self.board = identity["board"]
            software = ("Cisco IOS XE Software, Version 17.12.4" if
                        identity["os_family"] == "xe" else
                        "Cisco IOS XR Software, Version 7.9.2")
            return _transport_result(
                ("Processor board ID %s\nModel Number : %s\n%s\n" %
                 (identity["board"], identity["model"], software)
                 ).encode("ascii"))
        if purpose == "verification_disable":
            outcome = self._scripted_outcome("verification_disable")
            if outcome == "caf_transient":
                return _transport_result(
                    b"The process for the command is not responding or is "
                    b"otherwise unavailable\n", error_category="caf_transient")
            if outcome == "already_disabled":
                return _transport_result(
                    b"App hosting verification is already disabled\n",
                    error_category="unsupported_response")
            if outcome is not None:
                return _transport_result(
                    stderr=("injected %s\n" % outcome).encode("ascii"),
                    returncode=1, error_category=outcome,
                    framing_complete=False)
            if self.scenario is not None:
                self.scenario.verification = "disabled"
            self.verification = "disabled"
            return _transport_result(
                b"App hosting verification disabled successfully\n")
        if purpose == "verification_enable":
            outcome = self._scripted_outcome("verification_enable")
            if outcome is not None:
                return _transport_result(
                    stderr=("injected %s\n" % outcome).encode("ascii"),
                    returncode=1, error_category=outcome,
                    framing_complete=False)
            if self.scenario is not None:
                self.scenario.verification = "enabled"
            self.verification = "enabled"
            return _transport_result(
                b"App hosting verification enabled successfully\n")
        if purpose == "verification_read":
            if self.scenario is not None and self.scenario.read_states:
                self.scenario.verification = self.scenario.read_states.pop(0)
            if self.scenario is not None:
                self.verification = self.scenario.verification
            if self.verification == "unknown":
                return _transport_result(
                    b"verification state unavailable\n",
                    error_category="readback_unknown")
            return _transport_result(
                ("App signature verification: %s\n" % self.verification
                 ).encode("ascii"))
        outcome = self._scripted_outcome(purpose)
        if outcome is not None:
            return _transport_result(
                stderr=("injected %s\n" % outcome).encode("ascii"),
                returncode=1, error_category=outcome,
                framing_complete=False)
        if b"app-hosting uninstall" in lower:
            self.app_present = False
            return _transport_result()
        if b"app-hosting install" in lower:
            self.app_present = True
            return _transport_result()
        if b"show app-hosting list" in lower:
            return _transport_result(
                b"iris DEPLOYED\n" if self.app_present else b"")
        return _transport_result()

    def upload(self, snapshot_fd, remote_path, phase_deadline):
        assert phase_deadline is not None
        position = os.lseek(snapshot_fd, 0, os.SEEK_CUR)
        os.lseek(snapshot_fd, 0, os.SEEK_SET)
        body = os.read(snapshot_fd, 1024 * 1024)
        os.lseek(snapshot_fd, position, os.SEEK_SET)
        purpose = "upload_wrapper"
        if self.config.get("command_contexts"):
            scp = [value for value in self.config["command_contexts"].values()
                   if value.get("kind") == "scp"]
            if scp:
                purpose = max(scp, key=lambda value: value["command_id"])[
                    "purpose"]
        started_at = (self.scenario.clock.peek()
                      if self.scenario is not None and
                      self.scenario.clock is not None else None)
        self.calls.append(("upload", remote_path, body, phase_deadline,
                           purpose, started_at))
        if (self.scenario is not None and self.scenario.clock is not None and
                purpose in self.scenario.advances):
            self.scenario.clock.advance(self.scenario.advances[purpose])
        outcome = self._scripted_outcome(purpose)
        if outcome is not None:
            return _transport_result(
                stderr=("injected %s\n" % outcome).encode("ascii"),
                returncode=1, error_category=outcome,
                framing_complete=False)
        return _transport_result()

    def cancel_and_reap(self, deadline):
        self.calls.append(("cancel_and_reap", deadline))
        self.closed = True
        return True


class _TransportFactory(object):
    def __init__(self, board=_BOARD, verification="enabled", boards=None,
                 calls=None, read_states=None, command_outcomes=None,
                 clock=None, advances=None, identity_results=None):
        self.calls = calls if calls is not None else []
        self.created = []
        self.board = board
        self.boards = list(boards or [])
        self.verification = verification
        self.read_states = list(read_states or [])
        self.command_outcomes = dict(
            (key, list(value)) for key, value in
            (command_outcomes or {}).items())
        self.clock = clock
        self.advances = dict(advances or {})
        self.identity_results = [dict(value) for value in
                                 (identity_results or [])]

    def __call__(self, config, transcript, supervisor, monotonic_fn):
        args = (config, transcript, supervisor, monotonic_fn)
        self.calls.append(("factory", args, {}))
        board = (self.boards[len(self.created)]
                 if len(self.created) < len(self.boards) else self.board)
        transport = _StatefulTransport(
            self.calls, board=board, verification=self.verification,
            scenario=self, config=config, transcript=transcript,
            supervisor=supervisor)
        self.created.append(transport)
        return transport


class _PathCancel(object):
    def __init__(self, path):
        self.path = path

    def __call__(self):
        return os.path.exists(self.path)

    def is_set(self):
        return self()


class _AliasLockTransport(object):
    """File-observable transport used only by the cross-process lock test."""
    def __init__(self, root, role, config, transcript, supervisor):
        self.root = root
        self.role = role
        self.config = config
        self.transcript = transcript
        self.supervisor = supervisor

    def _marker(self, suffix, value):
        path = os.path.join(self.root, "%s-%s.json" % (self.role, suffix))
        with open(path, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())

    def command(self, command_id, command_bytes, phase_deadline):
        import base64
        import time

        context = dict(self.config["command_contexts"][command_id])
        purpose = context["purpose"]
        self.transcript.append(context)
        if purpose == "identity_discovery":
            self._marker("discovered", {
                "board_identity": _BOARD, "device_id": self.role,
                "host": self.config["host"], "pid": os.getpid()})
        elif purpose == "identity_revalidation":
            self._marker("revalidated", {
                "board_identity": _BOARD, "device_id": self.role,
                "host": self.config["host"], "pid": os.getpid()})
            if self.role == "alias-a":
                release = os.path.join(self.root, "release-alias-a")
                deadline = time.monotonic() + 5
                while not os.path.exists(release):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("alias-a revalidation release timed out")
                    time.sleep(0.01)

        stdout = (
            "Processor board ID %s\nModel Number : IE-3400-8T2S\n"
            "Cisco IOS XE Software, Version 17.12.4\n" % _BOARD).encode("ascii")
        self.transcript.append({
            "schema_version": 1, "type": "stream", "command_id": command_id,
            "stream": "stdout", "offset": 0,
            "data_b64": base64.b64encode(stdout).decode("ascii")})
        self.transcript.append({
            "schema_version": 1, "type": "command_end",
            "command_id": command_id, "finished_at": 100, "returncode": 0,
            "timed_out": False, "stdout_truncated": False,
            "stderr_truncated": False, "framing_complete": True,
            "error_category": None, "stdout_observed_bytes": len(stdout),
            "stderr_observed_bytes": 0, "stdout_dropped_bytes": 0,
            "stderr_dropped_bytes": 0,
            "payload_spans": [{"offset": 0, "length": len(stdout)}],
            "observed_state": None, "transition_response": None})
        return _Result(
            returncode=0, timed_out=False, stdout=stdout, stderr=b"",
            stdout_truncated=False, stderr_truncated=False,
            framing_complete=True, error_category=None,
            transcript_ref=self.transcript.reference())

    def upload(self, snapshot_fd, remote_path, phase_deadline):
        raise AssertionError("cancelled alias fixture reached upload")

    def cancel_and_reap(self, deadline):
        return True


class _AliasLockFactory(object):
    def __init__(self, root, role):
        self.root = root
        self.role = role

    def __call__(self, config, transcript, supervisor, monotonic_fn):
        assert callable(monotonic_fn)
        return _AliasLockTransport(
            self.root, self.role, config, transcript, supervisor)


def _alias_lock_worker(root, role, host):
    """One independent controller caller for the physical-board lock test."""
    from pathlib import Path

    result_path = os.path.join(root, role + "-result.json")
    controller = None
    try:
        store = _StatefulStore(Path(root))
        controller = _controller(
            Path(root), store, _AliasLockFactory(root, role))
        request = _request(
            action="uninstall", teardown_mode="force_agent_only",
            record_id=None, address=host,
            job_id=("1" * 16 if role == "alias-a" else "2" * 16))
        result = controller.run_uninstall(
            request, lambda *_args: None,
            lambda *_args: _Bag(
                device_identity=_BOARD, model="IE-3400-8T2S",
                os_family="xe", platform="iox"),
            lambda *_args: None,
            _PathCancel(os.path.join(root, "cancel-" + role)))
        value = {"result": dict(result)}
    except BaseException as exc:
        value = {"exception": type(exc).__name__, "detail": str(exc)[:1024]}
    finally:
        if controller is not None:
            try:
                controller.close()
            except BaseException as exc:
                value = {"exception": type(exc).__name__,
                         "detail": str(exc)[:1024]}
    with open(result_path, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))


def _journal(record_id="r1", phase="observed", state="enabled", revision=0,
             board=_BOARD, unresolved=None):
    if unresolved is None:
        unresolved = phase in ("disable_intent", "disabled_confirmed",
                               "installing", "ownership_probe",
                               "restore_intent", "indeterminate")
    initial_state = (state if phase in ("observed", "unchanged") else
                     "enabled")
    observation = _Bag(
        state=initial_state, observed_at=10, command_id=1,
        transcript_id="a" * 32, stdout_offset=0, stdout_length=36,
        stderr_offset=0, stderr_length=0, returncode=0, timed_out=False,
        truncated=False, framing_complete=True)
    ownership_phases = (
        "disabled_confirmed", "installing", "ownership_probe",
        "restore_intent", "restored", "relinquished", "indeterminate")
    pre_disable = None
    confirmation = None
    restore = None
    error = None
    if phase == "disable_intent" or phase in ownership_phases:
        pre_disable = copy.deepcopy(observation)
        pre_disable.update(observed_at=11, command_id=2)
    if phase in ownership_phases:
        confirmation = _Bag(
            confirmed_at=12, pre_disable_command_id=2,
            disable_command_id=3, disabled_readback_command_id=4,
            transition_response="disabled_successfully")
    if phase in ("restore_intent", "restored", "relinquished",
                 "indeterminate"):
        restore = copy.deepcopy(observation)
        restore.update(state=state, observed_at=13, command_id=5)
    if phase == "indeterminate":
        error = _Bag(category="reconciliation_required",
                     detail="fixture unresolved observation", at=13,
                     transcript_id="a" * 32)
    terminal_at = (14 if phase in ("restored", "unchanged", "relinquished")
                   else None)
    return _Bag(
        schema_version=1, transaction_id="d" * 32, revision=revision,
        record_id=record_id, controller_id=_CONTROLLER_ID,
        board_identity=board, wrapper_sha256="b" * 64,
        package_sign_present=False, package_cert_present=False,
        prior_state=initial_state, current_state=state, phase=phase,
        unresolved=unresolved, created_at=10, updated_at=terminal_at or 13,
        observed_at=(restore["observed_at"] if restore is not None else
                     confirmation["confirmed_at"] if confirmation is not None
                     else pre_disable["observed_at"] if pre_disable is not None
                     else observation["observed_at"]),
        terminal_at=terminal_at, initial_observation=observation,
        pre_disable_observation=pre_disable,
        disable_confirmation=confirmation,
        restore_observation=restore, error=error,
        transcript_refs=[_transcript_ref()])


def _record(record_id="r1", address="192.0.2.10", board=_BOARD,
            adopted=False, journal=None):
    value = _Bag(record_id=record_id, controller_id=_CONTROLLER_ID,
                 device_id="edge-01", state="active", adopted=adopted,
                 resolved=_Bag(platform="iox", device_ip=address,
                               device_identity=board,
                               resources=[{"kind": "iox-app",
                                           "ownership": "iris-created"}]),
                 resources=[{"kind": "iox-app", "ownership": "iris-created"}])
    if journal is not None:
        value["iox_verification"] = journal
    return value


class _StatefulStore(object):
    def __init__(self, tmp_path, records=None, obligations=None, calls=None):
        self.path = str(tmp_path / "deployment_records.json")
        self.calls = calls if calls is not None else []
        self.records = dict((record["record_id"], copy.deepcopy(record))
                            for record in (records or []))
        self.obligations = list(obligations or [])
        self.summaries = []
        self.change_on_second_get = None
        self._get_count = 0

    def get(self, record_id, strict=False):
        self.calls.append(("get", record_id, strict))
        self._get_count += 1
        if self.change_on_second_get is not None and self._get_count >= 2:
            self.records[record_id] = copy.deepcopy(self.change_on_second_get)
        value = self.records.get(record_id)
        return copy.deepcopy(value) if value is not None else None

    def list(self, device_id=None, strict=False):
        self.calls.append(("list", device_id, strict))
        values = list(self.records.values())
        if device_id is not None:
            values = [value for value in values
                      if value.get("device_id") == device_id]
        return copy.deepcopy(values)

    def active_for_device(self, device_id, strict=False):
        self.calls.append(("active_for_device", device_id, strict))
        values = [record for record in self.records.values()
                  if record.get("device_id") == device_id
                  and record.get("state") == "active"]
        if len(values) > 1:
            raise ValueError("multiple active records")
        return copy.deepcopy(values[0]) if values else None

    def recoverable_for_device(self, device_id, strict=False):
        self.calls.append(("recoverable_for_device", device_id, strict))
        values = [record for record in self.records.values()
                  if record.get("device_id") == device_id]
        if len(values) > 1:
            raise ValueError("multiple recoverable records")
        return copy.deepcopy(values[0]) if values else None

    def iox_obligations(self, board_identity):
        self.calls.append(("iox_obligations", board_identity))
        return copy.deepcopy([journal for journal in self.obligations
                              if journal["board_identity"] == board_identity])

    def iox_summary(self, device_id):
        self.calls.append(("iox_summary", device_id))
        return copy.deepcopy(self.summaries)

    def iox_begin(self, record_id, controller_id, board_identity,
                  wrapper_binding, initial_observation, transcript_ref):
        self.calls.append(("iox_begin", record_id, controller_id,
                           board_identity, copy.deepcopy(wrapper_binding)))
        value = _journal(record_id=record_id, board=board_identity,
                         state=initial_observation["state"])
        value["wrapper_sha256"] = wrapper_binding["wrapper_sha256"]
        value["package_sign_present"] = wrapper_binding[
            "package_sign_present"]
        value["package_cert_present"] = wrapper_binding[
            "package_cert_present"]
        value["initial_observation"] = copy.deepcopy(initial_observation)
        value["prior_state"] = initial_observation["state"]
        value["current_state"] = initial_observation["state"]
        self.records[record_id]["iox_verification"] = copy.deepcopy(value)
        return copy.deepcopy(value)

    def iox_event(self, record_id, transaction_id, expected_revision,
                  expected_phase, event, evidence, capability=None):
        self.calls.append(("iox_event", event, expected_revision,
                           expected_phase, copy.deepcopy(evidence), capability))
        value = self.records[record_id]["iox_verification"]
        if value["transaction_id"] != transaction_id:
            raise ValueError("transaction mismatch")
        if value["revision"] != expected_revision or value["phase"] != expected_phase:
            raise ValueError("stale CAS")
        value["revision"] += 1
        value["updated_at"] += 1
        phases = {"disable_confirmed": "disabled_confirmed"}
        if event != "error":
            value["phase"] = phases.get(event, event)
        observation = evidence.get("observation")
        if event == "disable_intent":
            value["pre_disable_observation"] = copy.deepcopy(observation)
        elif event == "unchanged" and observation is not None:
            value["pre_disable_observation"] = copy.deepcopy(observation)
        elif event == "disable_confirmed":
            value["disable_confirmation"] = copy.deepcopy(
                evidence["confirmation"])
            value["current_state"] = "disabled"
            value["observed_at"] = evidence["confirmation"]["confirmed_at"]
        elif event in ("restore_intent", "restored", "relinquished",
                       "indeterminate", "reconcile_enabled"):
            value["restore_observation"] = copy.deepcopy(observation)
        if observation is not None:
            value["current_state"] = observation["state"]
            value["observed_at"] = observation["observed_at"]
        if event == "error":
            value["error"] = copy.deepcopy(evidence["error"])
        if event == "reconcile_enabled":
            value["phase"] = "relinquished"
            value["current_state"] = "enabled"
            value["unresolved"] = False
            value["terminal_at"] = value["updated_at"]
        elif event == "indeterminate":
            value["phase"] = "indeterminate"
            value["unresolved"] = True
            value["error"] = copy.deepcopy(evidence["error"])
        elif value["phase"] in ("restored", "unchanged", "relinquished"):
            value["unresolved"] = False
            if value["terminal_at"] is None:
                value["terminal_at"] = value["updated_at"]
        elif value["phase"] in ("disable_intent", "disabled_confirmed",
                                "installing", "ownership_probe",
                                "restore_intent"):
            value["unresolved"] = True
        return copy.deepcopy(value)

    def transition(self, record_id, state, evidence=None):
        self.calls.append(("transition", record_id, state, evidence))
        self.records[record_id]["state"] = state
        return copy.deepcopy(self.records[record_id])

    def retire_device(self, device_id, reason):
        self.calls.append(("retire_device", device_id, reason))
        retired = []
        for value in self.records.values():
            if value.get("device_id") == device_id:
                value["state"] = "abandoned"
                retired.append(value["record_id"])
        return retired


def _authority(tmp_path, **overrides):
    certificate = tmp_path / "catalog-ca.pem"
    if not certificate.exists():
        certificate.write_text("fixture catalog certificate\n")
        certificate.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def credential_resolver(reference):
        assert reference == "device-profile-edge-01"
        return {"device_user": "fixture-user",
                "device_pass": "fixture-device-pass-SECRET",
                "enable_secret": "fixture-enable-SECRET"}

    value = _Bag(state_dir=str(tmp_path), controller_id=_CONTROLLER_ID,
                 record_store="deployment_records.json",
                 session_seconds=7200, restoration_reserve_seconds=180,
                 application_id="iris",
                 credential_resolver=credential_resolver,
                 enrollment_token_minter=lambda _device_id:
                     "fixture-catalog-token-SECRET",
                 catalog_certificate_path=str(certificate))
    value.update(overrides)
    return value


def _request(action="install", teardown_mode=None, record_id=None,
             address="192.0.2.10", wrapper_path=None, **overrides):
    if teardown_mode is None:
        teardown_mode = "none" if action == "install" else "recorded"
    value = _Bag(
        action=action, device_id="edge-01", job_id="0123456789abcdef",
        target=_Bag(host=address, port=22, platform="iox",
                    model="IE-3400-8T2S", os_family="xe"),
        credential_ref="device-profile-edge-01", record_id=record_id,
        teardown_mode=teardown_mode, wrapper_path=wrapper_path)
    value.update(overrides)
    return value


def _callbacks(calls, record_id="new-r1"):
    def prepare(request, identity):
        calls.append(("prepare", request, identity))
        return record_id

    def preflight(request, identity):
        calls.append(("preflight", request, identity))
        return _Bag(device_identity=_BOARD, model="IE-3400-8T2S",
                    os_family="xe", platform="iox")

    def on_output(stream, data):
        calls.append(("output", stream, data))

    return prepare, preflight, on_output


def _write_recipe_peer(tmp_path, fault=None, operations=None,
                       cleanup_on_error=False, event_path=None,
                       prefix_chunks=()):
    """Write a tiny recipe peer that speaks the real length-prefixed protocol."""
    if operations is None:
        operations = [
            ("command", {"name": "app_stop"}),
            ("command", {"name": "app_deactivate"}),
            ("command", {"name": "app_uninstall"}),
            ("command", {"name": "remove_app_config"}),
            ("command", {"name": "remove_wrapper"}),
            ("command", {"name": "remove_certificate"}),
            ("command", {"name": "cleanup_config_probe"}),
            ("command", {"name": "cleanup_stage_probe"}),
            ("finish", {"exit_intent": 0}),
        ]
    program = r'''import base64
import json
import os
import socket
import struct
import sys

sock = socket.socket(fileno=int(os.environ["IRIS_IOX_CONTROL_FD"]))
for chunk in json.loads(%(prefix_chunks)r):
    os.write(1, base64.b64decode(chunk))

def receive():
    header = sock.recv(4)
    if len(header) != 4:
        raise RuntimeError("missing frame")
    size = struct.unpack("!I", header)[0]
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            raise RuntimeError("short frame")
        body += chunk
    return json.loads(body.decode("utf-8"))

def send(value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(body)) + body)

operations = json.loads(%(operations)r)
fault = %(fault)r
cleanup_on_error = %(cleanup_on_error)r
event_path = %(event_path)r
saved = None
for operation, arguments in operations:
    ready = receive()
    request = {"version": 1, "sequence": ready["next_sequence"],
               "attempt_id": ready["attempt_id"], "action": ready["action"],
               "teardown_mode": ready["teardown_mode"],
               "record_id": ready["record_id"],
               "transaction_id": ready["transaction_id"],
               "expected_revision": ready["expected_revision"],
               "board_identity": ready["board_identity"],
               "wrapper_sha256": ready["wrapper_sha256"],
               "operation": operation, "arguments": arguments}
    if fault == "force_fabricates_transaction":
        request["transaction_id"] = "d" * 32
        fault = "sent"
    elif fault == "mode_change":
        request["teardown_mode"] = "recorded"
        fault = "sent"
    elif fault == "replay" and saved is not None:
        request = saved
        fault = "sent"
    send(request)
    if saved is None:
        saved = dict(request)
    result = None
    while result is None:
        frame = receive()
        if frame["type"] == "result":
            result = frame
    if fault == "sent":
        sys.exit(0)
    if cleanup_on_error and result["operation_code"] != 0:
        ready = receive()
        cleanup = {"version": 1, "sequence": ready["next_sequence"],
                   "attempt_id": ready["attempt_id"],
                   "action": ready["action"],
                   "teardown_mode": ready["teardown_mode"],
                   "record_id": ready["record_id"],
                   "transaction_id": ready["transaction_id"],
                   "expected_revision": ready["expected_revision"],
                   "board_identity": ready["board_identity"],
                   "wrapper_sha256": ready["wrapper_sha256"],
                   "operation": "cleanup",
                   "arguments": {"reason": "error", "exit_intent": 7}}
        send(cleanup)
        cleanup_result = None
        while cleanup_result is None:
            frame = receive()
            if frame["type"] == "result":
                cleanup_result = frame
        sys.exit(7)
    if operation == "finish":
        if event_path and result["operation_code"] == 0:
            fd = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
            try:
                os.write(fd, b"finish_ack\n")
                os.fsync(fd)
            finally:
                os.close(fd)
        intent = arguments["exit_intent"]
        sys.exit(intent if intent != 0 else result["operation_code"])
sys.exit(4)
''' % {"operations": json.dumps(operations), "fault": fault,
       "cleanup_on_error": cleanup_on_error, "event_path": event_path,
       "prefix_chunks": json.dumps([
           base64.b64encode(chunk).decode("ascii") for chunk in prefix_chunks])}
    path = tmp_path / ("recipe-%s.sh" % (fault or "valid"))
    shell = "#!/bin/bash\nexec %s - <<'PY'\n%s\nPY\n" % (
        sys.executable, program)
    path.write_text(shell)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return str(path)


def _write_wrapper(tmp_path, markers=()):
    import tarfile

    suffix = "unsigned" if not markers else "-".join(
        marker.replace(".", "-") for marker in markers)
    path = tmp_path / (suffix + "-wrapper.tar")
    body = b"descriptor-schema-version: '2.7'\ninfo:\n  name: iris\n"
    with tarfile.open(str(path), "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("package.yaml")
        member.size = len(body)
        member.mode = 0o644
        member.mtime = 1
        archive.addfile(member, io.BytesIO(body))
        for marker_name in markers:
            marker = tarfile.TarInfo("metadata/" + marker_name)
            marker.size = 0
            marker.mode = 0o644
            marker.mtime = 1
            archive.addfile(marker, io.BytesIO(b""))
    return str(path)


def _write_unsigned_wrapper(tmp_path):
    return _write_wrapper(tmp_path)


def _write_header_transcript(tmp_path, attempt):
    import struct

    transcript_dir = tmp_path / "iox" / "transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(tmp_path / "iox"), 0o700)
    os.chmod(str(transcript_dir), 0o700)
    header = {"schema_version": 1, "type": "header", "id": attempt,
              "attempt_id": attempt, "controller_id": _CONTROLLER_ID,
              "created_at": 1}
    payload = json.dumps(header, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    content = struct.pack("!I", len(payload)) + payload
    path = transcript_dir / (attempt + ".transcript")
    path.write_bytes(content)
    os.chmod(str(path), 0o600)
    return {"id": attempt, "attempt_id": attempt,
            "stored_bytes": len(content), "observed_bytes": 0,
            "dropped_bytes": 0, "truncated": False}


def _write_active_fence(tmp_path, transcript_ref, board=_BOARD):
    import hashlib

    sessions = tmp_path / "iox" / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    os.chmod(str(tmp_path / "iox"), 0o700)
    os.chmod(str(sessions), 0o700)
    lock_name = hashlib.sha256(
        b"IRIS-IOX-BOARD-v1\0" + board.encode("ascii")).hexdigest() + ".lock"
    boot_id = open("/proc/sys/kernel/random/boot_id").read().strip()
    fields = open("/proc/%d/stat" % os.getpid()).read().split()
    fence = {
        "schema_version": 1, "controller_id": _CONTROLLER_ID,
        "board_identity": board, "attempt_id": transcript_ref["attempt_id"],
        "device_id": "edge-01", "job_id": "0123456789abcdef",
        "operation": "reconcile_enabled", "teardown_mode": "none",
        "record_id": "r1", "boot_id": boot_id,
        "supervisor_pid": os.getpid(), "supervisor_start_ticks": int(fields[21]),
        "transcript_ref": transcript_ref, "state": "active",
        "created_at": 1, "updated_at": 1}
    path = sessions / (lock_name + ".json")
    path.write_text(json.dumps(fence, sort_keys=True))
    os.chmod(str(path), 0o600)
    return path


def _controller(tmp_path, store, factory, clock=None, **config):
    module = _module()
    fallback_clock = [1000.0]

    def monotonic():
        fallback_clock[0] += 0.01
        return fallback_clock[0]

    authority = _authority(tmp_path, **config)
    authority["record_store"] = os.path.realpath(store.path)
    return module.IoxController(store, authority, factory,
                                lambda: 100, clock or monotonic)


def _install_operations():
    return [
        ("upload_wrapper", {}),
        ("begin_install", {}),
        ("command", {"name": "app_stop"}),
        ("command", {"name": "app_deactivate"}),
        ("command", {"name": "app_uninstall"}),
        ("command", {"name": "remove_app_config"}),
        ("command", {"name": "configure_app"}),
        ("command", {"name": "app_install"}),
        ("deployed", {}),
        ("command", {"name": "app_activate"}),
        ("upload_certificate", {}),
        ("command", {"name": "app_start"}),
        ("command", {"name": "save"}),
        ("finish", {"exit_intent": 0}),
    ]


def _run_scripted_install(tmp_path, factory, markers=(), clock=None,
                          cleanup_on_error=True, authority=None,
                          prepare_hook=None, prefix_chunks=()):
    timeline = factory.calls
    store = _StatefulStore(tmp_path, calls=timeline)
    wrapper_path = _write_wrapper(tmp_path, markers)
    recipe = _write_recipe_peer(
        tmp_path, operations=_install_operations(),
        cleanup_on_error=cleanup_on_error, prefix_chunks=prefix_chunks)

    def preflight(request, identity):
        timeline.append(("preflight", request, identity))
        return _Bag(device_identity=_BOARD, model="IE-3400-8T2S",
                    os_family="xe", platform="iox")

    def prepare(request, identity):
        timeline.append(("prepare", request, identity))
        if prepare_hook is not None:
            prepare_hook(request, identity, wrapper_path)
        record = _record(record_id="new-r1")
        record["state"] = "planned"
        store.records["new-r1"] = record
        return "new-r1"

    config = dict(authority or {})
    config["recipe_argv_by_action"] = {"install": ["/bin/bash", recipe]}
    controller = _controller(
        tmp_path, store, factory, clock=clock, **config)
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path), prepare, preflight,
            lambda stream, data: timeline.append(("output", stream, data)),
            _Cancel())
    finally:
        controller.close()
    return result, store, timeline, wrapper_path


def _command_calls(factory, *purposes):
    return [call for call in factory.calls
            if call[0] == "command" and call[4] in purposes]


_APPLICATION_MUTATIONS = (
    "app_stop", "app_deactivate", "app_uninstall", "remove_app_config",
    "configure_app", "app_install", "app_activate", "app_start", "save")


def test_controller_exposes_only_the_frozen_execution_surface(tmp_path):
    store = _StatefulStore(tmp_path)
    controller = _controller(tmp_path, store, _TransportFactory())
    for method in ("run_install", "run_uninstall", "recover_board",
                   "reconcile_enabled", "summary_for_device", "close"):
        assert callable(getattr(controller, method))
    controller.close()


def test_separate_process_aliases_share_one_board_lock_without_holding_store_lock(
        tmp_path):
    import fcntl
    import signal
    import subprocess
    import time

    _module()  # Missing implementation is the intentional pre-foundation red.
    store_path = tmp_path / "deployment_records.json"
    with open(str(store_path), "w") as stream:
        json.dump({"records": {}}, stream, sort_keys=True,
                  separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(str(store_path), 0o600)

    program = (
        "import importlib.util,sys; "
        "sys.path.insert(0,sys.argv[3]); "
        "spec=importlib.util.spec_from_file_location('alias_fixture',sys.argv[1]); "
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m); "
        "m._alias_lock_worker(sys.argv[2],sys.argv[4],sys.argv[5])")

    def start(role, host):
        return subprocess.Popen(
            [sys.executable, "-c", program, __file__, str(tmp_path),
             os.path.dirname(os.path.dirname(__file__)), role, host],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)

    def wait_for(path, process):
        deadline = time.monotonic() + 5
        while not path.exists():
            if process.poll() is not None:
                raise AssertionError(
                    "%s exited before %s" % (process.pid, path.name))
            if time.monotonic() >= deadline:
                raise AssertionError("timed out waiting for %s" % path.name)
            time.sleep(0.01)

    def stop(process):
        if process is None:
            return
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=1)

    first = start("alias-a", "192.0.2.10")
    second = None
    try:
        wait_for(tmp_path / "alias-a-revalidated.json", first)
        second = start("alias-b", "198.51.100.20")
        wait_for(tmp_path / "alias-b-discovered.json", second)

        # The first controller is deliberately inside board-scoped transport.
        # Its record-store lock must already be free for other authority reads.
        store_lock_fd = os.open(str(store_path) + ".lock",
                                os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(store_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(store_lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(store_lock_fd)

        time.sleep(0.25)
        assert not (tmp_path / "alias-b-revalidated.json").exists()
        (tmp_path / "cancel-alias-b").touch()
        second.wait(timeout=5)
        assert second.returncode == 0
        second_result = json.loads(
            (tmp_path / "alias-b-result.json").read_text())
        assert "exception" not in second_result
        assert second_result["result"]["result_code"] == 130

        (tmp_path / "cancel-alias-a").touch()
        (tmp_path / "release-alias-a").touch()
        first.wait(timeout=5)
        assert first.returncode == 0
        first_result = json.loads(
            (tmp_path / "alias-a-result.json").read_text())
        assert "exception" not in first_result
        assert first_result["result"]["result_code"] == 130

        first_identity = json.loads(
            (tmp_path / "alias-a-revalidated.json").read_text())
        second_identity = json.loads(
            (tmp_path / "alias-b-discovered.json").read_text())
        assert first_identity["pid"] != second_identity["pid"]
        assert first_identity["device_id"] != second_identity["device_id"]
        assert first_identity["host"] != second_identity["host"]
        assert first_identity["board_identity"] == second_identity["board_identity"]
    finally:
        (tmp_path / "cancel-alias-a").touch()
        (tmp_path / "cancel-alias-b").touch()
        (tmp_path / "release-alias-a").touch()
        stop(second)
        stop(first)


@pytest.mark.parametrize("method,request_value", [
    ("run_install", _request(action="install", teardown_mode="recorded",
                             record_id="r1")),
    ("run_install", _request(action="install", teardown_mode="force_agent_only")),
    ("run_uninstall", _request(action="uninstall", teardown_mode="none")),
    ("run_uninstall", _request(action="uninstall", teardown_mode="recorded",
                               record_id=None)),
    ("run_uninstall", _request(action="uninstall",
                               teardown_mode="force_agent_only", record_id="r1")),
])
def test_mode_dependent_controller_request_tuple_fails_before_contact(
        tmp_path, method, request_value):
    request_value = copy.deepcopy(request_value)
    if method == "run_install":
        request_value["wrapper_path"] = _write_unsigned_wrapper(tmp_path)
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls)
    controller = _controller(tmp_path, store, factory)
    with pytest.raises(ValueError):
        getattr(controller, method)(request_value, prepare, preflight, on_output,
                                    _Cancel())
    assert factory.calls == []
    assert calls == []


@pytest.mark.parametrize("forbidden", [
    {"iox_verification": _journal()},
    {"verification_state": "enabled"},
    {"ownership": True},
])
def test_request_cannot_supply_journal_state_or_ownership(tmp_path, forbidden):
    request = _request(
        wrapper_path=_write_unsigned_wrapper(tmp_path), **forbidden)
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    prepare, preflight, on_output = _callbacks([])
    controller = _controller(tmp_path, store, factory)
    with pytest.raises(ValueError):
        controller.run_install(request, prepare, preflight, on_output, _Cancel())
    assert factory.calls == []


@pytest.mark.parametrize("bad_job_id", [
    "missing", None, True, "1" * 15, "A" * 16, "g" * 16,
])
def test_request_requires_an_exact_existing_service_job_id_before_contact(
        tmp_path, bad_job_id):
    request = _request(wrapper_path=_write_unsigned_wrapper(tmp_path))
    if bad_job_id == "missing":
        del request["job_id"]
    else:
        request["job_id"] = bad_job_id
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls)
    controller = _controller(tmp_path, store, factory)
    with pytest.raises(ValueError, match="job_id|job id"):
        controller.run_install(
            request, prepare, preflight, on_output, _Cancel())
    assert factory.calls == []
    assert calls == []


def test_invalid_wrapper_is_refused_before_prepare_record_or_upload(tmp_path):
    wrapper = tmp_path / "not-a-wrapper.tar"
    wrapper.write_bytes(b"not a tar archive")
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls)
    controller = _controller(
        tmp_path, store, factory,
        enrollment_token_minter=lambda _device_id:
            pytest.fail("invalid wrapper minted an enrollment token"))
    result = controller.run_install(
        _request(wrapper_path=str(wrapper)), prepare, preflight, on_output,
        _Cancel())
    assert {"result_code", "returncode", "recovery_code", "record_id",
            "iox_verification", "iox_session"}.issubset(set(result))
    assert result["result_code"] == 2
    assert result["error_category"] == "wrapper_archive_invalid"
    assert not [call for call in calls if call[0] == "prepare"]
    assert not [call for call in store.calls if call[0] == "iox_begin"]
    assert not [call for call in factory.calls if call[0] == "upload"]
    assert not [call for call in factory.calls if call[0] == "command" and
                b"verification" in call[2].lower()]
    assert not [call for call in factory.calls if call[0] == "command" and
                any(token in call[2].lower() for token in
                    (b" stop ", b" deactivate ", b" uninstall ",
                     b" install ", b" activate ", b" start "))]


@pytest.mark.parametrize("markers,initial_state,reason", [
    (("package.sign",), "enabled", "marker_present"),
    (("package.cert",), "enabled", "marker_present"),
    ((), "disabled", "initially_disabled"),
])
def test_marker_or_initially_disabled_install_never_mutates_verification(
        tmp_path, markers, initial_state, reason):
    factory = _TransportFactory(verification=initial_state)
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory, markers=markers)

    assert result["result_code"] == 0
    assert _command_calls(
        factory, "verification_disable", "verification_enable") == []
    unchanged = [call for call in timeline
                 if call[:2] == ("iox_event", "unchanged")]
    assert len(unchanged) == 1
    assert unchanged[0][4]["reason"] == reason
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "unchanged"
    assert journal["unresolved"] is False
    binding = [call[4] for call in timeline if call[0] == "iox_begin"][0]
    assert binding["package_sign_present"] is ("package.sign" in markers)
    assert binding["package_cert_present"] is ("package.cert" in markers)


@pytest.mark.parametrize("case,read_states,reason", [
    ("initial_unknown", ["unknown"], "initial_read_unknown"),
    ("pre_disable_disabled", ["enabled", "disabled"],
     "pre_disable_changed"),
    ("pre_disable_unknown", ["enabled", "unknown"],
     "pre_disable_changed"),
])
def test_unknown_or_changed_pre_disable_read_refuses_before_ownership(
        tmp_path, case, read_states, reason):
    factory = _TransportFactory(read_states=read_states)
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    events = [call for call in timeline if call[0] == "iox_event"]
    assert not [call for call in events
                if call[1] in ("disable_confirmed", "installing",
                               "ownership_probe", "restore_intent")]
    unchanged = [call for call in events if call[1] == "unchanged"]
    assert len(unchanged) == 1
    assert unchanged[0][4]["reason"] == reason
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "unchanged"
    assert journal["unresolved"] is False
    if case.startswith("pre_disable"):
        assert journal["pre_disable_observation"]["state"] == read_states[-1]


def test_runtime_credentials_are_resolved_without_raw_request_and_token_mints_last(
        tmp_path):
    timeline = []
    wrapper_seen = []
    secrets = ("resolver-device-pass-SECRET", "resolver-enable-SECRET",
               "resolver-catalog-token-SECRET")
    predecessor_journal = _journal(
        record_id="old-r1", phase="disabled_confirmed", state="disabled",
        revision=2, unresolved=True)
    predecessor = _record(
        record_id="old-r1", journal=predecessor_journal)

    class OrderedStore(_StatefulStore):
        def iox_event(self, record_id, transaction_id, expected_revision,
                      expected_phase, event, evidence, capability=None):
            value = _StatefulStore.iox_event(
                self, record_id, transaction_id, expected_revision,
                expected_phase, event, evidence, capability)
            if (record_id == "old-r1" and not value["unresolved"] and
                    value["phase"] in
                    ("restored", "relinquished", "unchanged")):
                timeline.append(("predecessor_terminal", value["phase"],
                                 copy.deepcopy(value)))
            return value

    def resolver(reference):
        timeline.append(("credential_resolver", reference))
        return {"device_user": "fixture-user", "device_pass": secrets[0],
                "enable_secret": secrets[1]}

    def minter(device_id):
        timeline.append(("enrollment_token_minter", device_id))
        assert wrapper_seen and not os.path.exists(wrapper_seen[0])
        return secrets[2]

    def prepare(request, identity):
        timeline.append(("prepare", request, identity))
        assert identity["device_identity"] == _BOARD
        rendered = json.dumps(request, sort_keys=True)
        assert request["credential_ref"] == "device-profile-edge-01"
        assert all(secret not in rendered for secret in secrets)
        wrapper_seen.append(wrapper_path)
        os.unlink(wrapper_path)
        record = _record(record_id="new-r1")
        record["state"] = "planned"
        store.records["new-r1"] = record
        return "new-r1"

    def preflight(request, identity):
        timeline.append(("preflight", request, identity))
        return _Bag(device_identity=_BOARD, model="IE-3400-8T2S",
                    os_family="xe", platform="iox")

    store = OrderedStore(
        tmp_path, records=[predecessor],
        obligations=[predecessor_journal], calls=timeline)
    factory = _TransportFactory(
        calls=timeline, verification="disabled")
    wrapper_path = _write_unsigned_wrapper(tmp_path)
    recipe = _write_recipe_peer(
        tmp_path, operations=_install_operations(), cleanup_on_error=True)
    controller = _controller(
        tmp_path, store, factory, credential_resolver=resolver,
        enrollment_token_minter=minter,
        recipe_argv_by_action={"install": ["/bin/bash", recipe]})
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path), prepare, preflight,
            lambda stream, data: timeline.append(("output", stream, data)),
            _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0

    names = [call[0] for call in timeline]
    assert names.count("credential_resolver") == 1
    first_transport = min(
        index for index, call in enumerate(timeline)
        if (call[0] == "factory" or
            (call[0] == "command" and call[4] in
             ("identity_discovery", "identity_revalidation"))))
    assert names.index("credential_resolver") < first_transport
    predecessor_events = [call for call in timeline
                          if call[0] == "predecessor_terminal"]
    assert len(predecessor_events) == 1
    assert predecessor_events[0][1] == "restored"
    assert names.count("enrollment_token_minter") == 1
    assert names.index("predecessor_terminal") < names.index("preflight") < \
        names.index("prepare") < \
        names.index("enrollment_token_minter")
    assert store.records["old-r1"]["iox_verification"]["phase"] == "restored"


def test_install_orders_upload_ownership_and_restoration_before_activation(tmp_path):
    timeline = []
    store = _StatefulStore(tmp_path, calls=timeline)
    factory = _TransportFactory(calls=timeline)
    wrapper_path = _write_unsigned_wrapper(tmp_path)
    operations = _install_operations()
    recipe = _write_recipe_peer(tmp_path, operations=operations)

    def prepare(request, identity):
        timeline.append(("prepare", request, identity))
        store.records["new-r1"] = _record(record_id="new-r1")
        store.records["new-r1"]["state"] = "planned"
        return "new-r1"

    def preflight(request, identity):
        timeline.append(("preflight", request, identity))
        return _Bag(device_identity=_BOARD, model="IE-3400-8T2S",
                    os_family="xe", platform="iox")

    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"install": ["/bin/bash", recipe]})
    result = controller.run_install(
        _request(wrapper_path=wrapper_path), prepare, preflight,
        lambda stream, data: timeline.append(("output", stream, data)),
        _Cancel())
    assert result["result_code"] == 0
    assert result["returncode"] == 0
    factory_calls = [call for call in timeline if call[0] == "factory"]
    assert factory_calls
    assert all(len(call[1]) == 4 and call[2] == {} for call in factory_calls)

    def position(predicate):
        return next(index for index, call in enumerate(timeline)
                    if predicate(call))

    preflight_at = position(lambda call: call[0] == "preflight")
    prepare_at = position(lambda call: call[0] == "prepare")
    upload_at = position(lambda call: call[0] == "upload")
    begin_at = position(lambda call: call[0] == "iox_begin")
    intent_at = position(lambda call: call[:2] == ("iox_event", "disable_intent"))
    confirmed_at = position(
        lambda call: call[:2] == ("iox_event", "disable_confirmed"))
    stop_at = position(lambda call: call[0] == "command" and
                       b"app-hosting stop" in call[2].lower())
    install_at = position(lambda call: call[0] == "command" and
                          b"app-hosting install" in call[2].lower())
    probe_at = position(lambda call: call[:2] == ("iox_event", "ownership_probe"))
    restore_intent_at = position(
        lambda call: call[:2] == ("iox_event", "restore_intent"))
    enable_at = position(lambda call: call[0] == "command" and
                         b"verification enable" in call[2].lower())
    restored_at = position(lambda call: call[:2] == ("iox_event", "restored"))
    activate_at = position(lambda call: call[0] == "command" and
                           b"app-hosting activate" in call[2].lower())
    assert (preflight_at < prepare_at < begin_at < upload_at < intent_at <
            confirmed_at < stop_at < install_at < probe_at <
            restore_intent_at < enable_at < restored_at < activate_at)


def test_wrapper_upload_failure_is_primary_and_never_reaches_disable_or_teardown(
        tmp_path):
    factory = _TransportFactory(
        command_outcomes={"upload_wrapper": ["connection"]})
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert result["error_category"] == "connection"
    assert result["recovery_code"] is None
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "observed"
    assert journal["unresolved"] is False
    assert not [call for call in timeline
                if call[:2] == ("iox_event", "installing")]


@pytest.mark.parametrize("failure_purpose", ["app_install", "app_list"])
def test_application_install_or_deployed_poll_failure_keeps_primary_after_restore(
        tmp_path, failure_purpose):
    timeline = []
    factory = _TransportFactory(
        calls=timeline,
        command_outcomes={failure_purpose: ["rejected"]})
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert result["error_category"] == "rejected"
    assert result["returncode"] == 7
    assert result["recovery_code"] == 0
    failed_at = next(index for index, call in enumerate(timeline)
                     if call[0] == "command" and
                     call[4] == failure_purpose)
    installing_at = next(index for index, call in enumerate(timeline)
                         if call[:2] == ("iox_event", "installing"))
    assert installing_at < failed_at
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "restored"
    assert journal["unresolved"] is False


@pytest.mark.parametrize("restore_failure", ["enable_transport", "readback"])
def test_restore_failure_preserves_application_primary_and_unresolved_journal(
        tmp_path, restore_failure):
    outcomes = {"app_install": ["rejected"]}
    read_states = None
    if restore_failure == "enable_transport":
        outcomes["verification_enable"] = ["transport"]
    else:
        read_states = ["enabled", "enabled", "disabled", "disabled",
                       "unknown"]
    factory = _TransportFactory(
        read_states=read_states, command_outcomes=outcomes)
    result, store, _timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert result["error_category"] == "rejected"
    assert result["returncode"] == 7
    assert result["recovery_code"] == 4
    assert len(_command_calls(factory, "verification_enable")) == 1
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] in ("ownership_probe", "restore_intent")
    assert journal["unresolved"] is True


def test_exact_caf_retries_require_fresh_enabled_reads_and_new_durable_intents(
        tmp_path):
    clock = _Clock()
    factory = _TransportFactory(
        clock=clock,
        command_outcomes={
            "verification_disable": ["caf_transient", "caf_transient", None]})
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory, clock=clock,
        authority={"session_seconds": 600,
                   "restoration_reserve_seconds": 180})

    assert result["result_code"] == 0
    disables = _command_calls(factory, "verification_disable")
    assert len(disables) == 3
    intents = [call for call in timeline
               if call[:2] == ("iox_event", "disable_intent")]
    assert [call[2] for call in intents] == [0, 1, 2]
    assert all(call[4]["observation"]["state"] == "enabled"
               for call in intents)
    assert intents[0][4]["retry_command"] is None
    assert all(call[4]["retry_command"] is not None
               for call in intents[1:])
    sequence = [call[4] for call in timeline if call[0] == "command" and
                call[4] in ("verification_read", "verification_disable")]
    disable_indices = [index for index, purpose in enumerate(sequence)
                       if purpose == "verification_disable"]
    assert sequence[:disable_indices[0]].count("verification_read") == 2
    for previous, following in zip(disable_indices, disable_indices[1:]):
        assert sequence[previous + 1:following] == ["verification_read"]
    assert store.records["new-r1"]["iox_verification"]["phase"] == "restored"

    # Every retry retains its phase ceiling; upload and readiness polling are
    # additionally clipped before the final restoration reserve.
    session_deadline = clock.origin + 600.5
    ordinary_deadline = clock.origin + 420.5
    for call in [item for item in timeline if item[0] == "command"]:
        assert call[3] <= session_deadline
        if call[4] in ("verification_read", "verification_disable",
                       "verification_enable"):
            assert call[3] <= call[5] + 45.05
    uploads = [call for call in timeline if call[0] == "upload"]
    assert uploads and all(call[3] <= ordinary_deadline for call in uploads)
    polls = _command_calls(factory, "app_list")
    assert polls and all(call[3] <= ordinary_deadline and
                         call[3] <= call[5] + 180.05 for call in polls)


@pytest.mark.parametrize("post_caf_state", ["disabled", "unknown"])
def test_caf_retry_stops_when_fresh_read_is_not_enabled(
        tmp_path, post_caf_state):
    factory = _TransportFactory(
        read_states=["enabled", "enabled", post_caf_state],
        command_outcomes={"verification_disable": ["caf_transient"]})
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] in (3, 4)
    assert len(_command_calls(factory, "verification_disable")) == 1
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    assert not [call for call in timeline
                if call[:2] == ("iox_event", "disable_confirmed")]
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] in ("disable_intent", "indeterminate")
    assert journal["unresolved"] is True


def test_already_disabled_transition_text_never_confirms_ownership_or_teardown(
        tmp_path):
    factory = _TransportFactory(
        read_states=["enabled", "enabled"],
        command_outcomes={"verification_disable": ["already_disabled"]})
    result, _store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert len(_command_calls(factory, "verification_disable")) == 1
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    assert not [call for call in timeline
                if call[:2] == ("iox_event", "disable_confirmed")]


def test_failed_enable_response_consumes_the_only_send_and_stays_unresolved(
        tmp_path):
    factory = _TransportFactory(
        command_outcomes={"verification_enable": ["unsupported_response"]})
    result, store, _timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert result["recovery_code"] == 4
    assert len(_command_calls(factory, "verification_enable")) == 1
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "restore_intent"
    assert journal["unresolved"] is True


def test_elapsed_session_is_not_reset_after_a_successful_wrapper_upload(tmp_path):
    clock = _Clock()
    factory = _TransportFactory(
        clock=clock, advances={"upload_wrapper": 601})
    result, store, _timeline, _wrapper = _run_scripted_install(
        tmp_path, factory, clock=clock,
        authority={"session_seconds": 600,
                   "restoration_reserve_seconds": 180})

    assert result["result_code"] == 4
    assert result["error_category"] == "timeout"
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "observed"
    assert journal["unresolved"] is False


def test_disable_is_refused_when_install_ceiling_would_spend_restoration_reserve(
        tmp_path):
    clock = _Clock()
    factory = _TransportFactory(clock=clock)
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory, clock=clock,
        authority={"session_seconds": 569,
                   "restoration_reserve_seconds": 180})

    assert result["result_code"] == 4
    assert result["error_category"] == "timeout"
    assert len(_command_calls(factory, "verification_read")) >= 2
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    assert not [call for call in timeline
                if call[:2] == ("iox_event", "disable_intent")]
    journal = store.records["new-r1"]["iox_verification"]
    assert journal["phase"] == "observed"


def test_controller_uses_exact_identity_upload_and_application_deadlines(
        tmp_path):
    clock = _ExactClock()
    factory = _TransportFactory(
        clock=clock,
        advances={"upload_wrapper": 400, "app_install": 250,
                  "app_activate": 250, "upload_certificate": 890})
    result, _store, _timeline, _wrapper = _run_scripted_install(
        tmp_path, factory, clock=clock,
        authority={"session_seconds": 2200,
                   "restoration_reserve_seconds": 180})
    assert result["result_code"] == 0

    deadline_calls = [call for call in factory.calls
                      if call[0] == "command" and call[4] in (
                          "identity_discovery", "identity_revalidation",
                          "app_install", "app_activate", "app_start")]
    assert [call[4] for call in deadline_calls] == [
        "identity_discovery", "identity_revalidation", "app_install",
        "app_activate", "app_start"]
    commands = dict((call[4], call) for call in deadline_calls)
    for purpose in ("identity_discovery", "identity_revalidation"):
        call = commands[purpose]
        assert call[3] == min(call[5] + 75, clock.origin + 2200)

    ordinary_deadline = clock.origin + 2200 - 180
    for purpose in ("app_install", "app_activate", "app_start"):
        call = commands[purpose]
        assert call[3] == min(call[5] + 300, ordinary_deadline)
    assert commands["app_install"][3] < ordinary_deadline
    assert commands["app_start"][3] == ordinary_deadline

    uploads = [call for call in factory.calls if call[0] == "upload"]
    assert [call[4] for call in uploads] == [
        "upload_wrapper", "upload_certificate"]
    combined_upload_deadline = min(
        uploads[0][5] + 1800, ordinary_deadline)
    assert combined_upload_deadline < ordinary_deadline
    assert [call[3] for call in uploads] == [
        combined_upload_deadline, combined_upload_deadline]


@pytest.mark.parametrize("session_seconds,expected_wait,code,category", [
    (1000, 60, 2, "board_busy"), (50, 50, 4, "timeout")])
def test_board_lock_wait_is_clipped_to_sixty_seconds_and_the_session(
        tmp_path, monkeypatch, session_seconds, expected_wait, code, category):
    _module()
    import errno
    import fcntl
    import time

    clock = _ExactClock()
    real_flock = fcntl.flock
    real_sleep = time.sleep
    lock_attempts = []
    sleeps = []
    expected_deadline = clock.origin + expected_wait

    def contended_board_lock(descriptor, operation):
        try:
            path = os.readlink("/proc/self/fd/%d" % descriptor)
        except OSError:
            path = ""
        if ("/iox/locks/" in path and operation & fcntl.LOCK_EX and
                operation & fcntl.LOCK_NB):
            lock_attempts.append(clock.peek())
            raise BlockingIOError(errno.EWOULDBLOCK, "fixture contention")
        return real_flock(descriptor, operation)

    def advance_without_sleep(seconds):
        assert 0 <= seconds <= expected_wait
        sleeps.append(seconds)
        assert len(sleeps) <= 1000
        remaining = expected_deadline - clock.peek()
        assert remaining >= 0
        clock.advance(min(max(seconds, 0.1), remaining))

    factory = _TransportFactory(clock=clock)
    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), factory, clock=clock,
        session_seconds=session_seconds)
    monkeypatch.setattr(fcntl, "flock", contended_board_lock)
    monkeypatch.setattr(time, "sleep", advance_without_sleep)
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only"),
            prepare, preflight, on_output, _Cancel())
    finally:
        monkeypatch.setattr(fcntl, "flock", real_flock)
        monkeypatch.setattr(time, "sleep", real_sleep)
        controller.close()

    assert result["result_code"] == code
    assert result["error_category"] == category
    assert lock_attempts and max(lock_attempts) <= expected_deadline
    assert sleeps and clock.peek() == pytest.approx(expected_deadline)
    assert [call[4] for call in factory.calls if call[0] == "command"] == [
        "identity_discovery"]
    assert not [call for call in calls
                if call[0] in ("preflight", "prepare")]


@pytest.mark.parametrize("advance,expected_deadline", [
    (0, 1010), (994, 2000)])
def test_controller_cleanup_grace_never_extends_the_original_session(
        tmp_path, advance, expected_deadline):
    clock = _ExactClock()
    factory = _TransportFactory(clock=clock)

    class CancelAfterLockedIdentity(object):
        def __init__(self):
            self.advanced = False

        def __call__(self):
            revalidated = bool([call for call in factory.calls
                                if call[0] == "command" and
                                call[4] == "identity_revalidation"])
            if revalidated and not self.advanced:
                clock.advance(advance)
                self.advanced = True
            return revalidated

        def is_set(self):
            return self()

    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), factory, clock=clock,
        session_seconds=1000)
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only"),
            prepare, preflight, on_output, CancelAfterLockedIdentity())
    finally:
        controller.close()

    assert result["result_code"] == 130
    cleanup_deadlines = [call[1] for call in factory.calls
                         if call[0] == "cancel_and_reap"]
    assert cleanup_deadlines
    assert max(cleanup_deadlines) == expected_deadline
    assert all(deadline <= clock.origin + 1000
               for deadline in cleanup_deadlines)
    assert not [call for call in calls
                if call[0] in ("preflight", "prepare")]


@pytest.mark.parametrize("adopted", [False, True])
def test_legacy_and_adopted_uninstall_use_the_recorded_target_without_a_journal(
        tmp_path, adopted):
    record = _record(address="192.0.2.10", adopted=adopted)
    store = _StatefulStore(tmp_path, records=[record])
    factory = _TransportFactory()
    calls = []
    _unused_prepare, preflight, on_output = _callbacks(calls, record_id="r1")

    def prepare(request, identity):
        calls.append(("prepare", request, identity))
        current = store.get("r1", strict=True)
        assert current == record
        return "r1"
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    result = controller.run_uninstall(
        _request(action="uninstall", record_id="r1", address="198.51.100.99"),
        prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 0
    assert result["record_id"] == "r1"
    rendered_factory_calls = repr(factory.calls)
    assert "192.0.2.10" in rendered_factory_calls
    assert "198.51.100.99" not in rendered_factory_calls
    assert not [call for call in store.calls if call[0] == "iox_begin"]
    assert len([call for call in calls if call[0] == "prepare"]) == 1
    assert [call[0] for call in calls
            if call[0] in ("preflight", "prepare")] == [
                "preflight", "prepare"]
    assert len([call for call in store.calls if call[0] == "get"]) >= 2
    assert all(call[2] is True for call in store.calls if call[0] == "get")


def test_recorded_teardown_never_inherits_unrecorded_cleanup_paths(tmp_path):
    record = _record(address="192.0.2.10")
    seed = _request(action="uninstall", record_id="r1")["target"]
    seed["share_ios_path"] = "flash:operator/unowned"
    seed["share_guest_path"] = "/operator/unowned"
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path, records=[record]),
        _TransportFactory())
    try:
        projected = controller._record_target(record, seed, "uninstall")
    finally:
        controller.close()
    assert projected.get("share_ios_path") != "flash:operator/unowned"
    assert projected.get("share_guest_path") != "/operator/unowned"


@pytest.mark.parametrize("adopted", [False, True])
def test_record_without_historical_identity_requires_two_matching_live_reads(
        tmp_path, adopted):
    record = _record(address="192.0.2.10", adopted=adopted)
    del record["resolved"]["device_identity"]
    store = _StatefulStore(tmp_path, records=[record])
    identity = {"board": _BOARD, "model": "IE-3400-8T2S",
                "os_family": "xe"}
    factory = _TransportFactory(identity_results=[identity, identity])
    calls = []
    _unused_prepare, preflight, _unused_output = _callbacks(
        calls, record_id="r1")

    def prepare(request, live_identity):
        calls.append(("prepare", request, live_identity))
        current = store.get("r1", strict=True)
        assert current == record
        return "r1"

    def on_output(stream, data):
        calls.append(("output", stream, data))

    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", record_id="r1"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()

    assert result["result_code"] == 0
    assert [call[0] for call in calls
            if call[0] in ("preflight", "prepare")] == [
                "preflight", "prepare"]
    identity_purposes = [call[4] for call in factory.calls
                         if call[0] == "command" and
                         call[4].startswith("identity_")]
    assert identity_purposes == ["identity_discovery",
                                 "identity_revalidation"]
    assert factory.identity_results == []
    disclosure_parts = [json.dumps(result, sort_keys=True)]
    disclosure_parts.extend(
        data.decode("utf-8", "replace") if isinstance(data, bytes) else
        str(data) for kind, _stream, data in calls if kind == "output")
    disclosure = "\n".join(disclosure_parts)
    normalized = disclosure.lower().replace("_", " ")
    assert "historical" in normalized and "identity" in normalized
    assert "unavailable" in normalized or "missing" in normalized
    assert len(disclosure.encode("utf-8")) <= 8192
    assert not [call for call in store.calls if call[0] == "iox_begin"]
    assert "iox_verification" not in store.records["r1"]


@pytest.mark.parametrize("changed", ["board", "model", "os_family"])
def test_locked_identity_revalidation_must_match_the_preliminary_tuple(
        tmp_path, changed):
    discovered = {"board": _BOARD, "model": "IE-3400-8T2S",
                  "os_family": "xe"}
    revalidated = dict(discovered)
    replacements = {"board": "FOC9999WXYZ", "model": "IE-3400-16T2S",
                    "os_family": "xr"}
    revalidated[changed] = replacements[changed]
    factory = _TransportFactory(
        identity_results=[discovered, revalidated])
    store = _StatefulStore(tmp_path)
    calls = []
    prepare, preflight, on_output = _callbacks(calls)
    wrapper_path = _write_unsigned_wrapper(tmp_path)
    recipe_started = tmp_path / "recipe-started"
    recipe = tmp_path / "must-not-start.sh"
    recipe.write_text("#!/bin/bash\nprintf started > '%s'\nexit 99\n" %
                      recipe_started)
    recipe.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"install": ["/bin/bash", str(recipe)]})
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path), prepare, preflight,
            on_output, _Cancel())
    finally:
        controller.close()

    assert result["result_code"] != 0
    command_purposes = [call[4] for call in factory.calls
                        if call[0] == "command"]
    assert command_purposes == ["identity_discovery",
                                "identity_revalidation"]
    assert factory.identity_results == []
    assert not [call for call in factory.calls if call[0] == "upload"]
    assert not [call for call in store.calls if call[0] == "iox_begin"]
    assert not [call for call in calls if call[0] in ("preflight", "prepare")]
    assert not recipe_started.exists()


@pytest.mark.parametrize("change", [
    "address", "identity", "platform", "cleanup_input", "resources",
])
def test_recorded_uninstall_refuses_binding_change_without_retargeting(
        tmp_path, change):
    original = _record(address="192.0.2.10")
    changed = copy.deepcopy(original)
    if change == "address":
        changed["resolved"]["device_ip"] = "192.0.2.11"
    elif change == "identity":
        changed["resolved"]["device_identity"] = "FOC9999WXYZ"
    elif change == "platform":
        changed["resolved"]["platform"] = "guestshell"
    elif change == "cleanup_input":
        changed["resolved"]["package_fs"] = "sdflash:other/"
    else:
        assert change == "resources"
        changed["resources"] = [
            {"kind": "iox-app", "ownership": "operator-owned"}]
    store = _StatefulStore(tmp_path, records=[original])
    factory = _TransportFactory()
    calls = []
    _unused_prepare, preflight, on_output = _callbacks(calls, record_id="r1")

    def prepare(request, identity):
        calls.append(("prepare", request, identity))
        # Model an inventory/record edit after preliminary selection but before
        # final teardown authorization, regardless of which strict selection
        # helper the controller used for the first read.
        store.records["r1"] = copy.deepcopy(changed)
        current = store.get("r1", strict=True)
        if current != original:
            raise ValueError("recorded teardown binding changed")
        return "r1"

    controller = _controller(tmp_path, store, factory)
    result = controller.run_uninstall(
        _request(action="uninstall", record_id="r1"), prepare, preflight,
        on_output, _Cancel())
    assert result["result_code"] == 2
    assert len([call for call in calls if call[0] == "prepare"]) == 1
    mutating = [call for call in factory.calls if call[0] == "command" and
                any(word in call[2].lower() for word in
                    (b" stop ", b" deactivate ", b" uninstall ", b"no "))]
    assert mutating == []


def test_force_does_not_select_a_record_or_create_a_dummy_journal(tmp_path):
    records = [_record(record_id="old-a"), _record(record_id="old-b")]
    store = _StatefulStore(tmp_path, records=records)
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    result = controller.run_uninstall(
        _request(action="uninstall", teardown_mode="force_agent_only",
                 record_id=None, vlan=None, wrapper_path=None),
        prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 0
    assert result["record_id"] is None
    assert not [call for call in store.calls
                if call[0] == "recoverable_for_device"]
    assert not [call for call in store.calls if call[0] == "iox_begin"]
    assert len([call for call in calls if call[0] == "prepare"]) == 1
    assert [call[0] for call in calls
            if call[0] in ("preflight", "prepare")] == [
                "preflight", "prepare"]


def test_successful_predecessor_recovery_does_not_bind_force_recipe_to_record(
        tmp_path):
    journal = _journal(
        record_id="old-r1", phase="disabled_confirmed", state="disabled",
        revision=2, unresolved=True)
    record = _record(record_id="old-r1", journal=journal)
    store = _StatefulStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="disabled")
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    prepare, preflight, on_output = _callbacks([], record_id=None)
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only",
                     record_id=None),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0
    assert result["record_id"] is None
    assert result["iox_verification"] is None


def test_cleanup_stage_probe_uses_ios_filename_without_filesystem_prefix(
        tmp_path):
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    request = _request(
        action="uninstall", teardown_mode="force_agent_only", record_id=None)
    attempt = module._Attempt(
        controller, "uninstall", request, _Cancel(), False)
    attempt.target = {
        "package_fs": "flash:", "target_fs": "sdflash:",
        "pkg": "iris-arm64.tar", "management_type": "routed",
    }
    try:
        rendered = controller._render_command(
            attempt, "cleanup_stage_probe").decode("ascii")
    finally:
        controller.close()
    first = rendered.splitlines()[0]
    assert first == (
        "dir flash: | include iris-arm64.tar|iris-ca.pem|iris-catalog.pem")


@pytest.mark.parametrize("exit_intent,expected_code,expect_retirement", [
    (0, 0, True),
    (7, 4, False),
])
def test_force_on_replacement_board_retires_only_after_acknowledged_success(
        tmp_path, exit_intent, expected_code, expect_retirement):
    old_board = "FOC-OLD-BOARD"
    old_journal = _journal(
        phase="indeterminate", state="unknown", revision=7,
        board=old_board, unresolved=True)
    old_record = _record(board=old_board, journal=old_journal)
    before = json.dumps(
        old_record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timeline = []
    finish_path = tmp_path / "force-finish-ack"

    class OrderedStore(_StatefulStore):
        def sync_finish_ack(self):
            if (finish_path.exists() and
                    not [call for call in self.calls
                         if call[0] == "finish_ack"]):
                assert finish_path.read_bytes() == b"finish_ack\n"
                self.calls.append(("finish_ack",))

        def retire_device(self, device_id, reason):
            self.sync_finish_ack()
            return _StatefulStore.retire_device(self, device_id, reason)

    store = OrderedStore(
        tmp_path, records=[old_record], obligations=[old_journal],
        calls=timeline)
    factory = _TransportFactory(board=_BOARD, calls=timeline)
    prepare, preflight, on_output = _callbacks(timeline, record_id=None)
    operations = [
        ("command", {"name": "app_stop"}),
        ("command", {"name": "app_deactivate"}),
        ("command", {"name": "app_uninstall"}),
        ("command", {"name": "remove_app_config"}),
        ("command", {"name": "cleanup_config_probe"}),
        ("command", {"name": "cleanup_stage_probe"}),
        ("finish", {"exit_intent": exit_intent}),
    ]
    recipe = _write_recipe_peer(
        tmp_path, operations=operations, event_path=str(finish_path))
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only",
                     record_id=None),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    store.sync_finish_ack()

    assert result["result_code"] == expected_code
    assert [call[0] for call in timeline
            if call[0] in ("preflight", "prepare")] == [
                "preflight", "prepare"]
    assert not [call for call in store.calls if call[0] == "iox_event"]
    ordered = [call[0] for call in timeline
               if call[0] in ("finish_ack", "retire_device")]
    if expect_retirement:
        assert ordered == ["finish_ack", "retire_device"]
        assert store.records["r1"]["state"] == "abandoned"
        assert store.records["r1"]["iox_verification"] == old_journal
    else:
        assert result["returncode"] == 7
        assert ordered == ["finish_ack"]
        after = json.dumps(
            store.records["r1"], sort_keys=True,
            separators=(",", ":")).encode("utf-8")
        assert after == before
        assert store.records["r1"]["iox_verification"] == old_journal


def test_private_recipe_accepts_the_exact_force_null_tuple(tmp_path):
    recipe = _write_recipe_peer(tmp_path)
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    result = controller.run_uninstall(
        _request(action="uninstall", teardown_mode="force_agent_only",
                 record_id=None), prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 0
    assert result["record_id"] is None
    assert result["returncode"] == 0
    assert [call[0] for call in calls
            if call[0] in ("preflight", "prepare")] == [
                "preflight", "prepare"]


def test_terminal_result_preserves_nonzero_recipe_exit_intent(tmp_path):
    operations = [
        ("command", {"name": "app_stop"}),
        ("command", {"name": "app_deactivate"}),
        ("command", {"name": "app_uninstall"}),
        ("command", {"name": "remove_app_config"}),
        ("command", {"name": "cleanup_config_probe"}),
        ("command", {"name": "cleanup_stage_probe"}),
        ("finish", {"exit_intent": 7}),
    ]
    recipe = _write_recipe_peer(tmp_path, operations=operations)
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    prepare, preflight, on_output = _callbacks([], record_id=None)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    result = controller.run_uninstall(
        _request(action="uninstall", teardown_mode="force_agent_only",
                 record_id=None), prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 4
    assert result["returncode"] == 7
    assert result["recovery_code"] is None


@pytest.mark.parametrize("fault", [
    "force_fabricates_transaction", "mode_change", "replay"])
def test_private_recipe_rejects_partial_tuple_mode_change_and_replay(
        tmp_path, fault):
    recipe = _write_recipe_peer(tmp_path, fault=fault)
    store = _StatefulStore(tmp_path)
    factory = _TransportFactory()
    prepare, preflight, on_output = _callbacks([], record_id=None)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    result = controller.run_uninstall(
        _request(action="uninstall", teardown_mode="force_agent_only",
                 record_id=None), prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 4
    assert result["returncode"] is not None
    mutating = [call for call in factory.calls if call[0] == "command" and
                any(word in call[2].lower() for word in
                    (b" stop ", b" deactivate ", b" uninstall ", b"no "))]
    if fault != "replay":
        assert mutating == []
    else:
        assert len([call for call in mutating
                    if b" stop " in call[2].lower()]) == 1
        assert not [call for call in mutating
                    if b" deactivate " in call[2].lower() or
                    b" uninstall " in call[2].lower()]


def test_unresolved_target_board_obligation_blocks_force_before_cleanup(tmp_path):
    obligation = _journal(phase="restore_intent", state="disabled", revision=4)
    store = _StatefulStore(tmp_path, records=[_record()],
                           obligations=[obligation])
    factory = _TransportFactory(verification="disabled")
    prepare, preflight, on_output = _callbacks([], record_id=None)
    controller = _controller(tmp_path, store, factory)
    result = controller.run_uninstall(
        _request(action="uninstall", teardown_mode="force_agent_only"),
        prepare, preflight, on_output, _Cancel())
    assert result["result_code"] == 3
    assert result["record_id"] is None
    # A recovered disabled restore intent has no live continuation and must not
    # be converted into an automatic enable.
    assert not [call for call in factory.calls if call[0] == "command" and
                b"verification enable" in call[2].lower()]


@pytest.mark.parametrize("deployment_state", ["removed", "abandoned",
                                               "superseded"])
def test_terminal_deployment_record_does_not_hide_recoverable_board_obligation(
        tmp_path, deployment_state):
    journal = _journal(
        phase="disabled_confirmed", state="disabled", revision=2,
        unresolved=True)
    record = _record(journal=journal)
    record["state"] = deployment_state
    store = _StatefulStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="disabled")
    controller = _controller(tmp_path, store, factory)
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()

    assert result["result_code"] == 0
    assert store.records["r1"]["state"] == deployment_state
    recovered = store.records["r1"]["iox_verification"]
    assert recovered["phase"] == "restored"
    assert recovered["unresolved"] is False
    assert len(_command_calls(factory, "verification_enable")) == 1


def test_recovery_transcripts_consume_one_shared_capacity_pool(tmp_path):
    # Small injected limits establish the global-pool rule without allocating
    # thousands of production-sized authority files.
    _write_header_transcript(tmp_path, "1" * 32)
    _write_header_transcript(tmp_path, "2" * 32)
    journals = [
        _journal(record_id="r1", phase="disable_intent", state="enabled",
                 revision=1, board="BOARD-A"),
        _journal(record_id="r2", phase="disable_intent", state="enabled",
                 revision=1, board="BOARD-B"),
        _journal(record_id="r3", phase="disable_intent", state="enabled",
                 revision=1, board="BOARD-C"),
    ]
    records = [_record(record_id=journal["record_id"], board=journal["board_identity"],
                       journal=journal) for journal in journals]
    store = _StatefulStore(tmp_path, records=records, obligations=journals)
    factory = _TransportFactory(verification="enabled")
    controller = _controller(
        tmp_path, store, factory,
        test_limits={"session_files": 4,
                     "transcript_files": 4,
                     "ordinary_transcripts": 2,
                     "active_fences": 4})
    factory.board = "BOARD-A"
    assert controller.recover_board("BOARD-A", _Cancel())["result_code"] == 0
    factory.board = "BOARD-B"
    assert controller.recover_board("BOARD-B", _Cancel())["result_code"] == 0
    before = len(factory.calls)
    factory.board = "BOARD-C"
    refused = controller.recover_board("BOARD-C", _Cancel())
    assert refused["result_code"] == 5
    assert refused["error_category"] == "transcript_limit"
    assert len(factory.calls) == before


def test_reconcile_enabled_is_observational_and_sends_no_mutation(tmp_path):
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    record = _record(journal=journal)
    store = _StatefulStore(tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="enabled")
    controller = _controller(tmp_path, store, factory)
    result = controller.reconcile_enabled(
        "r1", journal["transaction_id"], 7, True, _Cancel())
    assert result["result_code"] == 0
    events = [call for call in store.calls if call[0] == "iox_event"]
    assert events[-1][1] == "reconcile_enabled"
    assert events[-1][4]["acknowledge_external_resolution"] is True
    assert not [call for call in factory.calls if call[0] == "command" and
                (b"verification enable" in call[2].lower() or
                 b"verification disable" in call[2].lower())]


def test_reconcile_requires_ack_and_fresh_enabled_read(tmp_path):
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    factory = _TransportFactory(verification="disabled")
    controller = _controller(tmp_path, store, factory)
    with pytest.raises(ValueError, match="acknowledge"):
        controller.reconcile_enabled(
            "r1", journal["transaction_id"], 7, False, _Cancel())
    assert factory.calls == []
    result = controller.reconcile_enabled(
        "r1", journal["transaction_id"], 7, True, _Cancel())
    assert result["result_code"] == 3
    assert not [call for call in store.calls if call[0] == "iox_event" and
                call[1] == "reconcile_enabled"]


def test_reconciliation_does_not_clear_an_active_process_fence(tmp_path):
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    transcript_ref = _write_header_transcript(tmp_path, "3" * 32)
    fence_path = _write_active_fence(tmp_path, transcript_ref)
    before = fence_path.read_bytes()
    factory = _TransportFactory(verification="enabled")
    controller = _controller(tmp_path, store, factory)
    result = controller.reconcile_enabled(
        "r1", journal["transaction_id"], 7, True, _Cancel())
    assert result["result_code"] == 5
    assert result["error_category"] == "descendant_unreaped"
    assert fence_path.read_bytes() == before
    assert factory.calls == []
    assert not [call for call in store.calls if call[0] == "iox_event" and
                call[1] == "reconcile_enabled"]


def test_summary_for_device_has_only_safe_obligations_and_session_projection(
        tmp_path):
    safe = {
        "schema_version": 1, "record_id": "r1", "transaction_id": "d" * 32,
        "revision": 7, "board_identity": _BOARD, "prior_state": "enabled",
        "current_state": "unknown", "phase": "indeterminate",
        "unresolved": True, "created_at": 10, "updated_at": 20,
        "observed_at": 20, "terminal_at": None,
        "error_category": "readback_unknown"}
    store = _StatefulStore(tmp_path)
    store.summaries = [safe]
    controller = _controller(tmp_path, store, _TransportFactory())
    value = controller.summary_for_device("edge-01")
    assert set(value) == {"iox_verification_obligations", "iox_sessions"}
    assert value["iox_verification_obligations"] == [safe]
    assert value["iox_sessions"] == []
    assert "controller_id" not in json.dumps(value)
    assert "wrapper_sha256" not in json.dumps(value)
    assert "transcript" not in json.dumps(value)


def test_verification_read_fence_durability_failure_stops_all_later_commands(
        tmp_path, monkeypatch):
    module = _module()
    factory = _TransportFactory(verification="enabled")
    original = module.IoxController._update_fence
    failed = []

    def fail_after_fresh_read(controller, attempt, *args, **kwargs):
        if (not failed and attempt.record_id == "new-r1" and
                attempt.command_id >= 3):
            failed.append(attempt.command_id)
            raise OSError("injected fence durability failure")
        return original(controller, attempt, *args, **kwargs)

    monkeypatch.setattr(module.IoxController, "_update_fence",
                        fail_after_fresh_read)
    result, unused_store, unused_timeline, unused_wrapper = \
        _run_scripted_install(tmp_path, factory)
    assert failed
    assert result["result_code"] != 0
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


def test_discovery_cleanup_failure_dominates_the_original_error(
        tmp_path, monkeypatch):
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    abandoned = []

    class Supervisor(object):
        pid = os.getpid()
        start_ticks = 0
        def reap_all(self, deadline):
            return False
        def release(self, deadline):
            pytest.fail("unreaped discovery supervisor was released")
        def abandon(self, deadline):
            abandoned.append(deadline)
            return False

    monkeypatch.setattr(module._SupervisorClient, "start",
                        classmethod(lambda cls, *args: Supervisor()))
    monkeypatch.setattr(
        controller, "_make_transport",
        lambda *args: (_ for _ in ()).throw(
            RuntimeError("injected discovery construction failure")))
    attempt = module._Attempt(
        controller, "install", _request(), _Cancel(), False)
    attempt.target = _request()["target"]
    try:
        with pytest.raises(module._ControllerFailure) as failed:
            controller._discover_and_lock(attempt)
    finally:
        controller.close()
    assert failed.value.category == "descendant_unreaped"
    assert failed.value.code == 5
    assert len(abandoned) == 1


@pytest.mark.parametrize("fault", [
    "missing_transcript", "attempt_mismatch", "incomplete_transcript",
    "boolean_schema", "zero_supervisor_pid",
])
def test_reaped_fence_requires_closed_bound_committed_transcript(
        tmp_path, fault):
    reference = _write_header_transcript(tmp_path, "4" * 32)
    fence_path = _write_active_fence(tmp_path, reference)
    fence = json.loads(fence_path.read_text())
    fence["state"] = "reaped"
    transcript = (tmp_path / "iox" / "transcripts" /
                  (reference["id"] + ".transcript"))
    if fault == "missing_transcript":
        transcript.unlink()
    elif fault == "attempt_mismatch":
        fence["attempt_id"] = "5" * 32
    elif fault == "incomplete_transcript":
        transcript.write_bytes(b"\x00\x00\x00\x10{")
        fence["transcript_ref"]["stored_bytes"] = 5
    elif fault == "boolean_schema":
        fence["schema_version"] = True
    else:
        fence["supervisor_pid"] = 0
    fence_path.write_text(json.dumps(fence, sort_keys=True))
    fence_path.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        _controller(tmp_path, _StatefulStore(tmp_path), _TransportFactory())


def test_transcript_quota_check_and_creation_share_the_store_lock(
        tmp_path, monkeypatch):
    module = _module()
    import iox_transport
    held = [False]
    observed = []

    class Lock(object):
        def __enter__(self):
            assert not held[0]
            held[0] = True
        def __exit__(self, *unused):
            held[0] = False

    class LockedStore(_StatefulStore):
        def _store_lock(self):
            return Lock()

    original = iox_transport._TranscriptWriter

    def checked_writer(*args, **kwargs):
        observed.append(held[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(iox_transport, "_TranscriptWriter", checked_writer)
    controller = _controller(tmp_path, LockedStore(tmp_path),
                             _TransportFactory())
    attempt = controller._new_attempt("install", _request(), _Cancel())
    with controller._active_lock:
        controller._active.discard(attempt)
    controller.close()
    assert observed == [True]


def test_authority_scan_refuses_capacity_without_materializing_directory(
        tmp_path, monkeypatch):
    controller = _controller(tmp_path, _StatefulStore(tmp_path),
                             _TransportFactory())
    _write_header_transcript(tmp_path, "6" * 32)
    _write_header_transcript(tmp_path, "7" * 32)
    real_scandir = os.scandir
    consumed = []

    class Entries(object):
        def __init__(self, entries):
            self.entries = entries
        def __iter__(self):
            return self
        def __next__(self):
            value = next(self.entries)
            consumed.append(value.name)
            if len(consumed) > 2:
                pytest.fail("authority scan consumed beyond limit plus one")
            return value
        def close(self):
            self.entries.close()
        def __enter__(self):
            return self
        def __exit__(self, *unused):
            self.close()

    monkeypatch.setattr(os, "listdir", lambda *args, **kwargs:
                        pytest.fail("authority scan materialized os.listdir"))
    monkeypatch.setattr(os, "scandir", lambda *args, **kwargs:
                        Entries(real_scandir(*args, **kwargs)))
    try:
        with pytest.raises(ValueError, match="capacity"):
            controller._scan_directory(
                str(tmp_path / "iox" / "transcripts"), ".transcript", 1,
                1024 * 1024)
    finally:
        controller.close()
    assert len(consumed) == 2


def test_minted_catalog_token_is_stream_redacted_before_recipe_output(
        tmp_path):
    token = b"fixture-catalog-token-SECRET"
    factory = _TransportFactory(verification="enabled")
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, prefix_chunks=(token[:11], token[11:]))
    rendered = b"".join(
        call[2].encode("utf-8") if isinstance(call[2], str) else call[2]
        for call in timeline if call[0] == "output")
    assert result["result_code"] == 0
    assert token not in rendered
    assert b"<redacted>" in rendered
    assert factory.created[-1].config["credentials"]["CATALOG_TOKEN"] == \
        token.decode("ascii")


@pytest.mark.parametrize("record_id,transaction_id,revision", [
    ("r1\n", "d" * 32, 1),
    ("r1", "d" * 31, 1),
    ("r1", "d" * 32, True),
    ("r1", "d" * 32, -1),
])
def test_reconcile_rejects_malformed_binding_before_attempt(
        tmp_path, record_id, transaction_id, revision):
    journal = _journal(phase="indeterminate", state="unknown", revision=1)
    store = _StatefulStore(
        tmp_path, records=[_record(journal=journal)], obligations=[journal])
    factory = _TransportFactory(verification="enabled")
    controller = _controller(tmp_path, store, factory)
    try:
        with pytest.raises(ValueError):
            controller.reconcile_enabled(
                record_id, transaction_id, revision, True, _Cancel())
    finally:
        controller.close()
    assert factory.calls == []


@pytest.mark.parametrize("operation", [
    "install", "uninstall", "recover", "reconcile",
])
def test_session_deadline_starts_before_strict_pre_attempt_store_reads(
        tmp_path, operation):
    clock = _ExactClock()
    journal = _journal(
        phase="indeterminate", state="unknown", revision=7,
        unresolved=True)
    record = _record(journal=journal)

    class SlowStore(_StatefulStore):
        armed = False
        consumed = False
        def consume(self):
            if self.armed and not self.consumed:
                self.consumed = True
                clock.advance(200)
        def list(self, *args, **kwargs):
            if operation == "install":
                self.consume()
            return _StatefulStore.list(self, *args, **kwargs)
        def get(self, *args, **kwargs):
            if operation in ("uninstall", "reconcile"):
                self.consume()
            return _StatefulStore.get(self, *args, **kwargs)
        def iox_obligations(self, *args, **kwargs):
            if operation == "recover":
                self.consume()
            return _StatefulStore.iox_obligations(self, *args, **kwargs)

    store = SlowStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="enabled", clock=clock)
    controller = _controller(
        tmp_path, store, factory, clock=clock,
        session_seconds=100, restoration_reserve_seconds=10)
    store.armed = True
    prepare, preflight, on_output = _callbacks([], record_id="r1")
    try:
        if operation == "install":
            result = controller.run_install(
                _request(wrapper_path=_write_unsigned_wrapper(tmp_path)),
                prepare, preflight, on_output, _Cancel())
        elif operation == "uninstall":
            result = controller.run_uninstall(
                _request(action="uninstall", record_id="r1"),
                prepare, preflight, on_output, _Cancel())
        elif operation == "recover":
            result = controller.recover_board(_BOARD, _Cancel())
        else:
            result = controller.reconcile_enabled(
                "r1", journal["transaction_id"], 7, True, _Cancel())
    finally:
        controller.close()
    assert store.consumed is True
    assert result["result_code"] == 4
    assert result["error_category"] == "timeout"
    assert factory.calls == []


def test_force_retirement_runs_while_physical_board_lock_is_held(tmp_path):
    import fcntl

    checks = []

    class LockedRetirementStore(_StatefulStore):
        def retire_device(self, device_id, reason):
            import hashlib
            lock_name = hashlib.sha256(
                b"IRIS-IOX-BOARD-v1\0" + _BOARD.encode("ascii")
            ).hexdigest() + ".lock"
            descriptor = os.open(
                str(tmp_path / "iox" / "locks" /
                    lock_name), os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                checks.append((device_id, reason))
            finally:
                os.close(descriptor)
            return []

    store = LockedRetirementStore(tmp_path)
    factory = _TransportFactory(verification="enabled")
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    prepare, preflight, on_output = _callbacks([], record_id=None)
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0
    assert len(checks) == 1


class _PrivateClient(object):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, request):
        self.calls.append(copy.deepcopy(request))
        return copy.deepcopy(self.responses.pop(0))

    def close(self):
        self.calls.append({"operation": "close"})


@pytest.mark.parametrize("fault", [
    "valid", "peer", "request_domain", "boolean_schema", "extra_key",
    "oversized"])
def test_control_server_authenticates_raw_peer_and_domain_before_dispatch(
        tmp_path, monkeypatch, fault):
    module = _module()
    import socket
    import struct

    controller_id = "c" * 32
    job_id = "0123456789abcdef"
    dispatched = []
    logical_response = {"error": "job not found", "job_id": job_id}

    def dispatch(request):
        dispatched.append(copy.deepcopy(request))
        return copy.deepcopy(logical_response)

    server = module.IoxControlServer(
        str(tmp_path), controller_id, dispatch)
    server.start()
    socket_path = tmp_path / "iox" / "control.sock"
    metadata = os.lstat(str(socket_path))
    assert stat.S_ISSOCK(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()

    if fault == "peer":
        real_credentials = module._control_peer_credentials

        def foreign_credentials(connection):
            pid, uid, gid = real_credentials(connection)
            return pid, uid + 1, gid

        monkeypatch.setattr(
            module, "_control_peer_credentials", foreign_credentials)

    request = {
        "schema_version": True if fault == "boolean_schema" else 1,
        "controller_id": ("d" * 32 if fault == "request_domain" else
                          controller_id),
        "request": {"operation": "job", "job_id": job_id,
                    "wait": False},
    }
    if fault == "extra_key":
        request["unexpected"] = True
    body = json.dumps(
        request, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")

    def receive_exact(connection, size):
        value = b""
        while len(value) < size:
            chunk = connection.recv(size - len(value))
            assert chunk
            value += chunk
        return value

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1.0)
    try:
        client.connect(str(socket_path))
        wire = (struct.pack("!I", 65537) if fault == "oversized" else
                struct.pack("!I", len(body)) + body)
        client.sendall(wire)
        if fault == "valid":
            header = receive_exact(client, 4)
            length = struct.unpack("!I", header)[0]
            assert 1 <= length <= 65536
            response_body = receive_exact(client, length)
            response = json.loads(response_body.decode("utf-8"))
            assert response_body == json.dumps(
                response, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")
            assert response == {
                "schema_version": 1, "controller_id": controller_id,
                "response": logical_response}
        else:
            assert client.recv(1) == b""
    finally:
        client.close()
        server.close()

    assert not socket_path.exists()
    if fault == "valid":
        assert dispatched == [request["request"]]
    else:
        assert dispatched == []


def test_control_server_dispatches_only_one_request_per_connection(tmp_path):
    module = _module()
    import socket
    import struct

    controller_id = "c" * 32
    job_id = "0123456789abcdef"
    dispatched = []

    def dispatch(request):
        dispatched.append(copy.deepcopy(request))
        return {"error": "job not found", "job_id": job_id}

    server = module.IoxControlServer(
        str(tmp_path), controller_id, dispatch)
    server.start()
    logical = {"operation": "job", "job_id": job_id, "wait": False}
    request = {"schema_version": 1, "controller_id": controller_id,
               "request": logical}
    body = json.dumps(
        request, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    frame = struct.pack("!I", len(body)) + body
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1.0)
    try:
        client.connect(str(tmp_path / "iox" / "control.sock"))
        client.sendall(frame)
        header = b""
        while len(header) < 4:
            chunk = client.recv(4 - len(header))
            assert chunk
            header += chunk
        length = struct.unpack("!I", header)[0]
        response = b""
        while len(response) < length:
            chunk = client.recv(length - len(response))
            assert chunk
            response += chunk
        assert json.loads(response.decode("utf-8"))["response"] == {
            "error": "job not found", "job_id": job_id}
        try:
            client.sendall(frame)
        except (BrokenPipeError, ConnectionResetError):
            pass
        else:
            assert client.recv(1) == b""
    finally:
        client.close()
        server.close()

    assert dispatched == [logical]


@pytest.mark.parametrize("partial", [b"", b"\x00\x00"])
def test_control_server_close_is_bounded_with_an_incomplete_client(
        tmp_path, monkeypatch, partial):
    module = _module()
    import socket
    import threading

    accepted = threading.Event()
    real_credentials = module._control_peer_credentials

    def observed_credentials(connection):
        value = real_credentials(connection)
        accepted.set()
        return value

    monkeypatch.setattr(
        module, "_control_peer_credentials", observed_credentials)
    dispatched = []
    server = module.IoxControlServer(
        str(tmp_path), "c" * 32,
        lambda request: dispatched.append(copy.deepcopy(request)))
    server.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1.0)
    client.connect(str(tmp_path / "iox" / "control.sock"))
    if partial:
        client.sendall(partial)
    assert accepted.wait(1.0)

    completed = threading.Event()
    close_errors = []

    def close_server():
        try:
            server.close()
        except BaseException as exc:
            close_errors.append(exc)
        finally:
            completed.set()

    closer = threading.Thread(target=close_server)
    closer.daemon = True
    closer.start()
    bounded = completed.wait(1.0)
    client.close()
    closer.join(1.0)

    assert bounded and not closer.is_alive()
    assert close_errors == []
    assert dispatched == []
    assert not (tmp_path / "iox" / "control.sock").exists()


@pytest.mark.parametrize("shape", ["symlink", "nonsocket"])
def test_control_server_refuses_a_preexisting_endpoint_without_replacing_it(
        tmp_path, shape):
    module = _module()
    iox_dir = tmp_path / "iox"
    iox_dir.mkdir(mode=0o700)
    socket_path = iox_dir / "control.sock"
    target = tmp_path / "endpoint-target"
    target.write_bytes(b"preserve endpoint\n")
    if shape == "symlink":
        socket_path.symlink_to(target)
    else:
        socket_path.write_bytes(b"preserve endpoint\n")
        socket_path.chmod(0o600)
    before = os.lstat(str(socket_path))
    dispatched = []
    server = module.IoxControlServer(
        str(tmp_path), "c" * 32,
        lambda request: dispatched.append(copy.deepcopy(request)))
    try:
        with pytest.raises((OSError, RuntimeError, ValueError)):
            server.start()
    finally:
        server.close()

    after = os.lstat(str(socket_path))
    assert (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode)) == (
        before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
    assert dispatched == []
    assert target.read_bytes() == b"preserve endpoint\n"
    if shape == "nonsocket":
        assert socket_path.read_bytes() == b"preserve endpoint\n"


def test_control_server_close_preserves_a_replacement_endpoint(tmp_path):
    module = _module()
    server = module.IoxControlServer(
        str(tmp_path), "c" * 32,
        lambda _request: {"error": "job not found",
                          "job_id": "0123456789abcdef"})
    server.start()
    socket_path = tmp_path / "iox" / "control.sock"
    created = os.lstat(str(socket_path))
    assert stat.S_ISSOCK(created.st_mode)
    socket_path.unlink()
    socket_path.write_bytes(b"replacement endpoint\n")
    replacement = os.lstat(str(socket_path))
    assert (replacement.st_dev, replacement.st_ino) != (
        created.st_dev, created.st_ino)

    server.close()

    assert socket_path.read_bytes() == b"replacement endpoint\n"


@pytest.mark.parametrize("fault", [
    "valid", "owner", "mode", "symlink", "nonsocket", "peer",
    "request_domain", "response_domain", "authority_boolean_schema",
    "response_boolean_schema",
])
def test_default_cli_client_uses_authenticated_controller_domain_socket(
        tmp_path, monkeypatch, fault):
    """Exercise the real local-client path against one bounded v1 peer."""
    module = _module()
    import socket
    import struct
    import threading

    controller_id = "c" * 32
    other_controller = "d" * 32
    job_id = "0123456789abcdef"
    iox_dir = tmp_path / "iox"
    iox_dir.mkdir(mode=0o700)
    record_store = tmp_path / "deployment_records.json"
    record_store.write_text('{"records":{}}')
    record_store.chmod(0o600)
    authority_path = iox_dir / "authority.json"
    authority = {
        "schema_version": (True if fault == "authority_boolean_schema" else 1),
        "controller_id": controller_id,
        "record_store": os.path.realpath(str(record_store)),
    }
    authority_path.write_text(json.dumps(
        authority, sort_keys=True, separators=(",", ":")))
    authority_path.chmod(0o600)
    socket_path = iox_dir / "control.sock"

    real_socket = socket.socket
    listener = real_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener_path = (iox_dir / "listening.sock" if
                     fault in ("symlink", "nonsocket") else socket_path)
    listener.bind(str(listener_path))
    listener_path.chmod(0o600)
    if fault == "symlink":
        socket_path.symlink_to(listener_path.name)
    elif fault == "nonsocket":
        socket_path.write_bytes(b"not a socket\n")
        socket_path.chmod(0o600)
    elif fault == "mode":
        socket_path.chmod(0o666)
    listener.listen(1)
    listener.settimeout(1.0)
    events = []
    server_error = []

    def receive_exact(peer, size):
        value = b""
        while len(value) < size:
            chunk = peer.recv(size - len(value))
            if not chunk:
                raise EOFError("short local-control frame")
            value += chunk
        return value

    def serve_once():
        peer = None
        try:
            descriptor, _address = listener._accept()
            peer = real_socket(
                socket.AF_UNIX, socket.SOCK_STREAM, fileno=descriptor)
            peer.settimeout(1.0)
            events.append("accepted")
            raw_credentials = peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize("3i"))
            _pid, uid, gid = struct.unpack("3i", raw_credentials)
            assert (uid, gid) == (os.geteuid(), os.getegid())
            events.append("peer_valid")
            length = struct.unpack("!I", receive_exact(peer, 4))[0]
            assert 1 <= length <= 65536
            payload = receive_exact(peer, length)
            request = json.loads(payload.decode("utf-8"))
            assert payload == json.dumps(
                request, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")
            assert set(request) == {"schema_version", "controller_id",
                                    "request"}
            assert request["schema_version"] == 1
            assert request["request"] == {
                "operation": "job", "job_id": job_id, "wait": False}
            events.append("request_valid")
            running_id = (other_controller if fault == "request_domain" else
                          controller_id)
            if request["controller_id"] != running_id:
                events.append("request_domain_rejected")
                return
            events.append("dispatched")
            logical = {
                "terminal": True, "state": "done", "job_id": job_id,
                "record_id": None, "result_code": 0, "returncode": 0,
                "recovery_code": None,
            }
            response_id = (other_controller if fault == "response_domain" else
                           controller_id)
            response = {"schema_version": (
                            True if fault == "response_boolean_schema" else 1),
                        "controller_id": response_id,
                        "response": logical}
            body = json.dumps(
                response, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False).encode("utf-8")
            peer.sendall(struct.pack("!I", len(body)) + body)
        except (EOFError, OSError, socket.timeout):
            if fault not in ("owner", "mode", "symlink", "nonsocket",
                              "peer", "authority_boolean_schema"):
                server_error.append("unexpected peer close")
        except BaseException as exc:
            server_error.append("%s: %s" % (type(exc).__name__, exc))
        finally:
            if peer is not None:
                peer.close()

    if fault == "owner":
        real_lstat = module.os.lstat
        real_stat = module.os.stat
        real_fstat = module.os.fstat
        owner_inodes = set()
        socket_metadata = real_lstat(str(socket_path))
        owner_inodes.add((socket_metadata.st_dev, socket_metadata.st_ino))

        def foreign_if_target(value):
            if (value.st_dev, value.st_ino) not in owner_inodes:
                return value
            fields = list(value)
            fields[4] = value.st_uid + 1
            return os.stat_result(fields)

        def wrong_owner(path):
            return foreign_if_target(real_lstat(path))

        def wrong_owner_stat(path, *args, **kwargs):
            return foreign_if_target(real_stat(path, *args, **kwargs))

        def wrong_owner_fstat(descriptor):
            return foreign_if_target(real_fstat(descriptor))

        class WrongOwnerSocket(object):
            def __init__(self, *args, **kwargs):
                self.inner = real_socket(*args, **kwargs)
                value = real_fstat(self.inner.fileno())
                owner_inodes.add((value.st_dev, value.st_ino))

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def __enter__(self):
                return self

            def __exit__(self, _kind, _value, _traceback):
                self.inner.close()

        monkeypatch.setattr(module.os, "lstat", wrong_owner)
        monkeypatch.setattr(module.os, "stat", wrong_owner_stat)
        monkeypatch.setattr(module.os, "fstat", wrong_owner_fstat)
        monkeypatch.setattr(module.socket, "socket", WrongOwnerSocket)
    elif fault == "peer":
        class WrongPeerSocket(object):
            def __init__(self, *args, **kwargs):
                self.inner = real_socket(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def __enter__(self):
                return self

            def __exit__(self, _kind, _value, _traceback):
                self.inner.close()

            def getsockopt(self, level, option, *args):
                value = self.inner.getsockopt(level, option, *args)
                if level == socket.SOL_SOCKET and option == socket.SO_PEERCRED:
                    pid, uid, gid = struct.unpack("3i", value)
                    return struct.pack("3i", pid, uid + 1, gid)
                return value

        monkeypatch.setattr(module.socket, "socket", WrongPeerSocket)

    thread = threading.Thread(target=serve_once)
    thread.daemon = True
    thread.start()
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    output = io.StringIO()
    refused = False
    code = None
    try:
        try:
            code = module.main(
                argv=["job", "--job-id", job_id], stdout=output)
        except (OSError, RuntimeError, ValueError):
            refused = True
        except SystemExit as exc:
            code = exc.code
    finally:
        listener.close()
        thread.join(2.0)
    assert not thread.is_alive()
    assert server_error == []

    if fault == "valid":
        assert code == 0 and refused is False
        assert json.loads(output.getvalue()) == {
            "terminal": True, "state": "done", "job_id": job_id,
            "record_id": None, "result_code": 0, "returncode": 0,
            "recovery_code": None}
        assert events[-1] == "dispatched"
    else:
        assert refused or code != 0
        assert not output.getvalue() or not json.loads(
            output.getvalue()).get("accepted", False)
        if fault == "request_domain":
            assert events[-1] == "request_domain_rejected"
        elif fault in ("response_domain", "response_boolean_schema"):
            assert events[-1] == "dispatched"
        else:
            assert "request_valid" not in events


def _run_cli(module, argv, responses):
    client = _PrivateClient(responses)
    output = io.StringIO()
    code = module.main(argv=argv, client_factory=lambda: client, stdout=output)
    return code, json.loads(output.getvalue()), client


def test_cli_acceptance_is_not_reported_as_terminal_success():
    module = _module()
    accepted = {"accepted": True, "job_id": "0123456789abcdef",
                "state": "queued", "terminal": False, "record_id": None,
                "result_code": None}
    code, emitted, client = _run_cli(
        module, ["submit-install", "--device-id", "edge-01"], [accepted])
    assert code == 0
    assert emitted == accepted
    assert client.calls[0]["operation"] == "submit-install"
    assert client.calls[0]["wait"] is False


def test_cli_force_is_an_explicit_submission_property():
    module = _module()
    accepted = {"accepted": True, "job_id": "0123456789abcdef",
                "state": "queued", "terminal": False, "record_id": None,
                "result_code": None}
    code, emitted, client = _run_cli(
        module, ["submit-uninstall", "--device-id", "edge-01",
                 "--force-agent-only"], [accepted])
    assert code == 0 and emitted == accepted
    assert client.calls[0]["force_agent_only"] is True
    assert client.calls[0]["operation"] == "submit-uninstall"


def test_cli_recover_submits_the_named_device_without_force():
    module = _module()
    accepted = {"accepted": True, "job_id": "0123456789abcdef",
                "state": "queued", "terminal": False, "record_id": "r1",
                "result_code": None}
    code, emitted, client = _run_cli(
        module, ["recover", "--device-id", "edge-01"], [accepted])
    assert code == 0 and emitted == accepted
    assert client.calls[0] == {
        "operation": "recover", "device_id": "edge-01", "wait": False}


def test_cli_wait_timeout_does_not_cancel_or_replay_the_job():
    module = _module()
    timed_out = {"job_id": "0123456789abcdef", "state": "running",
                 "terminal": False, "record_id": "r1", "result_code": None,
                 "wait_timed_out": True}
    code, emitted, client = _run_cli(
        module, ["job", "--job-id", "0123456789abcdef", "--wait",
                 "--wait-timeout", "1"], [timed_out])
    assert code == 4
    assert emitted == timed_out
    assert [call for call in client.calls if call.get("operation") == "job"] == [
        {"operation": "job", "job_id": "0123456789abcdef", "wait": True,
         "wait_timeout": 1}]
    assert not [call for call in client.calls
                if call.get("operation") in ("cancel", "submit-install",
                                             "submit-uninstall")]


def test_cli_terminal_result_keeps_normalized_recipe_and_recovery_codes_distinct():
    module = _module()
    terminal = {"terminal": True, "state": "error",
                "job_id": "0123456789abcdef", "record_id": "r1",
                "result_code": 4, "returncode": -9, "recovery_code": 5}
    code, emitted, _client = _run_cli(
        module, ["job", "--job-id", "0123456789abcdef", "--wait"],
        [terminal])
    assert code == 4
    assert emitted == terminal
    assert emitted["returncode"] == -9
    assert emitted["recovery_code"] == 5


def test_cli_missing_job_exits_two_without_claiming_a_terminal_result():
    module = _module()
    missing = {"error": "job not found", "job_id": "0123456789abcdef"}
    code, emitted, client = _run_cli(
        module, ["job", "--job-id", "0123456789abcdef"], [missing])
    assert code == 2
    assert emitted == missing
    assert client.calls[0]["operation"] == "job"
    assert "terminal" not in emitted and "result_code" not in emitted


def test_cli_reconcile_enabled_sends_only_bound_identity_and_acknowledgement():
    module = _module()
    accepted = {"accepted": True, "job_id": "0123456789abcdef",
                "state": "queued", "terminal": False, "record_id": "r1",
                "result_code": None}
    code, emitted, client = _run_cli(
        module,
        ["reconcile-enabled", "--record-id", "r1", "--transaction-id",
         "d" * 32, "--revision", "7",
         "--acknowledge-external-resolution"], [accepted])
    assert code == 0 and emitted == accepted
    assert client.calls[0] == {
        "operation": "reconcile-enabled", "record_id": "r1",
        "transaction_id": "d" * 32, "revision": 7,
        "acknowledge_external_resolution": True, "wait": False}


@pytest.mark.parametrize("argv", [
    ["submit-install", "--device-id", "edge-01", "--force-agent-only"],
    ["recover", "--device-id", "edge-01", "--force-agent-only"],
    ["reconcile-enabled", "--record-id", "r1", "--transaction-id", "d" * 32,
     "--revision", "7", "--acknowledge-external-resolution",
     "--force-agent-only"],
    ["job", "--job-id", "0123456789abcdef", "--wait",
     "--wait-timeout", "0"],
    ["job", "--job-id", "0123456789abcdef", "--wait",
     "--wait-timeout", "7201"],
])
def test_cli_rejects_force_on_other_operations_and_unbounded_waits(argv):
    module = _module()
    client = _PrivateClient([])
    with pytest.raises(SystemExit) as exc:
        module.main(argv=argv, client_factory=lambda: client, stdout=io.StringIO())
    assert exc.value.code == 2
    assert client.calls == []
