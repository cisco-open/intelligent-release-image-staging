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
from pathlib import Path
import re
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
        self.app_state = "RUNNING"
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
        if (purpose == "fetch_instructions" and self.scenario is not None and
                self.scenario.artifacts_dir):
            # What the artifact server could serve at the moment the device
            # is told to fetch its envelope.
            staging = os.path.join(self.scenario.artifacts_dir, "staging")
            listing = []
            for root, unused_dirs, files in os.walk(staging):
                for name in files:
                    path = os.path.join(root, name)
                    info = os.stat(path)
                    listing.append((os.path.relpath(path, staging),
                                    info.st_size, stat.S_IMODE(info.st_mode)))
            self.calls.append(("staged", sorted(listing)))
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
        if self.scenario is not None and self.scenario.recipe_compatible:
            prerequisites = {
                "routing_prereq": b"Gateway of last resort is 192.0.2.1\n",
                "storage_prereq": b"IOx Partition Exists\n",
                "clock": b"14:23:07 UTC Thu Aug 20 2026\n",
                "iox_status": (b"IOx service (CAF) : Running\n"
                               b"Dockerd : Running\n"),
            }
            if purpose in prerequisites:
                return _transport_result(prerequisites[purpose])
            lifecycle = {
                "app_stop": "STOPPED", "app_deactivate": "DEPLOYED",
                "app_uninstall": "", "remove_app_config": "",
                "app_install": "DEPLOYED", "app_activate": "ACTIVATED",
                "app_start": "RUNNING",
            }
            if purpose in lifecycle:
                self.app_state = lifecycle[purpose]
                self.app_present = bool(self.app_state)
                return _transport_result()
            if purpose == "app_list":
                return _transport_result(
                    (("iris %s\n" % self.app_state).encode("ascii")
                     if self.app_state else b""))
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

    def cancel_and_reap(self, deadline):
        self.calls.append(("cancel_and_reap", deadline))
        self.closed = True
        return True


class _TransportFactory(object):
    def __init__(self, board=_BOARD, verification="enabled", boards=None,
                 calls=None, read_states=None, command_outcomes=None,
                 clock=None, advances=None, identity_results=None,
                 recipe_compatible=False, artifacts_dir=None):
        self.artifacts_dir = artifacts_dir
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
        self.recipe_compatible = recipe_compatible

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

    def iox_instruction_cleanup_intent(
            self, record_id, transaction_id, expected_revision,
            expected_phase):
        self.calls.append(("iox_instruction_cleanup_intent", record_id,
                           transaction_id, expected_revision, expected_phase))
        value = self.records[record_id]["iox_verification"]
        if value["transaction_id"] != transaction_id:
            raise ValueError("transaction mismatch")
        if (value["revision"] != expected_revision or
                value["phase"] != expected_phase or
                value.get("instruction_cleanup_pending")):
            raise ValueError("stale cleanup CAS")
        value["instruction_cleanup_pending"] = True
        value["revision"] += 1
        value["updated_at"] += 1
        return copy.deepcopy(value)

    def iox_instruction_cleanup_complete(
            self, record_id, transaction_id, expected_revision,
            expected_phase):
        self.calls.append(("iox_instruction_cleanup_complete", record_id,
                           transaction_id, expected_revision, expected_phase))
        value = self.records[record_id]["iox_verification"]
        if value["transaction_id"] != transaction_id:
            raise ValueError("transaction mismatch")
        if (value["revision"] != expected_revision or
                value["phase"] != expected_phase or
                value.get("instruction_cleanup_pending") is not True):
            raise ValueError("stale cleanup CAS")
        value.pop("instruction_cleanup_pending")
        value["revision"] += 1
        value["updated_at"] += 1
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
                 instruction_bootstrap_materializer=lambda _device_id:
                     b"fixture-instruction-envelope",
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
    boot_id = _module()._boot_id()
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


def _ok_result(stdout):
    return {"returncode": 0, "timed_out": False, "stdout_truncated": False,
            "stderr_truncated": False, "framing_complete": True,
            "stdout": stdout, "error_category": None}


def test_identity_from_result_reads_both_ie3400_and_c8000v(tmp_path):
    """The controller establishes device identity from `show version`. An
    IE-3400 carries a 'Model Number:' line; a Catalyst 8000V does not and
    reports 'cisco C8000V (VXE) processor (revision VXE) with ... memory.'
    -- the model text continues past 'processor'. Both must resolve, or a
    C8000V IOx onboard fails at discovery with 'unable to establish exact
    IOx identity' (live-reproduced 2026-09-10 on 100.90.170.101)."""
    module = _module()
    controller = _controller(tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    try:
        ie = controller._identity_from_result(_ok_result(
            b"Cisco IOS XE Software, Version 17.15.4\n"
            b"cisco IE-3400-8T2S (ARM) processor (revision V06) with 649067K bytes\n"
            b"Processor board ID FCW2716Y9J4\n"
            b"Model Number : IE-3400-8T2S\n"))
        assert ie["model"] == "IE-3400-8T2S" and ie["board_identity"] == "FCW2716Y9J4"
        assert ie["os_family"] == "xe"

        c8k = controller._identity_from_result(_ok_result(
            b"Cisco IOS XE Software, Version 17.15.05\n"
            b"cisco C8000V (VXE) processor (revision VXE) with 1890892K/3075K bytes of memory.\n"
            b"Processor board ID 97XHUO6BK8W\n"))
        assert c8k["model"] == "C8000V" and c8k["board_identity"] == "97XHUO6BK8W"
        assert c8k["os_family"] == "xe"

        # No recognisable model line still fails closed.
        import pytest
        with pytest.raises(module._ControllerFailure):
            controller._identity_from_result(_ok_result(
                b"Cisco IOS XE Software\nProcessor board ID ABC123\n"))
    finally:
        controller.close()


def _install_operations():
    return [
        ("fetch_wrapper", {}),
        ("fetch_certificate", {}),
        ("begin_install", {}),
        ("command", {"name": "app_stop"}),
        ("command", {"name": "app_deactivate"}),
        ("command", {"name": "app_uninstall"}),
        ("command", {"name": "remove_app_config"}),
        ("command", {"name": "configure_app"}),
        ("command", {"name": "app_install"}),
        ("deployed", {}),
        ("command", {"name": "app_activate"}),
        ("stage_instructions", {}),
        ("command", {"name": "copy_certificate"}),
        ("command", {"name": "remove_certificate"}),
        ("command", {"name": "remove_wrapper"}),
        ("command", {"name": "app_start"}),
        ("command", {"name": "save"}),
        ("finish", {"exit_intent": 0}),
    ]


@pytest.mark.parametrize("name", ["fetch_wrapper", "fetch_certificate"])
def test_recipe_cannot_invoke_fetch_as_a_generic_command(name):
    module = _module()
    protocol = {"finished": False, "cleanup": False, "begun": False,
                "completed": set(), "seen": set()}
    with pytest.raises(module._ControllerFailure) as failure:
        module.IoxController._admit_recipe_step(
            _Bag(), _Bag(primary=None), "install", "command", {"name": name}, protocol)
    assert failure.value.category == "rejected"
    assert protocol["seen"] == set()


def _run_scripted_install(tmp_path, factory, markers=(), clock=None,
                          cleanup_on_error=True, authority=None,
                          prepare_hook=None, prefix_chunks=(), cancel=None,
                          recipe_argv=None, request_overrides=None):
    timeline = factory.calls
    store = _StatefulStore(tmp_path, calls=timeline)
    wrapper_path = _write_wrapper(tmp_path, markers)
    recipe = (_write_recipe_peer(
        tmp_path, operations=_install_operations(),
        cleanup_on_error=cleanup_on_error, prefix_chunks=prefix_chunks)
        if recipe_argv is None else None)

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
    config["recipe_argv_by_action"] = {
        "install": (["/bin/bash", recipe] if recipe_argv is None else
                    list(recipe_argv))}
    controller = _controller(
        tmp_path, store, factory, clock=clock, **config)
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path, **(request_overrides or {})),
            prepare, preflight,
            lambda stream, data: timeline.append(("output", stream, data)),
            cancel or _Cancel())
    finally:
        controller.close()
    return result, store, timeline, wrapper_path


def _command_calls(factory, *purposes):
    return [call for call in factory.calls
            if call[0] == "command" and call[4] in purposes]


_APPLICATION_MUTATIONS = (
    "app_stop", "app_deactivate", "app_uninstall", "remove_app_config",
    "configure_app", "app_install", "app_activate", "app_start", "save")


def test_read_sibling_fence_tolerates_an_atomic_rewrite_and_a_reaped_fence(monkeypatch, tmp_path):
    """Fences are replaced by rename; a sibling updating its fence while this
    attempt is admitted gives the strict reader a changed file once. Re-read;
    a fence that disappeared was reaped; anything else is still refused."""
    module = _module()
    outcomes = [ValueError("authority file changed during read"), {"state": "active"}]
    monkeypatch.setattr(module, "_read_json_strict",
                        lambda path, maximum: (_ for _ in ()).throw(outcomes.pop(0))
                        if isinstance(outcomes[0], Exception) else outcomes.pop(0))
    assert module.IoxController._read_sibling_fence("x.lock.json") == {"state": "active"}
    monkeypatch.setattr(module, "_read_json_strict",
                        lambda path, maximum: (_ for _ in ()).throw(FileNotFoundError(path)))
    assert module.IoxController._read_sibling_fence("gone.lock.json") is None
    monkeypatch.setattr(module, "_read_json_strict",
                        lambda path, maximum: (_ for _ in ()).throw(ValueError("malformed IOx session fence")))
    with pytest.raises(ValueError, match="malformed"):
        module.IoxController._read_sibling_fence("bad.lock.json")
    monkeypatch.setattr(module, "_read_json_strict",
                        lambda path, maximum: (_ for _ in ()).throw(ValueError("unsafe authority file")))
    with pytest.raises(ValueError, match="unsafe authority file"):
        module.IoxController._read_sibling_fence("never.lock.json")


def test_command_failure_detail_names_the_step_and_quotes_the_device_verdict():
    """A refused recipe command used to end the job with only 'IOx command
    failed'; the router's own first '%' line is the verdict the operator
    needs (e.g. IOxMan refusing the app block on a Catalyst 8000V)."""
    detail = _module()._command_failure_detail("configure_app", {
        "stdout": (b"iris-c8kv-101#configure terminal\r\n"
                   b"iris-c8kv-101(config)#app-hosting appid iris\r\n"
                   b"% node--1:dbm:IOxMan:Resource Profile-names is not specified\r\n"
                   b"iris-c8kv-101(config)# app-vnic gateway0 virtualportgroup 1 guest-interface 0\r\n"
                   b"% Invalid input detected at '^' marker.\r\n"),
        "returncode": 0, "error_category": "unsupported_response"})
    assert detail == ("IOx command failed: configure_app: device said "
                      "% node--1:dbm:IOxMan:Resource Profile-names is not specified")
    # No verdict line: the step name alone. Control characters never reach
    # the log, and a long line is bounded.
    assert _module()._command_failure_detail(
        "app_install", {"stdout": b"Installing package\n"}) == "IOx command failed: app_install"
    noisy = _module()._command_failure_detail(
        "save", {"stdout": b"%\x1b[31m" + b"x" * 400 + b"\n"})
    assert noisy.startswith("IOx command failed: save: device said %[31mx")
    assert "\x1b" not in noisy and len(noisy) < 220
    assert _module()._command_failure_detail("save", {}) == "IOx command failed: save"


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
    assert _command_calls(factory, "configure_trustpoint",
                          "http_client_credentials", "fetch_wrapper") == []
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


def test_runtime_credentials_are_resolved_without_raw_request_and_bootstrap_mints_last(
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
        assert os.path.exists(wrapper_path)
        return secrets[2]

    def materializer(device_id):
        timeline.append(("instruction_bootstrap_materializer", device_id))
        assert device_id == "edge-01"
        return b"fixture-instruction-envelope"

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
        instruction_bootstrap_materializer=materializer,
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
    assert names.count("instruction_bootstrap_materializer") == 1
    assert names.index("predecessor_terminal") < names.index("preflight") < \
        names.index("enrollment_token_minter") < \
        names.index("instruction_bootstrap_materializer") < \
        names.index("prepare")
    assert store.records["old-r1"]["iox_verification"]["phase"] == "restored"


def test_predecessor_instruction_cleanup_uses_persisted_filesystem_not_retry_plan(
        tmp_path):
    predecessor_journal = _journal(
        record_id="old-r1", phase="unchanged", state="disabled",
        revision=2, unresolved=False)
    predecessor_journal["instruction_cleanup_pending"] = True
    predecessor = _record(
        record_id="old-r1", journal=predecessor_journal)
    predecessor["resolved"].update({
        "package_fs": "flash:", "target_fs": "sdflash:",
        "model": "IE-3400-8T2S", "os_family": "xe",
        "device_ip": "192.0.2.10", "device_identity": _BOARD,
    })
    store = _StatefulStore(
        tmp_path, records=[predecessor], obligations=[predecessor_journal])
    factory = _TransportFactory(verification="disabled")
    wrapper_path = _write_unsigned_wrapper(tmp_path)
    recipe = _write_recipe_peer(
        tmp_path, operations=_install_operations(), cleanup_on_error=True)

    def prepare(request, identity):
        record = _record(record_id="new-r1")
        record["state"] = "planned"
        store.records["new-r1"] = record
        return "new-r1"

    target = _Bag(
        host="192.0.2.10", port=22, platform="iox",
        model="IE-3400-8T2S", os_family="xe", package_fs="sdflash:")
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"install": ["/bin/bash", recipe]})
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path, target=target), prepare,
            lambda *_args: _Bag(
                device_identity=_BOARD, model="IE-3400-8T2S",
                os_family="xe", platform="iox"),
            lambda *_args: None, _Cancel())
    finally:
        controller.close()

    assert result["result_code"] == 0
    removals = _command_calls(factory, "remove_instructions")
    assert len(removals) == 2
    assert b"delete /force flash:iris-instructions-" in removals[0][2]
    assert b"delete /force sdflash:iris-instructions-" in removals[1][2]


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
    upload_at = position(lambda call: call[0] == "command" and
                         call[4] == "fetch_wrapper")
    trust_at = position(lambda call: call[0] == "command" and
                        call[4] == "configure_trustpoint")
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
    assert (preflight_at < prepare_at < begin_at < trust_at < upload_at <
            intent_at < confirmed_at < stop_at < install_at < probe_at <
            restore_intent_at < enable_at < restored_at < activate_at)


def test_instruction_bootstrap_is_private_bound_and_staged_after_activation(
        tmp_path):
    timeline = []
    payload = b"ciphertext-fixture-that-must-not-leak"
    store = _StatefulStore(tmp_path, calls=timeline)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    factory = _TransportFactory(calls=timeline, artifacts_dir=str(artifacts))
    wrapper_path = _write_unsigned_wrapper(tmp_path)
    recipe = _write_recipe_peer(
        tmp_path, operations=_install_operations(), cleanup_on_error=True)

    def minter(device_id):
        timeline.append(("enrollment_token_minter", device_id))
        return "fresh-catalog-token-SECRET"

    def materializer(device_id):
        timeline.append(("instruction_bootstrap_materializer", device_id))
        assert device_id == "edge-01"
        return payload

    def prepare(request, identity):
        timeline.append(("prepare", request, identity))
        record = _record(record_id="new-r1")
        record["state"] = "planned"
        store.records["new-r1"] = record
        return "new-r1"

    prepare_cb, preflight, on_output = _callbacks(timeline)
    del prepare_cb
    controller = _controller(
        tmp_path, store, factory, enrollment_token_minter=minter,
        instruction_bootstrap_materializer=materializer,
        artifacts_dir=str(artifacts),
        recipe_argv_by_action={"install": ["/bin/bash", recipe]})
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path), prepare, preflight, on_output,
            _Cancel())
    finally:
        controller.close()

    assert result["result_code"] == 0
    names = [call[0] for call in timeline]
    assert names.index("enrollment_token_minter") < \
        names.index("instruction_bootstrap_materializer") < \
        names.index("prepare") < names.index("iox_begin")
    assert not [call for call in timeline if call[0] == "upload"]
    transaction = store.records["new-r1"]["iox_verification"]["transaction_id"]
    fetches = _command_calls(factory, "fetch_wrapper", "fetch_certificate",
                             "fetch_instructions")
    assert [call[4] for call in fetches] == [
        "fetch_wrapper", "fetch_certificate", "fetch_instructions"]
    envelope = "iris-instructions-%s.envelope" % transaction
    assert fetches[2][2] == (
        "copy https://iris.invalid:8000/v1/devices/edge-01/artifacts/"
        "staging/edge-01/%s flash:%s\ndir flash: | include %s"
        % (envelope, envelope, re.escape(envelope))).encode("ascii")
    assert fetches[2][3] != fetches[0][3]
    # The envelope was published for the device alone (mode 0600, under its
    # own staging directory) exactly while it was told to fetch it, and is
    # gone afterwards.
    assert [call for call in timeline if call[0] == "staged"] == [
        ("staged", [("edge-01/" + envelope, len(payload), 0o600)])]
    assert not (artifacts / "staging" / "edge-01" / envelope).exists()

    def command_position(purpose):
        return next(index for index, call in enumerate(timeline)
                    if call[0] == "command" and call[4] == purpose)

    assert (command_position("app_activate") <
            command_position("fetch_instructions") <
            command_position("copy_instructions") <
            command_position("remove_instructions") <
            command_position("app_start"))
    public = json.dumps({
        "result": result,
        "store_calls": [call for call in store.calls if call[0] != "upload"],
        "records": store.records,
    }, sort_keys=True, default=str).encode("utf-8")
    assert payload not in public
    remote_name = ("flash:" + envelope).encode("ascii")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            persisted = path.read_bytes()
            assert payload not in persisted
            assert remote_name not in persisted
    assert list((tmp_path / "iox" / "snapshots").iterdir()) == []


def test_production_bash_recipe_accepts_exact_two_revision_instruction_commit(
        tmp_path):
    factory = _TransportFactory(recipe_compatible=True)
    recipe = (Path(__file__).resolve().parents[2] /
              "device" / "iox" / "install.sh")

    result, store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, recipe_argv=["/bin/bash", str(recipe)])

    assert result["result_code"] == 0
    assert result["returncode"] == 0
    intent = [call for call in store.calls
              if call[0] == "iox_instruction_cleanup_intent"]
    complete = [call for call in store.calls
                if call[0] == "iox_instruction_cleanup_complete"]
    assert len(intent) == len(complete) == 1
    assert complete[0][3] == intent[0][3] + 1
    assert "instruction_cleanup_pending" not in store.records[
        "new-r1"]["iox_verification"]
    assert _command_calls(factory, "app_start")


@pytest.mark.parametrize("outcome", ["raises", "empty", "oversize"])
def test_instruction_materialization_failure_precedes_prepare_journal_and_mutation(
        tmp_path, outcome):
    timeline = []
    store = _StatefulStore(tmp_path, calls=timeline)
    factory = _TransportFactory(calls=timeline)
    wrapper_path = _write_unsigned_wrapper(tmp_path)

    def materializer(device_id):
        timeline.append(("instruction_bootstrap_materializer", device_id))
        if outcome == "raises":
            raise RuntimeError("sensitive materialization detail")
        if outcome == "empty":
            return b""
        return b"x" * (256 * 1024 + 1)

    prepare, preflight, on_output = _callbacks(timeline)
    controller = _controller(
        tmp_path, store, factory,
        instruction_bootstrap_materializer=materializer)
    try:
        result = controller.run_install(
            _request(wrapper_path=wrapper_path), prepare, preflight, on_output,
            _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 2
    assert result["error_category"] == "rejected"
    assert result["detail"] == "IOx install controller failed"
    assert not [call for call in timeline if call[0] in ("prepare", "iox_begin")]
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []
    assert not [call for call in timeline if call[0] == "upload"]
    assert _command_calls(factory, "fetch_wrapper", "fetch_certificate",
                          "fetch_instructions") == []
    assert list((tmp_path / "iox" / "snapshots").iterdir()) == []


@pytest.mark.parametrize("failure_purpose", [
    "fetch_instructions", "copy_instructions", "remove_instructions",
])
def test_instruction_stage_failure_removes_only_transaction_source_and_never_starts(
        tmp_path, failure_purpose):
    factory = _TransportFactory(
        command_outcomes={failure_purpose: ["transport"]})
    result, store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory)
    assert result["result_code"] == 4
    assert result["error_category"] == "transport"
    removals = _command_calls(factory, "remove_instructions")
    assert removals
    if failure_purpose == "remove_instructions":
        assert len(removals) == 2
    assert _command_calls(factory, "app_start") == []
    rendered = b"\n".join(call[2] for call in timeline
                           if call[0] == "command")
    if failure_purpose != "fetch_instructions":
        assert b"iris-instructions.bootstrap" in rendered
    # The device's fetch credentials are removed after a failure as well.
    names = [call[4] for call in timeline if call[0] == "command"]
    assert names.index("clear_http_client", names.index("fetch_instructions")) > \
        names.index("fetch_instructions")
    assert b"delete /force flash:iris-instructions-" in rendered
    assert b"delete /force iris-instructions.bootstrap" not in rendered
    assert store.records["new-r1"]["iox_verification"]["unresolved"] is False


def test_wrapper_upload_failure_is_primary_and_never_reaches_disable_or_teardown(
        tmp_path):
    factory = _TransportFactory(
        command_outcomes={"fetch_wrapper": ["connection"]})
    result, store, timeline, _wrapper = _run_scripted_install(
        tmp_path, factory)

    assert result["result_code"] == 4
    assert result["error_category"] == "connection"
    assert result["recovery_code"] is None
    # Credentials were configured only for the copy and cleared after it
    # failed, before anything else happened on the device.
    names = [call[4] for call in timeline if call[0] == "command"]
    fetch_at = names.index("fetch_wrapper")
    assert names[fetch_at - 1] == "http_client_credentials"
    assert names[fetch_at + 1] == "clear_http_client"
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
    uploads = _command_calls(factory, "fetch_wrapper", "fetch_certificate",
                             "fetch_instructions")
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
        clock=clock, advances={"fetch_wrapper": 601})
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
        advances={"fetch_wrapper": 400, "app_install": 250,
                  "app_activate": 250, "fetch_certificate": 890})
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

    uploads = _command_calls(factory, "fetch_wrapper", "fetch_certificate",
                             "fetch_instructions")
    assert [call[4] for call in uploads] == [
        "fetch_wrapper", "fetch_certificate", "fetch_instructions"]
    combined_upload_deadline = min(
        uploads[0][5] + 1800, ordinary_deadline)
    assert combined_upload_deadline < ordinary_deadline
    assert [call[3] for call in uploads[:2]] == [
        combined_upload_deadline, combined_upload_deadline]
    instruction_upload = uploads[2]
    assert instruction_upload[3] == min(
        instruction_upload[5] + 300, ordinary_deadline)
    assert instruction_upload[3] != combined_upload_deadline


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


@pytest.mark.parametrize("share_ios", [
    "flash:..", "flash:share/../operator", "flash:share/./operator",
])
@pytest.mark.parametrize("action", ["install", "recorded", "force_agent_only"])
def test_native_share_dot_segments_are_rejected_before_device_contact(
        tmp_path, share_ios, action):
    record = _record()
    share = dict(share_host_path="/iox_data/share", share_ios_path=share_ios)
    if action == "recorded":
        record["resolved"].update(share)
    factory = _TransportFactory()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path, records=[record]), factory)
    calls = []
    prepare, preflight, on_output = _callbacks(calls)
    try:
        if action == "install":
            request = _request(wrapper_path=_write_wrapper(tmp_path))
            request["target"].update(share)
            run = controller.run_install
        else:
            request = _request(action="uninstall", teardown_mode=action,
                               record_id="r1" if action == "recorded" else None)
            if action == "force_agent_only":
                request["target"].update(share)
            run = controller.run_uninstall
        with pytest.raises(ValueError, match="invalid IOx target share_ios_path"):
            run(request, prepare, preflight, on_output, _Cancel())
        assert not factory.calls
        assert not calls
    finally:
        controller.close()


@pytest.mark.parametrize("share_ios", [
    "flash:iris.share/sub-dir", "bootflash:guest-share/iris",
])
def test_native_share_paths_preserve_ordinary_filename_dots(tmp_path, share_ios):
    controller = _controller(tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    target = _request()["target"]
    target.update(share_host_path="/iox_data/share", share_ios_path=share_ios)
    try:
        assert controller._validate_target(target, "install")["share_ios_path"] == share_ios
    finally:
        controller.close()


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


@pytest.mark.parametrize("persisted_log", ["off", "on"])
@pytest.mark.parametrize("requested_log", [None, "off", "on"],
                         ids=["default", "off", "on"])
def test_recorded_target_uses_job_log_option_without_inheriting_seed_authority(
        tmp_path, persisted_log, requested_log):
    record = _record(address="192.0.2.10")
    record["resolved"].update(
        log=persisted_log, telemetry="off", management_type="inband",
        inband_vlan=120, app_ip="192.0.2.11", app_gateway="192.0.2.1",
        app_mask="255.255.255.0", share_host_path="/iox_data/iris",
        share_ios_path="flash:guest-share/iris")
    before = copy.deepcopy(record)
    seed = _Bag(
        host="198.51.100.99", port=2222, platform="guestshell",
        resources=[{"kind": "iox-app", "ownership": "operator-owned"}],
        management_type="routed", inband_vlan=999, app_ip="198.51.100.11",
        app_gateway="198.51.100.1", telemetry="on", package_fs="disk0:",
        share_host_path="/operator/unowned",
        share_ios_path="flash:operator/unowned")
    if requested_log is not None:
        seed["log"] = requested_log
    seed_before = copy.deepcopy(seed)
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path, records=[record]),
        _TransportFactory())
    try:
        projected = controller._record_target(record, seed, "uninstall")
    finally:
        controller.close()
    assert projected["host"] == "192.0.2.10"
    assert projected["port"] == 22
    assert projected["platform"] == "iox"
    assert projected["resources"] == record["resources"]
    assert projected["management_type"] == "inband"
    assert projected["inband_vlan"] == 120
    assert projected["app_ip"] == "192.0.2.11"
    assert projected["app_gateway"] == "192.0.2.1"
    assert projected["package_fs"] == "flash:"
    assert projected["telemetry"] == "off"
    assert projected["share_host_path"] == "/iox_data/iris"
    assert projected["share_ios_path"] == "flash:guest-share/iris"
    assert record == before and seed == seed_before
    assert projected["log"] == (requested_log or "off")


@pytest.mark.parametrize("requested_log", ["off", "on"])
def test_strict_recovery_reread_preserves_attempt_log_only(
        tmp_path, requested_log):
    journal = _journal(phase="disable_intent", state="enabled", revision=2)
    record = _record(journal=journal)
    record["resolved"].update(
        log="off" if requested_log == "on" else "on",
        management_type="inband", inband_vlan=120)
    store = _StatefulStore(tmp_path, records=[record], obligations=[journal])
    controller = _controller(tmp_path, store, _TransportFactory())
    request = _request(action="uninstall", record_id="r1")
    request["target"].update(
        log=requested_log, inband_vlan=999,
        resources=[{"kind": "iox-app", "ownership": "operator-owned"}],
        share_ios_path="flash:operator/unowned")
    attempt = _module()._Attempt(controller, "recover", request, _Cancel())
    try:
        reread = controller._strict_recovery_binding(attempt, journal)
    finally:
        controller.close()
    assert reread == record
    assert [call for call in store.calls if call[0] == "get"] == [
        ("get", "r1", True)]
    assert attempt.target["host"] == record["resolved"]["device_ip"]
    assert attempt.target["resources"] == record["resources"]
    assert attempt.target["inband_vlan"] == 120
    assert "share_ios_path" not in attempt.target
    assert attempt.target["log"] == requested_log
    assert store.records["r1"] == record


@pytest.mark.parametrize("requested_log", [None, "off", "on"],
                         ids=["default", "off", "on"])
def test_production_recorded_uninstall_recipe_obeys_job_log_option(
        tmp_path, monkeypatch, requested_log):
    echo = b"Device#show app-hosting list\n"
    original_command = _StatefulTransport.command

    def command_with_echo(transport, command_id, command_bytes, deadline):
        result = original_command(
            transport, command_id, command_bytes, deadline)
        if transport._purpose(command_id, command_bytes) == "app_list":
            result["stdout"] = echo + result["stdout"]
        return result

    monkeypatch.setattr(_StatefulTransport, "command", command_with_echo)
    record = _record()
    record["resolved"].update(
        log="off" if requested_log == "on" else "on",
        management_type="inband", inband_vlan=120,
        model="IE-3400-8T2S", app_gateway="192.0.2.1")
    store = _StatefulStore(tmp_path, records=[record])
    factory = _TransportFactory(recipe_compatible=True)
    timeline = []
    prepare, preflight, output = _callbacks(timeline, record_id="r1")
    recipe = Path(__file__).resolve().parents[2] / "device/iox/uninstall.sh"
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", str(recipe)]})
    request = _request(action="uninstall", record_id="r1")
    if requested_log is not None:
        request["target"]["log"] = requested_log
    try:
        result = controller.run_uninstall(
            request, prepare, preflight, output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0, result
    rendered = _rendered_output(timeline)
    assert "[1/4] remove app: iris" in rendered
    assert "[4/4] verify cleanup and save" in rendered
    assert "app removed (poll 1/24)" in rendered
    assert bool(_command_calls(factory, "app_list"))
    assert (echo.decode().strip() in rendered) is (requested_log == "on")
    assert store.records["r1"]["resolved"] == record["resolved"]


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
        record_id="old-r1", phase="disable_intent", state="enabled",
        revision=2, unresolved=True)
    record = _record(record_id="old-r1", journal=journal)
    store = _StatefulStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="enabled")
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
    assert result["recovery_code"] == 0


def test_successful_predecessor_recovery_restores_recorded_uninstall_binding(
        tmp_path):
    predecessor = _journal(
        record_id="old-r1", phase="disable_intent", state="enabled",
        revision=2, unresolved=True)
    records = [
        _record(record_id="old-r1", journal=predecessor),
        _record(record_id="selected-r2"),
    ]
    store = _StatefulStore(
        tmp_path, records=records, obligations=[predecessor])
    factory = _TransportFactory(verification="enabled")
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    prepare, preflight, on_output = _callbacks(
        [], record_id="selected-r2")
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="recorded",
                     record_id="selected-r2"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0
    assert result["record_id"] == "selected-r2"
    assert result["iox_verification"] is None
    assert result["recovery_code"] == 0


def test_same_record_recovery_is_the_only_allowed_recorded_binding_change(
        tmp_path):
    journal = _journal(
        record_id="selected-r1", phase="disable_intent", state="enabled",
        revision=2, unresolved=True)
    record = _record(record_id="selected-r1", journal=journal)
    store = _StatefulStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="enabled")
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    prepare, preflight, on_output = _callbacks(
        [], record_id="selected-r1")
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="recorded",
                     record_id="selected-r1"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 0
    assert result["record_id"] == "selected-r1"
    assert result["recovery_code"] == 0
    recovered = store.records["selected-r1"]["iox_verification"]
    assert recovered["phase"] == "relinquished"
    assert recovered["unresolved"] is False


@pytest.mark.parametrize("drift", ["target", "resources", "journal"])
def test_same_record_recovery_still_rejects_unrelated_record_drift(
        tmp_path, drift):
    journal = _journal(
        record_id="selected-r1", phase="disable_intent", state="enabled",
        revision=2, unresolved=True)
    record = _record(record_id="selected-r1", journal=journal)
    store = _StatefulStore(
        tmp_path, records=[record], obligations=[journal])
    factory = _TransportFactory(verification="enabled")
    recipe_started = tmp_path / "recipe-started"
    recipe = _write_recipe_peer(tmp_path, event_path=str(recipe_started))

    def prepare(unused_request, unused_identity):
        store.transition("selected-r1", "applying")
        current = store.records["selected-r1"]
        if drift == "target":
            current["resolved"]["device_ip"] = "192.0.2.99"
        elif drift == "resources":
            current["resources"] = [
                {"kind": "iox-app", "ownership": "operator-owned"}]
        else:
            current["iox_verification"]["revision"] += 1
        return "selected-r1"

    unused_prepare, preflight, on_output = _callbacks([])
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="recorded",
                     record_id="selected-r1"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 2
    assert not recipe_started.exists()


def _share_render_target(share=True, router=True):
    """The renderer inputs gui_onboard builds for a Catalyst 8000 IOx job
    (with the share) or an IE-3x00 one (without)."""
    target = {
        "package_fs": "bootflash:" if router else "flash:",
        "target_fs": "bootflash:" if router else "sdflash:",
        "pkg": "iris-amd64.tar" if router else "iris-arm64.tar",
        "management_type": "router-routed" if router else "routed",
        "app_ip": "100.90.171.2", "app_mask": "255.255.255.252",
        "app_gateway": "100.90.171.1", "svi_ip": "10.66.6.1",
        "svi_mask": "255.255.255.252", "guest_ip": "10.66.6.2",
        "vlan": "666", "vpg_number": "1",
        "app_intf": "AppGigabitEthernet1/1",
        "nat_interface": "GigabitEthernet1", "bt_listen_port": "6881",
        "ios_ssh_host": "100.90.171.1",
        "telemetry": "on", "telemetry_stream": "off", "log": "off",
    }
    if share:
        target["share_host_path"] = "/bootflash/iox_host_data_share"
        target["share_ios_path"] = "bootflash:iox_host_data_share"
    return target


def _render_with_target(tmp_path, name, target):
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    attempt = module._Attempt(
        controller, "install", _request(action="install"), _Cancel(), False)
    attempt.target = target
    attempt.credentials = {"device_user": "operator", "device_pass": "pw",
                           "catalog_token": "0123456789abcdef"}
    try:
        return controller._render_command(attempt, name).decode("ascii")
    finally:
        controller.close()


@pytest.mark.parametrize("name", ["prepare_iox_scp", "configure_network"])
def test_scp_server_is_enabled_only_where_there_is_no_share(tmp_path, name):
    """#228: the device's SCP server exists for ONE thing -- the agent's
    runtime image hand-off on a platform that cannot bind-mount its staging
    filesystem into the app (IE-3x00). A share-configured target (C9300,
    Catalyst 8000) hands the image over through the mount plus an
    IOS-internal copy and has no scp fallback, so IRIS must not switch its
    SCP server on. `file prompt quiet` is NOT part of that decision: every
    platform needs it for the device-side `copy https:` fetch."""
    shared = _render_with_target(
        tmp_path, name, _share_render_target(share=True)).splitlines()
    bare = _render_with_target(
        tmp_path, name, _share_render_target(share=False, router=False)
    ).splitlines()
    assert "ip scp server enable" not in shared
    assert "ip scp server enable" in bare
    assert "file prompt quiet" in shared and "file prompt quiet" in bare
    # the rest of the step is untouched, and it still ends cleanly
    assert shared[-1] == "end" and bare[-1] == "end"
    assert "iox" in shared and "iox" in bare
    if name == "prepare_iox_scp":
        assert shared == ["configure terminal", "iox", "file prompt quiet",
                          "end"]


def test_router_app_block_renders_the_share_run_opts_and_mkdir(tmp_path):
    """A Catalyst 8000 IOx target carries the bootflash share, so the app
    block bind-mounts it (run-opts 12-14) and the recipe creates it."""
    target = _share_render_target(share=True)
    app = _render_with_target(tmp_path, "configure_app", target).splitlines()
    assert '  run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"' in app
    assert ('  run-opts 13 "-e IRIS_SHARE_IOS_PATH=bootflash:'
            'iox_host_data_share"') in app
    assert ('  run-opts 14 "-v /bootflash/iox_host_data_share:/mnt/share"'
            ) in app
    # inside the docker block, before the block closes
    assert app.index('  run-opts 11 "-e IRIS_LOG=off"') < app.index(
        '  run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"')
    assert app[-1] == "end"
    assert _render_with_target(tmp_path, "mkdir_share", target) == \
        "mkdir bootflash:iox_host_data_share"
    # an IE-3x00 target gets neither
    bare = _render_with_target(
        tmp_path, "configure_app", _share_render_target(share=False,
                                                        router=False))
    assert "IRIS_SHARE_DIR" not in bare and "/mnt/share" not in bare
    assert _render_with_target(
        tmp_path, "mkdir_share",
        _share_render_target(share=False, router=False)) == "dir sdflash:"


@pytest.mark.parametrize("router,mode,expected", [
    (True, "router-routed", 1024),
    (True, "router-nat", 1024),
    (False, "routed", 2048),
    (False, "inband", 2048),
])
def test_router_iox_reserves_less_persist_disk_than_a_switch(tmp_path, router,
                                                             mode, expected):
    """#238: on a router the app's persist-disk comes out of the same
    bootflash: the image is staged on, and placement transiently needs the
    scratch plus the root copy. A 2 GiB reservation left a ~1 GiB image
    nowhere to land on a 4.8 GiB Catalyst 8000V. Switches are unaffected --
    their IOx storage is a separate sdflash:/flash:."""
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    request = _request(action="install")
    attempt = module._Attempt(controller, "install", request, _Cancel(), False)
    attempt.target = {
        "package_fs": "bootflash:" if router else "flash:",
        "target_fs": "bootflash:" if router else "sdflash:",
        "pkg": "iris-amd64.tar" if router else "iris-arm64.tar",
        "management_type": mode,
        "app_ip": "100.90.171.2", "app_mask": "255.255.255.252",
        "app_gateway": "100.90.171.1", "svi_ip": "10.66.6.1",
        "svi_mask": "255.255.255.252", "guest_ip": "10.66.6.2",
        "vpg_number": "1", "app_intf": "AppGigabitEthernet1/1",
        "nat_interface": "GigabitEthernet1", "bt_listen_port": "6881",
        "ios_ssh_host": "100.90.171.1",
        "telemetry": "on", "telemetry_stream": "off", "log": "off",
    }
    attempt.credentials = {"device_user": "operator", "device_pass": "pw",
                           "catalog_token": "0123456789abcdef"}
    try:
        rendered = controller._render_command(
            attempt, "configure_app").decode("ascii")
    finally:
        controller.close()
    assert "  persist-disk %d" % expected in rendered.splitlines()
    assert "  cpu 400" in rendered and "  memory 768" in rendered


@pytest.mark.parametrize("name,action,teardown_mode", [
    ("remove_app_config", "install", None),
    ("cleanup_config", "uninstall", "recorded"),
])
@pytest.mark.parametrize("router", [True, False])
def test_app_block_is_emptied_before_it_is_removed(tmp_path, name, action,
                                                    teardown_mode, router):
    """Issue #230: a Catalyst 8000V keeps the app's resource-profile
    association after uninstall and then refuses every later
    `app-hosting appid iris` until it reloads, unless the block's profile,
    docker options, gateway and vnic are taken out explicitly before the
    block itself. Both teardown paths do that, on routers and switches."""
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    kwargs = {"action": action}
    if teardown_mode:
        kwargs.update(teardown_mode=teardown_mode, record_id="new-r1")
    request = _request(**kwargs)
    attempt = module._Attempt(controller, action, request, _Cancel(), False)
    attempt.target = {
        "package_fs": "bootflash:" if router else "flash:",
        "target_fs": "bootflash:" if router else "sdflash:",
        "pkg": "iris-amd64.tar" if router else "iris-arm64.tar",
        "management_type": "router-routed" if router else "routed",
        "app_gateway": "100.90.171.1", "svi_ip": "10.66.6.1",
        "vpg_number": "1", "app_intf": "AppGigabitEthernet1/1",
    }
    if action == "uninstall":
        attempt.journal = _journal(
            record_id="new-r1", phase="unchanged", state="disabled",
            revision=2, unresolved=False)
    try:
        rendered = controller._render_command(attempt, name).decode("ascii")
    finally:
        controller.close()
    lines = rendered.splitlines()
    vnic = (" no app-vnic gateway0 virtualportgroup 1 guest-interface 0"
            if router else " no app-vnic AppGigabitEthernet trunk")
    gateway = "100.90.171.1" if router else "10.66.6.1"
    emptied = ["app-hosting appid iris", " no app-resource docker",
               " no app-resource profile custom",
               " no app-default-gateway %s guest-interface 0" % gateway,
               vnic, "exit", "no app-hosting appid iris"]
    start = lines.index("app-hosting appid iris")
    assert lines[start:start + len(emptied)] == emptied
    assert lines.count("no app-hosting appid iris") == 1


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
        r"dir flash: | include iris\-arm64\.tar|iris-ca\.pem|iris-catalog\.pem")


@pytest.mark.parametrize("name", ["cleanup_files", "cleanup_stage_probe"])
def test_generic_cleanup_commands_do_not_repeat_private_instruction_source(
        tmp_path, name):
    module = _module()
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    request = _request(
        action="uninstall", teardown_mode="recorded", record_id="new-r1")
    attempt = module._Attempt(
        controller, "uninstall", request, _Cancel(), False)
    attempt.target = {
        "package_fs": "flash:", "target_fs": "sdflash:",
        "pkg": "iris-arm64.tar", "management_type": "routed",
    }
    attempt.journal = _journal(
        record_id="new-r1", phase="unchanged", state="disabled",
        revision=2, unresolved=False)
    try:
        rendered = controller._render_command(attempt, name)
    finally:
        controller.close()

    assert "iris-instructions-" not in rendered.decode("ascii").replace("\\", "")


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


@pytest.mark.parametrize("after_replace", [False, True])
def test_failed_reaped_fence_write_keeps_public_session_active(
        tmp_path, monkeypatch, after_replace):
    module = _module()
    original = module._durable_json
    failed = []

    def fail_reaped(path, value, *args, **kwargs):
        if (not failed and isinstance(value, dict) and
                value.get("state") == "reaped" and
                str(path).endswith(".lock.json")):
            failed.append(str(path))
            if after_replace:
                original(path, value, *args, **kwargs)
            raise OSError("injected reaped fence durability failure")
        return original(path, value, *args, **kwargs)

    monkeypatch.setattr(module, "_durable_json", fail_reaped)
    recipe = _write_recipe_peer(tmp_path)
    store = _StatefulStore(tmp_path, records=[_record(record_id="old-r1")])
    factory = _TransportFactory()
    prepare, preflight, on_output = _callbacks([], record_id=None)
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
    assert failed
    assert result["result_code"] == 5
    assert result["error_category"] == "journal_durability"
    assert result["iox_session"]["state"] == "active"
    assert result["iox_session"]["mutation_blocked"] is True
    with open(failed[0]) as stream:
        on_disk = json.load(stream)
    assert on_disk["state"] == ("reaped" if after_replace else "active")
    assert not [call for call in store.calls if call[0] == "retire_device"]


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


def _assert_console_safe_detail(detail):
    # gui_onboard refuses a controller detail over 512 UTF-8 bytes or one
    # carrying control characters; a refusal the operator cannot read in
    # the job log is no better than a bare one.
    assert len(detail.encode("utf-8")) <= 512
    assert not any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in detail)


_BINDING = re.compile(
    r"record ([A-Za-z0-9_-]+) \(transaction ([0-9a-f]{32}), revision (\d+)\)")


@pytest.mark.parametrize("operation", ["forced-undeploy", "onboard"])
def test_indeterminate_predecessor_refusal_names_the_reconcile_binding(
        tmp_path, operation):
    """Two server redeploys cut IOx attempts off mid-run on Iris-c8kv-102
    (2026-09-10) and left its journal in phase 'indeterminate'. Every later
    onboard, undeploy and forced undeploy failed with a bare 'predecessor
    recovery failed', and a forced teardown's result reports its own null
    binding rather than the predecessor's, so the operator could not learn
    the record id, transaction id and revision that reconcile-enabled
    demands (issue #231). The refusal now quotes the binding, the device
    step, and the runbook."""
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    factory = _TransportFactory(verification="disabled")
    prepare, preflight, on_output = _callbacks([], record_id=None)
    controller = _controller(tmp_path, store, factory)
    try:
        if operation == "forced-undeploy":
            result = controller.run_uninstall(
                _request(action="uninstall", teardown_mode="force_agent_only"),
                prepare, preflight, on_output, _Cancel())
            assert result["record_id"] is None
        else:
            result = controller.run_install(
                _request(wrapper_path=_write_unsigned_wrapper(tmp_path)),
                prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 3
    assert result["error_category"] == "reconciliation_required"
    detail = result["detail"]
    assert detail.startswith("predecessor recovery failed: ")
    assert _BINDING.search(detail).groups() == (
        "r1", journal["transaction_id"], "7")
    assert "is indeterminate" in detail
    assert "enable app signature verification on the device" in detail
    assert "iox_verification.py reconcile-enabled" in detail
    assert ("docs/operations/#recovering-an-iox-attempt-cut-off-mid-run"
            in detail)
    _assert_console_safe_detail(detail)
    assert not [call for call in factory.calls if call[0] == "command" and
                b"verification enable" in call[2].lower()]


def test_quoted_reconcile_binding_is_the_current_revision_and_is_accepted(
        tmp_path):
    """Recovering a disable_intent journal whose device now reads disabled
    writes an 'indeterminate' event, which advances the revision. The
    refusal must quote that advanced revision -- reconcile-enabled compares
    the triple against the stored journal and refuses a stale one -- and
    the quoted triple must be exactly what reconcile-enabled then accepts
    once the operator has re-enabled verification on the device."""
    journal = _journal(phase="disable_intent", state="enabled", revision=4)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    prepare, preflight, on_output = _callbacks([], record_id=None)
    controller = _controller(
        tmp_path, store, _TransportFactory(verification="disabled"))
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only"),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    stored = store.records["r1"]["iox_verification"]
    assert stored["phase"] == "indeterminate" and stored["revision"] == 5
    assert result["result_code"] == 3
    record_id, transaction_id, revision = _BINDING.search(
        result["detail"]).groups()
    assert (record_id, transaction_id, int(revision)) == (
        "r1", stored["transaction_id"], 5)

    # The operator ran 'app-hosting verification enable' by hand; the
    # quoted binding resolves the journal without another device mutation.
    factory = _TransportFactory(verification="enabled")
    controller = _controller(tmp_path, store, factory)
    try:
        resolved = controller.reconcile_enabled(
            record_id, transaction_id, int(revision), True, _Cancel())
    finally:
        controller.close()
    assert resolved["result_code"] == 0
    assert store.records["r1"]["iox_verification"]["unresolved"] is False
    assert not [call for call in factory.calls if call[0] == "command" and
                b"verification enable" in call[2].lower()]


def test_recover_board_unresolved_refusal_names_the_reconcile_binding(
        tmp_path):
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    controller = _controller(
        tmp_path, store, _TransportFactory(verification="disabled"))
    try:
        result = controller.recover_board(_BOARD, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 3
    assert result["error_category"] == "reconciliation_required"
    detail = result["detail"]
    assert detail.startswith("recovery unresolved: ")
    assert _BINDING.search(detail).groups() == (
        "r1", journal["transaction_id"], "7")
    assert "reconcile-enabled" in detail
    _assert_console_safe_detail(detail)


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
    assert result["error_category"] == "reconciliation_required"
    assert result["detail"].startswith(
        "fresh read did not establish enabled: ")
    assert "'app-hosting verification enable'" in result["detail"]
    assert "retry reconcile-enabled" in result["detail"]
    _assert_console_safe_detail(result["detail"])
    assert not [call for call in store.calls if call[0] == "iox_event" and
                call[1] == "reconcile_enabled"]


def test_boot_identity_changes_with_the_container_instance(monkeypatch):
    module = _module()
    host = open("/proc/sys/kernel/random/boot_id").read().strip().lower()
    first = module._boot_id()
    assert module._BOOT_ID.fullmatch(first) and first != host
    real = module._process_start_ticks
    monkeypatch.setattr(module, "_process_start_ticks",
                        lambda pid: real(pid) + 1 if pid == 1 else real(pid))
    assert module._boot_id() != first
    monkeypatch.setattr(module, "_process_start_ticks",
                        lambda pid: (_ for _ in ()).throw(FileNotFoundError(pid)))
    assert module._boot_id() == host


def test_a_fence_from_a_previous_container_instance_no_longer_blocks_the_board(tmp_path, monkeypatch):
    """The server runs in a container: a restart keeps the host boot id but
    kills every supervisor. An attempt cut off that way used to leave its
    device refusing every later attempt with 'active same-boot IOx session
    fence' until the fence was deleted by hand (IE-3400, 2026-09-10). The
    fence's boot identity now folds in pid 1's start, so the restarted
    container sees a fence from another boot and reaps it; a supervisor
    that crashed inside THIS container still fails closed (see the crash
    suite)."""
    module = _module()
    journal = _journal(phase="indeterminate", state="unknown", revision=7)
    store = _StatefulStore(tmp_path, records=[_record(journal=journal)],
                           obligations=[journal])
    transcript_ref = _write_header_transcript(tmp_path, "3" * 32)
    fence_path = _write_active_fence(tmp_path, transcript_ref)
    fence = json.loads(fence_path.read_text())
    fence["boot_id"] = module._boot_id()      # written by the previous instance
    fence_path.write_text(json.dumps(fence, sort_keys=True))
    real = module._process_start_ticks
    monkeypatch.setattr(module, "_process_start_ticks",
                        lambda pid: real(pid) + 1 if pid == 1 else real(pid))
    factory = _TransportFactory(verification="enabled")
    controller = _controller(tmp_path, store, factory)
    try:
        result = controller.reconcile_enabled(
            "r1", journal["transaction_id"], 7, True, _Cancel())
    finally:
        controller.close()
    assert result["error_category"] != "descendant_unreaped"


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
    assert result["result_code"] == 5
    assert result["error_category"] == "journal_durability"
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


def test_iox_begin_durability_failure_stops_all_later_commands(
        tmp_path, monkeypatch):
    factory = _TransportFactory(verification="enabled")

    def fail_begin(unused_store, *unused_args, **unused_kwargs):
        raise OSError("injected IOx journal creation failure")

    monkeypatch.setattr(_StatefulStore, "iox_begin", fail_begin)
    result, unused_store, unused_timeline, unused_wrapper = \
        _run_scripted_install(tmp_path, factory)
    assert result["result_code"] == 5
    assert result["error_category"] == "journal_durability"
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


def test_post_device_fence_failure_forbids_cleanup_and_recovery_commands(
        tmp_path, monkeypatch):
    module = _module()
    factory = _TransportFactory(verification="enabled")
    original = module.IoxController._update_fence
    failed = []

    def fail_after_app_stop(controller, attempt, *args, **kwargs):
        purposes = [call[4] for call in factory.calls
                    if call[0] == "command"]
        if not failed and purposes and purposes[-1] == "app_stop":
            failed.append(len(factory.calls))
            raise OSError("injected post-device fence failure")
        return original(controller, attempt, *args, **kwargs)

    monkeypatch.setattr(module.IoxController, "_update_fence",
                        fail_after_app_stop)
    result, unused_store, unused_timeline, unused_wrapper = \
        _run_scripted_install(tmp_path, factory, cleanup_on_error=True)
    assert failed
    assert result["result_code"] == 5
    assert result["error_category"] == "journal_durability"
    app_stop = max(index for index, call in enumerate(factory.calls)
                   if call[0] == "command" and call[4] == "app_stop")
    assert not [call for call in factory.calls[app_stop + 1:]
                if call[0] in ("command", "upload")]


def test_cancel_after_durable_event_never_uses_stale_journal_authority(
        tmp_path, monkeypatch):
    module = _module()
    cancel = _Cancel()
    journal = _journal(phase="disable_intent", state="enabled", revision=1)
    store = _StatefulStore(
        tmp_path, records=[_record(journal=journal)], obligations=[journal])
    controller = _controller(tmp_path, store, _TransportFactory())
    attempt = module._Attempt(
        controller, "install",
        _request(wrapper_path=_write_unsigned_wrapper(tmp_path)), cancel)
    attempt.board = _BOARD
    attempt.record_id = "r1"
    attempt.journal = copy.deepcopy(journal)
    original = _StatefulStore.iox_event
    committed = []

    def cancel_after_confirmation(store, *args, **kwargs):
        value = original(store, *args, **kwargs)
        if args[4] == "disable_confirmed" and not committed:
            committed.append(copy.deepcopy(value))
            cancel.cancelled = True
        return value

    monkeypatch.setattr(_StatefulStore, "iox_event",
                        cancel_after_confirmation)
    try:
        updated = controller._event(attempt, "disable_confirmed", {
            "confirmation": copy.deepcopy(
                _journal(phase="disabled_confirmed")["disable_confirmation"]),
            "transcript_refs": copy.deepcopy(journal["transcript_refs"]),
        })
    finally:
        controller.close()

    assert committed and updated == committed[0]
    assert attempt.journal == committed[0]
    assert attempt.journal["phase"] == "disabled_confirmed"
    assert attempt.journal["revision"] == 2
    with pytest.raises(module._ControllerFailure) as failure:
        attempt.check()
    assert failure.value.category == "cancelled"


def test_cancel_after_durable_begin_publishes_the_created_journal(
        tmp_path, monkeypatch):
    cancel = _Cancel()
    factory = _TransportFactory(verification="enabled")
    original = _StatefulStore.iox_begin

    def cancel_after_begin(store, *args, **kwargs):
        value = original(store, *args, **kwargs)
        cancel.cancelled = True
        return value

    monkeypatch.setattr(_StatefulStore, "iox_begin", cancel_after_begin)
    result, store, unused_timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, cancel=cancel)

    assert result["result_code"] == 130
    assert result["error_category"] == "cancelled"
    assert result["iox_verification"] is not None
    assert result["iox_verification"]["phase"] == "observed"
    assert result["iox_verification"]["revision"] == 0
    assert store.records["new-r1"]["iox_verification"]["phase"] == "observed"
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


def test_force_retirement_completed_before_late_cancel_remains_successful(
        tmp_path):
    cancel = _Cancel()
    old_record = _record(record_id="old-r1")

    class CancellingRetirementStore(_StatefulStore):
        def retire_device(self, device_id, reason):
            value = _StatefulStore.retire_device(self, device_id, reason)
            cancel.cancelled = True
            return value

    store = CancellingRetirementStore(tmp_path, records=[old_record])
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)
    recipe = _write_recipe_peer(tmp_path)
    controller = _controller(
        tmp_path, store, factory,
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only",
                     record_id=None),
            prepare, preflight, on_output, cancel)
    finally:
        controller.close()

    assert cancel.cancelled is True
    assert result["result_code"] == 0
    assert result["error_category"] is None
    assert store.records["old-r1"]["state"] == "abandoned"


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


def test_attempt_admission_store_deadline_returns_closed_timeout(
        tmp_path, monkeypatch):
    import contextlib
    import deployment_records

    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    factory = _TransportFactory()
    calls = []
    prepare, preflight, on_output = _callbacks(calls, record_id=None)

    @contextlib.contextmanager
    def expired(unused_store, deadline=None, monotonic_fn=None):
        assert deadline is not None
        assert monotonic_fn is not None
        raise deployment_records.StoreLockTimeout(
            "deployment record store lock timed out")
        yield

    monkeypatch.setattr(
        deployment_records.DeploymentRecordStore, "_store_lock", expired)
    controller = _controller(tmp_path, store, factory)
    try:
        result = controller.run_uninstall(
            _request(action="uninstall", teardown_mode="force_agent_only",
                     record_id=None),
            prepare, preflight, on_output, _Cancel())
    finally:
        controller.close()
    assert result["result_code"] == 4
    assert result["error_category"] == "timeout"
    assert factory.calls == []
    assert calls == []
    assert os.listdir(str(tmp_path / "iox" / "transcripts")) == []


@pytest.mark.parametrize("category,timed_out,expected_code", [
    ("timeout", True, 4),
    ("cancelled", False, 130),
])
def test_failed_transport_result_allows_no_process_returncode(
        category, timed_out, expected_code):
    module = _module()
    result = _transport_result(
        returncode=None, error_category=category, timed_out=timed_out,
        framing_complete=False)
    module.IoxController._validate_transport_result(result)
    assert module.IoxController._transport_ok(result) is False
    assert module._ControllerFailure(category, "transport failed").code == \
        expected_code


def test_no_process_returncode_cannot_describe_a_clean_transport_result():
    module = _module()
    invalid = [
        _transport_result(returncode=None),
        _transport_result(
            returncode=None, error_category="cancelled",
            framing_complete=True),
    ]
    for result in invalid:
        with pytest.raises(module._ControllerFailure) as failed:
            module.IoxController._validate_transport_result(result)
        assert failed.value.category == "unsupported_response"
    killed = _transport_result(
        returncode=-15, error_category="cancelled", framing_complete=False)
    module.IoxController._validate_transport_result(killed)
    assert module._ControllerFailure(
        killed["error_category"], "transport killed").code == 130


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


def _scan_fixture(tmp_path):
    controller = _controller(
        tmp_path, _StatefulStore(tmp_path), _TransportFactory())
    directory = tmp_path / "iox" / "transcripts"
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    good = directory / ("a" * 32 + ".transcript")
    good.write_bytes(b"x")
    os.chmod(good, 0o600)
    return controller, directory, good


def test_authority_scan_skips_a_sibling_writers_temporary_but_refuses_foreign_names(tmp_path):
    """The transcript writer stages '.transcript-*.tmp' and the fence writer
    '.iox-*.tmp' beside the file they rename into place; a scan that lands
    in that window used to fail the whole admission with 'unknown IOx
    authority entry' (four devices started in one second, 2026-09-10)."""
    controller, directory, good = _scan_fixture(tmp_path)
    for name in (".transcript-Ab12_x.tmp", ".iox-0a1b2c.tmp"):
        (directory / name).write_bytes(b"partial")
        os.chmod(directory / name, 0o600)
    try:
        found = controller._scan_directory(
            str(directory), ".transcript", 16, 1024 * 1024)
        assert found == [str(good)]
        (directory / "notes.txt").write_bytes(b"")
        with pytest.raises(ValueError, match="unknown IOx authority entry"):
            controller._scan_directory(
                str(directory), ".transcript", 16, 1024 * 1024)
    finally:
        controller.close()


def test_authority_scan_relooks_at_a_churning_entry_and_skips_a_vanished_one(tmp_path, monkeypatch):
    controller, directory, good = _scan_fixture(tmp_path)
    reaped = directory / ("b" * 32 + ".transcript")
    reaped.write_bytes(b"y")
    os.chmod(reaped, 0o600)
    real_stat = os.stat
    churned = []

    def racing_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path == good.name and kwargs.get("dir_fd") is not None and not churned:
            # First by-name look at the good entry reports a different inode,
            # as it does when a sibling has just renamed a new file over it.
            churned.append(True)
            values = list(result)
            values[1] = result.st_ino + 1
            return os.stat_result(values)
        if path == reaped.name and kwargs.get("dir_fd") is not None:
            raise FileNotFoundError(path)
        return result
    monkeypatch.setattr(os, "stat", racing_stat)
    try:
        found = controller._scan_directory(
            str(directory), ".transcript", 16, 1024 * 1024)
    finally:
        controller.close()
    assert found == [str(good)]
    assert churned


def test_authority_scan_still_refuses_an_entry_that_never_settles(tmp_path, monkeypatch):
    controller, directory, good = _scan_fixture(tmp_path)
    real_stat = os.stat
    counter = [0]

    def always_churning(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path == good.name and kwargs.get("dir_fd") is not None:
            counter[0] += 1
            values = list(result)
            values[1] = result.st_ino + counter[0]
            return os.stat_result(values)
        return result
    monkeypatch.setattr(os, "stat", always_churning)
    try:
        with pytest.raises(ValueError, match="unsafe IOx authority entry"):
            controller._scan_directory(
                str(directory), ".transcript", 16, 1024 * 1024)
    finally:
        controller.close()


@pytest.mark.parametrize("log", ["off", "on"])
def test_minted_catalog_token_is_stream_redacted_before_recipe_output(
        tmp_path, log):
    token = b"fixture-catalog-token-SECRET"
    factory = _TransportFactory(verification="enabled")
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, markers=("package.sign",),
        prefix_chunks=(token[:11], token[11:]),
        request_overrides={"target": _Bag(_request()["target"], log=log)})
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
                    clock.advance(400)
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
        session_seconds=300, restoration_reserve_seconds=180)
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


def _rendered_output(timeline):
    return b"".join(call[2] for call in timeline
                    if call[0] == "output").decode("utf-8", "replace")


def test_recipe_steps_reach_the_job_log_in_order_without_the_session(tmp_path):
    """The job log is the recipe's own lines plus one controller line per
    operation, streamed at each request boundary. The device session the
    controller drove is not in it; that lives in the persisted transcript."""
    factory = _TransportFactory(verification="enabled")
    header = b"[1/8] fetch package and certificate\n"
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, markers=("package.sign",), prefix_chunks=(header,))
    assert result["result_code"] == 0
    lines = _rendered_output(timeline).splitlines()
    assert lines[0] == "[1/8] fetch package and certificate"
    step_lines = [line for line in lines if line.startswith("  ")]
    expected = [arguments.get("name") if operation == "command" else operation
                for operation, arguments in _install_operations()]
    expected.remove("finish")
    assert [line.split()[0] for line in step_lines] == expected
    assert all(re.fullmatch(r"  [a-z_]+ ok \(\d+\.\ds\)", line)
               for line in step_lines)
    # Nothing else: no handshake lines, no device output, no controller prose.
    assert lines == [lines[0]] + step_lines
    # Streamed, not delivered after the recipe exits: the line for one step
    # is out before the transport drives the next one.
    outputs = [(index, call[2]) for index, call in enumerate(timeline)
               if call[0] == "output"]
    app_stop_reported = next(index for index, data in outputs
                             if data.startswith(b"  app_stop ok"))
    app_deactivate_driven = next(
        index for index, call in enumerate(timeline)
        if call[0] == "command" and call[4] == "app_deactivate")
    assert app_stop_reported < app_deactivate_driven


def test_a_failed_recipe_step_is_named_in_the_job_log(tmp_path):
    factory = _TransportFactory(
        verification="enabled",
        command_outcomes={"configure_app": ["transport"]})
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        tmp_path, factory, markers=("package.sign",))
    assert result["result_code"] == 4
    lines = _rendered_output(timeline).splitlines()
    assert any(re.fullmatch(r"  configure_app failed \(\d+\.\ds\)", line)
               for line in lines)
    assert not any(line.startswith("  configure_app ok") for line in lines)
    # The failed step is the last controller line: nothing after it ran, and
    # the recipe's cleanup handshake is not news.
    assert lines[-1].startswith("  configure_app failed")
    assert not any(line.startswith(("  cleanup", "  finish"))
                   for line in lines)
    # The detail belongs to the controller result, not to this line.
    assert "injected transport" not in "\n".join(lines)
    assert result["error_category"] == "transport"


def test_recipe_environment_carries_the_job_log_opt_in(tmp_path):
    """IRIS_LOG reaches the recipe as the target's normalized on/off, so the
    recipe can echo the raw session only for a job that opted in."""
    peer = _write_recipe_peer(tmp_path, operations=_install_operations())
    probe = tmp_path / "probe-recipe.sh"
    probe.write_text(
        '#!/bin/bash\nprintf "IRIS_LOG=%%s\\n" "${IRIS_LOG-unset}"\n'
        'exec /bin/bash "%s"\n' % peer)
    for name, log, expected in (("default", None, "IRIS_LOG=off"),
                                ("on", "on", "IRIS_LOG=on"),
                                ("off", "off", "IRIS_LOG=off")):
        root = tmp_path / name
        root.mkdir()
        overrides = {}
        if log is not None:
            overrides["target"] = _Bag(_request()["target"], log=log)
        result, unused_store, timeline, unused_wrapper = _run_scripted_install(
            root, _TransportFactory(verification="enabled"),
            markers=("package.sign",),
            recipe_argv=["/bin/bash", str(probe)],
            request_overrides=overrides)
        assert result["result_code"] == 0, name
        assert _rendered_output(timeline).splitlines()[0] == expected, name


_INSTALL_HEADERS = [
    "[1/8] fetch package and certificate",
    "[2/8] check prerequisites: routing, storage, clock, IOx services",
    "[3/8] remove any existing app",
    "[4/8] configure networking and app",
    "[5/8] install app (waiting for DEPLOYED)",
    "[6/8] activate app (waiting for ACTIVATED)",
    "[7/8] stage instructions, copy certificate, remove uploads, start app "
    "(waiting for RUNNING)",
    "[8/8] save configuration",
]


def test_production_bash_recipe_job_log_is_step_level(tmp_path):
    """device/iox/install.sh through the real controller: the job log is the
    recipe's numbered headers, its poll outcomes and the controller's line
    per operation, each header ahead of the operations it introduces, and
    none of the device session -- unless the job's IRIS_LOG opt-in is on."""
    recipe = (Path(__file__).resolve().parents[2] /
              "device" / "iox" / "install.sh")
    root = tmp_path / "default"
    root.mkdir()
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        root, _TransportFactory(recipe_compatible=True),
        recipe_argv=["/bin/bash", str(recipe)])
    assert result["result_code"] == 0
    rendered = _rendered_output(timeline)
    lines = rendered.splitlines()
    assert [line for line in lines if line.startswith("[")] == _INSTALL_HEADERS

    def at(prefix):
        return next(index for index, line in enumerate(lines)
                    if line.startswith(prefix))

    order = [
        "[1/8]", "  fetch_wrapper ok (", "  fetch_certificate ok (",
        "[2/8]", "  routing_prereq ok (", "  storage_prereq ok (",
        "  clock ok (", "  prepare_iox_scp ok (",
        "IOx services ready (poll 1/24)",
        "[3/8]", "  begin_install ok (", "  app_stop ok (",
        "  remove_app_config ok (",
        "[4/8]", "  configure_network ok (", "  mkdir_share ok (",
        "  configure_app ok (",
        "[5/8]", "  app_install ok (", "app is DEPLOYED (poll 1/24)",
        "  deployed ok (",
        "[6/8]", "  app_activate ok (", "app is ACTIVATED (poll 1/24)",
        "[7/8]", "  stage_instructions ok (", "  copy_certificate ok (",
        "  remove_certificate ok (", "  remove_wrapper ok (",
        "  app_start ok (", "app is RUNNING (poll 1/24)",
        "[8/8]", "  save ok (", "onboard complete: device",
    ]
    positions = [at(prefix) for prefix in order]
    assert positions == sorted(positions), list(zip(order, positions))
    assert lines[-1] == "onboard complete: device"
    # The polls and the closing handshake are silent on success.
    assert not any(line.startswith(("  app_list", "  iox_status",
                                    "  cleanup", "  finish"))
                   for line in lines)
    # The session the controller drove stays in its transcript.
    for session_text in ("Gateway of last resort", "IOx Partition Exists",
                         "IOx service (CAF)", "iris DEPLOYED",
                         "iris RUNNING", "14:23:07"):
        assert session_text not in rendered, session_text

    root = tmp_path / "opt-in"
    root.mkdir()
    result, unused_store, timeline, unused_wrapper = _run_scripted_install(
        root, _TransportFactory(recipe_compatible=True),
        recipe_argv=["/bin/bash", str(recipe)],
        request_overrides={"target": _Bag(_request()["target"], log="on")})
    assert result["result_code"] == 0
    rendered = _rendered_output(timeline)
    assert [line for line in rendered.splitlines()
            if line.startswith("[")] == _INSTALL_HEADERS
    for session_text in ("Gateway of last resort", "IOx Partition Exists",
                         "IOx service (CAF)", "iris DEPLOYED", "iris RUNNING"):
        assert session_text in rendered, session_text


# --- device-side artifact fetch (replaced the server-side SCP push) ---

def test_fetch_sequence_installs_trust_once_and_brackets_each_copy_with_credentials(
        tmp_path):
    """Every artifact the device needs -- the wrapper, the public catalog
    certificate, the sealed instruction envelope -- is fetched by the DEVICE
    over the catalog trustpoint the controller installed first, and the IOS
    HTTP client credentials exist only between the copy's own set and
    clear. Nothing is pushed over SCP any more."""
    factory = _TransportFactory()
    result, store, timeline, _wrapper = _run_scripted_install(tmp_path, factory)
    assert result["result_code"] == 0
    assert not [call for call in timeline if call[0] == "upload"]
    names = [call[4] for call in timeline if call[0] == "command"]
    assert names.count("configure_trustpoint") == 1
    assert names.index("configure_trustpoint") < names.index("fetch_wrapper")
    for purpose in ("fetch_wrapper", "fetch_certificate", "fetch_instructions"):
        at = names.index(purpose)
        assert names[at - 1] == "http_client_credentials"
        assert names[at + 1] == "clear_http_client"
    assert names.count("http_client_credentials") == names.count("clear_http_client") == 3
    rendered = dict((call[4], call[2]) for call in timeline if call[0] == "command")
    transaction = store.records["new-r1"]["iox_verification"]["transaction_id"]
    assert rendered["fetch_wrapper"] == (
        "copy https://iris.invalid:8000/v1/devices/edge-01/artifacts/iris-arm64.tar "
        "flash:iris-%s.tar\ndir flash: | include %s" % (
            transaction, re.escape("iris-%s.tar" % transaction))).encode("ascii")
    assert rendered["fetch_certificate"] == (
        b"copy https://iris.invalid:8000/v1/devices/edge-01/artifacts/iris-catalog.pem "
        b"flash:iris-ca.pem\ndir flash: | include iris-ca\\.pem")
    assert rendered["http_client_credentials"] == (
        b"configure terminal\nip http client username edge-01\n"
        b"ip http client password 0 fixture-catalog-token-SECRET\nend")
    assert rendered["clear_http_client"] == (
        b"configure terminal\nno ip http client username\n"
        b"no ip http client password\nend")
    trust = rendered["configure_trustpoint"].split(b"\n")
    assert trust[:7] == [
        b"configure terminal", b"no crypto pki trustpoint IRIS",
        b"crypto pki trustpoint IRIS", b" enrollment terminal",
        b" revocation-check none", b"exit", b"crypto pki authenticate IRIS"]
    assert trust[7:] == [b"fixture catalog certificate", b"quit",
                         b"ip http client secure-trustpoint IRIS", b"end"]
    assert not [call for call in timeline if call[0] == "command" and
                b"ip scp server" in call[2] and call[4] != "prepare_iox_scp"]


def test_trustpoint_failure_stops_before_credentials_or_any_fetch(tmp_path):
    factory = _TransportFactory(
        command_outcomes={"configure_trustpoint": ["rejected"]})
    result, store, timeline, _wrapper = _run_scripted_install(tmp_path, factory)
    assert result["result_code"] == 4
    assert result["error_category"] == "rejected"
    assert _command_calls(factory, "http_client_credentials", "fetch_wrapper",
                          "fetch_certificate", "fetch_instructions") == []
    assert _command_calls(factory, "verification_disable") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


def test_credentials_are_cleared_even_when_the_clear_itself_is_the_failure(tmp_path):
    factory = _TransportFactory(
        command_outcomes={"clear_http_client": ["connection"]})
    result, store, timeline, _wrapper = _run_scripted_install(tmp_path, factory)
    assert result["result_code"] == 4
    assert result["error_category"] == "connection"
    names = [call[4] for call in timeline if call[0] == "command"]
    assert names[names.index("fetch_wrapper") + 1] == "clear_http_client"
    assert _command_calls(factory, "fetch_certificate") == []
    assert _command_calls(factory, *_APPLICATION_MUTATIONS) == []


@pytest.mark.parametrize("stdout,category", [
    (b"Accessing https://s/x...\n65536 bytes copied in 1.0 secs (65536 bytes/sec)\n"
     b"   19  -rw-           65536  Sep 10 2026 12:00:00 +00:00  iris-x.tar\n", None),
    (b"Accessing https://s/x...\n65535 bytes copied in 1.0 secs (65536 bytes/sec)\n"
     b"   19  -rw-           65536  Sep 10 2026 12:00:00 +00:00  iris-x.tar\n",
     "readback_mismatch"),
    (b"Accessing https://s/x...\n65536 bytes copied in 1.0 secs (65536 bytes/sec)\n"
     b"   19  -rw-           65537  Sep 10 2026 12:00:00 +00:00  iris-x.tar\n",
     "readback_mismatch"),
    (b"Accessing https://s/x...\n65536 bytes copied in 1.0 secs (65536 bytes/sec)\n",
     "readback_unknown"),
    (b"   19  -rw-           65536  Sep 10 2026 12:00:00 +00:00  iris-x.tar\n",
     "readback_unknown"),
    (b"65536 bytes copied in 1.0 secs\n"
     b"   19  -rw-           65536  Sep 10 2026 12:00:00 +00:00  iris-x.tar.bak\n",
     "readback_unknown"),
])
def test_fetch_proof_needs_the_copy_report_and_the_dir_row_at_the_source_size(
        stdout, category):
    module = _module()
    result = {"stdout": stdout}
    if category is None:
        module.IoxController._verify_fetched("fetch_wrapper", result, "iris-x.tar", 65536)
        return
    with pytest.raises(module._ControllerFailure) as failure:
        module.IoxController._verify_fetched("fetch_wrapper", result, "iris-x.tar", 65536)
    assert failure.value.category == category


def _http_count(value):
    return ("Number of lines which match regexp = %s\n" % value).encode("ascii")


@pytest.mark.parametrize("username,password,own,collision", [
    (0, 0, 0, False), (1, 1, 1, False), (1, 0, 1, False),
    (1, 0, 0, True), (0, 1, 0, True), (1, 1, 0, True),
])
def test_operator_http_client_credentials_are_a_collision_but_iris_own_are_not(
        username, password, own, collision):
    module = _module()
    assert module._http_client_credentials_collision(
        _http_count(username), _http_count(password), _http_count(own)) is collision


@pytest.mark.parametrize("payload", [
    b"", b"0", _http_count(2), _http_count(-1), _http_count("01"),
    _http_count(0) + _http_count(0), b"% advisory\n" + _http_count(0),
    b"hostname edge\n" + _http_count(0),
    b"ip http client username operator\n", _http_count(0) + b"\x00",
    _http_count(0).replace(b" = ", b"="), b"\xff" + _http_count(0),
])
@pytest.mark.parametrize("slot", range(3))
def test_preflight_http_count_rejects_incomplete_or_ambiguous_payload(payload, slot):
    module = _module()
    counts = [_http_count(0), _http_count(0), _http_count(0)]
    counts[slot] = payload
    with pytest.raises(module._ControllerFailure) as failure:
        module._http_client_credentials_collision(*counts)
    assert failure.value.category == "unsupported_response"


@pytest.mark.parametrize("password", [0, 1])
def test_preflight_http_count_rejects_own_username_without_username(password):
    module = _module()
    with pytest.raises(module._ControllerFailure) as failure:
        module._http_client_credentials_collision(
            _http_count(0), _http_count(password), _http_count(1))
    assert failure.value.category == "unsupported_response"


def test_preflight_http_count_accepts_only_surrounding_ascii_whitespace():
    module = _module()
    assert module._http_client_credentials_collision(
        b"\r\n \t" + _http_count(1) + b"\t\r\n",
        _http_count(1), _http_count(1)) is False


@pytest.mark.parametrize("appid,device_id", [
    ("iris", "100.90.168.99"), ("iris-2", "edge-01:access"),
    ("iris", "." * 128),
])
def test_preflight_reads_only_collision_lines_and_http_counts(appid, device_id):
    commands = _module()._preflight_commands(appid, device_id)
    assert len(commands) == 5
    assert commands[0] == b"show app-hosting list"
    assert commands[1] == (
        b"show running-config | include ^app-hosting appid |"
        b"^event manager applet IRIS-(AGENT|COPYROOT|RECLAIM|RECLAIM-BUNDLE)( |$)|"
        b"^logging discriminator IRISQ( |$)|"
        b"^logging (buffered|console|monitor) discriminator IRISQ$")
    assert commands[2:4] == (
        b"show running-config | count ^ip http client username( |$)",
        b"show running-config | count ^ip http client password( |$)")
    assert commands[4] == (
        "show running-config | count ^ip http client username %s$" %
        device_id.replace(".", r"\.")).encode("ascii")
    assert all(len(command) <= 320 for command in commands)
    assert all(b"\n" not in command for command in commands)


@pytest.mark.parametrize("appid,device_id", [
    (None, "edge"), (True, "edge"), ("", "edge"), ("x" * 65, "edge"),
    ("iris|other", "edge"), ("iris", None), ("iris", ""),
    ("iris", "x" * 129), ("iris", "edge$"), ("iris", "edge\nshow run"),
    ("iris", "é"),
])
def test_preflight_rejects_unadmitted_ids_before_any_read(appid, device_id):
    module = _module()
    fake = _Bag(config={"application_id": "iris"})
    def no_command(*args, **kwargs):
        raise AssertionError("invalid preflight ID reached transport")
    fake._command = no_command
    attempt = _Bag(target={"iox_appid": appid}, identity={},
                   request={"device_id": device_id})
    with pytest.raises(module._ControllerFailure) as failure:
        module.IoxController._ordinary_install_preflight(fake, attempt)
    assert failure.value.category == "unsupported_syntax_local"


def _ordinary_preflight_fixture(monkeypatch, running=b"", app_state=None):
    module = _module()
    context, result, unused_prefix, unused_payloads = _preflight_prefix()
    calls = []
    fake = _Bag(config={"application_id": "iris"},
                state_dir="/state", controller_id=_CONTROLLER_ID)
    fake._transport_ok = module.IoxController._transport_ok
    def command(*args, **kwargs):
        calls.append((args, kwargs))
        return result, context
    fake._command = command
    attempt = _Bag(target={}, identity={}, request={"device_id": "edge-01"},
                   attempt_id="a" * 32)
    apps = ("iris %s\n" % app_state).encode("ascii") if app_state else b""
    if app_state:
        running = b"app-hosting appid iris\n" + running
    def payloads(state_dir, controller_id, attempt_id, actual_result, actual_context):
        assert (state_dir, controller_id, attempt_id) == (
            "/state", _CONTROLLER_ID, "a" * 32)
        assert actual_result is result and actual_context is context
        return (apps, running, _http_count(0), _http_count(0), _http_count(0))
    monkeypatch.setattr(module, "_preflight_payloads", payloads)
    return module, fake, attempt, calls


@pytest.mark.parametrize("app_state", [None, "DEPLOYED", "ACTIVATED"])
def test_ordinary_preflight_sends_five_validated_reads_in_one_bounded_session(
        monkeypatch, app_state):
    module, fake, attempt, calls = _ordinary_preflight_fixture(
        monkeypatch, app_state=app_state)
    module.IoxController._ordinary_install_preflight(fake, attempt)
    assert calls == [((attempt, "preflight", b"\n".join(
        module._preflight_commands("iris", "edge-01")), 90),
        {"ordinary": True, "record": False})]
    expected = {"status": "passed"}
    if app_state:
        expected["resumable_app_state"] = app_state
    assert attempt.identity == expected


@pytest.mark.parametrize("running,description", [
    (b"event manager applet IRIS-AGENT\n", "an IRIS EEM applet"),
    (b"event manager applet IRIS-COPYROOT\n", "an IRIS EEM applet"),
    (b"event manager applet IRIS-RECLAIM\n", "an IRIS EEM applet"),
    (b"event manager applet IRIS-RECLAIM-BUNDLE\n", "an IRIS EEM applet"),
    (b"logging discriminator IRISQ msg-body drops %IRIS\n", "logging discriminator IRISQ"),
    (b"logging buffered discriminator IRISQ\n", "an IRISQ logging binding"),
    (b"logging console discriminator IRISQ\n", "an IRISQ logging binding"),
    (b"logging monitor discriminator IRISQ\n", "an IRISQ logging binding"),
])
@pytest.mark.parametrize("app_state", [None, "DEPLOYED", "ACTIVATED"])
def test_ordinary_preflight_preserves_each_named_collision_even_when_resumable(
        monkeypatch, running, description, app_state):
    module, fake, attempt, unused = _ordinary_preflight_fixture(
        monkeypatch, running=running, app_state=app_state)
    with pytest.raises(module._ControllerFailure) as failure:
        module.IoxController._ordinary_install_preflight(fake, attempt)
    assert failure.value.category == "rejected"
    assert failure.value.detail == description + " already exists"
    assert attempt.identity == {}


def test_ordinary_preflight_nearby_names_do_not_become_collisions(monkeypatch):
    module, fake, attempt, unused = _ordinary_preflight_fixture(
        monkeypatch, running=(b"event manager applet IRIS-AGENT2\n"
                             b"logging discriminator IRISQ2\n"
                             b"logging buffered discriminator IRISQ2\n"))
    module.IoxController._ordinary_install_preflight(fake, attempt)
    assert attempt.identity == {"status": "passed"}


def _preflight_prefix():
    context = {"schema_version": 1, "type": "command_start", "command_id": 7,
               "kind": "ssh", "purpose": "preflight", "board_identity": _BOARD,
               "record_id": None, "transaction_id": None, "revision": None,
               "phase": None, "started_at": 100}
    payloads = [b"No apps found\n", b"", _http_count(0), _http_count(1), _http_count(0)]
    stdout = b""
    spans = []
    for payload in payloads:
        stdout += b"edge#read command\n"
        spans.append({"offset": len(stdout), "length": len(payload)})
        stdout += payload
    end = {"returncode": 0, "timed_out": False, "stdout_truncated": False,
           "stderr_truncated": False, "framing_complete": True,
           "error_category": None, "payload_spans": spans}
    command = {"start": context, "end": end, "stdout": stdout, "stderr": b""}
    reference = {"attempt_id": "a" * 32}
    result = dict(end, stdout=stdout, stderr=b"", transcript_ref=reference)
    prefix = {"attempt_id": "a" * 32, "commands": {7: command}}
    return context, result, prefix, payloads


def test_preflight_payloads_come_from_bound_durable_spans_not_result_bytes(monkeypatch):
    module = _module()
    import iox_transport
    context, result, prefix, payloads = _preflight_prefix()
    result["stdout"] = b"untrusted combined output"
    loaded = []
    def load(state_dir, reference, controller_id):
        loaded.append((state_dir, reference, controller_id))
        return prefix
    monkeypatch.setattr(iox_transport, "_load_transcript_prefix", load)
    assert module._preflight_payloads(
        "/state", _CONTROLLER_ID, "a" * 32, result, context) == tuple(payloads)
    assert loaded == [("/state", result["transcript_ref"], _CONTROLLER_ID)]


@pytest.mark.parametrize("damage", [
    "foreign_attempt", "foreign_context", "missing_command", "unfinished",
    "wrong_purpose", "failed_end", "timeout", "stdout_truncated", "stderr_truncated",
    "framing_incomplete", "error_category", "missing_span", "extra_span",
    "reordered_span", "overlapping_span", "out_of_bounds", "negative_offset",
    "bool_offset", "bool_length",
])
def test_preflight_payloads_reject_ambiguous_or_unbound_evidence(monkeypatch, damage):
    module = _module()
    import iox_transport
    context, result, prefix, unused = _preflight_prefix()
    command = prefix["commands"][7]
    end = command["end"]
    if damage == "foreign_attempt":
        result["transcript_ref"]["attempt_id"] = "b" * 32
    elif damage == "foreign_context":
        context = dict(context, board_identity="OTHER")
    elif damage == "missing_command":
        prefix["commands"].clear()
    elif damage == "unfinished":
        command["end"] = None
    elif damage == "wrong_purpose":
        context["purpose"] = "app_list"
    elif damage == "failed_end":
        end["returncode"] = 1
    elif damage in ("timeout", "stdout_truncated", "stderr_truncated"):
        end["timed_out" if damage == "timeout" else damage] = True
    elif damage == "framing_incomplete":
        end["framing_complete"] = False
    elif damage == "error_category":
        end["error_category"] = "cancelled"
    elif damage == "missing_span":
        end["payload_spans"].pop()
    elif damage == "extra_span":
        end["payload_spans"].append(dict(end["payload_spans"][-1]))
    elif damage == "reordered_span":
        end["payload_spans"].reverse()
    elif damage == "overlapping_span":
        end["payload_spans"][3] = dict(end["payload_spans"][2])
    elif damage == "out_of_bounds":
        end["payload_spans"][-1]["length"] = len(command["stdout"])
    elif damage in ("negative_offset", "bool_offset", "bool_length"):
        key = "length" if damage == "bool_length" else "offset"
        end["payload_spans"][0][key] = -1 if damage == "negative_offset" else True
    monkeypatch.setattr(iox_transport, "_load_transcript_prefix", lambda *args: prefix)
    with pytest.raises(module._ControllerFailure) as failure:
        module._preflight_payloads("/state", _CONTROLLER_ID, "a" * 32, result, context)
    assert failure.value.category in ("authority_mismatch", "journal_unreadable")


def test_strict_controller_requires_the_artifact_url_and_directory(tmp_path):
    module = _module()
    import iox_transport
    store = _StatefulStore(tmp_path)
    base = dict(_authority(tmp_path, catalog_url="https://192.0.2.2:8443"))
    base["record_store"] = os.path.realpath(store.path)
    for missing, message in (("artifact_url", "artifact URL"),
                             ("artifacts_dir", "artifacts directory")):
        config = dict(base, artifact_url="https://192.0.2.2:8000",
                      artifacts_dir=str(tmp_path / "artifacts"))
        del config[missing]
        with pytest.raises(ValueError) as failure:
            module.IoxController(store, _Bag(**config),
                                 iox_transport.IoxTransport, lambda: 100,
                                 lambda: 100.0)
        assert message in str(failure.value)
    with pytest.raises(ValueError):
        module.IoxController(
            store, _Bag(**dict(base, artifact_url="http://192.0.2.2:8000",
                               artifacts_dir=str(tmp_path / "artifacts"))),
            iox_transport.IoxTransport, lambda: 100, lambda: 100.0)


def test_command_failure_detail_names_a_timeout_instead_of_an_earlier_verdict():
    module = _module()
    result = {"timed_out": True, "returncode": -15,
              "stdout": b"no crypto pki trustpoint IRIS\r\n% Can't find policy IRIS\r\n"}
    assert module._command_failure_detail("configure_trustpoint", result) == (
        "IOx command failed: configure_trustpoint: timed out waiting for the device's prompt")
    plain = {"timed_out": False, "returncode": 4,
             "stdout": b"app-hosting appid iris\r\n% node--1:dbm:IOxMan:Resource Profile-names is not specified\r\n"}
    assert "Resource Profile-names" in module._command_failure_detail("configure_app", plain)
