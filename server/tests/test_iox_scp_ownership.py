# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local ownership and ordering checks; no device connections or package builds."""
import copy
from types import SimpleNamespace

import pytest

import deployment_records
import iox_verification as module
import test_iox_verification as fixtures
import test_iox_verification_crash as crash


@pytest.fixture
def store(tmp_path):
    crash._seed_phase(tmp_path, "unchanged")
    return deployment_records.DeploymentRecordStore(str(tmp_path))


def _state(store, **kwargs):
    return store.iox_scp_state(crash._RECORD, crash._CONTROLLER,
                               crash._BOARD, **kwargs)


def _new_record(store, record_id="new-record"):
    source = store.get(crash._RECORD, strict=True)
    value = copy.deepcopy(source)
    for field in ("state", "timestamps", "iox_verification", "scp_server"):
        value.pop(field, None)
    value["record_id"] = record_id
    store.create(value)
    journal = source["iox_verification"]
    store.iox_begin(record_id, crash._CONTROLLER, crash._BOARD,
                    {key: journal[key] for key in (
                        "wrapper_sha256", "package_sign_present", "package_cert_present")},
                    journal["initial_observation"], journal["transcript_refs"][0])
    return record_id


def test_generic_record_cannot_inject_scp_authority(store):
    value = crash._deployment_record(state="planned")
    value["record_id"] = "injected"
    value["scp_server"] = {"board_identity": crash._BOARD,
                           "prior_enabled": False, "phase": "enabled"}
    with pytest.raises(ValueError, match="generic records"):
        store.create(value)


@pytest.mark.parametrize("controller,board", [
    ("a" * 32, crash._BOARD), (crash._CONTROLLER, "OTHERBOARD")])
def test_claim_requires_controller_and_physical_board_binding(store, controller, board):
    with pytest.raises(ValueError, match="binding mismatch"):
        store.iox_scp_state(crash._RECORD, controller, board, prior_enabled=False)
    assert "scp_server" not in store.get(crash._RECORD, strict=True)


def test_prior_state_is_immutable_and_survives_record_lifecycle(store):
    assert _state(store, prior_enabled=False)["phase"] == "enable_intent"
    with pytest.raises(ValueError, match="transition"):
        _state(store, prior_enabled=True)
    assert _state(store, phase="enabled")["prior_enabled"] is False
    store.transition(crash._RECORD, "applying", {"status": "teardown"})
    assert _state(store)["phase"] == "enabled"
    assert _state(store, phase="restored")["phase"] == "restored"
    store.transition(crash._RECORD, "removed")
    persisted = deployment_records.DeploymentRecordStore(store.state_dir)
    assert persisted.get(crash._RECORD, strict=True)["scp_server"]["phase"] == "restored"
    with pytest.raises(ValueError, match="binding mismatch"):
        _state(store, phase="enabled")


def test_preexisting_enabled_claim_cannot_become_owned(store):
    assert _state(store, prior_enabled=True)["phase"] == "preserved"
    for phase in ("enabled", "restored", "enable_intent"):
        with pytest.raises(ValueError, match="transition"):
            _state(store, phase=phase)


@pytest.mark.parametrize("old_phase", ["enable_intent", "enabled"])
def test_older_claim_blocks_replacement_even_after_abandonment(store, old_phase):
    _state(store, prior_enabled=False)
    if old_phase == "enabled":
        _state(store, phase="enabled")
    store.transition(crash._RECORD, "abandoned")
    record_id = _new_record(store)
    with pytest.raises(ValueError, match="prior SCP ownership"):
        store.iox_scp_state(record_id, crash._CONTROLLER, crash._BOARD)


def test_restored_claim_allows_a_new_deployment(store):
    _state(store, prior_enabled=False)
    _state(store, phase="enabled")
    _state(store, phase="restored")
    store.transition(crash._RECORD, "applying")
    store.transition(crash._RECORD, "removed")
    record_id = _new_record(store)
    assert store.iox_scp_state(record_id, crash._CONTROLLER, crash._BOARD) is None


class _Harness:
    """Exercise real controller helpers with only transport/persistence replaced."""
    def __init__(self, monkeypatch, enabled=False, claim=None):
        self.controller = object.__new__(module.IoxController)
        self.enabled = enabled
        self.claim = copy.deepcopy(claim)
        self.calls = []
        self.apps = b"App id State\n--------------------\n"
        self.probe = None
        self.save_failed = False
        self.attempt = SimpleNamespace(
            target={}, request={"action": "uninstall", "teardown_mode": "recorded"},
            durability_uncertain=False, fence=None, operation_results=[],
            check=lambda: None,
            next_context=lambda purpose, **kwargs: {"command_id": purpose},
            deadline=lambda *args, **kwargs: 100)
        self.attempt.transport = SimpleNamespace(command=self.command)
        monkeypatch.setattr(self.controller, "_scp_state", self.state)
        monkeypatch.setattr(self.controller, "_adopt_synthetic_result", lambda *args: None)

    def state(self, attempt, **kwargs):
        self.calls.append(("state", copy.deepcopy(kwargs)))
        if "prior_enabled" in kwargs:
            prior = kwargs["prior_enabled"]
            self.claim = {"prior_enabled": prior,
                          "phase": "preserved" if prior else "enable_intent"}
        elif "phase" in kwargs:
            self.claim["phase"] = kwargs["phase"]
        return copy.deepcopy(self.claim)

    def command(self, purpose, body, deadline):
        self.calls.append((purpose, body))
        if purpose == "scp_read":
            return fixtures._transport_result(self.probe if self.probe is not None else
                b"hostname fixture\n" + (b"ip scp server enable\n" if self.enabled else b""))
        if purpose == "scp_enable":
            self.enabled = True
        elif purpose == "scp_disable":
            self.enabled = False
        elif purpose == "scp_apps":
            return fixtures._transport_result(self.apps)
        elif purpose == "save" and self.save_failed:
            return fixtures._transport_result(returncode=1, error_category="rejected")
        return fixtures._transport_result()

    def prepare(self):
        self.controller._prepare_scp(self.attempt)

    def save(self):
        return self.controller._command(self.attempt, "save", b"write memory")


@pytest.mark.parametrize("mode", ["routed", "inband", "router-routed", "router-nat"])
def test_capture_and_confirm_wrap_enable_before_other_configuration(monkeypatch, mode):
    h = _Harness(monkeypatch)
    h.attempt.target["management_type"] = mode
    h.controller._command(h.attempt, "prepare_iox_scp", b"configure terminal\niox\nend")
    assert [name for name, value in h.calls] == [
        "state", "scp_read", "state", "scp_enable", "scp_read", "state", "prepare_iox_scp"]
    assert h.calls[2] == ("state", {"prior_enabled": False})
    assert h.claim["phase"] == "enabled"


def test_preexisting_server_is_preserved_on_prepare_and_undeploy(monkeypatch):
    h = _Harness(monkeypatch, enabled=True)
    h.prepare()
    h.save()
    assert h.enabled is True and h.claim["phase"] == "preserved"
    assert not any(name in ("scp_enable", "scp_disable") for name, value in h.calls)


def test_legacy_and_force_undeploy_leave_server_unchanged(monkeypatch):
    h = _Harness(monkeypatch, enabled=True)
    h.save()
    assert h.claim is None and h.enabled
    assert [name for name, value in h.calls] == ["state", "save"]
    h.calls.clear()
    h.attempt.request["teardown_mode"] = "force_agent_only"
    h.save()
    assert [name for name, value in h.calls] == ["save"]


@pytest.mark.parametrize("output", [
    b"", b"ip scp server enable\n", b"% Invalid input\n",
    b"hostname fixture\nip scp server enable unexpected\n",
    b"hostname fixture\n % Invalid input\n"])
def test_unknown_probe_never_creates_claim_or_enables(monkeypatch, output):
    h = _Harness(monkeypatch)
    h.probe = output
    with pytest.raises(module._ControllerFailure, match="Cannot determine"):
        h.prepare()
    assert h.claim is None and not h.enabled


def test_whitespace_padded_enabled_line_is_preserved(monkeypatch):
    h = _Harness(monkeypatch, enabled=True)
    h.probe = b"hostname fixture\nip scp server enable \n"
    h.prepare()
    assert h.claim["phase"] == "preserved"
    assert not any(name == "scp_enable" for name, value in h.calls)


@pytest.mark.parametrize("overrides", [
    {"stdout_truncated": True}, {"framing_complete": False},
    {"returncode": 1}, {"error_category": "timeout"}])
def test_incomplete_or_failed_probe_is_not_disabled_evidence(monkeypatch, overrides):
    h = _Harness(monkeypatch)
    original = h.command

    def command(purpose, body, deadline):
        result = original(purpose, body, deadline)
        if purpose == "scp_read":
            result.update(overrides)
        return result

    h.attempt.transport.command = command
    with pytest.raises(module._ControllerFailure):
        h.prepare()
    assert h.claim is None and not h.enabled


@pytest.mark.parametrize("apps", [b"", b"App id State\niris RUNNING\n",
                                  b"other RUNNING\nNo App found\n",
                                  b"App id State\nother DEPLOYED\n",
                                  b"App id State\nother INSTALLING\n",
                                  b"App id State\nother UNKNOWN_FUTURE_STATE\n",
                                  b"App id State\n  other RUNNING\n",
                                  b"App id State\nother TRANSITION IN PROGRESS\n",
                                  b"App id State\n% Internal error\n"])
def test_undeploy_requires_proven_absence_of_all_apps(monkeypatch, apps):
    h = _Harness(monkeypatch, enabled=True,
                 claim={"prior_enabled": False, "phase": "enabled"})
    h.apps = apps
    with pytest.raises(module._ControllerFailure, match="apps are absent"):
        h.save()
    assert h.enabled and h.claim["phase"] == "enabled"
    assert not any(name in ("scp_disable", "save") for name, value in h.calls)


@pytest.mark.parametrize("apps", [
    b"App id State\n---------------------\n",
    b"App id State\n---------------------\nNo App found\n",
    b"3400-1#show app-hosting list\nNo App found\n3400-1#",
    b"iris-c8kv-104#show app-hosting list\nNo App found\niris-c8kv-104#",
])
def test_restoration_is_verified_before_save_and_committed_after(monkeypatch, apps):
    h = _Harness(monkeypatch, enabled=True,
                 claim={"prior_enabled": False, "phase": "enabled"})
    h.apps = apps
    h.save()
    assert [name for name, value in h.calls] == [
        "state", "scp_apps", "scp_read", "scp_disable", "scp_read", "save", "state"]
    assert h.calls[-1] == ("state", {"phase": "restored"})
    assert not h.enabled and h.claim["phase"] == "restored"


def test_failed_save_retains_claim_and_retry_saves_without_repeated_disable(monkeypatch):
    h = _Harness(monkeypatch, enabled=True,
                 claim={"prior_enabled": False, "phase": "enabled"})
    h.save_failed = True
    result, unused = h.save()
    assert result["returncode"] != 0
    assert not h.enabled and h.claim["phase"] == "enabled"
    h.calls.clear()
    h.save_failed = False
    h.save()
    assert h.claim["phase"] == "restored"
    assert not any(name == "scp_disable" for name, value in h.calls)


def test_interrupted_enable_is_not_assumed_owned(monkeypatch):
    h = _Harness(monkeypatch, enabled=True,
                 claim={"prior_enabled": False, "phase": "enable_intent"})
    for operation in (h.prepare, h.save):
        with pytest.raises(module._ControllerFailure, match="Interrupted SCP enable"):
            operation()
    assert h.enabled
    assert not any(name in ("scp_disable", "save") for name, value in h.calls)


def test_manually_disabled_interrupted_enable_can_be_completed(monkeypatch):
    h = _Harness(monkeypatch, enabled=False,
                 claim={"prior_enabled": False, "phase": "enable_intent"})
    h.save()
    assert h.claim["phase"] == "restored"
    assert [name for name, value in h.calls] == [
        "state", "scp_apps", "scp_read", "save", "state"]


def test_store_allows_manual_restoration_of_interrupted_intent(store):
    _state(store, prior_enabled=False)
    assert _state(store, phase="restored")["phase"] == "restored"


def test_shared_mount_still_checks_outstanding_ownership_without_enabling(monkeypatch):
    h = _Harness(monkeypatch)
    h.attempt.target["share_ios_path"] = "usbflash1:iox_host_data_share"
    h.prepare()
    assert h.calls == [("state", {})]
    assert h.claim is None and not h.enabled
