# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Origin-seeder QoS desired state, status, and reconcile lifecycle tests."""
import importlib
import json
import os

import pytest

import blocklist_reconciler
import peer_endpoints
import peer_policy
import tracker


def _module():
    return importlib.import_module("origin_qos")


def _configured_doc(up=9_000_000, per_torrent=3_000_000, peers=17):
    doc = peer_policy.base_document()
    doc["roles"] = {
        "defs": {},
        "role_of": {},
        "qos_default": {
            "origin_up_bps": up,
            "origin_per_torrent_up_bps": per_torrent,
            "origin_max_peers": peers,
        },
        "qos_device": {},
    }
    peer_policy.validate_document(doc)
    return doc


class FakeAria:
    def __init__(self, session="session-1", gids=("gid-2", "gid-1")):
        self.session = session
        self.gids = list(gids)
        self.blocklist_calls = []
        self.global_calls = []
        self.download_calls = []
        self.session_calls = 0
        self.target_calls = 0
        self.fail_blocklist = False
        self.fail_global = False
        self.fail_gid = None
        self.fail_gid_once = False
        self.session_error = False
        self.target_error = False
        self.change_session_after_gid = None

    def get_session_id(self):
        self.session_calls += 1
        if self.session_error:
            raise RuntimeError("rpc secret must not escape")
        return self.session

    def get_active_download_gids(self):
        self.target_calls += 1
        if self.target_error:
            raise RuntimeError("rpc secret must not escape")
        return tuple(sorted(set(self.gids)))

    def set_blocklist(self, ips):
        self.blocklist_calls.append(list(ips))
        if self.fail_blocklist:
            raise RuntimeError("blocklist failed")
        return {"revision": 1, "disconnectedPeers": 0, "removedPeers": 0}

    def set_global_options(self, options):
        self.global_calls.append(dict(options))
        if self.fail_global:
            raise RuntimeError("global failed")
        return "OK"

    def set_download_options(self, gid, options):
        self.download_calls.append((gid, dict(options)))
        if gid == self.fail_gid:
            if self.fail_gid_once:
                self.fail_gid = None
            raise RuntimeError("download failed")
        if gid == self.change_session_after_gid:
            self.session = "session-changed-mid-pass"
            self.change_session_after_gid = None
        return "OK"


class FakeRpc:
    def __init__(self, active_result):
        self.active_result = active_result
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "aria2.getSessionInfo":
            return {"sessionId": "session-1"}
        if method == "aria2.tellActive":
            return self.active_result
        if method == "aria2.setBtPeerBlocklist":
            return {"revision": 1, "disconnectedPeers": 0, "removedPeers": 0}
        return "OK"


def _paths(tmp_path):
    return {
        "policy": str(tmp_path / "peer-policy.json"),
        "lkg": str(tmp_path / "peer-policy.lkg.json"),
        "endpoints": str(tmp_path / "peer-endpoints.json"),
        "enforcement": str(tmp_path / "peer-enforcement.json"),
        "origin_qos": str(tmp_path / "origin-qos.json"),
    }


def _reconciler(tmp_path, aria, protected_seeder_ip=None):
    paths = _paths(tmp_path)
    peer_policy.initialize(paths["policy"], paths["lkg"])
    rec = tracker.TrackerReconciler(
        policy_paths=(paths["policy"], paths["lkg"]),
        endpoints_path=paths["endpoints"],
        enforcement_path=paths["enforcement"],
        origin_qos_path=paths["origin_qos"],
        aria=aria,
        pending_queue=peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: [],
        revoked_principals=lambda: set(),
        protected_seeder_ip=protected_seeder_ip,
        now=lambda: 1000.0)
    return rec, paths


class TestDesiredState:
    def test_defaults_are_exact_decimal_aria_options_including_zero(self):
        oq = _module()
        desired = oq.build_desired(peer_policy.base_document(), ["gid-2", "gid-1"])
        assert desired.global_options == {
            "max-overall-upload-limit": "0",
        }
        assert desired.download_options == {
            "max-upload-limit": "0",
            "bt-max-peers": "55",
        }
        assert desired.target_gids == ("gid-1", "gid-2")
        assert isinstance(desired.desired_hash, str) and desired.desired_hash

    def test_configured_values_map_without_unit_conversion(self):
        oq = _module()
        desired = oq.build_desired(_configured_doc(), ["gid-1"])
        assert desired.global_options["max-overall-upload-limit"] == "9000000"
        assert desired.download_options == {
            "max-upload-limit": "3000000",
            "bt-max-peers": "17",
        }

    def test_hash_is_order_independent_and_binds_options_and_targets(self):
        oq = _module()
        first = oq.build_desired(_configured_doc(), ["gid-2", "gid-1"])
        reordered = oq.build_desired(_configured_doc(), ["gid-1", "gid-2"])
        assert first.desired_hash == reordered.desired_hash
        assert first.desired_hash != oq.build_desired(
            _configured_doc(up=8_000_000), ["gid-1", "gid-2"]).desired_hash
        assert first.desired_hash != oq.build_desired(
            _configured_doc(), ["gid-1"]).desired_hash

    @pytest.mark.parametrize("gids", [
        [""], [None], [True], ["gid", "gid"], ["g\nsecret"],
    ])
    def test_target_ids_must_be_nonempty_unique_safe_strings(self, gids):
        with pytest.raises((TypeError, ValueError)):
            _module().build_desired(peer_policy.base_document(), gids)


class TestOriginQosStatus:
    def test_status_all_source_codes_and_invalid_known_fields(self, tmp_path):
        import reconciler_status
        oq = _module()
        path = str(tmp_path / "origin.json")
        for code in reconciler_status.ORIGIN_ERROR_CODES:
            status = oq.build_status("degraded", "s", "h", 0, 0, 0, 10, last_error=code)
            oq.write_status(path, dict(status, future="private"))
            assert oq.read_status(path) == status
        for change in ({"schema": 2}, {"updated_at": float("inf")},
                       {"last_reconciled_at": -1}, {"global_option_count": True},
                       {"target_download_count": -1}, {"applied_download_count": 1},
                       {"aria_session_id": []}, {"last_error": {}}, {"state": []}):
            oq.write_status(path, dict(status, **change))
            assert oq.read_status(path) is None

    def test_status_desired_failure_uses_source_code(self, tmp_path, monkeypatch):
        oq = _module()
        rec, paths = _reconciler(tmp_path, FakeAria())
        def fail(*args):
            raise PermissionError("secret")
        monkeypatch.setattr(oq, "build_desired", fail)
        rec.run_once()
        assert oq.read_status(paths["origin_qos"])["last_error"] == "origin_desired_state_failed"

    @pytest.mark.parametrize("error", ["PermissionError", "sentinel_secret"])
    def test_status_error_vocabulary_is_closed(self, tmp_path, error):
        oq = _module()
        with pytest.raises(ValueError):
            oq.build_status("degraded", "s", "h", 0, 0, 0, 10, last_error=error)
        status = oq.build_status("enforced", "s", "h", 1, 0, 0, 10)
        status["last_error"] = error
        path = str(tmp_path / "origin.json")
        oq.write_status(path, status)
        assert oq.read_status(path) is None

    @pytest.mark.parametrize("global_failure", [True, False])
    def test_status_writer_errors_are_semantic(self, global_failure):
        oq = _module()
        class Aria(FakeAria):
            def set_global_options(self, options):
                if global_failure:
                    raise PermissionError("secret")
            def set_download_options(self, gid, options):
                raise PermissionError("secret")
        outcome = oq.apply_desired(Aria(), oq.build_desired(_configured_doc(), ["gid"]), "s")
        assert outcome.last_error == ("origin_global_apply_failed" if global_failure
                                      else "origin_download_apply_failed")

    def _status(self, **overrides):
        values = {
            "state": "enforced",
            "aria_session_id": "session-1",
            "desired_hash": "abcd1234",
            "global_option_count": 1,
            "target_download_count": 2,
            "applied_download_count": 2,
            "now": 1000.0,
            "last_error": None,
        }
        values.update(overrides)
        return _module().build_status(**values)

    def test_exact_count_only_schema(self):
        status = self._status()
        assert status == {
            "schema": 1,
            "updated_at": 1000.0,
            "state": "enforced",
            "aria_session_id": "session-1",
            "desired_hash": "abcd1234",
            "global_option_count": 1,
            "target_download_count": 2,
            "applied_download_count": 2,
            "last_reconciled_at": 1000.0,
            "last_error": None,
        }

    @pytest.mark.parametrize("field", [
        "ips", "addresses", "denied_ips", "gids", "downloads", "info_hashes",
    ])
    def test_rejects_identifier_or_address_carriers(self, field):
        with pytest.raises((TypeError, ValueError)):
            self._status(**{field: ["10.0.0.1"]})

    @pytest.mark.parametrize("field", [
        "global_option_count", "target_download_count", "applied_download_count",
    ])
    @pytest.mark.parametrize("value", [True, -1, 1.5, "1"])
    def test_counts_are_nonboolean_nonnegative_integers(self, field, value):
        with pytest.raises((TypeError, ValueError)):
            self._status(**{field: value})

    def test_enforced_requires_session_hash_global_and_all_downloads(self):
        for changes in (
                {"aria_session_id": None}, {"desired_hash": None},
                {"global_option_count": 0}, {"applied_download_count": 1}):
            with pytest.raises((TypeError, ValueError)):
                self._status(**changes)

    def test_unknown_state_and_applied_above_target_are_rejected(self):
        with pytest.raises((TypeError, ValueError)):
            self._status(state="pending")
        with pytest.raises((TypeError, ValueError)):
            self._status(applied_download_count=3)

    @pytest.mark.parametrize("value", [
        "RpcError.10.0.0.98", "10.0.0.98", "error with address", "", ".",
        True, 7,
    ])
    def test_last_error_is_a_bare_safe_code(self, value):
        with pytest.raises((TypeError, ValueError)):
            self._status(state="degraded", last_error=value)
        assert self._status(state="degraded", last_error="origin_reconcile_failed") \
            ["last_error"] == "origin_reconcile_failed"

    def test_atomic_round_trip_and_corrupt_or_missing_read(self, tmp_path):
        oq = _module()
        path = str(tmp_path / "origin-qos.json")
        assert oq.read_status(path) is None
        oq.write_status(path, self._status())
        assert oq.read_status(path) == self._status()
        assert list(tmp_path.glob(".origin-qos-*.tmp")) == []
        with open(path, "w") as handle:
            handle.write("{broken")
        assert oq.read_status(path) is None


class TestAriaAdapter:
    def test_exact_rpc_methods_parameters_and_target_normalization(self):
        calls = []

        def rpc(method, params):
            calls.append((method, params))
            if method == "aria2.tellActive":
                return [{"gid": "g2"}, {"gid": "g1"}]
            if method == "aria2.getSessionInfo":
                return {"sessionId": "s1"}
            return "OK"

        aria = tracker.Aria2BlocklistAdapter(rpc)
        assert aria.get_active_download_gids() == ("g1", "g2")
        aria.set_global_options({"max-overall-upload-limit": "0"})
        aria.set_download_options(
            "g1", {"max-upload-limit": "8192", "bt-max-peers": "4"})
        assert calls == [
            ("aria2.tellActive", [["gid"]]),
            ("aria2.changeGlobalOption", [{"max-overall-upload-limit": "0"}]),
            ("aria2.changeOption", [
                "g1", {"max-upload-limit": "8192", "bt-max-peers": "4"}]),
        ]

    @pytest.mark.parametrize("result", [
        None, {}, "", 0, False, (),
        [{}], [{"gid": "g1"}, {}], [{"gid": "g1"}, {"gid": "g1"}],
        ["g1"], [{"gid": None}], [{"gid": True}], [{"gid": ""}],
        [{"gid": "bad\ngid"}],
    ])
    def test_target_discovery_rejects_incomplete_or_malformed_results(
            self, result):
        aria = tracker.Aria2BlocklistAdapter(
            lambda method, params: result if method == "aria2.tellActive"
            else "OK")
        with pytest.raises((TypeError, ValueError)):
            aria.get_active_download_gids()

    def test_adapter_rejects_option_scope_broadening_before_rpc(self):
        calls = []
        aria = tracker.Aria2BlocklistAdapter(
            lambda method, params: calls.append((method, params)))
        with pytest.raises(ValueError):
            aria.set_global_options({"max-download-limit": "1"})
        with pytest.raises(ValueError):
            aria.set_download_options("g1", {"seed-time": "0"})
        assert calls == []


class TestReconcileLifecycle:
    def test_first_run_full_applies_and_same_state_skips(self, tmp_path):
        oq = _module()
        aria = FakeAria()
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        assert aria.global_calls == [{"max-overall-upload-limit": "0"}]
        assert aria.download_calls == [
            ("gid-1", {"max-upload-limit": "0", "bt-max-peers": "55"}),
            ("gid-2", {"max-upload-limit": "0", "bt-max-peers": "55"}),
        ]
        status = oq.read_status(paths["origin_qos"])
        assert status["state"] == "enforced"
        assert status["global_option_count"] == 1
        assert status["target_download_count"] == 2
        assert status["applied_download_count"] == 2

        rec.run_once()
        assert len(aria.global_calls) == 1
        assert len(aria.download_calls) == 2

    def test_policy_hash_session_and_target_changes_force_full_apply(self,
                                                                    tmp_path):
        aria = FakeAria(gids=("g1",))
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()

        peer_policy.set_qos(
            paths["policy"], paths["lkg"],
            {"origin_up_bps": 8192,
             "origin_per_torrent_up_bps": 16384,
             "origin_max_peers": 9},
            actor="test", now=1001.0)
        rec.run_once()
        assert aria.global_calls[-1] == {"max-overall-upload-limit": "8192"}
        assert aria.download_calls[-1] == (
            "g1", {"max-upload-limit": "16384", "bt-max-peers": "9"})

        aria.session = "session-2"
        rec.run_once()
        aria.gids.append("g2")
        rec.run_once()
        assert len(aria.global_calls) == 4
        assert [gid for gid, _ in aria.download_calls[-2:]] == ["g1", "g2"]

    @pytest.mark.parametrize("failed_gid,expected_applied", [
        ("g1", 2), ("g2", 2), ("g3", 2),
    ])
    def test_partial_download_failure_is_degraded_and_retries_full_set(
            self, tmp_path, failed_gid, expected_applied):
        oq = _module()
        aria = FakeAria(gids=("g1", "g2", "g3"))
        aria.fail_gid = failed_gid
        aria.fail_gid_once = True
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        first = oq.read_status(paths["origin_qos"])
        assert first["state"] == "degraded"
        assert first["global_option_count"] == 1
        assert first["applied_download_count"] == expected_applied
        assert first["last_error"] == "origin_download_apply_failed"
        assert rec._qos_last_hash is None

        rec.run_once()
        second = oq.read_status(paths["origin_qos"])
        assert second["state"] == "enforced"
        assert [gid for gid, _ in aria.download_calls[-3:]] \
            == ["g1", "g2", "g3"]

    def test_global_failure_and_recovery_retry_everything(self, tmp_path):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        aria.fail_global = True
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        first = oq.read_status(paths["origin_qos"])
        assert first["state"] == "degraded"
        assert first["global_option_count"] == 0
        assert first["applied_download_count"] == 0
        assert aria.download_calls == []
        assert rec._qos_last_hash is None
        aria.fail_global = False
        rec.run_once()
        assert oq.read_status(paths["origin_qos"])["state"] == "enforced"
        assert [gid for gid, _ in aria.download_calls] == ["g1"]

    def test_unknown_session_applies_nothing_and_recovery_full_applies(self,
                                                                      tmp_path):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        aria.session_error = True
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        assert aria.global_calls == [] and aria.download_calls == []
        assert oq.read_status(paths["origin_qos"])["state"] == "rpc_unavailable"
        aria.session_error = False
        rec.run_once()
        assert aria.global_calls == [{"max-overall-upload-limit": "0"}]
        assert [gid for gid, _ in aria.download_calls] == ["g1"]

    def test_target_discovery_failure_is_unavailable_then_recovers(self,
                                                                   tmp_path):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        aria.target_error = True
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        assert aria.global_calls == [] and aria.download_calls == []
        assert oq.read_status(paths["origin_qos"])["state"] == "rpc_unavailable"
        aria.target_error = False
        rec.run_once()
        assert oq.read_status(paths["origin_qos"])["state"] == "enforced"
        assert [gid for gid, _ in aria.download_calls] == ["g1"]

    @pytest.mark.parametrize("result", [
        None, {}, "", 0, False, (),
        [{}], [{"gid": "g1"}, {}], [{"gid": "g1"}, {"gid": "g1"}],
        ["g1"], [{"gid": None}], [{"gid": True}], [{"gid": ""}],
        [{"gid": "bad\ngid"}],
    ])
    def test_malformed_target_discovery_is_unavailable_and_full_retries(
            self, tmp_path, result):
        oq = _module()
        rpc = FakeRpc(result)
        rec, paths = _reconciler(
            tmp_path, tracker.Aria2BlocklistAdapter(rpc))

        rec.run_once()
        first = oq.read_status(paths["origin_qos"])
        assert first["state"] == "rpc_unavailable"
        assert first["target_download_count"] == 0
        assert rec._qos_rpc_ok is False
        assert not [call for call in rpc.calls
                    if call[0] in ("aria2.changeGlobalOption",
                                   "aria2.changeOption")]

        rpc.active_result = [{"gid": "g2"}, {"gid": "g1"}]
        rec.run_once()
        second = oq.read_status(paths["origin_qos"])
        assert second["state"] == "enforced"
        assert second["target_download_count"] == 2
        assert second["applied_download_count"] == 2
        assert [call[0] for call in rpc.calls
                if call[0] in ("aria2.changeGlobalOption",
                               "aria2.changeOption")] == [
            "aria2.changeGlobalOption", "aria2.changeOption",
            "aria2.changeOption",
        ]

    def test_zero_active_downloads_still_applies_global(self, tmp_path):
        oq = _module()
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        assert aria.global_calls == [{"max-overall-upload-limit": "0"}]
        assert aria.download_calls == []
        status = oq.read_status(paths["origin_qos"])
        assert status["state"] == "enforced"
        assert status["target_download_count"] == 0
        assert status["applied_download_count"] == 0

    def test_midpass_session_change_is_degraded_then_fully_retried(self,
                                                                  tmp_path):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        aria.change_session_after_gid = "g1"
        rec, paths = _reconciler(tmp_path, aria)
        rec.run_once()
        assert oq.read_status(paths["origin_qos"])["state"] == "degraded"
        assert rec._qos_last_hash is None
        rec.run_once()
        assert oq.read_status(paths["origin_qos"])["state"] == "enforced"
        assert len(aria.global_calls) == 2
        assert [gid for gid, _ in aria.download_calls] == ["g1", "g1"]

    def test_blocklist_and_qos_success_memory_are_independent(self, tmp_path):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        aria.fail_blocklist = True
        rec, paths = _reconciler(tmp_path, aria)
        peer_status = rec.run_once()
        assert peer_status["state"] == "degraded"
        assert oq.read_status(paths["origin_qos"])["state"] == "enforced"
        assert rec._rpc_ok is False and rec._qos_rpc_ok is True

        aria.fail_blocklist = False
        aria.fail_gid = "g1"
        aria.session = "session-2"       # force a real full QoS apply attempt
        rec.run_once()
        assert json.load(open(paths["enforcement"]))["state"] == "enforced"
        assert oq.read_status(paths["origin_qos"])["state"] == "degraded"
        assert rec._rpc_ok is True and rec._qos_rpc_ok is False

    def test_qos_status_write_failure_does_not_degrade_blocklist_and_retries(
            self, tmp_path, monkeypatch):
        oq = _module()
        aria = FakeAria(gids=("g1",))
        rec, paths = _reconciler(tmp_path, aria)

        def unavailable(_path, _status):
            raise OSError(28, "status filesystem unavailable")

        monkeypatch.setattr(tracker._origin_qos, "write_status", unavailable)
        rec._safe_run()

        assert json.load(open(paths["enforcement"]))["state"] == "enforced"
        assert oq.read_status(paths["origin_qos"]) is None
        assert rec._rpc_ok is True and rec._qos_rpc_ok is False
        assert rec._next_maintenance is None

        monkeypatch.undo()
        rec._safe_run()
        assert oq.read_status(paths["origin_qos"])["state"] == "enforced"
        assert len(aria.global_calls) == 2
        assert [gid for gid, _ in aria.download_calls] == ["g1", "g1"]

    def test_idle_poll_detects_gid_churn_and_reuses_the_probe(self, tmp_path):
        aria = FakeAria(gids=("g1",))
        rec, _ = _reconciler(tmp_path, aria)
        rec.run_once()
        rec._poll_keys = rec._current_poll_keys()
        rec._next_maintenance = 2000.0
        initial_target_calls = aria.target_calls
        assert rec._poll_should_run(waked=False) is False
        assert aria.target_calls == initial_target_calls + 1

        aria.gids.append("g2")
        assert rec._poll_should_run(waked=False) is True
        detected_calls = aria.target_calls
        rec.run_once()
        assert aria.target_calls == detected_calls
        assert [gid for gid, _ in aria.download_calls[-2:]] == ["g1", "g2"]


class TestPreflightReconcilerIntegration:
    def test_persists_preflight_but_applies_only_current_blocklist(self,
                                                                  tmp_path):
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, "10.0.0.1")
        doc = _configured_doc()
        doc["roles"]["defs"] = {
            "boat": {"restricted": True, "peers": ["boat"],
                     "origin": False},
        }
        doc["roles"]["role_of"] = {"boat-1": "boat"}
        peer_policy.validate_document(doc)
        with open(paths["policy"], "w") as handle:
            json.dump(doc, handle)
        with open(paths["lkg"], "w") as handle:
            json.dump(doc, handle)
        peer_endpoints.record_endpoint(
            paths["endpoints"], type("P", (), {"type": "device", "id": "boat-1"})(),
            "10.0.0.9", 6881, 1000.0)

        status = rec.run_once()

        assert aria.blocklist_calls == [[]]
        assert status["desired_ip_count"] == 0
        assert status["desired_hash"] == blocklist_reconciler.canonical_hash([])
        assert status["mutual_origin"] == {
            "mode": "preflight",
            "newly_denied_device_count": 1,
            "newly_denied_device_ids": ["boat-1"],
        }

    def test_policy_fail_closed_preserves_last_valid_preflight(self, tmp_path):
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, "10.0.0.1")
        doc = _configured_doc()
        doc["roles"]["defs"] = {
            "boat": {"restricted": True, "peers": ["boat"],
                     "origin": False},
        }
        doc["roles"]["role_of"] = {"boat-1": "boat"}
        peer_policy.validate_document(doc)
        for path in (paths["policy"], paths["lkg"]):
            with open(path, "w") as handle:
                json.dump(doc, handle)
        peer_endpoints.record_endpoint(
            paths["endpoints"],
            type("P", (), {"type": "device", "id": "boat-1"})(),
            "10.0.0.19", 6881, 1000.0)
        observed = rec.run_once()["mutual_origin"]
        assert observed["newly_denied_device_ids"] == ["boat-1"]

        for path in (paths["policy"], paths["lkg"]):
            with open(path, "w") as handle:
                handle.write("{broken")
        status = rec.run_once()

        assert status["state"] == "fail_closed"
        assert status["mutual_origin"] == observed
        assert aria.blocklist_calls[-1] == ["10.0.0.19"]

    def test_failure_status_preserves_only_valid_prior_preflight(self,
                                                                tmp_path):
        oq = _module()
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, "10.0.0.1")
        rec.run_once()
        with open(paths["enforcement"]) as handle:
            prior = json.load(handle)
        prior["mutual_origin"] = {
            "mode": "preflight", "newly_denied_device_count": 1,
            "newly_denied_device_ids": ["boat-1"],
        }
        with open(paths["enforcement"], "w") as handle:
            json.dump(prior, handle)
        rec._note_pass_failure(RuntimeError("secret"))
        assert json.load(open(paths["enforcement"]))["mutual_origin"] \
            == prior["mutual_origin"]

        prior["mutual_origin"]["newly_denied_device_ids"] = ["same", "same"]
        prior["mutual_origin"]["newly_denied_device_count"] = 2
        with open(paths["enforcement"], "w") as handle:
            json.dump(prior, handle)
        rec._note_pass_failure(RuntimeError("secret"))
        assert json.load(open(paths["enforcement"]))["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": None,
            "newly_denied_device_ids": None,
        }
        assert oq.read_status(paths["origin_qos"])["last_error"] == "origin_reconcile_failed"

    def test_endpoint_store_failure_preserves_valid_prior_preflight(
            self, tmp_path, monkeypatch):
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, "10.0.0.1")
        rec.run_once()
        with open(paths["enforcement"]) as handle:
            prior = json.load(handle)
        prior["mutual_origin"] = {
            "mode": "preflight", "newly_denied_device_count": 1,
            "newly_denied_device_ids": ["boat-1"],
        }
        with open(paths["enforcement"], "w") as handle:
            json.dump(prior, handle)

        def corrupt(*args, **kwargs):
            raise peer_endpoints.EndpointStoreError("bad endpoint store")
        monkeypatch.setattr(tracker._peer_endpoints, "fresh_endpoints", corrupt)
        status = rec.run_once()
        assert status["state"] == "fail_closed"
        assert status["mutual_origin"] == prior["mutual_origin"]

    @pytest.mark.parametrize("protected_ip", [
        None, "", "unknown", "seeder.example", "2001:db8::1", "10.0.0.999",
        167772161, True,
    ])
    def test_unknown_seeder_keeps_preflight_unknown_and_current_acl_applied(
            self, tmp_path, protected_ip):
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, protected_ip)
        doc = _configured_doc()
        doc["acls"]["lan-only"] = {"rules": [
            {"seq": 10, "action": "permit",
             "match": {"type": "cidr", "value": "10.0.0.0/24"}},
            {"seq": 20, "action": "deny", "match": {"type": "any"}},
        ]}
        doc["assignments"] = {
            "permitted": "lan-only",
            "denied": peer_policy.RESERVED_QUARANTINE,
        }
        peer_policy.validate_document(doc)
        for path in (paths["policy"], paths["lkg"]):
            with open(path, "w") as handle:
                json.dump(doc, handle)
        for device_id, address in (("permitted", "10.0.0.9"),
                                   ("denied", "10.0.0.10")):
            peer_endpoints.record_endpoint(
                paths["endpoints"],
                type("P", (), {"type": "device", "id": device_id})(),
                address, 6881, 1000.0)

        status = rec.run_once()

        assert status["state"] == "enforced"
        assert status["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": None,
            "newly_denied_device_ids": None,
        }
        assert status["desired_ip_count"] == 1
        assert status["desired_hash"] == blocklist_reconciler.canonical_hash(
            ["10.0.0.10"])
        assert aria.blocklist_calls == [["10.0.0.10"]]
        assert json.load(open(paths["enforcement"])) == status

    def test_known_seeder_with_no_prospective_denials_reports_known_zero(
            self, tmp_path):
        aria = FakeAria(gids=())
        rec, _ = _reconciler(tmp_path, aria, "10.0.0.1")
        assert rec.run_once()["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": 0,
            "newly_denied_device_ids": [],
        }
        assert aria.blocklist_calls == [[]]

    def test_seeder_address_changes_refresh_preflight_without_reapplying_acl(
            self, tmp_path):
        aria = FakeAria(gids=())
        rec, _ = _reconciler(tmp_path, aria, "10.0.0.1")
        known = {
            "mode": "preflight", "newly_denied_device_count": 0,
            "newly_denied_device_ids": [],
        }
        assert rec.run_once()["mutual_origin"] == known
        rec._protected_seeder_ip = None
        assert rec.run_once()["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": None,
            "newly_denied_device_ids": None,
        }
        rec._protected_seeder_ip = "10.0.0.1"
        assert rec.run_once()["mutual_origin"] == known
        assert aria.blocklist_calls == [[]]

    @pytest.mark.parametrize("failure", [
        "policy", "endpoint_store", "unexpected_exception",
    ])
    @pytest.mark.parametrize("lost_address", [None, "invalid", True])
    def test_lost_seeder_address_does_not_preserve_numeric_preflight_on_failure(
            self, tmp_path, monkeypatch, failure, lost_address):
        aria = FakeAria(gids=())
        rec, paths = _reconciler(tmp_path, aria, "10.0.0.1")
        prior = rec.run_once()
        prior["mutual_origin"] = {
            "mode": "preflight", "newly_denied_device_count": 1,
            "newly_denied_device_ids": ["boat-1"],
        }
        with open(paths["enforcement"], "w") as handle:
            json.dump(prior, handle)
        rec._protected_seeder_ip = lost_address
        if failure == "policy":
            for path in (paths["policy"], paths["lkg"]):
                with open(path, "w") as handle:
                    handle.write("{broken")
        elif failure == "endpoint_store":
            def corrupt(*args, **kwargs):
                raise peer_endpoints.EndpointStoreError("bad endpoint store")
            monkeypatch.setattr(tracker._peer_endpoints, "fresh_endpoints", corrupt)

        if failure == "unexpected_exception":
            rec._note_pass_failure(RuntimeError("private exception detail"))
            status = json.load(open(paths["enforcement"]))
            assert status["state"] == "degraded"
        else:
            status = rec.run_once()
            assert status["state"] == "fail_closed"
        assert status["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": None,
            "newly_denied_device_ids": None,
        }
        assert aria.blocklist_calls == [[]]
