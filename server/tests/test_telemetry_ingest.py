# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json

import catalog
import live_samples


class _Store:
    """Minimal CatalogStore stand-in for route_post heartbeat tests.
    *approved* is a single image id (the common case) or a list of ids for a
    multi-image assignment -- get_policy normalises either into the real
    store's {approved_image_id, approved_image_ids} shape."""
    def __init__(self, approved="img-1", stage_error=None,
                 stage_state="ready"):
        self.approved = approved
        self.stage_error = stage_error
        self.stage_state = stage_state
        self.heartbeats = []

    def record_heartbeat(self, device_id, data, now=None):
        self.heartbeats.append((device_id, data))

    def get_policy(self, device_id):
        if isinstance(self.approved, (list, tuple)):
            ids = list(self.approved)
        else:
            ids = [self.approved] if self.approved else []
        return {"approved_image_id": ids[0] if ids else None,
                "approved_image_ids": ids}

    def pending_report(self, device_id, now):
        return None


SAMPLE = {"v": 1, "image_id": "img-1", "phase": "downloading",
          "done_bytes": 10, "down_bps": 1, "up_bps": 0, "peers": 1,
          "tier": "good"}


def _post(cat, body):
    status, ctype, raw = cat.route_post(
        "/v1/devices/d1/heartbeat", json.dumps(body).encode(), "10.0.0.9")
    return status, json.loads(raw)


def _cat(store=None, table=None, settings=None):
    return catalog.Catalog(store or _Store(), "/nonexistent-secrets",
                           audit_path="/dev/null",
                           live_table=table, stream_settings=settings)


class TestHeartbeatSampleIngest:
    def test_valid_sample_lands_in_table(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        status, resp = _post(cat, {"current_image_id": "img-1",
                                   "telemetry_stream_enabled": True,
                                   "sample": dict(SAMPLE)})
        assert status == 200 and resp["ok"] is True
        assert table.size() == 1

    def test_garbage_sample_rejected_heartbeat_still_200(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        for sample in ("junk", {"v": 9}, dict(SAMPLE, image_id="other")):
            status, resp = _post(cat, {"sample": sample})
            assert status == 200 and resp["ok"] is True
        snap = table.snapshot(0.0)
        assert snap["counters"]["samples_rejected_total"] == 3
        assert table.size() == 0

    def test_sample_for_second_assigned_image_accepted(self):
        # A device assigned MULTIPLE images (approved_image_ids) must accept a
        # live sample for any member, not just the first -- membership, not
        # singular equality against approved_image_id.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved=["img-1", "img-2"]), table=table)
        status, resp = _post(cat, {"current_image_id": "img-2",
                                   "sample": dict(SAMPLE, image_id="img-2")})
        assert status == 200 and resp["ok"] is True
        assert table.size() == 1                       # accepted, not rejected

    def test_sample_for_unassigned_image_still_rejected(self):
        # An id outside the whole assigned set stays rejected even when the
        # device carries a multi-image assignment.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved=["img-1", "img-2"]), table=table)
        status, resp = _post(cat, {"sample": dict(SAMPLE, image_id="img-3")})
        assert status == 200 and resp["ok"] is True
        assert table.snapshot(0.0)["counters"]["samples_rejected_total"] == 1
        assert table.size() == 0

    def test_no_sample_key_untouched_path(self):
        store = _Store()
        cat = _cat(store=store)
        status, resp = _post(cat, {"current_image_id": "img-1"})
        assert status == 200
        assert store.heartbeats[0][1]["telemetry_stream_enabled"] is None

    def test_stream_flag_recorded(self):
        store = _Store()
        cat = _cat(store=store)
        _post(cat, {"telemetry_stream_enabled": True})
        assert store.heartbeats[0][1]["telemetry_stream_enabled"] is True


class TestSettingsEcho:
    def test_unconditional_echo_when_wired(self, tmp_path):
        p = str(tmp_path / "telemetry-settings.json")
        live_samples.write_settings(p, 4, True)
        cat = _cat(settings=live_samples.StreamSettings(p))
        status, resp = _post(cat, {})          # no sample, still echoed
        assert (resp["stream_every"], resp["stream_pause"]) == (4, True)

    def test_no_settings_no_keys(self):
        _, resp = _post(_cat(), {})
        assert "stream_every" not in resp and "stream_pause" not in resp


# --- v2 telemetry_observation envelope in the heartbeat (Task 20) ----------

TID = "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"


def _obs(**over):
    env = {"v": 2, "obs_state": "observed", "observed_at": 1.0,
           "transfer_id": TID, "image_id": "img-1", "sample_seq": 1,
           "sampling_class": "good",
           "aria": {"status": "active", "completed_content_bytes": 1,
                    "total_content_bytes": 2, "receive_bps": 3,
                    "send_bps": 4, "connections": 5},
           "peer_connections": []}
    env.update(over)
    return env


class TestV2ObservationIngest:
    def test_valid_observation_lands(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        status, resp = _post(cat, {"current_image_id": "img-1",
                                   "telemetry_enabled": True,
                                   "telemetry_stream_enabled": True,
                                   "telemetry_observation": _obs()})
        assert status == 200 and resp["ok"] is True
        assert table.size() == 1
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["obs_state"] == "observed" and ent["schema"] == "v2"

    def test_observation_for_second_assigned_image_accepted(self):
        # Same membership fix as the v1 sample path: a v2 observation for the
        # device's SECOND assigned image must land, not be silently rejected.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved=["img-1", "img-2"]), table=table)
        status, resp = _post(cat, {"current_image_id": "img-2",
                                   "telemetry_enabled": True,
                                   "telemetry_stream_enabled": True,
                                   "telemetry_observation": _obs(image_id="img-2")})
        assert status == 200 and resp["ok"] is True
        assert table.size() == 1
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["valid"] is True and ent["image_id"] == "img-2"

    def test_observation_for_unassigned_image_still_rejected(self):
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved=["img-1", "img-2"]), table=table)
        status, resp = _post(cat, {"current_image_id": "img-3",
                                   "telemetry_enabled": True,
                                   "telemetry_stream_enabled": True,
                                   "telemetry_observation": _obs(image_id="img-3")})
        assert status == 200 and resp["ok"] is True
        assert table.snapshot(1.0)["counters"]["samples_rejected_total"] == 1
        assert table.size() == 0

    def test_bad_observation_rejected_heartbeat_still_200(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        status, resp = _post(cat, {"current_image_id": "img-1",
                                   "telemetry_observation": _obs(v=9)})
        assert status == 200 and resp["ok"] is True
        assert table.snapshot(0.0)["counters"]["samples_rejected_total"] == 1
        assert table.size() == 0

    def test_bad_observation_leaves_prior_good_data(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(sample_seq=5)})
        assert table.size() == 1
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(obs_state="running")})
        # bad envelope rejected + counted, prior good data untouched
        assert table.size() == 1
        assert table.snapshot(1.0)["samples"]["d1"]["sample_seq"] == 5

    def test_flags_off_withdraw_even_with_observed(self):
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs()})
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is True
        # telemetry disabled flag -> server withdraws even with observed
        _post(cat, {"current_image_id": "img-1", "telemetry_enabled": False,
                    "telemetry_observation": _obs(sample_seq=2)})
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["valid"] is False

    def test_unassigned_device_withdraws(self):
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved="img-1"), table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs()})
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is True
        # now the policy has no assignment -> withdraw
        cat2 = _cat(store=_Store(approved=None), table=table)
        cat2.route_post("/v1/devices/d1/heartbeat",
                        json.dumps({"telemetry_observation":
                                    {"v": 2, "obs_state": "not_active",
                                     "observed_at": 1.0}}).encode(),
                        "10.0.0.9")
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is False

    def test_unassigned_observed_old_image_withdraws_not_stale(self):
        # A prior good live observation exists; the server policy then loses
        # the assignment (approved=None) and the device still ships a v2
        # `observed` envelope carrying its OLD image_id. The image mismatch
        # must NOT bypass the policy-driven withdrawal: the heartbeat stays
        # 200, the live value is withdrawn as not_active (not left stale), and
        # the malformed-but-policy-driven case is NOT counted as a reject.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved="img-1"), table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs()})
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is True

        cat2 = _cat(store=_Store(approved=None), table=table)
        status, _ctype, _raw = cat2.route_post(
            "/v1/devices/d1/heartbeat",
            json.dumps({"current_image_id": "img-1",
                        "telemetry_observation": _obs(sample_seq=2)}).encode(),
            "10.0.0.9")
        assert status == 200
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is False
        assert table.snapshot(1.0)["samples"]["d1"]["obs_state"] == "not_active"
        # policy-driven withdrawal is not a malformed-sample reject
        assert table.snapshot(1.0)["counters"]["samples_rejected_total"] == 0

    def test_global_pause_observed_old_image_withdraws_not_reject(self):
        # Same withdrawal precedence for the global stream pause: a paused
        # stream withdraws even when the observed envelope would otherwise be
        # rejected on image mismatch, and it does not increment rejects.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved="img-1"), table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs()})
        settings_path = "/nonexistent"
        # simulate pause via a paused StreamSettings
        import tempfile
        import os as _os
        fd, p = tempfile.mkstemp()
        _os.close(fd)
        live_samples.write_settings(p, 1, True)   # paused
        cat2 = _cat(store=_Store(approved="img-1"), table=table,
                    settings=live_samples.StreamSettings(p))
        status, _ctype, _raw = cat2.route_post(
            "/v1/devices/d1/heartbeat",
            json.dumps({"current_image_id": "img-1",
                        "telemetry_observation": _obs(sample_seq=2)}).encode(),
            "10.0.0.9")
        _os.unlink(p)
        assert status == 200
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is False
        assert table.snapshot(1.0)["counters"]["samples_rejected_total"] == 0

    def test_malformed_observed_while_assigned_still_rejects(self):
        # When the device IS still assigned (no policy-driven withdrawal), a
        # genuinely malformed observed envelope still rejects-and-counts and
        # leaves the prior good value in place.
        table = live_samples.LiveTable()
        cat = _cat(store=_Store(approved="img-1"), table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(sample_seq=5)})
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(obs_state="running")})
        assert table.size() == 1
        assert table.snapshot(1.0)["samples"]["d1"]["sample_seq"] == 5
        assert table.snapshot(1.0)["counters"]["samples_rejected_total"] == 1

    def test_v1_sample_and_v2_envelope_coexist_v2_wins(self):
        # a v2 agent sends telemetry_observation; a legacy sample is ignored
        # when the v2 envelope is present (v2 supersedes v1 on v2 agents).
        table = live_samples.LiveTable()
        cat = _cat(table=table)
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(),
                    "sample": {"v": 1, "image_id": "img-1",
                               "phase": "downloading", "done_bytes": 1,
                               "down_bps": 1, "up_bps": 1, "peers": 1,
                               "tier": "good"}})
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["schema"] == "v2"


class TestWithdrawalReasonIsPreserved:
    """A policy-driven withdrawal must record WHY it withdrew (spec §3A
    obs_state fidelity). The agent genuinely emits `disabled` when its master
    toggle is off and `paused` when streaming is off/paused, but the server's
    tele_off short-circuit used to flatten every cause to `not_active`, so those
    two states could never appear in live-samples.json or /api/swarm at all.
    The reason is derived from the SERVER's own flags, never from the device's
    claimed obs_state."""

    def _seed(self, table):
        cat = _cat(table=table)
        _post(cat, {"current_image_id": "img-1", "telemetry_observation": _obs()})
        assert table.snapshot(1.0)["samples"]["d1"]["valid"] is True

    def test_master_toggle_off_records_disabled(self):
        table = live_samples.LiveTable()
        self._seed(table)
        _post(_cat(table=table),
              {"current_image_id": "img-1", "telemetry_enabled": False,
               "telemetry_observation": _obs(sample_seq=2)})
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["obs_state"] == "disabled"
        assert ent["valid"] is False

    def test_stream_toggle_off_records_paused(self):
        table = live_samples.LiveTable()
        self._seed(table)
        _post(_cat(table=table),
              {"current_image_id": "img-1", "telemetry_stream_enabled": False,
               "telemetry_observation": _obs(sample_seq=2)})
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["obs_state"] == "paused"
        assert ent["valid"] is False

    def test_global_stream_pause_records_paused(self, tmp_path):
        p = str(tmp_path / "telemetry-settings.json")
        live_samples.write_settings(p, 1, True)
        table = live_samples.LiveTable()
        cat0 = _cat(table=table)
        _post(cat0, {"current_image_id": "img-1", "telemetry_observation": _obs()})
        cat = _cat(table=table, settings=live_samples.StreamSettings(p))
        _post(cat, {"current_image_id": "img-1",
                    "telemetry_observation": _obs(sample_seq=2)})
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["obs_state"] == "paused"
        assert ent["valid"] is False

    def test_master_toggle_outranks_stream_toggle(self):
        """Mirrors the agent's own ladder: master beats stream beats assignment."""
        table = live_samples.LiveTable()
        self._seed(table)
        _post(_cat(table=table),
              {"current_image_id": "img-1", "telemetry_enabled": False,
               "telemetry_stream_enabled": False,
               "telemetry_observation": _obs(sample_seq=2)})
        assert table.snapshot(1.0)["samples"]["d1"]["obs_state"] == "disabled"

    def test_unassigned_still_records_not_active(self):
        """Regression guard: assignment loss keeps its original label."""
        table = live_samples.LiveTable()
        self._seed(table)
        cat = _cat(store=_Store(approved=None), table=table)
        cat.route_post("/v1/devices/d1/heartbeat",
                       json.dumps({"telemetry_observation":
                                   {"v": 2, "obs_state": "not_active",
                                    "observed_at": 1.0}}).encode(),
                       "10.0.0.9")
        ent = table.snapshot(1.0)["samples"]["d1"]
        assert ent["obs_state"] == "not_active"
        assert ent["valid"] is False

    def test_withdrawal_reason_is_not_taken_from_the_device(self):
        """The device claiming `observed` while the server says the master
        toggle is off must still be recorded as `disabled`, not `observed`."""
        table = live_samples.LiveTable()
        self._seed(table)
        _post(_cat(table=table),
              {"current_image_id": "img-1", "telemetry_enabled": False,
               "telemetry_observation": _obs(sample_seq=2, obs_state="observed")})
        assert table.snapshot(1.0)["samples"]["d1"]["obs_state"] == "disabled"
