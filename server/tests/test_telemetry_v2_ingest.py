# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Task 20: v2 telemetry ingest — the `telemetry_observation` live envelope
sanitizer, the v2 terminal-report sanitizer, and the canonical LiveTable
observation/withdrawal/reorder/validity model (spec §3/§4/§10.1/§10.2).

Exact enums/types/bounds, 8192-byte whole-envelope reject, peer truncation
(not reject), reject-leaves-good-data, receipt-based validity, retention math,
observed-only refresh, withdrawal states, out-of-order drop, and v2 report
dedupe by report_id."""

import pytest

import catalog
import live_samples

TID = "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"
TID2 = "aa0a9c1d8e2b4a6f9017c3d5e7b1a2c4"


def _obs(**over):
    env = {
        "v": 2,
        "obs_state": "observed",
        "observed_at": 1755743100.12,
        "transfer_id": TID,
        "image_id": "img-1",
        "sample_seq": 42,
        "aria_session_id": "b1d9c0a2f4e6",
        "sampling_class": "good",
        "aria": {"status": "active",
                 "completed_content_bytes": 734003200,
                 "total_content_bytes": 1288490188,
                 "receive_bps": 11534336, "send_bps": 262144,
                 "connections": 5},
        "peer_connections": [
            {"ip": "100.92.100.14", "send_bps": 131072, "receive_bps": 0}],
    }
    env.update(over)
    return env


# --- v2 observation sanitizer ---------------------------------------------

class TestSanitizeObservation:
    def test_observed_passes_and_whitelists(self):
        clean, trunc = live_samples.sanitize_observation(
            dict(_obs(), extra="dropme"), "img-1", 32)
        assert trunc is False
        assert clean["v"] == 2 and clean["obs_state"] == "observed"
        assert clean["schema"] == "v2"
        assert "extra" not in clean
        assert clean["transfer_id"] == TID
        assert clean["sample_seq"] == 42
        assert clean["sampling_class"] == "good"
        assert clean["aria"]["connections"] == 5
        assert clean["peer_connections"] == [
            {"ip": "100.92.100.14", "send_bps": 131072, "receive_bps": 0}]

    def test_state_only_paused_has_no_transfer_fields(self):
        env = {"v": 2, "obs_state": "paused", "observed_at": 1.0,
               "transfer_id": TID, "image_id": "img-1"}
        clean, trunc = live_samples.sanitize_observation(env, "img-1", 32)
        assert clean["obs_state"] == "paused"
        assert "aria" not in clean and "peer_connections" not in clean
        assert "sampling_class" not in clean and "sample_seq" not in clean

    def test_not_active_needs_no_transfer_id_or_image(self):
        env = {"v": 2, "obs_state": "not_active", "observed_at": 1.0}
        clean, _ = live_samples.sanitize_observation(env, None, 32)
        assert clean["obs_state"] == "not_active"
        assert "transfer_id" not in clean and "image_id" not in clean

    def test_rpc_unavailable_state_only(self):
        env = {"v": 2, "obs_state": "rpc_unavailable", "observed_at": 1.0,
               "transfer_id": TID, "image_id": "img-1"}
        clean, _ = live_samples.sanitize_observation(env, "img-1", 32)
        assert clean["obs_state"] == "rpc_unavailable"
        assert "aria" not in clean

    def test_rejects(self):
        bad = [
            dict(_obs(), v=1),                          # wrong version
            dict(_obs(), obs_state="running"),          # bad enum
            dict(_obs(), image_id="../evil"),           # bad image chars
            _obs(),                                      # policy mismatch below
            dict(_obs(), transfer_id="ZZZ"),            # bad hex id
            dict(_obs(), sample_seq=-1),               # negative seq
            dict(_obs(), sampling_class="bad"),        # bad sampling class
        ]
        # first four use approved=img-1, then a policy-mismatch case:
        for env in bad[:3]:
            with pytest.raises(ValueError):
                live_samples.sanitize_observation(env, "img-1", 32)
        with pytest.raises(ValueError):        # policy mismatch
            live_samples.sanitize_observation(_obs(), "other-image", 32)
        for env in bad[4:]:
            with pytest.raises(ValueError):
                live_samples.sanitize_observation(env, "img-1", 32)

    def test_observed_missing_required_rejected(self):
        for missing in ("sample_seq", "sampling_class"):
            env = _obs()
            del env[missing]
            with pytest.raises(ValueError):
                live_samples.sanitize_observation(env, "img-1", 32)

    def test_aria_forbidden_when_not_observed(self):
        env = {"v": 2, "obs_state": "paused", "observed_at": 1.0,
               "transfer_id": TID, "image_id": "img-1",
               "aria": {"status": "active"}}
        with pytest.raises(ValueError):
            live_samples.sanitize_observation(env, "img-1", 32)

    def test_peer_connections_forbidden_when_not_observed(self):
        env = {"v": 2, "obs_state": "not_due", "observed_at": 1.0,
               "transfer_id": TID, "image_id": "img-1",
               "peer_connections": [{"ip": "1.2.3.4"}]}
        with pytest.raises(ValueError):
            live_samples.sanitize_observation(env, "img-1", 32)

    def test_bad_aria_status_rejected(self):
        with pytest.raises(ValueError):
            live_samples.sanitize_observation(
                dict(_obs(), aria=dict(_obs()["aria"], status="frobnicate")),
                "img-1", 32)

    def test_numeric_bounds(self):
        for field, over in (
                ("completed_content_bytes", 2 ** 53 + 1),
                ("total_content_bytes", 2 ** 53 + 1),
                ("receive_bps", 10 ** 12 + 1),
                ("send_bps", 10 ** 12 + 1),
                ("connections", 1025)):
            env = _obs()
            env["aria"][field] = over
            with pytest.raises(ValueError):
                live_samples.sanitize_observation(env, "img-1", 32)

    def test_oversize_envelope_rejected(self):
        # A whole envelope over 8192 JSON bytes is rejected, never partial.
        big = _obs()
        big["peer_connections"] = [
            {"ip": "100.92.100.%d" % (i % 250),
             "send_bps": 1, "receive_bps": 2,
             "peer_client_name": "x" * 60} for i in range(400)]
        with pytest.raises(ValueError):
            live_samples.sanitize_observation(big, "img-1", 999)

    def test_peer_rows_truncated_not_rejected(self):
        # configured max 8 -> LIVE_PEER_ROWS_MAX = min(8, 32) = 8; extra rows
        # truncate to the prefix and set the stored flag, not reject.
        env = _obs()
        env["peer_connections"] = [
            {"ip": "10.0.0.%d" % i, "send_bps": 0, "receive_bps": 0}
            for i in range(20)]
        clean, trunc = live_samples.sanitize_observation(env, "img-1", 8)
        assert trunc is True
        assert clean["peer_connections_truncated"] is True
        assert len(clean["peer_connections"]) == 8
        assert clean["peer_connections"][0]["ip"] == "10.0.0.0"

    def test_peer_rates_are_optional_and_not_invented_as_zero(self):
        env = _obs(peer_connections=[{"ip": "10.0.0.1", "progress": 50.0}])
        clean, _ = live_samples.sanitize_observation(env, "img-1", 32)
        assert clean["peer_connections"] == [{"ip": "10.0.0.1", "progress": 50.0}]

    def test_peer_cap_hard_ceiling_32(self):
        # configured max 999 -> capped at 32.
        env = _obs()
        env["peer_connections"] = [
            {"ip": "10.0.0.%d" % (i % 250), "send_bps": 0, "receive_bps": 0}
            for i in range(50)]
        clean, trunc = live_samples.sanitize_observation(env, "img-1", 999)
        assert len(clean["peer_connections"]) == 32
        assert trunc is True


# --- LiveTable canonical observation model ---------------------------------

class TestLiveTableObservation:
    def test_observed_sets_valid_value(self):
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        snap = t.snapshot(1000.0)
        ent = snap["samples"]["d1"]
        assert ent["received_at"] == 1000.0
        assert ent["obs_state"] == "observed"
        assert ent["valid"] is True

    def test_validity_fixed_120s_receipt(self):
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        assert t.snapshot(1000.0 + 119)["samples"]["d1"]["valid"] is True
        assert t.snapshot(1000.0 + 121)["samples"]["d1"]["valid"] is False

    def test_retention_exact_good_tier(self):
        # good: TIER_TICKS=1, stream_every=1 -> max(1,1)*60*3 = 180
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        assert "d1" in t.snapshot(1000.0 + 179)["samples"]
        assert "d1" not in t.snapshot(1000.0 + 181)["samples"]

    def test_retention_capped_at_900(self):
        # constrained: TIER_TICKS=4, stream_every=20 -> max(4,20)*60*3 = 3600
        # capped at 900.
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(
            dict(_obs(), sampling_class="constrained"), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=20)
        assert "d1" in t.snapshot(1000.0 + 899)["samples"]
        assert "d1" not in t.snapshot(1000.0 + 901)["samples"]

    def test_not_due_does_not_extend_validity(self):
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        nd, _ = live_samples.sanitize_observation(
            {"v": 2, "obs_state": "not_due", "observed_at": 1.0,
             "transfer_id": TID, "image_id": "img-1"}, "img-1", 32)
        t.observe("d1", nd, now=1100.0, stream_every=1)
        # validity still keys off the last OBSERVED receipt (1000), so at 1121
        # (>1000+120) it is stale even though not_due arrived at 1100.
        assert t.snapshot(1121.0)["samples"]["d1"]["valid"] is False
        assert t.snapshot(1121.0)["samples"]["d1"]["obs_state"] == "not_due"

    def test_paused_withdraws_immediately(self):
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        p, _ = live_samples.sanitize_observation(
            {"v": 2, "obs_state": "paused", "observed_at": 1.0,
             "transfer_id": TID, "image_id": "img-1"}, "img-1", 32)
        t.observe("d1", p, now=1001.0, stream_every=1)
        ent = t.snapshot(1001.0)["samples"]["d1"]
        assert ent["valid"] is False
        assert "aria" not in ent

    def test_rpc_unavailable_marks_unavailable_no_rates(self):
        t = live_samples.LiveTable()
        clean, _ = live_samples.sanitize_observation(_obs(), "img-1", 32)
        t.observe("d1", clean, now=1000.0, stream_every=1)
        r, _ = live_samples.sanitize_observation(
            {"v": 2, "obs_state": "rpc_unavailable", "observed_at": 1.0,
             "transfer_id": TID, "image_id": "img-1"}, "img-1", 32)
        t.observe("d1", r, now=1001.0, stream_every=1)
        ent = t.snapshot(1001.0)["samples"]["d1"]
        assert ent["obs_state"] == "rpc_unavailable"
        assert ent["valid"] is False
        assert "aria" not in ent

    def test_out_of_order_seq_cannot_replace(self):
        t = live_samples.LiveTable()
        newer, _ = live_samples.sanitize_observation(
            dict(_obs(), sample_seq=42), "img-1", 32)
        t.observe("d1", newer, now=1000.0, stream_every=1)
        older, _ = live_samples.sanitize_observation(
            dict(_obs(), sample_seq=41,
                 aria=dict(_obs()["aria"], connections=99)), "img-1", 32)
        assert t.observe("d1", older, now=1001.0, stream_every=1) is False
        assert t.snapshot(1001.0)["samples"]["d1"]["aria"]["connections"] == 5

    def test_equal_seq_same_transfer_cannot_replace(self):
        t = live_samples.LiveTable()
        first, _ = live_samples.sanitize_observation(
            dict(_obs(), sample_seq=42), "img-1", 32)
        t.observe("d1", first, now=1000.0, stream_every=1)
        dup, _ = live_samples.sanitize_observation(
            dict(_obs(), sample_seq=42,
                 aria=dict(_obs()["aria"], connections=99)), "img-1", 32)
        assert t.observe("d1", dup, now=1001.0, stream_every=1) is False
        assert t.snapshot(1001.0)["samples"]["d1"]["aria"]["connections"] == 5

    def test_new_transfer_resets_seq_gate(self):
        t = live_samples.LiveTable()
        first, _ = live_samples.sanitize_observation(
            dict(_obs(), transfer_id=TID, sample_seq=99), "img-1", 32)
        t.observe("d1", first, now=1000.0, stream_every=1)
        # a different transfer with a low seq is legitimately newer
        nxt, _ = live_samples.sanitize_observation(
            dict(_obs(), transfer_id=TID2, sample_seq=1), "img-1", 32)
        assert t.observe("d1", nxt, now=1001.0, stream_every=1) is True
        assert t.snapshot(1001.0)["samples"]["d1"]["transfer_id"] == TID2


# --- v1 rollout mapping ----------------------------------------------------

V1_SAMPLE = {"v": 1, "image_id": "img-1", "phase": "downloading",
             "done_bytes": 100, "down_bps": 10, "up_bps": 5, "peers": 3,
             "tier": "good"}


class TestV1Rollout:
    def test_v1_sanitizes_as_schema_v1(self):
        clean = live_samples.sanitize_sample(dict(V1_SAMPLE), "img-1")
        assert clean["schema"] == "v1"
        assert clean["v"] == 1
        # v1 fields never reinterpreted as v2
        assert "transfer_id" not in clean and "sample_seq" not in clean

    def test_v1_validity_by_receipt_120(self):
        t = live_samples.LiveTable()
        clean = live_samples.sanitize_sample(dict(V1_SAMPLE), "img-1")
        t.observe("d1", clean, now=1000.0, stream_every=1)
        assert t.snapshot(1000.0 + 119)["samples"]["d1"]["valid"] is True
        assert t.snapshot(1000.0 + 121)["samples"]["d1"]["valid"] is False

    def test_v1_no_reorder_semantics(self):
        # v1 has no sample_seq: a later v1 always replaces (no drop).
        t = live_samples.LiveTable()
        a = live_samples.sanitize_sample(dict(V1_SAMPLE, peers=3), "img-1")
        t.observe("d1", a, now=1000.0, stream_every=1)
        b = live_samples.sanitize_sample(dict(V1_SAMPLE, peers=9), "img-1")
        assert t.observe("d1", b, now=1001.0, stream_every=1) is True
        assert t.snapshot(1001.0)["samples"]["d1"]["peers"] == 9


# --- v2 terminal report sanitizer + dedupe ---------------------------------

def _v2_report(**over):
    rep = {"v": 2, "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
           "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
           "report_request_id": None, "report_created_at": 1.0,
           "image_id": "img1", "event": "staging-complete",
           "window": {"start": 1.0, "end": 2.0, "complete": True},
           "content": {"completed_content_bytes": 10,
                       "total_content_bytes": 10},
           "content_sha256": {"state": "verified", "algo": "sha256"},
           "ios_copy_verify": {"state": "ok"},
           "sampling": {"sampling_class": "good", "catalog_rtt_ms_median": 1,
                        "catalog_rtt_samples": 1, "heartbeat_fail_streak": 0,
                        "report_fail_streak": 0},
           "stage_state": "ready", "peers": [], "peers_total": 0,
           "peers_truncated": False, "peers_saturated": False,
           "agent": {"version": "x", "runtime_mode": "guestshell"}}
    rep.update(over)
    return rep


class TestV2ReportSanitizer:
    def test_valid_v2_report(self):
        out = catalog._sanitize_report(_v2_report())
        assert out["schema"] == "v2"
        assert out["report_id"] == "7c1f0b9a2d3e4f5061728394a5b6c7d8"
        assert out["content_sha256"]["state"] == "verified"

    def test_rejects_bad_report_id(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2_report(report_id="ZZZ"))

    def test_rejects_bad_content_sha256_state(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(
                _v2_report(content_sha256={"state": "bogus"}))

    def test_rejects_bad_ios_copy_verify_state(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(
                _v2_report(ios_copy_verify={"state": "reboot"}))

    def test_rejects_bad_stage_state(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2_report(stage_state="installing"))

    def test_rejects_bad_event(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2_report(event="install-now"))

    def test_content_bytes_bound(self):
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2_report(
                content={"completed_content_bytes": 2 ** 53 + 1,
                         "total_content_bytes": 10}))

    def test_peer_rows_capped(self):
        rows = [{"ip": "10.0.0.%d" % i, "first_observed": 1.0,
                 "last_observed": 2.0, "observations": 1} for i in range(200)]
        out = catalog._sanitize_report(_v2_report(peers=rows, peers_total=200))
        assert len(out["peers"]) == 64

    def test_report_request_id_shape(self):
        # a bad-shaped request id on a pull report is rejected
        with pytest.raises(ValueError):
            catalog._sanitize_report(
                _v2_report(event="pull", report_request_id="NOPE"))
        # a valid 32-hex passes
        rid = "a" * 32
        out = catalog._sanitize_report(
            _v2_report(event="pull", report_request_id=rid))
        assert out["report_request_id"] == rid

    def test_oversize_stored_report_rejected(self):
        # A body whose STORED form exceeds _REPORT_STORE_MAX (16 KiB) is
        # rejected even though the wire transport cap is larger. The agent
        # dict is preserved verbatim (capped strings, uncapped key count).
        agent = {"version": "2026.08.20", "runtime_mode": "guestshell"}
        for i in range(400):
            agent["k%04d" % i] = "x" * 120
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2_report(agent=agent))


class TestV2ReportDedupe:
    def test_duplicate_report_id_is_noop(self, tmp_path):
        s = catalog.CatalogStore(str(tmp_path))
        s.record_telemetry("dev-1", catalog._sanitize_report(_v2_report()))
        s.record_telemetry("dev-1", catalog._sanitize_report(_v2_report()))
        assert len(s.get_telemetry("dev-1")) == 1

    def test_distinct_report_ids_both_stored(self, tmp_path):
        s = catalog.CatalogStore(str(tmp_path))
        s.record_telemetry("dev-1", catalog._sanitize_report(_v2_report()))
        s.record_telemetry("dev-1", catalog._sanitize_report(
            _v2_report(report_id="b" * 32)))
        assert len(s.get_telemetry("dev-1")) == 2

    def test_v2_stamps_received_at(self, tmp_path):
        s = catalog.CatalogStore(str(tmp_path))
        s.record_telemetry("dev-1", catalog._sanitize_report(_v2_report()))
        assert "received_at" in s.get_telemetry("dev-1")[0]


class TestV2DuplicateClearsInterruptedPull:
    def test_dedupe_retry_still_clears_matching_pull(self, tmp_path):
        # First store succeeded but the match-gated clear was interrupted
        # (crash between the ring write and clear_report_request). A duplicate
        # v2 report with the same report_id must be a storage no-op AND still
        # match-clear the still-pending pull directive.
        s = catalog.CatalogStore(str(tmp_path))
        now = 1000.0
        s.request_report("dev-1", now)
        rrid = s.pending_request("dev-1", now)["request_id"]
        rep = catalog._sanitize_report(
            _v2_report(event="pull", report_request_id=rrid))
        # first delivery stores the report...
        s.record_telemetry("dev-1", rep)
        assert len(s.get_telemetry("dev-1")) == 1
        # ...simulate the clear having been interrupted: re-arm the SAME pull
        s.request_report("dev-1", now)
        # but the retry must carry the ORIGINAL request id it echoed
        # (identical report), and the currently pending request differs, so a
        # mismatched id must not clear a newer request.
        s.record_telemetry("dev-1", rep)
        assert len(s.get_telemetry("dev-1")) == 1     # dedupe: still one
        assert s.pending_request("dev-1", now) is not None  # newer request kept

    def test_dedupe_retry_clears_same_still_pending_pull(self, tmp_path):
        # The realistic interrupted-clear case: the pull is STILL the same
        # request the report echoes. A dedupe retry must clear it.
        s = catalog.CatalogStore(str(tmp_path))
        now = 1000.0
        s.request_report("dev-1", now)
        rrid = s.pending_request("dev-1", now)["request_id"]
        rep = catalog._sanitize_report(
            _v2_report(event="pull", report_request_id=rrid))
        s.record_telemetry("dev-1", rep)
        # pretend the clear was interrupted: forcibly re-add the same directive
        import json as _json
        with open(s.pull_path, "w") as f:
            _json.dump({"dev-1": {"request_id": rrid, "requested_at": now,
                                  "expires_at": now + s.PULL_TTL}}, f)
        assert s.pending_request("dev-1", now) is not None
        # duplicate delivery: storage no-op, but the pending pull it matches
        # must now be cleared.
        s.record_telemetry("dev-1", rep)
        assert len(s.get_telemetry("dev-1")) == 1
        assert s.pending_request("dev-1", now) is None


class TestV2SeenReportLedger:
    """Durable bounded per-device seen-report-id ledger (spec §4/§8 stable
    report event ids / idempotence): a v2 retry after the report has been
    evicted from the TELEMETRY_RING must still be a no-op, without unbounded
    state. Bounds are deterministic (SEEN_REPORT_IDS per device) and the
    ledger is purged with the device."""

    def _store_n(self, s, device_id, n, start=0):
        for i in range(start, start + n):
            s.record_telemetry(device_id, catalog._sanitize_report(
                _v2_report(report_id="%032x" % i,
                           transfer_id="%032x" % (0xabc0000 + i))))

    def test_retry_after_ring_eviction_is_noop(self, tmp_path):
        s = catalog.CatalogStore(str(tmp_path))
        # store more than the ring bound (5) so the first ids are evicted
        self._store_n(s, "dev-1", 8)
        assert len(s.get_telemetry("dev-1")) == catalog.CatalogStore.TELEMETRY_RING
        # report_id 0 is long gone from the ring; a retry must still be a no-op
        before = list(s.get_telemetry("dev-1"))
        s.record_telemetry("dev-1", catalog._sanitize_report(
            _v2_report(report_id="%032x" % 0,
                       transfer_id="%032x" % 0xabc0000)))
        after = s.get_telemetry("dev-1")
        assert after == before          # no re-append after ring eviction

    def test_ledger_persists_across_restart(self, tmp_path):
        s = catalog.CatalogStore(str(tmp_path))
        self._store_n(s, "dev-1", 8)
        # fresh store object over the same state dir (process restart)
        s2 = catalog.CatalogStore(str(tmp_path))
        before = list(s2.get_telemetry("dev-1"))
        s2.record_telemetry("dev-1", catalog._sanitize_report(
            _v2_report(report_id="%032x" % 1,
                       transfer_id="%032x" % (0xabc0000 + 1))))
        assert s2.get_telemetry("dev-1") == before   # still deduped post-restart

    def test_ledger_bounded_per_device(self, tmp_path):
        import json as _json
        s = catalog.CatalogStore(str(tmp_path))
        cap = catalog.CatalogStore.SEEN_REPORT_IDS
        self._store_n(s, "dev-1", cap + 20)
        with open(s.report_ledger_path) as f:
            led = _json.load(f)
        assert len(led["dev-1"]) == cap          # deterministic bound
        # the newest ids are retained; the oldest were purged
        assert ("%032x" % (cap + 20 - 1)) in led["dev-1"]
        assert ("%032x" % 0) not in led["dev-1"]

    def test_purge_device_clears_ledger(self, tmp_path):
        import json as _json
        s = catalog.CatalogStore(str(tmp_path))
        self._store_n(s, "dev-1", 3)
        s.purge_device("dev-1")
        with open(s.report_ledger_path) as f:
            led = _json.load(f)
        assert "dev-1" not in led
