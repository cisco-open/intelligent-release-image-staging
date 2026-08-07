# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json

import catalog
import live_samples


class _Store:
    """Minimal CatalogStore stand-in for route_post heartbeat tests."""
    def __init__(self, approved="img-1"):
        self.approved = approved
        self.heartbeats = []

    def record_heartbeat(self, device_id, data):
        self.heartbeats.append((device_id, data))

    def get_policy(self, device_id):
        return {"approved_image_id": self.approved, "install_allowed": False}

    def pending_report(self, device_id, now):
        return False


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
