# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import threading

import pytest

import live_samples

OK = {"v": 1, "image_id": "img-1", "phase": "downloading",
      "done_bytes": 100, "down_bps": 10, "up_bps": 5, "peers": 3,
      "tier": "good"}


class TestSanitize:
    def test_valid_passes_and_whitelists(self):
        s = live_samples.sanitize_sample(dict(OK, extra="dropme"), "img-1")
        assert s == OK

    def test_rejects(self):
        bad = [
            (dict(OK, v=2), "img-1"),                  # unknown version
            (dict(OK, phase="seeding-only"), "img-1"), # wire enum is 'seeding'
            (dict(OK, tier="bad"), "img-1"),
            (dict(OK, done_bytes=2**53 + 1), "img-1"),
            (dict(OK, down_bps=10**12 + 1), "img-1"),
            (dict(OK, peers=1025), "img-1"),
            (dict(OK, peers=-1), "img-1"),
            (dict(OK, image_id="../evil"), "../evil"),
            (dict(OK), "other-image"),                 # policy mismatch
            (dict(OK), None),                          # no assignment
            ("not-a-dict", "img-1"),
        ]
        for data, approved in bad:
            with pytest.raises(ValueError):
                live_samples.sanitize_sample(data, approved)

    def test_oversize_rejected(self):
        with pytest.raises(ValueError):
            live_samples.sanitize_sample(
                dict(OK, image_id="x" * 2000), "x" * 2000)


class TestLiveTable:
    def test_update_reject_snapshot(self):
        t = live_samples.LiveTable()
        t.update("d1", dict(OK), 1000.0, 1)
        t.reject()
        snap = t.snapshot(1000.0)
        assert snap["counters"]["samples_rejected_total"] == 1
        ent = snap["samples"]["d1"]
        assert ent["received_at"] == 1000.0
        assert ent["effective_interval"] == 60      # good tier, every=1

    def test_ttl_scales_with_tier_and_stream_every(self):
        t = live_samples.LiveTable()
        t.update("good1", dict(OK), 1000.0, 1)                       # ttl 180
        t.update("con4", dict(OK, tier="constrained"), 1000.0, 1)    # ttl 720
        t.update("far", dict(OK), 1000.0, 10)                        # ttl 1800
        assert set(t.snapshot(1170.0)["samples"]) == {"good1", "con4", "far"}
        assert set(t.snapshot(1190.0)["samples"]) == {"con4", "far"}
        assert set(t.snapshot(1730.0)["samples"]) == {"far"}
        assert t.snapshot(2810.0)["samples"] == {}


class TestSettings:
    def test_roundtrip_and_mtime_cache(self, tmp_path):
        p = str(tmp_path / "telemetry-settings.json")
        s = live_samples.StreamSettings(p)
        assert s.read() == (1, False)                # missing file: defaults
        live_samples.write_settings(p, 5, True)
        assert s.read() == (5, True)
        with open(p, "w") as f:                      # garbage -> defaults
            f.write("{nope")
        os.utime(p, (9999999999, 9999999999))
        assert s.read() == (1, False)

    def test_clamping(self, tmp_path):
        p = str(tmp_path / "s.json")
        with open(p, "w") as f:
            json.dump({"stream_every": 999, "stream_pause": "yes"}, f)
        assert live_samples.StreamSettings(p).read() == (1, False)


class TestWriterLoop:
    def test_keeps_fresh_and_final_empty_write(self, tmp_path):
        import time as _time
        path = str(tmp_path / "live-samples.json")
        t = live_samples.LiveTable()
        t.update("d1", dict(OK), _time.time(), 1)    # fresh: writes non-empty
        stop = threading.Event()
        th = threading.Thread(target=live_samples.writer_loop,
                              args=(t, path, 0.05, stop), daemon=True)
        th.start()
        for _ in range(100):
            if os.path.exists(path):
                break
            stop.wait(0.05)
        with open(path) as f:
            assert "d1" in json.load(f)["samples"]
        # age the entry out (stale received_at, far past ttl on the real
        # clock) -> the next pass evicts it and makes ONE final empty write
        t.update("d1", dict(OK), 0.0, 1)
        for _ in range(100):
            with open(path) as f:
                if json.load(f)["samples"] == {}:
                    break
            stop.wait(0.05)
        with open(path) as f:
            assert json.load(f)["samples"] == {}
        stop.set()
        th.join(timeout=2)
