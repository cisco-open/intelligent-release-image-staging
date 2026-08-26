# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Task 20: v1 legacy report `_event_id` stamped at catalog ingest (spec §8/§9).

Every accepted v1 report gets a random stable `_event_id` stamped by the
catalog BEFORE the ring write; it persists in the ring and survives a restart /
reread; OTLP reads it (there is NO telemetry-process writeback API). v2 reports
use their own stored `report_id` and are NOT stamped with `_event_id`."""
import re

import catalog

_HEX = re.compile(r"^[a-f0-9]+$")


def _v1(**over):
    rep = {"ts": 1783000000, "image_id": "img1", "event": "staging-complete",
           "transfer": {"total_bytes": 10, "elapsed_s": 1, "avg_bps": 10,
                        "sha_ok": True, "stage_state": "ready"},
           "link": {"tier": "good", "rtt_ms_median": 1, "rtt_samples": 1,
                    "hb_failures": 0, "trimmed": False},
           "peers": [{"ip": "10.0.0.7"}], "peers_total": 1,
           "agent": {"version": "x", "runtime_mode": "guestshell"}}
    rep.update(over)
    return rep


def _v2(**over):
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


def test_v1_report_stamped_with_event_id(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v1()))
    stored = s.get_telemetry("dev-1")[0]
    assert _HEX.match(stored["_event_id"])
    assert stored["schema"] == "v1"


def test_v1_event_ids_are_distinct_per_report(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v1(ts=1)))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v1(ts=2)))
    ring = s.get_telemetry("dev-1")
    assert ring[0]["_event_id"] != ring[1]["_event_id"]


def test_v1_event_id_survives_restart(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v1()))
    eid = s.get_telemetry("dev-1")[0]["_event_id"]
    # fresh store instance re-reading telemetry.json retains the id verbatim
    s2 = catalog.CatalogStore(str(tmp_path))
    assert s2.get_telemetry("dev-1")[0]["_event_id"] == eid


def test_v1_event_id_stable_on_reread(tmp_path):
    """Rereading must NOT re-stamp / mutate the id (no writeback)."""
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v1()))
    eid1 = catalog.CatalogStore(str(tmp_path)).get_telemetry("dev-1")[0]["_event_id"]
    eid2 = catalog.CatalogStore(str(tmp_path)).get_telemetry("dev-1")[0]["_event_id"]
    assert eid1 == eid2


def test_v2_report_uses_report_id_not_event_id(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", catalog._sanitize_report(_v2()))
    stored = s.get_telemetry("dev-1")[0]
    assert stored["schema"] == "v2"
    assert stored["report_id"] == "7c1f0b9a2d3e4f5061728394a5b6c7d8"
    assert "_event_id" not in stored


def test_no_telemetry_writeback_api():
    """There must be NO mutation/writeback API on the store for OTLP to stamp
    ids after the fact — ids are ingest-stamped only. OTLP reads the ring."""
    assert not hasattr(catalog.CatalogStore, "set_event_id")
    assert not hasattr(catalog.CatalogStore, "stamp_event_id")
    assert not hasattr(catalog.CatalogStore, "update_telemetry")
