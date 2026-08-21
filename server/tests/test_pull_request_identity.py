# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Task 20: pull-request identity (spec §2/§10.2b).

request_report stores a random 32-hex request_id; heartbeat echoes both
report_requested:true and report_request_id; clear is MATCH-GATED — only the
matching request_id clears; a stale/mismatched pull cannot clear a newer
request. V2 pull with a matching-shaped id is accepted (even stale) without
clearing when it does not match. V1 arrival (no request_id) preserves the
current bridge behavior. TTL / one-pending preserved."""
import re

import catalog

_HEX32 = re.compile(r"^[a-f0-9]{32}$")


def _v2_report(request_id, **over):
    rep = {
        "v": 2,
        "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
        "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
        "report_request_id": request_id,
        "report_created_at": 1755743200.5,
        "image_id": "img1",
        "event": "pull",
        "window": {"start": 1.0, "end": 2.0, "complete": True},
        "content": {"completed_content_bytes": 10, "total_content_bytes": 10},
        "content_sha256": {"state": "verified", "algo": "sha256"},
        "ios_copy_verify": {"state": "ok"},
        "sampling": {"sampling_class": "good", "catalog_rtt_ms_median": 1,
                     "catalog_rtt_samples": 1, "heartbeat_fail_streak": 0,
                     "report_fail_streak": 0},
        "stage_state": "ready",
        "peers": [], "peers_total": 0, "peers_truncated": False,
        "peers_saturated": False,
        "agent": {"version": "2026.08.20", "runtime_mode": "guestshell"},
    }
    rep.update(over)
    return rep


def test_request_report_stores_random_request_id(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    assert s.request_report("dev-1", 1000.0) is True
    ent = s.pending_request("dev-1", 1001.0)
    assert ent is not None
    rid = ent["request_id"]
    assert _HEX32.match(rid)


def test_request_ids_distinct_across_devices(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    s.request_report("dev-2", 1000.0)
    r1 = s.pending_request("dev-1", 1001.0)["request_id"]
    r2 = s.pending_request("dev-2", 1001.0)["request_id"]
    assert r1 != r2


def test_heartbeat_echoes_report_request_id(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    rid = s.pending_request("dev-1", 1001.0)["request_id"]
    ent = s.pending_report("dev-1", 1001.0)
    assert ent is not None
    assert ent["report_requested"] is True
    assert ent["report_request_id"] == rid


def test_pending_report_none_when_absent(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    assert s.pending_report("dev-1", 1000.0) is None


def test_matching_pull_clears_request(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    rid = s.pending_request("dev-1", 1001.0)["request_id"]
    s.record_telemetry("dev-1", _v2_report(rid))
    assert s.pending_request("dev-1", 1002.0) is None


def test_stale_pull_cannot_clear_newer_request(tmp_path):
    """An old pull report echoing a superseded request_id must NOT clear the
    current pending request — the console re-pull minted a fresh id."""
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    old_rid = s.pending_request("dev-1", 1001.0)["request_id"]
    # expire + re-request -> new request_id
    s.clear_report_request("dev-1")
    s.request_report("dev-1", 2000.0)
    new_rid = s.pending_request("dev-1", 2001.0)["request_id"]
    assert new_rid != old_rid
    # a late report with the OLD id arrives -> must not clear the new request
    s.record_telemetry("dev-1", _v2_report(old_rid))
    still = s.pending_request("dev-1", 2002.0)
    assert still is not None and still["request_id"] == new_rid


def test_v2_pull_accepted_even_stale_without_clearing(tmp_path):
    """A v2 pull with a valid-shaped but mismatched request id is accepted
    (stored in the ring) as a contract, but does not clear the newer request."""
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    rid = s.pending_request("dev-1", 1001.0)["request_id"]
    other = "deadbeef" * 4
    assert other != rid
    s.record_telemetry("dev-1", _v2_report(other))
    assert len(s.get_telemetry("dev-1")) == 1        # accepted into the ring
    assert s.pending_request("dev-1", 1002.0)["request_id"] == rid  # unchanged


def test_ttl_and_one_pending_preserved(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    assert s.request_report("dev-1", 1000.0) is True
    assert s.request_report("dev-1", 1010.0) is False    # one pending
    assert s.pending_report("dev-1", 1000.0 + s.PULL_TTL + 1) is None  # TTL
    assert s.request_report("dev-1", 1000.0 + s.PULL_TTL + 2) is True  # renew


def test_v1_report_clears_pending_bridge(tmp_path):
    """V1 legacy pull report (no request_id) preserves the current bridge:
    an arriving v1 report clears the pending request for that device (old
    agents cannot echo an id, so the report IS the directive's answer)."""
    s = catalog.CatalogStore(str(tmp_path))
    s.request_report("dev-1", 1000.0)
    assert s.pending_request("dev-1", 1001.0) is not None
    v1 = {"ts": 1, "image_id": "img1", "event": "pull",
          "transfer": {}, "link": {}, "peers": [], "peers_total": 0,
          "agent": {"version": "x", "runtime_mode": "guestshell"}}
    s.record_telemetry("dev-1", catalog._sanitize_report(v1))
    assert s.pending_request("dev-1", 1002.0) is None
