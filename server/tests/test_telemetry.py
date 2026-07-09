# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import json
import os
import threading

import otlp
import telemetry
from peer_registry import PeerRegistry

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))


# --- poll_seeder (aria2 RPC) ---

def _fake_rpc(global_stat, active):
    def rpc(method, _params=None):
        if method == "aria2.getGlobalStat":
            return global_stat
        if method == "aria2.tellActive":
            return active
        raise AssertionError("unexpected method %s" % method)
    return rpc


def test_poll_seeder_maps_global_stat_and_sums_connections():
    rpc = _fake_rpc(
        {"uploadSpeed": "1000", "downloadSpeed": "50", "numActive": "2"},
        [{"connections": "3", "infoHash": "abc", "totalLength": "2048",
          "files": [{"path": "/img/cat9k.bin"}]},
         {"connections": "4", "infoHash": "def", "totalLength": "4096",
          "files": [{"path": "/img/img2.bin"}]}])
    stats, names, totals = telemetry.poll_seeder(rpc)
    assert stats["rpc_up"] is True
    assert stats["upload_speed"] == 1000
    assert stats["download_speed"] == 50
    assert stats["active_torrents"] == 2
    assert stats["connections"] == 7
    assert names["abc"] == "cat9k.bin"
    assert names["def"] == "img2.bin"
    assert totals["abc"] == 2048
    assert totals["def"] == 4096


def test_poll_seeder_rpc_error_reports_down():
    def rpc(method, _params=None):
        raise OSError("no rpc")
    stats, names, totals = telemetry.poll_seeder(rpc)
    assert stats == {"rpc_up": False}
    assert names == {}
    assert totals == {}


def test_poll_seeder_empty_files_list_does_not_raise():
    # aria2 may return files=[] for a metadata-only torrent; poll_seeder must
    # not raise and must simply leave that info_hash out of 'names'.
    rpc = _fake_rpc(
        {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "0", "infoHash": "abc", "totalLength": "0",
          "files": []}])
    stats, names, totals = telemetry.poll_seeder(rpc)
    assert stats["rpc_up"] is True
    assert "abc" not in names


def test_poll_seeder_file_missing_path_key_does_not_raise():
    # aria2 occasionally omits 'path' from a file entry (e.g. multi-file
    # torrents before metadata is fully loaded); poll_seeder must survive.
    rpc = _fake_rpc(
        {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "0", "infoHash": "abc", "totalLength": "0",
          "files": [{}]}])
    stats, names, totals = telemetry.poll_seeder(rpc)
    assert stats["rpc_up"] is True
    assert "abc" not in names


def test_swarm_snapshot_builds_per_peer_progress():
    rpc = _fake_rpc(
        {"uploadSpeed": "10", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "2", "infoHash": "abc", "totalLength": "1000",
          "files": [{"path": "/img/cat9k.bin"}]}])
    reg = PeerRegistry()
    hub = telemetry.Telemetry(reg, rpc=rpc)
    hub.sample()                                   # capture totals + names
    reg.announce("abc", "s1", "10.0.0.1", 6881, left=0)      # seeder
    reg.announce("abc", "l1", "10.0.0.2", 6882, left=500)    # 50% done
    snap = hub.swarm_snapshot()
    img = snap["images"][0]
    assert img["image"] == "cat9k.bin"
    assert img["total_bytes"] == 1000
    by_ip = {p["ip"]: p for p in img["peers"]}
    assert by_ip["10.0.0.1"]["is_seeder"] is True
    assert abs(by_ip["10.0.0.1"]["progress"] - 1.0) < 1e-9
    assert abs(by_ip["10.0.0.2"]["progress"] - 0.5) < 1e-9
    assert snap["seeder"]["connections"] == 2


def test_poll_seeder_peers_maps_server_upload_per_ip():
    def rpc(method, params=None):
        if method == "aria2.tellActive":
            return [{"gid": "g1", "infoHash": "abc", "uploadLength": "12345"}]
        if method == "aria2.getPeers":
            assert params[0] == "g1"
            return [{"ip": "10.0.0.2", "uploadSpeed": "500000"},
                    {"ip": "10.0.0.3", "uploadSpeed": "0"}]
        raise AssertionError(method)
    pu, upload_lengths = telemetry.poll_seeder_peers(rpc)
    assert pu == {"abc": {"10.0.0.2": 500000, "10.0.0.3": 0}}
    assert upload_lengths == {"abc": 12345}


def test_swarm_snapshot_includes_server_upload_and_accumulates_sent():
    # server_sent_bytes is calibrated against aria2's exact per-torrent
    # uploadLength counter, not integrated from the instantaneous rate. The
    # first sighting of a hash only BASELINES the counter; each later sample
    # distributes exactly the counter's delta since the previous one.
    ga = {"uploadSpeed": "500000", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "1", "infoHash": "abc", "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}
    upload_len = {"abc": 0}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":     # poll_seeder asks for files; peers for gid
            keys = params[0] if params else []
            if "files" in keys:
                return active_full
            return [{"gid": "g1", "infoHash": "abc",
                     "uploadLength": str(upload_len["abc"])}]
        if method == "aria2.getPeers":
            return peers.get(params[0], [])
        raise AssertionError(method)

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=10)
    hub.sample()                                   # baseline (attributes nothing)
    upload_len["abc"] = 1000
    hub.sample()                                   # delta = 1000
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=500)
    p = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
         if x["ip"] == "10.0.0.2"][0]
    assert p["server_up_bps"] == 100
    assert p["server_sent_bytes"] == 1000          # calibrated to the exact counter
    upload_len["abc"] = 1800                       # aria2's exact counter advances
    hub.sample()                                   # delta 800, one connected peer
    p2 = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
          if x["ip"] == "10.0.0.2"][0]
    assert p2["server_sent_bytes"] == 1800


def test_swarm_snapshot_server_sent_resets_on_new_download_cycle():
    # "sent by server" must reflect the CURRENT download, not the peer's
    # lifetime. When a finished peer re-downloads (its joined_at advances), the
    # calibrated bytes-sent accumulator resets — otherwise the map would show
    # the sum of every download the peer ever did. The reset logic runs before
    # the calibrated distribution each sample, so it still applies cleanly.
    ga = {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "1", "infoHash": "abc", "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}
    upload_len = {"abc": 0}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return active_full
            return [{"gid": "g1", "infoHash": "abc",
                     "uploadLength": str(upload_len["abc"])}]
        if method == "aria2.getPeers":
            return peers.get(params[0], [])
        raise AssertionError(method)

    def sent(hub, now):
        ps = hub.swarm_snapshot(now=now)["images"][0]["peers"]
        return [x for x in ps if x["ip"] == "10.0.0.2"][0]["server_sent_bytes"]

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=10)
    # cycle 1: downloading; two samples calibrated against aria2's exact
    # counter advancing to 2000 B total (1000 B delta per sample)
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=500, now=1000)
    hub.sample(now=1000)   # baseline (first sighting attributes nothing)
    upload_len["abc"] = 1000
    hub.sample(now=1000)
    upload_len["abc"] = 2000
    hub.sample(now=1000)
    assert sent(hub, 1000) == 2000
    # peer finishes (left=0), then re-downloads later (left>0) -> new cycle
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=0, now=1005)
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=500, now=1010)
    upload_len["abc"] = 3000             # aria2's counter keeps climbing (+1000)
    hub.sample(now=1010)                 # first sample of the new cycle -> reset
    assert sent(hub, 1010) == 1000       # ONLY this cycle's 1000, not 3000


# --- sent-bytes calibration against aria2's exact uploadLength counter ---
# (regression coverage for the rate*interval overcount bug: a per-peer row
# could exceed the torrent's own exact cumulative uploadLength on bursty
# transfers because the old code integrated the noisy instantaneous rate
# instead of calibrating against the exact counter.)

def _calibration_rpc(upload_len, peers_by_gid, connections="1"):
    """A _fake_rpc-style RPC double for calibration tests: single torrent
    'abc'/gid 'g1'. `upload_len` is a mutable {"abc": int} the test can bump
    between samples; `peers_by_gid["g1"]` is the getPeers() list."""
    active_full = [{"connections": connections, "infoHash": "abc",
                    "totalLength": "1000000000",
                    "files": [{"path": "/img/cat9k.bin"}]}]

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return active_full
            return [{"gid": "g1", "infoHash": "abc",
                     "uploadLength": str(upload_len["abc"])}]
        if method == "aria2.getPeers":
            return peers_by_gid.get(params[0], [])
        raise AssertionError(method)
    return rpc


def test_sample_distributes_delta_proportionally_to_peer_speed():
    # Two peers, speeds 3:1 -> a 100MB delta splits 75MB/25MB, summing exactly.
    upload_len = {"abc": 0}
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "300"},
                    {"ip": "10.0.0.3", "uploadSpeed": "100"}]}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=15)
    hub.sample()   # baseline: first sighting of a hash attributes nothing
    upload_len["abc"] = 100 * 1024 * 1024
    hub.sample()
    sent = hub._peer_sent["abc"]
    assert sent["10.0.0.2"] == 75 * 1024 * 1024
    assert sent["10.0.0.3"] == 25 * 1024 * 1024
    assert sent["10.0.0.2"] + sent["10.0.0.3"] == 100 * 1024 * 1024


def test_sample_calibration_prevents_burst_overcount_regression():
    # Regression for the confirmed bug: instantaneous uploadSpeed integrated
    # over the sample interval would have summed to 2x the exact delta on a
    # bursty LAN transfer. The calibrated sampler must store exactly the
    # exact-counter delta, never the (higher) naive rate*interval figure.
    interval = 15
    upload_len = {"abc": 0}
    # A speed high enough that rate*interval alone would double the real delta.
    exact_delta = 50_000_000
    naive_bps = exact_delta // interval           # what old code integrated...
    burst_bps = naive_bps * 2                      # ...at 2x the real rate (burst)
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": str(burst_bps)}]}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=interval)
    hub.sample()   # baseline: first sighting of a hash attributes nothing
    upload_len["abc"] = exact_delta
    hub.sample()
    stored = hub._peer_sent["abc"]["10.0.0.2"]
    assert stored == exact_delta
    assert stored != burst_bps * interval          # would be 2x if uncalibrated


def test_sample_zero_weight_window_splits_evenly():
    # All reported speeds are 0 this sample (e.g. momentarily idle) but the
    # exact counter still advanced -> split the delta evenly, not all-or-nothing.
    upload_len = {"abc": 0}
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "0"},
                    {"ip": "10.0.0.3", "uploadSpeed": "0"}]}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=15)
    hub.sample()   # baseline: first sighting of a hash attributes nothing
    upload_len["abc"] = 100
    hub.sample()
    sent = hub._peer_sent["abc"]
    assert sent["10.0.0.2"] == 50
    assert sent["10.0.0.3"] == 50


def test_sample_no_peer_window_carries_delta_to_next_window():
    # No peers connected this sample (getPeers returns []) but the exact
    # counter advanced -> nothing is dropped; the delta carries forward and is
    # attributed once a peer shows up in a later sample.
    upload_len = {"abc": 0}
    peers = {"g1": []}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=15)
    hub.sample()   # baseline: first sighting of a hash attributes nothing
    upload_len["abc"] = 1000
    hub.sample()
    assert hub._peer_sent.get("abc", {}) == {}     # nothing to attribute to
    assert hub._unattributed["abc"] == 1000         # but nothing lost either

    # a peer connects and the counter advances again -> both the carried and
    # the new delta are attributed together
    peers["g1"] = [{"ip": "10.0.0.2", "uploadSpeed": "100"}]
    upload_len["abc"] = 1500
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 1500  # 1000 carried + 500 new
    assert "abc" not in hub._unattributed or hub._unattributed["abc"] == 0


def test_sample_aria2_restart_rebaselines_without_misattribution():
    # If aria2 restarts, its cumulative uploadLength drops. Unexplained jumps
    # are BASELINED, never distributed: we lose at most one window instead of
    # misattributing post-restart bytes (or, worse, a huge stale counter).
    upload_len = {"abc": 0}
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=15)
    hub.sample()   # baseline: first sighting of a hash attributes nothing
    upload_len["abc"] = 900_000_000
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 900_000_000
    assert hub._last_upload_len["abc"] == 900_000_000

    # aria2 restarts: uploadLength drops way down -> rebaseline, attribute none
    upload_len["abc"] = 200
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 900_000_000
    assert hub._last_upload_len["abc"] == 200

    # deltas flow normally again from the new baseline
    upload_len["abc"] = 700
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 900_000_000 + 500


def test_sample_first_sighting_baselines_historical_upload():
    # Telemetry (re)starting while aria2 has been seeding for days (separate
    # processes in bare-metal deploys): the counter's history is
    # unattributable and must NOT be dumped onto whoever is connected at that
    # moment. Baseline only; nothing distributed.
    upload_len = {"abc": 5_000_000_000}
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=_calibration_rpc(upload_len, peers),
                              interval=15)
    hub.sample()
    assert hub._peer_sent.get("abc", {}).get("10.0.0.2", 0) == 0
    assert hub._last_upload_len["abc"] == 5_000_000_000


def test_sample_multi_hash_deltas_do_not_bleed_across_torrents():
    # Two torrents sampled together must keep independent counters/deltas —
    # a delta computed for one info_hash must never leak into the other's
    # accumulator.
    active_full = [
        {"connections": "1", "infoHash": "abc", "totalLength": "1000",
         "files": [{"path": "/img/a.bin"}]},
        {"connections": "1", "infoHash": "def", "totalLength": "2000",
         "files": [{"path": "/img/b.bin"}]},
    ]
    upload_len = {"abc": 0, "def": 0}
    peers = {
        "ga": [{"ip": "10.0.0.2", "uploadSpeed": "100"}],
        "gb": [{"ip": "10.0.0.9", "uploadSpeed": "50"}],
    }

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "2"}
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return active_full
            return [{"gid": "ga", "infoHash": "abc",
                     "uploadLength": str(upload_len["abc"])},
                    {"gid": "gb", "infoHash": "def",
                     "uploadLength": str(upload_len["def"])}]
        if method == "aria2.getPeers":
            return peers.get(params[0], [])
        raise AssertionError(method)

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=15)
    hub.sample()   # baseline: first sighting of each hash attributes nothing
    upload_len["abc"] = 300
    upload_len["def"] = 5000
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 300
    assert hub._peer_sent["def"]["10.0.0.9"] == 5000
    assert "10.0.0.9" not in hub._peer_sent["abc"]
    assert "10.0.0.2" not in hub._peer_sent["def"]

    # only 'abc' advances this round -> 'def' must not accumulate anything new
    upload_len["abc"] = 900
    hub.sample()
    assert hub._peer_sent["abc"]["10.0.0.2"] == 900
    assert hub._peer_sent["def"]["10.0.0.9"] == 5000    # unchanged


def test_distribute_upload_delta_no_peers_returns_none():
    assert telemetry._distribute_upload_delta(500, {}) is None


def test_metrics_server_serves_swarm_json():
    snap = {"images": [{"image": "x", "info_hash": "abc", "total_bytes": 1000,
                        "peers": [{"ip": "10.9.9.9", "progress": 0.5}],
                        "seeders": 0, "leechers": 1}], "seeder": {}}
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        swarm_provider=lambda: snap)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                       timeout=5)
        c.request("GET", "/swarm")
        r = c.getresponse()
        body = r.read()
        assert r.status == 200
        assert "application/json" in r.getheader("Content-Type")
        assert b"10.9.9.9" in body
    finally:
        srv.shutdown()


def test_metrics_server_serves_swarmmap_html():
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        swarm_provider=lambda: {},
                                        html="<html>SWARM-MAP</html>")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for path in ("/swarmmap", "/"):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", path)
            r = c.getresponse()
            body = r.read()
            assert r.status == 200, path
            assert "text/html" in r.getheader("Content-Type")
            assert b"SWARM-MAP" in body
    finally:
        srv.shutdown()


def test_metrics_server_swarmmap_html_can_be_a_callable():
    # a callable is read per request -> the page can hot-reload from disk
    pages = iter(["<html>ONE</html>", "<html>TWO</html>"])
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        swarm_provider=lambda: {},
                                        html=lambda: next(pages))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        got = []
        for _ in range(2):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", "/swarmmap")
            got.append(c.getresponse().read())
        assert b"ONE" in got[0] and b"TWO" in got[1]   # re-read each request
    finally:
        srv.shutdown()


# --- build_swarm (registry stats + name map -> render rows) ---

def test_build_swarm_uses_name_then_falls_back_to_hash():
    reg_stats = {"abc": {"seeders": 1, "leechers": 0, "peers": 1,
                         "bytes_remaining": 0, "completed": 0}}
    rows = telemetry.build_swarm(reg_stats, {"abc": "cat9k.bin"})
    assert rows[0]["image"] == "cat9k.bin"
    assert rows[0]["info_hash"] == "abc"
    rows2 = telemetry.build_swarm(reg_stats, {})
    assert rows2[0]["image"] == "abc"     # no name known -> hash


# --- Telemetry facade ---

def test_metrics_text_reflects_registry_swarm():
    reg = PeerRegistry()
    hub = telemetry.Telemetry(reg)
    # no now= -> announce at wall-clock time, so metrics_text()'s stats() read
    # (also wall-clock) sees a fresh, non-stale peer
    reg.announce("abc", "p1", "10.0.0.1", 6881, left=0)
    assert 'iris_swarm_seeders{image="abc",info_hash="abc"} 1' in \
        hub.metrics_text()


def test_note_announce_increments_counter():
    hub = telemetry.Telemetry(PeerRegistry())
    hub.note_announce()
    hub.note_announce()
    assert "iris_tracker_announces_total 2" in hub.metrics_text()


def test_on_swarm_event_forwards_to_exporter():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp)
    hub.on_swarm_event({"event": "join", "peer_id": "p1", "ts": 0})
    exp.flush()
    assert b"p1" in sent[0]


def test_sample_updates_seeder_stats_and_flushes_events():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    rpc = _fake_rpc(
        {"uploadSpeed": "1000", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "2", "infoHash": "abc",
          "files": [{"path": "/img/cat9k.bin"}]}])
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp, rpc=rpc)
    hub.on_swarm_event({"event": "join", "peer_id": "p1", "ts": 0})
    hub.sample()
    assert b"p1" in sent[0]      # queued events were flushed
    assert "iris_seeder_upload_bytes_per_second 1000" in hub.metrics_text()


# --- metrics HTTP server ---

def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.read()


def test_metrics_server_serves_provider_text():
    srv = telemetry.make_metrics_server(
        "127.0.0.1", 0, lambda: "iris_tracker_up 1\n")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/metrics")
        assert status == 200
        assert b"iris_tracker_up 1" in body
    finally:
        srv.shutdown()


def test_metrics_server_healthz_ok():
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/healthz")
        assert status == 200
        assert body.strip() == b"ok"
    finally:
        srv.shutdown()


def test_metrics_server_unknown_path_404():
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, _ = _get(srv.server_address[1], "/nope")
        assert status == 404
    finally:
        srv.shutdown()


# --- from_env / metrics_port config parsing ---

def test_from_env_without_otlp_endpoint_has_no_exporter():
    hub = telemetry.from_env({})
    assert hub.exporter is None
    assert hub.registry is not None      # always has a registry to read


def test_from_env_enables_exporter_when_observability_on_and_endpoint_set():
    hub = telemetry.from_env({"IRIS_OBSERVABILITY": "1",
                              "IRIS_OTLP_ENDPOINT": "http://collector:4318"})
    assert hub.exporter is not None
    assert hub.exporter.url == "http://collector:4318/v1/logs"


def test_from_env_otlp_requires_observability_flag():
    # endpoint set but observability OFF -> no external push (default posture)
    assert telemetry.from_env(
        {"IRIS_OTLP_ENDPOINT": "http://collector:4318"}).exporter is None


def test_observability_enabled_default_off_and_truthy_values():
    assert telemetry.observability_enabled({}) is False
    assert telemetry.observability_enabled({"IRIS_OBSERVABILITY": "0"}) is False
    assert telemetry.observability_enabled({"IRIS_OBSERVABILITY": "no"}) is False
    assert telemetry.observability_enabled({"IRIS_OBSERVABILITY": "1"}) is True
    assert telemetry.observability_enabled({"IRIS_OBSERVABILITY": "true"}) is True
    assert telemetry.observability_enabled({"IRIS_OBSERVABILITY": "ON"}) is True


def test_metrics_endpoint_gated_off_but_swarm_map_still_served():
    # provider=None (observability off) -> /metrics 404, but the self-contained
    # swarm server + page remain available.
    srv = telemetry.make_metrics_server("127.0.0.1", 0, None,
                                        swarm_provider=lambda: {"images": []},
                                        html="<html>MAP</html>")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        def code(path):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", path)
            return c.getresponse().status
        assert code("/metrics") == 404
        assert code("/swarm") == 200
        assert code("/swarmmap") == 200
        assert code("/healthz") == 200
    finally:
        srv.shutdown()


def test_from_env_parses_sample_interval():
    assert telemetry.from_env({"IRIS_SAMPLE_INTERVAL": "7"}).interval == 7
    assert telemetry.from_env({}).interval == telemetry.DEFAULT_INTERVAL


def test_metrics_port_default_explicit_and_disabled():
    assert telemetry.metrics_port({}) == 9101
    assert telemetry.metrics_port({"IRIS_METRICS_PORT": "9200"}) == 9200
    assert telemetry.metrics_port({"IRIS_METRICS_PORT": "0"}) is None
    assert telemetry.metrics_port({"IRIS_METRICS_PORT": ""}) is None


def test_swarm_snapshot_joins_device_model_by_swarm_ip():
    # The catalog records a device's model keyed to the heartbeat source IP
    # (== its swarm peer IP); swarm_snapshot must label that peer with the model,
    # and leave peers with no matching record as model=None (never error).
    devices = {"100.92.9.3": {"device_id": "100.92.9.3", "model": "C9300-48UXM",
                               "swarm_ip": "10.0.0.2"}}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    hub._registry.announce("abc", "p2", "10.0.0.9", 6883, left=5, now=0)
    peers = {p["ip"]: p for p in hub.swarm_snapshot(now=0)["images"][0]["peers"]}
    assert peers["10.0.0.2"]["model"] == "C9300-48UXM"
    assert peers["10.0.0.9"]["model"] is None


def test_swarm_snapshot_joins_telemetry_enabled_by_swarm_ip():
    # telemetry_enabled travels the same swarm_ip join as model/device_id (#13
    # final review Important-3): the console drawer branches its "no report
    # yet" text on this, so True/False/None (unknown — absent or a
    # pre-telemetry agent) must all survive the join, not just truthy values.
    devices = {"100.92.9.3": {"device_id": "100.92.9.3",
                              "swarm_ip": "10.0.0.2",
                              "telemetry_enabled": False},
               "100.90.168.99": {"device_id": "100.90.168.99",
                                 "swarm_ip": "10.0.0.5",
                                 "telemetry_enabled": True}}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    hub._registry.announce("abc", "p2", "10.0.0.5", 6883, left=5, now=0)
    hub._registry.announce("abc", "p3", "10.0.0.9", 6884, left=5, now=0)
    peers = {p["ip"]: p for p in hub.swarm_snapshot(now=0)["images"][0]["peers"]}
    assert peers["10.0.0.2"]["telemetry_enabled"] is False
    assert peers["10.0.0.5"]["telemetry_enabled"] is True
    # no matching device record at all -> unknown, not falsely "disabled"
    assert peers["10.0.0.9"]["telemetry_enabled"] is None


def _swarmmap_html():
    """Return the content of swarmmap.html for static analysis."""
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "swarmmap.html")
    with open(path) as f:
        return f.read()


def test_swarmmap_has_escape_helper():
    # The escapeHtml helper must be defined and must cover the five HTML-special
    # characters: & < > " '
    html = _swarmmap_html()
    assert "function escapeHtml" in html or "const escapeHtml" in html or \
           "const esc=" in html or "function esc(" in html, \
        "no escapeHtml / esc helper found in swarmmap.html"


def test_swarmmap_device_fields_not_raw_in_innerhtml():
    # Device-supplied strings (p.ip, p.port, p.model, p._img, im.image,
    # DATA.host) must NOT be interpolated directly into innerHTML — they must
    # be wrapped in the escape helper.  We check two things:
    # (a) raw unescaped patterns that actually appeared in the pre-fix code
    #     are absent, and
    # (b) the device-supplied fields go through escapeHtml() in the current code.
    html = _swarmmap_html()

    # (a) Patterns that existed in the old (unescaped) code must be absent.
    # These are the actual forms that were present before the XSS fix:
    #   p.port appeared as ${p.port||""} or ${p.port||"—"} (unescaped template)
    #   DATA.host appeared as "+DATA.host+" (string-concat into innerHTML)
    # We test the minimal distinguishing substrings — if these literal forms
    # reappear without escapeHtml() wrapping, the fix has regressed.
    forbidden = [
        "${p.ip}",
        "${p.model}",
        "${p._img}",
        "${im.image}",
        # Real pre-fix forms for port and DATA.host:
        '${p.port||""}',        # was inserted raw into tip innerHTML
        '"+DATA.host+"',        # was concatenated raw into innerHTML strings
    ]
    for pat in forbidden:
        assert pat not in html, (
            f"raw device field {pat!r} still interpolated into innerHTML "
            f"in swarmmap.html — XSS not fixed"
        )

    # (b) The escaped forms must be present — p.port and DATA.host must flow
    # through escapeHtml() on every innerHTML path where they appear.
    assert "escapeHtml(p.port" in html, (
        "p.port must be wrapped in escapeHtml() before insertion into innerHTML"
    )
    assert "escapeHtml(DATA.host" in html, (
        "DATA.host must be wrapped in escapeHtml() before insertion into innerHTML"
    )


def test_swarmmap_no_dead_stale_branch():
    # swarm_snapshot never emits a 'stale' field, so the p.stale colour branch
    # and its legend entry are dead. They must be removed.
    html = _swarmmap_html()
    assert "p.stale" not in html, \
        "dead stale peer colour branch still present in swarmmap.html"
    assert "idle / stale" not in html, \
        "dead stale legend entry still present in swarmmap.html"


# ---------------------------------------------------------------------------
# Telemetry (#13): swarm-map console mode — config placeholder, report drawer,
# pull flow, hub sent-bytes table, iframe embed. Same HTML-source guard style
# as the escapeHtml tests above: assert on the file's code shapes, not on a
# rendered DOM.
# ---------------------------------------------------------------------------

def _index_html():
    p = os.path.join(os.path.dirname(_THIS_DIR), "webroot", "index.html")
    with open(p, encoding="utf-8") as f:
        return f.read()


def _app_js():
    p = os.path.join(os.path.dirname(_THIS_DIR), "webroot", "app.js")
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_swarmmap_map_cfg_placeholder_exactly_once():
    html = _swarmmap_html()
    # Task 7's server-side substitution targets this exact line; a second
    # occurrence (or a reworded one) silently breaks console mode.
    assert html.count("window.IRIS_MAP_CFG = null;") == 1
    assert 'const MAP = window.IRIS_MAP_CFG || {swarmUrl: "/swarm", pull: false};' in html
    # the poll must go through the config, never a hardcoded path
    assert "fetch(MAP.swarmUrl" in html
    assert 'fetch("/swarm"' not in html


def test_swarmmap_script_and_style_tags_stay_attribute_free():
    # Task 7 nonces the tags by string-replacing '<script>' / '<style>' —
    # adding attributes to either open tag would silently skip the nonce and
    # the CSP would then block the page.
    html = _swarmmap_html()
    assert html.count("<script>") == 1 and "<script " not in html
    assert html.count("<style>") == 1 and "<style " not in html


def test_swarmmap_csrf_comes_from_session_not_cfg():
    html = _swarmmap_html()
    assert '"/api/session"' in html          # app.js-style bootstrap
    assert "X-CSRF-Token" in html            # header sent on the pull POST
    assert "csrf" not in _swarmmap_html().split("window.IRIS_MAP_CFG = null;")[0], \
        "no csrf material may ride above/inside the injected CFG line"


def test_swarmmap_pull_ui_gated_and_null_device_handled():
    html = _swarmmap_html()
    assert "MAP.pull" in html
    assert "request-report" in html
    assert "Pull fresh data from device" in html
    # a peer with no device_id (no heartbeat join) gets a disabled note, not a
    # broken POST to /api/devices/null/...
    assert "no device identity" in html


def test_swarmmap_pull_arrival_uses_server_clock():
    # The arrived-check must compare the SERVER-stamped received_at (same
    # clock domain as requested_at) — the device-stamped ts is fallback only.
    html = _swarmmap_html()
    body = html.split("function refreshDrawerReport")[1]
    assert "latest.received_at||latest.ts" in body


def test_swarmmap_report_fields_are_escaped():
    html = _swarmmap_html()
    # (a) raw interpolations of the device-supplied fields must not exist. The
    # per-peer row now leads with a resolved `lead` (device_id or the announce
    # ip) plus a joined `sub` detail line — both device-derived, both must be
    # escaped, never interpolated raw.
    for raw in ("${row.ip}", "${lead}", "${sub}", "${rep.event}",
                "${rep.link.tier}", "${h.ip}", "${devName}"):
        assert raw not in html, "unescaped interpolation: " + raw
    # (b) the escaped forms must exist
    for esc in ("escapeHtml(lead)", "escapeHtml(sub)", "escapeHtml(rep.event)",
                "escapeHtml(h.ip)"):
        assert esc in html, "missing escaped interpolation: " + esc


def test_swarmmap_hub_drawer_has_sent_bytes_table():
    html = _swarmmap_html()
    assert "server_sent_bytes" in html.split("function openHubDrawer")[1], \
        "hub drawer does not render the per-device sent-bytes table"


# ---------------------------------------------------------------------------
# Telemetry (#18): swarm-map leads with the CONSOLE device IP (device_id),
# richer per-peer drawer table (received + avg speed), wider drawer panel.
# Same HTML-source guard style as the escapeHtml tests above.
# ---------------------------------------------------------------------------

def test_swarmmap_has_device_id_preferred_label_helper():
    # A single helper decides the leading identity: the console device IP
    # (device_id) when known, else the raw announce/guest ip. It must be
    # referenced by the ring node label (render), the tooltip (showTip) and the
    # drawer title (openDrawer) so all three read one consistent identity.
    html = _swarmmap_html()
    assert ("function peerLabel(p)" in html or "peerLabel=" in html), \
        "no peerLabel(device_id||ip) helper found in swarmmap.html"
    # the helper must prefer device_id, falling back to ip
    assert "p.device_id||p.ip" in html, \
        "peerLabel must prefer device_id over ip, falling back to ip"
    for fn in ("function render(", "function showTip(", "function openDrawer("):
        body = html.split(fn)[1].split("\nfunction ")[0]
        assert "peerLabel(p)" in body, \
            fn + " must lead the peer identity with peerLabel(p)"


def test_swarmmap_shows_announce_ip_as_secondary_detail():
    # Operators still need the raw announce/guest ip — it must appear as a
    # secondary detail (only when it differs from the leading console ip), via a
    # dedicated helper referenced by the node/tooltip/drawer.
    html = _swarmmap_html()
    assert "function peerAnnounceSub(p)" in html, \
        "no peerAnnounceSub helper for the secondary announce-ip detail"
    # the sub must be escaped everywhere it lands in innerHTML
    assert "escapeHtml(asub)" in html, \
        "the announce-ip sub-detail must be escaped before innerHTML insertion"


def test_swarmmap_per_peer_table_received_and_avg_speed():
    # The drawer's per-peer report table is the "who served me how much + how
    # fast" view: received bytes via fmtBytes(rx_bytes) and average speed via
    # fmtBps(avg_bps), with escaped peer identity. tx no longer has its own
    # column (shown inline only when seeding).
    html = _swarmmap_html()
    body = html.split("function reportHtml")[1].split("\nfunction ")[0]
    # header carries ↓/↑ direction so received-vs-sent asymmetry reads as
    # this-device's-own-view, not a shared ledger
    assert "<th>↓ received</th>" in body and "<th>↓ avg speed</th>" in body, \
        "per-peer table header must be peer | ↓ received | ↓ avg speed | ↑ sent"
    assert "<th>↑ sent</th>" in body, "sent column must be direction-labeled"
    # received is rendered via fmtBytes(row.rx_bytes ...)
    assert "fmtBytes(row.rx_bytes" in body, \
        "received column must render rx_bytes via fmtBytes"
    # avg speed is rendered via fmtBps(row.avg_bps)
    assert "fmtBps(row.avg_bps)" in body, \
        "avg speed column must render avg_bps via fmtBps"
    # the peer identity resolves the announce ip -> its console device via byIp
    assert "byIp[row.ip]" in body, \
        "per-peer row must resolve the announce ip to its device via byIp"
    # seeding (tx) stays visible inline, without a dedicated column
    assert "row.tx_bytes" in body, \
        "nonzero tx (seeding) must still be surfaced inline"


def test_swarmmap_drawer_widened():
    # The drawer was cramped at 340px; #18 widens it to ~440px so the richer
    # per-peer table fits without column overflow.
    html = _swarmmap_html()
    assert "width:340px" not in html, "old 340px drawer width still present"
    assert "#drawer{" in html and "width:440px" in html, \
        "#drawer must be widened to 440px"


def test_index_html_embeds_swarmmap_iframe_lazily():
    idx = _index_html()
    assert '<iframe id="swarm-frame"' in idx
    assert 'src="/swarmmap"' not in idx, \
        "iframe src must be set lazily by app.js (avoid polling while hidden)"
    js = _app_js()
    assert "swarm-frame" in js and "'/swarmmap'" in js


def test_swarmmap_has_no_inline_event_handlers():
    # The console serves this page under a nonce-only CSP: inline on*=
    # attributes are blocked even inside the nonce'd script, so they must
    # not exist anywhere in the file (including innerHTML template strings).
    html = _swarmmap_html()
    assert "onclick=" not in html
    for h in ("onload=", "onerror=", "onmouseover="):
        assert h not in html


def test_swarmmap_explains_telemetry_disabled_device():
    # #13 final review Important-3: a telemetry-off (or pre-telemetry) device
    # must not look identical to "no report yet" — the drawer must say why.
    html = _swarmmap_html()
    assert "telemetry_enabled" in html, \
        "swarm_snapshot's telemetry_enabled join must be consumed by the drawer"
    assert "telemetry is disabled on this device" in html


def test_swarm_snapshot_includes_host_from_env(monkeypatch):
    # The swarm map needs the server's own IP to dedupe the seeder (it's the
    # central hub, not a peer node). swarm_snapshot surfaces it from IRIS_HOST_IP.
    monkeypatch.setenv("IRIS_HOST_IP", "100.90.168.20")
    hub = telemetry.Telemetry(PeerRegistry())
    assert hub.swarm_snapshot()["host"] == "100.90.168.20"


def test_peer_accumulators_pruned_on_stopped_event():
    # When a peer sends event=stopped, its IP must be removed from
    # _peer_sent and _peer_sent_since so those dicts don't grow unbounded.
    ga = {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "0", "infoHash": "abc",
                    "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]
    # the counter must ADVANCE between two samples for bytes to land (the
    # first sighting only baselines), so serve uploadLength from a mutable.
    upload_len = {"abc": 0}
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    peers_map = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            return active_full if "files" in keys else active_gid()
        if method == "aria2.getPeers":
            return peers_map.get(params[0], [])
        raise AssertionError(method)

    reg = PeerRegistry(on_event=lambda e: None)
    hub = telemetry.Telemetry(reg, rpc=rpc, interval=10)
    hub.registry = reg      # ensure on_swarm_event is wired
    reg._on_event = hub.on_swarm_event

    reg.announce("abc", "p1", "10.0.0.2", 6882, left=500, now=0)
    hub.sample(now=0)       # baseline (first sighting attributes nothing)
    upload_len["abc"] = 1000
    hub.sample(now=0)       # delta 1000 lands on 10.0.0.2
    assert "10.0.0.2" in hub._peer_sent.get("abc", {})
    assert "10.0.0.2" in hub._peer_sent_since.get("abc", {})

    # peer departs with event=stopped
    reg.announce("abc", "p1", "10.0.0.2", 6882, event="stopped", now=60)

    # accumulators for this IP must be gone
    assert "10.0.0.2" not in hub._peer_sent.get("abc", {})
    assert "10.0.0.2" not in hub._peer_sent_since.get("abc", {})


def test_peer_accumulators_pruned_on_stale_expiry():
    # When the registry prunes a silent peer (stale event), its accumulators
    # must also be removed — otherwise they grow for the lifetime of the process.
    ga = {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "0", "infoHash": "abc",
                    "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]
    # counter must ADVANCE between two samples for bytes to land (first
    # sighting only baselines), so serve uploadLength from a mutable.
    upload_len = {"abc": 0}
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    peers_map = {"g1": [{"ip": "10.0.0.3", "uploadSpeed": "50"}]}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            return active_full if "files" in keys else active_gid()
        if method == "aria2.getPeers":
            return peers_map.get(params[0], [])
        raise AssertionError(method)

    reg = PeerRegistry(interval=30)
    hub = telemetry.Telemetry(reg, rpc=rpc, interval=10)
    reg._on_event = hub.on_swarm_event

    reg.announce("abc", "p1", "10.0.0.3", 6882, left=500, now=0)
    hub.sample(now=0)       # baseline (first sighting attributes nothing)
    upload_len["abc"] = 1000
    hub.sample(now=0)       # delta 1000 lands on 10.0.0.3
    assert "10.0.0.3" in hub._peer_sent.get("abc", {})

    # advance time past 2*interval (60 s) so the registry prunes the peer
    reg.prune_all(now=61)

    assert "10.0.0.3" not in hub._peer_sent.get("abc", {})


# --- device telemetry reports: _read_reports / join / export / gauge ---

def _stored_report(ts=100, event="staging-complete", tier="good", rtt=12,
                   avg_bps=4052505, received_at=200.0):
    """One catalog-stored device report (spec shape + received_at stamp)."""
    return {"ts": ts, "image_id": "cat9k.bin", "event": event,
            "transfer": {"total_bytes": 10, "elapsed_s": 1,
                         "avg_bps": avg_bps, "sha_ok": True,
                         "stage_state": "ready"},
            "link": {"tier": tier, "rtt_ms_median": rtt, "rtt_samples": 8,
                     "hb_failures": 0, "trimmed": False},
            "peers": [], "agent": {"version": "x",
                                   "runtime_mode": "guestshell"},
            "received_at": received_at}


def test_read_reports_missing_file_returns_empty(tmp_path):
    assert telemetry._read_reports(str(tmp_path)) == {}


def test_read_reports_garbage_returns_empty(tmp_path):
    (tmp_path / "telemetry.json").write_text("{not json!!!")
    assert telemetry._read_reports(str(tmp_path)) == {}
    (tmp_path / "telemetry.json").write_text('["a list, not a dict"]')
    assert telemetry._read_reports(str(tmp_path)) == {}


def test_read_reports_parses_valid_ring(tmp_path):
    data = {"100.92.9.3": [{"ts": 1, "event": "pull", "received_at": 2.0}]}
    (tmp_path / "telemetry.json").write_text(json.dumps(data))
    assert telemetry._read_reports(str(tmp_path)) == data


def test_from_env_wires_reports_info_to_state_dir(tmp_path):
    data = {"d1": [{"ts": 1, "received_at": 2.0}]}
    (tmp_path / "telemetry.json").write_text(json.dumps(data))
    hub = telemetry.from_env({"IRIS_STATE": str(tmp_path)})
    assert hub._reports_info() == data


def test_swarm_snapshot_joins_device_id_and_report_by_swarm_ip():
    devices = {"100.92.9.3": {"device_id": "100.92.9.3",
                              "model": "C9300-48UXM", "swarm_ip": "10.0.0.2"},
               "100.90.168.99": {"device_id": "100.90.168.99",
                                 "swarm_ip": "10.0.0.5"}}
    reports = {"100.92.9.3": [
        _stored_report(ts=50, event="pull", tier="constrained"),
        _stored_report(ts=100, event="staging-complete", tier="good",
                       rtt=12, avg_bps=4052505)]}
    hub = telemetry.Telemetry(PeerRegistry(),
                              device_info=lambda: devices,
                              reports_info=lambda: reports)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    hub._registry.announce("abc", "p2", "10.0.0.5", 6883, left=5, now=0)
    hub._registry.announce("abc", "p3", "10.0.0.9", 6884, left=5, now=0)
    peers = {p["ip"]: p
             for p in hub.swarm_snapshot(now=0)["images"][0]["peers"]}
    # joined device: id + summary of the LATEST report (last ring entry)
    assert peers["10.0.0.2"]["device_id"] == "100.92.9.3"
    assert peers["10.0.0.2"]["report"] == {
        "ts": 100, "event": "staging-complete", "tier": "good",
        "rtt_ms_median": 12, "avg_bps": 4052505}
    # device known but no stored reports -> id joined, report None
    assert peers["10.0.0.5"]["device_id"] == "100.90.168.99"
    assert peers["10.0.0.5"]["report"] is None
    # unknown IP -> both None (keys still present: stable /swarm shape)
    assert peers["10.0.0.9"]["device_id"] is None
    assert peers["10.0.0.9"]["report"] is None


def test_swarm_snapshot_report_join_never_breaks_on_garbage():
    devices = {"d1": {"swarm_ip": "10.0.0.2", "model": "C9300"}}
    garbage = {"d1": "not-a-list", "d2": [123], "d3": []}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices,
                              reports_info=lambda: garbage)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert p["device_id"] == "d1"
    assert p["report"] is None          # garbage ring -> no summary
    assert p["model"] == "C9300"        # model join unaffected


def test_swarm_snapshot_survives_reports_info_raising():
    def boom():
        raise OSError("state dir gone")
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=boom)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert p["report"] is None
    assert p["device_id"] is None


def test_swarm_peer_rows_keep_existing_fields_plus_device_id_and_report():
    # /swarm response shape: everything that was there stays, two fields added.
    hub = telemetry.Telemetry(PeerRegistry())
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0)
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    for key in ("ip", "port", "left", "last_seen", "is_seeder", "progress",
                "server_up_bps", "server_sent_bytes", "model",
                "device_id", "report"):
        assert key in p, key
    assert p["device_id"] is None
    assert p["report"] is None


def test_sample_exports_each_stored_report_exactly_once():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    reports = {"d1": [_stored_report(received_at=10.0)],
               "d2": [_stored_report(received_at=5.0)]}
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp,
                              reports_info=lambda: reports)
    hub.sample()                    # first pass: both reports exported
    assert len(sent) == 1
    assert sent[0].decode().count('"device_id"') == 2   # one attr per record
    hub.sample()                    # same stored data -> nothing new to send
    assert len(sent) == 1
    # a NEW report lands (newer received_at) -> exported exactly once more
    reports["d1"].append(_stored_report(ts=999, received_at=20.0))
    hub.sample()
    assert len(sent) == 2
    body = sent[1].decode()
    assert body.count('"device_id"') == 1
    assert "999000000000" in body   # ts=999 -> timeUnixNano


def test_sample_survives_reports_info_raising():
    exp = otlp.OTLPLogExporter("http://c:4318", sender=lambda u, b: None)
    def boom():
        raise ValueError("bad state")
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp,
                              reports_info=boom)
    hub.sample()                    # must not raise


def test_metrics_text_reports_stored_gauge():
    reports = {"d1": [_stored_report(), _stored_report()],
               "d2": [_stored_report()],
               "d3": "garbage-not-a-list"}
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=lambda: reports)
    assert "iris_device_reports_stored 3" in hub.metrics_text()


def test_metrics_text_reports_stored_zero_when_unwired():
    hub = telemetry.Telemetry(PeerRegistry())
    assert "iris_device_reports_stored 0" in hub.metrics_text()


def test_moved_page_links_to_console(monkeypatch):
    monkeypatch.setenv("IRIS_HOST_IP", "100.90.168.20")
    page = telemetry.moved_page()
    assert isinstance(page, bytes)
    assert b"https://100.90.168.20:8080/" in page
    assert b"intelligent-release-image-staging Console" in page


def test_moved_page_honors_console_url_override(monkeypatch):
    # Shared hosts may publish the console on a non-default port (e.g. 8480
    # when :8080 is already taken) — IRIS_CONSOLE_URL, when non-empty, wins
    # verbatim over the IRIS_HOST_IP-derived default.
    monkeypatch.setenv("IRIS_HOST_IP", "100.90.168.20")
    monkeypatch.setenv("IRIS_CONSOLE_URL", "https://100.90.168.20:8480/")
    page = telemetry.moved_page()
    assert isinstance(page, bytes)
    assert b"https://100.90.168.20:8480/" in page
    assert b"intelligent-release-image-staging Console" in page
    assert b":8080" not in page


def test_metrics_server_serves_moved_page_at_swarmmap_and_root(monkeypatch):
    monkeypatch.setenv("IRIS_HOST_IP", "100.90.168.20")
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        swarm_provider=lambda: {"images": []},
                                        html=telemetry.moved_page)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for path in ("/swarmmap", "/"):
            status, body = _get(srv.server_address[1], path)
            assert status == 200, path
            assert b"https://100.90.168.20:8080/" in body, path
        # JSON + health surfaces untouched; /metrics still provider-gated
        assert _get(srv.server_address[1], "/swarm")[0] == 200
        assert _get(srv.server_address[1], "/healthz")[0] == 200
        assert _get(srv.server_address[1], "/metrics")[0] == 200
    finally:
        srv.shutdown()
