# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import json
import os
import threading

import metrics
import otlp
import telemetry
import telemetry_destination
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
    # tracker source carries presence/role/progress (spec §10.3)
    assert by_ip["10.0.0.1"]["tracker"]["role"] == "seeder"
    assert abs(by_ip["10.0.0.1"]["tracker"]["progress"] - 1.0) < 1e-9
    assert abs(by_ip["10.0.0.2"]["tracker"]["progress"] - 0.5) < 1e-9
    # global rates live under the canonical server source object
    assert snap["server"]["server_observation"]["global"]["connections"] == 2


def _peers_rpc(active_gid, peers_by_gid, session_id="s0"):
    """A _fake_rpc-style double for the truth-model peer path. `active_gid` is
    a callable returning the tellActive(gid+infoHash+uploadLength) list, so a
    test can mutate uploadLength between samples; `peers_by_gid[gid]` is the
    rate-only getPeers() list. Asserts the exact filtered key sets the truth
    model must send (never bitfield)."""
    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            return {"sessionId": session_id}
        if method == "aria2.tellActive":
            assert params and params[0] == ["gid", "infoHash", "uploadLength"]
            return active_gid()
        if method == "aria2.getPeers":
            assert params[1] == ["ip", "port", "uploadSpeed"]
            return peers_by_gid.get(params[0], [])
        raise AssertionError(method)
    return rpc


def test_poll_seeder_peers_uses_filtered_keys_and_reports_session():
    # The rate path fetches ONLY ip+uploadSpeed (never bitfield / cumulative),
    # tellActive fetches only gid+infoHash+uploadLength, and the session id
    # comes from aria2.getSessionInfo so the caller can detect a counter epoch.
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc", "uploadLength": "12345"}]
    peers = {"g1": [{"ip": "10.0.0.2", "port": "6882", "uploadSpeed": "500000"},
                    {"ip": "10.0.0.3", "port": "6883", "uploadSpeed": "0"}]}
    pu, upload_lengths, session_id = telemetry.poll_seeder_peers(
        _peers_rpc(active_gid, peers, session_id="sess-1"))
    assert pu == {"abc": {("10.0.0.2", 6882): 500000,
                           ("10.0.0.3", 6883): 0}}
    assert upload_lengths == {"abc": 12345}
    assert session_id == "sess-1"


def test_poll_seeder_peers_session_absent_is_empty_string():
    # getSessionInfo may be unavailable (old aria2 / RPC blip) -> best-effort
    # empty session id, and the rest of the peer view still works.
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc", "uploadLength": "10"}]

    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            raise OSError("no session info")
        if method == "aria2.tellActive":
            return active_gid()
        if method == "aria2.getPeers":
            return [{"ip": "10.0.0.2", "port": "6882", "uploadSpeed": "7"}]
        raise AssertionError(method)
    pu, upload_lengths, session_id = telemetry.poll_seeder_peers(rpc)
    assert pu == {"abc": {("10.0.0.2", 6882): 7}}
    assert upload_lengths == {"abc": 10}
    assert session_id == ""


def test_swarm_snapshot_surfaces_measured_peer_rate_no_inferred_bytes():
    # server_up_bps is the MEASURED current send rate to a connected peer. No
    # inferred cumulative per-peer bytes exist anywhere: server_sent_bytes is
    # gone from the row entirely (it was division, not measurement).
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc", "uploadLength": "1000"}]
    peers = {"g1": [{"ip": "10.0.0.2", "port": "6882", "uploadSpeed": "100"}]}
    ga = {"uploadSpeed": "500000", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "1", "infoHash": "abc", "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return active_full
            assert keys == ["gid", "infoHash", "uploadLength"]
            return active_gid()
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s0"}
        if method == "aria2.getPeers":
            assert params[1] == ["ip", "port", "uploadSpeed"]
            return peers.get(params[0], [])
        raise AssertionError(method)

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=10)
    hub.sample()
    import auth
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=500,
                           principal=auth.Principal("device", "d1"))
    p = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
         if x["ip"] == "10.0.0.2"][0]
    # MEASURED current send rate under the server_observation.peer source
    assert p["server_observation"]["peer"]["send_bps"] == 100
    assert "server_sent_bytes" not in p          # no inferred cumulative bytes
    # no ambiguous flat per-peer cumulative/rate field either
    assert "server_up_bps" not in p


def test_swarm_snapshot_torrent_upload_length_is_a_gauge():
    # uploadLength is surfaced only as a control-state gauge on the image
    # (server_observation.torrent), never split across peers. It may legitimately
    # exceed the image size on the same session (re-sends / multiple leechers).
    upload_len = {"abc": 0}

    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    ga = {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
    active_full = [{"connections": "1", "infoHash": "abc", "totalLength": "1000",
                    "files": [{"path": "/img/cat9k.bin"}]}]

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return ga
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            return active_full if "files" in keys else active_gid()
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s0"}
        if method == "aria2.getPeers":
            return [{"ip": "10.0.0.2", "uploadSpeed": "1"}]
        raise AssertionError(method)

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=10)
    hub.sample()
    upload_len["abc"] = 1500          # overshoot past the 1000 B image size
    hub.sample()
    hub._registry.announce("abc", "l1", "10.0.0.2", 6882, left=500)
    snap = hub.swarm_snapshot()
    # the gauge lives on the canonical server source (server_observation.torrent),
    # never split across peers, as a control-state-lifetime gauge.
    torrents = {t["info_hash"]: t
                for t in snap["server"]["server_observation"]["torrent"]}
    assert torrents["abc"]["upload_length_bytes"] == 1500
    assert torrents["abc"]["lifetime"] == "control-state"


def test_server_source_proves_typed_seeder_and_current_torrent_snapshot():
    import auth
    active = [{"gid": "g1", "connections": "1", "infoHash": "abc",
               "totalLength": "1000", "uploadLength": "3",
               "uploadSpeed": "7", "files": [{"path": "/img/a.bin"}]}]
    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "7", "downloadSpeed": "0", "numActive": "1"}
        if method == "aria2.tellActive":
            return active
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s1"}
        if method == "aria2.getPeers":
            return []
        raise AssertionError(method)
    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc)
    hub._registry.announce("abc", "seed", "10.0.0.1", 6881, left=0,
                           now=10, principal=auth.Principal("service", "seeder"))
    hub.sample(now=11)
    obs = hub.swarm_snapshot(now=11)["server"]["server_observation"]
    assert obs["tracker_observation"] == {
        "principal_type": "service", "principal_id": "seeder",
        "observed_info_hashes": ["abc"], "last_seen": 10,
        "last_seen_by_info_hash": {"abc": 10}}
    assert obs["torrent"] == [{"info_hash": "abc", "image": "a.bin",
                                "upload_length_bytes": 3, "upload_bps": 7,
                                "lifetime": "control-state"}]


def test_failed_or_vanished_peer_poll_clears_current_torrent_gauges():
    active = {"rows": [{"gid": "g1", "connections": "0", "infoHash": "abc",
                        "totalLength": "1", "uploadLength": "2",
                        "uploadSpeed": "3", "files": []}], "fail": False}
    def rpc(method, params=None):
        if method == "aria2.getGlobalStat": return {"numActive": "1"}
        if method == "aria2.tellActive":
            if active["fail"]: raise OSError("down")
            return active["rows"]
        if method == "aria2.getSessionInfo": return {"sessionId": "s"}
        if method == "aria2.getPeers": return []
        raise AssertionError(method)
    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc)
    hub.sample(now=10)
    active["rows"] = []
    hub.sample(now=11)
    assert hub._server_source(11)["server_observation"]["torrent"] == []


def test_sample_unchanged_session_reports_upload_length_verbatim():
    # On an unchanged session id, increases (including image-size overshoot)
    # are legitimate and the reported gauge tracks the counter exactly.
    upload_len = {"abc": 0}

    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "0"}]}
    hub = telemetry.Telemetry(PeerRegistry(),
                              rpc=_peers_rpc(active_gid, peers, session_id="s1"),
                              interval=15)
    hub.sample()
    upload_len["abc"] = 5_000_000_000
    hub.sample()
    assert hub._upload_len["abc"] == 5_000_000_000
    upload_len["abc"] = 6_000_000_000
    hub.sample()
    assert hub._upload_len["abc"] == 6_000_000_000


def test_sample_session_change_rebaselines_gauge_without_bridging():
    # A changed aria_session_id is a new counter epoch: the reported gauge
    # re-baselines to the new session's counter and never bridges the old
    # epoch's value into the new one.
    upload_len = {"abc": 900_000_000}
    session = {"id": "s1"}

    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]

    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            return {"sessionId": session["id"]}
        if method == "aria2.tellActive":
            return active_gid()
        if method == "aria2.getPeers":
            return [{"ip": "10.0.0.2", "uploadSpeed": "0"}]
        raise AssertionError(method)

    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=15)
    hub.sample()
    assert hub._upload_len["abc"] == 900_000_000
    # aria2 reloaded (new session), counter now small -> report the NEW epoch's
    # value as-is, do not bridge/keep the old 900_000_000.
    session["id"] = "s2"
    upload_len["abc"] = 200
    hub.sample()
    assert hub._upload_len["abc"] == 200
    assert hub._session_id == "s2"


def test_sample_counter_decrease_without_session_change_rebaselines():
    # A decrease without a session id change (control-state loss) is treated as
    # a new epoch too: re-baseline to the current counter, never carry the old.
    upload_len = {"abc": 0}

    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "0"}]}
    hub = telemetry.Telemetry(PeerRegistry(),
                              rpc=_peers_rpc(active_gid, peers, session_id="s1"),
                              interval=15)
    hub.sample()
    upload_len["abc"] = 700
    hub.sample()
    assert hub._upload_len["abc"] == 700
    upload_len["abc"] = 200          # decrease, same session -> rebaseline
    hub.sample()
    assert hub._upload_len["abc"] == 200


def test_sample_has_no_inferred_allocation_state():
    # The inferred-allocation machinery is gone: none of the removed
    # accumulators or the split function survive on the hub or the module.
    upload_len = {"abc": 0}

    def active_gid():
        return [{"gid": "g1", "infoHash": "abc",
                 "uploadLength": str(upload_len["abc"])}]
    peers = {"g1": [{"ip": "10.0.0.2", "uploadSpeed": "100"}]}
    hub = telemetry.Telemetry(PeerRegistry(),
                              rpc=_peers_rpc(active_gid, peers), interval=15)
    hub.sample()
    upload_len["abc"] = 1000
    hub.sample()
    for attr in ("_peer_sent", "_peer_sent_since", "_last_upload_len",
                 "_unattributed"):
        assert not hasattr(hub, attr), attr
    assert not hasattr(telemetry, "_distribute_upload_delta")
    assert not hasattr(hub, "_joined_at_by_ip")


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
    hub.on_swarm_event({"event": "join", "ip": "10.0.0.9", "ts": 0,
                        "principal_type": "device", "principal_id": "d1",
                        "event_id": "e1"})
    exp.flush()
    assert b"10.0.0.9" in sent[0]


def test_sample_updates_seeder_stats_and_flushes_events():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    rpc = _fake_rpc(
        {"uploadSpeed": "1000", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "2", "infoHash": "abc",
          "files": [{"path": "/img/cat9k.bin"}]}])
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp, rpc=rpc)
    hub.on_swarm_event({"event": "join", "ip": "10.0.0.9", "ts": 0,
                        "principal_type": "device", "principal_id": "d1",
                        "event_id": "e1"})
    hub.sample()
    assert b"10.0.0.9" in sent[0]      # queued events were flushed
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
    # JSON body (spec 7.7); status stays 200 — container HEALTHCHECK and
    # orchestrator probes are status-code based and unaffected.
    srv = telemetry.make_metrics_server(
        "127.0.0.1", 0, lambda: "",
        health=lambda: {"state": "ok", "last_success_ts": 0, "fail_streak": 0})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/healthz")
        assert status == 200
        data = json.loads(body)
        assert data["ok"] is True
        assert data["otlp_export"]["state"] in ("ok", "degraded", "off")
    finally:
        srv.shutdown()


def test_metrics_server_healthz_without_health_provider():
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/healthz")
        assert status == 200
        assert json.loads(body)["ok"] is True
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


def test_swarm_snapshot_joins_device_model_by_principal_id():
    # Device attribution joins on the AUTHENTICATED device principal id (== the
    # catalog's device_id key), NEVER on the heartbeat/source IP (spec §10.3).
    # model appears only for typed device principals; unattributed peers omit it.
    import auth
    devices = {"iris8kv-1": {"device_id": "iris8kv-1", "model": "C9300-48UXM",
                             "swarm_ip": "10.0.0.2"}}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "iris8kv-1"))
    hub._registry.announce("abc", "p2", "10.0.0.9", 6883, left=5, now=0,
                           principal=auth.Principal("device", "iris8kv-2"))
    peers = {p["ip"]: p for p in hub.swarm_snapshot(now=0)["images"][0]["peers"]}
    assert peers["10.0.0.2"]["model"] == "C9300-48UXM"
    assert peers["10.0.0.2"]["device_id"] == "iris8kv-1"
    # device principal with no matching record -> no model key, device_id kept
    assert "model" not in peers["10.0.0.9"]
    assert peers["10.0.0.9"]["device_id"] == "iris8kv-2"


def test_swarm_snapshot_legacy_peer_is_unattributed_no_identity_join():
    # A legacy-credential participant is legacy_unattributed regardless of IP:
    # no model/device_observation/latest_report/peer_policy, no quarantine
    # control, and the heartbeat swarm_ip must NOT establish identity (spec §10.3).
    import auth
    devices = {"iris8kv-1": {"device_id": "iris8kv-1", "model": "C9300-48UXM",
                             "swarm_ip": "10.0.0.2"}}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices)
    # legacy announce from the SAME IP a device record claims — must not join.
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=5, now=0,
                           principal=auth.Principal("legacy", ""))
    peer = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert peer["tracker"]["principal_type"] == "legacy"
    assert "principal_id" not in peer["tracker"]
    assert peer["tracker"]["participant_class"] == "legacy_unattributed"
    assert peer["warning"] == "legacy_unattributed"
    assert peer["device_id"] is None
    assert peer["quarantine_available"] is False
    assert "model" not in peer
    assert "device_observation" not in peer
    assert "latest_report" not in peer
    assert "peer_policy" not in peer


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


def old_swarmmap_device_fields_not_raw_in_innerhtml():
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


def old_swarmmap_rtt_median_rendered_only_when_numeric():
    # link.rtt_ms_median is device-supplied. It is semantically a number, so
    # instead of escapeHtml() the report drawer gates on Number.isFinite()
    # and shows the placeholder otherwise — the pre-fix form interpolated the
    # raw stored value into innerHTML (stored XSS via a device report).
    html = _swarmmap_html()
    assert "l.rtt_ms_median!=null?l.rtt_ms_median" not in html, (
        "raw rtt_ms_median still interpolated into innerHTML in swarmmap.html"
    )
    assert "Number.isFinite(l.rtt_ms_median)" in html, (
        "rtt_ms_median must be gated on Number.isFinite() before insertion"
    )


def old_swarmmap_pan_zoom_update_transform_not_rebuild():
    # Pan/zoom are camera moves: they must retarget the scene <g> transform in
    # place (applyView), never call render() — a full rebuild per pointermove
    # restarts every node's staggered fade-in (fill-mode "both" keeps a node
    # invisible until its delay elapses), strobing the graph during a drag.
    html = _swarmmap_html()
    assert "function applyView" in html
    move = [ln for ln in html.splitlines()
            if 'addEventListener("pointermove"' in ln]
    assert move, "svg pointermove pan handler missing from swarmmap.html"
    assert all("applyView()" in ln and "render()" not in ln for ln in move), (
        "pan must update the scene transform via applyView(), not re-render"
    )
    zoomfn = [ln for ln in html.splitlines() if "function changeZoom" in ln]
    assert zoomfn and all("render()" not in ln for ln in zoomfn), (
        "zoom must update the scene transform via applyView(), not re-render"
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


def old_swarmmap_map_cfg_placeholder_exactly_once():
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


def old_swarmmap_pull_ui_gated_and_null_device_handled():
    html = _swarmmap_html()
    assert "MAP.pull" in html
    assert "request-report" in html
    assert "Pull fresh data from device" in html
    # a peer with no device_id (no heartbeat join) gets a disabled note, not a
    # broken POST to /api/devices/null/...
    assert "no device identity" in html


def old_swarmmap_pull_arrival_uses_server_clock():
    # The arrived-check must compare the SERVER-stamped received_at (same
    # clock domain as requested_at) — the device-stamped ts is fallback only.
    html = _swarmmap_html()
    body = html.split("function refreshDrawerReport")[1]
    assert "latest.received_at||latest.ts" in body


def old_swarmmap_report_fields_are_escaped():
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


def old_swarmmap_hub_drawer_has_sent_bytes_table():
    html = _swarmmap_html()
    assert "server_sent_bytes" in html.split("function openHubDrawer")[1], \
        "hub drawer does not render the per-device sent-bytes table"


# ---------------------------------------------------------------------------
# Telemetry (#18): swarm-map leads with the CONSOLE device IP (device_id),
# participation-only per-peer drawer table (who was connected, no bytes),
# wider drawer panel.
# Same HTML-source guard style as the escapeHtml tests above.
# ---------------------------------------------------------------------------

def old_swarmmap_has_device_id_preferred_label_helper():
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


def old_swarmmap_shows_announce_ip_as_secondary_detail():
    # Operators still need the raw announce/guest ip — it must appear as a
    # secondary detail (only when it differs from the leading console ip), via a
    # dedicated helper referenced by the node/tooltip/drawer.
    html = _swarmmap_html()
    assert "function peerAnnounceSub(p)" in html, \
        "no peerAnnounceSub helper for the secondary announce-ip detail"
    # the sub must be escaped everywhere it lands in innerHTML
    assert "escapeHtml(asub)" in html, \
        "the announce-ip sub-detail must be escaped before innerHTML insertion"


def old_swarmmap_per_peer_table_is_participation_only():
    # Byte columns are gone BY DESIGN: per-peer rx/tx/avg were derived, not
    # measured (aria2 has no per-peer byte counters; the even-split fallback
    # fired on every multi-peer lab transfer). The drawer must not read any
    # per-peer byte field, and must render the exact peers_total count
    # number-gated (same stored-XSS discipline as rtt_ms_median).
    html = _swarmmap_html()
    body = html.split("function reportHtml")[1].split("\nfunction ")[0]
    assert "row.rx_bytes" not in body and "row.tx_bytes" not in body \
        and "row.avg_bps" not in body, \
        "per-peer byte fields are not measured and must not be rendered"
    assert "<th>peers observed</th>" in body, \
        "per-peer table header must be the single participation column"
    # the peer identity still resolves the announce ip -> device via byIp
    assert "byIp[row.ip]" in body, \
        "per-peer row must resolve the announce ip to its device via byIp"
    # overflow count interpolates as a NUMBER only
    assert "Number.isFinite(rep.peers_total)" in body, \
        "peers_total must be finite-number-gated before interpolation"


def old_swarmmap_drawer_widened():
    # The drawer was cramped at 340px. It is now responsive and substantially
    # wider on desktop so the per-peer table is readable without overflow.
    html = _swarmmap_html()
    assert "width:340px" not in html, "old 340px drawer width still present"
    assert "#drawer{" in html and "width:min(560px,52vw)" in html, \
        "#drawer must use the responsive wide layout"


def old_swarmmap_has_fleet_scale_controls():
    html = _swarmmap_html()
    assert 'id="peerfind"' in html
    assert 'id="zoom-out"' in html
    assert 'id="zoom-in"' in html
    assert 'id="fit"' in html
    assert 'id="legend-toggle"' in html
    assert "filterPeers" in html
    assert 'svg.addEventListener("wheel"' not in html
    assert 'svg.addEventListener("pointerdown"' in html


def old_swarmmap_hides_legend_and_labels_in_dense_view():
    html = _swarmmap_html()
    assert 'id="legend" hidden' in html
    assert "const dense=peers.length>40" in html
    assert "if(!dense || peerFilter)" in html


def test_index_html_embeds_swarmmap_iframe_lazily():
    idx = _index_html()
    assert '<iframe id="swarm-frame"' in idx
    assert 'src="/swarmmap"' not in idx, \
        "iframe src must be set lazily by app.js (avoid polling while hidden)"
    js = _app_js()
    assert "swarm-frame" in js and "'/swarmmap'" in js


def old_swarmmap_has_no_inline_event_handlers():
    # The console serves this page under a nonce-only CSP: inline on*=
    # attributes are blocked even inside the nonce'd script, so they must
    # not exist anywhere in the file (including innerHTML template strings).
    html = _swarmmap_html()
    assert "onclick=" not in html
    for h in ("onload=", "onerror=", "onmouseover="):
        assert h not in html


def old_swarmmap_explains_telemetry_disabled_device():
    # #13 final review Important-3: a telemetry-off (or pre-telemetry) device
    # must not look identical to "no report yet" — the drawer must say why.
    html = _swarmmap_html()
    assert "telemetry_enabled" in html, \
        "swarm_snapshot's telemetry_enabled join must be consumed by the drawer"
    assert "telemetry is disabled on this device" in html


def test_swarmmap_task26_canonical_topology_structure():
    """Static guards only; browser interaction remains a Task30 manual check."""
    html = _swarmmap_html()
    for canonical in ("DATA?.server", "server_observation?.peer", "tracker?.role",
                      "tracker?.participant_class", "device_observation",
                      "latest_report", "peer_policy", "peer_enforcement"):
        assert canonical in html
    for retired in ("server_sent_bytes", "server_up_bps", "DATA.host",
                    "DATA.seeder", "is_seeder", "~sent"):
        assert retired not in html
    assert "not a measured transfer path" in html
    assert "fresh measured server → peer" in html
    assert "marker-end" in html and "server_observation?.peer" in html
    assert "device_id" in html and "Legacy unattributed peer" in html
    assert "no per-device quarantine" in html
    assert "o.blocked===true" in html
    assert "conflict" in html


def test_swarmmap_task26_accessibility_polling_and_empty_states():
    html = _swarmmap_html()
    for heading in ("Tracker", "Server observation", "Device observation",
                    "Latest report", "Policy intent", "Enforcement"):
        assert 'section("' + heading + '"' in html
    for marker in ('role:\"button\"', "tabindex:\"0\"", "Current filtered tracker participants",
                   "prefers-reduced-motion", "document.addEventListener(\"visibilitychange\"",
                   "document.hidden", "AbortController", "inflight", "backoff",
                   "if(!r.ok)", "Initial loading…", "No active tracker participants.",
                   "No participants match the current filter.", "Unavailable/retrying",
                   "RPC unavailable; tracker peers may remain.", "Paused."):
        assert marker in html


def test_swarm_snapshot_includes_host_under_server_source(monkeypatch):
    # The origin host lives on the canonical `server` source object (spec §10.3):
    # the seeder is the central hub, not a peer node. From IRIS_HOST_IP.
    monkeypatch.setenv("IRIS_HOST_IP", "100.90.168.20")
    hub = telemetry.Telemetry(PeerRegistry())
    snap = hub.swarm_snapshot()
    assert snap["server"]["host"] == "100.90.168.20"
    # no legacy top-level flat host / seeder objects
    assert "host" not in snap
    assert "seeder" not in snap


def test_on_swarm_event_does_not_track_per_peer_accumulators():
    # With inferred allocation removed, a stop/stale event only forwards to the
    # exporter — there are no per-peer byte accumulators to prune anymore.
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    hub = telemetry.Telemetry(PeerRegistry(), exporter=exp)
    hub.on_swarm_event({"event": "stop", "info_hash": "abc", "ip": "10.0.0.2",
                        "peer_id": "p1", "ts": 0})
    exp.flush()
    assert b"10.0.0.2" in sent[0]
    for attr in ("_peer_sent", "_peer_sent_since"):
        assert not hasattr(hub, attr), attr


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


def test_swarm_snapshot_joins_device_id_and_report_by_principal_id():
    import auth
    devices = {"iris8kv-1": {"device_id": "iris8kv-1",
                             "model": "C9300-48UXM", "swarm_ip": "10.0.0.2"},
               "iris8kv-2": {"device_id": "iris8kv-2", "swarm_ip": "10.0.0.5"}}
    reports = {"iris8kv-1": [
        _stored_report(ts=50, event="pull", tier="constrained"),
        _stored_report(ts=100, event="staging-complete", tier="good",
                       rtt=12, avg_bps=4052505)]}
    hub = telemetry.Telemetry(PeerRegistry(),
                              device_info=lambda: devices,
                              reports_info=lambda: reports)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "iris8kv-1"))
    hub._registry.announce("abc", "p2", "10.0.0.5", 6883, left=5, now=0,
                           principal=auth.Principal("device", "iris8kv-2"))
    hub._registry.announce("abc", "p3", "10.0.0.9", 6884, left=5, now=0,
                           principal=auth.Principal("device", "iris8kv-3"))
    peers = {p["ip"]: p
             for p in hub.swarm_snapshot(now=0)["images"][0]["peers"]}
    # joined by principal id: latest_report is a SAFE v1 summary (no avg_bps
    # reinterpreted as v2), taken from the last ring entry.
    assert peers["10.0.0.2"]["device_id"] == "iris8kv-1"
    assert peers["10.0.0.2"]["latest_report"] == {
        "schema": "v1", "event": "staging-complete", "tier": "good",
        "rtt_ms_median": 12, "received_at": 200.0, "ts": 100}
    assert "avg_bps" not in peers["10.0.0.2"]["latest_report"]
    # device known but no stored reports -> id joined, no latest_report key
    assert peers["10.0.0.5"]["device_id"] == "iris8kv-2"
    assert "latest_report" not in peers["10.0.0.5"]
    # device with no record at all -> device_id kept, no latest_report/model
    assert peers["10.0.0.9"]["device_id"] == "iris8kv-3"
    assert "latest_report" not in peers["10.0.0.9"]


def test_latest_report_v2_summary_uses_taxonomy_fields():
    # A v2 stored report surfaces the taxonomy-correct summary (spec §10.2):
    # report_id/event/content_sha256_state/ios_copy_verify_state/received_at.
    import auth
    v2 = {"v": 2, "schema": "v2",
          "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
          "event": "staging-complete",
          "content_sha256": {"state": "verified", "algo": "sha256"},
          "ios_copy_verify": {"state": "ok"},
          "received_at": 200.0}
    hub = telemetry.Telemetry(PeerRegistry(),
                              reports_info=lambda: {"iris8kv-1": [v2]})
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "iris8kv-1"))
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert p["latest_report"] == {
        "schema": "v2",
        "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
        "event": "staging-complete",
        "content_sha256_state": "verified",
        "ios_copy_verify_state": "ok",
        "received_at": 200.0}


def test_swarm_snapshot_report_join_never_breaks_on_garbage():
    import auth
    devices = {"d1": {"swarm_ip": "10.0.0.2", "model": "C9300"}}
    garbage = {"d1": "not-a-list", "d2": [123], "d3": []}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: devices,
                              reports_info=lambda: garbage)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "d1"))
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert p["device_id"] == "d1"
    assert "latest_report" not in p     # garbage ring -> no summary
    assert p["model"] == "C9300"        # model join unaffected


def test_swarm_snapshot_survives_reports_info_raising():
    import auth
    def boom():
        raise OSError("state dir gone")
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=boom)
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "d1"))
    p = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
    assert "latest_report" not in p
    assert p["device_id"] == "d1"


def test_swarm_peer_row_is_source_grouped():
    # Canonical source-grouped row (spec §10.3): the tracker source carries
    # presence; no ambiguous flat legacy fields survive; the torrent gauge lives
    # on the server source, not the image or peer.
    import auth
    hub = telemetry.Telemetry(PeerRegistry())
    hub._registry.announce("abc", "p1", "10.0.0.2", 6882, left=0, now=0,
                           principal=auth.Principal("device", "d1"))
    snap = hub.swarm_snapshot(now=0)
    img = snap["images"][0]
    assert "upload_length_bytes" not in img       # gauge lives under server
    p = img["peers"][0]
    assert set(p["tracker"]) >= {"principal_type", "principal_id", "role",
                                 "left", "last_seen", "progress"}
    assert p["ip"] == "10.0.0.2" and p["port"] == 6882
    assert p["device_id"] == "d1"
    # retired / ambiguous flat fields must be gone
    for gone in ("server_sent_bytes", "server_up_bps", "is_seeder",
                 "report", "down_bps", "up_bps", "sample_age_s",
                 "telemetry_enabled"):
        assert gone not in p, gone


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
    assert sent[0].decode().count('"device.id"') == 2   # one attr per record
    hub.sample()                    # same stored data -> nothing new to send
    assert len(sent) == 1
    # a NEW report lands (newer received_at) -> exported exactly once more
    reports["d1"].append(_stored_report(ts=999, received_at=20.0))
    hub.sample()
    assert len(sent) == 2
    body = sent[1].decode()
    assert body.count('"device.id"') == 1
    assert "20000000000" in body   # received_at=20.0 -> timeUnixNano (§8)


def test_report_cursor_queues_equal_timestamps_once_and_replays_on_restart():
    reports = {
        "d2": [{"schema": "v2", "report_id": "r2", "received_at": 10}],
        "d1": [{"schema": "v2", "report_id": "r1", "received_at": 10}],
    }
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=lambda: reports)
    hub._export_new_reports()
    assert [telemetry._otlp_record_event_id(record)
            for record in hub.log_queue.snapshot()] == ["r1", "r2"]
    hub._export_new_reports()
    assert hub.log_queue.queued == 2
    reports["d1"].append(
        {"schema": "v2", "report_id": "r3", "received_at": 10})
    hub._export_new_reports()
    assert [telemetry._otlp_record_event_id(record)
            for record in hub.log_queue.snapshot()] == ["r1", "r2", "r3"]
    restarted = telemetry.Telemetry(PeerRegistry(), reports_info=lambda: reports)
    restarted._export_new_reports()
    assert [telemetry._otlp_record_event_id(record)
            for record in restarted.log_queue.snapshot()] == ["r1", "r2", "r3"]


def test_evicted_report_is_requeued_but_delivered_report_is_not():
    reports = {"d": [{"schema": "v2", "report_id": "r1", "received_at": 1}]}
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=lambda: reports)
    hub.log_queue._max = 1
    hub._export_new_reports()
    hub.log_queue.emit({"event": "join"})
    hub._export_new_reports()
    assert telemetry._otlp_record_event_id(hub.log_queue.snapshot()[0]) == "r1"
    assert hub.log_queue.flush(lambda batch: None) == 1
    hub._export_new_reports()
    assert hub.log_queue.queued == 0


def test_delivered_report_ids_are_bounded_to_current_ring():
    reports = {}
    hub = telemetry.Telemetry(PeerRegistry(), reports_info=lambda: reports)

    for generation in range(50):
        reports.clear()
        reports.update({
            "d%d" % device: [
                {"schema": "v2", "report_id": "r%d-%d-%d" %
                 (generation, device, report), "received_at": report}
                for report in range(3)]
            for device in range(10)})
        hub._export_new_reports()
        assert hub.log_queue.flush(lambda batch: None) == 30
        ring_ids = {report["report_id"]
                    for ring in reports.values() for report in ring}
        assert hub._seen_report_event_ids <= ring_ids
        assert len(hub._seen_report_event_ids) <= len(ring_ids)


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


# ---- live transfer streaming: aggregation + /swarm enrichment (spec 7.2/7.4)

IMAGES = {"img-1": {"id": "img-1", "filename": "cat9k.bin", "size": 1000,
                    "info_hash_hex": "aa11"},
          "img-2": {"id": "img-2", "filename": "ie3k.bin", "size": 2000,
                    "info_hash_hex": "bb22"}}


def _doc(now, samples):
    return {"written_at": now, "counters": {"samples_rejected_total": 7},
            "samples": samples}


class TestAggregateTransfers:
    # Task 23: canonical freshness-aware rollup over v2 observations (design
    # §10.9). Fresh observed entries contribute rates + progress; stale/
    # withdrawn entries never invent a fresh zero. Sampling class replaces the
    # old link "tier".
    def _v2(self, image_id, sc, status, receive, send, done, total_recv):
        return {"v": 2, "schema": "v2", "obs_state": "observed",
                "image_id": image_id, "sampling_class": sc, "valid": True,
                "observed_received_at": total_recv, "received_at": total_recv,
                "aria": {"status": status, "receive_bps": receive,
                         "send_bps": send, "connections": 1,
                         "completed_content_bytes": done}}

    def test_rollup_fresh_v2(self):
        samples = {
            "d1": self._v2("img-1", "good", "active", 100, 10, 500, 100.0),
            "d2": self._v2("img-1", "constrained", "active", 0, 0, 250, 100.0),
            "d3": self._v2("img-2", "good", "active", 0, 50, 2000, 100.0),
            "dX": self._v2("unknown", "good", "active", 1, 0, 1, 100.0),
        }
        rows, extras = telemetry.aggregate_transfers(
            _doc(100.0, samples), IMAGES, 100.0)
        assert extras["stream_devices"] == 3          # unknown dropped
        assert extras["samples_rejected_total"] == 7
        by_image = {r["image"]: r for r in rows}
        r1 = by_image["cat9k.bin"]
        assert r1["stale"] is False
        assert r1["devices"] == 2
        assert (r1["receive_bps"], r1["transmit_bps"]) == (100, 10)
        assert r1["zero_receive_devices"] == 1        # d2 active @ 0 receive
        assert (r1["sampling_class_good"], r1["sampling_class_constrained"]) \
            == (1, 1)
        assert abs(r1["progress_ratio"] - 750 / 2000) < 1e-9
        assert r1["freshness_age_seconds"] == 0
        assert by_image["ie3k.bin"]["info_hash"] == "bb22"

    def test_stale_image_marked_and_zero_receive_suppressed(self):
        # observation received at 10, evaluated at 140 (>120s) -> stale image.
        samples = {"d1": self._v2("img-1", "good", "active", 0, 0, 500, 10.0)}
        rows, _ = telemetry.aggregate_transfers(
            _doc(140.0, samples), IMAGES, 140.0)
        r1 = [r for r in rows if r["image"] == "cat9k.bin"][0]
        assert r1["stale"] is True
        assert r1["devices"] == 0                     # no FRESH streaming device
        assert r1["zero_receive_devices"] == 0        # never from stale
        assert r1["freshness_age_seconds"] == 130     # explanatory

    def test_stale_or_missing_doc_is_empty(self):
        assert telemetry.aggregate_transfers(None, IMAGES, 100.0) == \
            ([], {"stream_devices": 0, "samples_rejected_total": 0})
        rows, extras = telemetry.aggregate_transfers(
            _doc(100.0, {}), IMAGES, 131.0)              # > 2 x 15s old
        assert rows == [] and extras["stream_devices"] == 0


class TestSwarmSampleEnrichment:
    def _hub(self, sample, principal_id="d1"):
        import auth
        hub = telemetry.Telemetry(
            live_info=lambda: {"written_at": 100.0,
                               "counters": {"samples_rejected_total": 0},
                               "samples": {principal_id: sample}})
        hub.registry.announce("aa11", "peer1", "10.0.0.2", 6881,
                              left=500, now=100.0,
                              principal=auth.Principal("device", principal_id))
        return hub

    def test_fresh_v2_observed_surfaces_rates_under_device_observation(self):
        # A currently-valid observed v2 entry surfaces the aria rates/counters
        # under the device_observation source (spec §3B/§10.3).
        sample = {"v": 2, "schema": "v2", "obs_state": "observed",
                  "observed_at": 89.0, "observed_received_at": 90.0,
                  "received_at": 90.0, "valid": True,
                  "aria": {"status": "active", "receive_bps": 123,
                           "send_bps": 4, "connections": 2,
                           "completed_content_bytes": 500}}
        row = self._hub(sample).swarm_snapshot(now=100.0)["images"][0][
            "peers"][0]
        dobs = row["device_observation"]
        assert dobs["schema"] == "v2" and dobs["valid"] is True
        assert dobs["stale"] is False and dobs["age_s"] == 10
        assert dobs["receive_bps"] == 123 and dobs["send_bps"] == 4
        assert dobs["connections"] == 2
        assert dobs["completed_content_bytes"] == 500
        assert dobs["zero_receive_rate"] is False

    def test_zero_receive_rate_only_on_fresh_active_zero(self):
        # zero_receive_rate is a fresh-snapshot boolean: true only when a
        # currently-valid observed snapshot has receive_bps==0 & status active.
        sample = {"v": 2, "schema": "v2", "obs_state": "observed",
                  "observed_at": 89.0, "observed_received_at": 90.0,
                  "received_at": 90.0, "valid": True,
                  "aria": {"status": "active", "receive_bps": 0,
                           "send_bps": 4, "connections": 2,
                           "completed_content_bytes": 500}}
        dobs = self._hub(sample).swarm_snapshot(now=100.0)["images"][0][
            "peers"][0]["device_observation"]
        assert dobs["zero_receive_rate"] is True

    def test_stale_observation_retains_context_omits_rates(self):
        # Past LIVE_VALUE_VALIDITY the row is stale retained context: it keeps
        # age_s but OMITS receive/send/connections/current counters (never a
        # fresh zero).
        sample = {"v": 2, "schema": "v2", "obs_state": "observed",
                  "observed_at": 9.0, "observed_received_at": 10.0,
                  "received_at": 10.0, "valid": True,
                  "aria": {"status": "active", "receive_bps": 123,
                           "send_bps": 4, "connections": 2,
                           "completed_content_bytes": 500}}
        # observation is 130s old at now=140 (> 120s validity) while the peer
        # announced at now=100 is still within the registry window.
        dobs = self._hub(sample).swarm_snapshot(now=140.0)["images"][0][
            "peers"][0]["device_observation"]
        assert dobs["valid"] is False and dobs["stale"] is True
        assert dobs["age_s"] == 130
        for omitted in ("receive_bps", "send_bps", "connections",
                        "zero_receive_rate"):
            assert omitted not in dobs, omitted

    def test_paused_state_has_no_fresh_rates(self):
        # A withdrawn/non-observed state (paused/disabled/not_active/rpc) is
        # represented without fresh rates.
        sample = {"v": 2, "schema": "v2", "obs_state": "paused",
                  "observed_at": 89.0, "observed_received_at": 90.0,
                  "received_at": 90.0, "valid": False}
        dobs = self._hub(sample).swarm_snapshot(now=100.0)["images"][0][
            "peers"][0]["device_observation"]
        assert dobs["obs_state"] == "paused"
        assert dobs["valid"] is False and dobs["stale"] is True
        assert "receive_bps" not in dobs

    def test_v1_projected_under_schema_marker_no_v2_reinterpretation(self):
        # A v1 rollout sample is projected with a schema:"v1" marker using its
        # mapped legacy fields — never reinterpreted as a v2 measurement.
        sample = {"v": 1, "schema": "v1", "image_id": "img-1",
                  "phase": "downloading", "done_bytes": 500, "down_bps": 123,
                  "up_bps": 4, "tier": "good",
                  "observed_received_at": 90.0, "received_at": 90.0,
                  "valid": True}
        dobs = self._hub(sample).swarm_snapshot(now=100.0)["images"][0][
            "peers"][0]["device_observation"]
        assert dobs["schema"] == "v1" and dobs["valid"] is True
        assert dobs["receive_bps"] == 123 and dobs["send_bps"] == 4
        assert dobs["completed_content_bytes"] == 500
        assert dobs["zero_receive_rate"] is False
        assert "connections" not in dobs   # v1 has no aria connections


# ---- per-participant peer_policy / peer_enforcement facts (spec §7/§10.3) ----

class TestPeerPolicyEnforcementFacts:
    def _hub(self, policy=None, enforcement=None, principal_id="iris8kv-1",
             ip="100.92.100.14"):
        import auth
        hub = telemetry.Telemetry(
            PeerRegistry(),
            policy_info=(lambda: policy) if policy is not None else None,
            enforcement_info=(lambda: enforcement)
            if enforcement is not None else None)
        hub._registry.announce("abc", "p1", ip, 6881, left=5, now=0,
                               principal=auth.Principal("device", principal_id))
        return hub

    def _row(self, hub):
        return hub.swarm_snapshot(now=0)["images"][0]["peers"][0]

    def test_permit_and_no_quarantine(self):
        import peer_policy
        policy = peer_policy.PolicyResult(
            peer_policy.base_document(), degraded=False, fail_closed=False)
        row = self._row(self._hub(policy=policy))
        assert row["peer_policy"] == {
            "decision": "permit", "matched_seq": None,
            "assignment": None, "quarantined": False, "fail_closed": False}

    def test_quarantine_assignment_surfaces_decision_and_status(self):
        import peer_policy
        doc = peer_policy.base_document()
        doc["assignments"]["iris8kv-1"] = peer_policy.RESERVED_QUARANTINE
        policy = peer_policy.PolicyResult(doc, degraded=False,
                                          fail_closed=False)
        row = self._row(self._hub(policy=policy))
        assert row["peer_policy"]["decision"] == "deny"
        assert row["peer_policy"]["matched_seq"] == 10
        assert row["peer_policy"]["assignment"] == "quarantine"
        assert row["peer_policy"]["quarantined"] is True

    def test_fail_closed_is_explicit_deny(self):
        import peer_policy
        policy = peer_policy.PolicyResult(
            peer_policy._fail_closed_document(), degraded=True,
            fail_closed=True)
        row = self._row(self._hub(policy=policy))
        assert row["peer_policy"]["fail_closed"] is True
        assert row["peer_policy"]["decision"] == "deny"

    def test_conflict_surfaced_without_inferring_block_when_not_globally_blocked(
            self):
        # A shared_permit_deny conflict with global_block_applied False means the
        # tracker recorded a conflict but did NOT globally block this IP (Day1
        # semantics, spec §5/§7). The fact must surface the conflict truthfully
        # yet must NEVER infer blocked from mere conflict membership: blocked is
        # explicitly False here (not derived from the conflict or aggregate
        # count). See blocklist_reconciler._derive_valid.
        enforcement = {"state": "enforced", "conflicts": [
            {"denied_principal_type": "device",
             "denied_principal_id": "iris8kv-1",
             "reason": "shared_permit_deny", "global_block_applied": False}]}
        row = self._row(self._hub(enforcement=enforcement))
        enf = row["peer_enforcement"]
        assert enf["blocked"] is False
        assert enf["state"] == "enforced"
        assert enf["conflict"]["reason"] == "shared_permit_deny"
        assert enf["conflict"]["global_block_applied"] is False

    def test_conflict_with_global_block_applied_surfaces_blocked(self):
        # When the tracker DID globally block the IP for this conflict, blocked
        # is a directly-known fact (True) — not an inference from conflict
        # presence, but from the tracker's own global_block_applied signal.
        enforcement = {"state": "enforced", "conflicts": [
            {"denied_principal_type": "device",
             "denied_principal_id": "iris8kv-1",
             "reason": "shared_permit_deny", "global_block_applied": True}]}
        row = self._row(self._hub(enforcement=enforcement))
        enf = row["peer_enforcement"]
        assert enf["blocked"] is True
        assert enf["conflict"]["global_block_applied"] is True

    def test_enforcement_omits_blocked_when_absent(self):
        enforcement = {"state": "enforced", "conflicts": []}
        row = self._row(self._hub(enforcement=enforcement))
        assert "blocked" not in row["peer_enforcement"]
        assert "conflict" not in row["peer_enforcement"]

    def test_fail_closed_enforcement_state_does_not_prove_peer_block(self):
        enforcement = {"state": "fail_closed", "conflicts": []}
        row = self._row(self._hub(enforcement=enforcement))
        assert "blocked" not in row["peer_enforcement"]
        assert row["peer_enforcement"]["state"] == "fail_closed"

    def test_legacy_peer_gets_no_policy_or_enforcement(self):
        import auth
        import peer_policy
        policy = peer_policy.PolicyResult(
            peer_policy.base_document(), degraded=False, fail_closed=False)
        hub = telemetry.Telemetry(
            PeerRegistry(), policy_info=lambda: policy,
            enforcement_info=lambda: {"state": "enforced", "conflicts": []})
        hub._registry.announce("abc", "p1", "100.92.100.31", 6881, left=5,
                               now=0, principal=auth.Principal("legacy", ""))
        row = hub.swarm_snapshot(now=0)["images"][0]["peers"][0]
        assert "peer_policy" not in row
        assert "peer_enforcement" not in row

    def test_service_seeder_deduped_from_rings(self):
        # The current non-legacy service:seeder is the hub, deduped out of the
        # peer rings (represented under `server`), not a peer node.
        import auth
        hub = telemetry.Telemetry(PeerRegistry())
        hub._registry.announce("abc", "seed", "100.90.168.20", 6881, left=0,
                               now=0,
                               principal=auth.Principal("service", "seeder"))
        hub._registry.announce("abc", "dev", "100.92.100.14", 6881, left=5,
                               now=0,
                               principal=auth.Principal("device", "d1"))
        peers = hub.swarm_snapshot(now=0)["images"][0]["peers"]
        assert [p["ip"] for p in peers] == ["100.92.100.14"]

    def test_device_named_seeder_stays_a_device_peer(self):
        # A device literally named `seeder` (device:seeder) is NOT the service
        # seeder and remains a device peer row.
        import auth
        hub = telemetry.Telemetry(PeerRegistry())
        hub._registry.announce("abc", "p1", "100.92.100.14", 6881, left=5,
                               now=0,
                               principal=auth.Principal("device", "seeder"))
        peers = hub.swarm_snapshot(now=0)["images"][0]["peers"]
        assert len(peers) == 1
        assert peers[0]["tracker"]["principal_type"] == "device"
        assert peers[0]["device_id"] == "seeder"


# ---- OTLP export health + metrics push (spec 7.5/7.7) ----

class TestExportHealth:
    def test_transitions_fire_once_per_edge(self):
        events = []
        h = telemetry.ExportHealth(
            on_transition=lambda name: events.append(name))
        h.record(True, "logs", 100.0)           # logs ok (no edge from off)
        h.record(False, "metrics", 110.0)       # metrics degraded (edge)
        h.record(False, "logs", 120.0)          # logs degraded (edge)
        h.record(True, "metrics", 130.0)        # metrics recovered (edge)
        d = h.as_dict()
        # worst_of: logs still degraded -> aggregate degraded. A metrics
        # recovery never masks the outstanding logs failure (design §10.10).
        assert d["state"] == "degraded"
        assert d["signals"]["logs"]["state"] == "degraded"
        assert d["signals"]["metrics"]["state"] == "ok"
        assert d["signals"]["logs"]["last_success_ts"] == 100.0
        assert d["signals"]["metrics"]["last_success_ts"] == 130.0
        assert d["signals"]["logs"]["failures_total"] == 1
        assert d["signals"]["metrics"]["failures_total"] == 1
        # top-level compatibility fields (worst-of aggregate)
        assert d["last_success_ts"] == 130.0
        assert d["failures_total"] == 2
        # The public audit tracks aggregate health only: metrics recovering
        # cannot claim recovery while logs remain degraded.
        assert events == ["otlp-export-degraded"]


class TestSampleExportsMetrics:
    def test_conflated_snapshot_exported(self):
        exported = []
        class _M:
            def export(self, points):
                exported.append(list(points))
                return True
        hub = telemetry.Telemetry(
            live_info=lambda: {
                "written_at": 100.0,        # fresh: aggregation runs for real
                "counters": {"samples_rejected_total": 0},
                "samples": {"d1": {"v": 1, "image_id": "img-1",
                                   "phase": "downloading", "done_bytes": 500,
                                   "down_bps": 5, "up_bps": 2, "peers": 1,
                                   "tier": "good", "received_at": 100.0,
                                   "effective_interval": 60}}},
            images_info=lambda: {"img-1": {"id": "img-1",
                                           "filename": "cat9k.bin",
                                           "size": 1000,
                                           "info_hash_hex": "aa11"}})
        hub.metrics_exporter = _M()
        hub.export_health = telemetry.ExportHealth()
        hub.sample(now=100.0)
        names = {p["name"] for p in exported[-1]}
        assert "iris.transfer.throughput" in names
        assert "iris.transfer.progress" in names
        assert "iris.telemetry.export.failures" in names
        assert not any(n.endswith("_total") for n in names)

    def test_quiet_fleet_still_exports_counters(self):
        exported = []
        class _M:
            def export(self, points):
                exported.append(list(points))
                return True
        hub = telemetry.Telemetry(
            live_info=lambda: {"written_at": 0, "counters":
                               {"samples_rejected_total": 9}, "samples": {}},
            images_info=lambda: {})
        hub.metrics_exporter = _M()
        hub.export_health = telemetry.ExportHealth()
        hub.sample(now=100.0)
        names = {p["name"] for p in exported[-1]}
        assert "iris.telemetry.samples.rejected" in names

    def test_seeder_torrent_upload_length_metrics_are_current_and_catalog_fenced(self):
        exported = []
        class _M:
            def export(self, points):
                exported.append(list(points))
                return True
        state = {"rows": [{"gid": "g1", "infoHash": "known",
                           "uploadLength": "1500"}], "fail": False}
        def rpc(method, params=None):
            if method == "aria2.getGlobalStat": return {"numActive": "1"}
            if method == "aria2.getSessionInfo": return {"sessionId": "s1"}
            if method == "aria2.tellActive":
                if state["fail"]: raise OSError("down")
                return state["rows"]
            if method == "aria2.getPeers": return []
            raise AssertionError(method)
        hub = telemetry.Telemetry(
            PeerRegistry(), rpc=rpc,
            images_info=lambda: {"img-1": {"filename": "cat9k.bin",
                                             "info_hash_hex": "known"}})
        hub.metrics_exporter = _M()
        hub.sample(now=100.0)
        points = [p for p in exported[-1]
                  if p["name"] == "iris.seeder.torrent.upload_length"]
        assert points == [{"name": "iris.seeder.torrent.upload_length",
                           "unit": "By", "kind": "gauge", "value": 1500,
                           "attrs": {"iris.image.id": "img-1",
                                     "iris.torrent.info_hash": "known"},
                           "ts": 100.0}]
        state["rows"] = [{"gid": "g2", "infoHash": "unknown",
                          "uploadLength": "9999"}]
        hub.sample(now=101.0)
        assert not [p for p in exported[-1]
                    if p["name"] == "iris.seeder.torrent.upload_length"]
        state["fail"] = True
        hub.sample(now=102.0)
        assert not [p for p in exported[-1]
                    if p["name"] == "iris.seeder.torrent.upload_length"]

    def test_seeder_torrent_upload_length_prometheus_omits_unknown_and_failed_polls(self):
        state = {"rows": [{"gid": "g1", "infoHash": "known",
                           "uploadLength": "1500"}], "fail": False}
        def rpc(method, params=None):
            if method == "aria2.getGlobalStat": return {"numActive": "1"}
            if method == "aria2.getSessionInfo": return {"sessionId": "s1"}
            if method == "aria2.tellActive":
                if state["fail"]: raise OSError("down")
                return state["rows"]
            if method == "aria2.getPeers": return []
            raise AssertionError(method)
        hub = telemetry.Telemetry(
            PeerRegistry(), rpc=rpc,
            images_info=lambda: {"img-1": {"filename": "cat9k.bin",
                                             "info_hash_hex": "known"}})
        hub.sample(now=100.0)
        text = metrics.render([], hub._seeder, {}, seeder_torrents=
                              hub._seeder_torrent_metrics(100.0))
        assert ('iris_seeder_torrent_upload_length_bytes{image="cat9k.bin",'
                'info_hash="known"} 1500' in text)
        state["rows"] = [{"gid": "g2", "infoHash": "unknown",
                          "uploadLength": "9999"}]
        hub.sample(now=101.0)
        assert "iris_seeder_torrent_upload_length_bytes" not in metrics.render(
            [], hub._seeder, {}, seeder_torrents=hub._seeder_torrent_metrics(101.0))
        state["fail"] = True
        hub.sample(now=102.0)
        assert "iris_seeder_torrent_upload_length_bytes" not in metrics.render(
            [], hub._seeder, {}, seeder_torrents=hub._seeder_torrent_metrics(102.0))


class TestReportExportEnrichment:
    def test_v1_report_emitted_as_safe_subset(self):
        # Task 23: a stored v1 report exports the safe subset only; model/flash
        # enrichment is no longer folded into the canonical report event.
        hub = telemetry.Telemetry(
            device_info=lambda: {"d1": {"swarm_ip": "10.0.0.2",
                                        "model": "C9300"}},
            reports_info=lambda: {"d1": [{"v": 1, "schema": "v1",
                                          "_event_id": "abc123",
                                          "image_id": "img-1",
                                          "event": "staging-complete",
                                          "received_at": 50.0,
                                          "peers": [{"ip": "10.0.0.2"}],
                                          "peers_total": 1}]})
        hub._export_new_reports()
        emitted = hub.log_queue.snapshot()
        rec = emitted[0]
        assert rec["eventName"] == "iris.device.report"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["iris.telemetry.schema.version"] == {"intValue": "1"}
        assert attrs["iris.image.id"] == {"stringValue": "img-1"}
        assert attrs["network.peer.address"]["arrayValue"]["values"][0] == \
            {"stringValue": "10.0.0.2"}
        assert "device.model.identifier" not in attrs

    def test_v2_report_emitted_as_transfer_report(self):
        hub = telemetry.Telemetry(
            reports_info=lambda: {"d1": [{"v": 2, "schema": "v2",
                                          "report_id": "a" * 32,
                                          "transfer_id": "b" * 32,
                                          "image_id": "img-1",
                                          "event": "staging-complete",
                                          "content": {
                                              "completed_content_bytes": 5},
                                          "content_sha256": {
                                              "state": "verified"},
                                          "received_at": 50.0}]})
        hub._export_new_reports()
        rec = hub.log_queue.snapshot()[0]
        assert rec["eventName"] == "iris.device.transfer.report"
        assert telemetry._otlp_record_event_id(rec) == "a" * 32


# ---- :9101 /swarm loopback gate (console-only swarm data by default) ----

class TestSwarmPeerGate:
    def test_predicate_loopback_allowed(self):
        for p in ("127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1",
                  "::ffff:127.0.0.1%lo0"):
            assert telemetry.swarm_peer_allowed(p, False), p

    def test_predicate_non_loopback_denied(self):
        for p in ("10.0.0.9", "192.168.1.5", "::ffff:10.0.0.9",
                  "2001:db8::1", "not-an-ip", ""):
            assert not telemetry.swarm_peer_allowed(p, False), p

    def test_predicate_public_flag_allows_anything(self):
        assert telemetry.swarm_peer_allowed("10.0.0.9", True)
        assert telemetry.swarm_peer_allowed("garbage", True)


class TestSwarmRouteGate:
    """The deny path is unreachable by a real client (any connection to a
    127.0.0.1-bound test server IS loopback), so these patch the predicate
    the route consults at request time (module-global resolution)."""

    def _server(self, swarm_public=False):
        return telemetry.make_metrics_server(
            "127.0.0.1", 0, lambda: "", swarm_provider=lambda: {"ok": 1},
            health=lambda: {"state": "off"}, swarm_public=swarm_public)

    def test_loopback_client_gets_swarm(self):
        srv = self._server()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", "/swarm")
            r = c.getresponse()
            assert r.status == 200 and b"ok" in r.read()
        finally:
            srv.shutdown()

    def test_non_loopback_client_gets_403_but_healthz_ok(self, monkeypatch):
        srv = self._server()
        monkeypatch.setattr(telemetry, "swarm_peer_allowed",
                            lambda peer, public: False)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", "/swarm")
            r = c.getresponse()
            body = r.read()
            assert r.status == 403
            assert b"console" in body               # self-describing
            c2 = http.client.HTTPConnection("127.0.0.1",
                                            srv.server_address[1], timeout=5)
            c2.request("GET", "/healthz")            # probes unaffected
            assert c2.getresponse().status == 200
        finally:
            srv.shutdown()

    def test_swarm_public_true_serves_any_peer(self, monkeypatch):
        srv = self._server(swarm_public=True)
        monkeypatch.setattr(telemetry, "swarm_peer_allowed",
                            lambda peer, public: public)  # only the flag saves it
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=5)
            c.request("GET", "/swarm")
            assert c.getresponse().status == 200
        finally:
            srv.shutdown()


# ---- editable telemetry destination (design 2026-08-19 feature B):
# the hub resolves (endpoint, enabled) per sample pass — console override
# file wins per field, else the deployment env captured at startup ----

def _dest_hub(tmp_path, monkeypatch, posts, env_endpoint="",
              env_enabled=False, headers=None):
    """A hub wired the way from_env wires it (DestinationSettings + captured
    env) whose REBUILT exporters record every POST into `posts` instead of
    touching the network. Exporters resolve otlp._http_post from the module
    at construction time (`sender or _http_post`), so patching the module
    global first is inherited by every exporter _refresh_exporters builds."""
    def fake_post(url, body, headers=None):
        posts.append((url, dict(headers or {})))
    monkeypatch.setattr(otlp, "_http_post", fake_post)
    path = telemetry_destination.settings_path(str(tmp_path))
    hub = telemetry.Telemetry(
        PeerRegistry(),
        dest_settings=telemetry_destination.DestinationSettings(path),
        env_endpoint=env_endpoint, env_enabled=env_enabled, headers=headers)
    return hub, path


class TestEditableDestination:
    def test_refresh_is_noop_without_destination_settings(self):
        # Direct construction (tests/standalone) keeps explicitly-passed
        # exporters untouched pass after pass — nothing regresses for the
        # dozens of existing hubs built without dest_settings.
        exp = otlp.OTLPLogExporter("http://c:4318", sender=lambda u, b: None)
        hub = telemetry.Telemetry(PeerRegistry(), exporter=exp)
        hub.sample()
        assert hub.exporter is exp

    def test_override_change_mid_run_swaps_exporter_url(
            self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True)
        hub.sample(now=100.0)
        assert hub.exporter.url == "http://env-collector:4318/v1/logs"
        assert posts[-1][0] == "http://env-collector:4318/v1/metrics"
        first_log_exporter = hub.exporter
        # console override lands mid-run: endpoint only (enabled inherits)
        telemetry_destination.write(path, "http://other:4318", None)
        os.utime(path, (200, 200))
        hub.sample(now=115.0)
        assert hub.exporter is not first_log_exporter   # rebuilt, not mutated
        assert hub.exporter.url == "http://other:4318/v1/logs"
        assert hub.metrics_exporter.url == "http://other:4318/v1/metrics"
        assert posts[-1][0] == "http://other:4318/v1/metrics"

    def test_override_disable_drops_exporters(self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True)
        hub.sample(now=100.0)
        assert hub.exporter is not None
        n = len(posts)
        telemetry_destination.write(path, None, False)
        os.utime(path, (200, 200))
        hub.sample(now=115.0)
        assert hub.exporter is None
        assert hub.metrics_exporter is None
        assert len(posts) == n          # disabled pass attempts no export

    def test_override_enables_export_when_env_off(
            self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts)  # env fully off
        hub.sample(now=100.0)
        assert hub.exporter is None and hub.metrics_exporter is None
        assert posts == []
        telemetry_destination.write(path, "http://console:4318", True)
        os.utime(path, (200, 200))
        hub.sample(now=115.0)
        assert hub.exporter.url == "http://console:4318/v1/logs"
        assert posts[-1][0] == "http://console:4318/v1/metrics"

    def test_override_removed_reverts_to_env_config(
            self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True)
        telemetry_destination.write(path, "http://other:4318", None)
        os.utime(path, (100, 100))
        hub.sample(now=100.0)
        assert hub.exporter.url == "http://other:4318/v1/logs"
        telemetry_destination.clear(path)   # "Revert to deployment default"
        hub.sample(now=115.0)
        assert hub.exporter.url == "http://env-collector:4318/v1/logs"
        assert posts[-1][0] == "http://env-collector:4318/v1/metrics"

    def test_headers_reapplied_to_rebuilt_exporters(
            self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True,
                              headers={"Authorization": "Bearer s3cr3t"})
        hub.sample(now=100.0)
        telemetry_destination.write(path, "http://other:4318", None)
        os.utime(path, (200, 200))
        hub.sample(now=115.0)               # exporter swap
        url, hdrs = posts[-1]
        assert url == "http://other:4318/v1/metrics"
        assert hdrs["Authorization"] == "Bearer s3cr3t"

    def test_export_health_survives_destination_swap(
            self, tmp_path, monkeypatch):
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True)
        # every POST fails -> health degrades on the first pass
        def boom(url, body, headers=None):
            raise RuntimeError("collector down")
        monkeypatch.setattr(otlp, "_http_post", boom)
        health = hub.export_health
        hub.sample(now=100.0)
        assert health.as_dict()["state"] == "degraded"
        fails = health.as_dict()["failures_total"]
        assert fails >= 1
        # destination changes while degraded: the SAME health object rides
        # along and the new endpoint gets a fresh chance on the next pass
        def ok_post(url, body, headers=None):
            posts.append((url, dict(headers or {})))
        monkeypatch.setattr(otlp, "_http_post", ok_post)
        telemetry_destination.write(path, "http://other:4318", None)
        os.utime(path, (200, 200))
        hub.sample(now=115.0)
        assert hub.export_health is health          # hub-owned, not rebuilt
        d = health.as_dict()
        assert d["state"] == "ok"                   # recovered on new dest
        assert d["failures_total"] == fails         # history preserved

    def test_memoization_skips_rebuild_without_config_change(
            self, tmp_path, monkeypatch):
        # The memoization line (if effective == self._effective: return) is
        # untested. If it were deleted, exporters would rebuild EVERY pass,
        # silently discarding each interval's queued announce events. This
        # test verifies that with a stable file override, exporters stay the
        # same object across two sample() passes, and a queued event between
        # passes still flushes.
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="http://env-collector:4318",
                              env_enabled=True)
        hub.sample(now=100.0)
        first_log_exporter = hub.exporter
        first_metrics_exporter = hub.metrics_exporter
        # console override lands and stays stable
        telemetry_destination.write(path, "http://console:4318", None)
        os.utime(path, (150, 150))
        hub.sample(now=115.0)          # config changes: rebuild
        console_log_exporter = hub.exporter
        console_metrics_exporter = hub.metrics_exporter
        assert console_log_exporter is not first_log_exporter
        assert console_metrics_exporter is not first_metrics_exporter
        # queue an event
        hub.on_swarm_event({"event": "join", "peer_id": "p1", "ts": 100.0})
        # same config (file unchanged): no rebuild
        hub.sample(now=130.0)
        assert hub.exporter is console_log_exporter
        assert hub.metrics_exporter is console_metrics_exporter
        # queued event flushed to the same exporter
        assert len(posts) >= 1 and posts[-1][0] == "http://console:4318/v1/metrics"

    def test_enabled_true_no_endpoint_keeps_exporters_none(
            self, tmp_path, monkeypatch):
        # Mismatch cell of the truth table: file enabled=True but no endpoint
        # anywhere (env empty) → exporters stay None after sample(). This is
        # gated after the endpoint check, so the code path can be skipped if
        # tests only exercise common cases.
        posts = []
        hub, path = _dest_hub(tmp_path, monkeypatch, posts,
                              env_endpoint="", env_enabled=False)
        hub.sample(now=100.0)
        assert hub.exporter is None and hub.metrics_exporter is None
        # console sets enabled=True but no endpoint
        telemetry_destination.write(path, None, True)
        os.utime(path, (150, 150))
        hub.sample(now=115.0)
        assert hub.exporter is None
        assert hub.metrics_exporter is None
        assert posts == []  # no export attempted


class TestFromEnvDestination:
    def test_from_env_always_builds_hub_and_wires_destination(self,
                                                              tmp_path):
        hub = telemetry.from_env({"IRIS_STATE": str(tmp_path)})
        assert hub.exporter is None            # env off, no override: inert
        assert hub._dest is not None
        assert hub._dest.path == \
            str(tmp_path / "telemetry-destination.json")
        assert hub._env_endpoint == "" and hub._env_enabled is False

    def test_from_env_captures_env_fields_and_builds_exporters(self,
                                                               tmp_path):
        hub = telemetry.from_env({
            "IRIS_STATE": str(tmp_path),
            "IRIS_OBSERVABILITY": "1",
            "IRIS_OTLP_ENDPOINT": "http://collector:4318",
            "IRIS_OTLP_HEADERS": "Authorization=Bearer x"})
        assert hub._env_endpoint == "http://collector:4318"
        assert hub._env_enabled is True
        assert hub._headers == {"Authorization": "Bearer x"}
        # initial exporters exist BEFORE start() so announce-path events are
        # captured from process start, as construction-time exporters were
        assert hub.exporter is not None
        assert hub.exporter.url == "http://collector:4318/v1/logs"
        assert hub.metrics_exporter.url == "http://collector:4318/v1/metrics"

    def test_from_env_file_override_enables_export_with_env_off(self,
                                                                tmp_path):
        path = telemetry_destination.settings_path(str(tmp_path))
        telemetry_destination.write(path, "http://console:4318", True)
        hub = telemetry.from_env({"IRIS_STATE": str(tmp_path)})
        assert hub.exporter is not None
        assert hub.exporter.url == "http://console:4318/v1/logs"

    def test_from_env_headers_read_even_when_env_gate_off(self, tmp_path):
        # enable-from-off via the console must still authenticate to the
        # collector: headers are captured regardless of the env gate.
        hub = telemetry.from_env({
            "IRIS_STATE": str(tmp_path),
            "IRIS_OTLP_HEADERS": "Authorization=Bearer x"})
        assert hub._headers == {"Authorization": "Bearer x"}
