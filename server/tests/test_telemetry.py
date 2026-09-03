# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import json
import os
import socket
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


def test_poll_seeder_reports_queued_torrents():
    # aria2 caps concurrent downloads, and a SEEDING torrent never completes,
    # so anything past that cap sits in the waiting queue forever -- never
    # served, never an error. That starvation wedged an IE-3400 in staging for
    # half an hour on 2026-08-31 with nothing logged anywhere. getGlobalStat
    # already carries numWaiting on every poll; surfacing it is what makes the
    # condition observable instead of silent.
    rpc = _fake_rpc(
        {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "5",
         "numWaiting": "1"},
        [{"connections": "0", "infoHash": "abc", "totalLength": "1",
          "files": [{"path": "/img/cat9k.bin"}]}])
    stats, _names, _totals = telemetry.poll_seeder(rpc)
    assert stats["queued_torrents"] == 1


def test_poll_seeder_queued_torrents_defaults_to_zero():
    # An aria2 build that omits numWaiting must read as "nothing starved",
    # never raise and never render a missing gauge.
    rpc = _fake_rpc(
        {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"},
        [{"connections": "0", "infoHash": "abc", "totalLength": "1",
          "files": [{"path": "/img/cat9k.bin"}]}])
    stats, _names, _totals = telemetry.poll_seeder(rpc)
    assert stats["queued_torrents"] == 0


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
    getPeers() list. Asserts the exact filtered key sets the truth model must
    send (never bitfield)."""
    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            return {"sessionId": session_id}
        if method == "aria2.tellActive":
            assert params and params[0] == ["gid", "infoHash", "uploadLength"]
            return active_gid()
        if method == "aria2.getPeers":
            assert params[1] == telemetry._PEER_KEYS
            return peers_by_gid.get(params[0], [])
        raise AssertionError(method)
    return rpc


def test_poll_seeder_peers_uses_filtered_keys_and_reports_session():
    # The poll fetches ip+port+uploadSpeed plus aria2-next's per-connection
    # cumulative `uploaded` and the measured `seeder` flag (never bitfield),
    # tellActive fetches only gid+infoHash+uploadLength, and the session id
    # comes from aria2.getSessionInfo so the caller can detect a counter epoch.
    def active_gid():
        return [{"gid": "g1", "infoHash": "abc", "uploadLength": "12345"}]
    peers = {"g1": [{"ip": "10.0.0.2", "port": "6882", "uploadSpeed": "500000",
                     "uploaded": "900", "seeder": "false"},
                    {"ip": "10.0.0.3", "port": "6883", "uploadSpeed": "0",
                     "uploaded": "12", "seeder": "true"}]}
    pu, upload_lengths, session_id, peer_bytes = telemetry.poll_seeder_peers(
        _peers_rpc(active_gid, peers, session_id="sess-1"))
    assert pu == {"abc": {("10.0.0.2", 6882): 500000,
                           ("10.0.0.3", 6883): 0}}
    assert upload_lengths == {"abc": 12345}
    assert session_id == "sess-1"
    # aria2 renders JSON-RPC booleans as strings; the flag is decoded, not
    # left as the truthy string "false".
    assert peer_bytes == {"abc": {
        ("10.0.0.2", 6882): {"uploaded": 900, "seeder": False},
        ("10.0.0.3", 6883): {"uploaded": 12, "seeder": True}}}


def test_poll_seeder_peers_session_absent_is_unknown_not_empty():
    # getSessionInfo may be unavailable (old aria2 / RPC blip). It used to
    # report that as "", which is a VALUE: the ledger compares session ids to
    # detect an aria2 restart, so an unlucky blip read as a new counter epoch,
    # banked every connection baseline, and made the next sample re-count each
    # live connection's full cumulative counter. Unknown must be None, which
    # the ledger leaves alone -- see
    # test_unknown_aria2_session_does_not_rebank_totals for the effect.
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
    pu, upload_lengths, session_id, peer_bytes = \
        telemetry.poll_seeder_peers(rpc)
    assert pu == {"abc": {("10.0.0.2", 6882): 7}}
    assert upload_lengths == {"abc": 10}
    assert session_id is None
    # An aria2 that answers getPeers without the byte keys is not an error;
    # it simply attributes nothing, and the residue says so.
    assert peer_bytes == {"abc": {("10.0.0.2", 6882): {"uploaded": 0,
                                                       "seeder": False}}}


def test_poll_seeder_peers_failed_control_state_poll_returns_nothing():
    # A failed tellActive must not let a caller present retained state as a
    # current observation: everything but the session id comes back None.
    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s9"}
        raise OSError("rpc down")
    assert telemetry.poll_seeder_peers(rpc) == (None, None, "s9", None)


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
            assert params[1] == telemetry._PEER_KEYS
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


# --- /readyz + listener probing ---

def _listening():
    """A real bound+listening loopback socket. Returns (sock, port).

    Backlog is generous because nothing here ever accept()s: each probe leaves
    its connection sitting in the queue, so a backlog of 1 would refuse the
    second probe and read as "down". A real service accepts and drains.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    return s, s.getsockname()[1]


def _dead_port():
    """A port with nothing on it: bind to get one free, then release it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_parse_health_listeners_blank_falls_back_to_default():
    default = {"tracker": 6969}
    assert telemetry.parse_health_listeners(None, default) == default
    assert telemetry.parse_health_listeners("", default) == default
    assert telemetry.parse_health_listeners("   ", default) == default
    # a copy, not the caller's dict -- a later edit must not mutate the default
    got = telemetry.parse_health_listeners(None, default)
    got["catalog"] = 8443
    assert default == {"tracker": 6969}


def test_parse_health_listeners_off_probes_nothing():
    # explicit opt-out for a deployment running a subset of the services:
    # {} is "check nothing", which is NOT the same as None -> default
    assert telemetry.parse_health_listeners("off", {"tracker": 6969}) == {}
    assert telemetry.parse_health_listeners("OFF", {"tracker": 6969}) == {}


def test_parse_health_listeners_parses_pairs_and_skips_malformed():
    # a malformed entry is ignored, not fatal: a typo in one env pair must not
    # take down probing for the listeners that DID parse
    got = telemetry.parse_health_listeners(
        "tracker:6969, catalog:8443 ,nope,bad:port,,artifacts:8000")
    assert got == {"tracker": 6969, "catalog": 8443, "artifacts": 8000}


def test_readyz_200_when_every_listener_is_up():
    sock, port = _listening()
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        listeners={"tracker": port})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/readyz")
        assert status == 200
        data = json.loads(body)
        assert data["ok"] is True
        assert data["listeners"] == {"tracker": "up"}
        assert "down" not in data
    finally:
        srv.shutdown()
        sock.close()


def test_readyz_503_names_the_listener_that_is_down():
    # the whole point of the endpoint: a dead sub-service must fail the probe
    # by STATUS CODE (/healthz stays 200 by contract), and say which one.
    sock, up_port = _listening()
    srv = telemetry.make_metrics_server(
        "127.0.0.1", 0, lambda: "",
        listeners={"tracker": up_port, "artifacts": _dead_port()})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/readyz")
        assert status == 503
        data = json.loads(body)
        assert data["ok"] is False
        assert data["down"] == ["artifacts"]
        assert data["listeners"] == {"artifacts": "down", "tracker": "up"}
    finally:
        srv.shutdown()
        sock.close()


def test_readyz_is_inert_until_a_deployment_declares_listeners():
    # listeners=None -> nothing probed, 200. Keeps the endpoint harmless for
    # a deployment that has not opted in.
    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/readyz")
        assert status == 200
        data = json.loads(body)
        assert data["ok"] is True
        assert "listeners" not in data
    finally:
        srv.shutdown()


def test_readyz_listeners_can_be_a_callable_read_per_request():
    # read per request, so a port learned after startup is still probed
    sock, port = _listening()
    calls = []

    def listeners():
        calls.append(1)
        return {"tracker": port}

    srv = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "",
                                        listeners=listeners)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for _ in range(2):
            assert _get(srv.server_address[1], "/readyz")[0] == 200
        assert len(calls) == 2
    finally:
        srv.shutdown()
        sock.close()


def test_healthz_reports_listeners_but_keeps_its_200_contract():
    # a down listener must NOT flip /healthz's status: container HEALTHCHECK
    # and existing orchestrator probes read that code (spec 7.7).
    srv = telemetry.make_metrics_server(
        "127.0.0.1", 0, lambda: "",
        listeners={"artifacts": _dead_port()})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _get(srv.server_address[1], "/healthz")
        assert status == 200
        assert json.loads(body)["listeners"] == {"artifacts": "down"}
    finally:
        srv.shutdown()


def test_probe_listeners_never_raises_on_a_nonsense_port():
    # called from a request handler: a failure to MEASURE must not become a
    # 500 that looks like a failure of the thing being measured
    assert telemetry._probe_listeners({"bogus": 0}) == {"bogus": "down"}
    assert telemetry._probe_listeners({"bogus": 999999}) == {"bogus": "down"}
    assert telemetry._probe_listeners({}) == {}
    assert telemetry._probe_listeners(None) == {}


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

    assert "esc(p.ip" in html and "esc(server().host" in html


def test_swarmmap_historical_participation_is_escaped_and_bytes_free():
    # link.rtt_ms_median is device-supplied. It is semantically a number, so
    html = _swarmmap_html()
    body = html.split("function reportRows")[1].split("async function refreshDrawerReport")[0]
    assert "esc(" in body and "rx_bytes" not in body and "tx_bytes" not in body


def test_swarmmap_dense_layout_is_multi_ring_and_suppresses_labels():
    html = _swarmmap_html()
    assert "DENSE_LABEL_THRESHOLD" in html and "function position(" in html
    assert "if(!dense)" in html


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
    assert 'const MAP=window.IRIS_MAP_CFG||{swarmUrl:"/swarm",pull:false}' in html
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
    assert "no device identity" in html.lower()


def test_swarmmap_pull_arrival_uses_server_clock():
    # The arrived-check must compare the SERVER-stamped received_at (same
    # clock domain as requested_at) — the device-stamped ts is fallback only.
    html = _swarmmap_html()
    body = html.split("async function requestPull")[1]
    assert "latest.received_at" in body


def test_swarmmap_historical_object_without_ip_is_safe():
    html = _swarmmap_html()
    assert 'x.ip||"unknown participant"' in html


def test_swarmmap_hub_uses_observed_global_rates():
    html = _swarmmap_html()
    body = html.split("function openHub")[1].split("async function requestPull")[0]
    assert "g.send_bps" in body and "g.receive_bps" in body


# ---------------------------------------------------------------------------
# Telemetry (#18): swarm-map leads with the CONSOLE device IP (device_id),
# participation-only per-peer drawer table (who was connected, no bytes),
# wider drawer panel.
# Same HTML-source guard style as the escapeHtml tests above.
# ---------------------------------------------------------------------------

def test_swarmmap_typed_label_and_secondary_ip():
    # A single helper decides the leading identity: the console device IP
    # (device_id) when known, else the raw announce/guest ip. It must be
    # referenced by the ring node label (render), the tooltip (showTip) and the
    # drawer title (openDrawer) so all three read one consistent identity.
    html = _swarmmap_html()
    assert "(p.device_id||\"Unknown participant\")" in html
    assert "Announce IP:" in html


def test_swarmmap_pull_fetches_full_reports():
    html = _swarmmap_html()
    assert '"/reports"' in html and "refreshDrawerReport" in html


def test_swarmmap_per_peer_table_is_participation_only():
    # Byte columns are gone BY DESIGN: per-peer rx/tx/avg were derived, not
    # measured (aria2 has no per-peer byte counters; the even-split fallback
    # fired on every multi-peer lab transfer). The drawer must not read any
    # per-peer byte field, and must render the exact peers_total count
    # number-gated (same stored-XSS discipline as rtt_ms_median).
    html = _swarmmap_html()
    body = html.split("function reportRows")[1].split("async function refreshDrawerReport")[0]
    assert "row.rx_bytes" not in body and "row.tx_bytes" not in body \
        and "row.avg_bps" not in body, \
        "per-peer byte fields are not measured and must not be rendered"
    assert "Historical participation" in body


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


def test_swarmmap_measured_edge_uses_canonical_producer_timestamp_fallback():
    # A peer observation may omit observed_at while it is produced in the same
    # server poll. In that case the canonical server observation timestamp is
    # the valid freshness clock; a peer timestamp still wins when supplied.
    html = _swarmmap_html()
    body = html.split("function freshServerPeer")[1].split("function position")[0]
    assert "x?.observed_at??obs().observed_at" in body
    assert "Number(x.send_bps)>0" in body
    assert "MEASURED_RATE_FRESH_S" in body


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
    for marker in ('role="status"', 'aria-live="polite"', 'role="dialog"',
                   'aria-modal="true"', 'drawer.addEventListener("keydown"',
                   'MAP_PAUSE', 'MAP_RESUME', 'DENSE_LABEL_THRESHOLD',
                   'function position(', 'global||{}', 'g.send_bps', 'g.receive_bps'):
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


def _rate_hub(peer_rows):
    """A hub whose seeder poll reports *peer_rows* from aria2.getPeers."""
    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "500000", "downloadSpeed": "0", "numActive": "1"}
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return [{"connections": "1", "infoHash": "abc",
                         "totalLength": "1000",
                         "files": [{"path": "/img/cat9k.bin"}]}]
            return [{"gid": "g1", "infoHash": "abc", "uploadLength": "1000"}]
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s0"}
        if method == "aria2.getPeers":
            return peer_rows
        raise AssertionError(method)
    return telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=10)


def test_measured_rate_survives_an_ephemeral_source_port():
    """aria2 reports the SOCKET endpoint. A leecher dials the seeder, so the
    port aria2 sees is the peer's ephemeral source port -- not the listen port
    it announced to the tracker. Keying the join on (ip, port) alone therefore
    drops the rate for every incoming connection, which is every normal
    transfer: no measured arrow ever renders."""
    import auth
    hub = _rate_hub([{"ip": "10.0.0.2", "port": "51422", "uploadSpeed": "4096"}])
    hub.sample()
    hub._registry.announce("abc", "l1", "10.0.0.2", 6881, left=500,
                           principal=auth.Principal("device", "d1"))
    p = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
         if x["ip"] == "10.0.0.2"][0]
    assert p["server_observation"]["peer"]["send_bps"] == 4096


def test_two_connections_from_one_address_are_marked_aggregated():
    """The (ip, port) key existed to stop two connections being silently summed
    into one row. Keep that honesty: when the address is ambiguous the row still
    carries a rate, but says it is a sum rather than one connection."""
    import auth
    hub = _rate_hub([{"ip": "10.0.0.9", "port": "51422", "uploadSpeed": "1000"},
                     {"ip": "10.0.0.9", "port": "51423", "uploadSpeed": "2000"}])
    hub.sample()
    hub._registry.announce("abc", "l2", "10.0.0.9", 6881, left=500,
                           principal=auth.Principal("device", "d2"))
    p = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
         if x["ip"] == "10.0.0.9"][0]
    peer = p["server_observation"]["peer"]
    assert peer["send_bps"] == 3000
    assert peer["aggregated_connections"] == 2


def test_exact_endpoint_match_is_preferred_and_not_marked_aggregated():
    """When aria2's endpoint matches the announced one exactly, use it verbatim."""
    import auth
    hub = _rate_hub([{"ip": "10.0.0.3", "port": "6881", "uploadSpeed": "777"}])
    hub.sample()
    hub._registry.announce("abc", "l3", "10.0.0.3", 6881, left=500,
                           principal=auth.Principal("device", "d3"))
    p = [x for x in hub.swarm_snapshot()["images"][0]["peers"]
         if x["ip"] == "10.0.0.3"][0]
    peer = p["server_observation"]["peer"]
    assert peer["send_bps"] == 777
    assert "aggregated_connections" not in peer


def test_peer_rate_record_carries_the_measured_edge():
    """Per-peer speed has to reach the backend as a LOG record: the release put
    device- and peer-labelled history in logs so it does not multiply metric
    cardinality. The record must name both ends of the edge and the measured
    rate, plus an image id so a dashboard can filter by rollout."""
    import otlp
    rec = otlp.build_peer_rate_record({
        "principal": "device:100.90.168.114", "info_hash": "abc",
        "image_id": "cat9k_iosxe.26.01.01", "ip": "100.92.100.2", "port": 6881,
        "send_bps": 8_000_000, "left": 512, "role": "leecher",
        "ts": 1787000000.0, "event_id": "e1"})
    attrs = {a["key"]: list(a["value"].values())[0] for a in rec["attributes"]}
    assert rec["eventName"] == "iris.swarm.peer_rate"
    assert attrs["iris.principal"] == "device:100.90.168.114"
    assert attrs["network.peer.address"] == "100.92.100.2"
    assert attrs["iris.image.id"] == "cat9k_iosxe.26.01.01"
    assert int(attrs["iris.transfer.peer_send_bps"]) == 8_000_000
    assert int(attrs["iris.torrent.left"]) == 512
    assert attrs["iris.peer.role"] == "leecher"


def test_sampler_emits_a_peer_rate_record_per_measured_edge():
    """End to end: a measured connection produces one peer_rate log record
    naming the typed principal, the image and the rate."""
    import auth
    emitted = []
    hub = _rate_hub([{"ip": "10.0.0.5", "port": "51999", "uploadSpeed": "2048"}])
    hub._registry.announce("abc", "lx", "10.0.0.5", 6881, left=900,
                           principal=auth.Principal("device", "dz"))
    hub.log_queue.emit = lambda rec, **kw: emitted.append(rec)
    hub.sample()
    rates = [r for r in emitted if r.get("eventName") == "iris.swarm.peer_rate"]
    assert len(rates) == 1, emitted
    a = {x["key"]: list(x["value"].values())[0] for x in rates[0]["attributes"]}
    assert a["iris.principal"] == "device:dz"
    assert int(a["iris.transfer.peer_send_bps"]) == 2048
    assert a["iris.peer.role"] == "leecher"


def test_seeder_torrent_upload_rate_is_exported_and_measured():
    """The device-reported iris.transfer.throughput cannot see a transfer that
    finishes inside one 60s agent tick -- and at lab speed a 929 MB image lands
    in 7-33s, so it reads a truthful zero taken outside the window. The origin
    measures its own send rate every poll, independent of any device tick;
    export that so a fast transfer is visible at all.

    It is a LOWER BOUND: device-to-device reseed traffic is invisible to the
    origin. That limit is documented, not papered over.
    """
    pts = telemetry._metric_points(
        [], {}, now=1000.0,
        seeder_torrents=[{"image_id": "img-1", "image": "img-1.bin",
                          "info_hash": "abc", "upload_length": 4096,
                          "upload_bps": 92_173_949}])
    by = {p["name"]: p for p in pts}
    assert "iris.seeder.torrent.upload_rate" in by, sorted(by)
    rate = by["iris.seeder.torrent.upload_rate"]
    assert rate["value"] == 92_173_949
    assert rate["unit"] == "By/s"
    assert rate["attrs"]["iris.image.id"] == "img-1"
    # low cardinality preserved: no device or peer label ever
    assert not any(k.startswith("device.") or "peer" in k
                   for k in rate["attrs"])


# --- durable origin -> peer attribution (peer ledger wiring) ---

def _swarm_hub(tmp_path, peers, torrent, session=None, devices=None):
    """A hub with a durable peer ledger whose aria2 double reads the MUTABLE
    `peers` (the getPeers reply) and `torrent` ({"uploadLength": n}) so a test
    can move the swarm between samples the way a real transfer does."""
    import peer_ledger
    session = session if session is not None else {"id": "s0"}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "1"}
        if method == "aria2.tellActive":
            keys = params[0] if params else []
            if "files" in keys:
                return [{"connections": str(len(peers)), "infoHash": "abc",
                         "totalLength": "1000",
                         "files": [{"path": "/img/cat9k.bin"}]}]
            return [{"gid": "g1", "infoHash": "abc",
                     "uploadLength": str(torrent["uploadLength"])}]
        if method == "aria2.getSessionInfo":
            return {"sessionId": session["id"]}
        if method == "aria2.getPeers":
            return [dict(row) for row in peers]
        raise AssertionError(method)
    return telemetry.Telemetry(
        PeerRegistry(), rpc=rpc, interval=10,
        peer_ledger=peer_ledger.PeerLedger(str(tmp_path)),
        device_info=(lambda: devices) if devices is not None else None)


def _peer(ip, port, uploaded, seeder="false"):
    return {"ip": ip, "port": port, "uploadSpeed": "1000",
            "uploaded": str(uploaded), "seeder": seeder}


def test_sampler_accumulates_per_peer_bytes_across_samples(tmp_path):
    """aria2's per-peer counter is per CONNECTION and disappears with the
    connection, so it has to be banked as observed. Two samples of a growing
    counter must leave the cumulative total, not the last reading."""
    peers = [_peer("10.0.0.2", "51422", 400)]
    torrent = {"uploadLength": 400}
    hub = _swarm_hub(tmp_path, peers, torrent)
    hub.sample()
    peers[0] = _peer("10.0.0.2", "51422", 900)
    torrent["uploadLength"] = 900
    hub.sample()
    assert hub.peer_ledger.totals("abc") == {"abc": {"10.0.0.2": 900}}
    totals = hub.peer_ledger_totals()["abc"]
    assert totals["origin_total"] == 900
    assert totals["attributed"] == 900
    assert totals["unattributed"] == 0
    assert totals["image_id"] == "cat9k.bin"


def test_bytes_sent_to_a_vanished_peer_become_visible_residue(tmp_path):
    """The measured capture rate is 88.1% at 2s sampling: the rest went to
    connections that opened and closed between two samples. Those bytes must
    surface as an explicit residue -- never be dropped, and never be spread
    across the peers we did see."""
    peers = [_peer("10.0.0.2", "51422", 400)]
    torrent = {"uploadLength": 400}
    hub = _swarm_hub(tmp_path, peers, torrent)
    hub.sample()
    peers[:] = []                       # peer hung up; its counter is gone
    torrent["uploadLength"] = 1000      # but the origin's total kept climbing
    hub.sample()
    totals = hub.peer_ledger_totals()["abc"]
    assert totals["attributed"] == 400  # what we watched, kept
    assert totals["origin_total"] == 1000
    assert totals["unattributed"] == 600
    assert hub.peer_ledger.unattributed("abc") == 600


def test_completed_transfer_keeps_totals_after_the_swarm_goes_idle(tmp_path):
    """The operator requirement: panels must not blank when nothing is
    transferring. The ledger is durable, so the totals outlive both the swarm
    and the hub that observed it."""
    import peer_ledger
    peers = [_peer("10.0.0.2", "51422", 900)]
    torrent = {"uploadLength": 900}
    hub = _swarm_hub(tmp_path, peers, torrent)
    hub.sample()
    peers[:] = []
    hub.sample()
    reread = peer_ledger.PeerLedger(str(tmp_path)).torrent_totals()
    assert reread["abc"]["attributed"] == 900
    assert reread["abc"]["peers_attributed"] == 1


def test_peer_bytes_record_names_the_device_and_the_measured_role(tmp_path):
    """End to end: an attributed edge produces one peer_bytes record carrying
    the running total, the delta that produced it, the device resolved through
    the heartbeat IP join, and the role aria2 MEASURED (isSeeder) -- not a role
    guessed from progress."""
    peers = [_peer("10.0.0.2", "51422", 400, seeder="true")]
    torrent = {"uploadLength": 400}
    hub = _swarm_hub(tmp_path, peers, torrent,
                     devices={"rtr-04": {"swarm_ip": "10.0.0.2"}})
    hub.sample()
    emitted = []
    hub.log_queue.emit = lambda rec, **kw: emitted.append(rec)
    peers[0] = _peer("10.0.0.2", "51422", 700, seeder="true")
    torrent["uploadLength"] = 700
    hub.sample()
    rows = [r for r in emitted
            if r.get("eventName") == "iris.swarm.peer_bytes"]
    assert len(rows) == 1, emitted
    a = {x["key"]: list(x["value"].values())[0] for x in rows[0]["attributes"]}
    assert a["network.peer.address"] == "10.0.0.2"
    assert a["iris.device.id"] == "rtr-04"
    assert a["iris.image.id"] == "cat9k.bin"
    assert a["iris.peer.role"] == "seeder"
    assert int(a["iris.transfer.peer_sent_bytes"]) == 700
    assert int(a["iris.transfer.peer_sent_delta_bytes"]) == 300


def test_no_record_is_emitted_for_a_peer_that_gained_nothing(tmp_path):
    """A cumulative value that has not moved says nothing new; re-emitting it
    every 2s would only inflate the log stream."""
    peers = [_peer("10.0.0.2", "51422", 400)]
    hub = _swarm_hub(tmp_path, peers, {"uploadLength": 400})
    hub.sample()
    emitted = []
    hub.log_queue.emit = lambda rec, **kw: emitted.append(rec)
    hub.sample()                        # same counter, same sample
    assert [r for r in emitted
            if r.get("eventName") == "iris.swarm.peer_bytes"] == []


def test_an_aria2_restart_keeps_the_totals_it_already_banked(tmp_path):
    """A new session id invalidates every baseline, not the history: the
    counters restart at zero and are counted in full from there, while what
    was already attributed stays attributed."""
    peers = [_peer("10.0.0.2", "51422", 500)]
    torrent, session = {"uploadLength": 500}, {"id": "s0"}
    hub = _swarm_hub(tmp_path, peers, torrent, session=session)
    hub.sample()
    session["id"] = "s1"                # aria2 restarted
    peers[0] = _peer("10.0.0.2", "51422", 120)
    torrent["uploadLength"] = 120
    hub.sample()
    assert hub.peer_ledger.totals("abc") == {"abc": {"10.0.0.2": 620}}
    assert hub.peer_ledger_totals()["abc"]["origin_total"] == 620
    peers[0] = _peer("10.0.0.2", "51422", 200)
    torrent["uploadLength"] = 200
    hub.sample()
    assert hub.peer_ledger.totals("abc") == {"abc": {"10.0.0.2": 700}}
    assert hub.peer_ledger_totals()["abc"]["origin_total"] == 700


def test_a_failed_control_state_poll_attributes_nothing(tmp_path):
    """A poll that failed is not an observation of zero; nothing may be banked
    from it."""
    import peer_ledger

    def rpc(method, params=None):
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s0"}
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "0", "downloadSpeed": "0", "numActive": "0"}
        raise OSError("rpc down")
    hub = telemetry.Telemetry(
        PeerRegistry(), rpc=rpc, interval=10,
        peer_ledger=peer_ledger.PeerLedger(str(tmp_path)))
    hub.sample()
    assert hub.peer_ledger_totals() == {}


def test_hub_without_a_ledger_still_samples(tmp_path):
    """Tests and standalone runs wire no ledger; the poll must not care."""
    hub = _swarm_hub(tmp_path, [_peer("10.0.0.2", "51422", 5)],
                     {"uploadLength": 5})
    hub.peer_ledger = None
    hub.sample()
    assert hub.peer_ledger_totals() == {}
    assert hub._peer_up == {"abc": {("10.0.0.2", 51422): 1000}}


def test_sample_interval_is_fast_only_while_a_connection_is_live(tmp_path):
    """The sample rate IS the attribution rate (73.3% at 3s, 88.1% at 2s), so
    poll fast while anything is connected -- and stop spinning when the swarm
    is idle and there is nothing left to miss."""
    peers = [_peer("10.0.0.2", "51422", 5)]
    hub = _swarm_hub(tmp_path, peers, {"uploadLength": 5})
    assert hub._sample_interval() == 10         # nothing polled yet
    hub.sample()
    assert hub._sample_interval() == telemetry.ACTIVE_INTERVAL
    peers[:] = []
    hub.sample()
    assert hub._sample_interval() == 10


def test_active_cadence_never_slows_a_faster_configured_interval(tmp_path):
    """ACTIVE_INTERVAL is a ceiling on laziness, not a floor: an operator who
    configured a 1s interval keeps it."""
    hub = _swarm_hub(tmp_path, [_peer("10.0.0.2", "51422", 5)],
                     {"uploadLength": 5})
    hub.interval = 1
    hub.sample()
    assert hub._sample_interval() == 1


def test_fast_pass_polls_aria2_without_re_running_the_export_stages(tmp_path):
    """Only the aria2 poll runs on the fast cadence. Export cadence is
    deliberately unchanged: the collector should not see 7x the pushes just
    because the per-connection counters need watching."""
    peers = [_peer("10.0.0.2", "51422", 400)]
    hub = _swarm_hub(tmp_path, peers, {"uploadLength": 400})
    exports = []
    hub.metrics_exporter = type("E", (), {
        "export": lambda _self, points: exports.append(points) or True})()
    hub.sample_seeder()
    assert exports == []
    assert hub.peer_ledger.totals("abc") == {"abc": {"10.0.0.2": 400}}
    hub.sample()
    assert len(exports) == 1


# --- regressions the first cut of this feature shipped with -----------------

def test_metrics_endpoint_exports_the_ledger_families(tmp_path):
    """The four aggregate families must reach /metrics, not merely exist in
    render().

    They did not. metrics_text() called metrics.render() without swarm_bytes=,
    so the entire ledger block was dead at runtime and every aggregate panel on
    both dashboards was empty -- including the template-variable dropdowns that
    gate the rest of the board. It passed CI because test_metrics.py calls
    render() directly with a hand-built argument, and nothing exercised the
    endpoint. This test does."""
    peers = [_peer("10.0.0.2", 6881, 900)]
    torrent = {"uploadLength": "1500"}
    hub = _swarm_hub(tmp_path, peers, torrent)
    hub.sample()

    text = hub.metrics_text()

    for family in ("iris_origin_sent_bytes_total",
                   "iris_peer_attributed_bytes_total",
                   "iris_peer_unattributed_bytes_total",
                   "iris_swarm_peers_attributed"):
        assert family in text, "%s never reaches /metrics" % family
    # and it carries the real value, not just the HELP line
    assert "iris_peer_attributed_bytes_total{" in text
    assert "900" in text


def test_unknown_aria2_session_does_not_rebank_totals(tmp_path):
    """A getSessionInfo failure must not read as an aria2 restart.

    poll_seeder_peers used to swallow the exception and return session_id="",
    and the ledger treats ANY change of session id as a new counter epoch: it
    banks every connection baseline, so the next sample counts each live
    connection's full cumulative value again. One transient RPC hiccup
    therefore inflated every peer's durable total. Sampling an UNCHANGED
    connection across a probe failure must leave the total exactly where it
    was."""
    peers = [_peer("10.0.0.2", 6881, 1000)]
    torrent = {"uploadLength": "1000"}
    session = {"id": "sessA"}
    hub = _swarm_hub(tmp_path, peers, torrent, session=session)

    hub.sample()                       # first sight: banks 1000
    hub.sample()                       # unchanged: banks nothing
    session["id"] = None               # the probe fails -> unknown epoch
    hub.sample()
    session["id"] = "sessA"            # probe recovers, same aria2
    hub.sample()

    assert hub.peer_ledger.totals("abc") == {"abc": {"10.0.0.2": 1000}}, \
        "a transient session probe failure re-banked the connection"


# ---------------------------------------------------------------------------
# peer_transfer_records attribution: WHO sent the measured bytes
#
# The device measures exact bytes per BitTorrent peer and makes no claim about
# which peer was the origin -- it cannot: the origin seeder is an ordinary peer
# of every device and sits in aria2.getPeers like any other. Only the server
# knows, from the authenticated service:seeder principal. These tests pin that
# split, because getting it wrong reports a wave that was 28.9% peer-delivered
# as ~100%.
# ---------------------------------------------------------------------------

_ORIGIN_IP = "100.90.168.20"


def _transfer_record_row(ip, got, **extra):
    row = {"ip": ip, "session_bytes_from_peer": got,
           "session_bytes_to_peer": 0}
    row.update(extra)
    return row


def _transfer_record_block(rows, rows_omitted=0, bytes_omitted=0, complete=True):
    return {"source": "aria2_session_counters", "captured_at": 100.0,
            "complete": complete, "rows": list(rows),
            "rows_total": len(rows) + rows_omitted,
            "rows_omitted": rows_omitted,
            "bytes_from_all_senders_total": bytes_omitted + sum(
                r["session_bytes_from_peer"] for r in rows),
            "bytes_from_all_senders_omitted": bytes_omitted}


def test_origin_bytes_are_not_counted_as_peer_bytes():
    """The blocker this split exists for: the origin's row is in the device's
    own transfer records, so the device-side total includes it. Reporting that total as
    'from peers' turned a 28.9% peer-delivered wave into ~100%."""
    block = _transfer_record_block([_transfer_record_row(_ORIGIN_IP, 7110),
                            _transfer_record_row("10.0.0.7", 2890)])
    split = telemetry.classify_peer_transfer_records(
        block, {_ORIGIN_IP}, {"10.0.0.7": "rtr-07"})
    assert split["origin_rows"] == 1 and split["origin_bytes"] == 7110
    assert split["device_rows"] == 1 and split["device_bytes"] == 2890
    assert split["unknown_rows"] == 0 and split["unknown_bytes"] == 0
    # The device-side total is all senders together, origin included; the
    # peer-delivered figure is device_bytes and nothing else.
    assert split["bytes_from_all_senders_total"] == 10000
    assert split["device_bytes"] != split["bytes_from_all_senders_total"]


def test_a_device_that_became_a_seeder_is_still_a_device():
    """aria2's has_complete_file is true for ANY peer holding the whole file,
    so in a wave every device that finishes early raises it. Identity decides
    the class, never the flag."""
    block = _transfer_record_block([
        _transfer_record_row("10.0.0.7", 500, has_complete_file=True),
        _transfer_record_row(_ORIGIN_IP, 100, has_complete_file=True)])
    split = telemetry.classify_peer_transfer_records(
        block, {_ORIGIN_IP}, {"10.0.0.7": "rtr-07"})
    assert split["device_bytes"] == 500 and split["device_rows"] == 1
    assert split["origin_bytes"] == 100
    assert telemetry.transfer_record_source_class(
        "10.0.0.7", {_ORIGIN_IP}, {"10.0.0.7": "rtr-07"}) == "device"


def test_an_unresolvable_address_is_unknown_not_a_peer():
    """A third bucket, always. An address that is neither the origin nor a
    known device is UNKNOWN; folding it into either side would invent the
    attribution."""
    block = _transfer_record_block([_transfer_record_row("198.51.100.9", 4096)])
    split = telemetry.classify_peer_transfer_records(block, {_ORIGIN_IP}, {})
    assert split["unknown_rows"] == 1 and split["unknown_bytes"] == 4096
    assert split["device_bytes"] == 0 and split["origin_bytes"] == 0


def test_no_known_origin_leaves_rows_unknown_rather_than_peer_delivered():
    """An unreadable/empty registry must not promote the origin's bytes to
    peer-delivered: with no origin address known, an unjoinable row is
    unknown."""
    split = telemetry.classify_peer_transfer_records(
        _transfer_record_block([_transfer_record_row(_ORIGIN_IP, 9000)]), set(), {})
    assert split["unknown_bytes"] == 9000 and split["device_bytes"] == 0


def test_an_address_claimed_by_both_origin_and_device_is_unknown():
    """Two identity claims on one address cannot both be the sender, so we
    assert neither."""
    assert telemetry.transfer_record_source_class(
        _ORIGIN_IP, {_ORIGIN_IP}, {_ORIGIN_IP: "rtr-07"}) == "unknown"


def test_omitted_mass_is_reported_apart_and_never_redistributed():
    """Bytes from rows a cap dropped are real and measured, but no address
    survives to classify them. They get their own figure -- spreading them
    across the named buckets pro rata is the even-split fabrication that was
    removed in 2026.08.20."""
    block = _transfer_record_block([_transfer_record_row("10.0.0.7", 1000)],
                           rows_omitted=3, bytes_omitted=750)
    split = telemetry.classify_peer_transfer_records(
        block, {_ORIGIN_IP}, {"10.0.0.7": "rtr-07"})
    assert split["unattributed_omitted_rows"] == 3
    assert split["unattributed_omitted_bytes"] == 750
    assert split["device_bytes"] == 1000
    assert (split["origin_bytes"] + split["device_bytes"]
            + split["unknown_bytes"] + split["unattributed_omitted_bytes"]
            == split["bytes_from_all_senders_total"] == 1750)


def test_a_partial_capture_is_flagged_so_no_share_is_computed_blind():
    block = _transfer_record_block([_transfer_record_row("10.0.0.7", 10)], complete=False)
    split = telemetry.classify_peer_transfer_records(block, set(), {})
    assert split["capture_complete"] is False


def test_no_transfer_records_block_classifies_to_nothing_not_to_zero():
    """Absent means NOT MEASURED. An all-zero split would read as 'no peer
    bytes', which is a different, false claim."""
    assert telemetry.classify_peer_transfer_records(None, {_ORIGIN_IP}, {}) is None
    assert telemetry.classify_peer_transfer_records(7, {_ORIGIN_IP}, {}) is None


def test_origin_addresses_come_from_the_service_seeder_principal():
    """Identity, not an address list: the origin is whoever announced as the
    typed service:seeder principal. A device sharing the literal peer name
    'seeder' is a different principal and must not be mistaken for it."""
    import auth
    reg = PeerRegistry()
    reg.announce("abc", "seeder", _ORIGIN_IP, 6881, left=0,
                 principal=auth.Principal("service", "seeder"))
    reg.announce("abc", "p2", "10.0.0.7", 6881, left=0,
                 principal=auth.Principal("device", "seeder"))
    hub = telemetry.Telemetry(reg)
    assert hub._origin_swarm_ips() == {_ORIGIN_IP}


def test_an_unreadable_registry_yields_no_origin_rather_than_a_guess():
    class Boom:
        def snapshot(self, now=None):
            raise RuntimeError("registry down")
    hub = telemetry.Telemetry(PeerRegistry())
    hub._registry = Boom()
    assert hub._origin_swarm_ips() == set()


def test_export_attaches_attribution_to_the_report_that_carries_it(monkeypatch):
    """The split rides with the report it describes: a later report with no
    transfer records must not inherit the previous report's attribution."""
    import auth
    reg = PeerRegistry()
    reg.announce("abc", "seeder", _ORIGIN_IP, 6881, left=0,
                 principal=auth.Principal("service", "seeder"))
    with_transfer_records = {"schema": "v2", "report_id": "r1", "received_at": 1,
                     "peer_transfer_records": _transfer_record_block(
                         [_transfer_record_row(_ORIGIN_IP, 700),
                          _transfer_record_row("10.0.0.7", 300)])}
    without = {"schema": "v2", "report_id": "r2", "received_at": 2}
    hub = telemetry.Telemetry(
        reg,
        device_info=lambda: {"rtr-07": {"swarm_ip": "10.0.0.7"}},
        reports_info=lambda: {"rtr-07": [with_transfer_records, without]})
    seen = []
    real = otlp.build_report_record

    def spy(report, device_id, enrich=None):
        seen.append((report.get("report_id"), enrich))
        return real(report, device_id, enrich=enrich)

    monkeypatch.setattr(telemetry.otlp, "build_report_record", spy)
    hub._export_new_reports()
    by_id = dict(seen)
    # peer_origin_ips used to ride along here and was read by nobody -- the
    # tell that the per-peer fanout had never been wired. The origin addresses
    # are bound into the classify callback at the emit site instead; what the
    # report record carries is the SPLIT, asserted below.
    assert "peer_origin_ips" not in by_id["r1"]
    assert by_id["r1"]["peer_transfer_record_attribution"]["origin_bytes"] == 700
    assert by_id["r1"]["peer_transfer_record_attribution"]["device_bytes"] == 300
    assert "peer_transfer_record_attribution" not in by_id["r2"]


def test_peer_transfer_records_reach_the_log_queue_not_just_the_catalog():
    """The exact device-side measurement must LEAVE the server.

    build_peer_transfer_records existed in otlp.py and nothing called it: the
    export pipeline emitted only the report record, so iris.device.peer_transfer_record
    did not exist at runtime and the per-peer rows stopped in the catalog --
    while the LOSSY sampled estimate (iris.swarm.peer_bytes) was exported
    happily. The better number was the hidden one. Test the pipeline, not the
    builder: an otlp.py unit test passes either way."""
    report = _stored_report()
    report["peer_transfer_records"] = {
        "source": "aria2_session_counters", "captured_at": 150.0,
        "complete": True, "rows_total": 2, "rows_omitted": 0,
        "bytes_from_all_senders_total": 300,
        "bytes_from_all_senders_omitted": 0,
        "rows": [
            # the origin seeder -- must NOT be presented as a peer
            {"ip": "10.9.9.9", "port": 6881, "session_bytes_from_peer": 200,
             "session_bytes_to_peer": 0, "has_complete_file": True},
            # another device
            {"ip": "10.0.0.7", "port": 6881, "session_bytes_from_peer": 100,
             "session_bytes_to_peer": 0, "has_complete_file": False},
        ]}
    hub = telemetry.Telemetry(
        PeerRegistry(), reports_info=lambda: {"d1": [report]},
        # swarm_ip, not device_ip: _device_by_ip deliberately refuses to join
        # a peer on the management address ("matched on something weaker")
        device_info=lambda: {"d7": {"swarm_ip": "10.0.0.7"}})
    hub._origin_swarm_ips = lambda: {"10.9.9.9"}

    hub._export_new_reports()

    def log_name(record):
        for attr in record.get("attributes") or []:
            if attr.get("key") == "otel.log.name":
                return attr["value"].get("stringValue")
        return None

    names = [log_name(r) for r in hub.log_queue.snapshot()]
    assert "iris.device.peer_transfer_record" in names, \
        "the exact per-peer measurement never left the server"
    assert names.count("iris.device.peer_transfer_record") == 2, names

    # and each row carries its sender class, with the origin called the origin
    classes = {}
    for record in hub.log_queue.snapshot():
        if log_name(record) != "iris.device.peer_transfer_record":
            continue
        attrs = {a["key"]: a["value"] for a in record["attributes"]}
        ip = attrs["network.peer.address"]["stringValue"]
        classes[ip] = attrs["iris.peer.attribution"]["stringValue"]
    assert classes == {"10.9.9.9": "origin", "10.0.0.7": "device"}, classes


def test_image_size_family_reaches_the_metrics_endpoint(tmp_path):
    """iris_image_size_bytes must reach /metrics, tested at the ENDPOINT.

    Both dashboards ship panels that deliberately read "no data" until this
    family exists, refusing a hardcoded size constant. Twice in this feature's
    history a family existed in render() and never reached the endpoint because
    a caller argument was missing and only render() was unit-tested -- so this
    asserts through metrics_text(), not render()."""
    hub = telemetry.Telemetry(
        PeerRegistry(),
        images_info=lambda: {
            "cat9k": {"filename": "cat9k.bin", "info_hash_hex": "ab" * 20,
                      "size": 973065200},
            # no info_hash yet (publish in progress): must be skipped, not guessed
            "half": {"filename": "half.bin", "size": 5},
        })
    text = hub.metrics_text()
    assert "iris_image_size_bytes" in text
    assert ('iris_image_size_bytes{image="cat9k.bin",info_hash="%s"} 973065200'
            % ("ab" * 20)) in text
    assert "half.bin" not in text


# ---------------------------------------------------------------------------
# iris.transfer.lifecycle -- the server-side planned -> seeding_started events.
#
# Tested through Telemetry.sample(), never through
# otlp.build_transfer_lifecycle_record directly: a builder unit test passes
# whether or not anything calls the builder, which is exactly how
# iris.device.peer_transfer_record came to exist in otlp.py and never leave the
# server (see test_peer_transfer_records_reach_the_log_queue_not_just_the_catalog).
# Records are counted off hub.log_queue by their otel.log.name attribute --
# what a backend actually indexes on -- so a record that never reaches the
# queue fails the assertion instead of hiding behind a green builder test.
#
# The imports sit here rather than at the top of the file so this section is a
# pure APPEND: nothing above it is touched, and in particular the existing
# exact-shape assertions stay the regression guard they were written to be.
import auth
import transfer_lifecycle

_LIFECYCLE_NAME = "iris.transfer.lifecycle"
_REPORT_NAME = "iris.device.transfer.report"
_LC_DEVICE = "iris8kv-1"
_LC_IMAGE = "cat9k"
_LC_INFO_HASH = "ab" * 20
_LC_IMAGES = {_LC_IMAGE: {"filename": "cat9k.bin",
                          "info_hash_hex": _LC_INFO_HASH,
                          "size": 973065200}}
_LC_PLANNED_AT = 1000.0

# sample() reaches the EMISSION stage only when an exporter is wired
# (`self.exporter is not None`); the LATCH deliberately runs regardless, which
# is what test_facts_latch_with_the_exporter_disabled_and_emit_after_it_is_turned_on
# pins. A bare sentinel is enough to open that gate: with no _log_transport the
# queue is never flushed, so the records stay inspectable in
# hub.log_queue.snapshot() instead of disappearing into a sender.
_EXPORT_ON = object()


def _lc_id(n):
    """A 32-lowercase-hex id. The shape is load-bearing, not cosmetic: the
    device echoes transfer_id back on every report and both ingest paths
    re-validate it against that pattern, so live_plans_from_policy drops a plan
    whose ids are any other shape -- a test id like "plan-1" would silently
    test nothing."""
    return "%032x" % n


def _lc_plan_row(plan_id, transfer_id, planned_at=_LC_PLANNED_AT,
                 info_hash=_LC_INFO_HASH):
    return {"plan_id": plan_id, "transfer_id": transfer_id,
            "planned_at": planned_at, "info_hash": info_hash}


def _lc_policy(plan_id, transfer_id, device_id=_LC_DEVICE, image_id=_LC_IMAGE,
               **plan_row):
    """policy.json exactly as CatalogStore.set_policy writes it: the two
    pre-existing assignment keys plus the per-image `plans` map that carries
    the minted identity."""
    return {device_id: {"approved_image_id": image_id,
                        "approved_image_ids": [image_id],
                        "plans": {image_id: _lc_plan_row(plan_id, transfer_id,
                                                         **plan_row)}}}


def _lc_report(transfer_id, received_at=1200.0, image_id=_LC_IMAGE,
               event="staging-complete", sha_state="verified",
               window_end=None, report_id=None):
    """One stored v2 terminal report in the shape the catalog's telemetry.json
    ring holds. `received_at` is the SERVER clock stamp -- the instant the
    checksum attestation reached this container -- which is what the store
    latches; `window.end` is the DEVICE's own clock and only ever rides as an
    attribute."""
    report = {"schema": "v2",
              "report_id": report_id or ("rep-%s" % transfer_id[-6:]),
              "image_id": image_id, "transfer_id": transfer_id,
              "event": event,
              "content_sha256": {"algo": "sha256", "state": sha_state},
              "received_at": received_at}
    if window_end is not None:
        report["window"] = {"end": window_end}
    return report


def _lc_hub(tmp_path, policy, reports=None, images=None, exporting=True):
    """A tracker hub wired exactly as from_env() wires the real one: a real
    PeerRegistry, a real TransferLifecycle over a real state dir, and the two
    plain-data callables. Returns (hub, store) so a test can assert both what
    reached the wire and what was durably latched behind it."""
    store = transfer_lifecycle.TransferLifecycle(str(tmp_path))
    hub = telemetry.Telemetry(
        PeerRegistry(),
        reports_info=lambda: reports if reports is not None else {},
        images_info=lambda: images if images is not None else _LC_IMAGES,
        assignments_info=lambda: policy,
        transfer_lifecycle=store)
    if exporting:
        hub.exporter = _EXPORT_ON
    return hub, store


def _lc_announce(hub, now, device_id=_LC_DEVICE, info_hash=_LC_INFO_HASH,
                 left=0, peer_id="p1", ip="10.0.0.2"):
    """The device's aria2 announcing on its personalised token. The typed
    principal IS the authenticated join -- principal_id is the catalog's own
    device id -- so this is the same identity path the tracker sees in
    production, not an address match."""
    hub._registry.announce(info_hash, peer_id, ip, 6881, left=left, now=now,
                           principal=auth.Principal("device", device_id))


def _lc_attrs(record):
    return {a["key"]: a["value"] for a in record.get("attributes") or []}


def _lc_log_name(record):
    return (_lc_attrs(record).get("otel.log.name") or {}).get("stringValue")


def _lc_records(hub, name=_LIFECYCLE_NAME):
    return [r for r in hub.log_queue.snapshot() if _lc_log_name(r) == name]


def _lc_events(hub):
    """[(event, plan_id), ...] for every lifecycle record, in queue order."""
    out = []
    for record in _lc_records(hub):
        attrs = _lc_attrs(record)
        out.append((attrs["event"]["stringValue"],
                    attrs["iris.plan.id"]["stringValue"]))
    return out


def _lc_event_ids(hub):
    return [_lc_attrs(r)["event.id"]["stringValue"] for r in _lc_records(hub)]


def test_planned_reaches_the_log_queue_for_every_live_plan(tmp_path):
    """Every assignment the catalog minted becomes exactly one `planned` event,
    carrying the identity that was minted with it. The ids are asserted on the
    RECORD, not on the store, because the whole point of the plan living in
    policy.json is that the same transfer_id the device adopted is the one the
    backend can join on."""
    policy = _lc_policy(_lc_id(1), _lc_id(2))
    policy["iris8kv-2"] = {
        "approved_image_id": _LC_IMAGE,
        "approved_image_ids": [_LC_IMAGE],
        "plans": {_LC_IMAGE: _lc_plan_row(_lc_id(3), _lc_id(4))}}
    hub, _store = _lc_hub(tmp_path, policy)

    hub.sample(now=1100.0)

    assert _lc_events(hub) == [("planned", _lc_id(1)), ("planned", _lc_id(3))]
    attrs = _lc_attrs(_lc_records(hub)[0])
    assert attrs["iris.transfer.id"]["stringValue"] == _lc_id(2)
    assert attrs["iris.device.id"]["stringValue"] == _LC_DEVICE
    assert attrs["device.id"]["stringValue"] == _LC_DEVICE
    assert attrs["iris.image.id"]["stringValue"] == _LC_IMAGE
    assert attrs["iris.torrent.info_hash"]["stringValue"] == _LC_INFO_HASH
    # The decision instant is the policy row's own planned_at, never the pass
    # that first noticed it: the assignment happened when it was written.
    assert _lc_records(hub)[0]["timeUnixNano"] == str(int(_LC_PLANNED_AT * 1e9))


def test_seeding_started_reaches_the_log_queue_when_all_three_preconditions_hold(
        tmp_path):
    """Complete content, a verified checksum, and this tracker seeing the
    device itself announce left=0 -- only the conjunction publishes a seeding
    event, and only the tracker can see all three at once."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0,
                                       window_end=1190.0)]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    _lc_announce(hub, now=1150.0)

    hub.sample(now=1150.0)

    assert _lc_events(hub) == [("planned", plan), ("seeding_started", plan)]
    row = store.get(plan)
    assert row["state"] == "seeding"
    # The instant the LAST precondition became true. aria2 announced left=0 at
    # 1150 but the device's sha256 did not attest until 1200, so 1200 is the
    # honest answer -- not the earlier, unverified one.
    assert row["seeding_started_at"] == 1200.0
    record = _lc_records(hub)[1]
    assert record["timeUnixNano"] == str(int(1200.0 * 1e9))
    attrs = _lc_attrs(record)
    assert attrs["iris.transfer.seeding_started_at"]["stringValue"] \
        == "1970-01-01T00:20:00.000Z"
    # Both preconditions ride separately so an operator can see WHICH one was
    # the laggard rather than inferring it.
    assert attrs["iris.transfer.checksum_verified_at"]["stringValue"] \
        == "1970-01-01T00:20:00.000Z"
    assert attrs["iris.transfer.tracker_seeder_at"]["stringValue"] \
        == "1970-01-01T00:19:10.000Z"
    # The device's own clock, kept as a float epoch and never subtracted from
    # the server instants above.
    assert attrs["iris.device.observed_at"]["doubleValue"] == 1190.0


def test_planned_is_emitted_before_seeding_started_for_the_same_plan(tmp_path):
    """A backend must never see a transfer start before it was planned, even
    when both facts are already true on the first pass that ever looks. The two
    records must also carry DIFFERENT event.ids: LogQueue.emit refuses a key
    already queued or in flight, so a shared id would drop the second record
    silently rather than fail loudly."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    hub, _store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    _lc_announce(hub, now=1150.0)

    hub.sample(now=1150.0)

    events = [event for event, _plan in _lc_events(hub)]
    assert events.index("planned") < events.index("seeding_started")
    assert _lc_event_ids(hub) == ["%s.planned" % plan,
                                  "%s.seeding_started" % plan]
    assert len(set(_lc_event_ids(hub))) == 2


def test_each_lifecycle_event_is_emitted_exactly_once_across_repeated_sample_passes(
        tmp_path):
    """The durable marker, not the in-memory queue, is what makes this hold:
    LogQueue discards its dedupe key after a successful flush, so a queue-only
    guard would re-emit both events on the very next pass."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    _lc_announce(hub, now=1150.0)

    for now in (1150.0, 1160.0, 1170.0, 1180.0):
        hub.sample(now=now)

    assert _lc_events(hub) == [("planned", plan), ("seeding_started", plan)]
    assert sorted(store.get(plan)["emitted"]) == ["planned", "seeding_started"]


def test_a_fresh_hub_over_the_same_state_dir_does_not_re_emit_either_event(
        tmp_path):
    """Restart is the case requirement 4 exists for, and the one nothing
    existing covers: _seen_report_event_ids is a plain in-process set, and
    test_report_cursor_queues_equal_timestamps_once_and_replays_on_restart
    asserts the report ring DOES replay on a fresh hub -- by design, because
    those records are backend-deduped by report_id. The lifecycle markers are
    durable instead, so the same restart re-queues the report and NOT the
    lifecycle events."""
    plan, transfer = _lc_id(1), _lc_id(2)
    policy = _lc_policy(plan, transfer)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    hub, _store = _lc_hub(tmp_path, policy, reports=reports)
    _lc_announce(hub, now=1150.0)
    hub.sample(now=1150.0)
    assert len(_lc_records(hub)) == 2

    restarted, _store2 = _lc_hub(tmp_path, policy, reports=reports)
    _lc_announce(restarted, now=1300.0)
    restarted.sample(now=1300.0)

    assert _lc_records(restarted) == []
    assert len(_lc_records(restarted, _REPORT_NAME)) == 1, \
        "the report ring replay is deliberate and must not have been broken"


def test_a_refused_emit_leaves_the_plan_unmarked_and_retries_next_pass_with_an_identical_record(
        tmp_path):
    """MARK AFTER THE EFFECT. A full queue returns False from emit; writing the
    marker anyway would lose the event permanently, because nothing else ever
    revisits a marked row. The retry must also be byte-identical -- every
    instant in the record was latched into the store before the record existed,
    so a later retry cannot re-stamp it off the wall clock."""
    plan, transfer = _lc_id(1), _lc_id(2)
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer))
    hub.log_queue._max = 0              # the queue refuses everything

    hub.sample(now=1100.0)

    assert _lc_records(hub) == []
    assert store.get(plan)["emitted"] == {}

    hub.log_queue._max = 1000
    hub.sample(now=1500.0)             # a much later pass

    assert _lc_events(hub) == [("planned", plan)]
    assert "planned" in store.get(plan)["emitted"]
    record = _lc_records(hub)[0]
    assert record["timeUnixNano"] == str(int(_LC_PLANNED_AT * 1e9))
    assert _lc_attrs(record)["event.id"]["stringValue"] == "%s.planned" % plan


def test_seeder_without_a_verified_report_never_emits_seeding_started(tmp_path):
    """aria2 starts announcing left=0 the instant the last piece lands, while
    the agent's sha256 of a ~1.2 GB image does not run until its next tick and
    then takes minutes. Publishing on the tracker fact alone would report a
    seeding transfer for content nobody has verified -- for that whole window.
    The fact is still LATCHED, because the peer row is pruned at 2*INTERVAL."""
    plan, transfer = _lc_id(1), _lc_id(2)
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer))
    _lc_announce(hub, now=1150.0)

    hub.sample(now=1150.0)

    assert _lc_events(hub) == [("planned", plan)]
    row = store.get(plan)
    assert row["state"] == "planned"
    assert row["tracker_seeder_at"] == 1150.0
    assert row["checksum_verified_at"] is None


def test_verified_report_without_a_tracker_seeder_never_emits_seeding_started(
        tmp_path):
    """The device can attest its own checksum but can neither see nor attest
    that it is serving the swarm -- it never talks to the tracker; only its
    aria2 announces. A verified report alone therefore says the bytes are
    staged, not that anything is being seeded."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)

    hub.sample(now=1250.0)

    assert _lc_events(hub) == [("planned", plan)]
    row = store.get(plan)
    assert row["state"] == "planned"
    assert row["checksum_verified_at"] == 1200.0
    assert row["tracker_seeder_at"] is None


def test_a_sha_mismatch_report_never_promotes_the_plan(tmp_path):
    """A terminal report whose content_sha256 did not verify is the one case
    where every other signal looks right -- the bytes are complete, the device
    is seeding them -- and the answer is still no."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0,
                                       sha_state="mismatch")]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    # Announced on this pass's own clock, so the swarm row is still inside the
    # registry's 2*INTERVAL window and precondition 3 really does hold here.
    _lc_announce(hub, now=1250.0)

    hub.sample(now=1250.0)

    assert _lc_events(hub) == [("planned", plan)]
    assert store.get(plan)["tracker_seeder_at"] == 1250.0
    assert store.get(plan)["checksum_verified_at"] is None


def test_a_report_bearing_another_transfers_id_never_promotes_the_plan(tmp_path):
    """STRICT BINDING. A report attests a plan only when it carries THAT plan's
    transfer_id. Here the device is seeding the right image and has a verified
    terminal report for it -- but under an id it minted itself, which is what
    an agent too old to adopt the server's plan looks like. Promoting on it
    would publish "seeding" on the strength of a checksum computed for a
    different transfer, so the plan stays at `planned` and the fleet gap is
    visible in stats() rather than papered over with a wrong answer."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(_lc_id(99), received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    _lc_announce(hub, now=1250.0)

    hub.sample(now=1250.0)

    assert _lc_events(hub) == [("planned", plan)]
    row = store.get(plan)
    assert row["state"] == "planned"
    assert row["checksum_verified_at"] is None
    assert store.stats()["plans_awaiting_report"] == 1


def test_a_transfer_that_never_reports_stays_planned_forever(tmp_path):
    """Silence, never a guess. A plan whose device never delivers a report
    bearing its transfer_id emits `planned` and nothing else, for as many
    passes as you care to run -- there is deliberately no fallback that
    promotes it from some other evidence."""
    plan, transfer = _lc_id(1), _lc_id(2)
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer))
    _lc_announce(hub, now=1150.0)

    for now in (1150.0, 1400.0, 2000.0, 5000.0, 90000.0):
        hub.sample(now=now)

    assert _lc_events(hub) == [("planned", plan)]
    assert store.get(plan)["state"] == "planned"


def test_the_seeder_fact_latched_before_prune_all_still_yields_an_event_when_the_report_lands_later(
        tmp_path):
    """Why the latch is mandatory rather than an optimisation. The registry
    prunes a peer row at 2*INTERVAL, and the device's checksum report arrives
    minutes after aria2 first announced left=0. Requiring both facts in the
    SAME pass would mean the row vanishing in between blocks the event
    permanently."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports)
    _lc_announce(hub, now=1150.0)
    hub.sample(now=1150.0)
    assert store.get(plan)["tracker_seeder_at"] == 1150.0

    hub._registry.prune_all(now=1400.0)
    assert hub._registry.snapshot(now=1400.0) == {}

    reports[_LC_DEVICE] = [_lc_report(transfer, received_at=1400.0)]
    hub.sample(now=1400.0)

    assert _lc_events(hub) == [("planned", plan), ("seeding_started", plan)]
    # The latched instant, not the pass that noticed the pair complete.
    assert store.get(plan)["seeding_started_at"] == 1400.0
    assert store.get(plan)["tracker_seeder_at"] == 1150.0


def test_two_plans_for_the_same_device_and_image_emit_two_distinct_pairs(
        tmp_path):
    """Requirement 7's headline case: unassign and re-assign the same image and
    the second transfer is a genuinely separate one. Device-minted ids could
    not do this -- an unassign+reassign inside one agent tick is invisible to
    the device, so plan 2 would inherit plan 1's id and the two transfers would
    collapse into one timeline. The first plan is already `seeding` and is
    NEVER cancelled by the unassign: a later withdrawal does not un-happen a
    transfer that occurred."""
    plan1, transfer1 = _lc_id(1), _lc_id(2)
    plan2, transfer2 = _lc_id(3), _lc_id(4)
    policy = _lc_policy(plan1, transfer1)
    reports = {_LC_DEVICE: [_lc_report(transfer1, received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, policy, reports=reports)
    _lc_announce(hub, now=1150.0)
    hub.sample(now=1150.0)

    policy[_LC_DEVICE]["plans"] = {
        _LC_IMAGE: _lc_plan_row(plan2, transfer2, planned_at=1300.0)}
    reports[_LC_DEVICE].append(_lc_report(transfer2, received_at=1400.0))
    _lc_announce(hub, now=1400.0, peer_id="p2")
    hub.sample(now=1400.0)

    assert _lc_events(hub) == [("planned", plan1), ("seeding_started", plan1),
                               ("planned", plan2), ("seeding_started", plan2)]
    assert len(set(_lc_event_ids(hub))) == 4
    assert store.get(plan1)["state"] == "seeding"
    assert store.get(plan1)["seeding_started_at"] == 1200.0
    assert store.get(plan2)["seeding_started_at"] == 1400.0


def test_facts_latch_with_the_exporter_disabled_and_emit_after_it_is_turned_on(
        tmp_path):
    """Latching sits OUTSIDE sample()'s exporter guard on purpose: a deployment
    that enables OTLP export later must publish the plans that were already in
    flight while it was off, with the instants observed at the time -- not with
    the moment the operator flipped the switch, and not silently losing them."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, _lc_policy(plan, transfer), reports=reports,
                         exporting=False)
    _lc_announce(hub, now=1150.0)

    hub.sample(now=1150.0)

    assert hub.log_queue.snapshot() == []
    assert store.get(plan)["state"] == "seeding"
    assert store.get(plan)["seeding_started_at"] == 1200.0

    hub.exporter = _EXPORT_ON          # the console enables the destination
    hub.sample(now=99000.0)

    assert _lc_events(hub) == [("planned", plan), ("seeding_started", plan)]
    assert _lc_records(hub)[0]["timeUnixNano"] == str(int(_LC_PLANNED_AT * 1e9))
    assert _lc_records(hub)[1]["timeUnixNano"] == str(int(1200.0 * 1e9))


def test_the_info_hash_to_image_id_join_comes_from_catalog_json_not_from_names(
        tmp_path):
    """The swarm row is keyed by info_hash and the plan by image_id; the join
    between them is catalog.json's info_hash_hex. telemetry._names is NOT that
    join -- it is an aria2 file BASENAME harvested from the origin's RPC, and
    joining on it would match the wrong image (or nothing) the moment a
    filename and an image id differ."""
    plan, transfer = _lc_id(1), _lc_id(2)
    reports = {_LC_DEVICE: [_lc_report(transfer, received_at=1200.0)]}
    # The plan row captured no info_hash (published after the assignment), so
    # only the catalog can supply the join key.
    policy = _lc_policy(plan, transfer, info_hash=None)
    hub, store = _lc_hub(tmp_path / "with-catalog", policy, reports=reports)
    hub._names = {_LC_INFO_HASH: "cat9k.bin"}   # a basename, never an image id
    _lc_announce(hub, now=1150.0)

    hub.sample(now=1150.0)

    assert ("seeding_started", plan) in _lc_events(hub)
    assert store.get(plan)["tracker_seeder_at"] == 1150.0

    # And with the catalog entry carrying no info_hash_hex there is NO join key
    # at all: no event, never a guess from the basename map.
    blind, blind_store = _lc_hub(tmp_path / "no-catalog", policy,
                                 reports=reports,
                                 images={_LC_IMAGE: {"filename": "cat9k.bin"}})
    blind._names = {_LC_INFO_HASH: "cat9k.bin"}
    _lc_announce(blind, now=1150.0)

    blind.sample(now=1150.0)

    assert _lc_events(blind) == [("planned", plan)]
    assert blind_store.get(plan)["tracker_seeder_at"] is None


def test_existing_report_records_are_unchanged_by_the_lifecycle_pass(tmp_path):
    """The additive guarantee, asserted at the PIPELINE rather than at the
    builder: the report records a lifecycle-wired hub puts on the queue must be
    identical, attribute for attribute, to the ones a hub with no lifecycle
    wiring at all produces from the same inputs."""
    plan, transfer = _lc_id(1), _lc_id(2)
    report = _lc_report(transfer, received_at=1200.0, window_end=1190.0)
    hub, _store = _lc_hub(tmp_path, _lc_policy(plan, transfer),
                          reports={_LC_DEVICE: [report]})
    _lc_announce(hub, now=1150.0)
    hub.sample(now=1150.0)

    plain = telemetry.Telemetry(PeerRegistry(),
                                reports_info=lambda: {_LC_DEVICE: [report]})
    plain.exporter = _EXPORT_ON
    plain.sample(now=1150.0)

    assert _lc_records(hub, _REPORT_NAME) == _lc_records(plain, _REPORT_NAME)
    assert len(_lc_records(hub, _REPORT_NAME)) == 1
    # In particular the plan identity did NOT leak into the report event: an
    # attribute shipped once can never be withdrawn additively.
    report_attrs = _lc_attrs(_lc_records(hub, _REPORT_NAME)[0])
    assert "iris.plan.id" not in report_attrs
    assert "iris.transfer.planned_at" not in report_attrs
    assert "iris.transfer.seeding_started_at" not in report_attrs


# --- lifecycle records must survive a queue that drops them ---------------
#
# Appended as a pure block. These drive sample() through a REAL transport
# whose sender fails and then recovers, because that is the only way the
# difference between "the queue accepted it" and "the collector got it" is
# observable at all -- with no transport wired nothing is ever delivered and
# every enqueue looks like a success.


def _lc_flaky_hub(tmp_path, policy, reports=None, max_queue=1000):
    """(hub, store, outbox, link) over a real LogQueue + OTLPLogTransport.

    `link["up"]` switches the collector on and off; while it is down the
    sender raises, which is exactly what OTLPLogTransport.send promises to do
    on failure so the queue retains the batch. `outbox` collects the bodies
    that really went out.
    """
    outbox, link = [], {"up": False}

    def sender(_url, body):
        if not link["up"]:
            raise OSError("collector unreachable")
        outbox.append(body)

    exp = otlp.OTLPLogExporter("http://c:4318", sender=sender,
                               max_queue=max_queue)
    store = transfer_lifecycle.TransferLifecycle(str(tmp_path))
    hub = telemetry.Telemetry(
        PeerRegistry(), exporter=exp,
        reports_info=lambda: reports if reports is not None else {},
        images_info=lambda: _LC_IMAGES,
        assignments_info=lambda: policy,
        transfer_lifecycle=store)
    return hub, store, outbox, link


def _lc_sent_event_ids(outbox):
    ids = []
    for body in outbox:
        payload = json.loads(body.decode())
        for resource in payload.get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    attrs = _lc_attrs(record)
                    if _lc_log_name(record) == _LIFECYCLE_NAME:
                        ids.append(attrs["event.id"]["stringValue"])
    return ids


def test_a_lifecycle_event_is_marked_delivered_only_by_a_successful_send(
        tmp_path):
    """The durable marker that retires an event is written from the queue's
    delivered-callback, which fires only after a send succeeded. Until then the
    row is queued but unconfirmed -- because LogQueue.emit returning True says
    only that the deque took the record, and an unreachable collector is
    precisely when that is not the same thing."""
    plan, transfer = _lc_id(1), _lc_id(2)
    hub, store, outbox, link = _lc_flaky_hub(tmp_path,
                                             _lc_policy(plan, transfer))

    hub.sample(now=1100.0)                      # queued, send fails

    row = store.get(plan)
    assert "planned" in row["emitted"]
    assert row["delivered"] == {}
    assert store.stats()["plans_unconfirmed"] == 1
    assert outbox == []

    link["up"] = True
    hub.sample(now=1110.0)                      # the collector comes back

    assert store.get(plan)["delivered"].keys() == {"planned"}
    assert store.stats()["plans_unconfirmed"] == 0
    assert _lc_sent_event_ids(outbox) == ["%s.planned" % plan]
    # And the record went out ONCE: the still-queued copy was never queued a
    # second time behind it (LogQueue.contains, as _export_new_reports does).
    hub.sample(now=1120.0)
    assert _lc_sent_event_ids(outbox) == ["%s.planned" % plan]


def test_a_lifecycle_record_evicted_from_a_full_queue_is_re_queued_not_lost(
        tmp_path):
    """The failure the durable marker exists to prevent, and the one an
    enqueue-time marker cannot.

    LogQueue.emit returns False only for a duplicate key or a zero-capacity
    queue. A FULL queue does not refuse: it pops its oldest record, counts a
    drop and returns True. So an unreachable collector plus ordinary announce
    traffic evicts a lifecycle record that was already marked, and nothing
    ever revisits a marked row -- the event would be delivered zero times,
    forever. Held unconfirmed instead, it is simply queued again.
    """
    plan, transfer = _lc_id(1), _lc_id(2)
    hub, store, outbox, link = _lc_flaky_hub(tmp_path,
                                             _lc_policy(plan, transfer),
                                             max_queue=2)

    hub.sample(now=1100.0)                      # queued, send fails
    assert "planned" in store.get(plan)["emitted"]

    for n in range(4):                          # announces overrun the queue
        hub.on_swarm_event({"event": "join", "ip": "10.0.0.%d" % n, "ts": 0,
                            "principal_type": "device", "principal_id": "d1",
                            "event_id": "evt-%d" % n})
    assert _lc_records(hub) == [], "the record must really have been evicted"

    link["up"] = True
    hub.sample(now=1110.0)

    assert _lc_sent_event_ids(outbox) == ["%s.planned" % plan]
    assert store.get(plan)["delivered"].keys() == {"planned"}


def test_the_report_delivery_cursor_still_advances_through_the_shared_callback(
        tmp_path):
    """LogQueue has ONE delivered-callback slot and the report path already
    owned it. Lifecycle deliveries are fanned out from a wrapper rather than
    registered over the top of it: whichever registered last would otherwise
    silently disable the other, and the report replay guard failing open is
    invisible until a backend is holding every stored report twice."""
    plan, transfer = _lc_id(1), _lc_id(2)
    report = _lc_report(transfer, received_at=1200.0)
    hub, store, outbox, link = _lc_flaky_hub(
        tmp_path, _lc_policy(plan, transfer),
        reports={_LC_DEVICE: [report]})
    link["up"] = True

    hub.sample(now=1250.0)

    assert hub._seen_report_event_ids, \
        "the report cursor did not advance on delivery"
    assert len(_lc_sent_event_ids(outbox)) == 1
    sent = len(outbox)

    hub.sample(now=1260.0)                      # nothing new to say

    assert len(outbox) == sent
    assert store.get(plan)["delivered"].keys() == {"planned"}


def test_one_sample_pass_marks_every_lifecycle_event_in_a_single_store_write(
        tmp_path, monkeypatch):
    """Two plans promoting on one pass is four records, and marking them one
    at a time is four full read-modify-write cycles of the whole store -- on
    the same thread that then has to flush telemetry. The pass writes twice:
    once for the observation, once for the whole batch of markers."""
    plan1, transfer1 = _lc_id(1), _lc_id(2)
    plan2, transfer2 = _lc_id(3), _lc_id(4)
    policy = _lc_policy(plan1, transfer1)
    policy["iris8kv-2"] = {
        "approved_image_id": _LC_IMAGE,
        "approved_image_ids": [_LC_IMAGE],
        "plans": {_LC_IMAGE: _lc_plan_row(plan2, transfer2)}}
    reports = {_LC_DEVICE: [_lc_report(transfer1, received_at=1200.0)],
               "iris8kv-2": [_lc_report(transfer2, received_at=1200.0)]}
    hub, store = _lc_hub(tmp_path, policy, reports=reports)
    _lc_announce(hub, now=1150.0)
    _lc_announce(hub, now=1150.0, device_id="iris8kv-2", peer_id="p2",
                 ip="10.0.0.3")

    writes = []
    real = transfer_lifecycle._atomic_write_json

    def counted(path, obj):
        writes.append(path)
        return real(path, obj)

    monkeypatch.setattr(transfer_lifecycle, "_atomic_write_json", counted)
    hub.sample(now=1150.0)

    assert len(_lc_events(hub)) == 4
    assert len(writes) == 2


# ---------------------------------------------------------------------------
# IRIS-05-002: a multi-torrent wave's sampled records cannot evict the
# tracker peer event queued at the start of the flush window
# ---------------------------------------------------------------------------

def test_sampled_overflow_never_evicts_a_tracker_peer_event(tmp_path):
    """Reviewer probe: with several torrents transferring at aria2's default
    55 peers, ~2 sampled records per connection per 2 s pass overflow the
    log queue between two 15 s flushes; the drop-oldest policy then evicted
    the tracker lifecycle event queued at the window's start. The sampled
    stream is now evictable and drops among itself."""
    import auth
    import peer_ledger
    T, C = 3, 40
    IH = {t: "%040x" % (0xabc0 + t) for t in range(T)}
    tick = {"k": 0}

    def rpc(method, params=None):
        if method == "aria2.getGlobalStat":
            return {"uploadSpeed": "1", "downloadSpeed": "0",
                    "numActive": str(T)}
        if method == "aria2.tellActive":
            if "files" in params[0]:
                return [{"connections": str(C), "infoHash": IH[t],
                         "totalLength": "1000",
                         "files": [{"path": "/img/img%d.bin" % t}]}
                        for t in range(T)]
            return [{"gid": "g%d" % t, "infoHash": IH[t],
                     "uploadLength": str(1000 * tick["k"])} for t in range(T)]
        if method == "aria2.getSessionInfo":
            return {"sessionId": "s0"}
        if method == "aria2.getPeers":
            t = int(params[0][1:])
            return [{"ip": "10.%d.0.%d" % (t, i), "port": str(6000 + i),
                     "uploadSpeed": "100", "uploaded": str(100 * tick["k"]),
                     "seeder": "false"} for i in range(1, C + 1)]
        raise AssertionError(method)
    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc, interval=15,
                              peer_ledger=peer_ledger.PeerLedger(str(tmp_path)))
    for t in range(T):
        for i in range(1, C + 1):
            hub._registry.announce(
                IH[t], "p%d-%d" % (t, i), "10.%d.0.%d" % (t, i), 6000 + i,
                left=500, principal=auth.Principal("device", "d%d-%d" % (t, i)))
    hub.sample_seeder(0.0)
    hub.on_swarm_event({"event_id": "SENTINEL-tracker-peer-event",
                        "info_hash": IH[0], "ip": "10.0.0.1", "left": 0,
                        "ts": 1.0})
    for k in range(1, 15 // telemetry.ACTIVE_INTERVAL + 1):
        tick["k"] = k
        hub.sample_seeder(2.0 * k)
    assert hub.log_queue.dropped_total > 0            # the window did overflow
    assert any(isinstance(e, dict)
               and e.get("event_id") == "SENTINEL-tracker-peer-event"
               for e in hub.log_queue.snapshot())


# ---------------------------------------------------------------------------
# IRIS-05-003: the rejected-samples counter is monotonic across staleness
# ---------------------------------------------------------------------------

class TestRejectedCounterIsNotResetByStaleness:
    IMAGES = {"img1": {"filename": "img1.bin", "info_hash_hex": "a" * 40,
                       "size": 1000}}

    def test_stale_snapshot_keeps_its_last_written_count(self):
        live = {"written_at": 1000.0,
                "counters": {"samples_rejected_total": 37}, "samples": {}}
        _, fresh = telemetry.aggregate_transfers(live, self.IMAGES, 1010.0)
        _, stale = telemetry.aggregate_transfers(live, self.IMAGES, 1031.0)
        assert fresh["samples_rejected_total"] == 37
        assert stale["samples_rejected_total"] == 37    # not 0
        assert stale["stream_devices"] == 0

    def test_unreadable_snapshot_latches_the_hubs_last_known_count(self):
        docs = [{"written_at": 1000.0,
                 "counters": {"samples_rejected_total": 37}, "samples": {}},
                None, None,
                {"written_at": 1100.0,
                 "counters": {"samples_rejected_total": 40}, "samples": {}}]
        hub = telemetry.Telemetry(PeerRegistry(), rpc=None, interval=10,
                                  live_info=lambda: docs.pop(0),
                                  images_info=lambda: self.IMAGES)
        hub.sample(1010.0)
        assert hub._extras["samples_rejected_total"] == 37
        hub.sample(1020.0)                    # snapshot unreadable: unknown
        assert hub._extras["samples_rejected_total"] == 37
        pts = telemetry._metric_points([], hub._extras, 1020.0)
        assert [p for p in pts if p["name"] ==
                "iris.telemetry.samples.rejected"][0]["value"] == 37
        assert "iris_telemetry_samples_rejected_total 37" in hub.metrics_text()
        hub.sample(1030.0)
        assert hub._extras["samples_rejected_total"] == 37
        hub.sample(1110.0)                    # a real, newer count wins
        assert hub._extras["samples_rejected_total"] == 40


# ---------------------------------------------------------------------------
# IRIS-05-008: export-state audit events carry a category and an actor
# ---------------------------------------------------------------------------

def test_export_state_audit_events_are_categorised(tmp_path):
    import audit
    audit_path = str(tmp_path / "audit.jsonl")
    hub = telemetry.from_env({"IRIS_AUDIT": audit_path,
                              "IRIS_STATE": str(tmp_path)})
    hub.export_health.record(False, "logs", 100.0)     # -> degraded edge
    events = audit.read_events(audit_path)
    assert [e["event"] for e in events] == ["otlp-export-degraded"]
    ev = events[0]
    assert ev["category"] == "telemetry"
    assert ev["actor"] == "system"
    assert "device_id" not in ev
    assert audit.read_events(audit_path, category="telemetry")


# ---------------------------------------------------------------------------
# The transfer-lifecycle store's bounds reach an operator (issues #43, #63)
# ---------------------------------------------------------------------------

def _lc_metrics_hub(tmp_path, policy):
    hub, store = _lc_hub(tmp_path, policy)
    exports = []
    hub.metrics_exporter = type("E", (), {
        "export": lambda _self, points: exports.append(points) or True})()
    return hub, store, exports


def _points_by_name(points):
    return {p["name"]: p for p in points}


def test_the_lifecycle_store_bounds_reach_both_metric_surfaces(tmp_path):
    """TransferLifecycle.stats() had no caller anywhere in the tree.

    The store applies two hard bounds and counts every row and record they
    cost -- and the module docstring justifies that with "a bound the store
    applies is a bound the store reports ... shows up as a number on the
    dashboard rather than as events that quietly never arrived". Nothing read
    those counters, so a fleet past MAX_PLANS, or a collector outage long
    enough to age out unacknowledged records, presented to an operator as
    lifecycle events that simply never arrived -- indistinguishable from a
    fleet that never seeded. Asserted through the two surfaces an operator
    actually reads (the OTLP metric export and the :9101 exposition), never
    through stats() alone: a reader test passes whether or not anything calls
    the reader, which is the exact defect this covers.
    """
    plan_id, transfer_id = _lc_id(0x51), _lc_id(0x52)
    hub, store, exports = _lc_metrics_hub(
        tmp_path, _lc_policy(plan_id, transfer_id))

    hub.sample(1100.0)
    assert store.get(plan_id)["state"] == "planned"

    points = _points_by_name(exports[-1])
    assert points["iris.transfer.lifecycle.plans"]["value"] == 1
    assert points["iris.transfer.lifecycle.plan_cap"]["value"] == \
        transfer_lifecycle.MAX_PLANS
    assert points["iris.transfer.lifecycle.unconfirmed"]["value"] == 1
    assert points["iris.transfer.lifecycle.dropped_unemitted"]["kind"] == "sum"

    text = hub.metrics_text()
    assert "iris_transfer_lifecycle_plans 1" in text
    cap = transfer_lifecycle.MAX_PLANS
    assert "iris_transfer_lifecycle_plan_cap %d" % cap in text
    assert "iris_transfer_lifecycle_unconfirmed 1" in text

    # The counters the bounds increment travel too. What increments them is
    # covered in test_transfer_lifecycle.py; what is at stake HERE is the
    # plumbing, so the values are put in the store directly.
    with open(store.path) as stream:
        doc = json.load(stream)
    doc["counters"]["plans_dropped_unemitted"] = 5
    doc["counters"]["events_retired_undelivered"] = 3
    doc["counters"]["plans_live_evicted"] = 2
    with open(store.path, "w") as stream:
        json.dump(doc, stream)

    hub.sample(1200.0)
    points = _points_by_name(exports[-1])
    assert points["iris.transfer.lifecycle.dropped_unemitted"]["value"] == 5
    assert points["iris.transfer.lifecycle.retired_undelivered"]["value"] == 3
    assert points["iris.transfer.lifecycle.live_evicted"]["value"] == 2

    text = hub.metrics_text()
    assert "iris_transfer_lifecycle_dropped_unemitted_total 5" in text
    assert "iris_transfer_lifecycle_retired_undelivered_total 3" in text
    assert "iris_transfer_lifecycle_live_evicted_total 2" in text


def test_a_hub_with_no_lifecycle_store_omits_the_families_rather_than_zeroing(
        tmp_path):
    """An unreadable or unwired store is NOT a store with nothing in it. A
    fabricated 0 would read as "the bound never bit", which is the one thing
    these numbers exist to disprove -- the same rule the rest of this module
    follows for an unmeasured value."""
    hub = telemetry.Telemetry(PeerRegistry())
    exports = []
    hub.metrics_exporter = type("E", (), {
        "export": lambda _self, points: exports.append(points) or True})()
    hub.sample(1100.0)

    assert hub._transfer_lifecycle_numbers() is None
    assert not [p for p in exports[-1]
                if p["name"].startswith("iris.transfer.lifecycle.")]
    assert "iris_transfer_lifecycle_" not in hub.metrics_text()
