# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import threading
import time

import bencode
import secrets_store
import telemetry
import tracker


# ---------------------------------------------------------------------------
# Helpers for secrets_path fixture
# ---------------------------------------------------------------------------

def _secrets_path(tmp_path):
    return str(tmp_path / "secrets.json")


def _mint_announce_token(secrets_path, device_id="dev-1", now=None):
    """Mint an announce_token for device_id; return the token value."""
    now = now if now is not None else time.time()
    store = secrets_store.load(secrets_path)
    tok = secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.save(store, secrets_path)
    return tok


# ---------------------------------------------------------------------------
# Pure function tests (unchanged — these don't use tokens at all)
# ---------------------------------------------------------------------------

def test_parse_announce_handles_binary_info_hash():
    a = tracker.parse_announce(
        "info_hash=%C9%FD.%2B%92%8C%86B%00%D1%82U%10%EE%B8%9F%C3%9B%5B%00"
        "&peer_id=A2-1-37&port=6881&left=0&event=started&key=tok")
    assert a["info_hash"] == "c9fd2e2b928c864200d1825510eeb89fc39b5b00"
    assert a["port"] == 6881
    assert a["left"] == 0
    assert a["event"] == "started"


def test_build_announce_response_is_decodable():
    body = tracker.build_announce_response(
        [{"ip": "10.0.0.2", "port": 6882}], compact=False)
    decoded = bencode.decode(body)
    assert decoded[b"interval"] == tracker.INTERVAL
    assert decoded[b"peers"][0][b"ip"] == b"10.0.0.2"
    assert decoded[b"peers"][0][b"port"] == 6882


def test_compact_peers_is_six_bytes_each():
    body = tracker.build_announce_response(
        [{"ip": "10.0.0.2", "port": 6882}], compact=True)
    decoded = bencode.decode(body)
    assert decoded[b"peers"] == bytes([10, 0, 0, 2, 6882 >> 8, 6882 & 0xFF])


def test_build_failure_is_bencoded():
    decoded = bencode.decode(tracker.build_failure("bad token"))
    assert decoded[b"failure reason"] == b"bad token"


# ---------------------------------------------------------------------------
# HTTP server helpers (ported to secrets_path fixture)
# ---------------------------------------------------------------------------

def _serve(tmp_path, device_id="dev-1"):
    """Start a tracker with a secrets store; return (srv, port, announce_token)."""
    sp = _secrets_path(tmp_path)
    tok = _mint_announce_token(sp, device_id)
    srv = tracker.make_server("127.0.0.1", 0, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], tok


def _serve_empty(tmp_path):
    """Start a tracker with an empty secrets store (no tokens)."""
    sp = _secrets_path(tmp_path)
    srv = tracker.make_server("127.0.0.1", 0, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.read()


# ---------------------------------------------------------------------------
# Task 5 NEW: store-based announce auth
# ---------------------------------------------------------------------------

def test_announce_without_key_403(tmp_path):
    """Announce with no ?key= → 403."""
    srv, port = _serve_empty(tmp_path)
    try:
        status, body = _get(port, "/announce?info_hash=AABB&peer_id=p1&port=1")
        assert status == 403
        assert bencode.decode(body)[b"failure reason"]
    finally:
        srv.shutdown()


def test_announce_valid_store_token_200(tmp_path):
    """A valid announce_token from the store → 200."""
    srv, port, tok = _serve(tmp_path)
    try:
        status, _ = _get(
            port, "/announce?info_hash=AABB&peer_id=p1&port=6881&left=0&key=%s"
            % tok)
        assert status == 200
    finally:
        srv.shutdown()


def test_announce_revoked_token_403(tmp_path):
    """A revoked announce_token → 403 without restart."""
    sp = _secrets_path(tmp_path)
    tok = _mint_announce_token(sp, "dev-r")
    srv = tracker.make_server("127.0.0.1", 0, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # Token currently valid
        status, _ = _get(port, "/announce?info_hash=AABB&peer_id=p1&port=1&key=%s"
                         % tok)
        assert status == 200

        # Revoke the device in the store (no server restart)
        store = secrets_store.load(sp)
        secrets_store.revoke(store, "dev-r")
        secrets_store.save(store, sp)

        # Same token → 403 on the next request (per-request load)
        status, body = _get(port, "/announce?info_hash=AABB&peer_id=p1&port=1&key=%s"
                            % tok)
        assert status == 403
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Ported: existing lifecycle and telemetry tests (updated _serve signature)
# ---------------------------------------------------------------------------

def test_announce_requires_token(tmp_path):
    srv, port = _serve_empty(tmp_path)
    try:
        status, body = _get(port, "/announce?info_hash=AABB&peer_id=p1&port=1")
        assert status == 403
        assert bencode.decode(body)[b"failure reason"]
    finally:
        srv.shutdown()


def test_announce_lifecycle_over_http(tmp_path):
    srv, port, tok = _serve(tmp_path)
    try:
        _get(port, "/announce?info_hash=AABB&peer_id=p1&port=6881&left=0&key=%s"
             % tok)
        status, body = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9&key=%s"
            % tok)
        assert status == 200
        peers = bencode.decode(body)[b"peers"]
        # non-compact peers are dicts with an (empty) "peer id" key too
        assert any(p[b"ip"] == b"127.0.0.1" and p[b"port"] == 6881
                   for p in peers)
        # p1 leaves
        _get(port,
             "/announce?info_hash=AABB&peer_id=p1&port=6881&event=stopped&key=%s"
             % tok)
        status, body = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9&key=%s"
            % tok)
        assert bencode.decode(body)[b"peers"] == []
    finally:
        srv.shutdown()


def test_scrape_reports_counts(tmp_path):
    srv, port, tok = _serve(tmp_path)
    try:
        _get(port, "/announce?info_hash=AABB&peer_id=p1&port=6881&left=0&key=%s"
             % tok)
        status, body = _get(port, "/scrape?info_hash=AABB&key=%s" % tok)
        assert status == 200
        files = bencode.decode(body)[b"files"]
        stats = list(files.values())[0]
        assert stats[b"complete"] == 1
    finally:
        srv.shutdown()


def test_announce_feeds_telemetry_counter_and_swarm(tmp_path):
    # a Telemetry hub owns a registry wired to its on_event hook; make_server
    # uses that registry and calls note_announce() on every announce.
    sp = _secrets_path(tmp_path)
    tok = _mint_announce_token(sp, "dev-t")
    hub = telemetry.Telemetry()
    srv = tracker.make_server("127.0.0.1", 0, sp,
                              registry=hub.registry,
                              on_announce=hub.note_announce)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # info_hash bytes "AABB" -> hex 41414242; left=0 => a seeder
        _get(port, "/announce?info_hash=AABB&peer_id=p1&port=6881&left=0&key=%s"
             % tok)
        text = hub.metrics_text()
        assert "iris_tracker_announces_total 1" in text
        assert ('iris_swarm_seeders{image="41414242",info_hash="41414242"} 1'
                in text)
    finally:
        srv.shutdown()


def test_make_server_without_telemetry_still_works(tmp_path):
    # on_announce/registry are optional — the bare tracker must be unaffected
    srv, port, tok = _serve(tmp_path)
    try:
        status, _ = _get(port, "/announce?info_hash=AABB&peer_id=p1&port=1&key=%s"
                         % tok)
        assert status == 200
    finally:
        srv.shutdown()


def test_announce_ip_override_is_handed_to_peers(tmp_path):
    # a containerized seeder announces with ip=<external>; other peers must get
    # THAT address, not the announce's source address (127.0.0.1 here)
    srv, port, tok = _serve(tmp_path)
    try:
        _get(port, "/announce?info_hash=AABB&peer_id=seed&port=6881&left=0"
             "&ip=100.90.168.20&key=%s" % tok)
        status, body = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9&key=%s"
            % tok)
        peers = bencode.decode(body)[b"peers"]
        assert any(p[b"ip"] == b"100.90.168.20" and p[b"port"] == 6881
                   for p in peers)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Input validation: malicious ip= override and out-of-range port
# ---------------------------------------------------------------------------

def test_ipv6_ip_override_is_rejected_and_client_address_used(tmp_path):
    """An IPv6 ip= override must be ignored; the peer is stored with the
    socket address instead (127.0.0.1), and that address appears in compact."""
    srv, port, tok = _serve(tmp_path)
    try:
        # seeder announces with an IPv6 ip= — this must NOT raise
        status, body = _get(
            port, "/announce?info_hash=AABB&peer_id=seed&port=6881&left=0"
            "&ip=fe80::1&key=%s" % tok)
        assert status == 200
        # a second peer requests compact peers — must also return 200 without crash
        status2, body2 = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9"
            "&compact=1&key=%s" % tok)
        assert status2 == 200
        decoded = bencode.decode(body2)
        peers_bytes = decoded[b"peers"]
        # exactly one peer (6 bytes): the seed was stored with socket addr 127.0.0.1
        assert len(peers_bytes) == 6, (
            "expected exactly one compact peer (6 bytes), got %d bytes: %r"
            % (len(peers_bytes), peers_bytes))
        # first 4 bytes must be 127.0.0.1 — the socket addr, not fe80::1
        assert peers_bytes[:4] == bytes([127, 0, 0, 1]), (
            "seed must be stored with socket addr 127.0.0.1, got %r"
            % peers_bytes[:4])
    finally:
        srv.shutdown()


def test_ip_override_with_out_of_range_octet_is_rejected(tmp_path):
    """An ip= with an out-of-range octet (e.g. 10.0.0.999) must be silently
    dropped; socket address is used instead and compact announce must not crash."""
    srv, port, tok = _serve(tmp_path)
    try:
        status, _ = _get(
            port, "/announce?info_hash=AABB&peer_id=seed&port=6881&left=0"
            "&ip=10.0.0.999&key=%s" % tok)
        assert status == 200
        status2, body2 = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9"
            "&compact=1&key=%s" % tok)
        assert status2 == 200
        decoded = bencode.decode(body2)
        assert isinstance(decoded[b"peers"], bytes)
    finally:
        srv.shutdown()


def test_out_of_range_port_is_rejected_and_announce_returns_200(tmp_path):
    """A port value out of 1-65535 range must be handled safely; compact
    announce for that swarm must return 200 (no ValueError crash)."""
    srv, port, tok = _serve(tmp_path)
    try:
        # announce with port=70000 (> 65535)
        status, _ = _get(
            port, "/announce?info_hash=AABB&peer_id=seed&port=70000&left=0"
            "&key=%s" % tok)
        assert status == 200
        # another peer does a compact request — must not crash
        status2, body2 = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9"
            "&compact=1&key=%s" % tok)
        assert status2 == 200
        decoded = bencode.decode(body2)
        assert isinstance(decoded[b"peers"], bytes)
        # the bad-port seed must NOT appear in the peer list — it must be
        # excluded entirely, not re-advertised with a substitute port (6881)
        # that would send all leechers to the wrong port and fail silently.
        assert decoded[b"peers"] == b"", (
            "bad-port peer must be excluded from compact peers, got %r"
            % decoded[b"peers"])
    finally:
        srv.shutdown()


def test_bad_ip_and_port_in_registry_does_not_break_compact_for_other_peers(tmp_path):
    """If a poisoned peer somehow ends up in the registry, compact_peers must
    skip it gracefully and still encode the valid peers."""
    # Test compact_peers directly: one bad entry must not abort the whole encode
    good = {"ip": "10.0.0.1", "port": 6881}
    bad_ip = {"ip": "fe80::1", "port": 6881}
    bad_port = {"ip": "10.0.0.2", "port": 70000}
    # Without a fix, any of these would raise ValueError inside compact_peers
    result = tracker.compact_peers([good, bad_ip, bad_port])
    assert result == bytes([10, 0, 0, 1, 6881 >> 8, 6881 & 0xFF])


def test_valid_ipv4_ip_override_is_accepted(tmp_path):
    """A valid dotted-quad ip= override must still be accepted and propagated."""
    srv, port, tok = _serve(tmp_path)
    try:
        _get(port, "/announce?info_hash=AABB&peer_id=seed&port=6881&left=0"
             "&ip=192.168.1.50&key=%s" % tok)
        status, body = _get(
            port, "/announce?info_hash=AABB&peer_id=p2&port=6882&left=9"
            "&key=%s" % tok)
        peers = bencode.decode(body)[b"peers"]
        assert any(p[b"ip"] == b"192.168.1.50" for p in peers)
    finally:
        srv.shutdown()
