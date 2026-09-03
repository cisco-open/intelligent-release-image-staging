# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 13: typed tracker announce integration + candidate filtering (spec 6/7).

These tests exercise the HTTP announce path over the strict announce index:
typed public principal fields, device/service ``seeder`` distinction,
IP-independent ``legacy_unattributed`` classification, typed mutual-ACL
filtering (both directions and by IP), quarantine visibility, fail_closed zero
candidates, durable endpoint write attempts (valid vs bad port), endpoint write
failure posture (200 + filter + pending enqueue), and the exact override nets.
"""
import hashlib
import http.client
import threading
import time
from urllib.parse import quote_from_bytes

import bencode
import peer_endpoints
import peer_policy
import secrets_store
import tracker


INFO_HASH_BYTES = hashlib.sha1(b"iris-tracker-principals").digest()
INFO_HASH = quote_from_bytes(INFO_HASH_BYTES)
INFO_HASH_HEX = INFO_HASH_BYTES.hex()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _secrets_path(tmp_path):
    return str(tmp_path / "secrets.json")


def _mint_device(sp, device_id, now=None):
    now = time.time() if now is None else now
    store = secrets_store.load(sp)
    tok = secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.save(store, sp)
    return tok


def _mint_seeder(sp, now=None):
    now = time.time() if now is None else now
    store = secrets_store.load(sp)
    tok = secrets_store.mint(store, "seeder", "announce_token", now)
    secrets_store.save(store, sp)
    return tok


def _rotate_seeder(sp, now=None):
    """Mint a fresh current seeder token, keeping the prior as a legacy
    previous record; returns (previous_token, current_token)."""
    now = time.time() if now is None else now
    store = secrets_store.load(sp)
    # A current seeder token must exist before rotation can retire it.
    secrets_store.mint(store, "seeder", "announce_token", now)
    secrets_store.rotate_announce(store, now)
    secrets_store.save(store, sp)
    # rotate_announce prepends the OLD current into previous and mints a fresh
    # current. Fetch the previous value for the legacy announce.
    old = store["seeder"]["announce_token_previous"][0]["value"]
    return old, store["seeder"]["announce_token"]["value"]


def _serve(tmp_path, **kwargs):
    sp = kwargs.pop("secrets_path", None) or _secrets_path(tmp_path)
    srv = tracker.make_server("127.0.0.1", 0, sp, **kwargs)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    return r.status, r.read()


def _announce(port, peer_id, token, extra="", info_hash=INFO_HASH,
              port_val=6881, left=0):
    q = ("/announce?info_hash=%s&peer_id=%s&port=%s&left=%s&announce_token=%s%s"
         % (info_hash, peer_id, port_val, left, token, extra))
    return _get(port, q)


# ---------------------------------------------------------------------------
# Blank / dedicated resolver cases at the HTTP boundary
# ---------------------------------------------------------------------------

def test_missing_credential_is_403_token_free(tmp_path):
    srv, port = _serve(tmp_path)
    try:
        status, body = _get(
            port, "/announce?info_hash=%s&peer_id=p1&port=1" % INFO_HASH)
        assert status == 403
        assert bencode.decode(body)[b"failure reason"]
    finally:
        srv.shutdown()


def test_two_dedicated_occurrences_are_403(tmp_path):
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    srv, port = _serve(tmp_path, secrets_path=sp)
    try:
        status, _ = _get(
            port,
            "/announce?info_hash=%s&peer_id=p1&port=6881&left=0"
            "&announce_token=%s&announce_token=%s" % (INFO_HASH, tok, tok))
        assert status == 403
    finally:
        srv.shutdown()


def test_blank_dedicated_plus_valid_legacy_key_succeeds(tmp_path):
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    srv, port = _serve(tmp_path, secrets_path=sp)
    try:
        status, _ = _get(
            port,
            "/announce?info_hash=%s&peer_id=p1&port=6881&left=0"
            "&announce_token=&key=%s" % (INFO_HASH, tok))
        assert status == 200
    finally:
        srv.shutdown()


def test_blank_dedicated_without_legacy_is_403(tmp_path):
    sp = _secrets_path(tmp_path)
    _mint_device(sp, "dev-a")
    srv, port = _serve(tmp_path, secrets_path=sp)
    try:
        status, _ = _get(
            port,
            "/announce?info_hash=%s&peer_id=p1&port=6881&left=0"
            "&announce_token=" % INFO_HASH)
        assert status == 403
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Typed public fields on the swarm
# ---------------------------------------------------------------------------

def test_device_announce_registers_typed_device_principal(tmp_path):
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg)
    try:
        assert _announce(port, "p1", tok)[0] == 200
        snap = reg.snapshot()
        rows = snap[INFO_HASH_HEX]
        assert rows[0]["principal_type"] == "device"
        assert rows[0]["principal_id"] == "dev-a"
        assert rows[0]["participant_class"] == "device"
    finally:
        srv.shutdown()


def test_service_seeder_and_device_seeder_are_distinct(tmp_path):
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    seeder_tok = _mint_seeder(sp)
    # A device literally named "seeder" — write it directly under devices,
    # since mint("seeder") targets the service seeder store.
    store = secrets_store.load(sp)
    store.setdefault("devices", {})["seeder"] = {
        "announce_token": {"value": "devseeder0000000000000000000000",
                           "created_at": 0, "expires_at": 0, "revoked": False}}
    secrets_store.save(store, sp)
    dev_seeder_tok = "devseeder0000000000000000000000"
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg)
    try:
        assert _announce(port, "svc", seeder_tok)[0] == 200
        assert _announce(port, "dev", dev_seeder_tok)[0] == 200
        rows = reg.snapshot()[INFO_HASH_HEX]
        classes = {(r["principal_type"], r["participant_class"]) for r in rows}
        assert ("service", "seeder") in classes
        assert ("device", "device") in classes
        assert len(rows) == 2
    finally:
        srv.shutdown()


def test_legacy_token_is_legacy_unattributed_regardless_of_ip(tmp_path):
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    prev, _cur = _rotate_seeder(sp)
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg)
    try:
        # announce with a private ip= override -> still legacy_unattributed,
        # classification is by credential, never by comparing to a host IP.
        assert _announce(port, "leg", prev, extra="&ip=10.0.0.9")[0] == 200
        rows = reg.snapshot()[INFO_HASH_HEX]
        assert rows[0]["principal_type"] == "legacy"
        assert rows[0]["participant_class"] == "legacy_unattributed"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Typed mutual-ACL candidate filtering
# ---------------------------------------------------------------------------

def _policy_paths(tmp_path):
    return (str(tmp_path / "peer-policy.json"),
            str(tmp_path / "peer-policy.lkg.json"))


def _quarantine_device(auth_path, lkg_path, device_id, now):
    peer_policy.initialize(auth_path, lkg_path)

    def mutate(doc):
        doc["assignments"][device_id] = peer_policy.RESERVED_QUARANTINE

    peer_policy.commit_mutation(auth_path, lkg_path, "assign", device_id,
                                "test", now, mutate)


def test_quarantined_device_is_visible_but_filtered_both_directions(tmp_path):
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    good_tok = _mint_device(sp, "good")
    bad_tok = _mint_device(sp, "bad")
    ap, lp = _policy_paths(tmp_path)
    _quarantine_device(ap, lp, "bad", time.time())
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg,
                       policy_paths=(ap, lp))
    try:
        # quarantined device announces: 200 and visible in the swarm snapshot
        assert _announce(port, "pbad", bad_tok)[0] == 200
        assert reg.snapshot()[INFO_HASH_HEX]  # visible

        # a permitted device announces and asks for peers: the quarantined
        # device must NOT be returned (mutual deny), but good peer registers.
        status, body = _announce(port, "pgood", good_tok)
        assert status == 200
        peers = bencode.decode(body)[b"peers"]
        # only the quarantined peer exists besides self -> it is filtered out
        assert peers == []
    finally:
        srv.shutdown()


def test_legacy_credential_at_an_unquarantined_address_still_discovers(tmp_path):
    """Control for the test below: a legacy (previous seeder token) announce
    from an address no denied device is attributed to keeps its open
    discovery."""
    sp = _secrets_path(tmp_path)
    good_tok = _mint_device(sp, "good")
    prev, _cur = _rotate_seeder(sp)
    ap, lp = _policy_paths(tmp_path)
    peer_policy.initialize(ap, lp)
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, policy_paths=(ap, lp),
                       endpoints_path=ep_path)
    try:
        assert _announce(port, "pgood", good_tok, port_val=6881)[0] == 200
        status, body = _announce(port, "leg", prev, port_val=6890)
        assert status == 200
        peers = bencode.decode(body)[b"peers"]
        assert any(p[b"port"] == 6881 for p in peers)
    finally:
        srv.shutdown()


def test_quarantined_device_cannot_escape_quarantine_with_legacy_token(tmp_path):
    """IRIS-04-003: a quarantined device still holds the seeder's previous
    announce token from its torrent. Announcing with it resolved to a
    ``legacy`` principal with no ACL slot, so the device received the full
    permitted peer list and was handed out to permitted devices. Now a
    legacy requester or candidate at an address a durable endpoint
    attributes to a denied device is treated as that device: no peers for
    it, and it is handed to nobody. (Every peer here shares 127.0.0.1, which
    is exactly the situation on a device: the legacy announce comes from the
    address its own authenticated announce was recorded at.)"""
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    good_tok = _mint_device(sp, "good")
    bad_tok = _mint_device(sp, "bad")
    prev, _cur = _rotate_seeder(sp)
    ap, lp = _policy_paths(tmp_path)
    _quarantine_device(ap, lp, "bad", time.time())
    ep_path = str(tmp_path / "peer-endpoints.json")
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg,
                       policy_paths=(ap, lp), endpoints_path=ep_path)
    try:
        assert _announce(port, "pgood", good_tok, port_val=6881)[0] == 200
        # The quarantined device's own authenticated announce records its
        # address; with its own token it sees nothing (mutual deny).
        status, body = _announce(port, "pbad", bad_tok, port_val=6882,
                                 left=100)
        assert status == 200
        assert bencode.decode(body)[b"peers"] == []
        # Same device, same address, previous seeder token: still nothing.
        status, body = _announce(port, "pbad2", prev, port_val=6882, left=100)
        assert status == 200
        assert bencode.decode(body)[b"peers"] == []
        # ...and the permitted device is not handed the legacy-classified
        # peer at the quarantined address either.
        status, body = _announce(port, "pgood", good_tok, port_val=6881)
        assert bencode.decode(body)[b"peers"] == []
        # The legacy announce itself is still a visible participant.
        rows = reg.snapshot()[INFO_HASH_HEX]
        assert any(r["principal_type"] == "legacy" for r in rows)
    finally:
        srv.shutdown()


def test_legacy_discovery_fails_closed_when_endpoint_store_is_unreadable(tmp_path):
    """With the endpoint store unreadable the tracker cannot tell whether a
    legacy address belongs to a denied device, so a legacy requester gets no
    peers (attributable principals keep discovering -- see the corrupt-store
    announce test)."""
    sp = _secrets_path(tmp_path)
    good_tok = _mint_device(sp, "good")
    prev, _cur = _rotate_seeder(sp)
    ap, lp = _policy_paths(tmp_path)
    peer_policy.initialize(ap, lp)
    ep_path = str(tmp_path / "peer-endpoints.json")
    with open(ep_path, "w") as f:
        f.write("{ corrupt")
    srv, port = _serve(tmp_path, secrets_path=sp, policy_paths=(ap, lp),
                       endpoints_path=ep_path)
    try:
        assert _announce(port, "pgood", good_tok, port_val=6881)[0] == 200
        status, body = _announce(port, "leg", prev, port_val=6890)
        assert status == 200
        assert bencode.decode(body)[b"peers"] == []
    finally:
        srv.shutdown()


def test_permitted_peers_discover_each_other(tmp_path):
    sp = _secrets_path(tmp_path)
    a_tok = _mint_device(sp, "a")
    b_tok = _mint_device(sp, "b")
    ap, lp = _policy_paths(tmp_path)
    peer_policy.initialize(ap, lp)
    srv, port = _serve(tmp_path, secrets_path=sp, policy_paths=(ap, lp))
    try:
        _announce(port, "pa", a_tok, port_val=6881)
        status, body = _announce(port, "pb", b_tok, port_val=6882)
        peers = bencode.decode(body)[b"peers"]
        assert any(p[b"port"] == 6881 for p in peers)
    finally:
        srv.shutdown()


def test_fail_closed_policy_yields_zero_candidates(tmp_path):
    sp = _secrets_path(tmp_path)
    a_tok = _mint_device(sp, "a")
    b_tok = _mint_device(sp, "b")
    ap, lp = _policy_paths(tmp_path)
    # Both files present but corrupt -> fail_closed.
    with open(ap, "w") as f:
        f.write("{ this is not json")
    with open(lp, "w") as f:
        f.write("{ also broken")
    srv, port = _serve(tmp_path, secrets_path=sp, policy_paths=(ap, lp))
    try:
        _announce(port, "pa", a_tok, port_val=6881)
        status, body = _announce(port, "pb", b_tok, port_val=6882)
        assert status == 200
        assert bencode.decode(body)[b"peers"] == []
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Durable endpoint write attempts
# ---------------------------------------------------------------------------

def test_attributable_valid_port_writes_durable_endpoint(tmp_path):
    # Rewritten (IRIS-04-004): a device's durable endpoint is its SOCKET
    # source; the ip= override it sends is ignored (see the two tests below).
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, endpoints_path=ep_path)
    try:
        assert _announce(port, "p1", tok, extra="&ip=10.0.0.5")[0] == 200
        snap = peer_endpoints.fresh_endpoints(ep_path, time.time())
        assert "device:dev-a" in snap
        assert snap["device:dev-a"]["endpoints"][0]["ipv4"] == "127.0.0.1"
    finally:
        srv.shutdown()


def test_service_seeder_ip_override_is_persisted(tmp_path):
    """The containerized seeder's socket source is loopback/bridge-local, so
    the service principal's ip= override IS its durable endpoint."""
    sp = _secrets_path(tmp_path)
    tok = _mint_seeder(sp)
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, endpoints_path=ep_path)
    try:
        assert _announce(port, "seed", tok, extra="&ip=10.0.0.5")[0] == 200
        snap = peer_endpoints.fresh_endpoints(ep_path, time.time())
        assert snap["service:seeder"]["endpoints"][0]["ipv4"] == "10.0.0.5"
    finally:
        srv.shutdown()


def test_device_ip_override_cannot_forge_a_durable_endpoint(tmp_path):
    """IRIS-04-004: the seeder blocklist is derived from durable endpoints, so
    a permitted device that could name a quarantined device's address would
    create a shared permit/deny conflict and lift that block. A device's
    override is therefore never persisted -- only its socket source is."""
    sp = _secrets_path(tmp_path)
    good_tok = _mint_device(sp, "good")
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, endpoints_path=ep_path)
    try:
        assert _announce(port, "pg", good_tok, extra="&ip=10.0.0.2")[0] == 200
        snap = peer_endpoints.fresh_endpoints(ep_path, time.time())
        ips = [e["ipv4"] for e in snap["device:good"]["endpoints"]]
        assert ips == ["127.0.0.1"]
    finally:
        srv.shutdown()


def test_bad_port_is_200_and_writes_no_endpoint(tmp_path):
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, endpoints_path=ep_path)
    try:
        status, _ = _announce(port, "p1", tok, port_val=70000)
        assert status == 200
        snap = peer_endpoints.fresh_endpoints(ep_path, time.time())
        assert snap == {}
    finally:
        srv.shutdown()


def test_legacy_and_service_write_no_device_endpoint(tmp_path):
    sp = _secrets_path(tmp_path)
    prev, _cur = _rotate_seeder(sp)
    ep_path = str(tmp_path / "peer-endpoints.json")
    srv, port = _serve(tmp_path, secrets_path=sp, endpoints_path=ep_path)
    try:
        assert _announce(port, "leg", prev, extra="&ip=10.0.0.9")[0] == 200
        snap = peer_endpoints.fresh_endpoints(ep_path, time.time())
        # legacy is never persisted as an attributable endpoint
        assert "legacy:" not in " ".join(snap.keys())
        assert all(not k.startswith("legacy") for k in snap)
    finally:
        srv.shutdown()


def test_endpoint_write_failure_keeps_200_and_enqueues_pending(tmp_path):
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    ep_path = str(tmp_path / "peer-endpoints.json")
    pending = peer_endpoints.PendingEndpointQueue()
    degraded = []

    def failing_record(path, principal, ipv4, port_, now):
        raise OSError("disk full")

    srv, port = _serve(
        tmp_path, secrets_path=sp, endpoints_path=ep_path,
        pending_queue=pending,
        record_endpoint=failing_record,
        on_endpoint_failure=lambda: degraded.append(True))
    try:
        status, _ = _announce(port, "p1", tok, extra="&ip=10.0.0.5")
        # HTTP still 200; policy filtering unaffected
        assert status == 200
        # latest tuple enqueued for retry
        assert len(pending) == 1
        snap = pending.snapshot()
        # The device's socket source, not its ip= claim (IRIS-04-004).
        assert snap["device:dev-a"]["endpoints"][0]["ipv4"] == "127.0.0.1"
        assert degraded  # degrade callback fired
    finally:
        srv.shutdown()


def test_corrupt_endpoint_store_keeps_announce_200_and_enqueues_pending(tmp_path):
    """IRIS-04-002: a corrupt peer-endpoints.json raises EndpointStoreError
    from record_endpoint. That must take the same posture as an OSError --
    200 with the peer list, tuple queued, degrade signal -- not escape the
    handler and close the socket with no response (which stopped discovery
    for every attributable principal until the file was repaired)."""
    sp = _secrets_path(tmp_path)
    a_tok = _mint_device(sp, "a")
    b_tok = _mint_device(sp, "b")
    ep_path = str(tmp_path / "peer-endpoints.json")
    with open(ep_path, "w") as f:
        f.write("{ corrupt")
    pending = peer_endpoints.PendingEndpointQueue()
    degraded = []
    ap, lp = _policy_paths(tmp_path)
    peer_policy.initialize(ap, lp)
    srv, port = _serve(
        tmp_path, secrets_path=sp, endpoints_path=ep_path,
        pending_queue=pending, policy_paths=(ap, lp),
        on_endpoint_failure=lambda: degraded.append(True))
    try:
        assert _announce(port, "pa", a_tok, port_val=6881)[0] == 200
        status, body = _announce(port, "pb", b_tok, port_val=6882)
        assert status == 200
        peers = bencode.decode(body)[b"peers"]
        assert any(p[b"port"] == 6881 for p in peers)   # discovery continues
        assert len(pending) == 2
        assert degraded
    finally:
        srv.shutdown()
    with open(ep_path) as f:
        assert f.read() == "{ corrupt"      # never overwritten


# ---------------------------------------------------------------------------
# Same peer ID isolation
# ---------------------------------------------------------------------------

def test_same_peer_id_distinct_principals_isolated(tmp_path):
    from peer_registry import PeerRegistry
    sp = _secrets_path(tmp_path)
    a_tok = _mint_device(sp, "a")
    b_tok = _mint_device(sp, "b")
    ap, lp = _policy_paths(tmp_path)
    peer_policy.initialize(ap, lp)
    reg = PeerRegistry()
    srv, port = _serve(tmp_path, secrets_path=sp, registry=reg,
                       policy_paths=(ap, lp))
    try:
        # both use peer_id "shared" but different principals
        _announce(port, "shared", a_tok, port_val=6881)
        _announce(port, "shared", b_tok, port_val=6882)
        rows = reg.snapshot()[INFO_HASH_HEX]
        assert len(rows) == 2  # not collapsed into one slot
        # a stops via its own principal: b remains
        _get(port, "/announce?info_hash=%s&peer_id=shared&port=6881"
                   "&event=stopped&announce_token=%s" % (INFO_HASH, a_tok))
        rows2 = reg.snapshot()[INFO_HASH_HEX]
        assert len(rows2) == 1
        assert rows2[0]["principal_id"] == "b"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Preserved behavior + exact override nets
# ---------------------------------------------------------------------------

def test_override_nets_are_exactly_rfc1918_plus_cgnat():
    assert [str(n) for n in tracker._OVERRIDE_NETS] == [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]


def test_scrape_still_authenticates_and_reports(tmp_path):
    sp = _secrets_path(tmp_path)
    tok = _mint_device(sp, "dev-a")
    srv, port = _serve(tmp_path, secrets_path=sp)
    try:
        _announce(port, "p1", tok)
        status, body = _get(
            port, "/scrape?info_hash=%s&announce_token=%s" % (INFO_HASH, tok))
        assert status == 200
        files = bencode.decode(body)[b"files"]
        stats = list(files.values())[0]
        assert stats[b"complete"] == 1
    finally:
        srv.shutdown()


def test_scrape_without_credential_is_403(tmp_path):
    srv, port = _serve(tmp_path)
    try:
        status, _ = _get(port, "/scrape?info_hash=%s" % INFO_HASH)
        assert status == 403
    finally:
        srv.shutdown()
