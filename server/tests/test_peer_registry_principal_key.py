# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Peer lifecycle keyed by typed principal (spec §0a/§6).

Registry identity key is (principal.type, principal.id, peer_id). A device
literally named "seeder" (device:seeder) is distinct from the service seeder
(service:seeder); two principals sharing a peer_id are isolated; `stopped`
removes only the authenticated key; snapshots/events carry typed public fields
and a participant class; the lifecycle event id is in-process only.
"""
import re

import auth
from peer_registry import PeerRegistry


DEV = auth.Principal("device", "dev-1")
DEV_SEEDER = auth.Principal("device", "seeder")     # a device named "seeder"
SVC_SEEDER = auth.Principal("service", "seeder")    # the service seeder
LEGACY = auth.Principal("legacy", "10.0.0.9:6881")


def test_two_principals_share_peer_id_are_isolated():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    reg.announce("IH", "p1", "10.0.0.2", 6882, principal=SVC_SEEDER, now=0)
    # both keys coexist despite the shared peer_id
    peers = reg.peers("IH", "asker", numwant=50, now=0)
    ips = {p["ip"] for p in peers}
    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_device_seeder_distinct_from_service_seeder():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV_SEEDER, now=0)
    reg.announce("IH", "p1", "10.0.0.2", 6882, principal=SVC_SEEDER, now=0)
    snap = reg.snapshot(now=0)["IH"]
    by_ip = {p["ip"]: p for p in snap}
    assert by_ip["10.0.0.1"]["principal_type"] == "device"
    assert by_ip["10.0.0.1"]["principal_id"] == "seeder"
    assert by_ip["10.0.0.2"]["principal_type"] == "service"
    assert by_ip["10.0.0.2"]["principal_id"] == "seeder"


def test_stopped_removes_only_authenticated_key():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    reg.announce("IH", "p1", "10.0.0.2", 6882, principal=SVC_SEEDER, now=0)
    # stopping the DEV key must leave the service:seeder key untouched
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV,
                 event="stopped", now=1)
    ips = {p["ip"] for p in reg.peers("IH", "asker", numwant=50, now=1)}
    assert ips == {"10.0.0.2"}


def test_snapshot_carries_typed_public_fields_and_participant_class():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, left=0, principal=SVC_SEEDER,
                 now=0)
    reg.announce("IH", "p2", "10.0.0.2", 6882, left=100, principal=DEV, now=0)
    reg.announce("IH", "p3", "10.0.0.3", 6883, left=50, principal=LEGACY, now=0)
    by_ip = {p["ip"]: p for p in reg.snapshot(now=0)["IH"]}
    # participant class is derived from the principal type
    assert by_ip["10.0.0.1"]["participant_class"] == "seeder"
    assert by_ip["10.0.0.2"]["participant_class"] == "device"
    assert by_ip["10.0.0.3"]["participant_class"] == "legacy_unattributed"


def test_events_carry_typed_principal_and_inprocess_event_id():
    events = []
    reg = PeerRegistry(on_event=events.append)
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    join = next(e for e in events if e["event"] == "join")
    assert join["principal_type"] == "device"
    assert join["principal_id"] == "dev-1"
    # a random in-process lifecycle event id (32 hex, token_hex(16))
    assert re.fullmatch(r"[0-9a-f]{32}", join["event_id"])


def test_lifecycle_event_ids_are_unique_per_event():
    events = []
    reg = PeerRegistry(on_event=events.append)
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    reg.announce("IH", "p2", "10.0.0.2", 6882, principal=DEV, now=0)
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))


def test_legacy_principal_id_from_endpoint():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.9", 6881, principal=LEGACY, now=0)
    snap = reg.snapshot(now=0)["IH"][0]
    assert snap["principal_type"] == "legacy"
    # legacy principal_id may be omitted from public output; when present it is
    # the endpoint-derived nonsecret key, never a token
    assert snap.get("principal_id") in (None, "10.0.0.9:6881")


# ---------------------------------------------------------------------------
# Peer selection interface: requester principal/IP + predicate over both sides
# ---------------------------------------------------------------------------

def test_select_predicate_receives_both_complete_principals_and_ips():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    reg.announce("IH", "p2", "10.0.0.2", 6882, principal=SVC_SEEDER, now=0)

    seen = []

    def allow(req_principal, req_ip, cand_principal, cand_ip):
        seen.append((req_principal, req_ip, cand_principal, cand_ip))
        # permit only the service seeder candidate
        return cand_principal.type == "service"

    out = reg.select_peers("IH", "asker", requester_principal=DEV,
                           requester_ip="10.0.0.7", predicate=allow, now=0)
    # predicate saw complete typed principals + IPs on both sides
    assert all(isinstance(s[0], auth.Principal) for s in seen)
    assert all(isinstance(s[2], auth.Principal) for s in seen)
    assert all(s[1] == "10.0.0.7" for s in seen)
    # only the permitted candidate is returned
    assert out == [{"ip": "10.0.0.2", "port": 6882}]


def test_select_without_predicate_returns_all_others():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, principal=DEV, now=0)
    reg.announce("IH", "p2", "10.0.0.2", 6882, principal=SVC_SEEDER, now=0)
    out = reg.select_peers("IH", "asker", requester_principal=DEV,
                           requester_ip="10.0.0.7", predicate=None, now=0)
    ips = {p["ip"] for p in out}
    assert ips == {"10.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# Backward compatibility: bare (principal-less) callers still work
# ---------------------------------------------------------------------------

def test_bare_announce_still_works_without_principal():
    reg = PeerRegistry()
    reg.announce("IH", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("IH", "p2", "10.0.0.2", 6882, now=0)
    ips = {p["ip"] for p in reg.peers("IH", "p1", numwant=50, now=0)}
    assert ips == {"10.0.0.2"}
