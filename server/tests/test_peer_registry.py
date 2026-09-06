# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import auth

from peer_registry import PeerRegistry, INTERVAL


def test_announce_returns_other_peers_not_self():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, now=0)
    peers = reg.peers("ABC", "p1", numwant=50, now=0)
    assert {"ip": "10.0.0.2", "port": 6882} in peers
    assert {"ip": "10.0.0.1", "port": 6881} not in peers


def test_event_stopped_removes_peer():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, event="stopped", now=1)
    assert reg.peers("ABC", "p1", numwant=50, now=1) == []


def test_expiry_after_two_intervals():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, now=0)
    # p2 last seen at 0; at now > 2*INTERVAL it must be pruned
    assert reg.peers("ABC", "p1", numwant=50, now=2 * INTERVAL + 1) == []


def test_completed_marks_seeder_in_scrape():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=100, now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, left=0,
                 event="completed", now=0)
    s = reg.scrape("ABC", now=0)
    assert s == {"complete": 1, "incomplete": 1, "downloaded": 1}


def test_numwant_caps_results():
    reg = PeerRegistry()
    for n in range(10):
        reg.announce("ABC", "p%d" % n, "10.0.0.%d" % n, 6881 + n, now=0)
    assert len(reg.peers("ABC", "asker", numwant=3, now=0)) == 3


def test_zero_or_negative_numwant_returns_no_peer_or_predicate_call():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    assert reg.peers("ABC", "asker", numwant=0, now=0) == []
    assert reg.peers("ABC", "asker", numwant=-1, now=0) == []
    calls = []
    requester = auth.Principal("device", "requester")
    assert reg.select_peers(
        "ABC", "asker", requester, "10.0.0.9",
        predicate=lambda *args: calls.append(args) or True,
        numwant=0, now=0) == []
    assert calls == []


def test_numwant_cap_is_exact_at_and_above_two_hundred():
    reg = PeerRegistry()
    for index in range(210):
        reg.announce(
            "ABC", "p%d" % index, "10.0.%d.%d" %
            (index // 254, index % 254 + 1), 6000 + index, now=0)
    assert len(reg.peers("ABC", "asker", numwant=200, now=0)) == 200
    assert len(reg.peers("ABC", "asker", numwant=500, now=0)) == 200


def test_swarm_isolation_and_binary_info_hash():
    reg = PeerRegistry()
    reg.announce("c9fd2e2b00", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("XYZ", "p2", "10.0.0.2", 6882, now=0)
    assert reg.peers("c9fd2e2b00", "asker", numwant=50, now=0) == \
        [{"ip": "10.0.0.1", "port": 6881}]


# --- on_event lifecycle callback (telemetry) ---

def _recorder():
    events = []
    return events, lambda ev: events.append(ev)


def test_on_event_fires_join_for_new_peer():
    events, cb = _recorder()
    reg = PeerRegistry(on_event=cb)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=9, now=0)
    joins = [e for e in events if e["event"] == "join"]
    assert len(joins) == 1
    assert joins[0]["info_hash"] == "ABC"
    assert joins[0]["peer_id"] == "p1"
    assert joins[0]["ip"] == "10.0.0.1"


def test_on_event_join_fires_only_once_per_peer():
    events, cb = _recorder()
    reg = PeerRegistry(on_event=cb)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=9, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=5, now=1)
    assert len([e for e in events if e["event"] == "join"]) == 1


def test_on_event_fires_complete_on_completed_event():
    events, cb = _recorder()
    reg = PeerRegistry(on_event=cb)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=9, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0,
                 event="completed", now=1)
    completes = [e for e in events if e["event"] == "complete"]
    assert len(completes) == 1
    assert completes[0]["peer_id"] == "p1"


def test_on_event_fires_stop_on_stopped_event():
    events, cb = _recorder()
    reg = PeerRegistry(on_event=cb)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=9, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, event="stopped", now=1)
    stops = [e for e in events if e["event"] == "stop"]
    assert len(stops) == 1
    assert stops[0]["peer_id"] == "p1"


def test_on_event_fires_stale_on_prune():
    events, cb = _recorder()
    reg = PeerRegistry(on_event=cb)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=9, now=0)
    # p1 goes silent; pruning past 2*INTERVAL must emit exactly one "stale"
    reg.prune_all(now=2 * INTERVAL + 1)
    stale = [e for e in events if e["event"] == "stale"]
    assert len(stale) == 1
    assert stale[0]["peer_id"] == "p1"
    assert stale[0]["info_hash"] == "ABC"


def test_no_callback_is_safe():
    reg = PeerRegistry()  # on_event defaults to None
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, event="stopped", now=1)
    reg.prune_all(now=2 * INTERVAL + 1)  # must not raise


def test_raising_callback_never_breaks_announce():
    def boom(_ev):
        raise RuntimeError("telemetry sink is down")
    reg = PeerRegistry(on_event=boom)
    # announce must still register the peer despite the callback exploding
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=0)
    assert reg.scrape("ABC", now=0)["complete"] == 1


# --- stats() snapshot for the /metrics endpoint ---

def test_stats_counts_seeders_leechers_and_bytes_remaining():
    reg = PeerRegistry()
    reg.announce("ABC", "s1", "10.0.0.1", 6881, left=0, now=0)
    reg.announce("ABC", "l1", "10.0.0.2", 6882, left=500, now=0)
    reg.announce("ABC", "l2", "10.0.0.3", 6883, left=300, now=0)
    st = reg.stats(now=0)["ABC"]
    assert st["seeders"] == 1
    assert st["leechers"] == 2
    assert st["peers"] == 3
    assert st["bytes_remaining"] == 800


def test_stats_includes_completed_count():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0,
                 event="completed", now=0)
    assert reg.stats(now=0)["ABC"]["completed"] == 1


def test_stats_excludes_stale_peers():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=10, now=0)
    st = reg.stats(now=2 * INTERVAL + 1)
    assert "ABC" not in st


def test_stats_separates_swarms():
    reg = PeerRegistry()
    reg.announce("AAA", "p1", "10.0.0.1", 6881, left=0, now=0)
    reg.announce("BBB", "p2", "10.0.0.2", 6882, left=5, now=0)
    st = reg.stats(now=0)
    assert st["AAA"]["seeders"] == 1
    assert st["BBB"]["leechers"] == 1


def test_stats_left_unknown_does_not_break_bytes_remaining():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=None, now=0)
    st = reg.stats(now=0)["ABC"]
    assert st["bytes_remaining"] == 0
    assert st["peers"] == 1


# --- snapshot() per-peer detail for the live swarm map ---

def test_snapshot_lists_per_peer_detail():
    reg = PeerRegistry()
    reg.announce("ABC", "s1", "10.0.0.1", 6881, left=0, now=0)
    reg.announce("ABC", "l1", "10.0.0.2", 6882, left=500, now=0)
    by_ip = {p["ip"]: p for p in reg.snapshot(now=0)["ABC"]}
    assert by_ip["10.0.0.1"]["is_seeder"] is True
    assert by_ip["10.0.0.2"]["is_seeder"] is False
    assert by_ip["10.0.0.2"]["left"] == 500
    assert by_ip["10.0.0.2"]["port"] == 6882
    assert "last_seen" in by_ip["10.0.0.2"]


def test_snapshot_excludes_empty_and_stale_swarms():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=10, now=0)
    assert reg.snapshot(now=2 * INTERVAL + 1) == {}


# --- torrent download wall-clock time (joined_at -> completed_at). Used by the
# swarm-map's "torrent download" row. Excludes any post-download copy/verify
# (the agent's flash-root copy happens after the BT layer is already done). ---

def test_snapshot_carries_joined_at_from_first_announce():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    # re-announce later: joined_at must not move
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=300, now=200)
    by_ip = {p["ip"]: p for p in reg.snapshot(now=200)["ABC"]}
    assert by_ip["10.0.0.1"]["joined_at"] == 100


def test_snapshot_completed_at_is_first_announce_with_left_zero():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=412)
    # download_seconds = completed_at - joined_at (312s here)
    p = reg.snapshot(now=412)["ABC"][0]
    assert p["completed_at"] == 412
    assert p["download_seconds"] == 312


def test_snapshot_completed_at_does_not_move_on_later_seeding_announces():
    # After a peer finishes its download it keeps re-announcing as a seeder.
    # The completed_at stamp must lock in on the FIRST left=0 announce so the
    # download_seconds field stays stable (otherwise the map would tick up
    # as the peer keeps seeding). Lock holds across pure-seeding announces.
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=400)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=900)
    p = reg.snapshot(now=900)["ABC"][0]
    assert p["completed_at"] == 400          # frozen at first-zero, not 900
    assert p["download_seconds"] == 300


def test_snapshot_re_download_cycle_resets_joined_and_completed_at():
    # Real-world: device finishes its download, becomes a seeder; then an
    # operator deletes the file and the agent self-heals (re-downloads). The
    # tracker sees announces with left > 0 again. That's a NEW download cycle
    # — joined_at must reset to the moment left ticked back up, completed_at
    # must clear, and on the next left=0 it locks the new cycle's time.
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=400)   # cycle 1 done
    # ... peer seeds for a while ...
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=900) # cycle 2 starts
    p = reg.snapshot(now=900)["ABC"][0]
    assert p["joined_at"] == 900             # reset to the re-download moment
    assert p["completed_at"] is None         # cleared; next zero will lock it
    assert p["download_seconds"] is None     # in-flight
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=1100)  # cycle 2 done
    p = reg.snapshot(now=1100)["ABC"][0]
    assert p["completed_at"] == 1100
    assert p["download_seconds"] == 200      # ONLY cycle 2's time, not 1000


def test_snapshot_re_download_cycle_resets_even_after_omitted_left_announce():
    # A finished peer (left=0) that re-announces while OMITTING `left` is stored
    # with left=None. The cycle-reset must still fire on the next real
    # re-download (left>0): if the guard keyed off prev["left"]==0 it would miss
    # this (None != 0) and report the OLD cycle's stale time. We key off
    # completed_at instead, so the omitted-left seeding announce can't mask it.
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=0, now=400)    # cycle 1 done
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=None, now=600) # seeding, left omitted
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=900)  # cycle 2 starts
    p = reg.snapshot(now=900)["ABC"][0]
    assert p["joined_at"] == 900             # reset despite the left=None announce
    assert p["completed_at"] is None         # cleared; not frozen at 400
    assert p["download_seconds"] is None     # in-flight, not the stale 300


def test_snapshot_download_seconds_none_while_still_downloading():
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    p = reg.snapshot(now=150)["ABC"][0]   # within 2*INTERVAL, no prune
    assert p["completed_at"] is None
    assert p["download_seconds"] is None


def test_snapshot_completed_event_stamps_completed_at_even_if_left_unknown():
    # A "completed" event without an explicit left value (or with left>0 due
    # to a quirky client) should still stamp completed_at — the event itself
    # is the authoritative "I'm done downloading" signal.
    reg = PeerRegistry()
    reg.announce("ABC", "p1", "10.0.0.1", 6881, left=500, now=100)
    reg.announce("ABC", "p1", "10.0.0.1", 6881,
                 event="completed", left=None, now=350)
    p = reg.snapshot(now=350)["ABC"][0]
    assert p["completed_at"] == 350
    assert p["download_seconds"] == 250


def test_snapshot_seeder_first_announce_has_zero_download_seconds():
    # A peer that joins as a seeder (left=0 from first announce) has nothing
    # to download — joined_at == completed_at == now, so download_seconds == 0.
    # The map UI suppresses the row for seeders; this just nails the math.
    reg = PeerRegistry()
    reg.announce("ABC", "s1", "10.0.0.1", 6881, left=0, now=42)
    p = reg.snapshot(now=42)["ABC"][0]
    assert p["is_seeder"] is True
    assert p["joined_at"] == 42
    assert p["completed_at"] == 42
    assert p["download_seconds"] == 0


# ---------------------------------------------------------------------------
# Issued cadence and amortized pruning
# ---------------------------------------------------------------------------

def test_record_expires_against_its_issued_interval_at_strict_boundary():
    reg = PeerRegistry(interval=INTERVAL, read_prune_interval=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, interval=120, now=0)
    assert reg.snapshot(now=60)["ABC"][0]["interval"] == 120
    assert reg.snapshot(now=240)["ABC"][0]["peer_id"] == "p1"
    assert reg.snapshot(now=241) == {}


def test_reannounce_replaces_issued_interval_and_bare_call_uses_default():
    reg = PeerRegistry(interval=30, read_prune_interval=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=0)
    assert reg.snapshot(now=0)["ABC"][0]["interval"] == 30
    reg.announce("ABC", "p1", "10.0.0.1", 6881, interval=20, now=100)
    assert reg.snapshot(now=140)["ABC"][0]["interval"] == 20
    assert reg.snapshot(now=141) == {}


def test_read_paths_share_one_prune_gate_and_prune_all_always_sweeps(
        monkeypatch):
    reg = PeerRegistry(read_prune_interval=30)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=100)
    real_prune = reg._prune
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return real_prune(*args, **kwargs)

    monkeypatch.setattr(reg, "_prune", counted)
    principal = auth.Principal("device", "requester")
    reg.peers("ABC", "asker", now=100)
    reg.select_peers("ABC", "asker", principal, "10.0.0.9", now=100)
    reg.scrape("ABC", now=100)
    reg.stats(now=100)
    reg.snapshot(now=100)
    assert calls == ["ABC"]

    reg.prune_all(now=101)
    assert calls == ["ABC", "ABC"]
    reg.snapshot(now=101)
    assert calls == ["ABC", "ABC"]


def test_read_prune_gate_forces_a_sweep_when_clock_moves_back(monkeypatch):
    reg = PeerRegistry(read_prune_interval=30)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, now=100)
    real_prune = reg._prune
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return real_prune(*args, **kwargs)

    monkeypatch.setattr(reg, "_prune", counted)
    reg.snapshot(now=100)
    reg.snapshot(now=90)
    assert calls == ["ABC", "ABC"]


# ---------------------------------------------------------------------------
# Bounded indexed selection
# ---------------------------------------------------------------------------

def test_general_selection_inspects_at_most_four_times_numwant():
    reg = PeerRegistry(randbelow=lambda size: size // 2)
    for index in range(10_000):
        reg.announce(
            "ABC", "p%d" % index, "10.%d.%d.%d" %
            (index // 65536, (index // 256) % 256, index % 256),
            6000 + index % 1000,
            principal=auth.Principal("device", "d%d" % index), now=0)
    calls = []
    out = reg.select_peers(
        "ABC", "asker", auth.Principal("device", "requester"),
        "192.0.2.1", predicate=lambda *args: calls.append(args) or False,
        numwant=50, now=0)
    assert out == []
    assert len(calls) == 200


def test_random_start_changes_the_bounded_selection_window():
    starts = iter((0, 5))
    reg = PeerRegistry(randbelow=lambda _size: next(starts))
    for index in range(10):
        reg.announce(
            "ABC", "p%d" % index, "10.0.0.%d" % (index + 1),
            6000 + index, principal=auth.Principal("device", "d%d" % index),
            now=0)
    requester = auth.Principal("device", "requester")
    first = reg.select_peers(
        "ABC", "asker", requester, "192.0.2.1",
        predicate=lambda *args: True, numwant=1, now=0)
    second = reg.select_peers(
        "ABC", "asker", requester, "192.0.2.1",
        predicate=lambda *args: True, numwant=1, now=0)
    assert first != second


def test_sparse_candidate_principal_index_avoids_full_swarm_walk():
    reg = PeerRegistry(randbelow=lambda _size: 0)
    for index in range(10_000):
        reg.announce(
            "ABC", "p%d" % index, "10.%d.%d.%d" %
            (index // 65536, (index // 256) % 256, index % 256),
            6000 + index % 1000,
            principal=auth.Principal("device", "d%d" % index), now=0)
    calls = []
    out = reg.select_peers(
        "ABC", "asker", auth.Principal("device", "requester"),
        "192.0.2.1", predicate=lambda *args: calls.append(args) or True,
        numwant=50, now=0,
        candidate_principals=frozenset({("device", "d9999")}))
    assert out == [{"ip": "10.0.39.15", "port": 6999}]
    assert len(calls) == 1


def test_role_index_reuses_generation_and_tracks_ip_stop_expiry_and_policy():
    class Compiled:
        def __init__(self, role_of):
            self.role_of = role_of

    first = Compiled({"d1": "allowed", "d2": "allowed", "d3": "allowed"})
    reg = PeerRegistry(read_prune_interval=0, randbelow=lambda _size: 0)
    requester = auth.Principal("device", "requester")
    reg.announce("ABC", "p1", "10.0.0.1", 6881, interval=1,
                 principal=auth.Principal("device", "d1"), now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, interval=100,
                 principal=auth.Principal("device", "d2"), now=0)

    def select(compiled=first):
        return reg.select_peers(
            "ABC", "asker", requester, "192.0.2.1",
            predicate=lambda *_args: True, numwant=50, now=0,
            candidate_roles=frozenset({"allowed"}),
            compiled_roles=compiled)

    assert {row["ip"] for row in select()} == {"10.0.0.1", "10.0.0.2"}
    assert reg._role_index_builds == 1
    assert len(select()) == 2
    assert reg._role_index_builds == 1

    reg.announce("ABC", "p1", "10.0.0.9", 6881, interval=1,
                 principal=auth.Principal("device", "d1"), now=0)
    reg.announce("ABC", "p2", "10.0.0.2", 6882, event="stopped",
                 principal=auth.Principal("device", "d2"), now=0)
    reg.announce("ABC", "p3", "10.0.0.3", 6883, interval=100,
                 principal=auth.Principal("device", "d3"), now=0)
    assert {row["ip"] for row in select()} == {"10.0.0.9", "10.0.0.3"}
    assert reg._role_index_builds == 1

    reg.prune_all(now=3)
    assert reg.select_peers(
        "ABC", "asker", requester, "192.0.2.1",
        predicate=lambda *_args: True, numwant=50, now=3,
        candidate_roles=frozenset({"allowed"}),
        compiled_roles=first) == [{"ip": "10.0.0.3", "port": 6883}]

    second = Compiled({"d3": "other"})
    assert reg.select_peers(
        "ABC", "asker", requester, "192.0.2.1",
        predicate=lambda *_args: True, numwant=50, now=3,
        candidate_roles=frozenset({"allowed"}),
        compiled_roles=second) == []
    assert reg._role_index_builds == 2


# ---------------------------------------------------------------------------
# Session-cumulative transfer counter baselines
# ---------------------------------------------------------------------------

def _counter_row(reg, peer_id="p1", now=0):
    return next(row for row in reg.snapshot(now=now)["ABC"]
                if row["peer_id"] == peer_id)


def test_transfer_counters_baseline_then_report_positive_deltas():
    reg = PeerRegistry()
    principal = auth.Principal("device", "d1")
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=100, downloaded=200, now=0)
    assert _counter_row(reg)["uploaded_delta"] == 0
    assert _counter_row(reg)["downloaded_delta"] == 0
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=175, downloaded=260, now=1)
    row = _counter_row(reg, now=1)
    assert row["uploaded_delta"] == 75
    assert row["downloaded_delta"] == 60
    assert row["counter_reset"] is False


def test_started_peer_change_or_negative_delta_rebaselines_both_counters():
    reg = PeerRegistry()
    principal = auth.Principal("device", "d1")
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=100, downloaded=200, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=150, downloaded=250, event="started", now=1)
    started = _counter_row(reg, now=1)
    assert (started["uploaded_delta"], started["downloaded_delta"],
            started["counter_reset"]) == (0, 0, True)

    reg.announce("ABC", "p2", "10.0.0.1", 6881, principal=principal,
                 uploaded=175, downloaded=275, now=2)
    changed = _counter_row(reg, "p2", now=2)
    assert (changed["uploaded_delta"], changed["downloaded_delta"],
            changed["counter_reset"]) == (0, 0, True)

    reg.announce("ABC", "p2", "10.0.0.1", 6881, principal=principal,
                 uploaded=10, downloaded=300, now=3)
    negative = _counter_row(reg, "p2", now=3)
    assert (negative["uploaded_delta"], negative["downloaded_delta"],
            negative["counter_reset"]) == (0, 0, True)


def test_missing_counters_do_not_erase_a_sound_baseline():
    reg = PeerRegistry()
    principal = auth.Principal("device", "d1")
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=100, downloaded=200, now=0)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=None, downloaded=None, now=1)
    reg.announce("ABC", "p1", "10.0.0.1", 6881, principal=principal,
                 uploaded=130, downloaded=240, now=2)
    row = _counter_row(reg, now=2)
    assert row["uploaded_delta"] == 30
    assert row["downloaded_delta"] == 40


def test_stopping_or_pruning_old_peer_id_keeps_newer_counter_baseline():
    reg = PeerRegistry(read_prune_interval=0)
    principal = auth.Principal("device", "d1")
    reg.announce("ABC", "old", "10.0.0.1", 6881, principal=principal,
                 uploaded=100, downloaded=200, interval=1, now=0)
    reg.announce("ABC", "new", "10.0.0.1", 6881, principal=principal,
                 uploaded=10, downloaded=20, interval=100, now=1)
    reg.announce("ABC", "old", "10.0.0.1", 6881, principal=principal,
                 event="stopped", now=2)
    reg.prune_all(now=3)
    reg.announce("ABC", "new", "10.0.0.1", 6881, principal=principal,
                 uploaded=15, downloaded=27, interval=100, now=4)
    row = _counter_row(reg, "new", now=4)
    assert row["uploaded_delta"] == 5
    assert row["downloaded_delta"] == 7


def test_stale_old_peer_id_does_not_delete_newer_counter_baseline():
    reg = PeerRegistry(read_prune_interval=0)
    principal = auth.Principal("device", "d1")
    reg.announce("ABC", "old", "10.0.0.1", 6881, principal=principal,
                 uploaded=100, downloaded=200, interval=1, now=0)
    reg.announce("ABC", "new", "10.0.0.1", 6881, principal=principal,
                 uploaded=10, downloaded=20, interval=100, now=1)
    reg.prune_all(now=3)
    reg.announce("ABC", "new", "10.0.0.1", 6881, principal=principal,
                 uploaded=15, downloaded=27, interval=100, now=4)
    row = _counter_row(reg, "new", now=4)
    assert row["uploaded_delta"] == 5
    assert row["downloaded_delta"] == 7


# ---------------------------------------------------------------------------
# Concurrency: concurrent announce + prune + snapshot must not raise
# ---------------------------------------------------------------------------

def test_concurrent_announce_prune_snapshot_no_race():
    """Concurrent writers (announce) and readers (snapshot/stats/prune_all) must
    never raise RuntimeError('dictionary changed size during iteration') or any
    other exception.  Without a lock this is reliably triggered in <1 second."""
    import threading
    import time as _time

    errors = []
    registry = PeerRegistry(interval=1)

    def writer(n):
        for i in range(200):
            try:
                registry.announce("IH1", "peer%d-%d" % (n, i),
                                  "10.0.%d.%d" % (n, i % 254 + 1), 6881 + i,
                                  left=i, now=_time.time())
                # also trigger stopped to cause deletions
                if i % 5 == 0:
                    registry.announce("IH1", "peer%d-%d" % (n, i - 1),
                                      "10.0.%d.%d" % (n, i % 254 + 1), 6881 + i,
                                      event="stopped", now=_time.time())
            except Exception as e:
                errors.append(("writer", n, i, repr(e)))

    def reader():
        for _ in range(200):
            try:
                registry.snapshot(now=_time.time())
                registry.stats(now=_time.time())
                # peers() is the hottest lock path: called on every single
                # announce response in _handle_announce immediately after
                # registry.announce(), so it must be exercised concurrently.
                registry.peers("IH1", "reader-probe", numwant=10,
                                now=_time.time())
            except Exception as e:
                errors.append(("reader", repr(e)))

    def pruner():
        for _ in range(50):
            try:
                registry.prune_all(now=_time.time() + 10)
            except Exception as e:
                errors.append(("pruner", repr(e)))
            _time.sleep(0.005)

    threads = (
        [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        + [threading.Thread(target=reader) for _ in range(4)]
        + [threading.Thread(target=pruner)]
    )
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert errors == [], "Concurrency errors:\n" + "\n".join(str(e) for e in errors)
